"""Manual evidence-review state, source selection and export."""

from __future__ import annotations

import curses
import datetime as dt
import math
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from contextlib import closing
from pathlib import Path
from typing import Optional

from attacklog_correlator.config import HostResolver
from attacklog_correlator.ingestion.logtypes import LogTypeRule, matching_log_type
from attacklog_correlator.models import Attack, Correlation, LogEvent, UTC
from attacklog_correlator import manual_ui
from attacklog_correlator.manual_ui import SEARCH_ALL_KEY
from attacklog_correlator.manual_logs import (
    IndexedTimestamp, ManualLine, attack_details, indexed_lines_in_window,
    index_log_file, iter_search_lines, parse_search_query, search_match_spans,
)


class ManualBrowser:
    """Three-pane curses browser; selections are scoped to an attack and source line."""

    def __init__(
        self, attacks: list[Attack], files: list[Path], correlations: list[Correlation],
        events: list[LogEvent], log_root: Path, resolver: HostResolver, default_year: int,
        before: float, after: float, out_dir: Path,
        log_types: Optional[list[LogTypeRule]] = None,
    ) -> None:
        self.attacks = attacks
        self.files = files
        self.visible_files: list[Path] = []
        self._files_key: Optional[tuple] = None
        self._preferred_line: Optional[int] = None
        self._timestamps: Optional[dict[Path, list[IndexedTimestamp]]] = None
        self._times: dict[Path, list[dt.datetime]] = {}
        self._window_key: Optional[tuple[float, float]] = None
        self._window_files: list[list[Path]] = []
        self.log_root = log_root
        self.resolver = resolver
        self.default_year = default_year
        self.before = before
        self.after = after
        self.log_types = log_types
        self.attack_index = 0
        self.active_attack_index: Optional[int] = None
        self.attack_top = 0
        self.file_index = 0
        self.line_index = 0
        self.file_top = 0
        self.line_top = 0
        self.horizontal = 0
        self.focus = "attacks"
        self.status = "Indexing log timestamps at startup"
        self.auto_attr = curses.A_BOLD
        self.search_attr = curses.A_STANDOUT | curses.A_BOLD
        self.heatmap = True
        self.heat_attrs: list[int] = []
        self._view_key: Optional[tuple] = None
        self.lines: list[ManualLine] = []
        self.distance_range = (0.0, 0.0)
        self.search_results: Optional[dict[Path, list[ManualLine]]] = None
        self.search_query = ""

        # A source line can correlate with several attack steps. Keep those selections independent.
        self.automatic = {(c.attack_id, c.event_file, c.event_line) for c in correlations}
        self.auto_counts = Counter((attack_id, path) for attack_id, path, _ in self.automatic)
        self.auto_attacks = {attack_id for attack_id, _path, _line in self.automatic}
        self.selected = set(self.automatic)
        source_text = {(e.file_path, e.line_number): e.raw_line for e in events}
        self.text_by_key = {
            (c.attack_id, c.event_file, c.event_line): source_text.get((c.event_file, c.event_line), c.event_message)
            for c in correlations
        }
        self._complete_text = {key for key in self.text_by_key if (key[1], key[2]) in source_text}
        self.out_dir = out_dir
        self.output_path = out_dir / f"manual_selection_{dt.datetime.now(UTC):%Y%m%dT%H%M%S%fZ}.txt"
        self._saved = False

    def _index_files(self, screen=None) -> None:
        if self._timestamps is not None:
            return
        if screen is not None:
            height, width = screen.getmaxyx()
            self._write(screen, height - 1, 0, "Indexing log timestamps (once)...", width - 1, curses.A_REVERSE)
            screen.refresh()
        timestamps: dict[Path, list[IndexedTimestamp]] = {}
        errors = 0
        for path in self.files:
            rule = matching_log_type(path, self.log_types) if self.log_types is not None else None
            try:
                rows = index_log_file(path, self.log_root, self.resolver, self.default_year, rule)
            except (OSError, RuntimeError, ValueError):
                errors += 1
                continue
            if rows:
                timestamps[path] = rows
        self._timestamps = timestamps
        self._times = {path: [stamp.time for stamp in stamps] for path, stamps in timestamps.items()}
        self.status = f"Indexed {len(timestamps)} timestamped files" + (f" ({errors} unreadable)" if errors else "")

    def _matching_stamps(self, path: Path, attack: Attack) -> list[IndexedTimestamp]:
        stamps = self._timestamps[path]
        times = self._times[path]
        start = attack.timestamp - dt.timedelta(seconds=self.before)
        end = attack.timestamp + dt.timedelta(seconds=self.after)
        return stamps[bisect_left(times, start):bisect_right(times, end)]

    def _update_files(self) -> None:
        """Use indexed timestamps to determine visible files for every attack."""
        if self.search_results is not None:
            return
        if self._timestamps is None or self.active_attack_index is None:
            return
        key = (self.before, self.after)
        if key != self._window_key:
            self._window_files = []
            for attack in self.attacks:
                start = attack.timestamp - dt.timedelta(seconds=self.before)
                end = attack.timestamp + dt.timedelta(seconds=self.after)
                matching = []
                for path in self.files:
                    times = self._times.get(path)
                    if times:
                        index = bisect_left(times, start)
                        if index < len(times) and times[index] <= end:
                            matching.append(path)
                self._window_files.append(matching)
            self._window_key = key
        current = (self.visible_files[self.file_index]
                   if self.visible_files and self.file_index < len(self.visible_files) else None)
        new_files = self._window_files[self.active_attack_index]
        new_key = (self.active_attack_index, self.before, self.after)
        if new_key == self._files_key:
            return
        self.visible_files = new_files
        self._files_key = new_key
        if current in new_files:
            self.file_index = new_files.index(current)
        else:
            self.file_index = 0
        self.file_top = 0
        self._view_key = None

    def _key(self, line: ManualLine) -> tuple[str, str, int]:
        assert self.active_attack_index is not None
        return (self.attacks[self.active_attack_index].attack_id,
                str(self.visible_files[self.file_index]), line.line_number)

    def _load_lines(self) -> None:
        self._update_files()
        if self.search_results is not None:
            if not self.visible_files:
                self.lines = []
                return
            key = ("search", self.active_attack_index, self.file_index, self.search_query)
            if key != self._view_key:
                self._view_key = key
                self.lines = self.search_results[self.visible_files[self.file_index]]
                self.line_index = 0
                self.line_top = 0
                attack_time = self.attacks[self.active_attack_index].timestamp
                distances = [abs((row.timestamp - attack_time).total_seconds())
                             for row in self.lines if row.timestamp is not None]
                self.distance_range = (min(distances), max(distances)) if distances else (0, 0)
            return
        if self.active_attack_index is None or not self.visible_files:
            self.lines = []
            self.distance_range = (0.0, 0.0)
            return
        key = (self.active_attack_index, self.file_index, self.before, self.after)
        if key == self._view_key:
            return
        self._view_key = key
        path = self.visible_files[self.file_index]
        try:
            self.lines = indexed_lines_in_window(
                path, self._timestamps[path],
                self._matching_stamps(path, self.attacks[self.active_attack_index]),
            )
            self.status = ""
        except (OSError, RuntimeError) as exc:
            self.lines = []
            self.status = f"Cannot read {path.name}: {exc}"
        attack_time = self.attacks[self.active_attack_index].timestamp
        deltas = [abs((row.timestamp - attack_time).total_seconds())
                  for row in self.lines if row.timestamp is not None and row.timestamp_span is not None]
        self.distance_range = (min(deltas), max(deltas)) if deltas else (0.0, 0.0)
        if self._preferred_line is not None and self.lines:
            self.line_index = min(range(len(self.lines)),
                                  key=lambda i: abs(self.lines[i].line_number - self._preferred_line))
        else:
            self.line_index = next((i for i, line in enumerate(self.lines)
                                    if self._key(line) in self.automatic), 0)
        self._preferred_line = None
        self.line_top = 0

    def activate_attack(self, screen=None) -> None:
        if not self.attacks:
            return
        self._index_files(screen)
        if self.active_attack_index == self.attack_index:
            return
        if self.active_attack_index is not None and self.lines:
            self._preferred_line = self.lines[self.line_index].line_number
        self.active_attack_index = self.attack_index
        self.clear_search()
        self._files_key = None
        self._view_key = None
        self._load_lines()

    def toggle_selected(self) -> None:
        self._load_lines()
        if not self.lines:
            return
        line = self.lines[self.line_index]
        key = self._key(line)
        if key in self.selected:
            self.selected.remove(key)
        else:
            self.selected.add(key)
            self.text_by_key[key] = line.text
            self._complete_text.add(key)

    def toggle_auto_marks(self) -> None:
        if not self.automatic:
            self.status = "No automatic correlations loaded"
        elif self.selected.intersection(self.automatic):
            self.selected.difference_update(self.automatic)
            self.status = "Automatic matches deselected"
        else:
            self.selected.update(self.automatic)
            self.status = "Automatic matches selected"

    def clear_search(self) -> None:
        if self.search_results is None:
            return
        current = self.visible_files[self.file_index] if self.visible_files else None
        self.search_results = None
        self.search_query = ""
        self.visible_files = []
        self._files_key = None
        self._view_key = None
        self._update_files()
        if current in self.visible_files:
            self.file_index = self.visible_files.index(current)
        self._view_key = None

    def search(self, query: str, *, all_lines: bool = False) -> int:
        """Search all discovered logfiles, showing matching raw lines in the panes."""
        needle, exact_bytes = parse_search_query(query)
        if self.active_attack_index is None:
            return 0
        self._index_files()
        self._update_files()
        candidate_files = self.files if all_lines else self._window_files[self.active_attack_index]
        matches: dict[Path, list[ManualLine]] = {}
        target = needle if exact_bytes else needle.lower()
        total = 0
        errors = 0
        # shortcut: cap retained matches to bound memory for broad searches.
        for path in candidate_files:
            stamps = self._timestamps.get(path, [])
            by_line = {stamp.line_number: stamp for stamp in stamps}
            in_window = False
            selected_lines = ({stamp.line_number for stamp in
                               self._matching_stamps(path, self.attacks[self.active_attack_index])}
                              if not all_lines else set())
            found = []
            try:
                with closing(iter_search_lines(path)) as lines:
                    for number, raw in lines:
                        if not all_lines:
                            if number in by_line:
                                in_window = number in selected_lines
                            if not in_window:
                                continue
                        if target not in (raw if exact_bytes else raw.lower()):
                            continue
                        text = raw.decode("utf-8", errors="backslashreplace")
                        stamp = by_line.get(number)
                        span = timestamp_span(text, stamp.raw_timestamp) if stamp else None
                        found.append(ManualLine(number, text, stamp.time if stamp else None, span,
                                                search_match_spans(raw, needle, exact_bytes)))
                        total += 1
                        if total >= 2000:
                            break
            except (OSError, RuntimeError, ValueError):
                errors += 1
                continue
            if found:
                matches[path] = found
            if total >= 2000:
                break

        if not matches:
            self.clear_search()
            self.status = f"No matches for {query!r}" + (f" ({errors} unreadable files)" if errors else "")
            return 0
        self.search_results = matches
        self.search_query = query
        self.visible_files = list(matches)
        self.file_index = 0
        self.line_index = 0
        self._view_key = None
        self.focus = "lines"
        self._load_lines()
        scope = "all logs" if all_lines else "current time window"
        self.status = f"{total} matches in {scope}: {query!r} | Esc: return"
        if total == 2000:
            self.status += " (first 2000)"
        return total

    def jump_match(self, direction: int) -> None:
        """Move to the next/previous matching line, wrapping between files."""
        if self.search_results is None:
            self.status = "Search with Ctrl+F or F first"
            return
        self._load_lines()
        if not self.lines:
            return
        new_line = self.line_index + direction
        if 0 <= new_line < len(self.lines):
            self.line_index = new_line
        else:
            self.file_index = (self.file_index + direction) % len(self.visible_files)
            self._view_key = None
            self._load_lines()
            self.line_index = 0 if direction > 0 else len(self.lines) - 1
        self.focus = "lines"

    def change_window(self, seconds: float) -> None:
        # Keep the before offset unchanged; +/- extends the post-attack window.
        self.set_window(self.before, max(0.0, self.after + seconds))

    def set_window(self, before: float, after: float) -> None:
        if any(not math.isfinite(value) or value < 0 for value in (before, after)):
            raise ValueError("Time offsets must be non-negative finite seconds")
        self.before, self.after = before, after
        self._window_key = None
        self._files_key = None
        self._view_key = None
        self.clear_search()

    def save(self) -> Path:
        """Write raw selected lines, grouped by attack and source file, to one text file."""
        # Saved correlations contain previews, so recover original lines before export.
        missing: dict[str, dict[int, list[tuple[str, str, int]]]] = defaultdict(lambda: defaultdict(list))
        for key in self.selected - self._complete_text:
            missing[key[1]][key[2]].append(key)
        for filename, wanted in missing.items():
            try:
                with closing(iter_search_lines(Path(filename))) as lines:
                    for number, raw in lines:
                        for key in wanted.pop(number, []):
                            self.text_by_key[key] = raw.decode("utf-8", errors="backslashreplace")
                            self._complete_text.add(key)
                        if not wanted:
                            break
            except (OSError, RuntimeError):
                pass
        unavailable = {key for by_line in missing.values() for keys in by_line.values() for key in keys}
        selected_by_attack: dict[str, dict[str, list[tuple[int, str]]]] = defaultdict(lambda: defaultdict(list))
        for attack_id, file_name, line_number in self.selected:
            text = self.text_by_key[(attack_id, file_name, line_number)]
            selected_by_attack[attack_id][file_name].append((line_number, text))

        output = []
        for attack in self.attacks:
            by_file = selected_by_attack.get(attack.attack_id, {})
            if not by_file:
                continue
            output.append(f"# Attack {attack.timestamp.isoformat()} | {attack.source_file}:{attack.line_number}")
            cmd, description = attack_details(attack)
            output.append(f"# Command: {cmd}")
            output.append(f"# Description: {description}")
            for filename in sorted(by_file):
                output.append(f"\n## Log file: {filename}")
                for line_number, text in sorted(by_file[filename]):
                    if (attack.attack_id, filename, line_number) in unavailable:
                        output.append(f"# [SOURCE UNAVAILABLE: {filename}:{line_number}; saved preview only]")
                    output.append(text)
            output.append("")

        self.out_dir.mkdir(parents=True, exist_ok=True)
        if not self._saved and self.output_path.exists():
            raise FileExistsError(self.output_path)
        temporary = self.output_path.with_suffix(".tmp")
        with temporary.open("x", encoding="utf-8") as fh:
            fh.write("\n".join(output) + ("\n" if output else ""))
        temporary.replace(self.output_path)
        self._saved = True
        unresolved = len(unavailable)
        self.status = f"Saved {len(self.selected)} lines: {self.output_path.name}"
        if unresolved:
            self.status += f" ({unresolved} source lines unavailable; used previews)"
        return self.output_path

    # Presentation handlers use this browser's state, but live in the UI module.
    _prompt_search = manual_ui.prompt_search
    _prompt_window = manual_ui.prompt_window
    handle_key = manual_ui.handle_key
    _scroll = staticmethod(manual_ui.scroll)
    _write = staticmethod(manual_ui.write)
    _draw = manual_ui.draw
    _read_key = staticmethod(manual_ui.read_key)
    _main = manual_ui.main

    def run(self) -> Path:
        try:
            curses.wrapper(self._main)
        finally:
            self.save()
        return self.output_path
