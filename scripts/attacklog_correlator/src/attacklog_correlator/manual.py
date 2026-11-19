"""Manual evidence review over the correlator's normalized log timestamps."""

from __future__ import annotations

import curses
import datetime as dt
import math
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from attacklog_correlator.config import HostResolver
from attacklog_correlator.events import guess_host_from_line, normalize_event_time
from attacklog_correlator.ingestion import readers
from attacklog_correlator.ingestion.logtypes import LogTypeRule, matching_log_type
from attacklog_correlator.models import Attack, Correlation, LogEvent, UTC
from attacklog_correlator.tui import sanitize_preview_text


SEARCH_ALL_KEY = 0x110000


@dataclass(frozen=True)
class ManualLine:
    line_number: int
    text: str
    timestamp: Optional[dt.datetime] = None
    timestamp_span: Optional[tuple[int, int]] = None
    search_spans: tuple[tuple[int, int], ...] = ()


def attack_details(attack: Attack) -> tuple[str, str]:
    """Use parsed AttackMate fields rather than displaying the raw JSON."""
    description = attack.metadata.get("description")
    if not isinstance(description, str):
        description = ""
    return attack.cmd.replace("\n", " ") or "(none)", description.replace("\n", " ") or "(none)"


def timestamp_span(text: str, raw: str) -> Optional[tuple[int, int]]:
    """Locate the actual timestamp, tolerating extra spaces in BSD syslog."""
    start = text.find(raw)
    if start >= 0:
        return (start, start + len(raw))
    match = re.search(r"\s+".join(re.escape(part) for part in raw.split()), text)
    return match.span() if match else None


def lines_in_window(
    path: Path, log_root: Path, resolver: HostResolver, default_year: int,
    attack_time: dt.datetime, before: float, after: float,
    log_type: Optional[LogTypeRule] = None, *, first_timestamp_only: bool = False,
) -> list[ManualLine]:
    """Read one file on demand; include continuation lines after an in-window timestamp."""
    start = attack_time - dt.timedelta(seconds=before)
    end = attack_time + dt.timedelta(seconds=after)
    path_host = resolver.host_from_path(path, log_root) or "unknown-host"
    visible: list[ManualLine] = []
    within_window = False
    with closing(readers.iter_log_records(path, default_year, log_type=log_type)) as records:
        for record in records:
            timestamp = None
            if record.parsed_timestamp is not None:
                host = resolver.canonicalize_host(guess_host_from_line(record.raw_line) or path_host)
                timestamp = normalize_event_time(record.parsed_timestamp, host, resolver)
                within_window = start <= timestamp <= end
            if within_window:
                text = record.raw_line.rstrip("\r\n")
                span = timestamp_span(text, record.parsed_timestamp.raw_text) if timestamp else None
                visible.append(ManualLine(record.line_number, text, timestamp, span))
                if timestamp is not None and first_timestamp_only:
                    break
    return visible



@dataclass(frozen=True)
class IndexedTimestamp:
    time: dt.datetime
    line_number: int
    raw_timestamp: str


def index_log_file(
    path: Path, log_root: Path, resolver: HostResolver, default_year: int,
    log_type: Optional[LogTypeRule] = None,
) -> list[IndexedTimestamp]:
    """Normalize each timestamp once; keep line numbers, not full log contents."""
    if not readers.should_try_journalctl(path) and readers.is_probably_binary_file(path):
        return []
    host_hint = resolver.host_from_path(path, log_root) or "unknown-host"
    rows: list[IndexedTimestamp] = []
    with closing(readers.iter_log_records(path, default_year, log_type=log_type)) as records:
        for record in records:
            if record.parsed_timestamp is None:
                continue
            host = resolver.canonicalize_host(guess_host_from_line(record.raw_line) or host_hint)
            timestamp = normalize_event_time(record.parsed_timestamp, host, resolver)
            rows.append(IndexedTimestamp(timestamp, record.line_number, record.parsed_timestamp.raw_text))
    return sorted(rows, key=lambda row: (row.time, row.line_number))


def indexed_lines_in_window(
    path: Path, stamps: list[IndexedTimestamp], selected: list[IndexedTimestamp],
) -> list[ManualLine]:
    """Read raw text without parsing dates again; keep following continuation lines."""
    if not selected:
        return []
    by_line = {item.line_number: item for item in stamps}
    selected_numbers = {item.line_number for item in selected}
    last_selected = max(selected_numbers)
    if readers.should_try_journalctl(path):
        source = closing(readers.run_journalctl_export(path))
    else:
        source = path.open("r", encoding="utf-8", errors="replace")
    lines: list[ManualLine] = []
    within_window = False
    with source as stream:
        for number, raw in enumerate(stream, 1):
            stamp = by_line.get(number)
            if stamp is not None:
                if number > last_selected:
                    break
                within_window = number in selected_numbers
            if within_window:
                text = raw.rstrip("\r\n")
                span = timestamp_span(text, stamp.raw_timestamp) if stamp else None
                lines.append(ManualLine(number, text, stamp.time if stamp else None, span))
    return lines



def parse_search_query(query: str) -> tuple[bytes, bool]:
    r"""Turn \xNN escapes into literal bytes; otherwise use a text search."""
    if not query or re.search(r"\\x(?![0-9a-fA-F]{2})", query):
        raise ValueError("Enter text or valid \\xNN byte escapes")
    parts = re.split(r"(\\x[0-9a-fA-F]{2})", query)
    has_hex = any(re.fullmatch(r"\\x[0-9a-fA-F]{2}", part) for part in parts)
    needle = b"".join(
        bytes([int(part[2:], 16)]) if re.fullmatch(r"\\x[0-9a-fA-F]{2}", part)
        else part.encode("utf-8") for part in parts
    )
    return needle, has_hex


def search_match_spans(raw: bytes, needle: bytes, exact_bytes: bool) -> tuple[tuple[int, int], ...]:
    """Map matching source-byte positions to the rendered text positions."""
    haystack = raw if exact_bytes else raw.lower()
    target = needle if exact_bytes else needle.lower()
    starts, ends = [], []
    column = 0
    for char in raw.decode("utf-8", errors="surrogateescape"):
        byte_count = len(char.encode("utf-8", errors="surrogateescape"))
        display_width = 4 if "\udc80" <= char <= "\udcff" else 1
        starts.extend([column] * byte_count)
        ends.extend([column + display_width] * byte_count)
        column += display_width
    spans = []
    start = 0
    while (position := haystack.find(target, start)) >= 0:
        spans.append((starts[position], ends[position + len(needle) - 1]))
        start = position + len(needle)
    return tuple(spans)


def iter_search_lines(path: Path):
    """Yield source line numbers and raw bytes; preserve non-UTF8 bytes for hex search."""
    if readers.should_try_journalctl(path):
        with closing(readers.run_journalctl_export(path)) as lines:
            for line_number, line in enumerate(lines, 1):
                yield line_number, line.encode("utf-8")
    else:
        if readers.is_probably_binary_file(path):
            return
        with path.open("rb") as stream:
            for line_number, line in enumerate(stream, 1):
                yield line_number, line.rstrip(b"\r\n")



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

    def _prompt_search(self, screen, *, all_lines: bool = False) -> None:
        height, width = screen.getmaxyx()
        if height < 7 or width < 45:
            self.status = "Terminal too small for search"
            return
        size = min(74, width - 4)
        popup = curses.newwin(5, size, (height - 5) // 2, (width - size) // 2)
        popup.box()
        label = "Search ALL log lines" if all_lines else "Search current attack time window"
        self._write(popup, 1, 2, label, size - 4)
        self._write(popup, 2, 2, r"Text or bytes (\xef); Enter to search", size - 4)
        popup.refresh()
        curses.echo()
        try:
            curses.curs_set(1)
            query = popup.getstr(3, 2, min(256, size - 4)).decode("utf-8").strip()
        finally:
            curses.noecho()
            curses.curs_set(0)
        if not query or query.startswith("\x1b"):
            return
        try:
            self.search(query, all_lines=all_lines)
        except ValueError as exc:
            self.status = str(exc)

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

    def _prompt_window(self, screen) -> None:
        height, width = screen.getmaxyx()
        if height < 9 or width < 45:
            self.status = "Terminal too small for time-window input"
            return
        popup_width = min(58, width - 4)
        popup = curses.newwin(7, popup_width, (height - 7) // 2, (width - popup_width) // 2)
        popup.box()
        self._write(popup, 1, 2, "Window relative to selected attack (seconds)", popup_width - 4)
        self._write(popup, 2, 2, f"Before [{self.before:g}]:", popup_width - 4)
        self._write(popup, 4, 2, f"After  [{self.after:g}]:", popup_width - 4)
        popup.refresh()
        curses.echo()
        try:
            curses.curs_set(1)
            before_text = popup.getstr(3, 2, 24).decode("utf-8").strip()
            after_text = popup.getstr(5, 2, 24).decode("utf-8").strip()
        finally:
            curses.noecho()
            curses.curs_set(0)
        try:
            self.set_window(float(before_text) if before_text else self.before,
                            float(after_text) if after_text else self.after)
            self.status = f"Window: -{self.before:g}s / +{self.after:g}s"
        except ValueError:
            self.status = "Enter two non-negative numbers of seconds"

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
                output.extend(text for _line, text in sorted(by_file[filename]))
            output.append("")

        self.out_dir.mkdir(parents=True, exist_ok=True)
        if not self._saved and self.output_path.exists():
            raise FileExistsError(self.output_path)
        temporary = self.output_path.with_suffix(".tmp")
        with temporary.open("x", encoding="utf-8") as fh:
            fh.write("\n".join(output) + ("\n" if output else ""))
        temporary.replace(self.output_path)
        self._saved = True
        unresolved = sum(len(keys) for by_line in missing.values() for keys in by_line.values())
        self.status = f"Saved {len(self.selected)} lines: {self.output_path.name}"
        if unresolved:
            self.status += f" ({unresolved} source lines unavailable; used previews)"
        return self.output_path

    def handle_key(self, key: int, screen=None) -> bool:
        if key == ord("q"):
            return False
        if key == 27:
            if self.search_results is None:
                return False
            self.clear_search()
            self.status = "Returned to current attack time window"
        elif key == ord("s"):
            self.save()
        elif key == ord("a"):
            self.toggle_auto_marks()
        elif key == 6 and screen is not None:
            self._prompt_search(screen)
        elif key in (ord("F"), SEARCH_ALL_KEY) and screen is not None:
            self._prompt_search(screen, all_lines=True)
        elif key == 9:
            panes = ("attacks", "files", "lines")
            self.focus = panes[(panes.index(self.focus) + 1) % 3]
        elif key in (curses.KEY_LEFT, curses.KEY_RIGHT):
            panes = ("attacks", "files", "lines")
            delta = -1 if key == curses.KEY_LEFT else 1
            self.focus = panes[max(0, min(2, panes.index(self.focus) + delta))]
        elif key in (10, 13, curses.KEY_ENTER):
            if self.focus == "attacks":
                self.activate_attack(screen)
            elif self.focus == "files":
                self.focus = "lines"
        elif key in (ord("n"), ord("p")):
            self.jump_match(1 if key == ord("n") else -1)
        elif key in (ord("]"), ord("[")) and self.attacks:
            delta = 1 if key == ord("]") else -1
            self.attack_index = (self.attack_index + delta) % len(self.attacks)
            self.focus = "attacks"
            self.activate_attack()
        elif key in (ord("+"), ord("=")):
            self.change_window(10)
        elif key in (ord("-"), ord("_")):
            self.change_window(-10)
        elif key == ord("t") and screen is not None:
            self._prompt_window(screen)
        elif key == ord("c"):
            self.heatmap = not self.heatmap
        elif key in (ord("h"), ord("H")):
            self.horizontal = max(0, self.horizontal - 20)
        elif key in (ord("l"), ord("L")):
            self.horizontal += 20
        elif key in (curses.KEY_UP, ord("k"), curses.KEY_DOWN, ord("j"),
                     curses.KEY_NPAGE, curses.KEY_PPAGE, curses.KEY_HOME, curses.KEY_END):
            if self.focus == "attacks":
                total, selected = len(self.attacks), self.attack_index
            elif self.focus == "files":
                total, selected = len(self.visible_files), self.file_index
            else:
                self._load_lines()
                total, selected = len(self.lines), self.line_index
            if not total:
                return True
            if key == curses.KEY_HOME:
                selected = 0
            elif key == curses.KEY_END:
                selected = total - 1
            else:
                delta = (-10 if key == curses.KEY_PPAGE else 10 if key == curses.KEY_NPAGE
                         else -1 if key in (curses.KEY_UP, ord("k")) else 1)
                selected = max(0, min(total - 1, selected + delta))
            if self.focus == "attacks":
                if selected != self.attack_index:
                    self.attack_index = selected
                    self.activate_attack()
            elif self.focus == "files":
                self.file_index = selected
                self._view_key = None
                self._preferred_line = None
            else:
                self.line_index = selected
        elif key == ord(" ") and self.focus == "lines":
            self.toggle_selected()
        return True

    @staticmethod
    def _scroll(index: int, top: int, size: int) -> int:
        if index < top:
            return index
        return max(top, index - size + 1)

    @staticmethod
    def _write(win, y: int, x: int, text: str, width: int, attr: int = 0) -> None:
        try:
            if width > 0:
                win.addnstr(y, x, sanitize_preview_text(text), width, attr)
        except curses.error:
            pass

    def _draw(self, screen) -> None:
        height, width = screen.getmaxyx()
        screen.erase()
        if height < 12 or width < 70:
            self._write(screen, 0, 0, "Terminal too small (minimum 70x12)", width - 1)
            screen.refresh()
            return
        if self.active_attack_index is not None:
            self._load_lines()
        attack_width = min(31, max(24, width // 5 + 5))
        file_width = min(38, max(22, width // 4))
        log_width = width - attack_width - file_width
        body_height = height - 3
        attacks_win = screen.derwin(body_height, attack_width, 0, 0)
        files_win = screen.derwin(body_height, file_width, 0, attack_width)
        logs_win = screen.derwin(body_height, log_width, 0, attack_width + file_width)
        for win in (attacks_win, files_win, logs_win):
            win.box()
        self._write(attacks_win, 0, 2, f" Attacks ({len(self.attacks)}) ", attack_width - 4)
        self._write(files_win, 0, 2, f" Files ({len(self.visible_files)}) ", file_width - 4)
        self._write(logs_win, 0, 2, f" {'Search matches' if self.search_results is not None else 'Log lines'} ({len(self.lines)}) ", log_width - 4)

        attack_rows = body_height - 2
        self.attack_top = self._scroll(self.attack_index, self.attack_top, attack_rows)
        for i in range(self.attack_top, min(len(self.attacks), self.attack_top + attack_rows)):
            attack = self.attacks[i]
            active = ">" if i == self.active_attack_index else " "
            matched = attack.attack_id in self.auto_attacks
            text = f"{active}{i + 1:>3} {'A ' if matched else '  '}{attack.cmd}"
            attr = self.auto_attr if matched else 0
            if i == self.attack_index:
                attr |= curses.A_REVERSE
                if self.focus == "attacks":
                    attr |= curses.A_UNDERLINE
            self._write(attacks_win, i - self.attack_top + 1, 1, text, attack_width - 2, attr)

        self.file_top = self._scroll(self.file_index, self.file_top, attack_rows)
        for i in range(self.file_top, min(len(self.visible_files), self.file_top + attack_rows)):
            path = self.visible_files[i]
            count = self.auto_counts[(self.attacks[self.active_attack_index].attack_id, str(path))]
            name = (f"({count}) " if self.automatic else "") + path.relative_to(self.log_root).as_posix()
            attr = self.auto_attr if count else 0
            if i == self.file_index:
                attr |= curses.A_REVERSE
                if self.focus == "files":
                    attr |= curses.A_UNDERLINE
            self._write(files_win, i - self.file_top + 1, 1, name, file_width - 2, attr)
        if self.active_attack_index is None:
            self._write(logs_win, 1, 1, "Loading attack logs...", log_width - 2)
        else:
            attack = self.attacks[self.active_attack_index]
            cmd, description = attack_details(attack)
            self._write(logs_win, 1, 1, f"Time: {attack.timestamp.isoformat()}", log_width - 2)
            self._write(logs_win, 2, 1, f"Command: {cmd}", log_width - 2)
            self._write(logs_win, 3, 1, f"Description: {description}", log_width - 2)
            self._write(logs_win, 4, 1, "-" * (log_width - 2), log_width - 2)
            rows = max(1, body_height - 6)
            self.line_top = self._scroll(self.line_index, self.line_top, rows)
            closest, farthest = self.distance_range
            for i in range(self.line_top, min(len(self.lines), self.line_top + rows)):
                line = self.lines[i]
                key = self._key(line)
                marker = ("*" if key in self.selected else " ") + ("A" if key in self.automatic else " ")
                text = f"{marker} {line.line_number:>6} {line.text}"
                attr = self.auto_attr if key in self.automatic else 0
                if key in self.selected:
                    attr |= curses.A_BOLD
                if self.focus == "lines" and i == self.line_index:
                    attr |= curses.A_REVERSE
                prefix = text[:10]
                detail = text[10 + self.horizontal:]
                available = log_width - 2
                y = i - self.line_top + 5
                self._write(logs_win, y, 1, prefix + detail, available, attr)
                if self.heatmap and self.heat_attrs and line.timestamp is not None and line.timestamp_span is not None:
                    distance = abs((line.timestamp - attack.timestamp).total_seconds())
                    ratio = (distance - closest) / (farthest - closest) if farthest > closest else 0.0
                    color = self.heat_attrs[min(len(self.heat_attrs) - 1,
                                                int(ratio * (len(self.heat_attrs) - 1) + 0.5))]
                    first = max(line.timestamp_span[0], self.horizontal)
                    last = min(line.timestamp_span[1], self.horizontal + max(0, available - 10))
                    if first < last:
                        if self.focus == "lines" and i == self.line_index:
                            color |= curses.A_REVERSE
                        self._write(logs_win, y, 11 + first - self.horizontal,
                                    line.text[first:last], last - first, color)
                for begin, end in line.search_spans:
                    first = max(begin, self.horizontal)
                    last = min(end, self.horizontal + max(0, available - 10))
                    if first < last:
                        self._write(logs_win, y, 11 + first - self.horizontal,
                                    line.text[first:last], last - first, self.search_attr)
            if not self.visible_files:
                self._write(logs_win, 5, 1, "No timestamped logfiles in this window", log_width - 2)

        footer = f"{len(self.selected)} marked | {self.status or 'A/cyan: correlator match'}"
        self._write(screen, height - 3, 0, footer, width - 1, curses.A_REVERSE)
        self._write(screen, height - 2, 0,
                    "space: mark line | s: save marked lines to file | a: toggle auto | q: quit",
                    width - 1, curses.A_REVERSE)
        self._write(screen, height - 1, 0,
                    "Ctrl+F: search current time window | F/Ctrl+Shift+F: all | n/p: matches",
                    width - 1, curses.A_REVERSE)
        screen.refresh()

    @staticmethod
    def _read_key(screen) -> int:
        """Recognize modified Ctrl+Shift+F when a terminal sends distinct CSI keys."""
        key = screen.getch()
        if key != 27 or not hasattr(screen, "timeout"):
            return key
        screen.timeout(35)
        sequence = []
        try:
            for _ in range(16):
                value = screen.getch()
                if value < 0:
                    break
                if value > 255:
                    curses.ungetch(value)
                    break
                sequence.append(value)
                if value in (ord("u"), ord("~")):
                    break
        finally:
            screen.timeout(-1)
        if bytes(sequence) in (b"[102;6u", b"[70;6u", b"[27;6;102~", b"[27;6;70~"):
            return SEARCH_ALL_KEY
        for value in reversed(sequence):
            curses.ungetch(value)
        return key

    def _main(self, screen) -> None:
        screen.keypad(True)
        curses.curs_set(0)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            self.auto_attr = curses.color_pair(1) | curses.A_BOLD
            palette = ([196, 202, 208, 214, 220, 226, 190, 154, 118, 82, 46,
                        47, 48, 49, 50, 51, 45, 39, 33, 27, 21]
                       if curses.COLORS >= 256 and curses.COLOR_PAIRS >= 23
                       else [curses.COLOR_RED, curses.COLOR_YELLOW, curses.COLOR_GREEN,
                             curses.COLOR_CYAN, curses.COLOR_BLUE])
            for index, color in enumerate(palette, 2):
                if index >= curses.COLOR_PAIRS:
                    break
                curses.init_pair(index, color, -1)
                self.heat_attrs.append(curses.color_pair(index) | curses.A_BOLD)
            search_pair = len(self.heat_attrs) + 2
            if search_pair < curses.COLOR_PAIRS:
                curses.init_pair(search_pair, curses.COLOR_BLACK, curses.COLOR_YELLOW)
                self.search_attr = curses.color_pair(search_pair) | curses.A_BOLD
        self.activate_attack(screen)
        while True:
            self._draw(screen)
            if not self.handle_key(self._read_key(screen), screen):
                break

    def run(self) -> Path:
        try:
            curses.wrapper(self._main)
        finally:
            self.save()
        return self.output_path
