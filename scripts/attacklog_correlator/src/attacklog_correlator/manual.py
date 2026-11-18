"""Manual evidence review over the correlator's normalized log timestamps."""

from __future__ import annotations

import curses
import datetime as dt
from collections import defaultdict
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


@dataclass(frozen=True)
class ManualLine:
    line_number: int
    text: str


def lines_in_window(
    path: Path, log_root: Path, resolver: HostResolver, default_year: int,
    attack_time: dt.datetime, before: float, after: float,
    log_type: Optional[LogTypeRule] = None,
) -> list[ManualLine]:
    """Read one file on demand; include continuation lines after an in-window timestamp."""
    start = attack_time - dt.timedelta(seconds=before)
    end = attack_time + dt.timedelta(seconds=after)
    path_host = resolver.host_from_path(path, log_root) or "unknown-host"
    visible: list[ManualLine] = []
    within_window = False
    with closing(readers.iter_log_records(path, default_year, log_type=log_type)) as records:
        for record in records:
            if record.parsed_timestamp is not None:
                host = resolver.canonicalize_host(guess_host_from_line(record.raw_line) or path_host)
                timestamp = normalize_event_time(record.parsed_timestamp, host, resolver)
                within_window = start <= timestamp <= end
            if within_window:
                visible.append(ManualLine(record.line_number, record.raw_line.rstrip("\r\n")))
    return visible


class ManualBrowser:
    """Two-pane curses browser; selections are scoped to an attack and source line."""

    def __init__(
        self, attacks: list[Attack], files: list[Path], correlations: list[Correlation],
        events: list[LogEvent], log_root: Path, resolver: HostResolver, default_year: int,
        before: float, after: float, out_dir: Path,
        log_types: Optional[list[LogTypeRule]] = None,
    ) -> None:
        self.attacks = attacks
        self.files = files
        self.log_root = log_root
        self.resolver = resolver
        self.default_year = default_year
        self.before = before
        self.after = after
        self.log_types = log_types
        self.attack_index = 0
        self.file_index = 0
        self.line_index = 0
        self.file_top = 0
        self.line_top = 0
        self.horizontal = 0
        self.focus = "lines"
        self.status = ""
        self.auto_attr = curses.A_BOLD
        self._view_key: Optional[tuple] = None
        self.lines: list[ManualLine] = []

        # A source line can correlate with several attack steps. Keep those selections independent.
        self.automatic = {(c.attack_id, c.event_file, c.event_line) for c in correlations}
        self.selected = set(self.automatic)
        source_text = {(e.file_path, e.line_number): e.raw_line for e in events}
        self.text_by_key = {
            (c.attack_id, c.event_file, c.event_line): source_text.get((c.event_file, c.event_line), c.event_message)
            for c in correlations
        }
        self.out_dir = out_dir
        self.output_path = out_dir / f"manual_selection_{dt.datetime.now(UTC):%Y%m%dT%H%M%S%fZ}.txt"
        self._saved = False
        self._choose_auto_file()

    def _choose_auto_file(self) -> None:
        if not self.attacks or not self.files:
            return
        attack_id = self.attacks[self.attack_index].attack_id
        preferred = {path for aid, path, _line in self.automatic if aid == attack_id}
        self.file_index = next((i for i, path in enumerate(self.files) if str(path) in preferred), 0)
        self.file_top = 0
        self.line_index = 0
        self.line_top = 0
        self._view_key = None

    def _key(self, line: ManualLine) -> tuple[str, str, int]:
        return (self.attacks[self.attack_index].attack_id, str(self.files[self.file_index]), line.line_number)

    def _load_lines(self) -> None:
        if not self.files or not self.attacks:
            self.lines = []
            return
        key = (self.attack_index, self.file_index, self.before, self.after)
        if key == self._view_key:
            return
        self._view_key = key
        path = self.files[self.file_index]
        log_type = matching_log_type(path, self.log_types) if self.log_types is not None else None
        try:
            self.lines = lines_in_window(path, self.log_root, self.resolver, self.default_year,
                                         self.attacks[self.attack_index].timestamp,
                                         self.before, self.after, log_type)
            self.status = ""
        except (OSError, RuntimeError) as exc:
            self.lines = []
            self.status = f"Cannot read {path.name}: {exc}"
        self.line_index = next((i for i, line in enumerate(self.lines)
                                if self._key(line) in self.automatic), 0)
        self.line_top = 0

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

    def change_window(self, seconds: float) -> None:
        self.before = max(0.0, self.before + seconds)
        self.after = max(0.0, self.after + seconds)
        self._view_key = None

    def save(self) -> Path:
        """Write raw selected lines, grouped by attack and source file, to one text file."""
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
            output.append(f"# {attack.raw_line.rstrip()}")
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
        self.status = f"Saved {len(self.selected)} lines: {self.output_path.name}"
        return self.output_path

    def handle_key(self, key: int) -> bool:
        """Return False to exit (saving selections), True to keep browsing."""
        if key in (ord("q"), 27):
            return False
        if key in (ord("s"),):
            self.save()
        elif key in (curses.KEY_LEFT, curses.KEY_RIGHT, 9):
            self.focus = ("files" if key == curses.KEY_LEFT else "lines"
                          if key == curses.KEY_RIGHT else ("files" if self.focus == "lines" else "lines"))
        elif key in (ord("n"), ord("]"), ord("p"), ord("[")) and self.attacks:
            delta = 1 if key in (ord("n"), ord("]")) else -1
            self.attack_index = (self.attack_index + delta) % len(self.attacks)
            self._choose_auto_file()
        elif key in (ord("+"), ord("=")):
            self.change_window(30.0)
        elif key in (ord("-"), ord("_")):
            self.change_window(-30.0)
        elif key in (ord("h"), ord("H")):
            self.horizontal = max(0, self.horizontal - 20)
        elif key in (ord("l"), ord("L")):
            self.horizontal += 20
        elif key in (curses.KEY_UP, ord("k"), curses.KEY_DOWN, ord("j"), curses.KEY_NPAGE, curses.KEY_PPAGE):
            delta = -1 if key in (curses.KEY_UP, ord("k")) else 1
            if key in (curses.KEY_NPAGE, curses.KEY_PPAGE):
                delta = 10 if key == curses.KEY_NPAGE else -10
            if self.focus == "files":
                self.file_index = max(0, min(len(self.files) - 1, self.file_index + delta)) if self.files else 0
            else:
                self._load_lines()
                self.line_index = max(0, min(len(self.lines) - 1, self.line_index + delta)) if self.lines else 0
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
        if height < 12 or width < 55:
            self._write(screen, 0, 0, "Terminal too small (minimum 55x12)", width - 1)
            screen.refresh()
            return
        self._load_lines()
        attack = self.attacks[self.attack_index] if self.attacks else None
        title = (f"Attack {self.attack_index + 1}/{len(self.attacks)}  "
                 f"{attack.timestamp.isoformat()}  -{self.before:g}s/+{self.after:g}s"
                 if attack else "No AttackMate steps found")
        self._write(screen, 0, 0, title, width - 1, curses.A_BOLD)
        raw = attack.raw_line if attack else ""
        self._write(screen, 1, 0, raw[:width - 1], width - 1)
        self._write(screen, 2, 0, raw[width - 1:2 * (width - 1)], width - 1)
        self._write(screen, 3, 0, "-" * (width - 1), width - 1)

        left_width = min(38, max(20, width // 4))
        pane_height = height - 5
        left = screen.derwin(pane_height, left_width, 4, 0)
        right = screen.derwin(pane_height, width - left_width, 4, left_width)
        left.box()
        right.box()
        self._write(left, 0, 2, f" Files ({len(self.files)}) " + ("<" if self.focus == "files" else ""), left_width - 4)
        relative_path = self.files[self.file_index].relative_to(self.log_root).as_posix() if self.files else ""
        self._write(right, 0, 2, f" {relative_path} ({len(self.lines)} lines) " + ("<" if self.focus == "lines" else ""), width - left_width - 4)

        count = pane_height - 2
        self.file_top = self._scroll(self.file_index, self.file_top, count)
        for i in range(self.file_top, min(len(self.files), self.file_top + count)):
            rel = self.files[i].relative_to(self.log_root).as_posix()
            attr = curses.A_REVERSE if i == self.file_index and self.focus == "files" else 0
            self._write(left, i - self.file_top + 1, 1, rel, left_width - 2, attr)
        if not self.files:
            self._write(left, 1, 1, "No logfiles", left_width - 2)
        self.line_top = self._scroll(self.line_index, self.line_top, count)
        for i in range(self.line_top, min(len(self.lines), self.line_top + count)):
            row = self.lines[i]
            key = self._key(row)
            auto = key in self.automatic
            selected = key in self.selected
            marker = ("*" if selected else " ") + ("A" if auto else " ")
            text = f"{marker} {row.line_number:>6} {row.text}"
            attr = self.auto_attr if auto else 0
            if selected:
                attr |= curses.A_BOLD
            if self.focus == "lines" and i == self.line_index:
                attr |= curses.A_REVERSE
            prefix = text[:10]
            detail = text[10 + self.horizontal:]
            self._write(right, i - self.line_top + 1, 1, prefix + detail, width - left_width - 2, attr)
        if not self.lines:
            self._write(right, 1, 1, self.status or "No timestamped lines in this window", width - left_width - 2)
        footer = self.status or (f"{len(self.selected)} selected | Tab panes  arrows move  SPACE toggle  +/- 30s"
                                 "  [ ] attacks  h/l scroll  s save  q save+quit  A=auto")
        self._write(screen, height - 1, 0, footer, width - 1, curses.A_REVERSE)
        screen.refresh()

    def _main(self, screen) -> None:
        screen.keypad(True)
        curses.curs_set(0)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            self.auto_attr = curses.color_pair(1) | curses.A_BOLD
        while True:
            self._draw(screen)
            if not self.handle_key(screen.getch()):
                break

    def run(self) -> Path:
        try:
            curses.wrapper(self._main)
        finally:
            self.save()
        return self.output_path
