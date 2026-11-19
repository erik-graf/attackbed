"""Curses layout, key handling and dialogs for manual evidence review."""

from __future__ import annotations

import curses
import unicodedata

from attacklog_correlator.manual_logs import attack_details
from attacklog_correlator.tui import sanitize_preview_text


SEARCH_ALL_KEY = 0x110000


def char_columns(char: str, column: int) -> int:
    if char == "\t":
        return 8 - column % 8
    if unicodedata.combining(char) or unicodedata.category(char) == "Cf":
        return 0
    return 2 if unicodedata.east_asian_width(char) in "WF" else 1


def highlight_segment(
    text: str, begin: int, end: int, scroll: int, available: int,
) -> tuple[int, str] | None:
    """Return the displayed column offset and clipped substring for a highlight."""
    first = max(begin, scroll)
    if first >= end:
        return None
    column = 11
    for char in text[scroll:first]:
        column += char_columns(char, column)
    offset = column - 11
    if offset >= available:
        return None
    start_offset = offset
    shown = []
    for char in text[first:end]:
        width = char_columns(char, column)
        if offset + width > available:
            break
        shown.append(char)
        offset += width
        column += width
    return (start_offset, "".join(shown)) if shown else None


def prompt_search(browser, screen, *, all_lines: bool = False) -> None:
    height, width = screen.getmaxyx()
    if height < 7 or width < 45:
        browser.status = "Terminal too small for search"
        return
    size = min(74, width - 4)
    popup = curses.newwin(5, size, (height - 5) // 2, (width - size) // 2)
    popup.box()
    label = "Search ALL log lines" if all_lines else "Search current attack time window"
    browser._write(popup, 1, 2, label, size - 4)
    browser._write(popup, 2, 2, r"Text or bytes (\xef); Enter to search", size - 4)
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
        browser.search(query, all_lines=all_lines)
    except ValueError as exc:
        browser.status = str(exc)

def prompt_window(browser, screen) -> None:
    height, width = screen.getmaxyx()
    if height < 9 or width < 45:
        browser.status = "Terminal too small for time-window input"
        return
    popup_width = min(58, width - 4)
    popup = curses.newwin(7, popup_width, (height - 7) // 2, (width - popup_width) // 2)
    popup.box()
    browser._write(popup, 1, 2, "Window relative to selected attack (seconds)", popup_width - 4)
    browser._write(popup, 2, 2, f"Before [{browser.before:g}]:", popup_width - 4)
    browser._write(popup, 4, 2, f"After  [{browser.after:g}]:", popup_width - 4)
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
        browser.set_window(float(before_text) if before_text else browser.before,
                        float(after_text) if after_text else browser.after)
        browser.status = f"Window: -{browser.before:g}s / +{browser.after:g}s"
    except ValueError:
        browser.status = "Enter two non-negative numbers of seconds"

def handle_key(browser, key: int, screen=None) -> bool:
    if key == ord("q"):
        return False
    if key == 27:
        if browser.search_results is None:
            return False
        browser.clear_search()
        browser.status = "Returned to current attack time window"
    elif key == ord("s"):
        browser.save()
    elif key == ord("a"):
        browser.toggle_auto_marks()
    elif key == 6 and screen is not None:
        browser._prompt_search(screen)
    elif key in (ord("F"), SEARCH_ALL_KEY) and screen is not None:
        browser._prompt_search(screen, all_lines=True)
    elif key == 9:
        panes = ("attacks", "files", "lines")
        browser.focus = panes[(panes.index(browser.focus) + 1) % 3]
    elif key in (curses.KEY_LEFT, curses.KEY_RIGHT):
        panes = ("attacks", "files", "lines")
        delta = -1 if key == curses.KEY_LEFT else 1
        browser.focus = panes[max(0, min(2, panes.index(browser.focus) + delta))]
    elif key in (10, 13, curses.KEY_ENTER):
        if browser.focus == "attacks":
            browser.activate_attack(screen)
        elif browser.focus == "files":
            browser.focus = "lines"
    elif key in (ord("n"), ord("p")):
        browser.jump_match(1 if key == ord("n") else -1)
    elif key in (ord("]"), ord("[")) and browser.attacks:
        delta = 1 if key == ord("]") else -1
        browser.attack_index = (browser.attack_index + delta) % len(browser.attacks)
        browser.focus = "attacks"
        browser.activate_attack()
    elif key in (ord("+"), ord("=")):
        browser.change_window(10)
    elif key in (ord("-"), ord("_")):
        browser.change_window(-10)
    elif key == ord("t") and screen is not None:
        browser._prompt_window(screen)
    elif key == ord("c"):
        browser.heatmap = not browser.heatmap
    elif key in (ord("h"), ord("H")):
        browser.horizontal = max(0, browser.horizontal - 20)
    elif key in (ord("l"), ord("L")):
        browser.horizontal += 20
    elif key in (curses.KEY_UP, ord("k"), curses.KEY_DOWN, ord("j"),
                 curses.KEY_NPAGE, curses.KEY_PPAGE, curses.KEY_HOME, curses.KEY_END):
        if browser.focus == "attacks":
            total, selected = len(browser.attacks), browser.attack_index
        elif browser.focus == "files":
            total, selected = len(browser.visible_files), browser.file_index
        else:
            browser._load_lines()
            total, selected = len(browser.lines), browser.line_index
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
        if browser.focus == "attacks":
            if selected != browser.attack_index:
                browser.attack_index = selected
                browser.activate_attack()
        elif browser.focus == "files":
            browser.file_index = selected
            browser._view_key = None
            browser._preferred_line = None
        else:
            browser.line_index = selected
    elif key == ord(" ") and browser.focus == "lines":
        browser.toggle_selected()
    return True

def scroll(index: int, top: int, size: int) -> int:
    if index < top:
        return index
    return max(top, index - size + 1)

def write(win, y: int, x: int, text: str, width: int, attr: int = 0) -> None:
    try:
        if width > 0:
            win.addnstr(y, x, sanitize_preview_text(text), width, attr)
    except curses.error:
        pass

def draw(browser, screen) -> None:
    height, width = screen.getmaxyx()
    screen.erase()
    if height < 12 or width < 70:
        browser._write(screen, 0, 0, "Terminal too small (minimum 70x12)", width - 1)
        screen.refresh()
        return
    if browser.active_attack_index is not None:
        browser._load_lines()
    attack_width = min(31, max(24, width // 5 + 5))
    file_width = min(38, max(22, width // 4))
    log_width = width - attack_width - file_width
    body_height = height - 3
    attacks_win = screen.derwin(body_height, attack_width, 0, 0)
    files_win = screen.derwin(body_height, file_width, 0, attack_width)
    logs_win = screen.derwin(body_height, log_width, 0, attack_width + file_width)
    for win in (attacks_win, files_win, logs_win):
        win.box()
    browser._write(attacks_win, 0, 2, f" Attacks ({len(browser.attacks)}) ", attack_width - 4)
    browser._write(files_win, 0, 2, f" Files ({len(browser.visible_files)}) ", file_width - 4)
    browser._write(logs_win, 0, 2, f" {'Search matches' if browser.search_results is not None else 'Log lines'} ({len(browser.lines)}) ", log_width - 4)

    attack_rows = body_height - 2
    browser.attack_top = browser._scroll(browser.attack_index, browser.attack_top, attack_rows)
    for i in range(browser.attack_top, min(len(browser.attacks), browser.attack_top + attack_rows)):
        attack = browser.attacks[i]
        active = ">" if i == browser.active_attack_index else " "
        matched = attack.attack_id in browser.auto_attacks
        text = f"{active}{i + 1:>3} {'A ' if matched else '  '}{attack.cmd}"
        attr = browser.auto_attr if matched else 0
        if i == browser.attack_index:
            attr |= curses.A_REVERSE
            if browser.focus == "attacks":
                attr |= curses.A_UNDERLINE
        browser._write(attacks_win, i - browser.attack_top + 1, 1, text, attack_width - 2, attr)

    browser.file_top = browser._scroll(browser.file_index, browser.file_top, attack_rows)
    for i in range(browser.file_top, min(len(browser.visible_files), browser.file_top + attack_rows)):
        path = browser.visible_files[i]
        count = browser.auto_counts[(browser.attacks[browser.active_attack_index].attack_id, str(path))]
        name = (f"({count}) " if browser.automatic else "") + path.relative_to(browser.log_root).as_posix()
        attr = browser.auto_attr if count else 0
        if i == browser.file_index:
            attr |= curses.A_REVERSE
            if browser.focus == "files":
                attr |= curses.A_UNDERLINE
        browser._write(files_win, i - browser.file_top + 1, 1, name, file_width - 2, attr)
    if browser.active_attack_index is None:
        browser._write(logs_win, 1, 1, "Loading attack logs...", log_width - 2)
    else:
        attack = browser.attacks[browser.active_attack_index]
        cmd, description = attack_details(attack)
        browser._write(logs_win, 1, 1, f"Time: {attack.timestamp.isoformat()}", log_width - 2)
        browser._write(logs_win, 2, 1, f"Command: {cmd}", log_width - 2)
        browser._write(logs_win, 3, 1, f"Description: {description}", log_width - 2)
        browser._write(logs_win, 4, 1, "-" * (log_width - 2), log_width - 2)
        rows = max(1, body_height - 6)
        browser.line_top = browser._scroll(browser.line_index, browser.line_top, rows)
        closest, farthest = browser.distance_range
        for i in range(browser.line_top, min(len(browser.lines), browser.line_top + rows)):
            line = browser.lines[i]
            key = browser._key(line)
            marker = ("*" if key in browser.selected else " ") + ("A" if key in browser.automatic else " ")
            text = f"{marker} {line.line_number:>6} {line.text}"
            attr = browser.auto_attr if key in browser.automatic else 0
            if key in browser.selected:
                attr |= curses.A_BOLD
            if browser.focus == "lines" and i == browser.line_index:
                attr |= curses.A_REVERSE
            prefix = text[:10]
            detail = text[10 + browser.horizontal:]
            available = log_width - 2
            y = i - browser.line_top + 5
            browser._write(logs_win, y, 1, prefix + detail, available, attr)
            if browser.heatmap and browser.heat_attrs and line.timestamp is not None and line.timestamp_span is not None:
                distance = abs((line.timestamp - attack.timestamp).total_seconds())
                ratio = (distance - closest) / (farthest - closest) if farthest > closest else 0.0
                color = browser.heat_attrs[min(len(browser.heat_attrs) - 1,
                                            int(ratio * (len(browser.heat_attrs) - 1) + 0.5))]
                segment = highlight_segment(
                    line.text, *line.timestamp_span, browser.horizontal, max(0, available - 10)
                )
                if segment:
                    offset, value = segment
                    if browser.focus == "lines" and i == browser.line_index:
                        color |= curses.A_REVERSE
                    browser._write(logs_win, y, 11 + offset, value, len(value), color)
            for begin, end in line.search_spans:
                segment = highlight_segment(
                    line.text, begin, end, browser.horizontal, max(0, available - 10)
                )
                if segment:
                    offset, value = segment
                    browser._write(logs_win, y, 11 + offset, value, len(value), browser.search_attr)
        if not browser.visible_files:
            browser._write(logs_win, 5, 1, "No timestamped logfiles in this window", log_width - 2)

    footer = f"{len(browser.selected)} marked | {browser.status or 'A/cyan: correlator match'}"
    browser._write(screen, height - 3, 0, footer, width - 1, curses.A_REVERSE)
    browser._write(screen, height - 2, 0,
                "space: mark line | s: save marked lines to file | a: toggle auto | q: quit",
                width - 1, curses.A_REVERSE)
    browser._write(screen, height - 1, 0,
                "Ctrl+F: search current time window | F/Ctrl+Shift+F: all | n/p: matches",
                width - 1, curses.A_REVERSE)
    screen.refresh()

def read_key(screen) -> int:
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

def main(browser, screen) -> None:
    screen.keypad(True)
    curses.curs_set(0)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        browser.auto_attr = curses.color_pair(1) | curses.A_BOLD
        palette = ([196, 202, 208, 214, 220, 226, 190, 154, 118, 82, 46,
                    47, 48, 49, 50, 51, 45, 39, 33, 27, 21]
                   if curses.COLORS >= 256 and curses.COLOR_PAIRS >= 23
                   else [curses.COLOR_RED, curses.COLOR_YELLOW, curses.COLOR_GREEN,
                         curses.COLOR_CYAN, curses.COLOR_BLUE])
        for index, color in enumerate(palette, 2):
            if index >= curses.COLOR_PAIRS:
                break
            curses.init_pair(index, color, -1)
            browser.heat_attrs.append(curses.color_pair(index) | curses.A_BOLD)
        search_pair = len(browser.heat_attrs) + 2
        if search_pair < curses.COLOR_PAIRS:
            curses.init_pair(search_pair, curses.COLOR_BLACK, curses.COLOR_YELLOW)
            browser.search_attr = curses.color_pair(search_pair) | curses.A_BOLD
    browser.activate_attack(screen)
    while True:
        browser._draw(screen)
        if not browser.handle_key(browser._read_key(screen), screen):
            break
