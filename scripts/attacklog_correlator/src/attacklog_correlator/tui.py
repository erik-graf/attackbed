"""Curses browser, evidence highlighting and search."""

from __future__ import annotations

import curses
import functools
import json
import pprint as pp
import re
from collections import defaultdict
from pathlib import Path
from typing import Any
from typing import Optional

from attacklog_correlator.correlation import lexical_score_from_breakdown
from attacklog_correlator.models import Attack, Correlation
from attacklog_correlator.tokens import HOST_TOKEN_RE, extract_ips, sanitize_host_name


def sanitize_preview_text(value: str) -> str:
    value = str(value).replace(chr(0), "")
    cleaned = []
    for ch in value:
        code = ord(ch)
        if ch == "\t" or code >= 32:
            cleaned.append(ch)
        else:
            cleaned.append("?")
    return "".join(cleaned)

@functools.lru_cache(maxsize=256)
def read_context_lines(path: str, line_number: int, radius: int = 3) -> list[str]:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return [f"[missing file] {path}"]
    start = max(1, line_number - radius)
    end = line_number + radius
    out: list[str] = []

    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for idx, line in enumerate(fh, start=1):
                if idx < start:
                    continue
                if idx > end:
                    break
                prefix = ">" if idx == line_number else " "
                out.append(f"{prefix}{idx:6d} {sanitize_preview_text(line.rstrip())}")
    except Exception as exc:
        out.append(f"[unable to preview] {exc}")
    return out

def _collect_string_values(value: Any) -> list[str]:
    """Return string leaves from parsed attack-log JSON values, not JSON keys.

    This keeps green UI highlighting tied to evidence that actually came from
    an attack-log entry value, such as the command, attack type, metadata values,
    IPs, or target strings.  It intentionally avoids JSON field names like
    ``cmd`` or ``metadata`` because those are schema words, not evidence.
    """
    values: list[str] = []
    if isinstance(value, str):
        values.append(value)
    elif isinstance(value, dict):
        for child in value.values():
            values.extend(_collect_string_values(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(_collect_string_values(child))
    elif isinstance(value, (int, float)):
        values.append(str(value))
    return values

UI_HIGHLIGHT_STOP_TOKENS = {"the", "and", "for", "with", "from", "into", "that", "this", "false", "true", "null"}

def _highlight_tokens_from_attack_value(text: str) -> list[str]:
    """Extract display-highlight tokens from an attack-log value.

    This deliberately does not call extract_tokens(), because extract_tokens()
    removes common command words such as curl/nmap/bash.  Those words are too
    common for scoring, but they are exactly the evidence the UI should mark
    green when they appear in a matched host-log line.
    """
    out: list[str] = []
    for token in HOST_TOKEN_RE.findall(str(text)):
        st = sanitize_host_name(token)
        if len(st) < 3 or st.isdigit() or st in UI_HIGHLIGHT_STOP_TOKENS:
            continue
        if st not in out:
            out.append(st)
    for ip_text in extract_ips(str(text)):
        if ip_text not in out:
            out.append(ip_text)
    return out

def _preview_keywords(corr: Optional[Correlation]) -> list[str]:
    if not corr:
        return []

    # Prefer the exact scoring matches.  This makes the UI line up with the
    # lexical gate: green in host-log context means "this exact attack-log token
    # is why the correlation survived", not merely "this word appeared somewhere
    # in the attack JSON".
    matched_terms = [str(x).strip().lower() for x in getattr(corr, "matched_lexical_terms", []) or [] if str(x).strip()]
    if matched_terms:
        out: list[str] = []
        for term in matched_terms:
            if term not in out:
                out.append(term)
        return out[:80]

    # Backward-compatible fallback for older correlations.json files that do not
    # contain matched_lexical_terms yet.  New correlations should not normally
    # reach this path.
    out: list[str] = []
    raw_attack_line = getattr(corr, "attack_raw_line", "") or ""

    sources: list[str] = []
    try:
        parsed = json.loads(raw_attack_line)
    except Exception:
        parsed = None

    if parsed is not None:
        sources.extend(_collect_string_values(parsed))
    else:
        sources.append(raw_attack_line)

    if getattr(corr, "attack_cmd", ""):
        sources.append(corr.attack_cmd)
    if getattr(corr, "attack_type", ""):
        sources.append(corr.attack_type)

    for source in sources:
        for piece in _highlight_tokens_from_attack_value(source):
            if piece not in out:
                out.append(piece)

    return out[:80]

SEARCH_ENCODING_MODES = ("utf8", "hex", "utf16")

def _compact_hex(value: str) -> str:
    return re.sub(r"[^0-9a-f]", "", value.lower())

def _encoded_search_needles(query: str, mode: str) -> list[str]:
    if not query:
        return []
    if mode == "utf8":
        return [query.lower()]
    if mode == "hex":
        # Accept either a literal hex query like "636d64" or a normal string
        # that should be converted to its UTF-8 byte representation.
        compact = _compact_hex(query)
        needles = []
        if compact and len(compact) % 2 == 0:
            needles.append(compact)
        needles.append(query.encode("utf-8", errors="replace").hex())
        return sorted(set(needles), key=len, reverse=True)
    if mode == "utf16":
        # Include both common byte orders.  This is useful when logs contain
        # command text as a hex dump of UTF-16 data.
        return sorted({
            query.encode("utf-16le", errors="replace").hex(),
            query.encode("utf-16be", errors="replace").hex(),
        }, key=len, reverse=True)
    return [query.lower()]

def _search_matches_line(line: str, query: str, mode: str) -> bool:
    if not query:
        return False
    safe = sanitize_preview_text(line)
    lowered = safe.lower()
    if mode == "utf8":
        return query.lower() in lowered

    compact_line_hex_text = _compact_hex(lowered)
    line_utf8_hex = safe.encode("utf-8", errors="replace").hex()
    for needle in _encoded_search_needles(query, mode):
        if not needle:
            continue
        if needle in compact_line_hex_text or needle in line_utf8_hex:
            return True
    return False

def _search_spans(line: str, query: str, mode: str) -> list[tuple[int, int, str]]:
    if not query:
        return []
    safe = sanitize_preview_text(line)
    lowered = safe.lower()
    spans: list[tuple[int, int, str]] = []

    if mode == "utf8":
        needle = query.lower()
        pos = 0
        while needle:
            idx = lowered.find(needle, pos)
            if idx == -1:
                break
            spans.append((idx, idx + len(needle), "bold"))
            pos = idx + len(needle)
        return spans

    # For encoded searches, there is usually no clean character-position mapping
    # from the encoded byte pattern back to the displayed text.  When a line
    # matches through its hex/UTF-16 representation, mark the whole displayed
    # line as a search hit using bold/reverse styling rather than green.
    if _search_matches_line(safe, query, mode):
        return [(0, len(safe), "bold")]
    return []

def _correlation_log_text(corr: Correlation) -> str:
    pieces = [corr.event_message or ""]
    pieces.extend(read_context_lines(corr.event_file, corr.event_line, radius=0))
    return "\n".join(pieces)

def correlation_lexical_score(corr: Correlation) -> float:
    return lexical_score_from_breakdown(corr.score_breakdown or {})

def average_lexical_score(correlations: list[Correlation]) -> float:
    if not correlations:
        return 0.0
    vals = [correlation_lexical_score(c) for c in correlations]
    return sum(vals) / len(vals) if vals else 0.0

def build_preview_lines(corr: Optional[Correlation], collapsed: bool = True) -> list[str]:
    if not corr:
        return ["No selection"]

    lines: list[str] = [
        f"Host:  {corr.host}",
        f"Attacker: {getattr(corr, 'attacker_host', 'unknown-attacker')}",
        f"Time:  {corr.event_time.isoformat()}",
        f"Delta: {corr.delta_seconds:.3f}s    Score: {corr.score:.2f}",
        f"Command: {corr.attack_cmd}",
        f"Matched command tokens: {', '.join(getattr(corr, 'matched_command_terms', []) or ['<none>'])}",
        f"Matched metadata tokens: {', '.join(getattr(corr, 'matched_metadata_terms', []) or ['<none>'])}",
        f"File:  {corr.event_file}:{corr.event_line}",
    ]

    breakdown = getattr(corr, "score_breakdown", {}) or {}
    if breakdown:
        lines.append("Why this matched:")
        items = sorted(breakdown.items(), key=lambda kv: (-kv[1], kv[0]))
        if collapsed:
            items = items[:5]
        for key, value in items:
            pretty_key = key.replace("_", " ")
            lines.append(f"  - {pretty_key}: {value:.2f}")
        if collapsed and len(breakdown) > 5:
            lines.append(f"  ... {len(breakdown) - 5} more scoring details hidden")

    lines.append("Matched log line:")
    focus_line = [] if corr.event_source_type == "journalctl-export" else read_context_lines(corr.event_file, corr.event_line, radius=0)
    if not focus_line or focus_line[0].startswith(("[missing file]", "[unable to preview]")):
        focus_line = [f">{corr.event_line:6d} {sanitize_preview_text(corr.event_message)}"]
    lines.extend(focus_line)
    lines.append("------------------")
    lines.append("Context:")
    context = [] if corr.event_source_type == "journalctl-export" else read_context_lines(corr.event_file, corr.event_line, radius=2 if collapsed else 6)
    if context:
        if focus_line:
            context = [x for x in context if x not in focus_line]
        lines.extend(context)

    if not collapsed:
        lines.append("Event:")
        lines.append(sanitize_preview_text(corr.event_message))
        lines.append("Scoring breakdown:")
        pretty = pp.pformat(breakdown, width=88, compact=False, sort_dicts=True)
        lines.extend(sanitize_preview_text(pretty).splitlines())

    return lines

HILITE_BLUE_PATTERNS = [
    r'\bname="[^"]+"',
    r"\bcomm=[^\s]+",
    r"\bexe=[^\s]+",
    r"\bcmd=[^\s].*$",
    r"\b(?:sudo|curl|wget|nc|ncat|netcat|nmap|ssh|scp|ftp|python|python3|bash|sh|zsh|perl|ruby|php|busybox|systemctl|iptables|ip|ss|netstat|tcpdump|socat)\b",
    r"\b(?:/[A-Za-z0-9._-]+)+\b",
    r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b",
]

def _collect_semantic_spans(line: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    safe = sanitize_preview_text(line)

    for pat in HILITE_BLUE_PATTERNS:
        for m in re.finditer(pat, safe):
            spans.append((m.start(), m.end(), "blue"))

    for m in re.finditer(r'\b(?:error|failed|failure|denied|invalid|refused|blocked|drop(?:ped)?|alert)\b', safe, flags=re.I):
        spans.append((m.start(), m.end(), "bold"))

    return spans

def _merge_spans(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    if not spans:
        return []

    # Higher priority wins at every character position.  This fixes the case
    # where a broad blue semantic span, such as ``cmd=...`` or a full path,
    # starts before a green lexical match and would otherwise occupy the region
    # first.  Green is attack-log evidence, so it must always overpower blue.
    priority = {"blue": 1, "bold": 2, "green": 3}
    spans = [s for s in spans if s[0] < s[1]]
    if not spans:
        return []

    max_end = max(e for _s, e, _kind in spans)
    chosen: list[Optional[str]] = [None] * max_end

    for s, e, kind in spans:
        kind_priority = priority.get(kind, 0)
        for pos in range(max(0, s), min(e, max_end)):
            current = chosen[pos]
            if current is None or kind_priority > priority.get(current, 0):
                chosen[pos] = kind

    merged: list[tuple[int, int, str]] = []
    pos = 0
    while pos < max_end:
        kind = chosen[pos]
        if kind is None:
            pos += 1
            continue
        end = pos + 1
        while end < max_end and chosen[end] == kind:
            end += 1
        merged.append((pos, end, kind))
        pos = end

    return merged

def _lexical_highlight_spans(line: str, keywords: list[str]) -> list[tuple[int, int]]:
    wanted = {str(term).lower() for term in keywords if term}
    spans = [m.span() for m in HOST_TOKEN_RE.finditer(line) if m.group().lower() in wanted or sanitize_host_name(m.group()) in wanted]
    for match in re.finditer(r"(?<![A-Za-z0-9_.])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_.])", line):
        if match.group() in wanted:
            spans.append(match.span())
    for term in wanted:
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", term):
            continue  # IPs need stricter boundaries to avoid partial addresses.
        boundary = "A-Za-z0-9_.-" if len(term) < 3 else "A-Za-z0-9"
        pattern = rf"(?<![{boundary}])" + re.escape(term) + rf"(?![{boundary}])"
        for match in re.finditer(pattern, line, flags=re.I):
            if not any(start <= match.start() and match.end() <= end for start, end in spans):
                spans.append(match.span())
    return sorted(spans)

def _render_semantic_highlighted_line(
    win,
    y: int,
    x: int,
    width: int,
    line: str,
    keywords: list[str],
    blue_attr: int,
    green_attr: int,
    bold_attr: int,
    search_query: str = "",
    search_encoding: str = "utf8",
    forced_green_spans: Optional[list[tuple[int, int]]] = None,
) -> None:
    safe = sanitize_preview_text(line)
    spans: list[tuple[int, int, str]] = []

    spans.extend((start, end, "green") for start, end in _lexical_highlight_spans(safe, keywords))

    for s_idx, e_idx in forced_green_spans or []:
        spans.append((max(0, s_idx), min(len(safe), e_idx), "green"))

    spans.extend(_collect_semantic_spans(safe))
    spans.extend(_search_spans(safe, search_query, search_encoding))
    spans = _merge_spans(spans)

    cur = 0
    col = x
    remaining = width
    for s, e, kind in spans:
        if remaining <= 0:
            break
        if s > cur:
            chunk = safe[cur:s]
            draw = chunk[:remaining]
            win.addnstr(y, col, draw, remaining)
            col += len(draw)
            remaining -= len(draw)
            cur = s
            if remaining <= 0:
                break
        if e > cur:
            chunk = safe[cur:e]
            draw = chunk[:remaining]
            attr = green_attr if kind == "green" else blue_attr if kind == "blue" else bold_attr
            win.addnstr(y, col, draw, remaining, attr)
            col += len(draw)
            remaining -= len(draw)
            cur += len(draw)

    if remaining > 0 and cur < len(safe):
        chunk = safe[cur:cur + remaining]
        win.addnstr(y, col, chunk, remaining)

class CorrelationBrowser:
    # Build lookup indexes once so repeated correlation checks are fast.
    # These maps/lists are used for alias normalization, direct IP lookup,
    # CIDR-network lookup, and path-hint matching.
    def __init__(self, attacks: list[Attack], correlations: list[Correlation]):
        self.attacks = sorted(attacks, key=lambda x: x.timestamp)
        self.by_attack: dict[str, list[Correlation]] = defaultdict(list)
        self.attack_lookup = {a.attack_id: a for a in attacks}
        for c in correlations:
            self.by_attack[c.attack_id].append(c)
        for attack_id in self.by_attack:
            self.by_attack[attack_id].sort(key=lambda c: (-c.score, c.abs_delta_seconds))
        self.attack_idx = 0
        self.corr_idx = 0

    # Return the currently selected Attack, or None when there are no attacks.
    def current_attack(self) -> Optional[Attack]:
        if not self.attacks:
            return None
        return self.attacks[self.attack_idx]

    # Return correlations belonging to the currently selected attack.
    def current_correlations(self) -> list[Correlation]:
        attack = self.current_attack()
        if not attack:
            return []
        return self.by_attack.get(attack.attack_id, [])

    # Return the selected correlation and clamp the index into valid range.
    def current_correlation(self) -> Optional[Correlation]:
        rows = self.current_correlations()
        if not rows:
            return None
        self.corr_idx = max(0, min(self.corr_idx, len(rows) - 1))
        return rows[self.corr_idx]

    # Start curses safely; curses.wrapper restores the terminal on exit/crash.
    def run(self) -> None:
        curses.wrapper(self._main)

    def _prompt_search(self, stdscr, current_query: str) -> str:
        # A small one-line search prompt.  It uses curses' built-in line editor
        # so Backspace/Enter behave normally in most terminals.
        max_y, max_x = stdscr.getmaxyx()
        prompt = "Search logs: "
        stdscr.move(max_y - 1, 0)
        stdscr.clrtoeol()
        stdscr.addnstr(max_y - 1, 0, prompt, max_x - 1, curses.A_STANDOUT)
        curses.echo()
        try:
            curses.curs_set(1)
        except Exception:
            pass
        try:
            raw = stdscr.getstr(max_y - 1, len(prompt), max(1, max_x - len(prompt) - 1))
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            text = current_query
        finally:
            curses.noecho()
            try:
                curses.curs_set(0)
            except Exception:
                pass
        return text

    def _jump_to_next_search_match(self, search_query: str, search_encoding: str) -> bool:
        # Search within the correlations for the currently selected attack.
        # Matching is done against the stored event preview plus the exact host-log
        # line read from disk, so it searches log evidence rather than attack text.
        rows = self.current_correlations()
        if not rows or not search_query:
            return False
        start = self.corr_idx
        for step in range(1, len(rows) + 1):
            idx = (start + step) % len(rows)
            if _search_matches_line(_correlation_log_text(rows[idx]), search_query, search_encoding):
                self.corr_idx = idx
                return True
        return False

    # Draw a bordered selectable list pane.
    # Used for both the attack list and the correlation list.
    def _draw_list(
        self,
        win,
        title: str,
        rows: list[str],
        selected: int,
        top: int,
        highlighted: Optional[set[int]] = None,
        highlight_attr: Optional[int] = None,
        border_attr: int = curses.A_NORMAL,
    ) -> int:
        height, width = win.getmaxyx()
        try:
            win.attron(border_attr)
            win.box()
            win.addnstr(0, 2, f" {title} ", width - 4, curses.A_BOLD | border_attr)
            win.attroff(border_attr)
        except Exception:
            win.box()
            win.addnstr(0, 2, f" {title} ", width - 4, curses.A_BOLD)
        visible = max(1, height - 2)
        if rows:
            selected = max(0, min(selected, len(rows) - 1))
        if selected < top:
            top = selected
        if selected >= top + visible:
            top = selected - visible + 1
        highlighted = highlighted or set()
        highlight_attr = highlight_attr if highlight_attr is not None else curses.A_NORMAL
        for i in range(visible):
            idx = top + i
            if idx >= len(rows):
                break
            base_attr = curses.A_REVERSE if idx == selected else curses.A_NORMAL
            if idx in highlighted:
                attr = highlight_attr | (curses.A_REVERSE if idx == selected else curses.A_NORMAL)
            else:
                attr = base_attr
            win.addnstr(i + 1, 1, rows[idx].ljust(width - 2), width - 2, attr)
        return top

    # Draw a bordered scrollable text pane with wrapping and highlighting.
    # Used for the right-hand event preview.
    def _draw_text(
        self,
        win,
        title: str,
        lines: list[str],
        top: int = 0,
        keywords: Optional[list[str]] = None,
        search_query: str = "",
        search_encoding: str = "utf8",
        border_attr: int = curses.A_NORMAL,
    ) -> int:
        height, width = win.getmaxyx()
        inner_width = max(1, width - 2)
        max_rows = max(0, height - 2)
        try:
            win.attron(border_attr)
            win.box()
            win.attroff(border_attr)
        except Exception:
            win.box()

        rendered: list[tuple[str, list[tuple[int, int]]]] = []
        previous_blank = False
        event_line_next = False
        keywords = keywords or []
        for line in lines:
            safe_line = sanitize_preview_text(line)
            is_evidence = (
                bool(re.match(r"^[ >]\s*\d+\s", safe_line))
                or safe_line.startswith(("Command: ", "Matched command tokens: ", "Matched metadata tokens: "))
                or event_line_next
            )
            event_line_next = safe_line == "Event:"
            if safe_line == "":
                if not previous_blank:
                    rendered.append(("", []))
                previous_blank = True
                continue
            previous_blank = False
            green_spans = _lexical_highlight_spans(safe_line, keywords) if is_evidence else []
            start_idx = 0
            # Find matches on the complete line so wrapping cannot split a
            # lexical token into two unhighlighted fragments.
            while start_idx < len(safe_line):
                end_idx = start_idx + inner_width
                local_spans = [
                    (max(0, start - start_idx), min(inner_width, end - start_idx))
                    for start, end in green_spans if start < end_idx and end > start_idx
                ]
                rendered.append((safe_line[start_idx:end_idx], local_spans))
                start_idx += inner_width

        if top < 0:
            top = 0
        max_top = max(0, len(rendered) - max_rows)
        if top > max_top:
            top = max_top

        status = f" {title} [{top + 1}-{min(len(rendered), top + max_rows)}/{max(len(rendered), 1)}] "
        win.addnstr(0, 2, status, width - 4, curses.A_BOLD | border_attr)

        for i in range(max_rows):
            idx = top + i
            if idx >= len(rendered):
                break
            rendered_text, green_spans = rendered[idx]
            rendered_line = rendered_text.ljust(inner_width)
            _render_semantic_highlighted_line(
                win,
                i + 1,
                1,
                inner_width,
                rendered_line,
                [],
                getattr(self, "preview_blue_attr", curses.A_BOLD),
                getattr(self, "preview_green_attr", curses.A_BOLD),
                getattr(self, "preview_bold_attr", curses.A_BOLD),
                search_query,
                search_encoding,
                green_spans,
            )
        return top

    # Main event loop for the curses UI.
    # It lays out the three panes, renders them, reads a key, updates indexes/scroll
    # state, and repeats until the user quits.
    def _main(self, stdscr) -> None:
        curses.curs_set(0)
        stdscr.keypad(True)
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            curses.init_pair(2, curses.COLOR_BLUE, -1)
            curses.init_pair(3, curses.COLOR_RED, -1)  # Active-pane border.
            self.preview_green_attr = curses.color_pair(1) | curses.A_BOLD | curses.A_REVERSE
            self.preview_blue_attr = curses.color_pair(2) | curses.A_BOLD
            self.preview_bold_attr = curses.A_BOLD | curses.A_REVERSE
            self.correlation_highlight_attr = curses.color_pair(2) | curses.A_BOLD
            self.selected_pane_border_attr = curses.color_pair(3) | curses.A_BOLD
        except Exception:
            self.preview_green_attr = curses.A_BOLD | curses.A_REVERSE
            self.preview_blue_attr = curses.A_BOLD
            self.preview_bold_attr = curses.A_BOLD | curses.A_REVERSE
            self.correlation_highlight_attr = curses.A_BOLD
            self.selected_pane_border_attr = curses.A_BOLD | curses.A_REVERSE
        attack_top = 0
        corr_top = 0
        preview_top = 0
        preview_collapsed = True
        selected_pane = 0  # 0=attacks, 1=correlations, 2=preview.
        search_query = ""
        search_encoding_idx = 0
        search_status = ""
        while True:
            stdscr.erase()
            max_y, max_x = stdscr.getmaxyx()
            # Recompute layout on every loop so terminal resizes are handled
            # naturally.
            header = "Attack / Log Correlator  q:quit  TAB/left-right:pane  /:search  e:encoding  n:next  up-down:active pane  z:collapse"
            stdscr.addnstr(0, 0, header.ljust(max_x), max_x - 1, curses.A_STANDOUT)
            mid_w = max(34, max_x // 5)
            side_total = max_x - mid_w
            left_w = side_total // 2
            right_w = max_x - left_w - mid_w
            body_h = max(1, max_y - 2)
            attack_win = stdscr.derwin(body_h, left_w, 1, 0)
            corr_win = stdscr.derwin(body_h, mid_w, 1, left_w)
            preview_win = stdscr.derwin(body_h, right_w, 1, left_w + mid_w)
            def pane_title(idx: int, title: str) -> str:
                return ("> " if selected_pane == idx else "  ") + title

            def pane_border_attr(idx: int) -> int:
                return getattr(self, "selected_pane_border_attr", curses.A_BOLD) if selected_pane == idx else curses.A_NORMAL

            attack_rows = []
            highlighted_attack_rows: set[int] = set()
            attack_corr_counts = {a.attack_id: len(self.by_attack.get(a.attack_id, [])) for a in self.attacks}
            attack_score_totals = {
                a.attack_id: sum(float(c.score or 0.0) for c in self.by_attack.get(a.attack_id, []))
                for a in self.attacks
            }
            for idx, a in enumerate(self.attacks):
                cnt = attack_corr_counts.get(a.attack_id, 0)
                total_score = attack_score_totals.get(a.attack_id, 0.0)
                if cnt > 0:
                    highlighted_attack_rows.add(idx)
                attack_rows.append(
                    f"{idx+1:3d} {cnt:3d} total={total_score:7.1f} {a.attacker_host[:12]:<12} "
                    f"{a.timestamp.strftime('%Y-%m-%d %H:%M:%S')} {a.attack_type:<8} {a.cmd[:32]}"
                )
            attack_top = self._draw_list(
                attack_win,
                pane_title(0, f"Attacks ({len(self.attacks)})"),
                attack_rows,
                self.attack_idx,
                attack_top,
                highlighted=highlighted_attack_rows,
                highlight_attr=getattr(self, "correlation_highlight_attr", curses.A_BOLD),
                border_attr=pane_border_attr(0),
            )
            corr_rows = []
            attack = self.current_attack()
            correlations = self.current_correlations()
            lexical_avg = average_lexical_score(correlations)
            highlighted_corr_rows: set[int] = set()
            for idx, c in enumerate(correlations):
                lex_score = correlation_lexical_score(c)
                if lex_score > lexical_avg:
                    highlighted_corr_rows.add(idx)
                corr_rows.append(
                    f"{c.host:<16} s={c.score:6.1f} lx={lex_score:6.1f} dt={c.delta_seconds:8.2f}s {c.event_message[:70]}"
                )
            corr_top = self._draw_list(
                corr_win,
                pane_title(1, f"Correlations ({len(correlations)})"),
                corr_rows,
                self.corr_idx,
                corr_top,
                highlighted=highlighted_corr_rows,
                highlight_attr=getattr(self, "correlation_highlight_attr", curses.A_BOLD),
                border_attr=pane_border_attr(1),
            )
            corr = self.current_correlation()
            preview = build_preview_lines(corr, collapsed=preview_collapsed)
            preview_title = pane_title(2, "Event Preview (collapsed)" if preview_collapsed else "Event Preview (expanded)")
            preview_top = self._draw_text(
                preview_win,
                preview_title,
                preview,
                preview_top,
                _preview_keywords(corr),
                search_query,
                SEARCH_ENCODING_MODES[search_encoding_idx],
                border_attr=pane_border_attr(2),
            )
            footer = (
                f"Search[{SEARCH_ENCODING_MODES[search_encoding_idx]}]: "
                f"{search_query or '<empty>'}  {search_status}"
            )
            stdscr.addnstr(max_y - 1, 0, footer.ljust(max_x), max_x - 1, curses.A_STANDOUT)
            stdscr.refresh()
            ch = stdscr.getch()
            if ch in (ord("q"), 27):
                break
            if ch in (ord("\t"), 9):
                selected_pane = (selected_pane + 1) % 3
            elif ch == ord("/"):
                search_query = self._prompt_search(stdscr, search_query)
                search_status = ""
                if search_query:
                    found = self._jump_to_next_search_match(search_query, SEARCH_ENCODING_MODES[search_encoding_idx])
                    search_status = "match selected" if found else "no match"
                    preview_top = 0
            elif ch in (ord("e"), ord("E")):
                search_encoding_idx = (search_encoding_idx + 1) % len(SEARCH_ENCODING_MODES)
                search_status = f"encoding={SEARCH_ENCODING_MODES[search_encoding_idx]}"
            elif ch in (ord("n"), ord("N")):
                if search_query:
                    found = self._jump_to_next_search_match(search_query, SEARCH_ENCODING_MODES[search_encoding_idx])
                    search_status = "match selected" if found else "no match"
                    preview_top = 0
            elif ch == curses.KEY_LEFT:
                selected_pane = (selected_pane - 1) % 3
            elif ch == curses.KEY_RIGHT:
                selected_pane = (selected_pane + 1) % 3
            elif ch == curses.KEY_UP:
                if selected_pane == 0:
                    self.attack_idx = max(0, self.attack_idx - 1)
                    self.corr_idx = 0
                    preview_top = 0
                elif selected_pane == 1:
                    self.corr_idx = max(0, self.corr_idx - 1)
                    preview_top = 0
                else:
                    preview_top = max(0, preview_top - 1)
            elif ch == curses.KEY_DOWN:
                if selected_pane == 0:
                    self.attack_idx = min(max(0, len(self.attacks) - 1), self.attack_idx + 1)
                    self.corr_idx = 0
                    preview_top = 0
                elif selected_pane == 1:
                    self.corr_idx = min(max(0, len(correlations) - 1), self.corr_idx + 1)
                    preview_top = 0
                else:
                    preview_top += 1
            elif ch == curses.KEY_NPAGE:
                preview_top += max(1, preview_win.getmaxyx()[0] - 3)
            elif ch == curses.KEY_PPAGE:
                preview_top = max(0, preview_top - max(1, preview_win.getmaxyx()[0] - 3))
            elif ch in (ord("z"), ord("Z")):
                preview_collapsed = not preview_collapsed
                preview_top = 0
