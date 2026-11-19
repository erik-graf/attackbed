"""Logfile indexing, timestamped browsing and raw-byte search helpers for manual review."""

from __future__ import annotations

import datetime as dt
import re
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from attacklog_correlator.config import HostResolver
from attacklog_correlator.events import guess_host_from_line, normalize_event_time
from attacklog_correlator.ingestion import readers
from attacklog_correlator.ingestion.logtypes import LogTypeRule
from attacklog_correlator.models import Attack


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
