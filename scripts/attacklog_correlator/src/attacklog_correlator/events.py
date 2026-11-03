"""Adapt source records to normalized, enriched correlation candidates."""

from __future__ import annotations

import datetime as dt
import re
import sys
from bisect import bisect_left
from contextlib import closing
from pathlib import Path
from typing import Optional

from .ingestion import readers
from attacklog_correlator.config import HostResolver, MAX_TIME_DELTA_SECONDS
from attacklog_correlator.ingestion.discovery import discover_log_files
from attacklog_correlator.ingestion.timestamps import get_zone
from attacklog_correlator.models import (
    Attack,
    LogEvent,
    ParsedTimestamp,
    RunStats,
    UNKNOWN_TIMESTAMP_SENTINEL,
    UTC,
)
from attacklog_correlator.tokens import extract_ips, extract_tokens, sanitize_host_name


def guess_host_from_line(line: str) -> Optional[str]:
    m = re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+([A-Za-z0-9._-]+)\s+", line)
    if m:
        return sanitize_host_name(m.group(1))
    m = re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})\s+([A-Za-z0-9._-]+)\s+", line)
    if m:
        return sanitize_host_name(m.group(1))
    return None

def normalize_event_time(parsed: ParsedTimestamp, host: str, resolver: HostResolver) -> dt.datetime:
    base = parsed.timestamp_utc
    if parsed.naive:
        # The parser initially stored naive timestamps as UTC just to carry a
        # datetime object around.  Here we remove that placeholder tzinfo,
        # attach the host's real timezone, then convert to UTC.
        zone = get_zone(resolver.resolve_timezone(host))
        naive_local = base.replace(tzinfo=None)
        base = naive_local.replace(tzinfo=zone).astimezone(UTC)
    skew = resolver.resolve_clock_skew(host)
    if skew:
        base = base - dt.timedelta(seconds=skew)
    return base.astimezone(UTC)

def load_log_file(
    path: Path, root: Path, default_year: int, resolver: HostResolver,
    include_untimestamped: bool = False, *, attack_times: Optional[list[dt.datetime]] = None,
    window_before: float = 0.0, window_after: float = 0.0,
    stats: Optional[RunStats] = None,
) -> list[LogEvent]:
    if stats is None:
        stats = RunStats()
    events: list[LogEvent] = []
    before_delta = dt.timedelta(seconds=window_before)
    after_delta = dt.timedelta(seconds=window_after)
    path_host = resolver.host_from_path(path, root) or "unknown-host"
    journal = readers.should_try_journalctl(path)
    previous_count = stats.parsed_events
    try:
        with closing(readers.iter_log_records(path, default_year, stats=stats)) as records:
            for record in records:
                parsed = record.parsed_timestamp
                timestamp_missing = parsed is None
                line = record.raw_line
                host = resolver.canonicalize_host(guess_host_from_line(line) or path_host)
                if parsed:
                    normalized_ts = normalize_event_time(parsed, host, resolver)
                    raw_timestamp, parser_name = parsed.raw_text, parsed.parser_name
                else:
                    if not include_untimestamped:
                        continue
                    normalized_ts = UNKNOWN_TIMESTAMP_SENTINEL
                    raw_timestamp, parser_name = "", "missing"
                stats.parsed_events += 1
                # Normalize first, then prune before expensive token/host extraction.
                if attack_times is not None and not timestamp_missing:
                    idx = bisect_left(attack_times, normalized_ts - after_delta)
                    if idx == len(attack_times) or attack_times[idx] > normalized_ts + before_delta:
                        continue
                candidate_ips = extract_ips(line)
                candidate_hosts = resolver.candidate_hosts_for_tokens(extract_tokens(line) + candidate_ips, path=path, root=root)
                if host not in candidate_hosts:
                    candidate_hosts.insert(0, host)
                events.append(LogEvent(
                    event_id=f"{path}:{record.line_number}", timestamp=normalized_ts,
                    raw_timestamp=raw_timestamp, host=host,
                    source_type=record.source_type or readers.detect_source_type(path, line),
                    file_path=str(path), line_number=record.line_number,
                    message=readers.preview_message_from_line(line), raw_line=line.rstrip("\n"),
                    extra={"timestamp_parser": parser_name, "timestamp_missing": timestamp_missing},
                    candidate_hosts=candidate_hosts, candidate_ips=candidate_ips,
                ))
    except Exception as exc:
        if not journal:
            raise
        print(f"[warn] failed to export binary journal with journalctl: {path}: {exc}", file=sys.stderr)
        stats.binary_log_files_skipped += 1
        stats.parsed_events = previous_count
        return []
    return events

def load_all_events(
    log_root: Path, attack_root: Optional[Path], default_year: int, resolver: HostResolver,
    include_untimestamped: bool = False, *, attacks: Optional[list[Attack]] = None,
    window_before: float = 60.0, window_after: float = 240.0,
    stats: Optional[RunStats] = None, max_time_delta: float = MAX_TIME_DELTA_SECONDS,
) -> list[LogEvent]:
    events: list[LogEvent] = []
    if stats is None:
        stats = RunStats()
    attack_times = sorted(a.timestamp for a in attacks) if attacks is not None else None
    for path in discover_log_files(log_root, attack_root):
        try:
            events.extend(load_log_file(
                path, log_root, default_year, resolver, include_untimestamped,
                attack_times=attack_times,
                window_before=min(window_before, max_time_delta),
                window_after=min(window_after, max_time_delta),
                stats=stats,
            ))
        except Exception:
            print(f"[warn] failed to read log file: {path}", file=sys.stderr)
    return sorted(events, key=lambda x: x.timestamp)
