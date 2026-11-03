"""Existing timestamp parsers; naive wall clocks stay marked until normalization."""

from __future__ import annotations

import datetime as dt
import json
import re
import sys
from typing import Optional
from zoneinfo import ZoneInfo

from attacklog_correlator.models import ParsedTimestamp, UTC


EPOCH_MILLISECONDS_THRESHOLD = 10_000_000_000

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

def get_zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except Exception as exc:
        print(f"[warn] failed to load timezone {name!r}; falling back to UTC: {exc}", file=sys.stderr)
        return ZoneInfo("UTC")

def parse_iso_datetime(value: str) -> Optional[dt.datetime]:
    value = value.strip()
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)

def parse_attack_datetime(value: str, attacker_timezone: str = "UTC") -> Optional[dt.datetime]:
    """Parse an attack-log timestamp using the attacker's configured timezone.

    parse_iso_datetime() intentionally treats naive timestamps as UTC because
    many machine logs are UTC by convention.  Attack logs are different here:
    different attacker machines may have been configured to different local
    timezones.  This helper preserves existing behavior for timestamps that
    already include an offset, but interprets naive attack timestamps in the
    per-attacker timezone from host_config/generated config.
    """
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        zone = get_zone(attacker_timezone or "UTC")
        return parsed.replace(tzinfo=zone).astimezone(UTC)
    return parsed.astimezone(UTC)

def parse_epoch_seconds(text: str) -> Optional[dt.datetime]:
    try:
        value = float(text)
    except ValueError:
        return None

    # Many JSON loggers emit epoch milliseconds while auditd emits epoch
    # seconds.  Treat very large epoch-like values as milliseconds so
    # 1710000000123 becomes 1710000000.123 instead of year 56157.
    if abs(value) >= EPOCH_MILLISECONDS_THRESHOLD:
        value = value / 1000.0

    try:
        return dt.datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None

def parse_audit_timestamp(line: str, *_args) -> Optional[ParsedTimestamp]:
    m = re.search(r"audit\((\d+(?:\.\d+)?):\d+\)", line)
    if not m:
        return None
    ts = parse_epoch_seconds(m.group(1))
    if not ts:
        return None
    return ParsedTimestamp(ts, m.group(1), False, "auditd-epoch")

def parse_syslog_timestamp(line: str, default_year: int) -> Optional[tuple[dt.datetime, str]]:
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s+", line)
    if not m:
        return None
    month = MONTHS.get(m.group(1))
    if not month:
        return None
    day = int(m.group(2))
    hh, mm, ss = [int(x) for x in m.group(3).split(":")]
    micro = int((m.group(4) or "0")[:6].ljust(6, "0"))
    text = f"{m.group(1)} {m.group(2)} {m.group(3)}"
    try:
        return dt.datetime(default_year, month, day, hh, mm, ss, micro), text
    except ValueError:
        return None

def parse_syslog_like(line: str, default_year: int) -> Optional[ParsedTimestamp]:
    res = parse_syslog_timestamp(line, default_year)
    if not res:
        return None
    naive_dt, text = res
    return ParsedTimestamp(naive_dt.replace(tzinfo=UTC), text, True, "syslog-like")

def parse_suricata_timestamp(line: str, *_args) -> Optional[ParsedTimestamp]:
    m = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{2,4})\s+--\s+(\d{2}:\d{2}:\d{2})", line)
    if not m:
        return None
    day = int(m.group(1))
    month = int(m.group(2))
    year = int(m.group(3))
    if year < 100:
        year += 2000
    hh, mm, ss = [int(x) for x in m.group(4).split(":")]
    raw = m.group(0)
    try:
        naive_dt = dt.datetime(year, month, day, hh, mm, ss)
    except ValueError:
        return None
    return ParsedTimestamp(naive_dt.replace(tzinfo=UTC), raw, True, "suricata")

def parse_apache_nginx_timestamp(line: str, *_args) -> Optional[ParsedTimestamp]:
    m = re.search(r"\[(\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]", line)
    if not m:
        return None
    raw = m.group(1)
    try:
        parsed = dt.datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return ParsedTimestamp(parsed.astimezone(UTC), raw, False, "apache-nginx")

def parse_iso_prefix(line: str, *_args) -> Optional[ParsedTimestamp]:
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+", line)
    if not m:
        return None
    raw = m.group(1)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    naive = parsed.tzinfo is None
    return ParsedTimestamp(parsed.replace(tzinfo=UTC) if naive else parsed.astimezone(UTC), raw, naive, "iso-prefix")

def parse_json_line_timestamp(line: str, *_args) -> Optional[ParsedTimestamp]:
    if not line.lstrip().startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    for key in ("time", "timestamp", "@timestamp", "ts", "datetime", "date"):
        value = obj.get(key)
        if isinstance(value, str):
            try:
                parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
            naive = parsed.tzinfo is None
            timestamp = parsed.replace(tzinfo=UTC) if naive else parsed.astimezone(UTC)
            return ParsedTimestamp(timestamp, value, naive, f"json:{key}")
        elif isinstance(value, (int, float)):
            parsed = parse_epoch_seconds(str(value))
            if parsed:
                return ParsedTimestamp(parsed, str(value), False, f"json:{key}:epoch")
    return None

def try_parse_line_timestamp(line: str, default_year: int) -> Optional[ParsedTimestamp]:
    for parser in (parse_json_line_timestamp, parse_audit_timestamp, parse_iso_prefix, parse_apache_nginx_timestamp, parse_suricata_timestamp):
        parsed = parser(line, default_year)
        if parsed:
            return parsed
    parsed = parse_syslog_like(line, default_year)
    if parsed:
        return parsed
    return None
