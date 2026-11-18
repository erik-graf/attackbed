"""Filename-based log types for optional strict ingestion."""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from attacklog_correlator.ingestion.timestamps import (
    parse_apache_nginx_timestamp,
    parse_audit_timestamp,
    parse_epoch_seconds,
    parse_iso_prefix,
    parse_suricata_timestamp,
    parse_syslog_like,
)
from attacklog_correlator.models import ParsedTimestamp, UTC


DEFAULT_LOG_TYPES_FILE = Path(__file__).resolve().parents[1] / "log_types.json"
PARSERS = {
    "syslog": parse_syslog_like,
    "audit": parse_audit_timestamp,
    "access": parse_apache_nginx_timestamp,
    "suricata": parse_suricata_timestamp,
    "iso": parse_iso_prefix,
}


@dataclass(frozen=True)
class LogTypeRule:
    name: str
    patterns: tuple[str, ...]
    parser: str
    timestamp_key: Optional[str] = None
    timestamp_regex: Optional[re.Pattern[str]] = None
    datetime_format: Optional[str] = None

    def matches(self, path: Path) -> bool:
        # shortcut: compressed archives need a decoder; skip them until one is added.
        return (path.suffix.lower() not in {".gz", ".xz", ".bz2", ".zst"}
                and any(fnmatch.fnmatchcase(path.name, pattern) for pattern in self.patterns))

    def parse_timestamp(self, line: str, default_year: int) -> Optional[ParsedTimestamp]:
        if self.parser in PARSERS:
            return PARSERS[self.parser](line, default_year)
        if self.parser == "json":
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                return None
            if not isinstance(obj, dict):
                return None
            value = obj.get(self.timestamp_key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                timestamp = parse_epoch_seconds(str(value))
                return ParsedTimestamp(timestamp, str(value), False, f"json:{self.timestamp_key}") if timestamp else None
            if not isinstance(value, str):
                return None
            raw = value
        else:
            match = self.timestamp_regex.search(line) if self.timestamp_regex else None
            if not match:
                return None
            raw = match.group(1)
            if raw is None:
                return None

        try:
            if self.datetime_format:
                fmt = self.datetime_format
                value = raw
                if "%Y" not in fmt and "%y" not in fmt:
                    fmt, value = "%Y " + fmt, f"{default_year} {raw}"
                parsed = dt.datetime.strptime(value, fmt)
            else:
                parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        naive = parsed.tzinfo is None
        return ParsedTimestamp(
            parsed.replace(tzinfo=UTC) if naive else parsed.astimezone(UTC),
            raw, naive, f"{self.parser}:{self.name}",
        )


def matching_log_type(path: Path, rules: list[LogTypeRule]) -> Optional[LogTypeRule]:
    return next((rule for rule in rules if rule.matches(path)), None)


def load_log_types(path: Optional[Path] = None) -> list[LogTypeRule]:
    """Load ordered filename rules; the first matching type wins."""
    path = path or DEFAULT_LOG_TYPES_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("log_types"), list) or not data["log_types"]:
        raise ValueError(f"{path}: expected a non-empty 'log_types' list")

    rules = []
    for number, item in enumerate(data["log_types"], 1):
        if not isinstance(item, dict):
            raise ValueError(f"{path}: log type {number} must be an object")
        name, patterns, parser = item.get("name"), item.get("patterns"), item.get("parser")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{path}: log type {number} needs a name")
        if not isinstance(patterns, list) or not patterns or not all(isinstance(p, str) and p for p in patterns):
            raise ValueError(f"{path}: {name}: patterns must be a non-empty list of filename globs")
        if parser not in (*PARSERS, "json", "regex"):
            raise ValueError(f"{path}: {name}: unknown parser {parser!r}")
        key = item.get("timestamp_key")
        regex = item.get("timestamp_regex")
        fmt = item.get("datetime_format")
        if parser == "json" and (not isinstance(key, str) or not key):
            raise ValueError(f"{path}: {name}: json needs a timestamp_key")
        if parser == "regex" and (not isinstance(regex, str) or not regex or not isinstance(fmt, str) or not fmt):
            raise ValueError(f"{path}: {name}: regex needs timestamp_regex and datetime_format")
        if parser not in ("json", "regex") and any(v is not None for v in (key, regex, fmt)):
            raise ValueError(f"{path}: {name}: built-in parsers do not use custom timestamp fields")
        if parser == "json" and fmt is not None and (not isinstance(fmt, str) or not fmt):
            raise ValueError(f"{path}: {name}: datetime_format must be a non-empty string")
        if parser == "json" and regex is not None:
            raise ValueError(f"{path}: {name}: json does not use timestamp_regex")
        if parser == "regex" and key is not None:
            raise ValueError(f"{path}: {name}: regex does not use timestamp_key")
        compiled = None
        if regex is not None:
            try:
                compiled = re.compile(regex)
            except re.error as exc:
                raise ValueError(f"{path}: {name}: invalid timestamp_regex: {exc}") from exc
            if compiled.groups < 1:
                raise ValueError(f"{path}: {name}: timestamp_regex needs a capture group")
        rules.append(LogTypeRule(name, tuple(patterns), parser, key, compiled, fmt))
    return rules
