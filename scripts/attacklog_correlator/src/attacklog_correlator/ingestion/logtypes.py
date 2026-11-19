"""Configured filename selection and timestamp extraction for strict ingestion."""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from attacklog_correlator.ingestion.timestamps import parse_epoch_seconds
from attacklog_correlator.models import ParsedTimestamp, UTC


SOURCE_LOG_TYPES_FILE = Path(__file__).resolve().parents[3] / "logtypes.json"
DEFAULT_LOG_TYPES_FILE = (SOURCE_LOG_TYPES_FILE if SOURCE_LOG_TYPES_FILE.is_file()
                          else Path(sys.prefix) / "share/attacklog-correlator/logtypes.json")


@dataclass(frozen=True)
class TimestampPattern:
    regex: re.Pattern[str]
    format: str


@dataclass(frozen=True)
class LogTypeRule:
    name: str
    patterns: tuple[str, ...]
    timestamps: tuple[TimestampPattern, ...] = ()
    timestamp_key: Optional[str] = None

    def matches(self, path: Path) -> bool:
        # shortcut: compressed archives need a decoder; skip them until one is added.
        return (path.suffix.lower() not in {".gz", ".xz", ".bz2", ".zst"}
                and any(fnmatch.fnmatchcase(path.as_posix() if "/" in pattern else path.name, pattern)
                        for pattern in self.patterns))

    def parse_timestamp(self, line: str, default_year: int) -> Optional[ParsedTimestamp]:
        if self.timestamp_key:
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                return None
            if not isinstance(obj, dict):
                return None
            value = obj.get(self.timestamp_key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                timestamp = parse_epoch_seconds(str(value))
                return (ParsedTimestamp(timestamp, str(value), False, f"json:{self.timestamp_key}")
                        if timestamp else None)
            if not isinstance(value, str):
                return None
            return self._parsed(value, "iso8601", default_year, f"json:{self.timestamp_key}")

        for pattern in self.timestamps:
            match = pattern.regex.search(line)
            if match:
                result = self._parsed(match.group(1), pattern.format, default_year,
                                      f"regex:{self.name}")
                if result:
                    return result
        return None

    @staticmethod
    def _parsed(raw: str, fmt: str, default_year: int, parser_name: str) -> Optional[ParsedTimestamp]:
        if fmt == "epoch":
            parsed = parse_epoch_seconds(raw)
            return ParsedTimestamp(parsed, raw, False, parser_name) if parsed else None
        try:
            if fmt == "iso8601":
                parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            else:
                value = raw
                if "%Y" not in fmt and "%y" not in fmt:
                    fmt, value = "%Y " + fmt, f"{default_year} {raw}"
                parsed = dt.datetime.strptime(value, fmt)
        except ValueError:
            return None
        naive = parsed.tzinfo is None
        return ParsedTimestamp(parsed.replace(tzinfo=UTC) if naive else parsed.astimezone(UTC),
                               raw, naive, parser_name)


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
        name, patterns = item.get("name"), item.get("patterns")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{path}: log type {number} needs a name")
        if not isinstance(patterns, list) or not patterns or not all(isinstance(p, str) and p for p in patterns):
            raise ValueError(f"{path}: {name}: patterns must be a non-empty list of filename globs")
        key, formats = item.get("timestamp_key"), item.get("timestamps")
        if (isinstance(key, str) and bool(key)) == (isinstance(formats, list) and bool(formats)):
            raise ValueError(f"{path}: {name}: specify either timestamp_key or a non-empty timestamps list")
        if key is not None and (not isinstance(key, str) or not key or formats is not None):
            raise ValueError(f"{path}: {name}: invalid timestamp_key")
        timestamps = []
        if formats is not None:
            if not isinstance(formats, list) or not formats:
                raise ValueError(f"{path}: {name}: timestamps must be a non-empty list")
            for entry in formats:
                if not isinstance(entry, dict) or not isinstance(entry.get("regex"), str) or not isinstance(entry.get("format"), str):
                    raise ValueError(f"{path}: {name}: each timestamp needs a regex and format")
                try:
                    pattern = re.compile(entry["regex"])
                except re.error as exc:
                    raise ValueError(f"{path}: {name}: invalid timestamp regex: {exc}") from exc
                if pattern.groups < 1:
                    raise ValueError(f"{path}: {name}: timestamp regex needs a capture group")
                fmt = entry["format"]
                if not fmt or (fmt not in ("iso8601", "epoch") and "%" not in fmt):
                    raise ValueError(f"{path}: {name}: invalid timestamp format {fmt!r}")
                timestamps.append(TimestampPattern(pattern, fmt))
        rules.append(LogTypeRule(name, tuple(patterns), tuple(timestamps), key))
    return rules
