"""Data exchanged between ingestion, correlation, reports and the UI."""

from __future__ import annotations

import dataclasses
import datetime as dt
from typing import Any
from typing import Optional


UTC = dt.timezone.utc

UNKNOWN_TIMESTAMP_SENTINEL = dt.datetime.fromtimestamp(0, tz=UTC)

@dataclasses.dataclass
class Attack:
    attack_id: str
    timestamp: dt.datetime
    attack_type: str
    cmd: str
    source_file: str
    line_number: int
    metadata: dict[str, Any]
    raw_line: str = ""
    target_hosts: list[str] = dataclasses.field(default_factory=list)
    target_ips: list[str] = dataclasses.field(default_factory=list)
    target_networks: list[str] = dataclasses.field(default_factory=list)
    target_tokens: list[str] = dataclasses.field(default_factory=list)
    attacker_host: str = "unknown-attacker"

@dataclasses.dataclass
class LogEvent:
    event_id: str
    timestamp: dt.datetime
    raw_timestamp: str
    host: str
    source_type: str
    file_path: str
    line_number: int
    message: str
    raw_line: str
    extra: dict[str, Any]
    candidate_hosts: list[str]
    candidate_ips: list[str]

@dataclasses.dataclass
class Correlation:
    correlation_id: str
    attack_id: str
    event_id: str
    attacker_host: str
    attack_time: dt.datetime
    event_time: dt.datetime
    delta_seconds: float
    abs_delta_seconds: float
    attack_file: str
    attack_line: int
    attack_raw_line: str
    event_file: str
    event_line: int
    host: str
    attack_type: str
    attack_cmd: str
    attack_targets: list[str]
    target_host_matches: list[str]
    event_message: str
    event_source_type: str
    score: float
    score_breakdown: dict[str, float]
    matched_lexical_terms: list[str] = dataclasses.field(default_factory=list)
    matched_command_terms: list[str] = dataclasses.field(default_factory=list)
    matched_metadata_terms: list[str] = dataclasses.field(default_factory=list)

@dataclasses.dataclass
class ParsedTimestamp:
    timestamp_utc: dt.datetime
    raw_text: str
    naive: bool
    parser_name: str

@dataclasses.dataclass(slots=True)
class LogRecord:
    """A source line and its parsed timestamp, before host or attack enrichment.

    Naive timestamps retain their wall-clock value and naive flag; the event
    adapter applies host timezone and skew exactly once. Raw text is untruncated.
    """
    file_path: str
    line_number: int
    raw_line: str
    parsed_timestamp: Optional[ParsedTimestamp]
    source_type: Optional[str] = None

@dataclasses.dataclass
class RunStats:
    """Counters owned by one invocation, never shared across runs."""
    parsed_events: int = 0
    unparsable_lines: int = 0
    journalctl_converted_files: int = 0
    binary_log_files_skipped: int = 0
