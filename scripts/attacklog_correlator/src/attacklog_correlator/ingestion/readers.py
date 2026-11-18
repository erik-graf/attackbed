"""Streaming text/journal records independent of attacks and correlation windows."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Iterator
from typing import Optional

from attacklog_correlator.ingestion.logtypes import LogTypeRule
from attacklog_correlator.ingestion.timestamps import try_parse_line_timestamp
from attacklog_correlator.models import LogRecord, RunStats


BINARY_SAMPLE_BYTES = 8192

BINARY_CONTROL_BYTE_RATIO = 0.30

def run_journalctl_export(path: Path) -> Iterator[str]:
    cmd = ["journalctl", f"--file={path}", "-o", "short-iso-precise", "--no-pager"]
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as errors:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errors, text=True) as proc:
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    yield line.rstrip("\n")
                if proc.wait() != 0:
                    errors.seek(0)
                    raise RuntimeError(errors.read().strip() or "journalctl failed")
            finally:
                # A generic reader may be closed before journalctl finishes.
                if proc.poll() is None:
                    proc.terminate()

def file_starts_with_systemd_journal_magic(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(8) == b"LPKSHHRH"
    except Exception:
        return False

def is_probably_binary_file(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            sample = fh.read(BINARY_SAMPLE_BYTES)
    except Exception:
        return False
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    control_bytes = 0
    for value in sample:
        if value in (9, 10, 13):
            continue
        if value < 32:
            control_bytes += 1
    return (control_bytes / len(sample)) >= BINARY_CONTROL_BYTE_RATIO

def should_try_journalctl(path: Path) -> bool:
    lower_name = path.name.lower()
    return (
        path.suffix.lower() == ".journal"
        or file_starts_with_systemd_journal_magic(path)
        or ("journal" in lower_name and is_probably_binary_file(path))
    )

def detect_source_type(path: Path, line: str) -> str:
    lower = path.name.lower()
    if lower.endswith(".journal"):
        return "journal-binary"
    if "audit" in lower or "audit(" in line:
        return "auditd"
    if line.lstrip().startswith("{") and '"time"' in line and '"log"' in line:
        return "docker-json"
    if re.search(r"\[\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]", line):
        if "nginx" in lower:
            return "nginx-access"
        if "apache" in lower or "access" in lower:
            return "apache-access"
        return "http-access"
    if re.match(r"^\d{1,2}/\d{1,2}/\d{2,4}\s+--\s+\d{2}:\d{2}:\d{2}", line):
        return "suricata"
    if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", line):
        return "syslog-like"
    return "generic-text"

def preview_message_from_line(line: str) -> str:
    text = line.rstrip("\n")
    if text.lstrip().startswith("{"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                for key in ("log", "message", "msg", "MESSAGE"):
                    if isinstance(obj.get(key), str):
                        return obj[key].rstrip()[:400]
        except Exception:
            pass
    return text[:400]

def iter_log_records(path: Path, default_year: int, *, stats: Optional[RunStats] = None,
                     log_type: Optional[LogTypeRule] = None) -> Iterator[LogRecord]:
    """Stream raw records without host resolution, time filtering or scoring.

    Read/parse errors propagate to the caller. Close this iterator when stopping
    early, so its file or journal subprocess is released promptly.
    """
    if stats is None:
        stats = RunStats()
    journal = should_try_journalctl(path)
    if not journal and is_probably_binary_file(path):
        print(f"[warn] skipping binary-looking non-journal log file: {path}", file=sys.stderr)
        stats.binary_log_files_skipped += 1
        return
    source = closing(run_journalctl_export(path)) if journal else path.open("r", encoding="utf-8", errors="replace")
    with source as lines:
        for line_number, line in enumerate(lines, start=1):
            parsed = log_type.parse_timestamp(line, default_year) if log_type else try_parse_line_timestamp(line, default_year)
            if parsed is None:
                stats.unparsable_lines += 1
            yield LogRecord(str(path), line_number, line, parsed, "journalctl-export" if journal else None)
    if journal:
        stats.journalctl_converted_files += 1
