"""File discovery using the existing suffix and filename rules."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from attacklog_correlator.ingestion.logtypes import LogTypeRule, matching_log_type


ATTACK_LOG_SUFFIXES = {".json"}

TEXT_EXTENSIONS = {".log", ".txt", ".json", ".jsonl", ".out", ".err", ".messages", ".syslog", ".csv"}

def discover_attack_files(root: Path) -> list[Path]:
    found: list[Path] = []
    # rglob("*") recursively walks the entire attack root.  Any matching suffix
    # or filename containing "attack" is treated as an attack-log candidate.
    for path in root.rglob("*"):
        if path.is_file() and (path.suffix.lower() in ATTACK_LOG_SUFFIXES or "attack" in path.name.lower()):
            found.append(path)
    return sorted(found)

def looks_like_log_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS or path.suffix.lower() == ".journal":
        return True
    name = path.name.lower()
    keywords = ("syslog", "messages", "audit", "suricata", "eve", "journal", "docker", "container")
    return any(k in name for k in keywords)

def discover_log_files(root: Path, attack_root: Optional[Path], log_types: Optional[list[LogTypeRule]] = None) -> list[Path]:
    found: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if attack_root and attack_root.resolve() in path.resolve().parents:
            continue
        if (matching_log_type(path, log_types) is not None if log_types is not None else looks_like_log_file(path)):
            found.append(path)
    return sorted(found)
