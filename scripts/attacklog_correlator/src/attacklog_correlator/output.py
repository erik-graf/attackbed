"""Stable result serialization, saved-output loading and versioned run history."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any
from typing import Optional

from attacklog_correlator.config import ConfigBundle, MAX_TIME_DELTA_SECONDS, write_generated_config
from attacklog_correlator.correlation import correlations_by_host
from attacklog_correlator.ingestion.timestamps import parse_iso_datetime
from attacklog_correlator.metadata import __version__
from attacklog_correlator.models import Attack, Correlation, LogEvent, RunStats, UTC


def attack_summary_row(attack: Attack) -> dict[str, Any]:
    return {
        "attack_id": attack.attack_id,
        "timestamp": attack.timestamp.isoformat(),
        "type": attack.attack_type,
        "cmd": attack.cmd,
        "source_file": attack.source_file,
        "line_number": attack.line_number,
        "raw_line": attack.raw_line,
        "attacker_host": attack.attacker_host,
        "metadata": attack.metadata,
        "target_ips": attack.target_ips,
        "target_networks": attack.target_networks,
        "target_tokens": attack.target_tokens,
        "target_hosts": attack.target_hosts,
    }

def event_summary_row(event: LogEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "raw_timestamp": event.raw_timestamp,
        "host": event.host,
        "source_type": event.source_type,
        "file_path": event.file_path,
        "line_number": event.line_number,
        "message": event.message,
        "candidate_hosts": event.candidate_hosts,
        "candidate_ips": event.candidate_ips,
        "extra": event.extra,
    }

def correlation_row(c: Correlation) -> dict[str, Any]:
    return {
        "correlation_id": c.correlation_id,
        "attack_id": c.attack_id,
        "event_id": c.event_id,
        "attacker_host": getattr(c, "attacker_host", ""),
        "attack_time": c.attack_time.isoformat(),
        "event_time": c.event_time.isoformat(),
        "delta_seconds": c.delta_seconds,
        "abs_delta_seconds": c.abs_delta_seconds,
        "host": c.host,
        "attack_type": c.attack_type,
        "attack_cmd": c.attack_cmd,
        "attacker_host": getattr(c, "attacker_host", ""),
        "attack_targets": c.attack_targets,
        "target_host_matches": c.target_host_matches,
        "event_source_type": c.event_source_type,
        "event_message": c.event_message,
        "score": c.score,
        "score_breakdown": c.score_breakdown,
        "matched_lexical_terms": getattr(c, "matched_lexical_terms", []),
        "matched_command_terms": getattr(c, "matched_command_terms", []),
        "matched_metadata_terms": getattr(c, "matched_metadata_terms", []),
        "attack_file": c.attack_file,
        "attack_line": c.attack_line,
        "attack_raw_line": c.attack_raw_line,
        "event_file": c.event_file,
        "event_line": c.event_line,
    }

def _as_list(value: Any) -> list[Any]:
    """Normalize JSON fields that should be lists when loading saved output."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]

def _parse_saved_datetime(value: Any) -> dt.datetime:
    """Parse saved ISO timestamps from correlations.json back into datetime objects."""
    if isinstance(value, dt.datetime):
        parsed = value
    else:
        parsed = parse_iso_datetime(str(value))
    if not parsed:
        return dt.datetime.fromtimestamp(0, tz=UTC)
    return parsed.astimezone(UTC)

def attack_from_saved_row(row: dict[str, Any]) -> Attack:
    """Recreate an Attack object from the exported correlations.json attack row."""
    return Attack(
        attack_id=str(row.get("attack_id", "")),
        timestamp=_parse_saved_datetime(row.get("timestamp")),
        attack_type=str(row.get("type", row.get("attack_type", "unknown"))),
        cmd=str(row.get("cmd", row.get("attack_cmd", ""))),
        source_file=str(row.get("source_file", row.get("attack_file", ""))),
        line_number=int(row.get("line_number", row.get("attack_line", 0)) or 0),
        metadata=row.get("metadata", {}) if isinstance(row.get("metadata", {}), dict) else {},
        raw_line=str(row.get("raw_line", row.get("attack_raw_line", ""))),
        target_hosts=[str(x) for x in _as_list(row.get("target_hosts"))],
        target_ips=[str(x) for x in _as_list(row.get("target_ips"))],
        target_networks=[str(x) for x in _as_list(row.get("target_networks"))],
        target_tokens=[str(x) for x in _as_list(row.get("target_tokens"))],
        attacker_host=str(row.get("attacker_host", "unknown-attacker")),
    )

def correlation_from_saved_row(row: dict[str, Any]) -> Correlation:
    """Recreate a Correlation object from the exported correlations.json row."""
    breakdown = row.get("score_breakdown", {})
    if isinstance(breakdown, str):
        try:
            breakdown = json.loads(breakdown)
        except Exception:
            breakdown = {}
    if not isinstance(breakdown, dict):
        breakdown = {}
    return Correlation(
        correlation_id=str(row.get("correlation_id", "")),
        attack_id=str(row.get("attack_id", "")),
        event_id=str(row.get("event_id", "")),
        attacker_host=str(row.get("attacker_host", "unknown-attacker")),
        attack_time=_parse_saved_datetime(row.get("attack_time")),
        event_time=_parse_saved_datetime(row.get("event_time")),
        delta_seconds=float(row.get("delta_seconds", 0.0) or 0.0),
        abs_delta_seconds=float(row.get("abs_delta_seconds", abs(float(row.get("delta_seconds", 0.0) or 0.0))) or 0.0),
        attack_file=str(row.get("attack_file", "")),
        attack_line=int(row.get("attack_line", 0) or 0),
        attack_raw_line=str(row.get("attack_raw_line", "")),
        event_file=str(row.get("event_file", "")),
        event_line=int(row.get("event_line", 0) or 0),
        host=str(row.get("host", "unknown-host")),
        attack_type=str(row.get("attack_type", "unknown")),
        attack_cmd=str(row.get("attack_cmd", "")),
        attack_targets=[str(x) for x in _as_list(row.get("attack_targets"))],
        target_host_matches=[str(x) for x in _as_list(row.get("target_host_matches"))],
        event_message=str(row.get("event_message", "")),
        event_source_type=str(row.get("event_source_type", "")),
        score=float(row.get("score", 0.0) or 0.0),
        score_breakdown={str(k): float(v) for k, v in breakdown.items() if isinstance(v, (int, float))},
        matched_lexical_terms=[str(x) for x in _as_list(row.get("matched_lexical_terms"))],
        matched_command_terms=[str(x) for x in _as_list(row.get("matched_command_terms"))],
        matched_metadata_terms=[str(x) for x in _as_list(row.get("matched_metadata_terms"))],
    )

def load_existing_outputs(out_dir: Path) -> tuple[list[Attack], list[Correlation], dict[str, Any]]:
    """Load previously computed correlations from out_dir/correlations.json.

    This supports a UI-only review mode that skips attack/log discovery, parsing,
    scoring, and export.  The browser only needs Attack and Correlation objects,
    so those are reconstructed from the saved JSON rows.
    """
    path = out_dir / "correlations.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected object in {path}")
    attacks = [attack_from_saved_row(x) for x in data.get("attacks", []) if isinstance(x, dict)]
    correlations = [correlation_from_saved_row(x) for x in data.get("correlations", []) if isinstance(x, dict)]
    known_attack_ids = {a.attack_id for a in attacks}
    for c in correlations:
        if c.attack_id not in known_attack_ids:
            attacks.append(
                Attack(
                    attack_id=c.attack_id,
                    timestamp=c.attack_time,
                    attack_type=c.attack_type,
                    cmd=c.attack_cmd,
                    source_file=c.attack_file,
                    line_number=c.attack_line,
                    metadata={},
                    raw_line=c.attack_raw_line,
                    attacker_host=c.attacker_host,
                )
            )
            known_attack_ids.add(c.attack_id)
    return sorted(attacks, key=lambda a: a.timestamp), correlations, data.get("summary", {}) if isinstance(data.get("summary", {}), dict) else {}

def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

def write_correlation_csv(path: Path, correlations: list[Correlation]) -> None:
    fieldnames = [
        "correlation_id", "attack_id", "event_id", "attacker_host", "attack_time", "event_time", "delta_seconds",
        "abs_delta_seconds", "host", "attack_type", "attack_cmd", "attack_targets", "target_host_matches",
        "event_source_type", "event_message", "score", "score_breakdown", "matched_lexical_terms", "matched_command_terms", "matched_metadata_terms", "attack_file", "attack_line",
        "attack_raw_line", "event_file", "event_line",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        # extrasaction="ignore" protects the CSV writer if correlation_row()
        # contains fields not listed in fieldnames.
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for c in correlations:
            try:
                row = correlation_row(c)
                row["attack_targets"] = ";".join(str(x) for x in row.get("attack_targets", []))
                row["target_host_matches"] = ";".join(str(x) for x in row.get("target_host_matches", []))
                row["score_breakdown"] = json.dumps(row.get("score_breakdown", {}), ensure_ascii=False, sort_keys=True)
                row["matched_lexical_terms"] = ";".join(str(x) for x in row.get("matched_lexical_terms", []))
                row["matched_command_terms"] = ";".join(str(x) for x in row.get("matched_command_terms", []))
                row["matched_metadata_terms"] = ";".join(str(x) for x in row.get("matched_metadata_terms", []))
                row["attack_raw_line"] = str(row.get("attack_raw_line", "")).replace(chr(0), "")
                row["event_message"] = str(row.get("event_message", "")).replace(chr(0), "")
                writer.writerow(row)
            except Exception as exc:
                print(f"[warn] failed to write correlation row for {getattr(c, 'correlation_id', '<unknown>')}: {exc}", file=sys.stderr)
                continue

def write_human_summary(path: Path, attacks: list[Attack], correlations: list[Correlation]) -> None:
    by_attack: dict[str, list[Correlation]] = defaultdict(list)
    for c in correlations:
        by_attack[c.attack_id].append(c)

    for attack_id in by_attack:
        by_attack[attack_id].sort(key=lambda c: (-c.score, c.abs_delta_seconds, c.host, c.event_file, c.event_line))

    with path.open("w", encoding="utf-8") as fh:
        for idx, attack in enumerate(sorted(attacks, key=lambda a: a.timestamp), start=1):
            fh.write(f"Attack step {idx}\n")
            fh.write(f"  Time:   {attack.timestamp.isoformat()}\n")
            fh.write(f"  Type:   {attack.attack_type}\n")
            fh.write(f"  Source: {attack.source_file}:{attack.line_number}\n")
            fh.write(f"  Attacker: {attack.attacker_host}\n")
            fh.write(f"  Cmd:    {attack.cmd}\n")
            fh.write(f"  Attack: {attack.raw_line.replace(chr(0), '').strip()}\n\n")

            rows = by_attack.get(attack.attack_id, [])
            if not rows:
                fh.write("  No correlated host log entries found.\n\n")
                fh.write("-" * 100 + "\n\n")
                continue

            for c in rows:
                event_msg = (c.event_message or "").replace(chr(0), "").replace("\n", " ").replace("\r", " ").strip()
                fh.write(
                    f"  Host={c.host}  File={c.event_file}  Line={c.event_line}  "
                    f"Delta={c.delta_seconds:.3f}s  Score={c.score:.2f}\n"
                )
                fh.write(f"    Log: {event_msg}\n")
            fh.write("\n" + "-" * 100 + "\n\n")

def export_outputs(
    out_dir: Path, config: ConfigBundle, attacks: list[Attack],
    events: list[LogEvent], correlations: list[Correlation],
    processed_event_count: Optional[int] = None, *, stats: Optional[RunStats] = None,
    max_time_delta: float = MAX_TIME_DELTA_SECONDS,
) -> None:
    if stats is None:
        stats = RunStats()
    event_count = len(events) if processed_event_count is None else processed_event_count
    out_dir.mkdir(parents=True, exist_ok=True)
    write_generated_config(out_dir / "host_config.generated.json", config)
    matched_event_ids = {c.event_id for c in correlations}
    write_json(
        out_dir / "correlations.json",
        {
            "summary": {
                "attack_count": len(attacks),
                "event_count": event_count,
                "candidate_event_count": len(events),
                "correlation_count": len(correlations),
                "unparsable_lines": stats.unparsable_lines,
                "journalctl_converted_files": stats.journalctl_converted_files,
                "binary_log_files_skipped": stats.binary_log_files_skipped,
                "created_at": dt.datetime.now(tz=UTC).isoformat(),
            },
            "attacks": [attack_summary_row(a) for a in attacks],
            "events": [event_summary_row(e) for e in events if e.event_id in matched_event_ids],
            "correlations": [correlation_row(c) for c in correlations],
        },
    )
    write_correlation_csv(out_dir / "correlations.csv", correlations)
    write_human_summary(out_dir / "correlations_human.txt", attacks, correlations)

    # Per-host exports let an analyst inspect evidence host by host instead of
    # reading one global correlation file.
    grouped = correlations_by_host(correlations)
    per_host_dir = out_dir / "per_host"
    per_host_dir.mkdir(exist_ok=True)
    host_summary = {}

    for host, rows in grouped.items():
        host_dir = per_host_dir / host
        host_dir.mkdir(parents=True, exist_ok=True)
        write_json(
            host_dir / "correlations.json",
            {
                "host": host,
                "correlation_count": len(rows),
                "correlations": [correlation_row(c) for c in rows],
            },
        )
        write_correlation_csv(host_dir / "correlations.csv", rows)
        relevant_attack_ids = {c.attack_id for c in rows}
        write_human_summary(host_dir / "correlations_human.txt", [a for a in attacks if a.attack_id in relevant_attack_ids], rows)
        host_summary[host] = {"correlation_count": len(rows)}

    write_json(
        out_dir / "summary.json",
        {
            "attacks": len(attacks),
            "events": event_count,
            "candidate_events": len(events),
            "correlations": len(correlations),
            "unparsable_lines": stats.unparsable_lines,
            "journalctl_converted_files": stats.journalctl_converted_files,
            "binary_log_files_skipped": stats.binary_log_files_skipped,
            "per_host": host_summary,
            "created_at": dt.datetime.now(tz=UTC).isoformat(),
            "max_time_delta_seconds": max_time_delta,
        },
    )

def append_run_history(path: Path, summary_path: Path, args: argparse.Namespace) -> None:
    """Append a pretty-printed JSON object, separated from previous runs."""
    try:
        result = subprocess.run(
            ["git", "-C", str(Path(__file__).resolve().parent), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False,
        )
        revision = result.stdout.strip() if result.returncode == 0 else None
    except OSError:
        revision = None

    entry = {
        "correlator_version": __version__,
        "git_revision": revision,
        "source_sha256": package_source_sha256(),
        "settings": {
            "root": str(Path(args.root).expanduser().resolve()),
            "host_config": args.host_config,
            "default_timezone": args.default_timezone,
            "default_year": args.default_year,
            "window_before": args.window_before,
            "window_after": args.window_after,
            "max_time_delta": args.max_time_delta,
            "max_per_attack": args.max_per_attack,
            "process_untimestamped_lines": args.process_untimestamped_lines,
        },
        "summary": json.loads(summary_path.read_text(encoding="utf-8")),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        separator = "\n" if fh.tell() else ""
        fh.write(separator + json.dumps(entry, indent=2, ensure_ascii=False) + "\n")

def package_source_sha256(package_dir: Optional[Path] = None) -> str:
    """Hash all runtime Python sources, including paths, in deterministic order."""
    package_dir = Path(__file__).resolve().parent if package_dir is None else package_dir
    digest = hashlib.sha256()
    for path in sorted(package_dir.rglob("*.py")):
        name = path.relative_to(package_dir).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()
