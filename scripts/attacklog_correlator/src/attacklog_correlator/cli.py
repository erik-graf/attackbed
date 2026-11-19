"""Command-line arguments and orchestration."""

from __future__ import annotations

if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "attacklog_correlator"

import argparse
import json
import sys
import traceback
from pathlib import Path

from attacklog_correlator.attacks import load_all_attacks
from attacklog_correlator.config import (
    CURRENT_YEAR_FALLBACK,
    HostResolver,
    MAX_TIME_DELTA_SECONDS,
    discover_hosts_from_logs,
    guess_attacker_host_from_path,
    load_config,
)
from attacklog_correlator.correlation import correlate
from attacklog_correlator.events import load_all_events
from attacklog_correlator.ingestion.discovery import discover_attack_files, discover_log_files
from attacklog_correlator.ingestion.logtypes import load_log_types
from attacklog_correlator.models import RunStats
from attacklog_correlator.output import append_run_history, export_outputs, load_existing_outputs


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Correlate attack logs against heterogeneous host logs.")
    p.add_argument(
        "--root",
        required=True,
        help="Working directory containing attacklogs, hostlogs, and output subdirectories",
    )
    p.add_argument(
        "--view-existing",
        action="store_true",
        help="Load out-dir/correlations.json and open the browser without recomputing correlations",
    )
    p.add_argument("--host-config", help="Optional JSON config for host timezones, skew, aliases, and IPs")
    p.add_argument("--strict", action="store_true",
                   help="Only read filenames matched by log-type rules; no automatic timestamp parser fallback")
    p.add_argument("--log-config", help="JSON filename rules for --strict (default: bundled logtypes.json)")
    p.add_argument("--default-timezone", default="Europe/Vienna", help="Default timezone for naive host logs")
    p.add_argument("--window-before", type=float, help="Seconds before attack to include")
    p.add_argument("--window-after", type=float, help="Seconds after attack to include")
    p.add_argument(
        "--max-time-delta",
        type=float,
        default=MAX_TIME_DELTA_SECONDS,
        help=(
            "Strict maximum absolute timestamp difference, in seconds, for timestamped "
            "attack/event pairs before content scoring is attempted. Default: %(default)s"
        ),
    )
    p.add_argument("--max-per-attack", type=int, default=30, help="Maximum saved correlations per attack")
    p.add_argument("--default-year", type=int, default=CURRENT_YEAR_FALLBACK, help="Fallback year for yearless timestamps")
    p.add_argument(
        "--process-untimestamped-lines",
        action="store_true",
        help="Also load log lines with no parseable timestamp for content-only scoring; slower on noisy logs",
    )
    p.add_argument(
        "--history", nargs="?", const="run-history.jsonl", metavar="FILE",
        help="Append version, settings and summary.json to FILE (default: <root>/run-history.jsonl)",
    )
    p.add_argument("--manual", action="store_true", help="Browse and manually mark log lines without automatic correlation")
    p.add_argument("--include-auto", action="store_true",
                   help="With --manual, load automatic correlations (from --view-existing or a fresh run)")
    p.add_argument("--no-ui", action="store_true", help="Write outputs only")
    return p.parse_args()

def ensure_work_dirs(root: Path) -> tuple[Path, Path, Path]:
    """
    Ensure the standard correlator working directories exist below root.

    Returns:
        (attacklogs_dir, hostlogs_dir, output_dir)
    """
    root = root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    attacklogs_dir = root / "attacklogs"
    hostlogs_dir = root / "hostlogs"
    output_dir = root / "output"

    for directory in (attacklogs_dir, hostlogs_dir, output_dir):
        directory.mkdir(parents=True, exist_ok=True)

    return attacklogs_dir, hostlogs_dir, output_dir

def main() -> int:

    args = parse_args()
    # Automatic correlation retains its 60s/240s defaults; manual review starts at 0s/+30s.
    manual_before = 0.0 if args.window_before is None else args.window_before
    manual_after = 30.0 if args.window_after is None else args.window_after
    args.window_before = 60.0 if args.window_before is None else args.window_before
    args.window_after = 240.0 if args.window_after is None else args.window_after
    if args.max_time_delta < 0 or args.window_before < 0 or args.window_after < 0 or args.max_per_attack <= 0:
        print("[error] time limits must be non-negative and --max-per-attack must be positive", file=sys.stderr)
        return 2

    if args.manual and args.no_ui:
        print("[error] --manual cannot be combined with --no-ui", file=sys.stderr)
        return 2
    if args.include_auto and not args.manual:
        print("[error] --include-auto requires --manual", file=sys.stderr)
        return 2

    if args.log_config and not args.strict:
        print("[error] --log-config requires --strict", file=sys.stderr)
        return 2
    attack_root, log_root, out_dir = ensure_work_dirs(Path(args.root))
    host_config_path = Path(args.host_config).expanduser().resolve() if args.host_config else None
    history_path = Path(args.history).expanduser() if args.history is not None else None
    if history_path is not None:
        if not history_path.is_absolute():
            history_path = out_dir.parent / history_path
        if history_path.suffix.lower() != ".jsonl":
            print("[error] --history must point to a .jsonl file, not an existing JSON/CSV report", file=sys.stderr)
            return 2
        if history_path.resolve() == (out_dir / "summary.json").resolve():
            print("[error] --history cannot append to output/summary.json", file=sys.stderr)
            return 2


    if args.view_existing and not args.manual:
        attacks, correlations, saved_summary = load_existing_outputs(out_dir)
        summary = {
            "mode": "view-existing",
            "attacks": len(attacks),
            "correlations": len(correlations),
            "out_dir": str(out_dir),
            "loaded_from": str(out_dir / "correlations.json"),
            "saved_summary": saved_summary,
        }
        print(json.dumps(summary, indent=2))
        if not args.no_ui:
            try:
                from .tui import CorrelationBrowser
                CorrelationBrowser(attacks, correlations).run()
            except Exception:
                print("[error] curses UI crashed", file=sys.stderr)
                traceback.print_exc()
        return 0

    log_types = None
    if args.strict:
        try:
            log_types = load_log_types(Path(args.log_config).expanduser() if args.log_config else None)
        except (OSError, ValueError) as exc:
            print(f"[error] failed to load log-type rules: {exc}", file=sys.stderr)
            return 2

    # First infer host/attacker names from file layout.  The optional config
    # loaded next can correct or enrich these guesses.
    discovered_hosts = discover_hosts_from_logs(log_root, attack_root, args.default_timezone, log_types)
    discovered_attacker_hosts = sorted({guess_attacker_host_from_path(p, attack_root) for p in discover_attack_files(attack_root)})
    config = load_config(host_config_path, discovered_hosts, args.default_timezone)

    # ConfigBundle compatibility: enrich the underlying raw config dict if present.
    raw_cfg = getattr(config, "raw_config", None)
    if not isinstance(raw_cfg, dict):
        raw_cfg = {}
        try:
            config.raw_config = raw_cfg
        except Exception:
            pass

    raw_cfg.setdefault("attacker_hosts", {})
    raw_cfg.setdefault("default_attacker_timezone", "UTC")
    raw_cfg.setdefault("default_utc_offset_hours", 0)
    for attacker in discovered_attacker_hosts:
        raw_cfg["attacker_hosts"].setdefault(attacker, {
            "timezone": raw_cfg.get("default_attacker_timezone", "UTC"),
            "utc_offset_hours": raw_cfg.get("default_utc_offset_hours", 0),
            "notes": "Set timezone to UTC, Europe/Vienna, etc.; utc_offset_hours is an additional legacy correction",
        })

    resolver = HostResolver(config)

    # Manual review is a browsing tool by default; correlation is opt-in.
    if args.view_existing:
        try:
            attacks, saved_correlations, _ = load_existing_outputs(out_dir)
        except (OSError, ValueError) as exc:
            print(f"[error] cannot load saved correlations: {exc}", file=sys.stderr)
            return 1
        correlations = saved_correlations if args.include_auto else []
        events = []
    else:
        attacks = load_all_attacks(attack_root, resolver, config=config)
        correlations = []
        events = []
        if not args.manual or args.include_auto:
            stats = RunStats()
            events = load_all_events(
                log_root, attack_root, args.default_year, resolver,
                include_untimestamped=args.process_untimestamped_lines,
                attacks=attacks, window_before=args.window_before,
                window_after=args.window_after, stats=stats,
                max_time_delta=args.max_time_delta, log_types=log_types,
            )
            correlations = correlate(
                attacks, events, args.window_before, args.window_after,
                args.max_per_attack, max_time_delta=args.max_time_delta,
            )
            export_outputs(out_dir, config, attacks, events, correlations,
                           processed_event_count=stats.parsed_events,
                           stats=stats, max_time_delta=args.max_time_delta)
            if history_path is not None:
                try:
                    append_run_history(history_path, out_dir / "summary.json", args)
                except OSError as exc:
                    print(f"[error] failed to append run history: {exc}", file=sys.stderr)
                    return 1

    if args.manual:
        print(json.dumps({
            "mode": "manual",
            "attacks": len(attacks),
            "automatic_correlations": len(correlations),
            "source": "saved" if args.view_existing else ("computed" if args.include_auto else "manual-only"),
            "log_root": str(log_root),
            "out_dir": str(out_dir),
        }, indent=2))
    else:
        summary = {
            "attacks": len(attacks),
            "events": stats.parsed_events,
            "candidate_events": len(events),
            "correlations": len(correlations),
            "unparsable_lines": stats.unparsable_lines,
            "journalctl_converted_files": stats.journalctl_converted_files,
            "binary_log_files_skipped": stats.binary_log_files_skipped,
            "untimestamped_lines_loaded": args.process_untimestamped_lines,
            "strict": args.strict,
            "log_config": str(Path(args.log_config).expanduser().resolve()) if args.log_config else None,
            "attack_root": str(attack_root),
            "log_root": str(log_root),
            "out_dir": str(out_dir),
            "host_config": str(host_config_path) if host_config_path else None,
            "generated_host_config": str(out_dir / "host_config.generated.json"),
        }
        print(json.dumps(summary, indent=2))

    if args.manual:
        try:
            from .manual import ManualBrowser
            browser = ManualBrowser(
                attacks, discover_log_files(log_root, attack_root, log_types),
                correlations, events, log_root, resolver, args.default_year,
                manual_before, manual_after, out_dir, log_types,
            )
            print(f"[manual] selections written to {browser.run()}")
        except Exception:
            print("[error] manual review UI failed", file=sys.stderr)
            traceback.print_exc()
            return 1
    elif not args.no_ui:
        try:
            from .tui import CorrelationBrowser
            CorrelationBrowser(attacks, correlations).run()
        except Exception:
            print("[error] curses UI crashed", file=sys.stderr)
            traceback.print_exc()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
