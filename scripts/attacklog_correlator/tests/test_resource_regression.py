import datetime as dt
from pathlib import Path

from attacklog_correlator import cli


def test_binary_probe_only_reads_sample(tmp_path: Path, monkeypatch):
    path = tmp_path / "big.log"
    path.write_bytes(b"\x00" + b"A" * (cli.BINARY_SAMPLE_BYTES * 2))
    monkeypatch.setattr(Path, "read_bytes", lambda _: b"")
    assert cli.is_probably_binary_file(path) is True


def test_filter_event_candidates_before_retaining_them(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(cli, "MAX_TIME_DELTA_SECONDS", 5.0)
    root = tmp_path / "hostlogs"
    path = root / "target" / "syslog"
    path.parent.mkdir(parents=True)
    path.write_text(
        "2026-05-27T12:00:03+00:00 target sleep process started\n"
        "2026-05-27T12:10:00+00:00 target background service started\n",
        encoding="utf-8",
    )
    config = cli.ConfigBundle("UTC", 0.0, {"target": cli.HostProfile("target", "UTC")})
    attack = cli.Attack(
        attack_id="attack", timestamp=dt.datetime(2026, 5, 27, 12, tzinfo=cli.UTC),
        attack_type="execution", cmd="sleep 5", source_file="attack.jsonl",
        line_number=1, metadata={},
    )
    stats = {}
    events = cli.load_all_events(
        root, None, 2026, cli.HostResolver(config), attacks=[attack],
        window_before=60, window_after=240, stats=stats,
    )
    assert stats["parsed_events"] == 2
    assert len(events) == 1
    assert events[0].line_number == 1


def test_failed_journal_export_never_returns_partial_results(tmp_path: Path, monkeypatch):
    path = tmp_path / "journal"
    path.write_bytes(b"LPKSHHRH" + b"\x00" * 16)

    def faulty_export(_path):
        yield "2026-05-27T12:00:00Z target sleep"
        raise RuntimeError("truncated journal")

    monkeypatch.setattr(cli, "run_journalctl_export", faulty_export)
    config = cli.ConfigBundle("UTC", 0.0, {"target": cli.HostProfile("target", "UTC")})
    events = cli.load_log_file(path, tmp_path, 2026, cli.HostResolver(config))
    assert events == []
