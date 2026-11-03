from attacklog_correlator import config as config_module
from attacklog_correlator import events as events_module
from attacklog_correlator.ingestion import readers as ingestion_readers_module
from attacklog_correlator import models as models_module
import datetime as dt
from pathlib import Path



def test_binary_probe_only_reads_sample(tmp_path: Path, monkeypatch):
    path = tmp_path / "big.log"
    path.write_bytes(b"\x00" + b"A" * (ingestion_readers_module.BINARY_SAMPLE_BYTES * 2))
    monkeypatch.setattr(Path, "read_bytes", lambda _: b"")
    assert ingestion_readers_module.is_probably_binary_file(path) is True


def test_filter_event_candidates_before_retaining_them(tmp_path: Path, monkeypatch):
    root = tmp_path / "hostlogs"
    path = root / "target" / "syslog"
    path.parent.mkdir(parents=True)
    path.write_text(
        "2026-05-27T12:00:03+00:00 target sleep process started\n"
        "2026-05-27T12:10:00+00:00 target background service started\n",
        encoding="utf-8",
    )
    config = config_module.ConfigBundle("UTC", 0.0, {"target": config_module.HostProfile("target", "UTC")})
    attack = models_module.Attack(
        attack_id="attack", timestamp=dt.datetime(2026, 5, 27, 12, tzinfo=models_module.UTC),
        attack_type="execution", cmd="sleep 5", source_file="attack.jsonl",
        line_number=1, metadata={},
    )
    stats = models_module.RunStats()
    events = events_module.load_all_events(
        root, None, 2026, config_module.HostResolver(config), attacks=[attack],
        window_before=60, window_after=240, stats=stats,
    )
    assert stats.parsed_events == 2
    assert len(events) == 1
    assert events[0].line_number == 1


def test_failed_journal_export_never_returns_partial_results(tmp_path: Path, monkeypatch):
    path = tmp_path / "journal"
    path.write_bytes(b"LPKSHHRH" + b"\x00" * 16)

    def faulty_export(_path):
        yield "2026-05-27T12:00:00Z target sleep"
        raise RuntimeError("truncated journal")

    monkeypatch.setattr(ingestion_readers_module, "run_journalctl_export", faulty_export)
    config = config_module.ConfigBundle("UTC", 0.0, {"target": config_module.HostProfile("target", "UTC")})
    events = events_module.load_log_file(path, tmp_path, 2026, config_module.HostResolver(config))
    assert events == []
