from attacklog_correlator import config as config_module
from attacklog_correlator import events as events_module
from attacklog_correlator.ingestion import timestamps as ingestion_timestamps_module
from attacklog_correlator import models as models_module
import datetime as dt
import json
from pathlib import Path



def test_naive_iso_host_log_uses_host_timezone(tmp_path: Path):
    root = tmp_path / "hostlogs"
    path = root / "target" / "syslog"
    path.parent.mkdir(parents=True)
    path.write_text("2026-05-27T13:01:57 target process started\n", encoding="utf-8")
    config = config_module.ConfigBundle("Europe/Vienna", 0.0, {"target": config_module.HostProfile("target", "Europe/Vienna")})
    events = events_module.load_log_file(path, root, 2026, config_module.HostResolver(config))
    assert len(events) == 1
    assert events[0].timestamp == dt.datetime(2026, 5, 27, 11, 1, 57, tzinfo=models_module.UTC)


def test_naive_json_host_log_uses_host_timezone(tmp_path: Path):
    root = tmp_path / "hostlogs"
    path = root / "target" / "events.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"timestamp": "2026-05-27T13:01:57", "message": "process started"}) + "\n", encoding="utf-8")
    config = config_module.ConfigBundle("Europe/Vienna", 0.0, {"target": config_module.HostProfile("target", "Europe/Vienna")})
    events = events_module.load_log_file(path, root, 2026, config_module.HostResolver(config))
    assert len(events) == 1
    assert events[0].timestamp == dt.datetime(2026, 5, 27, 11, 1, 57, tzinfo=models_module.UTC)


def test_explicit_offset_stays_authoritative():
    parsed = ingestion_timestamps_module.parse_json_line_timestamp('{"timestamp":"2026-05-27T13:01:57Z"}', 2026)
    assert parsed is not None and not parsed.naive
    assert parsed.timestamp_utc == dt.datetime(2026, 5, 27, 13, 1, 57, tzinfo=models_module.UTC)


def test_default_clock_skew_applies_unless_overridden(tmp_path: Path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "default_clock_skew_seconds": 5,
        "hosts": {"explicit": {"clock_skew_seconds": 0}},
    }), encoding="utf-8")
    discovered = {name: config_module.HostProfile(name, "UTC") for name in ("explicit", "discovered")}
    resolver = config_module.HostResolver(config_module.load_config(path, discovered, "UTC"))
    assert resolver.resolve_clock_skew("explicit") == 0
    assert resolver.resolve_clock_skew("discovered") == 5
    assert resolver.resolve_clock_skew("unknown") == 5
