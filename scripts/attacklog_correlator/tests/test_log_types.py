import json
from pathlib import Path

import pytest

from attacklog_correlator import cli
from attacklog_correlator.ingestion.discovery import discover_log_files
from attacklog_correlator.ingestion.logtypes import load_log_types, matching_log_type
from attacklog_correlator.ingestion.readers import iter_log_records


def test_strict_discovery_matches_log_types_across_hosts(tmp_path):
    for name in ("first/syslog", "second/syslog.1", "third/audit.log", "fourth/unlisted.log", "fifth/syslog.1.gz"):
        path = tmp_path / name
        path.parent.mkdir()
        path.write_text("", encoding="utf-8")

    rules = load_log_types()
    configured = discover_log_files(tmp_path, None, rules)
    assert {p.name for p in configured} == {"syslog", "syslog.1", "audit.log"}
    assert {p.name for p in discover_log_files(tmp_path, None)} == {
        "syslog", "syslog.1", "audit.log", "unlisted.log", "syslog.1.gz"
    }


@pytest.mark.parametrize("filename,line,timestamp,naive", [
    ("syslog", "Nov 18 15:03:21 host sshd: test", "2026-11-18T15:03:21+00:00", True),
    ("syslog.1", "Nov 18 15:03:21.123456 host sshd: test", "2026-11-18T15:03:21.123456+00:00", True),
    ("syslog", "2026-11-18T15:03:21+01:00 host sshd: test", "2026-11-18T14:03:21+00:00", False),
    ("auth.log", "2026-11-18T15:03:21Z host sshd: test", "2026-11-18T15:03:21+00:00", False),
    ("audit.log", "type=SYSCALL msg=audit(1795014201.123:12): action", "2026-11-18T15:03:21.123000+00:00", False),
    ("access.log", '127.0.0.1 - - [18/Nov/2026:15:03:21 +0100] "GET /"', "2026-11-18T14:03:21+00:00", False),
    ("suricata.log", "18/11/2026 -- 15:03:21 alert", "2026-11-18T15:03:21+00:00", True),
    ("suricata.log", "18/11/26 -- 15:03:21 alert", "2026-11-18T15:03:21+00:00", True),
    ("eve.json", '{"timestamp":"2026-11-18T15:03:21Z"}', "2026-11-18T15:03:21+00:00", False),
    ("abc-json.log", '{"time":"2026-11-18T15:03:21Z"}', "2026-11-18T15:03:21+00:00", False),
    ("abc.journal", "2026-11-18T15:03:21.123456+01:00 host systemd[1]: hi", "2026-11-18T14:03:21.123456+00:00", False),
])
def test_bundled_timestamp_formats(filename, line, timestamp, naive):
    rule = matching_log_type(Path(filename), load_log_types())
    assert rule is not None
    parsed = rule.parse_timestamp(line, 2026)
    assert parsed is not None
    assert parsed.timestamp_utc.isoformat() == timestamp
    assert parsed.naive == naive


def test_strict_parsing_never_falls_back(tmp_path):
    path = tmp_path / "syslog"
    path.write_text('{"timestamp":"2026-11-18T15:00:00Z"}\nNov 18 15:00:01 host action\n')
    rule = matching_log_type(path, load_log_types())
    assert rule is not None
    strict = list(iter_log_records(path, 2026, log_type=rule))
    automatic = list(iter_log_records(path, 2026))
    assert strict[0].parsed_timestamp is None
    assert automatic[0].parsed_timestamp is not None
    assert strict[1].parsed_timestamp.parser_name == "regex:syslog"


def test_custom_filename_patterns_and_timestamp_format(tmp_path):
    config = tmp_path / "types.json"
    config.write_text(json.dumps({"log_types": [
        {"name": "custom", "patterns": ["service-*.txt"], "timestamps": [
            {"regex": r"time=(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})",
             "format": "%Y/%m/%d %H:%M:%S"}
        ]},
    ]}))
    path = tmp_path / "host" / "service-main.txt"
    path.parent.mkdir()
    path.write_text("time=2026/11/18 15:00:01 ready\n")
    rule = matching_log_type(path, load_log_types(config))
    assert rule is not None
    record = next(iter_log_records(path, 2026, log_type=rule))
    assert record.parsed_timestamp.timestamp_utc.isoformat() == "2026-11-18T15:00:01+00:00"
    assert record.parsed_timestamp.naive is True
    assert record.parsed_timestamp.parser_name == "regex:custom"


def test_configured_json_timestamp_key(tmp_path):
    config = tmp_path / "types.json"
    config.write_text(json.dumps({"log_types": [
        {"name": "custom-json", "patterns": ["app.json"], "timestamp_key": "when"}
    ]}))
    path = tmp_path / "app.json"
    path.write_text('{"when":"2026-11-18T15:00:01Z","msg":"hello"}\n')
    rule = matching_log_type(path, load_log_types(config))
    assert rule is not None
    record = next(iter_log_records(path, 2026, log_type=rule))
    assert record.parsed_timestamp.timestamp_utc.isoformat() == "2026-11-18T15:00:01+00:00"
    assert next(iter_log_records(path, 2026)).parsed_timestamp is None


def test_invalid_config_fails_early(tmp_path):
    config = tmp_path / "bad.json"
    config.write_text(json.dumps({"log_types": [
        {"name": "bad", "patterns": ["bad.log"], "timestamps": [
            {"regex": r"\d{4}", "format": "%Y"}
        ]}
    ]}))
    with pytest.raises(ValueError, match="capture group"):
        load_log_types(config)


def test_cli_strict_flag_names(monkeypatch):
    monkeypatch.setattr("sys.argv", ["attacklog-correlator", "--root", "work", "--strict", "--log-config", "types.json"])
    args = cli.parse_args()
    assert args.strict is True
    assert args.log_config == "types.json"
    monkeypatch.setattr("sys.argv", ["attacklog-correlator", "--root", "work"])
    assert cli.parse_args().strict is False
