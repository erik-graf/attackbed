import json

import pytest

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


def test_strict_parsing_never_falls_back(tmp_path):
    path = tmp_path / "syslog"
    path.write_text('{"timestamp":"2026-11-18T15:00:00Z"}\nNov 18 15:00:01 host action\n')
    rule = matching_log_type(path, load_log_types())
    assert rule is not None
    strict = list(iter_log_records(path, 2026, log_type=rule))
    automatic = list(iter_log_records(path, 2026))
    assert strict[0].parsed_timestamp is None
    assert automatic[0].parsed_timestamp is not None
    assert strict[1].parsed_timestamp.parser_name == "syslog-like"


def test_custom_filename_patterns_and_timestamp_format(tmp_path):
    config = tmp_path / "types.json"
    config.write_text(json.dumps({"log_types": [
        {"name": "custom", "patterns": ["service-*.txt"], "parser": "regex",
         "timestamp_regex": r"time=(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})",
         "datetime_format": "%Y/%m/%d %H:%M:%S"},
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
        {"name": "custom-json", "patterns": ["app.json"], "parser": "json", "timestamp_key": "when"}
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
        {"name": "bad", "patterns": ["bad.log"], "parser": "regex",
         "timestamp_regex": r"\d{4}", "datetime_format": "%Y"}
    ]}))
    with pytest.raises(ValueError, match="capture group"):
        load_log_types(config)
