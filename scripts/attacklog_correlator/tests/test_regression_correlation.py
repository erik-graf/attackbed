from attacklog_correlator import correlation as correlation_module
from attacklog_correlator import models as models_module
from attacklog_correlator import tokens as tokens_module
import datetime as dt


NOW = dt.datetime(2026, 5, 27, 12, 0, 0, tzinfo=models_module.UTC)


def make_attack(cmd: str = "sleep 5") -> models_module.Attack:
    return models_module.Attack(
        attack_id="attack:1",
        timestamp=NOW,
        attack_type="execution",
        cmd=cmd,
        source_file="attack.jsonl",
        line_number=1,
        metadata={},
        raw_line=f'{{"cmd":"{cmd}"}}',
        target_ips=["10.0.0.5"] if "10.0.0.5" in cmd else [],
        attacker_host="attacker",
    )


def make_event(message: str, seconds_after: float = 0.0) -> models_module.LogEvent:
    return models_module.LogEvent(
        event_id=f"event:{seconds_after}",
        timestamp=NOW + dt.timedelta(seconds=seconds_after),
        raw_timestamp="2026-05-27T12:00:00Z",
        host="target",
        source_type="generic-text",
        file_path="host.log",
        line_number=1,
        message=message,
        raw_line=message,
        extra={},
        candidate_hosts=["target"],
        candidate_ips=tokens_module.extract_ips(message),
    )


def test_time_only_event_is_not_correlated():
    correlations = correlation_module.correlate([make_attack("sleep 5")], [make_event("unrelated system log")], 60, 60, 10)

    assert correlations == []


def test_ip_only_event_is_not_correlated_without_command_match():
    attack = make_attack("curl http://10.0.0.5/payload.sh")
    event = make_event("connection from 10.0.0.5 accepted")

    correlations = correlation_module.correlate([attack], [event], 60, 60, 10)

    assert correlations == []


def test_command_match_creates_correlation_and_records_matched_command_token():
    attack = make_attack("sleep 5")
    event = make_event("audit: comm=\"sleep\" argc=2")

    correlations = correlation_module.correlate([attack], [event], 60, 60, 10)

    assert len(correlations) == 1
    assert "sleep" in correlations[0].matched_command_terms
    assert correlations[0].matched_metadata_terms == []


def test_max_time_delta_explicitly_caps_timestamped_matches():
    attack = make_attack("sleep 5")
    event = make_event("audit: comm=\"sleep\" argc=2", seconds_after=0.5)

    assert correlation_module.correlate([attack], [event], 60, 60, 10, max_time_delta=0.3) == []

    assert len(correlation_module.correlate([attack], [event], 60, 60, 10, max_time_delta=1.0)) == 1
