from attacklog_correlator import correlation as correlation_module
from attacklog_correlator import models as models_module
import datetime as dt


NOW = dt.datetime(2026, 5, 27, 12, 0, 0, tzinfo=models_module.UTC)


def make_attack(cmd: str, metadata: dict | None = None) -> models_module.Attack:
    return models_module.Attack(
        attack_id="attack:1",
        timestamp=NOW,
        attack_type="execution",
        cmd=cmd,
        source_file="attack.jsonl",
        line_number=1,
        metadata=metadata or {},
        raw_line=f'{{"type":"execution","cmd":"{cmd}"}}',
        attacker_host="attacker",
    )


def make_event(message: str) -> models_module.LogEvent:
    return models_module.LogEvent(
        event_id="event:1",
        timestamp=NOW,
        raw_timestamp="2026-05-27T12:00:00Z",
        host="target",
        source_type="generic-text",
        file_path="host.log",
        line_number=1,
        message=message,
        raw_line=message,
        extra={},
        candidate_hosts=["target"],
        candidate_ips=[],
    )


def test_command_token_match_is_recorded_as_command_evidence():
    attack = make_attack("sleep 5")
    event = make_event("systemd[1]: sleep process exited normally")

    score, breakdown, matched, command_matched, metadata_matched = correlation_module.lexical_overlap_score(attack, event)

    assert score > 0
    assert "sleep" in matched
    assert "sleep" in command_matched
    assert metadata_matched == []
    assert "lexical_exact_match" in breakdown or "binary_name_match" in breakdown


def test_metadata_only_match_is_rejected_without_command_match():
    attack = make_attack("sleep 5", metadata={"note": "dhcp"})
    event = make_event("dhcp lease renewed on target")

    score, breakdown, matched, command_matched, metadata_matched = correlation_module.lexical_overlap_score(attack, event)

    assert score == 0
    assert matched == []
    assert command_matched == []
    assert metadata_matched == []
    assert "metadata_lexical_match" not in breakdown


def test_metadata_match_can_support_after_command_match():
    attack = make_attack("sleep 5", metadata={"note": "dhcp"})
    event = make_event("sleep command observed while dhcp lease was renewed")

    score, breakdown, matched, command_matched, metadata_matched = correlation_module.lexical_overlap_score(attack, event)

    assert score > 0
    assert "sleep" in command_matched
    assert "dhcp" in metadata_matched
    assert "dhcp" in matched
    assert "metadata_lexical_match" in breakdown


def test_short_shell_token_does_not_match_inside_shell_word():
    attack = make_attack("sh -c id")
    event = make_event("user opened an interactive shell session")

    score, _breakdown, matched, command_matched, _metadata_matched = correlation_module.lexical_overlap_score(attack, event)

    assert score == 0
    assert matched == []
    assert command_matched == []


def test_json_schema_keys_from_raw_line_are_not_lexical_terms():
    attack = make_attack("sudo nmcli device set wlan1 managed")
    event = make_event("host log contains type and parameters but no command tokens")

    score, _breakdown, matched, _command_matched, _metadata_matched = correlation_module.lexical_overlap_score(attack, event)

    assert "type" not in correlation_module.extract_attack_command_lexical_terms(attack)
    assert "parameters" not in correlation_module.extract_attack_command_lexical_terms(attack)
    assert score == 0
    assert matched == []
