import datetime as dt

from attacklog_correlator import cli

NOW = dt.datetime(2026, 5, 27, 12, tzinfo=cli.UTC)


def attack(cmd: str, **kwargs) -> cli.Attack:
    return cli.Attack(
        attack_id="a", timestamp=NOW, attack_type="execution",
        cmd=cmd, source_file="attack.jsonl", line_number=1,
        metadata={}, raw_line=cmd, **kwargs,
    )


def event(text: str, seconds_after: float = 0) -> cli.LogEvent:
    return cli.LogEvent(
        event_id="e", timestamp=NOW + dt.timedelta(seconds=seconds_after),
        raw_timestamp="", host="target", source_type="syslog-like",
        file_path="syslog", line_number=1, message=text, raw_line=text,
        extra={}, candidate_hosts=["target"], candidate_ips=cli.extract_ips(text),
    )


def test_single_executable_is_insufficient_several_seconds_later(monkeypatch):
    monkeypatch.setattr(cli, "MAX_TIME_DELTA_SECONDS", 5.0)
    assert cli.correlate(
        [attack("sleep 5")], [event("sleep process exited", 3)], 60, 240, 30
    ) == []


def test_delayed_command_match_with_target_ip_is_kept(monkeypatch):
    monkeypatch.setattr(cli, "MAX_TIME_DELTA_SECONDS", 5.0)
    rows = cli.correlate(
        [attack("curl http://10.0.0.5/payload.sh", target_ips=["10.0.0.5"])],
        [event("GET /payload.sh from 10.0.0.5", 3)], 60, 240, 30,
    )
    assert len(rows) == 1
    assert "ip_literal_match" in rows[0].score_breakdown


def test_ip_literal_match_does_not_match_longer_address():
    score, breakdown, *_rest = cli.content_overlap_score(
        attack("curl http://10.0.0.5/", target_ips=["10.0.0.5"]),
        event("connection from 10.0.0.50"),
    )
    assert "ip_literal_match" not in breakdown


def test_default_time_cap_covers_second_precision_host_logs():
    assert cli.MAX_TIME_DELTA_SECONDS >= 1
