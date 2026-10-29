import dataclasses
import datetime as dt
import json
from pathlib import Path

from attacklog_correlator import cli


def test_export_only_keeps_matched_events(tmp_path: Path):
    now = dt.datetime(2026, 5, 27, 12, tzinfo=cli.UTC)
    attack = cli.Attack(
        attack_id="attack:1", timestamp=now, attack_type="execution",
        cmd="sleep 5", source_file="attack.jsonl", line_number=1,
        metadata={}, raw_line='{"cmd":"sleep 5"}',
    )
    matched = cli.LogEvent(
        event_id="event:matched", timestamp=now, raw_timestamp="",
        host="target", source_type="auditd", file_path="host.log",
        line_number=1, message='comm="sleep"', raw_line='comm="sleep"',
        extra={}, candidate_hosts=["target"], candidate_ips=[],
    )
    unrelated = dataclasses.replace(
        matched, event_id="event:unrelated", line_number=2,
        message="unrelated system activity", raw_line="unrelated system activity",
    )
    other_attack = dataclasses.replace(
        attack, attack_id="attack:other", cmd="echo harmless",
        line_number=2, raw_line='{"cmd":"echo harmless"}',
    )
    correlations = cli.correlate([attack, other_attack], [matched, unrelated], 60, 60, 30)
    assert [c.event_id for c in correlations] == [matched.event_id]

    config = cli.ConfigBundle(default_timezone="UTC", default_clock_skew_seconds=0, hosts={})
    cli.export_outputs(tmp_path, config, [attack, other_attack], [matched, unrelated], correlations)
    saved = json.loads((tmp_path / "correlations.json").read_text(encoding="utf-8"))
    assert saved["summary"]["event_count"] == 2
    assert [row["event_id"] for row in saved["events"]] == [matched.event_id]
    assert [row["event_id"] for row in saved["correlations"]] == [matched.event_id]
    per_host = (tmp_path / "per_host" / "target" / "correlations_human.txt").read_text(encoding="utf-8")
    assert "echo harmless" not in per_host
    assert len(cli.load_existing_outputs(tmp_path)[1]) == 1
