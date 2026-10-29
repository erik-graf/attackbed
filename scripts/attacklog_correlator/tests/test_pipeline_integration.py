"""Synthetic AttackMate-style log fixtures exercising the complete pipeline."""
import json
from pathlib import Path

from attacklog_correlator import cli


def test_pipeline_preserves_only_known_correlations(tmp_path: Path):
    root = tmp_path / "work"
    attack_file = root / "attacklogs" / "attacker-a" / "attackmate.json"
    host_file = root / "hostlogs" / "target" / "syslog"
    attack_file.parent.mkdir(parents=True)
    host_file.parent.mkdir(parents=True)

    steps = [
        {
            "start-datetime": "2026-05-27T11:00:00+00:00",
            "type": "execution", "cmd": "sleep 5",
            "parameters": {"metadata": {"note": "dhcp"}},
        },
        {
            "start-datetime": "2026-05-27T11:01:00+00:00",
            "type": "execution", "cmd": "curl http://10.0.0.5/payload.sh",
            "parameters": {"metadata": {}},
        },
    ]
    attack_file.write_text("\n".join(json.dumps(x) for x in steps) + "\n", encoding="utf-8")
    host_file.write_text(
        "2026-05-27T11:00:00.100+00:00 target audit: comm=\"sleep\" argc=2\n"
        "2026-05-27T11:00:00.200+00:00 target dhcp lease renewed\n"
        "2026-05-27T11:01:00.100+00:00 target connection from 10.0.0.5 accepted\n"
        "2026-05-27T11:01:00.200+00:00 target nginx: GET /payload.sh from 10.0.0.5\n",
        encoding="utf-8",
    )

    config = cli.ConfigBundle(
        default_timezone="UTC", default_clock_skew_seconds=0.0,
        hosts={"target": cli.HostProfile("target", "UTC", ip_addresses=["10.0.0.5"])},
    )
    resolver = cli.HostResolver(config)
    attacks = cli.load_all_attacks(root / "attacklogs", resolver, config)
    events = cli.load_all_events(root / "hostlogs", root / "attacklogs", 2026, resolver)
    correlations = cli.correlate(attacks, events, 60, 240, 30)

    assert len(attacks) == 2
    assert len(events) == 4
    assert {c.event_line for c in correlations} == {1, 4}
    assert {c.attacker_host for c in correlations} == {"attacker-a"}

    out = root / "output"
    cli.export_outputs(out, config, attacks, events, correlations)
    data = json.loads((out / "correlations.json").read_text(encoding="utf-8"))
    assert data["summary"]["event_count"] == 4
    assert {row["line_number"] for row in data["events"]} == {1, 4}
    assert {row["event_line"] for row in data["correlations"]} == {1, 4}

    saved_attacks, saved_correlations, _summary = cli.load_existing_outputs(out)
    assert len(saved_attacks) == 2
    assert len(saved_correlations) == 2
