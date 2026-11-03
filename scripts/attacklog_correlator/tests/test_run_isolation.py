import json
from pathlib import Path
import sys

from attacklog_correlator import cli, output


def test_repeated_main_calls_do_not_reuse_counters_or_time_limits(tmp_path, monkeypatch):
    attack = tmp_path / "attacklogs" / "attacker" / "attackmate.json"
    log = tmp_path / "hostlogs" / "target" / "app.log"
    attack.parent.mkdir(parents=True)
    log.parent.mkdir(parents=True)
    attack.write_text(json.dumps({"start-datetime": "2026-05-27T12:00:00Z", "cmd": "sleep 5"}) + "\n")
    log.write_text("2026-05-27T12:00:00.5Z target comm=sleep\nno timestamp\n")
    args = ["attacklog-correlator", "--root", str(tmp_path), "--no-ui"]
    for flags, count in [(["--max-time-delta", "0.3"], 0), ([], 1), ([], 1)]:
        monkeypatch.setattr(sys, "argv", args + flags)
        assert cli.main() == 0
        summary = json.loads((tmp_path / "output" / "summary.json").read_text())
        assert summary["correlations"] == count
        assert summary["unparsable_lines"] == 1
        assert summary["max_time_delta_seconds"] == (0.3 if flags else 5.0)


def test_source_checksum_covers_all_modules_and_paths(tmp_path):
    (tmp_path / "cli.py").write_text("# main\n")
    sub = tmp_path / "ingestion"
    sub.mkdir()
    parser = sub / "timestamps.py"
    parser.write_text("# original\n")
    before = output.package_source_sha256(tmp_path)
    assert before == output.package_source_sha256(tmp_path)
    parser.write_text("# changed\n")
    after = output.package_source_sha256(tmp_path)
    assert before != after
    parser.rename(sub / "readers.py")
    assert output.package_source_sha256(tmp_path) != after
    (tmp_path / "ignored.log").write_text("not source")
    assert len(output.package_source_sha256(tmp_path)) == 64
