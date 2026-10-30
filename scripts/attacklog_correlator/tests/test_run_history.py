import argparse
import json
import sys

from attacklog_correlator import cli
from attacklog_correlator.metadata import __version__


def test_history_appends_summaries_and_identifies_source(tmp_path, monkeypatch):
    summary_path = tmp_path / "output" / "summary.json"
    summary_path.parent.mkdir()
    history = tmp_path / "run-history.jsonl"
    monkeypatch.setattr(cli.subprocess, "run", lambda *_a, **_kw: argparse.Namespace(returncode=0, stdout="0123456789abcdef\n"))

    args = argparse.Namespace(
        root=str(tmp_path), host_config=None, default_timezone="UTC",
        default_year=2026, window_before=60, window_after=240,
        max_time_delta=5, max_per_attack=30, process_untimestamped_lines=False,
    )
    for count in (2, 3):
        summary_path.write_text(json.dumps({"correlations": count, "created_at": "2026-10-30T12:00:00Z"}))
        cli.append_run_history(history, summary_path, args)

    records = [json.loads(line) for line in history.read_text().splitlines()]
    assert [r["summary"]["correlations"] for r in records] == [2, 3]
    assert all(r["correlator_version"] == __version__ for r in records)
    assert all(r["git_revision"] == "0123456789abcdef" for r in records)
    assert len(records[0]["source_sha256"]) == 64
    assert records[0]["settings"]["max_time_delta"] == 5


def test_history_flag_accepts_default_and_explicit_path(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["attacklog-correlator", "--root", "work", "--history"])
    assert cli.parse_args().history == "run-history.jsonl"
    monkeypatch.setattr(sys, "argv", ["attacklog-correlator", "--root", "work", "--history", "results.jsonl"])
    assert cli.parse_args().history == "results.jsonl"
    monkeypatch.setattr(sys, "argv", ["attacklog-correlator", "--root", "work"])
    assert cli.parse_args().history is None


def test_history_does_not_corrupt_json_exports(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "attacklog-correlator", "--root", str(tmp_path),
        "--history", "output/correlations.json", "--no-ui",
    ])
    assert cli.main() == 2
    assert not (tmp_path / "output" / "correlations.json").exists()
