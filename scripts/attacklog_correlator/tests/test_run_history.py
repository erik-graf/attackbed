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

    content = history.read_text()
    assert content.startswith("{\n  \"correlator_version\":")
    assert content.count("\n\n{") == 1

    # Pretty-printed objects are whitespace-separated JSON, not strict JSON Lines.
    decoder = json.JSONDecoder()
    records = []
    index = 0
    while index < len(content):
        record, index = decoder.raw_decode(content, index)
        records.append(record)
        while index < len(content) and content[index].isspace():
            index += 1
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


def test_history_can_append_to_older_single_line_history(tmp_path, monkeypatch):
    summary_path = tmp_path / "summary.json"
    summary_path.write_text('{"correlations": 2}', encoding="utf-8")
    history = tmp_path / "run-history.jsonl"
    history.write_text('{"summary":{"correlations":1}}\n', encoding="utf-8")
    monkeypatch.setattr(cli.subprocess, "run", lambda *_a, **_kw: argparse.Namespace(returncode=1, stdout=""))
    args = argparse.Namespace(
        root=str(tmp_path), host_config=None, default_timezone="UTC",
        default_year=2026, window_before=60, window_after=240,
        max_time_delta=5, max_per_attack=30, process_untimestamped_lines=False,
    )
    cli.append_run_history(history, summary_path, args)
    content = history.read_text(encoding="utf-8")
    assert content.startswith('{"summary":{"correlations":1}}\n\n{\n')
    assert len(json.JSONDecoder().raw_decode(content, content.index("{", content.index("}") + 1))[0]) > 1
    assert content.endswith("\n")
