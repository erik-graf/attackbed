import datetime as dt
from pathlib import Path

import pytest

from attacklog_correlator.config import ConfigBundle, HostProfile, HostResolver
from attacklog_correlator.events import load_log_file
from attacklog_correlator.ingestion import readers
from attacklog_correlator.models import RunStats, UTC


def test_reader_keeps_full_records_without_attack_or_host_configuration(tmp_path):
    path = tmp_path / "arbitrary.log"
    long_line = "2026-05-27T14:00:00 " + "x" * 1000 + "\n"
    path.write_text(long_line + "missing timestamp\n2026-05-28T00:00:00Z next day\n")
    stats = RunStats()
    records = readers.iter_log_records(path, 2026, stats=stats)
    assert iter(records) is records
    rows = list(records)
    assert [r.line_number for r in rows] == [1, 2, 3]
    assert all(r.file_path == str(path) for r in rows)
    assert rows[0].raw_line == long_line
    assert rows[0].parsed_timestamp.naive
    assert rows[1].parsed_timestamp is None
    assert not rows[2].parsed_timestamp.naive
    assert stats.unparsable_lines == 1


def test_host_timezone_and_skew_are_applied_before_pruning(tmp_path):
    path = tmp_path / "target" / "app.log"
    path.parent.mkdir()
    path.write_text('2026-05-27T14:00:02 sleep\n')
    resolver = HostResolver(ConfigBundle("UTC", 0, {
        "target": HostProfile("target", "Europe/Vienna", clock_skew_seconds=2),
    }))
    instant = dt.datetime(2026, 5, 27, 12, tzinfo=UTC)
    rows = load_log_file(path, tmp_path, 2026, resolver, attack_times=[instant])
    assert len(rows) == 1
    assert rows[0].timestamp == instant


def test_pruning_happens_before_expensive_token_enrichment(tmp_path, monkeypatch):
    from attacklog_correlator import events
    path = tmp_path / "app.log"
    path.write_text('2026-05-28T00:00:00Z unrelated\n')
    resolver = HostResolver(ConfigBundle("UTC", 0, {}))
    def unexpected(_line):
        pytest.fail("Out-of-window records must not be tokenized")
    monkeypatch.setattr(events, "extract_tokens", unexpected)
    stats = RunStats()
    assert load_log_file(path, tmp_path, 2026, resolver, attack_times=[], stats=stats) == []
    assert stats.parsed_events == 1


def test_closing_reader_releases_journal_generator(tmp_path, monkeypatch):
    path = tmp_path / "data.journal"
    path.write_bytes(b"LPKSHHRH")
    closed = []
    def export(_path):
        try:
            yield "2026-05-27T12:00:00Z target sleep"
            pytest.fail("Reader consumed more than requested")
        finally:
            closed.append(True)
    monkeypatch.setattr(readers, "run_journalctl_export", export)
    records = readers.iter_log_records(path, 2026)
    assert next(records).source_type == "journalctl-export"
    records.close()
    assert closed == [True]


def test_journal_failure_discards_file_and_preserves_previous_counts(tmp_path, monkeypatch):
    path = tmp_path / "bad.journal"
    path.write_bytes(b"LPKSHHRH")
    def export(_path):
        yield "2026-05-27T12:00:00Z target sleep"
        yield "unparsed"
        raise RuntimeError("failed conversion")
    monkeypatch.setattr(readers, "run_journalctl_export", export)
    stats = RunStats(parsed_events=7)
    resolver = HostResolver(ConfigBundle("UTC", 0, {}))
    assert load_log_file(path, tmp_path, 2026, resolver, stats=stats) == []
    assert stats.parsed_events == 7
    assert stats.unparsable_lines == 1
    assert stats.journalctl_converted_files == 0
    assert stats.binary_log_files_skipped == 1


def test_binary_skip_is_reported_without_retaining_binary_rows(tmp_path):
    path = tmp_path / "binary.log"
    path.write_bytes(b"\x00" * 100)
    stats = RunStats()
    assert list(readers.iter_log_records(path, 2026, stats=stats)) == []
    assert stats.binary_log_files_skipped == 1


def test_early_close_terminates_journal_subprocess(tmp_path, monkeypatch):
    class Process:
        def __init__(self):
            self.stdout = iter(["2026-05-27T12:00:00Z target sleep\n"])
            self.terminated = False
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            pass
        def poll(self):
            return None
        def terminate(self):
            self.terminated = True
    proc = Process()
    monkeypatch.setattr(readers.subprocess, "Popen", lambda *args, **kwargs: proc)
    stream = readers.run_journalctl_export(tmp_path / "test.journal")
    assert next(stream).endswith("sleep")
    stream.close()
    assert proc.terminated
