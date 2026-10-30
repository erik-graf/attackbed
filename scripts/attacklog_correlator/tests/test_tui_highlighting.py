import datetime as dt
from types import SimpleNamespace

from attacklog_correlator import cli


def test_only_exact_lexical_tokens_are_highlighted():
    line = 'comm="curl" script.log curlycurl src=10.0.0.5 dst=10.0.0.50'
    spans = cli._lexical_highlight_spans(line, ["curl", "script", "10.0.0.5"])
    assert [line[start:end] for start, end in spans] == ["curl", "script.log", "10.0.0.5"]
    assert cli._lexical_highlight_spans("script.log", ["script.log"]) == [(0, 10)]
    assert cli._lexical_highlight_spans("src:10.0.0.5", ["10.0.0.5"]) == [(4, 12)]


def test_www_highlights_host_components_without_matching_longer_words():
    line = "user=www-data url=https://www.example.org/ www WWW wwwroot"
    spans = cli._lexical_highlight_spans(line, ["www"])
    assert [line[start:end] for start, end in spans] == ["www", "www", "www", "WWW"]
    assert cli._preview_keywords(SimpleNamespace(matched_lexical_terms=["www"])) == ["www"]


def test_short_binary_name_match_is_highlighted_without_substrings():
    line = "comm=nc ncat kernel session"
    assert cli._lexical_highlight_spans(line, ["nc"]) == [(5, 7)]


def test_preview_keeps_original_matched_term():
    corr = SimpleNamespace(matched_lexical_terms=["script.log"], attack_raw_line="")
    assert cli._preview_keywords(corr) == ["script.log"]


def test_tui_keeps_lexical_highlight_across_wrapping():
    class Window:
        def __init__(self):
            self.green_chunks = []

        def getmaxyx(self):
            return (20, 12)  # 10 printable columns, splitting "curl" across rows.

        def attron(self, *_args):
            pass

        def attroff(self, *_args):
            pass

        def box(self):
            pass

        def addnstr(self, _y, _x, text, _maxlen, attr=0):
            if attr == 123456:
                self.green_chunks.append(text)

    win = Window()
    browser = cli.CorrelationBrowser([], [])
    browser.preview_green_attr = 123456
    browser.preview_blue_attr = 654321
    browser.preview_bold_attr = 777777
    browser._draw_text(
        win, "Preview",
        ["Command: curl -k", "Matched command tokens: curl",
         ">     1 curl launched", ">     2 curlycurl launched",
         "Event:", "curl reported"],
        keywords=["curl"],
    )
    assert "".join(win.green_chunks) == "curl" * 4


def test_missing_or_binary_journal_context_uses_saved_message():
    corr = SimpleNamespace(
        host="target", attacker_host="attacker",
        event_time=dt.datetime(2026, 5, 27, tzinfo=cli.UTC),
        delta_seconds=0.1, score=15.0, attack_cmd="curl",
        matched_command_terms=["curl"], matched_metadata_terms=[],
        event_file="/does/not/exist", event_line=12, score_breakdown={},
        event_source_type="journalctl-export", event_message='comm="curl"',
    )
    lines = cli.build_preview_lines(corr)
    assert any(line.startswith(">") and 'comm="curl"' in line for line in lines)
