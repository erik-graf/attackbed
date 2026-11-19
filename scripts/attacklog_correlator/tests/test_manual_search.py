"""Tests for manual log searching, navigation and highlighted results."""

from types import SimpleNamespace

from attacklog_correlator import manual
from attacklog_correlator.manual import ManualBrowser
from manual_support import make_attack, make_browser, make_resolver


def test_window_search_finds_current_attack_matches_in_multiple_files(tmp_path):
    first = tmp_path / "host" / "syslog"
    second = tmp_path / "host" / "auth.log"
    first.parent.mkdir()
    first.write_text("Nov 18 12:00:05 host error in window\n"
                     "continued error text\n"
                     "Nov 18 12:01:00 host error outside window\n")
    second.write_text("Nov 18 12:00:10 host another ERROR\n")
    browser = ManualBrowser([make_attack()], [first, second], [], [], tmp_path,
                            make_resolver(), 2026, 0, 30, tmp_path / "output")
    browser.activate_attack()
    assert browser.search("error") == 3
    assert browser.visible_files == [first, second]
    assert [line.line_number for line in browser.lines] == [1, 2]
    assert browser.lines[0].timestamp_span == (0, len("Nov 18 12:00:05"))
    browser.focus = "lines"
    browser.handle_key(manual.curses.KEY_END)
    browser.toggle_selected()
    assert browser.lines[1].text == "continued error text"
    assert browser.handle_key(27) is True  # Escape returns to time-window browsing
    assert browser.search_results is None
    assert len(browser.visible_files) == 2


def test_hex_search_finds_original_invalid_utf8_even_outside_window(tmp_path):
    timed = tmp_path / "host" / "syslog"
    undated = tmp_path / "host" / "untimed.log"
    timed.parent.mkdir()
    timed.write_bytes(b"Nov 18 12:00:05 host normal\n"
                      b"Nov 18 12:02:00 host special \xef byte\n")
    undated.write_bytes(b"plain \xef no timestamp\n")
    browser = ManualBrowser([make_attack()], [timed, undated], [], [],
                            tmp_path, make_resolver(), 2026, 0, 30,
                            tmp_path / "output")
    browser.activate_attack()
    assert browser.search(r"\xef") == 0
    assert browser.search(r"\xef", all_lines=True) == 2
    assert browser.visible_files == [timed, undated]
    assert r"\xef" in browser.lines[0].text
    browser.toggle_selected()
    browser.file_index = 1
    browser._load_lines()
    browser.toggle_selected()
    text = browser.save().read_text()
    assert r"\xef" in text
    assert "special" in text and "no timestamp" in text


def test_search_query_escapes_and_invalid_sequences():
    assert manual.parse_search_query(r"\xef") == (bytes([0xef]), True)
    assert manual.parse_search_query(r"GET \xef") == (b"GET \xef", True)
    assert manual.parse_search_query("Failed password") == (b"Failed password", False)
    import pytest
    with pytest.raises(ValueError, match="escape"):
        manual.parse_search_query(r"\xZZ")


def test_toggle_all_auto_marks_preserves_manual_marks(tmp_path):
    browser, _ = make_browser(tmp_path, [
        "Nov 18 12:00:00 target auto", "Nov 18 12:00:01 target manual",
    ])
    browser.focus = "lines"
    browser.handle_key(manual.curses.KEY_END)
    browser.toggle_selected()
    assert len(browser.selected) == 2
    browser.handle_key(ord("a"))
    assert len(browser.selected) == 1
    assert not (browser.selected & browser.automatic)
    browser.handle_key(ord("a"))
    assert len(browser.selected) == 2


def test_saved_auto_previews_are_resolved_to_full_raw_lines(tmp_path):
    full = "Nov 18 12:00:00 target " + "very long content " * 100
    browser, path = make_browser(tmp_path, [full])
    key = browser._key(browser.lines[0])
    browser.text_by_key[key] = "truncated saved preview"
    browser._complete_text.clear()
    saved = browser.save().read_text()
    assert full in saved
    assert "truncated saved preview" not in saved


def test_search_popup_and_modified_control_key(tmp_path, monkeypatch):
    browser, _ = make_browser(tmp_path, ["Nov 18 12:00:00 target failed password"])
    class Popup:
        def box(self): pass
        def addnstr(self, *_a): pass
        def refresh(self): pass
        def getstr(self, *_a): return b"Failed"
    monkeypatch.setattr(manual.curses, "newwin", lambda *_a: Popup())
    monkeypatch.setattr(manual.curses, "echo", lambda: None)
    monkeypatch.setattr(manual.curses, "noecho", lambda: None)
    monkeypatch.setattr(manual.curses, "curs_set", lambda *_a: None)
    screen = SimpleNamespace(getmaxyx=lambda: (24, 110))
    browser.handle_key(6, screen)
    assert browser.search_results is not None
    assert browser.search_query == "Failed"
    browser.handle_key(ord("F"), screen)
    assert browser.search_results is not None

    class EnhancedKeys:
        def __init__(self):
            self.values = [27] + [ord(char) for char in "[102;6u"]
        def getch(self):
            return self.values.pop(0) if self.values else -1
        def timeout(self, _ms): pass
    assert browser._read_key(EnhancedKeys()) == manual.SEARCH_ALL_KEY


def test_search_match_spans_cover_repeated_text_and_non_utf8_bytes():
    raw = b"error ERROR error"
    rendered = raw.decode("utf-8", errors="backslashreplace")
    spans = manual.search_match_spans(raw, b"error", False)
    assert [rendered[start:end] for start, end in spans] == ["error", "ERROR", "error"]
    invalid = b"byte \xef and \xef"
    shown = invalid.decode("utf-8", errors="backslashreplace")
    spans = manual.search_match_spans(invalid, b"\xef", True)
    assert [shown[start:end] for start, end in spans] == [r"\xef", r"\xef"]
    utf8 = "wide Ａ glyph".encode("utf-8")
    spans = manual.search_match_spans(utf8, b"\xef", True)
    assert [utf8.decode("utf-8")[start:end] for start, end in spans] == ["Ａ"]


def test_search_next_previous_wrap_between_logfiles(tmp_path):
    first = tmp_path / "host" / "syslog"
    second = tmp_path / "host" / "auth.log"
    first.parent.mkdir(parents=True)
    first.write_text("Nov 18 12:00:01 host error first\nNov 18 12:00:02 host ERROR second\n")
    second.write_text("Nov 18 12:00:03 host error third\n")
    browser = ManualBrowser([make_attack("first"), make_attack("second")],
                            [first, second], [], [], tmp_path, make_resolver(),
                            2026, 0, 30, tmp_path / "output")
    browser.activate_attack()
    assert browser.search("error") == 3
    assert browser.file_index == browser.line_index == 0
    browser.handle_key(ord("n"))
    assert (browser.file_index, browser.line_index) == (0, 1)
    browser.handle_key(ord("n"))
    assert (browser.file_index, browser.line_index) == (1, 0)
    browser.handle_key(ord("n"))
    assert (browser.file_index, browser.line_index) == (0, 0)
    browser.handle_key(ord("p"))
    assert (browser.file_index, browser.line_index) == (1, 0)
    assert browser.attack_index == browser.active_attack_index == 0
    assert browser.focus == "lines"
    browser.handle_key(ord("]"))
    assert browser.attack_index == browser.active_attack_index == 1
    assert browser.search_results is None
    browser.handle_key(ord("p"))
    assert browser.attack_index == 1
    assert browser.status == "Search with Ctrl+F or F first"


def test_selected_attack_and_file_stay_highlighted_outside_their_panes(tmp_path):
    browser, _ = make_browser(tmp_path, ["Nov 18 12:00:00 target error"])
    browser.focus = "lines"

    class Window:
        def __init__(self):
            self.writes = []
            self.panes = []
        def getmaxyx(self):
            return (24, 100)
        def erase(self):
            pass
        def refresh(self):
            pass
        def box(self):
            pass
        def derwin(self, *_args):
            child = Window()
            self.panes.append(child)
            return child
        def addnstr(self, y, x, text, width, attr=0):
            self.writes.append((y, x, text[:width], attr))

    screen = Window()
    browser._draw(screen)
    attack_attrs = [attr for _y, _x, text, attr in screen.panes[0].writes if "curl" in text]
    file_attrs = [attr for _y, _x, text, attr in screen.panes[1].writes if "syslog" in text]
    assert len(attack_attrs) == len(file_attrs) == 1
    assert attack_attrs[0] & manual.curses.A_REVERSE
    assert file_attrs[0] & manual.curses.A_REVERSE


def test_search_highlights_matches_in_log_pane(tmp_path):
    browser, _ = make_browser(tmp_path, [
        "Nov 18 12:00:00 target error and ERROR, plus error"
    ])
    assert browser.search("error") == 1
    assert len(browser.lines[0].search_spans) == 3
    browser.heatmap = False
    browser.search_attr = manual.curses.A_STANDOUT | manual.curses.A_BOLD

    class Window:
        def __init__(self):
            self.writes = []
            self.panes = []
        def getmaxyx(self):
            return (24, 140)
        def erase(self):
            pass
        def refresh(self):
            pass
        def box(self):
            pass
        def derwin(self, *_args):
            child = Window()
            self.panes.append(child)
            return child
        def addnstr(self, y, x, text, width, attr=0):
            self.writes.append((y, x, text[:width], attr))

    screen = Window()
    browser._draw(screen)
    right = screen.panes[2]
    highlights = [text for _y, x, text, attr in right.writes
                  if x >= 11 and attr == browser.search_attr]
    assert highlights == ["error", "ERROR", "error"]


def test_unavailable_saved_correlation_is_identified_in_export(tmp_path):
    browser, path = make_browser(tmp_path, ["Nov 18 12:00:00 target complete"])
    key = browser._key(browser.lines[0])
    browser.text_by_key[key] = "short saved preview"
    browser._complete_text.clear()
    path.unlink()
    result = browser.save().read_text()
    assert "# [SOURCE UNAVAILABLE:" in result
    assert "saved preview only" in result
    assert "short saved preview" in result
    assert "1 source lines unavailable" in browser.status


def test_wide_and_combining_characters_do_not_shift_highlights():
    from attacklog_correlator.manual_ui import highlight_segment

    value = "Ａx e\u0301 error"
    start = value.index("error")
    assert highlight_segment(value, start, start + 5, 0, 40) == (6, "error")
    assert highlight_segment("x" * 50 + "hit", 50, 53, 0, 40) is None
    assert highlight_segment("abc hit", 4, 7, 2, 20) == (2, "hit")
