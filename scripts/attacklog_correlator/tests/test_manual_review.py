import datetime as dt
from pathlib import Path
from types import SimpleNamespace

from attacklog_correlator import manual
from attacklog_correlator.config import ConfigBundle, HostProfile, HostResolver
from attacklog_correlator.manual import ManualBrowser, lines_in_window
from attacklog_correlator.models import Attack, UTC


def make_resolver(timezone="UTC"):
    config = ConfigBundle(timezone, 0, {"target": HostProfile("target", timezone)})
    return HostResolver(config)


def make_attack(attack_id="a"):
    return Attack(
        attack_id=attack_id,
        timestamp=dt.datetime(2026, 11, 18, 12, tzinfo=UTC),
        attack_type="shell", cmd="curl", source_file="attack.json", line_number=3,
        metadata={}, raw_line='{"cmd":"curl"}',
    )


def make_browser(tmp_path, lines, auto_lines=(1,), attacks=None):
    path = tmp_path / "target" / "syslog"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
    attacks = attacks or [make_attack()]
    correlations = [SimpleNamespace(
        attack_id=attack.attack_id, event_file=str(path), event_line=line,
        event_message="short preview",
    ) for attack in attacks for line in auto_lines]
    events = [SimpleNamespace(file_path=str(path), line_number=n, raw_line=text)
              for n, text in enumerate(lines, 1)]
    browser = ManualBrowser(
        attacks, [path], correlations, events, tmp_path, make_resolver(),
        2026, 60, 60, tmp_path / "output",
    )
    browser.activate_attack()
    return browser, path


def test_time_window_keeps_following_untimestamped_context(tmp_path):
    path = tmp_path / "target" / "syslog"
    path.parent.mkdir()
    path.write_text(
        "Nov 18 11:50:00 target too early\n"
        "Nov 18 12:00:00 target matching event\n"
        "    continued stack trace\n"
        "Nov 18 12:05:00 target too late\n",
    )
    rows = lines_in_window(path, tmp_path, make_resolver(), 2026,
                           make_attack().timestamp, 60, 60)
    assert [(row.line_number, row.text) for row in rows] == [
        (2, "Nov 18 12:00:00 target matching event"),
        (3, "    continued stack trace"),
    ]


def test_time_window_uses_host_timezone(tmp_path):
    path = tmp_path / "target" / "syslog"
    path.parent.mkdir()
    path.write_text("Nov 18 13:00:00 target Vienna time\n")
    rows = lines_in_window(path, tmp_path, make_resolver("Europe/Vienna"),
                           2026, make_attack().timestamp, 1, 1)
    assert len(rows) == 1


def test_auto_selected_by_default_and_space_toggles(tmp_path):
    browser, _path = make_browser(tmp_path, [
        "Nov 18 12:00:00 target automatic", "Nov 18 12:00:01 target manual",
    ])
    browser._load_lines()
    assert browser._key(browser.lines[0]) in browser.selected
    assert browser._key(browser.lines[0]) in browser.automatic
    browser.focus = "lines"
    browser.handle_key(ord(" "))
    assert not browser.selected
    browser.handle_key(ord("j"))
    browser.handle_key(ord(" "))
    assert len(browser.selected) == 1
    assert browser._key(browser.lines[1]) in browser.selected
    browser.handle_key(ord(" "))
    assert not browser.selected


def test_selections_are_scoped_to_attack_and_save_raw_lines(tmp_path):
    text = "Nov 18 12:00:00 target " + "a" * 500
    browser, path = make_browser(tmp_path, [text], attacks=[make_attack("a"), make_attack("b")])
    assert len(browser.selected) == 2
    browser.toggle_selected()
    browser.handle_key(ord("]"))
    browser.handle_key(10)
    browser._load_lines()
    assert len(browser.selected) == 1
    assert browser._key(browser.lines[0]) in browser.selected
    output = browser.save().read_text()
    assert output.count(text) == 1
    assert f"## Log file: {path}" in output
    assert "# Attack" in output
    assert "1: Nov 18" not in output


def test_window_shortcuts_preserve_marks(tmp_path):
    browser, _path = make_browser(tmp_path, ["Nov 18 12:00:00 target event"])
    original = set(browser.selected)
    browser.handle_key(ord("+"))
    assert (browser.before, browser.after) == (60, 70)
    browser.handle_key(ord("-"))
    assert (browser.before, browser.after) == (60, 60)
    browser.change_window(-1000)
    assert (browser.before, browser.after) == (60, 0)
    assert browser.selected == original


def test_curses_panes_and_autocorrelation_marker(tmp_path):
    browser, _path = make_browser(tmp_path, ["Nov 18 12:00:00 target event"])

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

        def derwin(self, *dimensions):
            child = Window()
            self.panes.append((dimensions, child))
            return child

        def addnstr(self, y, x, text, width, attr=0):
            self.writes.append((y, x, text[:width], attr))

    screen = Window()
    browser._draw(screen)
    assert screen.panes[0][0] == (21, 25, 0, 0)
    assert screen.panes[1][0] == (21, 25, 0, 25)
    assert screen.panes[2][0] == (21, 50, 0, 50)
    assert any("*A" in row[2] and "target event" in row[2]
               for row in screen.panes[2][1].writes)


def test_quitting_saves_one_new_file(tmp_path, monkeypatch):
    browser, _path = make_browser(tmp_path, ["Nov 18 12:00:00 target event"])

    class Screen:
        def keypad(self, _enabled):
            pass

        def getmaxyx(self):
            return (8, 20)

        def erase(self):
            pass

        def addnstr(self, *_args):
            pass

        def refresh(self):
            pass

        def getch(self):
            return ord("q")

    monkeypatch.setattr(manual.curses, "wrapper", lambda main: main(Screen()))
    monkeypatch.setattr(manual.curses, "curs_set", lambda _visible: None)
    monkeypatch.setattr(manual.curses, "has_colors", lambda: False)
    assert browser.run() == browser.output_path
    assert "target event" in browser.output_path.read_text()
    second, _path = make_browser(tmp_path, ["Nov 18 12:00:00 target event"])
    assert second.output_path != browser.output_path


def test_manual_cli_flag_and_conflicting_modes(monkeypatch, capsys):
    from attacklog_correlator import cli

    monkeypatch.setattr("sys.argv", ["correlator", "--root", "work", "--manual"])
    assert cli.parse_args().manual is True
    monkeypatch.setattr("sys.argv", ["correlator", "--root", "work"])
    assert cli.parse_args().manual is False
    monkeypatch.setattr("sys.argv", ["correlator", "--root", "work", "--manual", "--no-ui"])
    assert cli.main() == 2
    assert "cannot be combined" in capsys.readouterr().err
    monkeypatch.setattr("sys.argv", ["correlator", "--root", "work", "--include-auto"])
    assert cli.main() == 2
    assert "requires --manual" in capsys.readouterr().err


def test_attack_details_show_only_command_and_description(tmp_path):
    attack = make_attack()
    attack.metadata = {"description": "Download a script", "irrelevant": "secret"}
    assert manual.attack_details(attack) == ("curl", "Download a script")
    browser, _path = make_browser(tmp_path, ["Nov 18 12:00:00 target event"], attacks=[attack])

    class Screen:
        writes = []
        def getmaxyx(self):
            return (24, 100)
        def erase(self):
            pass
        def refresh(self):
            pass
        def derwin(self, *_args):
            return self
        def box(self):
            pass
        def addnstr(self, y, x, text, _width, _attr=0):
            self.writes.append((y, text))

    screen = Screen()
    browser._draw(screen)
    assert (2, "Command: curl") in screen.writes
    assert (3, "Description: Download a script") in screen.writes
    assert all('"cmd"' not in text for _row, text in screen.writes)
    assert "# Description: Download a script" in browser.save().read_text()


def test_file_browser_hides_files_without_timestamps_in_window(tmp_path):
    right = tmp_path / "target" / "syslog"
    too_late = tmp_path / "target" / "auth.log"
    empty = tmp_path / "target" / "messages"
    untimed = tmp_path / "target" / "README.log"
    for path in (right, too_late, empty, untimed):
        path.parent.mkdir(parents=True, exist_ok=True)
    right.write_text("Nov 18 12:00:00 target matching\n")
    too_late.write_text("Nov 18 12:01:05 target later\n")
    empty.write_text("")
    untimed.write_text("No timestamp\n")
    browser = ManualBrowser([make_attack()], [right, too_late, empty, untimed], [], [],
                            tmp_path, make_resolver(), 2026, 60, 60, tmp_path / "output")
    browser.activate_attack()
    assert browser.visible_files == [right]
    browser.handle_key(ord("+"))
    browser._load_lines()
    assert browser.visible_files == [right, too_late]
    browser.handle_key(ord("-"))
    browser._load_lines()
    assert browser.visible_files == [right]


def test_next_attack_preserves_selected_file(tmp_path):
    first = tmp_path / "target" / "syslog"
    second = tmp_path / "target" / "auth.log"
    first.parent.mkdir(parents=True)
    for path in (first, second):
        path.write_text("Nov 18 12:00:00 target relevant\n")
    browser = ManualBrowser([make_attack('a'), make_attack('b')], [first, second], [], [],
                            tmp_path, make_resolver(), 2026, 60, 60, tmp_path / "output")
    browser.activate_attack()
    browser.focus = "files"
    browser.handle_key(ord("j"))
    assert browser.visible_files[browser.file_index] == second
    browser.handle_key(ord("]"))
    browser.handle_key(10)
    browser._load_lines()
    assert browser.visible_files[browser.file_index] == second


def test_popup_sets_symmetric_window_and_rejects_invalid(tmp_path, monkeypatch):
    browser, _path = make_browser(tmp_path, ["Nov 18 12:00:00 target event"])

    class Popup:
        values = [b"10", b"17.5"]
        def box(self):
            pass
        def addnstr(self, *_args):
            pass
        def refresh(self):
            pass
        def getstr(self, *_args):
            return self.values.pop(0)

    popup = Popup()
    monkeypatch.setattr(manual.curses, "newwin", lambda *_args: popup)
    monkeypatch.setattr(manual.curses, "echo", lambda: None)
    monkeypatch.setattr(manual.curses, "noecho", lambda: None)
    monkeypatch.setattr(manual.curses, "curs_set", lambda *_args: None)
    browser.handle_key(ord("t"), SimpleNamespace(getmaxyx=lambda: (24, 100)))
    assert (browser.before, browser.after) == (10, 17.5)
    popup.values = [b"NaN", b"20"]
    browser.handle_key(ord("t"), SimpleNamespace(getmaxyx=lambda: (24, 100)))
    assert (browser.before, browser.after) == (10, 17.5)
    assert "non-negative" in browser.status


def test_heatmap_default_red_closest_blue_farthest_and_toggle(tmp_path):
    browser, _path = make_browser(tmp_path, [
        "Nov 18 11:59:59 target close", "Nov 18 12:00:20 target mid",
        "Nov 18 12:00:50 target far",
    ])
    assert browser.heatmap is True
    browser.heat_attrs = [101, 102, 103, 104, 105]  # pretend colors: red -> blue

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
    right = screen.panes[2]
    colored = [(text, attr) for _y, x, text, attr in right.writes if x >= 11 and text.startswith("Nov 18")]
    assert len(colored) == 3
    assert colored[0][1] & ~manual.curses.A_REVERSE == 101  # closest is red
    assert colored[-1][1] & ~manual.curses.A_REVERSE == 105  # farthest is blue
    assert colored[1][1] & ~manual.curses.A_REVERSE in (102, 103, 104)
    assert all("target" not in text for text, _attr in colored)
    browser.handle_key(ord("c"))
    assert browser.heatmap is False
    screen = Window()
    browser._draw(screen)
    assert all(x != 11 for _y, x, _text, _attr in screen.panes[2].writes)


def test_switch_attack_indexes_only_once_without_enter(tmp_path, monkeypatch):
    path = tmp_path / "target" / "syslog"
    path.parent.mkdir()
    path.write_text("Nov 18 12:00:00 target first\nNov 18 12:00:20 target second\n")
    browser = ManualBrowser([make_attack("first"), make_attack("second")],
                            [path], [], [], tmp_path, make_resolver(), 2026,
                            0, 30, tmp_path / "output")
    calls = []
    real_index = manual.index_log_file
    def counting_index(*args, **kwargs):
        calls.append(args[0])
        return real_index(*args, **kwargs)
    monkeypatch.setattr(manual, "index_log_file", counting_index)
    browser.handle_key(manual.curses.KEY_END)
    assert browser.attack_index == browser.active_attack_index == 1
    assert calls == [path]
    browser.handle_key(manual.curses.KEY_HOME)
    assert browser.attack_index == browser.active_attack_index == 0
    assert calls == [path]
    assert browser.visible_files == [path]
    browser.handle_key(10)  # Enter remains optional and does not re-index
    assert browser.active_attack_index == 0
    browser.handle_key(manual.curses.KEY_END)
    assert browser.attack_index == browser.active_attack_index == 1
    assert calls == [path]
    browser.change_window(10)
    browser._load_lines()
    assert calls == [path]


def test_default_manual_window_shows_no_pre_attack_lines(tmp_path):
    browser, path = make_browser(tmp_path, [
        "Nov 18 11:59:59 target before",
        "Nov 18 12:00:01 target after",
        "Nov 18 12:00:31 target late",
    ], auto_lines=(2,))
    browser.set_window(0, 30)
    browser._load_lines()
    assert [line.line_number for line in browser.lines] == [2]
    browser.set_window(3, 30)
    browser._load_lines()
    assert [line.line_number for line in browser.lines] == [1, 2]


def test_home_end_select_first_last_in_each_pane_without_activation(tmp_path):
    attacks = [make_attack(str(i)) for i in range(5)]
    browser, path = make_browser(tmp_path, [
        "Nov 18 12:00:00 target first", "Nov 18 12:00:01 target second",
        "Nov 18 12:00:02 target third",
    ], attacks=attacks)
    browser.focus = "attacks"
    browser.handle_key(manual.curses.KEY_END)
    assert browser.attack_index == 4
    browser.handle_key(manual.curses.KEY_HOME)
    assert browser.attack_index == 0
    browser.focus = "lines"
    browser.handle_key(manual.curses.KEY_END)
    assert browser.line_index == 2
    browser.handle_key(manual.curses.KEY_HOME)
    assert browser.line_index == 0
    assert browser.active_attack_index == 0


def test_indexed_lines_include_context_and_preserve_actual_timestamp(tmp_path):
    path = tmp_path / "target" / "syslog"
    path.parent.mkdir()
    path.write_text("Nov 18 11:50:00 target early\nNov 18 12:00:00 target current\ncontinued\nNov 18 12:01:00 target late\n")
    resolver = make_resolver()
    stamps = manual.index_log_file(path, tmp_path, resolver, 2026)
    selected = [r for r in stamps if r.time == make_attack().timestamp]
    rows = manual.indexed_lines_in_window(path, stamps, selected)
    assert [r.line_number for r in rows] == [2, 3]
    assert rows[0].timestamp == make_attack().timestamp
    assert rows[0].timestamp_span == (0, len("Nov 18 12:00:00"))
    assert rows[1].timestamp is None


def test_window_recalculation_uses_cached_index_for_all_attacks(tmp_path, monkeypatch):
    first = tmp_path / "target" / "syslog"
    second = tmp_path / "target" / "auth.log"
    first.parent.mkdir(parents=True)
    first.write_text("Nov 18 12:00:05 target now\n")
    second.write_text("Nov 18 12:00:40 target later\n")
    browser = ManualBrowser([make_attack("a"), make_attack("b")], [first, second], [], [],
                            tmp_path, make_resolver(), 2026, 0, 30, tmp_path / "output")
    browser.activate_attack()
    assert browser.visible_files == [first]
    browser.handle_key(ord("+"))
    browser._load_lines()
    assert browser.visible_files == [first, second]
    browser.handle_key(manual.curses.KEY_END)
    assert browser.active_attack_index == 1
    assert browser.visible_files == [first, second]


def test_cli_manual_only_skips_scoring_and_keeps_window_defaults(tmp_path, monkeypatch):
    from attacklog_correlator import cli

    observed = {}
    class Browser:
        def __init__(self, *args):
            observed["manual"] = args[7:9]
            observed["correlations"] = args[2]

        def run(self):
            return tmp_path / "manual.txt"

    monkeypatch.setattr(manual, "ManualBrowser", Browser)
    monkeypatch.setattr(cli, "load_all_attacks", lambda *_a, **_kw: [make_attack()])
    def forbidden(*_a, **_kw):
        raise AssertionError("manual mode must not run lexical correlation")
    monkeypatch.setattr(cli, "load_all_events", forbidden)
    monkeypatch.setattr(cli, "correlate", forbidden)
    monkeypatch.setattr(cli, "export_outputs", forbidden)

    for flags, expected in [
        ([], (0.0, 30.0)),
        (["--window-before", "5", "--window-after", "50"], (5.0, 50.0)),
    ]:
        monkeypatch.setattr("sys.argv", ["correlator", "--root", str(tmp_path), "--manual"] + flags)
        assert cli.main() == 0
        assert observed == {"manual": expected, "correlations": []}


def test_cli_include_auto_opt_in_and_saved_manual_view(tmp_path, monkeypatch):
    from attacklog_correlator import cli

    seen = {}
    correlation = SimpleNamespace(attack_id="a", event_file="x", event_line=1, event_message="match")
    class Browser:
        def __init__(self, *args):
            seen["correlations"] = args[2]
        def run(self):
            return tmp_path / "manual.txt"

    monkeypatch.setattr(manual, "ManualBrowser", Browser)
    monkeypatch.setattr(cli, "load_all_attacks", lambda *_a, **_kw: [make_attack()])
    monkeypatch.setattr(cli, "load_all_events", lambda *_a, **_kw: [])
    monkeypatch.setattr(cli, "correlate", lambda *_a, **_kw: [correlation])
    monkeypatch.setattr(cli, "export_outputs", lambda *_a, **_kw: None)
    monkeypatch.setattr("sys.argv", ["correlator", "--root", str(tmp_path), "--manual", "--include-auto"])
    assert cli.main() == 0
    assert seen["correlations"] == [correlation]

    def forbidden(*_a, **_kw):
        raise AssertionError("saved manual review should not recompute")
    monkeypatch.setattr(cli, "load_all_attacks", forbidden)
    monkeypatch.setattr(cli, "load_all_events", forbidden)
    monkeypatch.setattr(cli, "correlate", forbidden)
    monkeypatch.setattr(cli, "load_existing_outputs",
                        lambda _out: ([make_attack()], [correlation], {}))
    for flags, expected in [([], []), (["--include-auto"], [correlation])]:
        monkeypatch.setattr("sys.argv", [
            "correlator", "--root", str(tmp_path), "--manual", "--view-existing", *flags
        ])
        assert cli.main() == 0
        assert seen["correlations"] == expected


def test_index_is_created_at_ui_startup(tmp_path, monkeypatch):
    browser, path = make_browser(tmp_path, ["Nov 18 12:00:00 target event"])
    browser._timestamps = None
    browser._times = {}
    browser._window_key = None
    browser._window_files = []
    browser.active_attack_index = None
    calls = []
    real = manual.index_log_file

    def tracked(*args, **kw):
        calls.append(args[0])
        return real(*args, **kw)

    monkeypatch.setattr(manual, "index_log_file", tracked)

    class Screen:
        def keypad(self, _enabled):
            pass

        def getmaxyx(self):
            return (24, 110)

        def erase(self):
            pass

        def derwin(self, *_args):
            return self

        def box(self):
            pass

        def addnstr(self, *_args):
            pass

        def refresh(self):
            pass

        def getch(self):
            assert browser.active_attack_index == 0
            assert calls == [path]
            return ord("q")

    monkeypatch.setattr(manual.curses, "curs_set", lambda _n: None)
    monkeypatch.setattr(manual.curses, "has_colors", lambda: False)
    browser._main(Screen())


def test_attack_and_file_correlations_highlight_and_show_counts(tmp_path):
    first = tmp_path / "target" / "syslog"
    second = tmp_path / "target" / "auth.log"
    first.parent.mkdir(parents=True)
    first.write_text("Nov 18 12:00:00 target a\nNov 18 12:00:01 target b\n")
    second.write_text("Nov 18 12:00:00 target no match\n")
    attacks = [make_attack("with-auto"), make_attack("without-auto")]
    matches = [SimpleNamespace(attack_id="with-auto", event_file=str(first),
                               event_line=line, event_message="matching") for line in (1, 2)]
    matches.append(SimpleNamespace(attack_id="with-auto", event_file=str(first),
                                   event_line=1, event_message="duplicate"))
    browser = ManualBrowser(attacks, [first, second], matches, [], tmp_path,
                            make_resolver(), 2026, 0, 30, tmp_path / "output")
    browser.activate_attack()
    browser.auto_attr = 4096

    class Window:
        def __init__(self):
            self.writes = []
            self.panes = []

        def getmaxyx(self):
            return (24, 110)

        def erase(self):
            pass

        def refresh(self):
            pass

        def box(self):
            pass

        def derwin(self, *_args):
            w = Window()
            self.panes.append(w)
            return w

        def addnstr(self, y, x, text, width, attr=0):
            self.writes.append((y, x, text[:width], attr))

    screen = Window()
    browser._draw(screen)
    attack_rows = screen.panes[0].writes
    file_rows = screen.panes[1].writes
    assert any("curl" in text and "12:00:00" not in text and "A" in text and attr & 4096
               for _y, _x, text, attr in attack_rows)
    assert any("curl" in text and not attr & 4096 for _y, _x, text, attr in attack_rows)
    assert any(text.startswith("(2) ") and "syslog" in text and attr & 4096
               for _y, _x, text, attr in file_rows)
    assert any(text.startswith("(0) ") and "auth.log" in text and not attr & 4096
               for _y, _x, text, attr in file_rows)
    browser.handle_key(manual.curses.KEY_END)
    screen = Window()
    browser._draw(screen)
    assert browser.active_attack_index == 1
    assert all(not (attr & 4096) for _y, _x, text, attr in screen.panes[0].writes
               if "curl" in text and text.startswith(">"))
    assert any(text.startswith("(0) ") for _y, _x, text, _attr in screen.panes[1].writes)


def test_footer_uses_descriptive_pipe_separated_labels(tmp_path):
    browser, _path = make_browser(tmp_path, ["Nov 18 12:00:00 target event"])

    class Screen:
        def __init__(self):
            self.lines = {}

        def getmaxyx(self):
            return (24, 120)

        def erase(self):
            pass

        def box(self):
            pass

        def derwin(self, *_args):
            return Screen()

        def addnstr(self, y, x, txt, width, attr=0):
            self.lines[y] = txt[:width]

        def refresh(self):
            pass

    screen = Screen()
    browser._draw(screen)
    assert "space: mark line | s: save marked lines to file" in screen.lines[22]
    assert "Ctrl+F: search current time window" in screen.lines[23]
    assert "n/p: matches" in screen.lines[23]
    assert "Home/End" not in screen.lines[23]


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
