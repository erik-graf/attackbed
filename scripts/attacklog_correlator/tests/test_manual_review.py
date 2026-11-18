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
    browser.handle_key(ord("n"))
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
    assert (browser.before, browser.after) == (70, 70)
    browser.handle_key(ord("-"))
    assert (browser.before, browser.after) == (60, 60)
    browser.change_window(-1000)
    assert (browser.before, browser.after) == (0, 0)
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
    assert screen.panes[0][0] == (19, 25, 4, 0)
    assert screen.panes[1][0] == (19, 75, 4, 25)
    assert any("Attack 1/1" in row[2] for row in screen.writes)
    assert any("*A" in row[2] and "target event" in row[2]
               for row in screen.panes[1][1].writes)


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
    assert (1, "Command: curl") in screen.writes
    assert (2, "Description: Download a script") in screen.writes
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
    browser.focus = "files"
    browser.handle_key(ord("j"))
    assert browser.visible_files[browser.file_index] == second
    browser.handle_key(ord("n"))
    browser._load_lines()
    assert browser.visible_files[browser.file_index] == second


def test_popup_sets_symmetric_window_and_rejects_invalid(tmp_path, monkeypatch):
    browser, _path = make_browser(tmp_path, ["Nov 18 12:00:00 target event"])

    class Popup:
        value = b"17.5"
        def box(self):
            pass
        def addnstr(self, *_args):
            pass
        def refresh(self):
            pass
        def getstr(self, *_args):
            return self.value

    popup = Popup()
    monkeypatch.setattr(manual.curses, "newwin", lambda *_args: popup)
    monkeypatch.setattr(manual.curses, "echo", lambda: None)
    monkeypatch.setattr(manual.curses, "noecho", lambda: None)
    monkeypatch.setattr(manual.curses, "curs_set", lambda *_args: None)
    browser.handle_key(ord("t"), SimpleNamespace(getmaxyx=lambda: (24, 100)))
    assert (browser.before, browser.after) == (17.5, 17.5)
    popup.value = b"NaN"
    browser.handle_key(ord("t"), SimpleNamespace(getmaxyx=lambda: (24, 100)))
    assert (browser.before, browser.after) == (17.5, 17.5)
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
    right = screen.panes[1]
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
    assert all(x != 11 for _y, x, _text, _attr in screen.panes[1].writes)
