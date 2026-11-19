"""Shared builders for manual browser tests."""

import datetime as dt
from types import SimpleNamespace

from attacklog_correlator.config import ConfigBundle, HostProfile, HostResolver
from attacklog_correlator.manual import ManualBrowser
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
