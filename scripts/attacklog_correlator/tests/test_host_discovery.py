from attacklog_correlator import config as config_module
from pathlib import Path



def test_top_level_host_folder_is_only_generated_path_hint(tmp_path: Path):
    log_root = tmp_path / "hostlogs"
    path = log_root / "fileshare" / "var" / "log" / "apt" / "history.log"
    path.parent.mkdir(parents=True)
    path.write_text("", encoding="utf-8")

    hosts = config_module.discover_hosts_from_logs(log_root, None, "Europe/Vienna")

    assert sorted(hosts) == ["fileshare"]
    assert hosts["fileshare"].path_hints == ["fileshare"]
