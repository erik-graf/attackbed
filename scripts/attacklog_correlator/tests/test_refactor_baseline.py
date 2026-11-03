"""Output fingerprints captured from fixes commit 0ada3ee, not new expectations."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

PACKAGE = Path(__file__).resolve().parents[1]
CASES = [([], "default"), (["--max-time-delta", "0.3"], "strict"),
         (["--process-untimestamped-lines"], "untimed"), (["--max-per-attack", "1"], "top1")]


def create_logs(root):
    def write(path, text):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    steps = [("00", "sleep 5"), ("20", "curl http://10.0.0.5/payload.sh"),
             ("40", "cat /var/www/report.txt")]
    write("attacklogs/attacker/attackmate.json", "\n".join(json.dumps({
        "start-datetime": f"2026-05-27T12:00:{second}Z", "type": "execution",
        "cmd": cmd, "parameters": {"metadata": {"note": "dhcp"}},
    }) for second, cmd in steps) + "\n")
    write("hostlogs/target/syslog", "\n".join([
        "May 27 14:00:00 target sleep process exited",
        "2026-05-27T12:00:00.300Z target comm=sleep",
        "2026-05-27T12:00:00.301Z target comm=sleep",
        "2026-05-27T12:00:03Z target sleep unrelated",
        "2026-05-27T12:00:25Z target GET /payload.sh 10.0.0.5",
        "2026-05-27T12:00:25.001Z target GET /payload.sh 10.0.0.5",
        "cat /var/www/report.txt 10.0.0.5 without timestamp",
        "unrelated untimestamped text",
        "2026-05-27T12:00:40Z target cat /var/www/report.txt",
        "2026-05-27T15:00:00Z target sleep far away",
    ]) + "\n")
    write("hostlogs/target/audit.log", 'type=EXECVE msg=audit(1779883200.125:1): a0="sleep"\n')
    write("hostlogs/target/access.log", '10.0.0.5 - - [27/May/2026:14:00:20 +0200] "GET /payload.sh HTTP/1.1" 200 1\n')
    write("hostlogs/target/eve.jsonl", '\n'.join([
        json.dumps({"timestamp": "2026-05-27T14:00:20.1", "message": "GET /payload.sh from 10.0.0.5"}),
        json.dumps({"time": 1779883220200, "msg": "GET /payload.sh from 10.0.0.5"}),
    ]) + '\n')
    write("hostlogs/other/mixed.log", "\n".join([
        "27/05/2026 -- 14:00:02 sleep dhcp",
        "2026-05-27T12:00:22Z other GET /payload.sh from 10.0.0.5",
    ]) + '\n')
    write("hostlogs/target/binary.log", "\x00not a journal")
    write("config.json", json.dumps({"hosts": {
        "target": {"timezone": "Europe/Vienna", "ip_addresses": ["10.0.0.5"]},
        "other": {"timezone": "Europe/Vienna", "clock_skew_seconds": 2},
    }}))


def normalize(value, root):
    if isinstance(value, dict):
        return {k: normalize(v, root) for k, v in value.items() if k != "created_at"}
    if isinstance(value, list):
        return [normalize(v, root) for v in value]
    if isinstance(value, str):
        return value.replace(str(root), "<ROOT>")
    return value


def snapshot(root, flags):
    env = dict(os.environ, PYTHONPATH=str(PACKAGE / "src"))
    args = [sys.executable, "-m", "attacklog_correlator", "--root", str(root),
            "--host-config", str(root / "config.json"), "--default-year", "2026", "--no-ui"]
    result = subprocess.run(args + flags, env=env, text=True, capture_output=True, check=True)
    outputs = {"stdout": normalize(json.loads(result.stdout), root),
               "stderr": normalize(result.stderr, root)}
    for path in sorted((root / "output").rglob("*")):
        if path.is_file():
            content = path.read_text(encoding="utf-8")
            outputs[str(path.relative_to(root / "output"))] = normalize(
                json.loads(content) if path.suffix == ".json" else content, root)
    # Fingerprint complete rows, scores, ordering, counters and all report formats.
    encoded = json.dumps(outputs, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


@pytest.mark.parametrize("flags,name", CASES)
def test_outputs_match_pre_refactor_baseline(tmp_path, flags, name):
    create_logs(tmp_path)
    expected = json.loads((Path(__file__).parent / "fixtures" / "baseline_hashes.json").read_text())
    assert snapshot(tmp_path, flags) == expected[name]
