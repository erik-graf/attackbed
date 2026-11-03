import ast
import os
from pathlib import Path
import subprocess
import sys

import pytest

PACKAGE = Path(__file__).resolve().parents[1]


def run_python(*args):
    return subprocess.run([sys.executable, *args], check=True, capture_output=True, text=True,
                          env=dict(os.environ, PYTHONPATH=str(PACKAGE / "src")))


def test_ingestion_and_headless_cli_do_not_import_ui_or_scoring():
    run_python("-c", "import sys; from attacklog_correlator.ingestion import readers; "
               "assert 'attacklog_correlator.correlation' not in sys.modules; "
               "assert 'attacklog_correlator.config' not in sys.modules; "
               "assert 'curses' not in sys.modules; "
               "from attacklog_correlator import cli; assert 'curses' not in sys.modules")


@pytest.mark.parametrize("args", [("-m", "attacklog_correlator", "--help"),
                                  (str(PACKAGE / "src/attacklog_correlator/cli.py"), "--help")])
def test_module_and_direct_script_entry_points(args):
    assert "--history" in run_python(*args).stdout


def test_runtime_source_remains_python_310_compatible():
    for path in (PACKAGE / "src/attacklog_correlator").rglob("*.py"):
        ast.parse(path.read_text(), filename=str(path), feature_version=(3, 10))
