"""Failure-path tests: no OpenStack, Packer, Ansible, or Terragrunt required."""

import json
import os
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from attackbed import cli, deploy, images
from attackbed.errors import AttackBedError, CommandError


def recipe_dir(root: Path) -> Path:
    directory = root / "packer" / "demo"
    directory.mkdir(parents=True)
    (directory / "default.json.example").write_text('{"image_name": "atb-demo"}')
    (root / "packer" / "defaults.json").write_text(
        json.dumps({"network": "build-net", "floating_ip_pool": "Ext-Net"})
    )
    return directory


def test_ansible_failure_stops_before_packer_and_redacts_log(tmp_path: Path) -> None:
    recipe_dir(tmp_path)
    log = tmp_path / "logs" / "demo.log"
    error = subprocess.CalledProcessError(17, ["ansible-galaxy"], output="SECRET: broken\n")

    with patch.dict(os.environ, {"CR_GITLAB_ACCESS_TOKEN": "SECRET"}), \
         patch.object(images.subprocess, "run", side_effect=error) as run, \
         patch.object(images.subprocess, "Popen") as packer:
        with pytest.raises(CommandError, match="exit code 17") as failure:
            images.build_image(None, tmp_path, "demo", log)

    assert run.call_count == 1
    packer.assert_not_called()
    assert failure.value.returncode == 17
    assert log.is_file()
    assert "[REDACTED]" in log.read_text()
    assert "SECRET" not in log.read_text()


def test_missing_ansible_executable_is_an_operational_error(tmp_path: Path) -> None:
    recipe_dir(tmp_path)
    log = tmp_path / "demo.log"
    with patch.object(images.subprocess, "run", side_effect=FileNotFoundError("ansible-galaxy")):
        with pytest.raises(CommandError, match="ansible-galaxy"):
            images.build_image(None, tmp_path, "demo", log)
    assert "FAILED:" in log.read_text()


def test_packer_init_failure_stops_before_build(tmp_path: Path) -> None:
    recipe_dir(tmp_path)
    log = tmp_path / "demo.log"
    prepared = subprocess.CompletedProcess(["ansible-galaxy"], 0, stdout="roles installed\n")
    failure = subprocess.CalledProcessError(8, ["packer", "init"], output="init failed\n")
    with patch.object(images.subprocess, "run", side_effect=[prepared, failure]) as run, \
         patch.object(images.subprocess, "Popen") as packer:
        with pytest.raises(CommandError, match="exit code 8"):
            images.build_image(None, tmp_path, "demo", log)
    assert run.call_count == 2
    packer.assert_not_called()
    assert "roles installed" in log.read_text()
    assert "init failed" in log.read_text()


def test_packer_build_nonzero_exit_does_not_validate_image(tmp_path: Path) -> None:
    recipe_dir(tmp_path)
    log = tmp_path / "demo.log"
    prepared = subprocess.CompletedProcess(["setup"], 0, stdout="ok\n")
    with patch.object(images.subprocess, "run", return_value=prepared), \
         patch.object(images.subprocess, "Popen") as packer, \
         patch.dict(os.environ, {"OS_PASSWORD": "SECRET"}):
        process = packer.return_value.__enter__.return_value
        process.stdout = ["packer output SECRET\n"]
        process.wait.return_value = 7
        with pytest.raises(CommandError, match="exit code 7"):
            images.build_image(None, tmp_path, "demo", log)
    assert "[REDACTED]" in log.read_text()
    assert "SECRET" not in log.read_text()


def test_one_failed_terragrunt_copy_does_not_stop_other_copy(tmp_path: Path) -> None:
    root = tmp_path / "terragrunt"
    (root / "bootstrap").mkdir(parents=True)
    (root / "bootstrap" / "terragrunt.hcl").touch()
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "scenarios.yaml").write_text("demo: [bootstrap]\n")
    run_dir = tmp_path / "runs" / "run-test"
    seen = []

    def launch(command, **kwargs):
        name = kwargs["env"]["ATTACKBED_DEPLOYMENT_ID"]
        seen.append(name)
        process = MagicMock()
        process.__enter__.return_value = process
        process.stdout = [f"running {name}\n"]
        process.wait.return_value = 1 if name == "lab-002" else 0
        return process

    with patch.object(deploy.subprocess, "Popen", side_effect=launch):
        result = deploy.main(
            ["demo", "apply", "--copies", "2", "--parallel-copies", "2"],
            root, run_dir=run_dir,
        )

    assert result == 1
    assert sorted(seen) == ["lab-001", "lab-002"]
    log = (run_dir / "logs" / "apply.log").read_text()
    assert "lab-001/bootstrap" in log
    assert "lab-002/bootstrap" in log
    assert "1 deployment(s) succeeded, 1 failed" in log


def test_missing_terragrunt_binary_fails_with_context(tmp_path: Path) -> None:
    root = tmp_path / "terragrunt"
    (root / "bootstrap").mkdir(parents=True)
    (root / "bootstrap" / "terragrunt.hcl").touch()
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "scenarios.yaml").write_text("demo: [bootstrap]\n")
    run_dir = tmp_path / "runs" / "run-test"

    with patch.object(deploy.subprocess, "Popen", side_effect=FileNotFoundError("terragrunt")):
        result = deploy.main(["demo", "plan", "--copies", "1"], root, run_dir=run_dir)

    assert result == 1
    log = (run_dir / "logs" / "plan.log").read_text()
    assert "Terragrunt plan for lab-001/bootstrap" in log
    assert "terragrunt" in log


def test_terragrunt_parser_checks_delete_states_action_and_positive_counts(tmp_path: Path) -> None:
    root = tmp_path / "terragrunt"
    for arguments in (
        ["demo", "apply", "--copies", "0"],
        ["demo", "destroy", "--copies", "-1"],
        ["demo", "apply", "--deployment", "INVALID"],
        ["demo", "apply", "--copies", "1", "--delete-states"],
    ):
        with pytest.raises(SystemExit) as error:
            deploy.main(arguments, root)
        assert error.value.code == 2


def test_destroy_does_not_require_cleanup_credentials_without_switch(tmp_path: Path) -> None:
    root = tmp_path / "terragrunt"
    (root / "bootstrap").mkdir(parents=True)
    (root / "bootstrap" / "terragrunt.hcl").touch()
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "scenarios.yaml").write_text("demo: [bootstrap]\n")
    run_dir = tmp_path / "runs" / "run-test"
    env_override = {
        "GITLAB_STATE_REPOSITORY": "", "CR_GITLAB_ACCESS_TOKEN": "",
        "OS_PROJECT_NAME": "", "OS_USER_DOMAIN_NAME": "",
    }
    with (
        patch.object(deploy.TerragruntDeployment, "run_unit"),
        patch.object(deploy, "delete_deployment_states") as delete,
    ):
        assert deploy.main(
            ["demo", "destroy", "--copies", "1"], root,
            run_dir=run_dir, env_override=env_override,
        ) == 0
    delete.assert_not_called()
    with pytest.raises(SystemExit) as error:
        deploy.main(
            ["demo", "destroy", "--copies", "1", "--delete-states"], root,
            run_dir=run_dir, env_override=env_override,
        )
    assert error.value.code == 2


def test_cli_reports_expected_error_without_traceback(capsys, monkeypatch) -> None:
    monkeypatch.setenv("CR_GITLAB_ACCESS_TOKEN", "SECRET")
    error = CommandError(
        "Packer adminpc", ["packer", "build"], returncode=1,
        reason="SECRET broke the build",
    )
    with patch.object(cli, "main", side_effect=error):
        assert cli.entrypoint(["build", "demo"]) == 1
    stderr = capsys.readouterr().err
    assert "Packer adminpc" in stderr
    assert "Traceback" not in stderr
    assert "SECRET" not in stderr


def test_debug_shows_redacted_traceback(capsys, monkeypatch) -> None:
    monkeypatch.setenv("CR_GITLAB_ACCESS_TOKEN", "SECRET")
    with patch.object(cli, "main", side_effect=AttackBedError("SECRET failed")):
        assert cli.entrypoint(["build", "demo", "--debug"]) == 1
    stderr = capsys.readouterr().err
    assert "Traceback" in stderr
    assert "[REDACTED]" in stderr
    assert "SECRET" not in stderr


def test_unexpected_programming_error_is_not_hidden() -> None:
    with patch.object(cli, "main", side_effect=RuntimeError("programming bug")):
        with pytest.raises(RuntimeError, match="programming bug"):
            cli.entrypoint(["build", "demo"])


def test_image_selection_is_passed_to_terragrunt_without_mutating_environment(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("ATTACKBED_IMAGES_FILE", "previous-value")
    images_file = tmp_path / "images.json"
    with patch.object(cli.deploy, "main", return_value=0) as invoke:
        cli.run_terragrunt(tmp_path, ["demo", "apply"], tmp_path / "run", images_file)
    assert os.environ["ATTACKBED_IMAGES_FILE"] == "previous-value"
    assert invoke.call_args.kwargs["env_override"]["ATTACKBED_IMAGES_FILE"] == str(images_file.resolve())
