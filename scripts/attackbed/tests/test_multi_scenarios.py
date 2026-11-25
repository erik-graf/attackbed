"""Multi-scenario deployments preserve isolation, progress, and run settings."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from attackbed import api, cli, deploy
from attackbed.errors import AttackBedError


def workspace(root: Path) -> None:
    (root / "config").mkdir()
    (root / "config/config.yaml").write_text(
        "scenarios:\n"
        "  all: [bootstrap, attacker, videoserver]\n"
        "  core: [bootstrap]\n"
        "  attack: [bootstrap, attacker]\n"
        "  video: [bootstrap, videoserver]\n"
        "image_recipes: {}\n"
    )
    for name in ("bootstrap", "attacker", "videoserver"):
        unit = root / "terragrunt" / name
        unit.mkdir(parents=True)
        (unit / "terragrunt.hcl").touch()
        (unit / "module").mkdir()


def connection():
    return SimpleNamespace(image=SimpleNamespace(images=lambda: []))


def test_deploy_every_scenario_as_separate_lab(tmp_path: Path) -> None:
    workspace(tmp_path)
    with patch.object(deploy, "run_deployments", return_value=0) as runner, \
         patch.object(api, "connect", return_value=connection()), \
         patch.object(api, "write_ssh_config"):
        assert cli.main([
            "deploy", "--all-scenarios", "--copies", "2", "--start-index", "101",
            "--parallel-copies", "3", "--no-provider-vlans",
        ], tmp_path) == 0

    run = next((tmp_path / "runs").iterdir())
    saved = json.loads((run / "run.json").read_text())
    expected = {
        "lab-core-101": ["bootstrap"],
        "lab-core-102": ["bootstrap"],
        "lab-attack-103": ["bootstrap", "attacker"],
        "lab-attack-104": ["bootstrap", "attacker"],
        "lab-video-105": ["bootstrap", "videoserver"],
        "lab-video-106": ["bootstrap", "videoserver"],
    }
    assert saved["scenario_deployments"] == expected
    assert saved["units"] == ["bootstrap", "attacker", "videoserver"]
    assert saved["complete"] and saved["deployed"]
    assert runner.call_args.args[1] == expected
    assert runner.call_args.args[2] == list(expected)
    assert runner.call_args.kwargs["parallel_copies"] == 3
    assert runner.call_args.kwargs["env_override"]["ATTACKBED_USE_PROVIDER_VLANS"] == "false"


def test_resume_retries_only_failed_scenarios(tmp_path: Path) -> None:
    workspace(tmp_path)
    attempts = []

    def runner(root, units, names, action, *, on_success, **kwargs):
        attempts.append(list(names))
        if len(attempts) == 1:
            on_success("lab-core-001")
            return 1
        for name in names:
            on_success(name)
        return 0

    with patch.object(deploy, "run_deployments", side_effect=runner), \
         patch.object(api, "write_ssh_config"):
        with pytest.raises(AttackBedError, match="Terragrunt apply failed"):
            api.deploy(all_scenarios=True, root=tmp_path, connection=connection())
        run = next((tmp_path / "runs").iterdir())
        saved = json.loads((run / "run.json").read_text())
        assert saved["completed_deployments"] == ["lab-core-001"]
        assert not saved["deployed"]
        api.resume(run.name, root=tmp_path, connection=connection())

    assert attempts == [
        ["lab-core-001", "lab-attack-002", "lab-video-003"],
        ["lab-attack-002", "lab-video-003"],
    ]
    saved = json.loads((run / "run.json").read_text())
    assert saved["deployed"] and saved["complete"]
    assert set(saved["completed_deployments"]) == set(saved["deployments"])


def test_destroy_run_uses_each_scenarios_units_and_vlan_switch(tmp_path: Path) -> None:
    workspace(tmp_path)
    with patch.object(deploy, "run_deployments", return_value=0) as runner, \
         patch.object(api, "write_ssh_config"):
        run = api.deploy(
            all_scenarios=True, use_provider_vlans=False,
            root=tmp_path, connection=connection(),
        )
        runner.reset_mock()
        api.destroy(run.name, root=tmp_path)

    saved = json.loads((run / "run.json").read_text())
    assert saved["destroyed"] and not saved["deployed"]
    assert runner.call_args.args[1] == saved["scenario_deployments"]
    assert runner.call_args.args[2] == saved["deployments"]
    assert runner.call_args.args[3] == "destroy"
    assert runner.call_args.kwargs["env_override"]["ATTACKBED_USE_PROVIDER_VLANS"] == "false"


def test_state_cleanup_uses_each_scenarios_unit_list(tmp_path: Path) -> None:
    workspace(tmp_path)
    with patch.object(deploy, "run_deployments", return_value=0), \
         patch.object(api, "write_ssh_config"):
        run = api.deploy(all_scenarios=True, root=tmp_path, connection=connection())
        api.destroy(run.name, root=tmp_path)

    with patch.object(api, "_check_state_credentials"), \
         patch.object(deploy, "delete_deployment_states") as cleanup:
        api.destroy(run.name, delete_states=True, root=tmp_path)

    assert [call.args for call in cleanup.call_args_list] == [
        ("lab-core-001", ["bootstrap"]),
        ("lab-attack-002", ["bootstrap", "attacker"]),
        ("lab-video-003", ["bootstrap", "videoserver"]),
    ]


def test_runner_uses_each_scenarios_own_unit_list(tmp_path: Path) -> None:
    workspace(tmp_path)
    mapping = {
        "lab-core-001": ["bootstrap"],
        "lab-attack-002": ["bootstrap", "attacker"],
    }
    launched = []
    completed = []

    def run(deployment, action):
        launched.append((deployment.name, deployment.units, action))

    with patch.object(deploy.TerragruntDeployment, "run", run):
        assert deploy.run_deployments(
            tmp_path / "terragrunt", mapping, list(mapping), "apply",
            on_success=completed.append,
        ) == 0

    assert sorted(launched) == sorted([
        ("lab-core-001", ["bootstrap"], "apply"),
        ("lab-attack-002", ["bootstrap", "attacker"], "apply"),
    ])
    assert sorted(completed) == sorted(mapping)


def test_invalid_all_scenario_arguments(tmp_path: Path) -> None:
    workspace(tmp_path)
    for argv in (
        ["deploy"],
        ["deploy", "core", "--all-scenarios"],
        ["deploy", "core", "--start-index", "2"],
    ):
        with pytest.raises(SystemExit):
            cli.main(argv, tmp_path)
    with pytest.raises(ValueError, match="between 1 and 500"):
        api.deploy(
            all_scenarios=True, copies=200, root=tmp_path,
            connection=connection(),
        )


def test_provider_vlan_setting_defaults_to_tfvars(tmp_path: Path) -> None:
    workspace(tmp_path)
    with patch.object(deploy, "run_deployments", return_value=0) as runner, \
         patch.object(api, "write_ssh_config"):
        api.deploy(all_scenarios=True, root=tmp_path, connection=connection())
    assert "ATTACKBED_USE_PROVIDER_VLANS" not in runner.call_args.kwargs["env_override"]

    module = api.ROOT / "terragrunt/bootstrap/module"
    assert (module / "main.tf").read_text().count(
        "value_specs = var.use_provider_vlans ?"
    ) == 5


def test_real_config_excludes_all_scenario() -> None:
    scenarios = api.all_scenario_units(api.ROOT)
    assert "all" not in scenarios
    assert list(scenarios) == [
        "core", "attack", "video", "demo", "repository",
        "client", "lanturtle", "docker",
    ]
