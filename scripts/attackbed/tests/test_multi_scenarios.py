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
        "  all: [bootstrap, attacker, videoserver, repository]\n"
        "  core: [bootstrap]\n"
        "  videoserver: [bootstrap, attacker, videoserver]\n"
        "  linuxmalware: [bootstrap, attacker, videoserver]\n"
        "  lateralmovement: [bootstrap, attacker, repository]\n"
        "image_recipes: {}\n"
    )
    for name in ("bootstrap", "attacker", "videoserver", "repository"):
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
        "lab-videoserver-101": ["bootstrap", "attacker", "videoserver"],
        "lab-videoserver-102": ["bootstrap", "attacker", "videoserver"],
        "lab-linuxmalware-103": ["bootstrap", "attacker", "videoserver"],
        "lab-linuxmalware-104": ["bootstrap", "attacker", "videoserver"],
        "lab-lateralmovement-105": ["bootstrap", "attacker", "repository"],
        "lab-lateralmovement-106": ["bootstrap", "attacker", "repository"],
    }
    assert saved["scenario_deployments"] == expected
    assert saved["units"] == ["bootstrap", "attacker", "videoserver", "repository"]
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
            on_success("lab-videoserver-001")
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
        assert saved["completed_deployments"] == ["lab-videoserver-001"]
        assert not saved["deployed"]
        api.resume(run.name, root=tmp_path, connection=connection())

    assert attempts == [
        ["lab-videoserver-001", "lab-linuxmalware-002", "lab-lateralmovement-003"],
        ["lab-linuxmalware-002", "lab-lateralmovement-003"],
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
        ("lab-videoserver-001", ["bootstrap", "attacker", "videoserver"]),
        ("lab-linuxmalware-002", ["bootstrap", "attacker", "videoserver"]),
        ("lab-lateralmovement-003", ["bootstrap", "attacker", "repository"]),
    ]


def test_runner_uses_each_scenarios_own_unit_list(tmp_path: Path) -> None:
    workspace(tmp_path)
    mapping = {
        "lab-videoserver-001": ["bootstrap", "attacker", "videoserver"],
        "lab-lateralmovement-002": ["bootstrap", "attacker", "repository"],
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
        ("lab-videoserver-001", ["bootstrap", "attacker", "videoserver"], "apply"),
        ("lab-lateralmovement-002", ["bootstrap", "attacker", "repository"], "apply"),
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


def test_real_config_matches_documented_scenarios() -> None:
    scenarios = api.all_scenario_units(api.ROOT)
    assert "all" not in scenarios
    assert "core" not in scenarios
    assert api.scenario_units(api.ROOT, "core") == ["bootstrap"]
    assert scenarios == {
        "videoserver": ["bootstrap", "attacker", "videoserver"],
        "linuxmalware": ["bootstrap", "attacker", "videoserver"],
        "lateralmovement": ["bootstrap", "attacker", "repository"],
        "network": ["bootstrap", "attacker", "repository"],
        "lanturtle": ["bootstrap", "lanturtle"],
        "client": ["bootstrap", "attacker", "client"],
        "docker": ["bootstrap", "attacker", "docker"],
    }


def test_short_options_and_top_level_help(tmp_path: Path, capsys) -> None:
    parser = cli.make_parser()
    deploy_options = parser.parse_args([
        "deploy", "-a", "-v", "-p", "7", "-t", "2",
        "-c", "2", "-I", "101", "-n", "test", "-d",
    ])
    assert deploy_options.all_scenarios
    assert deploy_options.no_provider_vlans
    assert deploy_options.parallel_copies == 7
    assert deploy_options.tofu_parallelism == 2
    assert deploy_options.copies == 2
    assert deploy_options.start_index == 101
    assert deploy_options.prefix == "test"
    assert deploy_options.debug

    destroy_options = parser.parse_args([
        "destroy", "videoserver", "-s", "-p", "3", "-t", "4", "-c", "2",
    ])
    assert destroy_options.delete_states
    assert destroy_options.parallel_copies == 3
    assert destroy_options.tofu_parallelism == 4
    assert destroy_options.copies == 2
    assert parser.parse_args(["deploy", "core", "-b"]).build
    assert parser.parse_args(["deploy", "core", "-i", "images.json"]).images == Path("images.json")

    with pytest.raises(SystemExit) as help_exit:
        cli.main(["--help"], tmp_path)
    assert help_exit.value.code == 0
    help_text = capsys.readouterr().out
    for expected in (
        "-a, --all-scenarios", "-v, --no-provider-vlans",
        "-s, --delete-states", "-p, --parallel-copies",
        "-t, --tofu-parallelism", "-c, --copies", "-n, --prefix",
        "-I, --start-index", "-b, --build", "-i, --images",
        "-d, --debug", "deploy core",
    ):
        assert expected in help_text


def test_short_switches_forward_correctly(tmp_path: Path) -> None:
    with patch.object(api, "deploy") as deploy_api, patch.object(api, "destroy") as destroy_api:
        cli.main(["deploy", "-a", "-v", "-p", "6", "-t", "3"], tmp_path)
        assert deploy_api.call_args.kwargs["all_scenarios"] is True
        assert deploy_api.call_args.kwargs["use_provider_vlans"] is False
        assert deploy_api.call_args.kwargs["parallel_copies"] == 6
        assert deploy_api.call_args.kwargs["tofu_parallelism"] == 3

        cli.main(["destroy", "videoserver", "-c", "1", "-s", "-p", "2", "-t", "4"], tmp_path)
        assert destroy_api.call_args.kwargs["delete_states"] is True
        assert destroy_api.call_args.kwargs["parallel_copies"] == 2
        assert destroy_api.call_args.kwargs["tofu_parallelism"] == 4
