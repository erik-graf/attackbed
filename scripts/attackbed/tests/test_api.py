"""Python API and per-run Terraform image-variable artifacts."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from attackbed import api, deploy as terragrunt
from attackbed.errors import AttackBedError


def workspace(root: Path) -> None:
    config = root / "config"
    config.mkdir()
    (config / "config.yaml").write_text(
        "scenarios:\n  core: [bootstrap]\n"
        "image_recipes:\n  inetfw_image: firewall\n  corpdns_image: corpdns\n"
    )
    module = root / "terragrunt" / "bootstrap"
    (module / "module").mkdir(parents=True)
    (module / "terragrunt.hcl").touch()
    (module / "module" / "variables.tf").write_text(
        'variable "inetfw_image" {}\nvariable "corpdns_image" {}\n'
    )
    for recipe in ("firewall", "corpdns"):
        path = root / "packer" / recipe
        path.mkdir(parents=True)
        (path / "default.json.example").write_text('{"image_name": "atb-' + recipe + '"}')


def test_python_build_api_writes_tfvars_for_both_images(tmp_path: Path) -> None:
    workspace(tmp_path)
    names = {"corpdns": "atb-corpdns-20261123", "firewall": "atb-firewall-20261123"}
    connection = SimpleNamespace()

    with patch.object(api, "build_image", side_effect=lambda conn, root, recipe, log, debug=False: {
        "id": recipe, "name": names[recipe],
    }):
        run = api.build("core", root=tmp_path, connection=connection)

    assert run.is_dir()
    assert (run / "images.json").is_file()
    assert (run / "images.tfvars").read_text().splitlines()[1:] == [
        'corpdns_image = "atb-corpdns-20261123"',
        'inetfw_image = "atb-firewall-20261123"',
    ]
    assert json.loads((run / "run.json").read_text())["complete"]


def test_python_api_deploy_resume_preserves_selected_image_names(tmp_path: Path) -> None:
    workspace(tmp_path)
    selected = [
        SimpleNamespace(
            id="id-dns", name="atb-corpdns-1", status="active", created_at="2026-11-23",
        ),
        SimpleNamespace(
            id="id-fw", name="atb-firewall-1", status="active", created_at="2026-11-23",
        ),
    ]
    connection = SimpleNamespace(image=SimpleNamespace(
        images=lambda: selected,
        get_image=lambda image_id: next((item for item in selected if item.id == image_id), None),
    ))
    with patch.object(terragrunt, "run_deployments", side_effect=[1, 0]) as runner, \
         patch.object(api, "write_ssh_config"):
        with pytest.raises(AttackBedError, match="Terragrunt apply failed"):
            api.deploy("core", root=tmp_path, connection=connection, copies=2)
        run = next((tmp_path / "runs").iterdir())
        assert 'inetfw_image = "atb-firewall-1"' in (run / "images.tfvars").read_text()
        completed = api.resume(run.name, root=tmp_path, connection=connection)

    assert completed == run
    assert runner.call_count == 2
    assert runner.call_args.args[2] == ["lab-001", "lab-002"]
    assert json.loads((run / "run.json").read_text())["complete"]


def test_image_tfvars_escapes_quotes_and_backslashes(tmp_path: Path) -> None:
    destination = tmp_path / "images.tfvars"
    api.write_image_tfvars(destination, {"adminpc_image": {"id": "1", "name": 'my"image\\v2'}})
    assert destination.read_text() == (
        '# Image names selected for this AttackBed run.\n'
        'adminpc_image = "my\\"image\\\\v2"\n'
    )


def test_all_scenario_resolves_all_terragrunt_units() -> None:
    units = api.scenario_units(api.ROOT, "all")
    assert units == [
        "bootstrap", "attacker", "client", "docker", "lanturtle",
        "logging", "repository", "videoserver", "wazuh",
    ]


def test_python_plan_api_does_not_require_argparse(tmp_path: Path) -> None:
    workspace(tmp_path)
    with patch.object(terragrunt, "run_deployments", return_value=0) as runner:
        run = api.plan("core", copies=2, root=tmp_path)
    assert run.parent == tmp_path / "runs"
    assert runner.call_args.args[:4] == (
        tmp_path / "terragrunt", ["bootstrap"], ["lab-001", "lab-002"], "plan"
    )
