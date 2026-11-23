"""Python API for building images and managing AttackBed deployments.

Import and call build(), deploy(), resume(), destroy(), or plan() without argparse.
Each completed call returns its run directory; operational failures raise exceptions.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Literal
from uuid import uuid4

import yaml

from . import deploy as terragrunt
from .errors import AttackBedError
from .images import active_image, build_image, latest_images, required_recipes
from .ssh import write_ssh_config

ROOT = Path(__file__).resolve().parents[4]


def connect() -> Any:
    """Connect using normal OpenStack SDK environment/cloud configuration."""
    try:
        import openstack
    except ImportError as exc:
        raise AttackBedError("OpenStack SDK is not installed; use uv to install CLI dependencies") from exc
    return openstack.connect()


def save_json(path: Path, value: object) -> None:
    """Atomically update resumable run metadata."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def resume_directory(runs: Path, requested: str) -> Path:
    """Find a saved run by ID, or the most recent run."""
    if requested == "latest":
        jobs = sorted(path for path in runs.glob("run-*") if (path / "run.json").is_file())
        if not jobs:
            raise ValueError("No runs to resume")
        return jobs[-1]
    if not re.fullmatch(r"run-[A-Za-z0-9-]+", requested):
        raise ValueError("Invalid run ID")
    directory = runs / requested
    if not (directory / "run.json").is_file():
        raise ValueError(f"Unknown run: {requested}")
    return directory


def scenario_units(root: Path, scenario: str) -> list[str]:
    """Resolve and validate the units for a configured scenario."""
    scenarios: dict[str, list[str]] = yaml.safe_load((root / "config/config.yaml").read_text())["scenarios"]
    if scenario not in scenarios:
        raise ValueError(f"Unknown scenario: {scenario}")
    units = list(dict.fromkeys(scenarios[scenario]))
    if "bootstrap" not in units:
        raise ValueError(f"Scenario {scenario} must include bootstrap")
    units.remove("bootstrap")
    units.insert(0, "bootstrap")
    for unit in units:
        if not (root / "terragrunt" / unit / "terragrunt.hcl").is_file():
            raise ValueError(f"Unknown Terragrunt unit: {unit}")
    return units


def write_image_tfvars(path: Path, images: dict[str, dict[str, str]]) -> None:
    """Write selected Glance image names as ordinary HCL Terraform variables."""
    lines = ["# Image names selected for this AttackBed run."]
    for variable, image in sorted(images.items()):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable):
            raise ValueError(f"Invalid Terraform variable name: {variable}")
        lines.append(f"{variable} = {json.dumps(image['name'])}")
    temporary = path.with_suffix(".tfvars.tmp")
    temporary.write_text("\n".join(lines) + "\n")
    temporary.replace(path)


def _save_images(directory: Path, images: dict[str, dict[str, str]]) -> None:
    save_json(directory / "images.json", images)
    write_image_tfvars(directory / "images.tfvars", images)


def _run_terragrunt(
    root: Path, units: list[str], deployments: list[str], action: str, *,
    run_dir: Path, images_file: Path | None = None, parallel_copies: int = 4,
    tofu_parallelism: int | None = None, delete_states: bool = False, debug: bool = False,
) -> None:
    env_override = {
        "ATTACKBED_IMAGES_FILE": str(images_file.resolve()) if images_file is not None else "",
    }
    result = terragrunt.run_deployments(
        root / "terragrunt", units, deployments, action, run_dir=run_dir,
        parallel_copies=parallel_copies, tofu_parallelism=tofu_parallelism,
        delete_states=delete_states, debug=debug, env_override=env_override,
    )
    if result:
        raise AttackBedError(f"Terragrunt {action} failed; see {run_dir / 'logs' / (action + '.log')}")


def _continue_run(
    directory: Path, job: dict[str, Any], *, root: Path, debug: bool,
    connection: Any = None,
) -> Path:
    if job.get("complete"):
        print(f"Already complete: {directory}", flush=True)
        return directory
    print(f"Run: {directory}", flush=True)
    conn = connection if connection is not None else connect()
    recipes = required_recipes(root, job["units"])
    images_file = directory / "images.json"
    images: dict[str, dict[str, str]] = json.loads(images_file.read_text()) if images_file.exists() else {}

    if job["mode"] == "build":
        packer_logs = directory / "logs" / "packer"
        packer_logs.mkdir(mode=0o700, parents=True, exist_ok=True)
        for role, recipe in recipes.items():
            if role in images:
                active_image(conn, images[role]["id"])
                continue
            print(f"Building {role} ({recipe})", flush=True)
            images[role] = build_image(conn, root, recipe, packer_logs / f"{recipe}.log", debug=debug)
            _save_images(directory, images)
    elif not images_file.exists():
        if job["mode"] == "latest":
            images = latest_images(conn, root, recipes)
        else:
            source = Path(job["source_images"])
            images = json.loads(source.read_text())
        images = {role: active_image(conn, images[role]["id"]) for role in recipes}
        _save_images(directory, images)

    # Resume older runs that already have images.json but no tfvars artifact.
    if not (directory / "images.tfvars").exists():
        _save_images(directory, images)

    if job["action"] == "build":
        job["complete"] = True
        save_json(directory / "run.json", job)
        print(f"Images: {images_file}")
        print(f"Terraform variables: {directory / 'images.tfvars'}")
        return directory

    if not job["deployed"]:
        _run_terragrunt(
            root, job["units"], job["deployments"], "apply", run_dir=directory,
            images_file=images_file, parallel_copies=job["parallel_copies"],
            tofu_parallelism=job["tofu_parallelism"], debug=debug,
        )
        job["deployed"] = True
        save_json(directory / "run.json", job)

    write_ssh_config(conn, job["deployments"], directory / "ssh_config")
    job["complete"] = True
    save_json(directory / "run.json", job)
    print(f"SSH: ssh -F {directory / 'ssh_config'} {job['deployments'][0]}-mgmt")
    return directory


def _start_run(
    scenario: str, action: Literal["build", "deploy"], *, root: Path,
    copies: int = 1, prefix: str = "lab", parallel_copies: int = 4,
    tofu_parallelism: int | None = None, build_images: bool = False,
    images: Path | None = None, connection: Any = None, debug: bool = False,
) -> Path:
    units = scenario_units(root, scenario)
    if copies < 1 or parallel_copies < 1 or (tofu_parallelism is not None and tofu_parallelism < 1):
        raise ValueError("Copies and parallelism must be positive")
    if not re.fullmatch(r"[a-z][a-z0-9-]*", prefix):
        raise ValueError("Invalid deployment prefix")
    if build_images and images is not None:
        raise ValueError("Cannot combine image builds with an explicit image file")
    if action == "build":
        build_images = True

    run_id = "run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
    directory = root / "runs" / run_id
    directory.mkdir(parents=True, mode=0o700)
    job: dict[str, Any] = {
        "action": action,
        "scenario": scenario,
        "units": units,
        "deployments": ([f"{prefix}-{n:03d}" for n in range(1, copies + 1)]
                        if action == "deploy" else []),
        "mode": "build" if build_images else "file" if images is not None else "latest",
        "source_images": str(images.expanduser().resolve()) if images is not None else None,
        "parallel_copies": parallel_copies if action == "deploy" else None,
        "tofu_parallelism": tofu_parallelism if action == "deploy" else None,
        "deployed": False,
        "complete": False,
    }
    save_json(directory / "run.json", job)
    return _continue_run(directory, job, root=root, connection=connection, debug=debug)


def build(scenario: str, *, root: Path = ROOT, connection: Any = None, debug: bool = False) -> Path:
    """Build the images required by a scenario, saving images.json and images.tfvars."""
    return _start_run(scenario, "build", root=root, connection=connection, debug=debug)


def deploy(
    scenario: str, *, copies: int = 1, prefix: str = "lab", parallel_copies: int = 4,
    tofu_parallelism: int | None = None, build_images: bool = False, images: Path | None = None,
    root: Path = ROOT, connection: Any = None, debug: bool = False,
) -> Path:
    """Deploy scenario copies, using latest, supplied, or freshly built images."""
    return _start_run(
        scenario, "deploy", copies=copies, prefix=prefix, parallel_copies=parallel_copies,
        tofu_parallelism=tofu_parallelism, build_images=build_images, images=images,
        root=root, connection=connection, debug=debug,
    )


def resume(
    run_id: str = "latest", *, root: Path = ROOT, connection: Any = None, debug: bool = False,
) -> Path:
    """Continue an interrupted build or deployment using saved run metadata."""
    directory = resume_directory(root / "runs", run_id)
    job = json.loads((directory / "run.json").read_text())
    if job.get("destroyed"):
        raise ValueError("This run was destroyed; start a new run")
    return _continue_run(directory, job, root=root, connection=connection, debug=debug)


def _check_state_credentials() -> None:
    for name in ("GITLAB_STATE_REPOSITORY", "CR_GITLAB_ACCESS_TOKEN",
                 "OS_PROJECT_NAME", "OS_USER_DOMAIN_NAME"):
        if not os.environ.get(name):
            raise ValueError(f"{name} is required for --delete-states")


def destroy(
    target: str, *, copies: int | None = None, prefix: str = "lab",
    parallel_copies: int | None = None, tofu_parallelism: int | None = None,
    delete_states: bool = False, root: Path = ROOT, debug: bool = False,
) -> Path:
    """Destroy a saved run or scenario copies; state removal is opt-in."""
    if copies is not None and copies < 1:
        raise ValueError("--copies must be positive")
    if parallel_copies is not None and parallel_copies < 1:
        raise ValueError("--parallel-copies must be positive")
    if tofu_parallelism is not None and tofu_parallelism < 1:
        raise ValueError("--tofu-parallelism must be positive")
    if not re.fullmatch(r"[a-z][a-z0-9-]*", prefix):
        raise ValueError("Invalid deployment prefix")

    if target.startswith("run-"):
        if copies is not None or prefix != "lab":
            raise ValueError("RUN_ID cannot be combined with --copies or --prefix")
        directory = resume_directory(root / "runs", target)
        job = json.loads((directory / "run.json").read_text())
        if job["action"] == "build":
            raise ValueError("Build-only runs have no infrastructure to destroy")
        if job.get("destroyed"):
            if delete_states and not job.get("states_deleted"):
                _check_state_credentials()
                for name in job["deployments"]:
                    terragrunt.delete_deployment_states(name, job["units"])
                job["states_deleted"] = True
                save_json(directory / "run.json", job)
                print(f"Deleted empty Terraform states: {directory}")
            else:
                print(f"Already destroyed: {directory}")
            return directory
        units = job.get("units") or scenario_units(root, job["scenario"])
        deployments = job["deployments"]
        parallel_copies = parallel_copies or job["parallel_copies"]
        tofu_parallelism = tofu_parallelism if tofu_parallelism is not None else job["tofu_parallelism"]
        image_file = directory / "images.json"
        if not image_file.exists():
            image_file = None
    else:
        if copies is None:
            raise ValueError("Destroying a scenario requires --copies")
        units = scenario_units(root, target)
        deployments = [f"{prefix}-{n:03d}" for n in range(1, copies + 1)]
        parallel_copies = parallel_copies or 4
        directory = root / "runs" / (
            "run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
        )
        image_file = None

    _run_terragrunt(
        root, units, deployments, "destroy", run_dir=directory, images_file=image_file,
        parallel_copies=parallel_copies, tofu_parallelism=tofu_parallelism,
        delete_states=delete_states, debug=debug,
    )
    if target.startswith("run-"):
        job["deployed"] = False
        job["destroyed"] = True
        job["states_deleted"] = delete_states
        save_json(directory / "run.json", job)
    return directory


def plan(
    scenario: str, *, copies: int = 1, prefix: str = "lab", parallel_copies: int = 4,
    tofu_parallelism: int | None = None, root: Path = ROOT, debug: bool = False,
) -> Path:
    """Run Terragrunt plans for scenario copies without changing infrastructure."""
    units = scenario_units(root, scenario)
    if copies < 1 or not re.fullmatch(r"[a-z][a-z0-9-]*", prefix):
        raise ValueError("Invalid copies or deployment prefix")
    directory = root / "runs" / (
        "run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
    )
    _run_terragrunt(
        root, units, [f"{prefix}-{n:03d}" for n in range(1, copies + 1)],
        "plan", run_dir=directory, parallel_copies=parallel_copies,
        tofu_parallelism=tofu_parallelism, debug=debug,
    )
    return directory
