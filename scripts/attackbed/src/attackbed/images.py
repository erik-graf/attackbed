"""Build or discover OpenStack images for the requested Terraform units."""

import json
import logging
import os
from pathlib import Path
from typing import Any, Mapping, Sequence
import re
import subprocess
from uuid import UUID

import yaml

from .errors import AttackBedError, CommandError, redact

LOGGER = logging.getLogger(__name__)


def required_recipes(root: Path, units: Sequence[str]) -> dict[str, str]:
    recipes: dict[str, str] = yaml.safe_load((root / "config/image-recipes.yaml").read_text())
    variables = set()
    for unit in units:
        for path in (root / "terragrunt" / unit / "module").glob("*.tf"):
            variables.update(re.findall(r'variable\s+"(\w+_image)"', path.read_text()))
    return {name: recipes[name] for name in sorted(variables & recipes.keys())}


def recipe_config(root: Path, recipe: str, build: bool = False) -> dict[str, Any]:
    directory = root / "packer" / recipe
    example = directory / "default.json.example"
    shared = root / "packer" / "defaults.json"
    local = directory / "default.json"
    config: dict[str, Any] = {}
    overrides: dict[str, Any] = {}
    for path in (example, shared, local):
        if path.is_file():
            values = json.loads(path.read_text())
            if not isinstance(values, dict):
                raise ValueError(f"{path} must contain a JSON object")
            config.update(values)
            if path != example:
                overrides.update(values)
    if build and any(not overrides.get(key) for key in ("network", "floating_ip_pool")):
        raise ValueError(f"Configure network and floating_ip_pool in {shared} or {local}")
    if not config:
        raise ValueError(f"Missing Packer configuration for {recipe}")
    return config


def active_image(conn: Any, image_id: str) -> dict[str, str]:
    image = conn.image.get_image(image_id)
    if not image or image.status.lower() != "active":
        raise ValueError(f"Image {image_id} is missing or not active")
    return {"id": image.id, "name": image.name}


def latest_images(conn: Any, root: Path, recipes: Mapping[str, str]) -> dict[str, dict[str, str]]:
    available = list(conn.image.images())
    selected: dict[str, dict[str, str]] = {}
    for role, recipe in recipes.items():
        config = recipe_config(root, recipe)
        prefix = config["image_name"]
        matches = [image for image in available if image.status.lower() == "active"
                   and (image.name == prefix or (config.get("timestamp_image", True)
                        and image.name.startswith(prefix + "-")))]
        if not matches:
            raise ValueError(f"No active image found for {role} ({prefix}); use --build")
        image = max(matches, key=lambda entry: entry.created_at or "")
        selected[role] = {"id": image.id, "name": image.name}
    return selected


def _setup_command(command: list[str], directory: Path, log_path: Path, recipe: str, debug: bool) -> None:
    """Run a Packer prerequisite; capture and record output even when it fails."""
    stage = f"{recipe}: {' '.join(command[:2])}"
    LOGGER.info("Running %s", stage)
    output = ""
    try:
        result = subprocess.run(
            command, cwd=directory, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        output = result.stdout if isinstance(result.stdout, str) else ""
    except subprocess.CalledProcessError as exc:
        output = exc.stdout if isinstance(exc.stdout, str) else ""
        with log_path.open("a") as logfile:
            logfile.write(f"\n--- {stage} ---\n{redact(output)}\nFAILED (exit code {exc.returncode})\n")
        raise CommandError(stage, command, returncode=exc.returncode, log_path=log_path) from exc
    except OSError as exc:
        with log_path.open("a") as logfile:
            logfile.write(f"\n--- {stage} ---\nFAILED: {redact(str(exc))}\n")
        raise CommandError(stage, command, log_path=log_path, reason=redact(str(exc))) from exc

    with log_path.open("a") as logfile:
        logfile.write(f"\n--- {stage} ---\n{redact(output)}")
    if debug and output:
        LOGGER.info("%s", redact(output).rstrip())


def build_image(conn: Any, root: Path, recipe: str, log_path: Path, debug: bool = False) -> dict[str, str]:
    """Build and validate a Glance image, stopping on any failed prerequisite."""
    config = recipe_config(root, recipe, build=True)
    directory = root / "packer" / recipe
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(mode=0o600, exist_ok=True)
    log_path.chmod(0o600)
    galaxy_cmd = [
        "ansible-galaxy", "role", "install",
        "-r", "playbook/requirements.yml", "-p", "playbook/roles",
    ]
    _setup_command(galaxy_cmd, directory, log_path, recipe, debug)
    _setup_command(["packer", "init", "."], directory, log_path, recipe, debug)

    config_file = log_path.with_suffix(".vars.json")
    config_file.touch(mode=0o600, exist_ok=True)
    config_file.chmod(0o600)
    config_file.write_text(json.dumps(config, indent=2) + "\n")

    image_id = None
    command = ["packer", "-machine-readable", "build", f"-var-file={config_file.resolve()}", "."]
    with log_path.open("a", buffering=1) as logfile:
        logfile.write(f"\n--- Packer build: {recipe} ---\n")
        try:
            with subprocess.Popen(
                command, cwd=directory, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True,
                env={**os.environ, "PACKER_LOG": "1"} if debug else None,
            ) as process:
                assert process.stdout is not None
                for line in process.stdout:
                    logfile.write(redact(line))
                    fields = line.rstrip("\n").split(",", 5)
                    if len(fields) == 6 and fields[2] == "artifact" and fields[4] == "id":
                        value = fields[5].strip().rsplit(":", 1)[-1]
                        try:
                            image_id = str(UUID(value))
                        except ValueError:
                            pass
                    if debug:
                        LOGGER.info("%s", redact(line).rstrip())
                    elif len(fields) >= 5 and fields[2] == "ui" and fields[3] in ("say", "message", "error"):
                        LOGGER.info("%s", redact(fields[4]))
                returncode = process.wait()
        except OSError as exc:
            raise CommandError(
                f"Packer build for {recipe}", command, log_path=log_path,
                reason=redact(str(exc)),
            ) from exc

    if returncode:
        raise CommandError(f"Packer build for {recipe}", command, returncode=returncode, log_path=log_path)
    if image_id is None:
        raise AttackBedError(f"Packer {recipe} returned no image UUID; see {log_path}")
    return active_image(conn, image_id)
