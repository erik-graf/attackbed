#!/usr/bin/env python3
"""Run independent AttackBed deployments using the existing Terragrunt units."""

import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Mapping, Sequence
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4

import yaml

from .errors import AttackBedError, CommandError, redact

ROOT = Path(__file__).resolve().parents[4] / "terragrunt"
LOGGER = logging.getLogger(__name__)


def scenario_units(root: Path, scenario: str) -> list[str]:
    with (root.parent / "config/scenarios.yaml").open() as stream:
        scenarios: dict[str, list[str]] = yaml.safe_load(stream)
    if scenario not in scenarios:
        raise ValueError(f"Unknown scenario: {scenario}")

    units = list(dict.fromkeys(scenarios[scenario]))
    if "bootstrap" not in units:
        raise ValueError(f"Scenario {scenario} must include bootstrap")
    units.remove("bootstrap")
    units.insert(0, "bootstrap")
    for unit in units:
        if not (root / unit / "terragrunt.hcl").is_file():
            raise ValueError(f"Unknown Terragrunt unit: {unit}")
    return units


class TerragruntDeployment:
    """Run the ordered units for one isolated deployment."""

    def __init__(
        self, root: Path, name: str, units: list[str], *,
        tofu_parallelism: int | None = None, log_path: Path | None = None,
        debug: bool = False, env: Mapping[str, str] | None = None,
    ) -> None:
        self.root = root
        self.name = name
        self.units = units
        self.tofu_parallelism = tofu_parallelism
        self.log_path = log_path
        self.debug = debug
        self.env = dict(os.environ if env is None else env)

    def run_unit(self, unit: str, action: str) -> None:
        env = {**self.env, "ATTACKBED_DEPLOYMENT_ID": self.name}
        command = ["terragrunt", action, "--non-interactive"]
        if self.tofu_parallelism is not None:
            if action == "apply":
                # The HCL supplies the apply flag; don't pass it twice.
                env["TF_VAR_parallelism"] = str(self.tofu_parallelism)
            else:
                command.append(f"-parallelism={self.tofu_parallelism}")
        if action in ("apply", "destroy"):
            command.append("-auto-approve")

        label = f"{self.name}/{unit}"
        stage = f"Terragrunt {action} for {label}"
        tail = deque(maxlen=40)
        LOGGER.info("[%s] %s started", label, action)
        try:
            with subprocess.Popen(
                command, cwd=self.root / unit, env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            ) as process:
                assert process.stdout is not None
                for line in process.stdout:
                    safe = redact(line.rstrip("\n"), env)
                    LOGGER.debug("[%s] %s", label, safe)
                    tail.append(safe)
                returncode = process.wait()
        except OSError as exc:
            raise CommandError(
                stage, command, log_path=self.log_path, reason=redact(str(exc), env),
            ) from exc

        if returncode:
            if not self.debug:
                for line in tail:
                    LOGGER.error("[%s] %s", label, line)
            raise CommandError(stage, command, returncode=returncode, log_path=self.log_path)

        LOGGER.info("[%s] OK", label)

    def run(self, action: str) -> None:
        order = reversed(self.units) if action == "destroy" else iter(self.units)
        for unit in order:
            self.run_unit(unit, action)
        if action == "destroy":
            try:
                delete_deployment_states(self.name, self.units, env=self.env)
            except (OSError, ValueError, RuntimeError, TypeError) as exc:
                raise AttackBedError(
                    f"{self.name}: infrastructure destroyed, but GitLab state cleanup failed: "
                    f"{redact(str(exc), self.env)}"
                ) from exc


def _configure_logging(log_path: Path, debug: bool) -> tuple[logging.Handler, logging.Handler]:
    """Give all deployment threads the same thread-safe console and file handlers."""
    LOGGER.setLevel(logging.DEBUG)
    LOGGER.propagate = False
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if debug else logging.INFO)
    file = logging.FileHandler(log_path, encoding="utf-8")
    file.setLevel(logging.DEBUG)
    for handler in (console, file):
        handler.setFormatter(logging.Formatter("%(message)s"))
        LOGGER.addHandler(handler)
    return console, file


def delete_deployment_states(
    deployment_id: str, units: Sequence[str], env: Mapping[str, str] | None = None,
) -> None:
    settings = os.environ if env is None else env
    base = settings["GITLAB_STATE_REPOSITORY"].rstrip("/")
    token = settings["CR_GITLAB_ACCESS_TOKEN"]
    path = urlsplit(base)
    if path.scheme != "https" or not re.fullmatch(r"/api/v4/projects/[^/]+/terraform/state", path.path):
        raise ValueError("GITLAB_STATE_REPOSITORY must be an HTTPS GitLab Terraform state API URL")
    prefix = "_".join((
        settings["OS_PROJECT_NAME"], settings["OS_USER_DOMAIN_NAME"],
        settings.get("OS_REGION_NAME", "default"), deployment_id,
    ))
    for unit in units:
        state_name = f"{prefix}_{unit}"
        url = f"{base}/{quote(state_name, safe='')}"
        headers = {"PRIVATE-TOKEN": token}
        try:
            with urlopen(Request(url, headers=headers), timeout=30) as response:
                state = json.load(response)
        except HTTPError as exc:
            if exc.code == 404:
                continue  # Already absent; no state to remove.
            raise
        if not isinstance(state, dict) or not isinstance(state.get("resources"), list):
            raise ValueError(f"Unexpected Terraform state format: {state_name}")
        if any(resource.get("mode") != "data" and resource.get("instances")
               for resource in state["resources"]):
            raise RuntimeError(f"GitLab state still tracks resources: {state_name}")
        try:
            with urlopen(Request(url, headers=headers, method="DELETE"), timeout=30):
                pass
        except HTTPError as exc:
            if exc.code != 404:
                raise
        LOGGER.info("[%s] deleted state %s", deployment_id, state_name)



def main(
    argv: Sequence[str] | None = None, root: Path = ROOT, run_dir: Path | None = None,
    env_override: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", help="Scenario from config/scenarios.yaml")
    parser.add_argument("action", choices=("plan", "apply", "destroy"))
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--copies", type=int, help="Select PREFIX-001 through PREFIX-N")
    selection.add_argument("--deployment", action="append", help="Deployment ID (repeatable)")
    parser.add_argument("--prefix", default="lab", help="Prefix for --copies")
    parser.add_argument("--parallel-copies", type=int, default=4, help="Concurrent deployments")
    parser.add_argument("--tofu-parallelism", type=int, help="OpenTofu operations per unit")
    parser.add_argument("--debug", action="store_true", help="Stream full Terragrunt output")
    args = parser.parse_args(argv)

    if args.copies is not None and args.copies < 1:
        parser.error("--copies must be positive")
    if args.parallel_copies < 1:
        parser.error("--parallel-copies must be positive")
    if args.tofu_parallelism is not None and args.tofu_parallelism < 1:
        parser.error("--tofu-parallelism must be positive")

    env = {**os.environ, **(env_override or {})}
    for variable in ("TG_DOWNLOAD_DIR", "TF_DATA_DIR"):
        if env.get(variable):
            parser.error(f"Unset {variable} to preserve cache isolation")

    names = args.deployment or [
        f"{args.prefix}-{index:03d}" for index in range(1, args.copies + 1)
    ]
    if any(not re.fullmatch(r"[a-z][a-z0-9-]*", name) for name in names):
        parser.error("Deployment IDs must be lowercase letters, digits or hyphens")
    names = list(dict.fromkeys(names))
    units = scenario_units(root, args.scenario)

    if args.action == "destroy":
        for variable in ("GITLAB_STATE_REPOSITORY", "CR_GITLAB_ACCESS_TOKEN",
                         "OS_PROJECT_NAME", "OS_USER_DOMAIN_NAME"):
            if not env.get(variable):
                parser.error(f"{variable} is required to delete GitLab states after destroy")

    if run_dir is None:
        run_id = "run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
        run_dir = root.parent / "runs" / run_id
    log_dir = run_dir / "logs"
    log_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    log_path = log_dir / f"{args.action}.log"
    log_path.touch(mode=0o600, exist_ok=True)
    log_path.chmod(0o600)

    handlers = _configure_logging(log_path, args.debug)
    try:
        LOGGER.info("--- %s %s ---", args.action, datetime.now(timezone.utc).isoformat())

        def worker(name: str) -> tuple[str, AttackBedError | None]:
            deployment = TerragruntDeployment(
                root, name, units, tofu_parallelism=args.tofu_parallelism,
                log_path=log_path, debug=args.debug, env=env,
            )
            try:
                deployment.run(args.action)
            except AttackBedError as exc:
                LOGGER.error("[%s] FAILED: %s", name, redact(str(exc), env))
                return name, exc
            return name, None

        with ThreadPoolExecutor(max_workers=args.parallel_copies) as executor:
            results = list(executor.map(worker, names))
        failures = [name for name, error in results if error is not None]
        LOGGER.info("%d deployment(s) succeeded, %d failed", len(results) - len(failures), len(failures))
    finally:
        for handler in handlers:
            LOGGER.removeHandler(handler)
            handler.close()

    print(f"Log: {log_path}", flush=True)
    return int(bool(failures))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AttackBedError, OSError, ValueError, yaml.YAMLError) as exc:
        print(f"Error: {redact(str(exc))}", file=sys.stderr)
        sys.exit(1)
