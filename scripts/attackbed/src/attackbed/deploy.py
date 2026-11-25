#!/usr/bin/env python3
"""Run independent AttackBed deployments using the existing Terragrunt units."""

from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable, Mapping, Sequence
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4

from .arguments import deployment_name, positive_int
from .errors import AttackBedError, CommandError, redact

LOGGER = logging.getLogger(__name__)


class TerragruntDeployment:
    """Run the ordered units for one isolated deployment."""

    def __init__(
        self, root: Path, name: str, units: list[str], *,
        tofu_parallelism: int | None = None, log_path: Path | None = None,
        debug: bool = False, env: Mapping[str, str] | None = None,
        delete_states: bool = False,
    ) -> None:
        self.root = root
        self.name = name
        self.units = units
        self.tofu_parallelism = tofu_parallelism
        self.log_path = log_path
        self.debug = debug
        self.delete_states = delete_states
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
        if action == "destroy" and self.delete_states:
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




def run_deployments(
    root: Path,
    units: Sequence[str] | Mapping[str, Sequence[str]],
    names: Sequence[str],
    action: str,
    *,
    run_dir: Path | None = None,
    parallel_copies: int = 4,
    tofu_parallelism: int | None = None,
    delete_states: bool = False,
    debug: bool = False,
    env_override: Mapping[str, str] | None = None,
    on_success: Callable[[str], None] | None = None,
) -> int:
    """Orchestrate the specified units without parsing CLI arguments."""
    if action not in ("plan", "apply", "destroy"):
        raise ValueError(f"Unknown Terragrunt action: {action}")
    if not names or any(not re.fullmatch(r"[a-z][a-z0-9-]*", name) for name in names):
        raise ValueError("Deployment IDs must contain lowercase letters, digits or hyphens")
    if parallel_copies < 1 or (tofu_parallelism is not None and tofu_parallelism < 1):
        raise ValueError("Parallelism must be positive")
    if delete_states and action != "destroy":
        raise ValueError("State cleanup is only available for destroy")
    if isinstance(units, Mapping):
        if any(name not in units for name in names):
            raise ValueError("Missing units for a deployment")
        unit_sets = {name: list(units[name]) for name in names}
    else:
        unit_sets = {name: list(units) for name in names}
    if any(not selected or any(not (root / unit / "terragrunt.hcl").is_file()
                               for unit in selected) for selected in unit_sets.values()):
        raise ValueError("Terragrunt units must exist and contain terragrunt.hcl")

    env = {**os.environ, **(env_override or {})}
    for variable in ("TG_DOWNLOAD_DIR", "TF_DATA_DIR"):
        if env.get(variable):
            raise ValueError(f"Unset {variable} to preserve cache isolation")
    if delete_states:
        for variable in (
            "GITLAB_STATE_REPOSITORY", "CR_GITLAB_ACCESS_TOKEN",
            "OS_PROJECT_NAME", "OS_USER_DOMAIN_NAME",
        ):
            if not env.get(variable):
                raise ValueError(f"{variable} is required for --delete-states")

    if run_dir is None:
        run_id = "run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
        run_dir = root.parent / "runs" / run_id
    log_dir = run_dir / "logs"
    log_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    log_path = log_dir / f"{action}.log"
    log_path.touch(mode=0o600, exist_ok=True)
    log_path.chmod(0o600)

    handlers = _configure_logging(log_path, debug)
    try:
        LOGGER.info("--- %s %s ---", action, datetime.now(timezone.utc).isoformat())

        def worker(name: str) -> tuple[str, AttackBedError | None]:
            deployment = TerragruntDeployment(
                root, name, unit_sets[name], tofu_parallelism=tofu_parallelism,
                log_path=log_path, debug=debug, env=env, delete_states=delete_states,
            )
            try:
                deployment.run(action)
            except AttackBedError as exc:
                LOGGER.error("[%s] FAILED: %s", name, redact(str(exc), env))
                return name, exc
            return name, None

        results = []
        with ThreadPoolExecutor(max_workers=parallel_copies) as executor:
            futures = [executor.submit(worker, name) for name in dict.fromkeys(names)]
            for future in as_completed(futures):
                name, error = future.result()
                results.append((name, error))
                if error is None and on_success is not None:
                    on_success(name)
        failures = [name for name, error in results if error is not None]
        LOGGER.info("%d deployment(s) succeeded, %d failed", len(results) - len(failures), len(failures))
    finally:
        for handler in handlers:
            LOGGER.removeHandler(handler)
            handler.close()

    print(f"Log: {log_path}", flush=True)
    return int(bool(failures))
