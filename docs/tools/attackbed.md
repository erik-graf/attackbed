# AttackBed CLI

Run from the repository root with `uv run attackbed`. The CLI is its own Python subproject in `scripts/attackbed/` (package: `scripts/attackbed/src/attackbed/`). `uv` resolves it through the root workspace. Requires OpenStack and GitLab state credentials, Packer, Ansible, Terragrunt, and OpenTofu.

## Commands

```sh
uv run attackbed build demo                    # Build required Packer images only
uv run attackbed deploy demo --copies 2        # Deploy with latest matching images
uv run attackbed deploy demo --build --copies 2
uv run attackbed deploy demo --images runs/RUN_ID/images.json
uv run attackbed resume                        # Resume latest run
uv run attackbed resume RUN_ID
uv run attackbed destroy RUN_ID
uv run attackbed destroy demo --copies 2
uv run attackbed destroy RUN_ID --delete-states # Also works after a previous destroy
```

Use `attackbed --help` and `attackbed ACTION --help` for all options.

- `--prefix NAME`: deployment IDs `NAME-001`, `NAME-002`, etc. (default: `lab`).
- `--parallel-copies N`: concurrent labs (default: 4).
- `--tofu-parallelism N`: OpenTofu parallelism per unit (otherwise uses the Terragrunt setting).
- `--debug`: stream full Terragrunt output or Packer diagnostics and show tracebacks for operational failures.
- Deploy and destroy run without confirmation. A run-ID destroy uses saved deployment names; scenario/copies destroy does **not** update a saved run.
- `--delete-states` (destroy only): clean up empty GitLab Terraform states after successful destroy. Without it, states are retained. You can add the flag to an already-destroyed run to clean up later.
- Resume continues the original action; resuming a `build` never deploys.

## Configuration

`config/config.yaml` holds two sections: `scenarios` selects Terragrunt units, and `image_recipes` maps Terraform image variables to Packer directories. The CLI builds each required recipe once, or selects the latest active Glance image by recipe `image_name` prefix. Image variables without a Packer recipe use their Terragrunt defaults.

Set shared Packer options in ignored `packer/defaults.json` (copy `defaults.json.example`). Merge order: `packer/RECIPE/default.json.example` → `packer/defaults.json` → optional ignored `packer/RECIPE/default.json`. The recipe override wins; common settings include build network, floating IP pool, and build flavor. Direct Packer invocations do not use this merge.

Deployment settings live in `terragrunt/defaults.tfvars` and optional ignored `terragrunt/terraform.tfvars`.

The `all` scenario includes all nine Terragrunt units, primarily for `attackbed build all`. It may not deploy as one lab because some units create overlapping infrastructure.

## Runs and networking

Each invocation saves `runs/RUN_ID/run.json`, image selections in `images.json`, and corresponding image-name assignments in `images.tfvars` (for example, `inetfw_image = "atb-firewall-..."`). `images.tfvars` is a run artifact; Terragrunt continues using `images.json` for automatic selection. The image artifacts are updated as individual builds succeed and retained on resume. Logs are stored under `logs/` (`packer/RECIPE.log`, `apply.log`, `destroy.log`). Packer logs include `ansible-galaxy` and `packer init` output, including failures. Terragrunt logs record the command output from all deployment threads. Errors exit nonzero; already-running copies are allowed to finish and the summary reports failures. Retries append. Successful deployment also writes `ssh_config`. Each host uses its OpenStack keypair name as `IdentityFile ~/.ssh/KEY_NAME`; keep the private key under that filename locally. Build-only runs create no OpenStack deployment VMs. A saved image selection can be reused with `deploy --images`.

Bootstrap creates five vRack networks per deployment with VLANs `1000 + (N - 1) * 5` through `+4`, where `N` is the deployment ID's three-digit suffix (`001`–`500`). **Prefixes do not isolate VLANs:** `lab-001` and `test-001` collide. Do not reuse suffixes within the same vRack. Use the same scenario when destroying, including after partial failures.

GitLab Terraform states remain after normal destroy. With `--delete-states`, the orchestrator deletes only empty states following successful destruction, refusing to delete states that still track managed resources. Glance images and logs remain.

The router gateway helper in `terragrunt/bootstrap/scripts/router_gateway.py` uses openstacksdk. Terraform runs it through `uv run --package attackbed-cli`, so uv must be on PATH for standalone Terragrunt runs.

## Python API

The `attackbed-cli` package exposes functions without argument parsing:

```python
from attackbed import api

images_run = api.build("all")                # returns a run directory
lab_run = api.deploy("demo", copies=2)
api.resume(lab_run.name)                     # resume after a failure
api.destroy(lab_run.name, delete_states=True)
api.plan("demo", copies=1)                   # programmatic Terragrunt plan
```

Functions raise exceptions on operational failure and accept `root=Path(...)` for a
different repository checkout. `build()`, `deploy()` and `resume()` accept an optional
OpenStack SDK `connection=` for reuse and testability. `cli.py` contains the only
command-line `main()`; the runner in `deploy.py` provides `run_deployments(...)`.

Tests: `uv run --package attackbed-cli pytest scripts/attackbed/tests tests/test_router_gateway.py`
from the repository root.

