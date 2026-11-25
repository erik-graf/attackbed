# AttackBed CLI

Run from the repository root with `uv run attackbed`. The CLI is its own Python subproject in `scripts/attackbed/` (package: `scripts/attackbed/src/attackbed/`). `uv` resolves it through the root workspace. Requires OpenStack and GitLab state credentials, Packer, Ansible, Terragrunt, and OpenTofu.

## Commands

```sh
uv run attackbed --help                         # Actions and all command options
uv run attackbed build all                       # Build all required Packer images
uv run attackbed deploy core                     # Bootstrap only
uv run attackbed deploy videoserver -c 2         # Two independent copies of Scenario 1
uv run attackbed deploy videoserver -b           # Build images before deploying
uv run attackbed deploy videoserver -i runs/RUN_ID/images.json
uv run attackbed deploy -a -v -p 7               # All seven attack scenarios in parallel; standard Neutron networks
uv run attackbed deploy -a -c 2 -I 101           # Two copies of every attack scenario, starting at suffix 101
uv run attackbed resume                          # Resume latest run
uv run attackbed resume RUN_ID
uv run attackbed destroy RUN_ID
uv run attackbed destroy videoserver -c 2
uv run attackbed destroy RUN_ID -s               # Destroy and delete empty Terraform states
```

Top-level `attackbed --help` lists options for all commands; `attackbed ACTION --help` shows detailed usage for one command.

- `-a, --all-scenarios` (deploy only): deploy each of the seven documented attack scenarios as an isolated lab. Excludes `core` and `all`.
- `-v, --no-provider-vlans` (deploy only): omit provider vRack VLAN type/segmentation IDs and create ordinary Neutron tenant networks.
- `-p N, --parallel-copies N`: concurrent labs or scenarios (default: 4).
- `-t N, --tofu-parallelism N`: OpenTofu parallelism per unit (otherwise uses the Terragrunt setting).
- `-c N, --copies N`: copies of one scenario, or copies **per scenario** with `-a` (default: 1).
- `-n NAME, --prefix NAME`: deployment name prefix (default: `lab`).
- `-I N, --start-index N`: starting numeric suffix for `-a`; use unused numbers (default: 1, max: 500).
- `-b, --build` / `-i FILE, --images FILE`: build images first or use a saved image selection (mutually exclusive).
- `-d, --debug`: stream full Terragrunt output or Packer diagnostics and show tracebacks for operational failures.
- Deploy and destroy run without confirmation. A run-ID destroy uses saved deployment names; scenario/copies destroy does **not** update a saved run.
- `-s, --delete-states` (destroy only): clean up empty GitLab Terraform states after successful destroy. Without it, states are retained. You can add the flag to an already-destroyed run to clean up later.
- Resume continues the original action; resuming a `build` never deploys.

## Configuration

`config/config.yaml` holds two sections: `scenarios` selects Terragrunt units, and `image_recipes` maps Terraform image variables to Packer directories. The CLI builds each required recipe once, or selects the latest active Glance image by recipe `image_name` prefix. Image variables without a Packer recipe use their Terragrunt defaults.

Set shared Packer options in ignored `packer/defaults.json` (copy `defaults.json.example`). Merge order: `packer/RECIPE/default.json.example` → `packer/defaults.json` → optional ignored `packer/RECIPE/default.json`. The recipe override wins; common settings include build network, floating IP pool, and build flavor. Direct Packer invocations do not use this merge.

Deployment settings live in `terragrunt/defaults.tfvars` and optional ignored `terragrunt/terraform.tfvars`.

When both images are required, the OpenSearch Packer build runs before Logstash: it fetches the CA certificate to `packer/logstash/playbook/files/ca.pem`, which Logstash needs during its build. A standalone Logstash Packer build still requires that file to exist.

The `all` scenario includes all nine Terragrunt units, primarily for `attackbed build all`. It may not deploy as one lab because some units create overlapping infrastructure. The `core` scenario deploys only bootstrap; use `attackbed deploy core` for that. `deploy --all-scenarios` deploys the **seven documented attack scenarios** (Videoserver, Linux Malware, Lateral Movement, Network, LAN Turtle, Client, Docker), excluding both `all` and `core`. The units for each scenario are defined in `config/config.yaml`; each scenario receives a separate deployment ID (for example, `lab-videoserver-001`, `lab-linuxmalware-002`) and its own Neutron networks, router, and Terraform states. Images are selected once and reused by all scenarios. Deploying the infrastructure does not run the attack Ansible playbooks.

For provider vRack networks, `use_provider_vlans = true` in `terragrunt/defaults.tfvars` preserves the existing behavior. Use `--no-provider-vlans` on a deploy to override it for that run, or set `use_provider_vlans = false` in `terragrunt/terraform.tfvars`. This omits both `provider:network_type` and `provider:segmentation_id` from all five bootstrap networks. Saved runs remember the CLI switch for resume and destroy; changing this setting on existing infrastructure could require replacing networks.

## Runs and networking

Each invocation saves `runs/RUN_ID/run.json`, image selections in `images.json`, and corresponding image-name assignments in `images.tfvars` (for example, `inetfw_image = "atb-firewall-..."`). `images.tfvars` is a run artifact; Terragrunt continues using `images.json` for automatic selection. The image artifacts are updated as individual builds succeed and retained on resume. Logs are stored under `logs/` (`packer/RECIPE.log`, `apply.log`, `destroy.log`). Packer logs include `ansible-galaxy` and `packer init` output, including failures. Terragrunt logs record the command output from all deployment threads. Errors exit nonzero; already-running copies are allowed to finish and the summary reports failures. Retries append. Successful deployment also writes `ssh_config`. Each host uses its OpenStack keypair name as `IdentityFile ~/.ssh/KEY_NAME`; keep the private key under that filename locally. Build-only runs create no OpenStack deployment VMs. A saved image selection can be reused with `deploy --images`.

Bootstrap creates five vRack networks per deployment with VLANs `1000 + (N - 1) * 5` through `+4`, where `N` is the deployment ID's three-digit suffix (`001`–`500`). **Prefixes do not isolate VLANs:** `lab-001` and `test-001` collide. Do not reuse suffixes within the same vRack. Use the same scenario when destroying, including after partial failures.

Multi-scenario runs record completed deployments individually. `resume RUN_ID` retries only failed/incomplete scenarios, and `destroy RUN_ID` uses each scenario's saved unit list. Use `--start-index` and a different prefix or nonoverlapping suffix range for subsequent batches; the CLI does not automatically discover existing VLAN allocations or Terraform states.

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

