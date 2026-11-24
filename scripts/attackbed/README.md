# AttackBed CLI

The Python CLI is a subproject inside the AttackBed repository. Its code lives in
`scripts/attackbed/src/attackbed/` and its tests in `scripts/attackbed/tests/`.

From the AttackBed repository root:

```sh
uv run attackbed --help
uv run attackbed deploy demo --copies 2
uv run --package attackbed-cli pytest scripts/attackbed/tests
```

The repository root remains the location for scenario configuration, Packer recipes,
Terragrunt units, and generated `runs/` output.

Failures of external commands are written to the run logs and reported with a
nonzero exit status. Use `--debug` for detailed subprocess output and tracebacks.

See [CLI usage](../../docs/tools/attackbed.md) for commands and configuration.

## Importable Python API

```python
from attackbed import api

run = api.build("all")
run = api.deploy("demo", copies=2)
run = api.resume(run.name)
api.destroy(run.name, delete_states=True)
```

The API returns run directories and raises exceptions for failures. No command-line
argument parsing is needed. Each image selection produces `images.json` and an
`images.tfvars` containing Terraform image-name assignments for that run.
Scenarios and recipe mappings live together in `config/config.yaml`.
