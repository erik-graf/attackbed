# Python environment

From the repository root (uv workspace):

```sh
uv run attackbed --help
uv run --package attackbed-cli pytest scripts/attackbed/tests
```

The Python CLI (also importable as `from attackbed import api`) lives in `scripts/attackbed/`, with source under `scripts/attackbed/src/attackbed/`. Its own `pyproject.toml` declares the CLI dependencies and entry point.

Ansible, Packer, OpenTofu, and Terragrunt are also required. See [AttackBed CLI](../tools/attackbed.md).

