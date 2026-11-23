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
