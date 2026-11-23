# AttackBed CLI development

Follow the Python conventions in [AIT's cookiecutter-ait-ad](https://github.com/ait-testbed/cookiecutter-ait-ad),
especially its `AGENTS.md` and repository checklist.

- This is a Python subproject within the AttackBed repository. Keep the package
  in `src/attackbed/` and its tests in `tests/`.
- Use `uv run`; declare runtime dependencies in `[project]` and developer
  dependencies in `[dependency-groups] dev`.
- Add type hints and focused pytest tests for changed behavior.
- Keep lines at most 110 characters; prefer the standard library, including `logging`.
- Do not suppress unexpected exceptions, log secrets, or make tests depend on
  OpenStack credentials, network access, or running Packer/Terragrunt.
- Run `uv run --dev pytest` and the project's formatting/type checks before shipping.
- Keep the implementation small and reviewable; avoid extra abstraction layers.
