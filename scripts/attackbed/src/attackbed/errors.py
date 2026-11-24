"""Operational errors and secret redaction for AttackBed."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping, Sequence

SECRET_VARIABLES = (
    "CR_GITLAB_ACCESS_TOKEN",
    "OS_PASSWORD",
    "OS_APPLICATION_CREDENTIAL_SECRET",
    "TF_HTTP_PASSWORD",
)


def redact(value: str, env: Mapping[str, str] | None = None) -> str:
    """Remove known credential values before printing or logging a message."""
    variables = os.environ if env is None else env
    for key in SECRET_VARIABLES:
        secret = variables.get(key)
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


class AttackBedError(Exception):
    """An expected failure that the CLI can report without a traceback."""


class CommandError(AttackBedError):
    """A failed external command, including context needed for diagnosis."""

    def __init__(
        self,
        stage: str,
        command: Sequence[str],
        *,
        returncode: int | None = None,
        log_path: Path | None = None,
        reason: str | None = None,
    ) -> None:
        self.command = tuple(command)
        self.returncode = returncode
        self.log_path = log_path
        description = reason or (f"exit code {returncode}" if returncode is not None else "could not start")
        message = f"{stage} failed ({description}); command: {' '.join(command)}"
        if log_path is not None:
            message += f"; log: {log_path}"
        super().__init__(message)
