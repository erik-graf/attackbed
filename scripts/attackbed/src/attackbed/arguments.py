"""Argument types shared by the AttackBed command-line interfaces."""

import argparse
import re


def positive_int(value: str) -> int:
    """Accept positive integer command-line arguments."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def deployment_name(value: str) -> str:
    """Accept a lowercase deployment name or prefix."""
    if not re.fullmatch(r"[a-z][a-z0-9-]*", value):
        raise argparse.ArgumentTypeError("must contain lowercase letters, digits, or hyphens")
    return value
