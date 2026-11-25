"""Command-line entry point for the AttackBed Python API."""

import argparse
import logging
from pathlib import Path
import sys
import traceback
from typing import Sequence

import yaml

from . import api
from .arguments import deployment_name, positive_int
from .errors import AttackBedError, redact


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build images and manage AttackBed deployments.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    commands = parser.add_subparsers(dest="action", required=True)

    build = commands.add_parser("build", help="Build scenario images without deploying")
    build.add_argument("scenario", help="Scenario from config/config.yaml")
    build.add_argument("-d", "--debug", action="store_true", help="Stream Packer diagnostic output")

    deploy_cmd = commands.add_parser("deploy", help="Deploy scenario using existing or newly built images")
    deploy_cmd.add_argument("scenario", nargs="?", help="Scenario from config/config.yaml")
    deploy_cmd.add_argument(
        "-a", "--all-scenarios", action="store_true",
        help="Deploy all documented attack scenarios (excluding all and core)",
    )
    deploy_cmd.add_argument(
        "-I", "--start-index", type=positive_int, default=1, metavar="N",
        help="First deployment number for --all-scenarios (default: 1)",
    )
    deploy_cmd.add_argument(
        "-v", "--no-provider-vlans", action="store_true",
        help="Use tenant networks (omit provider network type and VLAN IDs)",
    )
    source = deploy_cmd.add_mutually_exclusive_group()
    source.add_argument("-b", "--build", action="store_true", help="Build images before deploying")
    source.add_argument("-i", "--images", type=Path, metavar="FILE", help="Use image selection from JSON file")
    deploy_cmd.add_argument(
        "-c", "--copies", type=positive_int, default=1, metavar="N",
        help="Number of copies per scenario (default: 1)",
    )
    deploy_cmd.add_argument(
        "-n", "--prefix", type=deployment_name, default="lab", help="Deployment name prefix (default: lab)"
    )
    deploy_cmd.add_argument(
        "-p", "--parallel-copies", type=positive_int, default=4, metavar="N",
        help="Concurrent scenario deployments (default: 4)",
    )
    deploy_cmd.add_argument(
        "-t", "--tofu-parallelism", type=positive_int, metavar="N", help="OpenTofu operations per unit"
    )
    deploy_cmd.add_argument("-d", "--debug", action="store_true", help="Stream full Packer and Terragrunt output")

    resume = commands.add_parser("resume", help="Resume a run; defaults to the latest")
    resume.add_argument(
        "run_id", nargs="?", default="latest", metavar="RUN_ID",
        help="Saved run ID (default: latest)",
    )
    resume.add_argument("-d", "--debug", action="store_true", help="Stream full Packer and Terragrunt output")

    destroy_cmd = commands.add_parser("destroy", help="Destroy a saved run or scenario copies")
    destroy_cmd.add_argument("target", help="RUN_ID or scenario name")
    destroy_cmd.add_argument(
        "-c", "--copies", type=positive_int, metavar="N", help="Destroy PREFIX-001 through PREFIX-N"
    )
    destroy_cmd.add_argument(
        "-n", "--prefix", type=deployment_name, default="lab", help="Deployment name prefix (default: lab)"
    )
    destroy_cmd.add_argument(
        "-p", "--parallel-copies", type=positive_int, metavar="N", help="Concurrent deployments"
    )
    destroy_cmd.add_argument(
        "-t", "--tofu-parallelism", type=positive_int, metavar="N", help="OpenTofu operations per unit"
    )
    destroy_cmd.add_argument("-d", "--debug", action="store_true", help="Stream full Terragrunt output")
    destroy_cmd.add_argument(
        "-s", "--delete-states", action="store_true",
        help="Delete empty GitLab Terraform states after a successful destroy",
    )

    # Show every command's flags in top-level --help, without duplicating descriptions.
    overview = [
        "Examples:",
        "  uv run attackbed deploy core",
        "  uv run attackbed deploy -a -v -p 7",
        "  uv run attackbed destroy RUN_ID -s",
        "",
        "Options by action:",
    ]
    for name, command in commands.choices.items():
        overview.append(f"  {name}:")
        for option in command._actions:
            if not option.option_strings or option.dest == "help":
                continue
            switches = ", ".join(option.option_strings)
            if option.nargs != 0:
                switches += f" {option.metavar or option.dest.upper()}"
            overview.append(f"    {switches:<37} {option.help}")
    parser.epilog = "\n".join(overview)
    return parser


def main(argv: Sequence[str] | None = None, root: Path = api.ROOT) -> int:
    """Parse arguments once, then call the same API available to Python callers."""
    parser = make_parser()
    args = parser.parse_args(argv)

    if args.action == "build":
        api.build(args.scenario, root=root, debug=args.debug)
    elif args.action == "deploy":
        if args.all_scenarios and args.scenario is not None:
            parser.error("Do not provide a scenario with --all-scenarios")
        if not args.all_scenarios and args.scenario is None:
            parser.error("Specify a scenario or --all-scenarios")
        if not args.all_scenarios and args.start_index != 1:
            parser.error("--start-index requires --all-scenarios")
        api.deploy(
            args.scenario, copies=args.copies, prefix=args.prefix,
            parallel_copies=args.parallel_copies, tofu_parallelism=args.tofu_parallelism,
            build_images=args.build, images=args.images, root=root, debug=args.debug,
            all_scenarios=args.all_scenarios, start_index=args.start_index,
            use_provider_vlans=False if args.no_provider_vlans else None,
        )
    elif args.action == "resume":
        api.resume(args.run_id, root=root, debug=args.debug)
    elif args.action == "destroy":
        if args.target.startswith("run-") and (args.copies is not None or args.prefix != "lab"):
            parser.error("RUN_ID cannot be combined with --copies or --prefix")
        if not args.target.startswith("run-") and args.copies is None:
            parser.error("Destroying a scenario requires --copies")
        api.destroy(
            args.target, copies=args.copies, prefix=args.prefix,
            parallel_copies=args.parallel_copies, tofu_parallelism=args.tofu_parallelism,
            delete_states=args.delete_states, root=root, debug=args.debug,
        )
    return 0


def entrypoint(argv: Sequence[str] | None = None, root: Path = api.ROOT) -> int:
    """Convert expected operational failures to concise CLI errors."""
    arguments = sys.argv[1:] if argv is None else argv
    debug = "--debug" in arguments or "-d" in arguments
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO, format="%(message)s")
    try:
        return main(argv, root)
    except Exception as exc:
        try:
            from openstack.exceptions import SDKException
            sdk_error = isinstance(exc, SDKException)
        except ImportError:
            sdk_error = False
        if not isinstance(exc, (AttackBedError, OSError, ValueError, yaml.YAMLError)) and not sdk_error:
            raise
        if debug:
            report = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            print(redact(report), file=sys.stderr, end="")
        else:
            print(f"Error: {redact(str(exc))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(entrypoint())
