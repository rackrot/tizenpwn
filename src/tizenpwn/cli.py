from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .compatibility import TargetCompatibilityError
from .sdb import SdbError
from .tu7000 import (
    CONFIRMATION,
    CifsRouteError,
    assess_target,
    execute_command,
    execute_probe,
)


def emit(value: object, output: str) -> None:
    if output == "json":
        print(json.dumps(value, indent=2, sort_keys=True))
        return
    for line in render_human(value):
        print(line)


def render_human(value: object, indentation: int = 0) -> list[str]:
    prefix = " " * indentation
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            label = str(key).replace("_", " ")
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{label}:")
                lines.extend(render_human(item, indentation + 2))
            else:
                lines.append(f"{prefix}{label}: {human_scalar(item)}")
        return lines
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.extend(render_human(item, indentation + 2))
            else:
                lines.append(f"{prefix}- {human_scalar(item)}")
        return lines
    return [f"{prefix}{human_scalar(value)}"]


def human_scalar(value: object) -> str:
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def command_preflight(arguments: argparse.Namespace) -> int:
    assessment = assess_target(
        arguments.host,
        sdb_timeout=arguments.sdb_timeout,
    )
    if arguments.output == "json":
        emit(assessment.to_dict(), arguments.output)
    else:
        print(assessment.render())
    return 0


def command_probe(arguments: argparse.Namespace) -> int:
    evidence = execute_probe(
        arguments.host,
        confirm=arguments.confirm,
        accept_saved_profile=arguments.accept_saved_profile,
        sdb_timeout=arguments.sdb_timeout,
        callback_host=arguments.callback_host,
        bind_host=arguments.bind_host,
        rdp_port=arguments.rdp_port,
        smb_port=arguments.smb_port,
        image=arguments.image,
    )
    emit(evidence, arguments.output)
    return 0


def command_command(arguments: argparse.Namespace) -> int:
    evidence = execute_command(
        arguments.host,
        confirm=arguments.confirm,
        accept_saved_profile=arguments.accept_saved_profile,
        commands=tuple(arguments.command),
        sdb_timeout=arguments.sdb_timeout,
        callback_host=arguments.callback_host,
        bind_host=arguments.bind_host,
        rdp_port=arguments.rdp_port,
        smb_port=arguments.smb_port,
        image=arguments.image,
        agent_timeout=arguments.agent_timeout,
    )
    emit(evidence, arguments.output)
    return next(
        (
            command["exit_code"] or 1
            for command in evidence["commands"]
            if command["exit_code"] != 0
        ),
        0,
    )


def add_live_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("host", help="TV IPv4 address")
    command.add_argument(
        "--confirm",
        required=True,
        help=f"exact firmware confirmation phrase ({CONFIRMATION})",
    )
    command.add_argument(
        "--accept-saved-profile",
        action="store_true",
        required=True,
        help="accept that the TV stores a temporary Remote PC profile",
    )
    command.add_argument("--callback-host")
    command.add_argument("--bind-host")
    command.add_argument("--sdb-timeout", type=float, default=30.0)
    command.add_argument("--rdp-port", type=int, default=3389)
    command.add_argument("--smb-port", type=int, default=445)
    command.add_argument("--image")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tizenpwn",
        description=(
            "Owner-authorized TU7000 T-KTSU2AKUC-2743.0 Remote PC/CIFS route"
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--sdb",
        type=Path,
        help="absolute path to the Samsung sdb executable",
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=("human", "json"),
        default="human",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser(
        "preflight",
        help="read-only exact-target and artifact assessment",
    )
    preflight.add_argument("host", help="TV IPv4 address")
    preflight.add_argument("--sdb-timeout", type=float, default=30.0)
    preflight.set_defaults(handler=command_preflight)

    cifs = commands.add_parser(
        "cifs",
        help="Remote PC/CIFS one-shot route",
    )
    cifs_commands = cifs.add_subparsers(
        dest="cifs_command", required=True
    )
    probe = cifs_commands.add_parser(
        "probe",
        help="one bounded UID-0 identity proof",
    )
    add_live_options(probe)
    probe.set_defaults(handler=command_probe)

    command = cifs_commands.add_parser(
        "command",
        help="one bounded authenticated root command batch",
    )
    add_live_options(command)
    command.add_argument(
        "--command",
        action="append",
        required=True,
        metavar="SHELL",
        help="root shell command to run; repeat for multiple commands",
    )
    command.add_argument("--agent-timeout", type=float, default=30.0)
    command.set_defaults(handler=command_command)
    return parser


def main(argv: list[str] | None = None) -> None:
    arguments = build_parser().parse_args(argv)
    if arguments.sdb is not None:
        os.environ["SDB"] = str(arguments.sdb.expanduser())
    try:
        status = arguments.handler(arguments)
    except (
        CifsRouteError,
        SdbError,
        TargetCompatibilityError,
    ) as error:
        raise SystemExit(str(error)) from error
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    raise SystemExit(status)


if __name__ == "__main__":
    main(sys.argv[1:])
