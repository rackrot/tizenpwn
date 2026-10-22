#!/usr/bin/env python3
"""Build the TU7000 persistence probe and Node-loaded memfd loader.

The target has Node 4.4.3 (soft-float ARM, glibc 2.24) but no Python, Perl, or
SSH server. This helper produces:

  probe   a static ARM payload that prints a harmless marker
  loader  a dependency-free shared object containing the payload; a
          constructor writes it to memfd and executes it

The loader is loaded by signed Node with process.dlopen(). It links no libc.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOADER_C = HERE / "loader.c"
STAGE1_C = HERE / "stage1.c"
PROBE_C = HERE / "probe" / "probe.c"
DEFAULT_TARGET = "arm-linux-gnueabi.2.24"
DEFAULT_PROBE_TARGET = "arm-linux-musleabi"
DEFAULT_ENVIRONMENT = (
    "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
    "HOME=/root",
    "USER=root",
    "SHELL=/bin/bash",
    "LANG=C",
)


class BuildError(RuntimeError):
    pass


def run(arguments: list[str], *, cwd: Path | None = None) -> None:
    try:
        completed = subprocess.run(
            arguments,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as error:
        raise BuildError(
            f"required build command was not found: {arguments[0]}"
        ) from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise BuildError(
            f"build command failed: {' '.join(arguments[:4])}"
            + (f": {detail}" if detail else "")
        )


def elf_header(path: Path) -> dict[str, int]:
    data = path.read_bytes()[:64]
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise BuildError(f"{path} is not an ELF file")
    elf_class = data[4]
    flags_offset = 36 if elf_class == 1 else 48
    if len(data) < flags_offset + 4:
        raise BuildError(f"{path} has a truncated ELF header")
    return {
        "class": elf_class,
        "data": data[5],
        "type": struct.unpack_from("<H", data, 16)[0],
        "machine": struct.unpack_from("<H", data, 18)[0],
        "flags": struct.unpack_from("<I", data, flags_offset)[0],
    }


def require_machine(path: Path, target: str) -> dict[str, int]:
    header = elf_header(path)
    expected_machine = 40 if target.startswith("arm") else 62
    expected_class = 1 if target.startswith("arm") else 2
    if header["class"] != expected_class or header["data"] != 1:
        raise BuildError(
            f"{path} has an unexpected ELF class or byte order for {target}"
        )
    if header["machine"] != expected_machine:
        raise BuildError(
            f"{path} has ELF machine {header['machine']}, "
            f"expected {expected_machine} for {target}"
        )
    return header


def require_soft_float(path: Path) -> None:
    header = elf_header(path)
    if header["machine"] != 40:
        return
    flags = header["flags"]
    if flags & 0x400:
        raise BuildError(
            f"{path} is hard-float; Node on this target is soft-float"
        )
    if not flags & 0x200:
        raise BuildError(f"{path} does not declare the soft-float ABI")
    if flags & 0xFF000000 != 0x05000000:
        raise BuildError(f"{path} does not declare ARM EABI version 5")


def require_no_needed(path: Path) -> None:
    readelf = shutil.which("readelf")
    if readelf is None:
        return
    completed = subprocess.run(
        (readelf, "-d", str(path)),
        text=True,
        capture_output=True,
        check=False,
    )
    if "NEEDED" in completed.stdout:
        raise BuildError(f"{path} unexpectedly depends on a shared library")


def require_init_array(path: Path) -> None:
    readelf = shutil.which("readelf")
    if readelf is None:
        return
    sections = subprocess.run(
        (readelf, "-S", str(path)),
        text=True,
        capture_output=True,
        check=False,
    )
    if ".init_array" not in sections.stdout:
        raise BuildError(f"{path} has no .init_array constructor section")


def require_dynamic(path: Path) -> None:
    readelf = shutil.which("readelf")
    if readelf is None:
        return
    program_headers = subprocess.run(
        (readelf, "-l", str(path)),
        text=True,
        capture_output=True,
        check=False,
    )
    if "INTERP" not in program_headers.stdout:
        raise BuildError(f"{path} has no dynamic interpreter")
    dynamic = subprocess.run(
        (readelf, "-d", str(path)),
        text=True,
        capture_output=True,
        check=False,
    )
    if "NEEDED" not in dynamic.stdout:
        raise BuildError(f"{path} has no shared-library dependency")


def c_string(value: str) -> str:
    if not value:
        raise BuildError("empty argv or environment value")
    if any(character in value for character in ("\0", "\n", "\r")):
        raise BuildError("argv and environment values must be single-line")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_probe(arguments: argparse.Namespace) -> None:
    output = arguments.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        arguments.zig,
        "cc",
        "-target",
        arguments.target,
        "-static",
        "-O2",
        "-s",
    ]
    if arguments.probe_file:
        command.append(
            "-DTIZENPWN_PROBE_FILE=" + c_string(arguments.probe_file)
        )
    command.extend(["-o", str(output), str(PROBE_C)])
    run(command)
    header = require_machine(output, arguments.target)
    if header["type"] not in (2, 3):
        raise BuildError(f"{output} has unexpected ELF type {header['type']}")
    require_no_needed(output)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"probe: {output}")
    print(f"sha256: {digest}")
    print(f"size: {output.stat().st_size}")


def build_stage1(arguments: argparse.Namespace) -> None:
    output = arguments.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            arguments.zig,
            "cc",
            "-target",
            arguments.target,
            "-O2",
            "-s",
            "-o",
            str(output),
            str(STAGE1_C),
        ]
    )
    require_machine(output, arguments.target)
    require_soft_float(output)
    require_dynamic(output)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"stage1: {output}")
    print(f"sha256: {digest}")
    print(f"size: {output.stat().st_size}")


def build_loader(arguments: argparse.Namespace) -> None:
    payload = arguments.payload.expanduser().resolve()
    if not payload.is_file():
        raise BuildError(f"payload does not exist: {payload}")
    output = arguments.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    require_machine(payload, arguments.target)
    environment = [*DEFAULT_ENVIRONMENT, *arguments.env]
    for value in environment:
        if "=" not in value:
            raise BuildError(f"environment value is not KEY=VALUE: {value}")

    with tempfile.TemporaryDirectory(prefix="tizenpwn-loader-") as directory:
        build = Path(directory)
        shutil.copyfile(payload, build / "payload.bin")
        (build / "payload.S").write_text(
            ".section .rodata\n"
            ".balign 16\n"
            ".global tizenpwn_payload\n"
            ".global tizenpwn_payload_end\n"
            "tizenpwn_payload:\n"
            '.incbin "payload.bin"\n'
            "tizenpwn_payload_end:\n",
            encoding="ascii",
        )
        argv = [arguments.name, *arguments.arg]
        config = [
            "static char *const tizenpwn_argv[] = {",
            "".join(f"    {c_string(value)},\n" for value in argv),
            "    0,",
            "};",
            "static char *const tizenpwn_envp[] = {",
            "".join(f"    {c_string(value)},\n" for value in environment),
            "    0,",
            "};",
        ]
        if arguments.error_file:
            config.append(
                "#define TIZENPWN_ERROR_FILE "
                + c_string(arguments.error_file)
            )
        config.append("")
        (build / "loader_config.h").write_text(
            "\n".join(config), encoding="utf-8"
        )
        command = [
            arguments.zig,
            "cc",
            "-target",
            arguments.target,
            "-shared",
            "-nostdlib",
            "-fPIC",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-O2",
            "-Wl,--no-undefined",
            "-I",
            str(build),
            "-o",
            str(output),
            str(LOADER_C),
            "payload.S",
        ]
        if arguments.debug:
            command.insert(command.index("-O2"), "-DTIZENPWN_DEBUG")
        run(command, cwd=build)

    require_machine(output, arguments.target)
    require_soft_float(output)
    require_no_needed(output)
    require_init_array(output)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"loader: {output}")
    print(f"payload: {payload}")
    print(f"payload sha256: {hashlib.sha256(payload.read_bytes()).hexdigest()}")
    print(f"sha256: {digest}")
    print(f"size: {output.stat().st_size}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    probe = commands.add_parser("probe", help="build the static probe payload")
    probe.add_argument("--output", required=True, type=Path)
    probe.add_argument("--target", default=DEFAULT_PROBE_TARGET)
    probe.add_argument("--zig", default="zig")
    probe.add_argument(
        "--probe-file",
        default="",
        help="compile-time marker file for the probe",
    )
    probe.set_defaults(handler=build_probe)

    stage1 = commands.add_parser(
        "stage1", help="build the dynamic ld.so-executed memfd stage"
    )
    stage1.add_argument("--output", required=True, type=Path)
    stage1.add_argument("--target", default=DEFAULT_TARGET)
    stage1.add_argument("--zig", default="zig")
    stage1.set_defaults(handler=build_stage1)

    loader = commands.add_parser(
        "loader", help="embed a payload in the Node-loaded loader"
    )
    loader.add_argument("--payload", required=True, type=Path)
    loader.add_argument("--output", required=True, type=Path)
    loader.add_argument("--name", default="payload")
    loader.add_argument("--arg", action="append", default=[])
    loader.add_argument("--env", action="append", default=[])
    loader.add_argument("--target", default=DEFAULT_TARGET)
    loader.add_argument("--zig", default="zig")
    loader.add_argument(
        "--debug",
        action="store_true",
        help="write loader stage messages to stderr",
    )
    loader.add_argument(
        "--error-file",
        default="",
        help="compile-time file for loader failure messages",
    )
    loader.set_defaults(handler=build_loader)

    arguments = parser.parse_args(argv)
    try:
        arguments.handler(arguments)
    except BuildError as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    sys.exit(main())
