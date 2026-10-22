import importlib.util
import struct
from pathlib import Path

import pytest

BUILD_PATH = (
    Path(__file__).resolve().parents[1]
    / "payloads"
    / "tu7000"
    / "persistence"
    / "build.py"
)
SPEC = importlib.util.spec_from_file_location("tizenpwn_build", BUILD_PATH)
assert SPEC is not None and SPEC.loader is not None
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


def elf_bytes(
    *,
    machine: int = 40,
    flags: int = 0x05000200,
    elf_class: int = 1,
) -> bytes:
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4] = elf_class
    data[5] = 1
    data[16:18] = struct.pack("<H", 2)
    data[18:20] = struct.pack("<H", machine)
    flags_offset = 36 if elf_class == 1 else 48
    data[flags_offset : flags_offset + 4] = struct.pack("<I", flags)
    return bytes(data)


def write_elf(path: Path, **kwargs: int) -> Path:
    path.write_bytes(elf_bytes(**kwargs))
    return path


def test_c_string_escapes_quotes_and_backslashes() -> None:
    assert BUILD.c_string('a"b\\c') == '"a\\"b\\\\c"'


def test_c_string_rejects_a_newline() -> None:
    with pytest.raises(BUILD.BuildError, match="single-line"):
        BUILD.c_string("a\nb")


def test_elf_header_reads_arm_soft_float_flags(tmp_path: Path) -> None:
    header = BUILD.elf_header(
        write_elf(tmp_path / "probe", machine=40, flags=0x05000200)
    )

    assert header["class"] == 1
    assert header["machine"] == 40
    assert header["flags"] == 0x05000200


def test_require_machine_accepts_expected_arm(tmp_path: Path) -> None:
    header = BUILD.require_machine(
        write_elf(tmp_path / "probe", machine=40),
        "arm-linux-gnueabi.2.24",
    )

    assert header["machine"] == 40


def test_require_machine_rejects_a_wrong_machine(tmp_path: Path) -> None:
    with pytest.raises(BUILD.BuildError, match="ELF machine"):
        BUILD.require_machine(
            write_elf(tmp_path / "probe", machine=62),
            "arm-linux-gnueabi.2.24",
        )


def test_require_soft_float_rejects_hard_float(tmp_path: Path) -> None:
    with pytest.raises(BUILD.BuildError, match="hard-float"):
        BUILD.require_soft_float(
            write_elf(tmp_path / "loader", machine=40, flags=0x05000400)
        )


def test_require_soft_float_requires_the_soft_flag(tmp_path: Path) -> None:
    with pytest.raises(BUILD.BuildError, match="soft-float ABI"):
        BUILD.require_soft_float(
            write_elf(tmp_path / "loader", machine=40, flags=0x05000000)
        )
