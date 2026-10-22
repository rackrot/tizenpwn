"""Read-only discovery for a future persistent root SSH service.

This module deliberately stops at observation. It runs no listener, creates no
persistent files on the TV, and does not change UEP, SMACK, systemd, or any
reviewed system file. The existing SDB capture path may stage a temporary
self-deleting script when the probe exceeds the package-name injection limit.
The installer will only be added after the discovery and memfd execution gates
in docs/TU7000_PERSISTENCE_PLAN.md pass.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass

from .sdb import SdbClient, find_sdb
from .tu7000 import CifsRouteError, assess_target

MARKER = "TIZENPWN_INV_"
DEFAULT_SDB_TIMEOUT = 30.0

COMMANDS = (
    "sshd",
    "dropbear",
    "dropbearkey",
    "sftp-server",
    "scp",
    "ssh",
    "ssh-keygen",
    "python3",
    "perl",
    "node",
    "ruby",
    "php",
    "busybox",
    "nc",
    "socat",
    "telnetd",
    "inetd",
    "xinetd",
    "setsid",
    "nohup",
    "start-stop-daemon",
    "systemctl",
    "useradd",
    "groupadd",
    "usermod",
    "iptables",
    "nft",
    "ss",
    "netstat",
    "chpasswd",
    "logger",
)

FIELD_EXPRESSIONS = {
    "ARCH": "uname -m",
    "KERNEL": "uname -a",
    "CPU_FLAGS": (
        "grep -m1 -E '^(Features|flags)[[:space:]]*:' /proc/cpuinfo"
    ),
    "ROOT_MOUNT": "awk '$2==\"/\"{print $4}' /proc/mounts",
    "SMACK_CONTEXT": "cat /proc/self/attr/current",
    "MOUNTS": "cat /proc/mounts",
    "LISTENERS": "ss -ltn 2>/dev/null || netstat -ltn",
    "DISK": "df -h / /opt /data /home 2>/dev/null",
    "SERVER_FILES": (
        "ls -l /usr/sbin/sshd /usr/bin/sshd "
        "/usr/sbin/dropbear /usr/bin/dropbear "
        "/usr/lib/ssh/sftp-server /usr/libexec/sftp-server "
        "/usr/bin/scp /usr/bin/sftp 2>/dev/null"
    ),
    "SYSTEMD_VERSION": "systemctl --version | head -n 1",
    "SYSTEMD_STATE": "systemctl is-system-running",
    "ETC_SYSTEMD": "ls -ld /etc/systemd/system",
    "ROOT_PASSWD": "getent passwd root",
    "ROOT_HOME": "ls -ld /root",
    "DEV_PTS": "ls -ld /dev/pts /dev/ptmx",
    "DEVPTS_MOUNT": "grep ' /dev/pts ' /proc/mounts",
    "PTY_TEST": "python3 -c 'import pty; pty.openpty(); print(\"yes\")'",
    "PYTHON_VERSION": "python3 -V 2>&1",
    "PYTHON_MEMFD": (
        "python3 -c 'import os; "
        "print(\"yes\" if hasattr(os, \"memfd_create\") else \"no\")'"
    ),
    "PYTHON_CTYPES": "python3 -c 'import ctypes; print(\"yes\")'",
    "NODE_VERSION": "node -v 2>&1",
    "NODE_ARCH": "node -p 'process.arch' 2>&1",
    "NODE_VERSIONS": "node -p 'JSON.stringify(process.versions)' 2>&1",
    "NODE_CRYPTO": (
        "node -e 'const c=require(\"crypto\"); "
        "console.log(typeof c.generateKeyPairSync)' 2>&1"
    ),
    "NODE_DLOPEN": "node -e 'console.log(typeof process.dlopen)' 2>&1",
    "NODE_NET": "node -e 'console.log(typeof require(\"net\").createServer)' 2>&1",
    "WRITABLE_OPT": "if test -w /opt; then echo yes; else echo no; fi",
    "WRITABLE_DATA": "if test -w /data; then echo yes; else echo no; fi",
    "WRITABLE_ETC_SYSTEMD": (
        "if test -w /etc/systemd/system; then echo yes; else echo no; fi"
    ),
    "WRITABLE_HOME_OWNER": (
        "if test -w /home/owner; then echo yes; else echo no; fi"
    ),
    "INSTALL_ROOT": (
        "if test -e /opt/tizenpwn-ssh; then echo present; else echo absent; fi"
    ),
    "INSTALL_UNIT": (
        "if test -e /etc/systemd/system/tizenpwn-ssh.service; "
        "then echo present; else echo absent; fi"
    ),
    "UEP_LOG": "dmesg 2>/dev/null | grep -i uep | tail -n 10",
}

INVENTORY_FIELDS = (
    *FIELD_EXPRESSIONS,
    *(f"CMD_{name.upper().replace('-', '_')}" for name in COMMANDS),
)


def _field_command(name: str, expression: str) -> str:
    return (
        f"printf '{MARKER}{name}=%s\\n' "
        f"\"$({expression} 2>/dev/null | base64 -w0)\""
    )


PERSISTENCE_INVENTORY_COMMAND = ";".join(
    [
        *(
            _field_command(name, expression)
            for name, expression in FIELD_EXPRESSIONS.items()
        ),
        *(
            _field_command(
                f"CMD_{name.upper().replace('-', '_')}",
                f"command -v {name}",
            )
            for name in COMMANDS
        ),
    ]
)


class PersistenceError(CifsRouteError):
    pass


@dataclass(frozen=True)
class PersistenceInventory:
    values: dict[str, str]

    @classmethod
    def parse(cls, output: str) -> "PersistenceInventory":
        values: dict[str, str] = {}
        for line in output.splitlines():
            line = line.rstrip("\r")
            if not line.startswith(MARKER):
                continue
            body = line[len(MARKER) :]
            if "=" not in body:
                raise PersistenceError(
                    "persistence inventory contained a malformed field"
                )
            name, encoded = body.split("=", 1)
            if re.fullmatch(r"[A-Z0-9_]+", name) is None:
                raise PersistenceError(
                    "persistence inventory contained an invalid field name"
                )
            try:
                values[name] = (
                    base64.b64decode(encoded, validate=True)
                    .decode("utf-8", errors="replace")
                    .rstrip("\r\n")
                )
            except (ValueError, binascii.Error) as error:
                raise PersistenceError(
                    f"persistence inventory field {name} was not valid base64"
                ) from error
        missing = [name for name in INVENTORY_FIELDS if name not in values]
        if missing:
            raise PersistenceError(
                "persistence inventory was incomplete; missing: "
                + ", ".join(missing)
            )
        return cls(values=values)

    def _path(self, name: str) -> str | None:
        return self.values.get(f"CMD_{name.upper().replace('-', '_')}") or None

    @staticmethod
    def _yes_no(value: str) -> bool | None:
        if value == "yes":
            return True
        if value == "no":
            return False
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "architecture": self.values["ARCH"],
            "kernel": self.values["KERNEL"],
            "cpu_flags": self.values["CPU_FLAGS"],
            "root_mount_options": self.values["ROOT_MOUNT"],
            "smack_context": self.values["SMACK_CONTEXT"],
            "commands": {
                name: self._path(name)
                for name in COMMANDS
            },
            "python": {
                "path": self._path("python3"),
                "version": self.values["PYTHON_VERSION"],
                "memfd_create": self._yes_no(self.values["PYTHON_MEMFD"]),
                "ctypes": self._yes_no(self.values["PYTHON_CTYPES"]),
            },
            "node": {
                "path": self._path("node"),
                "version": self.values["NODE_VERSION"],
                "arch": self.values["NODE_ARCH"],
                "versions": self.values["NODE_VERSIONS"],
                "crypto": self.values["NODE_CRYPTO"],
                "dlopen": self.values["NODE_DLOPEN"],
                "net": self.values["NODE_NET"],
            },
            "server_files": self.values["SERVER_FILES"],
            "systemd": {
                "version": self.values["SYSTEMD_VERSION"],
                "state": self.values["SYSTEMD_STATE"],
                "unit_directory": self.values["ETC_SYSTEMD"],
                "unit_directory_writable_as_sdk": self._yes_no(
                    self.values["WRITABLE_ETC_SYSTEMD"]
                ),
            },
            "root_account": {
                "passwd": self.values["ROOT_PASSWD"],
                "home": self.values["ROOT_HOME"],
            },
            "pty": {
                "devices": self.values["DEV_PTS"],
                "devpts_mounted": bool(self.values["DEVPTS_MOUNT"]),
                "openpty": self._yes_no(self.values["PTY_TEST"]),
            },
            "writable_as_sdk": {
                "opt": self._yes_no(self.values["WRITABLE_OPT"]),
                "data": self._yes_no(self.values["WRITABLE_DATA"]),
                "etc_systemd": self._yes_no(
                    self.values["WRITABLE_ETC_SYSTEMD"]
                ),
                "home_owner": self._yes_no(
                    self.values["WRITABLE_HOME_OWNER"]
                ),
            },
            "existing_install": {
                "root": self.values["INSTALL_ROOT"],
                "unit": self.values["INSTALL_UNIT"],
            },
            "listeners": self.values["LISTENERS"],
            "mounts": self.values["MOUNTS"],
            "disk": self.values["DISK"],
            "uep_log": self.values["UEP_LOG"],
        }


@dataclass(frozen=True)
class PersistenceAssessment:
    target: object
    inventory: PersistenceInventory

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target.to_dict(),
            "inventory": self.inventory.to_dict(),
        }


def collect_persistence_inventory(
    client: SdbClient,
    *,
    timeout: float = DEFAULT_SDB_TIMEOUT,
) -> PersistenceInventory:
    result = client.capture(PERSISTENCE_INVENTORY_COMMAND, timeout=timeout)
    output = result.output
    if "[exit:0]" not in output:
        raise PersistenceError(
            "persistence inventory command did not complete on the TV: "
            + output.strip()
        )
    return PersistenceInventory.parse(output.split("\n[exit:0]", 1)[0].strip())


def inventory_target(
    tv_host: str,
    *,
    sdb_timeout: float = DEFAULT_SDB_TIMEOUT,
    client: SdbClient | None = None,
) -> PersistenceAssessment:
    ipaddress.IPv4Address(tv_host)
    client = client or SdbClient(
        find_sdb(), tv_host, timeout=sdb_timeout
    )
    target = assess_target(
        tv_host,
        sdb_timeout=sdb_timeout,
        client=client,
    )
    inventory = collect_persistence_inventory(
        client, timeout=sdb_timeout
    )
    return PersistenceAssessment(target=target, inventory=inventory)
