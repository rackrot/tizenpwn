import base64

import pytest

from tizenpwn import persistence
from tizenpwn.persistence import (
    INVENTORY_FIELDS,
    MARKER,
    PERSISTENCE_INVENTORY_COMMAND,
    PersistenceError,
    PersistenceInventory,
    collect_persistence_inventory,
    inventory_target,
)
from tizenpwn.tu7000 import (
    ARTIFACT_HASHES,
    MODEL,
    PROBE_COMMAND,
    SYSTEM_HASH_COMMAND,
    TESTED_BUILD,
)


BASE_VALUES = {
    "ARCH": "armv7l",
    "KERNEL": "Linux samsung 4.1.10 #1 SMP PREEMPT armv7l GNU/Linux",
    "CPU_FLAGS": "Features : half thumb fastmult vfp edsp neon vfpv3",
    "ROOT_MOUNT": "ro,relatime",
    "SMACK_CONTEXT": "System::Privileged",
    "MOUNTS": "/dev/root / squashfs ro 0 0\n",
    "LISTENERS": "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n",
    "DISK": "Filesystem Size Used Avail Use% Mounted on\n",
    "SERVER_FILES": "",
    "SYSTEMD_VERSION": "systemd 244",
    "SYSTEMD_STATE": "running",
    "ETC_SYSTEMD": "drwxr-xr-x 2 root root 4096 Jan 1 00:00 /etc/systemd/system",
    "ROOT_PASSWD": "root:x:0:0:root:/root:/bin/bash",
    "ROOT_HOME": "drwx------ 2 root root 4096 Jan 1 00:00 /root",
    "DEV_PTS": "drwxr-xr-x 2 root root 4096 Jan 1 00:00 /dev/pts",
    "DEVPTS_MOUNT": "devpts /dev/pts devpts rw 0 0",
    "PTY_TEST": "yes",
    "PYTHON_VERSION": "Python 3.8.2",
    "PYTHON_MEMFD": "yes",
    "PYTHON_CTYPES": "yes",
    "NODE_VERSION": "v12.22.9",
    "NODE_ARCH": "arm",
    "NODE_VERSIONS": '{"node":"12.22.9"}',
    "NODE_CRYPTO": "function",
    "NODE_DLOPEN": "function",
    "NODE_NET": "function",
    "WRITABLE_OPT": "no",
    "WRITABLE_DATA": "no",
    "WRITABLE_ETC_SYSTEMD": "no",
    "WRITABLE_HOME_OWNER": "yes",
    "INSTALL_ROOT": "absent",
    "INSTALL_UNIT": "absent",
    "UEP_LOG": "",
}


def inventory_output(**overrides: str) -> str:
    values = {
        name: BASE_VALUES.get(name, "")
        for name in INVENTORY_FIELDS
    }
    values.update(overrides)
    return "\n".join(
        f"{MARKER}{name}="
        + base64.b64encode(value.encode("utf-8")).decode("ascii")
        for name, value in values.items()
    )


def probe_output(*, build: str, hashes: dict[str, str]) -> str:
    hash_lines = "".join(
        f"{value}  {path}\n" for path, value in hashes.items()
    )
    return (
        "uid=901(sdk) gid=901(sdk)\n"
        "TIZENPWN_KERNEL=4.1.10\n"
        "TIZENPWN_ARCHITECTURE=armv7l\n"
        "Tizen5/TV 5.5.0 (arm)\n"
        f"BUILD_ID={build}\n"
        "TIZENPWN_CAPABILITY_PS_AGENT=ready\n"
        "TIZENPWN_CAPABILITY_MOUNT_SMB=ready\n"
        "TIZENPWN_CAPABILITY_REMOTEPC=ready\n"
        f"{hash_lines}"
        "[exit:0]"
    )


class FakeInventoryClient:
    def __init__(
        self,
        *,
        inventory: str | None = None,
        model: str = MODEL,
        complete: bool = True,
    ) -> None:
        self.inventory = inventory or inventory_output()
        self.model = model
        self.complete = complete

    def connect(self) -> None:
        pass

    def require_device(self) -> None:
        pass

    def reported_model(self) -> str:
        return self.model

    def require_shell_injection(self) -> None:
        pass

    def capture(self, command: str, *, timeout: float) -> object:
        if command == PROBE_COMMAND:
            text = probe_output(
                build=TESTED_BUILD,
                hashes=ARTIFACT_HASHES,
            )
        elif command == SYSTEM_HASH_COMMAND:
            text = "a" * 64 + "  /etc/passwd\n[exit:0]"
        elif command == PERSISTENCE_INVENTORY_COMMAND:
            text = self.inventory
            if self.complete:
                text += "\n[exit:0]"
        else:
            raise AssertionError(f"unexpected capture: {command}")
        return type("Result", (), {"output": text})()


def test_inventory_parses_every_field() -> None:
    inventory = PersistenceInventory.parse(
        inventory_output(
            CMD_SSHD="/usr/sbin/sshd",
            CMD_PYTHON3="/usr/bin/python3",
            CMD_NODE="/usr/bin/node",
            CMD_DROPBEAR="",
        )
    )

    data = inventory.to_dict()
    assert data["architecture"] == "armv7l"
    assert data["commands"]["sshd"] == "/usr/sbin/sshd"
    assert data["commands"]["dropbear"] is None
    assert data["python"]["path"] == "/usr/bin/python3"
    assert data["python"]["memfd_create"] is True
    assert data["python"]["ctypes"] is True
    assert data["node"]["path"] == "/usr/bin/node"
    assert data["node"]["net"] == "function"
    assert data["pty"]["openpty"] is True
    assert data["writable_as_sdk"]["home_owner"] is True
    assert data["existing_install"] == {
        "root": "absent",
        "unit": "absent",
    }


def test_inventory_strips_trailing_newlines() -> None:
    inventory = PersistenceInventory.parse(
        inventory_output(
            ARCH="armv7l\n",
            WRITABLE_OPT="no\n",
            CMD_NODE="/usr/bin/node\n",
        )
    )

    data = inventory.to_dict()
    assert data["architecture"] == "armv7l"
    assert data["writable_as_sdk"]["opt"] is False
    assert data["node"]["path"] == "/usr/bin/node"


def test_inventory_rejects_a_missing_field() -> None:
    output = inventory_output()
    lines = output.splitlines()
    missing = next(
        line for line in lines if f"{MARKER}ARCH=" in line
    )
    output = "\n".join(line for line in lines if line != missing)

    with pytest.raises(PersistenceError, match="incomplete"):
        PersistenceInventory.parse(output)


def test_inventory_rejects_invalid_base64() -> None:
    output = inventory_output()
    output = output.replace(
        f"{MARKER}ARCH=",
        f"{MARKER}ARCH=!!!!",
    )

    with pytest.raises(PersistenceError, match="not valid base64"):
        PersistenceInventory.parse(output)


def test_inventory_command_is_read_only() -> None:
    forbidden = (
        "rm ",
        "mkdir ",
        "chmod ",
        "touch ",
        "systemctl start",
        "systemctl enable",
        "iptables -A",
        "reboot",
        "shutdown",
        "dd if=",
        "tee ",
    )

    for token in forbidden:
        assert token not in PERSISTENCE_INVENTORY_COMMAND
    assert "base64 -w0" in PERSISTENCE_INVENTORY_COMMAND
    assert "CMD_SSHD" in PERSISTENCE_INVENTORY_COMMAND
    assert "WRITABLE_ETC_SYSTEMD" in PERSISTENCE_INVENTORY_COMMAND


def test_collect_rejects_a_failed_transport() -> None:
    client = FakeInventoryClient(
        inventory="no completion marker", complete=False
    )

    with pytest.raises(PersistenceError, match="did not complete"):
        collect_persistence_inventory(client)


def test_collect_returns_the_parsed_inventory() -> None:
    client = FakeInventoryClient(
        inventory=inventory_output(CMD_PYTHON3="/usr/bin/python3")
    )

    inventory = collect_persistence_inventory(client)

    assert inventory.to_dict()["python"]["path"] == "/usr/bin/python3"


def test_inventory_target_keeps_the_exact_target_assessment() -> None:
    client = FakeInventoryClient()

    assessment = inventory_target("192.0.2.10", client=client)

    data = assessment.to_dict()
    assert data["target"]["model"] == MODEL
    assert data["target"]["build"] == TESTED_BUILD
    assert data["inventory"]["architecture"] == "armv7l"


def test_inventory_module_exposes_no_installer_yet() -> None:
    assert not hasattr(persistence, "execute_persist")
