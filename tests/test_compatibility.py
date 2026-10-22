import pytest

from tizenpwn.compatibility import (
    TU7000_PROFILE,
    CompatibilityStatus,
    TargetCompatibilityError,
)


def tu7000_output(
    *,
    build: str = "T-KTSU2AKUC-REL-202607021959",
    kernel: str = "4.1.10",
    architecture: str = "armv7l",
    capabilities: tuple[str, ...] = ("PS_AGENT", "MOUNT_SMB", "REMOTEPC"),
) -> str:
    capability_lines = "".join(
        f"TIZENPWN_CAPABILITY_{capability}=ready\n"
        for capability in capabilities
    )
    return (
        "uid=901(sdk) gid=901(sdk)\n"
        f"TIZENPWN_KERNEL={kernel}\n"
        f"TIZENPWN_ARCHITECTURE={architecture}\n"
        "Tizen5/TV 5.5.0 (arm)\n"
        f"BUILD_ID={build}\n"
        f"{capability_lines}"
    )


def test_exact_tu7000_build_is_tested() -> None:
    assessment = TU7000_PROFILE.assess(tu7000_output()).require_compatible()

    assert assessment.status is CompatibilityStatus.TESTED
    assert assessment.differences == ()


def test_tu7000_different_build_family_fails_closed() -> None:
    assessment = TU7000_PROFILE.assess(
        tu7000_output(build="T-NKLDEUC-REL-202607021959")
    )

    with pytest.raises(TargetCompatibilityError, match="outside T-KTSU2AKUC-REL"):
        assessment.require_compatible()


def test_tu7000_wrong_architecture_fails_closed() -> None:
    assessment = TU7000_PROFILE.assess(
        tu7000_output(architecture="aarch64")
    )

    with pytest.raises(TargetCompatibilityError, match="architecture"):
        assessment.require_compatible()


def test_tu7000_missing_mount_helper_fails_before_live_work() -> None:
    assessment = TU7000_PROFILE.assess(
        tu7000_output(capabilities=("PS_AGENT", "REMOTEPC"))
    )

    with pytest.raises(TargetCompatibilityError, match="mount-smb"):
        assessment.require_compatible()


def test_tu7000_new_build_is_attempted_but_not_tested() -> None:
    assessment = TU7000_PROFILE.assess(
        tu7000_output(build="T-KTSU2AKUC-REL-202701010101")
    ).require_compatible()

    assert assessment.status is CompatibilityStatus.COMPATIBLE
    with pytest.raises(TargetCompatibilityError, match="build-specific"):
        assessment.require_tested("TU7000 CIFS route")


def test_probe_command_collects_the_reviewed_paths() -> None:
    probe = TU7000_PROFILE.probe_command()

    assert "/usr/apps/privileged-service/bin/ps_agent" in probe
    assert "mount.smb.sh" in probe
    assert "org.tizen.remotepc" in probe
