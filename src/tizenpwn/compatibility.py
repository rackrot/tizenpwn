from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


CAPABILITY_PREFIX = "TIZENPWN_CAPABILITY_"
KERNEL_MARKER = "TIZENPWN_KERNEL="
ARCHITECTURE_MARKER = "TIZENPWN_ARCHITECTURE="


class CompatibilityStatus(str, Enum):
    TESTED = "tested"
    COMPATIBLE = "compatible-untested"
    INCOMPATIBLE = "incompatible"


class TargetCompatibilityError(RuntimeError):
    pass


@dataclass(frozen=True)
class TargetFingerprint:
    output: str
    sdk_uid: int | None
    build_id: str | None
    kernel_release: str | None
    architecture: str | None
    tizen_release: str | None
    capabilities: frozenset[str]

    @classmethod
    def parse(cls, output: str) -> TargetFingerprint:
        sdk_uid_match = re.search(r"(?m)^uid=(\d+)\(", output)
        build_match = re.search(r"(?m)^BUILD_ID=(\S+)[ \t]*$", output)
        kernel_release = _marker_value(output, KERNEL_MARKER)
        if kernel_release is None:
            kernel_match = re.search(
                r"(?m)^Linux\s+\S+\s+(\d+\.\d+\.\d+)\b", output
            )
            kernel_release = (
                kernel_match.group(1) if kernel_match else None
            )
        architecture = _marker_value(output, ARCHITECTURE_MARKER)
        if architecture is None:
            architecture_match = re.search(r"\b(armv7l|aarch64)\b", output)
            architecture = (
                architecture_match.group(1) if architecture_match else None
            )
        tizen_match = re.search(r"(?m)^(Tizen[^\r\n]+)$", output)
        capabilities = frozenset(
            match.group(1).lower().replace("_", "-")
            for match in re.finditer(
                rf"(?m)^{CAPABILITY_PREFIX}([A-Z0-9_]+)=ready[ \t]*$",
                output,
            )
        )
        return cls(
            output=output,
            sdk_uid=int(sdk_uid_match.group(1)) if sdk_uid_match else None,
            build_id=build_match.group(1) if build_match else None,
            kernel_release=kernel_release,
            architecture=architecture,
            tizen_release=tizen_match.group(1) if tizen_match else None,
            capabilities=capabilities,
        )


@dataclass(frozen=True)
class TargetAssessment:
    profile: str
    status: CompatibilityStatus
    fingerprint: TargetFingerprint
    tested_build: str
    tested_kernel: str
    differences: tuple[str, ...]
    failures: tuple[str, ...]
    additional_tested_builds: tuple[str, ...] = ()

    @property
    def tested_builds(self) -> tuple[str, ...]:
        return (self.tested_build, *self.additional_tested_builds)

    def require_compatible(self) -> TargetAssessment:
        if self.status is CompatibilityStatus.INCOMPATIBLE:
            raise TargetCompatibilityError(
                f"{self.profile.upper()} target is incompatible: "
                + "; ".join(self.failures)
            )
        return self

    def require_tested(self, operation: str) -> TargetAssessment:
        self.require_compatible()
        if self.status is not CompatibilityStatus.TESTED:
            raise TargetCompatibilityError(
                f"{operation} uses build-specific addresses and requires the "
                f"tested builds {', '.join(self.tested_builds)}; observed "
                f"{self.fingerprint.build_id or 'unknown'}"
            )
        return self

    def render(self) -> str:
        fingerprint = self.fingerprint
        tested_label = (
            "Tested build"
            if len(self.tested_builds) == 1
            else "Tested builds"
        )
        lines = [
            f"Compatibility: {self.status.value}",
            f"Profile: {self.profile}",
            f"Build: {fingerprint.build_id or 'unknown'}",
            f"{tested_label}: {', '.join(self.tested_builds)}",
            f"Kernel: {fingerprint.kernel_release or 'unknown'}",
            f"Architecture: {fingerprint.architecture or 'unknown'}",
            f"Tizen: {fingerprint.tizen_release or 'unknown'}",
            "Capabilities: "
            + (", ".join(sorted(fingerprint.capabilities)) or "none"),
        ]
        lines.extend(
            f"Difference: {difference}" for difference in self.differences
        )
        lines.extend(f"Failure: {failure}" for failure in self.failures)
        return "\n".join(lines)


@dataclass(frozen=True)
class ExploitCompatibilityProfile:
    name: str
    tested_build: str
    build_family: str
    tested_kernel: str
    kernel_family: str
    architecture: str
    tizen_prefix: str
    required_capabilities: frozenset[str]
    capability_probes: tuple[str, ...]
    compatible_builds: frozenset[str] = frozenset()
    additional_tested_builds: frozenset[str] = frozenset()

    @property
    def tested_builds(self) -> frozenset[str]:
        return self.additional_tested_builds | {self.tested_build}

    def probe_command(self) -> str:
        commands = (
            "id",
            f"printf '{KERNEL_MARKER}'; uname -r",
            f"printf '{ARCHITECTURE_MARKER}'; uname -m",
            "cat /etc/tizen-release",
            "cat /etc/tizen-build.conf",
            "cat /proc/cmdline",
            *self.capability_probes,
        )
        return ";".join(commands)

    def assess(self, output: str) -> TargetAssessment:
        fingerprint = TargetFingerprint.parse(output)
        failures: list[str] = []
        if fingerprint.sdk_uid != 901:
            failures.append(
                f"SDK foothold UID is {fingerprint.sdk_uid}, expected 901"
            )
        if fingerprint.build_id is None:
            failures.append("build ID was not observed")
        elif not fingerprint.build_id.startswith(
            self.build_family
        ) and fingerprint.build_id not in (
            self.compatible_builds | self.tested_builds
        ):
            failures.append(
                f"build {fingerprint.build_id} is outside "
                f"{self.build_family} and is not a reviewed compatible build"
            )
        if fingerprint.kernel_release is None:
            failures.append("kernel release was not observed")
        elif not fingerprint.kernel_release.startswith(
            self.kernel_family
        ):
            failures.append(
                f"kernel {fingerprint.kernel_release} is outside "
                f"{self.kernel_family}"
            )
        if fingerprint.architecture != self.architecture:
            failures.append(
                f"architecture is {fingerprint.architecture or 'unknown'}, "
                f"expected {self.architecture}"
            )
        if (
            fingerprint.tizen_release is None
            or not fingerprint.tizen_release.startswith(self.tizen_prefix)
        ):
            failures.append(
                f"Tizen release is {fingerprint.tizen_release or 'unknown'}, "
                f"expected {self.tizen_prefix}"
            )
        missing_capabilities = sorted(
            self.required_capabilities - fingerprint.capabilities
        )
        if missing_capabilities:
            failures.append(
                "required runtime probes did not confirm: "
                + ", ".join(missing_capabilities)
            )
        differences: list[str] = []
        if fingerprint.build_id not in self.tested_builds:
            differences.append(
                f"build {fingerprint.build_id or 'unknown'} differs from "
                f"{self.tested_build}"
            )
        if fingerprint.kernel_release != self.tested_kernel:
            differences.append(
                f"kernel {fingerprint.kernel_release or 'unknown'} differs "
                f"from {self.tested_kernel}"
            )
        if failures:
            status = CompatibilityStatus.INCOMPATIBLE
        elif differences:
            status = CompatibilityStatus.COMPATIBLE
        else:
            status = CompatibilityStatus.TESTED
        return TargetAssessment(
            profile=self.name,
            status=status,
            fingerprint=fingerprint,
            tested_build=self.tested_build,
            tested_kernel=self.tested_kernel,
            differences=tuple(differences),
            failures=tuple(failures),
            additional_tested_builds=tuple(
                sorted(self.additional_tested_builds)
            ),
        )


def _marker_value(output: str, marker: str) -> str | None:
    match = re.search(
        rf"(?m)^{re.escape(marker)}(\S+)[ \t]*$", output
    )
    return match.group(1) if match else None


def _capability_probe(name: str, condition: str) -> str:
    marker = name.upper().replace("-", "_")
    return (
        f"if {condition};then printf "
        f"'{CAPABILITY_PREFIX}{marker}=ready\\n';"
        f"else printf '{CAPABILITY_PREFIX}{marker}=missing\\n';fi"
    )


TU7000_PROFILE = ExploitCompatibilityProfile(
    name="tu7000",
    tested_build="T-KTSU2AKUC-REL-202607021959",
    build_family="T-KTSU2AKUC-REL-",
    tested_kernel="4.1.10",
    kernel_family="4.1.",
    architecture="armv7l",
    tizen_prefix="Tizen5/TV 5.5.",
    required_capabilities=frozenset(("ps-agent", "mount-smb", "remotepc")),
    capability_probes=(
        _capability_probe(
            "ps-agent",
            "test -x /usr/apps/privileged-service/bin/ps_agent "
            "&& pgrep -f '^/usr/apps/privileged-service/bin/ps_agent$' "
            ">/dev/null",
        ),
        _capability_probe(
            "mount-smb",
            "test -x /usr/apps/privileged-service/bin/mount.smb.sh",
        ),
        _capability_probe(
            "remotepc",
            "test -x /usr/apps/org.tizen.remotepc/bin/remotepc_rdp "
            "&& test -f /usr/lib/systemd/system/org.tizen.remotepc.service",
        ),
    ),
)
