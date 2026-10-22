# tizenpwn

Owner-authorized Samsung Tizen TV research. This repository contains one
exact-target route:

**`UN65TU7000FXZA` / `T-KTSU2AKUC-2743.0` /
`T-KTSU2AKUC-REL-202607021959`**

It uses the SDB package-name foothold for read-only assessment and for a
two-push UID-0 classifier, then the TV's privileged Remote PC CIFS helper for
bounded root execution. A disposable Docker RDP/SMB lab on the controller
supplies the RDP session and SMB share that the TV's Remote PC app connects to.

Use this only on a TV you own, on a trusted local network, with the owner
present at the TV. It starts host listeners, changes TV-side Remote PC profile
state, and must not be exposed to the Internet.

## Exact target

| Field | Value |
| --- | --- |
| Model | `UN65TU7000FXZA` |
| Firmware release | `T-KTSU2AKUC-2743.0` |
| Build ID | `T-KTSU2AKUC-REL-202607021959` |
| Tizen | `Tizen5/TV 5.5.0 (arm)` |
| Kernel | `4.1.10` |
| Architecture | `armv7l` |

The route rejects any other model, build family, kernel family, architecture,
Tizen prefix, or reviewed-artifact hash before starting the lab. Support is
claimed only for the exact model/build above.

## Requirements

- Python 3.12+
- Samsung `sdb` from Tizen Studio, with the TV in Developer Mode and listed as
  `device`
- Docker and OpenSSL on the controller
- Host TCP 3389 and 445 free; SMB 445 is published by the Docker daemon
- TV and controller on the same trusted LAN
- The owner can use a pointer and keyboard at the TV

## Install

```console
uv sync --group dev
```

Or run directly from a source checkout with `PYTHONPATH=src`.

## Preflight

Read-only on the TV. It verifies the SDB foothold, target fingerprint,
`ps_agent`, `mount.smb.sh`, Remote PC presence, and these exact artifact
hashes:

| Artifact | SHA-256 |
| --- | --- |
| `mount.smb.sh` | `37aaf2f05bf714332a6bf8f14b543ac9584a1b9a051341674a74fc0dd753c57e` |
| `ps_agent` | `402885bce04ca3a04c2cb322cbe83dd96d05e17457717b4627a85b0fdb004c33` |
| `remotepc_rdp` | `5d5b8277b20cae7ec993be7ff8f556a5f04cdff07109beb025c0e377f4dff9e4` |
| `remotepc_uilauncher` | `b87e23127fe04cfab9e2c43468a99a4c4aa0b852fd5923de17104c3cf9d872da` |

```console
uv run tizenpwn preflight "$TV_IP"
uv run tizenpwn -o json preflight "$TV_IP"
```

## Read-only persistence inventory

```console
uv run tizenpwn cifs inventory "$TV_IP"
uv run tizenpwn -o json cifs inventory "$TV_IP"
```

This is discovery for the proposed persistent SSH mode. It runs the same exact
target assessment and then reports candidate SSH binaries, Python and `memfd`
support, systemd/unit-directory state, root account and shell, PTY/devpts
state, listeners, mount options, disk space, SDK-user writability, and any
existing `tizenpwn-ssh` install.

It does not start a listener, install a service, change UEP/SMACK, or create
persistent state. Like the existing preflight, it may use the SDB capture path's
temporary self-deleting script under `/home/owner/share/tmp/sdk_tools` when the
probe is larger than the package-name injection limit.

## One bounded UID-0 proof

This starts the disposable lab and waits for two manual gates. It is not a
read-only check. The TV stores a temporary Remote PC profile that must be
deleted through the TV UI afterward.

```console
uv run tizenpwn cifs probe "$TV_IP" \
  --confirm TU7000-T-KTSU2AKUC-2743.0 \
  --accept-saved-profile
```

The lab prints a private form card: controller address, username `owner`, a
one-shot password containing the UID-0 marker command, a share name, and the
disposable RDP certificate fingerprint. The operator:

1. creates/selects the Remote PC profile with exactly those values, over RDP;
2. connects once, compares the certificate fingerprint, and leaves persistent
   certificate trust unchecked;
3. waits for the disposable host xterm and types `CONNECTED`;
4. reveals the TV's in-session top toolbar, clicks **Shared Folder exactly
   once**, and types `CLICKED`.

The harness requires exactly one new RDP login and one new SMB share
enumeration, classifies a fresh root-owned marker beginning
`uid=0(root) gid=0(root)`, reads it through SDB, removes it, re-hashes system
files, checks `ps_agent`, removes the lab containers, and verifies 3389/445 are
closed. A timeout, extra enumeration, or ambiguous push result is terminal; do
not retry the same run.

## One authenticated root command batch

```console
uv run tizenpwn cifs command "$TV_IP" \
  --confirm TU7000-T-KTSU2AKUC-2743.0 \
  --accept-saved-profile \
  --command 'id' \
  --command 'uname -a'
```

The agent stages non-executable data under
`/home/owner/share/tmp/sdk_tools`, authenticates to a fresh host listener with
a 128-bit shared-secret challenge, sends its root identity, runs the requested
commands, and exits on an explicit `__EXIT__`. The staged data is removed
afterward. It installs no persistent service or listener; every batch requires
a new manual Shared Folder trigger.

Direct execution of the staged file is UEP-blocked on this firmware:

```text
[uep][bash] the file is NOT signed!!
```

The adapter therefore uses the already-signed inline `bash -c` path. It does
not change UEP or any UEP setting.

## Cleanup

Host cleanup is automatic. On the TV, exit Remote Access Player, delete the
temporary Remote PC profile, and revoke any disposable validation pairing.
Those are TV UI actions and are not automated.

## Evidence

The live runs were performed against this implementation before the repository
split; the moved code retains the reviewed logic and was re-verified with a
live preflight and the full disposable-lab self-test from this checkout.

Live-validated once on the owner's TV on 2026-10-22:

- probe: `uid=0(root) gid=0(root) context="System::Privileged"`, one RDP
  login, one SMB enumeration, unchanged system hashes, cleaned staging;
- agent: `id` and `uname -a` exit `0` as UID 0, challenge-response passed,
  agent data removed, `ps_agent` healthy, lab ports closed.

Full evidence and the original plan:

- [`docs/TU7000_2743.md`](docs/TU7000_2743.md)
- [`docs/TU7000_2743_PLAN.md`](docs/TU7000_2743_PLAN.md)

A proposed opt-in persistent root SSH service is described in
[`docs/TU7000_PERSISTENCE_PLAN.md`](docs/TU7000_PERSISTENCE_PLAN.md). The
current route still installs no persistent service.

Host-side prototype, not wired into the CLI and not live-installed:

- `payloads/tu7000/persistence`: Node-loaded `memfd` loader and probe.
- `payloads/tu7000/sshd`: static Go SSH daemon with key-only auth, PTY, SFTP,
  and SCP.

The native memfd/loader path is blocked by UEP on this firmware. The current
path is a pure-JS SSH daemon under the signed Node runtime; it is host-tested
and reached a live listener once, but the live service is currently stopped.
The live deploy, crash diagnosis, `cifs persist` installer, and boot
persistence remain pending.

- Current status and resume commands:
  [`docs/TU7000_PERSISTENCE_STATUS.md`](docs/TU7000_PERSISTENCE_STATUS.md)
- Plan: [`docs/TU7000_PERSISTENCE_PLAN.md`](docs/TU7000_PERSISTENCE_PLAN.md)
- Payload notes: `payloads/tu7000/persistence/README.md` and
  `payloads/tu7000/sshd-js/README.md`

## Scope

No Samsung firmware is included or redistributed. No UEP change, firmware
flash, persistent service, or debloat is part of this route. The root process
still carries Samsung's `System::Privileged` context; UID 0 is not proof that
every security boundary is gone.

## Licensing

- Main code: Unlicense; adapted from
  [chris-ritsen/samsung-tv-root](https://github.com/chris-ritsen/samsung-tv-root).
- Disposable lab: MIT; adapted from
  [sebastianspicker/tiz0wn](https://github.com/sebastianspicker/tiz0wn),
  `research/remotepc-cifs-root/lab`. See
  `payloads/tu7000/cifs-lab/LICENSE` and `NOTICE.md`.
- See [`NOTICE.md`](NOTICE.md) for attribution and third-party tools.
