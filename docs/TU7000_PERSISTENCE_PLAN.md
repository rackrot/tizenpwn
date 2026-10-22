# TU7000 persistent root SSH plan

Status: proposed. Nothing in this plan has been implemented or run against the
TV. The existing one-shot proof stays the default and must remain unchanged.

This plan turns the current Remote PC/CIFS one-shot root command into an opt-in
persistent root SSH service on the exact target:

`UN65TU7000FXZA` / `T-KTSU2AKUC-2743.0` /
`T-KTSU2AKUC-REL-202607021959`

The requested end state is an SSH daemon running on the TV, key-only root
login with a caller-supplied public key, working SFTP/SCP, and a service that
survives SSH disconnects, crashes, and (if the platform allows it) a reboot.
OpenSSH, Dropbear, or a small static daemon are all acceptable if the behavior
and evidence are equivalent; the target constraints decide which one is
practical.

## Outcome and completion

- Outcome: `tizenpwn cifs persist` installs and starts a root SSH service on the
  exact target; `tizenpwn cifs persist --uninstall` removes it and restores the
  pre-install state as far as the platform permits.
- Observable completion conditions:
  1. The install command reports `persistent: true`, `uid: 0`, the live SMACK
     context, the SSH listen address/port, the host-key fingerprint, and the
     authorized-key fingerprint.
  2. From a separate host, `ssh -i <key> -p <port> root@<TV> 'id; uname -a'`
     succeeds with `uid=0(root)`, without SDB, a lab, or a manual TV click.
  3. `sftp` and `scp` put/get a file with a matching SHA-256.
  4. Closing and reopening SSH works; killing the server is recovered by the
     supervisor; the service still answers after a reboot **if** the boot gate
     passes.
  5. `cifs persist --uninstall` stops and removes the service, unit, install
     directory, key material, and firewall exception, then verifies the port is
     closed and the paths are absent.
  6. `cifs probe` and `cifs command` still work exactly as before.
  7. Existing tests pass; README and evidence docs distinguish the default
     one-shot mode from the new persistent mode.

## Requirements and choices

### Product requirements and constraints

- Exact-target checks stay mandatory: model, build, kernel family,
  architecture, Tizen prefix, and the four reviewed artifact hashes.
- The only credential accepted is a caller-supplied SSH **public** key. The
  private key must never be copied to the TV, logged, or written to evidence.
- Root login is public-key only. Password, keyboard-interactive, and empty-key
  authentication must be disabled.
- The service must be reachable only on the trusted LAN. Do not expose it to
  the Internet.
- The install still uses the reviewed Remote PC/CIFS trigger and the two manual
  gates. The service starts only after the authenticated root agent returns
  success.
- Do not change UEP or any UEP sysfs setting, flash firmware, or alter the
  reviewed system binaries.
- The existing one-shot `probe` and `command` modes remain available as a
  fallback and must not acquire persistent state.
- Boot persistence is a separate, explicit opt-in because it writes TV-side
  boot configuration. It must not silently alter `/etc`, `/usr`, or the boot
  path.

### Implementation suggestions that may be replaced

- The current prototype is a small static **Go** SSH daemon using
  `golang.org/x/crypto/ssh`, `pkg/sftp`, and `creack/pty`. OpenSSH and Dropbear
  are not present on the target; either can replace the Go payload later if it
  can be cross-built and run under the same loader boundary.
- Run an unsigned server binary through a `memfd` loader. The observed target
  has no Python; the leading candidate is a dependency-free `.so` loaded by
  signed Node 4.4.3 through `process.dlopen`, with a constructor that writes the
  embedded server to `memfd` and executes it. UEP remains enabled.
- Use `/opt/tizenpwn-ssh` (or another discovered root-owned writable path) for
  the binary, config, keys, logs, and manifest.
- Use a dedicated `AuthorizedKeysFile` so uninstall does not edit
  `/root/.ssh/authorized_keys` or any unrelated key.
- Use a systemd unit for boot persistence when systemd and a writable unit path
  are verified; otherwise report boot persistence as unavailable.
- Default port `2222`, configurable. Default listen address `0.0.0.0`, with a
  documented recommendation to bind the TV's LAN address or restrict by
  firewall.
- Proposed CLI shape:

  ```console
  tizenpwn cifs persist "$TV_IP" \
    --confirm TU7000-T-KTSU2AKUC-2743.0 \
    --accept-saved-profile \
    --authorized-key ~/.ssh/tizenpwn_tv.pub \
    --identity-file ~/.ssh/tizenpwn_tv \
    --port 2222 \
    --boot

  tizenpwn cifs persist "$TV_IP" \
    --confirm TU7000-T-KTSU2AKUC-2743.0 \
    --accept-saved-profile \
    --uninstall
  ```

  `--identity-file` is used only by the controller for verification and the
  SSH-based uninstall path. It is never staged or stored on the TV.

### Scope and affected boundaries

- `src/tizenpwn/tu7000.py`: reuse target assessment, lab lifecycle, agent
  channel, staging, and evidence helpers; keep the one-shot paths intact.
- New `src/tizenpwn/persistence.py`: key validation, install/uninstall script
  construction, daemon arguments, manifest, and host-side verification.
- `src/tizenpwn/cli.py`: add `cifs persist` and uninstall options; update
  parser tests.
- `payloads/tu7000/ssh/`: reproducible cross-build for the static server and
  loader; no Samsung firmware.
- `tests/`: unit tests for key handling, config/script generation, manifest,
  and command parsing; no live target required.
- `README.md`, `docs/TU7000_2743.md`, and a new evidence section: document the
  opt-in persistent mode, security warnings, rollback, and exact limits.
- `NOTICE.md`: Go dependency licenses (BSD/MIT) and, if used, OpenSSH (BSD)
  and/or Dropbear (MIT) attribution and pinned source versions.

### Discovery: what must be learned before choosing the final design

The current evidence proves outbound root command execution only. It does not
prove that an SSH server can run, listen, or survive a reboot.

Read-only discovery (SDB, no persistent writes; the existing capture path may
stage a temporary self-deleting script):

- Is a signed `sshd`, `dropbear`, `sftp-server`, `scp`, `node`, an interpreter,
  or a loader already present?
- Node version, ABI, float ABI, `crypto` capabilities, and `process.dlopen`.
- If no interpreter exists, is there another signed process that can load a
  dependency-free `.so` or call `memfd_create`?
- `uname -m`, VFP/float ABI indicators, and whether an armv7l hard-float static
  binary runs.
- `mount`, `findmnt`, `df -h`, and candidate writable paths (`/opt`, `/data`,
  `/mnt`, `/etc`, `/home`); which are root-owned and not owner-writable?
- `systemctl --version`, `systemctl is-system-running`, and whether
  `/etc/systemd/system` is writable. `/etc` is `vdfs ro`, so also inspect
  `/opt/etc`, `/opt/systemrw`, `/opt/var`, `/etc/rc.d`, and existing boot
  targets for a writable, executed hook.
- `getent passwd root` and the root shell; `/root` writability (it is currently
  `dr-xr-x---`, so use a dedicated key file under `/opt`).
- `/dev/ptmx`, `/dev/pts`, and whether `devpts` is mounted.
- Current listeners (`/proc/net/tcp`, `ss -ltn`) and any firewall policy
  (`iptables -S`, `nft list ruleset`).
- Free space and the size of the staged server binary.

Root-only discovery (one bounded one-shot, no persistence):

- Confirm `memfd` execution with a trivial static armv7l payload loaded by
  signed Node; capture `dmesg`/UEP output on failure.
- Test write access to each candidate install path, creating and removing a
  marker.
- Test a temporary listener on the chosen port and connect from the host to
  prove inbound TCP is allowed.
- Test PTY allocation with the eventual `ssh -tt` session; `/dev/pts` is
  already mounted.
- Check whether `/etc/systemd/system` is actually writable as root; if not,
  test the candidate `/opt` hook paths and do not assume `systemctl enable`
  will work.
- Verify `setsid`/`nohup`/`start-stop-daemon` availability.
- Verify the root shell and SMACK context from a root child.

### Live discovery 2026-10-22 (read-only)

`tizenpwn cifs inventory 192.168.0.53` passed the exact-target checks and
changed several assumptions:

| Observation | Consequence |
| --- | --- |
| No `sshd`, Dropbear, `sftp-server`, `telnetd`, `inetd`, or `xinetd` | The server binary must be built and embedded; no signed server can be reused |
| No `python3`, `perl`, `ruby`, `php`, `busybox`, `nc`, `socat`, or `lua` | The Python `memfd` loader assumption is invalid |
| `/usr/bin/node` is Node `v4.4.3`, ABI 46, soft-float ARM, with `process.dlopen`, `net`, and OpenSSL 1.0.2 | Node is the only confirmed signed interpreter; a dependency-free `.so` loaded by Node is the leading execution rail |
| `/usr/bin/ssh`, `scp`, `sftp`, `ssh-keygen`, `ssh-keyscan` exist | Clients and key generation are available; only the server is missing |
| `/` is `vdfs ro` and 100% used; `/opt` is `vdfs rw` with ~301 MB free | Runtime state must live under `/opt`; `/root` is `dr-xr-x---` |
| `/etc/systemd/system` exists; systemd `231`, state `degraded`; `/etc` is `vdfs ro` | The unit directory is on a read-only root filesystem, so `systemctl enable` is doubtful; a boot hook elsewhere must be found or boot persistence must be reported unavailable |
| `/opt/etc` is world-writable; `/opt/systemrw` and `/opt/var` exist | `/opt` is the persistent writable area, but no existing boot hook is identified yet |
| `/dev/pts` is mounted with `devpts` | PTY support is available in principle |
| `smack_context` for the SDK shell is `System`; the root one-shot reported `System::Privileged` | The loader and service must be tested under both contexts |
| `sdb push` accepts `/home/owner/share/tmp/sdk_tools` but rejects `/tmp`, `/run`, `/dev/shm`, and `/opt/usr/home/owner/content` | Stage via `sdk_tools`; the root one-shot must copy to `/opt` |
| A soft-float test `.so` loaded from `/tmp` or `sdk_tools` failed with `failed to map segment` under the SDK context | Test `dlopen` from `/opt` under the root context before building the server |
| Root shell is `/bin/bash`; root home is read-only | Use a dedicated `AuthorizedKeysFile` under `/opt`, not `/root/.ssh` |
| No listener on 2222 in the observed list | 2222 is a candidate, subject to the inbound gate |

The leading execution rail is therefore:

1. build a static soft-float ARM server binary;
2. embed it in a dependency-free ARM soft-float `.so`;
3. load that `.so` with signed Node 4.4.3 using `process.dlopen`;
4. let the `.so` constructor create a `memfd`, write the embedded server, and
   `execve` it;
5. start the resulting process under a supervisor.

The constructor does not modify UEP. It is still subject to SMACK and to whether
`/opt` permits executable mappings. If `/opt` fails, the fallback is a
pure-JavaScript SSH server under Node (no unsigned exec), or the host-proxied
shell; both are more work and are not assumed.

### Status update 2026-10-22

The native execution rail is blocked by UEP on this firmware: both an unsigned
`.so` loaded by Node and an unsigned dynamic stage1 run through signed `ld.so`
were rejected. The current path is a pure-JS SSH daemon under the signed Node
4.4.3 runtime. It is host-tested and reached a live listener once, but the live
service is stopped for diagnosis. See
[`TU7000_PERSISTENCE_STATUS.md`](TU7000_PERSISTENCE_STATUS.md) for the resume
point and exact commands.

### Progress 2026-10-22

Host-side work is complete enough to test the rail on the TV:

- `tizenpwn cifs inventory 192.168.0.53` passed the exact-target checks.
- The Node-loaded `.so` rail was built for ARM soft-float and tested on the
  host: a dependency-free `.so` constructor creates a memfd, writes an embedded
  static probe, and executes it. Node 4.4.3 marks stdio close-on-exec, so the
  probe writes `/tmp/tizenpwn-memfd-ok` rather than stdout.
- A static Go SSH daemon prototype was host-tested with `ssh`, `sftp`, and
  `scp`: key-only exec, PTY, SFTP put/get, SCP put, and rejection of password
  and keyless auth all pass.
- The same daemon was cross-compiled static for ARM, embedded in the loader,
  and loaded through Node 4.4.3 on the host end-to-end. The resulting service
  accepted SSH and SFTP.
- OpenSSH/Dropbear are no longer the leading server choice: neither exists on
  the TV, and both would need a cross-build plus either a writable root home
  (Dropbear) or a privsep account (OpenSSH). The Go daemon uses a dedicated
  `AuthorizedKeysFile`, built-in SFTP, and the same loader boundary, so it is
  the pragmatic prototype. The loader/installer boundary remains
  server-agnostic.

Remaining gates are live-only:

1. `process.dlopen` of the probe `.so` from `/opt` under `System::Privileged`.
2. The same for the Go server, followed by host SSH/SFTP/SCP.
3. Inbound TCP to 2222; a firewall rule if required.
4. systemd unit/enable and reboot recovery.
5. Installer, uninstaller, evidence, and documentation.

### Material unknowns

| Unknown | Bounded assumption | Least updating evidence | Continue / change / stop |
| --- | --- | --- | --- |
| Unsigned exec under UEP | A dependency-free `.so` loaded by signed Node can `memfd`-exec an embedded static payload | Node `process.dlopen` of a harmless `.so` from `/opt` prints a marker | Continue if it prints; if `/opt` mappings are blocked, test another writable path or a pure-JS server; stop direct native-server work if no rail exists |
| Inbound TCP | A high port is reachable on the LAN | Temporary listener on the TV plus host connect | Continue if reachable; add one exact firewall rule if needed; stop if the firewall cannot be changed without weakening the LAN |
| SMACK context | A server started by the root one-shot inherits `System::Privileged`; boot systemd may differ | `cat /proc/self/attr/current` over SSH; compare with one-shot | Prefer the one-shot start path; use a unit label only if verified |
| PTY | `devpts` is mounted and interactive sessions work | `ssh -tt` runs `tty` | Mount `devpts` if missing; otherwise document non-interactive-only |
| Root account | Root has a usable shell and can read a dedicated key file | `getent passwd root`, key-auth `id` | Change the shell only if necessary and record it; never enable password login |
| Persistent path | `/opt` is root-writable and survives reboot | Mount/df plus create/remove marker, then reboot check | Use a root-owned, non-owner-writable path; stop boot persistence if none exists |
| Boot hook | systemd unit can be enabled | `/etc/systemd/system` write test, `systemctl enable`, reboot test | If no hook, deliver runtime persistence only and say so explicitly |
| SFTP/SCP | The Go daemon's `pkg/sftp` and SCP paths work | `sftp` and `scp` round-trip hashes on host, then live | If only SCP works, document it; if neither works, fix or replace the daemon |
| Server binary | Static ARM Go build runs on this kernel | `file`/`readelf` on host, then live SSH banner | Rebuild with the correct Go ABI or replace the server if it is wrong |

## Steps

1. **Add read-only persistence discovery.** Extend preflight (or add a small
   `inventory` mode) with the commands above. It must not write, start a
   listener, or change TV state. Record the exact target fingerprint and the
   discovery output in a gitignored evidence file.

2. **Prove the execution rail.** Build a harmless static armv7l payload and a
   minimal Node-loaded `memfd` loader. Run it through one reviewed one-shot
   with no persistence. Capture the marker, UEP message, kernel log, and
   timing. Do not proceed to server work until this gate passes; do not disable
   UEP.

3. **Prove inbound reachability and PTY.** In the same bounded run or a second
   one-shot, start a temporary listener on the intended port, connect from the
   host, and test PTY allocation. Remove the listener and temporary files. If a
   firewall rule is needed, add exactly one rule and record how it will be
   removed.

4. **Build the server payload reproducibly.** Keep the Go daemon in
   `payloads/tu7000/sshd` with pinned, vendored modules and a host test. Build
   a static ARMv7 binary, verify it with `file`/`readelf`, and embed it in the
   loader with `payloads/tu7000/persistence/build.py`. OpenSSH/Dropbear can be
   substituted here if a reviewed cross-build succeeds. The loader is staged
   as data and run by signed Node `process.dlopen`; the server binary is
   embedded in the `.so`, written to a `memfd`, and executed from
   `/proc/self/fd/N`.

5. **Define the install contract.** In `persistence.py`, add validated types
   for the public key, port, listen address, install root, host key, manifest,
   and service state. Generate the daemon arguments, the loader invocation, the
   install script, and the uninstall script from those types only. Reject
   absolute-path traversal, shell metacharacters in generated paths, private
   keys, multiple key lines, and unsafe ports. Unit-test every rejection.

6. **Implement install orchestration.** Add `cifs persist` that reuses
   `assess_target`, `CifsLab`, `AgentServer`, `_stage_agent`, and the existing
   two manual gates. Stage the loader `.so`, public key, and host key under
   random paths; verify their SHA-256 through SDB; run one authenticated install
   command as root. The install script must:
   - create the root-owned install directory and key/config files with exact
     modes;
   - install the authorized key into the dedicated `AuthorizedKeysFile`;
   - generate an Ed25519 host key on the controller when none exists, preserve
     it on reinstall, and print only its fingerprint;
   - start the server detached with a bounded startup wait. Prefer a systemd
     unit even for runtime-only installs; if systemd is unavailable, start a
     signed-`bash` supervisor loop with a backoff that restarts the loader;
     do not rely on a single unsupervised foreground process;
   - verify the listener and report PID, banner, fingerprints, `id`, and SMACK
     context;
   - roll back its own files and process if startup verification fails;
   - remove the staging files but leave the installed service;
   - report every path outside the install root that it changed. If it creates
     an account, unit, symlink, or firewall rule, record it in the manifest and
     do not reuse the one-shot `system_files_unchanged` result as if the TV were
     otherwise unchanged.

7. **Implement host-side verification.** After the install command returns,
   connect from the controller over SSH with a temporary `known_hosts` built
   from the reported host key. Verify the banner, key-only auth, `id`, PTY
   (`ssh -tt`), and SFTP/SCP round-trip hashes. Confirm that password auth and
   keyless auth fail. Store only fingerprints and observed output in evidence.

8. **Add boot persistence behind an explicit flag.** With `--boot`, first prove
   that a root-writable unit or hook path exists. `/etc` is currently `vdfs ro`,
   so do not assume `/etc/systemd/system` works. If it does, install
   `tizenpwn-ssh.service` with `Restart=always`, a start-limit, and an explicit
   `ExecStart` that runs the loader, then enable and verify `is-enabled` /
   `is-active`. If not, inspect `/opt`/`systemrw` boot hooks; only use one that
   is demonstrably executed. Offer a separate `--reboot-test` gate. If no hook
   exists, report `boot_persistent: false` with the reason; do not fake it with
   an owner-writable script.

9. **Implement uninstall and rollback.** Add `cifs persist --uninstall`. Prefer
   SSH when a usable identity file and host key are available; otherwise reuse
   the one-shot. Stop/disable the unit, kill the exact PID, remove the unit and
   symlink, remove the install directory, remove the firewall rule, and verify
   the port, process, and paths are absent. Preserve unrelated files. If the
   install created a system account, record it in the manifest and remove only
   that account.

10. **Update docs and notices.** Keep the one-shot proof as the default.
    Document the persistent mode as an opt-in backdoor with a dedicated key,
    trusted-LAN-only warning, host-key verification, SFTP/SCP behavior, boot
    caveats, firmware-update behavior, and the exact uninstall command. Update
    the old "no persistent service" claim where it applies to the new mode.

11. **Regression-test the existing route.** Run the existing one-shot tests and
    a live preflight. Confirm `cifs probe` and `cifs command` do not create the
    persistent directory, unit, listener, or key file.

## Verification

| Condition or risk | Hypothesis or what the check learned | Least-expensive reliable evidence | Why this evidence is sufficient | Rerun when | If it fails |
| --- | --- | --- | --- | --- | --- |
| Public-key parsing and permissions | Only one bare public key is accepted; private/option-bearing keys are rejected | Unit tests with valid ed25519/rsa keys and malformed inputs | Pure host-side validation; no target needed | `persistence.py` key code changes | Fix validation; never weaken to accept private keys |
| Generated config and scripts | Exact paths, modes, and quoted arguments; no injected shell | Unit tests that render scripts and assert the command string and modes | The generated text is the only thing the root agent runs | Config/script generation changes | Fix generation before any live run |
| Payload provenance | Static armv7l binary is built from the pinned source and matches `SHA256SUMS` | Docker build, `file`, `readelf`, and SHA-256 comparison | Prevents a host-built binary from silently changing | Dockerfile, version, or build flags change | Rebuild; do not stage an unverified binary |
| UEP execution rail | A Node-loaded `.so` can `memfd`-exec a harmless static payload from `/opt` | One-shot marker plus captured UEP/kernel output | This is the exact policy boundary the server depends on | Loader, Node, kernel, or firmware changes | Try another writable path or a pure-JS server; if still blocked, stop direct native-server work |
| Inbound TCP and PTY | The chosen port is reachable and a PTY can be allocated | Host connect to a temporary listener; `ssh -tt` `tty` | Proves the network and terminal path independent of SSH auth | Port, firewall, or boot config changes | Add one exact firewall rule or mount `devpts`; do not disable the firewall |
| Root SSH identity | Key-only auth returns UID 0 and the expected SMACK context | `ssh ... 'id; cat /proc/self/attr/current'` | Directly reaches the requested outcome | Install/config/key changes | Classify as auth, account, shell, or context failure; fix the named cause |
| SFTP/SCP | Both transfer a file with matching hashes | `sftp` put/get and `scp` put/get, then remote `sha256sum` | Proves the actual file-transfer requirement | Server choice, subsystem, or client version changes | If only SCP works, document it; if neither works, fix or replace the daemon |
| Detach and recovery | Server survives session close and is restarted after a kill | Close/reconnect; kill PID; observe new PID and successful `id` | Proves "runs all the time" without a reboot | Supervisor or unit changes | Fix supervision; do not leave a non-restarting process |
| Boot persistence | After reboot, SSH answers without a lab or manual click | `systemctl is-enabled`, reboot, bounded SSH retry, `id` | The only direct evidence of the requested persistence | Unit, boot path, or firmware changes | Report `boot_persistent: false`; recover via SDB/one-shot; do not boot-loop |
| Uninstall | Service, unit, files, key, and firewall rule are gone; port closed | Uninstall command plus port/process/path checks and a follow-up one-shot | Proves reversibility and limits residue | Manifest, unit, or install path changes | Stop and fix cleanup; do not claim removal |
| Existing route | `probe` and `command` still behave as documented | Existing tests plus one live preflight; optional one live one-shot | Confirms the new mode did not change the fallback | Shared code changes | Fix regression before live persistence work |
| No secret leakage | Private key and key contents never appear in logs/evidence | Unit test for evidence redaction; grep logs/evidence | Prevents credential exposure | Evidence schema or logging changes | Remove the field and rotate the key |

## Baseline, limits, and record

- Baseline: the one-shot probe and authenticated command were live-validated
  once on 2026-10-22. Persistent SSH has no baseline; every claim below the
  execution-rail gate is unproven until a live run.
- Known baseline failures and their relevance: UEP blocks direct execution of
  unsigned staged files; the existing agent avoids it with the signed inline
  `bash -c` path. The persistent design must not assume that direct exec works.
- Evidence to retain: target fingerprint and artifact hashes; discovery output;
  payload source version and SHA-256; host-key and authorized-key fingerprints;
  install/uninstall transcripts with secrets redacted; service state;
  `uid`/context; SSH banner; PTY/SFTP/SCP results; reboot result; any UEP,
  SMACK, or firewall denial; and every failed first attempt.
- Unreached conditions: if the execution rail, inbound port, writable boot
  path, or SFTP path fails, say so plainly. Runtime persistence without boot
  persistence is not the same outcome as reboot persistence.
- Stop when all completion conditions have direct evidence, uninstall has been
  demonstrated, and the existing one-shot route still passes. Stop early and
  report the failing gate if UEP bypass, inbound traffic, a safe persistent
  path, or a boot hook cannot be obtained without modifying UEP, disabling
  SMACK, weakening the firewall, or exposing the service to the Internet.

## Decisions to confirm before implementation

1. **Boot persistence:** install only a runtime service, or also an opt-in
   systemd boot unit? Recommended: runtime by default, `--boot` for the
   persistent end state.
2. **Server:** the host-tested static Go daemon, or invest in a reviewed
   OpenSSH/Dropbear cross-build? Recommended: keep the Go daemon for the first
   live gate because it already provides key-only auth, PTY, SFTP, and SCP;
   treat OpenSSH/Dropbear as a later substitution.
3. **Port and bind:** default `2222` on all interfaces, or bind the TV's LAN
   address? Recommended: `2222` with a firewall rule and LAN-only warning.
4. **Key:** default to `~/.ssh/id_ed25519.pub`, or require an explicit
   dedicated `~/.ssh/tizenpwn_tv.pub`? Recommended: require an explicit path;
   never default to a personal key.

## Fallback if the direct-server gate fails

If a `memfd` server cannot run, or inbound TCP cannot be opened safely, do not
modify UEP or disable the firewall. The fallback is a host-proxied root shell:

- the TV runs a long-lived signed-`bash` agent that reconnects outbound to the
  controller;
- the controller exposes SSH locally and forwards sessions or file operations
  over that agent;
- SFTP/SCP would be host-mediated and slower, and the controller must stay
  online;
- boot persistence still needs a TV-side hook, so this fallback does not solve
  an untethered reboot by itself.

This fallback preserves the current execution policy but does not satisfy the
literal "sshd on the TV" preference. It should be chosen only after the direct
gate fails and the user accepts the tradeoff.
