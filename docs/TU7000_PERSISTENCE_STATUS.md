# TU7000 persistent root SSH status

Status as of 2026-10-22: **paused mid-deploy; no service is running.**

This document is the resume point. The existing one-shot `probe` and `command`
routes are unchanged. No UEP or firmware change was made.

## Target

- `UN65TU7000FXZA`
- `T-KTSU2AKUC-2743.0`
- `T-KTSU2AKUC-REL-202607021959`
- TV address observed during work: `192.168.0.53`
- Controller address: `192.168.0.80`

## What is proven

### Native execution is blocked

UEP rejects unsigned native code from disk, including:

- an unsigned `.so` loaded with Node `process.dlopen`:
  `[UEP] file /opt/tizenpwn-gate/loader.so is not signed`;
- an unsigned dynamic stage1 executed through signed
  `/lib/ld-linux.so.3`:
  `[UEP] file .../tizenpwn-stage1 is not signed`.

An `O_TMPFILE` attempt caused the TV shell session to wedge and was abandoned.
The TV was power-cycled; SDB recovered.

**Conclusion:** do not pursue the native memfd loader, Go server, OpenSSH, or
Dropbear on this firmware without an explicit decision to disable UEP. The
loader/probe and Go server directories are retained as host-tested research,
not as the current path.

### Pure-JS SSH server works on the host

`payloads/tu7000/sshd-js/` is a Node 4.4.3-compatible SSH daemon built on
`ssh2@0.8.9` with vendored dependencies. Host tests pass for:

- key-only auth, root user, ECDSA or RSA client keys (Ed25519 client keys did
  not authenticate with this stack);
- exec with correct exit status;
- PTY shell via `/usr/bin/script`;
- SFTP put/get/list/remove;
- modern `scp` (SFTP) and legacy `scp -O`;
- rejection of password and keyless auth.

The server uses an RSA host key. Modern clients need:

```text
-o HostKeyAlgorithms=+ssh-rsa
```

ECDSA client keys need no `PubkeyAcceptedAlgorithms` override. RSA client keys
also need `-o PubkeyAcceptedAlgorithms=+ssh-rsa`.

The vendored `ssh2` has one local patch: the SFTP subsystem exposes its channel
and sends `exit-status` after a clean close. Without it, modern `scp` transfers
the file but exits 1. The patch is in
`payloads/tu7000/sshd-js/node_modules/ssh2/lib/server.js`.

### Live deploy reached a running listener

The first deployment succeeded:

- extracted under `/opt/tizenpwn-ssh`;
- Node listened on `0.0.0.0:2222` as root;
- host key fingerprint:
  `SHA256:BW3fSY45P0hLUYlBLECcSogFIZFK+gyaL9r3fYJ4hZM`;
- one-shot evidence: `uid=0(root)`, `System::Privileged`, system hashes
  unchanged, lab cleaned.

The first SSH exec connection was **closed by the remote host**, and the Node
process exited (connection refused afterwards). The root-only log was not
readable through SDB, so the crash cause is not yet known. The running service
is dead; there is no listener on 2222.

A hardened second tarball was built and staged, but **not deployed**:

- `/tmp/tizenpwn-deploy/sshd-js2.tar.gz`
- SHA-256 `e80425e83a0d528486f925914527c31eea14035ec46bb422bfc012c4f9643cfb`
- TV staging path:
  `/home/owner/share/tmp/sdk_tools/tizenpwn-sshd-js2.tar.gz`

It adds channel/child error handlers, a `/tmp/tizenpwn-sshd-crash` record, and
session error logging. The redeploy will use a world-readable log at
`/tmp/tizenpwn-sshd.log` so the next failure can be inspected without root.

## Current TV state

- No process is listening on 2222.
- `/opt/tizenpwn-ssh` exists, root-owned mode 700. It contains the first
  deployment and its old `var/sshd.log`; it is not running.
- The first deploy's PID was `3540`.
- Staged under `/home/owner/share/tmp/sdk_tools`:
  - `tizenpwn-sshd-js2.tar.gz` (new, hardened)
  - `tizenpwn-sshd-js.tar.gz` (old)
  - `tizenpwn_host_key`
  - `tizenpwn_authorized_keys`
  - older native probe/stage1 files
- The TV still has a saved Remote PC profile from the last attempt. Delete it
  through the TV UI when done.
- No lab container is running; host TCP 3389/445 are closed.

## Host artifacts to resume

`/tmp/tizenpwn-deploy/`:

| File | Purpose | SHA-256 / fingerprint |
| --- | --- | --- |
| `sshd-js2.tar.gz` | hardened deploy tarball | `e80425e83a0d528486f925914527c31eea14035ec46bb422bfc012c4f9643cfb` |
| `host_key` | temporary RSA host key | `edb3dbbf054abba4cef1d29355c783a93b5f0b15fa9793b9ceabf803e2b8264b` |
| `host_key.pub` | host public key | `SHA256:BW3fSY45P0hLUYlBLECcSogFIZFK+gyaL9r3fYJ4hZM` |
| `client_key` | temporary ECDSA client key | `SHA256:RcJtE5gwxKaw7m5gNGxu5yA+DJLOeXNy+QvcVudEQcU` |
| `authorized_keys` | gate public key | `9afc88f24797acc3495cc833c276ee4bafabd9afa8108794b83afb3aa3ca98c7` |
| `known_hosts` | `[192.168.0.53]:2222` entry | host key above |
| `deploy2.txt` | hardened deploy command body | — |

These are temporary test credentials. Replace them with the owner's chosen
ECDSA/RSA key in the installer. Do not commit `/tmp` keys.

## Resume steps

1. Confirm SDB and Developer Mode:

   ```console
   sdb connect 192.168.0.53:26101
   uv run tizenpwn preflight 192.168.0.53
   ```

2. Start the redeploy one-shot in an interactive terminal:

   ```console
   uv run tizenpwn cifs command 192.168.0.53 \
     --confirm TU7000-T-KTSU2AKUC-2743.0 \
     --accept-saved-profile \
     --accept-timeout 1800 \
     --command "$(cat /tmp/tizenpwn-deploy/deploy2.txt)"
   ```

   It extracts the hardened tarball, copies the temporary host/authorized keys,
   starts Node with `/tmp/tizenpwn-sshd.log` and `/tmp/tizenpwn-sshd.pid`, and
   prints the old root log, new log, PID, and crash file. The usual two manual
   Remote PC/Shared Folder gates are required.

3. Verify from the controller:

   ```console
   ssh -i /tmp/tizenpwn-deploy/client_key \
     -o IdentitiesOnly=yes -o BatchMode=yes \
     -o HostKeyAlgorithms=+ssh-rsa \
     -o StrictHostKeyChecking=yes \
     -o UserKnownHostsFile=/tmp/tizenpwn-deploy/known_hosts \
     -p 2222 root@192.168.0.53 \
     'id; uname -a; cat /proc/self/attr/current'
   ```

4. Test PTY, SFTP, modern SCP, and legacy SCP:

   ```console
   ssh ... -tt 'tty; echo PTY_OK'
   sftp ...   # put/get/rm
   scp ...    # modern
   scp -O ... # legacy
   ```

5. If the service dies, read:

   ```console
   cat /tmp/tizenpwn-sshd-crash
   cat /tmp/tizenpwn-sshd.log
   cat /tmp/tizenpwn-sshd-oldlog
   ```

6. After it is stable, implement `tizenpwn cifs persist` / `--uninstall`:
   - validate an ECDSA or RSA public key, reject Ed25519 with a clear error;
   - stage the JS tarball, host key, and authorized key;
   - reuse `assess_target`, `CifsLab`, `AgentServer`, and the two gates;
   - deploy under `/opt`, set root ownership/modes, start via `setsid`;
   - verify SSH, PTY, SFTP, and SCP from the controller;
   - uninstall by killing the PID and removing `/opt/tizenpwn-ssh`;
   - report `boot_persistent: false` unless a writable, executed boot hook is
     found. `/etc` is read-only; no hook has been identified yet.

## Boot persistence

`/` and `/etc` are `vdfs ro`. `/opt` is writable and persistent. No writable
boot hook has been identified. Do not claim reboot persistence until a hook is
found and a reboot test passes. Runtime persistence (until reboot) is the
supported target for the next gate.

## Security and limits

- This is a persistent root backdoor. Use a dedicated ECDSA/RSA key and a
  trusted LAN. Never expose port 2222 to the Internet.
- Node 4.4.3 is EOL. The server is a custom JS implementation, not OpenSSH or
  Dropbear. The host-key algorithm is `ssh-rsa`; modern clients need
  `HostKeyAlgorithms=+ssh-rsa`.
- Ed25519 client keys did not authenticate with this stack. RSA client keys
  need `PubkeyAcceptedAlgorithms=+ssh-rsa`; ECDSA works without it.
- PTY sessions are fixed at approximately 80x24 because `script` owns the PTY;
  window-change requests are accepted but not resized.
- No UEP change, firmware flash, or Samsung binary modification was made.
