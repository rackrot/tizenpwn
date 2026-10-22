# TU7000 SSH daemon prototype

Status: host-tested; not yet live-tested on the TV.

This is a small static Go SSH daemon intended to run under the
`payloads/tu7000/persistence` memfd loader. It exists because the target has no
`sshd`, Dropbear, `sftp-server`, Python, Perl, or writable root home:

- key-only authentication with a dedicated `authorized_keys` file;
- one allowed user, default `root`;
- PTY shell sessions and non-interactive `exec`;
- SFTP via `github.com/pkg/sftp`;
- SCP through the client's SFTP path (modern OpenSSH) or legacy `scp -O`;
- no password, keyboard-interactive, certificate, or no-auth login;
- global requests discarded; only `session` channels accepted;
- client environment requests are ignored;
- fixed root environment and `HISTFILE=/dev/null` for the read-only `/root`;
- logs to a file, never to stdout (Node's stdio is close-on-exec).

The server is a prototype choice, not a claim that it is equivalent to
OpenSSH or Dropbear. The loader/installer boundary is server-agnostic; a
Dropbear or OpenSSH binary can replace this payload if it can be built and run
under the same rail.

## Build

```console
# Host test binary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags='-s -w' -o /tmp/tizenpwn-sshd .

# Target binary (ARMv7, static, no libc)
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
  go build -trimpath -ldflags='-s -w' -o /tmp/tizenpwn-sshd-arm .
```

Dependencies are vendored in `vendor/`; build with `-mod=vendor` if the
environment does not allow network access.

## Host test

```console
PORT=2222 ./test_host.sh
```

The script builds, starts, and removes a throwaway server. It verifies exec,
PTY, SFTP put/get, SCP put, and rejection of password and keyless auth. It
requires `ssh`, `sftp`, `scp`, `ssh-keygen`, and `go`.

## Runtime defaults

| Option | Default |
| --- | --- |
| `--listen` | `0.0.0.0:2222` |
| `--host-key` | `/opt/tizenpwn-ssh/etc/ssh_host_ed25519_key` |
| `--authorized-keys` | `/opt/tizenpwn-ssh/etc/authorized_keys` |
| `--log` | `/opt/tizenpwn-ssh/var/sshd.log` |
| `--log-max-bytes` | `1048576` (one rotated `.1` file) |
| `--pid-file` | `/opt/tizenpwn-ssh/var/sshd.pid` |
| `--user` | `root` |
| `--shell` | `/bin/bash` |
| `--home` | `/root` |

The host key and `authorized_keys` must be owned by the server user and must
not be group- or world-accessible. `--generate-host-key` creates a PKCS#8
Ed25519 host key with mode `0600` if the file is missing.

## Security limits

- This process runs as root and gives full-filesystem SFTP. It is a persistent
  root backdoor by design. Use a dedicated key and a trusted LAN/VPN only.
- It is not a sandbox. `--user root` plus `/bin/bash` means anything the key
  holder runs is root.
- Logs can contain commands when `--log-commands` is set. Leave it off unless
  diagnosing a problem.
- The server does not implement port forwarding, agent forwarding, X11, or
  tunnels. Keep it that way unless a reviewed use case requires it.
- The Go module versions are pinned in `go.mod` and vendored. Review updates;
  do not silently float them.

## Licensing

The daemon source is part of this repository (Unlicense). Vendored
dependencies retain their licenses:

- `github.com/pkg/sftp`: BSD-2-Clause
- `github.com/creack/pty`: MIT
- `github.com/kr/fs`: BSD-3-Clause
- `golang.org/x/crypto`, `golang.org/x/sys`: BSD-3-Clause

See the `LICENSE` files under `vendor/`.
