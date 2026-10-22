# TU7000 pure-JS SSH daemon

Status: host-tested; live deploy reached a listener once, then the process
exited on the first remote exec. The current live service is stopped. See
[`docs/TU7000_PERSISTENCE_STATUS.md`](../../../docs/TU7000_PERSISTENCE_STATUS.md).

This daemon exists because UEP blocks unsigned native code on the target,
including `.so` `dlopen` and unsigned binaries run through `ld.so`. The target's
signed Node 4.4.3 runtime can execute JavaScript as data, so the SSH server is
implemented in JS:

- `ssh2@0.8.9` server, vendored under `node_modules`;
- key-only public-key auth;
- one allowed user, default `root`;
- exec and PTY shell (`/usr/bin/script` provides the PTY);
- SFTP served by `ssh2-streams`;
- modern `scp` (SFTP) and legacy `scp -O`;
- no password, keyboard-interactive, certificate, or no-auth login;
- no port forwarding, agent forwarding, X11, or tunnels;
- logs to a file or stderr, never to the SSH channel.

## Target constraints and key types

- Node must be the target's **v4.4.3** (or another Node supported by
  `ssh2@0.8.9`). The file starts with `Buffer` compatibility shims for Node 4.4.
- The host key must be an **RSA private key in PEM**. Node 4's OpenSSL/`ssh2`
  stack cannot parse the ECDSA/Ed25519 private-key formats used for host keys.
- Client keys: **ECDSA** works without extra client flags. **RSA** works with
  `-o PubkeyAcceptedAlgorithms=+ssh-rsa`. **Ed25519 client keys did not
  authenticate** with this stack.
- Modern OpenSSH clients need `-o HostKeyAlgorithms=+ssh-rsa` for the RSA host
  key. KEX `diffie-hellman-group14-sha256` works without an override.
- PTY sessions are approximately 80x24. `window-change` is accepted but not
  applied because `script` owns the PTY.

## Why the vendored `ssh2` is patched

The SFTP subsystem in `ssh2@0.8.9` closes the channel without an
`exit-status`. Modern `scp` transfers the file but exits 1. The vendored
`node_modules/ssh2/lib/server.js` exposes the SFTP channel and sends
`exit-status 0` after a clean close. Do not replace the vendored tree with an
unpatched npm install without re-applying that change.

## Run

```console
node server.js \
  --listen 0.0.0.0:2222 \
  --host-key /opt/tizenpwn-ssh/etc/ssh_host_rsa_key \
  --authorized-keys /opt/tizenpwn-ssh/etc/authorized_keys \
  --log /opt/tizenpwn-ssh/var/sshd.log \
  --pid-file /opt/tizenpwn-ssh/var/sshd.pid \
  --user root \
  --home /root \
  --shell /bin/bash \
  --script /usr/bin/script
```

The host key and `authorized_keys` must be owned by the server user and must
not be group- or world-accessible. `--log -` writes to stderr; otherwise a
1 MiB rotating log is kept.

## Host test

```console
NODE=/path/to/node-v4.4.3/bin/node ./test_host.sh
```

The script expects the host Node to be able to run Node 4.4 code and uses
`/usr/bin/script`. It tests exec, PTY, SFTP, modern SCP, legacy SCP, and
password/keyless rejection. The script is currently under investigation for a
hang on some host Node combinations; the manual commands in the status document
are the authoritative evidence.

## Client examples

```console
# ECDSA client key, RSA host key
ssh -i ~/.ssh/tizenpwn_tv \
  -o HostKeyAlgorithms=+ssh-rsa \
  -o IdentitiesOnly=yes \
  -p 2222 root@TV 'id; uname -a'

# SFTP/SCP use the same host-key flag
sftp -i ~/.ssh/tizenpwn_tv -P 2222 \
  -o HostKeyAlgorithms=+ssh-rsa root@TV
scp -i ~/.ssh/tizenpwn_tv -P 2222 \
  -o HostKeyAlgorithms=+ssh-rsa local-file root@TV:/tmp/
```

## Security

This is a persistent root backdoor by design. Use a dedicated ECDSA/RSA key,
trusted LAN/VPN only, and never expose port 2222 to the Internet. Node 4.4.3 is
end-of-life; the server is a custom JS implementation, not OpenSSH or Dropbear.
No UEP change or firmware modification is made.

## Licensing

The daemon source is part of this repository (Unlicense). Vendored dependencies
retain their licenses:

- `ssh2`, `ssh2-streams`, `asn1`, `streamsearch`: MIT
- `bcrypt-pbkdf`: BSD-style (Blowfish portions; see its `LICENSE`)
- `safer-buffer`: MIT
- `tweetnacl`: public domain / Unlicense

See the `LICENSE` files under `node_modules/`.
