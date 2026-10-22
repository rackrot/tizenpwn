# NOTICE

## Main code

The host orchestration and SDB transport in this repository are adapted from
[chris-ritsen/samsung-tv-root](https://github.com/chris-ritsen/samsung-tv-root),
released under the Unlicense (public domain). See `LICENSE`.

The TU7000 target binding, Remote PC/CIFS proof, authenticated one-shot agent,
and disposable-lab orchestration are separate target-specific work.

## Disposable lab

`payloads/tu7000/cifs-lab` is adapted from
[sebastianspicker/tiz0wn](https://github.com/sebastianspicker/tiz0wn),
`research/remotepc-cifs-root/lab`, Copyright (c) 2026 Sebastian J. Spicker,
released under the MIT License. The full MIT text is in
`payloads/tu7000/cifs-lab/LICENSE`; local modifications are listed in
`payloads/tu7000/cifs-lab/NOTICE.md`.

## Persistent SSH prototype

`payloads/tu7000/persistence` (the Node-loaded memfd loader, probe, and build
helper) is target-specific work and part of this repository's Unlicense code.

`payloads/tu7000/sshd` is a Go SSH daemon prototype. Its vendored dependencies
retain their upstream licenses:

- `github.com/pkg/sftp`: BSD-2-Clause
- `github.com/creack/pty`: MIT
- `github.com/kr/fs`: BSD-3-Clause
- `golang.org/x/crypto`, `golang.org/x/sys`: BSD-3-Clause

The full texts are in the corresponding `LICENSE` files under
`payloads/tu7000/sshd/vendor/`. The Go standard library is used under its
BSD-3-Clause license; no Go toolchain or prebuilt Go binary is redistributed.

## Pure-JS SSH daemon

`payloads/tu7000/sshd-js` is a target-specific JS daemon. Its vendored
dependencies retain their upstream licenses:

- `ssh2`, `ssh2-streams`, `asn1`, `streamsearch`: MIT
- `bcrypt-pbkdf`: BSD-style (Blowfish portions; see its `LICENSE`)
- `safer-buffer`: MIT
- `tweetnacl`: public domain / Unlicense

The full texts are under `payloads/tu7000/sshd-js/node_modules/*/LICENSE`.
The vendored `ssh2` SFTP subsystem has a local patch documented in
`payloads/tu7000/sshd-js/README.md`.

## Third-party tools

The Docker lab installs Debian packages, xrdp, xorgxrdp, and Fortra Impacket
from upstream package sources at build time. Their source is not vendored
here. Impacket is pinned to 0.13.1 in the lab Dockerfile.

## What this repository does not contain

- No Samsung firmware, decrypted or otherwise.
- No firmware signing keys, Samsung credentials, or device-identifying
  captures.
- No persistence, firmware modification, or UEP change.

## Trademarks

Samsung, Tizen, and other product names are trademarks of their respective
owners and are used here for identification and interoperability only. This
project is not affiliated with or endorsed by Samsung.

## Scope

All work concerns a device the author owns, on a trusted local network. The
route was live-validated once on the exact model/build recorded in
`docs/TU7000_2743.md`. It does not establish an affected-version range.
