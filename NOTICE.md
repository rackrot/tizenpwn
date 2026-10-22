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
