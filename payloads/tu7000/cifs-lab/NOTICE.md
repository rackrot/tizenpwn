# Vendored CIFS lab notice

The disposable Docker lab in this directory is adapted from
[tiz0wn](https://github.com/sebastianspicker/tiz0wn), specifically
`research/remotepc-cifs-root/lab`, Copyright (c) 2026 Sebastian J. Spicker,
released under the MIT License in `LICENSE`.

Local modifications:

- fixed the disposable username to `owner`;
- changed the one-shot share and credential patterns for this project;
- changed container-internal paths and script names;
- no Samsung firmware or proprietary artifact is included here.

The adapted host orchestration in `src/tizenpwn/tu7000.py` is
separate original work. Upstream `research/remotepc-cifs-root` documentation
and host code were reviewed for behavior; they are not redistributed.
