#!/bin/sh
set -eu

# Build the probe and the static SSH server, then embed each in its loader.
# Outputs are written outside the repository by default.

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../../.." && pwd)
out=${1:-/tmp/tizenpwn-build}
zig=${ZIG:-zig}

mkdir -p "$out"

python3 "$here/build.py" probe \
    --zig "$zig" \
    --output "$out/tizenpwn-probe"

python3 "$here/build.py" loader \
    --zig "$zig" \
    --payload "$out/tizenpwn-probe" \
    --output "$out/libtizenpwn-probe.so" \
    --name tizenpwn-probe \
    --error-file /tmp/tizenpwn-loader-error

(
    cd "$root/payloads/tu7000/sshd"
    CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
        go build -trimpath -ldflags='-s -w' \
        -o "$out/tizenpwn-sshd-arm" .
)

python3 "$here/build.py" loader \
    --zig "$zig" \
    --payload "$out/tizenpwn-sshd-arm" \
    --output "$out/libtizenpwn-sshd.so" \
    --name sshd \
    --error-file /opt/tizenpwn-ssh/var/loader-error

cd "$out"
sha256sum \
    tizenpwn-probe \
    libtizenpwn-probe.so \
    tizenpwn-sshd-arm \
    libtizenpwn-sshd.so > SHA256SUMS
cat SHA256SUMS
ls -lh \
    tizenpwn-probe \
    libtizenpwn-probe.so \
    tizenpwn-sshd-arm \
    libtizenpwn-sshd.so
