#!/bin/sh
set -eu

# Host-only test of the Node-loaded memfd rail. It needs Zig and Node, but not
# the TV or the Go daemon.

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
zig=${ZIG:-zig}
work=$(mktemp -d "${TMPDIR:-/tmp}/tizenpwn-loader-test.XXXXXX")

cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

python3 "$here/build.py" probe \
    --zig "$zig" \
    --target x86_64-linux-musl \
    --probe-file "$work/marker" \
    --output "$work/probe"

python3 "$here/build.py" loader \
    --zig "$zig" \
    --payload "$work/probe" \
    --output "$work/libtizenpwn.so" \
    --name tizenpwn-probe \
    --target x86_64-linux-gnu \
    --error-file "$work/loader-error"

if ! node -e "try{process.dlopen({exports:{}}, \"$work/libtizenpwn.so\")}catch(e){console.error(e.message)}"; then
    if [ -f "$work/loader-error" ]; then
        cat "$work/loader-error" >&2
    fi
fi

if ! grep -q TIZENPWN_MEMFD_OK "$work/marker"; then
    echo "loader did not produce the expected marker" >&2
    if [ -f "$work/loader-error" ]; then
        cat "$work/loader-error" >&2
    fi
    exit 1
fi

echo "LOADER_HOST_TEST_OK"
