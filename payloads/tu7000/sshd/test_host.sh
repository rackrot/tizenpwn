#!/bin/sh
set -eu

# Host integration test for the prototype SSH daemon. This exercises the same
# key-only, PTY, SFTP, and SCP paths that the TV service will use.

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
port=${PORT:-2222}
work=$(mktemp -d "${TMPDIR:-/tmp}/tizenpwn-sshd-test.XXXXXX")
server_pid=

cleanup() {
    if [ -n "$server_pid" ]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

if ! command -v ssh >/dev/null 2>&1 ||
    ! command -v sftp >/dev/null 2>&1 ||
    ! command -v scp >/dev/null 2>&1 ||
    ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "host test requires ssh, sftp, scp, and ssh-keygen" >&2
    exit 77
fi

ssh-keygen -q -t ed25519 -N '' -f "$work/host_key"
ssh-keygen -q -t ed25519 -N '' -f "$work/client_key"
cp "$work/client_key.pub" "$work/authorized_keys"
chmod 600 "$work/authorized_keys"

(
    cd "$here"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -ldflags='-s -w' -o "$work/sshd" .
)

"$work/sshd" \
    --listen "127.0.0.1:$port" \
    --host-key "$work/host_key" \
    --authorized-keys "$work/authorized_keys" \
    --log "$work/sshd.log" \
    --pid-file "$work/sshd.pid" \
    --user "$(id -un)" \
    --home "$HOME" \
    --log-commands &
server_pid=$!

SSH="ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $work/client_key -p $port $(id -un)@127.0.0.1"

ready=0
for _ in $(seq 1 50); do
    if $SSH true >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" != 1 ]; then
    echo "server did not become ready" >&2
    cat "$work/sshd.log" >&2 || true
    exit 1
fi

$SSH 'id; uname -a; echo EXEC_OK' >"$work/exec.out"
grep -q 'EXEC_OK' "$work/exec.out"

$SSH -tt 'tty; echo PTY_OK' </dev/null >"$work/pty.out" 2>&1
grep -q 'PTY_OK' "$work/pty.out"
grep -q '/dev/pts/' "$work/pty.out"

printf 'put %s %s\nget %s %s\nrm %s\n' \
    "$work/client_key.pub" "$work/uploaded.pub" \
    "$work/uploaded.pub" "$work/downloaded.pub" \
    "$work/uploaded.pub" |
    sftp -q -o BatchMode=yes -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -i "$work/client_key" -P "$port" "$(id -un)@127.0.0.1"
cmp "$work/client_key.pub" "$work/downloaded.pub"

scp -q -o BatchMode=yes -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -i "$work/client_key" -P "$port" \
    "$work/client_key.pub" "$(id -un)@127.0.0.1:$work/scp.pub"
cmp "$work/client_key.pub" "$work/scp.pub"
rm -f "$work/scp.pub"

# Legacy SCP executes the remote `scp -t`/`-f` command through the shell. The
# TV has a signed /usr/bin/scp for this path.
scp -O -q -o BatchMode=yes -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -i "$work/client_key" -P "$port" \
    "$work/client_key.pub" "$(id -un)@127.0.0.1:$work/scp-legacy.pub"
cmp "$work/client_key.pub" "$work/scp-legacy.pub"
rm -f "$work/scp-legacy.pub"

if ssh -o BatchMode=yes -o IdentitiesOnly=yes \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -p "$port" \
    "$(id -un)@127.0.0.1" true 2>/dev/null; then
    echo "password authentication unexpectedly succeeded" >&2
    exit 1
fi

if ssh -o BatchMode=yes -o IdentitiesOnly=yes \
    -o PubkeyAuthentication=no -o ConnectTimeout=3 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p "$port" "$(id -un)@127.0.0.1" true 2>/dev/null; then
    echo "keyless authentication unexpectedly succeeded" >&2
    exit 1
fi

echo "HOST_TEST_OK"
