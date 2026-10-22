#!/bin/sh
set -eu

# Host integration test for the pure-JS SSH daemon. Set NODE=/path/to/node to
# exercise the target's Node 4.4.3; otherwise the host node is used.

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
node_bin=${NODE:-node}
port=${PORT:-2244}
work=$(mktemp -d "${TMPDIR:-/tmp}/tizenpwn-sshd-js-test.XXXXXX")
server_pid=

cleanup() {
    if [ -n "$server_pid" ]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

ssh-keygen -q -t rsa -b 2048 -m PEM -N '' -f "$work/host_key"
ssh-keygen -q -t ecdsa -b 256 -m PEM -N '' -f "$work/client_key"
chmod 600 "$work/host_key" "$work/client_key"
cp "$work/client_key.pub" "$work/authorized_keys"
chmod 600 "$work/authorized_keys"

"$node_bin" "$here/server.js" \
    --listen "127.0.0.1:$port" \
    --host-key "$work/host_key" \
    --authorized-keys "$work/authorized_keys" \
    --log "$work/sshd.log" \
    --pid-file "$work/sshd.pid" \
    --user "$(id -un)" \
    --home "$HOME" \
    --script /usr/bin/script \
    --log-commands &
server_pid=$!

common="-o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o HostKeyAlgorithms=+ssh-rsa -i $work/client_key -p $port"
SSH="ssh $common $(id -un)@127.0.0.1"

ready=0
for _ in $(seq 1 50); do
    if timeout 5 $SSH true >/dev/null 2>&1; then
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

timeout 20 $SSH 'id; uname -a; echo EXEC_OK' >"$work/exec.out"
grep -q 'EXEC_OK' "$work/exec.out"

timeout 20 $SSH -tt 'tty; echo PTY_OK' </dev/null >"$work/pty.out" 2>&1
grep -q 'PTY_OK' "$work/pty.out"
grep -q '/dev/pts/' "$work/pty.out"

printf 'put %s %s\nget %s %s\nrm %s\n' \
    "$work/client_key.pub" "$work/uploaded.pub" \
    "$work/uploaded.pub" "$work/downloaded.pub" \
    "$work/uploaded.pub" |
    timeout 20 sftp -q $common "$(id -un)@127.0.0.1"
cmp "$work/client_key.pub" "$work/downloaded.pub"

timeout 20 scp -q $common "$work/client_key.pub" "$(id -un)@127.0.0.1:$work/scp.pub"
cmp "$work/client_key.pub" "$work/scp.pub"
rm -f "$work/scp.pub"

timeout 20 scp -O -q $common "$work/client_key.pub" "$(id -un)@127.0.0.1:$work/scp-legacy.pub"
cmp "$work/client_key.pub" "$work/scp-legacy.pub"
rm -f "$work/scp-legacy.pub"

if ssh -o BatchMode=yes -o IdentitiesOnly=yes \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o HostKeyAlgorithms=+ssh-rsa \
    -p "$port" "$(id -un)@127.0.0.1" true 2>/dev/null; then
    echo "password authentication unexpectedly succeeded" >&2
    exit 1
fi

if ssh -o BatchMode=yes -o IdentitiesOnly=yes \
    -o PubkeyAuthentication=no -o ConnectTimeout=3 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o HostKeyAlgorithms=+ssh-rsa \
    -p "$port" "$(id -un)@127.0.0.1" true 2>/dev/null; then
    echo "keyless authentication unexpectedly succeeded" >&2
    exit 1
fi

echo "JS_HOST_TEST_OK"
