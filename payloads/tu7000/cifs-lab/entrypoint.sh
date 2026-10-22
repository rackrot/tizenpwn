#!/bin/sh
set -eu

secret_dir=/run/cifs-lab-secrets
for name in username password share; do
    test -f "$secret_dir/$name" || {
        echo "missing required secret file" >&2
        exit 64
    }
done

username=$(cat "$secret_dir/username")
password=$(cat "$secret_dir/password")
share=$(cat "$secret_dir/share")

case "$username" in
    owner) ;;
    *) echo "invalid fixed lab username" >&2; exit 64 ;;
esac
case "$share" in
    TVROOT[0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]) ;;
    *) echo "invalid one-shot share name" >&2; exit 64 ;;
esac
# Validate the exact literal one-shot password before it reaches chpasswd or
# any shell. The probe and the inline agent deliberately use different shapes.
if ! /usr/bin/python3 - "$password" <<'PY'
import re
import sys

probe = r"\$\(/usr/bin/id>/home/owner/share/tmp/sr-[0-9a-f]{12}\)"
agent = (
    r':;bash\$IFS-c\$IFS"\$\(cat\$IFS/home/owner/share/tmp/sdk_tools/'
    r'a[0-9a-f]{8}\)"'
)
value = sys.argv[1]
raise SystemExit(
    0 if re.fullmatch(probe, value) or re.fullmatch(agent, value) else 1
)
PY
then
    echo "invalid literal one-shot password" >&2
    exit 64
fi

# Feed the validated literal through stdin, never shell syntax or process argv.
# XRDP's PAM stack then authenticates the same exact credential as SMB.
printf '%s:%s\n' "$username" "$password" | /usr/sbin/chpasswd
unset password

rm -f /run/xrdp/xrdp.pid /run/xrdp/xrdp-sesman.pid
mkdir -p /run/dbus /run/xrdp
dbus-daemon --system --fork

/usr/sbin/xrdp-sesman --nodaemon &
sesman_pid=$!
/usr/sbin/xrdp --nodaemon &
xrdp_pid=$!
/usr/bin/python3 /usr/local/lib/cifs-lab-server.py &
smb_pid=$!

mkdir -p /run/cifs-lab
printf '%s\n' "$sesman_pid" > /run/cifs-lab/sesman.pid
printf '%s\n' "$xrdp_pid" > /run/cifs-lab/xrdp.pid
printf '%s\n' "$smb_pid" > /run/cifs-lab/smb.pid

# Invoked indirectly by the trap below.
# shellcheck disable=SC2329
stop_all() {
    kill "$smb_pid" "$xrdp_pid" "$sesman_pid" 2>/dev/null || true
    wait "$smb_pid" "$xrdp_pid" "$sesman_pid" 2>/dev/null || true
}
trap stop_all INT TERM EXIT

while kill -0 "$smb_pid" "$xrdp_pid" "$sesman_pid" 2>/dev/null; do
    sleep 1
done
exit 1
