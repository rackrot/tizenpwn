#!/bin/sh
set -eu

for name in sesman xrdp smb; do
    pid=$(cat "/run/cifs-lab/$name.pid")
    kill -0 "$pid"
done
