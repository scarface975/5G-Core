#!/bin/sh
# Generates throw-away development secrets into ./secrets (git-ignored). Never use these outside a lab.
set -eu
d="$(dirname "$0")/secrets"; mkdir -p "$d"; umask 077
rnd() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
[ -f "$d/udm-master.key" ] || rnd 32 > "$d/udm-master.key"
[ -f "$d/hn-1.key" ]       || rnd 32 > "$d/hn-1.key"
[ -f "$d/admin.token" ]    || rnd 24 > "$d/admin.token"
[ -f "$d/udr-provisioning.token" ] || rnd 24 > "$d/udr-provisioning.token"
chmod 644 "$d"/*   # read by the unprivileged container user; the directory itself stays private to you
echo "secrets written to $d"
