#!/usr/bin/env bash
# Installs a built or packaged g5c release on a host (see docs/install.md).
#
#   deploy/install.sh [--bin DIR] [--prefix /usr/local] [--no-user]
#
#   --bin DIR    where the binaries are (default: ~/.cache/g5c-bin/bin, what scripts/c_install.sh makes; in a release archive: ./bin)
#   DESTDIR=...  install into a staging root instead of the host (what the tests do; no user is created, no service is touched)
#
# What it does: the functions into <prefix>/bin, the service units into /etc/systemd/system (or DESTDIR), the system user g5c, /etc/g5c (0750, keys/ 0700), /var/lib/g5c, a PKI under
# /etc/g5c/pki when none is there, example configurations into /etc/g5c/examples (never over a configuration that exists). Idempotent: run it again for an upgrade (see docs/upgrade.md).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="${G5C_BIN_DIR:-$HOME/.cache/g5c-bin/bin}"; PREFIX=/usr/local; MKUSER=1
while [ $# -gt 0 ]; do case "$1" in --bin) BIN="$2"; shift 2;; --prefix) PREFIX="$2"; shift 2;; --no-user) MKUSER=0; shift;; *) echo "unknown argument $1"; exit 2;; esac; done
D="${DESTDIR:-}"
[ -n "$D" ] && MKUSER=0
[ -d "$BIN" ] || { [ -d "$ROOT/bin" ] && BIN="$ROOT/bin"; }
[ -x "$BIN/amf" ] || { echo "no binaries in $BIN (build with scripts/c_install.sh, or unpack a release archive)"; exit 1; }
if [ -z "$D" ] && [ "$(id -u)" != 0 ]; then echo "run as root (sudo), or set DESTDIR for a staging install"; exit 1; fi

if [ "$MKUSER" = 1 ] && ! id g5c >/dev/null 2>&1; then useradd --system --no-create-home --home-dir /var/lib/g5c --shell /usr/sbin/nologin g5c; echo "user g5c created"; fi
install -d -m 0755 "$D$PREFIX/bin" "$D/etc/systemd/system/g5c@upf.service.d" "$D/usr/share/doc/g5c"
for f in "$BIN"/*; do install -m 0755 "$f" "$D$PREFIX/bin/$(basename "$f")"; done
install -m 0644 "$HERE/systemd/g5c@.service" "$HERE/systemd/g5c.target" "$D/etc/systemd/system/"
install -m 0644 "$HERE/systemd/g5c@upf.service.d/override.conf" "$D/etc/systemd/system/g5c@upf.service.d/override.conf"
install -d -m 0750 "$D/etc/g5c" "$D/etc/g5c/examples"; install -d -m 0700 "$D/etc/g5c/keys"; install -d -m 0750 "$D/var/lib/g5c"
for c in "$ROOT"/configs/*.yaml; do [ -f "$c" ] && install -m 0640 "$c" "$D/etc/g5c/examples/$(basename "$c")"; done
for d in install.md upgrade.md admin-guide.md ops/runbooks.md ops/slo.md api/README.md; do
  [ -f "$ROOT/docs/$d" ] && install -D -m 0644 "$ROOT/docs/$d" "$D/usr/share/doc/g5c/$d"
done
[ -f "$ROOT/VERSION" ] && install -m 0644 "$ROOT/VERSION" "$D/usr/share/doc/g5c/VERSION"
[ -f "$ROOT/NOTICE" ] && install -m 0644 "$ROOT/NOTICE" "$D/usr/share/doc/g5c/NOTICE"
if [ -z "$D" ]; then
  chown -R g5c:g5c /etc/g5c /var/lib/g5c 2>/dev/null || true
  if [ ! -f /etc/g5c/pki/ca.crt ]; then bash "$HERE/run/g5c-pki.sh" init /etc/g5c/pki && chown -R g5c:g5c /etc/g5c/pki && echo "PKI created in /etc/g5c/pki: issue a certificate per function with deploy/run/g5c-pki.sh issue"; fi
  systemctl daemon-reload 2>/dev/null || true
fi
echo "installed g5c $(cat "$ROOT/VERSION" 2>/dev/null) into ${D}${PREFIX}: functions in $PREFIX/bin, units g5c@<function>.service and g5c.target, configuration in /etc/g5c"
