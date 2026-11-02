#!/usr/bin/env bash
# with_pg.sh <test-executable> [args]: run a UDR test against a throw-away PostgreSQL server (G5C_UDR_TEST_PG).
# Exit status 77 (skipped) when no PostgreSQL server binaries are available.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d /tmp/g5c-pgtest-XXXXXX)"
cleanup() { bash "$here/../../../deploy/run/pg-temp.sh" drop "$tmp" >/dev/null 2>&1 || rm -rf "$tmp"; }
trap cleanup EXIT
conn="$(G5C_PG_PORT="${G5C_PG_PORT:-$((54000 + RANDOM % 1000))}" bash "$here/../../../deploy/run/pg-temp.sh" start "$tmp")"
rc=$?
[ $rc -eq 77 ] && exit 77
[ $rc -eq 0 ] || { echo "cannot start PostgreSQL" >&2; exit 1; }
G5C_UDR_TEST_PG="$conn" "$@"
