#!/usr/bin/env bash
# Build the C tree and run the payload dumper into $1 (default build/payloads). Run inside WSL/Linux.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
out="${G5C_C_BUILD:-$HOME/g5c-cbuild}/plain"
dir="${1:-$here/build/payloads}"
cmake -S "$here" -B "$out" -DG5C_SANITIZE=OFF >/dev/null
cmake --build "$out" -j"$(nproc)" --target dump_payloads >/dev/null
mkdir -p "$dir"
G5C_PAYLOAD_DIR="$dir" "$out/tests/conformance/dump_payloads"
