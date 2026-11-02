#!/usr/bin/env bash
# Copy the newest oracle capture of a scenario into tests/fixtures/golden under a descriptive name. Run inside WSL.
# usage: scripts/save_golden.sh <scenario: s1|s2|s3|s4> <target-file-name>
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
src="$(ls -t "${ORACLE_HOME:-$HOME/g5c-oracle}/pcap/$1-"*.pcapng | head -1)"
cp "$src" "$here/tests/fixtures/golden/$2"
echo "saved $src -> tests/fixtures/golden/$2 ($(stat -c %s "$here/tests/fixtures/golden/$2") bytes)"
