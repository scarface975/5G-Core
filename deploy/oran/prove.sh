#!/usr/bin/env bash
# The ORAN emulator (its N2 stack as gNB and UE) against this core, end to end, in a private user + network namespace (no sudo):
#   ORAN_EMULATOR=/path/to/ORAN_emulator/oran deploy/oran/prove.sh [ues]
# The emulator's drivers are used exactly as they are (their defaults: AMF 127.0.0.5:38412, PLMN 999/70, TAC 1, SST 1, IMSI 999700000000001, ICMP echo to 10.45.0.1); the core is configured
# to match them, never the other way round. The report is written to $G5C_RUN/oran-proof/report.txt, the drivers' own output next to it, and the GTP-U frame as a pcap.
# Exit 0 = PASS, 1 = a check failed, 77 = the emulator or its N2 drivers are not there.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export ORAN_EMULATOR="${ORAN_EMULATOR:-/mnt/c/Users/Work/Documents/ORAN_emulator/oran}"
[ -d "$ORAN_EMULATOR/build-n2" ] || { echo "SKIP: $ORAN_EMULATOR/build-n2 is not there (build the emulator's N2 drivers: make -f tools/Makefile.n2)"; exit 77; }
export PROVE_UES="${1:-${PROVE_UES:-16}}"
export G5C_MCC=999 G5C_MNC=70 G5C_AMF_ADDR=127.0.0.5 G5C_TAC=1 G5C_TLS="${G5C_TLS:-0}" G5C_OAUTH2="${G5C_OAUTH2:-1}" G5C_RUN="${G5C_RUN:-$HOME/g5c-oran-run}"
[ -d "$HOME/g5c-cbuild/plain/nf" ] && export G5C_BUILD_DIR="${G5C_BUILD_DIR:-$HOME/g5c-cbuild/plain}"
exec bash "$ROOT/deploy/run/g5c-cluster.sh" ns exec bash "$HERE/inside.sh"
