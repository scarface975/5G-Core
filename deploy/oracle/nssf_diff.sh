#!/usr/bin/env bash
# Differential analysis of the NSSF: Open5GS's NSSF (the unmodified system binary, behind Open5GS's NRF) and ours, side by side in a private network namespace,
# configured with the same slices, the same Nnssf_NSSelection requests to both (tools/diff/nssf_diff.py). Needs the Open5GS binaries and our binaries installed
# (scripts/c_install.sh). Exit status 77 (skipped) when user and network namespaces or Open5GS are not available.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="${G5C_BIN_DIR:-$HOME/.cache/g5c-bin/bin}"
NSSF_BIN="${NSSF_BIN:-$BIN/nssf}"
if [ "${G5C_NETNS:-}" != 1 ]; then
  [ -x /usr/bin/open5gs-nssfd ] && [ -x /usr/bin/open5gs-nrfd ] || { echo "SKIP: no Open5GS NSSF"; exit 77; }
  unshare -Urn true 2>/dev/null || { echo "SKIP: no user and network namespaces"; exit 77; }
  exec unshare -Urn env G5C_NETNS=1 bash "$0" "$@"
fi
ip link set lo up
T="$(mktemp -d /tmp/nssfdiff-XXXXXX)"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
cat > "$T/nrf.yaml" <<EOF
logger: { file: { path: $T/nrf.log } }
nrf:
  serving: [ { plmn_id: { mcc: 001, mnc: 01 } } ]
  sbi: { server: [ { address: 127.0.0.10, port: 7777 } ] }
EOF
cat > "$T/nssf.yaml" <<EOF
logger: { file: { path: $T/nssf.log } }
nssf:
  sbi:
    server: [ { address: 127.0.0.14, port: 7777 } ]
    client:
      nrf: [ { uri: http://127.0.0.10:7777 } ]
      nsi:
        - { uri: http://127.0.0.10:7777, s_nssai: { sst: 1 } }
        - { uri: http://127.0.0.11:7777, s_nssai: { sst: 2, sd: 000001 } }
EOF
cat > "$T/ours.yaml" <<EOF
name: g5c-nssf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.0.0.30, port: 7777 }
nssf:
  slices:
    - { snssai: { sst: 1 }, nrf: 'http://127.0.0.10:7777' }
    - { snssai: { sst: 2, sd: '000001' }, nrf: 'http://127.0.0.11:7777' }
EOF
/usr/bin/open5gs-nrfd -c "$T/nrf.yaml" >"$T/nrf.out" 2>&1 & pids+=($!)
sleep 0.5
/usr/bin/open5gs-nssfd -c "$T/nssf.yaml" >"$T/nssf.out" 2>&1 & pids+=($!)
"$NSSF_BIN" "$T/ours.yaml" >"$T/ours.out" 2>&1 & pids+=($!)
for _ in $(seq 1 60); do
  curl -s -o /dev/null --http2-prior-knowledge http://127.0.0.14:7777/nnssf-nsselection/v2/x && curl -s -o /dev/null --http2-prior-knowledge http://127.0.0.30:7777/nnssf-nsselection/v2/x && break
  sleep 0.2
done
python3 "$ROOT/tools/diff/nssf_diff.py" http://127.0.0.14:7777 http://127.0.0.30:7777
