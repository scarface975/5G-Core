#!/usr/bin/env bash
# Differential analysis of the BSF: Open5GS's BSF (the unmodified system binary, registered at Open5GS's NRF) and ours, side by side in a private network namespace, the
# same Nbsf_Management requests to both (tools/diff/bsf_diff.py). Needs the Open5GS binaries and our binaries installed (scripts/c_install.sh). Exit status 77 (skipped)
# when user and network namespaces or Open5GS are not available.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="${G5C_BIN_DIR:-$HOME/.cache/g5c-bin/bin}"
BSF_BIN="${BSF_BIN:-$BIN/bsf}"
if [ "${G5C_NETNS:-}" != 1 ]; then
  [ -x /usr/bin/open5gs-bsfd ] && [ -x /usr/bin/open5gs-nrfd ] || { echo "SKIP: no Open5GS BSF"; exit 77; }
  [ -x "$BSF_BIN" ] || { echo "SKIP: no BSF binary"; exit 77; }
  unshare -Urn true 2>/dev/null || { echo "SKIP: no user and network namespaces"; exit 77; }
  exec unshare -Urn env G5C_NETNS=1 bash "$0" "$@"
fi
ip link set lo up
T="$(mktemp -d /tmp/bsfdiff-XXXXXX)"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
cat > "$T/nrf.yaml" <<EOF
logger: { file: { path: $T/nrf.log } }
nrf:
  serving: [ { plmn_id: { mcc: 001, mnc: 01 } } ]
  sbi: { server: [ { address: 127.0.0.10, port: 7777 } ] }
EOF
cat > "$T/bsf.yaml" <<EOF
logger: { file: { path: $T/bsf.log } }
bsf:
  sbi:
    server: [ { address: 127.0.0.15, port: 7777 } ]
    client:
      nrf: [ { uri: http://127.0.0.10:7777 } ]
EOF
cat > "$T/ours.yaml" <<EOF
name: g5c-bsf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.0.0.31, port: 7777 }
bsf: {}
EOF
/usr/bin/open5gs-nrfd -c "$T/nrf.yaml" >"$T/nrf.out" 2>&1 & pids+=($!)
sleep 0.5
/usr/bin/open5gs-bsfd -c "$T/bsf.yaml" >"$T/bsf.out" 2>&1 & pids+=($!)
"$BSF_BIN" "$T/ours.yaml" >"$T/ours.out" 2>&1 & pids+=($!)
for _ in $(seq 1 60); do
  curl -s -o /dev/null --http2-prior-knowledge http://127.0.0.15:7777/nbsf-management/v1/x && curl -s -o /dev/null --http2-prior-knowledge http://127.0.0.31:7777/nbsf-management/v1/x && break
  sleep 0.2
done
python3 "$ROOT/tools/diff/bsf_diff.py" http://127.0.0.15:7777 http://127.0.0.31:7777
