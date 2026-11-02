#!/usr/bin/env bash
# Differential analysis of the SCP: Open5GS's SCP (the unmodified system binary, with Open5GS's NRF) and ours, side by side in a private network namespace in front of
# the same NRF and the same producer (our NSSF, registered at the NRF), the same requests to both (tools/scp_diff.py). Needs the Open5GS binaries and our binaries
# installed (scripts/c_install.sh). Exit status 77 (skipped) when user and network namespaces or Open5GS are not available.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="${G5C_BIN_DIR:-$HOME/.cache/g5c-bin/bin}"
SCP_BIN="${SCP_BIN:-$BIN/scp}"
NSSF_BIN="${NSSF_BIN:-$BIN/nssf}"
if [ "${G5C_NETNS:-}" != 1 ]; then
  [ -x /usr/bin/open5gs-scpd ] && [ -x /usr/bin/open5gs-nrfd ] || { echo "SKIP: no Open5GS SCP"; exit 77; }
  [ -x "$NSSF_BIN" ] || { echo "SKIP: no NSSF binary"; exit 77; }
  unshare -Urn true 2>/dev/null || { echo "SKIP: no user and network namespaces"; exit 77; }
  exec unshare -Urn env G5C_NETNS=1 bash "$0" "$@"
fi
ip link set lo up
T="$(mktemp -d /tmp/scpdiff-XXXXXX)"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
cat > "$T/nrf.yaml" <<EOF
logger: { file: { path: $T/nrf.log } }
nrf:
  serving: [ { plmn_id: { mcc: 001, mnc: 01 } } ]
  sbi: { server: [ { address: 127.0.0.10, port: 7777 } ] }
EOF
cat > "$T/o5gs-scp.yaml" <<EOF
logger: { file: { path: $T/scp.log } }
scp:
  sbi:
    server: [ { address: 127.0.0.200, port: 7777 } ]
    client:
      nrf: [ { uri: http://127.0.0.10:7777 } ]
EOF
cat > "$T/our-scp.yaml" <<EOF
name: g5c-scp
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.0.0.201, port: 7777 }
nrf: { uri: 'http://127.0.0.10:7777' }
scp: {}
EOF
cat > "$T/nssf.yaml" <<EOF
name: g5c-nssf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.0.0.30, port: 7777 }
nrf: { uri: 'http://127.0.0.10:7777' }
nssf:
  slices:
    - { snssai: { sst: 1 }, nrf: 'http://127.0.0.10:7777' }
EOF
/usr/bin/open5gs-nrfd -c "$T/nrf.yaml" >"$T/nrf.out" 2>&1 & pids+=($!)
sleep 0.5
/usr/bin/open5gs-scpd -c "$T/o5gs-scp.yaml" >"$T/o5gs-scp.out" 2>&1 & pids+=($!)
"$SCP_BIN" "$T/our-scp.yaml" >"$T/our-scp.out" 2>&1 & pids+=($!)
"$NSSF_BIN" "$T/nssf.yaml" >"$T/nssf.out" 2>&1 & pids+=($!)
for _ in $(seq 1 60); do
  curl -s -o /dev/null --http2-prior-knowledge http://127.0.0.200:7777/x && curl -s -o /dev/null --http2-prior-knowledge http://127.0.0.201:7777/x && curl -s -o /dev/null --http2-prior-knowledge http://127.0.0.30:7777/x && break
  sleep 0.2
done
sleep 1 # the NSSF registers at the NRF
PID="$(curl -s --http2-prior-knowledge 'http://127.0.0.10:7777/nnrf-disc/v1/nf-instances?target-nf-type=NSSF&requester-nf-type=AMF' | python3 -c 'import json,sys; print(json.load(sys.stdin)["nfInstances"][0]["nfInstanceId"])')"
python3 "$ROOT/tools/scp_diff.py" http://127.0.0.200:7777 http://127.0.0.201:7777 http://127.0.0.30:7777 "$PID"
