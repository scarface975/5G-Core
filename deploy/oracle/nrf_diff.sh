#!/usr/bin/env bash
# Differential analysis of the NRF: Open5GS's NRF (the unmodified system binary) and ours started side by side in a private network namespace, the same
# requests to both (tools/diff/nrf_diff.py). Needs the oracle templates (deploy/oracle/oracle.sh gen) and our nrf installed (scripts/c_install.sh).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ORACLE_HOME="${ORACLE_HOME:-$HOME/g5c-oracle}"
NRF_BIN="${NRF_BIN:-${G5C_BIN_DIR:-$HOME/.cache/g5c-bin/bin}/nrf}"
if [ "${G5C_NETNS:-}" != 1 ]; then
  unshare -Urn true 2>/dev/null || { echo "SKIP: no user and network namespaces"; exit 77; }
  exec unshare -Urn env G5C_NETNS=1 bash "$0" "$@"
fi
ip link set lo up
mkdir -p "$ORACLE_HOME"/{conf,log,run,keys}
[ -f "$ORACLE_HOME/conf/nrf.yaml" ] || "$HERE/oracle.sh" gen >/dev/null
cat > "$ORACLE_HOME/conf/g5c-nrf-diff.yaml" <<EOF
name: g5c-nrf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.110, port: 7777 }
log: { level: info }
registry:
  heartbeat_timer: 10
  oauth2: { enabled: true }
EOF
/usr/bin/open5gs-nrfd -c "$ORACLE_HOME/conf/nrf.yaml" >"$ORACLE_HOME/log/diff-o5gs-nrf.stdout" 2>&1 &
O5=$!
"$NRF_BIN" "$ORACLE_HOME/conf/g5c-nrf-diff.yaml" >"$ORACLE_HOME/log/diff-g5c-nrf.stdout" 2>&1 &
G5=$!
trap 'kill $O5 $G5 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  curl -s -o /dev/null --http2-prior-knowledge http://127.1.0.10:7777/nnrf-nfm/v1/nf-instances && curl -s -o /dev/null --http2-prior-knowledge http://127.1.0.110:7777/nnrf-nfm/v1/nf-instances && break
  sleep 0.2
done
python3 "$ROOT/tools/diff/nrf_diff.py" http://127.1.0.10:7777 http://127.1.0.110:7777
