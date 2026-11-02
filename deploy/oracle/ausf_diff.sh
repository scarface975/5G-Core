#!/usr/bin/env bash
# Differential analysis of the AUSF: Open5GS's AUSF (the unmodified system binary) and ours, side by side in a private network namespace behind the same UDM
# (ours, with our UDR-lite; Open5GS's AUSF finds the UDM at Open5GS's NRF), the same requests to both (tools/diff/ausf_diff.py).
# Needs the oracle templates (deploy/oracle/oracle.sh gen) and our binaries installed (scripts/c_install.sh).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ORACLE_HOME="${ORACLE_HOME:-$HOME/g5c-oracle}"
BIN="${G5C_BIN_DIR:-$HOME/.cache/g5c-bin/bin}"
AUSF_BIN="${AUSF_BIN:-$BIN/ausf}"
if [ "${G5C_NETNS:-}" != 1 ]; then
  unshare -Urn true 2>/dev/null || { echo "SKIP: no user and network namespaces"; exit 77; }
  exec unshare -Urn env G5C_NETNS=1 bash "$0" "$@"
fi
ip link set lo up
mkdir -p "$ORACLE_HOME"/{conf,log,run,keys}
# always generated here: a configuration left by an earlier scenario may enforce access tokens (OUR_OAUTH2=1), which the AUSF of Open5GS does not send
OUR_UDM=1 OUR_OAUTH2=0 "$HERE/oracle.sh" gen >/dev/null
rm -f "$ORACLE_HOME/g5c-udr.json"
cat > "$ORACLE_HOME/conf/g5c-ausf-diff.yaml" <<EOF
name: g5c-ausf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.111, port: 7777 }
log: { level: info }
nrf: { uri: 'http://127.1.0.10:7777' }
EOF
pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT
/usr/bin/open5gs-nrfd -c "$ORACLE_HOME/conf/nrf.yaml" >"$ORACLE_HOME/log/diff-o5gs-nrf.stdout" 2>&1 & pids+=($!)
sleep 0.5
"$BIN/udr" "$ORACLE_HOME/conf/g5c-udr.yaml" >"$ORACLE_HOME/log/diff-g5udr.stdout" 2>&1 & pids+=($!)
sleep 0.4
"$BIN/udm" "$ORACLE_HOME/conf/g5c-udm.yaml" >"$ORACLE_HOME/log/diff-g5udm.stdout" 2>&1 & pids+=($!)
sleep 0.5
/usr/bin/open5gs-ausfd -c "$ORACLE_HOME/conf/ausf.yaml" >"$ORACLE_HOME/log/diff-o5gs-ausf.stdout" 2>&1 & pids+=($!)
"$AUSF_BIN" "$ORACLE_HOME/conf/g5c-ausf-diff.yaml" >"$ORACLE_HOME/log/diff-g5c-ausf.stdout" 2>&1 & pids+=($!)
REF=$(sed -n '/ausf:/,$p' "$ORACLE_HOME/conf/ausf.yaml" | awk '/address:/{a=$NF} /port:/{p=$NF; print "http://" a ":" p; exit}')
for _ in $(seq 1 60); do
  curl -s -o /dev/null --http2-prior-knowledge "$REF/nausf-auth/v1/x" && curl -s -o /dev/null --http2-prior-knowledge http://127.1.0.111:7777/nausf-auth/v1/x && break
  sleep 0.2
done
sleep 1.5 # the UDM's registration at the NRF, and the AUSFs' discovery of it
tok="$(cat "$ORACLE_HOME/keys/admin_token")"
curl -s --http2-prior-knowledge -o /dev/null -w "provisioned: HTTP %{http_code}\n" -H "authorization: Bearer $tok" -H 'content-type: application/json' \
  -d '{"supi":"imsi-001010000000001","k":"465b5ce8b199b49faa5f0a2ee238a6bc","opc":"e8ed289deba952e4283b54e88e6183ca"}' http://127.1.0.1:7773/admin/v1/subscribers
python3 "$ROOT/tools/diff/ausf_diff.py" "$REF" http://127.1.0.111:7777
