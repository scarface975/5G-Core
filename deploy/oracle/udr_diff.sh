#!/usr/bin/env bash
# Differential analysis of the UDR: Open5GS's UDR (the unmodified system binary, over a private MongoDB) and ours, side by side in a private network
# namespace, the same requests to both (tools/diff/udr_diff.py). Needs the Open5GS binaries and mongod, and our binaries installed (scripts/c_install.sh).
# Exit status 77 (skipped) when user and network namespaces, Open5GS or mongod are not available.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="${G5C_BIN_DIR:-$HOME/.cache/g5c-bin/bin}"
UDR_BIN="${UDR_BIN:-$BIN/udr}"
if [ "${G5C_NETNS:-}" != 1 ]; then
  [ -x /usr/bin/open5gs-udrd ] && [ -x /usr/bin/open5gs-nrfd ] && command -v mongod >/dev/null && command -v mongosh >/dev/null || { echo "SKIP: no Open5GS UDR / mongod"; exit 77; }
  unshare -Urn true 2>/dev/null || { echo "SKIP: no user and network namespaces"; exit 77; }
  exec unshare -Urn env G5C_NETNS=1 bash "$0" "$@"
fi
ip link set lo up
T="$(mktemp -d /tmp/udrdiff-XXXXXX)"
mkdir -p "$T/db"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; mongod --dbpath "$T/db" --shutdown >/dev/null 2>&1 || true; rm -rf "$T"; }
trap cleanup EXIT
mongod --dbpath "$T/db" --bind_ip 127.0.0.1 --port 27017 --nounixsocket --fork --logpath "$T/mongod.log" >/dev/null
cat > "$T/nrf.yaml" <<EOF
logger: { file: { path: $T/nrf.log } }
nrf:
  serving: [ { plmn_id: { mcc: 001, mnc: 01 } } ]
  sbi: { server: [ { address: 127.0.0.10, port: 7777 } ] }
EOF
cat > "$T/udr.yaml" <<EOF
db_uri: mongodb://127.0.0.1/open5gs_diff
logger: { file: { path: $T/udr.log } }
udr:
  sbi:
    server: [ { address: 127.0.0.20, port: 7777 } ]
    client: { nrf: [ { uri: http://127.0.0.10:7777 } ] }
EOF
echo -n "provisioning-token-0123456789" > "$T/token"
cat > "$T/ours.yaml" <<EOF
name: g5c-udr
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.0.0.30, port: 7777 }
store: { type: memory }
provisioning: { token_file: $T/token }
log: { level: info }
EOF
/usr/bin/open5gs-nrfd -c "$T/nrf.yaml" >"$T/nrf.out" 2>&1 & pids+=($!)
sleep 0.5
/usr/bin/open5gs-udrd -c "$T/udr.yaml" >"$T/udr.out" 2>&1 & pids+=($!)
"$UDR_BIN" "$T/ours.yaml" >"$T/ours.out" 2>&1 & pids+=($!)
for _ in $(seq 1 60); do
  curl -s -o /dev/null --http2-prior-knowledge http://127.0.0.20:7777/nudr-dr/v1/x && curl -s -o /dev/null --http2-prior-knowledge http://127.0.0.30:7777/nudr-dr/v1/x && break
  sleep 0.2
done
mongosh --quiet mongodb://127.0.0.1/open5gs_diff --eval "
db.subscribers.insertOne({
  schema_version: 1, imsi: '001010000000001', msisdn: ['12025550100'], imeisv: null,
  mme_host: [], mme_realm: [], purge_flag: [], access_restriction_data: 32,
  subscriber_status: 0, operator_determined_barring: 0, network_access_mode: 0, subscribed_rau_tau_timer: 12,
  ambr: {downlink:{value:1,unit:3}, uplink:{value:1,unit:3}},
  security: {k:'465B5CE8B199B49FAA5F0A2EE238A6BC', amf:'8000', op:null, opc:'E8ED289DEBA952E4283B54E88E6183CA', sqn: NumberLong('0')},
  slice: [{sst:1, default_indicator:true, sd:'ffffff', session:[{
    name:'internet', type:3, qos:{index:9, arp:{priority_level:8, pre_emption_capability:1, pre_emption_vulnerability:1}},
    ambr:{downlink:{value:1,unit:3}, uplink:{value:1,unit:3}}, pcc_rule:[]}]}]
});" >/dev/null
python3 "$ROOT/tools/diff/udr_diff.py" http://127.0.0.20:7777 http://127.0.0.30:7777 "$(cat "$T/token")"
