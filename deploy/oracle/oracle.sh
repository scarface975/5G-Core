#!/usr/bin/env bash
# Isolated Open5GS "oracle" core for behavioural comparison and interop (TEST ONLY, see ADR-0002).
#
# - Runs the UNMODIFIED system binaries (/usr/bin/open5gs-*d) as separate processes.
# - Fully isolated from any other Open5GS instance on the machine:
#     loopback 127.1.0.x (not 127.0.0.x), MongoDB database `g5c_oracle`, PLMN 001/01,
#     TUN device `ogstun5g` with 10.46.0.0/16, all files under $ORACLE_HOME.
# - Configs are GENERATED at run time from a template directory (nothing Open5GS-derived is
#   committed to this repo).
#
# Usage: deploy/oracle/oracle.sh {gen|up|down|status|provision|capture-start|capture-stop}
set -euo pipefail

ORACLE_HOME="${ORACLE_HOME:-$HOME/g5c-oracle}"
TEMPLATE_CONF="${O5GS_TEMPLATE_CONF:-$HOME/o5gs-run/conf}"
DB_NAME="${ORACLE_DB:-g5c_oracle}"
BIN_DIR="${O5GS_BIN_DIR:-/usr/bin}"
TUN_DEV="${ORACLE_TUN:-ogstun5g}"
# OUR_UDM=1 replaces Open5GS's UDM with OUR UDM (+ our UDR-lite), so Open5GS's AMF/AUSF/SMF/PCF are the
# interop peers of our implementation. Build and install first: scripts/c_install.sh
OUR_UDM="${OUR_UDM:-0}"
# OUR_PCF=1 replaces Open5GS's PCF with OUR PCF (it uses our UDR-lite for policy data).
# Build and install first: scripts/c_install.sh
OUR_PCF="${OUR_PCF:-0}"
# OUR_UPF=1 replaces Open5GS's UPF with OUR UPF (N4 on 127.1.0.7:8805, N3 on 127.1.0.7:2152, N6 on the TUN device), so Open5GS's SMF
# and UERANSIM are the interop peers of our user plane. Build and install first: scripts/c_install.sh
OUR_UPF="${OUR_UPF:-0}"
# OUR_SMF=1 replaces Open5GS's SMF with OUR SMF (SBI 127.1.0.4:7777, N4 127.1.0.4:8805): Open5GS's AMF and UERANSIM drive it, and it talks to our
# or Open5GS's UDM / PCF / UPF (OUR_UDM, OUR_PCF and OUR_UPF are recommended together with it).
OUR_SMF="${OUR_SMF:-0}"
# OUR_AMF=1 replaces Open5GS's AMF with OUR AMF (NGAP on 127.1.0.5:38412, SBI 127.1.0.5:7777): UERANSIM drives it, and it talks to Open5GS's AUSF, NRF and
# (with OUR_SMF / OUR_UDM / OUR_PCF) to our own NFs.
OUR_AMF="${OUR_AMF:-0}"
# OUR_NRF=1 replaces Open5GS's NRF with OUR NRF (SBI 127.1.0.10:7777): Open5GS's NFs register, heart-beat, subscribe and discover at it, and so do ours.
OUR_NRF="${OUR_NRF:-0}"
# OUR_AUSF=1 replaces Open5GS's AUSF with OUR AUSF (SBI 127.1.0.11:7777): Open5GS's AMF (or ours) finds it through the NRF, and it finds the UDM there too.
OUR_AUSF="${OUR_AUSF:-0}"
# OUR_NSSF=1 replaces Open5GS's NSSF with OUR NSSF (SBI 127.1.0.14:7777, registered at the NRF): Open5GS's AMF asks it for the network slice instance of a PDU
# session (Nnssf_NSSelection) and uses the NRF it names to find the SMF.
OUR_NSSF="${OUR_NSSF:-0}"
# OUR_NEF=1 starts OUR NEF (SBI 127.1.0.15:7784, registered at the NRF; Open5GS has none): scenario s6 drives its northbound APIs (traffic influence into our
# UDR, monitoring events from our AMF through our UDM) and needs OUR_UDR=1 OUR_UDM=1 OUR_AMF=1.
OUR_NEF="${OUR_NEF:-0}"
# OUR_SCP=1 starts OUR SCP (SBI 127.1.0.200:7777) and sends every function's requests to the other functions through it: Open5GS's (their `client.scp`) and ours (their
# `scp_client`); the NRF is reached directly. OUR_SCP_MODE=c: the functions discover at the NRF and name the producer in 3gpp-Sbi-Target-apiRoot (Open5GS: indirect
# communication without delegated discovery); OUR_SCP_MODE=d: Open5GS's functions delegate the discovery to the SCP (3gpp-Sbi-Discovery-* headers; ours stay on c);
# OUR_SCP_NFM=yes: Open5GS's functions also register through the SCP.
OUR_SCP="${OUR_SCP:-0}"
# OUR_BSF=1 replaces Open5GS's BSF with OUR BSF (SBI 127.1.0.17:7786, registered at the NRF): Open5GS's PCF (or ours) finds it there and registers the binding of every
# PDU session with a UE address, which scenario s8 looks for through the BSF's discovery while the session is up and after it was released.
OUR_BSF="${OUR_BSF:-0}"
# OUR_OAUTH2=1: every function of ours requires the access token of the NRF for its services and asks the NRF for one for the services it calls (TS 33.501 13.4.1). Open5GS's functions
# send and check none, so it needs the NRF and every function that talks to another over SBI ours: OUR_NRF OUR_UDR OUR_UDM OUR_AUSF OUR_PCF OUR_SMF OUR_AMF (the BSF, NSSF and NEF may be either).
OUR_OAUTH2="${OUR_OAUTH2:-0}"
if [ "$OUR_OAUTH2" = 1 ] && ! { [ "$OUR_NRF" = 1 ] && [ "$OUR_UDR" = 1 ] && [ "$OUR_UDM" = 1 ] && [ "$OUR_AUSF" = 1 ] && [ "$OUR_PCF" = 1 ] && [ "$OUR_SMF" = 1 ] && [ "$OUR_AMF" = 1 ]; }; then
  echo "OUR_OAUTH2=1 needs OUR_NRF OUR_UDR OUR_UDM OUR_AUSF OUR_PCF OUR_SMF OUR_AMF (Open5GS's functions send no access tokens)" >&2
  exit 1
fi
OUR_SCP_MODE="${OUR_SCP_MODE:-c}"
OUR_SCP_NFM="${OUR_SCP_NFM:-no}"
# OUR_UDR=1 replaces Open5GS's UDR with OUR UDR (SBI 127.1.0.201:7790, registered at the NRF): Open5GS's UDM, AUSF and PCF find it there and read and write
# the subscriber data through it, as they would through their own. Without OUR_UDM the subscriber is provisioned into our UDR in the document format
# Open5GS's UDR returns (plain K and OPc), by the provisioning extension of the API.
OUR_UDR="${OUR_UDR:-0}"
G5C_BIN_DIR="${G5C_BIN_DIR:-$HOME/.cache/g5c-bin/bin}"
# start order matters: NRF first, AMF last
NFS=(nrf ausf udr udm bsf pcf nssf smf upf amf)
[ "$OUR_NRF" = 1 ] && NFS=(${NFS[@]/nrf})
[ "$OUR_UDM" = 1 ] && NFS=(${NFS[@]/udm})
[ "$OUR_PCF" = 1 ] && NFS=(${NFS[@]/pcf})
[ "$OUR_UPF" = 1 ] && NFS=(${NFS[@]/upf})
[ "$OUR_SMF" = 1 ] && NFS=(${NFS[@]/smf})
[ "$OUR_AMF" = 1 ] && NFS=(${NFS[@]/amf})
[ "$OUR_AUSF" = 1 ] && NFS=(${NFS[@]/ausf})
[ "$OUR_NSSF" = 1 ] && NFS=(${NFS[@]/nssf})
[ "$OUR_UDR" = 1 ] && NFS=(${NFS[@]/udr})
[ "$OUR_BSF" = 1 ] && NFS=(${NFS[@]/bsf})
OURS=(g5nrf g5scp g5udr g5udm g5ausf g5nssf g5nef g5bsf g5pcf g5upf g5smf g5amf)
USE_OURS=0; { [ "$OUR_NRF" = 1 ] || [ "$OUR_AUSF" = 1 ] || [ "$OUR_UDM" = 1 ] || [ "$OUR_PCF" = 1 ] || [ "$OUR_UPF" = 1 ] || [ "$OUR_SMF" = 1 ] || [ "$OUR_AMF" = 1 ] || [ "$OUR_UDR" = 1 ] || [ "$OUR_NSSF" = 1 ] || [ "$OUR_NEF" = 1 ] || [ "$OUR_SCP" = 1 ] || [ "$OUR_BSF" = 1 ]; } && USE_OURS=1
mkdir -p "$ORACLE_HOME"/{conf,log,run,pcap}

gen() {
  [ -d "$TEMPLATE_CONF" ] || { echo "template conf dir not found: $TEMPLATE_CONF (set O5GS_TEMPLATE_CONF)"; exit 1; }
  for nf in "${NFS[@]}"; do
    [ -f "$TEMPLATE_CONF/$nf.yaml" ] || { echo "missing template $nf.yaml"; exit 1; }
    sed -E \
      -e 's/127\.0\.0\./127.1.0./g' \
      -e "s#mongodb://localhost/[A-Za-z0-9_]+#mongodb://localhost/$DB_NAME#" \
      -e 's/^( *)mcc: .*/\1mcc: 001/' \
      -e "s/^( *)mnc: .*/\1mnc: 01/" \
      -e "s#^( *)path: .*/([a-z0-9]+)\.log#\1path: $ORACLE_HOME/log/\2.log#" \
      -e 's#10\.45\.0\.#10.46.0.#g' \
      -e 's#10\.45\.0\.0/16#10.46.0.0/16#g' \
      -e '/freeDiameter:/d' \
      "$TEMPLATE_CONF/$nf.yaml" > "$ORACLE_HOME/conf/$nf.yaml"
  done
  if [ "$OUR_SCP" = 1 ]; then
    # Open5GS's functions: the SCP as the client of their SBI, delegated discovery (and registration) when asked for
    local disc=no; [ "$OUR_SCP_MODE" = d ] && disc=yes
    for nf in "${NFS[@]}"; do
      local f="$ORACLE_HOME/conf/$nf.yaml"
      grep -q "^      nrf:\$" "$f" || continue
      sed -i -E -e "s#^      nrf:\$#      scp:\n      - uri: http://127.1.0.200:7777\n      nrf:#" -e "s#^( +)disc: 'no'#\1disc: '$disc'#" -e "s#^( +)nfm: 'no'#\1nfm: '$OUR_SCP_NFM'#" "$f"
    done
  fi
  [ "$USE_OURS" = 1 ] && gen_ours
  scp_for_ours
  oauth2_for_ours
  # bind the UPF session pool to our own TUN device
  [ "$OUR_UPF" = 1 ] || sed -i -E "s#^( *)gateway: .*#&\n\1dev: $TUN_DEV#" "$ORACLE_HOME/conf/upf.yaml"
  echo "generated configs in $ORACLE_HOME/conf (PLMN 001/01, loopback 127.1.0.x, db $DB_NAME)"
}

# Configuration, secrets and keys for our own UDM + UDR (test keys only: the home network key is the public
# TS 33.501 Annex C.4.3 test key).
gen_ours() {
  mkdir -p "$ORACLE_HOME/keys"
  [ -f "$ORACLE_HOME/keys/admin_token" ] || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ORACLE_HOME/keys/admin_token"
  [ -f "$ORACLE_HOME/keys/master.key" ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ORACLE_HOME/keys/master.key"
  [ -f "$ORACLE_HOME/keys/udr-provisioning.token" ] || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ORACLE_HOME/keys/udr-provisioning.token"
  echo -n c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d > "$ORACLE_HOME/keys/hn-1.key"
  chmod 600 "$ORACLE_HOME"/keys/*
  cat > "$ORACLE_HOME/conf/g5c-nrf.yaml" <<EOF
name: g5c-nrf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.10, port: 7777 }
log: { level: debug }
registry:
  heartbeat_timer: 10
  state_file: $ORACLE_HOME/g5c-nrf.json
  oauth2: { enabled: true, key_file: $ORACLE_HOME/keys/nrf-oauth2.pem }
EOF
  rm -f "$ORACLE_HOME/g5c-nrf.json"
  cat > "$ORACLE_HOME/conf/g5c-udr.yaml" <<EOF
name: g5c-udr
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.201, port: 7790 }
log: { level: debug }
nrf: { uri: 'http://127.1.0.10:7777' }
store: { type: file, path: $ORACLE_HOME/g5c-udr.json }
provisioning: { token_file: $ORACLE_HOME/keys/udr-provisioning.token }
compat: { put_no_content: true }   # Open5GS's UDM (OUR_UDR=1) accepts only 204 for the PUTs it makes
EOF
  cat > "$ORACLE_HOME/conf/g5c-udm.yaml" <<EOF
name: g5c-udm
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.1, port: 7773 }
log: { level: debug }
nrf: { uri: 'http://127.1.0.10:7777' }
udr: { uri: 'http://127.1.0.201:7790', token_file: $ORACLE_HOME/keys/udr-provisioning.token }
hn_keys:
  - { id: 1, scheme: profile-a, private_key_file: $ORACLE_HOME/keys/hn-1.key }
master_key_file: $ORACLE_HOME/keys/master.key
admin_token_file: $ORACLE_HOME/keys/admin_token
EOF
  [ -f "$ORACLE_HOME/keys/ausf-master.key" ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ORACLE_HOME/keys/ausf-master.key"
  chmod 600 "$ORACLE_HOME"/keys/*
  rm -f "$ORACLE_HOME/g5c-ausf.json"
  cat > "$ORACLE_HOME/conf/g5c-ausf.yaml" <<EOF
name: g5c-ausf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.11, port: 7777 }
log: { level: debug }
nrf: { uri: 'http://127.1.0.10:7777' }
ausf:
  state_file: $ORACLE_HOME/g5c-ausf.json
  master_key_file: $ORACLE_HOME/keys/ausf-master.key
EOF
  rm -f "$ORACLE_HOME/g5c-nssf.json"
  cat > "$ORACLE_HOME/conf/g5c-nssf.yaml" <<EOF
name: g5c-nssf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.14, port: 7777 }
log: { level: debug }
nrf: { uri: 'http://127.1.0.10:7777' }
nssf:
  slices:
    - { snssai: { sst: 1 }, nrf: 'http://127.1.0.10:7777' }
  state_file: $ORACLE_HOME/g5c-nssf.json
EOF
  rm -f "$ORACLE_HOME/g5c-nef.json"
  NEF_PCF_LINE=""; [ -n "${NEF_PCF_URI:-}" ] && NEF_PCF_LINE="  pcf: { uri: '$NEF_PCF_URI' }"
  cat > "$ORACLE_HOME/conf/g5c-nef.yaml" <<EOF
name: g5c-nef
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.15, port: 7784 }
log: { level: debug }
nrf: { uri: 'http://127.1.0.10:7777' }
nef:
  afs:
    - { id: af-1, no_auth: true, any_notify_host: true }
  callback_uri: http://127.1.0.15:7784
  state_file: $ORACLE_HOME/g5c-nef.json
$NEF_PCF_LINE
EOF
  cat > "$ORACLE_HOME/conf/g5c-scp.yaml" <<EOF
name: g5c-scp
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.200, port: 7777 }
log: { level: debug }
nrf: { uri: 'http://127.1.0.10:7777' }
scp:
  routing: { timeout_ms: 8000, workers: 64 }
EOF
  cat > "$ORACLE_HOME/conf/g5c-bsf.yaml" <<EOF
name: g5c-bsf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.17, port: 7786 }
log: { level: debug }
nrf: { uri: 'http://127.1.0.10:7777' }
bsf: {}
EOF
  cat > "$ORACLE_HOME/conf/g5c-pcf.yaml" <<EOF
name: g5c-pcf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.13, port: 7777 }
log: { level: debug }
nrf: { uri: 'http://127.1.0.10:7777' }
udr: { uri: 'http://127.1.0.201:7790' }
admin_token_file: $ORACLE_HOME/keys/admin_token
policy:
  default: {}
  rfsp: 1
policy_authorization:
  qos_references:
    voice: { qi5: 1, gbr_ul: 128 Kbps, gbr_dl: 128 Kbps, mbr_ul: 256 Kbps, mbr_dl: 256 Kbps }
    streaming: { qi5: 7 }
EOF
  cat > "$ORACLE_HOME/conf/g5c-upf.yaml" <<EOF
name: g5c-upf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.7, port: 9091 }
log: { level: debug }
upf:
  pfcp: { address: 127.1.0.7, port: 8805 }
  gtpu: { address: 127.1.0.7, port: 2152 }
  n6: { device: $TUN_DEV }
EOF
  local udm_uri=http://127.1.0.12:7777
  [ "$OUR_UDM" = 1 ] && udm_uri=http://127.1.0.1:7773
  cat > "$ORACLE_HOME/conf/g5c-smf.yaml" <<EOF
name: g5c-smf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.4, port: 7777 }
log: { level: debug }
nrf: { uri: 'http://127.1.0.10:7777' }
smf:
  udm: { uri: '$udm_uri' }
  pcf: { uri: 'http://127.1.0.13:7777' }
  n4: { address: 127.1.0.4, port: 8805 }
  upfs:
    - { name: upf-1, address: 127.1.0.7, port: 8805, dnns: [internet] }
  dnns:
    - { name: internet, ipv4_pool: 10.46.0.0/16, dns: [8.8.8.8, 8.8.4.4] }
EOF
  cat > "$ORACLE_HOME/conf/g5c-amf.yaml" <<EOF
name: g5c-amf
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.1.0.5, port: 7777 }
log: { level: debug }
nrf: { uri: 'http://127.1.0.10:7777' }
amf:
  self_uri: 'http://127.1.0.5:7777'
  guami: { region: 2, set: 1, pointer: 0 }
  ngap: { address: 127.1.0.5, port: 38412 }
  tais: [ { tac: 1 } ]
  slices: [ { sst: 1 } ]
  default_dnn: internet
  network_name: { full: g5c, short: g5c }
EOF
  rm -f "$ORACLE_HOME/g5c-udr.json"   # every oracle run starts with an empty subscriber store
}

scp_for_ours() {
  [ "$OUR_SCP" = 1 ] || return 0
  for f in "$ORACLE_HOME"/conf/g5c-*.yaml; do
    case "$f" in *g5c-nrf.yaml|*g5c-scp.yaml) continue;; esac
    grep -q '^scp_client:' "$f" || sed -i "/^sbi:/a scp_client: { uri: 'http://127.1.0.200:7777' }" "$f"
  done
}

oauth2_for_ours() {
  [ "$OUR_OAUTH2" = 1 ] || return 0
  for f in "$ORACLE_HOME"/conf/g5c-*.yaml; do
    case "$f" in *g5c-nrf.yaml|*g5c-scp.yaml) continue;; esac
    grep -q '^nrf:' "$f" || continue
    grep -q '^oauth2:' "$f" || sed -i "/^sbi:/a oauth2: { enforce: true, acquire: true }" "$f"
  done
}

start_scp() {
  [ "$OUR_SCP" = 1 ] && [ ! -f "$ORACLE_HOME/run/g5scp.pid" ] || return 0
  [ -x "$G5C_BIN_DIR/scp" ] || { echo "missing $G5C_BIN_DIR/scp: run scripts/c_install.sh"; exit 1; }
  nohup "$G5C_BIN_DIR/scp" "$ORACLE_HOME/conf/g5c-scp.yaml" >"$ORACLE_HOME/log/g5scp.stdout" 2>&1 &
  echo $! > "$ORACLE_HOME/run/g5scp.pid"; sleep 0.5
}

start_ours() {
  if [ "$OUR_NRF" = 1 ] && [ ! -f "$ORACLE_HOME/run/g5nrf.pid" ]; then
    [ -x "$G5C_BIN_DIR/nrf" ] || { echo "missing $G5C_BIN_DIR/nrf: run scripts/c_install.sh"; exit 1; }
    nohup "$G5C_BIN_DIR/nrf" "$ORACLE_HOME/conf/g5c-nrf.yaml" >"$ORACLE_HOME/log/g5nrf.stdout" 2>&1 &
    echo $! > "$ORACLE_HOME/run/g5nrf.pid"; sleep 0.5
  fi
  if [ "$OUR_UPF" = 1 ]; then
    [ -x "$G5C_BIN_DIR/upf" ] || { echo "missing $G5C_BIN_DIR/upf: run scripts/c_install.sh"; exit 1; }
    nohup "$G5C_BIN_DIR/upf" "$ORACLE_HOME/conf/g5c-upf.yaml" >"$ORACLE_HOME/log/g5upf.stdout" 2>&1 &
    echo $! > "$ORACLE_HOME/run/g5upf.pid"; sleep 0.5
  fi
  [ -x "$G5C_BIN_DIR/udr" ] || { echo "missing $G5C_BIN_DIR/udr: run scripts/c_install.sh"; exit 1; }
  # our UDR is visible at the NRF only when it replaces Open5GS's (OUR_UDR=1); otherwise Open5GS's UDM would find this empty one
  sed -i "/^nrf:/d" "$ORACLE_HOME/conf/g5c-udr.yaml"
  [ "$OUR_UDR" = 1 ] && sed -i "/^sbi:/a nrf: { uri: 'http://127.1.0.10:7777' }" "$ORACLE_HOME/conf/g5c-udr.yaml"
  nohup "$G5C_BIN_DIR/udr" "$ORACLE_HOME/conf/g5c-udr.yaml" >"$ORACLE_HOME/log/g5udr.stdout" 2>&1 &
  echo $! > "$ORACLE_HOME/run/g5udr.pid"; sleep 0.5
  if [ "$OUR_UDM" = 1 ]; then
    nohup "$G5C_BIN_DIR/udm" "$ORACLE_HOME/conf/g5c-udm.yaml" >"$ORACLE_HOME/log/g5udm.stdout" 2>&1 &
    echo $! > "$ORACLE_HOME/run/g5udm.pid"; sleep 0.5
  fi
  if [ "$OUR_NSSF" = 1 ]; then
    [ -x "$G5C_BIN_DIR/nssf" ] || { echo "missing $G5C_BIN_DIR/nssf: run scripts/c_install.sh"; exit 1; }
    nohup "$G5C_BIN_DIR/nssf" "$ORACLE_HOME/conf/g5c-nssf.yaml" >"$ORACLE_HOME/log/g5nssf.stdout" 2>&1 &
    echo $! > "$ORACLE_HOME/run/g5nssf.pid"; sleep 0.5
  fi
  if [ "$OUR_NEF" = 1 ]; then
    [ -x "$G5C_BIN_DIR/nef" ] || { echo "missing $G5C_BIN_DIR/nef: run scripts/c_install.sh"; exit 1; }
    nohup "$G5C_BIN_DIR/nef" "$ORACLE_HOME/conf/g5c-nef.yaml" >"$ORACLE_HOME/log/g5nef.stdout" 2>&1 &
    echo $! > "$ORACLE_HOME/run/g5nef.pid"; sleep 0.5
  fi
  if [ "$OUR_BSF" = 1 ]; then
    [ -x "$G5C_BIN_DIR/bsf" ] || { echo "missing $G5C_BIN_DIR/bsf: run scripts/c_install.sh"; exit 1; }
    nohup "$G5C_BIN_DIR/bsf" "$ORACLE_HOME/conf/g5c-bsf.yaml" >"$ORACLE_HOME/log/g5bsf.stdout" 2>&1 &
    echo $! > "$ORACLE_HOME/run/g5bsf.pid"; sleep 0.5
  fi
  if [ "$OUR_AUSF" = 1 ]; then
    [ -x "$G5C_BIN_DIR/ausf" ] || { echo "missing $G5C_BIN_DIR/ausf: run scripts/c_install.sh"; exit 1; }
    nohup "$G5C_BIN_DIR/ausf" "$ORACLE_HOME/conf/g5c-ausf.yaml" >"$ORACLE_HOME/log/g5ausf.stdout" 2>&1 &
    echo $! > "$ORACLE_HOME/run/g5ausf.pid"; sleep 0.5
  fi
  if [ "$OUR_PCF" = 1 ]; then
    [ -x "$G5C_BIN_DIR/pcf" ] || { echo "missing $G5C_BIN_DIR/pcf: run scripts/c_install.sh"; exit 1; }
    nohup "$G5C_BIN_DIR/pcf" "$ORACLE_HOME/conf/g5c-pcf.yaml" >"$ORACLE_HOME/log/g5pcf.stdout" 2>&1 &
    echo $! > "$ORACLE_HOME/run/g5pcf.pid"; sleep 0.5
  fi
  if [ "$OUR_SMF" = 1 ]; then
    [ -x "$G5C_BIN_DIR/smf" ] || { echo "missing $G5C_BIN_DIR/smf: run scripts/c_install.sh"; exit 1; }
    nohup "$G5C_BIN_DIR/smf" "$ORACLE_HOME/conf/g5c-smf.yaml" >"$ORACLE_HOME/log/g5smf.stdout" 2>&1 &
    echo $! > "$ORACLE_HOME/run/g5smf.pid"; sleep 0.5
  fi
  if [ "$OUR_AMF" = 1 ]; then
    [ -x "$G5C_BIN_DIR/amf" ] || { echo "missing $G5C_BIN_DIR/amf: run scripts/c_install.sh"; exit 1; }
    nohup "$G5C_BIN_DIR/amf" "$ORACLE_HOME/conf/g5c-amf.yaml" >"$ORACLE_HOME/log/g5amf.stdout" 2>&1 &
    echo $! > "$ORACLE_HOME/run/g5amf.pid"; sleep 0.5
  fi
}

up() {
  [ -f "$ORACLE_HOME/conf/nrf.yaml" ] || gen
  pgrep -x mongod >/dev/null || { echo "mongod is not running"; exit 1; }
  local with_upf=1
  if ! ip link show "$TUN_DEV" >/dev/null 2>&1; then
    echo "NOTE: TUN device $TUN_DEV missing -> starting WITHOUT upf. One-time setup (needs sudo):"
    echo "  sudo ip tuntap add name $TUN_DEV mode tun user $USER && sudo ip addr add 10.46.0.1/16 dev $TUN_DEV && sudo ip link set $TUN_DEV up"
    with_upf=0
  fi
  if [ "$OUR_NRF" = 1 ]; then start_ours; start_scp; fi # our NRF (and the SCP that goes with it) has to be listening before any other function starts
  for nf in "${NFS[@]}"; do
    [ "$nf" = upf ] && [ $with_upf = 0 ] && continue
    if [ -f "$ORACLE_HOME/run/$nf.pid" ] && kill -0 "$(cat "$ORACLE_HOME/run/$nf.pid")" 2>/dev/null; then continue; fi
    nohup "$BIN_DIR/open5gs-${nf}d" -c "$ORACLE_HOME/conf/$nf.yaml" >"$ORACLE_HOME/log/$nf.stdout" 2>&1 &
    echo $! > "$ORACLE_HOME/run/$nf.pid"
    sleep 0.6
    if [ "$nf" = nrf ] && [ "$USE_OURS" = 1 ] && [ "$OUR_NRF" != 1 ]; then start_scp; start_ours; fi
  done
  status
}

down() {
  for nf in amf g5amf upf g5upf smf g5smf nssf pcf bsf g5bsf g5pcf g5ausf g5nssf g5nef g5udm g5udr udm udr ausf g5scp g5nrf nrf; do
    if [ -f "$ORACLE_HOME/run/$nf.pid" ]; then
      kill "$(cat "$ORACLE_HOME/run/$nf.pid")" 2>/dev/null || true
      rm -f "$ORACLE_HOME/run/$nf.pid"
    fi
  done
  echo "oracle stopped (only processes recorded in $ORACLE_HOME/run were signalled)"
}

status() {
  for nf in "${NFS[@]}" $([ "$USE_OURS" = 1 ] && echo "${OURS[@]}"); do
    if [ -f "$ORACLE_HOME/run/$nf.pid" ] && kill -0 "$(cat "$ORACLE_HOME/run/$nf.pid")" 2>/dev/null; then
      printf '%-5s up   pid %s\n' "$nf" "$(cat "$ORACLE_HOME/run/$nf.pid")"
    else
      printf '%-5s down\n' "$nf"
    fi
  done
  ss -lnH 2>/dev/null | grep -E '127\.1\.0\.5:38412' >/dev/null && echo "NGAP listening on 127.1.0.5:38412" || echo "NGAP not listening"
}

# provision <imsi> <k-hex> <opc-hex>   (defaults: TS 35.208 test set 1 key material)
provision() {
  local imsi="${1:-001010000000001}" k="${2:-465B5CE8B199B49FAA5F0A2EE238A6BC}" opc="${3:-E8ED289DEBA952E4283B54E88E6183CA}"
  mongosh --quiet "mongodb://localhost/$DB_NAME" --eval "
    db.subscribers.deleteOne({imsi:'$imsi'});
    db.subscribers.insertOne({
      schema_version: 1, imsi: '$imsi', msisdn: [], imeisv: null,
      mme_host: [], mme_realm: [], purge_flag: [], access_restriction_data: 32,
      subscriber_status: 0, operator_determined_barring: 0, network_access_mode: 0,
      subscribed_rau_tau_timer: 12,
      ambr: {downlink:{value:1,unit:3}, uplink:{value:1,unit:3}},
      security: {k:'$k', amf:'8000', op:null, opc:'$opc', sqn: NumberLong(0)},
      slice: [{sst:1, default_indicator:true, sd:'ffffff', session:[{
        name:'internet', type:3, qos:{index:9, arp:{priority_level:8, pre_emption_capability:1, pre_emption_vulnerability:1}},
        ambr:{downlink:{value:1,unit:3}, uplink:{value:1,unit:3}}, pcc_rule:[]}]}]
    });
    print('provisioned $imsi in $DB_NAME');"
  if [ "$OUR_UDR" = 1 ] && [ "$OUR_UDM" != 1 ]; then
    local utok base kl="${k,,}" opcl="${opc,,}"
    utok="$(cat "$ORACLE_HOME/keys/udr-provisioning.token")"
    base="http://127.1.0.201:7790/nudr-dr/v1/subscription-data/imsi-$imsi"
    uput() { curl -s --http2-prior-knowledge -o /dev/null -w "our UDR $1: HTTP %{http_code}\n" -X PUT -H "authorization: Bearer $utok" -H 'content-type: application/json' -d "$3" "$base/$2"; }
    uput auth authentication-data/authentication-subscription \
      "{\"authenticationMethod\":\"5G_AKA\",\"encPermanentKey\":\"$kl\",\"sequenceNumber\":{\"sqn\":\"000000000000\"},\"authenticationManagementField\":\"8000\",\"encOpcKey\":\"$opcl\"}"
    uput am 00101/provisioned-data/am-data \
      '{"subscribedUeAmbr":{"uplink":"1000000 Kbps","downlink":"1000000 Kbps"},"nssai":{"defaultSingleNssais":[{"sst":1}]}}'
    uput sm 00101/provisioned-data/sm-data \
      '[{"singleNssai":{"sst":1},"dnnConfigurations":{"internet":{"pduSessionTypes":{"defaultSessionType":"IPV4V6","allowedSessionTypes":["IPV4","IPV6","IPV4V6"]},"sscModes":{"defaultSscMode":"SSC_MODE_1","allowedSscModes":["SSC_MODE_2","SSC_MODE_3"]},"5gQosProfile":{"5qi":9,"arp":{"priorityLevel":8,"preemptCap":"NOT_PREEMPT","preemptVuln":"NOT_PREEMPTABLE"},"priorityLevel":8},"sessionAmbr":{"uplink":"1000000 Kbps","downlink":"1000000 Kbps"}}}}]'
    # the policy data Open5GS's PCF reads: the UDR it was written for derives these from the subscriber
    curl -s --http2-prior-knowledge -o /dev/null -w "our UDR policy am-data: HTTP %{http_code}\n" -X PUT -H "authorization: Bearer $utok" -H 'content-type: application/json' -d '{}' \
      "http://127.1.0.201:7790/nudr-dr/v1/policy-data/ues/imsi-$imsi/am-data"
    curl -s --http2-prior-knowledge -o /dev/null -w "our UDR policy sm-data: HTTP %{http_code}\n" -X PUT -H "authorization: Bearer $utok" -H 'content-type: application/json' \
      -d '{"smPolicySnssaiData":{"1":{"snssai":{"sst":1},"smPolicyDnnData":{"internet":{"dnn":"internet"}}}}}' \
      "http://127.1.0.201:7790/nudr-dr/v1/policy-data/ues/imsi-$imsi/sm-data"
    uput smf-selection 00101/provisioned-data/smf-selection-subscription-data \
      '{"subscribedSnssaiInfos":{"1":{"dnnInfos":[{"dnn":"internet","defaultDnnIndicator":true}]}}}'
  fi
  if [ "$OUR_UDM" = 1 ]; then
    local tok; tok="$(cat "$ORACLE_HOME/keys/admin_token")"
    curl -s --http2-prior-knowledge -o /dev/null -w "our UDM provisioning $imsi: HTTP %{http_code}\n" \
      -H "authorization: Bearer $tok" -H 'content-type: application/json' \
      -d "{\"supi\":\"imsi-$imsi\",\"k\":\"$k\",\"opc\":\"$opc\"${AUTH_METHOD:+,\"auth_method\":\"$AUTH_METHOD\"}}" http://127.1.0.1:7773/admin/v1/subscribers
  fi
}

capture_start() {
  local f="$ORACLE_HOME/pcap/${1:-capture}-$(date +%Y%m%d-%H%M%S).pcapng"
  nohup dumpcap -q -i lo -f 'net 127.1.0.0/24 and (sctp or udp port 8805 or udp port 2152 or tcp port 7777)' -w "$f" >/dev/null 2>&1 &
  echo $! > "$ORACLE_HOME/run/capture.pid"; echo "capturing to $f"
}
capture_stop() { [ -f "$ORACLE_HOME/run/capture.pid" ] && kill "$(cat "$ORACLE_HOME/run/capture.pid")" 2>/dev/null; rm -f "$ORACLE_HOME/run/capture.pid"; echo stopped; }

case "${1:-}" in
  gen) gen;; up) up;; down) down;; status) status;;
  provision) shift; provision "$@";;
  capture-start) shift; capture_start "$@";; capture-stop) capture_stop;;
  *) sed -n '2,12p' "$0"; exit 1;;
esac
