#!/usr/bin/env bash
# Run our network functions as real processes, the way an operator would: one daemon per NF, one config file and one log file each.
#
#   g5c-cluster.sh up              generate the configs and start every NF (background; logs in $RUN/log)
#   g5c-cluster.sh down            stop them
#   g5c-cluster.sh status          which NFs run, their RSS and descriptors, and the gauges that matter
#   g5c-cluster.sh logs [nf]       follow the logs (all NFs, or one)
#   g5c-cluster.sh run <nf>        run ONE NF in the foreground with its log on the terminal (one terminal per NF, as with open5gs-amfd)
#   g5c-cluster.sh restart <nf>    stop and start one NF (state files and the UDR store survive)
#   g5c-cluster.sh kill <nf>       kill -9 one NF (failure injection); `start <nf>` brings it back
#   g5c-cluster.sh conf            only generate the configs (then start the NFs by hand with `run`)
#   g5c-cluster.sh rss             one line per NF: RSS in kB (used by the load runs)
#   g5c-cluster.sh certs [status|renew]   with G5C_TLS=1: certificate expiry; new certificates for every function and SIGHUP (no restart)
#
# Test modes that need no privileges (a user + network namespace with its own loopback and TUN device; nothing leaves the process tree):
#   g5c-cluster.sh ns load <ues> [gnbs] [waves]     bring the cluster up, drive it with the load generator in remote mode, bring it down
#   g5c-cluster.sh ns chaos <ues> <seconds>         the same load while NFs are killed and restarted, then a clean wave that must pass
#   g5c-cluster.sh ns soak <ues> <seconds> [gnbs]   waves of register / session / de-register for a fixed time; RSS of every NF must stay flat
#   g5c-cluster.sh ns tls                            mutual TLS: refusals, service with the right certificate, rotation by SIGHUP without a restart (G5C_TLS=1)
#   g5c-cluster.sh ns secrets                        no key, token or credential in a log, a configuration or (K, OPc) in the clear in a state file
#   g5c-cluster.sh ns ops                            log level at run time, master key rotation, exec: key source, charging records (G5C_OAUTH2=0)
#   g5c-cluster.sh ns slices                         the NSSF's slice decisions (registration, PDU session) and the AMF consuming both (G5C_OAUTH2=0)
#   g5c-cluster.sh ns upgrade <ues> <seconds>        every function restarted gracefully one at a time under load (upgrade), then with the previous binaries (rollback); a clean wave must pass
#   g5c-cluster.sh ns support                        the diagnostics bundle (tools/cli/g5c-diag) holds logs, metrics, versions and no subscriber, key or token
#   g5c-cluster.sh ns shell                          a shell inside the namespace with the cluster up (inspect, curl, tcpdump)
#
# Addresses are 127.2.0.x so that the cluster can sit next to the Open5GS oracle (127.1.0.x) and to a real RAN on 127.0.0.x or a LAN address (set
# G5C_AMF_ADDR / G5C_UPF_ADDR to the host address the gNB can reach, and G5C_N6_DEV to an existing TUN device).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RUN="${G5C_RUN:-$HOME/g5c-run}"
BIN="${G5C_BIN_DIR:-$HOME/.cache/g5c-bin/bin}"
LOAD="${G5C_LOAD_BIN:-$HOME/g5c-cbuild/plain/nf/amf/load_core}"
LOGJSON="${G5C_LOG_JSON:-false}"
LOGLEVEL="${G5C_LOG_LEVEL:-info}"
N6_DEV="${G5C_N6_DEV:-ogstun}"
UE_POOL="${G5C_UE_POOL:-10.45.0.0/16}"
# the tracking area codes the AMF serves (comma separated; the gNB's TAC has to be one of them) and, when set, the NAS ciphering algorithms it may choose (e.g. NEA0)
TAIS="$(printf '%s' "${G5C_TAC:-1,2}" | sed -E 's/([0-9]+)/{ tac: \1 }/g; s/ *, */, /g')"
AMF_SEC=""; [ -n "${G5C_AMF_CIPHERING:-}" ] && AMF_SEC="  security: { integrity: [ NIA2 ], ciphering: [ ${G5C_AMF_CIPHERING} ] }"
TOKEN="admin-token-0123456789"     # the load generator's provisioning token; replace for anything but a test cluster

A_UDR="${G5C_UDR_ADDR:-127.2.0.201}"; A_UDM="${G5C_UDM_ADDR:-127.2.0.1}"; A_AUSF="${G5C_AUSF_ADDR:-127.2.0.2}"; A_NSSF="${G5C_NSSF_ADDR:-127.2.0.14}"; A_NEF="${G5C_NEF_ADDR:-127.2.0.15}"; A_SCP="${G5C_SCP_ADDR:-127.2.0.16}"; A_BSF="${G5C_BSF_ADDR:-127.2.0.17}"; A_CHF="${G5C_CHF_ADDR:-127.2.0.18}"
A_PCF="${G5C_PCF_ADDR:-127.2.0.3}";   A_SMF="${G5C_SMF_ADDR:-127.2.0.4}"; A_AMF="${G5C_AMF_ADDR:-127.2.0.5}"
A_UPF="${G5C_UPF_ADDR:-127.2.0.7}"
A_NRF="${G5C_NRF_ADDR:-127.2.0.10}"
# G5C_DISCOVERY=1 (default): the NRF is started first, every function registers with it and finds its peers there (no peer addresses in the
# configurations except the SMF's UPFs). G5C_DISCOVERY=0: no NRF, peers are named in the configurations.
DISCOVERY="${G5C_DISCOVERY:-1}"
# G5C_SCP=1 (default): the SCP (indirect communication, TS 29.500 6.10) is started after the NRF and every function sends its requests to other functions through it
# (the NRF is reached directly). G5C_SCP=0: the functions talk to each other directly.
SCPON="${G5C_SCP:-1}"
# G5C_PIN_PEERS=1 (with G5C_TLS=1): sbi.tls.allowed_peers on every function, from the call graph (see tls_conf)
# G5C_AMBR_UL / G5C_AMBR_DL: the session AMBR the PCF gives every session (default 1 Gbps / 2 Gbps), e.g. '1 Mbps' to see the UPF enforce it (scenarios/traffic-ambr.yaml)
# G5C_AMF_EXTRA / G5C_SMF_EXTRA: lines added to the amf: / smf: block of the configuration (two-space indent), e.g. failure injection:
#   G5C_AMF_EXTRA='  inject: { registration_reject: [{ supi: imsi-00101, cause: 11 }] }'
# G5C_BSF=1 (default): the BSF (Nbsf_Management, TS 29.521) is started before the PCF; the PCF registers the binding of every PDU session that has a UE address and the NEF asks
# for the PCF of a UE address there. G5C_BSF=0: no BSF (the PCF does not register, the NEF takes the PCF from the NRF).
BSFON="${G5C_BSF:-1}"
# G5C_CHF=1: the CHF (Nchf_ConvergedCharging, TS 32.291) is started before the SMF; the SMF opens a charging session for every PDU session and closes it with the usage the UPF measured.
# G5C_CHF_EXTRA: lines added to the chf: block (two-space indent), e.g. G5C_CHF_EXTRA="  default_balance_bytes: 0" to refuse every session. G5C_CHF=0 (default): no charging.
CHFON="${G5C_CHF:-0}"
ALLNFS="nrf scp bsf udr nssf nef udm ausf pcf upf smf amf"; [ "$CHFON" = 1 ] && ALLNFS="$ALLNFS chf"
# G5C_OAUTH2=1 (default, needs discovery): every function requires the access token of the NRF for its services and asks the NRF for one for every service it calls
# (TS 33.501 13.4.1; `oauth2: { enforce, acquire }` of the common configuration). G5C_OAUTH2=0: no tokens.
OAUTH2ON="${G5C_OAUTH2:-1}"
# G5C_TLS=1: mutual TLS on every SBI listener and every outgoing request (TS 33.501 13.1, 13.3.2.1): a CA and one certificate per function are made under $RUN/pki
# (deploy/run/g5c-pki.sh) and every URI is https. G5C_TLS=0 (default of this script): cleartext HTTP/2. Certificates are rotated without a restart: `g5c-cluster.sh certs renew`.
TLSON="${G5C_TLS:-0}"
if [ "$TLSON" = 1 ]; then
  SCH=https
  # the operator's own client certificate (the same file pair the functions use among themselves)
  curlf() { echo "--cacert $RUN/pki/ca.crt --cert $RUN/pki/admin.crt --key $RUN/pki/admin.key"; }
  export G5C_TLS_CA="$RUN/pki/ca.crt" G5C_TLS_CERT="$RUN/pki/admin.crt" G5C_TLS_KEY="$RUN/pki/admin.key" # g5c-ctl and the load generator
else
  SCH=http
  curlf() { echo "--http2-prior-knowledge"; }
fi
if [ "$DISCOVERY" = 1 ]; then
  NFS="nrf udr nssf udm ausf pcf upf smf amf nef"   # start order; stopped in reverse
else
  NFS="udr nssf udm ausf pcf upf smf amf nef"
fi
[ "$SCPON" = 1 ] && NFS="$(echo "$NFS" | sed 's/^nrf /nrf scp /; t; s/^/scp /')"
[ "$BSFON" = 1 ] && NFS="$(echo "$NFS" | sed 's/ pcf / bsf pcf /')"
[ "$CHFON" = 1 ] && NFS="$(echo "$NFS" | sed 's/ pcf / chf pcf /')"

# where the binary of an NF is: the installed set, or a CMake build tree (G5C_BUILD_DIR, used by the ctest wrappers)
bin_of() {
  if [ -n "${G5C_BUILD_DIR:-}" ]; then
    case "$1" in
      udr) echo "$G5C_BUILD_DIR/nf/$1/$1";;
      *) echo "$G5C_BUILD_DIR/nf/$1/$1";;
    esac
  else
    echo "$BIN/$1"
  fi
}

pidfile() { echo "$RUN/run/$1.pid"; }
# the pid of a function: the one this script started, or (a function started by hand with `run`, one per terminal) the process of that name
pid_of() {
  local p; p="$(cat "$(pidfile "$1")" 2>/dev/null)"
  if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
    echo "$p"
  elif [ "${G5C_IN_NS:-}" != 1 ]; then
    pgrep -x "$1" 2>/dev/null | head -1 # not in a test namespace: the process table is shared with other clusters, so only here is the name a safe key
  fi
}
alive() { [ -n "$(pid_of "$1")" ]; }

gen_conf() {
  mkdir -p "$RUN"/{conf,log,run,keys,state}
  [ -f "$RUN/keys/admin_token" ] || printf '%s' "$TOKEN" > "$RUN/keys/admin_token"
  [ -f "$RUN/keys/master.key" ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$RUN/keys/master.key"
  [ -f "$RUN/keys/ausf-master.key" ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$RUN/keys/ausf-master.key"
  [ -f "$RUN/keys/udr-provisioning.token" ] || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$RUN/keys/udr-provisioning.token"
  # the home network key is the public TS 33.501 Annex C.4.3 test key; replace for anything but a test cluster
  [ -f "$RUN/keys/hn-1.key" ] || printf '%s' c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d > "$RUN/keys/hn-1.key"
  chmod 600 "$RUN"/keys/*
  [ "$TLSON" = 1 ] && gen_pki
  local common_noscp="plmn: { mcc: '${G5C_MCC:-001}', mnc: '${G5C_MNC:-01}' }
log: { level: $LOGLEVEL, json: $LOGJSON }" common
  common="$common_noscp"
  [ "$SCPON" = 1 ] && common="$common_noscp
scp_client: { uri: 'http://$A_SCP:7785' }"
  local chf_peer=""
  [ "$CHFON" = 1 ] && chf_peer="  chf: { uri: 'http://$A_CHF:7787', quota_bytes: ${G5C_CHF_QUOTA:-10485760} }"
  local bsf_peer="bsf: { enabled: false }"
  [ "$BSFON" = 1 ] && bsf_peer="bsf: { uri: 'http://$A_BSF:7786' }"
  [ "$OAUTH2ON" = 1 ] && [ "$DISCOVERY" = 1 ] && common="$common
oauth2: { enforce: true, acquire: true }"
  local nrfline="" udr_peer="udr: { uri: 'http://$A_UDR:7790' }" udm_peer="udm: { uri: 'http://$A_UDM:7773' }"
  # the UDM provisions through the UDR's extension operations and presents the provisioning token
  local udm_udr_peer="udr: { uri: 'http://$A_UDR:7790', token_file: $RUN/keys/udr-provisioning.token }"
  if [ "$DISCOVERY" = 1 ]; then
    nrfline="nrf: { uri: 'http://$A_NRF:7777' }"
    udr_peer=""; udm_peer=""
    udm_udr_peer="udr: { token_file: $RUN/keys/udr-provisioning.token }"
  fi
  local smf_peers amf_peers
  # G5C_AMF_NSSF=1 (default): the AMF asks the NSSF which of the requested and subscribed slices are allowed (Nnssf_NSSelection); 0: its own lists decide
  local amf_nssf=""
  if [ "${G5C_AMF_NSSF:-1}" = 1 ]; then
    if [ "$DISCOVERY" = 1 ]; then amf_nssf="  nssf: { enabled: true }"; else amf_nssf="  nssf: { uri: http://$A_NSSF:7783 }"; fi
  fi
  if [ "$DISCOVERY" = 1 ]; then
    smf_peers=""; amf_peers=""
  else
    smf_peers="  udm: { uri: 'http://$A_UDM:7773' }
  pcf: { uri: 'http://$A_PCF:7775' }
  amf: { uri: 'http://$A_AMF:7777' }"
    amf_peers="  ausf: { uri: 'http://$A_AUSF:7774' }
  udm: { uri: 'http://$A_UDM:7773' }
  pcf: { uri: 'http://$A_PCF:7775' }
  smf: { uri: 'http://$A_SMF:7776' }"
  fi
  cat > "$RUN/conf/scp.yaml" <<EOF
name: scp-1
$common_noscp
$nrfline
sbi: { address: $A_SCP, port: 7785 }
scp:
  routing: { workers: ${G5C_SCP_WORKERS:-128}, timeout_ms: ${G5C_SCP_TIMEOUT_MS:-5000} }
EOF
  cat > "$RUN/conf/bsf.yaml" <<EOF
name: bsf-1
$common
$nrfline
sbi: { address: $A_BSF, port: 7786 }
bsf:
  state_file: $RUN/state/bsf.json
EOF
  [ "$CHFON" = 1 ] && cat > "$RUN/conf/chf.yaml" <<EOF
name: chf-1
$common
$nrfline
sbi: { address: $A_CHF, port: 7787 }
chf:
  cdr_file: $RUN/state/chf-cdr.jsonl
  max_grant_bytes: ${G5C_CHF_GRANT:-10485760}
${G5C_CHF_EXTRA:-}
EOF
  cat > "$RUN/conf/nrf.yaml" <<EOF
name: nrf-1
$common_noscp
sbi: { address: $A_NRF, port: 7777 }
registry:
  heartbeat_timer: ${G5C_NRF_HEARTBEAT:-10}
  suspend_after: 3
  state_file: $RUN/state/nrf.json
  oauth2: { enabled: true, key_file: $RUN/keys/nrf-oauth2.pem }
EOF
  cat > "$RUN/conf/udr.yaml" <<EOF
name: udr-1
$common
$nrfline
sbi: { address: $A_UDR, port: 7790 }
store: { type: file, path: $RUN/state/udr.json }
provisioning: { token_file: $RUN/keys/udr-provisioning.token }
EOF
  cat > "$RUN/conf/nssf.yaml" <<EOF
name: nssf-1
$common
$nrfline
sbi: { address: $A_NSSF, port: 7783 }
nssf:
  slices:
    - { snssai: { sst: 1 }, nrf: http://:7777 }
  state_file: $RUN/state/nssf.json
EOF
  [ -f "$RUN/keys/nef-af-1.token" ] || { umask 077; head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$RUN/keys/nef-af-1.token"; }
  cat > "$RUN/conf/nef.yaml" <<EOF
name: nef-1
$common
$nrfline
sbi: { address: $A_NEF, port: 7784 }
nef:
  afs:
    - { id: af-1, token_file: $RUN/keys/nef-af-1.token, any_notify_host: true }
  callback_uri: http://$A_NEF:7784
  state_file: $RUN/state/nef.json
EOF
  cat > "$RUN/conf/udm.yaml" <<EOF
name: udm-1
$common
sbi: { address: $A_UDM, port: 7773 }
$nrfline
$udm_udr_peer
hn_keys:
  - { id: 1, scheme: profile-a, private_key_file: $RUN/keys/hn-1.key }
master_key_file: $RUN/keys/master.key
admin_token_file: $RUN/keys/admin_token
ee: { state_file: $RUN/state/udm-ee.json }
EOF
  cat > "$RUN/conf/ausf.yaml" <<EOF
name: ausf-1
$common
sbi: { address: $A_AUSF, port: 7774 }
$nrfline
$udm_peer
ausf:
  state_file: $RUN/state/ausf.json
  master_key_file: $RUN/keys/ausf-master.key
EOF
  cat > "$RUN/conf/pcf.yaml" <<EOF
name: pcf-1
$common
sbi: { address: $A_PCF, port: 7775 }
$nrfline
$udr_peer
$bsf_peer
admin_token_file: $RUN/keys/admin_token
policy:
  rfsp: 1
  default:
    session_ambr: { uplink: ${G5C_AMBR_UL:-1 Gbps}, downlink: ${G5C_AMBR_DL:-2 Gbps} }
EOF
  cat > "$RUN/conf/upf.yaml" <<EOF
name: upf-1
$common
$nrfline
sbi: { address: $A_UPF, port: 9091 }
upf:
  pfcp: { address: $A_UPF, port: 8805 }
  gtpu: { address: $A_UPF, port: 2152 }
  n6: { device: $N6_DEV }
  max_sessions: 200000
EOF
  cat > "$RUN/conf/smf.yaml" <<EOF
name: smf-1
$common
$nrfline
sbi: { address: $A_SMF, port: 7776 }
smf:
  self_uri: 'http://$A_SMF:7776'
$smf_peers
  state_file: $RUN/state/smf-state.json
  cdr: { file: $RUN/state/cdr.jsonl }
  n4: { address: $A_SMF, port: 8805, heartbeat: { interval: 2, failures: 3 }, lost_after: 10 }
  upfs:
    - { name: upf-1, address: $A_UPF, port: 8805, dnns: [internet] }
  dnns:
    - { name: internet, ipv4_pool: $UE_POOL, dns: [8.8.8.8, 8.8.4.4] }
${chf_peer}
${G5C_SMF_EXTRA:-}
EOF
  cat > "$RUN/conf/amf.yaml" <<EOF
name: amf-1
$common
$nrfline
sbi: { address: $A_AMF, port: 7777 }
amf:
  self_uri: 'http://$A_AMF:7777'
  guami: { region: 2, set: 1, pointer: 0 }
  ngap: { address: $A_AMF, port: 38412 }
  tais: [ $TAIS ]
$AMF_SEC
  slices: [ { sst: 1 } ]
$amf_peers
$amf_nssf
  default_dnn: internet
  network_name: { full: g5c, short: g5c }
  workers: ${G5C_AMF_WORKERS:-8}
  max_unauthenticated: ${G5C_AMF_MAX_UNAUTH:-4096}
  state_file: $RUN/state/amf-state.json
${G5C_AMF_EXTRA:-}
EOF
  echo "$TLSON" > "$RUN/conf/.tls"
  if [ "$TLSON" = 1 ]; then for nf in $ALLNFS; do tls_conf "$nf"; done; fi
}

# the CA, the certificates of the functions (their addresses as subject alternative names) and the operator's
gen_pki() {
  local pki="$RUN/pki" nf a
  bash "$HERE/g5c-pki.sh" init "$pki"
  for nf in $ALLNFS; do
    case "$nf" in nrf) a=$A_NRF;; scp) a=$A_SCP;; bsf) a=$A_BSF;; chf) a=$A_CHF;; udr) a=$A_UDR;; nssf) a=$A_NSSF;; nef) a=$A_NEF;; udm) a=$A_UDM;; ausf) a=$A_AUSF;; pcf) a=$A_PCF;; upf) a=$A_UPF;; smf) a=$A_SMF;; amf) a=$A_AMF;; esac
    [ -f "$pki/$nf.crt" ] || bash "$HERE/g5c-pki.sh" issue "$pki" "$nf" "$a"
  done
  [ -f "$pki/admin.crt" ] || bash "$HERE/g5c-pki.sh" issue "$pki" admin 127.0.0.1
  chmod 755 "$pki" 2>/dev/null || true
}

# https in every URI and the certificate of each function in its `sbi:` line
tls_conf() {
  local nf f="$RUN/conf/$1.yaml"
  nf="$1"
  sed -i -E "s#http://#https://#g; s#^sbi: \{ address: ([^,]+), port: ([0-9]+) \}#sbi: { address: \1, port: \2, tls: { cert: $RUN/pki/$nf.crt, key: $RUN/pki/$nf.key, ca: $RUN/pki/ca.crt, crl: $RUN/pki/ca.crl } }#" "$f"
  # G5C_PIN_PEERS=1 (backlog D-02): every function accepts client certificates only from the functions that call it. With the SCP in the middle that is the SCP, the NRF (discovery,
  # tokens, registration) and the operator's certificate; the NRF and the SCP are called by every function.
  if [ "${G5C_PIN_PEERS:-0}" = 1 ]; then
    local peers="admin, scp, nrf"
    case "$nf" in nrf|scp) peers="admin, nrf, scp, bsf, chf, udr, nssf, nef, udm, ausf, pcf, smf, amf, upf";; esac
    sed -i -E "/^sbi:/ s#crl: ([^ ]+) \}#crl: \1, allowed_peers: [$peers] }#" "$f"
  fi
}

# configuration and keys are written once, under a lock: several terminals start their function at the same moment and must all see the same keys
gen_conf_once() {
  mkdir -p "$RUN"
  (
    command -v flock >/dev/null 2>&1 && flock -x 9
    if [ ! -f "$RUN/conf/amf.yaml" ] || [ ! -f "$RUN/keys/master.key" ] || [ ! -f "$RUN/keys/ausf-master.key" ] || [ "$(cat "$RUN/conf/.tls" 2>/dev/null)" != "$TLSON" ]; then gen_conf; fi
  ) 9>"$RUN/.conf.lock"
}

sbi_of() {
  case "$1" in
    nrf) echo "$SCH://$A_NRF:7777";; udr) echo "$SCH://$A_UDR:7790";; nssf) echo "$SCH://$A_NSSF:7783";; nef) echo "$SCH://$A_NEF:7784";; scp) echo "$SCH://$A_SCP:7785";; bsf) echo "$SCH://$A_BSF:7786";; chf) echo "$SCH://$A_CHF:7787";; udm) echo "$SCH://$A_UDM:7773";; ausf) echo "$SCH://$A_AUSF:7774";;
    pcf) echo "$SCH://$A_PCF:7775";; smf) echo "$SCH://$A_SMF:7776";; amf) echo "$SCH://$A_AMF:7777";; upf) echo "$SCH://$A_UPF:9091";;
  esac
}

start_nf() {
  local nf="$1"
  [ -x "$(bin_of "$nf")" ] || { echo "missing $(bin_of "$nf") (run scripts/c_install.sh)"; return 1; }
  alive "$nf" && { echo "$nf already running"; return 0; }
  nohup "$(bin_of "$nf")" "$RUN/conf/$nf.yaml" >>"$RUN/log/$nf.log" 2>&1 &
  echo $! > "$(pidfile "$nf")"
  # wait until it answers its health endpoint (every NF serves /health/ready on its SBI port)
  for _ in $(seq 1 100); do
    curl -s -o /dev/null --max-time 1 $(curlf) "$(sbi_of "$nf")/health/live" 2>/dev/null && { echo "started $nf (pid $(cat "$(pidfile "$nf")"))"; return 0; }
    alive "$nf" || { echo "$nf exited at start-up:"; tail -5 "$RUN/log/$nf.log"; return 1; }
    sleep 0.1
  done
  echo "$nf did not become live"; return 1
}

stop_nf() {
  local nf="$1" p
  p="$(cat "$(pidfile "$nf")" 2>/dev/null)" || return 0
  [ -n "$p" ] && kill "$p" 2>/dev/null
  for _ in $(seq 1 50); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done
  kill -9 "$p" 2>/dev/null
  rm -f "$(pidfile "$nf")"
}

rss_of() { local p; p="$(pid_of "$1")"; [ -n "$p" ] && awk '/VmRSS/{print $2}' "/proc/$p/status" 2>/dev/null || echo 0; }
cpu_of() { local p; p="$(pid_of "$1")"; [ -n "$p" ] && awk '{printf "%.1f", ($14+$15)/100}' "/proc/$p/stat" 2>/dev/null || echo 0; }
fds_of() { local p n; p="$(pid_of "$1")"; n=0; [ -n "$p" ] && n="$(ls "/proc/$p/fd" 2>/dev/null | wc -l)"; echo "${n:-0}"; }

cmd_rss() { for nf in $NFS; do printf '%s=%s ' "$nf" "$(rss_of "$nf")"; done; echo "(kB)"; }

gauge() { curl -s --max-time 2 $(curlf) "$1/metrics" 2>/dev/null | awk -v n="$2" '$1==n{print $2; exit}'; }

cmd_status() {
  for nf in $NFS; do
    if alive "$nf"; then printf '%-10s up    pid %-7s rss %-8s kB  fds %-4s cpu %s s\n' "$nf" "$(pid_of "$nf")" "$(rss_of "$nf")" "$(fds_of "$nf")" "$(cpu_of "$nf")"
    else printf '%-10s DOWN\n' "$nf"; fi
  done
  echo "AMF: gNBs $(gauge "$(sbi_of amf)" g5c_amf_gnbs), UE contexts $(gauge "$(sbi_of amf)" g5c_amf_ue_contexts), registered $(gauge "$(sbi_of amf)" g5c_amf_registered_ues)," \
       "connected $(gauge "$(sbi_of amf)" g5c_amf_connected_ues)"
  echo "SMF: PDU sessions $(gauge "$(sbi_of smf)" g5c_smf_pdu_sessions_active);  UPF: sessions $(gauge "$(sbi_of upf)" g5c_upf_sessions)"
}

# wait until every function has registered at the NRF (a function is live before its registration is in: the first request that needs a peer
# would otherwise find nothing)
wait_registered() {
  local want n i
  [ "$DISCOVERY" = 1 ] || return 0
  want=$(( $(echo $NFS | wc -w) - 1 ))
  for i in $(seq 1 600); do
    n=$(curl -s --max-time 1 $(curlf) "$(sbi_of nrf)/nnrf-nfm/v1/nf-instances" 2>/dev/null | grep -o '"href"' | wc -l)
    [ "$n" -ge "$want" ] && return 0
    sleep 0.1
  done
  echo "only $n of $want functions registered at the NRF"
  return 1
}

cmd_up() {
  gen_conf
  for nf in $NFS; do start_nf "$nf" || return 1; done
  wait_registered || return 1
  echo "cluster up: AMF N2 $A_AMF:38412, UDM admin $SCH://$A_UDM:7773/admin/v1 (token in $RUN/keys/admin_token), logs in $RUN/log"
}

cmd_down() { for nf in $(echo $NFS | tr ' ' '\n' | tac); do stop_nf "$nf"; done; }

in_ns_prepare() {
  ip link set lo up
  ip tuntap add name "$N6_DEV" mode tun 2>/dev/null
  ip addr add "${UE_POOL%/*}/16" dev "$N6_DEV" 2>/dev/null || ip addr add 10.45.0.1/16 dev "$N6_DEV"
  ip link set "$N6_DEV" up
}

cmd_ns() {
  if [ "${G5C_IN_NS:-}" != 1 ]; then
    unshare -Urn true 2>/dev/null || { echo "SKIP: user and network namespaces are not available here"; exit 77; }
    exec unshare -Urn env G5C_IN_NS=1 bash "$0" ns "$@"
  fi
  in_ns_prepare
  local what="${1:-shell}"; shift || true
  rm -rf "$RUN/log" "$RUN/state"; mkdir -p "$RUN/log" "$RUN/state"
  cmd_up || { cmd_down; return 1; }
  local rc=0
  case "$what" in
    load)  rc=$(do_load "$@") ;;
    chaos) do_chaos "$@"; rc=$? ;;
    soak)  do_soak "$@"; rc=$? ;;
    tls)   do_tls; rc=$? ;;
    ops)   do_ops; rc=$? ;;
    support) do_support; rc=$? ;;
    upgrade) do_upgrade "$@"; rc=$? ;;
    slices) do_slices; rc=$? ;;
    secrets) do_secrets; rc=$? ;;
    keylog) do_keylog; rc=$? ;;
    scenario) do_scenario "$@"; rc=$? ;;
    shell) echo "inside the namespace; the cluster is up (exit to stop it)"; bash -i; ;;
    *) echo "unknown ns mode $what"; rc=2 ;;
  esac
  cmd_down
  return "$rc"
}

# link impairment (scenario steps, backlog B-08): packets TO one function's address are delayed, dropped, duplicated and/or reordered (tc netem on the loopback of the namespace, selected by destination),
# every other link stays as it was. `impair NF DELAY_MS [LOSS_PCT [REORDER_PCT [DUP_PCT [JITTER_MS]]]]`, `impair clear`. Needs the private namespace (ns mode) or root.
addr_of() {
  case "$1" in nrf) echo "$A_NRF";; scp) echo "$A_SCP";; bsf) echo "$A_BSF";; chf) echo "$A_CHF";; udr) echo "$A_UDR";; nssf) echo "$A_NSSF";; nef) echo "$A_NEF";; udm) echo "$A_UDM";; ausf) echo "$A_AUSF";;
    pcf) echo "$A_PCF";; smf) echo "$A_SMF";; amf) echo "$A_AMF";; upf) echo "$A_UPF";; *) return 1;; esac
}
cmd_impair() {
  local nf="${1:?function or clear}" delay="${2:-0}" loss="${3:-0}" reorder="${4:-0}" dup="${5:-0}" jitter="${6:-0}" a opts
  tc qdisc del dev lo root 2>/dev/null
  [ "$nf" = clear ] && { echo "impairment cleared"; return 0; }
  a="$(addr_of "$nf")" || { echo "unknown function $nf" >&2; return 2; }
  tc qdisc add dev lo root handle 1: prio || return 1
  [ "$reorder" != 0 ] && [ "$delay" = 0 ] && delay=1 # netem reorders by sending some packets ahead of the delayed ones: it needs a delay
  opts="delay ${delay}ms"
  [ "$jitter" != 0 ] && opts="$opts ${jitter}ms"
  [ "$reorder" != 0 ] && opts="$opts reorder ${reorder}% 50%"
  [ "$loss" != 0 ] && opts="$opts loss ${loss}%"
  [ "$dup" != 0 ] && opts="$opts duplicate ${dup}%"
  # shellcheck disable=SC2086
  tc qdisc add dev lo parent 1:3 handle 30: netem $opts || return 1
  tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip dst "$a/32" flowid 1:3 || return 1
  echo "impairment to $nf ($a): $opts"
}

# scenarios (backlog B-01): the cluster is up; tools/cli/g5c-scenario runs the steps of each file against it (load, kill, restart, impair, assert on metrics and KPIs, HTTP calls)
do_scenario() {
  local rc=0 f
  export G5C_CLUSTER_SH="$0" G5C_CURL_ARGS="$(curlf)" G5C_SCENARIO_NFS="$NFS"
  for f in "$@"; do
    python3 "$ROOT/tools/cli/g5c-scenario" run "$f" || rc=1
    cmd_impair clear >/dev/null 2>&1
  done
  return "$rc"
}

# mutual TLS: what must be refused, what must work, and a rotation under a running cluster (G5C_TLS=1 is needed for this mode)
do_tls() {
  local f=0 nrf="$A_NRF:7777" cert0 cert1 pid0 pid1 other="$RUN/pki-other" h code n
  ck() { if [ "$1" = ok ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; f=1; fi; }
  [ "$TLSON" = 1 ] || { echo "tls: needs G5C_TLS=1"; return 1; }
  h="https://$nrf/health/live"
  # without TLS, without a client certificate, with a certificate of another CA: all refused; with the cluster's: served
  if curl -s -o /dev/null --max-time 3 --http2-prior-knowledge "http://$nrf/health/live"; then ck bad "cleartext request to a TLS listener"; else ck ok "cleartext request to a TLS listener refused"; fi
  if curl -s -o /dev/null --max-time 3 --cacert "$RUN/pki/ca.crt" "$h"; then ck bad "no client certificate"; else ck ok "request without a client certificate refused"; fi
  bash "$HERE/g5c-pki.sh" issue "$other" intruder 127.0.0.1
  if curl -s -o /dev/null --max-time 3 --cacert "$RUN/pki/ca.crt" --cert "$other/intruder.crt" --key "$other/intruder.key" "$h"; then ck bad "certificate of another CA"; else ck ok "client certificate of another CA refused"; fi
  if curl -s -o /dev/null --max-time 3 --cacert "$other/ca.crt" --cert "$RUN/pki/admin.crt" --key "$RUN/pki/admin.key" "$h"; then ck bad "server certificate of another CA"; else ck ok "a client that trusts another CA refuses the server"; fi
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 $(curlf) "$h")"
  if [ "$code" = 200 ]; then ck ok "request with the cluster's certificate served"; else ck bad "request with the cluster's certificate ($code)"; fi
  if grep -l "has no TLS" "$RUN"/log/*.log >/dev/null 2>&1; then ck bad "warning about missing TLS in a log"; else ck ok "no function warns about missing TLS"; fi
  # rotation: new certificates, SIGHUP, same processes, new serial on the wire, traffic keeps working
  cert0="$(openssl s_client -connect "$nrf" -cert "$RUN/pki/admin.crt" -key "$RUN/pki/admin.key" -CAfile "$RUN/pki/ca.crt" </dev/null 2>/dev/null | openssl x509 -noout -serial)"
  pid0="$(pid_of nrf)"
  cmd_certs renew >/dev/null
  sleep 1
  cert1="$(openssl s_client -connect "$nrf" -cert "$RUN/pki/admin.crt" -key "$RUN/pki/admin.key" -CAfile "$RUN/pki/ca.crt" </dev/null 2>/dev/null | openssl x509 -noout -serial)"
  pid1="$(pid_of nrf)"
  if [ -n "$cert0" ] && [ "$cert0" != "$cert1" ]; then ck ok "the NRF serves the new certificate after SIGHUP ($cert0 -> $cert1)"; else ck bad "certificate not rotated ($cert0 / $cert1)"; fi
  if [ "$pid0" = "$pid1" ]; then ck ok "no restart (pid $pid0)"; else ck bad "the NRF restarted"; fi
  if [ "$(do_load 10 | tail -1)" = 0 ]; then ck ok "registrations and sessions work through the rotated certificates"; else ck bad "load after rotation"; fi
  n="$(cat "$RUN"/log/*.log | grep -c "certificates reloaded")"
  if [ "$n" -ge 12 ]; then ck ok "$n reloads logged (every function)"; else ck bad "only $n reloads logged"; fi
  # a damaged file on reload is refused and the old certificate stays in use
  cp "$RUN/pki/nrf.crt" "$RUN/pki/nrf.crt.good"; echo garbage > "$RUN/pki/nrf.crt"
  kill -HUP "$(pid_of nrf)"; sleep 1
  if grep -q "certificate reload failed" "$RUN/log/nrf.log"; then ck ok "a damaged certificate file is refused on reload"; else ck bad "damaged file accepted?"; fi
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 $(curlf) "$h")"
  if [ "$code" = 200 ]; then ck ok "the NRF keeps serving with the old certificate"; else ck bad "the NRF stopped serving ($code)"; fi
  mv "$RUN/pki/nrf.crt.good" "$RUN/pki/nrf.crt"
  # revocation: a certificate of the cluster's CA works until it is on the revocation list, and is refused by every function after the functions have read the list again
  bash "$HERE/g5c-pki.sh" issue "$RUN/pki" rogue 127.0.0.1
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 --cacert "$RUN/pki/ca.crt" --cert "$RUN/pki/rogue.crt" --key "$RUN/pki/rogue.key" --http2-prior-knowledge "$h")"
  if [ "$code" = 200 ]; then ck ok "a fresh certificate of the CA is served"; else ck bad "fresh certificate ($code)"; fi
  cmd_certs revoke rogue >/dev/null; sleep 1
  if curl -s -o /dev/null --max-time 3 --cacert "$RUN/pki/ca.crt" --cert "$RUN/pki/rogue.crt" --key "$RUN/pki/rogue.key" --http2-prior-knowledge "$h"; then ck bad "revoked certificate served"; else ck ok "the revoked certificate is refused after the reload"; fi
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 $(curlf) "$h")"
  if [ "$code" = 200 ]; then ck ok "the other certificates are unaffected"; else ck bad "admin after the revocation ($code)"; fi
  # identity pinning: the UDM accepts only the functions that call it (and the operator); another certificate of the same CA is refused
  stop_nf udm
  sed -i -E "/^sbi:/ s#crl: ([^ ]+) \}#crl: \1, allowed_peers: [admin, scp, amf, ausf, smf, pcf, nef] }#" "$RUN/conf/udm.yaml"
  start_nf udm >/dev/null; sleep 1
  bash "$HERE/g5c-pki.sh" issue "$RUN/pki" stranger 127.0.0.1
  h="https://$A_UDM:7773/health/live"
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 $(curlf) "$h")"
  if [ "$code" = 200 ]; then ck ok "the UDM serves the operator's certificate (admin is on its list)"; else ck bad "UDM with the admin certificate ($code)"; fi
  if curl -s -o /dev/null --max-time 3 --cacert "$RUN/pki/ca.crt" --cert "$RUN/pki/stranger.crt" --key "$RUN/pki/stranger.key" --http2-prior-knowledge "$h"; then ck bad "a certificate not on the list was served"; else ck ok "a valid certificate of the CA whose name is not on the list is refused"; fi
  if curl -s -o /dev/null --max-time 3 --cacert "$RUN/pki/ca.crt" --cert "$RUN/pki/nssf.crt" --key "$RUN/pki/nssf.key" --http2-prior-knowledge "$h"; then ck bad "the NSSF certificate was served by the UDM"; else ck ok "another function's certificate (nssf) cannot be used to call the UDM"; fi
  if [ "$(do_load 10 | tail -1)" = 0 ]; then ck ok "registrations and sessions work with the UDM pinned to its callers"; else ck bad "load with the pinned UDM"; fi
  if [ "$f" = 0 ]; then echo "tls: PASS"; else echo "tls: FAIL"; fi
  return "$f"
}

# TLS key log (backlog C-02): the functions run with G5C_TLS_KEYLOG; a capture of requests to the UDM shows only TLS records without the key log and the HTTP/2 requests with it
do_keylog() {
  local f=0 kl="${G5C_TLS_KEYLOG:-}" cap="$RUN/keylog.pcap" tp n_plain n_dec
  ck() { if [ "$1" = ok ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; f=1; fi; }
  [ "$TLSON" = 1 ] && [ -n "$kl" ] || { echo "keylog: needs G5C_TLS=1 and G5C_TLS_KEYLOG=<file>"; return 1; }
  command -v tcpdump >/dev/null 2>&1 && command -v tshark >/dev/null 2>&1 || { echo "SKIP: tcpdump and tshark are needed"; return 77; }
  tcpdump -i lo -Z root -U -w "$cap" "tcp port 7773" >/dev/null 2>&1 &
  tp=$!
  sleep 1
  for i in 1 2 3; do curl -s -o /dev/null --max-time 5 $(curlf) "$SCH://$A_UDM:7773/health/ready?probe=keylog-check-$i"; done
  sleep 1
  kill "$tp" 2>/dev/null; wait "$tp" 2>/dev/null
  n_plain="$(tshark -r "$cap" -d tcp.port==7773,tls -Y 'http2.headers.path contains "keylog-check"' 2>/dev/null | wc -l)"
  n_dec="$(tshark -r "$cap" -d tcp.port==7773,tls -o "tls.keylog_file:$kl" -Y 'http2.headers.path contains "keylog-check"' 2>/dev/null | wc -l)"
  if [ -s "$kl" ] && [ "$(stat -c %a "$kl")" = 600 ]; then ck ok "the key log exists ($(wc -l < "$kl") lines, mode 600)"; else ck bad "no key log or wrong mode"; fi
  if [ "${n_plain:-0}" = 0 ]; then ck ok "without the key log the capture shows no HTTP/2 request (the SBI is encrypted)"; else ck bad "requests visible without keys: $n_plain"; fi
  if [ "${n_dec:-0}" -ge 3 ]; then ck ok "with the key log Wireshark decrypts $n_dec HTTP/2 requests to the UDM"; else ck bad "only ${n_dec:-0} requests decrypted"; fi
  if [ "$f" = 0 ]; then echo "keylog: PASS"; else echo "keylog: FAIL"; fi
  return "$f"
}

# secrets: nothing secret in a log, a configuration file or the state of a function (the home network key, the master keys and tokens by their own value, K and OPc of a subscriber at rest)
do_secrets() {
  local f=0 k=00112233445566778899aabbccddeeff opc=ffeeddccbbaa99887766554433221100 udm="$SCH://$A_UDM:7773" v name n
  ck() { if [ "$1" = ok ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; f=1; fi; }
  "$BIN/g5c-ctl" --udm "$udm" --token-file "$RUN/keys/admin_token" subscriber add --supi imsi-001019999999999 --k "$k" --opc "$opc" --slice 1 --dnn internet >/dev/null 2>&1 \
    && ck ok "a subscriber with a known K and OPc was provisioned" || ck bad "provisioning"
  [ "$(do_load 10 | tail -1)" = 0 ] && ck ok "traffic ran (logs and state have content)" || ck bad "load"
  sleep 2 # the write-behind of the state files
  # at rest: the stores hold K and OPc only as ciphertext
  n="$(grep -rIl -i -e "$k" -e "$opc" "$RUN/state" 2>/dev/null | wc -l)"
  [ "$n" = 0 ] && ck ok "K and OPc of the subscriber are not in any state file in the clear" || ck bad "K / OPc in the clear in $n state file(s)"
  # the secrets of the cluster by value, in logs, configurations and state
  for name in master.key ausf-master.key admin_token udr-provisioning.token hn-1.key nef-af-1.token; do
    v="$(cat "$RUN/keys/$name" 2>/dev/null)"
    [ -n "$v" ] || continue
    n="$(grep -rIl -F -e "$v" "$RUN/log" "$RUN/conf" "$RUN/state" 2>/dev/null | wc -l)"
    [ "$n" = 0 ] && ck ok "$name does not appear in a log, a configuration or a state file" || ck bad "$name appears in $n file(s)"
  done
  # the keys directory is not readable by others
  n="$(find "$RUN/keys" -type f \( -perm -g+r -o -perm -o+r \) ! -name '*.crt' | wc -l)"
  [ "$n" = 0 ] && ck ok "key files are mode 600" || ck bad "$n key file(s) readable by group or others"
  if [ "$TLSON" = 1 ]; then
    n="$(find "$RUN/pki" -name '*.key' \( -perm -g+r -o -perm -o+r \) | wc -l)"
    [ "$n" = 0 ] && ck ok "private keys of the PKI are mode 600" || ck bad "$n PKI key(s) readable by group or others"
  fi
  # the configuration names files, never values
  grep -rIn -E "(token|master_key|private_key|password|secret)[a-z_]*: *['\"]?[0-9a-fA-F]{24,}" "$RUN/conf" >/dev/null 2>&1 && ck bad "a secret value in a configuration file" || ck ok "configurations name key files, not key values"
  if [ "$f" = 0 ]; then echo "secrets: PASS"; else echo "secrets: FAIL"; fi
  return "$f"
}

# operations: the log level at run time (SIGUSR1 debug, SIGUSR2 back), rotation of the UDM's master key (previous key, rewrap, previous removed), a secret read through a command
# (the KMS / HSM hook: `exec:<command>`), and the charging record file. Needs G5C_OAUTH2=0 (the test calls the UDM directly).
do_ops() {
  local f=0 udm="$SCH://$A_UDM:7773" supi=imsi-001019999999998 k=00112233445566778899aabbccddeeff opc=ffeeddccbbaa99887766554433221100 code body n pid
  local body_auth='{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}'
  ck() { if [ "$1" = ok ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; f=1; fi; }
  auth() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 $(curlf) -X POST -H 'content-type: application/json' -d "$body_auth" "$udm/nudm-ueau/v1/$supi/security-information/generate-auth-data"; }
  restart_udm() { stop_nf udm; start_nf udm >/dev/null; sleep 1; }
  # 1. the log level at run time
  pid="$(pid_of amf)"
  kill -USR1 "$pid"; sleep 1
  if grep -q "SIGUSR1: log level is now debug" "$RUN/log/amf.log"; then ck ok "SIGUSR1 switches the AMF to debug logging without a restart"; else ck bad "SIGUSR1 not acted on"; fi
  kill -USR2 "$pid"; sleep 1
  if grep -q "SIGUSR2: log level is now the configured one" "$RUN/log/amf.log" && [ "$(pid_of amf)" = "$pid" ]; then ck ok "SIGUSR2 restores the configured level (same process)"; else ck bad "SIGUSR2 not acted on"; fi
  # 2. rotation of the master key of the UDM
  "$BIN/g5c-ctl" --udm "$udm" --token-file "$RUN/keys/admin_token" subscriber add --supi "$supi" --k "$k" --opc "$opc" --slice 1 --dnn internet >/dev/null 2>&1 && ck ok "subscriber provisioned under master key A" || ck bad "provisioning"
  [ "$(auth)" = 200 ] && ck ok "authentication vector generated under key A" || ck bad "authentication under key A"
  cp "$RUN/keys/master.key" "$RUN/keys/master-A.key"
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$RUN/keys/master-B.key"; chmod 600 "$RUN/keys/master-B.key"
  sed -i "s#^master_key_file: .*#master_key_file: $RUN/keys/master-B.key\nmaster_key_previous_file: $RUN/keys/master-A.key#" "$RUN/conf/udm.yaml"
  restart_udm
  [ "$(auth)" = 200 ] && ck ok "key B current, key A previous: the credentials stored under A still work" || ck bad "authentication with the previous key"
  body="$(curl -s --max-time 10 $(curlf) -X POST -H "authorization: Bearer $(cat "$RUN/keys/admin_token")" "$udm/admin/v1/keys/rewrap")"
  echo "$body" | grep -q '"rewrapped":[1-9]' && ck ok "rewrap protected the stored credentials again under key B ($body)" || ck bad "rewrap: $body"
  sed -i '/^master_key_previous_file: /d' "$RUN/conf/udm.yaml"
  restart_udm
  [ "$(auth)" = 200 ] && ck ok "key A removed: the credentials open with key B alone" || ck bad "authentication after removing the previous key"
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$RUN/keys/master-C.key"; chmod 600 "$RUN/keys/master-C.key"
  sed -i "s#^master_key_file: .*#master_key_file: $RUN/keys/master-C.key#" "$RUN/conf/udm.yaml"
  restart_udm
  code="$(auth)"
  [ "$code" != 200 ] && ck ok "a wrong master key does not open the credentials (HTTP $code)" || ck bad "authentication with a wrong key succeeded"
  # 3. a secret read through a command (a KMS client, a vault agent): `exec:<command>` instead of a file name
  sed -i "s#^master_key_file: .*#master_key_file: exec:/bin/cat $RUN/keys/master-B.key#" "$RUN/conf/udm.yaml"
  restart_udm
  [ "$(auth)" = 200 ] && ck ok "the master key read through exec: works (the key never touched the configuration)" || ck bad "exec: key source"
  # 4. charging records: every released PDU session leaves one
  [ "$(do_load 10 | tail -1)" = 0 ] && ck ok "10 UEs registered, got sessions and de-registered" || ck bad "load"
  sleep 1
  n="$(grep -c "\"usageReported\":true" "$RUN/state/cdr.jsonl" 2>/dev/null)"
  if [ "${n:-0}" -ge 10 ]; then ck ok "$n charging records with usage reports"; else ck bad "only ${n:-0} charging records"; fi
  # 5. bulk import of an Open5GS-style subscriber dump, and the inventory read back
  local imp="$RUN/state/o5gs-import.json" inv
  printf '%s\n' \
    '{"imsi":"001019999000001","msisdn":["4915100001"],"security":{"k":"00112233445566778899aabbccddee01","opc":"ffeeddccbbaa99887766554433221101","amf":"8000","sqn":{"$numberLong":"32"}},"slice":[{"sst":1,"session":[{"name":"internet","type":1,"qos":{"index":9}}]}]}' \
    '{"imsi":"001019999000002","security":{"k":"00112233445566778899aabbccddee02","op":"00112233445566778899aabbccddee22"},"slice":[{"sst":1,"session":[{"name":"internet","type":3}]}]}' \
    '{"imsi":"001019999000003","security":{"k":"nothex","opc":"ffeeddccbbaa99887766554433221103"}}' > "$imp"
  inv="$(python3 "$ROOT/tools/cli/g5c-subscribers" import --format open5gs "$imp" --apply --bulk --ctl "$BIN/g5c-ctl" --udm "$udm" --token-file "$RUN/keys/admin_token" 2>&1)"
  if echo "$inv" | grep -q "3 read, 2 valid, 1 rejected, 2 provisioned, 0 failed"; then ck ok "bulk import (the bulk endpoint): 2 of 3 Open5GS records provisioned, the malformed one reported and not sent"; else ck bad "bulk import: $inv"; fi
  inv="$(python3 "$ROOT/tools/cli/g5c-subscribers" export --format csv --ctl "$BIN/g5c-ctl" --udm "$udm" --token-file "$RUN/keys/admin_token" 2>/dev/null)"
  if echo "$inv" | grep -q "imsi-001019999000001" && echo "$inv" | grep -q "imsi-001019999000002" && ! echo "$inv" | grep -q "001019999000003" && ! echo "$inv" | grep -qi "ffeeddccbbaa9988"; then ck ok "export lists the imported subscribers, without keys"; else ck bad "export: $(echo "$inv" | head -c 300)"; fi
  # 6. Nudm_EventExposure: a subscription for any UE at the UDM reaches the AMF (found through the NRF), and the AMF's reports come back through the UDM
  local ee_body='{"callbackReference":"http://127.0.0.1:9/ee","monitoringConfigurations":{"1":{"eventType":"LOSS_OF_CONNECTIVITY"}}}' ne
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 $(curlf) -X POST -H 'content-type: application/json' -d "$ee_body" "$udm/nudm-ee/v1/anyUE/ee-subscriptions")"
  if [ "$code" = 201 ]; then ck ok "EE subscription for any UE accepted by the UDM (201)"; else ck bad "EE subscription answered $code"; fi
  [ "$(do_load 5 | tail -1)" = 0 ] && ck ok "5 UEs registered and de-registered" || ck bad "load"
  sleep 1
  ne="$(curl -s --max-time 5 $(curlf) "$udm/metrics" | awk '/^g5c_udm_ee_notifications_total/{s+=$NF} END{print s+0}')"
  if [ "${ne:-0}" -ge 5 ]; then ck ok "the AMF reported $ne losses of connectivity through the UDM"; else ck bad "only ${ne:-0} EE reports reached the UDM"; fi
  if grep -q '"amfSub"' "$RUN/state/udm-ee.json" 2>/dev/null; then ck ok "the UDM keeps its event exposure subscriptions in a state file"; else ck bad "no event exposure state file"; fi
  # 7. the KPIs of the loads above, from the live metrics through the one definition file
  local kpi
  kpi="$(G5C_CURL_ARGS="$(curlf)" python3 "$ROOT/tools/cli/g5c-kpi" --json "$(sbi_of amf)/metrics" "$(sbi_of smf)/metrics" "$(sbi_of upf)/metrics" 2>&1)"
  if echo "$kpi" | python3 -c '
import json, sys
r = {k["id"]: k for k in json.load(sys.stdin)}
assert r["registration_attempts"]["value"] >= 15, r["registration_attempts"]
assert r["registration_success_rate"]["value"] == 100.0, r["registration_success_rate"]
assert r["pdu_session_establishment_success_rate"]["value"] == 100.0, r["pdu_session_establishment_success_rate"]
assert r["charging_records"]["value"] >= 15, r["charging_records"]
' 2>/dev/null; then ck ok "KPIs from live metrics: every registration and PDU session of the loads succeeded, records written"; else ck bad "KPIs: $(echo "$kpi" | head -c 300)"; fi
  # 8. every function serves its routes as OpenAPI; a client generated from them reaches the live UDM
  local sdk="$RUN/sdk" nfn
  mkdir -p "$sdk"
  G5C_CURL_ARGS="$(curlf)" python3 "$ROOT/tools/cli/g5c-sdk" fetch --out "$sdk/docs" $(for nfn in $NFS; do echo "$nfn=$(sbi_of "$nfn")"; done) >/dev/null 2>&1
  nfn="$(ls "$sdk/docs" 2>/dev/null | wc -l)"
  if [ "$nfn" -ge 11 ] && grep -q '"/nudm-ee/v1/{ueIdentity}/ee-subscriptions"' "$sdk/docs/udm.json"; then ck ok "$nfn functions serve /openapi.json (the UDM lists the event exposure routes)"; else ck bad "only $nfn OpenAPI documents"; fi
  python3 "$ROOT/tools/cli/g5c-sdk" python --from "$sdk/docs" --out "$sdk/g5c_sdk.py" >/dev/null 2>&1
  if G5C_CURL_ARGS="$(curlf)" SDK_DIR="$sdk" UDM_URL="$udm" python3 -c '
import os, sys
sys.path.insert(0, os.environ["SDK_DIR"])
from g5c_sdk import Client
c = Client({"udm": os.environ["UDM_URL"]})
st, body = c.udm.get_health_live()
assert st == 200 and body["status"] == "UP", (st, body)
' 2>/dev/null; then ck ok "the generated Python client called the live UDM (GET /health/live: UP)"; else ck bad "generated client"; fi
  # 9. one trace id follows a UE's procedure through the functions: the logs, joined by it, show a registration across several of them
  local tr
  tr="$(python3 "$ROOT/tools/cli/g5c-trace" "$RUN/log" --min-functions 3 2>&1 | tail -3)"
  if echo "$tr" | grep -qE '^[0-9]+ traces' && [ "$(echo "$tr" | tail -1 | cut -d' ' -f1)" -ge 5 ]; then ck ok "log lines joined by trace id: $(echo "$tr" | tail -1) that touch three functions or more"; else ck bad "traces: $tr"; fi
  if [ "$f" = 0 ]; then echo "ops: PASS"; else echo "ops: FAIL"; fi
  return "$f"
}

# slices: the NSSF decides what the AMF is told (G5C_OAUTH2=0: the test calls the NSSF directly). Slice 1 is served, slice 2 is not: a registration asking for both gets slice 1 allowed and slice 2
# rejected; a PDU session on slice 2 is refused, on slice 1 accepted. The AMF's consumption of both procedures is checked through its counters after a load.
do_slices() {
  local f=0 nssf="$SCH://$A_NSSF:7783" out code tai='{"plmnId":{"mcc":"001","mnc":"01"},"tac":"000001"}' amfm
  ck() { if [ "$1" = ok ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; f=1; fi; }
  q() { curl -s -G --max-time 5 $(curlf) -w '\n%{http_code}' "$nssf/nnssf-nsselection/v2/network-slice-information" --data-urlencode "nf-type=AMF" --data-urlencode "nf-id=11111111-2222-4333-8444-555555555555" --data-urlencode "tai=$tai" "$@"; }
  out="$(q --data-urlencode 'slice-info-request-for-registration={"requestedNssai":[{"sst":1},{"sst":2}],"subscribedNssai":[{"subscribedSnssai":{"sst":1},"defaultIndication":true},{"subscribedSnssai":{"sst":2}}]}')"
  code="$(echo "$out" | tail -1)"
  if [ "$code" = 200 ] && echo "$out" | head -n -1 | grep -q '"allowedSnssai":{"sst":1}' && ! echo "$out" | head -n -1 | grep -q '"allowedSnssai":{"sst":2}' && echo "$out" | head -n -1 | grep -q '"rejectedNssaiInPlmn":\[{"sst":2}'; then
    ck ok "registration asking for slices 1 and 2: slice 1 allowed, slice 2 rejected"
  else ck bad "registration slice selection ($code): $(echo "$out" | head -c 300)"; fi
  code="$(q --data-urlencode 'slice-info-request-for-pdu-session={"sNssai":{"sst":2},"roamingIndication":"NON_ROAMING"}' | tail -1)"
  if [ "$code" = 403 ]; then ck ok "PDU session on the slice that is not served: refused (403)"; else ck bad "PDU session on slice 2 answered $code"; fi
  code="$(q --data-urlencode 'slice-info-request-for-pdu-session={"sNssai":{"sst":1},"roamingIndication":"NON_ROAMING"}' | tail -1)"
  if [ "$code" = 200 ]; then ck ok "PDU session on slice 1: accepted with the NSI information"; else ck bad "PDU session on slice 1 answered $code"; fi
  [ "$(do_load 10 | tail -1)" = 0 ] && ck ok "10 UEs registered and got sessions through the NSSF" || ck bad "load"
  amfm="$(sbi_of amf)"
  [ "$(gauge "$amfm" 'g5c_amf_nssf_pdu_session_checks_total{result="ok"}' | cut -d. -f1)" -ge 10 ] 2>/dev/null && ck ok "the AMF asked the NSSF for every PDU session" || ck bad "the AMF did not check PDU sessions with the NSSF"
  if [ "$f" = 0 ]; then echo "slices: PASS"; else echo "slices: FAIL"; fi
  return "$f"
}

# support tools: a diagnostics bundle after a load has the logs, metrics, versions and configurations and none of the subscribers, keys or tokens; the capture helper builds its filters
do_support() {
  local f=0 b="$RUN/diag.tar.gz" d n name v root="$HERE/../../tools/cli"
  ck() { if [ "$1" = ok ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; f=1; fi; }
  [ "$(do_load 20 | tail -1)" = 0 ] && ck ok "20 UEs registered, got sessions and de-registered (the logs have subscribers in them)" || ck bad "load"
  "$BIN/g5c-ctl" --udm "$SCH://$A_UDM:7773" --token-file "$RUN/keys/admin_token" subscriber add --supi imsi-001019999999977 --k 00112233445566778899aabbccddee77 --opc ffeeddccbbaa99887766554433221177 --slice 1 --dnn internet >/dev/null 2>&1
  bash "$root/g5c-diag" --run "$RUN" --lines 5000 --out "$b" >/dev/null 2>&1 && [ -s "$b" ] && ck ok "bundle made" || ck bad "g5c-diag failed"
  d="$RUN/diag-x"; rm -rf "$d"; mkdir -p "$d"; tar -xzf "$b" -C "$d"
  [ -s "$d/g5c-diag/summary.txt" ] && [ -n "$(ls "$d/g5c-diag/log" 2>/dev/null)" ] && [ -n "$(ls "$d/g5c-diag/conf" 2>/dev/null)" ] && ck ok "bundle has the summary, the logs and the configurations" || ck bad "bundle is incomplete"
  n="$(cat "$d"/g5c-diag/metrics/* 2>/dev/null | grep -c "^g5c_build_info")"
  [ "$n" -ge 10 ] && ck ok "metrics of $n functions with their version (g5c_build_info)" || ck bad "metrics of only $n functions"
  grep -q "$(cat "$HERE/../../VERSION")" "$d/g5c-diag/log/amf.log" && ck ok "the log names the release version" || ck bad "no version in the log"
  # the original log has subscribers; the bundle must not
  n="$(grep -c "imsi-0010100000" "$RUN/log/amf.log")"
  [ "$n" -gt 0 ] && ck ok "(the log itself has $n lines with an IMSI)" || ck bad "no IMSI in the log to redact: the check proves nothing"
  n="$(grep -rIl -e "imsi-0010100000" -e "imsi-001019999999977" "$d/g5c-diag" 2>/dev/null | wc -l)"
  [ "$n" = 0 ] && ck ok "no IMSI in the bundle" || ck bad "an IMSI is in $n file(s) of the bundle"
  for name in master.key ausf-master.key admin_token udr-provisioning.token hn-1.key nef-af-1.token; do
    v="$(cat "$RUN/keys/$name" 2>/dev/null)"; [ -n "$v" ] || continue
    n="$(grep -rIl -F -e "$v" "$d/g5c-diag" 2>/dev/null | wc -l)"
    [ "$n" = 0 ] && ck ok "$name is not in the bundle" || ck bad "$name is in $n file(s) of the bundle"
  done
  n="$(grep -rIl -e "00112233445566778899aabbccddee77" -e "ffeeddccbbaa99887766554433221177" "$d/g5c-diag" 2>/dev/null | wc -l)"
  [ "$n" = 0 ] && ck ok "K and OPc of the provisioned subscriber are not in the bundle" || ck bad "K / OPc in the bundle"
  n="$(find "$d" -name "*.key" -o -name "state" -o -name "*-state.json" | wc -l)"
  [ "$n" = 0 ] && ck ok "no key file and no state file in the bundle" || ck bad "$n key / state file(s) in the bundle"
  bash "$root/g5c-capture" core --print | grep -q 38412 && bash "$root/g5c-capture" n4 --print | grep -q 8805 && ck ok "the capture helper builds the filters of N2, N3, N4 and the SBI" || ck bad "g5c-capture"
  if [ "$f" = 0 ]; then echo "support: PASS"; else echo "support: FAIL"; fi
  return "$f"
}

load_env() {
  export G5C_LOAD_REMOTE=1 G5C_LOAD_AMF_NGAP="$A_AMF:38412" G5C_LOAD_UDM="$SCH://$A_UDM:7773" G5C_LOAD_AMF_SBI="$(sbi_of amf)" \
         G5C_LOAD_SMF_SBI="$(sbi_of smf)" G5C_LOAD_UPF_SBI="$(sbi_of upf)" G5C_LOAD_CHECK_MEM=0 # the load process is not what is measured
}

# reload FUNCTION [FROM TO]: replace the text FROM by TO in the function's configuration (when given), send it SIGHUP and print the line of the log that says what became of the configuration
cmd_reload() {
  local nf="${1:?function}" from="${2:-}" to="${3:-}" f="$RUN/conf/${1}.yaml" log="$RUN/log/${1}.log" before pid i
  [ -f "$f" ] || { echo "reload: no configuration for $nf in $RUN/conf" >&2; return 1; }
  if [ -n "$from" ]; then
    grep -qF -- "$from" "$f" || { echo "reload: '$from' is not in $f" >&2; return 1; }
    python3 -c 'import sys; p, a, b = sys.argv[1:4]; t = open(p).read(); open(p, "w").write(t.replace(a, b, 1))' "$f" "$from" "$to" || return 1
  fi
  pid="$(pid_of "$nf")"; [ -n "$pid" ] || { echo "reload: $nf is not running" >&2; return 1; }
  before="$(grep -c 'SIGHUP: configuration' "$log")"
  kill -HUP "$pid" || return 1
  for i in $(seq 1 100); do
    [ "$(grep -c 'SIGHUP: configuration' "$log")" -gt "$before" ] && break
    sleep 0.1
  done
  grep 'SIGHUP: configuration' "$log" | tail -1
}

do_load() {
  local ues="${1:-200}" gnbs="${2:-16}" waves="${3:-1}"
  load_env
  echo "RSS before: $(cmd_rss)" >&2
  if [ "${G5C_LOAD_PROCESSES:-1}" -gt 1 ] 2>/dev/null; then # B-03: the population is `processes` load processes of `ues` UEs each, with disjoint IMSI ranges (tools/cli/g5c-fanout)
    python3 "$HERE/../../tools/cli/g5c-fanout" run --load-bin "$LOAD" --processes "$G5C_LOAD_PROCESSES" --ues "$ues" --gnbs "$gnbs" >&2
  else
    G5C_LOAD_UES="$ues" G5C_LOAD_GNBS="$gnbs" G5C_LOAD_WAVES="$waves" G5C_LOAD_WAVE_HOOK="$0 rss" "$LOAD" >&2
  fi
  local rc=$?
  echo "RSS after:  $(cmd_rss)" >&2
  if [ "${G5C_AMF_NSSF:-1}" = 1 ] && [ -z "${G5C_LOAD_STORM_SECONDS:-}" ]; then # a storm leaves the admitted UEs unfinished: nothing reaches the NSSF
    local nok nun
    nok="$(gauge "$(sbi_of amf)" 'g5c_amf_nssf_selections_total{result="ok"}')"; nun="$(gauge "$(sbi_of amf)" 'g5c_amf_nssf_selections_total{result="unavailable"}')"
    echo "AMF slice selections by the NSSF: ok=${nok:-0} unavailable=${nun:-0}" >&2
    # every registration of the run must have been decided by the NSSF; a run where the AMF never asked it is not the configuration under test
    [ "${nok:-0}" -gt 0 ] 2>/dev/null || { echo "load: FAIL: the AMF did not use the NSSF" >&2; rc=1; }
  fi
  cmd_status >&2
  echo $rc
}

# the cluster is up; kill and restart NFs at random while the load runs, then require a clean wave
do_chaos() {
  local ues="${1:-200}" secs="${2:-40}" gnbs="${G5C_CHAOS_GNBS:-8}" victims=(upf smf amf udm pcf ausf udr) n=0
  [ "$DISCOVERY" = 1 ] && victims+=(nrf nrf)
  load_env
  G5C_LOAD_UES="$ues" G5C_LOAD_GNBS="$gnbs" G5C_LOAD_CHAOS_SECONDS="$secs" "$LOAD" &
  local lp=$!
  sleep 3
  local end=$((SECONDS + secs - 4))
  while [ $SECONDS -lt $end ]; do
    local v="${victims[$((RANDOM % ${#victims[@]}))]}"
    echo "chaos: kill -9 $v"; kill -9 "$(cat "$(pidfile "$v")")" 2>/dev/null; rm -f "$(pidfile "$v")"
    sleep 1
    start_nf "$v" >/dev/null || echo "chaos: $v did not restart"
    n=$((n+1))
    sleep $((2 + RANDOM % 3))
  done
  wait "$lp"
  echo "chaos: $n kills; waiting for the cluster to settle"
  for nf in $NFS; do alive "$nf" || start_nf "$nf"; done
  sleep 12   # heartbeats and recovery timers (UPF loss detection, SMF re-association)
  cmd_status
  # recovery proof: a clean wave with new subscribers must pass in every detail
  echo "chaos: recovery wave"
  G5C_LOAD_BASE=500000 G5C_LOAD_UES=100 G5C_LOAD_GNBS=8 G5C_LOAD_WAVES=1 G5C_LOAD_CHAOS_SECONDS= "$LOAD"
  local rc=$?
  [ $rc -eq 0 ] && echo "chaos: RECOVERED" || echo "chaos: NOT RECOVERED"
  return $rc
}

# upgrade and rollback under load: every function is stopped gracefully (SIGTERM) and started again, one at a time, first with the same binaries (the upgrade) and then with a copy of the
# binaries kept as the "previous version" (the rollback), while UEs register and de-register; the state files and the stores must be readable by the function that starts again. A clean
# wave with new subscribers must pass at the end, with no function restarted in between.
do_upgrade() {
  local ues="${1:-200}" secs="${2:-60}" gnbs="${G5C_CHAOS_GNBS:-8}" nf n=0 order="udr udm ausf pcf nssf nef bsf scp smf amf upf nrf" lp
  mkdir -p "$RUN/bin-prev"
  for nf in $NFS; do cp "$(bin_of "$nf")" "$RUN/bin-prev/$nf"; done
  load_env
  G5C_LOAD_UES="$ues" G5C_LOAD_GNBS="$gnbs" G5C_LOAD_CHAOS_SECONDS="$secs" "$LOAD" &
  lp=$!
  sleep 3
  for phase in upgrade rollback; do
    for nf in $order; do
      case " $NFS " in *" $nf "*) ;; *) continue;; esac
      echo "$phase: restarting $nf"
      stop_nf "$nf"
      if [ "$phase" = rollback ]; then G5C_BUILD_DIR= BIN="$RUN/bin-prev" start_nf "$nf" >/dev/null || echo "$phase: $nf did not restart"; else start_nf "$nf" >/dev/null || echo "$phase: $nf did not restart"; fi
      n=$((n+1))
      sleep 2
    done
  done
  wait "$lp"
  echo "upgrade: $n graceful restarts (upgrade and rollback); waiting for the cluster to settle"
  for nf in $NFS; do alive "$nf" || start_nf "$nf"; done
  sleep 12
  cmd_status
  echo "upgrade: verification wave"
  G5C_LOAD_BASE=700000 G5C_LOAD_UES=100 G5C_LOAD_GNBS=8 G5C_LOAD_WAVES=1 G5C_LOAD_CHAOS_SECONDS= "$LOAD"
  local rc=$?
  [ $rc -eq 0 ] && echo "upgrade: PASS" || echo "upgrade: FAIL"
  return $rc
}

# repeated waves for a fixed time; every NF's RSS is sampled after each wave and the last sample must not be far above the second (the first wave
# builds the pools and tables)
do_soak() {
  local ues="${1:-500}" secs="${2:-300}" gnbs="${3:-16}" rc m
  load_env
  : > "$RUN/rss.log"
  G5C_LOAD_UES="$ues" G5C_LOAD_GNBS="$gnbs" G5C_LOAD_SECONDS="$secs" G5C_LOAD_CHECK_MEM=0 G5C_LOAD_WAVE_HOOK="$0 rss >> $RUN/rss.log" "$LOAD" | tail -12
  rc=${PIPESTATUS[0]}
  cmd_status
  [ "$(wc -l < "$RUN/rss.log")" -ge 3 ] || { echo "soak: fewer than three waves ran"; return 1; }
  awk -v check="${G5C_SOAK_CHECK_RSS:-1}" '
    function field(line, nf,   a, n, i, kv) { n = split(line, a, " "); for (i = 1; i <= n; i++) { split(a[i], kv, "="); if (kv[1] == nf) return kv[2] + 0 } return 0 }
    { rows[NR] = $0 }
    END {
      split("nrf udr udm ausf pcf upf smf amf", nfs, " "); bad = 0
      for (i = 1; i <= 8; i++) {
        a = field(rows[2], nfs[i]); b = field(rows[NR], nfs[i])
        printf "soak: %-10s RSS after wave 2 %7d kB, after wave %d %7d kB\n", nfs[i], a, NR, b
        if (b > a * 1.25 + 20480) { printf "soak: %s RSS keeps growing\n", nfs[i]; if (check + 0 != 0) bad = 1 }
      }
      exit bad
    }' "$RUN/rss.log"
  m=$?
  if [ "$rc" -eq 0 ] && [ "$m" -eq 0 ]; then echo "soak: PASS"; else echo "soak: FAIL"; return 1; fi
}

# certs status: the expiry of every certificate;  certs renew: new certificates from the same CA for every function, then SIGHUP to each running one (they read them again, no restart)
cmd_certs() {
  [ "$TLSON" = 1 ] || { echo "certs: this cluster runs without TLS (G5C_TLS=1)"; return 1; }
  case "${1:-status}" in
    status) bash "$HERE/g5c-pki.sh" status "$RUN/pki";;
    renew)
      local nf a p
      for nf in $NFS admin; do
        [ -f "$RUN/pki/$nf.crt" ] || continue
        bash "$HERE/g5c-pki.sh" renew "$RUN/pki" "$nf"
        p="$(pid_of "$nf")"; [ -n "$p" ] && kill -HUP "$p" 2>/dev/null && echo "$nf: new certificate, SIGHUP sent"
      done;;
    revoke)
      bash "$HERE/g5c-pki.sh" revoke "$RUN/pki" "${2:?name}" || return 1
      for nf in $NFS; do p="$(pid_of "$nf")"; [ -n "$p" ] && kill -HUP "$p" 2>/dev/null; done;;
    *) echo "certs status|renew|revoke NAME"; return 2;;
  esac
}

case "${1:-}" in
  certs) shift; cmd_certs "$@";;
  up) cmd_up;;
  down) cmd_down;;
  status) cmd_status;;
  conf) gen_conf; echo "configs in $RUN/conf";;
  url) sbi_of "${2:?function}";;
  load) shift; do_load "$@";;
  impair) shift; cmd_impair "$@";;
  rss) cmd_rss;;
  logs) shift; if [ -n "${1:-}" ]; then tail -F "$RUN/log/$1.log"; else tail -F "$RUN"/log/*.log; fi;;
  conf-once) gen_conf_once; echo "configs in $RUN/conf";;
  run) shift; nf="${1:?nf name}"; gen_conf_once; exec "$(bin_of "$nf")" "$RUN/conf/$nf.yaml";;
  start) shift; start_nf "${1:?nf name}";;
  restart) shift; stop_nf "${1:?nf name}"; start_nf "$1";;
  reload) shift; cmd_reload "$@";;
  logdir) echo "$RUN/log";;
  kill) shift; kill -9 "$(cat "$(pidfile "${1:?nf name}")")"; rm -f "$(pidfile "$1")";;
  ns) shift; cmd_ns "$@";;
  *) sed -n 2,22p "$0"; exit 2;;
esac
