#!/usr/bin/env bash
# The ZMQ demo: the OCUDU gNB and srsUE (srsRAN 4G, 5G SA) talk I/Q over ZeroMQ, the gNB attaches to a 5G core over NGAP / GTP-U, the UE registers, gets a PDU session and an IP
# address, and pings an address of the core through the user plane. Everything runs in an unprivileged user + network namespace (no sudo), the core being Open5GS (CORE=open5gs, the
# baseline that shows the radio side works) or ours (CORE=ours: every function of the core is ours).
#
#   deploy/demo/zmq_demo.sh                run it, keep the namespace up for ${DEMO_HOLD:-0} seconds after the ping, then stop everything
#   CORE=ours deploy/demo/zmq_demo.sh      the same against our core
#
# The binaries and their configuration are the ones of the startup guide: /home/work/ocudu/build/apps/gnb/gnb with /etc/open5gs/gnb.yml, and
# /home/work/srsRAN_4G/build/srsue/src/srsue with /etc/open5gs/ue.conf (read, never changed: the copies this script writes go to $DEMO_HOME).
# Exit status 0 when the UE got an IP address and the ping through the core worked, 1 otherwise, 77 (skipped) when the gNB, the UE or the namespaces are not there.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ORACLE="$ROOT/deploy/oracle/oracle.sh"
CORE="${CORE:-open5gs}"
GNB_BIN="${GNB_BIN:-/home/work/ocudu/build/apps/gnb/gnb}"
UE_BIN="${UE_BIN:-/home/work/srsRAN_4G/build/srsue/src/srsue}"
[ -x "$UE_BIN" ] || UE_BIN=/home/work/srsRAN_4G/build/apps/srsue/srsue
GNB_CONF="${GNB_CONF:-/etc/open5gs/gnb.yml}"
UE_CONF="${UE_CONF:-/etc/open5gs/ue.conf}"
export ORACLE_HOME="${ORACLE_HOME:-$HOME/g5c-oracle}"
DEMO_HOME="${DEMO_HOME:-$ORACLE_HOME/demo}"
TUN_DEV="${ORACLE_TUN:-ogstun5g}"
export ORACLE_TUN="$TUN_DEV"

for f in "$GNB_BIN" "$UE_BIN" "$GNB_CONF" "$UE_CONF"; do [ -e "$f" ] || { echo "SKIP: missing $f (the OCUDU gNB and srsUE of the startup guide)"; exit 77; }; done
unshare -Urn true 2>/dev/null || { echo "SKIP: no user and network namespaces"; exit 77; }
case "$CORE" in
  open5gs) ;;
  ours) export OUR_NRF=1 OUR_AUSF=1 OUR_AMF=1 OUR_UDM=1 OUR_UDR=1 OUR_PCF=1 OUR_UPF=1 OUR_SMF=1 OUR_NSSF=1 OUR_BSF=1
        # DEMO_OAUTH2=1: every function requires the NRF's access token for its services and asks for one (TS 33.501 13.4.1)
        [ "${DEMO_OAUTH2:-0}" = 1 ] && export OUR_OAUTH2=1 ;;
  *) echo "CORE must be open5gs or ours"; exit 2 ;;
esac

# the whole demo in a user + network namespace of its own: root there, TUN devices, a private loopback, a private MongoDB for Open5GS
if [ "${G5C_NETNS:-}" != 1 ]; then
  exec unshare -Urn env G5C_NETNS=1 bash "$0" "$@"
fi
ip link set lo up
mkdir -p "$DEMO_HOME" "$ORACLE_HOME"/{conf,log,run,pcap}
ip tuntap add name "$TUN_DEV" mode tun
ip addr add 10.46.0.1/16 dev "$TUN_DEV"
ip link set "$TUN_DEV" up
sysctl -qw net.ipv4.ip_forward=1
# a host behind the UPF's TUN device, as in the oracle (the UE can ping it as well as the UPF's own address)
unshare -n sleep 100000 & DN_PID=$!
sleep 0.5
ip link add veth0 type veth peer name veth1
ip link set veth1 netns "$DN_PID"
ip addr add 10.99.0.254/24 dev veth0
ip link set veth0 up
nsenter -t "$DN_PID" -n sh -c 'ip link set lo up; ip addr add 10.99.0.1/24 dev veth1; ip link set veth1 up; ip route add 10.46.0.0/16 via 10.99.0.254'
# the UE's namespace: its own, so that its traffic has to go through the radio, the gNB and the core to reach anything; a veth pair carries the ZMQ sockets
unshare -n sleep 100000 & UE_NS_PID=$!
sleep 0.5
ip link add zveth0 type veth peer name zveth1
ip link set zveth1 netns "$UE_NS_PID"
ip addr add 10.77.0.1/24 dev zveth0
ip link set zveth0 up
nsenter -t "$UE_NS_PID" -n sh -c 'ip link set lo up; ip addr add 10.77.0.2/24 dev zveth1; ip link set zveth1 up'
# a private MongoDB: Open5GS reads its subscribers there, and the oracle's provisioning step writes them there for either core
if true; then
  mkdir -p "$ORACLE_HOME/mongo-ns"
  rm -rf "$ORACLE_HOME/mongo-ns"/*
  mongod --dbpath "$ORACLE_HOME/mongo-ns" --bind_ip 127.0.0.1 --port 27017 --nounixsocket --fork --logpath "$ORACLE_HOME/log/mongod-ns.log" >/dev/null
fi

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  "$ORACLE" down >/dev/null 2>&1 || true
  kill "${DN_PID:-}" "${UE_NS_PID:-}" 2>/dev/null || true
  mongod --dbpath "$ORACLE_HOME/mongo-ns" --shutdown >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() { # wait_for <file> <regex> <seconds>
  for _ in $(seq "$3"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 1; done
  echo "TIMEOUT waiting for /$2/ in $1"; return 1
}

# ---- the core -------------------------------------------------------------------------------------------------------------------------------------------------
"$ORACLE" down >/dev/null 2>&1 || true
sleep 1
rm -f "$ORACLE_HOME"/log/*.log "$ORACLE_HOME"/log/*.stdout
"$ORACLE" gen >/dev/null
# the gNB's tracking area is the one of its configuration (the guide's gnb.yml has TAC 7): the AMF of the core has to serve it
TAC="$(sed -n 's/^ *tac: *\([0-9][0-9]*\).*/\1/p' "$GNB_CONF" | tail -1)"
if [ -f "$ORACLE_HOME/conf/amf.yaml" ]; then sed -i -E "s/^( *)tac: *[0-9]+/\1tac: $TAC/" "$ORACLE_HOME/conf/amf.yaml"; fi
if [ -f "$ORACLE_HOME/conf/g5c-amf.yaml" ]; then sed -i -E "s/tais: \[ \{ tac: [0-9]+ \} \]/tais: [ { tac: $TAC } ]/" "$ORACLE_HOME/conf/g5c-amf.yaml"; fi
# The ciphering of the NAS messages. srsUE (srsRAN 4G, 5G SA) cannot decipher them with NEA1/2/3: its cipher_decrypt() (srsue/src/stack/upper/nas_base.cc) takes the sequence number
# from msg[5], which is the last byte of the MAC in a 5G NAS message (the sequence number is msg[6]; msg[5] is where the 4G NAS format has it), so it works only when the two bytes are
# equal. Open5GS's default order is NEA0 first, which is why that never showed. Our AMF prefers NEA2; for this UE it is told to use NEA0 (integrity stays NIA2).
# DEMO_CIPHERING=NEA2 for a UE that implements TS 33.501 (UERANSIM does, the oracle scenarios run NEA2 with it).
DEMO_CIPHERING="${DEMO_CIPHERING:-NEA0}"
if [ -f "$ORACLE_HOME/conf/g5c-amf.yaml" ]; then sed -i -E "s/^( *)tais: (.*)$/\1tais: \2\n\1security: { integrity: [ NIA2 ], ciphering: [ $DEMO_CIPHERING ] }/" "$ORACLE_HOME/conf/g5c-amf.yaml"; fi
"$ORACLE" up >/dev/null
# the subscriber of the UE configuration (IMSI, K and OPc exactly as in ue.conf)
IMSI="$(sed -n 's/^imsi *= *//p' "$UE_CONF" | head -1 | tr -d ' \r')"
K="$(sed -n 's/^k *= *//p' "$UE_CONF" | head -1 | tr -d ' \r')"
OPC="$(sed -n 's/^opc *= *//p' "$UE_CONF" | head -1 | tr -d ' \r')"
if ! "$ORACLE" provision "$IMSI" "$K" "$OPC" > "$DEMO_HOME/provision.log" 2>&1; then echo "provisioning the subscriber failed:"; tail -15 "$DEMO_HOME/provision.log"; exit 1; fi
echo "core: $CORE; subscriber imsi-$IMSI provisioned"

# ---- the gNB: the OCUDU gNB with the configuration of the guide, pointed at this core's AMF; each side binds its own TX socket and connects to the other's (the gNB's at 10.77.0.1, the UE's at 10.77.0.2) -------------------------------------------
sed -E \
  -e 's#^( *addrs:) *127\.0\.0\.5#\1 127.1.0.5#' \
  -e 's#^( *bind_addrs:) *127\.0\.0\.1#\1 127.1.0.100#' \
  -e 's#tx_port=tcp://127\.0\.0\.1:#tx_port=tcp://10.77.0.1:#; s#rx_port=tcp://127\.0\.0\.1:#rx_port=tcp://10.77.0.2:#' \
  -e "s#^( *filename:) */tmp/gnb.log#\1 $DEMO_HOME/gnb.log#" \
  -e "s#^( *mac_filename:) */tmp/gnb_mac.pcap#\1 $DEMO_HOME/gnb_mac.pcap#" \
  -e "s#^( *ngap_filename:) */tmp/gnb_ngap.pcap#\1 $DEMO_HOME/gnb_ngap.pcap#" "$GNB_CONF" > "$DEMO_HOME/gnb.yml"
: > "$DEMO_HOME/gnb.out"
( cd "$DEMO_HOME" && exec stdbuf -oL -eL "$GNB_BIN" -c "$DEMO_HOME/gnb.yml" ) > "$DEMO_HOME/gnb.out" 2>&1 & pids+=($!)
wait_for "$DEMO_HOME/gnb.out" 'gNB started|failed to connect to AMF|NG Setup Procedure.* failed|ERROR' 40 || { tail -20 "$DEMO_HOME/gnb.out"; exit 1; }
if ! grep -q 'gNB started' "$DEMO_HOME/gnb.out"; then echo "the gNB did not come up:"; tail -8 "$DEMO_HOME/gnb.out"; exit 1; fi
echo "gNB: up, NG setup done with the AMF (TAC $TAC)"

# ---- the UE: srsUE in its own namespace, ZMQ over the veth pair --------------------------------------------------------------------------------------------------------------
sed -E \
  -e 's#tx_port=tcp://127\.0\.0\.1:#tx_port=tcp://10.77.0.2:#; s#rx_port=tcp://127\.0\.0\.1:#rx_port=tcp://10.77.0.1:#' \
  -e "s#^( *mac_filename *=) *.*#\1 $DEMO_HOME/ue_mac.pcap#" \
  -e "s#^( *mac_nr_filename *=) *.*#\1 $DEMO_HOME/ue_mac_nr.pcap#" \
  -e "s#^( *nas_filename *=) *.*#\1 $DEMO_HOME/ue_nas.pcap#" \
  -e "s#^( *filename *=) */tmp/ue.log#\1 $DEMO_HOME/ue.log#" "$UE_CONF" > "$DEMO_HOME/ue.conf"
# DEMO_UE_DEBUG=1: the UE logs every NAS message in hex (in the copy of its configuration, never in the original)
if [ "${DEMO_UE_DEBUG:-0}" = 1 ]; then
  sed -i -E 's/^all_level *=.*/all_level = debug/; s/^all_hex_limit *=.*/all_hex_limit = 512/' "$DEMO_HOME/ue.conf"
fi
: > "$DEMO_HOME/ue.out"
nsenter -t "$UE_NS_PID" -n stdbuf -oL -eL "$UE_BIN" "$DEMO_HOME/ue.conf" > "$DEMO_HOME/ue.out" 2>&1 & pids+=($!)
wait_for "$DEMO_HOME/ue.out" 'PDU Session Establishment successful|Network attach successful|PDU Session Reject|Registration reject' 90 || { tail -30 "$DEMO_HOME/ue.out"; exit 1; }
grep -E "Network attach successful|PDU Session Establishment successful|Registration reject|PDU Session Reject" "$DEMO_HOME/ue.out" | head -4
UE_IP="$(grep -oE 'PDU Session Establishment successful\. IP: [0-9.]+' "$DEMO_HOME/ue.out" | grep -oE '[0-9.]+$' | tail -1 || true)"
[ -n "$UE_IP" ] || { echo "the UE did not get an IP address"; tail -30 "$DEMO_HOME/ue.out"; exit 1; }
echo "UE: IP address $UE_IP on tun_srsue"
sleep 1
nsenter -t "$UE_NS_PID" -n ip addr show tun_srsue | sed -n 's/^ *inet /  tun_srsue inet /p'
for net in 10.46.0.0/16 10.99.0.0/24; do nsenter -t "$UE_NS_PID" -n ip route add $net dev tun_srsue 2>/dev/null || true; done

# ---- the ping through the core -------------------------------------------------------------------------------------------------------------------------------------------
rc=0
for target in 10.46.0.1 10.99.0.1; do
  if nsenter -t "$UE_NS_PID" -n ping -c "${PING_COUNT:-5}" -W 2 "$target" > "$DEMO_HOME/ping-$target.txt" 2>&1; then
    echo "ping $target from the UE ($UE_IP): PASS ($(grep -E 'packets transmitted' "$DEMO_HOME/ping-$target.txt" | sed 's/, time.*//'); $(grep -E 'rtt' "$DEMO_HOME/ping-$target.txt"))"
  else
    echo "ping $target from the UE ($UE_IP): FAIL"; cat "$DEMO_HOME/ping-$target.txt"; rc=1
  fi
done
[ "$rc" = 0 ] && echo "ZMQ demo ($CORE core): PASS" || echo "ZMQ demo ($CORE core): FAIL"
[ "${DEMO_HOLD:-0}" -gt 0 ] && sleep "$DEMO_HOLD"
exit "$rc"
