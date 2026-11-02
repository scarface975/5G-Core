#!/usr/bin/env bash
# The host demo of docs/demo/host-demo.md, run without sudo: the same commands, each in the place of one of the terminals, inside a private user + network + mount namespace that stands
# in for the host (root there, so the commands that need sudo on the host run as they do under sudo). It starts the functions one by one, provisions the subscriber, starts the
# OCUDU gNB and srsUE exactly as the guide does (gnb.yml and ue.conf unchanged), and pings from the UE's namespace.
#   deploy/demo/host_selftest.sh            exit status 0 when the ping crossed the radio, the gNB and the core; 77 when the gNB or srsUE is not there
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEMO="$HERE/g5c-demo"
GNB_BIN="${GNB_BIN:-/home/work/ocudu/build/apps/gnb/gnb}"
UE_BIN="${UE_BIN:-/home/work/srsRAN_4G/build/srsue/src/srsue}"
GNB_CONF="${GNB_CONF:-/etc/open5gs/gnb.yml}"
UE_CONF="${UE_CONF:-/etc/open5gs/ue.conf}"
for f in "$GNB_BIN" "$UE_BIN" "$GNB_CONF" "$UE_CONF" "$HOME/.cache/g5c-bin/bin/amf"; do [ -e "$f" ] || { echo "SKIP: missing $f"; exit 77; }; done
if [ "${G5C_NETNS:-}" != 1 ]; then
  unshare -Urnm true 2>/dev/null || { echo "SKIP: no user, network and mount namespaces"; exit 77; }
  exec unshare -Urnm env G5C_NETNS=1 G5C_HOME="$HOME" bash "$0" "$@"
fi
ip link set lo up
mount -t tmpfs tmpfs /run && mkdir -p /run/netns   # ip netns keeps its namespaces here
T="$(mktemp -d /tmp/g5c-hostdemo-XXXXXX)"
export G5C_RUN="$T/run"
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  sleep 1
  pkill -f "$T/" 2>/dev/null || true # the functions run as children of a pipeline (| tee), so killing the recorded pid leaves them: they carry this run's directory in their command line
  # KEEP_LOGS=dir: what each terminal printed, to look at afterwards
  if [ -n "${KEEP_LOGS:-}" ]; then mkdir -p "$KEEP_LOGS" && cp "$T"/term-*.log "$T"/ping*.txt "$KEEP_LOGS"/ 2>/dev/null || true; fi
  rm -rf "$T"
}
trap cleanup EXIT
wait_for() { for _ in $(seq "$3"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 1; done; echo "TIMEOUT waiting for /$2/ in $1"; tail -5 "$1"; return 1; }

if [ -n "${DEMO_PCAP:-}" ] && command -v tshark >/dev/null 2>&1; then # DEMO_PCAP=file: a capture of everything on the loopback of the namespace, as with tshark on the host
  tshark -q -i any -w "$DEMO_PCAP" >/dev/null 2>&1 & pids+=($!)
  sleep 1
fi
echo "--- terminal: sudo g5c-demo net"
bash "$DEMO" net | sed 's/^/    /'
# one terminal per function, in the order of the guide: the NRF first
for nf in nrf scp udr udm ausf pcf nssf nef smf upf amf; do
  bash "$DEMO" "$nf" > "$T/term-$nf.log" 2>&1 & pids+=($!)
  wait_for "$T/term-$nf.log" 'SBI listening|N2 \(SCTP\) listening|PFCP|listening' 20 || exit 1
  echo "--- terminal: sudo g5c-demo $nf  ($(grep -m1 -E 'SBI listening|listening' "$T/term-$nf.log" | sed 's/^[^ ]* *//' | cut -c1-90))"
done
sleep 2
echo "--- terminal: sudo g5c-demo provision"
bash "$DEMO" provision || exit 1
bash "$DEMO" check | sed 's/^/    /'

echo "--- terminal: sudo $GNB_BIN -c $GNB_CONF"
( cd "$T" && exec stdbuf -oL -eL "$GNB_BIN" -c "$GNB_CONF" ) > "$T/term-gnb.log" 2>&1 & pids+=($!)
wait_for "$T/term-gnb.log" 'gNB started|failed to connect|NG Setup Procedure.* failed' 40 || exit 1
grep -q 'gNB started' "$T/term-gnb.log" || { echo "the gNB did not come up"; tail -5 "$T/term-gnb.log"; exit 1; }
echo "    gNB started; AMF log: $(grep -m1 'NG Setup' "$T/term-amf.log" | sed 's/^[^ ]* *//' | cut -c1-100)"

echo "--- terminal: sudo $UE_BIN $UE_CONF --gw.netns=ue1"
stdbuf -oL -eL "$UE_BIN" "$UE_CONF" --gw.netns=ue1 > "$T/term-ue.log" 2>&1 & pids+=($!)
wait_for "$T/term-ue.log" 'PDU Session Establishment successful|PDU Session Reject|Registration reject' 90 || exit 1
grep -E 'RRC Connected|Network attach successful|PDU Session Establishment successful' "$T/term-ue.log" | sed 's/^/    /'
grep -q 'PDU Session Establishment successful' "$T/term-ue.log" || { echo "no PDU session"; tail -20 "$T/term-ue.log"; exit 1; }
sleep 2

echo "--- terminal: sudo g5c-demo ping"
rc=0
bash "$DEMO" ping -c 5 10.45.0.1 > "$T/ping.txt" 2>&1 || rc=1
sed 's/^/    /' "$T/ping.txt"
if [ "${DEMO_RENEW:-1}" = 1 ]; then # the certificates of all functions are replaced while the UE is attached (SIGHUP, no restart): the ping keeps working
  echo "--- certificates renewed while running: certs renew"
  G5C_TLS=1 bash "$HERE/../run/g5c-cluster.sh" certs renew | sed 's/^/    /' | tail -3
  sleep 2
  bash "$DEMO" ping -c 3 10.45.0.1 > "$T/ping-renew.txt" 2>&1 || rc=1
  tail -2 "$T/ping-renew.txt" | sed 's/^/    /'
  n=0; for f in "$T"/term-*.log; do grep -q "certificates reloaded" "$f" && n=$((n + 1)); done
  if [ "$n" -ge 11 ]; then echo "    $n functions reloaded their certificates"; else echo "    FAIL: only $n functions reloaded"; rc=1; fi
fi
if [ "${DEMO_REATTACH:-0}" = 1 ]; then # the UE is stopped (Ctrl+C in its terminal) and started again: it registers again and the ping works again
  echo "--- the UE and the gNB are stopped (Ctrl+C in their terminals) and started again, the gNB first (srsRAN's ZeroMQ radio does not recover when one side restarts alone)"
  pkill -x srsue; pkill -x gnb; sleep 3
  ( cd "$T" && exec stdbuf -oL -eL "$GNB_BIN" -c "$GNB_CONF" ) > "$T/term-gnb2.log" 2>&1 & pids+=($!)
  wait_for "$T/term-gnb2.log" 'gNB started|failed to connect|NG Setup Procedure.* failed' 40 || exit 1
  stdbuf -oL -eL "$UE_BIN" "$UE_CONF" --gw.netns=ue1 > "$T/term-ue2.log" 2>&1 & pids+=($!)
  wait_for "$T/term-ue2.log" 'PDU Session Establishment successful|PDU Session Reject|Registration reject' 90 || exit 1
  grep -E 'PDU Session Establishment successful' "$T/term-ue2.log" | sed 's/^/    /'
  sleep 2
  bash "$DEMO" ping -c 5 10.45.0.1 > "$T/ping2.txt" 2>&1 || rc=1
  sed 's/^/    /' "$T/ping2.txt" | tail -3
  # the first session ended when the UE attached again (replaced by the new establishment): its charging record has the octets of the first pings
  CDR="$G5C_RUN/state/cdr.jsonl"
  for _ in $(seq 20); do [ -s "$CDR" ] && break; sleep 1; done
  if [ -s "$CDR" ] && grep -q '"usageReported":true' "$CDR" && ! grep -q '"uplinkOctets":0,' "$CDR"; then
    echo "    charging record: $(head -1 "$CDR" | sed -E 's/.*"duration":([0-9]+).*"uplinkOctets":([0-9]+),"downlinkOctets":([0-9]+).*"closeCause":"([^"]*)".*/duration \1 s, uplink \2 octets, downlink \3 octets, closed: \4/')"
  else
    echo "    FAIL: no charging record with traffic ($(head -c 300 "$CDR" 2>/dev/null))"; rc=1
  fi
fi
echo "--- terminal: sudo g5c-demo status"
bash "$DEMO" status | sed 's/^/    /'
[ "$rc" = 0 ] && echo "host demo (simulated host): PASS" || echo "host demo (simulated host): FAIL"
[ "${DEMO_HOLD:-0}" -gt 0 ] && sleep "$DEMO_HOLD"
exit "$rc"
