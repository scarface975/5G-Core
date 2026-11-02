#!/usr/bin/env bash
# Drive a UERANSIM UE+gNB against the isolated oracle core and record a golden trace (TEST ONLY).
#   scenario.sh s1      registration + deregistration (no TUN / root needed)
#   scenario.sh s2      registration + PDU session + ping through the UPF + deregistration
#   scenario.sh s3      s2 + PDU session release before deregistration
#   scenario.sh s5      s2 + the gNB releases the UE context (inactivity) and the UE comes back with a service request: ping again
#   scenario.sh s6      s1 + the NEF's northbound APIs for an AF (needs OUR_NEF=1 OUR_UDR=1 OUR_UDM=1 OUR_AMF=1): a traffic influence subscription lands in the
#                       UDR, a monitoring event subscription for the UE reaches the AMF, and the UE's de-registration is reported to the AF
#   scenario.sh s7      s2 + the NEF's AsSessionWithQoS API (needs OUR_NEF=1 OUR_PCF=1; the rest of the core is Open5GS or ours): an AF asks for a QoS for a flow of the UE, the
#                       PCF authorizes it (Npcf_PolicyAuthorization) and has the rule installed at the SMF (Open5GS's or ours), the AF is told it was allocated
#   scenario.sh s8      s2 + the BSF: the PCF (Open5GS's or ours) registered the binding of the PDU session, which the BSF's discovery (ours with OUR_BSF=1, else Open5GS's)
#                       finds by the UE's address while the session is up, and no longer after it was released
#   scenario.sh s4      s2 + a policy change while the session is up (needs OUR_PCF=1): the PCF throttles the
#                       subscriber and must push the new decision to Open5GS's SMF
# Output: $ORACLE_HOME/pcap/<scenario>-*.pcapng (copy to tests/fixtures/golden/ once reviewed).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ORACLE_HOME="${ORACLE_HOME:-$HOME/g5c-oracle}"
UERANSIM="${UERANSIM_DIR:-$HOME/test-peers/UERANSIM}/build"
IMSI="${IMSI:-001010000000001}"
K="${K:-465B5CE8B199B49FAA5F0A2EE238A6BC}"
OPC="${OPC:-E8ED289DEBA952E4283B54E88E6183CA}"
SCEN="${1:-s1}"

# S2/S3 need TUN devices. Instead of sudo, run the whole scenario in an unprivileged user+network
# namespace (own loopback, own TUN devices, private MongoDB), which also isolates it completely from the host.
if [ "$SCEN" != s1 ] && [ "${G5C_NETNS:-}" != 1 ]; then
  exec unshare -Urn env G5C_NETNS=1 bash "$0" "$@"
fi
if [ "${G5C_NETNS:-}" = 1 ]; then
  ip link set lo up
  ip tuntap add name "${ORACLE_TUN:-ogstun5g}" mode tun
  ip addr add 10.46.0.1/16 dev "${ORACLE_TUN:-ogstun5g}"
  ip link set "${ORACLE_TUN:-ogstun5g}" up
  # emulated data network: a nested netns reachable over a veth pair, routed via the UPF's TUN
  unshare -n sleep 3600 & DN_PID=$!
  sleep 0.5
  ip link add veth0 type veth peer name veth1
  ip link set veth1 netns "$DN_PID"
  ip addr add 10.99.0.254/24 dev veth0
  ip link set veth0 up
  nsenter -t "$DN_PID" -n sh -c 'ip link set lo up; ip addr add 10.99.0.1/24 dev veth1; ip link set veth1 up; ip route add 10.46.0.0/16 via 10.99.0.254'
  sysctl -qw net.ipv4.ip_forward=1
  mkdir -p "$ORACLE_HOME/mongo-ns"
  rm -rf "$ORACLE_HOME/mongo-ns"/*
  mongod --dbpath "$ORACLE_HOME/mongo-ns" --bind_ip 127.0.0.1 --port 27017 --nounixsocket --fork --logpath "$ORACLE_HOME/log/mongod-ns.log" >/dev/null
fi
mkdir -p "$ORACLE_HOME/peers"

gen_peers() {
  local t="${UERANSIM%/build}/config"
  sed -E -e "s/^mcc: .*/mcc: '001'/" -e "s/^mnc: .*/mnc: '01'/" \
         -e 's/^(linkIp|ngapIp|gtpIp): .*/\1: 127.1.0.100/' \
         -e 's/address: 127\.0\.0\.5/address: 127.1.0.5/' "$t/open5gs-gnb.yaml" > "$ORACLE_HOME/peers/gnb.yaml"
  sed -E -e "s/^supi: .*/supi: 'imsi-$IMSI'/" -e "s/^mcc: .*/mcc: '001'/" -e "s/^mnc: .*/mnc: '01'/" \
         -e "s/^key: .*/key: '$K'/" -e "s/^op: .*/op: '$OPC'/" \
         -e 's/^  - 127\.0\.0\.1/  - 127.1.0.100/'           "$t/open5gs-ue.yaml" > "$ORACLE_HOME/peers/ue.yaml"
}

cleanup() {
  [ -n "" ] && kill "" 2>/dev/null || true
  [ -f "$ORACLE_HOME/run/ue.pid" ] && kill "$(cat "$ORACLE_HOME/run/ue.pid")" 2>/dev/null || true
  [ -f "$ORACLE_HOME/run/gnb.pid" ] && kill "$(cat "$ORACLE_HOME/run/gnb.pid")" 2>/dev/null || true
  rm -f "$ORACLE_HOME/run/ue.pid" "$ORACLE_HOME/run/gnb.pid"
  "$HERE/oracle.sh" capture-stop >/dev/null 2>&1 || true
  "$HERE/oracle.sh" down >/dev/null 2>&1 || true
  if [ "${G5C_NETNS:-}" = 1 ]; then kill "${DN_PID:-}" "${UE_NS_PID:-}" 2>/dev/null || true; mongod --dbpath "$ORACLE_HOME/mongo-ns" --shutdown >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

wait_for() {  # wait_for <file> <regex> <seconds>
  for _ in $(seq "$3"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 1; done
  echo "TIMEOUT waiting for /$2/ in $1"; return 1
}

# every scenario starts from a clean oracle with fresh logs (stale SMF/AMF state breaks reruns)
"$HERE/oracle.sh" down >/dev/null 2>&1 || true
sleep 1
rm -f "$ORACLE_HOME"/log/*.log "$ORACLE_HOME"/log/*.stdout
"$HERE/oracle.sh" gen >/dev/null
gen_peers
"$HERE/oracle.sh" up >/dev/null
"$HERE/oracle.sh" provision "$IMSI" "$K" "$OPC" >/dev/null 2>&1
"$HERE/oracle.sh" capture-start "$SCEN"; sleep 1

: > "$ORACLE_HOME/log/gnb.log"; : > "$ORACLE_HOME/log/ue.log"
nohup "$UERANSIM/nr-gnb" -c "$ORACLE_HOME/peers/gnb.yaml" > "$ORACLE_HOME/log/gnb.log" 2>&1 & echo $! > "$ORACLE_HOME/run/gnb.pid"
wait_for "$ORACLE_HOME/log/gnb.log" 'NG Setup procedure is successful' 15
nohup "$UERANSIM/nr-ue" -c "$ORACLE_HOME/peers/ue.yaml" > "$ORACLE_HOME/log/ue.log" 2>&1 & echo $! > "$ORACLE_HOME/run/ue.pid"
wait_for "$ORACLE_HOME/log/ue.log" 'Registration is successful|Registration Reject|registration failed' 20
grep -E "Registration is successful" "$ORACLE_HOME/log/ue.log" && echo "S1 registration: PASS" || { echo "S1 registration: FAIL"; tail -20 "$ORACLE_HOME/log/ue.log"; exit 1; }

if [ "${OUR_OAUTH2:-0}" = 1 ]; then
  # access tokens of the NRF are enforced: a request for a service of one of our functions without one, or with one that is not the NRF's, is refused (the registration above
  # went through only because every function sent a token for every service it called)
  U=http://127.1.0.201:7790/nudr-dr/v1/subscription-data/imsi-$IMSI/authentication-data/authentication-subscription
  c1="$(curl -s -o /dev/null -w '%{http_code}' --http2-prior-knowledge "$U" || true)"
  c2="$(curl -s -o /dev/null -w '%{http_code}' --http2-prior-knowledge -H 'authorization: Bearer aaaa.bbbb.cccc' "$U" || true)"
  [ "$c1" = 401 ] && [ "$c2" = 401 ] && echo "OAuth2 request without a valid access token refused by the UDR: PASS" || echo "OAuth2 request without a valid access token refused by the UDR: FAIL ($c1 $c2)"
fi
if [ "$SCEN" = s2 ] || [ "$SCEN" = s3 ] || [ "$SCEN" = s4 ] || [ "$SCEN" = s5 ] || [ "$SCEN" = s7 ] || [ "$SCEN" = s8 ]; then
  wait_for "$ORACLE_HOME/log/ue.log" 'PDU Session establishment is successful' 20
  grep -E "PDU Session establishment is successful|TUN interface" "$ORACLE_HOME/log/ue.log"
  # traffic goes UE -> gNB (GTP-U N3) -> UPF -> UPF's TUN (10.46.0.1) and back
  # 10.99.0.1 lives in the "data network" namespace behind the UPF's TUN device, so the echo
  # must travel UE -> gNB (GTP-U) -> UPF -> ogstun -> veth -> DN and all the way back.
  # The UE address is local to whatever namespace holds uesimtun0, so replies would never leave through the
  # UPF if the UE TUN shared a namespace with it. Move uesimtun0 into its own namespace first.
  UE_IP="$(grep -oE 'uesimtun0, [0-9.]+' "$ORACLE_HOME/log/ue.log" | tail -1 | grep -oE '[0-9.]+$')"
  unshare -n sleep 3600 & UE_NS_PID=$!
  sleep 0.5
  ip link set uesimtun0 netns "$UE_NS_PID"
  nsenter -t "$UE_NS_PID" -n sh -c "ip link set lo up; ip addr add $UE_IP/24 dev uesimtun0; ip link set uesimtun0 up; ip route add default dev uesimtun0"
  nsenter -t "$UE_NS_PID" -n ping -c 3 -W 2 10.99.0.1 && echo "S2 user plane: PASS" || echo "S2 user plane: FAIL"
  if [ -n "${G5C_DEBUG:-}" ]; then
    ip -s link show ogstun5g | sed -n 1,6p; ip -s link show veth0 | sed -n 1,6p; ip route
    sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.ogstun5g.rp_filter
    nsenter -t "$DN_PID" -n ip -s link show veth1 | sed -n 1,6p
  fi
fi
if [ "$SCEN" = s6 ]; then
  [ "${OUR_NEF:-0}" = 1 ] && [ "${OUR_UDR:-0}" = 1 ] && [ "${OUR_UDM:-0}" = 1 ] && [ "${OUR_AMF:-0}" = 1 ] || { echo "s6 needs OUR_NEF=1 OUR_UDR=1 OUR_UDM=1 OUR_AMF=1"; exit 1; }
  NEF=http://127.1.0.15:7784; UDR=http://127.1.0.201:7790
  AF_SINK="${G5C_C_BUILD:-$HOME/g5c-cbuild}/release/nf/nef/nef_af_sink"
  [ -x "$AF_SINK" ] || { echo "missing $AF_SINK: run scripts/c_install.sh"; exit 1; }
  ptok="$(cat "$ORACLE_HOME/keys/udr-provisioning.token")"
  jh=(-H 'content-type: application/json')
  # the subscriber's external identities (identity data of the UDR: the provisioning extension writes this GET-only resource)
  code="$(curl -s -o /dev/null -w '%{http_code}' --http2-prior-knowledge -X PUT -H "authorization: Bearer $ptok" "${jh[@]}" \
    -d "{\"supiList\":[\"imsi-$IMSI\"],\"gpsiList\":[\"msisdn-491700000001\",\"extid-ue1@example.com\"]}" "$UDR/nudr-dr/v1/subscription-data/imsi-$IMSI/identity-data")"
  case "$code" in 200|201|204) echo "S6 identity data provisioned: PASS";; *) echo "S6 identity data provisioned: FAIL ($code)";; esac
  : > "$ORACLE_HOME/log/af-sink.log"
  "$AF_SINK" 127.1.0.200 9100 "$ORACLE_HOME/log/af-sink.log" & AF_PID=$!
  sleep 0.5
  # traffic influence for any UE of an application: stored as influence data in the UDR
  out="$(curl -s -D - --http2-prior-knowledge -X POST "${jh[@]}" -d '{"afAppId":"app-s6","anyUeInd":true,"dnn":"internet","trafficRoutes":[{"dnai":"edge1","routeProfId":"p1"}]}' "$NEF/3gpp-traffic-influence/v1/af-1/subscriptions")"
  echo "$out" | head -1 | grep -q ' 201' && echo "S6 traffic influence subscription created: PASS" || { echo "S6 traffic influence subscription created: FAIL"; echo "$out" | head -5; }
  curl -s --http2-prior-knowledge "$UDR/nudr-dr/v1/application-data/influenceData" | grep -q app-s6 && echo "S6 traffic influence data in the UDR: PASS" || echo "S6 traffic influence data in the UDR: FAIL"
  # monitoring of the UE's loss of connectivity, by its external identifier
  out="$(curl -s -D - --http2-prior-knowledge -X POST "${jh[@]}" -d '{"externalId":"ue1@example.com","monitoringType":"LOSS_OF_CONNECTIVITY","maximumNumberOfReports":1,"supportedFeatures":"1","notificationDestination":"http://127.1.0.200:9100/notify"}' "$NEF/3gpp-monitoring-event/v1/af-1/subscriptions")"
  echo "$out" | head -1 | grep -q ' 201' && echo "S6 monitoring event subscription created: PASS" || { echo "S6 monitoring event subscription created: FAIL"; echo "$out" | head -8; }
fi
if [ "$SCEN" = s5 ]; then
  # idle mode: the gNB asks for the UE context release (UE inactivity), the AMF deactivates the session at the SMF; the UE's next uplink packet makes it
  # send a service request, which the AMF accepts with a context setup that re-establishes the user plane
  "$UERANSIM/nr-cli" UERANSIM-gnb-1-1-1 --exec "ue-release 1" || true
  sleep 2
  nsenter -t "$UE_NS_PID" -n ping -c 5 -W 2 10.99.0.1 && echo "S5 user plane after idle mode: PASS" || echo "S5 user plane after idle mode: FAIL"
  grep -ciE "service request|service accept" "$ORACLE_HOME/log/ue.log" || true
fi
if [ "$SCEN" = s7 ]; then
  [ "${OUR_NEF:-0}" = 1 ] && [ "${OUR_PCF:-0}" = 1 ] || { echo "s7 needs OUR_NEF=1 OUR_PCF=1"; exit 1; }
  NEF=http://127.1.0.15:7784
  AF_SINK="${G5C_C_BUILD:-$HOME/g5c-cbuild}/release/nf/nef/nef_af_sink"
  [ -x "$AF_SINK" ] || { echo "missing $AF_SINK: run scripts/c_install.sh"; exit 1; }
  : > "$ORACLE_HOME/log/af-sink.log"
  "$AF_SINK" 127.1.0.200 9100 "$ORACLE_HOME/log/af-sink.log" & AF_PID=$!
  sleep 0.5
  body="{\"ueIpv4Addr\":\"$UE_IP\",\"qosReference\":\"voice\",\"flowInfo\":[{\"flowId\":1,\"flowDescriptions\":[\"permit out 17 from $UE_IP 5004 to 10.99.0.1 5004\"]}],\"supportedFeatures\":\"2\",\"notificationDestination\":\"http://127.1.0.200:9100/notify\"}"
  out="$(curl -s -D - --http2-prior-knowledge -X POST -H 'content-type: application/json' -d "$body" "$NEF/3gpp-as-session-with-qos/v1/af-1/subscriptions")"
  echo "$out" | head -1 | grep -q ' 201' && echo "S7 AS session with QoS created: PASS" || { echo "S7 AS session with QoS created: FAIL"; echo "$out" | head -8; }
  loc="$(echo "$out" | tr -d '\r' | grep -i '^location:' | head -1 | sed 's/^[^:]*: *//')"
  # With our BSF the NEF finds the PCF of the UE address there, not by asking the NRF for any PCF. Open5GS's BSF registers allowedNfTypes [SCP, PCF, AF] (TS 29.521 4.1.2
  # lists the NEF among the consumers), so Open5GS's NRF does not discover it for our NEF and the NEF takes the PCF from the NRF.
  if [ "${OUR_BSF:-0}" = 1 ]; then
    curl -s --http2-prior-knowledge "$NEF/metrics" | grep -qE 'g5c_nef_bsf_discoveries_total\{result="binding"\} [1-9]' && echo "S7 PCF of the UE address found through the BSF: PASS" || echo "S7 PCF of the UE address found through the BSF: FAIL"
  fi
  wait_for "$ORACLE_HOME/log/af-sink.log" 'SUCCESSFUL_RESOURCES_ALLOCATION' 10 && echo "S7 allocation of the QoS notified to the AF (the SMF accepted the PCC rule): PASS" || { echo "S7 allocation of the QoS notified to the AF: FAIL"; cat "$ORACLE_HOME/log/af-sink.log"; }
  nsenter -t "$UE_NS_PID" -n ping -c 2 -W 2 10.99.0.1 >/dev/null && echo "S7 user plane after the QoS rule: PASS" || echo "S7 user plane after the QoS rule: FAIL"
  if [ -n "$loc" ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --http2-prior-knowledge -X DELETE "$loc")"
    [ "$code" = 204 ] && echo "S7 AS session with QoS deleted: PASS" || echo "S7 AS session with QoS deleted: FAIL ($code)"
  fi
  kill "$AF_PID" 2>/dev/null || true
fi
if [ "$SCEN" = s8 ]; then
  # Nbsf_Management_Discovery for the UE's address: the PCF registers the binding when the SM policy association is created and removes it when it ends
  BSF=http://127.1.0.15:7777; if [ "${OUR_BSF:-0}" = 1 ]; then BSF=http://127.1.0.17:7786; fi
  q() { curl -s -o "$ORACLE_HOME/log/bsf-answer.json" -w '%{http_code}' --http2-prior-knowledge "$BSF/nbsf-management/v1/pcfBindings?ipv4Addr=$UE_IP" || true; }
  if [ "${OUR_OAUTH2:-0}" = 1 ] && [ "${OUR_BSF:-0}" = 1 ]; then
    # the BSF takes only requests with an access token of the NRF (and this script is no registered function): its own count of the bindings tells the same, as 200 / 204
    q() { n="$(curl -s --http2-prior-knowledge "$BSF/metrics" | sed -n 's/^g5c_bsf_bindings \([0-9][0-9]*\)$/\1/p')"; echo '{"dnn":"internet","pcfIpEndPoints":[]}' > "$ORACLE_HOME/log/bsf-answer.json"; if [ "${n:-0}" -ge 1 ]; then echo -n 200; else echo -n 204; fi; }
  fi
  code=000
  for _ in 1 2 3 4 5 6 7 8 9 10; do code="$(q)"; [ "$code" = 200 ] && break; sleep 1; done
  [ "$code" = 200 ] && echo "S8 binding of the PDU session found at the BSF: PASS" || { echo "S8 binding of the PDU session found at the BSF: FAIL ($code)"; }
  if [ "$code" = 200 ]; then
    cat "$ORACLE_HOME/log/bsf-answer.json"; echo
    grep -q '"dnn":"internet"' "$ORACLE_HOME/log/bsf-answer.json" && grep -qE 'pcfFqdn|pcfIpEndPoints' "$ORACLE_HOME/log/bsf-answer.json" && echo "S8 binding names the DNN and the PCF: PASS" || echo "S8 binding names the DNN and the PCF: FAIL"
  fi
  "$UERANSIM/nr-cli" "imsi-$IMSI" --exec "ps-release 1" || true
  # UERANSIM asks for a new PDU session a moment after the release: the binding of the released one has to be seen gone before that, so poll quickly
  code=000
  for _ in $(seq 1 150); do code="$(q)"; if [ "$code" = 204 ] || [ "$code" = 404 ]; then break; fi; sleep 0.1; done
  { [ "$code" = 204 ] || [ "$code" = 404 ]; } && echo "S8 binding gone from the BSF after the PDU session release: PASS ($code)" || echo "S8 binding gone from the BSF after the PDU session release: FAIL ($code)"
fi
if [ "$SCEN" = s4 ]; then
  [ "$OUR_PCF" = 1 ] || { echo "s4 needs OUR_PCF=1"; exit 1; }
  tok="$(cat "$ORACLE_HOME/keys/admin_token")"
  SMF_LOG="$ORACLE_HOME/log/smf.log"; [ "${OUR_SMF:-0}" = 1 ] && SMF_LOG="$ORACLE_HOME/log/g5smf.stdout"
  : > "$ORACLE_HOME/log/smf.mark"; wc -l < "$SMF_LOG" > "$ORACLE_HOME/log/smf.mark"
  out="$(curl -s --http2-prior-knowledge -X PUT -H "authorization: Bearer $tok" -H 'content-type: application/json' \
    -d '{"default":{"session_ambr":{"uplink":"2 Mbps","downlink":"4 Mbps"},"pcc_rules":[{"id":"video","flows":["permit out 17 from any to assigned"],"qi5":7}]}}' "http://127.1.0.13:7777/admin/v1/policies/imsi-$IMSI")"
  echo "PCF admin answer: $out"
  sleep 2
  echo "--- SMF log after the policy push:"
  tail -n +"$(( $(cat "$ORACLE_HOME/log/smf.mark") + 1 ))" "$SMF_LOG" | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-200 | head -12
  echo "$out" | grep -q '"notifiedSessions":1' && echo "S4 policy push accepted by the SMF: PASS" || echo "S4 policy push: FAIL"
  # the session must keep working after the policy change
  ip netns >/dev/null 2>&1; nsenter -t "$UE_NS_PID" -n ping -c 2 -W 2 10.99.0.1 >/dev/null && echo "S4 user plane after policy change: PASS" || echo "S4 user plane after policy change: FAIL"
fi
if [ "$SCEN" = s3 ]; then
  "$UERANSIM/nr-cli" "imsi-$IMSI" --exec "ps-release 1" || true
  wait_for "$ORACLE_HOME/log/ue.log" 'PDU Session Release Command received' 10 && echo "S3 PDU session release: PASS" || echo "S3 PDU session release: FAIL"
fi
sleep 1
"$UERANSIM/nr-cli" "imsi-$IMSI" --exec "deregister normal" || true
sleep 2
if [ "$SCEN" = s6 ]; then
  wait_for "$ORACLE_HOME/log/af-sink.log" 'LOSS_OF_CONNECTIVITY' 10 && grep -q '"lossOfConnectReason":6' "$ORACLE_HOME/log/af-sink.log" && echo "S6 de-registration notified to the AF: PASS" || { echo "S6 de-registration notified to the AF: FAIL"; cat "$ORACLE_HOME/log/af-sink.log"; }
  kill "$AF_PID" 2>/dev/null || true
fi
chmod a+r "$ORACLE_HOME"/pcap/"$SCEN"-*.pcapng 2>/dev/null || true
if [ "$SCEN" = s4 ] && [ "${OUR_SMF:-0}" = 1 ]; then
  # our SMF turned the policy change into a PDU session modification: the AMF must have sent the gNB a PDUSessionResourceModifyRequest (NGAP procedure 26).
  # UERANSIM's gNB does not answer it (the simulator has no modification handling), so the request itself is the evidence.
  sleep 1
  cap="$(ls -t "$ORACLE_HOME"/pcap/s4-*.pcapng | head -1)"
  python3 "$(cd "$(dirname "$0")/../.." && pwd)/tools/gen/pcap_ngap_to_hex.py" "$cap" 2>/dev/null | grep -qE ' 001a'     && echo "S4 PDU session modification reached the gNB (NGAP PDUSessionResourceModifyRequest): PASS"     || echo "S4 PDU session modification reached the gNB: FAIL"
fi
ls -l "$ORACLE_HOME"/pcap/"$SCEN"-*.pcapng | tail -1
