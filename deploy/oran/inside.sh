#!/usr/bin/env bash
# Runs inside the cluster namespace with the core up (started by deploy/oran/prove.sh through `g5c-cluster.sh ns exec`): provisions the subscribers the ORAN emulator's tests use,
# runs the emulator's N2 test drivers against our AMF, and checks what our own functions counted. Exit 0 only when every driver and every cross-check passed.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/../.."
ORAN="${ORAN_EMULATOR:?ORAN_EMULATOR must name the oran/ directory of the emulator}"
N2="$ORAN/build-n2"
RUN="${G5C_RUN:?}"
CURLF="${G5C_CURL:---http2-prior-knowledge}"
CTL="${G5C_CTL:-${G5C_BUILD_DIR:+$G5C_BUILD_DIR/ctl/g5c-ctl}}"
[ -x "$CTL" ] || CTL="$HOME/.cache/g5c-bin/bin/g5c-ctl"
UDM="${G5C_UDM_URL:-http://127.2.0.1:7773}"
AMF_SBI="${G5C_AMF_SBI:-http://127.0.0.5:7777}"
SMF_SBI="${G5C_SMF_SBI:-http://127.2.0.4:7776}"
UPF_SBI="${G5C_UPF_SBI:-http://127.2.0.7:9091}"
OUT="${PROVE_OUT:-$RUN/oran-proof}"
MULTI="${PROVE_UES:-16}"
mkdir -p "$OUT"
fail=0
say() { printf '%s\n' "$*" | tee -a "$OUT/report.txt"; }
ck() { if [ "$1" = ok ]; then say "  PASS  $2"; else say "  FAIL  $2"; fail=1; fi; }
metric() { curl -s --max-time 5 $CURLF "$1/metrics" | awk -v n="$2" '$1==n || index($1, n"{")==1 {s+=$NF} END{printf "%d", s}'; }
: > "$OUT/report.txt"

say "ORAN emulator against the g5c core"
say "  emulator: $ORAN"
for t in n2_attach_test n2_register_test n2_session_test n2_teardown_test n2_multi_test; do [ -x "$N2/$t" ] || { say "  FAIL  $N2/$t is not built (make -f tools/Makefile.n2 in the emulator)"; exit 2; }; done

# the subscribers of the emulator: IMSI 999700000000001..N, the K and OPc of its provisioning script
total=$((MULTI + 4))
for i in $(seq 0 $((total - 1))); do
  supi="imsi-$((999700000000001 + i))"
  "$CTL" --udm "$UDM" --token-file "$RUN/keys/admin_token" subscriber add --supi "$supi" --k 465B5CE8B199B49FAA5F0A2EE238A6BC --opc E8ED289DEBA952E4283B54E88E6183CA --slice 1 --dnn internet >/dev/null 2>&1 || { say "  FAIL  provisioning $supi"; exit 2; }
done
say "  $total subscribers provisioned (PLMN 999/70, K and OPc of the emulator's provisioning script)"

reg0=$(metric "$AMF_SBI" g5c_amf_registrations_total)
sess0=$(metric "$SMF_SBI" g5c_smf_sm_context_requests_total)

say ""
say "1. NG Setup (n2_attach_test)"
( cd "$ORAN" && timeout 60 "$N2/n2_attach_test" 127.0.0.5 38412 1 ) > "$OUT/attach.log" 2>&1 && ck ok "NG Setup accepted by our AMF" || { ck bad "NG Setup"; tail -5 "$OUT/attach.log" | sed 's/^/        /' | tee -a "$OUT/report.txt"; }

say "2. Registration with 5G-AKA and security mode (n2_register_test)"
( cd "$ORAN" && timeout 90 "$N2/n2_register_test" 999700000000001 ) > "$OUT/register.log" 2>&1 && ck ok "UE registered: authentication, security mode, registration accept" || { ck bad "registration"; tail -8 "$OUT/register.log" | sed 's/^/        /' | tee -a "$OUT/report.txt"; }

say "3. PDU session and a GTP-U frame through our UPF (n2_session_test)"
( cd "$ORAN" && timeout 90 "$N2/n2_session_test" 999700000000002 "$OUT/gtpu.pcap" ) > "$OUT/session.log" 2>&1 && ck ok "PDU session established, GTP-U frame sent" || { ck bad "PDU session"; tail -8 "$OUT/session.log" | sed 's/^/        /' | tee -a "$OUT/report.txt"; }

say "4. Release and de-registration (n2_teardown_test)"
( cd "$ORAN" && timeout 90 "$N2/n2_teardown_test" 999700000000003 ) > "$OUT/teardown.log" 2>&1 && ck ok "PDU session released, UE de-registered, contexts gone" || { ck bad "teardown"; tail -8 "$OUT/teardown.log" | sed 's/^/        /' | tee -a "$OUT/report.txt"; }

command -v tcpdump >/dev/null 2>&1 && { tcpdump -Z root -i lo -U -w "$OUT/n3.pcap" udp port 2152 >/dev/null 2>&1 & TCPD=$!; sleep 0.5; }
say "5. $MULTI UEs at once over one association, with ICMP echo through the UPF (n2_multi_test)"
( cd "$ORAN" && timeout 180 "$N2/n2_multi_test" "$MULTI" 999700000000005 10.45.0.1 ) > "$OUT/multi.log" 2>&1 && ck ok "$MULTI UEs registered, sessions up, echo answered per UE" || { ck bad "multi-UE"; tail -12 "$OUT/multi.log" | sed 's/^/        /' | tee -a "$OUT/report.txt"; }

say ""
for nf in amf:$AMF_SBI smf:$SMF_SBI upf:$UPF_SBI; do curl -s --max-time 5 $CURLF "${nf#*:}/metrics" > "$OUT/${nf%%:*}-metrics.txt"; done
[ -n "${TCPD:-}" ] && { sleep 0.5; kill "$TCPD" 2>/dev/null; }
say "What our own functions counted"
reg1=$(metric "$AMF_SBI" g5c_amf_registrations_total)
acc=$(curl -s --max-time 5 $CURLF "$AMF_SBI/metrics" | awk '/^g5c_amf_registrations_total\{.*result="accepted"/ {s+=$NF} END{printf "%d", s}')
rej=$(curl -s --max-time 5 $CURLF "$AMF_SBI/metrics" | awk '/^g5c_amf_registrations_total\{.*result="rejected"/ {s+=$NF} END{printf "%d", s}')
ues=$(metric "$AMF_SBI" g5c_amf_registered_ues)
sessions=$(metric "$SMF_SBI" g5c_smf_pdu_sessions_active)
fwd=$(curl -s --max-time 5 $CURLF "$UPF_SBI/metrics" | awk '/^g5c_upf_.*(forwarded|packets)/ && !/dropped/ {s+=$NF} END{printf "%d", s}')
say "  registrations accepted $acc, rejected $rej; UEs still registered $ues; PDU sessions still held $sessions; UPF packet counters $fwd"
[ "$acc" -ge $((MULTI + 3)) ] && ck ok "the AMF accepted at least $((MULTI + 3)) registrations ($acc)" || ck bad "the AMF accepted only $acc registrations"
[ "$rej" = 0 ] && ck ok "no registration was rejected" || ck bad "$rej registrations were rejected"
[ "$fwd" -gt 0 ] && ck ok "the UPF counted user-plane packets ($fwd)" || ck bad "the UPF counted no user-plane packets"
bad=$(grep -hE "ERROR|panic|Assertion|AddressSanitizer" "$RUN"/log/*.log 2>/dev/null | grep -v "injected" | head -3)
[ -z "$bad" ] && ck ok "no function logged an error" || { ck bad "a function logged errors:"; echo "$bad" | cut -c1-200 | sed 's/^/        /' | tee -a "$OUT/report.txt"; }

say ""
[ "$fail" = 0 ] && say "ORAN emulator + g5c core: PASS" || say "ORAN emulator + g5c core: FAIL"
exit "$fail"
