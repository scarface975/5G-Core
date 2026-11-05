#!/usr/bin/env bash
# g5c-policy-eval: names the script that holds, refuses a bad condition (exit 2)
set -u
tool=$1
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
cat > "$d/ok.yaml" <<'EOF'
name: pcf-1
plmn: { mcc: '001', mnc: '01' }
policy:
  default: { session_ambr: { uplink: 1 Gbps, downlink: 2 Gbps } }
  scripts:
    - when: "dnn == 'iot' and supi startswith 'imsi-00101'"
      session_ambr: { uplink: 1 Mbps, downlink: 2 Mbps }
    - when: "dnn == 'iot'"
      session_ambr: { uplink: 9 Mbps, downlink: 9 Mbps }
EOF
sed 's/dnn == .iot. and supi/dnn == and supi/' "$d/ok.yaml" > "$d/bad.yaml"
cat > "$d/grp.yaml" <<'EOF'
name: pcf-1
plmn: { mcc: '001', mnc: '01' }
policy:
  default: { session_ambr: { uplink: 1 Gbps, downlink: 2 Gbps } }
  scripts:
    - when: "memberof 'meters' and dnn == 'iot'"
      session_ambr: { uplink: 64 Kbps, downlink: 64 Kbps }
EOF
fail=0
check() { if ! grep -q "$2" <<<"$1"; then echo "FAIL: wanted $2 in: $1"; fail=1; else echo "PASS  $3"; fi; }
check "$("$tool" "$d/ok.yaml" supi=imsi-001010000000001 dnn=iot)" '"matched":0' "first script holds"
check "$("$tool" "$d/ok.yaml" supi=imsi-262010000000001 dnn=iot)" '"matched":1.*"9 Mbps"' "second script holds"
check "$("$tool" "$d/ok.yaml" supi=imsi-001010000000001 dnn=internet)" '"matched":null.*"1 Gbps"' "no script: the operator default"
check "$("$tool" "$d/grp.yaml" supi=imsi-001010000000001 dnn=iot group=meters)" '"matched":0.*"64 Kbps"' "a device group selects its script"
check "$("$tool" "$d/grp.yaml" supi=imsi-001010000000001 dnn=iot)" '"matched":null' "without the group no script holds"
"$tool" "$d/bad.yaml" >/dev/null 2>&1; [ $? -eq 2 ] && echo "PASS  a bad condition is exit 2" || { echo "FAIL: bad condition"; fail=1; }
exit $fail
