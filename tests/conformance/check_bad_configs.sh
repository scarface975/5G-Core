#!/usr/bin/env bash
# Configuration negative tests: every broken config must make `<nf> --check` exit 1 with a message that names the problem.
# usage: check_bad_configs.sh <udm> <pcf> <udr> <ausf> <upf> <smf> <amf> <nrf> <nssf> <nef> <scp> <bsf>
set -uo pipefail
declare -A bin=([udm]="$1" [pcf]="$2" [udr]="$3" [ausf]="$4" [upf]="$5" [smf]="$6" [amf]="$7" [nrf]="$8" [nssf]="$9" [nef]="${10}" [scp]="${11}" [bsf]="${12}")
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
printf '%064d\n' 0 | tr 0 7 > "$tmp/good.key"
printf 'short\n' > "$tmp/short.key"
printf 'zz%062d\n' 0 > "$tmp/nothex.key"
printf 'test-admin-token-0123456789\n' > "$tmp/admin.token"
printf 'tiny\n' > "$tmp/tiny.token"
COMMON="name: x
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.0.0.1, port: 17000 }"
fail=0
n=0
# expect <nf> <substring-of-error> <config-text>
expect() {
  local nf="$1" want="$2" cfg="$3" out rc
  n=$((n+1))
  printf '%s\n' "$cfg" > "$tmp/c$n.yaml"
  out="$("${bin[$nf]}" --check "$tmp/c$n.yaml" 2>&1)"; rc=$?
  if [ $rc -ne 1 ] || ! grep -qF -- "$want" <<<"$out"; then
    echo "FAIL case $n ($nf): exit=$rc, wanted error containing [$want], got: $out"; fail=1
  fi
}
# --- common sections, via every NF
SMFOK="smf: { udm: { uri: 'http://u:1' }, pcf: { uri: 'http://p:1' }, n4: { address: 127.0.0.1 }, upfs: [ { name: u, address: 127.0.0.2 } ], dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24 } ] }"
AMFOK="amf: { ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"
for nf in udm pcf udr ausf upf smf amf nssf nef scp bsf; do
  extra=""; [ $nf = smf ] && extra="$SMFOK"; [ $nf = amf ] && extra="$AMFOK"; [ $nf = upf ] && extra="upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 } }"; [ $nf = udm ] && extra="udr: { uri: 'http://u:1' }"; [ $nf = pcf ] && extra="udr: { uri: 'http://u:1' }"; [ $nf = ausf ] && extra="udm: { uri: 'http://u:1' }"; [ $nf = nssf ] && extra="nssf: { slices: [ { snssai: { sst: 1 }, nrf: 'http://n:1' } ] }"; [ $nf = nef ] && extra="nef: { afs: [ { id: a, no_auth: true } ] }"
  expect $nf "" "not: [valid"
  expect $nf "" ""
  expect $nf "plmn" "name: x
sbi: { address: 127.0.0.1, port: 17000 }
$extra"
  expect $nf "mcc" "name: x
plmn: { mcc: '1', mnc: '01' }
sbi: { address: 127.0.0.1, port: 17000 }
$extra"
  expect $nf "mnc" "name: x
plmn: { mcc: '001', mnc: 'abcd' }
sbi: { address: 127.0.0.1, port: 17000 }
$extra"
  expect $nf "sbi" "name: x
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.0.0.1, port: 99999 }
$extra"
  expect $nf "sbi" "name: x
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.0.0.1, port: 17000, typo: 1 }
$extra"
  expect $nf "" "name: x
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.0.0.1, port: 17000, tls: { cert: /nonexistent/c.pem, key: /nonexistent/k.pem } }
$extra"
  expect $nf "" "name: x
plmn: { mcc: '001', mnc: '01' }
sbi: { address: 127.0.0.1, port: 17000 }
nrf: { uri: 5, typo: 1 }
$extra"
  # the access tokens of the NRF (common section `oauth2`)
  expect $nf "oauth2" "$COMMON
oauth2: 5
$extra"
  expect $nf "oauth2" "$COMMON
oauth2: { surprise: 1 }
$extra"
  expect $nf "oauth2.enforce" "$COMMON
nrf: { uri: 'http://n:1' }
oauth2: { enforce: maybe }
$extra"
  expect $nf "needs \`nrf.uri\`" "$COMMON
oauth2: { acquire: true }
$extra"
  expect $nf "oauth2.leeway_s" "$COMMON
nrf: { uri: 'http://n:1' }
oauth2: { enforce: true, leeway_s: 9000 }
$extra"
done
# --- UDM specific
expect udm "udr.uri" "$COMMON"
expect udm "udr" "$COMMON
udr: { uri: 'http://u:1', typo: 1 }"
expect udm "master key must be 64 hex" "$COMMON
udr: { uri: 'http://u:1' }
master_key_file: $tmp/short.key"
expect udm "master key must be 64 hex" "$COMMON
udr: { uri: 'http://u:1' }
master_key_file: $tmp/nothex.key"
expect udm "" "$COMMON
udr: { uri: 'http://u:1' }
master_key_file: $tmp/missing.key"
expect udm "admin token must be at least 16" "$COMMON
udr: { uri: 'http://u:1' }
admin_token_file: $tmp/tiny.token"
expect udm "hn_keys" "$COMMON
udr: { uri: 'http://u:1' }
hn_keys: 5"
expect udm "mapping" "$COMMON
udr: { uri: 'http://u:1' }
hn_keys: [ 5 ]"
expect udm "id (0-255)" "$COMMON
udr: { uri: 'http://u:1' }
hn_keys: [ { id: 300, scheme: profile-a, private_key_file: $tmp/good.key } ]"
expect udm "unknown scheme" "$COMMON
udr: { uri: 'http://u:1' }
hn_keys: [ { id: 1, scheme: profile-z, private_key_file: $tmp/good.key } ]"
expect udm "32 bytes" "$COMMON
udr: { uri: 'http://u:1' }
hn_keys: [ { id: 1, scheme: profile-a, private_key_file: $tmp/short.key } ]"
expect udm "32 bytes" "$COMMON
udr: { uri: 'http://u:1' }
hn_keys: [ { id: 1, scheme: profile-b, private_key_file: $tmp/missing.key } ]"
expect udm "hn_keys" "$COMMON
udr: { uri: 'http://u:1' }
hn_keys: [ { id: 1, scheme: profile-a, private_key_file: $tmp/good.key, typo: 1 } ]"
# --- PCF specific
expect pcf "policy_authorization" "$COMMON
udr: { uri: http://u:1 }
policy_authorization: { surprise: 1 }"
expect pcf "qi5" "$COMMON
udr: { uri: http://u:1 }
policy_authorization: { qos_references: { x: { qi5: 0 } } }"
expect pcf "GBR" "$COMMON
udr: { uri: http://u:1 }
policy_authorization: { qos_references: { x: { qi5: 1 } } }"
expect pcf "max_app_sessions" "$COMMON
udr: { uri: http://u:1 }
policy_authorization: { max_app_sessions: 0 }"
expect pcf "udr.uri" "$COMMON"
expect pcf "udr" "$COMMON
udr: { uri: 'http://u:1', typo: 1 }"
expect pcf "admin token must be at least 16" "$COMMON
udr: { uri: 'http://u:1' }
admin_token_file: $tmp/tiny.token"
expect pcf "unknown" "$COMMON
udr: { uri: 'http://u:1' }
policy: { unknown_field: 1 }"
expect pcf "qi5" "$COMMON
udr: { uri: 'http://u:1' }
policy: { default: { default_qos: { qi5: 1 } } }"
expect pcf "" "$COMMON
udr: { uri: 'http://u:1' }
policy: { rfsp: 70000 }"
# --- UPF specific
UPFOK="upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 } }"
expect upf "upf" "$COMMON"
expect upf "upf" "$COMMON
upf: { typo: 1, pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 } }"
expect upf "pfcp" "$COMMON
upf: { gtpu: { address: 127.0.0.1 } }"
expect upf "gtpu" "$COMMON
upf: { pfcp: { address: 127.0.0.1 } }"
expect upf "address" "$COMMON
upf: { pfcp: { address: not-an-ip }, gtpu: { address: 127.0.0.1 } }"
expect upf "specific address" "$COMMON
upf: { pfcp: { address: 0.0.0.0 }, gtpu: { address: 127.0.0.1 } }"
expect upf "specific address" "$COMMON
upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 0.0.0.0 } }"
expect upf "port" "$COMMON
upf: { pfcp: { address: 127.0.0.1, port: 70000 }, gtpu: { address: 127.0.0.1 } }"
expect upf "port" "$COMMON
upf: { pfcp: { address: 127.0.0.1, port: 0 }, gtpu: { address: 127.0.0.1 } }"
expect upf "device" "$COMMON
upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 }, n6: { device: this-name-is-far-too-long } }"
expect upf "n6" "$COMMON
upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 }, n6: { dev: tun0 } }"
expect upf "check_source" "$COMMON
upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 }, check_source: maybe }"
expect upf "retries" "$COMMON
upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 }, heartbeat: { interval: 5, retries: 0 } }"
expect upf "heartbeat" "$COMMON
upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 }, heartbeat: { interval: 5, typo: 1 } }"
expect upf "max_age" "$COMMON
upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 }, buffer: { max_age: 0 } }"
expect upf "max_age" "$COMMON
upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 }, buffer: { max_age: 99999 } }"
expect upf "buffer" "$COMMON
upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 }, buffer: { max_packets: -1 } }"
expect upf "max_sessions" "$COMMON
upf: { pfcp: { address: 127.0.0.1 }, gtpu: { address: 127.0.0.1 }, max_sessions: 99999999999 }"
# --- SMF
smf_with() { # smf_with <replacement of one member of the minimal section>
  printf '%s
' "$COMMON"; printf '%s
' "$1"
}
expect smf "smf" "$COMMON"
expect smf "typo" "$COMMON
smf: { typo: 1, udm: { uri: 'http://u:1' }, pcf: { uri: 'http://p:1' }, n4: { address: 127.0.0.1 }, upfs: [ { name: u, address: 127.0.0.2 } ], dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24 } ] }"
expect smf "smf.udm.uri" "$COMMON
smf: { pcf: { uri: 'http://p:1' }, n4: { address: 127.0.0.1 }, upfs: [ { name: u, address: 127.0.0.2 } ], dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24 } ] }"
expect smf "smf.udm.uri" "$COMMON
smf: { udm: { uri: 'udm:7777' }, pcf: { uri: 'http://p:1' }, n4: { address: 127.0.0.1 }, upfs: [ { name: u, address: 127.0.0.2 } ], dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24 } ] }"
expect smf "smf.pcf.uri" "$COMMON
smf: { udm: { uri: 'http://u:1' }, n4: { address: 127.0.0.1 }, upfs: [ { name: u, address: 127.0.0.2 } ], dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24 } ] }"
expect smf "smf.amf.uri" "$COMMON
smf: { udm: { uri: 'http://u:1' }, pcf: { uri: 'http://p:1' }, amf: { uri: 'amf' }, n4: { address: 127.0.0.1 }, upfs: [ { name: u, address: 127.0.0.2 } ], dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24 } ] }"
for bad in "mtu: 100" "mtu: 70000" "n1n2_delay_ms: -1" "n1n2_delay_ms: 99999" "release_guard_ms: 5" "release_guard_ms: 9999999" "state_file: ''" "self_uri: ftp://x" "slices: []" "slices: [ { sst: 999 } ]" "slices: [ { sst: 1, sd: abc } ]" "slices: x"; do
  expect smf "smf." "$COMMON
smf: { $bad, udm: { uri: 'http://u:1' }, pcf: { uri: 'http://p:1' }, n4: { address: 127.0.0.1 }, upfs: [ { name: u, address: 127.0.0.2 } ], dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24 } ] }"
done
S_REST="udm: { uri: 'http://u:1' }, pcf: { uri: 'http://p:1' }, upfs: [ { name: u, address: 127.0.0.2 } ], dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24 } ]"
expect smf "smf.n4" "$COMMON
smf: { $S_REST }"
expect smf "smf.n4.address" "$COMMON
smf: { $S_REST, n4: { port: 8805 } }"
expect smf "smf.n4.address" "$COMMON
smf: { $S_REST, n4: { address: 0.0.0.0 } }"
expect smf "smf.n4.address" "$COMMON
smf: { $S_REST, n4: { address: ::1 } }"
expect smf "smf.n4.port" "$COMMON
smf: { $S_REST, n4: { address: 127.0.0.1, port: 70000 } }"
expect smf "smf.n4.t1_ms" "$COMMON
smf: { $S_REST, n4: { address: 127.0.0.1, t1_ms: 1 } }"
expect smf "smf.n4.n1" "$COMMON
smf: { $S_REST, n4: { address: 127.0.0.1, n1: 0 } }"
expect smf "lost_after" "$COMMON
smf: { $S_REST, n4: { address: 127.0.0.1, lost_after: -3 } }"
expect smf "lost_after" "$COMMON
smf: { $S_REST, n4: { address: 127.0.0.1, lost_after: 999999 } }"
expect smf "heartbeat" "$COMMON
smf: { $S_REST, n4: { address: 127.0.0.1, heartbeat: { typo: 1 } } }"
expect smf "heartbeat interval" "$COMMON
smf: { $S_REST, n4: { address: 127.0.0.1, heartbeat: { interval: 99999 } } }"
expect smf "heartbeat failures" "$COMMON
smf: { $S_REST, n4: { address: 127.0.0.1, heartbeat: { failures: 0 } } }"
S_HEAD="udm: { uri: 'http://u:1' }, pcf: { uri: 'http://p:1' }, n4: { address: 127.0.0.1 }"
D_OK="dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24 } ]"
U_OK="upfs: [ { name: u, address: 127.0.0.2 } ]"
expect smf "smf.upfs" "$COMMON
smf: { $S_HEAD, $D_OK }"
expect smf "smf.upfs" "$COMMON
smf: { $S_HEAD, upfs: [], $D_OK }"
expect smf "name" "$COMMON
smf: { $S_HEAD, upfs: [ { address: 127.0.0.2 } ], $D_OK }"
expect smf "address" "$COMMON
smf: { $S_HEAD, upfs: [ { name: u } ], $D_OK }"
expect smf "IPv4 address" "$COMMON
smf: { $S_HEAD, upfs: [ { name: u, address: upf.example } ], $D_OK }"
expect smf "port" "$COMMON
smf: { $S_HEAD, upfs: [ { name: u, address: 127.0.0.2, port: 0 } ], $D_OK }"
expect smf "typo" "$COMMON
smf: { $S_HEAD, upfs: [ { name: u, address: 127.0.0.2, typo: 1 } ], $D_OK }"
expect smf "dnns must be strings" "$COMMON
smf: { $S_HEAD, upfs: [ { name: u, address: 127.0.0.2, dnns: [ 5 ] } ], $D_OK }"
expect smf "sst" "$COMMON
smf: { $S_HEAD, upfs: [ { name: u, address: 127.0.0.2, slices: [ { sst: 999 } ] } ], $D_OK }"
expect smf "sd" "$COMMON
smf: { $S_HEAD, upfs: [ { name: u, address: 127.0.0.2, slices: [ { sst: 1, sd: zz } ] } ], $D_OK }"
expect smf "smf.dnns" "$COMMON
smf: { $S_HEAD, $U_OK }"
expect smf "smf.dnns" "$COMMON
smf: { $S_HEAD, $U_OK, dnns: [] }"
expect smf "name" "$COMMON
smf: { $S_HEAD, $U_OK, dnns: [ { ipv4_pool: 10.0.0.0/24 } ] }"
expect smf "typo" "$COMMON
smf: { $S_HEAD, $U_OK, dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24, typo: 1 } ] }"
expect smf "needs an IPv4 or an IPv6 range" "$COMMON
smf: { $S_HEAD, $U_OK, dnns: [ { name: internet } ] }"
expect smf "prefix length" "$COMMON
smf: { $S_HEAD, $U_OK, dnns: [ { name: internet, ipv4_pool: 10.0.0.0/31 } ] }"
expect smf "needs a prefix length" "$COMMON
smf: { $S_HEAD, $U_OK, dnns: [ { name: internet, ipv4_pool: 10.0.0.0 } ] }"
expect smf "bad address" "$COMMON
smf: { $S_HEAD, $U_OK, dnns: [ { name: internet, ipv4_pool: 300.0.0.0/24 } ] }"
expect smf "prefix length" "$COMMON
smf: { $S_HEAD, $U_OK, dnns: [ { name: internet, ipv6_pool: '2001:db8::/64' } ] }"
expect smf "dns" "$COMMON
smf: { $S_HEAD, $U_OK, dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24, dns: [ not-an-ip ] } ] }"
expect smf "dns" "$COMMON
smf: { $S_HEAD, $U_OK, dnns: [ { name: internet, ipv4_pool: 10.0.0.0/24, dns: [ 1.1.1.1, 2.2.2.2, 3.3.3.3 ] } ] }"
# --- AMF specific
AOK="ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' }"
expect amf "amf" "$COMMON"
expect amf "typo" "$COMMON
amf: { typo: 1, $AOK }"
expect amf "ausf" "$COMMON
amf: { udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"
expect amf "amf.ausf.uri" "$COMMON
amf: { ausf: { uri: 'ausf:7777' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"
expect amf "amf.self_uri" "$COMMON
amf: { $AOK, self_uri: 'amf' }"
expect amf "amf.guami.region" "$COMMON
amf: { $AOK, guami: { region: 300 } }"
expect amf "amf.guami.set" "$COMMON
amf: { $AOK, guami: { set: 1024 } }"
expect amf "amf.guami.pointer" "$COMMON
amf: { $AOK, guami: { pointer: 64 } }"
expect amf "amf.guami" "$COMMON
amf: { $AOK, guami: { typo: 1 } }"
expect amf "amf.ngap.port" "$COMMON
amf: { $AOK, ngap: { address: 127.0.0.1, port: 70000 } }"
expect amf "amf.capacity" "$COMMON
amf: { $AOK, capacity: 256 }"
expect amf "amf.tais" "$COMMON
amf: { $AOK, tais: [] }"
expect amf "amf.tais[].tac" "$COMMON
amf: { $AOK, tais: [ { tac: 99999999 } ] }"
expect amf "amf.slices" "$COMMON
amf: { $AOK, slices: [ { sst: 300 } ] }"
expect amf "SNOW 3G" "$COMMON
amf: { $AOK, security: { integrity: [NIA1] } }"
expect amf "SNOW 3G" "$COMMON
amf: { $AOK, security: { ciphering: [NEA3, NEA2] } }"
expect amf "integrity" "$COMMON
amf: { $AOK, security: { integrity: [] } }"
expect amf "amf.security" "$COMMON
amf: { $AOK, security: { typo: [] } }"
expect amf "amf.timers.t3550" "$COMMON
amf: { $AOK, timers: { t3550: 0 } }"
expect amf "amf.timers" "$COMMON
amf: { $AOK, timers: { t9999: 1 } }"
expect amf "amf.paging_tries" "$COMMON
amf: { $AOK, paging_tries: 0 }"
expect amf "amf.workers" "$COMMON
amf: { $AOK, workers: 0 }"
expect amf "amf.state_file" "$COMMON
amf: { $AOK, state_file: '' }"
expect amf "amf.network_name" "$COMMON
amf: { $AOK, network_name: { typo: x } }"
# --- AUSF
expect ausf "udm.uri" "$COMMON"
expect ausf "ausf" "$COMMON
udm: { uri: 'http://u:1' }
ausf: 5"
expect ausf "colour" "$COMMON
udm: { uri: 'http://u:1' }
ausf: { colour: red }"
expect ausf "ausf.context_lifetime" "$COMMON
udm: { uri: 'http://u:1' }
ausf: { context_lifetime: 0 }"
expect ausf "ausf.max_contexts" "$COMMON
udm: { uri: 'http://u:1' }
ausf: { max_contexts: 0 }"
expect ausf "ausf.serving_networks" "$COMMON
udm: { uri: 'http://u:1' }
ausf: { serving_networks: ['evil.example.org'] }"
expect ausf "ausf.eap.result_indication" "$COMMON
udm: { uri: 'http://u:1' }
ausf: { eap: { result_indication: maybe } }"
expect ausf "master key" "$COMMON
udm: { uri: 'http://u:1' }
ausf: { state_file: /tmp/ausf.json }"
expect ausf "cannot read" "$COMMON
udm: { uri: 'http://u:1' }
ausf: { state_file: /tmp/ausf.json, master_key_file: /nonexistent/ausf-master.key }"
expect ausf "ausf.supi_ranges" "$COMMON
udm: { uri: 'http://u:1' }
ausf: { supi_ranges: [{ start: '2', end: '1' }] }"
expect ausf "ausf.routing_indicators" "$COMMON
udm: { uri: 'http://u:1' }
ausf: { routing_indicators: ['12345'] }"
expect ausf "ausf.self_uri" "$COMMON
udm: { uri: 'http://u:1' }
ausf: { self_uri: 'ausf.example:7774' }"
# --- UDR
expect udr "" "$COMMON
store_path: /nonexistent-dir/deeper/udr.json"
expect udr "store.type" "$COMMON
store: { type: mongodb }"
expect udr "store.path" "$COMMON
store: { type: file }"
expect udr "store" "$COMMON
store: { type: memory, surprise: 1 }"
expect udr "store.pool" "$COMMON
store: { type: postgres, pool: 0 }"
expect udr "conninfo" "$COMMON
store: { type: postgres }"
expect udr "provisioning" "$COMMON
provisioning: { token: inline-secret-0123456789 }"
expect udr "16 characters" "$COMMON
provisioning: { token_file: $tmp/tiny.token }"
expect udr "validate" "$COMMON
validate: maybe"
expect udr "udr.supi_ranges" "$COMMON
udr: { supi_ranges: [{ start: '002', end: '001' }] }"
expect udr "udr.supi_ranges" "$COMMON
udr: { supi_ranges: [] }"
expect udr "udr.data_sets" "$COMMON
udr: { data_sets: [SUBSCRIPTION, GALAXY] }"
expect udr "udr" "$COMMON
udr: { surprise: 1 }"
expect udr "subscriptions.max_lifetime_s" "$COMMON
subscriptions: { max_lifetime_s: 5 }"
expect udr "subscriptions" "$COMMON
subscriptions: { surprise: 1 }"
expect udr "cache.max_age_s" "$COMMON
cache: { max_age_s: -1 }"
expect udr "group_ids[0]" "$COMMON
group_ids: [{ nf_type: udm, nf_group_id: g1, supi_ranges: [{ start: '00101', end: '00102' }] }]"
expect udr "group_ids[0]" "$COMMON
group_ids: [{ nf_type: UDM, supi_ranges: [{ start: '00101', end: '00102' }] }]"
expect udr "group_ids[0].supi_ranges" "$COMMON
group_ids: [{ nf_type: UDM, nf_group_id: g1, supi_ranges: [{ start: '1', end: '2' }] }]"
# --- NSSF
expect nssf "nssf" "$COMMON"
expect nssf "nssf.slices" "$COMMON
nssf: { slices: [] }"
expect nssf "nssf.slices[0].snssai" "$COMMON
nssf: { slices: [ { snssai: { sst: 999 }, nrf: 'http://n:1' } ] }"
expect nssf "nssf.slices[0].nrf" "$COMMON
nssf: { slices: [ { snssai: { sst: 1 } } ] }"
expect nssf "repeats" "$COMMON
nssf: { slices: [ { snssai: { sst: 1 }, nrf: 'http://n:1' }, { snssai: { sst: 1 }, nrf: 'http://n:1' } ] }"
expect nssf "nssf.slices[0].tais[0]" "$COMMON
nssf: { slices: [ { snssai: { sst: 1 }, nrf: 'http://n:1', tais: [ { mcc: '1', mnc: '01', tac: '1' } ] } ] }"
expect nssf "amf_sets[0].id" "$COMMON
nssf: { slices: [ { snssai: { sst: 1 }, nrf: 'http://n:1' } ], amf_sets: [ { id: 'x' } ] }"
expect nssf "not one of the slices" "$COMMON
nssf: { slices: [ { snssai: { sst: 1 }, nrf: 'http://n:1' } ], mappings: [ { home_plmn: '310-260', serving: { sst: 5 }, home: { sst: 1 } } ] }"
expect nssf "max_allowed" "$COMMON
nssf: { slices: [ { snssai: { sst: 1 }, nrf: 'http://n:1' } ], policy: { max_allowed: 9 } }"
expect nssf "max_lifetime_s" "$COMMON
nssf: { slices: [ { snssai: { sst: 1 }, nrf: 'http://n:1' } ], subscriptions: { max_lifetime_s: 5 } }"
expect nssf "nssf" "$COMMON
nssf: { slices: [ { snssai: { sst: 1 }, nrf: 'http://n:1' } ], surprise: 1 }"
# --- NRF
expect nrf "registry.heartbeat_timer" "$COMMON
registry: { heartbeat_timer: 0 }"
expect nrf "registry.suspend_after" "$COMMON
registry: { suspend_after: 0 }"
expect nrf "registry.validity_period" "$COMMON
registry: { validity_period: 0 }"
expect nrf "registry.max_profiles" "$COMMON
registry: { max_profiles: 0 }"
expect nrf "registry" "$COMMON
registry: { surprise: 1 }"
expect nrf "registry.oauth2" "$COMMON
registry: { oauth2: { surprise: 1 } }"
expect nrf "enforce" "$COMMON
registry: { oauth2: { enabled: false, enforce: true } }"
expect nrf "registry.oauth2.token_lifetime" "$COMMON
registry: { oauth2: { token_lifetime: 0 } }"
expect nrf "registry" "$COMMON
registry: 7"
expect nrf "configure it under" "$COMMON
nrf: { uri: 'http://elsewhere:7777' }"
# --- the functions that can find their peers through the NRF accept a configuration without them (and still refuse one with neither)
expect udm "nrf.uri" "$COMMON"
expect pcf "nrf.uri" "$COMMON"
expect ausf "nrf.uri" "$COMMON"
# --- and the good ones still pass (guards against the checks above passing for the wrong reason)
printf '%s\n%s\n' "$COMMON" "udr: { uri: 'http://u:1' }" > "$tmp/ok.yaml"
"${bin[udm]}" --check "$tmp/ok.yaml" >/dev/null 2>&1 || { echo "FAIL: minimal good UDM config rejected"; fail=1; }
"${bin[pcf]}" --check "$tmp/ok.yaml" >/dev/null 2>&1 || { echo "FAIL: minimal good PCF config rejected"; fail=1; }
printf '%s\n%s\n' "$COMMON" "$UPFOK" > "$tmp/okupf.yaml"
"${bin[upf]}" --check "$tmp/okupf.yaml" >/dev/null 2>&1 || { echo "FAIL: minimal good UPF config rejected"; fail=1; }
printf '%s
%s
' "$COMMON" "$SMFOK" > "$tmp/oksmf.yaml"
"${bin[smf]}" --check "$tmp/oksmf.yaml" >/dev/null 2>&1 || { echo "FAIL: minimal good SMF config rejected"; fail=1; }
printf '%s
%s
' "$COMMON" "$AMFOK" > "$tmp/okamf.yaml"
"${bin[amf]}" --check "$tmp/okamf.yaml" >/dev/null 2>&1 || { echo "FAIL: minimal good AMF config rejected"; fail=1; }
printf '%s
%s
' "$COMMON" "nrf: { uri: 'http://n:7777' }" > "$tmp/okdisc.yaml"
for nf in udm pcf ausf; do
  "${bin[$nf]}" --check "$tmp/okdisc.yaml" >/dev/null 2>&1 || { echo "FAIL: $nf with an NRF and no peer addresses rejected"; fail=1; }
done
printf '%s
%s
' "$COMMON" "registry: { heartbeat_timer: 5 }" > "$tmp/oknrf.yaml"
"${bin[nrf]}" --check "$tmp/oknrf.yaml" >/dev/null 2>&1 || { echo "FAIL: minimal good NRF config rejected"; fail=1; }
echo "$n bad-configuration cases run"

# --- NEF
expect nef "nef" "$COMMON"
expect nef "nef.afs" "$COMMON
nef: { afs: [] }"
expect nef "nef.afs[0].id" "$COMMON
nef: { afs: [ { id: 'a b', no_auth: true } ] }"
expect nef "no bearer token" "$COMMON
nef: { afs: [ { id: a } ] }"
expect nef "listed twice" "$COMMON
nef: { afs: [ { id: a, no_auth: true }, { id: a, no_auth: true } ] }"
expect nef "nef.afs[0].apis" "$COMMON
nef: { afs: [ { id: a, no_auth: true, apis: [ nope ] } ] }"
expect nef "notify_hosts[0]" "$COMMON
nef: { afs: [ { id: a, no_auth: true, notify_hosts: [ 'a/b' ] } ] }"
expect nef "at least 16" "$COMMON
nef: { afs: [ { id: a, token_file: $tmp/tiny.token } ] }"
expect nef "nef.udr.uri" "$COMMON
nef: { afs: [ { id: a, no_auth: true } ], udr: { uri: 'ftp://x' } }"
expect nef "callback_uri" "$COMMON
nef: { afs: [ { id: a, no_auth: true } ], callback_uri: nope }"
expect nef "notify_retries" "$COMMON
nef: { afs: [ { id: a, no_auth: true } ], subscriptions: { notify_retries: 99 } }"
expect nef "nef" "$COMMON
nef: { afs: [ { id: a, no_auth: true } ], surprise: 1 }"
# --- SCP
expect scp "scp.prefix" "$COMMON
scp: { prefix: 'no-slash' }"
expect scp "scp.next.uri" "$COMMON
scp: { next: { uri: 'ftp://x' } }"
expect scp "scp.next.delegate_discovery" "$COMMON
scp: { next: { uri: 'http://x:1', delegate_discovery: 3 } }"
expect scp "scp.discovery.delegated" "$COMMON
scp: { discovery: { delegated: 3 } }"
expect scp "scp.routing.attempts" "$COMMON
scp: { routing: { attempts: 0 } }"
expect scp "scp.routing.timeout_ms" "$COMMON
scp: { routing: { timeout_ms: 99999999 } }"
expect scp "scp.routing.retry_on_503" "$COMMON
scp: { routing: { retry_on_503: 5 } }"
expect scp "scp.routing.workers" "$COMMON
scp: { routing: { workers: 100000 } }"
expect scp "scp.targets.allow" "$COMMON
scp: { targets: { allow: 5 } }"
expect scp "scp.targets.allow[0]" "$COMMON
scp: { targets: { allow: [ 'a b/c' ] } }"
expect scp "scp" "$COMMON
scp: { surprise: 1 }"
expect scp "scp" "$COMMON
scp: 5"
# --- BSF
expect bsf "bsf" "$COMMON
bsf: 5"
expect bsf "bsf" "$COMMON
bsf: { surprise: 1 }"
expect bsf "bsf.max_bindings" "$COMMON
bsf: { max_bindings: 0 }"
expect bsf "bsf.features[0]" "$COMMON
bsf: { features: [ Nope ] }"
expect bsf "requires SamePcf" "$COMMON
bsf: { features: [ ExtendedSamePcf ] }"
expect bsf "bsf.purge_on_recovery" "$COMMON
bsf: { purge_on_recovery: 3 }"
expect bsf "bsf.replace_stale" "$COMMON
bsf: { replace_stale: 3 }"
expect bsf "bsf.validate" "$COMMON
bsf: { validate: maybe }"
expect bsf "bsf.state_file" "$COMMON
bsf: { state_file:  }"
expect bsf "bsf.info.dnn_list" "$COMMON
bsf: { info: { dnn_list: [] } }"
expect bsf "bsf.info.ipv4_address_ranges" "$COMMON
bsf: { info: { ipv4_address_ranges: [ { start: 10.0.0.9, end: 10.0.0.1 } ] } }"
expect bsf "bsf.info.ipv6_prefix_ranges" "$COMMON
bsf: { info: { ipv6_prefix_ranges: [ { start: nope, end: nope } ] } }"
expect nef "nef.bsf.uri" "$COMMON
nef: { afs: [ { id: a, no_auth: true } ], bsf: { uri: ftp://x } }"
expect pcf "bsf" "$COMMON
udr: { uri: http://u:1 }
bsf: { surprise: 1 }"
expect pcf "bsf.uri" "$COMMON
udr: { uri: http://u:1 }
bsf: { uri: ftp://x }"
exit $fail
