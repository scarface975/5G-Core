#!/usr/bin/env bash
# The tester edition against a core that is not ours: the Open5GS oracle (unmodified binaries) with scripted gNBs and UEs of tools/cli/g5c-tester (TEST ONLY).
#   tester.sh [ues] [gnbs]        registration, authentication, PDU session, de-registration for every UE; exit 0 when all UEs completed
# Runs in a private user + network namespace (own loopback, TUN, MongoDB) like scenario.sh. The subscribers are provisioned into Open5GS's MongoDB (no admin API of ours is involved).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/../.."
ORACLE_HOME="${ORACLE_HOME:-$HOME/g5c-oracle}"
UES="${1:-5}"; GNBS="${2:-1}"
LOAD="${G5C_LOAD_BIN:-$HOME/g5c-cbuild/plain/nf/amf/load_core}"
# the load generator's UEs hold K and OP (e2e_env.h); the HSS-side value is OPc = AES-128(K, OP) xor OP (TS 35.206)
K="${K:-465b5ce8b199b49faa5f0a2ee238a6bc}"
OP="${OP:-cdc202d5123e20f62b6d676ac72cb318}"
enc="$(printf '%s' "$OP" | xxd -r -p | openssl enc -aes-128-ecb -K "$K" -nopad | xxd -p | tr -d '\n')"
OPC="$(printf '%016x%016x' $(( 0x${enc:0:16} ^ 0x${OP:0:16} )) $(( 0x${enc:16:16} ^ 0x${OP:16:16} )))"
if [ "${G5C_NETNS:-}" != 1 ]; then
  [ -x "$LOAD" ] || { echo "SKIP: no load_core ($LOAD)"; exit 77; }
  [ -x /usr/bin/open5gs-amfd ] || { echo "SKIP: no Open5GS"; exit 77; }
  unshare -Urn true 2>/dev/null || { echo "SKIP: no user and network namespaces"; exit 77; }
  exec unshare -Urn env G5C_NETNS=1 bash "$0" "$@"
fi
ip link set lo up
ip tuntap add name "${ORACLE_TUN:-ogstun5g}" mode tun
ip addr add 10.46.0.1/16 dev "${ORACLE_TUN:-ogstun5g}"
ip link set "${ORACLE_TUN:-ogstun5g}" up
sysctl -qw net.ipv4.ip_forward=1
mkdir -p "$ORACLE_HOME/mongo-ns" "$ORACLE_HOME/log"
rm -rf "$ORACLE_HOME/mongo-ns"/*
mongod --dbpath "$ORACLE_HOME/mongo-ns" --bind_ip 127.0.0.1 --port 27017 --nounixsocket --fork --logpath "$ORACLE_HOME/log/mongod-ns.log" >/dev/null
trap '"$HERE/oracle.sh" down >/dev/null 2>&1 || true; pkill -u 0 mongod 2>/dev/null || true' EXIT
"$HERE/oracle.sh" down >/dev/null 2>&1 || true
rm -f "$ORACLE_HOME"/log/*.log "$ORACLE_HOME"/log/*.stdout
"$HERE/oracle.sh" gen >/dev/null
"$HERE/oracle.sh" up >/dev/null
# the tester's subscribers are 00101 + 10 digits counted from 1
for i in $(seq 1 "$UES"); do "$HERE/oracle.sh" provision "$(printf '00101%010d' "$i")" "$K" "$OPC" >/dev/null 2>&1; done
echo "Open5GS up, $UES subscribers provisioned"
python3 "$ROOT/tools/cli/g5c-tester" run --amf 127.1.0.5:38412 --no-provision --foreign --ues "$UES" --gnbs "$GNBS" --load-bin "$LOAD"
