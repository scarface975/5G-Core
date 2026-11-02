#!/usr/bin/env bash
# Builds a copy of UERANSIM's nr-ue that can decode a standard EAP-AKA' request (TEST PEER ONLY; the original tree is left alone).
# UERANSIM 3.3.0 rejects every EAP attribute whose Length is below 2 (src/lib/nas/eap.cpp, EAP decoder), but AT_KDF has Length 1 by definition
# (RFC 5448 3.2: "The length of the attribute, MUST be set to 1"), so the UE stops on the first EAP-Request/AKA'-Challenge of any conforming server
# ("Bad constructed NAS message"). The copy accepts Length 1. Everything else in UERANSIM's EAP-AKA' (key derivation, AT_MAC, AT_RES) is untouched,
# which makes it an independent implementation of the peer side to test our AUSF against.
#   usage: build_ueransim_eap.sh        -> $HOME/test-peers/UERANSIM-eap/build/nr-ue
set -euo pipefail
SRC="${UERANSIM_SRC:-$HOME/test-peers/UERANSIM}"
DST="${UERANSIM_EAP_DIR:-$HOME/test-peers/UERANSIM-eap}"
[ -d "$SRC/src" ] || { echo "UERANSIM source not found in $SRC"; exit 1; }
rm -rf "$DST"
cp -r "$SRC" "$DST"
cd "$DST"
grep -q 'if (attributeLength < 2)' src/lib/nas/eap.cpp || { echo "unexpected UERANSIM source: the attribute length check is not where it was"; exit 1; }
sed -i 's/if (attributeLength < 2)/if (attributeLength < 1)/' src/lib/nas/eap.cpp
rm -rf cmake-build-release
cmake -DCMAKE_BUILD_TYPE=Release . -B cmake-build-release >/dev/null
cmake --build cmake-build-release --target nr-ue -j"$(nproc)" >/dev/null
cp cmake-build-release/nr-ue build/nr-ue
echo "built $DST/build/nr-ue (use UERANSIM_DIR=$DST)"
