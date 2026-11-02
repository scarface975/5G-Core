#!/usr/bin/env bash
# Every sample in configs/ must load through its NF's real loader (`<nf> --check`). Paths under /etc/g5c and /var/lib/g5c are
# redirected to a scratch directory holding throw-away key files.
# usage: check_configs.sh <configs-dir> <udm> <pcf> <udr> <ausf> <upf> <smf> <amf> <nrf> <nssf> <nef> <scp> <bsf>  (paths of the binaries)
set -euo pipefail
cfgs="$1"; declare -A bin=([udm]="$2" [pcf]="$3" [udr]="$4" [ausf]="$5" [upf]="$6" [smf]="$7" [amf]="$8" [nrf]="$9" [nssf]="${10}" [nef]="${11}" [scp]="${12}" [bsf]="${13}")
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/etc/keys" "$tmp/var"

printf '%064d\n' 0 | tr 0 7 > "$tmp/etc/keys/hn-1.key"
printf '%064d\n' 0 | tr 0 5 > "$tmp/etc/keys/udm-master.key"
printf '%064d\n' 0 | tr 0 3 > "$tmp/etc/keys/ausf-master.key"
echo "test-provisioning-token-0123456789" > "$tmp/etc/keys/udr-provisioning.token"
echo "test-af-token-0123456789abcdef" > "$tmp/etc/keys/nef-af-1.token"
for t in udm-admin pcf-admin; do echo "test-admin-token-0123456789" > "$tmp/etc/keys/$t.token"; done
fail=0
for nf in udm pcf udr ausf upf smf amf nrf nssf nef scp bsf; do
  sed -e "s#/etc/g5c#$tmp/etc#g" -e "s#/var/lib/g5c#$tmp/var#g" "$cfgs/$nf.yaml" > "$tmp/$nf.yaml"
  if ! "${bin[$nf]}" --check "$tmp/$nf.yaml"; then echo "FAIL: configs/$nf.yaml"; fail=1; fi
done
exit $fail
