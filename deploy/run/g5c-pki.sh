#!/usr/bin/env bash
# The PKI of a cluster (TS 33.501 13.1, 13.3.2.1): one CA, one certificate per function, one for the operator's tools. EC P-256 keys, SHA-256, leaf certificates valid for
# G5C_PKI_DAYS (default 90), the CA for G5C_PKI_CA_DAYS (default 1825). Every certificate carries the function's addresses as subject alternative names (the functions
# are reached by IP address) and both server and client authentication, so the same file serves the listener and the outgoing requests (mutual TLS).
#
#   g5c-pki.sh init <dir>                          create the CA (kept if it exists)
#   g5c-pki.sh issue <dir> <name> <ip[,ip...]>     (re)issue <dir>/<name>.crt and .key for a function; DNS:localhost and IP:127.0.0.1 are always added
#   g5c-pki.sh renew <dir> <name>                  a new certificate with the subject alternative names of the current one
#   g5c-pki.sh status <dir>                        every certificate with its expiry; exit 1 when one expires within G5C_PKI_WARN_DAYS (default 14)
#   g5c-pki.sh check <dir> <name>                  the certificate verifies against the CA and its key matches
#   g5c-pki.sh revoke <dir> <name>                 put <name>'s current certificate on the CA's revocation list (<dir>/ca.crl); functions read it again on SIGHUP
#   g5c-pki.sh crl <dir>                           make the revocation list again (valid G5C_PKI_CRL_DAYS, default 365)
#
# The CA key stays in <dir>/ca.key (mode 600). On a production cluster keep it offline and issue with `issue` on the machine that holds it.
set -euo pipefail
cmd="${1:-}"; dir="${2:-}"
DAYS="${G5C_PKI_DAYS:-90}"; CADAYS="${G5C_PKI_CA_DAYS:-1825}"; WARN="${G5C_PKI_WARN_DAYS:-14}"
[ -n "$cmd" ] && [ -n "$dir" ] || { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
umask 077

# the revocation list: `openssl ca` keeps its database next to the CA; every function's `crl:` names <dir>/ca.crl, so the list exists from the start (empty)
crl() {
  local db="$dir/ca.db"
  mkdir -p "$db"
  [ -f "$db/index.txt" ] || : > "$db/index.txt"
  [ -f "$db/crlnumber" ] || echo 01 > "$db/crlnumber"
  printf '[ca]\ndefault_ca=c\n[c]\ndatabase=%s/index.txt\ncrlnumber=%s/crlnumber\ndefault_md=sha256\ndefault_crl_days=%s\ncertificate=%s/ca.crt\nprivate_key=%s/ca.key\nunique_subject=no\nnew_certs_dir=%s\ncopy_extensions=none\n' \
    "$db" "$db" "${G5C_PKI_CRL_DAYS:-365}" "$dir" "$dir" "$db" > "$db/ca.cnf"
  openssl ca -config "$db/ca.cnf" -gencrl -out "$dir/ca.crl.new" 2>/dev/null
  mv "$dir/ca.crl.new" "$dir/ca.crl"; chmod 644 "$dir/ca.crl"
}

revoke() {
  local name="$3"
  [ -f "$dir/$name.crt" ] || { echo "revoke: no certificate for $name"; exit 1; }
  crl
  openssl ca -config "$dir/ca.db/ca.cnf" -revoke "$dir/$name.crt" >/dev/null 2>&1 || { echo "revoke: $name is revoked already or not ours"; exit 1; }
  crl
  echo "$name: revoked; reload the functions (SIGHUP) to make them read $dir/ca.crl"
}

init() {
  mkdir -p "$dir"
  [ -f "$dir/ca.crt" ] && [ -f "$dir/ca.key" ] && { [ -f "$dir/ca.crl" ] || crl; return 0; }
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/ca.key" 2>/dev/null
  openssl req -x509 -new -key "$dir/ca.key" -sha256 -days "$CADAYS" -subj "/O=g5c/CN=g5c cluster CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$dir/ca.crt" 2>/dev/null
  chmod 600 "$dir/ca.key"; chmod 644 "$dir/ca.crt"
  crl
}

issue() {
  local name="$3" ips="${4:-127.0.0.1}" san="DNS:localhost,IP:127.0.0.1" ip t
  [ -n "$name" ] || { echo "issue: name missing"; exit 1; }
  init
  for ip in $(echo "$ips" | tr ',' ' '); do san="$san,IP:$ip"; done
  t="$(mktemp -d)"
  openssl ecparam -name prime256v1 -genkey -noout -out "$t/k.pem" 2>/dev/null
  openssl req -new -key "$t/k.pem" -subj "/O=g5c/CN=$name" -out "$t/r.csr" 2>/dev/null
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=%s\n' "$san" > "$t/ext"
  openssl x509 -req -in "$t/r.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial -CAserial "$dir/ca.srl" -days "$DAYS" -sha256 -extfile "$t/ext" -out "$t/c.pem" 2>/dev/null
  # the files are replaced atomically so that a function reading them on SIGHUP never sees a certificate and a key of two generations
  mv "$t/k.pem" "$dir/$name.key.new"; mv "$t/c.pem" "$dir/$name.crt.new"
  mv "$dir/$name.key.new" "$dir/$name.key"; mv "$dir/$name.crt.new" "$dir/$name.crt"
  chmod 600 "$dir/$name.key"; chmod 644 "$dir/$name.crt"
  rm -rf "$t"
}

# new certificate with the same subject alternative names as the current one (the addresses the function really has, whatever the environment of this call says)
renew() {
  local name="$3" ips
  [ -f "$dir/$name.crt" ] || { echo "renew: no certificate for $name"; exit 1; }
  ips="$(openssl x509 -in "$dir/$name.crt" -noout -ext subjectAltName | tr ',' '\n' | sed -n 's/.*IP Address:\([0-9a-fA-F.:]*\).*/\1/p' | paste -sd, -)"
  issue "$cmd" "$dir" "$name" "${ips:-127.0.0.1}"
}

status() {
  local f bad=0 end left
  for f in "$dir"/*.crt; do
    [ -e "$f" ] || continue
    end="$(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)"
    left=$(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))
    printf '%-14s expires %s (%d days)\n' "$(basename "$f" .crt)" "$end" "$left"
    [ "$left" -lt "$WARN" ] && bad=1
  done
  return $bad
}

check() {
  local name="$3"
  openssl verify -CAfile "$dir/ca.crt" "$dir/$name.crt" >/dev/null
  [ "$(openssl x509 -in "$dir/$name.crt" -noout -pubkey)" = "$(openssl pkey -in "$dir/$name.key" -pubout)" ] || { echo "$name: key does not match"; exit 1; }
  echo "$name: ok"
}

case "$cmd" in
  init) init ;;
  issue) issue "$@" ;;
  renew) renew "$@" ;;
  status) status ;;
  check) check "$@" ;;
  revoke) revoke "$@" ;;
  crl) init; crl ;;
  *) echo "unknown command $cmd"; exit 1 ;;
esac
