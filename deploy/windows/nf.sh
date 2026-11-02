#!/usr/bin/env bash
# Runs ONE network function in the foreground of the terminal that started it (the .bat files call this through WSL).
#   nf.sh <udr|nssf|nef|scp|bsf|udm|ausf|pcf|upf|smf|amf>
# The log goes to the terminal as the function writes it, and is also appended to $G5C_RUN/log/<nf>.log.
set -u
nf="${1:?usage: nf.sh <network function>}"
H="${G5C_HOME:-$HOME}"                       # the Linux user's home, also when started as root (the UPF)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export G5C_RUN="${G5C_RUN:-$H/g5c-run}"
export G5C_BIN_DIR="${G5C_BIN_DIR:-$H/.cache/g5c-bin/bin}"
export G5C_LOG_JSON="${G5C_LOG_JSON:-false}"
export G5C_LOG_LEVEL="${G5C_LOG_LEVEL:-info}"
CL="$HERE/../run/g5c-cluster.sh"

if [ ! -x "$G5C_BIN_DIR/$nf" ]; then
  echo "The binary $G5C_BIN_DIR/$nf does not exist."
  echo "Run 0-prepare.bat first (it builds the network functions once)."
  exit 1
fi

bash "$CL" conf-once >/dev/null || exit 1
mkdir -p "$G5C_RUN/log"

if [ "$nf" = upf ]; then
  # N6: the TUN device the UE traffic leaves through. Needs root (the .bat starts this one as root without a password prompt).
  if [ "$(id -u)" != 0 ]; then echo "The UPF needs root for its TUN device; start 5-upf.bat, not this script directly."; exit 1; fi
  DEV="${G5C_N6_DEV:-ogstun}"
  ip link show "$DEV" >/dev/null 2>&1 || ip tuntap add name "$DEV" mode tun
  ip addr show dev "$DEV" | grep -q "10.45.0.1/" || ip addr add 10.45.0.1/16 dev "$DEV"
  ip link set "$DEV" up
  sysctl -qw net.ipv4.ip_forward=1 2>/dev/null
  # let UE traffic reach the outside (best effort: only when iptables is present)
  if command -v iptables >/dev/null 2>&1; then
    iptables -t nat -C POSTROUTING -s 10.45.0.0/16 ! -o "$DEV" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o "$DEV" -j MASQUERADE 2>/dev/null
  fi
fi

echo "=== $nf ==="
echo "configuration: $G5C_RUN/conf/$nf.yaml"
echo "log file:      $G5C_RUN/log/$nf.log"
echo "-------------------------------------------------------------------------------"
sed -E -n '/^[a-z]/p; /^  (pfcp|gtpu|n6|ngap|n4|upfs|udm|pcf|smf|amf|ausf|udr|self_uri):/p' "$G5C_RUN/conf/$nf.yaml" | sed 's/^/  /'
echo "-------------------------------------------------------------------------------"
echo "Ctrl+C stops the function. The log follows."
echo

touch "$G5C_RUN/log/$nf.log"
[ "$(id -u)" = 0 ] && chown --reference="$H" "$G5C_RUN/log/$nf.log" 2>/dev/null
bash "$CL" run "$nf" 2>&1 | tee -a "$G5C_RUN/log/$nf.log"
echo
echo "[$nf stopped]"
