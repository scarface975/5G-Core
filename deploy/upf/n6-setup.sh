#!/usr/bin/env bash
# One-time N6 setup for the UPF on a Linux host: a persistent TUN device, a route for the UE pool, forwarding, and optional NAT.
# Needs root (CAP_NET_ADMIN). UNVERIFIED on this project's host (no sudo there): the oracle scenarios create the same objects inside an
# unprivileged user and network namespace instead. Read it before running it.
#   usage: n6-setup.sh <tun-device> <gateway-cidr> [nat-out-interface]
#   e.g.   n6-setup.sh ogstun 10.60.0.1/16 eth0
set -euo pipefail
dev="${1:?tun device name}"; gw="${2:?gateway address with prefix, e.g. 10.60.0.1/16}"; out="${3:-}"
ip tuntap add name "$dev" mode tun
ip addr add "$gw" dev "$dev"
ip link set "$dev" up
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w "net.ipv4.conf.$dev.rp_filter=0" >/dev/null   # replies for UE addresses arrive on another interface than they leave
if [ -n "$out" ]; then
  pool="$(ip -4 -o addr show dev "$dev" | awk '{print $4}' | head -1)"
  iptables -t nat -A POSTROUTING -s "$pool" -o "$out" -j MASQUERADE
  iptables -A FORWARD -i "$dev" -o "$out" -j ACCEPT
  iptables -A FORWARD -i "$out" -o "$dev" -m state --state RELATED,ESTABLISHED -j ACCEPT
fi
echo "N6 ready on $dev ($gw)${out:+, NAT out via $out}"
