# Running the UPF

```
upf [--check] configs/upf.yaml
```

- **N4 (PFCP)** listens on `upf.pfcp` (UDP 8805), **N3 (GTP-U)** on `upf.gtpu` (UDP 2152). Use specific addresses: they are sent to the SMF as
  the F-SEID and F-TEID of every session. `upf --check` validates the file and the TLS material without opening any port.
- **N6** is a TUN device named by `upf.n6.device`. The process attaches to an existing device or creates it, so it needs CAP_NET_ADMIN and
  `/dev/net/tun`. `n6-setup.sh` makes the device persistent, routes the UE pool to it, enables forwarding and optionally NAT (masquerade on
  the outgoing interface). NAT is host configuration; the UPF does not translate addresses itself.
- **Health and metrics**: the `sbi` section serves `/health/live`, `/health/ready` and `/metrics` (Prometheus text): packets and bytes by direction,
  drops by reason, PFCP messages, sessions, Error Indications, reports.
- **Signals**: SIGTERM and SIGINT stop it cleanly.

What the UPF does not do yet (see `docs/conformance/phase3-matrix.json`): UE address allocation (the SMF allocates), N3/N9 over IPv6, GBR
guarantees, ATSSS and the other multi-access features, the AF_XDP fast path (Stage B), NRF registration with UPF info.

Interop: `OUR_UPF=1 deploy/oracle/scenario.sh s3` runs Open5GS's AMF, SMF, AUSF and NRF with UERANSIM against this UPF (add `OUR_UDM=1 OUR_PCF=1` for our UDM and PCF too).
