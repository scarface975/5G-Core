# Running the SMF

```
smf [--check] configs/smf.yaml
```

- **N11 (Nsmf_PDUSession)** is served on the `sbi` address: `POST /nsmf-pdusession/v1/sm-contexts` (create) and `.../{smContextRef}/modify`,
  `.../release`. Bodies are `multipart/related`: a JSON part and the N1 SM / N2 SM binary parts it refers to by `contentId`.
- **The AMF** is reached with Namf_Communication N1N2MessageTransfer: at `smf.amf.uri` when set, otherwise at the endpoint the NRF returns for the
  `servingNfId` the AMF sent (Nnrf_NFDiscovery, cached for a minute), otherwise at the host of the `smContextStatusUri` of the create request.
- **N4 (PFCP)** is opened on `smf.n4.address` (UDP 8805 by default). Use a specific address: it is the Node ID and F-SEID address the UPFs reply to.
  With an IPv6 pool configured the SMF also listens for GTP-U on UDP 2152 of that address: the UPF forwards router solicitations there and the SMF answers
  them with the session's /64.
  The SMF associates with every UPF listed in `smf.upfs` and keeps retrying while one is down; it picks among the associated UPFs that serve the
  DNN and slice (round-robin). `smf --check` validates the file and the TLS material without opening any port.
- **UDM and PCF** are addressed by `smf.udm.uri` and `smf.pcf.uri` (NRF discovery is Phase 7). The SMF registers in the NRF itself when `nrf.uri` is set,
  advertising `smf.slices` x `smf.dnns`.
- **UE addresses**: per DNN, `ipv4_pool` (the first host address is the gateway) and/or `ipv6_pool` (a /48 to /63, handed out as /64s).
- **Health and metrics**: `/health/live`, `/health/ready`, `/metrics` - requests by operation and result, create latency, sessions, addresses in use,
  UPF restarts and losses, N4 retransmissions and timeouts, stale sessions.
- **Signals**: SIGTERM and SIGINT stop it cleanly.

- **PCF changes**: an SM policy update is applied to the UPF and then signalled to the UE and the gNB (PDU session modification command, resource modify
  request); a termination releases the session through the AMF (`smf.release_guard_ms` bounds the wait for the UE's complete).
- **UPF failure**: a restart (changed Recovery Time Stamp) or silence longer than `smf.n4.lost_after` releases that UPF's sessions towards the AMF, the PCF and
  the UDM and returns their addresses. A downlink data report for an idle session pages the UE through the AMF.
- **Persistence**: with `smf.state_file` set, sessions are written after every change and restored at start-up; the SMF keeps its own Recovery Time Stamp
  so the UPFs keep the sessions. Sessions of a UPF that restarted in the meantime are released as above.

What the SMF does not do (see `docs/conformance/phase4-matrix.json`): UE-requested modification (answered with a reject), charging / usage reporting, ATSSS,
Ethernet and unstructured session types, SSC modes 2 and 3, handover, I-SMF / V-SMF roles, OAuth2 on the SBI, NRF discovery of UPFs.

Interop: `OUR_SMF=1 OUR_UDM=1 OUR_PCF=1 OUR_UPF=1 deploy/oracle/scenario.sh s3` (and `s4` for the policy push) runs Open5GS's AMF, AUSF and NRF with UERANSIM against this SMF.
