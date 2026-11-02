# Changelog

Newest first. Versions follow `MAJOR.MINOR.PATCH[-rcN]` (docs/guides/release-process.md). The detailed engineering log is `docs/history/update.md`.

## 0.9.0-rc1 (release candidate)
The first release candidate: all eleven functions of the strategy and the optional BSF, validated against Open5GS 2.8.0 and UERANSIM and against an OCUDU gNB with srsUE over ZeroMQ.

### Core
- AMF, SMF, UPF, PCF, UDM, UDR, AUSF, NRF, NSSF, NEF, SCP and BSF as separate daemons; every function finds its peers through the NRF and can send through the SCP.
- Registration, authentication (5G-AKA, EAP-AKA'), NAS security, PDU sessions (IPv4, IPv6, IPv4v6), mobility (Xn path switch, N2 handover), paging, policy (AM, SM, application sessions), network slice
  selection by the NSSF (registration and PDU session, with fallback), traffic influence, monitoring events.

### Security (Phase 8)
- Mutual TLS between all functions with a cluster CA (`deploy/run/g5c-pki.sh`); certificate renewal by SIGHUP without a restart.
- OAuth2 access tokens of the NRF enforced between all functions (TS 33.501 13.4.1).
- Secrets only as files or the output of a command (`exec:`); no secret in a log; K / OPc encrypted at rest; UDM master key rotation with `rewrap`.
- Audit lines for provisioning and policy changes; threat model (`docs/security/threat-model.md`).

### Operations (Phase 8)
- `tools/cli/g5c-subscribers`: bulk import of Open5GS, free5GC and CSV subscribers (validated like the UDM does, applied through `g5c-ctl`) and a key-less export.
- Nudm_EventExposure at the UDM (`/nudm-ee/v1`): loss of connectivity, CM state, location and reachability events for a UE, a GPSI or any UE, relayed from the AMF; `nef.events_via_udm` routes the NEF's monitoring events through it.
- Operator tools and test helpers: `g5c-init`, scenarios (`g5c-scenario`, `g5c-api`, link impairment with `tc netem`), `g5c-dn`, `g5c-ladder`, `g5c-trace`, `g5c-dossier`, `g5c-sdk`, `perf_history.py` (see the admin guide).
- Finishing the first versions: bulk subscriber endpoint (`POST /admin/v1/subscribers-bulk`, `g5c-ctl subscriber bulk`, `g5c-subscribers import --apply --bulk`); event exposure subscriptions kept in a state file
  (`ee.state_file`); per-slice KPIs (`slice` label on the PDU session counter, `by:` in the KPI definitions); link impairment with reordering, duplication and jitter; RADIUS accounting in `g5c-dn`; the
  automation API follows output with `?since=`, refuses to listen on a network address without TLS, and its OpenAPI makes a client; a JavaScript client from `g5c-sdk js`; systemd units from `g5c-init --systemd`;
  `G5C_PIN_PEERS=1` / `g5c-init --pin-peers` pin every function to its callers; the TLS key log is proven to decrypt a capture with tshark.
- Usage monitoring (volume threshold, report, throttle) through the PCF, SMF and UPF; user plane traffic profiles in the load generator with a numeric check of the session AMBR on the UPF.
- Failure injection in the AMF and the SMF (`amf.inject`, `smf.inject`); identity pinning of client certificates (`sbi.tls.allowed_peers`) and revocation lists (`sbi.tls.crl`, `g5c-pki.sh revoke`).
- Trace ids over the SBI (`traceparent`) in every log line; `/openapi.json` on every function; an operator console at the UDM (`/console`).
- KPIs from one definition file (`deploy/ops/kpis.json`): `tools/cli/g5c-kpi` for lab runs and gates, generated Prometheus recording rules for dashboards.
- `G5C_TLS_KEYLOG=<file>` writes the TLS session secrets (NSS key log, mode 0600) so Wireshark can decrypt a capture of the SBI; off by default, a warning is printed when on, for debugging only.
- Charging data records: one JSON line per PDU session with volumes and duration measured by the UPF (`smf.cdr.file`).
- Prometheus alert rules, Grafana dashboard, runbooks, SLOs with regression gates (`docs/ops`).
- Log level at run time (SIGUSR1 / SIGUSR2), release version in every log and metric (`g5c_build_info`).
- Upgrade and rollback under load tested on every regression.

### Release engineering (Phase 9)
- systemd units, installer, administrator / installation / upgrade guides, generated API reference.
- Diagnostics bundle (`tools/cli/g5c-diag`), log and configuration redaction (`tools/cli/g5c-redact`), capture helper (`tools/cli/g5c-capture`).
- Signed release archives, SBOM, automated licence audit, NOTICE, release manifest (`tools/release/release.sh`).

### Fixed during the release candidate
- AMF: a de-registered UE context stayed for ever when the gNB closed its association right behind the request (found by the small-load test, one run in eight).
- SMF: a read of an unset response when the UPF did not answer an N4 request.
- SMF: the S-NSSAI of the PFCP session establishment was one octet instead of the four of TS 29.244 8.2.176 (found with Wireshark in a capture of the demo).
- AMF: acknowledgement of every SCTP packet at once (the gNB retransmitted two messages because of the kernel's 200 ms SACK delay).
- UPF: SIGHUP terminated it; it now reloads certificates.
- NRF: its default self URI used http and 127.0.0.1 whatever its configuration.

### Not in this release
Roaming, non-3GPP access, EAP-TLS, Nchf, lawful intercept (design only), shared-state high availability, PCF UE policy and usage monitoring, Nudm_EventExposure, a Kubernetes operator, multi-PLMN, a user
plane beyond one core of userspace forwarding. Containers and Kubernetes manifests are written but unverified.
