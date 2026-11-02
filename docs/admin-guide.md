# Administrator guide

Release 0.9.0-rc1. For installation see `install.md`, for upgrades `upgrade.md`, for alerts and what to do about them `ops/runbooks.md`, for capacity `ops/slo.md`, for every HTTP route `api/README.md`.

## Subscribers (UDM admin API, `g5c-ctl`)
`g5c-ctl` talks to the UDM's `/admin/v1` with the admin token (`--token-file`, or `G5C_ADMIN_TOKEN`); over mutual TLS it uses the client certificate named by `G5C_TLS_CA`, `G5C_TLS_CERT`, `G5C_TLS_KEY`.
```
g5c-ctl subscriber add --supi imsi-001010000000001 --k <32 hex> (--op <32 hex> | --opc <32 hex>) [--amf HEX] [--sqn HEX] [--slice SST[:SD]]... [--dnn NAME]...
g5c-ctl subscriber add --json FILE|-        # the full record, for per-slice DNNs, AMBR, 5QI
g5c-ctl subscriber get SUPI | list | delete SUPI
```
**Bulk import and export** (`tools/g5c-subscribers`): converts an Open5GS dump (`mongoexport` of the `subscribers` collection), free5GC web-console subscriber documents or a CSV into the UDM's documents,
checks each one the way the UDM does and sends them through `g5c-ctl`:
```
tools/g5c-subscribers import --format open5gs subscribers.json --dry-run                 # validate only; a bad record is named (never its keys) and the rest still counts
tools/g5c-subscribers import --format open5gs subscribers.json --apply --udm URL --token-file admin_token
tools/g5c-subscribers import --format csv subs.csv --out subs.jsonl                      # the converted documents, one per line (they hold K and OPc in clear: keep the file private)
tools/g5c-subscribers export --format csv --udm URL --token-file admin_token              # an inventory: SUPI, SQN, slices, DNNs; no keys
```
CSV columns: `supi,k,opc,op,amf,sqn,msisdn,slices,dnns,ue_ambr_ul,ue_ambr_dl` (`slices` `1;2:00000a`, `dnns` `internet;ims/IPV4V6`). Open5GS units and session types, free5GC AMBR strings and QoS profiles are carried over;
things that have no equivalent here (PCC rules, several MSISDNs) are left out. Test the import on a copy of the data first.

K and OPc are encrypted (AES-256-GCM, the SUPI as associated data) with the UDM's master key before they reach the UDR; the admin API never returns them. Every provisioning change writes an audit line
(`g5c_audit`) to the UDM's log. There is no web UI in this release; the API is the interface for a provisioning system.

## Policies (PCF admin API)
```
g5c-ctl --pcf https://pcf.example:7775 policy put SUPI FILE|-     # session AMBR, default QoS, PCC rules for this subscriber; sessions that exist are updated at once
g5c-ctl policy get SUPI | delete SUPI
g5c-ctl session list | terminate SMPOLICYID
```
The default policy for subscribers without one is the `policy:` block of the PCF's configuration.

## Slices
The NSSF decides which S-NSSAIs a UE is allowed: `nssf.slices` lists what the PLMN serves (and where: tracking areas), the UE's subscribed slices come from the UDM (`--slice`), and the AMF asks the NSSF
at registration and at every PDU session (`amf.nssf: { enabled: true }`; without an answer the AMF's own `amf.slices` list decides). A slice the NSSF does not serve is rejected in the registration
accept's rejected NSSAI; a PDU session on it is refused. The SMF's `smf.dnns` give every DNN its address pool.

## Security
* **Mutual TLS** between all functions (`sbi.tls`), **access tokens** of the NRF on top (`oauth2: { enforce, acquire }`, TS 33.501 13.4.1). Certificates: `deploy/run/g5c-pki.sh` (issue, renew, status, check); renewal needs
  no restart. The CA key belongs offline.
* **Secrets** are files (mode 600) named in the configuration; `exec:<absolute command>` reads one from a vault or KMS client instead. Nothing secret is written to a log (`g5c-cluster.sh ns secrets` checks).
* **Master key rotation (UDM)**: put the new key in `master_key_file` and the old one in `master_key_previous_file`, restart the UDM (credentials stored under the old key still open), `POST /admin/v1/keys/rewrap`
  (re-protects every stored credential under the new key; the answer counts `rewrapped`, `alreadyCurrent`, `failed`), remove `master_key_previous_file`, restart. Tested by `g5c-cluster.sh ns ops`.
* **Admin tokens** are bearer secrets: one per operator system, rotate by replacing the file and restarting the function.

## Operating
* **Logs**: one line per significant event on standard output (journald under systemd), `log: { level: info, json: true }` for structured output. **SIGUSR1** raises a running function to debug level, **SIGUSR2**
  puts it back (no restart); every start logs the release version. Provisioning and policy changes carry the tag `g5c_audit`.
* **Metrics**: `GET /metrics` on every function (Prometheus text); `deploy/ops/prometheus-rules.yml` has the alert rules, `grafana-g5c.json` the dashboard.
* **Charging data records**: with `smf.cdr: { file: /var/lib/g5c/cdr.jsonl }` the SMF writes one JSON line per released PDU session: `supi`, `pduSessionId`, `dnn`, `snssai`, `ueIpv4Address`, `upf`, `startTime`,
  `endTime`, `duration`, `uplinkOctets`, `downlinkOctets`, packets, `usageReported`, `closeCause`, `recordSequenceNumber`, `smfInstanceId`. The UPF measures (a usage reporting rule installed with the session);
  the file is opened for every record, so rotating by rename needs no signal. The records are the integration point for a charging system (an Nchf client is not part of this release).
* **KPIs**: `deploy/ops/kpis.json` defines the service KPIs once (registration, authentication, service request, PDU session and handover success rates, latency, throughput, drops, session and UE counts).
  `tools/g5c-kpi URL...` computes them from live `/metrics`, `--interval 60` gives the last minute, `--baseline OLD NEW --elapsed S` the period between two saved samples, and `--check` exits 1 when a KPI misses its target
  (usable as a lab gate). `deploy/ops/prometheus-kpi-rules.yml` holds the Prometheus recording rules generated from the same file (`g5c-kpi --rules`), so a dashboard and a lab report use the same arithmetic.
  Counters carry no slice label yet; per-slice KPIs need one.
* **Event exposure**: the UDM serves Nudm_EventExposure (`/nudm-ee/v1/{ueIdentity}/ee-subscriptions`; a SUPI, a GPSI or `anyUE`): events LOSS_OF_CONNECTIVITY, UE_CONNECTION_MANAGEMENT_STATE, LOCATION_REPORTING and
  UE_REACHABILITY_FOR_DATA, `reportingOptions` `maxNumOfReports` and `expiry`. It subscribes at the serving AMF and relays the AMF's reports as MonitoringReports. Configuration: `ee: { amf_uri, notify_uri }` (both optional:
  the AMF is taken from the UE's registration or found through the NRF, the notification address from `sbi.address`). With `nef: { events_via_udm: true }` the NEF's monitoring events go through the UDM instead of straight to
  the AMF. Subscriptions are kept in memory (lost when the UDM restarts, as the AMF's are).
* **Debugging TLS**: `G5C_TLS_KEYLOG=/path` writes the TLS session secrets for Wireshark (see `docs/ops/runbooks.md`); never leave it set in production.
* **Health**: `/health/live`, `/health/ready`; systemd restarts a function that exits.
* **Diagnostics**: `tools/g5c-diag` makes a bundle (versions, host, logs, metrics, configurations, certificate expiry) with identities, keys and tokens removed (`tools/g5c-redact`); `tools/g5c-capture n2|n3|n4|sbi|core`
  captures signalling with the right filters (a capture holds identities: handle it as personal data; the SBI is encrypted).

## Tools and test helpers
| Tool | What it does |
|---|---|
| `deploy/run/g5c-init` | Guided setup for one host: PLMN, tracking areas, N2/N3 addresses and UE pool in, twelve configurations, fresh secrets, a CA and certificates, and a `START-HERE.md` out. |
| `tools/g5c-subscribers`, `tools/g5c-kpi` | Bulk import / export of subscribers; service KPIs from one definition file (above). |
| `tools/g5c-scenario`, `scenarios/` | A test as YAML steps (load, kill, restart, impair a link, assert on metrics and KPIs, HTTP calls); `deploy/run/g5c-cluster.sh ns scenario FILE...` runs them against a private cluster. |
| `tools/g5c-api` | The same runs from CI or a notebook over HTTP with a bearer token (start, status, stop, list). |
| `tools/g5c-dn` | The data network behind N6 for scenarios: DNS, HTTP (`/bytes/N`, `/delay/MS`), UDP echo, a RADIUS server for slice authentication. |
| `tools/g5c-ladder` | A capture as one call-flow ladder per UE and per N4 session, with red flags (no Security Mode Command, unanswered requests, malformed PFCP, retransmissions); needs `tshark`. |
| `tools/g5c-trace` | The logs of all functions joined by trace id: one timeline per procedure (`traceparent` is carried over the SBI; the AMF starts one trace per UE connection; N4 carries none). |
| `tools/g5c-dossier` | The conformance report (HTML, CSV, JUnit) and the release dossier (report, test results, SBOM, licence audit, threat model, guides, hashes) in one folder and one zip. |
| `tools/g5c-sdk` | A Python client and a Postman collection generated from the `/openapi.json` every function serves. |
| `tools/perf_history.py` | Performance per release, regressions against the earlier releases, a chart. |

**Usage monitoring** (PCF, SMF, UPF): with `pcf.policy.usage_monitoring: { volume_threshold: 500000000, throttle: { uplink: 1 Mbps, downlink: 1 Mbps } }` every SM policy decision carries a volume threshold (`umDecs`,
referenced by the session rule, trigger `US_RE`). The SMF installs a second usage reporting rule (URR 2, separate from the charging one) with that threshold on the UPF; when the UPF reports that the volume has passed, the SMF
sends the PCF an update with the `accuUsageReports`, and the PCF answers with the throttle AMBR, which the SMF applies at once (QER update on the UPF, modification command to the UE and the gNB). Counters:
`g5c_smf_usage_reports_total{result}`, `g5c_pcf_usage_reports_total`, `g5c_pcf_usage_throttled_total`. One threshold for all sessions in this release (per-subscriber thresholds, time thresholds and re-arming after a billing period are not built).

**User plane traffic profiles**: the load generator can send uplink GTP-U for every UE once it has its session (`load: {ues: 4, traffic_mbps: 4, traffic_ms: 1500, expect_mbps: 1}` in a scenario, or `G5C_LOAD_TRAFFIC_MBPS`,
`G5C_LOAD_TRAFFIC_MS`, `G5C_LOAD_TRAFFIC_SIZE`, `G5C_LOAD_EXPECT_MBPS`). The UPF's own counters give what it forwarded and what its rate limiter dropped; the run fails when the delivered rate per UE is not within 0.5x to 1.3x of the expected one
(`scenarios/traffic-ambr.yaml`: a session AMBR of 1 Mbit/s set with `G5C_AMBR_UL` / `G5C_AMBR_DL` held a 4 Mbit/s offer to 1.03 Mbit/s). Uplink only: downlink needs a sender on the data network side.

**Pinning every function to its callers**: `G5C_PIN_PEERS=1` in the cluster script (or `g5c-init --pin-peers`) writes `sbi.tls.allowed_peers` into every configuration from the call graph: with the SCP in the middle a
function accepts the SCP, the NRF and the operator's certificate, and the NRF and the SCP accept every function. A full wave runs under it (`cluster_load_pinned`).

**Bulk and persistence**: `POST /admin/v1/subscribers-bulk` stores up to 1000 subscribers, each on its own, and answers per record; `g5c-subscribers import --apply --bulk` uses it in batches of 200. The UDM keeps its event
exposure subscriptions in `ee.state_file`, so a restart does not lose them. KPIs with `by: snssai` give one row per slice.

**Failure injection** (for testing a RAN against a core that misbehaves; a warning is logged at start, every injection is counted in `g5c_*_injected_total`): `amf.inject: { registration_reject: [{ supi: imsi-00101, cause: 11 }], accept_delay_ms: 2000 }`,
`smf.inject: { pdu_session_reject: [{ supi: imsi-00101, status: 403 }], n4_drop_responses_percent: 10 }`. `supi` is a prefix.

**Who may connect, and revocation** (mutual TLS): `sbi.tls.allowed_peers: [admin, scp, amf-*]` lets only client certificates with those common names in (the PKI names a certificate after its function, so a stolen
certificate of one function cannot be used as another); `sbi.tls.crl: /path/ca.crl` checks client certificates against the CA's revocation list, read again on SIGHUP. `deploy/run/g5c-pki.sh revoke <dir> <name>` adds
a certificate to the list (`g5c-cluster.sh certs revoke NAME` also signals the functions). Without a list every certificate of the CA is accepted, as before.

**Console**: `https://<udm>/console` (only while the admin API is on) lists, adds, imports and deletes subscribers with the admin token typed in; a browser needs TLS to reach the function (import the operator certificate). Policies and
sessions are on the PCF and are not in the console yet.

## Capacity and limits
`docs/ops/slo.md`. In configuration: UE pools (`smf.dnns[].ipv4_pool`), `upf.max_sessions`, `amf.max_unauthenticated`, `workers` of each function. A function that reaches a limit answers with 503 / 429 and
counts it (`g5c_sbi_requests_total{status}`), which the alert rules watch.

## What this release does not do
Roaming (SEPP, home-routed sessions), non-3GPP access, EAP-TLS, charging via Nchf, lawful intercept (a design is in `docs/security/lawful-intercept-design.md`), shared-state high availability of the AMF and
SMF (a function that dies loses its connected UEs; the registrations and sessions come back from the state file), multi-PLMN.
