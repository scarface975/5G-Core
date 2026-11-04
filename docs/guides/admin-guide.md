# Administrator guide

Release 0.9.0-rc1. For installation see `install.md`, for upgrades `upgrade.md`, for alerts and what to do about them `ops/runbooks.md`, for capacity `ops/slo.md`, for every HTTP route `api/README.md`.

## Subscribers (UDM admin API, `g5c-ctl`)
`g5c-ctl` talks to the UDM's `/admin/v1` with the admin token (`--token-file`, or `G5C_ADMIN_TOKEN`); over mutual TLS it uses the client certificate named by `G5C_TLS_CA`, `G5C_TLS_CERT`, `G5C_TLS_KEY`.
```
g5c-ctl subscriber add --supi imsi-001010000000001 --k <32 hex> (--op <32 hex> | --opc <32 hex>) [--amf HEX] [--sqn HEX] [--slice SST[:SD]]... [--dnn NAME]...
g5c-ctl subscriber add --json FILE|-        # the full record, for per-slice DNNs, AMBR, 5QI
g5c-ctl subscriber get SUPI | list | delete SUPI
```
**Bulk import and export** (`tools/cli/g5c-subscribers`): converts an Open5GS dump (`mongoexport` of the `subscribers` collection), free5GC web-console subscriber documents or a CSV into the UDM's documents,
checks each one the way the UDM does and sends them through `g5c-ctl`:
```
tools/cli/g5c-subscribers import --format open5gs subscribers.json --dry-run                 # validate only; a bad record is named (never its keys) and the rest still counts
tools/cli/g5c-subscribers import --format open5gs subscribers.json --apply --udm URL --token-file admin_token
tools/cli/g5c-subscribers import --format csv subs.csv --out subs.jsonl                      # the converted documents, one per line (they hold K and OPc in clear: keep the file private)
tools/cli/g5c-subscribers export --format csv --udm URL --token-file admin_token              # an inventory: SUPI, SQN, slices, DNNs; no keys
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

**Slice admission control**: `amf.slice_limits: [ { sst: 1, sd: "000001", max_ues: 1000 } ]` caps the UEs registered in a slice at this AMF (a full slice is left out of the allowed NSSAI and put in the rejected NSSAI; a UE that has the slice already keeps it; metric `g5c_amf_slice_admission_total`), and `smf.slice_limits: [ { sst: 1, max_sessions: 5000 } ]` caps PDU sessions (refused with 5GSM cause #69; `g5c_smf_slice_admission_total`). Counts are per function instance.

**Power saving**: `amf.power_saving: { mico: true, edrx: true, max_edrx_cycle: 13, psm: true, max_t3324_s: 600 }` (all on by default) grants MICO mode, extended DRX and the active timer T3324 to a UE that asks. An idle UE in MICO mode, or after its T3324, is not paged: the SMF's transfer fails at once with UE_NOT_REACHABLE (`g5c_amf_paging_suppressed_total{reason}`). A UE with extended DRX is paged with its cycle and paging time window.

**Online charging**: `chf` (a function of its own, `chf: { default_balance_bytes, accounts: [ { supi, balance_bytes } ], max_grant_bytes, validity_s, cdr_file }`) and `smf.chf: { uri, rating_group, quota_bytes, required }`. With `required: true` a session whose charging session the CHF denies is refused. Start it in the cluster with `G5C_CHF=1`.

## Security
* **Mutual TLS** between all functions (`sbi.tls`), **access tokens** of the NRF on top (`oauth2: { enforce, acquire }`, TS 33.501 13.4.1). Certificates: `deploy/run/g5c-pki.sh` (issue, renew, status, check); renewal needs
  no restart. The CA key belongs offline.
* **Secrets** are files (mode 600) named in the configuration; `exec:<absolute command>` reads one from a vault or KMS client instead. Nothing secret is written to a log (`g5c-cluster.sh ns secrets` checks).
* **Master key rotation (UDM)**: put the new key in `master_key_file` and the old one in `master_key_previous_file`, restart the UDM (credentials stored under the old key still open), `POST /admin/v1/keys/rewrap`
  (re-protects every stored credential under the new key; the answer counts `rewrapped`, `alreadyCurrent`, `failed`), remove `master_key_previous_file`, restart. Tested by `g5c-cluster.sh ns ops`.
* **SUCI privacy**: `hn_keys` (Profile A / B) conceal the subscriber identity on the radio path; `suci: { null_scheme: reject }` at the UDM refuses a SUCI sent in clear (403 `AUTHENTICATION_REJECTED`; the default `allow`
  keeps labs and the UERANSIM default working). `tools/cli/g5c-privacy CAPTURE` reads a capture of N1 / N2 and reports a null-scheme SUCI, an IMSI in clear, a SUCI scheme output that repeats, a Registration Accept that
  does not reallocate the 5G-GUTI, and with `--msin DIGITS` the subscriber digits found as ASCII or packed BCD anywhere; exit 1 on a high finding. Messages after the Security Mode Command are ciphered and are not read.
* **Roles and tenants for the admin APIs**: `admin_tokens_file` (UDM and PCF) lists who may do what: each token has a name, the SHA-256 of the token (the file never holds a token), roles and optionally a tenant. Roles:
  `read` (list and show subscribers, policies, sessions), `provision` (create, change and delete subscribers, single and bulk), `policy` (change policies, end sessions) and `key-admin` (re-wrap the credential keys; not for a
  tenant). A tenant has SUPI prefixes (`"tenants": {"acme": {"supi_prefixes": ["imsi-0010199"]}}`) and its tokens see and change only the subscribers, policies and sessions inside them: what lies outside is simply not
  there (404, never a 403 that would say it exists), a request to create one outside is 403, and a bulk request judges each record. Too few roles is 403 and names the missing role; no or an unknown token is 401. Every
  audit line names who did it (`by=<token name>`). `tools/cli/g5c-tokens FILE new NAME --roles read,provision --tenant acme` makes a token and prints it once; `tenant`, `list` and `revoke` maintain the file, which is
  read again when it changes (a revoked token stops working within a second, no signal needed; a file that no longer parses leaves the old tokens in force and is logged). The single `admin_token_file` keeps working
  as the principal `admin` with every role, next to the file or alone.
* **Admin tokens** are bearer secrets: one per operator system, rotate by replacing the file and restarting the function.

## Operating
* **Logs**: one line per significant event on standard output (journald under systemd), `log: { level: info, json: true }` for structured output. **SIGUSR1** raises a running function to debug level, **SIGUSR2**
  puts it back (no restart); every start logs the release version. Provisioning and policy changes carry the tag `g5c_audit`.
* **Metrics**: `GET /metrics` on every function (Prometheus text); `deploy/ops/prometheus-rules.yml` has the alert rules, `grafana-g5c.json` the dashboard.
* **Configuration reload**: **SIGHUP** (and `POST /admin/v1/reload`, `g5c-ctl --url BASE reload [--dry-run | status]`) makes a function read the file it was started from again. The new file is validated like at
  start-up (a bad one changes nothing: `rejected`), compared with what is in force, and the sections that changed are applied one after the other where the function can do it live: `overload`, `events` and
  `log.level` in every function, `suci` at the UDM, `amf.overload` at the AMF. Whatever else changed (a slice list, a TAC, the SBI address, a policy file) is listed as `restartRequired` and stays listed on every later
  reload until the function is restarted. If a section cannot be applied the ones before it are put back (`rolled-back`, `failedSection`). After the change the function is watched for `reload.settle_ms` (default
  1000 ms): if it stops being ready or answers three server errors, everything is put back too. `reload: { token_file: /etc/g5c/keys/reload.token, settle_ms: 1000 }` enables the endpoint (bearer token; HTTP
  200 `applied` / `unchanged` / `dry-run` / `restart-required`, 400 `rejected`, 409 `rolled-back`; `GET` returns the last report); `g5c_config_reloads_total{result}` counts the outcomes and every reload leaves a
  `g5c_audit` line (and so an event, if `events` is on). Certificates are still reloaded by the same SIGHUP.
* **Overload and rate control**: `amf: { overload: { registrations_per_s, per_gnb_per_s, burst_s, t3346_s } }` makes the AMF refuse registrations above the rate (for all gNBs and for each) with 5GMM cause #22 and the
  back-off timer T3346 (default 30 s) instead of queueing them; `overload: { rate_per_source, burst, retry_after_s, capacity_rps }` (top level, any function) limits each client address on the SBI: above the rate a
  request gets 429 with `Retry-After` and `3gpp-Sbi-Oci` (TS 29.500 6.4), health and metrics are never limited, and `capacity_rps` makes every answer carry `3gpp-Sbi-Lci` with the load. The SBI client of every function
  honours `Retry-After` and the overload reduction metric (it does not send to that producer for the period, or only the share not reduced); the SCP reselects another producer, does not count a busy one as broken,
  and answers 429 itself when all are busy. Behind an SCP the producers see the SCP's address as the source. `cluster_overload_amf` runs a storm (`load_core` with `G5C_LOAD_STORM_SECONDS`): about 22,000 registrations in
  4 s against 20 admitted a second, all the rest refused with #22, the AMF ready throughout and a normal wave served afterwards.
* **Alarm and event streaming**: `events: { min_level: warn, syslog: { host, port, proto: udp|tcp|tls, ca, facility }, http: { uri, ca, batch } }` sends every warning and error and every `g5c_audit` line (whatever the log level)
  to a collector as JSON: RFC 5424 syslog (octet-counted over tcp and tls; `tls` verifies the collector against `ca`) and/or a POST of a JSON array. An event has `time`, `function`, `instance`, `host`, `kind` (`alarm` or
  `audit`), `source`, `text`, and for alarms the ITU-T X.733 fields `perceivedSeverity` (error: major, warning: minor), `eventType`, `probableCause`. A queue of 2048 events and one worker keep the function from waiting on the
  network; an unreachable collector is retried for about five seconds per batch, then the events are counted in `g5c_events_dropped_total{reason="send"}` (a full queue drops the oldest, `reason="queue"`); delivered events
  are in `g5c_events_sent_total{sink}`. One stream per process. The Prometheus alerts become alarms in the same schema: `deploy/ops/alarms.json` (generated, `tools/gen/gen_alarms.py`) gives each alert rule its
  severity, event type, probable cause and runbook link, and `tools/cli/g5c-alarms serve --syslog HOST:PORT` is an Alertmanager webhook receiver that forwards them (a resolved alert is a `cleared` alarm).
* **Charging data records**: with `smf.cdr: { file: /var/lib/g5c/cdr.jsonl }` the SMF writes one JSON line per released PDU session: `supi`, `pduSessionId`, `dnn`, `snssai`, `ueIpv4Address`, `upf`, `startTime`,
  `endTime`, `duration`, `uplinkOctets`, `downlinkOctets`, packets, `usageReported`, `closeCause`, `recordSequenceNumber`, `smfInstanceId`. The UPF measures (a usage reporting rule installed with the session);
  the file is opened for every record, so rotating by rename needs no signal. `tools/cli/g5c-cdr report` turns the file into usage, quality and roaming reports and checks the file itself for lost or duplicated records. The records are the integration point for a charging system (an Nchf client is not part of this release).
* **KPIs**: `deploy/ops/kpis.json` defines the service KPIs once (registration, authentication, service request, PDU session and handover success rates, latency, throughput, drops, session and UE counts).
  `tools/cli/g5c-kpi URL...` computes them from live `/metrics`, `--interval 60` gives the last minute, `--baseline OLD NEW --elapsed S` the period between two saved samples, and `--check` exits 1 when a KPI misses its target
  (usable as a lab gate). `deploy/ops/prometheus-kpi-rules.yml` holds the Prometheus recording rules generated from the same file (`g5c-kpi --rules`), so a dashboard and a lab report use the same arithmetic.
  Counters carry no slice label yet; per-slice KPIs need one.
* **Event exposure**: the UDM serves Nudm_EventExposure (`/nudm-ee/v1/{ueIdentity}/ee-subscriptions`; a SUPI, a GPSI or `anyUE`): events LOSS_OF_CONNECTIVITY, UE_CONNECTION_MANAGEMENT_STATE, LOCATION_REPORTING and
  UE_REACHABILITY_FOR_DATA, `reportingOptions` `maxNumOfReports` and `expiry`. It subscribes at the serving AMF and relays the AMF's reports as MonitoringReports. Configuration: `ee: { amf_uri, notify_uri }` (both optional:
  the AMF is taken from the UE's registration or found through the NRF, the notification address from `sbi.address`). With `nef: { events_via_udm: true }` the NEF's monitoring events go through the UDM instead of straight to
  the AMF. Subscriptions are kept in memory (lost when the UDM restarts, as the AMF's are).
* **Debugging TLS**: `G5C_TLS_KEYLOG=/path` writes the TLS session secrets for Wireshark (see `docs/ops/runbooks.md`); never leave it set in production.
* **Health**: `/health/live`, `/health/ready`; systemd restarts a function that exits.
* **Diagnostics**: `tools/cli/g5c-diag` makes a bundle (versions, host, logs, metrics, configurations, certificate expiry) with identities, keys and tokens removed (`tools/cli/g5c-redact`); `tools/cli/g5c-capture n2|n3|n4|sbi|core`
  captures signalling with the right filters (a capture holds identities: handle it as personal data; the SBI is encrypted).

## Tools and test helpers
| Tool | What it does |
|---|---|
| `deploy/run/g5c-init` | Guided setup for one host: PLMN, tracking areas, N2/N3 addresses and UE pool in, twelve configurations, fresh secrets, a CA and certificates, and a `START-HERE.md` out. |
| `tools/cli/g5c-subscribers`, `tools/cli/g5c-kpi` | Bulk import / export of subscribers; service KPIs from one definition file (above). |
| `tools/cli/g5c-fanout`, `tools/cli/g5c-tester` | One population from many load processes (`--processes`, `--slice K/N` over hosts); the load generator pointed at a core (`--amf ip:port --subscribers URL`) with storms, mobility and traffic, and `pack` for one bundle. |
| `tools/cli/g5c-interop`, `deploy/radio-kit/g5c-radio-kit` | The interoperability register (`docs/interop`) checked; the radio lab (OCUDU gNB + srsUE over ZeroMQ against our core) in one command. |
| `tools/cli/g5c-nwdaf` | Analytics from the functions' counters (NF load, slice load, registration anomaly) as JSON in the Nnwdaf shape and as Prometheus series. |
| `tools/cli/g5c-fleet`, `tools/cli/g5c-triage`, `tools/cli/g5c-conform` | Fleet reports and group provisioning for device populations; a diagnostics bundle checked against known issues (`docs/ops/known-issues.json`); a capture checked against the procedure rules (`docs/conformance/procedures.json`). |
| `tools/cli/g5c-scenario`, `scenarios/` | A test as YAML steps (load, kill, restart, impair a link, assert on metrics and KPIs, HTTP calls); `deploy/run/g5c-cluster.sh ns scenario FILE...` runs them against a private cluster. |
| `tools/cli/g5c-api` | The same runs from CI or a notebook over HTTP with a bearer token (start, status, stop, list). |
| `tools/cli/g5c-dn` | The data network behind N6 for scenarios: DNS, HTTP (`/bytes/N`, `/delay/MS`), UDP echo, a RADIUS server for slice authentication. |
| `tools/cli/g5c-ladder` | A capture as one call-flow ladder per UE and per N4 session, with red flags (no Security Mode Command, unanswered requests, malformed PFCP, retransmissions); needs `tshark`. |
| `tools/cli/g5c-privacy` | A capture of N1 / N2 checked for subscriber identities in clear, null-scheme SUCIs, repeated SUCIs and GUTIs that were not reallocated (`--msin` searches the wire for given digits). |
| `tools/cli/g5c-atlas-live` | The Atlas fed by a running core: `serve --nf amf=URL --nf smf=URL ... --nrf URL` reads health, release and metrics of the functions and the NRF's registry, computes the KPIs with the arithmetic of `g5c-kpi` (since start and over the last minute, with targets) and serves a page that refreshes itself. Read-only, no login: bind it to a trusted interface. `snapshot` prints the JSON the page reads. |
| `tools/cli/g5c-compat` | "Does your core behave like Open5GS?" as a report: runs the nine differential tests against the installed Open5GS 2.8.0 (`run`) or reads their output (`parse`) and writes one row per compared case with a verdict (match, ours adds, documented difference with its reason, unexplained) as text, Markdown, HTML, CSV and JSON. Exit 1 on an unexplained difference. |
| `tools/cli/g5c-replay` | A capture of N2 as a script, replayed against the AMF over SCTP (`extract`, `show`, `run --amf HOST:PORT`): each answer is compared with the recorded one and the first difference is reported; the replay stops where the recorded session's keys would be needed. |
| `tools/cli/g5c-mutate` | Negative testing for LAB use: `sbi URL` sends hostile requests to every route of a function (from its `/openapi.json`) and checks for 5xx, silence, a function that stops being ready, and accepting what is not JSON; `n2 CAPTURE --amf HOST:PORT` corrupts the gNB messages. |
| `tools/cli/g5c-lab` | The training exercises of `docs/training`: `list`, `show N`, `check N|all` (runs the reference solution on a private cluster and judges it). |
| `tools/cli/g5c-cdr` | Reports from the SMF charging records (`smf.cdr`): usage by DNN, slice, UPF, hour, day or subscriber, session length and throughput, why sessions ended, the share of inbound roamers against a home PLMN, the heaviest subscribers, and data-quality checks (records missing from the sequence, duplicates, unreadable lines, sessions without a usage measurement; exit 1 on a problem). `--csv` exports for the operator's own tools; `--from` / `--to` make it a cron job. |
| `tools/cli/g5c-why` | Why a subscriber failed: reads the logs of the functions (a directory, files or standard input, text or JSON), explains each failure in plain words with the likely cause, the function and clause, what to check and the runbook entry, and joins lines of one trace across functions (`--supi`, `--json`, `--all`). |
| `tools/cli/g5c-alarms` | Prometheus alerts as X.733 alarms: `convert` a webhook body, or `serve` as an Alertmanager receiver that forwards to syslog and HTTP collectors (catalog: `deploy/ops/alarms.json`). |
| `tools/cli/g5c-trace` | The logs of all functions joined by trace id: one timeline per procedure (`traceparent` is carried over the SBI; the AMF starts one trace per UE connection; N4 carries none). |
| `tools/release/g5c-dossier` | The conformance report (HTML, CSV, JUnit), the security assurance report (`security`: the 17 named cases of `docs/conformance/security-suite.json` with their results and the security rows of the matrices; `--regex` is the `ctest -R` expression that runs exactly the suite) and the release dossier (reports, test results, SBOM, licence audit, threat model, guides, hashes) in one folder and one zip. |
| `tools/cli/g5c-sdk` | A Python client and a Postman collection generated from the `/openapi.json` every function serves. |
| `tools/release/perf_history.py` | Performance per release, regressions against the earlier releases, a chart. |

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
Roaming (SEPP, home-routed sessions), non-3GPP access, EAP-TLS, rating and offline charging in a standard format (online charging with quota grants and renewal during the session exists, volume only), slice-specific authentication (NSSAA), RedCap, lawful intercept (a design is in `docs/security/lawful-intercept-design.md`), shared-state high availability of the AMF and
SMF (a function that dies loses its connected UEs; the registrations and sessions come back from the state file), multi-PLMN.

## Extension hooks
`smf.cdr.sink_command` (absolute path and arguments), `sink_timeout_s` (default 10) and `sink_queue` (default 1024) hand every charging record, as one line of JSON on standard input, to a program of yours (contract `g5c-hook/1`, `libs/nfcore/include/g5c/hook.h`): the program runs with an empty environment except `G5C_HOOK` and `G5C_HOOK_API`, exit status 0 means taken, a program that does not finish is killed with whatever it started, and a full queue drops the newest item. Counters: `g5c_hook_items_total{hook,result}`. The record is also written to `smf.cdr.file`; write anything you cannot lose to a file first, the hook is not retried.

## Policy scripts
`policy.scripts` at the PCF: a list of `{ when: "<condition>", session_ambr: {...}, default_qos: {...} }`. The first entry whose condition holds for the session adds its profile to the session's policy, below the subscriber's own policy document and above the operator's DNN profile. A condition is built from the fields `supi`, `dnn`, `sst`, `sd`, `plmn` and `qi5` (the subscribed default 5QI), strings in single quotes, numbers, `==` `!=` `<` `<=` `>` `>=`, `startswith` `endswith` `contains`, `in [a, b]`, `and` `or` `not` and parentheses. It has no loops and no calls and is limited to 400 characters; a mistake is reported when the configuration is read. Example: `when: "dnn == 'iot' and supi startswith 'imsi-00101'"`.

## N2 multi-homing
`amf.ngap.addresses: [10.0.0.5, 10.0.1.5]` replaces `address` and binds the N2 SCTP endpoint to every listed address (same family, same port); a gNB that is configured with both reaches the AMF over either path. Failover between the paths is the gNB's SCTP stack's business.

## Roaming: the SEPP
`sepp` (a function of its own, `configs/sepp.yaml`) sits at the edge of the network. A local function that needs another network sends its request there with the partner's apiRoot in `3gpp-Sbi-Target-apiRoot`; the SEPP checks the policy of that partner, sends the request to the partner's SEPP over TLS and returns the answer. A request from a partner is recognised by the address it comes from (`sources`; there is no header for it in the TLS mode of TS 29.573, so pin the partner SEPP certificate with `sbi.tls.allowed_peers` as well), and the SEPP applies the partner's policy (`allow_services`, `deny_path_contains`, `rate_per_s` / `burst`, `supi_must_be_local`) and delivers to the local function that the target apiRoot stands for (`local_targets`). Counters: `g5c_sepp_requests_total{partner,direction,result}`. Use `sbi.tls.allowed_peers` to pin the partner SEPP's certificate. The N32-c handshake and PRINS are not implemented; the relation between two networks is configured on both sides.
