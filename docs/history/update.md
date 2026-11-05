# Progress Log (update.md)

Append-only, **newest entry first**. One entry per working session or merged milestone.

Entry template:
```
## YYYY-MM-DD - Phase N - short title
- Built:
- Spec clauses covered:
- Tests added / status:
- Known gaps:
- Next:
```

## 2026-11-05 - Phase 9 - possible-now backlog, ORAN emulator proof, CI green
- Built: the ORAN emulator proof (`deploy/oran`); the SMF buffers downlink until the AN tunnel is known; SMF N4 timers (request, heartbeat, association retry, lost-after) on the virtual clock; reload of the whole PCF `policy` section and `g5c-policy-eval`; `memberof` and device groups in policy scripts; hooks: UDM `auth_hook`, AMF `event_hook`, PCF `decision_hook`; SEPP N32-c security capability negotiation (the PRINS-only operations answered 501); UDM device groups (`groups`, GetGroupIdentifiers, `internalGroupIds`); six more `g5c-conform` rules and whole-word phrase matching; `g5c-pm` with 19 TS 28.552 measurements, per-S-NSSAI subcounters for registrations, files and a read-only view.
- Spec clauses covered: TS 29.573 6.1.4.2 and 5.2 (N32-c), TS 28.552 5.1-5.4 (measurement names and clauses, checked against the pinned text), TS 38.413 8.2-8.7 and TS 24.501 5.6.1 (conformance rules), TS 29.503 (GetGroupIdentifiers).
- Tests added / status: 156 tests, all passing (153 under ASan + UBSan); lint clean; GitHub Actions green on 674c0c2 after `g5c-lab` learned to report a skipped exercise as a skip (the runner has no network namespaces).
- Known gaps: URSP delivery (nothing here decodes it), PRINS, one source of group membership for the UDM and the PCF, the UPF's own timers under warp, a million-subscriber run, HSM, IPsec/DTLS (see `guides/known-gaps.md`).
- Next: `guides/todo.md`.

## Status board
| NF / component | Phase | Status | Notes |
|---|---|---|---|
| libs/crypto | 0 | Done except SNOW 3G / ZUC | Milenage (all 20 TS 35.208 sets), KDF, 5G-AKA keys, SUCI ECIES A/B, NEA0/2 + NIA0/2 (TS 33.401 vectors). NIA1/3, NEA1/3 blocked on algorithm licensing (see 2026-10-01 entry) |
| libs/gtpu, libs/pfcp | 0 | Headers/framing done (C) | 200k random-input round trips each, plus replay fuzzing. Typed PFCP IEs arrive with the UPF/SMF phases |
| libs/ngap | 0 | Done (C, generic APER interpreter) | Schema generated from the pinned ASN.1; all 138 golden PDUs (14 message types) byte-exact, 21 nested transfers, robustness under ASan |
| libs/nas | 0 | Done (C) | Table-driven codec, 48 messages, security envelope, typed IEs; 33 real MACs verified; fuzz seeds from the traces |
| libs/sbi | 0 | Done (C) | libuv + nghttp2 + OpenSSL: h2c, TLS/mTLS, per-server worker pool, pooled client with deadlines, router, ProblemDetails |
| libs/base, config, nfcore, testkit | 0 | Done (C) | Checked buffers, JSON DOM, YAML-subset config, logging, Prometheus metrics; NF runtime with NRF registration + heartbeat |
| CI / licence scan / fuzz | 0 | Local gate green | `scripts/c_check.sh` (27 ctest programs, plain and ASan+UBSan, -Werror), `scripts/c_lint.sh` (banned functions, licences, gcc -fanalyzer); `ci.yml` never run (no remote); coverage-guided fuzz needs clang (not installed here) |
| Oracle test env (Open5GS + UERANSIM) | 0 | S1-S5 done | No sudo: namespaces. Golden traces S1-S3 stored. `OUR_AMF=1` / `OUR_SMF=1` / `OUR_UPF=1` / `OUR_UDM=1` / `OUR_PCF=1` swap in our C NFs |
| UDM (+udr-lite) | 1 | Done (C), interop-verified | See 2026-10-01 Phase 1 entry; re-verified against Open5GS after the C port. About 6,900 vectors/s on one host |
| PCF | 2 | Done (C), interop-verified | See 2026-10-05 Phase 2 entry; S4 policy push re-verified after the C port |
| UPF | 3 | Stage A done (C), interop-verified | See 2026-10-08 Phase 3 entry; Stage B (AF_XDP) later. |
| SMF | 4 | Done (C), interop-verified | See the 2026-10-09 and 2026-10-12 Phase 4 entries; UE-requested modification, charging, ATSSS are not in v1 scope; the handover transfers (path switch, N2 handover) were added with the AMF in Phase 5 |
| AMF | 5 | Done (C), interop-verified | See the 2026-10-13 Phase 5 entry; SNOW 3G / ZUC, AMF relocation, emergency services, non-3GPP access are not in v1 scope |
| Integration / validation | 6 | Done (C), see docs/history/phase6-baseline.md | 10,000 UEs with a session through the daemons as separate processes in 20.7 s; failure injection (SIGKILL / restart under load) recovers; soak harness `ns soak`; 72 h run, srsRAN / OCUDU / O-RAN emulator passes not done (P6-GAP-01/02) |
| NRF | 7 | Done (C), interop-verified | See the 2026-10-15 Phase 7 entry; every function discovers its peers through it; NRF-to-NRF, roaming, NF sets, producer-side token checks are not in scope yet |
| AUSF | 7 | Done (C), interop-verified | See the 2026-10-21 Phase 7 entry; 5G AKA, EAP-AKA' (UERANSIM's peer end to end), SoR / UPU protection; EAP-TLS, the UDM / AMF consumers of the protection services, producer-side tokens are not in scope yet |
| UDR | 7 | Done (C), interop-verified | See the 2026-10-23 Phase 7 entry; all four published API files generated from the pinned OpenAPI, PostgreSQL / journalled file / memory, subscriptions and notifications; `udr-lite` is gone; producer-side tokens, PFD notifications are not in scope yet |
| NSSF | 7 | Done (C), differential-verified | See the 2026-10-23 Phase 7 entry; Nnssf_NSSelection (four procedures) and Nnssf_NSSAIAvailability; slice policy in configuration; our AMF does not consume it yet, no H-NSSF query, no redirection |
| NEF | 7 | Done (C), interop-verified through the functions behind it | See the 2026-10-23 NEF entry; TrafficInfluence, MonitoringEvent, AsSessionWithQoS northbound APIs; the PCF got N5 (Npcf_PolicyAuthorization); the AMF got LOSS_OF_CONNECTIVITY and the reachability report, the UDM id translation; traffic influence by UE address, groups, UDM subscriptions, PFD management, Nnef_* services are gaps |
| Phase 8 WP1: OAuth2 access tokens | 8 | Built (C), tested end to end with every function ours | See the 2026-10-26 Phase 8 entry and ADR-0025; every function can require the NRF's token for its services and ask for one for the services it calls (`oauth2:` of the common configuration); the cluster does by default; TLS (WP2), assertions, additional scope are gaps |
| BSF | 7 | Done (C), interop-verified (optional twelfth function) | See the 2026-10-26 BSF entry; Nbsf_Management (register, discover, update, deregister) by IPv4, IPv6 longest prefix, MAC and framed routes, SamePcf, stale-binding clean-up; the PCF registers, the NEF discovers; compared with Open5GS's BSF; NRF supervision of the PCFs, ES3XX, OAuth2 are gaps |
| SCP | 7 | Done (C), interop-verified | See the 2026-10-26 SCP entry; indirect communication of TS 29.500 6.10 (Models C and D), reselection, quarantine, chained SCPs, late requests, target allow-list; every function's SBI client can send through it (`scp_client`), the cluster does by default; compared with Open5GS's SCP (`scp_differential`); redirection, OAuth2 at the SCP, default notification subscriptions, SEPP are gaps |
| Phase 8 WP2 to WP4, WP7 (CDR), WP9 | 8 | Built (C), tested on the cluster under ASan / TSan | See the 2026-10-28 and 2026-10-29 entries and ADR-0025: mutual TLS and certificate renewal, secrets hygiene, master key rotation, operations files, SLO gates, upgrade and rollback under load, charging data records, the NSSF used by the AMF for registration and PDU sessions. Open: shared-state HA, UPF 10-100 Gbit/s (hardware), PCF UE policy / usage monitoring, Nudm_EE, Nchf, lawful intercept (design only), pen test and 7 day soak (third party / time) |
| Phase 9 release candidate 0.9.0-rc1 | 9 | Built; gates pending | See the 2026-10-29 entry: versioned signed archives, SBOM, automated licence audit, NOTICE, systemd units and installer, guides, API reference, diagnostics / redaction / capture tools, pilot plan, threat model. Pending: counsel's sign-off, vulnerability scan, offline-key signing, container / Kubernetes builds, the pilot |

Decisions: see docs/adr/ (0001 Rust is superseded by 0013 C; proprietary + permissive deps, Rel-16 ceiling with Rel-17 per feature, PostgreSQL, userspace->AF_XDP, 11th NF = SCP, SNOW 3G required).

---

## 2026-10-29 - Phase 8 rest and Phase 9: charging records, key rotation, SLOs, upgrade / rollback, support tools, release candidate 0.9.0-rc1
- **Phase 8, built and tested:** charging data records (`smf.cdr.file`: a usage reporting rule on the UPF, the termination report read from the session deletion, one JSON line per released session; the
  host demo's 5 pings give 468 octets up / 420 down); the AMF consults the NSSF for PDU sessions too (`ns slices`); log level at run time (SIGUSR1 / SIGUSR2) and the release version in logs and `g5c_build_info`;
  `exec:` secret source (a KMS / vault client); the UDM's master key rotation with a previous key and `rewrap` is now tested (`ns ops`; it existed untested); upgrade and rollback of every function one at a time
  under load (`ns upgrade`); SLOs with gates (`docs/ops/slo.md`, `tools/check/check_slo.py`); threat model, lawful intercept interface design (design only).
- **Bugs found by the new tests, all fixed:** AMF kept a de-registered context for ever when the gNB closed its association behind the request (one run in eight of a 10-UE load, found while measuring the SLOs);
  the redaction filter missed multi-line PEM blocks; the usage-rule flag of policy-update contexts was cleared by a memset. Earlier today's: renewed certificates with the wrong names, N2 SACK delay, a malformed
  S-NSSAI in PFCP (see the findings table).
- **Phase 9, built:** `VERSION` 0.9.0-rc1 in every binary; `tools/release/release.sh` (gates, archives, SHA256SUMS, GnuPG signatures, smoke install of the archive, `RELEASE.json`); SBOM of all functions;
  `tools/release/licence_audit.py` (SPDX identifiers, no copyleft or foreign copyright, SBOM and THIRD_PARTY agree, test-only tools not in build files) writing `docs/legal/audit-<version>.md` and `NOTICE`;
  `deploy/systemd` units and `deploy/install.sh` (tested into a staging root); `docs/guides/install.md`, `upgrade.md`, `admin-guide.md`, `release-process.md`, `docs/api/README.md` (generated, 296 routes, checked for drift);
  `tools/cli/g5c-diag`, `g5c-redact`, `g5c-capture`; `docs/guides/pilot-plan.md`; `docs/legal/patent-frand-review.md` (recorded for counsel, not concluded); `CHANGELOG.md`, `LICENSE` (placeholder).
- **Not done, and why:** shared-state HA (a design of its own), the 10-100 Gbit/s UPF (needs a NIC), PCF UE policy and usage monitoring and Nudm_EE (each needs a design and tests), Nchf, lawful intercept
  beyond the design, Helm / operator and any container or Kubernetes verification (no runtime), the external penetration test and the 7 day soak (third party / a week), counsel's sign-off, a scan of the SBOM
  against a vulnerability database (no scanner installed), signing with an offline key (the candidate is signed with a test key and says so).
- **Tests:** ctest `cluster_ops`, `cluster_slices`, `cluster_upgrade`, `cluster_support`, `cluster_load_small`, `redact_tool`, `api_docs_fresh`, `licence_audit` added; matrix 387 rows.

## 2026-10-28 - Phase 8: WP2 mutual TLS, WP3 secrets hygiene, WP4 operations files, WP9 NSSF in the AMF; host demo and patched srsUE
- **Built (WP2, mutual TLS between all functions):** the SBI library already had TLS; what was missing is built. `deploy/run/g5c-pki.sh` (a CA, one EC P-256 certificate per function with its addresses as
  SANs and server + client authentication, one for the operator; `status`, `check`); the cluster script's `G5C_TLS=1` makes the PKI, writes `https` URIs and `sbi.tls` into every configuration (the
  demo launcher turns it on by default, `DEMO_TLS=0` for cleartext); `g5c-ctl` and the load generator speak TLS through `G5C_TLS_CA/CERT/KEY` (`g5c_client_new_env`). **Certificate rotation without a
  restart:** `g5c_server_swap_tls` / `g5c_client_swap_tls` (contexts swapped under a lock, `SSL_new` holds a reference so nothing is freed under a handshake, idle pooled connections dropped), SIGHUP in
  `g5c_nf_run`, the NRF's and the UPF's own mains (the UPF got a signal thread: SIGHUP would have killed it); a damaged file is refused and the old certificates stay. `g5c-cluster.sh certs renew|status`.
  Found on the way: the NRF's default self URI used `http` and 127.0.0.1 whatever its address (fixed, uses the configured scheme and address).
- **WP3 (secrets):** `g5c-cluster.sh ns secrets` proves that no key or token is in a log, a configuration or a state file and that K / OPc are ciphertext at rest (the UDM's AES-256-GCM, already there);
  key and PKI private key files are mode 600. **Not done:** key ids and rotation of the UDM / AUSF master keys, an HSM / KMS interface, an offline CA (rows SEC-GAP-02).
- **WP4 (operations):** `deploy/ops/prometheus-rules.yml` (14 alerts, 3 recording rules), `prometheus-scrape.yml` (mutual TLS client), `grafana-g5c.json` (14 panels, generated by `tools/gen/gen_grafana.py`),
  `docs/ops/runbooks.md` (one section per alert, certificate and secret procedures), `tools/check/check_ops.py` (every metric used is registered by a function). Audit lines (`g5c_audit`) for provisioning and
  policy changes in the UDM and PCF admin APIs. **Not done:** configuration hot reload other than certificates, Helm chart / operator (no Kubernetes cluster here to test one against).
- **WP9 (AMF consumes the NSSF):** `amf_nssf_registration`: Nnssf_NSSelection with the subscribed and requested NSSAI and the TAI, allowed / rejected from the answer cut to the AMF's slices, refusal = cause #62,
  no answer = the AMF's own lists. Configuration `amf.nssf: { enabled, uri? }` (cluster default on, found through the NRF). Metric `g5c_amf_nssf_selections_total`. **Not done:** PDU-session NSI
  information, target AMF, NSSAI availability, a scripted two-slice scenario (row NSSF-C-GAP).
- **Demo:** AUSF and UDM now log the authentication and the AMF registration (`5G AKA authentication succeeded`, `authentication vector generated`, `AMF registration stored`), `docs/demo/host-demo.md` and
  its PDF, `deploy/demo/host_selftest.sh` (the terminal commands in a private namespace, PASS with mutual TLS and the restart rule), a patched copy of srsUE in `/home/work/srsRAN_4G_nea2` that deciphers NEA2
  (`msg[5]` -> `msg[seq_offset]` in `cipher_decrypt`): demo PASS with `DEMO_CIPHERING=NEA2`, the unpatched UE never registers with it.
- **Bugs the new tests found (all fixed):** (1) the SMF read the cause of an N4 response that was never filled when the UPF did not answer: a SEGV in `pfcp_ie_next` (found by the TSan run of the TLS cluster test, the
  UPF having died on SIGHUP); `call_ex` now leaves an empty response on failure. (2) the UPF had no SIGHUP handler (default action: terminate) and a first version of the handler raced with start-up
  (TSan): SIGHUP is blocked first thing in `main`, a thread takes it, a lock orders reload and stop. (3) `certs renew` issued certificates with the addresses of the environment of the call, not those of the
  function: in the demo (AMF at 127.0.0.5) the renewed AMF certificate no longer matched and new registrations failed; `g5c-pki.sh renew` keeps the SANs of the current certificate (host_selftest now renews
  while the UE is attached and then re-attaches). (4) `ausf_differential` used a configuration an earlier scenario had left (OAuth2 enforced) and failed whenever it ran after one: it regenerates its own.
  (5) `host_selftest.sh` left the functions running (they are children of a `| tee` pipeline).
- **Tests:** ctest `sbi_router_h2_tls` (+ `test_tls_rotation`), `cluster_load_tls`, `cluster_chaos_tls`, `cluster_tls`, `cluster_secrets`, `ops_files_check`; clean under ASan and TSan; matrix 376 rows.
- **Not started in Phase 8 (honest list):** WP5 high availability (shared state stores, N4 failover, rolling upgrade), WP6 performance to target (needs a NIC with XDP), WP7 operator features (Nchf / CDR,
  lawful intercept), WP8 assurance that needs a third party or time (7-day soak, penetration test, signed artifacts, a commercial test tool), WP10 PCF UE policy and usage monitoring, WP11 Nudm_EE and the rest
  of event exposure. Each needs its own design; they stay in ADR-0025 as the open packages.
- **Next:** whichever of these you choose; the load test (6) and the HA work (5) are the ones that change what a buyer measures.

## 2026-10-26 - Phase 8 starts: the plan (ADR-0025) and WP1, OAuth2 access tokens of the NRF enforced between the functions
- **Phase 7 closed** as done with three items carried as backlog (the AMF as an NSSF consumer and the multi-slice scenario, the PCF's UE policy and usage monitoring, event exposure completion): they are
  work packages WP9 to WP11. Phase 8 is split into WP1 to WP11 (ADR-0025) with the order that puts first what the rest depends on and what needs no hardware or third party.
- **Built (WP1):** `libs/nfcore/src/oauth.c`: the producer's resource server guard (`g5c_oauth_rs`: signature against the NRF's key set fetched on first use, on an unknown key id and when old;
  `exp`, `iat`, `nbf`, subject; audience as NF type or instance id; scope = the service; 401 / 403 with `WWW-Authenticate`; 503 without a key) and the consumer's token client (`g5c_oauth_client` through
  the new `g5c_client_set_token_provider` hook of the SBI client: a token per target service, kept and renewed before it ends, one request at a time, refusals remembered). Router route flags
  (`G5C_ROUTE_OWN_AUTH`) for the UDR's provisioning extensions, and a guard getter so the check chains with a function's own guard. The common section `oauth2: { enforce, acquire, leeway_s,
  jwks_refresh_s }`; the cluster turns it on for every function by default (`G5C_OAUTH2`), the oracle has `OUR_OAUTH2=1`. The UDM now sends the UDR provisioning token in its own header
  (`x-g5c-provisioning-token`), the UDR still accepts the bearer form.
- **Spec clauses covered:** TS 33.501 13.4.1.1.1, 13.4.1.1.2, 13.3.1.3, 13.4.1 (SEC-OA-*).
- **Tests added / status:** `nrf_oauth2` (a real NRF issuing, a producer behind the guard, a consumer's client: no / damaged / forged / alg none / expired / wrong audience / wrong scope tokens, the
  requests left alone, the function's own guard, refusal back-off, NRF unreachable, config), 5 bad configurations for each of 11 functions; ASan / UBSan and TSan clean; cluster load, chaos and soak
  with tokens enforced; oracle S4, S7 and S8 with every function ours and tokens enforced, each also checking that the UDR refuses a request without a token. Two bugs found by the tests: a token was
  accepted during the second of its `exp` (RFC 7519 says on or after it is not), and a consumer could send a token that the producer already saw as expired because the NRF truncates `exp`.
  Matrix: 367 rows, OK; the OAuth2 gap rows of the NRF, AUSF, UDR, NSSF and BSF are replaced by the SEC-OA rows.
- **Known gaps:** SEC-GAP-01 (no TLS: TS 33.501 13.3.2.1; the functions log a warning), SEC-GAP-02 (client credentials assertions, additional scope, NSSAI / NSI / NF set claims, roaming, SCP-obtained
  tokens, revocation, a second signing key).
- **Next:** WP2, mutual TLS between all functions; then WP3 (secrets and keys), WP4 (operations), WP5 (HA and scale).

---

## 2026-10-26 - Phase 7: the BSF (PCF binding), the PCF that registers with it, the NEF that asks it
- **Built:** `nf/bsf` (ADR-0024; TS 29.521 v16.11.0 pinned with the owner's permission): Nbsf_Management register, discover, update and deregister; bindings found by IPv4 address, IPv6 prefix
  (longest prefix match), MAC address and framed routes without a scan; overlapping addresses told apart by slice and IP domain; SamePcf; feature negotiation; a new registration for the same
  address, DNN, slice and domain replaces the stale binding, a newer recovery time of a PCF removes its older bindings; state file; metrics; schema tables generated from the OpenAPI file. The PCF
  got `nf/pcf/src/bsfreg.c` (registers the binding of an SM policy association with a UE address and removes it, from a queue and a thread of its own, so the SMF never waits). The NEF asks the BSF
  for the PCF of the UE address of an AsSessionWithQoS request and falls back to the NRF. Cluster (`G5C_BSF`), compose, Windows (`13-bsf.bat`), oracle (`OUR_BSF=1`, scenario s8).
- **Spec clauses covered:** TS 29.521 4.1.3.2, 4.2.2.2, 4.2.3.2, 4.2.4.2, 4.2.5.2, 5.3.2.3.1, 5.3.2.3.2, 5.3.3.3.1, 5.3.3.3.2, 5.6.2.2 - 5.6.2.5, 5.7.3, 5.8 (BSF-*, PCF-BSF-01, NEF-BSF-01).
- **Tests added / status:** `bsf_e2e` (config, IPv4, IPv6 / MAC / framed routes, overlap, update, registration rules, SamePcf, replace and purge, state file, 20,000 bindings from 8 threads, metrics),
  `test_bsf_binding` in `pcf_policy_and_services`, `test_as_qos_via_bsf` in `nef_e2e`, `fuzz_replay_bsf` (38 seeds), `bsf_differential` (Open5GS's BSF and ours: 0 differences outside the documented ones),
  15 bad configurations, 6 payloads validated against TS 29.521 (87 of 87 in all); oracle S8 with Open5GS's PCF against our BSF, with our PCF against Open5GS's BSF, and with every function ours (S7 too:
  the NEF finds the PCF at the BSF). ASan / UBSan and TSan clean. Matrix: 361 rows, OK.
- **Findings about Open5GS's BSF:** it ignores the narrowing query parameters, answers 404 for no match, takes the first of several, refuses `2001:db8:1:2::/64`, cannot register a MAC address, has no PATCH,
  leaves the address and SUPI out of the discovery answer, **aborts on a registration with only the Diameter identities**, and lists allowedNfTypes without the NEF (so Open5GS's NRF will not discover it for
  our NEF). Each is in `tools/diff/bsf_diff.py` with the clause that says what ours does.
- **Known gaps:** BSF-GAP-01..03 (no supervision of the PCFs at the NRF, ES3XX, OAuth2), PCF-BSF-GAP-01 (the PCF registers without features), NEF-GAP-04 (a UE address with no binding gets any PCF of the NRF).
- **Next:** the regression on the whole tree; the AMF as the NSSF consumer; OAuth2 on every producer (NRF-GAP-04); the demo (srsUE + OCUDU + the load tool) now that every function exists.

---

## 2026-10-26 - Phase 7: the SCP (indirect communication), the last of the 11 functions
- **Built:** `nf/scp` (ADR-0023): the Service Communication Proxy of TS 29.500 6.10. Model C: the consumer names the producer in `3gpp-Sbi-Target-apiRoot`; Model D: delegated discovery,
  the `3gpp-Sbi-Discovery-*` headers become an Nnrf_NFDiscovery query (the requester type from the User-Agent when not given), the NRF's answers are cached, the candidates are ordered by
  priority and then weighted by capacity and load. Reselection (attempts, timeout, 503), quarantine of failing producers, `3gpp-Sbi-Producer-Id`, `3gpp-Sbi-Routing-Binding`,
  the `ck` parameter, the SCP's own prefix, notifications (`3gpp-Sbi-Callback`), loop detection by Via, late requests (Sender-Timestamp / Max-Rsp-Time), ProblemDetails with the Server
  header for errors the SCP makes and Via for errors it relays, a body limit and an in-flight limit, a next-hop SCP, an allow-list of targets, metrics. The SBI client in `libs/sbi`
  gained `g5c_client_set_scp` (every request except those to the NRF and to the SCP itself, with the NF type in the User-Agent); the common configuration key is `scp_client`; the
  cluster starts the SCP after the NRF and every function uses it (`G5C_SCP=0` to go direct). TS 29.500 was already pinned.
- **Spec clauses covered:** TS 29.500 5.2.3.2.3 - 5.2.3.2.8, 5.2.3.2.12, 5.2.3.3.2, 5.2.3.3.3, 5.2.7.4, 6.10.2, 6.10.3, 6.10.4, 6.10.5, 6.10.7, 6.10.8, 6.11.2 (SCP-* rows).
- **Tests added / status:** `scp_e2e` (config, Model C and D against scripted producers and NRF, limits and targets, reselection and quarantine, chain, the client side, metrics under
  concurrency), `fuzz_replay_scp` (29 seeds), `scp_differential` (Open5GS's SCP and ours in front of the same NRF and producer; 0 differences outside the documented ones: Open5GS sends the bare
  instance id in Producer-Id where the specification has `nfinst=<id>`, and answers 500 where the specification gives no status or ours is 504 / 400), 12 bad SCP configurations; oracle S3 with
  Open5GS's whole core and UERANSIM through our SCP in Model C and in Model D with delegated registration, and S4 with every function ours through our SCP. ASan / UBSan and TSan clean (TSan
  found a racy flag in the test, fixed; UBSan found a memcpy of a null pointer in the client with no headers, fixed).
- **Known gaps:** SCP-GAP-01..04 (redirection, OAuth2 at the SCP, OCI / LCI and set-based reselection, default notification subscriptions, SEPP).
- **Next:** the regression on the whole tree; the AMF as the NSSF consumer; OAuth2 on every producer (NRF-GAP-04); BSF (optional twelfth); the demo now that all 11 functions exist.

---

## 2026-10-23 - Phase 7: the NEF (traffic influence, monitoring events, AS session with QoS) and N5 in the PCF
- **Built:** `nf/nef` (ADR-0022): the northbound APIs of TS 29.522 / TS 29.122 for application functions: TrafficInfluence (stored as TrafficInfluData in the UDR), MonitoringEvent
  (loss of connectivity, UE reachability, location, from the AMF through the serving AMF found by the UDM and the NRF) and AsSessionWithQoS (authorized at the PCF); an AF is a configuration
  entry (bearer token, APIs, QoS references, notification hosts, limits); state file; notifications from a worker; deployment (cluster, compose, Windows, oracle toggle `OUR_NEF`). The PCF
  got Npcf_PolicyAuthorization (`nf/pcf/src/policyauth.c`, TS 29.514: create, update, delete, events, termination; PCC rules from QoS references, pushed to the SMF). The AMF got the
  LOSS_OF_CONNECTIVITY event and the reachability report; the UDM got id translation and the GPSIs of a subscriber. TS 29.522, 29.122, 29.514 and 29.591 were pinned with the owner's permission.
  The published TS 29.519 file rejects `AnyUE` where the text of the specification demands it: the generators and the validator apply the amendment of `tools/spec/oa_pool.py`.
- **Spec clauses covered:** TS 29.522 4.4.2, 4.4.7.3, 4.4.9; TS 29.122 4.4.2, 4.4.13, 5.2.5.3, 5.3, 5.14; TS 29.514 4.2.2.2, 4.2.2.10, 4.2.2.32, 4.2.3.2, 4.2.4.2, 4.2.5.3, 4.2.5.8 (NEF-*, PCF-N5-*, UDM-IDT-01, AMF-EE-01).
- **Tests added / status:** `nef_e2e`, `fuzz_replay_nef` (it found a null flow description, fixed), `test_policy_authorization` in `pcf_policy_and_services`, the AMF event assertions, 12 bad NEF
  configurations and 4 for N5; oracle S6 (traffic influence into the UDR, monitoring reported to the AF with UERANSIM) and S7 (QoS request becomes a PCC rule at Open5GS's SMF and at ours).
  Open5GS's PCF answers 403 to a media component that has only a QoS reference (it derives QoS from the media type, TS 29.513). Matrix: 313 rows, OK.
- **Known gaps:** NEF-GAP-01..05, PCF-N5-GAP-01 (traffic influence by UE address and for groups, no UDM subscription for UEs that are not registered, PFD management, Nnef services, BSF selection,
  OAuth2).
- **Next:** SCP; the AMF as the NSSF consumer; OAuth2 on every producer (NRF-GAP-04); the demo after all 11 functions exist.

## 2026-10-23 - Phase 7: the UDR (replacing udr-lite) and the NSSF
- **Built:** `nf/udr` (ADR-0020): one engine generated from the pinned OpenAPI of TS 29.505 / 29.519 (176 operations, 444 schemas), ETag and preconditions, JSON and merge patch,
  `fields`, composites, GPSI aliases, subscriptions and notifications by worker threads, Nudr_GroupIDmap, a provisioning extension behind a bearer token, storage on memory, a journalled
  file or PostgreSQL (libpq, row locks, a connection pool). `libs/oaschema` (the schema validator, shared) and `tools/spec/oa_pool.py` (the shared generator code). `nf/nssf` (ADR-0021):
  Nnssf_NSSelection for the registration, PDU session, UE configuration update and PDN connection procedures, Nnssf_NSSAIAvailability (update, patch, delete, subscribe, modify,
  unsubscribe, notify, options), the slice policy in configuration, roaming mappings, AMF sets, a state file; registration at the NRF; deployment (compose, Windows, cluster, oracle toggle).
  TS 29.531 v16.11.0 pinned.
- **Spec clauses covered:** TS 29.504 / 29.505 / 29.519 as listed by the UDR-* matrix rows; TS 29.531 5.2.2.2.2 to 5.2.2.2.5, 5.3.2.2 to 5.3.2.7, 6.1.3.2.3.1, 6.1.8 (NSSF-* rows).
- **Tests added / status:** `udr_api`, `udr_notify`, `udr_db` (+ PostgreSQL variants), `udr_config`, `udr_differential` (against Open5GS's UDR), `fuzz_replay_udr`; `nssf_e2e`,
  `fuzz_replay_nssf`, `nssf_differential` (against Open5GS's NSSF: the differential found that `nrfId` must be the NFDiscovery URI, fixed), 11 bad NSSF configurations; the oracle
  runs S3 / S4 with our UDR and S3 with our NSSF. Matrix: 283 rows, OK.
- **Known gaps:** UDR-GAP-01..07, NSSF-GAP-01..05 (no H-NSSF query, no redirection, pattern TAC ranges, producer-side OAuth2, our AMF does not consume the NSSF). Open5GS's AMF asks an NSSF
  only on the home-routed roaming path, so oracle S3 proves our NSSF's registration and discovery only; the answers are proven by the differential.
- **Next:** NEF and SCP; the AMF as the NSSF consumer; OAuth2 on every producer (NRF-GAP-04); the demo after all 11 functions exist.

## 2026-10-21 - Phase 7: the AUSF (5G AKA, EAP-AKA', SoR and UPU protection), replacing the shim
- **Built:** `nf/ausf` (ADR-0019), the three services of TS 29.509: Nausf_UEAuthentication (5G AKA with the serving network checks, EAP-AKA' as the EAP server, the removal of a result,
  deregister, the FN-RG authentication), Nausf_SoRProtection and Nausf_UPUProtection (the MACs and counters of TS 33.501 6.14 / 6.15, A.17 to A.20); the latest KAUSF per SUPI in an
  AES-256-GCM wrapped state file; registration at the NRF with `ausfInfo`; the UDM found through the NRF. `libs/crypto/eapaka` (CK'/IK', PRF', the EAP-AKA' key schedule, EAP framing
  and AT_MAC), `libs/base` base64. UDM: `auth_method` (5G_AKA / EAP_AKA_PRIME) in the admin API, the AV' with CK' and IK', the FN-RG answer, EAP-TLS refused as AUTHENTICATION_REJECTED.
  AMF: EAP-AKA' (the challenge in the EAP message of the Authentication request, the EAP-success and the ABBA in the Security mode command, the EAP-failure in the Authentication reject)
  and the removal of the authentication result at de-registration, implicit de-registration and a refused security mode command. `ausf-lite` is gone: tests, cluster, compose, Windows
  launchers (`4-ausf.bat`), oracle and dashboard use the AUSF; `configs/ausf.yaml`.
- **Specifications pinned for it:** RFC 4187, RFC 5448, RFC 9048 (the owner agreed to the download; SHA-256 in `docs/specs/pinned.json`) and TS 31.102 16.17.0 (access technology bits of the
  SoR list; the text conversion loses the bit positions of that figure, so they were read from the cell borders in the document). 31 pinned documents verify.
- **Verified against real peers:** Open5GS's AMF and UERANSIM through our AUSF behind Open5GS's NRF and UDM (S3); every function ours, no Open5GS function in the path (S3, S4, S5);
  EAP-AKA' against UERANSIM's own peer through our whole core (S3, S5 with `AUTH_METHOD=EAP_AKA_PRIME`; needs the copy of `nr-ue` that `deploy/oracle/build_ueransim_eap.sh` builds,
  because UERANSIM 3.3.0 rejects every EAP attribute of Length 1 and AT_KDF has Length 1 by definition); the four test vectors of RFC 9048 Annex D; a differential against Open5GS's AUSF
  (`ausf_differential`: same status codes and attributes, two documented differences); every body validates against the pinned OpenAPI (44 of 44 payloads).
- **Found on the way:** Open5GS's UDM refuses the removal of an authentication result unless `success` is true next to `authRemovalInd` (the specification says false): the AUSF sends the
  specified form first and the other one when the UDM answers 400. UERANSIM's EAP peer repeats AT_KDF in its response (RFC 5448 does not allow it): tolerated when it repeats the value in
  use. ASan found a use after free in the first version of the start handler (a newer start for the same UE replaced the context while the previous request still read its id) and a buffer
  overflow in one of the new tests.
- **Tests added:** `ausf_e2e` (the shim's 13 tests plus 16 new, ASan and TSan clean), `crypto_eapaka`, `amf_e2e` `test_eap_registration`, `udm_unit_and_services` `test_ueau_eap`,
  `fuzz_replay_ausf`, `ausf_differential`, bad configurations of the `ausf` block, the sample configuration loader, oracle scenarios with `OUR_AUSF=1` and EAP-AKA'; matrix
  `docs/conformance/phase7-matrix.json` now 44 rows (AUSF-*). Full regression: plain 59 / ASan 56 / TSan 56 tests, 231 matrix rows (75 verified), 90.8% line coverage, lint and
  `-fanalyzer` clean, cluster 2,000 UEs x 2 waves at 357 UE/s, chaos run recovers with the AUSF among the killed functions.
- **Known gaps (AUSF-GAP-01..05):** EAP-TLS (Annex B, N5GC), the consumers of the protection services (the UDM asking for SoR / UPU MACs, the AMF conveying the containers, the UDM clearing
  a stale context at an old AUSF), producer-side OAuth2 (with NRF-GAP-04), EAP identity exchange / fast re-authentication (not used in 5GS), 307 / 308 redirection and the SCP.
- **Next:** UDR (replacing `udr-lite`), then NSSF, NEF, SCP.

---

## 2026-10-15 - Phase 7: the NRF, and every function finding its peers through it
- **Built:** `nf/nrf` (ADR-0018): Nnrf_NFManagement (register / replace / JSON-patch / heart-beat / deregister / retrieve / list, status subscriptions and
  NFStatusNotify, heart-beat supervision with SUSPENDED and purge, entity tags), Nnrf_NFDiscovery (target / requester type, service names with the
  intersection returned, snssais, dnn, tai, guami, supi ranges and patterns, PLMN, allowedNfTypes, locality / priority / load ordering, Service-Map conversion),
  Nnrf_AccessToken (ES256 JWTs, scope and producer checks, optional enforcement on the NRF's own API), persistence, metrics. `libs/sbi/jwt` (ES256),
  `libs/base/jsonpatch` (moved out of the UDR shim), `libs/nfcore/disc` (the discovery client). UDM, PCF, AUSF-lite, SMF and AMF resolve their peers through it
  when no address is configured (the AMF's private copy was replaced); `deploy/run/g5c-cluster.sh` and the Windows launchers start the NRF first and give the
  other functions nothing but its address. `configs/nrf.yaml`, compose service, `deploy/oracle` `OUR_NRF=1`, `deploy/oracle/nrf_diff.sh`, `tools/diff/nrf_diff.py`.
- **Verified against real peers:** Open5GS's AUSF, UDR, UDM, BSF, PCF, NSSF, SMF, AMF and UERANSIM complete S3 against our NRF; every function but the AUSF ours passes S3
  and S5 with our NRF; the differential against Open5GS's NRF has the same status code for every request (attribute differences are the documented ones:
  ProblemDetails `type` / `instance`, and the map returned only to a consumer that asks for it).
- **Found on the way:** Open5GS registers its services as a map and reads them as an array - the NRF has to convert (first version: the AMF could not reach the AUSF); the
  reference NRF refuses a single S-NSSAI object where the OpenAPI says array; `service-names` is a comma separated list; ProblemDetails now carry a `title`.
- **Tests added:** `nrf_e2e`, `nrf_differential`, `fuzz_replay_nrf`, NRF cases in `bad_configs_rejected` and the sample / compose config loaders, discovery mode in
  `cluster_load` / `cluster_chaos` / `cluster_soak` (the NRF is among the killed functions); matrix `docs/conformance/phase7-matrix.json` (23 rows).
- **Known gaps (NRF-GAP-01..05):** NRF-to-NRF forwarding and redirection, other PLMNs / SNPNs, NF sets and groups, producer-side token validation in the other functions,
  ETag handling on PUT.
- **Next:** AUSF and UDR (replacing the shims), then NSSF, NEF, SCP.

---

## 2026-10-14 - Phase 6: the five-function core as a system (daemons, scale, failure injection, soak)
- **Built:** `deploy/run/g5c-cluster.sh` runs udr-lite, UDM, AUSF-lite, PCF, UPF, SMF and AMF as separate daemons (one config and one log each; `run <nf>` for one terminal
  per NF, `up` / `down` / `status` / `logs` / `kill` / `restart`) and, in a private user + network namespace that needs no privileges, `ns load`, `ns chaos`
  (SIGKILL and restart of random functions under load, then a clean recovery wave) and `ns soak` (waves for a fixed time, RSS of every function must stay
  flat). `nf/amf/tests/load_core.c`: multi-threaded gNB / UE load generator (every UE derives its keys and verifies the network's answers), in-process or against
  the daemons (`G5C_LOAD_REMOTE=1`, counts from `/metrics`), waves, soak and chaos modes. The scripted UE / gNB procedures moved out of `test_amf_e2e.c`
  into `nf/amf/tests/e2e_procs.h`. `deploy/run/README.md`. ADR-0017 opens the Release 17 track (after Phase 7; pinned text and a gate per feature).
- **Measured** (docs/history/phase6-baseline.md): 10,000 UEs, each registering with 5G-AKA and establishing a PDU session: all up in 20.7 s (484 UE/s), registration p50
  38 ms, session p50 25 ms, de-registration p50 29 ms, flat as the population grows; counts return to zero. Chaos: 16 kills in 60 s, no hang, recovery wave passes.
- **Bugs the scale / soak runs found, all fixed:** the AMF's unauthenticated-connection limit counted every connection (cap of 4,096 UEs); the AMF timer thread
  scanned every timer per wake-up; AMF, SMF and UDR-lite rewrote their whole state on every change (now write-behind: AMF / SMF delayed, bounded to a tenth of a
  core; UDR-lite snapshot + journal with crash-image test); the SMF ran every deferred job on one thread (blocking sleep inside) and looked sessions up by list scan
  (pool + hash indexes); the AMF never deleted its SDM subscription (UDM grew 0.9 KB per registration); after a UPF process restart the SMF released the sessions but never
  set the N4 association up again (every establishment refused with cause 72 until an SMF restart).
- **Tests added:** `load_core_small`, `cluster_load`, `cluster_chaos`, `cluster_soak` (ctest; the cluster ones skip where user namespaces are unavailable),
  `test_journal_recovery`, an SDM-subscription assertion in `test_registration`; matrix `docs/conformance/phase6-matrix.json` (20 rows, `tools/gen/gen_phase6_matrix.py`).
- **Known gaps:** 72 h soak not run (command ready); srsUE + OCUDU gNB, O-RAN emulator, S6-S8 on them deferred by the owner to after Phase 7; no combined traffic +
  signalling run; an SMF killed inside the 25 ms write-behind window leaves PFCP sessions on the UPF (P6-GAP-04, needs an N4 audit).
- **Owner decisions of 2026-10-14:** Release 17 track opened (ADR-0017); SNOW 3G licence not needed for a demo with srsUE / UERANSIM (NEA2 / NIA2) and left open;
  Stage B UPF target left as is (software-only validation would not be representative).
- **Next:** Phase 7 (NRF, AUSF, UDR, NSSF, NEF, SCP); then the srsUE + OCUDU interop pass and the demo environment on top of `g5c-cluster.sh`.

---

## 2026-10-13 - Phase 5: the AMF (N2 over SCTP, 5GMM, NAS security, mobility, Namf services, persistence)
- **What was built (`nf/amf`, ADR-0016):** an N2 endpoint on kernel SCTP (PPID 60, one reader thread, epoll) with NG Setup, RAN Configuration Update, NG Reset, Error
  Indication, Initial UE Message, UL / DL NAS Transport, Initial Context Setup, UE Context Release (both directions), PDU Session Resource Setup / Modify / Release,
  Paging, Path Switch Request and N2 handover (required, request, acknowledge, command, notify, cancel, failure, RAN status transfer). 5GMM: initial, mobility and
  periodic registration, identification by SUCI, 5G-AKA through the AUSF (HRES* check, resynchronisation), NAS security mode control (NIA2; NEA2 then NEA0 by preference
  list, NIA0 only when configured; SNOW 3G / ZUC refused at configuration time, ADR-0012), 5G-GUTI allocation, service request (also the ciphered NAS message
  container), network-triggered paging with T3513 repetition, UE- and network-initiated de-registration, implicit de-registration, configuration update (new GUTI,
  allowed NSSAI, network name and time), retransmission timers, slice selection with rejected NSSAI. 5GSM relay to the SMF over Nsmf_PDUSession (establish, forward,
  release, activate / deactivate on idle, handover transfers). SBI servers: Namf_Communication N1N2MessageTransfer (200 / 202, failure notification URI),
  callbacks (SM context status, UDM de-registration, AM policy update / terminate, SDM change) and Namf_EventExposure (registration, connectivity, reachability,
  location). Clients: AUSF, UDM (UECM, SDM, subscription), PCF (AM policy), SMF, NRF discovery by service / S-NSSAI / DNN with a cache. Persistence of the
  registered contexts in an atomic state file, restored in CM-IDLE. Metrics, configuration (`configs/amf.yaml`, compose, `deploy/amf/README.md`).
- **SMF extensions for mobility:** `PATH_SWITCH_REQ`, `HANDOVER_REQUIRED`, `HANDOVER_REQ_ACK` and `hoState` COMPLETED / CANCELLED in Update SM Context, with the
  PathSwitchRequestTransfer / HandoverRequestAcknowledgeTransfer parsers and the acknowledge / command transfers (`nf/smf`, unit and end-to-end tests).
- **Verified against real peers (oracle, `OUR_AMF=1`):** UERANSIM registers, establishes a session, pings through the UPF, releases the session and de-registers
  against our AMF with Open5GS's SMF / UPF / AUSF / NRF (S2, S3) and with every NF of the core ours (S3, S4 policy push reaching the gNB, S5 idle mode: UE context
  release by the gNB, service request, ping again). `tools/diff/amf_diff.py`: the AMF's NGAP message sequence and information elements equal Open5GS's AMF for the same
  scenario (one allowed extra identity request, one extra IE). The oracle found two defects the unit tests could not (NrLocation without ncgi at the AM policy,
  the NRF's `snssais` encoding).
- **Tests:** `amf_units` (byte-exact builders, GPRS timers, COUNT estimation across the wrap, NH chain, algorithm selection, maps, configuration) and `amf_e2e`:
  22 groups in one process (udr-lite, UDM, AUSF shim, PCF, SMF, the real UPF runtime, the AMF; scripted gNBs over real SCTP and scripted UEs that derive KAMF, the NAS
  keys and KgNB independently): NG Setup refusals, registration, authentication failures and resynchronisation, sessions with user plane and policy push, idle mode,
  service request, paging and its failure, context reuse and identification, network-initiated de-registration and configuration update, association loss and NG
  Reset, event exposure, SBI errors, Xn path switch (NH chain), N2 handover, cancellation and failure, algorithm negotiation and rejects, uplink protection
  (MAC / replay), registration update and session replacement, network name, timers (4 retransmissions then abort), implicit de-registration, persistence. Passes
  plain, under ASan/UBSan (leak-free) and ThreadSanitizer. `fuzz_replay_amf`: golden NGAP PDUs raw and with the NAS wrapped in a valid protected envelope, plus SBI
  bodies, with mutations. Configuration: 25 negative cases, sample and compose configuration loaded through `amf --check`. Matrix `docs/conformance/phase5-matrix.json`
  (45 rows).
- **Found by the tests:** the first TSan run found three races (gNB slot flags written and read under different mutexes, state counters read by the gauges without the
  UE mutex, a plain stop flag); the first ASan run a leaked temporary in the path switch; a context that failed security mode negotiation was kept after its
  connection was released.
- **Known gaps (matrix AMF-GAP-01..04):** SNOW 3G / ZUC (ADR-0012), emergency services, MICO, NB-IoT, SMS over NAS, UE policy delivery, NSSAA; AMF sets and relocation
  (UEContextTransfer, CreateUEContext, inter-AMF handover); non-3GPP access, EPS interworking, LADN, NSSF slice selection, OAuth2. A GUTI of another AMF is answered with
  an identity request. Open5GS's UDM does not implement the UECM DELETE (403), which the AMF tolerates. The compose service is unverified (no Docker daemon).
- **Next:** Phase 6, integration of the whole core (S1-S4 with every NF ours, multi-UE and multi-gNB load, failure injection), or the open owner decisions (SNOW 3G licence,
  Stage B UPF target, Rel-17 track).

---

## 2026-10-12 - Phase 4 (second half): policy-driven modification, paging, UPF recovery, persistence, discovery, IPv6 router advertisement
- **What was added to `nf/smf`:** PCF-initiated SM policy update (the decision is diffed against the one in force; Update QER, Create / Remove PDR and QER on the
  UPF first, then a PDU SESSION MODIFICATION COMMAND with PTI 0 to the UE and a PDU session resource modify request to the gNB through N1N2MessageTransfer) and PCF
  termination (release through the AMF and UE, bounded by a guard timer). Network-triggered service request: a Downlink Data Report for an idle session becomes an
  N1N2MessageTransfer with the N2 setup request. UPF recovery: a restart (Recovery Time Stamp) or `n4.lost_after` seconds of silence release that UPF's sessions
  towards the AMF and UE, clean PCF / UDM / pools, and notify the AMF's status endpoint. Persistence: atomic state file after every change, restored before the first
  association. NRF discovery of the AMF by `servingNfId` (cached, with the status URI as fall-back). IPv6: router solicitations forwarded by the UPF to the SMF over
  GTP-U (control-plane PDR + FAR), router advertisement with the session's /64 and the MTU returned through the UPF. Details: ADR-0015 "Second half".
- **Stable identities:** flows carry QER id and QFI, PCC rules QRI and PDR ids (`smf_policy_assign_ids`), so an update is a diff of two models and the three
  messages (N4, NAS, N2) come from the same comparison. The delayed-job queue also serves the guard timers.
- **Verified against real peers:** scenario S4 with `OUR_SMF=1` (new): our PCF pushes a changed policy, our SMF applies it on our UPF, Open5GS's AMF accepts the
  modification transfer and sends the gNB a PDUSessionResourceModifyRequest (NGAP procedure 26), the session keeps working. UERANSIM's gNB does not answer a modify
  request and its UE has no handling for the modification command, so the capture of the request is the evidence; the NAS and N2 contents are decoded in the tests.
  S3 passes as before; both PFCP differentials still pass.
- **Tests:** units (identifier assignment, QFI of real traffic through the UPF engine before / after an update, NAS / N2 modification messages, router advertisement
  validation) and end to end (policy update in two steps with decoded commands, no-op update, termination with and without the UE's complete, paging, router
  solicitation through the real UPF, NRF discovery and fall-back, UPF restart releasing sessions, SMF restart with sessions kept, SMF restart with the UPF
  restarted meanwhile). Full regression: 45 programs plain, 42 under ASan/UBSan, 42 under TSan; 121 matrix rows (7 new SMF rows, 7 gaps left across all matrices
  of which 2 are SMF); coverage 91.4%; lint and `-fanalyzer` clean; oracle S3 and S4 with Open5GS's SMF and with ours.
- **Found by the tests:** a restarted SMF changed its own Recovery Time Stamp, which makes the UPF drop that peer's sessions (so the stamp is persisted); the
  router-solicitation PDR with `to assigned` could not match a link-local source (now `to any`); a QFI freed by a deleted flow is not reused in the same step; a
  leak of the kept decision on shutdown (ASan); the earlier matrix row for the release transfer cited TS 38.413 9.3.4.5 instead of 9.3.4.12 (fixed).
- **Known gaps:** UE-requested modification is rejected (#31); charging / usage reporting, ATSSS, Ethernet and unstructured session types, SSC modes 2 and 3,
  handover and I-SMF / V-SMF roles; OAuth2 on the SBI; UPFs are discovered by configuration, not the NRF; an IPv6 UE has not run against Open5GS's AMF and UERANSIM
  (the router advertisement is verified against our UPF) and N3 over IPv6 is not supported by the UPF; the compose service is still unverified (no Docker).
- **Next:** Phase 5, the AMF (needs the owner's SNOW 3G licence decision for the algorithm set, ADR-0012), or the open owner decisions (Stage B UPF target, Rel-17).

---

## 2026-10-09 - Phase 4 (first half): the SMF creates, activates, deactivates and releases PDU sessions, interop-verified
- **What exists:** `nf/smf` in C, about 4,300 lines, plus `libs/sbi` multipart/related support. Nsmf_PDUSession (TS 29.502): Create SM Context (multipart
  with the N1 SM part), Update SM Context (PDU_RES_SETUP_RSP, AN release, service request, UE-requested release), Release SM Context; the PDU Session
  Establishment Accept and the N2 setup request go to the AMF in an N1N2MessageTransfer after the 201. 5GSM (TS 24.501): accept with QoS rules, QoS flow
  descriptions, Session-AMBR, PDU address, S-NSSAI, DNN and the DNS / MTU replies of the extended PCO (TS 24.008 container ids), reject, release command.
  N2 SM information (TS 38.413): setup request transfer, setup response / unsuccessful / release transfers. N4 client (TS 29.244): association, heartbeats,
  retransmission, restart detection by the Recovery Time Stamp, Session Report answers; establishment built from the PCF decision (default QoS flow plus a
  PDR pair and QER per PCC rule, session AMBR QER, BAR), activate / deactivate modifications, deletion. IPv4 and IPv6 /64 pools per DNN, UPF selection by DNN
  and slice, UDM (sm-data, SMF registration) and PCF (SM policy) integration, NRF registration with smfInfo (`g5c_nrf_reg.extra`). ADR-0015 records the design.
- **Specs pinned for it:** TS 29.502 v16.17.0, TS 29.518 v16.19.0, TS 24.008 v16.7.0 (27 documents now; `python tools/spec/verify_pins.py`). Bit layouts were read
  from the pinned text: the unit coding of Session-AMBR and rate parameters, the QoS rule and flow description layouts, the PCO container ids, the SDF filter
  direction rule of TS 29.244 5.2.1A.2A (a Flow Description from the PCF is copied unchanged into uplink and downlink PDRs, the UPF swaps for ACCESS), the 3GPP
  Interface Type values.
- **Verified against real peers:** Open5GS's AMF + UERANSIM against our SMF (with our UDM, PCF and UPF): registration, PDU session, ping through our UPF,
  UE-requested release, deregistration (`OUR_SMF=1 OUR_UDM=1 OUR_PCF=1 OUR_UPF=1 deploy/oracle/scenario.sh s3`, first try). `tools/diff/pfcp_diff.py --smf` compares Open5GS's SMF
  with ours on the same UPF: identical request sequence; the first diff run showed our requests lacked the 3GPP Interface Type of PDRs and FARs and used one Outer Header
  Removal value, both fixed; the remaining differences are an allow-list with reasons (charging URR, user id, match-all filters, IPv6 router-solicitation forwarding).
- **Tests:** `smf_units` (bit rates, pools, IPFilterRule table, policy decisions incl. refusals, byte-exact NAS, N2 transfers, PCC-to-PFCP mapping checked by feeding the
  generated request to the real UPF engine and observing the QFI of each flow), `smf_e2e` (udr-lite + UDM + PCF + the UPF runtime on real sockets + SMF + scripted AMF and
  gNB: happy path with a GBR rule, AN release and service request, replacement, 25 rejection and malformed-input cases, AMF refusal, pool exhaustion, UPF stopped and
  restarted, 8 threads of session cycles), `sbi_multipart`, `fuzz_replay_smf`, about 50 SMF configuration cases, `pfcp_differential_smf`. Full regression: 45 programs plain,
  42 under ASan/UBSan, 42 under TSan, all pass; 114 matrix rows (41 new, `docs/conformance/phase4-matrix.json`); coverage 91.3% (SMF files 82% to 99%; the n4c.c gap is
  hostile-datagram and UPF-initiated association paths); lint and `-fanalyzer` clean. The dashboard has the SMF in the explorer, N11 verified, N4 verified in both directions.
- **Found by the tests:** a GBR QoS data without maximum bit rates (valid, the maximum defaults to the guaranteed rate) made a strict reading refuse the whole decision;
  ThreadSanitizer flagged the test reading UPF engine counters across threads, so `upf_rt_snapshot()` publishes a copy; the missing Interface Types above.
- **Known gaps (the second half, all in the matrix as `gap`):** PDU session modification (a UE request is answered with a reject, PCF update / terminate notifications answer 501 so
  nothing is silently ignored); recovery after a UPF restart (detected and counted, the stale sessions wait for the AMF's release); paging on a Downlink Data Report (acknowledged
  only); IPv6 router advertisement and an IPv6 user plane (addresses are allocated and signalled); NRF discovery of the AMF and UPFs (the AMF is found from `smContextStatusUri`);
  persistence of SM contexts; scenario S4 (policy push) with our SMF; the compose service is unverified (no Docker daemon).
- **Next:** the second half of Phase 4 in this order: PDU session modification and PCF-initiated updates (S4 with our SMF), downlink-data paging, UPF recovery, IPv6 router function.

## 2026-10-08 - Phase 3: the UPF (Stage A, userspace) is built and interop-verified
- **What exists:** `nf/upf` in C. An I/O-free engine (N4 handler, PDR/FAR/QER/URR/BAR store, packet pipeline, timers) and a single-threaded runtime
  (epoll, UDP for N4 and N3, a TUN device for N6, batched recvmmsg/sendmmsg, metrics, health). `libs/pfcp` gained the typed information elements and
  builders. Design record: ADR-0014. Run guide: `deploy/upf/README.md`; sample `configs/upf.yaml`.
- **Real peers:** Open5GS's AMF, SMF, AUSF and NRF with UERANSIM, and our UDM, PCF and UPF: registration, PDU session, ping through the UPF with 0% loss,
  release, de-registration, and the S4 mid-session policy push (`OUR_UPF=1 OUR_UDM=1 OUR_PCF=1 deploy/oracle/scenario.sh s3|s4`).
- **Byte-level evidence:** the real Open5GS association, establishment, modification and deletion messages are replayed into the engine and answered correctly;
  a downlink G-PDU our UPF produces is byte-identical to the one Open5GS's UPF produced; every typed IE of eight real messages decodes and re-encodes to the same bytes.
  `tools/diff/pfcp_diff.py` compares the same SMF against both UPFs: identical request sequence, matching responses.
- **A real bug the interop and the differential found:** the UP Function Features bits were written from memory in the wrong order (we claimed traffic steering and PFD
  management instead of F-TEID allocation), so the Open5GS SMF allocated TEIDs itself and the unit tests had not noticed. Fixed from the pinned spec table, with named
  constants and an exact-bytes assertion. Other findings: an empty error message for a missing config section, a UBSan memcpy(NULL), DROBU not implemented.
- **Tests:** engine (replay of real messages, QoS, SDF and precedence, buffering, usage reports, retransmission, rollback, handover, heartbeats, IPv6, 41 malformed
  rule shapes, 29 invalid modifications), runtime over real sockets, unit tests (hash map against a model, SDF parser and matcher, IP header parser), 27 bad-config cases,
  a fuzz target (1.2 million mutated inputs under ASan+UBSan without a finding), TSan and ASan runs of all of it, and two opt-in benchmarks.
- **Performance (this host, 1400-byte packets):** engine alone about 20 Mpps; end to end through the runtime between 2.3 and 4.9 Gbit/s uplink and 1.4 to 2.2 Gbit/s
  downlink of UPF capacity per core, against the Stage A criterion of at least 1 Gbit/s (sendmmsg batching doubled the downlink figure). The host is noisy (WSL2 under
  Windows): right after the VM started the same binary measured 0.3 to 0.6 Gbit/s, so the gate takes the best of three attempts and judges the UPF thread's capacity
  (bytes per CPU second), and every attempt is printed. Downlink is bounded by one read() per packet on a TUN device.
- **Conformance matrix:** `docs/conformance/phase3-matrix.json` (30 rows). Gaps and limits stated there: UP-initiated association, UE address allocation by the UPF (the SMF
  allocates), GBR guarantee, N3/N9 over IPv6, ATSSS and the other multi-access features; NAT is host configuration (`deploy/upf/n6-setup.sh`, unverified: no sudo here).
- **Not done:** Stage B (AF_XDP, multi-queue, CPU pinning) needs a NIC with XDP support; the target is proposed in ADR-0014 and is an owner decision. The container build is
  still unverified (no daemon); the compose file now carries a UPF service.
- Next: Phase 4, the SMF (PFCP N4 client, PDU session handling) against our UPF and Open5GS's.

## 2026-10-08 - Phase 1 and 2 test campaign, conformance matrix and dashboard
Phases 1 and 2 were tested against every layer of the strategy's test pyramid (see `docs/guides/testing.md`). Result: 30 ctest programs pass plain,
under ASan+UBSan and (for the first time) ThreadSanitizer; `gcc -fanalyzer` clean; Open5GS + UERANSIM scenarios S3 and S4 pass against our
UDM, PCF and udr-lite; line coverage rose from 86.6% to 90.5% (UDM 95%, PCF 94%, udr-lite 95%); 5,500 auth vectors/s against the 1,000 target;
a 12 s soak with the UDR killed and restarted three times shows no unexpected status, no leaked sessions and flat memory and descriptors.
- **New tests:** table-driven negative tests (40 invalid provisioning bodies, 35 invalid policy documents, 57 broken configurations), protocol
  abuse (garbage, oversized and deeply nested bodies), failure injection (UDR 500/malformed/404/down for UDM and PCF, UDM faults for the AUSF),
  TLS negative paths (rogue client CA, wrong server name, unusable key material), RFC 6902 patch cases, JSON property tests (round trip,
  truncation, mutation, model-based object index), SUCI Annex C vectors for both profiles and both identifier types, a soak harness
  (`tests/soak`), a throughput gate, and test layers as ctest labels.
- **Defects found and fixed:** quadratic admin-API behaviour on large bodies (JSON objects now carry a hash index; limits of 64 slices and 256 DNNs);
  numbers such as 1e999 silently became null; ServingNetworkName with the SNPN suffix was refused; udr-lite accepted an unwritable store path;
  `--check` did not open TLS material; JSON Patch error class for scalar parents. Missing operation implemented: SDM retrieval of multiple data sets.
  Full list with the guarding test: dashboard, Quality tab.
- **Conformance matrix:** `docs/conformance/phase1-2-matrix.json`, 42 rows (13 verified against a real peer or published vector, 24 tested, 1 partial,
  2 gaps, 2 out of scope), checked by `tools/check/check_matrix.py`. Gaps: AMF registration for non-3GPP access; AM policy UpdateNotify toward the AMF.
- **Dashboard:** `tools/docs/gen_dashboard.py` + `tools/docs/dashboard/template.html`, built from the repository (real route tables, coverage, test results,
  decoded captures). Published as a private Artifact.
- **Strategy PDF:** the nine phase titles still carried week estimates against the standing "no timelines" decision; removed and the PDF rebuilt. The
  phase text is now also data (`docs/strategy/phases.json`).
- Known limits: the Docker image and compose file are still unbuilt (no daemon here); coverage-guided fuzzing runs in CI only; the SDM subscription
  store is in memory; `libs/crypto` intermediates have not been audited for wiping.

## 2026-10-07 - Phase 0-2 audit and gap closure
Audit of Phases 0-2 against the plan found the NF code and its evidence complete, and a set of supporting deliverables missing or thin.
Closed in this entry:
- **Nudm_SDM change notifications.** Re-provisioning a subscriber now sends a `ModificationNotification` (notifyItems with resourceId and
  changes) to the callback of every sdm-subscription of that SUPI; unreachable or rejecting consumers are logged and counted
  (`g5c_udm_sdm_notifications_total{result}`), never an error for the provisioning call. Test `test_sdm_notification`; the payload is
  in the OpenAPI validation set (now 26/26 valid).
- **Sample configs** in `configs/` for udm, pcf, udr-lite, ausf-lite, and compose variants in `deploy/compose/config/`. Each NF binary has
  `--check <config>` (load, validate, exit); ctests `sample_configs_load` and `compose_configs_load` run it with scratch key files.
- **`g5c-ctl`** (`ctl/`): subscriber add/get/list/delete (UDM), policy get/put/delete and session list/terminate (PCF), token from
  `--token-file` or `G5C_ADMIN_TOKEN`, path-safe identifiers, exit codes 0/1/2/3. ctest `ctl_cli` runs it against in-process UDM, udr-lite and PCF.
- **Threat note** `docs/security/udm-key-handling-threat-note.md` (Phase 1 exit criterion), with the open items listed as open.
- **SBOM** `docs/sbom/g5c.cdx.json` (CycloneDX 1.5, from `tools/release/gen_sbom.py`; regenerate in the build environment).
- **Container build**: `deploy/docker/Dockerfile`, `g5c-entrypoint` and `deploy/compose/compose.yaml` with `gen-secrets.sh`.
  **Not verified**: the Docker CLI is installed on the host but its daemon was not running, so nothing was built or started.
- Empty placeholder test directories removed (tests live beside the code they test; cross-component tests are in `tests/conformance`).
- Gate after the changes: 27 ctest programs pass plain and under ASan+UBSan; `scripts/c_lint.sh` and `-fanalyzer` clean; oracle
  scenario S4 (our UDM, PCF and udr-lite with Open5GS and UERANSIM) passes.
Still open, deliberately: request tracing / OpenTelemetry (planned with Phase 8 hardening; metrics, JSON logs and health exist now);
Kubernetes manifests (Phase 8, see `deploy/k8s/README.md`); OAuth2 enforcement (needs the NRF, Phase 7); the Docker image and compose file
need a first real build.

## 2026-10-07 - Language change: Rust to C, full port (ADR-0013)
- Decision (owner): the whole code base moves to C. ADR-0013 supersedes ADR-0001. Licensing is language-independent (3GPP,
  SNOW 3G ETSI/SAGE licence, clean-room rules are unchanged); the controls that replace Rust's memory safety are enforced in the build.
- The Rust tree was moved out of the repository to the sibling folder `5G_core_rust_archive` (reference only, not part of the
  product). The repository now contains only C, scripts, docs and fixtures.
- Ported, all passing plain and under ASan+UBSan (24 ctest programs, -Wall -Wextra -Wconversion -Wshadow -Werror, stack protector,
  FORTIFY_SOURCE=3, relro/now): libs/crypto, libs/base (checked buffer, JSON, YAML-subset config, logging, metrics), libs/config,
  libs/sbi, libs/nfcore, libs/pfcp, libs/gtpu, libs/nas, libs/ngap, shims/udr-lite, nf/udm, shims/ausf-lite, nf/pcf.
- New design points: generic X.691 aligned-PER interpreter for NGAP driven by a schema generated from the pinned ASN.1
  (`tools/spec/gen_ngap_c.py`, JSON trees as values); table-driven NAS (`tools/spec/gen_nas_defs.py` now emits C); per-server handler worker
  pool in the SBI server (a first version used libuv's process-global pool and deadlocked when UDM and udr-lite shared a process in
  the benchmark; fixed and the cause documented in `libs/sbi/src/server.c`).
- Evidence on real traffic (Open5GS v2.8.0 + UERANSIM): all 138 golden NGAP PDUs decode and re-encode byte-exact; 33 NAS integrity
  MACs verify with our key derivation; 13 AUTN/RES* checks bit-exact; 11 nested 5GSM payloads round-trip; 25/25 JSON payloads our NFs emit
  validate against the official 3GPP OpenAPI schemas (`scripts/validate_payloads.ps1`); scenarios S3 and S4 run with OUR C UDM, PCF and
  udr-lite in place of Open5GS's (registration with 5G-AKA, PDU session, ping through the UPF 0% loss, session release, de-registration,
  mid-session policy push accepted by Open5GS's SMF); UDM throughput about 6,900 auth vectors/s (target 1,000) with K/OPc encrypted at rest.
- What the C controls caught: an ASan stack overflow (a test bug), and `gcc -fanalyzer` findings in production code - a leaked FILE on
  an error path in the udr-lite persistence and a fragile connection-teardown order in the SBI server (both fixed).
- Tooling: `scripts/c_check.sh`, `c_lint.sh`, `c_install.sh`, `dump_payloads.sh`, `validate_payloads.ps1`; `.github/workflows/ci.yml` rewritten (never run:
  no remote); fuzz targets in `fuzz/` (replay driver runs in ctest under the sanitizers; real libFuzzer needs clang, `-DG5C_FUZZ=ON`);
  licence allow-list in `docs/legal/THIRD_PARTY.md` (OpenSSL Apache-2.0, nghttp2 MIT, libuv MIT).
- Known gaps / honest limits: coverage-guided fuzzing has not been run locally (clang absent); NGAP rejects length-prefixed values of 16 KiB
  or more (no fragmentation) and IE-pair containers (unused); the YAML reader is a subset (no anchors, tags, block scalars); SNOW 3G still
  waits for the director-signed ETSI/SAGE licence; OAuth2 token validation is a hook only.
- Next: Phase 3 (UPF: PFCP N4 + GTP-U datapath, userspace first) in C, verified against Open5GS SMF and UERANSIM.

## 2026-10-05 - Vendor comparison workbook regenerated with Amarisoft
- `docs/strategy/3GPP_Release_and_Vendor_Comparison.xlsx`: octoScope removed, Amarisoft added (Callbox Classic: 5G core and
  gNB Release 15; Callbox Ultimate/Extreme: compact Release 18 core with AMF, AUSF, SMF, UPF, UDM and a Release 19 software
  gNB/eNB; UE Simbox E: SA Release 15, MBS: SA Release 16). Counts now: 5 vendors state a release, 4 at or above Release 16,
  3 at or above Release 17, 2 at Release 18, median 17; Artiza is the only vendor with no release number. Our ceiling
  (Release 16) is unchanged; ADR-0003 wording corrected (it had said only Spirent and Viavi go beyond Release 16).

## 2026-10-05 - Phase 0/2 follow-up - spec pinning and conformance check
- Built: downloaded the 20 missing Release 16 documents (23.003, 23.501, 23.502, 23.503, 29.244, 29.281, 29.500, 29.501,
  29.503, 29.504, 29.505, 29.507, 29.509, 29.510, 29.512, 29.519, 29.571, 33.220, 33.501, 38.415) and pinned all 24
  documents we use in `docs/specs/pinned.json` / `PINNED.md` with SHA-256 (`tools/spec/fetch_specs.ps1`, `tools/spec/verify_pins.py`).
  `tools/spec/spec_text.py` extracts text; `tools/spec/extract_openapi.py` extracts the 24 normative OpenAPI documents embedded in the
  annexes; `tools/spec/validate_openapi.py` + `scripts/validate_payloads.ps1` validate what our NFs really emit (dump tests in
  `shims/ausf-lite`, `nf/pcf`, `libs/nfcore`, active only when `G5C_PAYLOAD_DIR` is set).
- Findings: (1) TS 33.501 Annex A constants and the K_AMF SUPI input match our implementation. (2) Two real conformance bugs
  found and fixed in the PCF: `pduSessionType` is mandatory in `SmPolicyContextData`, and `PolicyUpdate` must carry
  `resourceUri`. (3) After the fixes 25/25 emitted payloads are valid against the official OpenAPI schemas; the validator
  rejects a known-bad sample (self-check). (4) TS 33.501 5.2.2/5.2.3/5.3.2 make NEA1/NIA1 (SNOW 3G) mandatory and NEA3/NIA3
  (ZUC) optional, which confirms the decision to implement SNOW 3G first (ADR-0012).
- SNOW 3G: the algorithm specification is a licensed ETSI/SAGE document released only against a Restricted Usage Undertaking
  signed by a director, via GSMA/ETSI; cannot be signed by engineering. Checklist in `docs/legal/SNOW3G-licensing.md`;
  implementation is a hard gate for Phase 5 (AMF). Licensed material goes in the git-ignored `docs/specs/restricted/`.
- Release policy: ADR-0003 amended: Release 15 mandatory, Release 16 ceiling for v1, Release 17/18 scheduled per feature
  after v1 when a customer needs it, an independent peer exists to verify it and the spec is stable.
- Known gaps: UDR payloads only validated for authentication and AM data (SM, SMF-selection and policy documents use the
  UDR-lite shim format); requests we receive from Open5GS are not yet validated against the request schemas; the AMF-facing
  NAS side is validated by traces, not by schema; TS 29.571/29.500 conformance beyond the validated payloads is by interop only.
- Next: Phase 3 (UPF), unchanged.

## 2026-10-05 - Phase 2 - PCF
- Built: `nf/pcf` (binary `pcf`): **Npcf_SMPolicyControl** (create / update / delete / get SM policy associations,
  `UpdateNotify` and terminate towards the SMF), **Npcf_AMPolicyControl** (create / update / delete, RFSP), a layered
  policy engine (subscriber DNN > subscriber default > configured DNN > configured default > subscribed values > built-in;
  session AMBR, default QoS, dedicated PCC rules with QoS data), policy validation, a token-protected admin API
  (`/admin/v1/policies/{supi}`, `/admin/v1/sessions`) and metrics. Policy overrides are stored in the UDR via new
  `policy-data/ues/{ueId}/sm-data|am-data` endpoints in `udr-lite`. ADR-0011 records the design.
- Spec clauses covered: TS 29.512 (SM policy control, decision model), TS 29.507 (AM policy control), TS 29.519 (policy
  data, subset), TS 23.503 (policy model), TS 29.500 (absolute Location).
- Tests added / status (workspace: 123 passing, 1 opt-in perf test; gate `scripts/check.sh` green):
  * 6 unit tests (policy layering, decision shape, validation, bit-rate syntax) and 10 component tests over sockets:
    SM lifecycle, validation with `invalidParams`, configured DNN profile with a dedicated GBR rule, **mid-session policy
    push to a mock SMF** (change, idempotent re-apply sends nothing, new sessions get the override, removal restores the
    subscribed values), admin protection and validation, PCF-side termination, unreachable SMF tolerated, AM policy,
    metrics, empty-array omission, mandatory `suppFeat`.
  * **Interop with Open5GS:** `OUR_PCF=1` (and with `OUR_UDM=1` together) - Open5GS's AMF and SMF discover our PCF
    through the NRF and S1-S3 pass (registration, PDU session, ping through the UPF, release, de-registration); the PCF log
    shows AM policy creation and SM policy creation/deletion for each session, and Open5GS's own UDM and PCF were not running.
  * **Mid-session policy change (scenario S4, exit criterion):** with the session up, the admin API throttles the
    subscriber and adds a dedicated PCC rule; our PCF POSTs `UpdateNotify` to Open5GS's SMF, which accepts it and, 0.4 ms later,
    sends a **PFCP Session Modification to the UPF** (visible in the pcap). An AMBR-only change is accepted by the SMF
    but does not trigger any PFCP modification (Open5GS reprograms the UPF for rule changes). User plane keeps working.
- Findings from interop (fixed): (1) Open5GS's AMF refuses a `PolicyAssociation` whose `triggers` is an empty array
  ("Expected triggersList to not be empty"): empty optional arrays are omitted (also `policyCtrlReqTriggers`). (2) `suppFeat`
  is mandatory in `PolicyAssociation` and was missing. Both were invisible to our own tests, which is why the reference
  implementation stays in the loop.
- Known gaps: SM and AM associations live in PCF memory only (restart loses them; HA needs an external store); no usage
  monitoring, charging triggers, UE policy (UCU), N5/AF traffic influence or BSF binding registration (Open5GS's PCF
  registers bindings with the BSF, ours does not, so Rx/AF use cases are out of scope); `policyCtrlReqTriggers`
  from the SMF's update requests are accepted but not acted upon; UDR policy data uses an opaque shim format that
  differs from the TS 29.519 `SmPolicyData` structure; no automated side-by-side comparison of our SM policy decision
  with Open5GS's own PCF decision (the SMF accepting and acting on ours is the evidence); OAuth2 token validation is
  still only a hook.
- Next: Phase 3 (UPF): PFCP N4 and GTP-U datapath, first against a scripted PFCP client and then against Open5GS's SMF
  with UERANSIM traffic. The oracle harness already records the N4 traffic to compare against.

## 2026-10-01 - Phase 1 - UDM, UDR-lite, AUSF-lite
- Built: `nf/udm` (binary `udm`): **Nudm_UEAuthentication** (5G-AKA HE vectors, SQN step/persist, resynchronisation, SUCI
  de-concealment with profile A/B home-network keys, auth events and auth removal), **Nudm_SDM** (am-data, sm-data with
  S-NSSAI/DNN filtering, nssai, smf-select-data, ue-context-in-smf-data, sdm-subscriptions; served as v1 and v2),
  **Nudm_UECM** (AMF registration with deregistration notification of the previous AMF, SMF registrations), an admin
  provisioning API (`/admin/v1`, token-protected, off by default) and AES-256-GCM protection of K/OPc at rest.
  `shims/udr-lite` (Nudr_DataRepository subset, JSON-file persistence, JSON Patch) and `shims/ausf-lite`
  (Nausf_UEAuthentication 5G-AKA: HXRES*, K_SEAF, confirmation, auth events). ADR-0010 records the design.
- Spec clauses covered: TS 29.503 (UEAU, SDM, UECM), TS 29.504/505 (subset), TS 29.509 (5G-AKA subset), TS 33.501 6.1.3.2 and
  6.12, TS 33.102 6.3.5 + Annex C, TS 29.500 5.2.3.2 (Location).
- Tests added / status (workspace: 107 passing, 1 opt-in perf test):
  * **Bit-exact vs the reference implementations:** for every challenge in the S1-S3 traces our code regenerates
    Open5GS's AUTN (MAC-A included) from K/OPc/RAND/SQN, and our XRES* equals the RES* UERANSIM computed.
  * 10 end-to-end tests (UDR-lite + UDM + AUSF-lite on sockets, simulated USIM with real checks): successful
    5G-AKA with independent K_SEAF agreement, wrong RES*, SQN steps of 32, resynchronisation, forged AUTS, SUCI profile A
    and null scheme, error cases, encryption at rest (and SUPI binding), 40 concurrent requests never reusing an SQN,
    admin API validation and secrecy. 7 UDM service tests (SDM data and filters, subscriptions, UECM incl. old-AMF
    notification, validation, persistence, absolute Location, auth removal).
  * **Throughput baseline: 7,467 auth vectors/s** (release build, AES-GCM at rest, UDM + UDR-lite + 64 load workers on
    one host; target was 1,000).
  * **Interop:** `OUR_UDM=1 deploy/oracle/scenario.sh s3` - Open5GS's AMF, AUSF, SMF, PCF and UPF with UERANSIM, and OUR
    UDM + UDR-lite in place of Open5GS's UDM: registration (5G-AKA with our vectors), PDU session, ping through the UPF,
    PDU session release and de-registration all pass with no errors in the Open5GS logs.
- Findings from interop (fixed): (1) Open5GS's AUSF rejects relative `Location` headers ("No http.scheme found"); the SBI
  server now tracks scheme/authority and `Req::url` builds absolute URIs. (2) At de-registration Open5GS's AUSF sends
  `PUT /nudm-ueau/v1/{supi}/auth-events` (auth removal, no id) which we answered 405; accepted on both path forms.
  The SBI router now logs a warning for unmatched routes, which is what exposed (2).
- Known gaps: SDM change notifications are not sent (subscriptions are stored in memory only); AMF/SMF registrations are
  stored in the UDR only (no UDM cache); the per-SUPI lock covers a single UDM instance (HA needs CAS in the UDR);
  EAP-AKA' unsupported (501); no OAuth2 access-token validation yet (guard hook exists); the UDR is configured
  statically (no NRF discovery); UDR keys ignore the serving PLMN; no key rotation/HSM; `ausf-lite` keeps contexts in
  memory only; Profile B SUCI untested against a published vector.
- Next: Phase 2 (PCF) on top of the same NF runtime and UDR-lite policy data; add SDM change notifications when the PCF
  and AMF need them.

## 2026-10-01 - Phase 0 - completion
- Built / finished: **S2 and S3 golden traces** without sudo: `deploy/oracle/scenario.sh s2|s3` re-executes itself in an
  unprivileged user+network namespace (own loopback, TUN device, private MongoDB, a nested "data network" namespace
  behind the UPF and a separate namespace for the UE's TUN so pings really cross gNB -> UPF). Needed fix: the oracle must
  also run the BSF (PCF discovers it). S1-S3 pcaps and extracted NGAP hex are in `tests/fixtures/golden/`.
  **Crypto vectors:** all 20 TS 35.208 Milenage sets (OPc, f1, f1*, f2-f5*) and TS 33.401 Annex C vectors for 128-EEA2
  (6 sets) and 128-EIA2 (byte-aligned sets 2, 5, 8), generated from the spec text (`tools/spec/doc_to_text.py` is a small Word
  97 reader, `tools/gen/gen_milenage_vectors.py`, `tools/gen/gen_nas_sec_vectors.py`). **SBI:** TLS 1.2/1.3 and mutual TLS (rustls,
  ring), bearer-token guard hook, metrics observer hook. **Telemetry:** Prometheus-format metrics registry.
  **`libs/nfcore`:** shared NF runtime (config -> telemetry -> SBI server -> NRF registration/heartbeat/deregistration ->
  health, readiness, `/metrics`). **Tooling:** cargo-deny installed and passing, nightly + cargo-fuzz installed, four
  fuzz targets (`fuzz/`), `scripts/check.sh` (the CI gate), `scripts/fuzz.sh`, `scripts/fuzz_all.sh`.
- Tests / status: all four cargo-deny checks pass. NGAP and NAS golden tests now cover S1-S3: **38 protected NAS messages
  MAC-verified** with keys derived by our crypto, 14 NGAP message types round-trip byte-exact. Fuzzing: GTP-U 16.3M runs,
  PFCP 35.7M runs, NGAP 229k runs (decode -> encode -> decode invariant), NAS found a real bug within seconds (unknown
  one-octet optional IEs were re-encoded as two octets); fixed, regression test added, 180 s re-fuzz clean.
- Findings: `rustls-pemfile` was flagged unmaintained (RUSTSEC-2025-0134); replaced by `rustls-pki-types` PEM parsing.
  **SNOW 3G and ZUC cannot be implemented from 3GPP documents:** TS 35.216 and 35.222 are cover pages; the algorithm
  specifications are ETSI SAGE documents "subject to licensing conditions", so NIA1/NEA1 (SNOW 3G, mandatory for an
  AMF) and NIA3/NEA3 (ZUC) are blocked on a licensing decision (obtain the SAGE specs and licence terms). The current
  core test peers negotiate NIA2/NEA0, so Phases 1-6 are not blocked.
- Known gaps (carried forward): NIA1/3 and NEA1/3 (licensing); typed PFCP IEs (Phase 3); NGAP `PrivateMessage`; CI workflow
  has never executed (no remote); fuzz corpora are not stored; OAuth2 token issuance is Phase 7 (NRF).
- Phase 0 exit criteria status: libs pass spec vectors (yes, except the licensed algorithms); CI green (local gate green,
  remote not available); golden traces S1-S3 stored (yes); ADRs signed off (yes, 0001-0010).

## 2026-09-30 - Phase 0 - NGAP and NAS codecs
- Built: **NGAP** - `tools/spec/extract_asn1.py` (TS 38.413 v16.18.0 ASN.1 from the docx), `tools/ngap-gen` (rasn-compiler),
  `tools/gen_ngap_ies.py` (typed IE enums + `NgapMessage` dispatcher, 96 messages), `libs/ngap`. **NAS** -
  `tools/spec/extract_nas_tables.py` + `tools/spec/gen_nas_defs.py` (TS 24.501 v16.15.0 clause 8 tables -> `libs/nas/src/defs.rs`),
  generic table-driven `Message` codec for 32 5GMM + 16 5GSM messages, `ie.rs` typed IEs, `security.rs`
  (SHT 1-4, NIA2/NEA2, NIA0/NEA0). New ADR-0008 (NGAP pipeline, vendored rasn) and ADR-0009 (NAS).
  `tools/gen/pcap_ngap_to_hex.py` extracts NGAP PDUs from pcaps. Specs downloaded with approval into the git-ignored
  `docs/specs/src/`.
- Spec clauses covered: TS 38.413 (all procedures), TS 24.501 clause 8 (all messages), 9.7, 9.11.2/3 (selected IEs),
  4.4/9.3 (security), TS 33.501 6.4 (NAS integrity).
- Tests added / status: workspace 61 tests passing; fmt and clippy `-D warnings` clean. 67 real NGAP PDUs from three
  traces decode and re-encode byte-identically, including nested PDU-session transfers. NAS: 12 message types from the
  traces re-encode byte-exact; nested 5GSM in UL NAS transport decodes. **Every real integrity MAC in the S1 trace
  verifies with keys derived by our crypto (Milenage -> K_AUSF -> K_SEAF -> K_AMF -> K_NASint, NIA2)**. This closes the
  earlier gap that the AKA key chain was only property-tested, and showed K_AMF's SUPI input is the digits-only IMSI.
- Findings: rasn 0.28.15's APER codec has two bugs hit by real NGAP traffic (decoder aligned after constrained
  SEQUENCE OF lengths; encoder did not align ranges > 255). Both fixed in `vendor/rasn` (README there); not reported
  upstream yet. rasn-compiler omits one import (patched by ngap-gen) and leaves IE open types as `Any` (hence
  `gen_ngap_ies.py`). The spec's clause number "8.6.27" is a typo for Security mode reject; handled in the generator.
- Known gaps: NGAP `PrivateMessage` not typed; no NGAP criticality handling / error-indication logic yet (AMF phase).
  NAS: only a first set of typed IEs; NIA1/NIA3/NEA1/NEA3 (SNOW 3G, ZUC) missing; no NAS COUNT/replay state machine
  (belongs to AMF/UE context). Extra NGAP/NAS fixtures come from the user's ORAN-emulator captures (other keys), so
  only S1 is MAC-verified. Fuzzing is seeded random tests, not coverage-guided. Regenerating `generated.rs` /
  `typed.rs` requires `cargo fmt` afterwards. Extracted ASN.1/tables are derived from 3GPP text: confirm
  redistribution terms with counsel before shipping them in a source release.
- Next: run `cargo-deny` and install `cargo-fuzz`, S2/S3 golden traces (needs sudo TUN), Milenage test sets 2-19,
  SNOW 3G/ZUC; then Phase 1 (UDM) on top of crypto + sbi.

## 2026-09-30 - Phase 0 - SBI transport library
- Built: `g5c-sbi` on tokio + hyper 1 (ADR-0007): path-template `Router` (404/405 with `Allow`), h2c HTTP/2 `serve`
  with 1 MiB body limit (413), pooled multiplexed `Client` with timeout, `ProblemDetails` (TS 29.571 5.2.4.1) and JSON
  helpers that turn malformed bodies into 400 problem+json.
- Spec clauses covered: TS 29.500 (HTTP/2 + JSON usage), TS 29.571 5.2.4.
- Tests added / status: 6 unit + 5 loopback end-to-end tests (incl. 200 concurrent requests on one connection, timeout,
  oversize body) passing. Opt-in `oracle_interop` test: our client discovered the UDM via the real Open5GS NRF
  (Nnrf_NFDiscovery) and received the expected 404 - passing. fmt and clippy `-D warnings` clean workspace-wide.
- Known gaps: cleartext h2c only (TLS 1.3/mTLS via rustls next; mandatory by Phase 8); no OAuth2 access-token
  validation, no NRF registration/heartbeat helper, no graceful drain of in-flight connections on shutdown, no
  HTTP/1.1 fallback, no server-side metrics. No per-service API models yet (owned by each NF, validated against the
  3GPP YAML once downloaded).
- Next: NAS and NGAP codecs (ADR for the ASN.1 pipeline first), then remaining Phase 0 items: cargo-deny/cargo-fuzz
  runs, S2/S3 golden traces (needs one-time sudo TUN setup), AKA cross-check against the oracle, Milenage sets 2-19.

## 2026-09-30 - Phase 0 - SUCI/NAS security, oracle test environment, S1 golden trace
- Built: `g5c-crypto::suci` (ECIES Profiles A and B: X9.63 KDF, AES-128-CTR, HMAC-SHA-256 tag, BCD MSIN helpers),
  `g5c-crypto::nas_sec` (NEA0/NIA0, 128-NEA2, 128-NIA2). `deploy/oracle/` harness: isolated Open5GS v2.8.0 core
  (generated configs, loopback 127.1.0.x, DB `g5c_oracle`, PLMN 001/01) + UERANSIM built in `~/test-peers`;
  `scenario.sh s1` runs registration/deregistration and records a pcap. Golden S1 trace stored in
  `tests/fixtures/golden/`.
- Spec clauses covered: TS 33.501 Annex C.3 (SUCI), Annex D (128-NEA2/NIA2); TS 23.502 4.2.2.2 (registration) observed
  on the oracle.
- Tests added / status: crypto now 16 tests passing. The SUCI Profile A vector from TS 33.501 Annex C.4.3
  (HN/ephemeral public keys, ciphertext, MAC tag) matches bit-exactly. S1 passed 4/4 consecutive runs against
  the oracle after making each run start from a clean oracle (stale SMF state without a UPF broke a rerun).
- Findings: UERANSIM is now AGPL-3.0 (dual-licensed with a commercial licence), not GPL-3.0 as the strategy PDF
  first stated; PDF and ADR-0002 corrected (still test-only). A second Open5GS instance (user's own, PLMN 999/70)
  runs on the machine; the oracle is isolated from it and verified not to disturb it. A local Open5GS source
  checkout exists; ADR-0002 now forbids opening its `src/` during implementation.
- Known gaps: NEA1/NIA1 (SNOW 3G) and NEA3/NIA3 (ZUC) not implemented (need spec S-box tables + vectors).
  NEA2/NIA2 and Profile B have no published 3GPP vectors yet. S2/S3 golden traces need sudo for a TUN device
  (`deploy/oracle/README.md`). The S1 trace includes a failed PDU-session attempt (no UPF). AKA oracle
  cross-check (comparing our RES*/KAUSF etc. with values from the oracle's logs/pcap) not done.
- Next: `libs/sbi` (HTTP/2 stack ADR, OpenAPI model generation, ProblemDetails, OAuth2 hooks), then NAS/NGAP codecs.

## 2026-09-30 - Phase 0 - Workspace, first libs, ADRs
- Built: Cargo workspace (`libs/*`), toolchain pin, rustfmt/clippy config (`unsafe` forbidden, unwrap linted),
  `deny.toml` licence policy, GitHub Actions `ci.yml` (fmt, clippy, test, cargo-deny, CycloneDX SBOM),
  `scripts/dev.ps1|dev.sh` to run cargo in WSL Ubuntu (Rust 1.98.1 installed there via rustup).
  Libraries: `g5c-crypto` (Milenage, generic KDF, 5G-AKA functions and key hierarchy), `g5c-gtpu`
  (GTP-U v1 header, extension headers, PDU Session Container), `g5c-pfcp` (header + IE TLV framing),
  `g5c-config` (shared NF YAML config + validation), `g5c-telemetry` (tracing init), `g5c-testkit`.
  ADR-0001..0006 accepted; spec traceability table in `docs/specs/README.md`.
- Spec clauses covered: TS 35.206/208, 33.220 B.2, 33.501 Annex A + 6.1, 29.281 5, 38.415, 29.244 7.2/8.1.
- Tests added / status: 19 unit tests, all passing in WSL; `cargo fmt --check` and
  `clippy -D warnings` clean. Milenage matches TS 35.208 Test Set 1 bit-exactly. GTP-U and PFCP decoders
  have 200k-iteration random-input tests (no panics, decode/encode round-trip).
- Known gaps: 5G-AKA functions (RES*, KAUSF, KSEAF, KAMF, algo keys, KgNB) have property tests only - no
  published numeric vectors used yet; must be cross-checked against the Open5GS oracle. CI and cargo-deny
  have not been executed (no remote repo, cargo-deny not installed locally). No fuzz harness (cargo-fuzz) yet.
  SBI/NAS/NGAP still placeholders. Compose env and golden pcaps not started.
- Next: SUCI ECIES + NEA/NIA in crypto; remaining Milenage test sets; `libs/sbi` (HTTP/2 + OpenAPI
  generation, ADR for HTTP stack); NAS/NGAP codecs (ADR for ASN.1 pipeline); compose with UERANSIM + Open5GS;
  capture golden pcaps; install cargo-deny/cargo-fuzz and run them.

## 2026-09-30 - Phase 0 - Project kickoff
- Built: phase-wise strategy PDF (`docs/strategy/5G_Core_Phase_Strategy.pdf`), repository scaffold (libs/, nf/, shims/, tests/, deploy/, configs/, docs/), docs README and this log.
- Spec clauses covered: n/a (planning).
- Tests added / status: none.
- Known gaps: language, licence and 11th-NF decisions pending; no code yet.
- Next: confirm D1-D5, set up Linux dev env with UERANSIM + Open5GS oracle, write ADR-0001..0003, scaffold workspace/CI, start libs/crypto and libs/sbi.
