# 5G Core

A clean-room implementation of a 5G standalone (SA) core network, written in C17 directly from the 3GPP Release 16 specifications, with Release 17 additions where the baseline leaves room. It comprises twelve cooperating network functions, the shared protocol and platform libraries beneath them, an operator control surface, a verification harness, and the deployment assets needed to run the whole system on a laptop, in containers, or on systemd hosts.

Third-party stacks (Open5GS, UERANSIM, srsRAN) appear only as interoperability peers and behavioural oracles for differential testing; none of their code is used.

---

## 1. System model

The core follows the Service-Based Architecture of TS 23.501. Control-plane functions expose HTTP/2 + JSON services (the SBI) and discover one another through the NRF; the radio side speaks NGAP/SCTP (N2) and NAS (N1) to the AMF; the user plane is steered over PFCP (N4) and carries traffic as GTP-U (N3) to the data network (N6).

```
                 Nnrf  ┌───────┐  Nnrf
        ┌──────────────┤  NRF  ├──────────────┐         every function registers,
        │              └───┬───┘              │         heart-beats, and discovers
   ┌────┴───┐   N8   ┌─────┴────┐  N13   ┌────┴───┐     its peers here; the SCP can
   │  AMF   ├────────┤   UDM    ├────────┤  AUSF  │     front all SBI traffic
   └─┬──┬───┘        └────┬─────┘        └────────┘
     │  │ N15        N35  │  N36
     │  └──────┐     ┌────┴─────┐     ┌─────────┐
 N2  │         └─────┤   UDR    ├─────┤   PCF   ├── N5 ── NEF ── (application functions)
     │   N11         └──────────┘     └──┬────┬─┘
 ┌───┴──┐       ┌─────┐   N7             │    └── Nbsf ── BSF
 │ gNB  │       │ SMF ├──────────────────┘
 └───┬──┘       └──┬──┘
     │ N3          │ N4 (PFCP)
     │         ┌───┴──┐  N6
     └─────────┤ UPF  ├────────── data network
               └──────┘
```

## 2. Network functions

| Function | Responsibility | Notable internals |
|----------|----------------|-------------------|
| **AMF** | Access and mobility. Terminates N1/N2: NG setup, registration, 5G-AKA and EAP-AKA' orchestration, NAS security mode, service request and paging, de-registration, configuration update, Xn and N2 handover, N1N2 message transfer, event exposure. | SCTP transport, NAS security context per UE, persistent UE state, per-slice session accounting, fault injection hooks for resilience tests. |
| **SMF** | Session management. PDU session create/modify/release, UE address allocation, UPF selection, PFCP rule generation (PDR, FAR, QER, URR, BAR), PCF-driven modification, paging triggers, UPF restart recovery. | Usage-monitoring loop (PCF thresholds → URR → usage report → policy update), CDR emission, persistence of session state, PFCP retransmission and message caching. |
| **UPF** | User plane. GTP-U termination on N3, N6 forwarding through a TUN device, SDF classification, QoS enforcement (token buckets for MBR/AMBR), downlink buffering with end markers, usage reporting. | Open-addressed pointer maps for TEID/UE lookup, rule store validated on every PFCP modification, runtime event loop separate from the pure dataplane engine. |
| **PCF** | Policy control. SM and AM policy associations, PCC rule decisions, per-subscriber policy from the UDR, application-function sessions (Npcf_PolicyAuthorization) with QoS references, BSF binding registration. | Mid-session policy push, usage-monitoring decisions, operator admin API for policies and sessions. |
| **UDM** | Subscriber data and credentials. Nudm_UEAuthentication (5G-AKA, EAP-AKA' vector generation), SDM, UECM, event exposure, SUCI de-concealment, ID translation. | Keys encrypted at rest through a master key, serialized per-SUPI SQN handling, bulk subscriber provisioning, embedded operator console. |
| **UDR** | Unified data repository. Nudr data APIs for subscription, policy, exposure and application data, group-ID mapping. | Operations and schemas generated from the pinned OpenAPI files; one storage interface with memory, journalled-file and PostgreSQL backends; ETag/precondition handling; subscriptions and notifications. |
| **AUSF** | Authentication server. Nausf_UEAuthentication for 5G-AKA and EAP-AKA', SoR and UPU protection, FN-RG authentication. | KAUSF per SUPI in an encrypted state file. |
| **NRF** | Registry. Nnrf_NFManagement, NFDiscovery with filters and ordering, AccessToken (ES256 JWT). | Heart-beat supervision, status notifications, persistence. |
| **NSSF** | Slice selection. NSSelection and NSSAIAvailability, roaming mappings, configured/allowed NSSAI. | Slice policy in configuration, generated schema tables. |
| **NEF** | Northbound exposure for application functions: traffic influence, monitoring events, AS session with QoS. | Per-AF access control, bridges to UDR, AMF, PCF, UDM and BSF. |
| **SCP** | Service communication proxy: indirect communication models C and D (TS 29.500 §6.10). | Delegated discovery with cache, producer reselection with quarantine, loop detection, chained SCPs. |
| **BSF** | Binding support. Nbsf_Management register/update/deregister/discover. | IPv4 and IPv6 longest-prefix match, MAC and framed-route bindings, overlapping address handling. |

Every function is a single binary configured by one YAML file, started as `<name> [--check] <config.yaml>` (`--check` validates the configuration and exits), and exposes `/health/live`, `/health/ready`, `/metrics` and, where applicable, an authenticated `/admin/v1` surface.

## 3. Shared libraries (`libs/`)

| Library | Contents |
|---------|----------|
| `base` | Byte buffers and bit readers, JSON and YAML parsers (hardened against depth and size abuse), structured logging with trace correlation, Prometheus metrics registry. |
| `config` | Typed configuration loading and validation shared by all functions. |
| `sbi` | The service-based interface stack on libuv, nghttp2 and OpenSSL: HTTP/2 over h2c, TLS and mutual TLS; router; client with connection reuse; OAuth2 client credentials and access-token verification; certificate rotation on SIGHUP; CN pinning and CRL checking; TLS key-log export; W3C `traceparent` propagation. |
| `nfcore` | The skeleton every function is built on: NRF registration and heart-beats, discovery, admin guard, health and metrics endpoints, `/openapi.json`, SCP client. |
| `nas` | A table-driven 5GS NAS codec generated from the TS 24.501 information-element tables. |
| `ngap` | An NGAP codec driven by schema tables generated from the TS 38.413 ASN.1 modules (aligned PER). |
| `pfcp` | PFCP message and IE codec for TS 29.244, including grouped IEs and rule structures. |
| `gtpu` | GTP-U header and extension handling for TS 29.281. |
| `crypto` | Milenage, 5G-AKA and EAP-AKA' key hierarchies, SUCI ECIES, NAS integrity and ciphering (including SNOW 3G), built on OpenSSL primitives. |
| `oaschema` | A JSON validator that evaluates payloads against the 3GPP OpenAPI schemas. |
| `testkit` | Fixtures and helpers shared by unit and integration tests. |

## 4. Cross-cutting design

**Security.** Credentials never appear inline in configuration; keys live in files or environment variables. SBI traffic can run in plaintext for lab use, TLS, or mutual TLS with peer CN allow-lists and revocation lists. Subscriber keys are encrypted at rest. Admin APIs are token-guarded and audit-logged. Message parsers are fuzzed and every external-facing decoder has a bounded-resource budget.

**Observability.** Each function publishes Prometheus metrics, JSON logs carrying the trace id of the originating request, and health endpoints. `deploy/ops` holds alert rules, KPI recording rules, a Grafana dashboard and a KPI catalogue from which both are derived.

**State and recovery.** AMF, SMF, NRF, NEF, BSF, AUSF and UDR persist what they must to survive restarts; the SMF reconciles with the UPF after a PFCP restart; the NRF supervises heart-beats and notifies subscribers of status changes.

**Fault injection.** The AMF and SMF accept injected failures (rejected procedures, dropped N4 messages) so resilience can be exercised deterministically rather than by chance.

## 5. Verification

- **Unit and component tests** per function and per library, registered in CMake and run by `ctest` with labels (`unit`, `component`, `integration`, `conformance`, `fuzz`, `perf`).
- **Sanitizers.** The same suites run plain and under ASan + UBSan; a ThreadSanitizer script covers the concurrent paths.
- **Fuzzing.** libFuzzer targets for NAS, NGAP, PFCP/GTP-U, JSON/YAML and every function's SBI entry points; without clang the same entry points run as replay drivers over checked-in seeds inside `ctest`.
- **Conformance matrix.** Specification clauses are mapped to functions and to the tests that prove them (`docs/conformance/*.json`); `tools/check/check_matrix.py` rejects a row whose proving test does not exist.
- **Golden traces.** Captured NGAP/NAS/PFCP/GTP-U exchanges are decoded and re-encoded byte-exactly; payload dumps are validated against the official OpenAPI documents.
- **Differential tests.** `deploy/oracle` and `tools/diff` run our functions and Open5GS's against the same stimuli and compare status codes, bodies and wire bytes.
- **Cluster tests.** `deploy/run/g5c-cluster.sh` builds a full multi-function core in network namespaces and runs load, chaos (latency, loss, kills), soak, TLS, secrets, slices, upgrade, key-log and scenario modes. `load_core` generates registrations and user-plane traffic; `g5c-scenario` interprets declarative YAML scenarios from `scenarios/`.
- **Static checks.** `scripts/c_lint.sh` enforces banned functions, dependency licences and `gcc -fanalyzer`; `-Werror` with hardening flags is the default build.

## 6. Tooling (`tools/`)

| Folder | Role |
|--------|------|
| `cli/` | Operator and tester commands: `g5c-api` (SBI explorer), `g5c-sdk` (generates a client from live `/openapi.json`), `g5c-subscribers` (Open5GS/free5GC/CSV import and export), `g5c-scenario`, `g5c-kpi`, `g5c-trace` (cross-function trace stitching), `g5c-ladder` (message-flow ladders and anomaly detection from packet captures), `g5c-capture`, `g5c-diag` (support bundle with redaction), `g5c-redact`, `g5c-dn`. |
| `spec/` | Fetches the pinned 3GPP documents, extracts ASN.1, NAS tables and OpenAPI files, and generates the NGAP schema, NAS definitions and per-function API tables. |
| `gen/` | Reproducible generators for test vectors, fuzz seeds, conformance matrices, the web console and the Grafana dashboard. |
| `check/` | Consistency gates for matrices, operations files and service-level objectives. |
| `diff/` | Python differential harnesses for each function against Open5GS. |
| `release/` | Release assembly: archives, checksums, signatures, SBOM, licence audit, performance history, compliance dossier. |
| `inspect/` | `g5c-inspect`, a C decoder for NGAP and NAS hex dumps. |

## 7. Deployment (`deploy/`)

`docker` and `compose` (including a UERANSIM + Open5GS oracle topology), `k8s`, `systemd` units with a `g5c@` template, `run` (namespace cluster, PKI generation with CRL and revocation, one-command init), `oracle` (interop scenarios), `ops` (monitoring), `console` (single-file web UI served by the UDM), `demo`, `windows`, and `install.sh` for host installation.

## 8. Repository map

| Path | Contents |
|------|----------|
| `nf/<function>/` | `include/`, `src/`, `tests/` for each of the twelve functions. Functions never include each other; shared code is only reached through `libs/`. |
| `libs/` | The libraries of section 3. |
| `ctl/` | `g5c-ctl`, the command-line client for the admin interfaces. |
| `tools/` | Section 6. |
| `scripts/` | Build, test, lint, coverage, TSan and full-regression entry points. |
| `tests/` | Cross-function tests: `conformance`, `support` (tests of the tools), `fixtures` (golden captures, fuzz seeds), `soak`. |
| `fuzz/` | libFuzzer targets and replay driver. |
| `scenarios/` | Declarative YAML scenarios for the cluster runner. |
| `configs/` | One sample configuration per function. |
| `deploy/` | Section 7. |


## 9. Building

Requirements: a C17 compiler (GCC or Clang), CMake, OpenSSL 3, nghttp2, libuv; Linux for SCTP, TUN and XDP (on Windows, use WSL2).

```
bash scripts/c_check.sh        # build and run every test, plain and under ASan + UBSan
bash scripts/c_lint.sh         # banned functions, licences, static analysis
bash scripts/c_install.sh      # optimised build; installs binaries to ~/.cache/g5c-bin/bin
bash scripts/g5c_regress.sh    # full regression; add --oracle for the Open5GS differentials
```

## 10. Provenance and licensing

The implementation derives from the pinned 3GPP specifications listed in `docs/specs/PINNED.md`. Dependencies are limited to permissive licences (MIT, Apache-2.0, BSD, ISC, MPL-2.0); the build audits this on every release. See `LICENSE`, `NOTICE` and `docs/legal/`.
