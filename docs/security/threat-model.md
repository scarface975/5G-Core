# Threat model of the g5c core (release 0.9.0-rc1)

STRIDE over the interfaces, with what the code does about each and what is left. It complements `udm-key-handling-threat-note.md`. An external penetration test is planned in
`docs/pilot-plan.md`; this document is the engineering view that the test is briefed with.

## Assets
Subscriber credentials (K, OPc, home network private keys), session keys (KAUSF, KSEAF, KAMF, NAS keys), subscriber identities and locations, the access-token signing key of the NRF, the CA key, admin tokens,
the availability of the signalling and the user plane, and the integrity of policy and charging data.

## Trust boundaries
1. UE / gNB to the core: N2 (SCTP) and N3 (GTP-U) are not authenticated by the core beyond NG Setup and the NAS security between UE and AMF. The RAN is untrusted for content, trusted for identity of cells.
2. Between functions (SBI): mutual TLS with the cluster CA, plus the NRF's OAuth2 access tokens (service and audience scoped).
3. Operators and application functions: admin APIs (bearer tokens over mutual TLS), the NEF's northbound API (a token per AF).
4. The host: files (keys, state, configurations), processes, the kernel.

## STRIDE by interface
| Threat | Interface / asset | Control in the code | Evidence | Left open |
|---|---|---|---|---|
| Spoofing a function | SBI | mutual TLS (a client certificate of the cluster CA); optional `sbi.tls.allowed_peers` (the common name of the client certificate must match, so one function cannot call as another) and `sbi.tls.crl` (revoked certificates are refused, read again on SIGHUP); access token bound to NF type and instance | `cluster_tls`, `nrf_oauth2`, `sbi_router_h2_tls` | `allowed_peers` is off by default (any certificate of the CA is accepted) and the lists are the operator's to write; with indirect communication the caller the function sees is the SCP |
| Spoofing a UE | N1 | 5G-AKA with RES* check in the AUSF, NAS integrity (NIA2), replay protection by counts | `amf_e2e`, oracle scenarios | NIA1/NIA3 and NEA1/NEA3 not offered (licensing) |
| Spoofing a gNB | N2 | NG Setup against the configured PLMN and TAs only | `amf_e2e` | no IPsec / DTLS on N2 and N3 (TS 33.501 9): the transport network must be protected |
| Tampering with signalling | SBI, N4 | TLS integrity; PFCP over a trusted link only | `cluster_tls` | PFCP is cleartext UDP: protect the N4 link |
| Tampering with state | state files | encrypted with a master key where they hold credentials (KAUSF, K / OPc); mode 600 | `cluster_secrets` | state files of AMF / SMF hold identities in the clear: restrict the directory |
| Repudiation | admin and policy changes | `g5c_audit` lines (who, what), charging records with a sequence number | `cluster_ops` | the audit lines name the operation, not the calling token: one token per operator system |
| Information disclosure: logs | all | no key, token or credential is written to a log; the diagnostics bundle redacts identities | `cluster_secrets`, `cluster_support` | the logs hold SUPIs by design (operations need them): restrict log access, ship through a redactor |
| Information disclosure: wire | SBI | TLS 1.2+; content not visible to a capture | `cluster_tls` | TLS 1.2 is still allowed |
| Information disclosure: keys at rest | UDM store | K / OPc AES-256-GCM under the master key (SUPI as associated data); rotation by `rewrap` | `cluster_ops` | the master key is a file (or the output of a command: `exec:`); an HSM is the integration, not included |
| Denial of service: signalling | AMF N2, SBI | bounded unauthenticated contexts (`max_unauthenticated`), per-server connection limits, deadlines on every request, overload answered with 503, worker pools sized by configuration | fuzzing, chaos and load tests | no per-source rate limit on N2; no TS 29.500 overload control (the 429 / LCI headers) |
| Denial of service: user plane | UPF | session limit (`max_sessions`), QER rate enforcement, drop counters | `upf_*` tests | no NIC offload; a flood saturates one core |
| Elevation of privilege | host | non-root service user, no capabilities except the UPF's CAP_NET_ADMIN, read-only system, no new privileges, memory W^X (`deploy/systemd/g5c@.service`) | `systemd-analyze verify` of the units | containers are unbuilt: not assessed |
| Malformed input | NGAP, NAS, PFCP, GTP-U, SBI bodies | table-driven decoders with bounds checks; JSON schema validation of every SBI body (payloads against the pinned OpenAPI); fuzz replay under ASan / UBSan on every build; no banned libc functions (lint) | `fuzz_replay_*`, `payload validation 87/87`, `c_lint.sh` | no coverage-guided fuzzing in CI (needs clang); no long fuzz campaign |
| Supply chain | build | dependencies pinned in the SBOM, licence audit automated, release archive checksummed and signed | `licence_audit.py`, `tools/release.sh` | no reproducible build; no scan against a vulnerability database in this environment (run one at release: `docs/release-process.md`) |

## Abuse cases that drove tests
A request without a token, with an expired token, a forged key id, another audience (`nrf_oauth2`); a foreign CA's certificate, no client certificate, cleartext to a TLS port (`cluster_tls`); a certificate
file replaced by garbage during a reload (`cluster_tls`); a UPF that dies while the SMF waits (found a null response read, fixed); a gNB that closes the association behind a de-registration (found a
context that stayed, fixed); K and OPc looked for in logs and state after traffic (`cluster_secrets`).

## Residual risk accepted for the release candidate
N2 / N3 / N4 transport protection is the operator's network; SBI certificate revocation needs the operator to publish and distribute the CRL (`g5c-pki.sh revoke`; no OCSP); the penetration test is outstanding and must close with no critical or high finding open before
a release is called general availability.
