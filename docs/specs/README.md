# Spec index and traceability

Pinned document versions: [PINNED.md](PINNED.md) (24 Release 16 documents, SHA-256 in `pinned.json`; `python tools/spec/verify_pins.py`).
Schema conformance: `scripts/validate_payloads.ps1` validates the JSON our NFs emit against the official OpenAPI files embedded in the specs.


Baseline: 3GPP Release 15 mandatory, Release 16 ceiling for v1 (ADR-0003). Specs are downloaded from https://www.3gpp.org/ftp/Specs/archive into `docs/specs/src/` (git-ignored, not redistributed);
derived ASN.1 (`docs/specs/asn1/`) and NAS tables (`docs/specs/nas/`) are kept. Record the exact version (e.g. `33.501 v16.x.y`) you work from in the table below.

| Spec | Topic | Module | Tests | Status |
|------|-------|--------|-------|--------|
| TS 35.205/206/208 | MILENAGE + test data | `libs/crypto/src/milenage.c` | all 20 TS 35.208 sets (OPc, f1, f1*, f2-f5*) via `tests/test_milenage.rs` | done |
| TS 33.220 Annex B | Generic KDF | `libs/crypto/src/kdf.c` | RFC 2104 cross-check | done |
| TS 33.501 13.3.1.3, 13.4.1 | OAuth 2.0 access tokens of the NRF between functions: producer check (signature, expiry, audience, scope), consumer token client | `libs/nfcore/src/oauth.c`, `nf/nrf/src/oauth.c` | `nrf_oauth2`, cluster runs, oracle S4 / S7 / S8 with `OUR_OAUTH2=1` | done for the service level (SEC-GAP-01..02) |
| TS 33.501 Annex A, 6.1 | 5G-AKA key hierarchy | `libs/crypto/src/aka5g.c` | NAS MACs of S1-S3 traces verified with derived keys; AUTN and RES* reproduced from Open5GS/UERANSIM traces | done |
| TS 33.501 Annex C.3 | SUCI ECIES (profiles A/B) | `libs/crypto/src/suci.c` | Annex C.4.3 Profile A vector (keys, ciphertext, MAC) passing; Profile B round-trip + tamper only (no published vector used yet) | done (B vector TODO) |
| TS 33.501 Annex D | NEA0/2, NIA0/2 | `libs/crypto/src/nas_sec.c` | TS 33.401 Annex C: 6 EEA2 sets and byte-aligned EIA2 sets 2/5/8 (`tests/test_nas_sec.rs`); AES-CTR/CMAC primitives vs SP 800-38A / RFC 4493 | done |
| ETSI SAGE (via TS 35.216/35.222) | NEA1/NIA1 (SNOW 3G), NEA3/NIA3 (ZUC) | `libs/crypto` | - | **blocked: algorithm specs are licensed ETSI SAGE documents** |
| TS 29.281 | GTP-U header + extensions | `libs/gtpu` | known bytes, fuzz-style | header done |
| TS 38.415 | PDU Session Container | `libs/gtpu` | known bytes | done |
| TS 29.244 7.2, 8.1 | PFCP header, IE framing | `libs/pfcp` | known bytes, fuzz-style | framing done; typed IEs TODO |
| TS 24.501 v16.15.0 cl. 8, 9.7 | NAS message framing, all 32 5GMM + 16 5GSM messages | `libs/nas` (`defs.c` generated) | 12 message types from real traces re-encode byte-exact; garbage/truncation fuzz | done |
| TS 24.501 cl. 9.11 | Typed IEs (mobile identity, ngKSI, reg type, UE sec cap, NSSAI, DNN, ...) | `libs/nas/src/nasie.c` | unit tests; SUCI/GUTI layouts checked vs trace | partial (more IEs per procedure) |
| TS 24.501 4.4, 9.3; TS 33.501 6.4 | Security-protected NAS, NIA2/NEA2 | `libs/nas/src/security.c` | real MACs of S1 trace verified; tamper + roundtrip tests | done for NIA0/2, NEA0/2 |
| TS 38.413 v16.18.0 | NGAP (ASN.1 APER), 96 messages typed | `libs/ngap` (`schema.c` generated) | 67 real PDUs round-trip byte-identical; nested PDU-session transfers; garbage fuzz | done (PrivateMessage not typed) |
| TS 29.500/501, 29.571 5.2.4 | SBI transport (HTTP/2 h2c), ProblemDetails | `libs/sbi` | unit + loopback e2e (11 tests); opt-in interop with Open5GS NRF discovery passing | transport done; TLS/mTLS, OAuth2, NF-specific models TODO |
| TS 29.503 (UEAU, SDM, UECM) | UDM services | `nf/udm` | 10 e2e + 7 service tests, AUTN/RES* bit-exact vs Open5GS+UERANSIM, interop (`OUR_UDM=1`) S1-S3 | done (gaps in update.md) |
| TS 29.504, 29.505 | Nudr_DataRepository (query, create, update, delete, subscribe, notify; ETag / preconditions / `fields`), Nudr_GroupIDmap | `nf/udr` (generated tables from the pinned OpenAPI) | `udr_api`, `udr_notify`, `udr_db`, `udr_config`, PostgreSQL variants, `fuzz_replay_udr`, `udr_differential`, oracle `OUR_UDR=1` | done (gaps UDR-GAP-01..07) |
| TS 29.509 | Nausf_UEAuthentication (5G AKA, EAP-AKA', removal, deregister, FN-RG), Nausf_SoRProtection, Nausf_UPUProtection | `nf/ausf` | `ausf_e2e`, RFC 9048 vectors, `amf_e2e`, `fuzz_replay_ausf`, `ausf_differential`, UERANSIM EAP-AKA' end to end | done (gaps AUSF-GAP-01..05) |
| RFC 4187, 5448, 9048; TS 33.501 Annex F | EAP-AKA' (framing, key schedule, AT_MAC) | `libs/crypto/src/eapaka.c` | all four vectors of RFC 9048 Annex D | done (pinned from the RFC texts) |
| TS 31.102 4.2.5, TS 24.008 10.5.1.13 | access technology and PLMN coding of the SoR list | `nf/ausf/src/prot.c` | byte strings in `test_sor` | done |
| TS 29.510 5.2.2 | NRF registration, heartbeat, deregistration (client side) | `libs/nfcore/src/nfcore.c` | mock NRF test; accepted by the Open5GS NRF in interop | done |
| TS 33.501 13 | TLS / mTLS on SBI | `libs/sbi/src/tls.c` | server auth, mTLS, rogue-CA rejection | done (OAuth2 token validation: hook only) |
| TS 29.502 5.2.2 (v16.17.0) | Nsmf_PDUSession: Create / Update / Release SM Context, status notify | `nf/smf/src/sm.c` | 2 unit + 1 end-to-end test file, S1-S3 with Open5GS's AMF (`OUR_SMF=1`) | done (UE-requested modification not supported) |
| TS 29.518 5.2.2.3.1 (v16.19.0) | Namf_Communication N1N2MessageTransfer (client side, the SMF) | `nf/smf/src/peers.c` | end-to-end test, Open5GS AMF accepts | done |
| TS 24.501 8.3.2, 9.11.4 (5GSM) | PDU session establishment accept / reject, release command, QoS rules, QoS flow descriptions, Session-AMBR, PDU address | `nf/smf/src/gsm.c` | byte-exact unit tests, UERANSIM accepts | done for establishment, release, network-requested modification |
| TS 24.008 10.5.6.3A | Extended protocol configuration options: DNS, MTU | `nf/smf/src/gsm.c` | unit + end-to-end | done |
| TS 38.413 9.3.4 | PDU session resource setup / release transfers (SMF side) | `nf/smf/src/n2sm.c` | unit + end-to-end, gNB accepts | done |
| TS 29.244 (SMF side) | PFCP client: association, heartbeat, restart detection, session establishment with PCC mapping, policy-update modification, deletion, report handling, CP-function PDRs for IPv6 router solicitation | `nf/smf/src/n4c.c`, `n4rules.c` | unit against the UPF engine, end-to-end, `pfcp_diff.py --smf` | done |
| TS 29.512 (SM policy), 23.503 | PCF SM policy control and decision model | `nf/pcf` | 6 unit + 10 component tests; S1-S4 interop with Open5GS AMF/SMF/UPF; PFCP modification observed after a pushed PCC rule | done (usage monitoring, UCU, N5 pending) |
| TS 29.507 | PCF AM policy control | `nf/pcf/src/ampolicy.c` | component tests; accepted by Open5GS AMF in S1-S4 | done (basic) |
| TS 38.413 8.7, 8.6, 8.3, 8.2, 8.5, 8.4 | N2 procedures (AMF side): NG Setup, RAN configuration update, NG reset, error indication, NAS transport, context setup, context release, PDU session resource setup / modify / release, paging, path switch, handover | `nf/amf/src/ngap.c`, `ho.c`, `sctp.c` | `amf_e2e` (scripted gNBs over SCTP), UERANSIM S1-S5, `amf_diff.py` | done (no RRC inactive, no PWS, no trace, no SON) |
| TS 24.501 5.4, 5.5, 5.6 | 5GMM: authentication, security mode control, identification, configuration update, registration, de-registration, service request, paging | `nf/amf/src/gmm.c`, `nasmsg.c` | `amf_units` (byte-exact), `amf_e2e` (independent UE), UERANSIM S1-S5 | done for 3GPP access (no emergency, MICO, NSSAA, SOR) |
| TS 33.501 6.1.3.2, 6.7, 6.8, 6.9.2.3, A.7-A.10 | 5G-AKA at the SEAF, NAS algorithm selection, KgNB, {NH, NCC} chain | `nf/amf/src/sec.c`, `gmm.c`, `ho.c` | UE side derives the same keys (e2e); UERANSIM accepts | done for NIA2 / NEA2 / NEA0 (SNOW 3G, ZUC: ADR-0012) |
| TS 29.518 5.2.2.3 (v16.19.0), 5.3 | Namf_Communication N1N2MessageTransfer (server), Namf_EventExposure | `nf/amf/src/session.c`, `events.c` | e2e, Open5GS SMF and ours | done (UEContextTransfer, N1MessageNotify not built) |
| TS 29.509 5.2, 29.503 5.3 / 5.2, 29.507 5.2 | AMF as client of AUSF, UDM (UECM, SDM), PCF (AM policy) | `nf/amf/src/sbi_out.c`, `callbacks.c` | S1-S5 with Open5GS and our NFs, e2e | done |
| TS 29.519 | Policy, exposure and application data of the UDR (all operations of the three API files), data change notifications | `nf/udr`, `nf/pcf/src/pcf.c` (operator-specific policy data) | as above; Open5GS's PCF reads `am-data` / `sm-data` from our UDR | done (PFD notifications need TS 29.551, not pinned) |
| TS 29.531 | Nnssf_NSSelection (registration, PDU session, UE configuration update, PDN connection), Nnssf_NSSAIAvailability (update, subscribe, notify, options) | `nf/nssf` | differential against Open5GS's NSSF (PDU session procedure; it implements nothing else), 73 of 73 payloads valid | done (H-NSSF query, redirection, pattern TAC ranges are gaps) |
| TS 29.522 | NEF northbound: TrafficInfluence (create, read, replace, patch, delete into the UDR) and the monitoring and QoS procedures it applies to the 5GS | `nf/nef` | oracle S6 / S7 end to end, 81 of 81 payloads valid | done (the other APIs of the file, traffic influence by UE address and for groups are gaps) |
| TS 29.122 | MonitoringEvent (loss of connectivity, reachability, location) and AsSessionWithQoS, with the common data and the notification rules | `nf/nef` | as above | done for those two APIs; the others of the file are not built |
| TS 29.514 | Npcf_PolicyAuthorization (N5): create, update, delete, events, notifications, termination, required QoS | `nf/pcf/src/policyauth.c`, `nf/nef/src/as.c` | oracle S7 against Open5GS's SMF and ours | done for service information with QoS references (derivation from media types needs TS 29.513, not pinned) |
| TS 29.500 6.10, 6.11; TS 23.501 6.2.19 | Indirect communication: Model C and D, reselection, late requests, errors an SCP makes and relays | `nf/scp`, `libs/sbi/src/client.c` | `scp_e2e`, `scp_differential` (Open5GS SCP), oracle S3 / S4 through our SCP | done (SCP-GAP-01..04) |
| TS 29.521 | Nbsf_Management: register, discover, update and deregister the binding of a PDU session to its PCF; SamePcf; feature negotiation | `nf/bsf`, `nf/pcf/src/bsfreg.c`, `nf/nef/src/nef.c` | `bsf_e2e`, `bsf_differential` (Open5GS BSF), oracle S8 | done (BSF-GAP-01..03) |
| TS 29.591 | Nnef services | - | pinned; nothing in this core produces the events of Nnef_EventExposure | not built (NEF-GAP-03) |

## Verification against the pinned specs (2026-10-05)
Checked after downloading the documents we had previously implemented from knowledge:
- TS 33.501 v16.20.0 Annex A: FC values 0x6A/6B/6C/6D/69/6E, HXRES* = 128 LSB of SHA-256(RAND||RES*), K_AMF input P0 = IMSI string: all match `libs/crypto`.
- TS 33.501 v16.20.0 5.2.2/5.2.3/5.3.2: NEA1/NIA1 (SNOW 3G) mandatory for UE and gNB, NEA3/NIA3 (ZUC) optional (ADR-0012).
- TS 29.503 v16.18.0: `POST /{supi}/auth-events` and `PUT /{supi}/auth-events/{authEventId}` exist as implemented; SDM is `nudm-sdm/v2`.
- TS 29.512 v16.23.0: `{notificationUri}/update` and `/terminate` as implemented; `pduSessionType` is mandatory in `SmPolicyContextData` (**we treated it as optional: fixed**).
- TS 29.507 v16.11.0: `PolicyUpdate` requires `resourceUri` (**we omitted it: fixed**); `triggers` has minItems 1 (matches our omission).
- 25 payloads our UDM, AUSF-lite, UDR-lite, PCF and NF profile registration actually emit validate against the official OpenAPI schemas (63 now, 19 of them the UDR's).
