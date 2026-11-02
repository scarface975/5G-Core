# ADR-0017: Release 17 track - opened by the owner on 2026-10-14

Status: Accepted (2026-10-14). Amends ADR-0003 ("Release 17 and 18 are scheduled feature by feature, after v1").

## Decision
- The Release 17 track is **opened**. It starts after Phase 7 has produced the eleven network functions, because Release 17 changes the interfaces
  of those functions and every change has to land in the function that owns it. Until then the baseline stays Release 15 mandatory / Release 16 ceiling
  (ADR-0003) and nothing in Phases 6 and 7 is held back for it.
- Release 17 behaviour is **additive and negotiated**: a UE, gNB or peer function at Release 15 or 16 sees exactly what it sees today. Every Release 17
  feature has a configuration switch (`release: 17` capability list per NF), so that a deployment can run the Release 16 profile unchanged and the
  Release 16 conformance matrix keeps passing in both profiles.
- The owner's requirement that the eleven functions be "in step with the industry and market standards" is made testable as the **gate below**; a
  feature is not called supported until it passes it.

## Gate for every Release 17 feature
1. **Spec text pinned first.** The Release 17 version of each specification the feature touches is added to `docs/specs/PINNED.md` / `pinned.json`
   (official 3GPP archive, SHA-256), and the ASN.1 and OpenAPI inputs of the generators (`tools/extract_asn1.py`, `tools/extract_openapi.py`,
   `tools/gen_nas_defs.py`) are regenerated from it. Bit layouts are read from that text, never from memory (the lesson of the UP Function Features bug).
2. **Delta analysis** per network function: the clauses that changed between the pinned Release 16 text and the Release 17 text, recorded in
   `docs/conformance/release17-delta.md`, each row either "implemented", "not applicable to a core function", or "out of scope" with the reason.
3. **Matrix row** per behaviour (`docs/conformance/`), checked by `tools/check_matrix.py`: clause, test, status. `verified` needs an independent peer
   that implements the feature; with none, the row stays `tested` and says so (ADR-0003 criterion b is kept, not waived).
4. **Negotiation and fallback tests**: the same registration / session flow with a Release 16 peer must be byte-for-byte what the Release 16 profile
   produces; a Release 17 IE must be ignored or rejected as the Release 16 specification says when the capability is off.
5. **Differential analysis** against an open implementation that has the feature, where one exists (the method of `tools/amf_diff.py`,
   `tools/pfcp_diff.py`).

## Candidate increments (to be confirmed or discarded by the delta analysis; no behaviour is implemented from this list alone)
| Area | Network functions affected | Note |
|---|---|---|
| RedCap UEs: indication in NGAP and NAS, admission and paging handling | AMF | needs a RedCap-capable gNB / UE simulator to verify |
| Network slice admission control and enhanced slicing (slice groups, slice-based mobility information, NSSAA interworking) | AMF, NSSF, UDM, PCF | slice admission control is specified as a separate function; the eleven functions carry the hooks and the AMF / NSSF side |
| Multi-USIM: release / paging indications | AMF | NAS and NGAP additions |
| Non-terrestrial access: RAT types, location and tracking-area handling, long delays in timers | AMF, SMF, PCF, UDM | needs NTN-aware peers |
| Paging and DRX enhancements, extended DRX | AMF | |
| Edge computing support: EAS / ECS configuration, session continuity hints | SMF, PCF, UDM, NEF | |
| SBI evolution: new API versions, OAuth2 scope refinements, indirect communication through the SCP | all, NRF, SCP | the SCP is built in Phase 7 with this in view |
| User plane additions of Release 17 (additional PFCP IEs and features negotiated through UP Function Features) | SMF, UPF | feature bits are read from the pinned TS 29.244 text |
| Standalone non-public networks and 5G-LAN style groups | AMF, SMF, UDM, PCF, UPF | Release 16 groundwork exists in the pinned text; scope decided in the delta analysis |

Out of scope regardless of release stays as in ADR-0003 (NSA / EPC interworking, roaming, non-3GPP access) unless the owner changes it by a
further decision.

## Why this order
- The Release 17 changes sit on interfaces that are still being finished: the NRF, NSSF, NEF and SCP do not exist yet, and several candidate
  features (slice admission, edge discovery, indirect communication) live in them. Adding the track before them would mean changing each interface twice.
- The pinning step has to happen anyway and is independent of the rest of the work, so it can start whenever the owner wishes without disturbing
  Phase 7.
