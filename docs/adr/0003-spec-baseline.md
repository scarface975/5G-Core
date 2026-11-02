# ADR-0003: Specification baseline - 3GPP Release 15 mandatory, Release 16 ceiling for v1, per-feature Release 17+ policy

Status: Accepted (2026-09-30); amended 2026-10-05 (release policy made explicit)

## Decision
- **Baseline:** SA, non-roaming, 3GPP Release 16 documents (exact versions in `docs/specs/PINNED.md`). Every procedure we
  implement today is a Release 15 procedure specified in the Release 16 text.
- **Ceiling for v1 (GA):** Release 16. Release 16 features are added only when needed for SA service; they must be
  negotiated or optional so peers at Release 15 (Valid8, UERANSIM) keep working.
- **Release 17 and 18 are not excluded; they are scheduled feature by feature, after v1.** A Release 17+ feature enters the
  backlog when (a) a customer or regulator needs it, (b) an independent peer exists to verify it (a tester, a UE/gNB
  simulator or a reference core that implements it), and (c) its specification is stable (Stage 3 frozen, ASN.1 and OpenAPI
  available). Anything failing (b) cannot be verified the way we verify everything else, so it is not shipped.
- Out of scope regardless of release: NSA/EPC interworking, roaming (SEPP, home-routed), non-3GPP access.

## Why not simply adopt Release 17/18 now (evidence, 2026-10-05)
- Most of Release 17's weight is in the radio side (RedCap, NTN); the 5G core impact is comparatively small and can be
  added incrementally.
- Test peers: UERANSIM states Release 15, Valid8 Release 15, Accuver Release 16; Spirent Landslide ("up to Release 17"),
  Viavi TM500 (roadmap 16-18) and Amarisoft (compact Release 18 core with AMF, AUSF, SMF, UPF, UDM; Release 19 software
  gNB; entry models Release 15/16) go beyond. A test tool's ceiling is not a statement that a core must follow, but the
  Amarisoft evidence (a commercial integrated core claiming Release 18) is the strongest argument for the post-v1 Release 17 track.
- Production core vendors position themselves the same way (for example Huawei: Release 15 fully, Release 16 mostly,
  Release 17 in progress).
- Backward compatibility: Release 17+ features are additive and negotiated, so deferring them causes no rework.

## Candidate Release 17 increments for the post-v1 backlog
Network slice admission control and enhanced slicing; RedCap handling in NGAP/NAS; NTN-related RAT types and location
handling; NWDAF phase 2; multi-USIM. Each needs its own ADR when started.
