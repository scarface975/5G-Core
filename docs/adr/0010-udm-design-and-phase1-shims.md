# ADR-0010: UDM design and the Phase 1 shims

Status: Accepted (2026-10-01)

## Context
Phase 1 builds the UDM. It needs a data store (UDR) and, for a real registration, an AUSF. The real UDR and AUSF
are Phase 7 (ADR-0006), so Phase 1 ships deliberately small stand-ins that speak the real service interfaces.

## Decisions
1. **Interfaces, not internals.** UDM talks to the UDR only through Nudr_DataRepository (`/nudr-dr/v1`), and the
   AUSF talks to UDM only through Nudm_UEAuthentication. `shims/udr-lite` (memory + JSON file) and
   `shims/ausf-lite` (5G-AKA only) are replaced in Phase 7 without touching UDM.
2. **UDM is the only holder of plaintext credentials.** K and OPc are stored in the UDR as `encPermanentKey` /
   `encOpcKey` protected by AES-256-GCM (`protectionParameterId = aes-256-gcm-v1`) with the SUPI as associated
   data, under a master key supplied via environment or file, never YAML. `none` (plaintext) exists for development
   and logs a warning. A KMS/HSM implementation replaces `KeyProtector` in Phase 8.
3. **SQN is advanced and persisted before a vector is returned**, in steps of 32 (SEQ+1, IND unchanged), so a crash can
   never re-issue an SQN. Reads-modify-writes for one SUPI are serialised by a per-SUPI lock; this protects a single
   UDM instance only. Multi-instance deployments need a compare-and-swap in the UDR (Phase 8).
4. **Resynchronisation** follows TS 33.102 6.3.5 (AK*, MAC-S with AMF* = 0000); a forged AUTS is rejected without
   moving the SQN.
5. **Provisioning** is an admin API on the UDM (`/admin/v1`), disabled unless an admin token (>= 16 characters) is
   configured, which converts OP to OPc, validates input, protects credentials and writes AM, SM and SMF-selection
   data. It never returns K or OPc.
6. **Absolute `Location` headers.** TS 29.500 requires absolute URIs; the SBI server records scheme and authority per
   request (`Req::url`). Found by interop with Open5GS's AUSF.
7. **Compatibility with the reference implementation is validated, not assumed:** AUTN and RES* are reproduced from
   Open5GS/UERANSIM traces, and Open5GS's AMF/AUSF/SMF/PCF run against our UDM in the oracle harness
   (`OUR_UDM=1 deploy/oracle/scenario.sh s3`).

## Consequences
UDM can be tested end to end today, and later phases swap shims for real NFs behind unchanged APIs. Known gaps are
listed in `docs/history/update.md` (SDM change notifications, EAP-AKA', OAuth2 token validation, NRF discovery of the UDR).
