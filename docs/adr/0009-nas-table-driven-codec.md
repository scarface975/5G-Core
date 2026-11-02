# ADR-0009: NAS codec - table-driven from TS 24.501, typed IEs added per need

Status: Accepted (2026-09-30)

## Decision
`tools/extract_nas_tables.py` pulls the message-content tables of TS 24.501 v16.15.0 (clause 8) into
`docs/specs/nas/messages.json`; `tools/gen_nas_defs.py` turns them into static `nas_msgdef`/`nas_iedef` tables
(`libs/nas/src/defs.c`: IEIs, formats V/LV/LV-E/T/TV/TLV/TLV-E, presence, order) for all 32 5GMM and 16 5GSM
messages. One generic encoder/decoder handles every message, including half-octet packing; unknown optional IEs are
preserved. Typed views (`nasie.c`) and the security envelope (`security.c`: SHT 1-4, NIA2/NEA2, NIA0/NEA0) are
hand-written and grow with the procedures implemented (Phases 4-5).

## Validation
NAS messages from the golden traces re-encode byte-identically; every real integrity MAC in the S1 trace verifies with
keys derived by `libs/crypto` (Milenage -> K_AUSF -> K_SEAF -> K_AMF -> K_NASint), which also fixed the K_AMF SUPI input
as the digits-only IMSI.

## Consequences
Full message coverage without hand-typing 48 layouts. Per-IE semantics (clause 9.11) still need typed helpers;
SNOW 3G / ZUC based NIA1/NIA3/NEA1/NEA3 are not implemented.
