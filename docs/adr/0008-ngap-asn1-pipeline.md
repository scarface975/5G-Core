# ADR-0008: NGAP codec pipeline - spec ASN.1, generated schema tables, generic APER interpreter

Status: Accepted (2026-09-30); revised 2026-10-07 for the C implementation (ADR-0013). The Rust pipeline (rasn-compiler,
typed IE enums, a vendored rasn with two APER fixes) is replaced by the design below.

## Decision
1. Source of truth: the normative ASN.1 of TS 38.413 v16.18.0, extracted from the 3GPP .docx by
   `tools/extract_asn1.py` into `docs/specs/asn1/` (six modules).
2. `tools/gen_ngap_c.py` parses those modules (the ASN.1 subset NGAP uses: INTEGER/ENUMERATED/BIT STRING/OCTET STRING
   including CONTAINING, character strings, SEQUENCE with extension additions, SEQUENCE OF, CHOICE, and the parameterised
   protocol containers resolved against the `NGAP-PROTOCOL-IES` / `-EXTENSION` / `-PRIVATE-IES` object sets and the
   `NGAP-ELEMENTARY-PROCEDURE` objects) and emits `libs/ngap/src/schema.c` (about 1,900 type nodes, 426 IE sets, 66
   procedures) and `libs/ngap/include/g5c/ngap_ids.h` (procedure codes and IE ids). Generated files are committed.
3. `libs/ngap/src/aper.c` is a generic X.691 aligned-PER codec that interprets the schema. PDUs are exchanged as JSON
   trees (representation documented in `ngap.h`): OPTIONAL fields are absent keys, unknown protocol IEs and unknown
   extension additions are preserved as hex and re-encoded verbatim, `OCTET STRING (CONTAINING T)` values are decoded
   on demand with `ngap_decode_as("T", ...)`.
4. Limits are enforced in the codec: depth 48, 200,000 decoded values, no length fragmentation (values of 16 KiB or more in
   one length-prefixed field are rejected), IE-pair containers unsupported (no NGAP message uses them).

## Validation
All 138 real NGAP PDUs of the golden traces (Open5GS + UERANSIM S1-S3, and the ORAN emulator vs Open5GS) decode and
re-encode byte-identically (APER is canonical) - 14 message types, plus 21 nested PDU-session transfer containers. Every
truncation and 300 random bit flips of each real PDU, plus pure noise, decode or fail cleanly under ASan/UBSan
(`test_ngap`, `fuzz/fuzz_ngap.c`).

## Consequences
All 3GPP NGAP messages are available from day one with no per-message code; correctness is anchored on independent
implementations. A later Release needs only a regenerated schema. Cost: tree-based access is slower than typed structs,
which is acceptable for the control plane (the UPF does not use NGAP); typed accessors for hot procedures can be added
on top of the same tree.
