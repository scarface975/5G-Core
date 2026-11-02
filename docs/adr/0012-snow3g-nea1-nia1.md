# ADR-0012: SNOW 3G (128-NEA1 / 128-NIA1) is the required algorithm; ZUC is deferred

Status: Accepted (2026-10-05); implementation blocked on a licence (see `docs/legal/SNOW3G-licensing.md`)

## Context
TS 33.501 v16.20.0 makes SNOW 3G based algorithms mandatory: clauses 5.2.2 and 5.2.3 say the UE "shall implement NEA0,
128-NEA1, 128-NEA2" and "NIA0, 128-NIA1, 128-NIA2", and clause 5.3.2 requires the same of the gNB. ZUC based 128-NEA3 /
128-NIA3 are "may implement" in every case. Interoperability testing (UERANSIM and commercial UEs negotiate from this
list) therefore needs NEA1/NIA1 in a production AMF, whereas ZUC matters mainly for the Chinese market.

## Decision
1. Implement **128-NEA1 / 128-NIA1 (SNOW 3G)** as part of Phase 5 (AMF). Defer **NEA3 / NIA3 (ZUC)** until a customer needs it.
2. The algorithm specifications (UEA2/UIA2, TS 35.215/35.216 with test data in TS 35.217/35.218) are licensed ETSI/SAGE
   documents released only against a signed Restricted Usage Undertaking. We implement **only from the licensed documents**
   and verify only against their test data. We do not copy open-source implementations or unofficial copies of the
   specification, so the product's provenance stays clean (ADR-0002).
3. The licensed documents are kept out of the repository (`docs/specs/restricted/` is git-ignored).
4. Until they are available, `libs/crypto` and `libs/nas` expose NEA2/NIA2 and NEA0/NIA0 only and reject NEA1/NIA1 with an
   explicit "not supported" error (already the case in `security::{IntAlg, EncAlg}::from_id`); the AMF must not advertise or
   select SNOW 3G until the implementation and its vectors pass.

## Consequences
Registration against peers that insist on SNOW 3G cannot be claimed as production-ready before the licence arrives.
Phases 1-4 are not affected; Phase 5 has a hard gate on this item.
