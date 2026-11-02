# SNOW 3G (UEA2/UIA2 = 128-NEA1/NIA1) licensing: what has to happen

This is an engineering checklist, not legal advice. A director or senior executive must sign, so it cannot be done by
engineering or by tooling on the company's behalf.

## What we found (2026-10-05)
- 3GPP TS 35.216 (SNOW 3G specification) and TS 35.217 (test data) are cover pages only; the technical content is
  "contained in the SAGE Specification" (ETSI TC SAGE, UEA2 & UIA2 Document 2 and Document 3).
- ETSI is the custodian. Documents are released to a customer who **signs a Restricted Usage Undertaking and pays an
  administrative fee (if any)**. ETSI's page directs requests to the GSMA security-algorithms page:
  https://www.gsma.com/solutions-and-impact/technologies/security/security-algorithms/
  (ETSI overview: https://www.etsi.org/security-algorithms-and-codes/security-algorithms).
- The form (`ALGO_3GPP_UEA2_UIA2_undertaking_form.doc` on etsi.org) must be signed by "a director or senior executive".
  Points counsel should review before signing:
  * permitted use per beneficiary category (a manufacturer may use the algorithms "exclusively for the provision of
    3GPP Algorithms components, systems or services");
  * the obligation to design equipment so it cannot be used for anything other than to provide the algorithm services;
  * no registration of IPR relating to the algorithm; indemnity of the custodian against third-party claims;
  * the form's silence on source-code escrow, open-source distribution and term: ask ETSI/GSMA to clarify in writing,
    particularly because our product is proprietary and we intend to ship binaries to operators.
- Separately, SEP/patent exposure for the algorithm is not removed by the undertaking (see the strategy PDF, section 2).

## Steps
1. Counsel reviews the undertaking and the points above; decide the beneficiary category (manufacturer).
2. A director signs; submit via GSMA/ETSI; pay the fee if requested.
3. Put the received documents in `docs/specs/restricted/` (git-ignored) and tell engineering.
4. Engineering implements `libs/crypto/src/snow3g.c` from those documents only, wires NEA1/NIA1 into
   `libs/nas::security`, and passes all provided test sets (ADR-0012). No third-party or leaked copies are used.
5. Only then the AMF may advertise and select NEA1/NIA1.

## What is already prepared
`IntAlg::from_id(1)` and `EncAlg::from_id(1)` return an explicit "not supported" error; all other NAS security paths are
tested; the Phase 5 plan has this as a hard gate.
