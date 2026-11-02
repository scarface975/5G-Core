# ADR-0019: AUSF design (Phase 7, second function; replaces the ausf-lite shim)

Status: Accepted (2026-10-21)

## Decision
- **One process, three services** on the AUSF's SBI port, from TS 29.509 Release 16 as pinned: Nausf_UEAuthentication (`/nausf-auth/v1`: POST
  `ue-authentications`, PUT / DELETE `.../5g-aka-confirmation`, POST / DELETE `.../eap-session`, POST `ue-authentications/deregister`, POST `rg-authentications`),
  Nausf_SoRProtection (`/nausf-sorprotection/v1/{supi}/ue-sor/generate-sor-data`) and Nausf_UPUProtection (`/nausf-upuprotection/v1/{supi}/ue-upu/generate-upu-data`).
  It registers all three with the NRF (with `ausfInfo` when configured) and finds the UDM through the NRF, or at the address given by `udm.uri`.
- **5G AKA** as the shim did it, tightened to the clauses: the serving network name must be well formed (`5G:mnc<3>.mcc<3>.3gppnetwork.org`) and, when a list is
  configured, listed (403 SERVING_NETWORK_NOT_AUTHORIZED); identifiers are validated before they can reach the UDM's URI; one pending context per UE and serving network;
  a null RES* is a failure; the confirmation resource does not persist after it was read; the errors of the UDM are mapped to the causes of the AUSF's table (404
  USER_NOT_FOUND, the four 403 causes, 501, 500 AV_GENERATION_PROBLEM, 504 UPSTREAM_SERVER_ERROR / NETWORK_FAILURE).
- **EAP-AKA'** as the EAP server of RFC 4187 / 5448 / 9048 with the 5G profile of TS 33.501 Annex F. The UDM returns an AV' (RAND, AUTN with the AMF separation bit, XRES,
  CK', IK') for a subscriber whose method is EAP_AKA_PRIME; the AUSF derives MK = PRF'(IK'|CK', "EAP-AKA'"|IMSI) (the identity is the IMSI digits, no prefix, Annex F.3),
  sends the EAP-Request/AKA'-Challenge (AT_KDF 1, AT_KDF_INPUT = the serving network name, optional AT_RESULT_IND, AT_MAC) base64-encoded in `5gAuthData`, and
  verifies the response (AT_MAC before anything else, then RES). Failures follow RFC 4187 Figure 2: a notification (code 16384, no AT_MAC), then EAP-Failure once it is
  acknowledged; AKA'-Authentication-Reject and Client-Error end the session at once; a synchronisation failure is answered with a new challenge from the UDM (at most
  twice); a protected success indication (code 32768 with AT_MAC) is used when both sides ask for one. The result is EAP-Success with KSEAF = KDF(first 256 bits of the
  EMSK as KAUSF). Fast re-authentication, pseudonyms and identity requests are not used in 5GS (Annex F.2, F.3 NOTE 1) and not implemented.
  The CK'/IK' function (TS 33.501 Annex A.3 = TS 33.402 A.2) is `g5c_ck_ik_prime`, validated by the four test vectors of RFC 9048 Annex D together with PRF', the key
  schedule and the AT_MAC framing (`libs/crypto/eapaka`). The RFCs were downloaded and pinned (SHA-256 in `docs/specs/pinned.json`) so that attribute layouts and
  constants are read from text.
- **The security context** (the latest KAUSF per SUPI, with CounterSoR and CounterUPU) is stored on every successful authentication of either method (TS 33.501 6.1.1.2,
  6.14.1, 6.15.1), replacing the previous one and resetting both counters to 1. It is cleared by Deregister. With a state file it survives a restart: the file holds KAUSF
  wrapped with AES-256-GCM under a master key (`G5C_AUSF_MASTER_KEY` or `ausf.master_key_file`), the SUPI as associated data, written behind the requests by one thread
  with a delay that grows with the cost of a write, through a temporary file and a rename. The counters in the file are ahead of the live ones by 256, because a counter value
  must never be used twice for one KAUSF and the last increments before a crash may not have been written. A state file without a master key is a configuration error.
- **SoR and UPU protection** compute the MACs of TS 33.501 A.17 to A.20 with the generic KDF: SoR-MAC-IAUSF = the 128 least significant bits of KDF(KAUSF, 0x77, SoR header,
  CounterSoR, list); the SoR header, the PLMN ID and access technology list (PLMN as TS 24.008 10.5.1.13, access technology as TS 31.102 4.2.5) and the UE parameters
  update list (TS 24.501 9.11.3.53A) are encoded from the JSON of the consumer. The counter in use is the current one, incremented afterwards; the service for a UE is
  suspended (503 COUNTER_WRAP) when it reaches 0xFFFF, until the next authentication gives a fresh KAUSF. TS 31.102 (16.17.0) was downloaded and pinned for the access
  technology bits; the table is read from the cell borders of the document, since the text conversion loses the bit positions.
- **Authentication results at the UDM**: the result of every run is POSTed to the UDM's `auth-events` (the id from the `Location` header is kept); the removal (the AMF's DELETE
  on the confirmation or eap-session resource) is `PUT auth-events/{authEventId}` with `authRemovalInd` and `success: false` as TS 29.503 6.3.6.2.6 says, and `success: true`
  once more when the UDM answers 400 (Open5GS's UDM insists on it next to `authRemovalInd`; its own AUSF sends that). Only the current result of a UE is removed.
  The AMF now deletes the result when the UE is de-registered, implicitly de-registered, or refuses the security mode command (TS 29.509 5.2.2.2.5, 5.2.2.2.6).
- **State is O(1) per request**: authentication contexts live in hash tables by id and by (UE, serving network), expiry is by list order (the lifetime is constant), the
  security contexts in a table by SUPI; one mutex guards the tables and is held only for table operations. A context is taken out of the tables for the length of a
  request and put back when the exchange goes on, so two requests never work on one context. The tables are bounded (`max_contexts`, `max_ue_contexts`); a start beyond the
  bound is answered 503 and finished records are the first to give way.
- **AMF**: EAP-AKA' is carried in the EAP message IE of the Authentication request, response and reject, and the EAP-Success and the ABBA in the Security mode command
  (TS 24.501 5.4.1.2.1, 5.4.1.2.2), reusing the AMF's T3560 retransmission and security mode procedures.
- **UDM**: `auth_method` in the admin API (5G_AKA or EAP_AKA_PRIME), the AV' generation, EAP-TLS and anything else answered 403 AUTHENTICATION_REJECTED (the user cannot be
  authenticated with that method), and the FN-RG answer (`GET .../security-information-rg`).

## Tolerated deviations (written down, not hidden)
- A challenge response with an `AT_KDF` that repeats the value in use (1) is accepted: RFC 5448 does not allow a peer to send it, UERANSIM does; the attribute is covered by
  AT_MAC and asks for nothing. A different value is a request for another function and fails.
- `servingNetworkName`, `supi` are returned in responses where the specification makes them conditional (always present: the AMF needs the SUPI, a SUPI the AMF already has costs
  nothing).

## Why not
- A database for the security contexts: one record per authenticated UE, rewritten as a whole behind the requests, is cheaper than one more service to operate; the file is bound
  to a key.
- Deriving the EAP identifier from a counter: RFC 3748 4.1 lets it start anywhere; it is random, and `ausf_opts.eap_first_id` fixes it for tests and fuzzing.

## Verification
`nf/ausf/tests/test_ausf.c` and `test_more.inc` (5G AKA, EAP-AKA' with an independent peer written from the RFCs, results removal, deregister, SoR and UPU with hand-computed
byte strings, the state file, configuration, limits, FN-RG, faults of the UDM, concurrency), `crypto_eapaka` (RFC 9048 vectors), `amf_e2e` (EAP-AKA' registration through the
AMF), `fuzz_replay_ausf`, `ausf_differential` (Open5GS's AUSF as the reference), the oracle scenarios with `OUR_AUSF=1` and with every function ours, and with
`AUTH_METHOD=EAP_AKA_PRIME` against UERANSIM's own EAP-AKA' peer (`deploy/oracle/build_ueransim_eap.sh` builds a copy of `nr-ue` that decodes AT_KDF of Length 1: UERANSIM
3.3.0 rejects every EAP attribute shorter than two words, which makes it unable to read a conforming challenge; the rest of its EAP-AKA' is untouched).
Matrix: `docs/conformance/phase7-matrix.json` (AUSF-* rows).
