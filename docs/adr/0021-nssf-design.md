# ADR-0021: NSSF design (Phase 7, fourth function)

Status: Accepted (2026-10-23)

## Decision
- **Pinned source.** TS 29.531 v16.11.0 (`docs/specs/src/29531-gb0.zip`, Release 16 is the ceiling, ADR-0017). Its two OpenAPI files are read by `tools/gen_nssf_api.py`, which writes
  `nf/nssf/src/api_schemas.gen.c` and `api_ids.gen.h` (43 schemas); both are committed and `python3 tools/gen_nssf_api.py --check` fails when they are stale. Bodies are
  validated by the shared schema validator (`libs/oaschema`, moved out of the UDR where it was born; `tools/oa_pool.py` is the shared flattening code of the generators). The one
  defect of the published file that matters, the `{2-3}` repetition in the AMF Set pattern of NSSelection, is patched in `tools/validate_openapi.py` only (the spec is not edited).
- **Services.** `nnssf-nsselection` v2 (GET `/network-slice-information` for the registration, PDU session, UE configuration update and PDN connection procedures; the
  query parameters are JSON-encoded as the specification says) and `nnssf-nssaiavailability` v1 (PUT/PATCH/DELETE of `/nssai-availability/{nfId}`, `/subscriptions`
  POST, `/subscriptions/{id}` PATCH/DELETE, OPTIONS). Supported features: ONSSAI, SUMOD, EANAN (availability), RSIPCE (selection); the answer carries the intersection.
- **Policy is configuration, not a database.** TS 23.501 5.15.5 leaves the slice-selection policy to the operator. The NSSF holds: the slices of the PLMN (S-NSSAI, the NRF of the
  slice, optional nsiId and NRF management / token URIs, tracking areas or TAC ranges where it is available, home PLMNs it is restricted for), the AMF sets (identifier, NRF, member
  AMFs, S-NSSAIs, whether candidate AMFs are returned), the roaming mappings (home PLMN, home S-NSSAI <-> serving S-NSSAI) and limits (allowed NSSAI at most 8, configured at most
  16). Everything is validated at start and a wrong value refuses to start naming the key. Run-time data (the NSSAI each AMF supports per tracking area, the subscriptions) is
  kept in memory with a write-behind state file (atomic replace, a damaged file is refused), not in the UDR: it is soft state that the AMFs re-send.
- **Allowed NSSAI** (registration, UE configuration update). Requested S-NSSAIs that are subscribed (or mapped from the home PLMN) are permitted; when none is requested the default
  subscribed S-NSSAIs are; optionally all subscribed ones (`include_subscribed`). The result is filtered by the configured slices and by the tracking area; slices that are
  not valid in the PLMN go to `rejectedNssaiInPlmn`, those not available in the TA to `rejectedNssaiInTa` (an S-NSSAI that ends up allowed is removed from both). A configured NSSAI
  is returned when nothing valid was requested or the AMF asked for it. The target AMF set is the requesting AMF's own set when its supported NSSAI covers the allowed NSSAI, else the
  configured set (or the one computed from the NSSAI availability the AMFs reported) that does; candidate AMFs are listed when the set says so.
- **The NRF is named by its NFDiscovery URI.** TS 29.531 says `nrfId` and `nrfAmfSet` are the API URI of the NRF's NFDiscovery service. The configuration gives the API root and the
  NSSF appends `/nnrf-disc/v1/nf-instances` (Open5GS's NSSF does the same; found by the differential, which first showed the bare root).
- **Availability.** An AMF's PUT lists the S-NSSAIs it supports per tracking area; the NSSF answers with the part that is authorized (a slice that is not configured or is restricted
  for the PLMN is 403 / left out) and records it. A change to the union per tracking area notifies the subscribers (NssfEventNotification) from a worker thread with a bounded queue and
  retries; subscriptions expire (never more than `max_lifetime_s`) and are bounded in number.
- **Interop facts that shaped it.** Open5GS's NSSF implements the PDU session procedure only (the others answer 400) and Open5GS's AMF calls it only on the home-routed roaming path;
  the registration-time slice decision of Open5GS's AMF is local. So the oracle scenario with our NSSF proves registration and discovery, and the answers are proven by
  `nssf_differential` (`tools/nssf_diff.py`, `deploy/oracle/nssf_diff.sh`: both NSSFs side by side in a private namespace behind Open5GS's NRF, nine requests compared plus three
  that exist only in ours).

## Gaps (matrix rows NSSF-GAP-*)
No query of the H-NSSF for the home-routed case (mappings are configured); no HTTP redirection; pattern-based TAC ranges are not supported (exact ranges are); no producer-side
OAuth2 yet (NRF-GAP-04 covers all functions); our AMF does not yet consume the NSSF (it decides slices locally, `gmm.c select_slices`).

## Consequences
The NSSF is small, deterministic and testable (unit and end-to-end tests, replay fuzz, payload validation, differential). Operators change policy by editing the file and restarting;
a policy database or a management API is a later decision, not forced by anything in TS 29.531.
