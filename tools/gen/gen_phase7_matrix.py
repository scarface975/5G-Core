#!/usr/bin/env python3
"""Writes docs/conformance/phase7-matrix.json (Phase 7: NRF and the discovery client of the other functions). The matrix is data;
tools/check/check_matrix.py validates every reference in it. Rows of the functions that follow in Phase 7 are added here as they are built.

    python3 tools/gen/gen_phase7_matrix.py"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
N = ("nrf_e2e", "nf/nrf/tests/test_nrf.c")
D = ("nrf_differential", "tools/diff/nrf_diff.py", "main")
F = ("fuzz_replay_nrf", "fuzz/fuzz_nrf.c", "LLVMFuzzerTestOneInput")
B = ("bad_configs_rejected", "tests/conformance/check_bad_configs.sh", "-")
CL = ("cluster_load", "deploy/run/g5c-cluster.sh", "-")
CC = ("cluster_chaos", "deploy/run/g5c-cluster.sh", "-")
U = ("udr_patch_store_routes", "nf/udr/tests/test_udr.c", "test_journal_recovery")
A = ("ausf_e2e", "nf/ausf/tests/test_ausf.c")
AM = ("ausf_e2e", "nf/ausf/tests/test_more.inc")
AD = ("ausf_differential", "tools/diff/ausf_diff.py", "main")
AF = ("fuzz_replay_ausf", "fuzz/fuzz_ausf.c", "LLVMFuzzerTestOneInput")
AMF_E = ("amf_e2e", "nf/amf/tests/test_amf_e2e.c")
EAPC = ("crypto_eapaka", "libs/crypto/tests/test_eapaka.c")
UDM_E = ("udm_unit_and_services", "nf/udm/tests/test_udm.c")

rows = []


def row(rid, nf, proc, spec, clause, status, tests, evidence, also=None):
    r = {"id": rid, "phase": 7, "nf": nf, "procedure": proc, "spec": spec, "clause": clause}
    if also:
        r["also"] = also
    r["status"] = status
    r["tests"] = [{"ctest": c, "file": f, "fn": fn} for (c, f, fn) in tests]
    r["evidence"] = evidence
    rows.append(r)


# ---- Nnrf_NFManagement ----------------------------------------------------------------------------------------------------------------
row("NRF-NFM-01", "NRF", "NFRegister: PUT of the NFProfile; 201 with Location, ETag and the heart-beat timer; refusals (400) for a malformed profile, an id that differs "
    "from the URI, a missing nfType, a bad nfStatus, bad lists; custom NF types and vendor attributes are stored; the registry fills priority / capacity / load / plmnList "
    "when absent", "TS 29.510", "5.2.2.2.2", "verified", [N + ("test_registration",), D],
    "Open5GS's AUSF, UDR, UDM, BSF, PCF, NSSF, SMF and AMF register at our NRF in oracle scenario S3 (OUR_NRF=1) and complete the registration, session and "
    "release; the differential against Open5GS's NRF gives the same status codes.")
row("NRF-NFM-02", "NRF", "NFUpdate by replacement (PUT on an existing instance: 200) and by JSON Patch (PATCH: 200 with the profile; 404, 409 for a non-existing "
    "attribute, 412 for a stale If-Match, 400 for an immutable attribute, a bad status or a malformed patch)", "TS 29.510", "5.2.2.3.1", "tested",
    [N + ("test_update",)], "End-to-end with the HTTP/2 client; the patch engine is the shared RFC 6902 implementation.")
row("NRF-NFM-03", "NRF", "NF heart-beat: PATCH replace /nfStatus (and /load): 204 and no new entity tag when nothing changed; a function back from SUSPENDED "
    "gets 200 with its profile; UNDISCOVERABLE accepted", "TS 29.510", "5.2.2.3.2", "verified", [N + ("test_update",), N + ("test_monitor",)],
    "Open5GS's functions and ours heart-beat at our NRF for the length of the oracle scenarios.")
row("NRF-NFM-04", "NRF", "heart-beat supervision: a function that misses suspend_after heart-beats becomes SUSPENDED (not discoverable, subscribers notified); "
    "after purge_after seconds the profile is removed and NF_DEREGISTERED is sent", "TS 29.510", "5.2.2.3.2", "tested", [N + ("test_monitor",)],
    "Timers shortened in the test (1 s heart-beat, 2 missed, 3 s purge).")
row("NRF-NFM-05", "NRF", "NFDeregister: DELETE; 204, 404 when unknown; subscribers get NF_DEREGISTERED", "TS 29.510", "5.2.2.4.1", "verified",
    [N + ("test_registration",), N + ("test_subscriptions",)], "Every oracle scenario ends with the functions deregistering from our NRF.")
row("NRF-NFM-06", "NRF", "NFListRetrieval (nf-type, limit; UriList with _links.item) and NFProfileRetrieval (200, 404; the services as the nfServices array, or "
    "the nfServiceList map for a consumer that indicates the Service-Map feature)", "TS 29.510", "5.2.2.9.1", "tested", [N + ("test_registration",), D],
    "Differential: the reference answers a retrieval with the map unasked, ours follows NOTE 15 (array unless Service-Map is indicated).", also=["5.2.2.8.1"])
row("NRF-NFM-07", "NRF", "NFStatusSubscribe / Update / Unsubscribe: nfStatusNotificationUri, subscrCond (nfInstanceId, nfType, serviceName, amfSetId / amfRegionId, "
    "snssaiList, nfGroupId), reqNotifEvents, notifCondition (monitored / unmonitored attributes), validityTime; 201 with Location and subscriptionId; validity "
    "extension by PATCH; 404, 400 for unsupported conditions", "TS 29.510", "5.2.2.5.2", "verified", [N + ("test_subscriptions",), D],
    "Open5GS's functions subscribe at our NRF and receive the status notifications in the oracle scenarios.", also=["5.2.2.5.6", "5.2.2.7.2"])
row("NRF-NFM-08", "NRF", "NFStatusNotify: POST NotificationData (NF_REGISTERED, NF_PROFILE_CHANGED, NF_DEREGISTERED) with nfInstanceUri and the profile in the "
    "subscriber's representation of the services; a load report alone is not a change; three attempts", "TS 29.510", "5.2.2.6.2", "tested",
    [N + ("test_subscriptions",)], "A callback server in the test receives and decodes each notification.")
row("NRF-NFM-09", "NRF", "OPTIONS on nf-instances answers with the capabilities", "TS 29.510", "5.2.2.2.2", "tested", [N + ("test_registration",)], "")

# ---- Nnrf_NFDiscovery ----------------------------------------------------------------------------------------------------------------------
row("NRF-DISC-01", "NRF", "NFDiscover: target-nf-type and requester-nf-type mandatory; only REGISTERED instances; service-names (comma separated list, or repeated) "
    "with the services of the answer reduced to the intersection; snssais and target-plmn-list as JSON arrays; dnn, tai, guami, amf-set-id, amf-region-id, supi "
    "(ranges and patterns), target-nf-instance-id; allowedNfTypes of the profile and of its services; limit; unknown parameters ignored; complexQuery refused",
    "TS 29.510", "5.3.2.2.2", "verified", [N + ("test_discovery",), D, F],
    "Our AMF, SMF, UDM, PCF and AUSF find their peers through it in the cluster and in the oracle (S3-S5); Open5GS's AMF, SMF and AUSF find ours. The differential "
    "has the same status codes for every query including the refusals.")
row("NRF-DISC-02", "NRF", "result order: preferred-locality first, then priority (lower first), then load; validityPeriod and nrfSupportedFeatures in the answer",
    "TS 29.510", "5.3.2.2.2", "tested", [N + ("test_discovery",)], "")
row("NRF-DISC-03", "NRF", "Service-Map feature (supported-features): nfServiceList map or nfServices array in discovery, retrieval and notifications",
    "TS 29.510", "6.1.9", "verified", [N + ("test_discovery",), N + ("test_discovery_client",)],
    "Found by the oracle run: Open5GS's functions register with the map and its clients expect the array; the first version of the NRF returned the map and the AMF could "
    "not reach the AUSF.")
row("NRF-DISC-04", "libs/nfcore", "discovery client shared by the functions: apiRoot of the first matching instance, cached for the validity period, forgotten "
    "after a connection failure", "TS 29.510", "5.3.2.2.2", "verified", [N + ("test_discovery_client",), CL],
    "UDM (UDR), PCF (UDR), AUSF (UDM), SMF (UDM, PCF, AMF) and AMF (AUSF, UDM, PCF, SMF) run with no peer address in their configuration in the cluster tests.")

# ---- Nnrf_AccessToken -----------------------------------------------------------------------------------------------------------------------
row("NRF-OAUTH-01", "NRF", "Access token request: client_credentials grant, form body; the requester must be a registered instance of the stated type; the scope "
    "must be offered by a registered producer (or the given instance) that allows the requester's type; 200 with an ES256 JWT (iss, sub, aud, scope, exp), "
    "Bearer, expires_in; error body with invalid_request / invalid_client / invalid_scope / unsupported_grant_type", "TS 29.510", "5.4.2.2.1", "tested",
    [N + ("test_tokens",)], "The test verifies the signature with the public key from /oauth2/jwks and rejects a damaged token, alg none and a malformed one.",
    also=["TS 33.501 13.4.1"])
row("NRF-OAUTH-02", "NRF", "enforcement: with oauth2.enforce the discovery, retrieval, list and subscription endpoints need a bearer token whose audience is the NRF "
    "and whose scope covers the service (401, 403); registration, heart-beat and deregistration are authenticated by the transport", "TS 33.501", "13.4.1",
    "tested", [N + ("test_enforcement",)], "")

# ---- operation -----------------------------------------------------------------------------------------------------------------------------
row("NRF-OP-01", "NRF", "the registry survives a restart (state file, written behind); registrations get a full heart-beat interval to come back", "TS 29.510", "5.2.2.2.2",
    "tested", [N + ("test_persistence",), CC], "The chaos run kills and restarts the NRF under load; the functions register again by themselves and the recovery wave passes.")
row("NRF-OP-02", "NRF", "configuration: registry block validated (ranges, unknown keys, enforce needs enabled, the top-level nrf key refused for the NRF itself)",
    "TS 29.510", "5.2.2.3.2", "tested", [N + ("test_config_errors",), B], "")
row("NRF-OP-03", "NRF", "hostile input: replay fuzzing of registration, patch, subscription, discovery query and token request under ASan / UBSan", "TS 29.510", "5.2.2.2.2",
    "tested", [F], "")

# ---- gaps -----------------------------------------------------------------------------------------------------------------------------------
row("NRF-GAP-01", "NRF", "NRF-to-NRF: registration of an NRF with another, forwarding and redirecting discovery, subscription and token requests, hnrf-uri",
    "TS 29.510", "5.2.2.2.3", "gap", [], "Single NRF per PLMN; the hierarchy comes with the roaming scope, which is out of v1.")
row("NRF-GAP-02", "NRF", "other PLMNs and SNPNs: target-plmn-list towards a home NRF, subscription ids prefixed with the PLMN, SNPN lists", "TS 29.510", "5.3.2.2.3",
    "gap", [], "Roaming is out of scope for v1 (ADR-0003).")
row("NRF-GAP-03", "NRF", "NF sets and groups: nfSetId-based discovery and subscription conditions, nfSetIdList, NF group ids as discovery parameters", "TS 29.510",
    "5.3.2.2.2", "gap", [], "Profiles are stored whole, so a set-aware consumer's attributes are kept; the filters are not implemented.")
row("NRF-GAP-05", "NRF", "ETag / If-Match on PUT (replacement), If-None-Match handling, compression of registration bodies", "TS 29.510", "6.1.2.2.4", "gap", [],
    "Entity tags are issued and honoured for PATCH.")

# ================================================================================================================================================
# AUSF
# ================================================================================================================================================
row("AUSF-UEAU-01", "AUSF", "Authenticate with 5G AKA: POST AuthenticationInfo (SUPI or SUCI, serving network name) gets the vector from the UDM and answers 201 with "
    "UEAuthenticationCtx (rand, autn, HXRES*, the 5g-aka link) and Location; the AMF's PUT of RES* is compared with XRES*; 200 with AUTHENTICATION_SUCCESS, SUPI and KSEAF, "
    "or AUTHENTICATION_FAILURE without a key; the context is single use", "TS 29.509", "5.2.2.2.2", "verified",
    [A + ("test_full_aka",), A + ("test_wrong_res_star",), A + ("test_suci",), AD],
    "Open5GS's AMF and UERANSIM register through our AUSF behind Open5GS's UDM and NRF (oracle S3, OUR_AUSF=1), and with every function ours (S3, S4, S5). The differential "
    "against Open5GS's AUSF gives the same status codes and attributes for the shared requests; the two documented differences (a second confirmation, the kseaf attribute "
    "of a failure) are in tools/diff/ausf_diff.py.", also=["TS 33.501 6.1.3.2.0", "TS 33.501 A.5", "TS 33.501 A.6"])
row("AUSF-UEAU-02", "AUSF", "the serving network name: constructed as 5G:mnc<3>.mcc<3>.3gppnetwork.org, checked by the AUSF before it asks the UDM, restricted to a configured "
    "list of serving networks (SERVING_NETWORK_NOT_AUTHORIZED, 403)", "TS 33.501", "6.1.2", "tested", [AM + ("test_serving_network",), AM + ("test_allow_list",)], "")
row("AUSF-UEAU-03", "AUSF", "synchronisation failure: resynchronizationInfo (RAND, AUTS) is passed to the UDM, a forged AUTS is refused (403), the SQN continues from the UE's",
    "TS 33.501", "6.1.3.3.2", "verified", [A + ("test_resync",), A + ("test_forged_auts",)],
    "Open5GS's AMF resynchronises through our AUSF in the oracle scenarios that include a stale SQN.")
row("AUSF-UEAU-04", "AUSF", "a null RES* (no response from the UE, a failed check in the AMF) is a failure; a malformed one is 400; an unknown or expired context is 404 "
    "CONTEXT_NOT_FOUND; one pending context per UE and serving network (a new start replaces it); the tables are bounded (503 beyond)", "TS 29.509", "5.2.2.2.2", "tested",
    [AM + ("test_supersede_and_limits",), AM + ("test_null_res_star",), AM + ("test_removal_and_deregister",), A + ("test_context_expiry",), AF], "")
row("AUSF-UEAU-05", "AUSF", "Authenticate with EAP-AKA': the UDM's AV' (RAND, AUTN with the AMF separation bit, XRES, CK', IK') is turned into the EAP-Request/AKA'-Challenge "
    "(AT_RAND, AT_AUTN, AT_KDF 1, AT_KDF_INPUT = the serving network name, optional AT_RESULT_IND, AT_MAC) in the 5gAuthData string and the eap-session link; the response "
    "is verified (AT_MAC first, then RES; an AT_KDF that asks for another function fails), with a failure notification and EAP-Failure after a failed round, "
    "AKA'-Authentication-Reject and Client-Error ending the session, a protected success indication when both sides ask for one, the synchronisation failure answered with a "
    "new challenge (at most twice), and EAP-Success with KSEAF (the first 256 bits of the EMSK -> KAUSF -> KSEAF) at the end",
    "TS 29.509", "5.2.2.2.3", "verified",
    [AM + ("test_eap_full",), AM + ("test_eap_result_indication",), AM + ("test_eap_failures",), AM + ("test_eap_resync",), EAPC + ("test_vectors",),
     AMF_E + ("test_eap_registration",), UDM_E + ("test_ueau_eap",)],
    "Key derivation: the four test vectors of RFC 9048 Annex D (CK', IK', K_encr, K_aut, K_re, MSK, EMSK) are reproduced. End to end: UERANSIM's own EAP-AKA' peer (nr-ue, "
    "with the one-line decoder fix of deploy/oracle/build_ueransim_eap.sh) registers, sets up a PDU session and pings through our NRF, AUSF, AMF, SMF, UPF, UDM and PCF "
    "(oracle S3, S5 with AUTH_METHOD=EAP_AKA_PRIME); the AMF carries the challenge in the EAP message of the Authentication request and the EAP-success in the Security mode "
    "command (TS 24.501 5.4.1.2.1).", also=["TS 33.501 6.1.3.1", "TS 33.501 Annex F", "RFC 5448", "RFC 4187", "RFC 9048", "TS 24.501 5.4.1.2.2"])
row("AUSF-UEAU-06", "AUSF", "removal of an authentication result (DELETE on the 5g-aka-confirmation or eap-session resource): 204, the UDM is told (PUT auth-events/{authEventId} with "
    "authRemovalInd), only for the current result of the UE; the AMF deletes the result when the UE is de-registered, implicitly de-registered or rejects the security mode command",
    "TS 29.509", "5.2.2.2.5", "verified", [AM + ("test_removal_and_deregister",), AM + ("test_eap_full",)],
    "In the oracle scenarios our AUSF forwards Open5GS's AMF's DELETE to Open5GS's UDM, which accepts it (it wants success=true next to authRemovalInd: our AUSF sends the "
    "specified false first and the other form when the UDM answers 400).", also=["TS 29.509 5.2.2.2.6", "TS 29.503 6.3.3.6"])
row("AUSF-UEAU-07", "AUSF", "deregister: POST .../ue-authentications/deregister clears the security context of a SUPI (204; 404 CONTEXT_NOT_FOUND; 400)", "TS 29.509", "5.2.2.3.1",
    "tested", [AM + ("test_removal_and_deregister",)], "")
row("AUSF-UEAU-08", "AUSF", "FN-RG authentication: POST rg-authentications with the SUCI and the authenticated indication; the UDM's RgAuthCtx gives the SUPI; AUTHENTICATION_SUCCESS "
    "with authInd when the W-AGF authenticated the gateway, AUTHENTICATION_FAILURE otherwise", "TS 29.509", "5.2.2.2.4", "tested", [AM + ("test_rg",), UDM_E + ("test_ueau_eap",)],
    "The UDM side (GET security-information-rg) is part of the same change.")
row("AUSF-UEAU-09", "AUSF", "errors of the UDM mapped as the AUSF table says: USER_NOT_FOUND (404), AUTHENTICATION_REJECTED / SERVING_NETWORK_NOT_AUTHORIZED / "
    "INVALID_HN_PUBLIC_KEY_IDENTIFIER / INVALID_SCHEME_OUTPUT (403), UNSUPPORTED_PROTECTION_SCHEME (501), AV_GENERATION_PROBLEM (500), UPSTREAM_SERVER_ERROR and NETWORK_FAILURE (504)",
    "TS 29.509", "6.1.7.3", "tested", [A + ("test_ausf_udm_faults",), A + ("test_error_cases",), A + ("test_udm_damaged_credentials",), AD], "")

row("AUSF-SOR-01", "AUSF", "Nausf_SoRProtection generate-sor-data: the SoR header (ACK, list type, list indication), SoR-MAC-IAUSF = the 128 least significant bits of "
    "KDF(KAUSF, 0x77, header, CounterSoR, list), SoR-XMAC-IUE = KDF(KAUSF, 0x78, 0x01, CounterSoR); PLMN identities as TS 24.008, access technologies as TS 31.102, secured packets "
    "as base64; CounterSoR starts at 1 with every new KAUSF, goes up with every MAC and suspends the service (503 COUNTER_WRAP) at 0xFFFF; 404 without a security context",
    "TS 29.509", "5.3.2.2.1", "tested", [AM + ("test_sor",)],
    "The expected MACs in the test are computed from the clauses' own constants and byte strings written out by hand. The consumer side (UDM, AMF, UE) does not exist yet: AUSF-GAP-02.",
    also=["TS 33.501 6.14", "TS 33.501 A.17", "TS 33.501 A.18", "TS 24.501 9.11.3.51"])
row("AUSF-UPU-01", "AUSF", "Nausf_UPUProtection generate-upu-data: UPU-MAC-IAUSF = KDF(KAUSF, 0x7B, UE parameters update list, CounterUPU) (secured packet, default configured NSSAI and "
    "ME routing indicator data sets as TS 24.501 9.11.3.53A encodes them), UPU-XMAC-IUE = KDF(KAUSF, 0x7C, 0x01, CounterUPU); the same counter rules", "TS 29.509", "5.4.2.2.1", "tested",
    [AM + ("test_upu",)], "As for SoR.", also=["TS 33.501 6.15", "TS 33.501 A.19", "TS 33.501 A.20", "TS 24.501 9.11.3.53A"])

row("AUSF-OP-01", "AUSF", "the latest KAUSF of every authenticated SUPI, with its counters, is kept in an AES-256-GCM wrapped state file (bound to the SUPI) written behind the requests "
    "and restored at start-up with the counters ahead of the last values used; a wrong key, a tampered ciphertext, a moved record and a damaged file stop the start", "TS 33.501", "6.1.1.2",
    "tested", [AM + ("test_state_file",), CC], "The chaos run kills and restarts the AUSF under load.")
row("AUSF-OP-02", "AUSF", "registration at the NRF with the three services (nausf-auth, nausf-sorprotection, nausf-upuprotection) and ausfInfo (supiRanges, routingIndicators, groupId); "
    "the UDM is found through the NRF", "TS 29.510", "6.1.6.2.8", "verified", [AM + ("test_config",), CL],
    "Open5GS's AMF finds our AUSF at Open5GS's NRF and ours; our AMF finds it at ours.")
row("AUSF-OP-03", "AUSF", "configuration: the ausf block validated (ranges, unknown keys, serving network names, state file needs the master key, supi_ranges, routing_indicators)", "TS 33.501", "6.1.2",
    "tested", [AM + ("test_config",), B], "")
row("AUSF-OP-04", "AUSF", "hostile input: replay fuzzing of every request of the three services against a stub UDM with a known EAP-AKA' vector, under ASan / UBSan", "TS 29.509", "6.1.3.2.3",
    "tested", [AF], "")
row("AUSF-OP-05", "AUSF", "every body the AUSF produces (UEAuthenticationCtx for both methods, ConfirmationDataResponse, EapSession in three states, RgAuthCtx, SorSecurityInfo, "
    "UpuSecurityInfo, ProblemDetails) validates against the OpenAPI of the pinned specification; so do the UDM's EAP-AKA' vector and RgAuthCtx", "TS 29.509", "Annex A", "verified",
    [("conformance_dump_payloads_noop", "tests/conformance/dump_payloads.c", "ausf_more_payloads")], "scripts/validate_payloads.ps1: 44 of 44 payloads valid.")

row("AUSF-GAP-01", "AUSF", "EAP-TLS for N5GC devices and FN-RGs in private networks (n5gcInd, Annex B)", "TS 29.509", "Annex B", "gap", [],
    "A request with n5gcInd true is refused (403 AUTHENTICATION_REJECTED).")
row("AUSF-GAP-02", "AUSF", "the consumers of the protection services: the UDM requesting SoR-MAC-IAUSF / UPU-MAC-IAUSF when it delivers steering information or UE parameters "
    "(including the SoR / UPU containers in the AMF's Registration accept and DL NAS transport and the acknowledgement checks), and the UDM clearing a stale context at an old AUSF "
    "(deregister)", "TS 33.501", "6.14.2", "gap", [],
    "The AUSF side is complete and tested through its API; wiring the UDM and the AMF is a Release 15 / 16 feature pass of its own.")
row("AUSF-GAP-04", "AUSF", "EAP identity exchange (EAP-Request/Identity, AKA'-Identity with AT_*_ID_REQ), pseudonyms and fast re-authentication", "TS 33.501", "Annex F.2", "gap", [],
    "5GS does not use fast re-authentication (Annex F.3 NOTE 1) and sends the SUCI outside EAP; the AUSF never requests an identity.")
row("AUSF-GAP-05", "AUSF", "HTTP 307 / 308 redirection (ES3XX) between AUSF instances of a set, indirect communication through an SCP", "TS 29.509", "6.1.10", "gap", [],
    "One AUSF instance per deployment unit; the SCP is a later function.")


# ---- UDR: Nudr_DataRepository, Nudr_GroupIDmap -----------------------------------------------------------------------------------------
UA = "nf/udr/tests/test_udr_api.c"
UN = "nf/udr/tests/test_udr_notify.c"
UD = "nf/udr/tests/test_udr_db.c"
UC = "nf/udr/tests/test_udr_config.c"
UAT = ("udr_api", UA)
UNT = ("udr_notify", UN)
UDT = ("udr_db", UD)
UAP = ("udr_api_postgres", UA)
UNP = ("udr_notify_postgres", UN)
UDP = ("udr_db_postgres", UD)
UDIFF = ("udr_differential", "tools/diff/udr_diff.py", "main")
UFZ = ("fuzz_replay_udr", "fuzz/fuzz_udr.c", "LLVMFuzzerTestOneInput")
UPAY = ("conformance_dump_payloads_noop", "tests/conformance/dump_payloads.c", "udr_payloads")
OUR_UDR_EVIDENCE = ("Oracle S3 and S4 with Open5GS's UDM, AUSF, PCF, SMF and AMF against our UDR (OUR_UDR=1): the subscriber is provisioned in Open5GS's document format and "
                    "UERANSIM registers, opens a PDU session, pings and releases it.")

row("UDR-API-01", "UDR", "every operation of the four published API files (subscription data, policy data, exposure data, application data: 176 operations, 444 schemas) is "
    "generated from the pinned OpenAPI files and served under /nudr-dr/v1 and /nudr-dr/v2, from one engine", "TS 29.504", "6.1.1", "tested",
    [UAT + ("test_validation_and_status",), UPAY], "tools/spec/gen_udr_api.py --check proves that the committed tables are those of the pinned files; 19 UDR payloads validate against the OpenAPI.")
row("UDR-DR-01", "UDR", "Query: GET of a document, of a collection (the children of a path), of a composite parent (ProvisionedDataSets, ContextDataSets); 404 with USER_NOT_FOUND when "
    "the subscriber is unknown and DATA_NOT_FOUND when the data is; the SM data filters single-nssai and dnn, the SM policy filters snssai and dnn", "TS 29.504", "5.2.2.2.2",
    "verified", [UAT + ("test_fields_filters_composites",), UDIFF], OUR_UDR_EVIDENCE)
row("UDR-DR-02", "UDR", "retrieval of a subset of a resource: ?fields= with JSON pointers (members, members of members, members of every array element); a bare member name is "
    "taken as a pointer (Open5GS's UDM sends fields=nssai)", "TS 29.504", "5.2.2.2.3", "verified", [UAT + ("test_fields_filters_composites",), UDIFF],
    "The differential compares fields=nssai with Open5GS's UDR; Open5GS's UDM's NSSAI query works against our UDR in oracle S3.")
row("UDR-DR-03", "UDR", "Create: PUT of a new resource answers 201 with the representation and the Location, POST to a collection allocates the identifier and answers 201; a "
    "replacing PUT answers 204 (or 200 where the operation lists it); compat.put_no_content answers 204 for Open5GS's UDM", "TS 29.504", "5.2.2.3.2", "verified",
    [UAT + ("test_validation_and_status",), UNT + ("test_subscription_data",)], OUR_UDR_EVIDENCE, also=["TS 29.504 5.2.2.3.3"])
row("UDR-DR-04", "UDR", "Delete: 204; 404 when absent; the subscriber's whole data (DELETE /subscription-data/{ueId}, provisioning extension) removes its aliases too", "TS 29.504",
    "5.2.2.4.2", "verified", [UAT + ("test_fields_filters_composites",), UAT + ("test_aliases_and_policy",)], OUR_UDR_EVIDENCE + " Open5GS's UDM deletes the SMF registration at release.")
row("UDR-DR-05", "UDR", "Update: PATCH with JSON Patch (application/json-patch+json, plain application/json taken as one) or merge patch, atomic, the result validated, a failing "
    "patch changes nothing (400 MODIFICATION_NOT_ALLOWED); PUT replaces", "TS 29.504", "5.2.2.5.2", "verified", [UAT + ("test_etag_and_patch",), ("udr_patch_store_routes", "nf/udr/tests/test_udr.c", "test_patch_rfc6902")],
    "Open5GS's UDM updates the SQN with a JSON Patch on the authentication subscription in every registration of oracle S3.", also=["TS 29.504 5.2.2.5.3"])
row("UDR-DR-06", "UDR", "entity tags and validators: strong ETag (the revision) and Last-Modified on every representation, 304 for If-None-Match and If-Modified-Since, 412 for a "
    "failed If-Match / If-None-Match: * on PUT, PATCH and DELETE, checked inside the storage operation (atomic), Cache-Control max-age configurable", "TS 29.504", "6.1.2.2.4",
    "tested", [UAT + ("test_etag_and_patch",), UDT + ("test_conditions",), UDT + ("test_contention",)], "Eight threads create one key: exactly one wins, on every backend.",
    also=["TS 29.504 6.1.2.2.5", "TS 29.504 6.1.2.2.6", "TS 29.504 6.1.2.2.7"])
row("UDR-DR-07", "UDR", "bodies are validated against the schemas of the pinned OpenAPI files (type, enum, range, length, pattern, required members, additional properties, "
    "combinators) and the document a PATCH produces too; the error names the JSON pointer", "TS 29.505", "5.2.2", "tested", [UAT + ("test_validation_and_status",), UAP + ("test_validation_and_status",)],
    "Open5GS's SM data (three allowed SSC modes, schema maximum two) is refused, and the oracle provisions a conforming document: the validator is strict where the reference is not.")
row("UDR-DR-08", "UDR", "Subscribe and unsubscribe: POST to subs-to-notify of each data set (subscription, policy, exposure, application, influence data), 201 with Location and the "
    "subscriptionId, expiry chosen by the UDR (bounded, spread), a bound on the number of subscriptions (429), DELETE to unsubscribe, expired subscriptions removed", "TS 29.504",
    "5.2.2.6.2", "tested", [UNT + ("test_subscription_data",), UNT + ("test_limits_expiry_and_failures",)], "", also=["TS 29.504 5.2.2.7.2"])
row("UDR-DR-09", "UDR", "Notify on a change of subscription data: DataChangeNotify with NotifyItem / ChangeItem (whole document ADD or REMOVE, else one item per changed member), the "
    "originalCallbackReference of a stateless UDM, 3gpp-Sbi-Notification-Correlation suppresses the named subscriptions; delivery by worker threads with retries, a bounded queue and "
    "outcome counters", "TS 29.504", "5.2.2.8.2", "tested", [UNT + ("test_subscription_data",), UNP + ("test_subscription_data",), UNT + ("test_limits_expiry_and_failures",)],
    "A real callback server over HTTP/2.", also=["TS 29.504 5.2.2.8.3", "TS 29.504 6.1.2.3.3"])
row("UDR-DR-10", "UDR", "notifications of policy data (PolicyDataChangeNotification by resource: am-data, sm-data, usage monitoring, operator-specific data, sponsor, BDT, PLMN UE policy; "
    "delResources on removal), exposure data (ExposureDataChangeNotification), influence data and application data (TrafficInfluDataNotif, ApplicationDataChangeNotif, filtered by "
    "dnns, snssais, internalGroupIds, supis, appIds / dataFilters)", "TS 29.519", "6.2.2", "tested", [UNT + ("test_other_data_sets",), UPAY],
    "The notification bodies validate against the OpenAPI schemas of the pinned specification.")
row("UDR-DR-11", "UDR", "a subscriber addressed by GPSI (msisdn-, extid-) is resolved to its SUPI through the alias index kept from the identity data; S-NSSAI comparison treats the "
    "slice differentiator FFFFFF as none", "TS 29.505", "5.2.2", "verified", [UAT + ("test_aliases_and_policy",), UAT + ("test_fields_filters_composites",)],
    "Open5GS's UDM and SMF send single-nssai {sst, sd: ffffff}; without the equivalence they get no SM data (found by oracle S3).")
row("UDR-DR-12", "UDR", "the provisioning extension (PUT and DELETE on the GET-only resources, DELETE of a subscriber, listing the subscribers) needs the bearer token, 403 "
    "PROVISIONING_DISABLED without one configured; the UDM presents it; the operations of the specification need none", "TS 29.505", "5.2.2", "tested",
    [UAT + ("test_provisioning_access",), UDM_E + ("test_udr_provisioning_token",), CL], "The cluster runs with a token on the UDR and one on the UDM.")
row("UDR-GRP-01", "UDR", "Nudr_GroupIDmap: GET nf-group-ids with nf-type (list) and subscriberId answers the map NF type -> group id from the configured SUPI ranges; a GPSI is resolved first; "
    "400 for a missing or malformed parameter, 404 when nothing is configured", "TS 29.504", "5.3.2.2.2", "tested", [("udr_config", UC, "test_config_and_groupids")], "")
row("UDR-STO-01", "UDR", "storage interface (get, put with precondition and replaced record, delete, atomic mutate, prefix listing, partitions) with the same expectations on the "
    "memory, the journalled file and the PostgreSQL backend: revisions, preconditions, prefix semantics (keys with LIKE metacharacters and unicode), eight-thread read-modify-write without a lost update",
    "TS 29.504", "5.2.1.2", "tested", [UDT + ("test_basic",), UDP + ("test_basic",), UDP + ("test_contention",)], "PostgreSQL 18 started without root for each test run (deploy/run/pg-temp.sh).")
row("UDR-STO-02", "UDR", "PostgreSQL: one table with jsonb documents, revisions from a sequence, row locks for the transactions, a connection pool, schema version check, an unreachable "
    "server is a start-up error; the API tests, the notification tests and the storage tests all run on it", "TS 29.504", "5.2.1.2", "tested",
    [UAP + ("test_etag_and_patch",), UNP + ("test_other_data_sets",), UDP + ("test_mutate",)], "")
row("UDR-STO-03", "UDR", "the journalled file store: write-behind journal and snapshot, recovery from a crash image (including a journal older than its snapshot), refusal of an unreadable, "
    "corrupt or unwritable store at start-up", "TS 29.504", "5.2.1.2", "tested", [U, ("udr_patch_store_routes", "nf/udr/tests/test_udr.c", "test_store_startup")], "")
row("UDR-OP-01", "UDR", "registration at the NRF: nudr-dr (v1 and v2 as one service with two versions), nudr-group-id-map and udrInfo (group id, SUPI / GPSI ranges, supported data sets); "
    "found by Open5GS's UDM, AUSF and PCF through the NRF", "TS 29.510", "6.1.6.2.8", "verified", [("nfcore_runtime_nrf", "libs/nfcore/tests/test_nfcore.c", "test_profile_versions"), UC and ("udr_config", UC, "test_config_and_groupids"), CL],
    OUR_UDR_EVIDENCE)
row("UDR-OP-02", "UDR", "configuration: store (memory, file, postgres; the connection string only from the environment or a file), provisioning token (16 characters at least), "
    "validation switch, udrInfo ranges, subscription limits, cache, compatibility, group map; unknown keys and bad values refused with the name of the key", "TS 29.504", "6.1.7", "tested",
    [B, ("udr_config", UC, "test_defaults_and_refusals")], "")
row("UDR-OP-03", "UDR", "hostile input: replay fuzzing of requests to 33 resources with every method, content type, query and precondition, of arbitrary paths and of the group "
    "map query, under ASan / UBSan (30,000 mutations per seed run locally)", "TS 29.504", "6.1.6", "tested", [UFZ], "")
row("UDR-OP-04", "UDR", "every body the UDR produces (the composites, registrations, identity data, subscriptions in all five data sets, the five notifications, ProblemDetails for "
    "404 / 400 / 412) validates against the OpenAPI of the pinned specifications", "TS 29.505", "Annex A", "verified", [UPAY], "scripts/validate_payloads.ps1: every payload valid in the run of the time (63 of 63, 19 of them the UDR's; 81 of 81 now).")
row("UDR-OP-05", "UDR", "Open5GS as the consumer: its UDM, AUSF, PCF, SMF and AMF run their registration, PDU session, policy and release procedures against our UDR", "TS 29.505",
    "5.2.2", "verified", [("sbi_oracle_interop", "tests/conformance/CMakeLists.txt", "-")], OUR_UDR_EVIDENCE + " scripts/g5c_regress.sh --oracle runs S3 and S4 this way.")
row("UDR-OP-06", "UDR", "Open5GS as the reference: the same requests to its UDR (over MongoDB) and to ours, with the documents of the reference written into ours first; statuses and attribute "
    "sets compared, every accepted difference written down with its reason", "TS 29.504", "5.2.2", "verified", [UDIFF],
    "28 requests; the documents of the reference are accepted by our validator except the SSC-mode list that violates the schema.")

row("UDR-GAP-01", "UDR", "26 schema references into specifications that are not pinned (TS 29.122, 29.514, 29.518, 29.522, 29.544, 29.551, 29.554, 29.572) accept any value: BDT, "
    "traffic influence, service parameter and IPTV details are not validated", "TS 29.519", "Annex A", "gap", [],
    "Downloading those specifications needs the owner's permission; the generator lists the references.")
row("UDR-GAP-02", "UDR", "PFD change notifications (ApplicationDataChangeNotif.pfdData, TS 29.551) are not sent; monResItems of a policy data subscription is not supported", "TS 29.519", "6.2.3", "gap", [], "")
row("UDR-GAP-03", "UDR", "the implicit subscription of the UDM to permanent subscription data (the UDR selects a UDM through the NRF to notify a provisioning change)", "TS 29.504", "5.2.2.6.1", "gap", [],
    "Subscriptions are explicit; the UDM does not yet subscribe to the data it caches (it caches nothing).")
row("UDR-GAP-04", "UDR", "feature negotiation (supportedFeatures is stored, not negotiated), DELETE of a subscription collection by query filters, 3gpp-Sbi-Message-Priority", "TS 29.504", "6.1.8", "gap", [], "")
row("UDR-GAP-05", "UDR", "the group data aggregates (5g-vn-groups/internal, pp-profile-data, group-identifiers) are stored documents, not derived from the groups", "TS 29.505", "5.2.2", "gap", [], "")
row("UDR-GAP-06", "UDR", "PostgreSQL: one database, no sharding, schema version 1 only, the records gauge counts this process's changes after start; replication and failover are the database's", "TS 29.504", "5.2.1.2", "gap", [], "")

# ---- NSSF: Nnssf_NSSelection, Nnssf_NSSAIAvailability ----------------------------------------------------------------------------------
NT = "nf/nssf/tests/test_nssf.c"
NSS = lambda fn: ("nssf_e2e", NT, fn)
NSDIFF = ("nssf_differential", "tools/diff/nssf_diff.py", "main")
NSFZ = ("fuzz_replay_nssf", "fuzz/fuzz_nssf.c", "LLVMFuzzerTestOneInput")
NSPAY = ("conformance_dump_payloads_noop", "tests/conformance/dump_payloads.c", "nssf_payloads")
NS_OUR = ("Oracle S3 with our NSSF in place of Open5GS's (OUR_NSSF=1): it registers at the NRF and the core completes registration, PDU session and release; Open5GS's AMF asks an "
          "NSSF only on the home-routed roaming path, so the answers are compared by the differential.")

row("NSSF-SEL-01", "NSSF", "Nnssf_NSSelection for the registration procedure: allowed NSSAI from the requested and the subscribed S-NSSAIs filtered by the slices that are "
    "configured and by the tracking area, rejected in the PLMN and in the TA, configured NSSAI when nothing valid was requested or defaultConfiguredSnssaiInd is set, target AMF set "
    "(the requesting AMF's own set when it covers the allowed NSSAI) and candidate AMFs", "TS 29.531", "5.2.2.2.2", "tested", [NSS("test_registration"), NSFZ],
    "Replayed requests of 22 shapes (fuzz seeds); the allowed-NSSAI rules are those of TS 23.501 5.15.5.", also=["6.1.6.2.2", "6.1.6.2.10"])
row("NSSF-SEL-02", "NSSF", "Nnssf_NSSelection for the PDU session establishment: the network slice instance (NSI information: the NRF to use for the slice, nsiId, NRF "
    "management and token URIs); 403 SNSSAI_NOT_SUPPORTED for a slice that is not configured; the NRF is named by the API URI of its NFDiscovery service", "TS 29.531",
    "5.2.2.2.3", "verified", [NSS("test_registration"), NSS("test_policy_and_errors"), NSDIFF], NS_OUR + " The differential gives the same status and the same NRF as Open5GS's NSSF "
    "for five requests (sd FFFFFF, tracking area, local breakout).", also=["6.1.6.2.7", "6.1.6.2.11"])
row("NSSF-SEL-03", "NSSF", "Nnssf_NSSelection for the UE configuration update: configured NSSAI (and allowed NSSAI when requested) for the subscribed S-NSSAIs of the UE",
    "TS 29.531", "5.2.2.2.4", "tested", [NSS("test_other_procedures")], "", also=["6.1.6.2.13"])
row("NSSF-SEL-04", "NSSF", "Nnssf_NSSelection for the PDN connection establishment (interworking with EPS): the S-NSSAI the PDN connection maps to, with the roaming "
    "mapping of the home PLMN", "TS 29.531", "5.2.2.2.5", "tested", [NSS("test_other_procedures")], "")
row("NSSF-SEL-05", "NSSF", "roaming: requested and subscribed S-NSSAIs of a home PLMN are mapped to the serving PLMN's by the configured mapping; the allowed NSSAI carries "
    "mappedHomeSnssai and the answer mappingOfNssai; a slice restricted for a home PLMN is rejected", "TS 29.531", "5.2.2.2.2", "tested", [NSS("test_roaming")], "",
    also=["6.1.6.2.8"])
row("NSSF-SEL-06", "NSSF", "query handling: nf-type and nf-id are required, exactly one of the four slice information parameters, JSON-encoded parameters, "
    "supported-features; a malformed or missing parameter is 400 with the cause and the invalid parameter", "TS 29.531", "6.1.3.2.3.1", "verified",
    [NSS("test_policy_and_errors"), NSDIFF, NSPAY], "The differential gives 400 for a missing nf-id, nf-type and slice information, as Open5GS's NSSF does.")
row("NSSF-AV-01", "NSSF", "Nnssf_NSSAIAvailability update: PUT of the NSSAI supported per tracking area of an AMF (NssaiAvailabilityInfo; 200 with the authorized part, 403 "
    "for slices that are not configured or are restricted, 400 for a malformed body); PATCH (JSON Patch) and DELETE (204)", "TS 29.531", "5.3.2.2.1", "tested",
    [NSS("test_availability"), NSPAY], "", also=["6.2.3.2.3.1"])
row("NSSF-AV-02", "NSSF", "Nnssf_NSSAIAvailability subscribe: POST to /subscriptions with nfNssaiAvailabilityUri, the tracking areas and the expiry chosen by the NSSF (never more "
    "than max_lifetime_s), a bound on the number of subscriptions; modify (PATCH of expiry, SUMOD feature) and unsubscribe (DELETE)", "TS 29.531", "5.3.2.3.1", "tested",
    [NSS("test_subscriptions"), NSPAY], "", also=["5.3.2.3.2", "5.3.2.4.1"])
row("NSSF-AV-03", "NSSF", "Nnssf_NSSAIAvailability notify: NssfEventNotification with the authorized NSSAI per tracking area to the subscribers when an AMF's update changes it, "
    "delivered by a worker thread (bounded queue, retries), expired subscriptions removed", "TS 29.531", "5.3.2.5.1", "tested", [NSS("test_subscriptions"), NSPAY],
    "A real callback server receives the notification in the test.")
row("NSSF-AV-04", "NSSF", "Nnssf_NSSAIAvailability OPTIONS: 200 with Accept-Encoding: identity (RFC 7694; no content coding is supported)", "TS 29.531", "5.3.2.7.1",
    "tested", [NSS("test_availability")], "")
row("NSSF-AV-05", "NSSF", "supported features: the NSSF keeps and answers the intersection of what the consumer offered and what it supports (availability: ONSSAI, SUMOD, EANAN; selection: RSIPCE)",
    "TS 29.531", "6.1.8", "tested", [NSS("test_availability"), NSS("test_registration")], "")
row("NSSF-OP-01", "NSSF", "registration at the NRF with the two services (nnssf-nsselection v2, nnssf-nssaiavailability v1); the AMF discovers it without a configured address", "TS 29.510",
    "5.2.2.2.2", "verified", [CL, ("sbi_oracle_interop", "tests/conformance/CMakeLists.txt", "-")], NS_OUR + " The cluster tests start the NSSF with the other functions.")
row("NSSF-OP-02", "NSSF", "configuration: slices (S-NSSAI, NRF, tracking areas or TAC ranges, restriction per home PLMN), AMF sets, roaming mappings, policy limits, subscriptions, "
    "state file; every wrong value is refused at start with the key that is wrong", "TS 29.531", "-", "verified", [NSS("test_config"), B], "11 bad configurations are rejected by the binary.")
row("NSSF-OP-03", "NSSF", "state: subscriptions and the NSSAI availability of the AMFs survive a restart (write-behind state file, atomic replace, a damaged file refused)",
    "TS 29.531", "-", "tested", [NSS("test_state")], "")
row("NSSF-OP-04", "NSSF", "hostile input: replay fuzzing of selection and availability requests and notifications (30,000 mutations under ASan in the regression)",
    "TS 29.531", "-", "verified", [NSFZ], "")
row("NSSF-OP-05", "NSSF", "every body the NSSF produces (selection answers for the four procedures, ProblemDetails 403 and 400, subscription created, availability info, "
    "notification) validates against the OpenAPI of TS 29.531", "TS 29.531", "Annex A", "verified", [NSPAY], "every payload valid in the current run (81 of 81, the NSSF's among them).")
row("NSSF-OP-06", "NSSF", "Open5GS as the reference: the same Nnssf_NSSelection requests to its NSSF (behind its NRF) and to ours with the same slices; statuses, the NRF of the "
    "slice and the attributes of the answers are compared (the other three procedures are only in ours: Open5GS answers 400)", "TS 29.531", "5.2.2.2.3", "verified", [NSDIFF], "")
row("NSSF-GAP-01", "NSSF", "the NSSF of the home PLMN (H-NSSF) is not queried for the home-routed roaming case; the mapping is configured", "TS 23.501", "5.15.5.2", "gap", [], "")
row("NSSF-GAP-02", "NSSF", "HTTP redirection (307/308 with a Location to another NSSF) and the NSSF-assisted re-routing responses are not produced", "TS 29.531", "6.1.10", "gap", [], "")
row("NSSF-GAP-03", "NSSF", "slice-to-tracking-area rules by TAC range are exact; the pattern-based TacRange form (TS 29.531 NssaiAvailability tacRangeList pattern) is not supported", "TS 29.531",
    "6.2.6", "gap", [], "")
row("NSSF-GAP-05", "NSSF", "the AMF decides the allowed NSSAI from its own configuration; it does not yet consume Nnssf_NSSelection / Nnssf_NSSAIAvailability", "TS 23.502", "4.2.2.2.3", "gap", [], "")

# ---- NEF: TrafficInfluence, MonitoringEvent, AsSessionWithQoS (and the N5 of the PCF, the id translation of the UDM, the events of the AMF they use) ----------------
NEFT = "nf/nef/tests/test_nef.c"
NE = lambda fn: ("nef_e2e", NEFT, fn)
NEFZ = ("fuzz_replay_nef", "fuzz/fuzz_nef.c", "LLVMFuzzerTestOneInput")
NEPAY = ("conformance_dump_payloads_noop", "tests/conformance/dump_payloads.c", "nef_payloads")
ORACLE = ("sbi_oracle_interop", "tests/conformance/CMakeLists.txt", "-")
PCFN5 = ("pcf_policy_and_services", "nf/pcf/tests/test_pcf.c", "test_policy_authorization")
S6 = ("Oracle S6: UERANSIM registers against our NRF, AUSF, AMF, UDM, UDR and PCF; the NEF stores an AF's traffic influence in the UDR and subscribes at the AMF for the UE (an external "
      "identifier resolved by our UDM); the UE's de-registration reaches the AF as a LOSS_OF_CONNECTIVITY report.")
S7 = ("Oracle S7: UERANSIM with a PDU session; an AF asks the NEF for a QoS for a flow of the UE; our PCF authorizes it and has the PCC rule installed at Open5GS's SMF and at ours "
      "(the AF is told the resources were allocated, the user plane keeps working).")

row("NEF-TI-01", "NEF", "TrafficInfluence: POST creates (201, Location, the representation with self), GET lists and reads, PUT replaces, PATCH (merge patch) changes, DELETE removes "
    "the subscription and its influence data in the UDR; the stored TrafficInfluData is the mapping of TS 29.519 6.2.6.2.2", "TS 29.522", "4.4.7.3", "verified",
    [NE("test_traffic_influence"), NEPAY, NEFZ], S6, also=["5.4.1.3.3.4"])
row("NEF-TI-02", "NEF", "the UE of a traffic influence request: a GPSI (msisdn- or extid-) is resolved to the SUPI by Nudm_SDM id translation (404 USER_NOT_FOUND when unknown), a request "
    "for any UE is stored with interGroupId AnyUE", "TS 29.522", "4.4.7.3", "verified", [NE("test_traffic_influence")], S6)
row("NEF-TI-03", "NEF", "refusals and the test notification: 400 with the pointer of the member that is wrong, 403 for a notification destination the AF may not name, 501 for a "
    "request identified by the UE's address or for a group of UEs, a test notification when requestTestNotification is true and feature 2 is negotiated", "TS 29.122", "5.2.5.3",
    "tested", [NE("test_traffic_influence")], "")
row("NEF-ME-01", "NEF", "MonitoringEvent subscription for one UE (external identifier or MSISDN): LOSS_OF_CONNECTIVITY, UE_REACHABILITY and LOCATION_REPORTING; the NEF finds the serving "
    "AMF (UECM, NRF) and subscribes there; 201 with Location, supportedFeatures negotiated; GET, PUT (Subscription_modification: the UE and the type cannot change), DELETE (also at the AMF)",
    "TS 29.122", "4.4.2.2.2.2", "verified", [NE("test_monitoring"), NEPAY, NEFZ], S6, also=["TS 29.522 4.4.2"])
row("NEF-ME-02", "NEF", "the reports: the AMF's notification (checked against the correlation identifier) becomes a MonitoringNotification with the MonitoringEventReport (loss of "
    "connectivity reason 6 / 7 / 8, reachability type, location information); reaching maximumNumberOfReports or monitorExpireTime removes the subscription here and at the AMF",
    "TS 29.122", "4.4.2.3", "verified", [NE("test_monitoring")], S6)
row("NEF-ME-03", "NEF", "a one-time request is answered with the report (200) when the AMF has one, nothing is kept; LAST_KNOWN_LOCATION is a one-time request whatever the AF said",
    "TS 29.522", "4.4.2", "tested", [NE("test_monitoring")], "")
row("NEF-ME-04", "NEF", "application errors: EVENT_FEATURE_MISMATCH (400), EVENT_UNSUPPORTED (500), PARAMETER_OUT_OF_RANGE (403; a value above the operator's limit is replaced by the "
    "limit), IDLE_STATUS_UNSUPPORTED (403); 404 for an unknown UE and for a UE that no AMF serves", "TS 29.122", "5.3.5.3", "tested", [NE("test_monitoring")], "")
row("NEF-AQ-01", "NEF", "AsSessionWithQoS: POST creates an application session at the PCF (Npcf_PolicyAuthorization, one media component with the QoS reference and the flows, "
    "subscription to the allocation outcome), 201 with Location; 403 REQUESTED_SERVICE_NOT_AUTHORIZED and 404 PDU_SESSION_NOT_AVAILABLE as the PCF decides", "TS 29.522", "4.4.9", "verified",
    [NE("test_as_qos"), NEFZ], S7, also=["TS 29.122 4.4.13"])
row("NEF-AQ-02", "NEF", "PUT replaces and PATCH changes the subscription (the media component at the PCF is brought to the new flows and QoS reference; the UE address stays); DELETE ends "
    "the application session at the PCF", "TS 29.122", "4.4.13", "verified", [NE("test_as_qos")], S7)
row("NEF-AQ-03", "NEF", "notifications: the PCF's SUCCESSFUL_ / FAILED_RESOURCES_ALLOCATION reach the AF as UserPlaneNotificationData; the end of the PDU session is SESSION_TERMINATION "
    "and removes the subscription", "TS 29.522", "4.4.9", "verified", [NE("test_as_qos")], S7)
row("NEF-AQ-04", "NEF", "what the NEF does not serve is 501: Ethernet and IPv6 UEs, usage thresholds, sponsored connectivity, QoS monitoring, alternative QoS references; the QoS references an AF "
    "may name are configured", "TS 29.122", "4.4.13", "tested", [NE("test_as_qos")], "")
row("NEF-OP-01", "NEF", "access control: the AF of {afId} must exist, may use the API and must present its bearer token (401, 403); a notification destination must be a host of the AF; "
    "a limit on its subscriptions (429)", "TS 29.122", "5.2.5.2", "tested", [NE("test_traffic_influence"), NE("test_monitoring"), NE("test_as_qos")], "")
row("NEF-OP-02", "NEF", "registration at the NRF as an NEF (nefInfo); the functions behind it (UDR, UDM, PCF, the AMF of the UE) found through the NRF unless the configuration names them", "TS 29.510",
    "5.2.2.2.2", "verified", [CL, ORACLE], S6 + " The cluster tests start the NEF with the other functions.")
row("NEF-OP-03", "NEF", "configuration: AFs (token, APIs, QoS references, notification hosts, limits), callback address, addresses of the other functions, limits, state file; every wrong "
    "value is refused at start with the key that is wrong", "TS 29.522", "-", "verified", [NE("test_config"), B], "12 bad configurations are rejected by the binary.")
row("NEF-OP-04", "NEF", "state: the subscriptions and what the NEF holds at other functions (correlation identifiers included) survive a restart; a damaged state file is refused",
    "TS 29.522", "-", "tested", [NE("test_state")], "")
row("NEF-OP-05", "NEF", "hostile input: replay fuzzing of the northbound requests and of the callbacks of the AMF and the PCF (30,000 mutations under ASan in the regression; it found "
    "and fixed a null flow description)", "TS 29.522", "-", "verified", [NEFZ], "")
row("NEF-OP-06", "NEF", "every body the NEF produces (the representations, the two notifications, ProblemDetails, the influence data it stores) validates against the OpenAPI of TS 29.522 / "
    "TS 29.122 / TS 29.519", "TS 29.522", "5.4.3", "verified", [NEPAY], "every payload valid in the current run (81 of 81).")
row("NEF-GAP-01", "NEF", "traffic influence for a UE identified by its address (the PCF's afRoutReq, 4.4.7.2) and for a group of UEs (the UDM's group identifier translation) are 501; "
    "the SMF's UP path change notifications are not received", "TS 29.522", "4.4.7.2", "gap", [], "")
row("NEF-GAP-02", "NEF", "monitoring: no subscription at the UDM (Nudm_EventExposure is not built), so the UE must be registered; groups of UEs and the other monitoring types are "
    "refused; no group reporting guard time; no Ngmlc location for accuracy above cell level", "TS 29.522", "4.4.2", "gap", [], "")
row("NEF-GAP-03", "NEF", "PFD management (TS 29.551 is not pinned and the SMF does not read PFDs), Nnef_EventExposure (nothing in this core produces AF or analytics events), "
    "Nnef_PFDmanagement, Nnef_TrafficInfluence", "TS 29.591", "-", "gap", [], "")
row("NEF-GAP-04", "NEF", "a UE address with no binding at the BSF (or no BSF) gets any PCF of the NRF, which is the right one only with a single PCF; the PCF Set Id and PCF instance Id of the "
    "binding are not used when its address cannot be reached (TS 29.521 4.2.4.2 NOTE 2); the address of a UE of IPv6 or Ethernet is not asked for", "TS 29.522", "4.4.9", "gap", [], "")
row("NEF-GAP-05", "NEF", "AFs present a configured bearer token, not an access token of the NRF (an AF is not a function of the core; the functions behind the NEF use NRF tokens, SEC-OA-*); websocket notification delivery (Notification_websocket)", "TS 33.501",
    "13.4.1", "gap", [], "")
row("PCF-N5-01", "PCF", "Npcf_PolicyAuthorization Create: POST app-sessions with the UE's IPv4 address; session binding to the SM policy of the PDU session (DNN, SUPI, S-NSSAI when given); "
    "500 PDU_SESSION_NOT_AVAILABLE when none; 201 with Location and the AppSessionContext; 400 for a malformed request; 429 at the limit", "TS 29.514", "4.2.2.2", "verified",
    [PCFN5], S7)
row("PCF-N5-02", "PCF", "required QoS: a media component that names a QoS reference of the configuration becomes a PCC rule with its 5QI (and GBR / MBR) and the AF's flows, installed at the SMF "
    "by an update notification of the SM policy; a closed gate installs no rule; an unknown reference, no reference, Ethernet flows: 403 REQUESTED_SERVICE_NOT_AUTHORIZED", "TS 29.514",
    "4.2.2.32", "verified", [PCFN5], S7)
row("PCF-N5-03", "PCF", "Update: PATCH (merge patch of ascReqData: media components added, replaced, removed with null) and the SMF is updated; Delete: POST .../delete removes the rules; "
    "GET reads the context; 404 for an unknown one", "TS 29.514", "4.2.3.2", "verified", [PCFN5], S7, also=["4.2.4.2"])
row("PCF-N5-04", "PCF", "notifications to the AF: SUCCESSFUL_ / FAILED_RESOURCES_ALLOCATION (the SMF's acceptance or refusal of the update, from a thread of its own) to the events "
    "subscription's notifUri + /notify, the events subscription as a resource of its own (PUT, DELETE); TerminationInfo to notifUri + /terminate when the PDU session ends",
    "TS 29.514", "4.2.5.8", "verified", [PCFN5], S7, also=["4.2.5.3", "4.2.2.10"])
row("PCF-N5-05", "PCF", "configuration policy_authorization (QoS references with their 5QI and bit rates, the limit of application sessions); wrong values refused at start", "TS 29.514",
    "-", "verified", [PCFN5, B], "")
row("PCF-N5-GAP-01", "PCF", "QoS from the media type and the bandwidths (TS 29.513 is not pinned), usage monitoring, sponsored connectivity, traffic routing (afRoutReq), access network information, "
    "QoS notification control, IPv6 and Ethernet sessions", "TS 29.514", "4.2.2.2", "gap", [], "Open5GS's PCF answers 403 to a media component that has only a QoS reference.")
row("UDM-IDT-01", "UDM", "Nudm_SDM id translation: GET {gpsi}/id-translation-result answers the SUPI (and the GPSI) from the identity data of the UDR; 404 for an unknown GPSI, 400 for "
    "something that is not a GPSI; the subscriber API takes msisdn and gpsi and writes the identity data", "TS 29.503", "-", "tested", [NE("test_monitoring"), NE("test_traffic_influence")], S6)
row("AMF-EE-01", "AMF", "Namf_EventExposure: the LOSS_OF_CONNECTIVITY event (UE_DEREGISTERED, MAX_DETECTION_TIME_EXPIRED for the implicit de-registration) and the reachability report "
    "when a UE becomes connected", "TS 29.518", "5.3.2.2", "tested", [NE("test_monitoring"), ("amf_e2e", "nf/amf/tests/test_amf_e2e.c", "test_events")], S6)

# ---- SCP: indirect communication (TS 29.500 6.10, 6.11), TS 23.501 6.2.19 --------------------------------------------------------------
SCT = "nf/scp/tests/test_scp.c"
SC = lambda fn: ("scp_e2e", SCT, fn)
SCDIFF = ("scp_differential", "tools/diff/scp_diff.py", "main")
SCFZ = ("fuzz_replay_scp", "fuzz/fuzz_scp.c", "LLVMFuzzerTestOneInput")
SC_OUR = ("Oracle S3 through our SCP (OUR_SCP=1): Open5GS's NRF, UDR, UDM, AUSF, PCF, SMF and AMF send every request to the other functions to our SCP "
          "(client.scp); UERANSIM registers, establishes a PDU session and releases it. Mode c names the producer, mode d delegates the discovery and the registration.")
SC_ALL = ("Oracle S4 with every function ours and every request between the functions through our SCP (scp_client in each configuration); the user plane keeps working "
          "after the policy change.")

row("SCP-C-01", "SCP", "indirect communication without delegated discovery (Model C): the request goes to the apiRoot named in 3gpp-Sbi-Target-apiRoot, the path and query are kept, "
    "the Target-apiRoot is taken off and Via is added; the response is relayed with its headers and body; the producer is named in 3gpp-Sbi-Producer-Id", "TS 29.500", "6.10.5.1",
    "verified", [SC("test_model_c"), SCDIFF, SCFZ], SC_OUR + " The differential gives the same status and body as Open5GS's SCP for the same requests.", also=["5.2.3.2.4", "5.2.3.2.8"])
row("SCP-C-02", "SCP", "the ck (cache key) query parameter is removed before the request is forwarded; the SCP's own prefix (the deployment-specific string of its apiRoot) is removed from the path",
    "TS 29.500", "6.10.2.6", "tested", [SC("test_model_c"), SC("test_limits_and_targets")], "", also=["6.10.4"])
row("SCP-C-03", "SCP", "notifications and callbacks: a request with 3gpp-Sbi-Callback is forwarded to the callback URI named in Target-apiRoot with the header kept; the default "
    "notification subscription pseudo URI (/scp-default-sub-notify-uri) is answered 404, as no default subscription is supported", "TS 29.500", "6.10.7", "tested", [SC("test_model_c")], "",
    also=["5.2.3.2.3", "6.10.5.2"])
row("SCP-D-01", "SCP", "delegated discovery (Model D): the 3gpp-Sbi-Discovery-* headers become the query of an Nnrf_NFDiscovery request (every header "
    "3gpp-Sbi-Discovery-<name> is the query parameter <name>: target-nf-type, service-names, requester-nf-type, target-nf-instance-id and the others), the NF profiles are turned into candidate apiRoots (priority, capacity, the service's address)",
    "TS 29.500", "6.10.3.2", "verified", [SC("test_model_d"), SCDIFF, SCFZ], SC_OUR, also=["5.2.3.2.7"])
row("SCP-D-02", "SCP", "the requester NF type is taken from the User-Agent when the consumer did not give it; a request with discovery factors but no target NF type, or with no "
    "requester type, is 400 MANDATORY_IE_MISSING with the SCP named in the Server header; the NRF used is the one in 3gpp-Sbi-Nrf-Uri (nnrf-disc) or the configured one", "TS 29.500", "6.10.3.2",
    "verified", [SC("test_model_d"), SCDIFF], "Open5GS's SCP answers 500 for the same requests; the specification gives no status for a missing discovery factor.", also=["5.2.3.2.12", "5.2.7.4"])
row("SCP-D-03", "SCP", "the answers of the NRF are cached (cache_ttl_s, cache_max) per discovery query; NRF failure is 504 TARGET_NF_NOT_REACHABLE, a refusal of the query is "
    "400 NF_DISCOVERY_FAILURE, an empty result is 400 NF_DISCOVERY_FAILURE", "TS 29.500", "6.10.3.2", "tested", [SC("test_model_d")], "")
row("SCP-D-04", "SCP", "the NF service producer ID is returned to the consumer in 3gpp-Sbi-Producer-Id (nfinst=<id>) after delegated discovery, so the consumer can bind to the instance; "
    "the apiRoot of a reselected producer is returned in 3gpp-Sbi-Target-apiRoot", "TS 29.500", "6.10.3.4", "verified", [SC("test_model_d"), SC("test_retries_and_health"), SCDIFF],
    "Open5GS's SCP sends the bare instance id; the differential accepts that and checks ours is nfinst=<id> as the specification gives it.", also=["5.2.3.2.8", "6.10.4"])
row("SCP-R-01", "SCP", "reselection: when a producer cannot be reached, times out or answers 503 (retry_on_503) the next candidate is tried (attempts, timeout_ms) with the same "
    "request; the candidate order is priority, then random weighted by capacity and load; Routing-Binding restricts or prefers the instance named by nfinst", "TS 29.500", "6.10.5.1", "tested",
    [SC("test_retries_and_health")], "", also=["5.2.3.2.5"])
row("SCP-R-02", "SCP", "producers that fail failures times in a row are left alone for seconds (quarantine) and tried last; the gauge of quarantined producers", "TS 23.501", "6.2.19",
    "tested", [SC("test_retries_and_health"), SC("test_metrics_and_concurrency")], "")
row("SCP-E-01", "SCP", "errors made by the SCP: 400 (MANDATORY_IE_MISSING, INVALID_API, INVALID_DISCOVERY_PARAM, NF_DISCOVERY_FAILURE), 413 for a body above max_body, 503 NF_CONGESTION above "
    "max_inflight, 504 TARGET_NF_NOT_REACHABLE and TIMED_OUT_REQUEST; ProblemDetails with the cause and the Server header naming the SCP", "TS 29.500", "6.10.8.2", "verified",
    [SC("test_limits_and_targets"), SC("test_retries_and_health"), SCDIFF], "The differential gives 504 for an unreachable target (Open5GS: 500).", also=["5.2.7.4"])
row("SCP-E-02", "SCP", "an error answer of the producer is relayed unchanged with Via added and no Server header of the SCP; a request that already passed this SCP (its Via names it) "
    "is refused as a loop", "TS 29.500", "6.10.8.3", "verified", [SC("test_model_c"), SC("test_limits_and_targets"), SCDIFF], "The differential relays a producer's 400 as Open5GS's SCP does.")
row("SCP-E-03", "SCP", "late arriving requests: 3gpp-Sbi-Sender-Timestamp with 3gpp-Sbi-Max-Rsp-Time; a request that has timed out at the client is refused with 504 TIMED_OUT_REQUEST, the "
    "two headers are forwarded unmodified (the specification allows that)", "TS 29.500", "6.11.2.2", "tested", [SC("test_model_c"), SCFZ], "", also=["5.2.3.3.2", "5.2.3.3.3"])
row("SCP-X-01", "SCP", "chained SCPs: a next-hop SCP (scp.next) receives the request with the apiRoot this SCP selected, or with the discovery headers when it delegates the discovery; the "
    "prefix of each SCP is handled; the Via of the chain is kept", "TS 23.501", "6.2.19", "tested", [SC("test_chain")], "")
row("SCP-X-02", "SCP", "access control on the targets (scp.targets.allow: host names, wildcard names, IPv4 CIDRs): a Target-apiRoot outside the list is 403 TARGET_NOT_ALLOWED and a discovered producer outside it is not a candidate (400 NF_DISCOVERY_FAILURE when none is left)", "TS 29.500",
    "6.10.5.1", "tested", [SC("test_limits_and_targets"), SCFZ], "")
row("SCP-X-03", "SCP", "the client side: the SBI client of every function sends its requests through the SCP (scp_client) with Target-apiRoot set to the producer and the User-Agent "
    "carrying the NF type, except requests to the NRF and to the SCP itself; the NF type is registered as SCP with scpInfo.scpPorts", "TS 29.500", "6.10.2", "verified",
    [SC("test_client_side"), CL], SC_OUR + " " + SC_ALL, also=["6.10.2.4"])
row("SCP-OP-01", "SCP", "configuration: prefix, next hop, discovery, routing, quarantine, limits, workers, targets; every wrong value is refused at start with the key that is wrong", "TS 29.500",
    "-", "verified", [SC("test_config"), B], "12 bad configurations are rejected by the binary; configs/scp.yaml and the compose configuration load.")
row("SCP-OP-02", "SCP", "metrics: requests by model, responses by class, attempts, discovery cache results, quarantined producers and the in-flight gauge, a latency histogram; a totals "
    "line at shutdown; correct under concurrent consumers", "TS 29.500", "-", "tested", [SC("test_metrics_and_concurrency")], "")
row("SCP-OP-03", "SCP", "hostile input: replay fuzzing of the headers, path, query and body of requests to the SCP (30,000 mutations under ASan in the regression)", "TS 29.500", "-", "verified",
    [SCFZ], "")
row("SCP-OP-04", "SCP", "the cluster runs through the SCP (G5C_SCP=1, the default): load and chaos tests pass with every request between the functions forwarded by it", "TS 29.500",
    "6.10.2", "verified", [CL, CC], SC_ALL)
row("SCP-GAP-01", "SCP", "HTTP redirection (307/308) is not generated and a 307/308 of a producer is relayed, not followed; no reselection on a redirect", "TS 29.500", "6.10.9", "gap", [], "")
row("SCP-GAP-02", "SCP", "authorization: the SCP does not obtain access tokens for the consumers (Model D) and does not check them (Model C); 401/403 with WWW-Authenticate are relayed", "TS 29.500",
    "6.10.11", "gap", [], "Planned with the pass over all functions (NRF-GAP-04).")
row("SCP-GAP-03", "SCP", "overload and load control information (3gpp-Sbi-Oci, 3gpp-Sbi-Lci) and message priority are relayed and not interpreted; no NF set / service set based reselection beyond nfinst", "TS 29.500",
    "6.3", "gap", [], "")
row("SCP-GAP-04", "SCP", "default notification subscriptions are not supported (the pseudo URI is 404); no SEPP functions (N32); no TLS between the SCP and the functions in the sample configuration", "TS 29.500",
    "6.10.3.3", "gap", [], "")

# ---- BSF: Nbsf_Management (TS 29.521), the PCF that registers bindings, the NEF that asks for them ------------------------------------------
BST = "nf/bsf/tests/test_bsf.c"
BS = lambda fn: ("bsf_e2e", BST, fn)
BSDIFF = ("bsf_differential", "tools/diff/bsf_diff.py", "main")
BSFZ = ("fuzz_replay_bsf", "fuzz/fuzz_bsf.c", "LLVMFuzzerTestOneInput")
BSPAY = ("conformance_dump_payloads_noop", "tests/conformance/dump_payloads.c", "bsf_payloads")
BS_S8A = ("Oracle S8 with our BSF in place of Open5GS's (OUR_BSF=1): Open5GS's PCF registers the binding of the PDU session (UE address, DNN, slice, its own address) at it, "
          "the BSF's discovery finds it by the UE's address while the session is up, and it is gone after the release.")
BS_S8B = ("Oracle S8 with our PCF and Open5GS's BSF: our PCF registers the binding, Open5GS's BSF finds it by the UE's address, and it is removed at the release.")
BS_ALL = ("Oracle S8 and S7 with every function ours, the BSF and the SCP among them: the PCF registers, the NEF asks the BSF which PCF holds the UE address and "
          "reaches it (g5c_nef_bsf_discoveries_total).")

row("BSF-REG-01", "BSF", "Nbsf_Management_Register: POST /pcfBindings creates the binding (201, Location with the bindingId, the PcfBinding with the features that were negotiated); "
    "the BSF assigns the identifier and keeps what the PCF sent", "TS 29.521", "4.2.2.2", "verified", [BS("test_ipv4"), BSDIFF, BSPAY, BSFZ], BS_S8A, also=["5.3.2.3.1"])
row("BSF-REG-02", "BSF", "what a registration must carry: DNN and S-NSSAI always; the UE address (ipv4Addr, ipv6Prefix, addIpv6Prefixes, macAddr48, addMacAddrs) and the PCF address "
    "(pcfFqdn, pcfIpEndPoints, or both Diameter identities) unless ExtendedSamePcf is negotiated; the IP domain only with an IPv4 address; members of a feature that was not "
    "negotiated are refused; 400 with the member that is wrong in invalidParams", "TS 29.521", "5.6.2.2", "tested", [BS("test_registration_rules"), BSFZ], "",
    also=["4.2.2.2"])
row("BSF-REG-03", "BSF", "SamePcf: a registration with a parameter combination (SUPI, DNN, S-NSSAI, any of them) for which a binding with Npcf_SMPolicyControl addressing exists is "
    "refused with 403 EXISTING_BINDING_INFO_FOUND and the pcfSmFqdn / pcfSmIpEndPoints of the existing one", "TS 29.521", "4.2.2.2", "tested", [BS("test_same_pcf")], "",
    also=["5.7.3", "5.6.2.4", "5.6.2.5"])
row("BSF-REG-04", "BSF", "more than one address per binding (MultiUeAddr): additional IPv6 prefixes and MAC addresses, framed routes for IPv4 and IPv6; at most 64 of each", "TS 29.521",
    "5.6.2.2", "tested", [BS("test_ipv6_mac_framed")], "")
row("BSF-REG-05", "BSF", "stale bindings: a registration for a UE address, DNN, S-NSSAI and IP domain that another binding holds replaces it (the address is unique there), and a PCF that "
    "registers with a newer recoveryTime has its older bindings removed", "TS 29.521", "4.2.2.2", "tested", [BS("test_replace_and_purge")],
    "Open5GS's BSF keeps both and answers the first.")
row("BSF-DEL-01", "BSF", "Nbsf_Management_Deregister: DELETE /pcfBindings/{bindingId}: 204, 404 when it does not exist", "TS 29.521", "4.2.3.2", "verified",
    [BS("test_ipv4"), BSDIFF], BS_S8A + " " + BS_S8B, also=["5.3.3.3.1"])
row("BSF-DIS-01", "BSF", "Nbsf_Management_Discovery by the UE's IPv4 address: 200 with the PcfBinding, 204 when nothing matches; dnn, snssai, supi, gpsi and ipDomain narrow the match; "
    "supp-feat selects whether suppFeat is in the answer", "TS 29.521", "4.2.4.2", "verified", [BS("test_ipv4"), BSDIFF, BSPAY], BS_S8A + " " + BS_S8B +
    " The differential gives the same answer for the address; Open5GS ignores the narrowing parameters and answers 404 where the specification says 204.", also=["5.3.2.3.2"])
row("BSF-DIS-02", "BSF", "discovery by an IPv6 address (longest prefix match over the /64 and longer prefixes, the shorter ones, the /128 host entries, additional prefixes), by a MAC "
    "address, and through framed routes (the address itself wins over a route)", "TS 29.521", "4.2.4.2", "tested", [BS("test_ipv6_mac_framed")],
    "Open5GS's BSF refuses an IPv6 prefix of the form 2001:db8:1:2::/64 and cannot register a MAC address, so nothing compares these.")
row("BSF-DIS-03", "BSF", "overlapping addresses: the same IPv4 address in two slices or IP domains; a query that does not tell which is 400 MULTIPLE_BINDING_INFO_FOUND, snssai and "
    "ipDomain pick one", "TS 29.521", "5.7.3", "tested", [BS("test_overlap")], "", also=["4.2.4.2"])
row("BSF-DIS-04", "BSF", "query errors: no UE address is 400 MANDATORY_QUERY_PARAM_MISSING, two of them or a malformed one MANDATORY_QUERY_PARAM_INCORRECT, a query parameter the service "
    "does not define INVALID_QUERY_PARAM, a malformed optional one OPTIONAL_QUERY_PARAM_INCORRECT; each with invalidParams", "TS 29.521", "4.2.4.2", "tested",
    [BS("test_ipv4"), BSFZ], "")
row("BSF-UPD-01", "BSF", "Nbsf_Management_Update (BindingUpdate): PATCH /pcfBindings/{bindingId} with a merge patch: new addresses (the old ones stop matching), null removes a member, "
    "the address cannot be removed unless ExtendedSamePcf; DNN, S-NSSAI and the like are not modifiable (403 MODIFICATION_NOT_ALLOWED); 415 with Accept-Patch for another media type; "
    "501 for a binding that did not negotiate the feature", "TS 29.521", "4.2.5.2", "tested", [BS("test_update"), BSFZ], "Open5GS's BSF has no PATCH.", also=["5.3.3.3.2", "5.6.2.3"])
row("BSF-FEAT-01", "BSF", "supported features: the BSF offers MultiUeAddr, BindingUpdate, SamePcf and ExtendedSamePcf (configurable), answers the intersection with what the consumer offered, "
    "ExtendedSamePcf only together with SamePcf; ES3XX is not offered", "TS 29.521", "5.8", "tested", [BS("test_registration_rules"), BS("test_config")], "")
row("BSF-OP-01", "BSF", "registration at the NRF as a BSF with the nbsf-management service and the bsfInfo of the configuration; the PCF and the NEF discover it without a configured address",
    "TS 29.510", "-", "verified", [CL, ORACLE], BS_S8A + " " + BS_ALL + " The cluster tests start the BSF with the other functions.")
row("BSF-OP-02", "BSF", "configuration: bindings limit, offered features, clean-up rules, bsfInfo, state file; every wrong value is refused at start with the key that is wrong, and the "
    "PCF's `bsf` block and the NEF's `bsf` block likewise", "TS 29.521", "-", "verified", [BS("test_config"), B], "15 bad configurations are rejected by the binaries.")
row("BSF-OP-03", "BSF", "state: the bindings survive a restart (write-behind state file, atomic replace); a damaged file is refused and invalid bindings are dropped", "TS 29.521", "-",
    "tested", [BS("test_state")], "")
row("BSF-OP-04", "BSF", "hostile input: replay fuzzing of registrations, discovery queries, updates and deregistrations (30,000 mutations under ASan in the regression)", "TS 29.521", "-",
    "verified", [BSFZ], "")
row("BSF-OP-05", "BSF", "every body the BSF produces (the registered binding, the discovered one, the updated one, ExtProblemDetails with the existing PCF, ProblemDetails) validates against "
    "the OpenAPI of TS 29.521", "TS 29.521", "5.6.2.2", "verified", [BSPAY], "every payload valid in the current run.")
row("BSF-OP-06", "BSF", "Open5GS as the reference: the same Nbsf_Management requests to its BSF (behind its NRF) and to ours; statuses, Location and the attributes of the answers are "
    "compared, the differences (Open5GS ignores narrowing parameters, answers 404 for no match, refuses IPv6 prefixes, has no PATCH, and its bsfd aborts on a registration that "
    "has only the Diameter identities of the PCF) are listed with the clause of the specification", "TS 29.521", "4.2.4.2", "verified", [BSDIFF], "")
row("BSF-OP-07", "BSF", "many bindings: 20,000 registered by 8 threads at once and found, indexed by address (no scan); under ASan, UBSan and TSan", "TS 29.521", "-", "tested", [BS("test_many")], "")
row("PCF-BSF-01", "PCF", "the PCF as consumer of Nbsf_Management: it registers the binding (UE address from the SM policy association, DNN, S-NSSAI, its address, instance id, recovery time) "
    "when an association with an IPv4 address or IPv6 prefix is created and removes it when the association ends or the PCF ends it; done from a queue by a thread of its own, "
    "so a missing or refusing BSF costs the PDU session nothing; the BSF is the configured one or the one found at the NRF", "TS 29.521", "4.1.3.2", "verified",
    [("pcf_policy_and_services", "nf/pcf/tests/test_pcf.c", "test_bsf_binding"), B], BS_S8A + " " + BS_S8B, also=["4.2.2.2", "4.2.3.2"])
row("NEF-BSF-01", "NEF", "the NEF as consumer of Nbsf_Management_Discovery: for an AsSessionWithQoS request it asks the BSF for the PCF of the UE's address (with the IP domain, DNN and "
    "S-NSSAI when the AF gave them) and calls the PCF the binding names; without a binding or without a BSF it takes a PCF of the NRF; a configured `pcf:` overrides", "TS 29.521",
    "4.1.3.2", "verified", [("nef_e2e", "nf/nef/tests/test_nef.c", "test_as_qos_via_bsf"), B], BS_ALL + " Open5GS's BSF registers allowedNfTypes without the NEF, so Open5GS's NRF "
    "does not discover it for our NEF.", also=["4.2.4.2"])
row("BSF-GAP-01", "BSF", "the BSF does not supervise the PCFs at the NRF (Nnrf_NFManagement status subscription) to remove the bindings of a PCF that was deregistered or suspended; stale bindings "
    "go when their address is registered again or the PCF registers with a newer recovery time", "TS 29.521", "4.2.2.2", "gap", [], "")
row("BSF-GAP-02", "BSF", "redirection (the ES3XX feature: 307 / 308) is not offered; no BSF collocated with the PCF, UDR, NRF or SMF (it is a function of its own)", "TS 29.521", "5.8", "gap", [], "")
row("PCF-BSF-GAP-01", "PCF", "the PCF registers with SuppFeat 0: it does not use BindingUpdate (a changed UE address is a new registration), SamePcf (same PCF for the sessions of a UE: "
    "the paraCom and pcfSm* attributes), MultiUeAddr, or the Diameter identities (no Rx)", "TS 29.521", "4.2.2.2", "gap", [], "")

doc = {
    "title": "Conformance matrix, Phase 7 (NRF: Nnrf_NFManagement, Nnrf_NFDiscovery, Nnrf_AccessToken; discovery in the other functions; AUSF: Nausf_UEAuthentication, "
             "Nausf_SoRProtection, Nausf_UPUProtection; UDR: Nudr_DataRepository, Nudr_GroupIDmap; NSSF: Nnssf_NSSelection, Nnssf_NSSAIAvailability; NEF: TrafficInfluence, MonitoringEvent, AsSessionWithQoS; SCP: indirect communication; BSF: Nbsf_Management; PCF: Npcf_PolicyAuthorization)",
    "note": "Same rules as the other matrices. 'verified' = tests pass and an independent peer (Open5GS's functions and its NRF as the reference, UERANSIM end to end) confirms it. "
            "The gap rows are what the phase leaves out so far.",
    "specs": {
        "TS 29.510": "29510-gf0.txt",
        "TS 33.501": "33501-gk0.txt",
        "TS 29.571": "29571-gf0.txt",
        "TS 29.509": "29509-gb0.txt",
        "TS 29.503": "29503-gi0.txt",
        "TS 24.501": "24501-gf0.txt",
        "TS 29.504": "29504-ge0.txt",
        "TS 29.505": "29505-gc0.txt",
        "TS 29.519": "29519-ge0.txt",
        "TS 29.531": "29531-gb0.txt",
        "TS 29.522": "29522-gi0.txt",
        "TS 29.122": "29122-gj0.txt",
        "TS 29.514": "29514-gn0.txt",
        "TS 29.518": "29518-gj0.txt",
        "TS 29.500": "29500-gf0.txt",
        "TS 29.521": "29521-gb0.txt",
        "TS 23.501": "23501-gk0.txt",
    },
    "rows": rows,
}
(ROOT / "docs" / "conformance" / "phase7-matrix.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf8")
print("wrote %d rows" % len(rows))
