#!/usr/bin/env python3
"""Writes docs/conformance/phase5-matrix.json (Phase 5, AMF). The matrix is data; tools/check/check_matrix.py validates every reference in it.

    python3 tools/gen/gen_phase5_matrix.py"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
U = ("amf_units", "nf/amf/tests/test_amf_units.c")
E = ("amf_e2e", "nf/amf/tests/test_amf_e2e.c")
F = ("fuzz_replay_amf", "fuzz/fuzz_amf.c", "LLVMFuzzerTestOneInput")

rows = []


def row(rid, proc, spec, clause, status, tests, evidence, also=None):
    r = {"id": rid, "phase": 5, "nf": "AMF", "procedure": proc, "spec": spec, "clause": clause}
    if also:
        r["also"] = also
    r["status"] = status
    r["tests"] = [{"ctest": c, "file": f, "fn": fn} for (c, f, fn) in tests]
    r["evidence"] = evidence
    rows.append(r)


# ---- N2: NGAP ----------------------------------------------------------------------------------------------------------------------
row("AMF-N2-01", "NG Setup: the gNB's supported TAs and broadcast PLMNs are checked against the AMF's; the answer carries the AMF name, served GUAMIs, relative capacity "
    "and the PLMN support list with the slices; unknown PLMN / unserved TAC give an NG Setup Failure with a cause and time to wait", "TS 38.413", "8.7.1", "verified",
    [E + ("test_ng_setup",)],
    "UERANSIM's gNB completes NG Setup against our AMF in every oracle scenario. The scripted gNB covers the refusals and checks every IE of the response.")
row("AMF-N2-02", "RAN Configuration Update: new supported TA list accepted when it intersects ours, refused with a cause otherwise", "TS 38.413", "8.7.3", "tested",
    [E + ("test_ng_setup",)], "Scripted gNB.")
row("AMF-N2-03", "NG Reset (whole interface and part of it): the UE contexts of the association are released and the reset acknowledged", "TS 38.413", "8.7.4.2.2",
    "tested", [E + ("test_association_loss",)], "Scripted gNB: after the reset the UE is CM-IDLE and its session reference is kept.")
row("AMF-N2-04", "Error Indication for a message before NG Setup, for undecodable PDUs and for unknown / inconsistent UE-NGAP-IDs", "TS 38.413", "8.7.5",
    "tested", [E + ("test_ng_setup",), E + ("test_path_switch",), F], "Scripted gNB; replay fuzzing with mutations under ASan/UBSan.")
row("AMF-N2-05", "Initial UE Message / Uplink NAS Transport / Downlink NAS Transport: routing by AMF-UE-NGAP-ID, user location (NR-CGI, TAI) taken from every message",
    "TS 38.413", "8.6.1", "verified", [E + ("test_registration",), E + ("test_sessions",)],
    "UERANSIM registers, establishes a session and de-registers through our AMF (S1-S4).", also=["8.6.2", "8.6.3"])
row("AMF-N2-06", "Initial Context Setup: GUAMI, allowed NSSAI, UE security capabilities, KgNB, the registration / service accept and, for reactivated sessions, the PDU "
    "session resource setup list; response and failure handled", "TS 38.413", "8.3.1", "verified", [E + ("test_registration",), E + ("test_idle_service_paging",)],
    "UERANSIM's gNB accepts the setup and derives working AS keys from our KgNB; the scripted UE derives the same KgNB from KAMF and the uplink NAS COUNT.")
row("AMF-N2-07", "UE Context Release: gNB-initiated request (inactivity) and AMF-initiated command (de-registration, reject, abort), confirmed by the complete; "
    "guard timer when the gNB stays silent", "TS 38.413", "8.3.3", "verified", [E + ("test_idle_service_paging",), E + ("test_timers",)],
    "UERANSIM exercises the AMF-initiated release at de-registration; the scripted gNB covers the request and the missing complete.", also=["8.3.2"])
row("AMF-N2-08", "PDU Session Resource Setup / Modify / Release requests built from the SMF's N2 transfers, responses and failures reported back to the SMF", "TS 38.413",
    "8.2.1", "verified", [E + ("test_sessions",)],
    "S2/S3: the session is set up and released through Open5GS's SMF and ours; S4's policy push reaches the gNB as a Modify Request. The scripted gNB "
    "answers the modify (which UERANSIM does not).", also=["8.2.3", "8.2.2"])
row("AMF-N2-09", "Paging: the UE's 5G-S-TMSI and the TAIs of its registration area per gNB, repeated every T3513 up to the configured number of attempts", "TS 38.413",
    "8.5.1", "tested", [E + ("test_idle_service_paging",), E + ("test_paging_failure",)], "Scripted gNB: both pages arrive, the second after T3513.")
row("AMF-N2-10", "Path Switch Request (Xn handover): per-session switching at the SMF, fresh {NH, NCC} for the target gNB, acknowledge; failure for an unknown UE",
    "TS 38.413", "8.4.4", "tested", [E + ("test_path_switch",)],
    "Two scripted gNBs; the next hop the AMF sends equals the one the UE side derives; the user plane then runs through gNB B.", also=["TS 33.501 6.9.2.3"])
row("AMF-N2-11", "N2 handover: Handover Required, target selection by node id and TAI, Handover Request with security context and the SMF's setup transfer, "
    "Acknowledge, Command, Notify and release of the source; cancellation and target refusal", "TS 38.413", "8.4.1", "tested",
    [E + ("test_n2_handover",), E + ("test_handover_failure",)], "Two scripted gNBs against the real SMF and UPF; the source leg is released with cause "
    "successful-handover and the user plane follows the target tunnel.", also=["8.4.2", "8.4.3", "8.4.6"])
row("AMF-N2-12", "UE radio capability and location reports stored / forwarded; NAS non-delivery indication counted", "TS 38.413", "8.14.1", "partial",
    [E + ("test_events",)], "The radio capability is returned in the next Initial Context Setup; location reports feed the event exposure.")

# ---- N1: 5GMM -----------------------------------------------------------------------------------------------------------------------
row("AMF-N1-01", "Initial registration: SUCI, authentication, NAS security mode control, UDM registration and subscription data, AM policy, slice selection, 5G-GUTI "
    "allocation, accept in the context setup, complete", "TS 24.501", "5.5.1.2", "verified", [E + ("test_registration",)],
    "UERANSIM registers (SUCI null scheme) against our AMF with Open5GS's AUSF / UDM and with ours; the scripted UE checks every IE of the accept.")
row("AMF-N1-02", "Registration for mobility / periodic update on an established connection and with a stored context (no authentication when the integrity "
    "check passes)", "TS 24.501", "5.5.1.3", "tested", [E + ("test_context_reuse",), E + ("test_registration_update_and_replacement",)],
    "Scripted UE: protected request under the stored context needs neither authentication nor a security mode command; an update on an existing connection is "
    "answered in a DL NAS transport.")
row("AMF-N1-03", "Registration reject causes: #3/#5/#7/#12/#23/#62/#111 as the situation requires; the connection is released and a context that never "
    "registered is not kept", "TS 24.501", "5.5.1.2.5", "tested", [E + ("test_auth_failures",), E + ("test_algorithms_and_rejects",)],
    "Unknown subscriber (#7), emergency (#5), tracking area (#12, protected under the new context), no common algorithm (#23).")
row("AMF-N1-04", "Identification: identity request for an unknown 5G-GUTI, SUCI in the response, then authentication", "TS 24.501", "5.4.3", "tested",
    [E + ("test_context_reuse",)], "Scripted UE (unprotected request with a GUTI nobody knows).")
row("AMF-N1-05", "5G-AKA authentication: challenge from the AUSF, HRES* checked by the AMF, confirmation at the AUSF, KAMF with ABBA; MAC failure, synchronisation "
    "failure (AUTS to the AUSF, new challenge) and wrong RES* handled; Authentication reject", "TS 24.501", "5.4.1.3", "verified",
    [E + ("test_auth_failures",), E + ("test_registration",)], "UERANSIM authenticates against our AMF + Open5GS's AUSF/UDM (S1) including the SQN "
    "resynchronisation of the golden capture; the scripted UE verifies AUTN, derives KAMF independently and drives the failure paths.",
    also=["TS 33.501 6.1.3.2"])
row("AMF-N1-06", "NAS security mode control: algorithm selection by preference list (NIA2; NEA2 then NEA0), replayed capabilities, IMEISV request, RINMR for an "
    "unprotected initial message, complete with the NAS message container", "TS 24.501", "5.4.2", "verified",
    [E + ("test_registration",), E + ("test_algorithms_and_rejects",), U + ("test_algorithm_selection",), U + ("test_builders",)],
    "UERANSIM accepts the command with its replayed capabilities and answers with the ciphered complete; byte-exact SMC encoding in the unit test.",
    also=["TS 33.501 6.7.1.1"])
row("AMF-N1-07", "NAS integrity protection and ciphering (NIA2 / NEA2), COUNT estimation across the 8-bit wrap, replay and MAC failure dropped", "TS 24.501", "4.4.3",
    "verified", [U + ("test_security",), E + ("test_uplink_protection",), E + ("test_registration",)],
    "Keys and counts agree with UERANSIM for the whole registration / session procedure; hostile messages are dropped without side effects.",
    also=["TS 33.501 6.4"])
row("AMF-N1-08", "Service request: 5G-S-TMSI identification, integrity check, ciphered NAS message container with the uplink data status, service accept, "
    "reactivation of the sessions in the context setup; reject #9 for an unknown / unverified UE", "TS 24.501", "5.6.1", "tested",
    [E + ("test_idle_service_paging",), E + ("test_association_loss",), E + ("test_persistence",)], "Scripted UE and gNB against the real SMF and UPF; the buffered "
    "downlink packet arrives at the new tunnel.", also=["TS 33.501 6.4.6"])
row("AMF-N1-09", "Paging and mobile-terminated service request: the SMF's N1N2 transfer for an idle UE is answered 202, queued, delivered with the context setup",
    "TS 23.502", "4.2.3.3", "tested", [E + ("test_idle_service_paging",), E + ("test_paging_failure",)],
    "Scripted: downlink data from the data network triggers the report, the SMF's transfer, the pages and the delivery; unanswered paging reports a failure to the SMF's URI.")
row("AMF-N1-10", "UE-originated de-registration (normal and switch off): sessions released at the SMF, UDM / PCF cleaned, accept, context release", "TS 24.501",
    "5.5.2.2", "verified", [E + ("test_registration",)], "S1-S4 de-register UERANSIM's UE; the scripted UE covers switch off.")
row("AMF-N1-11", "Network-initiated de-registration with re-registration required (T3522), also towards an idle UE after paging; local de-registration when it "
    "cannot be reached", "TS 24.501", "5.5.2.3", "tested", [E + ("test_network_initiated",)], "Scripted UE.")
row("AMF-N1-12", "Generic UE configuration update: new 5G-GUTI with acknowledgement (T3555), TAI list, allowed NSSAI, network names; pending until the UE is "
    "reachable", "TS 24.501", "5.4.4", "tested", [E + ("test_network_initiated",), U + ("test_registration_accept",)], "Scripted UE.")
row("AMF-N1-13", "5G-GUTI: AMF identity, 5G-TMSI uniqueness, reallocation at every registration, old GUTI invalid after completion", "TS 24.501", "5.4.4.1", "tested",
    [E + ("test_context_reuse",), E + ("test_network_initiated",), U + ("test_registration_accept",)], "Byte-exact GUTI and TAI list encodings; the old 5G-TMSI is "
    "rejected with #9.", also=["TS 23.003 2.10"])
row("AMF-N1-14", "Retransmission timers T3550 / T3560 / T3570 / T3555 / T3522: four retransmissions then abort; implicit de-registration after T3512 + grace", "TS 24.501",
    "5.5.1.2.8", "tested", [E + ("test_timers",), E + ("test_implicit_deregistration",)], "Counted at the scripted gNB; the abort releases the connection and drops "
    "a context that never registered.", also=["5.4.1.3.7", "5.3.7"])
row("AMF-N1-15", "UL / DL NAS transport of 5GSM messages: routing by PDU session id, request type, S-NSSAI and DNN (default DNN), slice check against the allowed "
    "NSSAI, other payload types refused with #90", "TS 24.501", "5.4.5", "verified", [E + ("test_sessions",)],
    "UERANSIM's sessions (S2/S3); the scripted UE checks the #90 answer for a slice outside the allowed NSSAI.")
row("AMF-N1-16", "PDU session status and uplink data status in registration and service request: sessions the UE does not hold are released at the SMF, "
    "reactivation result returned", "TS 24.501", "5.5.1.3.4", "tested", [E + ("test_registration_update_and_replacement",), E + ("test_idle_service_paging",)],
    "Scripted UE.")
row("AMF-N1-17", "Slice selection: requested NSSAI intersected with the subscription and the AMF's slices, rejected NSSAI with cause, default S-NSSAIs when nothing "
    "was requested, #62 when nothing remains", "TS 23.501", "5.15.5.2.1", "tested", [E + ("test_registration",), U + ("test_registration_accept",)],
    "Scripted UE (slice 1 allowed); the rejected NSSAI IE is byte-checked.")

# ---- SBI --------------------------------------------------------------------------------------------------------------------------
row("AMF-SBI-01", "Nausf_UEAuthentication client: start with SUCI / SUPI and optional resynchronisation info, 5G-AKA confirmation with RES*", "TS 29.509", "5.2.2.2",
    "verified", [E + ("test_auth_failures",)], "Open5GS's AUSF (S1-S4) and our AUSF shim (e2e).", also=["5.2.2.3"])
row("AMF-SBI-02", "Nudm_UECM registration / de-registration of the AMF (3GPP access) with the de-registration callback, Nudm_SDM access and mobility subscription "
    "data (subscribed UE-AMBR and NSSAI) and subscription", "TS 29.503", "5.3.2.2.2", "verified", [E + ("test_registration",)],
    "Against Open5GS's UDM and ours; Open5GS's UDM refuses the UECM DELETE (answered 403), which the AMF tolerates.", also=["TS 29.503 5.2.2.2"])
row("AMF-SBI-03", "Npcf_AMPolicyControl create / delete of the policy association with the notification URIs", "TS 29.507", "5.2.2.2", "verified",
    [E + ("test_registration",)], "Open5GS's PCF (after the NrLocation fix found by the oracle run) and ours.")
row("AMF-SBI-04", "Nsmf_PDUSession create / update / release SM context towards the SMF, multipart bodies, SM context status callback", "TS 29.502", "5.2.2.2.1",
    "verified", [E + ("test_sessions",), E + ("test_n2_handover",)], "S2-S4 with Open5GS's SMF and with ours.", also=["5.2.2.3.1", "5.2.2.4.1"])
row("AMF-SBI-05", "Namf_Communication N1N2MessageTransfer: N1 only, N2 setup / modify / release, with and without N1; 200 delivered, 202 attempting to reach the UE, "
    "failure notification URI; unknown UE 404, bad bodies 400, unsupported N2 type 501", "TS 29.518", "5.2.2.3.1", "verified",
    [E + ("test_sessions",), E + ("test_paging_failure",), E + ("test_sbi_errors",)], "Open5GS's SMF and ours.")
row("AMF-SBI-06", "Namf_EventExposure: subscriptions for registration state, connectivity state, reachability and location (one UE or any), notifications, "
    "delete, immediate report; unsupported events 501", "TS 29.518", "5.3.2.2", "tested", [E + ("test_events",), E + ("test_sbi_errors",)],
    "Scripted subscriber.")
row("AMF-SBI-07", "NF discovery through the NRF for AUSF / UDM / PCF / SMF (by service, S-NSSAI, DNN) with a one minute cache; configured URIs take precedence", "TS 29.510",
    "5.3.2.2", "verified", [E + ("test_registration",)], "Open5GS's NRF finds the SMF, AUSF and our UDM / PCF (oracle S2-S4); the AMF registers with an amfInfo profile.")

# ---- robustness and operation -------------------------------------------------------------------------------------------------------
row("AMF-OPS-01", "UE context persistence: registered contexts (GUTI, security context, NSSAI, session references) in an atomically written state file, "
    "restored in CM-IDLE; downlink NAS COUNT kept above the UE's expectation", "-", "-", "tested", [E + ("test_persistence",)],
    "The AMF is stopped and started; the UE's service request is served without authentication and the session's user plane comes back.")
row("AMF-OPS-02", "Configuration: strict keys, ranges, SNOW 3G / ZUC refused by name (ADR-0012), NRF profile with amfInfo", "-", "-", "tested",
    [U + ("test_config",), ("bad_configs_rejected", "tests/conformance/check_bad_configs.sh", "-"), ("sample_configs_load", "tests/conformance/check_configs.sh", "-")],
    "Negative cases name the setting; the sample configuration loads through `amf --check`.")
row("AMF-OPS-03", "Concurrency: per-connection ordering, per-UE mutual exclusion, no data races in the whole end-to-end suite", "-", "-", "tested",
    [E + ("test_idle_service_paging",)], "The e2e suite passes under ThreadSanitizer and AddressSanitizer / UBSan (scripts/g5c_regress.sh).")
row("AMF-OPS-04", "Hostile NGAP PDUs, NAS under a valid envelope and SBI bodies never crash or leak", "-", "-", "tested", [F],
    "Replay fuzzing with mutations under ASan/UBSan: golden NGAP PDUs raw and with the NAS wrapped in a protected envelope, plus SBI bodies for every route.")
row("AMF-OPS-05", "Metrics: NG Setup, NGAP and NAS message counts, registrations, authentications, service requests, pagings, handovers, N1N2 transfers, "
    "PDU session requests, registered / connected UE and gNB gauges", "-", "-", "tested", [E + ("test_registration",)], "Registered with the shared registry.")

# ---- what is still open --------------------------------------------------------------------------------------------------------------------------
row("AMF-GAP-01", "SNOW 3G (NEA1 / NIA1) and ZUC (NEA3 / NIA3): not selected, not advertised (a UE offering only these is rejected with #23)", "TS 33.501", "D.2", "gap", [],
    "ADR-0012: the algorithms are not implemented until the owner signs the ETSI/SAGE licence; no unlicensed implementation exists in the tree.")
row("AMF-GAP-02", "Emergency registration and services, MICO, extended DRX, NB-IoT / CIoT, SMS over NAS, UE policy delivery (UCU), SOR, NSSAA", "TS 24.501", "5.5.1.2.2",
    "gap", [], "Emergency registration is rejected with #5; the other features are not signalled.")
row("AMF-GAP-03", "AMF sets and relocation: Namf_Communication UEContextTransfer / CreateUEContext, AMF status indication, GUAMI backup, inter-AMF handover and "
    "registration with a GUTI of another AMF (answered with an identity request)", "TS 29.518", "5.2.2.2", "gap", [],
    "Single AMF per PLMN; the state file is the first step towards externalised contexts (a shared store is not built).")
row("AMF-GAP-04", "Non-3GPP access (N3IWF), EPS interworking (N26) and handover to E-UTRAN, LADN, network slice selection through the NSSF", "-", "-", "gap", [],
    "Single access type (NR); slices come from configuration and the UDM.")

doc = {
    "title": "Conformance matrix, Phase 5 (AMF: NGAP / N2, 5GMM / N1, NAS security, mobility, Namf services, persistence)",
    "note": "Same rules as the other matrices: every test reference, function and clause is checked by tools/check/check_matrix.py. verified = tests pass and a real peer "
            "confirms it (UERANSIM + Open5GS's AUSF / NRF with our AMF, SMF, UPF, UDM and PCF in scenarios S1-S4 with OUR_AMF=1). The scripted gNB and UE of the "
            "end-to-end suite derive every key independently of the AMF and run over real SCTP. The gap rows are what the phase leaves out.",
    "specs": {
        "TS 24.501": "24501-gf0.txt", "TS 38.413": "38413-gi0.txt", "TS 33.501": "33501-gk0.txt", "TS 23.501": "23501-gk0.txt", "TS 23.502": "23502-gj0.txt",
        "TS 29.518": "29518-gj0.txt", "TS 29.502": "29502-gh0.txt", "TS 29.503": "29503-gi0.txt", "TS 29.507": "29507-gb0.txt", "TS 29.509": "29509-gb0.txt",
        "TS 29.510": "29510-gf0.txt", "TS 23.003": "23003-gc0.txt",
    },
    "rows": rows,
}
(ROOT / "docs" / "conformance" / "phase5-matrix.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf8", newline="\n")
print(len(rows), "rows")
