#!/usr/bin/env python3
"""Writes docs/conformance/phase4-matrix.json (Phase 4, SMF). The matrix is data; tools/check_matrix.py validates every reference in it.

    python3 tools/gen_phase4_matrix.py"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
U = ("smf_units", "nf/smf/tests/test_smf_units.c")
PERSIST = ("smf_e2e", "nf/smf/tests/test_smf_e2e.c")
E = ("smf_e2e", "nf/smf/tests/test_smf_e2e.c")

rows = []


def row(rid, proc, spec, clause, status, tests, evidence, also=None):
    r = {"id": rid, "phase": 4, "nf": "SMF", "procedure": proc, "spec": spec, "clause": clause}
    if also:
        r["also"] = also
    r["status"] = status
    r["tests"] = [{"ctest": c, "file": f, "fn": fn} for (c, f, fn) in tests]
    r["evidence"] = evidence
    rows.append(r)


# ---- N11: Nsmf_PDUSession ------------------------------------------------------------------------------------------------------
row("SMF-N11-01", "Create SM Context: multipart request with the N1 SM part, subscription check, UPF selection, address allocation, UDM registration, "
    "SM policy, N4 establishment, 201 with Location", "TS 29.502", "5.2.2.2.1", "verified",
    [E + ("test_happy_path",), E + ("test_release_and_replace",)],
    "Open5GS's AMF creates the SM context of a UERANSIM UE against our SMF in oracle scenarios S1-S3 (OUR_SMF=1 with our UDM, PCF and UPF): registration, PDU "
    "session, ping through our UPF, release and deregistration pass.")
row("SMF-N11-02", "Create SM Context refusals: bad body, unknown DNN / subscriber / slice, disallowed PDU session type, pool exhausted, no UPF, "
    "unsupported request type; the PDU Session Establishment Reject travels as the N1 part of the error body", "TS 29.502", "5.2.2.2.1", "tested",
    [E + ("test_rejections",), E + ("test_failures",), E + ("test_upf_outage",)],
    "Scripted AMF. The reject message and the 5GSM cause are decoded again with the NAS library; no refused request leaves anything behind in the SMF, "
    "UPF, PCF, UDM or address pool.")
row("SMF-N11-03", "Update SM Context, user plane activation: PDU_RES_SETUP_RSP from the gNB turns the downlink FAR to the gNB tunnel", "TS 29.502", "5.2.2.3.2.2",
    "verified", [E + ("test_happy_path",)],
    "UERANSIM's gNB answers the N2 setup request our SMF built; the ping in S2 runs through the downlink tunnel the SMF configured from its response.")
row("SMF-N11-04", "Update SM Context, user plane deactivation (AN release): downlink buffered in the UPF, the report answered and turned into a page", "TS 29.502",
    "5.2.2.3.2.3", "tested", [E + ("test_happy_path",)], "Scripted AMF and gNB against the real UPF runtime; the buffered packet is delivered after reactivation.")
row("SMF-N11-05", "Update SM Context, service request (ACTIVATING): the N2 setup request is returned in the response", "TS 29.502", "5.2.2.3.2.2", "tested",
    [E + ("test_happy_path",)], "Scripted AMF; the returned transfer decodes and carries the UPF's tunnel.")
row("SMF-N11-06", "UE-requested PDU session release: release request answered with the release command and the N2 release command, resources freed "
    "on the release complete / N2 release response", "TS 24.501", "6.4.3.1", "verified", [E + ("test_happy_path",)],
    "S3 releases the PDU session from the UE (nr-cli ps-release) through Open5GS's AMF; the SMF frees UPF, PCF, UDM and the address.",
    also=["TS 29.502 5.2.2.3.1"])
row("SMF-N11-07", "Release SM Context (AMF-initiated, e.g. deregistration)", "TS 29.502", "5.2.2.4.1", "verified",
    [E + ("test_release_and_replace",), E + ("test_failures",)],
    "S3 deregisters the UE with an active session; our SMF releases it. Unknown contexts answer 404.")
row("SMF-N11-08", "A second establishment of the same PDU session id replaces the first (the AMF-requested release of the duplicate)", "TS 29.502",
    "5.2.2.3.11", "tested", [E + ("test_release_and_replace",)], "Both contexts are accounted for: the old reference is gone, one UPF session, one PCF association, one address in use.")
row("SMF-N11-09", "Multipart/related framing of the SM context bodies (JSON part, N1 and N2 binary parts addressed by Content-Id)", "TS 29.500", "-", "verified",
    [("sbi_multipart", "libs/sbi/tests/test_multipart.c", "test_roundtrip"), ("sbi_multipart", "libs/sbi/tests/test_multipart.c", "test_mutations")],
    "Parsed and built bodies interoperate with Open5GS's AMF in both directions (create, N1N2 transfer, modify).")
row("SMF-N11-10", "SM context status notification to the AMF when the SMF releases a context on its own (AMF refused the transfer, UPF lost)", "TS 29.502", "5.2.2.5.1",
    "tested", [E + ("test_failures",), E + ("test_upf_outage",)],
    "The AMF's status endpoint receives RELEASED with the cause after the release command has been delivered.")

# ---- N11 towards the AMF: Namf_Communication ----------------------------------------------------------------------------------------
row("SMF-N11-11", "N1N2MessageTransfer with the PDU Session Establishment Accept and the PDU session resource setup request (deferred until the 201 is out)",
    "TS 29.518", "5.2.2.3.1.1", "verified", [E + ("test_happy_path",), E + ("test_failures",)],
    "Open5GS's AMF accepts the transfer and sends the accept to the UE and the setup request to the gNB; a refusal by the AMF makes the SMF give the "
    "session back. The AMF address is taken from the smContextStatusUri (or smf.amf.uri); NRF discovery is later.")

# ---- 5GSM NAS -----------------------------------------------------------------------------------------------------------------------
row("SMF-NAS-01", "PDU SESSION ESTABLISHMENT ACCEPT: selected type and SSC mode, QoS rules, Session-AMBR, PDU address, S-NSSAI, DNN, optional cause and PCO",
    "TS 24.501", "8.3.2.1", "verified", [U + ("test_gsm",), E + ("test_happy_path",)],
    "UERANSIM accepts the message and brings up its tunnel interface with the allocated address.")
row("SMF-NAS-02", "Authorized QoS rules (default rule and one rule per PCC rule, packet filter components from the IPFilterRule, precedence 80 avoided)",
    "TS 24.501", "9.11.4.13", "tested", [U + ("test_gsm",), U + ("test_ipfilter",)],
    "Byte-exact expected encodings for the default rule and a two-filter rule, including the match-all restriction for downlink-only filters.")
row("SMF-NAS-03", "Authorized QoS flow descriptions for the non-default flows (5QI, GFBR, MFBR)", "TS 24.501", "9.11.4.12", "tested", [U + ("test_gsm",)],
    "Byte-level checks of a GBR and a non-GBR flow description.")
row("SMF-NAS-04", "Session-AMBR coding (unit = 4^(n-1) kbit/s, value rounded up to 16 bits)", "TS 24.501", "9.11.4.14", "verified", [U + ("test_gsm",)],
    "Boundary values checked; the UE accepts the 100/200 Mbit/s values in S3.")
row("SMF-NAS-05", "PDU address for IPv4, IPv6 (interface identifier) and IPv4v6", "TS 24.501", "9.11.4.10", "partial", [U + ("test_gsm",), E + ("test_rejections",),
    E + ("test_router_solicitation",)],
    "IPv4 is verified end to end. IPv6 and IPv4v6 are encoded, allocated and completed by a router advertisement, tested against our UPF; no IPv6 UE has run against "
    "Open5GS's AMF and UERANSIM, and N3 over IPv6 is not supported by the UPF.")
row("SMF-NAS-06", "Extended protocol configuration options: DNS server (IPv4/IPv6) and IPv4 link MTU replies to what the UE asked for", "TS 24.008", "10.5.6.3A",
    "tested", [U + ("test_gsm",), E + ("test_happy_path",)], "Container identifiers are those of the pinned TS 24.008 v16.7.0.")
row("SMF-NAS-07", "PDU session type selection: requested type if subscribed, else the allowed single stack with cause #50 / #51, else reject #28", "TS 24.501",
    "6.4.1.3", "tested", [E + ("test_rejections",)], "Dual stack, narrowing to IPv6 only, and refusal of IPv6 on an IPv4-only subscription.")
row("SMF-NAS-08", "PDU SESSION ESTABLISHMENT REJECT with the matching 5GSM cause (#26, #27, #28, #38, #96, #97)", "TS 24.501", "8.3.3.1", "tested",
    [E + ("test_rejections",), U + ("test_gsm",)], "Decoded again from the multipart error body.")
row("SMF-NAS-09", "Malformed or foreign 5GSM input is refused without reading out of bounds (truncations, wrong EPD, wrong PSI, wrong message type)", "TS 24.501",
    "-", "tested", [U + ("test_gsm",), ("fuzz_replay_smf", "fuzz/fuzz_smf.c", "LLVMFuzzerTestOneInput")], "Replay fuzzing with mutations under ASan/UBSan.")

# ---- N2 -----------------------------------------------------------------------------------------------------------------------------
row("SMF-N2-01", "PDUSessionResourceSetupRequestTransfer: UL NG-U tunnel, PDU session type, session AMBR, QoS flow list with ARP and GBR information", "TS 38.413",
    "9.3.4.1", "verified", [U + ("test_n2",), E + ("test_happy_path",)], "UERANSIM's gNB decodes the transfer and answers with its tunnel in S2/S3.")
row("SMF-N2-02", "PDUSessionResourceSetupResponseTransfer and ...UnsuccessfulTransfer parsing (IPv4, IPv6, dual-stack addresses; accepted flow list; cause)", "TS 38.413",
    "9.3.4.2", "verified", [U + ("test_n2",), E + ("test_failures",)], "The gNB's response in S2/S3 yields the downlink tunnel used for the ping.")
row("SMF-N2-03", "PDUSessionResourceReleaseCommandTransfer", "TS 38.413", "9.3.4.12", "tested", [U + ("test_n2",), E + ("test_happy_path",)],
    "Accepted by Open5GS's AMF and the gNB in the UE-requested release of S3.")

# ---- N4 -----------------------------------------------------------------------------------------------------------------------------
row("SMF-N4-01", "PFCP Association Setup initiated by the SMF, heartbeats, association accepted from a configured UPF", "TS 29.244", "6.2.6.2", "verified",
    [E + ("setup",), E + ("test_upf_outage",)], "Associates with our UPF in every oracle scenario; Open5GS's UPF-initiated association is accepted from a configured address.",
    also=["6.2.2"])
row("SMF-N4-02", "PFCP Session Establishment from the policy: default PDRs, one PDR pair per PCC rule, FARs, session QER and one QER per flow, BAR, "
    "PDN Type, DNN, S-NSSAI", "TS 29.244", "7.5.2", "verified", [U + ("test_rule_mapping",), E + ("test_happy_path",)],
    "Accepted by our UPF engine and runtime; the first request of each type matches Open5GS's SMF element for element apart from the documented allow-list "
    "(pfcp_diff.py --smf).", also=["7.5.3"])
row("SMF-N4-03", "PCC rule -> PDR/FAR/QER mapping table, including the SDF filter direction rule (the Flow Description is copied unchanged to uplink and downlink "
    "PDRs; the UPF swaps for ACCESS) and per-flow QFI marking", "TS 29.244", "5.2.1A.2A", "tested", [U + ("test_rule_mapping",)],
    "Table-driven against the real UPF engine: downlink packets matching each rule leave with the QFI of that rule's flow; uplink goes through the tunnel.",
    also=["5.4.2"])
row("SMF-N4-04", "PFCP Session Modification: downlink FAR to the gNB tunnel (activate) and to buffering with downlink-data notification (deactivate)", "TS 29.244",
    "7.5.4", "verified", [U + ("test_rule_mapping",), E + ("test_happy_path",)], "The ping of S2 depends on it.")
row("SMF-N4-05", "PFCP Session Deletion", "TS 29.244", "7.5.6", "verified", [E + ("test_release_and_replace",)], "Every release path ends with the UPF session gone.")
row("SMF-N4-06", "PFCP Session Report Request (downlink data) answered with the right SEID and cause; unknown sessions answered with Session Not Found", "TS 29.244",
    "7.5.8", "tested", [E + ("test_happy_path",)], "The Session Report Response is counted by the UPF.")
row("SMF-N4-07", "Request retransmission (T1/N1), loss of a UPF detected by heartbeats, restart detected by the Recovery Time Stamp", "TS 29.244", "6.2.2", "tested",
    [E + ("test_upf_outage",)], "UPF stopped and restarted on the same ports: no UPF is selected while it is down, the restart is counted, its sessions are released, "
    "new sessions work again.")
row("SMF-DIFF-01", "Differential PFCP analysis of the SMF: same UPF and scenario, Open5GS's SMF versus ours (request sequence, information elements per message)",
    "TS 29.244", "7.5.2", "verified", [("pfcp_differential_smf", "tools/pfcp_diff.py", "smf_mode")],
    "Identical request sequence (establishment, modification, deletion); every element Open5GS's SMF sends is either sent by ours or on the documented allow-list "
    "(charging URR, user id, match-all filters, IPv6 router-solicitation forwarding).")

# ---- address management, peers, policy ----------------------------------------------------------------------------------------------
row("SMF-IPAM-01", "UE IPv4 address and IPv6 /64 prefix pools per DNN: allocation, rotation, exhaustion, release on every path", "TS 23.501", "5.8.2.2", "tested",
    [U + ("test_pools",), E + ("test_failures",)], "Pool exhaustion rejects with cause #26; addresses are returned on release, replacement, refusal and AMF failure.")
row("SMF-UDM-01", "Nudm_SDM session management subscription data per slice and DNN; Nudm_UECM SMF registration and deregistration", "TS 29.503", "-", "verified",
    [E + ("test_happy_path",), E + ("test_rejections",)], "Against our UDM (and, in S3, through it from Open5GS's AMF).")
row("SMF-PCF-01", "Npcf_SMPolicyControl create / delete; the decision (session AMBR, default QoS, PCC rules, QoS data) drives NAS, N2 and N4", "TS 29.512", "4.2.2.2", "verified",
    [E + ("test_happy_path",), U + ("test_policy",)], "Against our PCF with a GBR voice rule; S3 against the same PCF with Open5GS's AMF and UERANSIM.")
row("SMF-CFG-01", "Configuration: strict keys, address formats, ranges; nothing is bound by --check", "-", "-", "tested", [("bad_configs_rejected", "tests/conformance/check_bad_configs.sh", "-"),
    ("sample_configs_load", "tests/conformance/check_configs.sh", "-")], "About 50 SMF-specific negative cases plus the sample and compose configurations.")
row("SMF-SEC-01", "Hostile peer input (multipart, NAS, N2, IPFilterRule, policy JSON, bit rates, PFCP responses) is bounded and never crashes", "-", "-", "tested",
    [("fuzz_replay_smf", "fuzz/fuzz_smf.c", "LLVMFuzzerTestOneInput"), ("sbi_multipart", "libs/sbi/tests/test_multipart.c", "test_mutations")],
    "Replay fuzzing with deterministic mutations under ASan/UBSan; ThreadSanitizer run of the end-to-end test.")

# ---- the second half: modification, paging, recovery, persistence, discovery, IPv6 -----------------------------------------------------------------
row("SMF-MOD-01", "PCF-initiated SM policy update: the decision is diffed against the one in force (session AMBR, flow rates, rules and flows added / removed), "
    "the UPF is modified (Update QER, Create / Remove PDR and QER) before anyone is told", "TS 29.512", "4.2.3", "verified",
    [U + ("test_policy_update",), E + ("test_policy_update",)],
    "Scenario S4 with OUR_SMF=1: the PCF pushes a throttled AMBR and a new rule to our SMF, the UPF is modified, the AMF sends the gNB a PDUSessionResourceModifyRequest "
    "and the session keeps carrying traffic. The unit test checks the QFI of downlink traffic before and after against the real UPF engine.")
row("SMF-MOD-02", "PDU SESSION MODIFICATION COMMAND towards the UE (new Session-AMBR, QoS rules created / deleted, QoS flow descriptions created / modified / "
    "deleted), PTI 0; the UE's complete is accepted", "TS 24.501", "6.4.2", "tested",
    [U + ("test_policy_update",), E + ("test_policy_update",)], "Decoded again with the NAS library; Open5GS's AMF forwards it to the gNB. UERANSIM's UE has no handling "
    "for the message, so the UE side is not exercised.")
row("SMF-MOD-03", "PDUSessionResourceModifyRequestTransfer: new session AMBR, QoS flows added / modified, flows to release", "TS 38.413", "9.3.4.3", "tested",
    [U + ("test_policy_update",), E + ("test_policy_update",)], "Encoded with the generated APER schema and decoded again; reaches the gNB through Open5GS's AMF (S4).")
row("SMF-MOD-04", "PCF-initiated termination of the SM policy association releases the PDU session through the AMF and the UE, guarded by a timer", "TS 29.512", "4.2.3.3",
    "tested", [E + ("test_policy_update",)], "Release command with PTI 0 delivered; the release complete frees everything; without it the guard timer does.")
row("SMF-REC-01", "A UPF that restarts (changed Recovery Time Stamp) or stays unreachable is handled: its sessions are released towards the UE / AMF "
    "(release command, status notification), the PCF, UDM and the address pool are cleaned", "TS 29.244", "6.2.2", "tested", [E + ("test_upf_outage",)],
    "The UPF process is stopped and restarted on the same ports; no stale session is left in the SMF, the UPF, the PCF or the pools.")
row("SMF-PAGE-01", "Network-triggered service request: a Downlink Data Report for an idle session becomes an N1N2MessageTransfer with the N2 setup request and no N1 message",
    "TS 23.502", "4.2.3.3", "tested", [E + ("test_happy_path",)], "The AMF receives the transfer after the downlink packet is buffered; the report is acknowledged first.")
row("SMF-PERS-01", "SM contexts survive an SMF restart: state file written atomically after every change, addresses and policy restored, the SMF's own Recovery Time "
    "Stamp kept (a changed stamp would make the UPFs drop its sessions), sessions of a UPF that restarted meanwhile released", "-", "-", "tested",
    [PERSIST + ("test_persistence",)], "Restart with the UPF alive: the restored context deactivates and releases normally. Restart with the UPF restarted in between: "
    "the sessions are released towards the AMF.")
row("SMF-DISC-01", "The AMF is discovered through the NRF by the servingNfId the AMF sent (Nnrf_NFDiscovery, cached for a minute); an unknown AMF falls back to the host of "
    "the smContextStatusUri", "TS 29.510", "5.3.2.2", "tested", [E + ("test_discovery",)],
    "Scripted NRF; against the Open5GS NRF in S3/S4 the SMF registers with smfInfo and the Open5GS AMF finds it.")
row("SMF-IP6-01", "IPv6 router advertisement: the UE's router solicitation is forwarded by the UPF to the SMF (control-plane PDR and FAR with GTP-U to the SMF), the "
    "advertisement with the session's /64 and the MTU goes back through the UPF", "TS 23.501", "5.8.2.2", "tested",
    [U + ("test_router_advertisement",), E + ("test_router_solicitation",)],
    "Checksum, hop limit and type validated as RFC 4861 asks; end to end through the real UPF runtime to the gNB tunnel.")
row("SMF-SEC-02", "Hostile policy pairs and solicitations (identifier assignment, modification builders, router advertisement) never crash", "-", "-", "tested",
    [("fuzz_replay_smf", "fuzz/fuzz_smf.c", "LLVMFuzzerTestOneInput")], "Replay fuzzing with mutations under ASan/UBSan.")

# ---- what is still open --------------------------------------------------------------------------------------------------------------------------
row("SMF-GAP-01", "UE-requested PDU session modification (requested QoS rules / flows, packet filter operations)", "TS 24.501", "6.4.2", "gap", [],
    "A UE modification request is answered with a PDU SESSION MODIFICATION REJECT (cause #31). Network-initiated modification is complete; mapping the UE's request to a "
    "PCF update (UE-initiated resource modification) is not.")
row("SMF-GAP-02", "Charging (CHF / usage reporting URRs), ATSSS, Ethernet and unstructured PDU session types, SSC modes 2 and 3, handover procedures, "
    "I-SMF / V-SMF roles, discovery of UPFs through the NRF", "-", "-", "gap", [],
    "UPFs are configured peers; only SSC mode 1 and IP session types are offered; usage reports from the UPF are not requested.")

doc = {
    "title": "Conformance matrix, Phase 4 (SMF: Nsmf_PDUSession, 5GSM, N2 SM information, N4, modification, recovery, paging, persistence)",
    "note": "Same rules as the other matrices: every test reference, function and clause is checked by tools/check_matrix.py. verified = tests pass and a real "
            "peer or a capture confirms it (Open5GS AMF + UERANSIM against our SMF with our UDM, PCF and UPF, scenarios S1-S4 with OUR_SMF=1). The gap rows are "
            "what the phase leaves out; they are listed so nothing is hidden.",
    "specs": {
        "TS 29.502": "29502-gh0.txt", "TS 29.518": "29518-gj0.txt", "TS 29.244": "29244-gd0.txt", "TS 24.501": "24501-gf0.txt", "TS 24.008": "24008-g70.txt",
        "TS 38.413": "38413-gi0.txt", "TS 23.501": "23501-gk0.txt", "TS 23.502": "23502-gj0.txt", "TS 29.512": "29512-gn0.txt", "TS 29.500": "29500-gf0.txt",
        "TS 29.510": "29510-gf0.txt",
    },
    "rows": rows,
}
(ROOT / "docs" / "conformance" / "phase4-matrix.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf8", newline="\n")
print(len(rows), "rows")
