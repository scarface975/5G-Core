#!/usr/bin/env python3
"""One-shot patch of tools/gen_dashboard.py and the template for Phase 5 (the AMF). Idempotent."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
gp = ROOT / "tools" / "gen_dashboard.py"
s = gp.read_text(encoding="utf8", newline="")
nl = "\r\n" if "\r\n" in s else "\n"
s = s.replace("\r\n", "\n")


def rep(old, new, count=1):
    global s
    if old not in s:
        raise SystemExit("not found: " + old[:80])
    if new in s:
        return
    s = s.replace(old, new, count)


rep('    (r"^/nsmf-pdusession/", "Nsmf_PDUSession", "TS 29.502 5.2.2"),\n',
    '    (r"^/nsmf-pdusession/", "Nsmf_PDUSession", "TS 29.502 5.2.2"),\n'
    '    (r"^/namf-comm/", "Namf_Communication", "TS 29.518 5.2"),\n'
    '    (r"^/namf-evts/", "Namf_EventExposure", "TS 29.518 5.3"),\n'
    '    (r"^/namf-callback/", "AMF callbacks (SM context status, de-registration, AM policy, subscriber data)", "TS 29.502 / 29.503 / 29.507"),\n')
rep('NF_DIRS = {"udm": ["nf/udm"], "pcf": ["nf/pcf"], "upf": ["nf/upf"], "smf": ["nf/smf"],',
    'NF_DIRS = {"udm": ["nf/udm"], "pcf": ["nf/pcf"], "upf": ["nf/upf"], "smf": ["nf/smf"], "amf": ["nf/amf"],')
rep('("AMF", "AMF", "nf", 300, 250, 5, "planned", "Access and Mobility Management: registration, connection and mobility, NAS security termination (N1/N2).", "TS 23.501 6.2.1"),',
    '("AMF", "AMF", "nf", 300, 250, 5, "built", "Access and Mobility Management: N2 over SCTP, registration, 5G-AKA, NAS security, service request and paging, '
    'de-registration, configuration update, Xn and N2 handover, N1N2 transfer, event exposure, persistence.", "TS 23.501 6.2.1"),')
rep('("N1", "UE", "AMF", "N1", "NAS over N2", "TS 24.501", "codec", "NAS codec (48 messages, security envelope) verified against 33 real MACs and all golden NAS PDUs; the AMF itself is Phase 5."),',
    '("N1", "UE", "AMF", "N1", "NAS over N2", "TS 24.501", "verified", "UERANSIM registers, authenticates, establishes sessions and de-registers through our AMF '
    '(S1-S4); the scripted UE of the end-to-end suite verifies every message with independently derived keys."),')
rep('("N2", "gNB", "AMF", "N2", "NGAP / SCTP", "TS 38.413", "codec", "NGAP codec round-trips all 138 golden PDUs byte-exact; the AMF endpoint is Phase 5."),',
    '("N2", "gNB", "AMF", "N2", "NGAP / SCTP", "TS 38.413", "verified", "UERANSIM\'s gNB sets up, registers UEs and carries sessions through our AMF over '
    'SCTP; scripted gNBs cover paging, service request, Xn path switch and N2 handover."),')
rep('("N8", "AMF", "UDM", "N8", "Nudm_UECM / SDM", "TS 29.503", "verified", "Open5GS AMF registers and reads subscriber data from our UDM in oracle scenarios S3/S4."),',
    '("N8", "AMF", "UDM", "N8", "Nudm_UECM / SDM", "TS 29.503", "verified", "Open5GS\'s AMF (S3/S4) and our AMF (OUR_AMF=1) register and read subscriber data '
    'from our UDM."),')
rep('("N12", "AMF", "AUSF", "N12", "Nausf_UEAuthentication", "TS 29.509", "tested", "ausf-lite verified end to end with a simulated USIM; the real peer in S3/S4 is Open5GS\'s own AUSF."),',
    '("N12", "AMF", "AUSF", "N12", "Nausf_UEAuthentication", "TS 29.509", "verified", "Our AMF authenticates UERANSIM through Open5GS\'s AUSF (S1-S4) '
    'and through ausf-lite (end-to-end suite, with resynchronisation)."),')
rep('("N15", "AMF", "PCF", "N15", "Npcf_AMPolicyControl", "TS 29.507", "tested", "Create/update/delete tested with a mock AMF; real AMF is Phase 5. UpdateNotify toward the AMF is a known gap."),',
    '("N15", "AMF", "PCF", "N15", "Npcf_AMPolicyControl", "TS 29.507", "verified", "Our AMF creates and deletes the AM policy association at our PCF and at '
    'Open5GS\'s PCF (S2-S4); the update / terminate callbacks are accepted."),')
rep('FINDINGS = [\n',
    'FINDINGS = [\n'
    '    ("2026-10-13", "AMF", "medium", "Open5GS\'s PCF refused the AM policy request because the NrLocation carried no ncgi (mandatory in the OpenAPI model).", '
    '"The location JSON always carries tai and ncgi (cell id zero-padded to 9 digits).", "oracle S2 (OUR_AMF=1)"),\n'
    '    ("2026-10-13", "AMF", "medium", "NRF discovery of the SMF with the S-NSSAI as a single JSON object was answered 400 by Open5GS\'s NRF.", '
    '"snssais is sent as a JSON array.", "oracle S2 (OUR_AMF=1)"),\n'
    '    ("2026-10-13", "AMF", "medium", "A UE that failed security mode negotiation (#23) kept a context after the connection was released.", '
    '"Release completion drops every context that never became a registration.", "test_algorithms_and_rejects"),\n'
    '    ("2026-10-13", "AMF", "low", "ThreadSanitizer: gNB slot flags were written under the send mutex and read under the table mutex; UE state counters were read by the '
    'gauges without the UE mutex; the stop flag was a plain bool.", "Nested locking for the slot flags, atomic state fields and stop flag.", "amf_e2e (tsan)"),\n'
    '    ("2026-10-13", "AMF", "low", "AddressSanitizer: a stray temporary of the UE security capabilities leaked in the path switch.", "Removed.", "amf_e2e (asan)"),\n')
gp.write_text(s.replace("\n", nl), encoding="utf8", newline="")

tp = ROOT / "tools" / "dashboard" / "template.html"
t = tp.read_text(encoding="utf8", newline="")
tn = "\r\n" if "\r\n" in t else "\n"
t = t.replace("\r\n", "\n")
old = 'const NF_TITLE = { udm: "UDM", pcf: "PCF", upf: "UPF", smf: "SMF",'
if old in t and 'amf: "AMF"' not in t:
    t = t.replace(old, 'const NF_TITLE = { udm: "UDM", pcf: "PCF", upf: "UPF", smf: "SMF", amf: "AMF",', 1)
old2 = "UDM, PCF, UPF, SMF)"
t = t.replace('Some rooms are finished and lived in (UDM, PCF, UPF, SMF).', 'Some rooms are finished and lived in (UDM, PCF, UPF, SMF, AMF).')
t = t.replace('and the SMF (" + nfs.smf.routes.length + " routes, N4 client, 5GSM and N2 builders, policy-driven modification, recovery, persistence).',
              'and the SMF (" + nfs.smf.routes.length + " routes, N4 client, 5GSM and N2 builders, policy-driven modification, recovery, persistence) and the AMF (N2 over SCTP, 5GMM, NAS security, mobility; "'
              ' + nfs.amf.routes.length + " routes).')
tp.write_text(t.replace("\n", tn), encoding="utf8", newline="")
print("patched")
