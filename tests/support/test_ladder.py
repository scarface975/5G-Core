#!/usr/bin/env python3
"""tools/g5c-ladder: ladders per UE and per N4 session from tshark rows, the red flags (no SMC, unanswered requests, malformed, retransmission, rejects), and a real capture when one is at hand."""
import importlib.machinery
import importlib.util
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
loader = importlib.machinery.SourceFileLoader("g5c_ladder", str(ROOT / "tools" / "g5c-ladder"))
spec = importlib.util.spec_from_loader("g5c_ladder", loader)
ld = importlib.util.module_from_spec(spec)
loader.exec_module(ld)


def row(n, t, src, dst, proto, info, ran="", amf="", seid="", retx="", seq=""):
    return "\t".join([str(n), str(t), src, dst, proto, info, ran, amf, seid, retx, seq])


GOOD = [
    row(1, 0.0, "10.0.0.1", "10.0.0.5", "NGAP", "NGSetupRequest"), row(2, 0.1, "10.0.0.5", "10.0.0.1", "NGAP", "NGSetupResponse"),
    row(3, 1.0, "10.0.0.1", "10.0.0.5", "NGAP/NAS-5GS", "InitialUEMessage, Registration request", ran="7"),
    row(4, 1.1, "10.0.0.5", "10.0.0.1", "NGAP/NAS-5GS", "SACK (Ack=1, Arwnd=1) , DownlinkNASTransport, Authentication request", ran="7", amf="2"),
    row(5, 1.2, "10.0.0.1", "10.0.0.5", "NGAP/NAS-5GS", "UplinkNASTransport, Authentication response", ran="7", amf="2"),
    row(6, 1.3, "10.0.0.5", "10.0.0.1", "NGAP/NAS-5GS", "DownlinkNASTransport, Security mode command", ran="7", amf="2"),
    row(7, 1.4, "10.0.0.5", "10.0.0.1", "NGAP", "InitialContextSetupRequest", ran="7", amf="2"),
    row(8, 1.5, "10.0.0.1", "10.0.0.5", "NGAP", "InitialContextSetupResponse", ran="7", amf="2"),
    row(9, 1.6, "10.0.0.4", "10.0.0.7", "PFCP", "PFCP Session Establishment Request", seid="0x0,0x11", seq="5"),
    row(10, 1.7, "10.0.0.7", "10.0.0.4", "PFCP", "PFCP Session Establishment Response", seid="0x11,0x22", seq="5"),
    row(11, 2.0, "10.0.0.4", "10.0.0.7", "PFCP", "PFCP Heartbeat Request", seq="9"),
]


def analyse(lines):
    rows = ld.parse_rows("\n".join(lines))
    return ld.text_report(rows)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    text, found = analyse(GOOD)
    check("a clean registration has no findings", found == [], found)
    check("noise (SACK) is removed from the ladder and heart-beats are not listed", "SACK" not in text and "Heartbeat" not in text and "ladders: 3" in text, text)
    check("the UE ladder is keyed by gNB and RAN UE id; the NG setup has its own", "UE 10.0.0.1 ran-ue-id 7  (6 messages)" in text and "NG setup" in text, text)
    nosmc = [r for r in GOOD if "Security mode" not in r]
    text, found = analyse(nosmc)
    check("no Security Mode Command before the Initial Context Setup is a high finding naming the matrix", any(s == "high" and "Security Mode Command" in m for s, m, _ in found), found)
    noauth = [r for r in GOOD if "Authentication" not in r]
    check("no Authentication request is a high finding", any("Authentication request" in m for s, m, _ in analyse(noauth)[1]))
    unanswered = [r for r in GOOD if "InitialContextSetupResponse" not in r]
    check("an unanswered Initial Context Setup is flagged", any("InitialContextSetupRequest not answered" in m for _, m, _ in analyse(unanswered)[1]))
    lone = [r for r in GOOD if "Establishment Response" not in r]
    check("a PFCP request without a response is flagged with its sequence number", any("sequence 5" in m for _, m, _ in analyse(lone)[1]))
    mal = [r.replace("Establishment Request", "Establishment Request[Malformed Packet]") for r in GOOD]
    check("a malformed message is flagged (Wireshark glues the marker to the name)", any("Malformed" in m for _, m, _ in analyse(mal)[1]))
    retx = list(GOOD)
    retx[4] = row(5, 1.2, "10.0.0.1", "10.0.0.5", "NGAP/NAS-5GS", "DATA (TSN=4) (retransmission) , UplinkNASTransport", ran="7", amf="2")
    check("an SCTP retransmission is a low finding", [s for s, _, _ in analyse(retx)[1]] == ["low"], analyse(retx)[1])
    rej = [r.replace("Authentication response", "Registration reject") for r in GOOD]
    check("a reject in the flow is flagged", any("eject" in m for _, m, _ in analyse(rej)[1]))
    check("the HTML page is produced", "<h2>" in ld.html_report(ld.parse_rows("\n".join(GOOD))))
    # a real capture, when the tool and a file are at hand: the SMF's PFCP of the capture of 2026-10-28 carried a malformed S-NSSAI (fixed since), and nothing else was wrong
    cap = os.environ.get("G5C_LADDER_CAPTURE", "/mnt/c/Users/Work/Downloads/5g_signaling.pcapng")
    if shutil.which("tshark") and Path(cap).exists():
        rows = ld.parse_rows(ld.run_tshark(cap))
        _, found = ld.text_report(rows)
        highs = [m for s, m, _ in found if s == "high"]
        check("real capture: exactly the malformed PFCP is a high finding", len(highs) == 1 and "Malformed" in highs[0], highs)
    print("ladder: PASS" if ok else "ladder: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
