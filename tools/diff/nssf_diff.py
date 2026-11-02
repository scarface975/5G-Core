#!/usr/bin/env python3
"""Differential analysis of two NSSFs (strategy 4.1, conformance layer): the same Nnssf_NSSelection requests to a reference NSSF (Open5GS's) and to ours, both
configured with the same slices. For every step the HTTP status and the sets of JSON attributes of the answers are compared; the values must be equal where
the answer is the NSI information (the NRF of the slice).

    python3 tools/diff/nssf_diff.py <reference-base-url> <our-base-url>

Run by deploy/oracle/nssf_diff.sh (which starts both in a private network namespace). Open5GS's NSSF implements the PDU session procedure only; the other
procedures are run against ours alone and listed as such. Exit status 1 when a status differs or a value or attribute differs apart from the allow-lists."""
import json
import subprocess
import sys
import urllib.parse as up

ROOT = "/nnssf-nsselection/v2/network-slice-information"
TAI = {"plmnId": {"mcc": "001", "mnc": "01"}, "tac": "000001"}

# step -> why a different status is accepted
ALLOW_STATUS = {
    "registration request": "Open5GS answers 400 (\"Not implemented except PDU session\"); the registration procedure is implemented here (TS 29.531 5.2.2.2.2)",
    "UE configuration update request": "as above (5.2.2.2.4)",
    "PDN connection request": "as above (5.2.2.2.5)",
    "unknown slice": None,
}
# step -> attributes the reference includes and ours does not
ALLOW_MISSING = {
    "unknown slice": {"type", "instance"},          # optional members of ProblemDetails (TS 29.571 5.2.4.1)
    "no nf-id": {"type", "instance"},
    "no nf-type": {"type", "instance"},
    "no slice information": {"type", "instance"},
}
EXTRA_OK = {"cause", "invalidParams", "detail"}


def call(base, query):
    cmd = ["curl", "-s", "--http2-prior-knowledge", "-o", "-", "-w", "\n%{http_code}", base + ROOT + "?" + query]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    text, _, code = out.rpartition("\n")
    try:
        doc = json.loads(text) if text.strip() else None
    except ValueError:
        doc = None
    return int(code or 0), doc


def attrs(doc, prefix=""):
    out = set()
    if isinstance(doc, dict):
        for k, v in doc.items():
            out.add(prefix + k)
            if isinstance(v, dict):
                out |= attrs(v, prefix + k + ".")
    return out


def j(o):
    return up.quote(json.dumps(o, separators=(",", ":")), safe="")


def main():
    ref, ours = sys.argv[1], sys.argv[2]
    nf = "nf-type=AMF&nf-id=3a29fd6c-cdee-41f1-a39b-af55908ebd32"
    pdu = lambda sn, ri="NON_ROAMING", extra="": f"{nf}&slice-info-request-for-pdu-session={j({'sNssai': sn, 'roamingIndication': ri})}{extra}"
    steps = [
        ("PDU session, slice 1", pdu({"sst": 1})),
        ("PDU session, slice 1 with sd FFFFFF", pdu({"sst": 1, "sd": "ffffff"})),
        ("PDU session, slice 2 sd 000001", pdu({"sst": 2, "sd": "000001"})),
        ("PDU session, tracking area given", pdu({"sst": 1}, extra="&tai=" + j(TAI))),
        ("PDU session, local breakout", pdu({"sst": 1}, "LOCAL_BREAKOUT")),
        ("unknown slice", pdu({"sst": 77})),
        ("no nf-id", "nf-type=AMF&slice-info-request-for-pdu-session=" + j({"sNssai": {"sst": 1}, "roamingIndication": "NON_ROAMING"})),
        ("no nf-type", "nf-id=3a29fd6c-cdee-41f1-a39b-af55908ebd32&slice-info-request-for-pdu-session=" + j({"sNssai": {"sst": 1}, "roamingIndication": "NON_ROAMING"})),
        ("no slice information", nf),
        ("registration request", f"{nf}&slice-info-request-for-registration={j({'requestedNssai': [{'sst': 1}], 'subscribedNssai': [{'subscribedSnssai': {'sst': 1}, 'defaultIndication': True}]})}&tai={j(TAI)}"),
        ("UE configuration update request", f"{nf}&slice-info-request-for-ue-cu={j({'subscribedNssai': [{'subscribedSnssai': {'sst': 1}}]})}&tai={j(TAI)}"),
        ("PDN connection request", f"nf-type=SMF&nf-id=3a29fd6c-cdee-41f1-a39b-af55908ebd32&slice-info-request-for-pdn-connection={j([{'sst': 1}])}&home-plmn-id={j({'mcc': '310', 'mnc': '260'})}"),
    ]
    failed = 0
    print(f"{'step':40s} {'ref':>4s} {'ours':>5s}  result")
    for name, q in steps:
        rs, rd = call(ref, q)
        os_, od = call(ours, q)
        verdict = []
        if rs != os_ and name not in ALLOW_STATUS:
            verdict.append("FAIL: status differs")
            failed += 1
        elif rs != os_:
            verdict.append("(status differs: " + ALLOW_STATUS[name] + ")")
        elif rs == 200:
            rn = (rd or {}).get("nsiInformation", {})
            on = (od or {}).get("nsiInformation", {})
            if rn.get("nrfId") != on.get("nrfId"):
                verdict.append(f"FAIL: nrfId {rn.get('nrfId')} vs {on.get('nrfId')}")
                failed += 1
            miss = (attrs(rd) - attrs(od)) - {"nsiInformation.nsiId"}  # optional; Open5GS numbers its slice instances, ours are named in the configuration
            if miss:
                verdict.append("FAIL: missing in ours: " + ", ".join(sorted(miss)))
                failed += 1
        elif rs != 200:
            miss = (attrs(rd) - attrs(od)) - ALLOW_MISSING.get(name, set())
            if miss:
                verdict.append("FAIL: missing in ours: " + ", ".join(sorted(miss)))
                failed += 1
            extra = (attrs(od) - attrs(rd)) - EXTRA_OK
            if extra:
                verdict.append("(extra in ours: " + ", ".join(sorted(extra)) + ")")
        print(f"{name:40s} {rs:4d} {os_:5d}  " + (" ".join(verdict) if verdict else "ok"))
    print(f"\nNSSF differential: {failed} difference(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
