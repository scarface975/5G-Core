#!/usr/bin/env python3
"""Differential analysis of two SCPs (strategy 4.1, conformance layer): the same requests to a reference SCP (Open5GS's) and to ours, both in front of the same NRF and
the same producer. For every step the HTTP status, the headers the SCP adds, and the body of an answer that comes from the producer are compared.

    python3 tools/diff/scp_diff.py <reference-scp-url> <our-scp-url> <producer-root> <producer-nf-instance-id>

Run by deploy/oracle/scp_diff.sh (which starts both in a private network namespace). Exit status 1 when a difference is not in the allow-lists."""
import json
import subprocess
import sys

NSSF = "/nnssf-nsselection/v2/network-slice-information"
Q = "?nf-type=AMF&nf-id=3a29fd6c-cdee-41f1-a39b-af55908ebd32&slice-info-request-for-pdu-session=%7B%22sNssai%22%3A%7B%22sst%22%3A1%7D%2C%22roamingIndication%22%3A%22NON_ROAMING%22%7D"

# step -> why a different status is accepted
ALLOW_STATUS = {
    "no target and no discovery factors": "the specification gives no status for this; ours is 400 MANDATORY_IE_MISSING (TS 29.500 5.2.7.4), Open5GS's is its own",
    "discovery without a requester type": "as above (ours 400 MANDATORY_IE_MISSING)",
    "discovery without a target type": "as above (ours 400 MANDATORY_IE_MISSING)",
    "unreachable target": "ours is 504 TARGET_NF_NOT_REACHABLE (TS 29.500 6.10.8.2); Open5GS's answer is its own",
}
# headers that only one of them adds and that are not required
IGNORE_HEADERS = {"date", "server", "content-length", "content-type", "vary", "via"}


def call(base, path, headers):
    cmd = ["curl", "-s", "-D", "-", "-o", "/tmp/scpdiff.body", "--http2-prior-knowledge"] + sum([["-H", f"{k}: {v}" if v else f"{k}:"] for k, v in headers.items()], []) + [base + path]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    lines = [l.rstrip("\r") for l in out.split("\n") if l.strip()]
    status = int(lines[0].split()[1]) if lines and lines[0].startswith("HTTP") else 0
    hdr = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            hdr[k.strip().lower()] = v.strip()
    try:
        body = open("/tmp/scpdiff.body").read()
        doc = json.loads(body) if body.strip() else None
    except ValueError:
        doc = None
    return status, hdr, doc


def main():
    ref, ours, producer, pid = sys.argv[1:5]
    steps = [
        ("model C: target apiRoot", NSSF + Q, {"3gpp-Sbi-Target-apiRoot": producer, "User-Agent": "AMF-1"}),
        ("model D: delegated discovery", NSSF + Q, {"3gpp-Sbi-Discovery-target-nf-type": "NSSF", "3gpp-Sbi-Discovery-service-names": "nnssf-nsselection",
                                                    "3gpp-Sbi-Discovery-requester-nf-type": "AMF", "User-Agent": "AMF-1"}),
        ("model D: requester type from the User-Agent", NSSF + Q, {"3gpp-Sbi-Discovery-target-nf-type": "NSSF", "3gpp-Sbi-Discovery-service-names": "nnssf-nsselection",
                                                                   "User-Agent": "AMF-1"}),
        ("model D: instance id", NSSF + Q, {"3gpp-Sbi-Discovery-target-nf-type": "NSSF", "3gpp-Sbi-Discovery-service-names": "nnssf-nsselection",
                                            "3gpp-Sbi-Discovery-target-nf-instance-id": pid, "User-Agent": "AMF-1"}),
        ("target and discovery factors", NSSF + Q, {"3gpp-Sbi-Target-apiRoot": producer, "3gpp-Sbi-Discovery-target-nf-type": "NSSF",
                                                    "3gpp-Sbi-Discovery-service-names": "nnssf-nsselection", "User-Agent": "AMF-1"}),
        ("producer error relayed", NSSF + "?nf-type=AMF", {"3gpp-Sbi-Target-apiRoot": producer, "User-Agent": "AMF-1"}),
        ("unreachable target", NSSF + Q, {"3gpp-Sbi-Target-apiRoot": "http://127.0.0.250:9", "User-Agent": "AMF-1"}),
        ("no target and no discovery factors", NSSF + Q, {"User-Agent": "AMF-1"}),
        ("discovery without a requester type", NSSF + Q, {"3gpp-Sbi-Discovery-target-nf-type": "NSSF", "3gpp-Sbi-Discovery-service-names": "nnssf-nsselection", "User-Agent": ""}),
        ("discovery without a target type", NSSF + Q, {"3gpp-Sbi-Discovery-service-names": "nnssf-nsselection", "User-Agent": "AMF-1"}),
    ]
    failed = 0
    print(f"{'step':50s} {'ref':>4s} {'ours':>5s}  result")
    for name, path, hdrs in steps:
        rs, rh, rd = call(ref, path, hdrs)
        os_, oh, od = call(ours, path, hdrs)
        verdict = []
        if rs != os_ and name not in ALLOW_STATUS:
            verdict.append("FAIL: status differs")
            failed += 1
        elif rs != os_:
            verdict.append("(status differs: " + ALLOW_STATUS[name] + ")")
        else:
            if rs == 200 and rd != od:
                verdict.append("FAIL: the producer's answer differs")
                failed += 1
            # the headers one adds and the other does not (apart from the allow-list)
            only_ref = (set(rh) - set(oh)) - IGNORE_HEADERS
            only_our = (set(oh) - set(rh)) - IGNORE_HEADERS
            if only_ref:
                verdict.append("FAIL: missing in ours: " + ", ".join(sorted(only_ref)))
                failed += 1
            if only_our:
                verdict.append("(extra in ours: " + ", ".join(sorted(only_our)) + ")")
            # TS 29.500 5.2.3.2.8 defines "nfinst=<NF instance id>"; Open5GS's SCP sends the bare id
            rp, op = rh.get("3gpp-sbi-producer-id"), oh.get("3gpp-sbi-producer-id")
            if rp is not None and op is not None:
                if op != "nfinst=" + rp.replace("nfinst=", ""):
                    verdict.append("FAIL: the producer id differs")
                    failed += 1
                elif rp != op:
                    verdict.append("(the producer id: ours is nfinst=<id> as in TS 29.500 5.2.3.2.8, Open5GS's is the bare id)")
        print(f"{name:50s} {rs:4d} {os_:5d}  " + (" ".join(verdict) if verdict else "ok"))
    print(f"\nSCP differential: {failed} difference(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
