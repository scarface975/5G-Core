#!/usr/bin/env python3
"""Differential analysis of two AUSFs (strategy 4.1, conformance layer): the same requests, once to a reference AUSF (Open5GS's) and once to ours, both behind the
same UDM. For every step the HTTP status codes and the sets of JSON attributes (top level, 5gAuthData, _links) of the answers are compared; the values differ
(identifiers, vectors).

    python3 tools/ausf_diff.py <reference-base-url> <our-base-url>

Run by deploy/oracle/ausf_diff.sh (which starts both in a private network namespace). Needs curl with HTTP/2 prior knowledge. Exit status 1 when a status code
differs or when our answer leaves out an attribute the reference's carries (apart from the documented allow-list)."""
import json
import re
import subprocess
import sys

SNN = "5G:mnc001.mcc001.3gppnetwork.org"
SUPI = "imsi-001010000000001"
SUCI = "suci-0-001-01-0000-0-0-0000000001"
BASE = "/nausf-auth/v1/ue-authentications"

# attributes the reference includes in a response and ours does not, by step name -> why it is accepted
# - ProblemDetails "type" and "instance" are optional members (TS 29.571 5.2.4.1); ours carries status, title, detail, cause and invalidParams.
# - the reference puts a "kseaf" into the answer to a failed confirmation; TS 29.509 6.1.6.2.8 has it only when the authentication succeeded (ours leaves it out).
ALLOW_MISSING = {
    "confirm with a wrong RES*": {"kseaf"},
    "confirm an unknown context": {"instance", "type"},
    "delete the result of an unknown context": {"instance", "type"},
}
# status codes that may differ, by step name
# - the reference answers a second confirmation of the same context again; TS 29.509 6.1.3.3.1 says the 5g-aka-confirmation sub-resource "should not persist after
#   the AUSF has read its content": ours answers 404 CONTEXT_NOT_FOUND, which also makes a replayed RES* worthless.
ALLOW_STATUS = {"confirm again (single use)"}


def call(base, method, path, body=None):
    cmd = ["curl", "-s", "--http2-prior-knowledge", "-o", "-", "-w", "\n%{http_code}", "-X", method, base + path]
    if body is not None:
        cmd += ["-H", "content-type: application/json", "-d", body if isinstance(body, str) else json.dumps(body)]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    text, _, code = out.rpartition("\n")
    try:
        j = json.loads(text) if text.strip() else None
    except ValueError:
        j = None
    return int(code or 0), j


def keys_of(j):
    ks = set()
    if isinstance(j, dict):
        for k, v in j.items():
            ks.add(k)
            if k in ("5gAuthData", "_links") and isinstance(v, dict):
                for kk, vv in v.items():
                    ks.add(k + "." + kk)
                    if isinstance(vv, dict):
                        ks.update(k + "." + kk + "." + x for x in vv)
    return ks


def ctx_path(j):
    href = ((j or {}).get("_links") or {}).get("5g-aka", {}).get("href", "")
    return re.sub(r"^https?://[^/]+", "", href)


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    bases = {"ref": argv[0], "ours": argv[1]}
    ctx = {"ref": "/nausf-auth/v1/ue-authentications/none/5g-aka-confirmation", "ours": "/nausf-auth/v1/ue-authentications/none/5g-aka-confirmation"}
    zero = "0" * 32
    steps = [
        ("start with a SUPI", "POST", BASE, {"supiOrSuci": SUPI, "servingNetworkName": SNN}, "save"),
        ("start with a SUCI (null scheme)", "POST", BASE, {"supiOrSuci": SUCI, "servingNetworkName": SNN}, None),
        ("start with an unknown subscriber", "POST", BASE, {"supiOrSuci": "imsi-001010000000099", "servingNetworkName": SNN}, None),
        ("start without a serving network name", "POST", BASE, {"supiOrSuci": SUPI}, None),
        ("start without an identity", "POST", BASE, {"servingNetworkName": SNN}, None),
        ("start with a malformed body", "POST", BASE, "{", None),
        ("start with a malformed serving network name", "POST", BASE, {"supiOrSuci": SUPI, "servingNetworkName": "evil.example.org"}, None),
        ("confirm with a wrong RES*", "PUT", "{CTX}", {"resStar": zero}, None),
        ("confirm again (single use)", "PUT", "{CTX}", {"resStar": zero}, None),
        ("confirm an unknown context", "PUT", BASE + "/00000000-0000-4000-8000-000000000000/5g-aka-confirmation", {"resStar": zero}, None),
        ("confirm without RES*", "PUT", BASE + "/00000000-0000-4000-8000-000000000000/5g-aka-confirmation", {}, None),
        ("delete the result of an unknown context", "DELETE", BASE + "/00000000-0000-4000-8000-000000000000/5g-aka-confirmation", None, None),
    ]
    bad = 0
    print("%-46s %-6s %-6s  %s" % ("step", "ref", "ours", "attributes"))
    for name, method, path, body, mode in steps:
        res = {}
        for who in ("ref", "ours"):
            p = ctx[who] if path == "{CTX}" else path
            res[who] = call(bases[who], method, p, body)
            if mode == "save" and res[who][0] == 201:
                ctx[who] = ctx_path(res[who][1])
        (rc, rj), (oc, oj) = res["ref"], res["ours"]
        rk, ok = keys_of(rj), keys_of(oj)
        problems = []
        if rc != oc:
            problems.append("STATUS DIFFERS")
        missing = rk - ok - set(ALLOW_MISSING.get(name, ()))
        if missing and rc == oc:
            problems.append("missing in ours: " + ", ".join(sorted(missing)))
        extra = ok - rk
        line = "%-46s %-6s %-6s " % (name, rc, oc)
        if extra:
            line += "(extra in ours: %s) " % ", ".join(sorted(extra))
        if problems and name in ALLOW_STATUS:
            line += "(accepted difference) "
            problems = []
        print(line + ("FAIL: " + "; ".join(problems) if problems else "ok"))
        if problems:
            bad += 1
    print("AUSF differential: %s" % ("OK" if bad == 0 else "%d differences" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
