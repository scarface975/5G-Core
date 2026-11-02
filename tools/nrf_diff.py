#!/usr/bin/env python3
"""Differential analysis of two NRFs (strategy 4.1, conformance layer): the same requests, once to a reference NRF (Open5GS's) and once to ours.
For every step the HTTP status codes and the set of top-level JSON attributes of the answers are compared (the values differ: identifiers, timers).

    python3 tools/nrf_diff.py <reference-base-url> <our-base-url>

Run by deploy/oracle/nrf_diff.sh (which starts both in a private network namespace). Needs curl with HTTP/2 prior knowledge. Exit status 1 when a status
code differs or when our answer leaves out an attribute the reference's carries (apart from the documented allow-list)."""
import json
import subprocess
import sys

SMF_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
AMF_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

SMF_PROFILE = {
    "nfInstanceId": SMF_ID, "nfType": "SMF", "nfStatus": "REGISTERED", "heartBeatTimer": 10,
    "ipv4Addresses": ["127.0.0.4"], "allowedNfTypes": ["AMF"],
    "nfServices": [{"serviceInstanceId": "1", "serviceName": "nsmf-pdusession", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "127.0.0.4", "port": 7777}],
                    "allowedNfTypes": ["AMF"]}],
    "smfInfo": {"sNssaiSmfInfoList": [{"sNssai": {"sst": 1}, "dnnSmfInfoList": [{"dnn": "internet"}]}]},
}
AMF_PROFILE = {"nfInstanceId": AMF_ID, "nfType": "AMF", "nfStatus": "REGISTERED", "ipv4Addresses": ["127.0.0.5"],
               "nfServices": [{"serviceInstanceId": "1", "serviceName": "namf-comm", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                               "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "127.0.0.5", "port": 7777}]}]}

# attributes the reference includes in a response and ours does not, by step name -> why it is accepted
# - ProblemDetails "type" and "instance" are optional members (TS 29.571 5.2.4.1); ours carries status, title, detail, cause and invalidParams.
# - "nfServiceList" in a retrieval: TS 29.510 6.1.6.2.2 NOTE 15 - the map is returned only to a consumer that indicated the Service-Map feature, the
#   array otherwise; the reference answers with the map without being asked.
ALLOW_MISSING = {
    "retrieve SMF": {"nfServiceList"},
    "retrieve unknown": {"instance", "type"},
    "heart-beat unknown": {"instance", "type"},
    "discover without requester type": {"instance", "type"},
    "deregister SMF again": {"instance", "type"},
}
# attributes ours includes that the reference does not (informational only)
SHOW_EXTRA = True


def call(base, method, path, body=None, ctype="application/json"):
    cmd = ["curl", "-s", "--http2-prior-knowledge", "-o", "-", "-w", "\n%{http_code}", "-X", method, base + path]
    if body is not None:
        cmd += ["-H", "content-type: " + ctype, "-d", json.dumps(body)]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    text, _, code = out.rpartition("\n")
    try:
        j = json.loads(text) if text.strip() else None
    except ValueError:
        j = None
    return int(code or 0), j


def keys_of(j):
    if isinstance(j, dict):
        return set(j.keys())
    if isinstance(j, list):
        return {"[]"}
    return set()


def first_instance(j):
    items = (j or {}).get("nfInstances") if isinstance(j, dict) else None
    return items[0] if items else None


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    ref, ours = argv
    steps = []
    nfm = "/nnrf-nfm/v1/nf-instances/"
    disc = "/nnrf-disc/v1/nf-instances"
    steps.append(("register SMF", "PUT", nfm + SMF_ID, SMF_PROFILE))
    steps.append(("register SMF again (replace)", "PUT", nfm + SMF_ID, SMF_PROFILE))
    steps.append(("register AMF", "PUT", nfm + AMF_ID, AMF_PROFILE))
    steps.append(("retrieve SMF", "GET", nfm + SMF_ID, None))
    steps.append(("retrieve unknown", "GET", nfm + "cccccccc-cccc-4ccc-8ccc-cccccccccccc", None))
    steps.append(("list SMF", "GET", nfm + "?nf-type=SMF" if False else "/nnrf-nfm/v1/nf-instances?nf-type=SMF", None))
    steps.append(("heart-beat", "PATCH", nfm + SMF_ID, [{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"}]))
    steps.append(("heart-beat unknown", "PATCH", nfm + "cccccccc-cccc-4ccc-8ccc-cccccccccccc", [{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"}]))
    steps.append(("discover SMF by service", "GET", disc + "?target-nf-type=SMF&requester-nf-type=AMF&service-names=nsmf-pdusession", None))
    steps.append(("discover SMF by DNN", "GET", disc + "?target-nf-type=SMF&requester-nf-type=AMF&dnn=internet", None))
    steps.append(("discover SMF by slice (object)", "GET", disc + "?target-nf-type=SMF&requester-nf-type=AMF&snssais=%7B%22sst%22%3A1%7D", None))
    steps.append(("discover SMF by slice (array)", "GET", disc + "?target-nf-type=SMF&requester-nf-type=AMF&snssais=%5B%7B%22sst%22%3A1%7D%5D", None))
    steps.append(("discover SMF by slice and DNN", "GET", disc + "?target-nf-type=SMF&requester-nf-type=AMF&dnn=internet&snssais=%7B%22sst%22%3A1%7D", None))
    steps.append(("discover without requester type", "GET", disc + "?target-nf-type=SMF", None))
    steps.append(("discover no match", "GET", disc + "?target-nf-type=UDR&requester-nf-type=AMF", None))
    steps.append(("subscribe", "POST", "/nnrf-nfm/v1/subscriptions",
                  {"nfStatusNotificationUri": "http://127.0.0.1:9/cb", "subscrCond": {"nfType": "SMF"}, "reqNfType": "AMF"}))
    steps.append(("deregister SMF", "DELETE", nfm + SMF_ID, None))
    steps.append(("deregister SMF again", "DELETE", nfm + SMF_ID, None))
    steps.append(("discover after deregistration", "GET", disc + "?target-nf-type=SMF&requester-nf-type=AMF", None))
    bad = 0
    print("%-34s %-6s %-6s  %s" % ("step", "ref", "ours", "attributes"))
    sub_ref = sub_ours = None
    for name, method, path, body in steps:
        r_code, r_json = call(ref, method, path, body, "application/json-patch+json" if method == "PATCH" else "application/json")
        o_code, o_json = call(ours, method, path, body, "application/json-patch+json" if method == "PATCH" else "application/json")
        rk, ok = keys_of(r_json), keys_of(o_json)
        if name.startswith("discover") and r_code == 200 and o_code == 200:
            ri, oi = first_instance(r_json), first_instance(o_json)
            if ri is not None and oi is not None:
                rk, ok = rk | {"instance." + k for k in ri}, ok | {"instance." + k for k in oi}
            elif (ri is None) != (oi is None):
                print("%-34s %-6s %-6s  FAIL: one result is empty, the other is not" % (name, r_code, o_code))
                bad += 1
                continue
        line = "%-34s %-6s %-6s " % (name, r_code, o_code)
        problems = []
        if r_code != o_code:
            problems.append("STATUS DIFFERS")
        missing = rk - ok - set(ALLOW_MISSING.get(name, ()))
        if missing:
            problems.append("missing in ours: " + ", ".join(sorted(missing)))
        extra = ok - rk
        if extra and SHOW_EXTRA:
            line += "(extra in ours: %s) " % ", ".join(sorted(extra))
        print(line + ("FAIL: " + "; ".join(problems) if problems else "ok"))
        if problems:
            bad += 1
    print("NRF differential: %s" % ("OK" if bad == 0 else "%d differences" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
