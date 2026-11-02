#!/usr/bin/env python3
"""Differential analysis of two UDRs (strategy 4.1, conformance layer): the same requests to a reference UDR (Open5GS's, over MongoDB) and to ours.

    python3 tools/udr_diff.py <reference-base-url> <our-base-url> <our-provisioning-token>

Both hold the same subscriber. The documents the reference returns are written into ours through the provisioning extension first (that is also a test:
ours has to accept what a deployed UDR serves, apart from the documented exceptions), then the same operations go to both. For every step the HTTP status
and the sets of JSON attributes of the answers are compared; the values differ (revisions, SQN handling, identifiers). Run by deploy/oracle/udr_diff.sh,
which starts both in a private network namespace. Needs curl with HTTP/2 prior knowledge. Exit status 1 when a status differs or when our answer leaves
out an attribute that the reference's carries, apart from the allow-lists below, each with the reason."""
import json
import subprocess
import sys

SUPI = "imsi-001010000000001"
PLMN = "00101"
SD = "/subscription-data/" + SUPI

# a step -> why a different status is accepted
ALLOW_STATUS = {
    "PUT amf-3gpp-access (create)": "TS 29.504 5.2.2.3.2: the creation of a resource by PUT is answered 201 with the representation and a Location; Open5GS answers 204",
    "PUT smf-registration (create)": "as above",
    "GET amf-3gpp-access": "the registration is readable (TS 29.505 6.1.3.x GET); Open5GS has no GET for it (405)",
    "GET smf-registrations (list)": "as above: the list of SMF registrations is readable; Open5GS answers 405",
    "GET context-data (composite)": "ContextDataSets is a resource of TS 29.505; Open5GS answers 405",
    "GET unknown resource name": "an unknown resource is 404 (TS 29.500 5.2.7.2); Open5GS answers 400",
    "GET identity-data": "identity-data is a resource of TS 29.505; Open5GS answers 400 (unknown resource name)",
    "GET sdm-subscriptions": "sdm-subscriptions is a resource of TS 29.505; Open5GS answers 400 (unknown resource name)",
    "GET policy sm-data, slice not provisioned": "no data for the slice is 404 DATA_NOT_FOUND (TS 29.519); Open5GS answers 400",
    "GET policy sm-data without a slice": "without ?snssai the whole SmPolicyData is returned; Open5GS requires the parameter (400)",
    "GET policy sm-data/{usageMonId}": "the resource of TS 29.519; Open5GS answers 400",
    "GET policy operator-specific-data": "a resource of TS 29.519; Open5GS answers 405",
    "GET policy ue-policy-set": "a resource of TS 29.519; Open5GS answers 405",
    "GET subs-to-notify": "subscriptions are a resource of TS 29.505; Open5GS answers 400 (unknown resource name)",
}
# a step -> attributes the reference includes and ours does not, with the reason
# - ProblemDetails `type` and `instance` are optional members (TS 29.571 5.2.4.1); ours carries status, title, detail and cause.
# - the reference puts the SM data of ProvisionedDataSets in an object { "SessionManagementSubscriptionDataList": [...] }; the member smData of TS 29.505 is an
#   array of SessionManagementSubscriptionData (ours).
ALLOW_MISSING = {
    "GET unknown subscriber": {"type", "instance"},
    "GET unknown subscriber policy am-data": {"type", "instance"},
    "GET sm-data, other slice": {"type", "instance"},
    "GET provisioned-data": {"smData.SessionManagementSubscriptionDataList"},
}
# a step -> attributes ours carries in addition (reported, not a failure): `cause` of ProblemDetails
EXPECTED_EXTRA = {"cause", "detail", "supportedFeatures", "smData.[]dnnConfigurations", "smData.[]singleNssai"}


def call(base, method, path, body=None, ctype="application/json", token=None):
    cmd = ["curl", "-s", "--http2-prior-knowledge", "-o", "-", "-w", "\n%{http_code}", "-X", method, base + path]
    if body is not None:
        cmd += ["-H", "content-type: " + ctype, "-d", body if isinstance(body, str) else json.dumps(body)]
    if token:
        cmd += ["-H", "authorization: Bearer " + token]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
    text, _, code = out.rpartition("\n")
    try:
        doc = json.loads(text) if text.strip() else None
    except ValueError:
        doc = None
    return int(code or 0), doc


def attrs(doc, depth=2, prefix=""):
    """Set of attribute paths (objects to `depth` levels; a list is looked into through its first element)."""
    out = set()
    if isinstance(doc, list) and doc:
        return attrs(doc[0], depth, prefix + "[]")
    if isinstance(doc, dict):
        for k, v in doc.items():
            out.add(prefix + k)
            if depth > 1 and isinstance(v, (dict, list)):
                out |= attrs(v, depth - 1, prefix + k + ".")
    return out


def main():
    ref, ours, token = sys.argv[1], sys.argv[2], sys.argv[3]
    failed = 0
    notes = []

    # 1. what the reference holds, written into ours (the provisioning extension)
    print("provisioning ours with the documents of the reference:")
    for name, path in [("authentication subscription", SD + "/authentication-data/authentication-subscription"),
                       ("am-data", SD + f"/{PLMN}/provisioned-data/am-data"),
                       ("smf-selection", SD + f"/{PLMN}/provisioned-data/smf-selection-subscription-data"),
                       ("sm-data", SD + f"/{PLMN}/provisioned-data/sm-data?single-nssai=%7B%22sst%22%3A1%2C%22sd%22%3A%22ffffff%22%7D&dnn=internet")]:
        st, doc = call(ref, "GET", "/nudr-dr/v1" + path)
        assert st == 200 and doc is not None, f"reference {name}: {st}"
        # the reference lists all three SSC modes as allowed, TS 29.503 allows two besides the default (maxItems 2): a known deviation of the reference
        if isinstance(doc, list):
            for e in doc:
                for dc in (e.get("dnnConfigurations") or {}).values():
                    ssc = dc.get("sscModes", {})
                    if len(ssc.get("allowedSscModes", [])) > 2:
                        ssc["allowedSscModes"] = [m for m in ssc["allowedSscModes"] if m != ssc.get("defaultSscMode")]
                        notes.append("sm-data: the reference's allowedSscModes has three entries (maxItems is 2); the default mode was left out before writing it into ours")
        wpath = path.split("?")[0]
        wst, wdoc = call(ours, "PUT", "/nudr-dr/v1" + wpath, doc, token=token)
        ok = wst in (201, 204)
        print(f"  {name:28s} reference 200 -> ours PUT {wst} {'ok' if ok else 'FAIL ' + json.dumps(wdoc)}")
        failed += 0 if ok else 1
    for name, path, body in [("policy am-data", "/policy-data/ues/" + SUPI + "/am-data", None),
                             ("policy sm-data", "/policy-data/ues/" + SUPI + "/sm-data?snssai=%7B%22sst%22%3A1%7D&dnn=internet", None)]:
        st, doc = call(ref, "GET", "/nudr-dr/v1" + path)
        assert st == 200, f"reference {name}: {st}"
        wst, wdoc = call(ours, "PUT", "/nudr-dr/v1" + path.split("?")[0], doc, token=token)
        print(f"  {name:28s} reference 200 -> ours PUT {wst} {'ok' if wst in (201, 204) else 'FAIL ' + json.dumps(wdoc)}")
        failed += 0 if wst in (201, 204) else 1

    # 2. the same operations to both
    def snssai(sst, sd=None):
        d = {"sst": sst}
        if sd:
            d["sd"] = sd
        return json.dumps(d, separators=(",", ":"))

    import urllib.parse as up
    q = lambda s: up.quote(s, safe="")
    amf_reg = {"amfInstanceId": "7a1d3b52-0a0e-4c3c-9d57-5b2a3f6f1a10", "deregCallbackUri": "http://amf.example/dereg",
               "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "010203"}, "ratType": "NR"}
    smf_reg = {"smfInstanceId": "3f1a8c1e-8b8e-4b7e-9c0a-111111111111", "pduSessionId": 1, "singleNssai": {"sst": 1}, "plmnId": {"mcc": "001", "mnc": "01"}}
    status_ev = {"nfInstanceId": "c22f4910-cc36-43e1-a33e-e213b6aba908", "success": True, "timeStamp": "2026-10-22T10:00:00Z", "authType": "5G_AKA",
                 "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"}
    P = "/policy-data/ues/" + SUPI
    steps = [
        ("GET authentication subscription", "GET", SD + "/authentication-data/authentication-subscription", None),
        ("GET unknown subscriber", "GET", "/subscription-data/imsi-999990000000009/authentication-data/authentication-subscription", None),
        ("GET am-data", "GET", SD + f"/{PLMN}/provisioned-data/am-data", None),
        ("GET am-data, fields=nssai", "GET", SD + f"/{PLMN}/provisioned-data/am-data?fields=nssai", None),
        ("GET sm-data, slice and DNN", "GET", SD + f"/{PLMN}/provisioned-data/sm-data?single-nssai={q(snssai(1, 'ffffff'))}&dnn=internet", None),
        ("GET sm-data, other slice", "GET", SD + f"/{PLMN}/provisioned-data/sm-data?single-nssai={q(snssai(2))}&dnn=internet", None),
        ("GET smf-selection", "GET", SD + f"/{PLMN}/provisioned-data/smf-selection-subscription-data", None),
        ("GET provisioned-data", "GET", SD + f"/{PLMN}/provisioned-data", None),
        ("PATCH authentication subscription", "PATCH", SD + "/authentication-data/authentication-subscription",
         [{"op": "replace", "path": "/sequenceNumber/sqn", "value": "000000000040"}], "application/json-patch+json"),
        ("PUT authentication-status", "PUT", SD + "/authentication-data/authentication-status", status_ev),
        ("PUT amf-3gpp-access (create)", "PUT", SD + "/context-data/amf-3gpp-access", amf_reg),
        ("GET amf-3gpp-access", "GET", SD + "/context-data/amf-3gpp-access", None),
        ("PUT smf-registration (create)", "PUT", SD + "/context-data/smf-registrations/1", smf_reg),
        ("GET smf-registrations (list)", "GET", SD + "/context-data/smf-registrations", None),
        ("GET context-data (composite)", "GET", SD + "/context-data", None),
        ("DELETE smf-registration", "DELETE", SD + "/context-data/smf-registrations/1", None),
        ("GET unknown resource name", "GET", SD + "/nothing", None),
        ("GET identity-data", "GET", SD + "/identity-data", None),
        ("GET sdm-subscriptions", "GET", SD + "/sdm-subscriptions", None),
        ("GET subs-to-notify", "GET", "/subscription-data/subs-to-notify", None),
        ("GET policy am-data", "GET", P + "/am-data", None),
        ("GET unknown subscriber policy am-data", "GET", "/policy-data/ues/imsi-777/am-data", None),
        ("GET policy sm-data, slice and DNN", "GET", P + f"/sm-data?snssai={q(snssai(1))}&dnn=internet", None),
        ("GET policy sm-data, slice not provisioned", "GET", P + f"/sm-data?snssai={q(snssai(2))}&dnn=internet", None),
        ("GET policy sm-data without a slice", "GET", P + "/sm-data", None),
        ("GET policy sm-data/{usageMonId}", "GET", P + "/sm-data/abc", None),
        ("GET policy operator-specific-data", "GET", P + "/operator-specific-data", None),
        ("GET policy ue-policy-set", "GET", P + "/ue-policy-set", None),
    ]
    print(f"\n{'step':46s} {'ref':>4s} {'ours':>5s}  attributes")
    for step in steps:
        name, method, path, body = step[:4]
        ctype = step[4] if len(step) > 4 else "application/json"
        rs, rd = call(ref, method, "/nudr-dr/v1" + path, body, ctype)
        os_, od = call(ours, method, "/nudr-dr/v1" + path, body, ctype, token=token if method in ("PUT", "DELETE") and "context-data" not in path
                       and "authentication-status" not in path else None)
        ra, oa = attrs(rd), attrs(od)
        miss = (ra - oa) - ALLOW_MISSING.get(name, set())
        extra = (oa - ra) - EXPECTED_EXTRA
        verdict = []
        if rs != os_ and name not in ALLOW_STATUS:
            verdict.append("FAIL: status differs")
            failed += 1
        elif rs != os_:
            verdict.append("(status differs: " + ALLOW_STATUS[name] + ")")
        if miss and not (rs != os_ and name in ALLOW_STATUS):
            verdict.append("FAIL: missing in ours: " + ", ".join(sorted(miss)))
            failed += 1
        if extra and rs == os_:
            verdict.append("(extra in ours: " + ", ".join(sorted(extra)) + ")")
        print(f"{name:46s} {rs:4d} {os_:5d}  " + (" ".join(verdict) if verdict else "ok"))

    for n in sorted(set(notes)):
        print("note:", n)
    print(f"\nUDR differential: {failed} difference(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
