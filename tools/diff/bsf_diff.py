#!/usr/bin/env python3
"""Differential analysis of two BSFs (strategy 4.1, conformance layer): the same Nbsf_Management requests to a reference BSF (Open5GS's) and to ours. For every step the
HTTP status, the Location header, the sets of JSON attributes of the answers, and the values the BSF only echoes are compared.

    python3 tools/diff/bsf_diff.py <reference-base-url> <our-base-url>

Run by deploy/oracle/bsf_diff.sh (which starts both in a private network namespace). A step that ends the same in both is "ok"; a difference that the allow-lists below
explain (the specification gives no status, or a choice that is ours on purpose) is listed with its reason; anything else fails (exit status 1)."""
import json
import subprocess
import sys
import urllib.parse as up

BASE = "/nbsf-management/v1/pcfBindings"
SNSSAI = {"sst": 1, "sd": "000001"}
PCF_EP = [{"ipv4Address": "127.0.0.13", "transport": "TCP", "port": 7777}]


def binding(**kw):
    b = {"supi": "imsi-001010000000001", "dnn": "internet", "snssai": SNSSAI, "pcfFqdn": "pcf.example.org", "pcfIpEndPoints": PCF_EP, "suppFeat": "0"}
    b.update(kw)
    return {k: v for k, v in b.items() if v is not None}


def call(base, method, path, body=None, ctype="application/json", extra=None):
    cmd = ["curl", "-s", "-D", "-", "-o", "/tmp/bsfdiff.body", "--http2-prior-knowledge", "-X", method]
    if body is not None:
        cmd += ["-H", "content-type: " + ctype, "--data-binary", body if isinstance(body, str) else json.dumps(body)]
    cmd += [base + path]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    lines = [ln.rstrip("\r") for ln in out.split("\n") if ln.strip()]
    status = int(lines[0].split()[1]) if lines and lines[0].startswith("HTTP") else 0
    hdr = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdr[k.strip().lower()] = v.strip()
    try:
        text = open("/tmp/bsfdiff.body").read()
        doc = json.loads(text) if text.strip() else None
    except ValueError:
        doc = None
    return status, hdr, doc


def attrs(doc, prefix=""):
    out = set()
    if isinstance(doc, dict):
        for k, v in doc.items():
            out.add(prefix + k)
            if isinstance(v, dict):
                out |= attrs(v, prefix + k + ".")
    return out


def q(**kw):
    return "?" + "&".join(f"{k}={up.quote(v if isinstance(v, str) else json.dumps(v, separators=(',', ':')), safe='')}" for k, v in kw.items())


# step -> why a different status is accepted. Open5GS's BSF is partial: it ignores the optional query parameters, answers 404 where TS 29.521 4.2.4.2 says 204, and has
# no IPv6, MAC or update support, so what the specification text says is what ours does (the clause is in each reason).
NO204 = "TS 29.521 4.2.4.2: no matching binding is 204 No Content; Open5GS answers 404"
NOFILTER = "TS 29.521 5.3.2.3.2: dnn, snssai, supi and ipDomain narrow the match; Open5GS ignores them"
NOV6 = "Open5GS's BSF refuses the IPv6 prefix 2001:db8:1:2::/64 of TS 29.571 Ipv6Prefix (400 Invalid IPv6 prefix)"
NOMAC = "Open5GS's BSF cannot register a MAC address binding (404)"
ALLOW_STATUS = {
    "discover by IPv4 with another DNN": NOFILTER,
    "discover by IPv4 with another S-NSSAI": NOFILTER,
    "discover an address nobody has": NO204,
    "discover without a UE address": "TS 29.521 4.2.4.2: 400 MANDATORY_QUERY_PARAM_MISSING; Open5GS answers 404",
    "discover with two UE addresses": "TS 29.521 5.3.2.3.2 NOTE 1: one and only one of ipv4Addr, ipv6Prefix and macAddr48; Open5GS takes the first",
    "discover with an unknown query parameter": "TS 29.500 5.2.7.2: INVALID_QUERY_PARAM; Open5GS ignores it",
    "register an IPv6 prefix binding": NOV6,
    "discover by an IPv6 address inside the prefix": NOV6,
    "discover by an IPv6 address outside the prefix": NOV6,
    "register a MAC binding": NOMAC,
    "discover by MAC address": NOMAC,
    "register with IPv4 and IPv6": NOV6,
    "discover that one by IPv4": NOV6,
    "discover that one by IPv6": NOV6,
    "discover that address without a slice": "TS 29.521 4.2.4.2: two bindings match, 400 MULTIPLE_BINDING_INFO_FOUND; Open5GS returns the first",
    "discover the deregistered address": NO204,
    "register without a UE address": "TS 29.521 4.2.2.2: the address of the UE is required (without ExtendedSamePcf); Open5GS answers 404",
    "update a binding (merge patch)": "TS 29.521 4.2.5: Nbsf_Management_Update (BindingUpdate); Open5GS has no PATCH",
    "discover the updated address": "as above",
}
# step -> attributes the reference has and ours does not / ours has and the reference does not
ALLOW_MISSING = {}
ALLOW_EXTRA = {}
EXTRA_OK = {"ipv4Addr": "TS 29.521 4.2.4.2: the PcfBinding as the PCF registered it; Open5GS leaves ipv4Addr and supi out of the answer", "supi": "as above"}


def main():
    ref, ours = sys.argv[1:3]
    ids = {ref: {}, ours: {}}
    failed = 0
    print(f"{'step':58s} {'ref':>4s} {'ours':>5s}  result")

    def step(name, method, path, body=None, ctype="application/json", save=None, use=None):
        nonlocal failed
        res = {}
        for who in (ref, ours):
            p = path
            if use is not None:
                bid = ids[who].get(use)
                p = path.replace("{id}", bid if bid else "unknown")
            st, hdr, doc = call(who, method, p, body, ctype)
            if save is not None and st == 201 and hdr.get("location"):
                ids[who][save] = hdr["location"].rsplit("/", 1)[-1]
            res[who] = (st, hdr, doc)
        (rs, rh, rd), (os_, oh, od) = res[ref], res[ours]
        notes = []
        if rs != os_:
            if name in ALLOW_STATUS:
                notes.append("(status differs: " + ALLOW_STATUS[name] + ")")
            else:
                notes.append("FAIL: status differs")
                failed += 1
        else:
            if ("location" in rh) != ("location" in oh):
                notes.append("FAIL: Location header")
                failed += 1
            ra, oa = attrs(rd), attrs(od)
            if rs < 400:  # the members of an error body are optional (ProblemDetails): only the status is compared
                miss = ra - oa - ALLOW_MISSING.get(name, set())
                extra = oa - ra - ALLOW_EXTRA.get(name, set())
                if miss:
                    notes.append("FAIL: missing in ours: " + ", ".join(sorted(miss)))
                    failed += 1
                if extra - set(EXTRA_OK):
                    notes.append("FAIL: extra in ours: " + ", ".join(sorted(extra - set(EXTRA_OK))))
                    failed += 1
                elif extra:
                    notes.append("(extra in ours: " + ", ".join(sorted(extra)) + "; " + EXTRA_OK[sorted(extra)[0]] + ")")
        print(f"{name:58s} {rs:4d} {os_:5d}  " + (" ".join(notes) if notes else "ok"))
        return res

    step("register an IPv4 binding", "POST", BASE, binding(ipv4Addr="10.45.0.2"), save="a")
    step("discover by IPv4", "GET", BASE + q(ipv4Addr="10.45.0.2"))
    step("discover by IPv4, DNN, S-NSSAI and SUPI", "GET", BASE + q(ipv4Addr="10.45.0.2", dnn="internet", snssai=SNSSAI, supi="imsi-001010000000001"))
    step("discover by IPv4 with another DNN", "GET", BASE + q(ipv4Addr="10.45.0.2", dnn="ims"))
    step("discover by IPv4 with another S-NSSAI", "GET", BASE + q(ipv4Addr="10.45.0.2", snssai={"sst": 2}))
    step("discover an address nobody has", "GET", BASE + q(ipv4Addr="10.45.9.9"))
    step("discover without a UE address", "GET", BASE + q(dnn="internet"))
    step("discover with two UE addresses", "GET", BASE + q(ipv4Addr="10.45.0.2", macAddr48="00-11-22-33-44-55"))
    step("discover with a malformed IPv4 address", "GET", BASE + q(ipv4Addr="10.45.0"))
    step("discover with an unknown query parameter", "GET", BASE + q(ipv4Addr="10.45.0.2", colour="red"))
    step("register an IPv6 prefix binding", "POST", BASE, binding(supi="imsi-001010000000002", ipv6Prefix="2001:db8:1:2::/64"), save="b")
    step("discover by an IPv6 address inside the prefix", "GET", BASE + q(ipv6Prefix="2001:db8:1:2::8a2e:370:7334/128"))
    step("discover by an IPv6 address outside the prefix", "GET", BASE + q(ipv6Prefix="2001:db8:1:3::1/128"))
    step("register a MAC binding", "POST", BASE, binding(supi="imsi-001010000000003", macAddr48="00-11-22-33-44-55"), save="c")
    step("discover by MAC address", "GET", BASE + q(macAddr48="00-11-22-33-44-55"))
    step("register with IPv4 and IPv6", "POST", BASE, binding(supi="imsi-001010000000004", ipv4Addr="10.45.0.4", ipv6Prefix="2001:db8:4::/64"), save="d")
    step("discover that one by IPv4", "GET", BASE + q(ipv4Addr="10.45.0.4"))
    step("discover that one by IPv6", "GET", BASE + q(ipv6Prefix="2001:db8:4::1/128"))
    step("register the same IPv4 address in another slice", "POST", BASE, binding(supi="imsi-001010000000005", ipv4Addr="10.45.0.2", snssai={"sst": 2}), save="e")
    step("discover that address without a slice", "GET", BASE + q(ipv4Addr="10.45.0.2"))
    step("discover that address in the second slice", "GET", BASE + q(ipv4Addr="10.45.0.2", snssai={"sst": 2}))
    step("deregister a binding", "DELETE", BASE + "/{id}", use="a")
    step("deregister it again", "DELETE", BASE + "/{id}", use="a")
    step("deregister an unknown binding", "DELETE", BASE + "/no-such-binding")
    step("discover the deregistered address", "GET", BASE + q(ipv4Addr="10.45.0.2", snssai=SNSSAI))
    step("register without a DNN", "POST", BASE, {k: v for k, v in binding(ipv4Addr="10.45.0.9").items() if k != "dnn"})
    step("register without an S-NSSAI", "POST", BASE, {k: v for k, v in binding(ipv4Addr="10.45.0.9").items() if k != "snssai"})
    step("register without a UE address", "POST", BASE, binding())
    step("register without a PCF address", "POST", BASE, {k: v for k, v in binding(ipv4Addr="10.45.0.9").items() if k not in ("pcfFqdn", "pcfIpEndPoints")})
    step("register a malformed IPv4 address", "POST", BASE, binding(ipv4Addr="10.45.0.999"))
    step("register something that is not JSON", "POST", BASE, "{not json")
    step("update a binding (merge patch)", "PATCH", BASE + "/{id}", {"ipv4Addr": "10.45.0.44"}, ctype="application/merge-patch+json", use="d")
    step("discover the updated address", "GET", BASE + q(ipv4Addr="10.45.0.44"))
    step("update an unknown binding", "PATCH", BASE + "/no-such-binding", {"ipv4Addr": "10.45.0.45"}, ctype="application/merge-patch+json")
    print(f"\nBSF differential: {failed} difference(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
