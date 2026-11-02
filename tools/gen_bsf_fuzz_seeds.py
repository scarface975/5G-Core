#!/usr/bin/env python3
"""Writes tests/fixtures/fuzz/bsf_seed.hex: valid inputs of fuzz/fuzz_bsf.c (one "<id> <hex>" line each; byte 0 selects the operation, byte 1 is a selector, the rest is
the input; see the table in the C file).

    python3 tools/gen_bsf_fuzz_seeds.py"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
seeds = []


def op(code, sel, value):
    seeds.append(bytes([code, sel]) + (value if isinstance(value, bytes) else value.encode()))


def j(o):
    return json.dumps(o, separators=(",", ":"))


PCF = {"pcfFqdn": "pcf.example.org", "pcfIpEndPoints": [{"ipv4Address": "127.0.0.13", "transport": "TCP", "port": 7777}]}


def binding(**kw):
    b = {"supi": "imsi-001010000000001", "dnn": "internet", "snssai": {"sst": 1, "sd": "000001"}, "suppFeat": "1f"}
    b.update(PCF)
    b.update(kw)
    return j(b)


op(0, 0, binding(ipv4Addr="10.45.0.2"))
op(0, 0, binding(ipv6Prefix="2001:db8:1:2::/64", addIpv6Prefixes=["2001:db8:9::/48"]))
op(0, 0, binding(macAddr48="00-11-22-33-44-55", addMacAddrs=["00-11-22-33-44-56"]))
op(0, 0, binding(ipv4Addr="10.45.0.3", ipDomain="d1", ipv4FrameRouteList=["192.168.50.0/24"], ipv6FrameRouteList=["2001:db8:f::/48"]))
op(0, 0, binding(ipv4Addr="10.45.0.4", pcfId="11111111-1111-4111-8111-111111111111", recoveryTime="2030-01-01T00:00:00Z", pcfSetId="set1.pcfset.5gc.mnc001.mcc001", bindLevel="NF_SET"))
op(0, 0, binding(ipv4Addr="10.45.0.5", pcfSmFqdn="sm.example.org", paraCom={"supi": "imsi-001010000000001", "dnn": "internet"}, suppFeat="4"))
op(0, 0, j({"dnn": "internet", "snssai": {"sst": 1}, "suppFeat": "14"}))
op(0, 0, "{")
op(0, 0, "[]")
for sel, v in enumerate(["10.45.0.6", "2001:db8:6::/64", "00-11-22-33-44-66", "domain1", "2001:db8:7::/64", "192.168.60.0/24"]):
    op(1, sel, v)
op(1, 0, "999.1.1.1")
op(1, 1, "2001:db8::/129")
for sel, v in enumerate(["10.45.0.2", "2001:db8:1:2::77/128", "00-11-22-33-44-55", "internet", "imsi-001010000000001", "msisdn-1", j({"sst": 1, "sd": "000001"}), "d1", "1f"]):
    op(2, sel, v)
op(2, 0, "10.45")
op(5, 0, "ipv4Addr=10.45.0.2&dnn=internet&colour=red")
op(5, 0, "ipv4Addr=10.45.0.2&macAddr48=00-11-22-33-44-55")
op(5, 0, "supp-feat=zz&ipv4Addr=1.2.3.4")
op(5, 0, "&&==")
op(3, 0, j({"ipv4Addr": "10.45.0.22", "pcfFqdn": "pcf2.example.org"}))
op(3, 1, j({"ipv4Addr": None, "ipv6Prefix": "2001:db8:22::/64"}))
op(3, 2, j({"dnn": "ims"}))
op(3, 3, j({"addMacAddrs": None, "macAddr48": None}))
op(3, 0, "{")
op(4, 0, "")
op(4, 1, "")

out = ROOT / "tests" / "fixtures" / "fuzz" / "bsf_seed.hex"
out.write_text("".join(f"bsf{i:02d} {s.hex()}\n" for i, s in enumerate(seeds)), encoding="utf8", newline="\n")
print(f"{len(seeds)} seeds -> {out}")
