#!/usr/bin/env python3
"""tools/cli/g5c-subscribers: Open5GS, free5GC and CSV subscribers become UDM admin documents that pass the UDM's own checks; bad records are reported, not sent."""
import json
import subprocess
import sys
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent.parent / "tools" / "cli" / "g5c-subscribers"
K, OPC, OP = "465b5ce8b199b49faa5f0a2ee238a6bc", "e8ed289deba952e4283b54e88e6183ca", "11111111111111111111111111111111"


def run(fmt, text, *args, ctl=None):
    cmd = [sys.executable, str(TOOL), "import", "--format", fmt, "-", *args]
    if ctl:
        cmd += ["--ctl", ctl]
    return subprocess.run(cmd, input=text, capture_output=True, text=True)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    # Open5GS (mongoexport style: extended JSON numbers, units, session types)
    o5 = [{"_id": {"$oid": "65f"}, "imsi": "999700000000001", "msisdn": ["491234567"],
           "security": {"k": K, "opc": OPC, "amf": "8000", "sqn": {"$numberLong": "64"}},
           "ambr": {"downlink": {"value": 1, "unit": 3}, "uplink": {"value": 500, "unit": 2}},
           "slice": [{"sst": 1, "default_indicator": True,
                      "session": [{"name": "internet", "type": 3, "qos": {"index": 9}, "ambr": {"downlink": {"value": 1, "unit": 3}, "uplink": {"value": 1, "unit": 3}}}]},
                     {"sst": {"$numberInt": "2"}, "sd": "000001", "session": [{"name": "ims", "type": 1, "qos": {"index": 5}}]}]},
          {"imsi": "999700000000002", "security": {"k": K, "op": OP}, "slice": [{"sst": 1, "session": [{"name": "internet", "type": 1}]}]}]
    p = run("open5gs", json.dumps(o5), "--dry-run")
    check("open5gs: both records valid", p.returncode == 0 and "2 valid, 0 rejected" in p.stderr, p.stderr)
    p = run("open5gs", "\n".join(json.dumps(r) for r in o5))  # JSON lines
    docs = [json.loads(l) for l in p.stdout.splitlines()]
    d = docs[0]
    check("open5gs: identity, keys, sqn in hex", d["supi"] == "imsi-999700000000001" and d["k"] == K and d["opc"] == OPC and d["sqn"] == "000000000040", d)
    check("open5gs: AMBR with units", d["ue_ambr_ul"] == "500 Mbps" and d["ue_ambr_dl"] == "1 Gbps", d)
    check("open5gs: slices with and without SD", d["slices"] == [{"sst": 1}, {"sst": 2, "sd": "000001"}], d.get("slices"))
    check("open5gs: dnns with type and 5QI", d["dnns"]["internet"]["session_types"] == ["IPV4V6"] and d["dnns"]["ims"]["qi5"] == 5, d.get("dnns"))
    check("open5gs: MSISDN kept, OP record keeps op", d["msisdn"] == "491234567" and docs[1].get("op") == OP and "opc" not in docs[1], docs[1])

    # free5GC web console documents
    f5 = {"ueId": "imsi-208930000000003",
          "AuthenticationSubscription": {"authenticationMethod": "5G_AKA", "permanentKey": {"permanentKeyValue": K}, "opc": {"opcValue": OPC},
                                         "sequenceNumber": "16f3b3f70fc2", "authenticationManagementField": "8000"},
          "AccessAndMobilitySubscriptionData": {"nssai": {"defaultSingleNssais": [{"sst": 1, "sd": "010203"}]}, "subscribedUeAmbr": {"uplink": "1 Gbps", "downlink": "2 Gbps"}},
          "SessionManagementSubscriptionData": [{"singleNssai": {"sst": 1, "sd": "010203"},
                                                  "dnnConfigurations": {"internet": {"pduSessionTypes": {"allowedSessionTypes": ["IPV4"]}, "5gQosProfile": {"5qi": 9},
                                                                                       "sessionAmbr": {"uplink": "200 Mbps", "downlink": "100 Mbps"}}}}]}
    p = run("free5gc", json.dumps([f5]))
    d = json.loads(p.stdout.splitlines()[0]) if p.stdout else {}
    check("free5gc: converted", p.returncode == 0 and d.get("supi") == "imsi-208930000000003" and d.get("sqn") == "16f3b3f70fc2" and d.get("slices") == [{"sst": 1, "sd": "010203"}], p.stderr + str(d))
    check("free5gc: dnn and AMBR", d.get("dnns", {}).get("internet") == {"qi5": 9, "session_types": ["IPV4"], "ambr_ul": "200 Mbps", "ambr_dl": "100 Mbps"} and d.get("ue_ambr_dl") == "2 Gbps", d)

    # CSV
    csv_text = "supi,k,opc,op,amf,sqn,msisdn,slices,dnns,ue_ambr_ul,ue_ambr_dl\nimsi-001010000000009,%s,%s,,8000,,,1;2:00000a,internet;ims/IPV4V6,,\n" % (K, OPC)
    p = run("csv", csv_text)
    d = json.loads(p.stdout.splitlines()[0]) if p.stdout else {}
    check("csv: slices and dnns", d.get("slices") == [{"sst": 1}, {"sst": 2, "sd": "00000a"}] and d.get("dnns", {}).get("ims") == {"session_types": ["IPV4V6"]}, p.stderr + str(d))

    # bad records are reported (no key in the message), the good ones still come out, exit code 1
    bad = [{"imsi": "999700000000010", "security": {"k": "short", "opc": OPC}}, o5[1]]
    p = run("open5gs", "\n".join(json.dumps(r) for r in bad))
    check("bad records: reported, good one kept, exit 1", p.returncode == 1 and "k must be 32 hex" in p.stderr and len(p.stdout.splitlines()) == 1, p.stderr)
    p = run("g5c", json.dumps([{"supi": "imsi-001010000000012", "k": K, "opc": OPC, "op": OP}, {"supi": "imsi-001010000000013", "k": K, "opc": OPC, "pin": 1}]))
    check("g5c documents: both opc and op, and unknown fields, refused", p.returncode == 1 and "exactly one of opc and op" in p.stderr and "unknown field(s) pin" in p.stderr and p.stdout == "", p.stderr)
    check("no key material in messages", K not in p.stderr and OPC not in p.stderr, p.stderr)

    # --apply sends one document per subscriber through g5c-ctl (stubbed here)
    stub = Path(__file__).with_name("_ctl_stub.sh")
    log = Path(str(stub) + ".log")
    stub.write_text("#!/bin/sh\ncat >> '%s'; echo >> '%s'\nexit 0\n" % (log, log))
    stub.chmod(0o755)
    try:
        log.unlink()
    except FileNotFoundError:
        pass
    p = run("open5gs", json.dumps(o5), "--apply", ctl=str(stub))
    sent = [json.loads(l) for l in log.read_text().splitlines() if l.strip()] if log.exists() else []
    check("--apply: one request per subscriber", p.returncode == 0 and [s["supi"] for s in sent] == ["imsi-999700000000001", "imsi-999700000000002"] and "2 provisioned" in p.stderr, p.stderr)
    # --apply --bulk: batches go to `subscriber bulk -`, the answer says per record what happened
    stub.write_text("#!/usr/bin/env python3\nimport json, sys\nrecs = json.load(sys.stdin)\nopen(%r, 'a').write(json.dumps(len(recs)) + '\\n')\n"
                    "print(json.dumps({'results': [{'supi': r['supi'], 'status': 400 if r['supi'].endswith('2') else 201, 'detail': 'refused by the UDM'} for r in recs]}))\n" % str(log))
    stub.chmod(0o755)
    try:
        log.unlink()
    except FileNotFoundError:
        pass
    p = run("open5gs", json.dumps(o5), "--apply", "--bulk", ctl=str(stub))
    check("--apply --bulk: one batch, per-record results counted", p.returncode == 1 and "1 provisioned, 1 failed" in p.stderr and "imsi-999700000000002: 400 refused by the UDM" in p.stderr and log.read_text().split() == ["2"], p.stderr)
    for f in (stub, log):
        try:
            f.unlink()
        except FileNotFoundError:
            pass
    print("subscribers: PASS" if ok else "subscribers: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
