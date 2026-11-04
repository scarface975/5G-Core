#!/usr/bin/env python3
"""tools/cli/g5c-conform: the real captures of Open5GS with UERANSIM (and with some of our functions in it) keep every rule; synthetic captures break them one by one (a context setup without
authentication or security mode, an unanswered request, a late answer, an NG Setup nobody answered, a PFCP establishment without a response); input and rule errors are exit 2."""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-conform"
GOLDEN = ROOT / "tests" / "fixtures" / "golden"


def run(args):
    return subprocess.run([sys.executable, str(TOOL)] + args, capture_output=True, text=True)


def row(n, t, src, dst, proto, info, ran="", amf="", seid="", seq=""):
    return "\t".join([str(n), "%.6f" % t, src, dst, proto, info, ran, amf, seid, "", seq])


UE, AMF = "10.0.0.100", "10.0.0.5"


def ue_flow(base, steps, ran="1"):
    """steps: (dt, direction, info); direction 'u' = gNB to AMF, 'd' = AMF to gNB."""
    rows, t = [], 0.0
    for k, (dt, d, info) in enumerate(steps):
        t += dt
        src, dst = (UE, AMF) if d == "u" else (AMF, UE)
        rows.append(row(base + k, t, src, dst, "NGAP/NAS-5GS", info, ran, "1"))
    return rows


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    ng = [row(1, 0.0, UE, AMF, "NGAP", "NGSetupRequest"), row(2, 0.01, AMF, UE, "NGAP", "NGSetupResponse")]
    good = ue_flow(10, [(0.1, "u", "InitialUEMessage, Registration request"), (0.01, "d", "DownlinkNASTransport, Authentication request"), (0.01, "u", "UplinkNASTransport, Authentication response"),
                        (0.01, "d", "DownlinkNASTransport, Security mode command"), (0.01, "u", "UplinkNASTransport"), (0.02, "d", "InitialContextSetupRequest"), (0.01, "u", "InitialContextSetupResponse")])

    def conform(rows, extra=()):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "rows.tsv"
            p.write_text("\n".join(rows) + "\n")
            r = run(["--from-tsv", str(p), "--json"] + list(extra))
            return r.returncode, (json.loads(r.stdout) if r.stdout.strip() else {}), r.stderr

    rc, rep, _ = conform(ng + good)
    check("a correct registration keeps every rule", rc == 0 and rep["violations"] == [] and rep["applied"].get("REG-FLOW") == 1 and rep["applied"].get("N2-SETUP") == 1, rep)

    no_smc = ue_flow(10, [(0.1, "u", "InitialUEMessage, Registration request"), (0.01, "d", "DownlinkNASTransport, Authentication request"), (0.01, "u", "UplinkNASTransport, Authentication response"),
                          (0.02, "d", "InitialContextSetupRequest"), (0.01, "u", "InitialContextSetupResponse")])
    rc, rep, _ = conform(ng + no_smc)
    check("a context setup without a Security Mode Command breaks REG-FLOW (the clause is named)", rc == 1 and [v["rule"] for v in rep["violations"]] == ["REG-FLOW"] and "TS 24.501" in rep["violations"][0]["clause"] and
          "Security mode command" in rep["violations"][0]["what"], rep["violations"])

    no_auth = ue_flow(10, [(0.1, "u", "InitialUEMessage, Registration request"), (0.01, "d", "DownlinkNASTransport, Security mode command"), (0.02, "d", "InitialContextSetupRequest"),
                           (0.01, "u", "InitialContextSetupResponse")])
    rc, rep, _ = conform(ng + no_auth)
    check("a registration accepted without authentication breaks REG-FLOW", rc == 1 and any(v["rule"] == "REG-FLOW" and "Authentication request" in v["what"] for v in rep["violations"]), rep["violations"])

    rejected = ue_flow(10, [(0.1, "u", "InitialUEMessage, Registration request"), (0.01, "d", "DownlinkNASTransport, Registration reject")])
    rc, rep, _ = conform(ng + rejected)
    check("a registration that is rejected is not a violation", rc == 0 and rep["violations"] == [], rep["violations"])

    unanswered = good[:-1]
    rc, rep, _ = conform(ng + unanswered)
    check("an unanswered InitialContextSetupRequest breaks N2-ANSWERS", rc == 1 and any(v["rule"] == "N2-ANSWERS" and "not answered" in v["what"] for v in rep["violations"]), rep["violations"])

    late = ue_flow(10, [(0.1, "u", "InitialUEMessage, Registration request"), (0.01, "d", "DownlinkNASTransport, Authentication request"), (9.0, "u", "UplinkNASTransport, Authentication response"),
                        (0.01, "d", "DownlinkNASTransport, Security mode command"), (0.02, "d", "InitialContextSetupRequest"), (0.01, "u", "InitialContextSetupResponse")])
    rc, rep, _ = conform(ng + late)
    check("an Authentication response after 9 s breaks AUTH-TIMER (T3560 is 6 s)", rc == 1 and any(v["rule"] == "AUTH-TIMER" and "9.0 s" in v["what"] for v in rep["violations"]), rep["violations"])

    rc, rep, _ = conform([row(1, 0.0, UE, AMF, "NGAP", "NGSetupRequest")] + good)
    check("an NG Setup Request nobody answered breaks N2-SETUP", rc == 1 and any(v["rule"] == "N2-SETUP" for v in rep["violations"]), rep["violations"])

    pf = [row(30, 1.0, "10.0.0.4", "10.0.0.7", "PFCP", "PFCP Session Establishment Request", seid="0x0", seq="7"),
          row(31, 1.01, "10.0.0.7", "10.0.0.4", "PFCP", "PFCP Session Establishment Response", seid="0x1", seq="7")]
    rc, rep, _ = conform(ng + good + pf)
    check("a PFCP establishment with its response keeps N4-ESTABLISH", rc == 0 and rep["applied"].get("N4-ESTABLISH") == 1, rep)
    rc, rep, _ = conform(ng + good + pf[:1])
    check("a PFCP establishment without a response breaks N4-ESTABLISH", rc == 1 and any(v["rule"] == "N4-ESTABLISH" for v in rep["violations"]), rep["violations"])

    rc, rep, _ = conform(ng)
    check("a capture with only NG Setup says the UE rules are not applicable", rc == 0 and "REG-FLOW" in rep["notApplicable"] or "REG-FLOW" not in rep["applied"], rep)

    # bad input
    check("no input is exit 2", run([]).returncode == 2)
    with tempfile.TemporaryDirectory() as d:
        bad = Path(d) / "r.json"
        bad.write_text("{}")
        p = Path(d) / "rows.tsv"
        p.write_text("\n".join(ng) + "\n")
        check("rules without a rules list are exit 2", run(["--from-tsv", str(p), "--rules", str(bad)]).returncode == 2)
    check("a missing file is exit 2", run(["--from-tsv", "/nonexistent.tsv"]).returncode == 2)

    # the rule file itself
    rules = json.loads((ROOT / "docs" / "conformance" / "procedures.json").read_text())["rules"]
    check("every rule has an id, a clause, a scope and either steps or answers", all(r["id"] and r["clause"] and r["scope"] in ("ue", "n2", "n4") and ("then" in r or "answers" in r) for r in rules) and len({r["id"] for r in rules}) == len(rules))

    # the real captures (tshark is needed)
    if shutil.which("tshark"):
        for name in ("s2_open5gs_v2.8.0_ueransim", "s3_open5gs_v2.8.0_ueransim", "s3_our_amf_open5gs_core_ueransim", "s3_our_smf_our_upf_open5gs_amf_ueransim"):
            r = run([str(GOLDEN / (name + ".pcapng")), "--json"])
            rep = json.loads(r.stdout) if r.stdout.strip() else {}
            check("the capture %s keeps every rule" % name, r.returncode == 0 and rep.get("violations") == [] and rep.get("applied", {}).get("REG-FLOW", 0) >= 1, (r.returncode, rep.get("violations")))
    else:
        print("SKIP  the real captures (tshark is not installed)")
    print("conform: PASS" if ok else "conform: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
