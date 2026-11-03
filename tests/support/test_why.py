#!/usr/bin/env python3
"""tools/cli/g5c-why: the failures the functions log become a plain explanation per subscriber (cause, function, clause, what to check, runbook); lines of one trace are joined across functions;
repeated failures are counted once; every runbook entry it points to exists."""
import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-why"
loader = importlib.machinery.SourceFileLoader("g5c_why", str(TOOL))
spec = importlib.util.spec_from_loader("g5c_why", loader)
why = importlib.util.module_from_spec(spec)
loader.exec_module(why)

T1 = "a" * 32
T2 = "b" * 32


def line(ts, level, target, msg, trace=""):
    return "2026-11-03T07:%s.000000Z %5s %s: %s%s" % (ts, level, target, msg, (" trace=" + trace) if trace else "")


def analyse(lines, nf="amf", **kw):
    recs = []
    for ln in lines:
        r = why.parse_line(ln, nf)
        if r:
            r["nf"] = nf if isinstance(nf, str) else r["nf"]
            recs.append(r)
    return why.analyse(recs, **kw)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    S = "imsi-001010000000001"
    g = analyse([line("00:01", "INFO", "g5c_amf", "registration of %s rejected, cause #7 (no access and mobility subscription data)" % S)])
    check("cause 7: the UDM has no subscription; the answer names the subscriber, the check and the runbook", len(g) == 1 and g[0]["supi"] == S and "UDM has no access and mobility subscription" in g[0]["why"]
          and "g5c-ctl subscriber get " + S in g[0]["check"] and g[0]["runbook"].endswith("#registrations-rejected") and "24.501" in g[0]["clause"], g)
    g = analyse([line("00:02", "INFO", "g5c_amf", "registration of %s rejected, cause #12 (tracking area not served)" % S)])
    check("cause 12: the TAC is not in amf.tais", "amf.tais" in g[0]["check"], g)
    g = analyse([line("00:03", "INFO", "g5c_amf", "registration of %s rejected, cause #62 (no network slice is available to the UE)" % S)])
    check("cause 62: slices", "slices" in g[0]["check"] and "NSSF" in g[0]["where"], g)
    g = analyse([line("00:04", "INFO", "g5c_amf", "registration of %s rejected, cause #22 (the registration rate is above amf.overload)" % S)])
    check("cause 22: overload, with its own runbook entry", "amf.overload" in g[0]["where"] and g[0]["runbook"].endswith("#overload-and-rate-control"), g)
    g = analyse([line("00:05", "INFO", "g5c_amf", "registration of %s rejected, cause #11 (injected failure (amf.inject))" % S)])
    check("an injected failure is called that", g[0]["id"] == "injected" and "on purpose" in g[0]["what"], g)
    g = analyse([line("00:06", "INFO", "g5c_amf", "registration of %s rejected, cause #99 (something new)" % S)])
    check("an unknown cause still gets an answer", len(g) == 1 and "cause 99" in g[0]["what"] and g[0]["why"] == "something new", g)

    g = analyse([line("00:07", "INFO", "g5c_amf", "registration of (unidentified) rejected, cause #22 (the registration rate is above amf.overload)") for _ in range(5)])
    check("refusals before the UE is identified are summed up under one entry", len(g) == 1 and g[0]["supi"] == "(unidentified UE)" and g[0]["count"] == 5 and g[0]["id"] == "registration", g)

    # the chain: the AMF refused because the AUSF could not reach the UDM; same trace
    amf = [line("01:00", "INFO", "g5c_amf", "registration of %s rejected, cause #111 (the AUSF refused the request)" % S, T1)]
    ausf = [line("01:00", "WARN", "g5c_ausf", "UDM unreachable: connection refused", T1), line("01:01", "WARN", "g5c_ausf", "UDM unreachable: connection refused", T2)]
    recs = [dict(why.parse_line(x, "amf"), nf="amf") for x in amf] + [dict(why.parse_line(x, "ausf"), nf="ausf") for x in ausf]
    g = why.analyse(recs)
    reg = [x for x in g if x["id"] == "registration"][0]
    check("a refusal shows the error of the function that caused it, found by the trace id", any("ausf: UDM unreachable" in r for r in reg["related"]), reg)
    check("the same failure repeated is counted, not listed again", analyse([line("02:0%d" % i, "INFO", "g5c_amf", "registration of %s rejected, cause #7 (no access and mobility subscription data)" % S) for i in range(3)])[0]["count"] == 3)

    # other functions
    cases = [
        ("g5c_smf", "N4 session establishment on upf-1 failed for %s/1 (cause 75)" % S, "n4", "no resources"),
        ("g5c_udm", "SUCI resolution failed (-3)", "suci", "key identifier"),
        ("g5c_udm", "SUCI resolution failed (-5): the null protection scheme is refused (suci.null_scheme)", "suci", "null protection scheme"),
        ("g5c_udm", "%s: stored credentials unusable (wrong master key, corruption or missing OPc)" % S, "creds", "master key"),
        ("g5c_amf", "authentication of %s failed: wrong RES*" % S, "auth", "K or OPc"),
        ("g5c_amf", "paging of %s failed" % S, "paging", "paged"),
        ("g5c_amf", "procedure 3 of %s aborted after 5 retransmissions" % S, "timer", "stopped answering"),
        ("g5c_amf", "uplink NAS message of %s dropped (integrity check failed)" % S, "nas_drop", "security context"),
        ("g5c_amf", "SMF answered 503 for a 5GSM message of %s/1" % S, "smf_status", "SMF"),
        ("g5c_smf", "the gNB could not set up PDU session 1 of %s: radio-resources-not-available" % S, "gnb_setup", "radio side"),
        ("g5c_smf", "policy decision for %s rejected: bad QoS" % S, "policy", "PCF"),
        ("g5c_ausf", "UDM refused the authentication event of %s (404 USER_NOT_FOUND)" % S, "udm_refused", "UDM"),
        ("g5c_pcf", "policy data unavailable for %s" % S, "pcf_data", "UDR"),
    ]
    for target, msg, want_id, want_in_why in cases:
        g = analyse([line("03:00", "WARN", target, msg)], nf=target.replace("g5c_", ""), include_unnamed=True)
        check("rule %s" % want_id, len(g) == 1 and g[0]["id"] == want_id and want_in_why.lower() in (g[0]["why"] + g[0]["what"] + g[0]["where"]).lower(), g)
    g = analyse([line("03:01", "WARN", "g5c_smf", "UPF upf-1 has been unreachable for 5s: declared lost")], nf="smf", include_unnamed=True)
    check("a failure that names no subscriber appears only with --all", analyse([line("03:01", "WARN", "g5c_smf", "UPF upf-1 has been unreachable for 5s: declared lost")], nf="smf") == [] and len(g) == 1 and g[0]["id"] == "upf")
    check("lines that explain nothing are ignored", analyse([line("03:02", "INFO", "g5c_amf", "5G-AKA authentication of x succeeded"), line("03:03", "DEBUG", "g5c_amf", "registration of x rejected, cause #7 (y)")]) == [])

    # JSON log lines
    j = json.dumps({"timestamp": "2026-11-03T07:04:00.000000Z", "level": "INFO", "target": "g5c_amf", "message": "registration of %s rejected, cause #7 (no access and mobility subscription data)" % S, "trace_id": T1})
    g = analyse([j])
    check("JSON log lines are read too", len(g) == 1 and g[0]["trace"] == T1, g)

    # the command line: a directory of <function>.log files, --supi, --json, the exit code
    with tempfile.TemporaryDirectory() as d:
        Path(d, "amf.log").write_text("\n".join(amf + [line("04:00", "INFO", "g5c_amf", "registration of imsi-001010000000002 rejected, cause #12 (tracking area not served)")]) + "\n")
        Path(d, "ausf.log").write_text("\n".join(ausf) + "\n")
        p = subprocess.run([sys.executable, str(TOOL), d], capture_output=True, text=True)
        check("a directory of logs: exit 1, both subscribers, the related line", p.returncode == 1 and S in p.stdout and "imsi-001010000000002" in p.stdout and "also:  ausf: UDM unreachable" in p.stdout, p.stdout + p.stderr)
        p = subprocess.run([sys.executable, str(TOOL), d, "--supi", "imsi-001010000000002", "--json"], capture_output=True, text=True)
        out = json.loads(p.stdout)
        check("--supi and --json", len(out) == 1 and out[0]["supi"] == "imsi-001010000000002", p.stdout)
        p = subprocess.run([sys.executable, str(TOOL), d, "--supi", "imsi-009990000000001"], capture_output=True, text=True)
        check("nothing found: exit 0 and a sentence", p.returncode == 0 and "nothing in these logs" in p.stdout, p.stdout)
        p = subprocess.run([sys.executable, str(TOOL), "-"], input=amf[0] + "\n", capture_output=True, text=True)
        check("standard input", p.returncode == 1 and S in p.stdout)

    # every runbook entry it points to is a heading in the runbooks
    heads = {re.sub(r"[^a-z0-9 -]", "", h.lower()).strip().replace(" ", "-") for h in re.findall(r"^## (.+)$", (ROOT / "docs" / "ops" / "runbooks.md").read_text(), re.M)}
    wanted = {kw["runbook"].split("#")[1] for _, kw in why.RULES if "runbook" in kw} | {"overload-and-rate-control", "registrations-rejected", "authentication-failures"}
    check("every runbook entry named by a rule exists", wanted <= heads, wanted - heads)

    # the real logs of a cluster run, when one is at hand: nothing may crash
    real = os.environ.get("G5C_WHY_LOGS")
    if real and os.path.isdir(real):
        p = subprocess.run([sys.executable, str(TOOL), real, "--all"], capture_output=True, text=True)
        check("real cluster logs are read without error", p.returncode in (0, 1) and "Traceback" not in p.stderr, p.stderr[-300:])
    print("why: PASS" if ok else "why: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
