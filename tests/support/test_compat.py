#!/usr/bin/env python3
"""tools/cli/g5c-compat on a real run of the nine differential tests (tests/fixtures/compat/differentials.log): every case becomes a row with the right verdict, no case is unexplained, and a difference
nobody wrote a reason for is. The reports are written in five formats."""
import csv
import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-compat"
LOG = ROOT / "tests" / "fixtures" / "compat" / "differentials.log"
loader = importlib.machinery.SourceFileLoader("g5c_compat", str(TOOL))
spec = importlib.util.spec_from_loader("g5c_compat", loader)
cp = importlib.util.module_from_spec(spec)
loader.exec_module(cp)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    rows, finals = cp.parse(LOG.read_text())
    by = {(r["function"].split(" (")[0], r["case"]): r for r in rows}
    summ = cp.summarise(rows)
    check("nine functions are covered", len(summ) == 9 and len(finals) == 9, list(summ))
    check("no case is unexplained, and the tests themselves said OK or 0 differences", all(r["verdict"] != "UNEXPLAINED" for r in rows) and all("OK" in f or "0 difference" in f for f in finals.values()), [r for r in rows if r["verdict"] == "UNEXPLAINED"])
    check("a status that the TS says otherwise is documented with its reason", by[("UDR", "PUT amf-3gpp-access (create)")]["verdict"] == "documented" and "29.504" in by[("UDR", "PUT amf-3gpp-access (create)")]["note"] and
          by[("UDR", "PUT amf-3gpp-access (create)")]["ref"] == "204" and by[("UDR", "PUT amf-3gpp-access (create)")]["ours"] == "201", by.get(("UDR", "PUT amf-3gpp-access (create)")))
    check("the SCP's 504 against the reference's own answer", by[("SCP", "unreachable target")]["verdict"] == "documented" and "504" in by[("SCP", "unreachable target")]["note"])
    check("an accepted difference of the status is documented too", by[("AUSF", "confirm again (single use)")]["verdict"] == "documented" and "200" in by[("AUSF", "confirm again (single use)")]["note"], by.get(("AUSF", "confirm again (single use)")))
    check("extra fields in ours are 'ours adds', with the fields named", by[("NRF", "register SMF")]["verdict"] == "ours adds" and "capacity" in by[("NRF", "register SMF")]["note"], by.get(("NRF", "register SMF")))
    check("identical answers are matches", by[("UDR", "GET authentication subscription")]["verdict"] == "match" and by[("NSSF", "unknown slice")]["verdict"] == "match")
    check("PFCP: matching messages, an extra element in ours, a message only the reference sent", by[("UPF", "PFCP Session Establishment Response")]["verdict"] == "match" and
          by[("UPF", "PFCP Session Deletion Response")]["verdict"] == "ours adds" and by[("UPF", "PFCP Association Setup Response")]["verdict"] == "not compared", {k: v["verdict"] for k, v in by.items() if k[0] == "UPF"})
    check("PFCP: a missing element with an allowed reason is documented", by[("SMF", "PFCP Session Establishment Request")]["verdict"] == "documented" and "match-all filter" in by[("SMF", "PFCP Session Establishment Request")]["note"], by.get(("SMF", "PFCP Session Establishment Request")))
    check("NGAP: the allowed extra message is documented, the extra IE is 'ours adds'", by[("AMF", "messages from the AMF to the gNB")]["verdict"] == "documented" and by[("AMF", "InitialContextSetup")]["verdict"] == "ours adds" and
          by[("AMF", "NGSetup")]["verdict"] == "match")

    # a difference that nobody explained
    text = "    Start 111: udr_differential\nstep   ref  ours  attributes\nGET something        200   500  \nGET fine             200   200  ok\n"
    r2, _ = cp.parse(text)
    check("a status that differs without a reason is UNEXPLAINED", [x["verdict"] for x in r2] == ["UNEXPLAINED", "match"], r2)
    text = "    Start 108: pfcp_differential_smf\n  PFCP Session Establishment Request         42 elements; ours differs\n      missing in ours: Create PDR > Foo\n"
    check("a PFCP element missing without an 'allowed' reason is UNEXPLAINED", cp.parse(text)[0][0]["verdict"] == "UNEXPLAINED")

    with tempfile.TemporaryDirectory() as d:
        p = subprocess.run([sys.executable, str(TOOL), "parse", str(LOG), "--out", d], capture_output=True, text=True)
        check("the command writes the five reports and exits 0 when nothing is unexplained", p.returncode == 0 and all((Path(d) / f).exists() for f in ("report.txt", "report.md", "report.html", "report.csv", "report.json")), p.stderr)
        data = json.loads((Path(d) / "report.json").read_text())
        check("report.json: the reference, the summary and every row", data["reference"] == "Open5GS 2.8.0" and len(data["rows"]) == len(rows) and "UDR" in data["summary"] and any(k.startswith("UDR") for k in data["summary"]))
        check("report.csv has a line per row", len(list(csv.reader(open(Path(d) / "report.csv")))) == len(rows) + 1)
        check("the Markdown names the differences and their reasons", "## Differences and their reasons" in (Path(d) / "report.md").read_text() and "TS 29.504" in (Path(d) / "report.md").read_text())
        bad = Path(d) / "bad.log"
        bad.write_text(text.replace("pfcp_differential_smf", "udr_differential") + "GET x   200   500\n")
        p = subprocess.run([sys.executable, str(TOOL), "parse", str(bad), "--out", str(Path(d) / "o2")], capture_output=True, text=True)
        check("exit code 1 when something is unexplained", p.returncode == 1, p.stdout)
        p = subprocess.run([sys.executable, str(TOOL), "parse", "-", "--out", str(Path(d) / "o3")], input="nothing here\n", capture_output=True, text=True)
        check("input with no comparison is an error", p.returncode == 2, p.stderr)
    print("compat: PASS" if ok else "compat: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
