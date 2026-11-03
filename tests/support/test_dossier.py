#!/usr/bin/env python3
"""tools/release/g5c-dossier: rows get the verdict of their tests, a gap stays a gap, the three report formats are written, the dossier has a manifest that matches its files."""
import hashlib
import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "release" / "g5c-dossier"
JUNIT = """<testsuite name="x" tests="3"><testcase name="crypto_milenage"/><testcase name="nrf_oauth2"><failure message="boom"/></testcase><testcase name="udm_unit_and_services"/></testsuite>"""


def run(*a):
    return subprocess.run([sys.executable, str(TOOL), *a], capture_output=True, text=True)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "junit.xml").write_text(JUNIT)
        p = run("report", "--results", str(d / "junit.xml"), "--out", str(d / "rep"))
        check("report written", p.returncode == 0 and "rows" in p.stdout, p.stderr)
        csv_text = (d / "rep" / "report.csv").read_text()
        check("CSV has a header and one line per row", csv_text.splitlines()[0].startswith("id,phase,function") and len(csv_text.splitlines()) > 380, len(csv_text.splitlines()))
        junit = ET.parse(d / "rep" / "report.junit.xml").getroot()
        check("a row proven by a failing test is a failure", int(junit.get("failures")) >= 1, junit.attrib)
        check("gaps are skipped, not passed", int(junit.get("skipped")) >= 50, junit.attrib)
        html_text = (d / "rep" / "report.html").read_text()
        check("html lists the gap rows as gaps", "gap" in html_text and "<table>" in html_text)
        # without a results file nothing is claimed as passed
        p = run("report", "--results", str(d / "none.xml"), "--out", str(d / "rep2"))
        check("without results: not run, never pass", "'pass'" not in p.stdout and "not run" in p.stdout, p.stdout)
        p = run("dossier", "--results", str(d / "junit.xml"), "--out", str(d / "dos" / "dossier"))
        check("dossier built", p.returncode == 0 and "files" in p.stdout, p.stderr + p.stdout)
        dos = d / "dos" / "dossier"
        manifest = (dos / "MANIFEST.sha256").read_text().splitlines()
        good = all(hashlib.sha256((dos / name).read_bytes()).hexdigest() == h for h, name in (l.split("  ", 1) for l in manifest))
        check("every file in the manifest matches", good and len(manifest) > 10, len(manifest))
        check("index, zip and the SBOM are there", (dos / "index.html").exists() and list((d / "dos").glob("g5c-dossier-*.zip")) and (dos / "supply-chain" / "g5c.cdx.json").exists())

    # the security suite (backlog B-13, D-05): it names only tests that exist, the verdicts follow the results, the dossier carries the report
    import re
    names = set()
    for cm in ROOT.rglob("CMakeLists.txt"):
        if "build" in cm.parts:
            continue
        text = cm.read_text(errors="replace")
        names.update(re.findall(r"add_test\(NAME\s+(\w+)", text))
        for var, items, block in re.findall(r"foreach\((\w+)\s+([^)]*)\)(.*?)endforeach", text, re.S):  # add_test(NAME prefix_${var}) in a loop
            for pre in re.findall(r"add_test\(NAME\s+(\w*)\$\{%s\}" % var, block):
                names.update(pre + i for i in items.split())
    suite = json.loads((ROOT / "docs" / "conformance" / "security-suite.json").read_text())
    wanted = {x for c in suite["cases"] for x in c["tests"]}
    check("every test the security suite names is registered in CMake", wanted <= names, sorted(wanted - names))
    check("every case has an id, a requirement, a specification and at least one test", all(c["id"] and c["title"] and c["spec"] and c["tests"] for c in suite["cases"]))
    check("no case invents an SCAS test case name", all(c.get("scas", "") == "" for c in suite["cases"]))
    rx = run("security", "--regex").stdout.strip()
    check("--regex is the expression that selects exactly the suite", rx.startswith("^(") and rx.endswith(")$") and set(rx[2:-2].split("|")) == wanted)
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        cases = suite["cases"]
        passing = {x for c in cases[:-2] for x in c["tests"]}
        failing = cases[-2]["tests"][0]
        body = "".join('<testcase name="%s"/>' % n for n in sorted(passing)) + '<testcase name="%s"><failure message="boom"/></testcase>' % failing
        (d / "sec.xml").write_text('<testsuite name="x">%s</testsuite>' % body)
        p = run("security", "--results", str(d / "sec.xml"), "--out", str(d / "sec"))
        rep = json.loads((d / "sec" / "security.json").read_text())
        by = {c["id"]: c["result"] for c in rep["cases"]}
        check("verdicts: passing tests pass, a failing test fails its case, tests that did not run are not run", by[cases[0]["id"]] == "pass" and by[cases[-2]["id"]] == "fail" and by[cases[-1]["id"]] == "not run", by)
        check("a failed case is exit code 1", p.returncode == 1, p.stdout)
        html_text = (d / "sec" / "security.html").read_text()
        check("the report lists the security rows of the matrices, the gaps among them", "AMF-GAP-01" in html_text and "gap" in html_text and "SEC-AKA-01" in html_text)
        csv_lines = (d / "sec" / "security.csv").read_text().splitlines()
        check("CSV has one line per case and an empty SCAS column", len(csv_lines) == len(cases) + 1 and csv_lines[0].split(",")[6] == "scas test case")
        p = run("security", "--results", str(d / "none.xml"), "--out", str(d / "sec2"))
        check("without results nothing is claimed as passed", "'pass'" not in p.stdout and "not run" in p.stdout and p.returncode == 0, p.stdout)
        (d / "ok.xml").write_text('<testsuite name="x">%s</testsuite>' % "".join('<testcase name="%s"/>' % n for n in sorted(wanted)))
        p = run("security", "--results", str(d / "ok.xml"), "--out", str(d / "sec3"))
        check("all passing: exit 0", p.returncode == 0 and "'pass': %d" % len(cases) in p.stdout, p.stdout)
        p = run("dossier", "--results", str(d / "ok.xml"), "--out", str(d / "dos" / "dossier"))
        check("the dossier has the security assurance folder and lists it in its index", (d / "dos" / "dossier" / "security-assurance" / "security.html").exists()
              and "security-assurance/security.html" in (d / "dos" / "dossier" / "index.html").read_text())
    print("dossier: PASS" if ok else "dossier: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
