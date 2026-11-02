#!/usr/bin/env python3
"""tools/g5c-dossier: rows get the verdict of their tests, a gap stays a gap, the three report formats are written, the dossier has a manifest that matches its files."""
import hashlib
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "g5c-dossier"
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
    print("dossier: PASS" if ok else "dossier: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
