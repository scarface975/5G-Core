#!/usr/bin/env python3
"""tools/cli/g5c-triage on synthetic bundles: a sick one (UPF refusing, paging failures, injection left in, no TLS, a certificate about to expire, rejected registrations) is found rule by rule
with its advice; a healthy one is clean; a bundle without parts says 'not checked'; every runbook the rules point at exists; bad input is exit 2."""
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-triage"


def bundle(path, files):
    with tarfile.open(path, "w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo("g5c-diag/" + name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))


def run(args):
    return subprocess.run([sys.executable, str(TOOL)] + args, capture_output=True, text=True)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    sick = {
        "summary.txt": "bundle made: x\nrelease: 0.9.0-rc1\n",
        "certificates.txt": "amf            expires Nov 20 07:46:15 2026 GMT (10 days)\nca             expires Nov  3 07:46:14 2031 GMT (1824 days)\n",
        "log/smf.log": "2026-11-04T08:00:00Z  INFO g5c_smf: ok\n" + "2026-11-04T08:00:01Z  ERROR g5c_smf: N4 session establishment on upf-1 failed for imsi-1/5 (cause 72)\n" * 2 +
                       "2026-11-04T08:00:02Z  WARN g5c_smf: UPF upf-1 is down: heartbeat\n",
        "log/amf.log": "".join("2026-11-04T08:00:%02dZ  WARN g5c_amf: paging of imsi-00101~%d failed\n" % (i, i) for i in range(5)),
        "conf/amf.yaml": "name: amf-1\nsbi: { address: 127.0.0.5, port: 7777 }\namf:\n  inject: { registration_reject: [] }\n",
        "conf/nrf.yaml": "name: nrf-1\nsbi: { address: 127.0.0.10, port: 7777 }\n",
        "metrics/amf.txt": "# TYPE g5c_amf_registrations_total counter\ng5c_amf_registrations_total{result=\"rejected\"} 12\ng5c_amf_registrations_total{result=\"accepted\"} 100\n",
        "metrics/nrf.txt": "g5c_nrf_profiles 12\n",
    }
    healthy = {
        "summary.txt": "release: 0.9.0-rc1\n",
        "certificates.txt": "amf            expires Feb  2 07:46:15 2027 GMT (89 days)\n",
        "log/smf.log": "2026-11-04T08:00:00Z  INFO g5c_smf: all well\n",
        "conf/smf.yaml": "name: smf-1\nsbi: { address: 1.2.3.4, port: 1, tls: { cert: a, key: b, ca: c } }\n",
        "conf/nrf.yaml": "name: nrf-1\nsbi: { tls: {} }\noauth2: { enforce: true }\n",
        "metrics/amf.txt": "g5c_amf_registrations_total{result=\"rejected\"} 0\n",
        "metrics/nrf.txt": "g5c_nrf_profiles 12\n",
    }
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        bundle(d / "sick.tar.gz", sick)
        bundle(d / "ok.tar.gz", healthy)
        bundle(d / "thin.tar.gz", {"summary.txt": "release: 0.9.0-rc1\n"})

        r = run([str(d / "sick.tar.gz"), "--json"])
        rep = json.loads(r.stdout)
        ids = {f["rule"]: f for f in rep["findings"]}
        check("the sick bundle exits 1", r.returncode == 1, r.returncode)
        check("the UPF refusing N4, the UPF down, paging failures, injection, no TLS, the certificate, rejected registrations are all found",
              {"KI-LOG-N4-REFUSED", "KI-LOG-UPF-ASSOC", "KI-LOG-PAGING", "KI-CONF-INJECT", "KI-CONF-NOTLS", "KI-CERT-EXPIRY", "KI-METRIC-REJECT"} <= set(ids), sorted(ids))
        check("counts and places: two N4 failures in smf, five pagings in amf, the certificate named", ids["KI-LOG-N4-REFUSED"]["count"] == 2 and ids["KI-LOG-N4-REFUSED"]["where"] == ["smf"] and
              ids["KI-LOG-PAGING"]["count"] == 5 and "amf (10 days)" in ids["KI-CERT-EXPIRY"]["where"], ids["KI-LOG-N4-REFUSED"])
        check("the registrations metric is judged on the series asked for (12 rejected, not the 100 accepted)", ids["KI-METRIC-REJECT"]["count"] == 12)
        check("nothing is reported for what is fine: 12 NRF profiles, no 'unreachable' flood", "KI-METRIC-NRFREG" not in ids and "KI-LOG-UNREACHABLE" not in ids)
        r = run([str(d / "sick.tar.gz")])
        check("the text names the severity, the advice and the runbook", "[HIGH]" in r.stdout and "do:" in r.stdout and "runbook: docs/ops/runbooks.md" in r.stdout and "release 0.9.0-rc1" in r.stdout, r.stdout[:400])
        r = run([str(d / "sick.tar.gz"), "--min-severity", "high", "--json"])
        check("--min-severity high keeps only the high ones", all(f["severity"] == "high" for f in json.loads(r.stdout)["findings"]) and r.returncode == 1)

        r = run([str(d / "ok.tar.gz"), "--json"])
        rep = json.loads(r.stdout)
        check("a healthy bundle exits 0 with no findings", r.returncode == 0 and rep["findings"] == [], rep["findings"])

        r = run([str(d / "thin.tar.gz"), "--json"])
        rep = json.loads(r.stdout)
        check("a bundle with nothing in it says 'not checked' for every rule instead of passing them", r.returncode == 0 and len(rep["notChecked"]) == rep["checked"], rep)

        check("an unreadable bundle is exit 2", run([str(d / "nope.tar.gz")]).returncode == 2 and run([]).returncode == 2)
        (d / "badrules.json").write_text("{}")
        check("rules without a rules list are exit 2", run([str(d / "ok.tar.gz"), "--rules", str(d / "badrules.json")]).returncode == 2)

    rules = json.loads((ROOT / "docs" / "ops" / "known-issues.json").read_text())["rules"]
    headings = set(re.findall(r"^## (.+)$", (ROOT / "docs" / "ops" / "runbooks.md").read_text(), re.M))
    check("every rule has an id, a title, advice and a runbook that exists in docs/ops/runbooks.md",
          all(r.get("id") and r.get("title") and r.get("advice") and r.get("runbook") in headings for r in rules) and len({r["id"] for r in rules}) == len(rules),
          [r["id"] for r in rules if r.get("runbook") not in headings])
    for r in rules:
        if r["kind"] in ("log",):
            re.compile(r["pattern"])
    print("triage: PASS" if ok else "triage: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
