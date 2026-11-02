#!/usr/bin/env python3
"""tools/cli/g5c-scenario: validation, step semantics (expect pass / fail / any, background loads, assertions on metrics, KPIs), stopping at the first failure, impairment always cleared."""
import importlib.machinery
import importlib.util
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
loader = importlib.machinery.SourceFileLoader("g5c_scenario", str(ROOT / "tools" / "cli" / "g5c-scenario"))
spec = importlib.util.spec_from_loader("g5c_scenario", loader)
sc = importlib.util.module_from_spec(spec)
loader.exec_module(sc)


class Fake:
    def __init__(self, load_ok=True, metrics=None, kpis=None, http=200):
        self.calls, self.load_ok, self.metrics, self.kpis, self.http_code = [], load_ok, metrics or {}, kpis or {}, http
        self.cleared = 0

    def load(self, a):
        self.calls.append(("load", a["ues"]))
        return self.load_ok

    def load_bg(self, a):
        self.calls.append(("load_bg", a["id"]))

    def join(self, i):
        self.calls.append(("join", i))
        return self.load_ok

    def impair(self, a):
        if a == "clear":
            self.cleared += 1
        self.calls.append(("impair", a))

    def kill(self, nf): self.calls.append(("kill", nf))
    def restart(self, nf): self.calls.append(("restart", nf))
    def start(self, nf): self.calls.append(("start", nf))
    def sleep(self, s): self.calls.append(("sleep", s))
    def metric(self, nf, name, labels): return self.metrics.get((nf, name, tuple(sorted(labels.items()))), 0.0)
    def kpi_value(self, n): return self.kpis.get(n)

    def fetch(self, nf, path, method="GET", body=None):
        self.calls.append(("http", nf, path))
        return self.http_code, ""


def run(steps, r):
    res, _ = sc.run_scenario({"steps": steps}, r, out=lambda *a: None)
    return res


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    check("well formed", sc.validate({"steps": [{"load": {"ues": 5}}, {"kill": "smf"}, {"wait": 2}, {"impair": "clear"}]}) == [])
    check("no steps", sc.validate({"steps": []}) != [])
    check("unknown step", any("exactly one" in e for e in sc.validate({"steps": [{"explode": 1}]})))
    check("join without a background load", any("join" in e for e in sc.validate({"steps": [{"join": "x"}]})))
    check("background load needs an id", any("id" in e for e in sc.validate({"steps": [{"load": {"ues": 3, "background": True}}]})))
    check("bad assert", any("assert" in e for e in sc.validate({"steps": [{"assert": {"metric": "nonsense"}}]})))
    check("impair needs a target", any("impair" in e for e in sc.validate({"steps": [{"impair": {"delay_ms": 5}}]})))
    check("impair with duplication / reordering / jitter is valid", sc.validate({"steps": [{"impair": {"to": "upf", "duplicate_pct": 3, "reorder_pct": 10, "delay_ms": 20, "jitter_ms": 5}}]}) == [])
    check("impair with only a jitter is not (there is no delay to refine)", any("impair" in e for e in sc.validate({"steps": [{"impair": {"to": "upf", "jitter_ms": 5}}]})))
    check("bad expect", any("expect" in e for e in sc.validate({"steps": [{"load": {"ues": 1}, "expect": "maybe"}]})))
    check("metric spec parsed", sc.parse_metric('amf:g5c_amf_registrations_total{result="accepted",x=y}') == ("amf", "g5c_amf_registrations_total", {"result": "accepted", "x": "y"}))

    r = Fake(metrics={("amf", "g5c_amf_registrations_total", (("result", "accepted"),)): 25.0}, kpis={"registration_success_rate": 99.5})
    res = run([{"load": {"ues": 5}}, {"assert": {"metric": "amf:g5c_amf_registrations_total{result=accepted}", ">=": 20}}, {"kpi": {"name": "registration_success_rate", ">=": 99}}, {"http": {"nf": "udm", "path": "/x"}}], r)
    check("a passing scenario", all(x["ok"] for x in res) and len(res) == 4, res)
    res = run([{"assert": {"metric": "amf:g5c_amf_registrations_total{result=accepted}", ">=": 30}}, {"log": "never reached"}], r)
    check("a failed assertion stops the scenario and says why", len(res) == 1 and not res[0]["ok"] and "25.0 >= 30" in res[0]["detail"], res)
    res = run([{"kpi": {"name": "registration_success_rate", ">=": 99}}, {"kpi": {"name": "no_traffic", ">=": 1}}], r)
    check("a KPI without a value fails", res[0]["ok"] and not res[1]["ok"], res)
    bad = Fake(load_ok=False)
    check("a failed load fails the step", not run([{"load": {"ues": 5}}], bad)[0]["ok"])
    check("expect: fail passes on failure and fails on success", run([{"load": {"ues": 5}, "expect": "fail"}], bad)[0]["ok"] and not run([{"load": {"ues": 5}, "expect": "fail"}], Fake())[0]["ok"])
    check("expect: any accepts both", run([{"load": {"ues": 5}, "expect": "any"}], bad)[0]["ok"] and run([{"load": {"ues": 5}, "expect": "any"}], Fake())[0]["ok"])
    r = Fake()
    run([{"load": {"ues": 9, "id": "w", "background": True}}, {"kill": "smf"}, {"start": "smf"}, {"join": "w"}], r)
    check("a background load runs while the function is killed, then is joined", [c[0] for c in r.calls[:4]] == ["load_bg", "kill", "start", "join"], r.calls)
    r = Fake()
    run([{"impair": {"to": "upf", "delay_ms": 100}}, {"assert": {"metric": "amf:x", ">=": 1}}], r)
    check("a failing scenario still lifts the impairment", r.cleared >= 1, r.calls)
    check("an http step compares the status", run([{"http": {"nf": "udm", "path": "/x", "expect": 404}}], Fake(http=404))[0]["ok"] and not run([{"http": {"nf": "udm", "path": "/x"}}], Fake(http=500))[0]["ok"])
    xml = sc.junit("t", [{"step": 1, "name": "load", "ok": True, "detail": "", "seconds": 1}, {"step": 2, "name": "assert", "ok": False, "detail": "1 >= 2", "seconds": 0.1}], 1.1)
    root = ET.fromstring(xml)
    check("JUnit: two cases, one failure", root.get("tests") == "2" and root.get("failures") == "1" and root.find("testcase[2]/failure") is not None, xml)
    for f in sorted((ROOT / "scenarios").glob("*.yaml")):
        errs = sc.validate(sc.load_doc(f))
        check("shipped scenario %s is valid" % f.name, errs == [], errs)
    print("scenario: PASS" if ok else "scenario: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
