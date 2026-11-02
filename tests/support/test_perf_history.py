#!/usr/bin/env python3
"""tools/release/perf_history.py: the numbers come out of a regression summary, a collapse is flagged, a normal swing is not, the chart renders."""
import importlib.util
import sys
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("ph", Path(__file__).resolve().parent.parent.parent / "tools" / "release" / "perf_history.py")
ph = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ph)

SUMMARY = """\
UPF uplink   best: 3.60 Gbit/s delivered, 3.7 Gbit/s capacity
UPF downlink best: 2.09 Gbit/s delivered, 2.1 Gbit/s capacity
SLO (cluster-load): SLO: PASS (throughput 127 UE/s, p99 registration 177.1 ms, PDU session 92.5 ms, de-registration 129.0 ms)
SLO (cluster-load-tls): SLO: PASS (throughput 93 UE/s, p99 registration 443.8 ms, PDU session 209.9 ms, de-registration 98.6 ms)
"""


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    m = ph.parse_summary(SUMMARY)
    check("numbers parsed", m == {"reg_per_s": 127.0, "p99_registration_ms": 177.1, "reg_per_s_tls": 93.0, "p99_registration_ms_tls": 443.8, "upf_uplink_gbit": 3.6, "upf_downlink_gbit": 2.09}, m)
    base = [{"version": "0.8.%d" % i, "metrics": dict(m)} for i in range(4)]
    swing = {"version": "0.9", "metrics": dict(m, reg_per_s=80.0, p99_registration_ms=230.0)}  # a bad day on a shared host, inside the tolerance
    check("a normal swing is not a regression", ph.regress(base + [swing], 0.4, 5) == [])
    collapse = {"version": "0.9", "metrics": dict(m, reg_per_s=30.0, upf_downlink_gbit=0.4, p99_registration_ms=900.0)}
    bad = {k for k, _, _ in ph.regress(base + [collapse], 0.4, 5)}
    check("a collapse is flagged for throughput, latency and the user plane", bad == {"reg_per_s", "upf_downlink_gbit", "p99_registration_ms"}, bad)
    check("one entry alone cannot regress", ph.regress(base[:1], 0.4, 5) == [])
    page = ph.chart(base + [swing])
    check("the chart is a page with a line per metric", page.startswith("<!doctype html>") and page.count("<polyline") == 6, page.count("<polyline"))
    print("perf history: PASS" if ok else "perf history: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
