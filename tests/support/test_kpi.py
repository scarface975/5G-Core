#!/usr/bin/env python3
"""tools/g5c-kpi: the KPI arithmetic on a fixed exposition, targets and the exit code, periods from two samples, the recording rules in step with the definitions, and every metric the
definitions name exists in the sources."""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "g5c-kpi"
DEFS = ROOT / "deploy" / "ops" / "kpis.json"

SAMPLE_A = """\
# HELP g5c_amf_registrations_total Registration requests by result.
g5c_amf_registrations_total{result="accepted"} 90
g5c_amf_registrations_total{result="rejected"} 10
g5c_amf_authentications_total{result="success"} 95
g5c_amf_authentications_total{result="failed"} 5
g5c_amf_pdu_session_requests_total{result="created",snssai="1"} 30
g5c_amf_pdu_session_requests_total{result="created",snssai="2-000001"} 20
g5c_amf_pdu_session_requests_total{result="smf_error",snssai="1"} 10
g5c_amf_pdu_session_requests_total{result="smf_error",snssai="2-000001"} 40
g5c_amf_handover_total{result="completed"} 19
g5c_amf_handover_total{result="aborted"} 1
g5c_amf_registered_ues 7
g5c_smf_pdu_sessions_active 3
g5c_upf_bytes_total{direction="uplink"} 1000
g5c_upf_bytes_total{direction="downlink"} 4000
g5c_upf_packets_total{direction="uplink"} 990
g5c_upf_dropped_packets_total{reason="no_pdr"} 10
g5c_smf_create_sm_context_seconds_bucket{le="0.1"} 50
g5c_smf_create_sm_context_seconds_bucket{le="0.5"} 95
g5c_smf_create_sm_context_seconds_bucket{le="+Inf"} 100
g5c_sbi_requests_total{status="200"} 990
g5c_sbi_requests_total{status="503"} 10
"""

SAMPLE_B = SAMPLE_A.replace('{result="accepted"} 90', '{result="accepted"} 190').replace('g5c_upf_bytes_total{direction="downlink"} 4000', 'g5c_upf_bytes_total{direction="downlink"} 14000').replace("g5c_amf_registered_ues 7", "g5c_amf_registered_ues 9")


def run(*args, expect=0):
    p = subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True)
    return p


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        a, b = Path(d) / "a.prom", Path(d) / "b.prom"
        a.write_text(SAMPLE_A)
        b.write_text(SAMPLE_B)
        p = run("--json", str(a))
        rows = {r["id"]: r for r in json.loads(p.stdout)}
        check("registration success 90/100", abs(rows["registration_success_rate"]["value"] - 90.0) < 1e-9, rows["registration_success_rate"])
        check("authentication success 95/100", abs(rows["authentication_success_rate"]["value"] - 95.0) < 1e-9)
        check("PDU session success 50/100, handover 19/20", abs(rows["pdu_session_establishment_success_rate"]["value"] - 50.0) < 1e-9 and abs(rows["handover_success_rate"]["value"] - 95.0) < 1e-9)
        check("gauges summed", rows["registered_ues"]["value"] == 7 and rows["active_pdu_sessions"]["value"] == 3)
        check("p95 of the latency histogram is the 0.5 s bucket's edge", abs(rows["sm_context_create_p95"]["value"] - 0.5) < 1e-9, rows["sm_context_create_p95"])
        check("drop rate = dropped / (forwarded + dropped)", abs(rows["user_plane_drop_rate"]["value"] - 1.0) < 1e-9, rows["user_plane_drop_rate"])
        check("regex label selector (5xx) and a plain ratio", abs(rows["sbi_error_rate"]["value"] - 1.0) < 1e-9, rows["sbi_error_rate"])
        check("a rate without a period is empty", rows["uplink_throughput"]["value"] is None)
        check("a KPI `by` a label gets one row per slice", abs(rows["pdu_session_success_per_slice{snssai=1}"]["value"] - 75.0) < 1e-9 and abs(rows["pdu_session_success_per_slice{snssai=2-000001}"]["value"] - 100.0 * 20 / 60) < 1e-9
              and "pdu_session_success_per_slice" not in rows, [k for k in rows if "slice" in k])
        check("target missed -> MISS (registration 90 < 99)", rows["registration_success_rate"]["status"] == "MISS")
        check("--check exits 1 on a miss", run("--check", str(a)).returncode == 1)
        # the period between two samples: 100 more registrations all accepted, 10000 more downlink bytes in 10 s
        p = run("--json", "--baseline", str(a), "--elapsed", "10", str(b))
        rows = {r["id"]: r for r in json.loads(p.stdout)}
        check("period: 100 of 100 accepted", abs(rows["registration_success_rate"]["value"] - 100.0) < 1e-9 and rows["registration_success_rate"]["status"] == "ok", rows["registration_success_rate"])
        check("period: downlink 10000 bytes in 10 s = 8 kbit/s", abs(rows["downlink_throughput"]["value"] - 8000.0) < 1e-6, rows["downlink_throughput"])
        check("period: gauges are the latest values, not deltas", rows["registered_ues"]["value"] == 9)
        check("period: too little traffic is n/a, not a miss", rows["handover_success_rate"]["status"] == "n/a", rows["handover_success_rate"])
        check("--check passes on that period", run("--check", "--baseline", str(a), "--elapsed", "10", str(b)).returncode == 0)
        # a directory (a diagnostics bundle's metrics folder)
        p = run("--json", d)
        check("a directory of files is read as one", p.returncode == 0 and len(json.loads(p.stdout)) > 10, p.stderr)

    check("recording rules match the committed file", run("--check-rules", str(ROOT / "deploy" / "ops" / "prometheus-kpi-rules.yml")).returncode == 0)
    # every metric the definitions use is registered somewhere in the sources
    names = set(re.findall(r'"(g5c_[a-z0-9_]+)"', "".join(f.read_text(errors="replace") for f in list((ROOT / "nf").rglob("*.c")) + list((ROOT / "libs").rglob("*.c")))))
    defs = json.load(open(DEFS))
    used = set()
    for k in defs["kpis"]:
        for key in ("of", "num", "den", "den_add"):
            used |= {s["metric"] for s in k.get(key, [])}
        if "histogram" in k:
            used.add(k["histogram"])
    missing = sorted(used - names)
    check("every metric of the definitions exists in the sources", not missing, missing)
    print("kpi: PASS" if ok else "kpi: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
