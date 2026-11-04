#!/usr/bin/env python3
"""tools/cli/g5c-nwdaf: the load, slice and registration analytics on constructed windows (steady, a spike, a drop, rejections, too few samples), and the service against fake functions: the
analytics endpoint, a bad event id, the Prometheus series."""
import importlib.machinery
import importlib.util
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent.parent
os.environ["G5C_LIVE_HTTP1"] = "1"
ld = importlib.machinery.SourceFileLoader("g5c_nwdaf", str(ROOT / "tools" / "cli" / "g5c-nwdaf"))
spec = importlib.util.spec_from_loader("g5c_nwdaf", ld)
nw = importlib.util.module_from_spec(spec)
ld.exec_module(nw)
ARGS = SimpleNamespace(sigma=3.0, reject_share=20.0)


def amf(regs, rej=0, ues=10):
    return [("g5c_amf_registrations_total", {"result": "accepted"}, float(regs - rej)), ("g5c_amf_registrations_total", {"result": "rejected"}, float(rej)),
            ("g5c_amf_ue_contexts", {}, float(ues)), ("g5c_sbi_requests_total", {"status": "200"}, float(regs * 3)), ("g5c_sbi_requests_total", {"status": "503"}, float(rej))]


def window(counts, rej=None):
    w = nw.Window(60)
    for i, c in enumerate(counts):
        w.add(1000.0 + i * 5, {"amf": amf(c, rej[i] if rej else 0)})
    return w


def fake(body):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            b = body().encode() if self.path == "/metrics" else b""
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    s = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, "http://127.0.0.1:%d" % s.server_address[1]


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    steady = [0, 50, 100, 150, 200, 250, 300, 350]  # 10 registrations a second
    an = nw.registration_anomaly(window(steady), 3.0, 20.0)
    check("a steady registration rate is normal", an["status"] == "normal" and abs(an["ratePerSecond"] - 10) < 0.01, an)
    spike = steady + [350 + 500]  # 100 a second after ten
    an = nw.registration_anomaly(window(spike), 3.0, 20.0)
    check("a ten-fold jump is abnormal and says so", an["status"] == "abnormal" and an["zScore"] > 3 and "above" in an["reasons"][0], an)
    drop = steady + [350]  # nothing new in the last interval
    an = nw.registration_anomaly(window(drop), 3.0, 20.0)
    check("a stop is abnormal too (below the mean)", an["status"] == "abnormal" and "below" in an["reasons"][0], an)
    an = nw.registration_anomaly(window([0, 50, 100, 150, 200, 250], rej=[0, 20, 40, 60, 80, 100]), 3.0, 20.0)
    check("a high rejected share is abnormal although the rate is steady", an["status"] == "abnormal" and any("rejected" in r for r in an["reasons"]), an)
    an = nw.registration_anomaly(window([0, 50, 100]), 3.0, 20.0)
    check("too few samples are said so, not called normal", an["status"] == "not enough samples" and an["needed"] == 5, an)

    load = nw.nf_load(window(steady))
    check("NF_LOAD: the gauge, the request rate over the window and the share of server errors", load[0]["nfLoadLevelAverage"] == 10.0 and abs(load[0]["requestsPerSecond"] - 30) < 0.01 and
          load[0]["serverErrorSharePercent"] == 0.0, load)
    w = nw.Window(5)
    w.add(1.0, {"smf": [("g5c_smf_pdu_sessions_by_slice", {"snssai": "1"}, 30.0), ("g5c_smf_pdu_sessions_by_slice", {"snssai": "1-000001"}, 10.0)]})
    sl = nw.slice_load(w)
    check("SLICE_LOAD_LEVEL: sessions per slice and their share", sl == [{"snssai": "1", "pduSessions": 30, "sharePercent": 75.0}, {"snssai": "1-000001", "pduSessions": 10, "sharePercent": 25.0}], sl)
    check("no slice metric, no slice analytics (an empty list, not a guess)", nw.slice_load(window(steady)) == [])

    # the service
    state = {"n": 0}

    def body():
        state["n"] += 1
        return "g5c_amf_registrations_total{result=\"accepted\"} %d\ng5c_amf_ue_contexts 7\n" % (state["n"] * 50)

    srv, url = fake(body)
    sm = nw.Sampler([("amf", url)], 20)
    for _ in range(6):
        sm.sample()
    http = ThreadingHTTPServer(("127.0.0.1", 0), nw.make_handler(sm, ARGS))
    threading.Thread(target=http.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % http.server_address[1]
    d = json.loads(urllib.request.urlopen(base + "/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD").read())
    check("GET analytics NF_LOAD from fake functions", d["nfLoadLevelInfos"][0]["nfInstanceName"] == "amf" and d["nfLoadLevelInfos"][0]["nfLoadLevelAverage"] == 7.0, d)
    d = json.loads(urllib.request.urlopen(base + "/nnwdaf-analyticsinfo/v1/analytics?event-id=REGISTRATION_ANOMALY").read())
    check("GET analytics REGISTRATION_ANOMALY", d["registrationAnomaly"]["status"] in ("normal", "abnormal") and d["registrationAnomaly"]["samples"] == 6, d)
    try:
        urllib.request.urlopen(base + "/nnwdaf-analyticsinfo/v1/analytics?event-id=NOPE")
        check("an unknown event id is 400", False)
    except urllib.error.HTTPError as e:
        check("an unknown event id is 400 with a problem document", e.code == 400 and json.loads(e.read())["cause"] == "MANDATORY_QUERY_PARAM_INCORRECT")
    m = urllib.request.urlopen(base + "/metrics").read().decode()
    check("Prometheus series for the same analytics", 'g5c_nwdaf_nf_load{function="amf"} 7.0' in m and "g5c_nwdaf_registration_abnormal" in m, m)
    try:
        nw.parse_nfs(["amf"])
        check("--nf without a URL is refused", False)
    except SystemExit:
        check("--nf without a URL is refused", True)
    http.shutdown()
    srv.shutdown()
    print("nwdaf: PASS" if ok else "nwdaf: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
