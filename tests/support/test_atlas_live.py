#!/usr/bin/env python3
"""tools/cli/g5c-atlas-live: against fake functions and a fake NRF - the snapshot (health, release, KPIs with targets, the NRF's registry), a function that is down, the last-minute window, one snapshot per
interval however many browsers ask, the page served with a strict content security policy, and a page that never builds HTML out of data."""
import importlib.machinery
import importlib.util
import json
import os
import re
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-atlas-live"
os.environ["G5C_LIVE_HTTP1"] = "1"
loader = importlib.machinery.SourceFileLoader("g5c_atlas_live", str(TOOL))
spec = importlib.util.spec_from_loader("g5c_atlas_live", loader)
al = importlib.util.module_from_spec(spec)
loader.exec_module(al)

METRICS = """g5c_build_info{version="0.9.0-rc1",function="amf-1"} 1
g5c_amf_registrations_total{result="accepted"} %d
g5c_amf_registrations_total{result="rejected"} %d
g5c_amf_ue_contexts 7
"""
PROFILES = {"11111111-0000-4000-8000-000000000001": {"nfType": "SMF", "nfInstanceId": "11111111-0000-4000-8000-000000000001", "nfStatus": "REGISTERED", "nfServices": [{}, {}]},
            "22222222-0000-4000-8000-000000000002": {"nfType": "AMF", "nfInstanceId": "22222222-0000-4000-8000-000000000002", "nfStatus": "REGISTERED", "nfServices": [{}]}}


def fake(accepted=90, rejected=10, is_nrf=False):
    state = {"accepted": accepted, "rejected": rejected}

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            p = self.path
            if p.startswith("/health/"):
                body, code = b"", 200
            elif p == "/metrics":
                body, code = (METRICS % (state["accepted"], state["rejected"])).encode(), 200
            elif is_nrf and p == "/nnrf-nfm/v1/nf-instances":
                body, code = json.dumps({"_links": {"item": [{"href": "/nnrf-nfm/v1/nf-instances/" + i} for i in PROFILES]}}).encode(), 200
            elif is_nrf and p.startswith("/nnrf-nfm/v1/nf-instances/"):
                body, code = json.dumps(PROFILES[p.rsplit("/", 1)[1]]).encode(), 200
            else:
                body, code = b"", 404
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, state, "http://127.0.0.1:%d" % srv.server_address[1]


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    a_srv, a_state, a_url = fake()
    b_srv, b_state, b_url = fake(accepted=100, rejected=0)
    n_srv, _, n_url = fake(is_nrf=True)
    atlas = al.Atlas([("amf", a_url), ("smf", b_url)], n_url, None)
    snap = atlas.snapshot()
    check("two functions, both live and ready, with the release they run", [f["name"] for f in snap["functions"]] == ["amf", "smf"] and all(f["live"] and f["ready"] for f in snap["functions"]) and
          snap["functions"][0]["version"] == "0.9.0-rc1" and snap["functions"][0]["load"] == 7.0, snap["functions"])
    kp = {k["id"]: k for k in snap["kpis"]}
    check("the KPIs are those of g5c-kpi over the sum of the functions: 190 accepted of 200 = 95 %, below the target of 99", abs(kp["registration_success_rate"]["value"] - 95.0) < 0.01 and
          kp["registration_success_rate"]["status"] == "MISS" and snap["summary"]["kpiMisses"] >= 1, kp.get("registration_success_rate"))
    check("the NRF's registry, by type", [(r["type"], r["services"]) for r in snap["registry"]] == [("AMF", 1), ("SMF", 2)], snap["registry"])
    check("no last-minute view before a minute of samples", snap["kpisLastMinute"] is None and snap["summary"]["windowSeconds"] is None)

    # a minute later: 60 more registrations, all accepted
    now = time.time()
    with atlas.lock:
        atlas.ring = [(now - 60, atlas.ring[-1][1])]
    a_state["accepted"] += 60
    snap = atlas.snapshot()
    check("the last-minute window is computed from the difference, 100 % of the new registrations accepted", snap["kpisLastMinute"] is not None and 58 <= snap["summary"]["windowSeconds"] <= 64 and
          abs({k["id"]: k for k in snap["kpisLastMinute"]}["registration_success_rate"]["value"] - 100.0) < 0.01, snap["summary"])

    # a function goes down
    b_srv.shutdown()
    b_srv.server_close()
    snap = atlas.snapshot()
    smf = [f for f in snap["functions"] if f["name"] == "smf"][0]
    check("a function that stops answering is shown down, the others are not", not smf["live"] and not smf["ready"] and snap["functions"][0]["live"] and snap["summary"]["live"] == 1, snap["summary"])

    # the server
    srv = ThreadingHTTPServer(("127.0.0.1", 0), al.make_handler(atlas, 30))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    r = urllib.request.urlopen(base + "/")
    page = r.read().decode()
    check("the page is served, with a content security policy that allows only itself", r.status == 200 and "Atlas live" in page and "default-src 'self'" in r.headers["Content-Security-Policy"] and "no-store" in r.headers["Cache-Control"])
    d1 = json.loads(urllib.request.urlopen(base + "/api/live").read())
    d2 = json.loads(urllib.request.urlopen(base + "/api/live").read())
    check("/api/live is one snapshot per interval, however many browsers ask", d1["time"] == d2["time"] and "functions" in d1 and "kpis" in d1)
    try:
        urllib.request.urlopen(base + "/nope")
        check("an unknown path is 404", False)
    except urllib.error.HTTPError as e:
        check("an unknown path is 404", e.code == 404)
    srv.shutdown()
    check("the page builds no HTML from data (no innerHTML, no document.write, no eval) and loads nothing from outside", not re.search(r"innerHTML|document\.write|eval\(|insertAdjacentHTML", page) and not re.search(r"https?://", page), re.findall(r"https?://\S+", page))
    check("the page refreshes itself and can switch the KPIs to the last minute", "setInterval(tick" in page and "k-min" in page)
    try:
        al.parse_nfs(["amf"])
        check("--nf without a URL is refused", False)
    except SystemExit as e:
        check("--nf without a URL is refused", "NAME=URL" in str(e))
    try:
        al.parse_nfs([])
        check("no function named is refused", False)
    except SystemExit:
        check("no function named is refused", True)
    for s in (a_srv, n_srv):
        s.shutdown()
    print("atlas live: PASS" if ok else "atlas live: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
