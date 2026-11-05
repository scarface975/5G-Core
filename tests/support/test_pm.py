#!/usr/bin/env python3
"""tools/cli/g5c-pm: the measurements of TS 28.552 computed from metrics text: a count since start, the increase over a period (with a counter that went back), the mean and the maximum of a gauge,
a measurement whose metric is absent; the files; the read-only HTTP view (types, measurements, files, the token, no writes); the table itself (clauses present, names unique)."""
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-pm"

AMF = """# HELP g5c_amf_registration_procedures_total x
g5c_amf_registration_procedures_total{type="initial",stage="requested"} 10
g5c_amf_registration_procedures_total{type="initial",stage="accepted"} 9
g5c_amf_registration_procedures_total{type="periodic",stage="requested"} 4
g5c_amf_registration_procedures_by_slice_total{type="initial",stage="requested",snssai="1"} 6
g5c_amf_registration_procedures_by_slice_total{type="initial",stage="requested",snssai="1-000001"} 4
g5c_amf_registration_procedures_by_slice_total{type="initial",stage="accepted",snssai="1"} 5
g5c_amf_registration_procedures_by_slice_total{type="periodic",stage="requested",snssai="none"} 4
g5c_amf_service_requests_total{result="accepted"} 6
g5c_amf_service_requests_total{result="rejected"} 2
g5c_amf_registered_ues 9
"""
SMF = ('g5c_smf_sm_context_requests_total{op="create",result="ok"} 8\n'
       'g5c_smf_sm_context_requests_total{op="create",result="rejected"} 1\n'
       'g5c_smf_sm_context_requests_total{op="release",result="ok"} 5\n')
UPF = ('g5c_upf_packets_total{direction="uplink"} 100\n'
       'g5c_upf_packets_total{direction="downlink"} 90\n'
       'g5c_upf_bytes_total{direction="uplink"} 12000\n')


def run(args, **kw):
    return subprocess.run([sys.executable, str(TOOL)] + args, capture_output=True, text=True, **kw)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        for n, t in (("amf", AMF), ("smf", SMF), ("upf", UPF)):
            (d / (n + ".txt")).write_text(t)
        srcs = ["--amf-file", str(d / "amf.txt"), "--smf-file", str(d / "smf.txt"), "--upf-file", str(d / "upf.txt")]
        r = run(["collect"] + srcs + ["--out", str(d / "out")])
        files = sorted((d / "out").glob("PM_*"))
        check("collect since start writes a JSON and a CSV file", r.returncode == 0 and [f.suffix for f in files] == [".csv", ".json"], (r.returncode, r.stderr, files))
        rep = json.loads(next(f for f in files if f.suffix == ".json").read_text())
        v = {m["name"]: m["value"] for m in rep["measurements"]}
        check("registrations are counted per type", v.get("RM.RegInitReq") == 10 and v.get("RM.RegInitSucc") == 9 and v.get("RM.RegPeriodReq") == 4 and v.get("RM.RegMobReq") == 0, v)
        check("the registration measurements have a subcounter per S-NSSAI",
              v.get("RM.RegInitReq.1") == 6 and v.get("RM.RegInitReq.1-000001") == 4 and v.get("RM.RegInitSucc.1") == 5 and v.get("RM.RegPeriodReq.none") == 4 and "RM.RegMobReq.1" not in v, v)
        check("service requests: attempts are accepted + rejected, successes the accepted", v.get("MM.ServiceReqTotalAtt") == 8 and v.get("MM.ServiceReqTotalSucc") == 6, v)
        check("PDU session creations count the create operation only", v.get("SM.PduSessionCreationReq") == 9 and v.get("SM.PduSessionCreationSucc") == 8, v)
        check("GTP packets and octets by direction; what is not exposed is zero",
              v.get("GTP.InDataPktN3UPF") == 100 and v.get("GTP.OutDataPktN3UPF") == 90 and v.get("GTP.InDataOctN3UPF") == 12000 and v.get("GTP.OutDataOctN3UPF") == 0, v)
        check("a gauge since start is its value", v.get("RM.RegisteredSubNbrMax") == 9 and v.get("RM.RegisteredSubNbrMean") == 9, v)
        check("every row carries its clause and fidelity", all(m["clause"].startswith("TS 28.552 5.") and m["fidelity"] for m in rep["measurements"]))
        csvtxt = next(f for f in files if f.suffix == ".csv").read_text()
        check("the CSV has a header and a row per measurement", csvtxt.splitlines()[0].startswith("beginTime,endTime") and len(csvtxt.splitlines()) == len(rep["measurements"]) + 1)

        only = run(["collect", "--amf-file", str(d / "amf.txt"), "--out", str(d / "o2"), "--format", "json"])
        rep2 = json.loads(next((d / "o2").glob("PM_*.json")).read_text())
        check("with only the AMF as a source only AMF measurements are reported",
              only.returncode == 0 and {m["nf"] for m in rep2["measurements"]} == {"AMF"} and rep2["sources"] == ["AMF"], rep2["sources"])
        check("no source is exit 2", run(["collect"]).returncode == 2)
        check("an unreadable source is exit 2", run(["collect", "--amf-file", str(d / "none.txt")]).returncode == 2)
        check("types lists every measurement of the table",
              len(run(["types"]).stdout.splitlines()) == len(json.loads((ROOT / "docs/pm/measurements.json").read_text())["measurements"]))

    # a period: the increase, a counter that went back, the mean and the maximum of a gauge
    state = {"n": 0}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            state["n"] += 1
            n = state["n"]
            ues = [3, 9, 6, 6, 6, 6, 6, 6][min(n - 1, 7)]
            reg = 100 + 5 * n if n < 4 else 2   # restarts: 2 is below the start value
            body = ('g5c_amf_registration_procedures_total{type="initial",stage="requested"} %d\n'
                    'g5c_amf_service_requests_total{result="accepted"} %d\n'
                    'g5c_amf_registered_ues %d\n') % (reg, 10 * n, ues)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d/metrics" % srv.server_address[1]
    with tempfile.TemporaryDirectory() as d:
        r = run(["collect", "--amf", url, "--period", "3", "--interval", "1", "--out", d, "--format", "json"])
        rep = json.loads(next(Path(d).glob("PM_*.json")).read_text()) if r.returncode == 0 else {}
        v = {m["name"]: m["value"] for m in rep.get("measurements", [])}
        check("a period of 3 s sampled every second keeps the maximum of the gauge",
              r.returncode == 0 and v.get("RM.RegisteredSubNbrMax") == 9 and 3 <= v.get("RM.RegisteredSubNbrMean", 0) <= 9, (r.stderr, v))
        check("a counter that went back counts from zero", v.get("RM.RegInitReq") == 2 and rep.get("granularityPeriod") == 3, v)
        check("a counter that rose is the increase over the period", v.get("MM.ServiceReqTotalSucc", 0) >= 20, v)
    srv.shutdown()

    # the HTTP view
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "amf.txt").write_text(AMF)
        (d / "pmout").mkdir()
        (d / "pmout" / "PM_x_0s.json").write_text('{"a":1}')
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        env = dict(os.environ, G5C_PM_TOKEN="tok-for-the-test")
        p = subprocess.Popen([sys.executable, str(TOOL), "serve", "--amf-file", str(d / "amf.txt"), "--out", str(d / "pmout"), "--listen", "127.0.0.1:%d" % port],
                             env=env, stderr=subprocess.DEVNULL)

        def get(path, tok="tok-for-the-test", method="GET"):
            rq = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), method=method, data=b"{}" if method != "GET" else None)
            if tok:
                rq.add_header("Authorization", "Bearer " + tok)
            try:
                with urllib.request.urlopen(rq, timeout=5) as resp:
                    return resp.status, resp.read().decode()
            except urllib.error.HTTPError as e:
                return e.code, e.read().decode()

        try:
            for _ in range(50):
                try:
                    socket.create_connection(("127.0.0.1", port), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
            st, body = get("/pm/v1/measurementTypes")
            check("the view lists the measurement types", st == 200 and len(json.loads(body)["measurements"]) >= 15, (st, body[:80]))
            st, body = get("/pm/v1/measurements?period=0")
            check("the view reports the measurements now",
                  st == 200 and any(m["name"] == "RM.RegInitReq" and m["value"] == 10 for m in json.loads(body)["measurements"]), (st, body[:80]))
            check("a period above 300 s is refused", get("/pm/v1/measurements?period=1000")[0] == 400)
            st, body = get("/pm/v1/files")
            check("the files are listed and can be read", st == 200 and "PM_x_0s.json" in body and get("/pm/v1/files/PM_x_0s.json") == (200, '{"a":1}'), (st, body))
            check("a path outside the files is not served", get("/pm/v1/files/..%2Famf.txt")[0] == 404 and get("/pm/v1/files/PM_none.json")[0] == 404)
            check("without the token it is 401, with a wrong one too", get("/pm/v1/files", tok="")[0] == 401 and get("/pm/v1/files", tok="nope")[0] == 401)
            check("nothing can be written", all(get("/pm/v1/files", method=m)[0] == 405 for m in ("POST", "PUT", "DELETE", "PATCH")))
        finally:
            p.terminate()
            p.wait(5)

    table = json.loads((ROOT / "docs/pm/measurements.json").read_text())["measurements"]
    check("the table has unique names, clauses and a fidelity statement for each",
          len({m["name"] for m in table}) == len(table) and all(m["clause"].startswith("5.") and m["fidelity"] and m["nf"] in ("AMF", "SMF", "UPF") for m in table))
    print("pm: PASS" if ok else "pm: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
