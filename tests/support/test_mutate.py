#!/usr/bin/env python3
"""tools/cli/g5c-mutate: against fake functions that misbehave in each way the sweep must catch (a 500 on hostile input, accepting what is not JSON, going down, answering 401 to everything), and one that behaves.
Also the corruptions it makes of N2 messages. (The fake functions speak HTTP/1.1; G5C_MUTATE_HTTP1=1 makes the tool do the same.)"""
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-mutate"
loader = importlib.machinery.SourceFileLoader("g5c_mutate", str(TOOL))
spec = importlib.util.spec_from_loader("g5c_mutate", loader)
mu = importlib.util.module_from_spec(spec)
loader.exec_module(mu)
os.environ["G5C_MUTATE_HTTP1"] = "1"

DOC = {"paths": {"/good/{id}": {"post": {}, "get": {}}, "/crashy/{id}": {"post": {}}, "/lax": {"put": {}}, "/locked/{id}": {"get": {}, "post": {}}, "/health/ready": {"get": {}}, "/metrics": {"get": {}}}}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    down = False

    def log_message(self, *a):
        pass

    def reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_any(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(n) if n else b""
        path = self.path.split("?")[0]
        if path == "/openapi.json":
            return self.reply(200, json.dumps(DOC).encode())
        if path == "/health/ready":
            return self.reply(503 if H.down else 200)
        if path.startswith("/locked"):
            return self.reply(401)
        if path.startswith("/crashy"):
            if b"[[[[" in body:
                H.down = True
                return self.reply(500)  # a JSON bomb brings it down
            return self.reply(400)
        if path.startswith("/lax"):
            return self.reply(200)  # accepts anything, even what is not JSON
        # /good: validates
        try:
            json.loads(body or b"null")
            ok = self.headers.get("Content-Type") == "application/json"
        except ValueError:
            ok = False
        return self.reply(404 if "%" in self.path or ".." in self.path else (200 if ok and body in (b"{}", b"[]", b"null") else 400))

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_any


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    rep = {(r["method"], r["path"]): r for r in mu.sweep_sbi(base, {"GET", "POST", "PUT", "PATCH", "DELETE"}, 0, "")}
    check("the routes come from /openapi.json (health and metrics are not swept); the sweep stops when the function does not come back, so what follows the crash is not tested",
          set(rep) == {("POST", "/good/{id}"), ("GET", "/good/{id}"), ("POST", "/crashy/{id}")}, set(rep))
    check("a route that validates passes, and most requests reached its parsing", rep[("POST", "/good/{id}")]["result"] == "pass" and rep[("POST", "/good/{id}")]["reached"] >= 10, rep[("POST", "/good/{id}")])
    check("a 500 on a JSON bomb fails the route and says what did it", rep[("POST", "/crashy/{id}")]["result"] == "FAIL" and any("json bomb" in f or "deep object" in f for f in rep[("POST", "/crashy/{id}")]["failures"]), rep[("POST", "/crashy/{id}")])
    check("... and the function not being ready afterwards is noticed", any("no longer ready" in f for f in rep[("POST", "/crashy/{id}")]["failures"]), rep[("POST", "/crashy/{id}")]["failures"])
    H.down = False
    rep2 = {(r["method"], r["path"]): r for r in mu.sweep_sbi(base, {"PUT"}, 0, "/lax")}
    check("accepting what is not JSON, or is cut off, fails the route", rep2[("PUT", "/lax")]["result"] == "FAIL" and any("not json accepted" in f or "truncated accepted" in f for f in rep2[("PUT", "/lax")]["failures"]), rep2)
    rep3 = mu.sweep_sbi(base, {"GET", "POST"}, 0, "/locked")
    check("a function that answers 401 to everything passes but reached nothing, and the report says so", all(r["result"] == "pass" and r["reached"] <= 1 for r in rep3)
          and "proves little" in mu.text_sbi(rep3), mu.text_sbi(rep3))
    check("--only and --max-routes narrow the sweep", len(mu.sweep_sbi(base, {"GET", "POST"}, 1, "/good")) == 1)
    p = subprocess.run([sys.executable, str(TOOL), "sbi", base, "--only", "/lax", "--methods", "PUT"], capture_output=True, text=True)
    check("the exit code is 1 when a route fails", p.returncode == 1 and "FAIL" in p.stdout, p.stdout + p.stderr)
    p = subprocess.run([sys.executable, str(TOOL), "sbi", "http://127.0.0.1:1"], capture_output=True, text=True)
    check("an unreachable function is an error, not a pass", p.returncode != 0 and "openapi.json" in p.stderr, p.stderr)
    srv.shutdown()

    # the corruptions of an N2 message
    pdu = bytes(range(1, 41))
    cs = dict(mu.corruptions(pdu))
    check("N2 corruptions: cuts, flips, garbage and repetition, each different from the original", len(cs) >= 12 and all(v != pdu for v in cs.values()) and cs["cut to 1 byte"] == pdu[:1] and
          cs["appended zeros"].endswith(b"\x00" * 64) and cs["byte 0 inverted"][0] == (pdu[0] ^ 0xFF) and len(cs["repeated twice"]) == 80, sorted(cs))
    print("mutate: PASS" if ok else "mutate: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
