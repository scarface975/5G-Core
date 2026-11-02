#!/usr/bin/env python3
"""tools/cli/g5c-api: token required, a run starts / reports / is stopped, one run at a time, bad input refused, OpenAPI served."""
import importlib.machinery
import importlib.util
import json
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
loader = importlib.machinery.SourceFileLoader("g5c_api", str(ROOT / "tools" / "cli" / "g5c-api"))
spec = importlib.util.spec_from_loader("g5c_api", loader)
api = importlib.util.module_from_spec(spec)
loader.exec_module(api)

TOKEN = "0123456789abcdef-token"


def call(base, method, path, body=None, token=TOKEN):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def wait_status(base, rid, want, secs=10):
    end = time.time() + secs
    while time.time() < end:
        st, v = call(base, "GET", "/v1/runs/" + rid)
        if v["status"] in want:
            return v
        time.sleep(0.1)
    return v


def _refuses(bind):
    try:
        s = api.serve(api.Api(TOKEN, ".", "true"), bind, 0)
    except SystemExit:
        return True
    s.server_close()
    return False


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "quick.yaml").write_text("name: quick\nsteps:\n  - log: hi\n")
        (d / "runner.sh").write_text('#!/bin/sh\nfor f in "$@"; do echo "ran $(basename $f)"; done\nif [ -n "$SLOW" ]; then sleep 30; fi\nexit ${FAIL:-0}\n')
        (d / "runner.sh").chmod(0o755)
        srv = api.serve(api.Api(TOKEN, d, "%s {files}" % (d / "runner.sh")), "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        try:
            check("no token: 401", call(base, "GET", "/v1/runs", token=None)[0] == 401)
            check("wrong token: 401", call(base, "GET", "/v1/runs", token="wrong-token-0123456789")[0] == 401)
            check("OpenAPI needs no token", call(base, "GET", "/openapi.json", token=None)[0] == 200)
            st, v = call(base, "GET", "/v1/scenarios")
            check("scenarios listed", st == 200 and v == [{"name": "quick", "steps": 1}], v)
            check("unknown scenario: 404", call(base, "POST", "/v1/runs", {"scenarios": ["nope"]})[0] == 404)
            check("empty request: 400", call(base, "POST", "/v1/runs", {})[0] == 400)
            check("invalid inline scenario: 400 with the problems", call(base, "POST", "/v1/runs", {"yaml": "steps: []"})[0] == 400)
            st, v = call(base, "POST", "/v1/runs", {"scenarios": ["quick"]})
            check("a run starts: 202", st == 202 and v["status"] == "running", v)
            run = wait_status(base, v["id"], ("passed", "failed"))
            check("it passes with the output of the runner", run["status"] == "passed" and run["exit"] == 0 and "ran quick.yaml" in run["output"], run)
            st, v = call(base, "POST", "/v1/runs", {"yaml": "name: inline\nsteps:\n  - log: x\n"})
            check("an inline scenario runs", st == 202 and wait_status(base, v["id"], ("passed", "failed"))["status"] == "passed", v)
            check("runs are listed", len(call(base, "GET", "/v1/runs")[1]) == 2)
            check("metrics without cluster tooling: 404", call(base, "GET", "/v1/metrics/amf")[0] == 404)
            # following the output: ?since= returns the rest, `next` is the offset to ask for next
            full = call(base, "GET", "/v1/runs/" + v["id"])[1]
            part = call(base, "GET", "/v1/runs/%s?since=4" % v["id"])[1]
            check("?since= returns the output from that octet, with the offset to continue from", part["output"] == full["output"][4:] and part["next"] == full["next"] == len(full["output"]), part)
            check("?since= at the end returns nothing new", call(base, "GET", "/v1/runs/%s?since=%d" % (v["id"], full["next"]))[1]["output"] == "")
            # a client generated from the API's own OpenAPI document talks to it
            import importlib.machinery as im, importlib.util as iu
            sdk_tool = iu.module_from_spec(iu.spec_from_loader("sdk", im.SourceFileLoader("sdk", str(ROOT / "tools" / "cli" / "g5c-sdk"))))
            sdk_tool.__spec__.loader.exec_module(sdk_tool)
            (d / "docs").mkdir()
            (d / "docs" / "automation.json").write_text(json.dumps(api.OPENAPI))
            sdk_tool.gen_python(sdk_tool.load_docs(d / "docs"), d / "automation_sdk.py")
            spec2 = iu.spec_from_file_location("automation_sdk", d / "automation_sdk.py")
            gen = iu.module_from_spec(spec2)
            spec2.loader.exec_module(gen)

            def transport(method, url, headers, body):
                req = urllib.request.Request(url, method=method, data=body, headers=headers)
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        return resp.status, resp.read()
                except urllib.error.HTTPError as e:
                    return e.code, e.read()

            cl = gen.Client({"automation": base}, token=TOKEN, transport=transport)
            st, runs = cl.automation.get_v1_runs()
            check("the generated Python client lists the runs", st == 200 and len(runs) >= 2, (st, runs))
            st, one = cl.automation.get_v1_runs_by_id(v["id"], query={"since": 4})
            check("and reads one run incrementally", st == 200 and one["output"] == full["output"][4:], one)
            check("a non-loopback address refuses to start without TLS", _refuses("0.0.0.0"))
            check("loopback is allowed without TLS", not _refuses("127.0.0.1"))
            check("unknown run: 404", call(base, "GET", "/v1/runs/000000000000")[0] == 404)
        finally:
            srv.shutdown()
        # a failing runner, a stopped run, and the one-at-a-time rule
        import os
        os.environ["FAIL"] = "3"
        srv = api.serve(api.Api(TOKEN, d, "%s {files}" % (d / "runner.sh")), "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        try:
            st, v = call(base, "POST", "/v1/runs", {"scenarios": ["quick"]})
            check("a non-zero exit is `failed`", wait_status(base, v["id"], ("passed", "failed"))["status"] == "failed")
        finally:
            srv.shutdown()
        os.environ["FAIL"], os.environ["SLOW"] = "0", "1"
        srv = api.serve(api.Api(TOKEN, d, "%s {files}" % (d / "runner.sh")), "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        try:
            st, v = call(base, "POST", "/v1/runs", {"scenarios": ["quick"]})
            check("a second run while one is running: 409", call(base, "POST", "/v1/runs", {"scenarios": ["quick"]})[0] == 409)
            st, s = call(base, "DELETE", "/v1/runs/" + v["id"])
            check("DELETE stops the run", st == 200 and s["status"] == "stopped", s)
            time.sleep(0.5)
            check("and a new run can start", call(base, "POST", "/v1/runs", {"scenarios": ["quick"]})[0] == 202)
            call(base, "DELETE", "/v1/runs/" + call(base, "GET", "/v1/runs")[1][-1]["id"])
        finally:
            srv.shutdown()
    print("api: PASS" if ok else "api: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
