#!/usr/bin/env python3
"""tools/g5c-sdk: a generated Python client builds the right requests (path parameters encoded, body as JSON, token), and the Postman collection has a folder per function."""
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent.parent / "tools" / "g5c-sdk"

DOC = {"openapi": "3.0.3", "info": {"title": "udm-1", "version": "9.9.9"}, "paths": {
    "/nudm-ee/v1/{ueIdentity}/ee-subscriptions": {"post": {"operationId": "x"}},
    "/nudm-ee/v1/{ueIdentity}/ee-subscriptions/{subscriptionId}": {"delete": {}, "patch": {}},
    "/admin/v1/subscribers": {"get": {}, "post": {}},
    "/health/live": {"get": {}}}}


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "docs").mkdir()
        (d / "docs" / "udm.json").write_text(json.dumps(DOC))
        (d / "docs" / "amf.json").write_text(json.dumps({"openapi": "3.0.3", "info": {"title": "amf-1", "version": "9.9.9"}, "paths": {"/namf-evts/v1/subscriptions": {"post": {}}}}))
        p = subprocess.run([sys.executable, str(TOOL), "python", "--from", str(d / "docs"), "--out", str(d / "g5c_sdk.py")], capture_output=True, text=True)
        check("python client generated", p.returncode == 0, p.stderr)
        spec = importlib.util.spec_from_file_location("g5c_sdk", d / "g5c_sdk.py")
        sdk = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sdk)
        seen = []

        def transport(method, url, headers, body):
            seen.append((method, url, headers, body))
            return 201, b'{"ok":true}'

        c = sdk.Client({"udm": "http://u:1", "amf": "http://a:2"}, token="tok", transport=transport)
        st, body = c.udm.post_nudm_ee_v1_ee_subscriptions("anyUE", body={"callbackReference": "http://x"})
        check("POST with a path parameter and a JSON body", st == 201 and body == {"ok": True} and seen[-1][0] == "POST" and seen[-1][1] == "http://u:1/nudm-ee/v1/anyUE/ee-subscriptions"
              and json.loads(seen[-1][3]) == {"callbackReference": "http://x"} and seen[-1][2]["authorization"] == "Bearer tok", seen[-1])
        c.udm.delete_nudm_ee_v1_ee_subscriptions("extid-a@b.c", "7")
        check("path parameters are percent-encoded, in order", seen[-1][1] == "http://u:1/nudm-ee/v1/extid-a%40b.c/ee-subscriptions/7", seen[-1][1])
        c.udm.get_admin_v1_subscribers(query={"limit": 5})
        check("query string", seen[-1][1] == "http://u:1/admin/v1/subscribers?limit=5", seen[-1][1])
        try:
            c.udm.get_health_live("extra")
            check("wrong number of path parameters is refused", False)
        except TypeError:
            check("wrong number of path parameters is refused", True)
        check("one object per configured function", hasattr(c, "amf") and hasattr(c, "udm"))
        p = subprocess.run([sys.executable, str(TOOL), "postman", "--from", str(d / "docs"), "--out", str(d / "p.json")], capture_output=True, text=True)
        coll = json.loads((d / "p.json").read_text())
        check("postman: a folder per function, base URL variables", p.returncode == 0 and [i["name"] for i in coll["item"]] == ["amf", "udm"] and {v["key"] for v in coll["variable"]} >= {"udm", "amf", "token"}, coll["item"][0]["name"])
        check("postman: path parameters become variables", any("{{ueIdentity}}" in r["request"]["url"]["raw"] for f in coll["item"] for r in f["item"]))
    print("sdk: PASS" if ok else "sdk: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
