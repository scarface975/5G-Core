#!/usr/bin/env python3
"""The operator console: the embedded copy is current, the page has no external resources or unsafe DOM writes, the script parses (node), its list and import helpers behave, and the policy hashes match."""
import base64
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PAGE = ROOT / "deploy" / "console" / "index.html"
HDR = ROOT / "nf" / "udm" / "src" / "console_html.h"


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    p = subprocess.run([sys.executable, str(ROOT / "tools" / "gen_console.py"), "--check"], capture_output=True, text=True)
    check("the embedded copy is current", p.returncode == 0, p.stdout + p.stderr)
    html = PAGE.read_text(encoding="utf-8")
    script = re.findall(r"<script>(.*?)</script>", html, re.S)
    style = re.findall(r"<style>(.*?)</style>", html, re.S)
    check("one script and one style element", len(script) == 1 and len(style) == 1)
    check("no external resource (http/https URL, src=, href=)", not re.search(r"https?://|\bsrc=|\bhref=|@import|url\(", html), re.findall(r"https?://\S+", html))
    check("no inline event handler attributes, no innerHTML, no eval", not re.search(r"\son[a-z]+=\"|innerHTML|outerHTML|document\.write|\beval\(|new Function", html.replace("b.onclick", "")), "")
    hdr = HDR.read_text()
    csp = re.search(r'UDM_CONSOLE_CSP "([^"]+)"', hdr).group(1)
    for tag, content in (("script", script[0]), ("style", style[0])):
        h = "'sha256-%s'" % base64.b64encode(hashlib.sha256(content.encode()).digest()).decode()
        check("the policy allows exactly this %s (hash matches)" % tag, h in csp, csp)
    check("the policy forbids everything else", "default-src 'none'" in csp and "connect-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp)
    node = shutil.which("node")
    if node:
        with tempfile.TemporaryDirectory() as d:
            js = Path(d) / "console.js"
            js.write_text(script[0])
            r = subprocess.run([node, "--check", str(js)], capture_output=True, text=True)
            check("the script parses (node --check)", r.returncode == 0, r.stderr[:300])
            # the pure helpers, run in a sandbox with no DOM
            fns = "".join(re.search(r"(function %s\(.*?\n\})" % n, script[0], re.S).group(1) + "\n" for n in ("supisOf", "parseRecords"))
            test = fns + r'''
const assert = require("assert");
assert.deepStrictEqual(supisOf(["imsi-1", "imsi-2"]), ["imsi-1", "imsi-2"]);
assert.deepStrictEqual(supisOf([{ supi: "imsi-3" }, null, {}]), ["imsi-3"]);
assert.deepStrictEqual(supisOf({ subscribers: ["imsi-4"] }), ["imsi-4"]);
assert.deepStrictEqual(supisOf(null), []);
assert.strictEqual(parseRecords('[{"supi":"a"},{"supi":"b"}]').length, 2);
assert.strictEqual(parseRecords('{"supi":"a"}\n\n{"supi":"b"}\r\n').length, 2);
assert.deepStrictEqual(parseRecords("   "), []);
assert.throws(() => parseRecords('{"supi":"a"}\nnot json'), /line 2/);
console.log("helpers ok");
'''
            (Path(d) / "t.js").write_text(test)
            r = subprocess.run([node, str(Path(d) / "t.js")], capture_output=True, text=True)
            check("list and import helpers behave", r.returncode == 0 and "helpers ok" in r.stdout, r.stderr[:400])
    else:
        print("SKIP  node is not installed: the script is not syntax-checked")
    print("console: PASS" if ok else "console: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
