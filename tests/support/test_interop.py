#!/usr/bin/env python3
"""tools/cli/g5c-interop on the real register of docs/interop (every entry complete, every evidence file there, the page in docs/interop/README.md is what the register generates) and on
registers that are wrong."""
import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-interop"
loader = importlib.machinery.SourceFileLoader("g5c_interop", str(TOOL))
spec = importlib.util.spec_from_loader("g5c_interop", loader)
io = importlib.util.module_from_spec(spec)
loader.exec_module(io)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    reg = io.load(io.DEFAULT)
    check("the register is complete and every evidence file exists", io.check(reg) == [], io.check(reg))
    check("it says what was not tested", len(reg["not_tested"]) >= 3 and any("commercial" in x for x in reg["not_tested"]))
    check("it names the radio side and the core side of the demo that really runs", any(e["id"] == "ran-ocudu-srsue" and e["result"] == "pass" for e in reg["entries"]))
    page = (ROOT / "docs" / "interop" / "README.md").read_text()
    check("docs/interop/README.md is generated from the register (python tools/cli/g5c-interop md > docs/interop/README.md)", page.strip() == io.markdown(reg).strip())

    bad = json.loads(json.dumps(reg))
    bad["entries"][0]["evidence"] = "docs/interop/nonexistent.pcap"
    bad["entries"][1]["reproduce"] = ""
    bad["entries"].append(dict(bad["entries"][2]))
    bad["not_tested"] = []
    problems = io.check(bad)
    check("a missing evidence file, an empty field, a duplicate and an empty not_tested are all found", len(problems) == 4, problems)

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "r.json"
        p.write_text(json.dumps(bad))
        r = subprocess.run([sys.executable, str(TOOL), "check", "--register", str(p)], capture_output=True, text=True)
        check("the command exits 1 on a bad register", r.returncode == 1 and "FAIL" in r.stdout, r.stdout)
    r = subprocess.run([sys.executable, str(TOOL), "check"], capture_output=True, text=True)
    check("and 0 on the real one", r.returncode == 0 and "OK" in r.stdout, r.stdout)
    r = subprocess.run([sys.executable, str(TOOL), "list", "--register", "/nonexistent.json"], capture_output=True, text=True)
    check("an unreadable register is exit 2", r.returncode == 2)
    print("interop: PASS" if ok else "interop: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
