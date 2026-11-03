#!/usr/bin/env python3
"""tools/cli/g5c-tester: what it says it can and cannot do, the environment it builds for the load generator from its options (dry run), refusing bad calls, and the bundle (every file
hashed in the manifest, the same bytes for the same inputs, nothing from outside the list)."""
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-tester"


def run(args, env=None):
    return subprocess.run([sys.executable, str(TOOL)] + args, capture_output=True, text=True, env=env)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    r = run(["info"])
    check("info says what it can and what it cannot, including that a million subscribers has not been run", r.returncode == 0 and "Can:" in r.stdout and "Cannot:" in r.stdout and "has not been run" in r.stdout, r.stdout)

    r = run(["run", "--amf", "10.0.0.5:38412", "--subscribers", "http://10.0.0.1:7773/", "--ues", "500", "--gnbs", "12", "--mobility", "6", "--dry-run"])
    check("a dry run prints the environment of the load generator and starts nothing", r.returncode == 0 and "G5C_LOAD_REMOTE=1" in r.stdout and "G5C_LOAD_AMF_NGAP=10.0.0.5:38412" in r.stdout and "G5C_LOAD_UDM=http://10.0.0.1:7773" in r.stdout
          and "G5C_LOAD_UES=500" in r.stdout and "G5C_LOAD_GNBS=12" in r.stdout and "G5C_LOAD_MOBILITY=6" in r.stdout and "STORM" not in r.stdout, r.stdout)
    r = run(["run", "--amf", "10.0.0.5:38412", "--no-provision", "--ues", "10", "--processes", "3", "--dry-run"])
    check("several processes go through g5c-fanout, and --no-provision is passed on", "g5c-fanout" in r.stdout and "--processes 3" in r.stdout and "G5C_LOAD_NO_PROVISION=1" in r.stdout, r.stdout)

    for name, args in (("no port in --amf", ["run", "--amf", "10.0.0.5", "--no-provision"]), ("neither --subscribers nor --no-provision", ["run", "--amf", "1.2.3.4:38412"]),
                       ("mobility and storm together", ["run", "--amf", "1.2.3.4:38412", "--no-provision", "--mobility", "2", "--storm-seconds", "2"]), ("zero UEs", ["run", "--amf", "1.2.3.4:38412", "--no-provision", "--ues", "0"])):
        check("refused: " + name, run(args + ["--dry-run"]).returncode == 2)
    r = run(["run", "--amf", "1.2.3.4:38412", "--no-provision", "--load-bin", "/nonexistent/load_core"], {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"})
    check("without a load generator it says so (exit 2)", r.returncode == 2 and "load_core not found" in r.stderr, r.stderr)

    with tempfile.TemporaryDirectory() as d:
        fake = Path(d) / "load_core"
        fake.write_bytes(b"#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
        a, b = Path(d) / "a.tar.gz", Path(d) / "b.tar.gz"
        r1 = run(["pack", str(a), "--load-bin", str(fake)])
        r2 = run(["pack", str(b), "--load-bin", str(fake)])
        check("the bundle is written", r1.returncode == 0 and a.exists() and "files in" in r1.stdout, r1.stderr)
        with tarfile.open(a) as tf:
            names = tf.getnames()
            man = json.loads(tf.extractfile("g5c-tester/MANIFEST.json").read())
            hashes_ok = all(hashlib.sha256(tf.extractfile("g5c-tester/" + n).read()).hexdigest() == h for n, h in man["files"].items())
        check("it holds the tester, the load generator, the tools, the scenarios, the training exercises and the guide", all(any(n.endswith(x) for n in names) for x in (
            "bin/g5c-tester", "bin/load_core", "bin/g5c-fanout", "bin/g5c-scenario", "share/scenarios/mobility-xn.yaml", "share/training/README.md", "share/testing.md", "README.txt")), names[:8])
        check("the manifest hashes every file and the hashes are right", len(man["files"]) >= 20 and hashes_ok and man["load_core"] is True)
        check("nothing from outside the list: no keys, no state, no build tree", not any(x in n for n in names for x in (".key", "state", "/build/", "__pycache__", ".git")), [n for n in names if "state" in n or ".key" in n])
        check("the same inputs give the same bytes", a.read_bytes() == b.read_bytes() and r2.returncode == 0)
    print("tester: PASS" if ok else "tester: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
