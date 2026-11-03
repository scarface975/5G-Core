#!/usr/bin/env python3
"""tools/cli/g5c-fanout with a stand-in for the load generator: the plan (slices, hosts), disjoint IMSI ranges that add up to the population, the environment each process gets, the totals,
a process that fails, a process that hangs, and bad calls."""
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-fanout"

FAKE = """#!/bin/sh
# a load process that writes its report; FAIL_BASE makes the one with that base exit 1, HANG_BASE makes it sleep
[ "$G5C_LOAD_BASE" = "$FAIL_BASE" ] && { echo "boom"; exit 1; }
[ "$G5C_LOAD_BASE" = "$HANG_BASE" ] && sleep 30
cat > "$G5C_LOAD_JSON" <<EOF
{"ues": $G5C_LOAD_UES, "gnbs": $G5C_LOAD_GNBS, "base": $G5C_LOAD_BASE, "fanout": "$G5C_LOAD_FANOUT", "remote": "$G5C_LOAD_REMOTE",
 "latency": {"registration": {"n": $G5C_LOAD_UES, "p99_ms": $((G5C_LOAD_BASE % 7 + 10)).0}}}
EOF
"""


def run(args, env=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, str(TOOL)] + args, capture_output=True, text=True, env=e)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        fake = Path(d) / "load_core"
        fake.write_text(FAKE)
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        out = Path(d) / "out.json"

        p = run(["plan", "--total", "1000000", "--per-process", "5000", "--hosts", "4"])
        check("the plan deals 200 processes to 4 hosts, 50 each, 250,000 UEs a host", p.returncode == 0 and p.stdout.count("host ") == 4 and "50 processes, 250000 UEs" in p.stdout, p.stdout)

        p = run(["run", "--load-bin", str(fake), "--processes", "4", "--ues", "250", "--gnbs", "8", "--base", "1000", "--json", str(out)])
        data = json.loads(out.read_text())
        bases = sorted(r["report"]["base"] for r in data["processes"])
        check("four processes, disjoint ranges of 250 from the base", p.returncode == 0 and bases == [1000, 1250, 1500, 1750], bases)
        check("every process was told it is one of a fleet, remote, and its own UE and gNB counts", all(r["report"]["fanout"] == "1" and r["report"]["remote"] == "1" and r["report"]["ues"] == 250 and r["report"]["gnbs"] == 8
                                                                                                         for r in data["processes"]))
        s = data["summary"]
        check("the totals: 1,000 of 1,000 UEs, the slowest p99", s["ues_completed"] == 1000 and s["ues_planned"] == 1000 and not s["failed_processes"] and s["worst_p99_ms"]["registration"] >= 10, s)

        p = run(["run", "--load-bin", str(fake), "--total", "10", "--per-process", "4", "--slice", "2/2", "--json", str(out)])
        data = json.loads(out.read_text())
        check("a slice of two hosts: host 2 gets the second of three processes (the third goes to host 1)", p.returncode == 0 and [r["ues"] for r in data["processes"]] == [4], [r["ues"] for r in data["processes"]])

        p = run(["run", "--load-bin", str(fake), "--processes", "3", "--ues", "10", "--json", str(out)], {"FAIL_BASE": "10"})
        data = json.loads(out.read_text())
        check("one process failing is exit 1, named, with its log, and the others still counted", p.returncode == 1 and data["summary"]["failed_processes"] == [1] and data["summary"]["ues_completed"] == 20 and "boom" in p.stderr,
              (p.returncode, p.stderr))

        p = run(["run", "--load-bin", str(fake), "--processes", "2", "--ues", "5", "--timeout", "1", "--json", str(out)], {"HANG_BASE": "5"})
        check("a process that hangs is killed at the timeout", p.returncode == 1 and json.loads(out.read_text())["summary"]["failed_processes"] == [1], p.stderr)

        for args in (["run", "--load-bin", str(fake)], ["run", "--load-bin", str(fake), "--processes", "2", "--ues", "5", "--slice", "3/2"], ["plan", "--total", "0"],
                     ["run", "--load-bin", str(fake), "--processes", "2", "--ues", "5", "--env", "NOEQUALS"]):
            check("a bad call is exit 2: %s" % " ".join(args[2:]), run(args).returncode == 2)
    print("fanout: PASS" if ok else "fanout: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
