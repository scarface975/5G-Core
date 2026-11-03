#!/usr/bin/env python3
"""tools/cli/g5c-lab and docs/training: the exercises are complete (a README with the four parts, a scenario or command that exists and parses), the runner lists and shows them, an unknown exercise is
an error, and the environment it gives a run is the one the tests use. (`check` itself needs a cluster: the cluster_lab_* tests run it.)"""
import importlib.machinery
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "cli" / "g5c-lab"
loader = importlib.machinery.SourceFileLoader("g5c_lab", str(TOOL))
spec = importlib.util.spec_from_loader("g5c_lab", loader)
lab = importlib.util.module_from_spec(spec)
loader.exec_module(lab)


def run(*a):
    return subprocess.run([sys.executable, str(TOOL), *a], capture_output=True, text=True)


def main():
    ok = True

    def check(name, cond, got=""):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  -> " + repr(got)))
        ok = ok and cond

    ex = lab.exercises()
    ids = [e["id"] for e in ex]
    check("at least twelve exercises with distinct, consecutive ids", len(ex) >= 12 and len(set(ids)) == len(ids) and ids == ["%02d" % i for i in range(1, len(ex) + 1)], ids)
    sl = importlib.machinery.SourceFileLoader("g5c_scenario", str(ROOT / "tools" / "cli" / "g5c-scenario"))
    ss = importlib.util.spec_from_loader("g5c_scenario", sl)
    sc = importlib.util.module_from_spec(ss)
    sl.exec_module(sc)
    problems = []
    for e in ex:
        rd = ROOT / e["readme"]
        text = rd.read_text(encoding="utf-8") if rd.exists() else ""
        for part in ("## Goal", "## Do it by hand", "## What you should see", "## Why"):
            if part not in text:
                problems.append("%s: %s missing" % (e["id"], part))
        if "scenario" in e:
            f = ROOT / e["scenario"]
            if not f.exists():
                problems.append("%s: %s missing" % (e["id"], e["scenario"]))
            else:
                doc = sc.load_doc(str(f)) if hasattr(sc, "load_doc") else None
                if doc is not None and not doc.get("steps"):
                    problems.append("%s: no steps" % e["id"])
        else:
            if not e.get("contains") or not all((ROOT / c).exists() for c in e["command"][1:] if "/" in c and not c.startswith("-") and c not in ("ns", "tls", "ops")):
                problems.append("%s: command or expected text missing" % e["id"])
        if not all(k.startswith("G5C_") for k in e.get("env", {})):
            problems.append("%s: env keys must be G5C_*" % e["id"])
    check("every exercise has a README with goal, steps, expected result and reason, and a scenario or command that exists", not problems, problems)
    readme = (ROOT / "docs" / "training" / "README.md").read_text(encoding="utf-8")
    check("the index lists every exercise", all(("[%s]" % e["title"]) in readme for e in ex))
    p = run("list")
    check("list", p.returncode == 0 and len(p.stdout.splitlines()) == len(ex) and "Start a core" in p.stdout, p.stdout)
    p = run("show", "7")
    check("show 7 (and 07) prints the exercise", p.returncode == 0 and "Exercise 07" in p.stdout and "## Why" in p.stdout and run("show", "07").stdout == p.stdout)
    check("an unknown exercise is exit 2", run("show", "99").returncode == 2 and run("check", "99").returncode == 2)
    env = lab.base_env("03")
    check("a run gets what the tests give it: TLS, no tokens, its own run directory, the build's load tool",
          env["G5C_TLS"] == "1" and env["G5C_OAUTH2"] == "0" and env["G5C_RUN"].endswith("run-03") and env["G5C_LOAD_BIN"].endswith("nf/amf/load_core"), env)
    unknown = []
    for e in ex:
        if "scenario" in e:
            for st in sc.load_doc(str(ROOT / e["scenario"]))["steps"]:
                if not any(k in sc.STEPS for k in st):
                    unknown.append((e["id"], sorted(st)))
    check("the scenarios of the exercises use only steps the engine knows", not unknown, unknown)
    print("lab: PASS" if ok else "lab: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
