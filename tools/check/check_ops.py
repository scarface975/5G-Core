#!/usr/bin/env python3
"""Every metric the alert rules and the Grafana dashboard use must be registered by a function (a string in the sources); the rule files must parse.
   python3 tools/check/check_ops.py   (exit 1 on a miss)"""
import glob
import json
import os
import re
import sys

try:
    import yaml
except ImportError:
    print("SKIP: PyYAML is not installed")
    sys.exit(77)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
src = set()
for p in glob.glob(os.path.join(ROOT, "nf", "*", "src", "*.c")) + glob.glob(os.path.join(ROOT, "libs", "*", "src", "*.c")):
    src.update(re.findall(r'"(g5c_[a-z0-9_]+)"', open(p, encoding="utf-8", errors="replace").read()))
recorded = set()
rules = yaml.safe_load(open(os.path.join(ROOT, "deploy", "ops", "prometheus-rules.yml")))
texts = []
for g in rules["groups"]:
    for r in g["rules"]:
        if "record" in r:
            recorded.add(r["record"])
        texts.append(r["expr"])
dash = json.load(open(os.path.join(ROOT, "deploy", "ops", "grafana-g5c.json")))
for pnl in dash["panels"]:
    texts.extend(t["expr"] for t in pnl["targets"])
bad = []
for t in texts:
    for m in re.findall(r"\bg5c[_:][a-z0-9_:]*", t):
        base = re.sub(r"_(bucket|count|sum)$", "", m)
        if m in recorded or base in src or m in src:
            continue
        bad.append(m)
for b in sorted(set(bad)):
    print("not registered by any function:", b)
print("ops check:", "FAIL" if bad else "PASS", "(%d expressions, %d metrics known)" % (len(texts), len(src)))
sys.exit(1 if bad else 0)
