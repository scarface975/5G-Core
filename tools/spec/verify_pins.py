#!/usr/bin/env python3
"""Check that every downloaded 3GPP document still matches docs/specs/pinned.json (SHA-256) and print the table.

Usage: python tools/spec/verify_pins.py          (exit status 1 on any mismatch or missing file)
"""
import hashlib
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent.parent / "docs" / "specs"
pins = json.loads((root / "pinned.json").read_text(encoding="utf-8-sig"))
bad = 0
print(f"{'Spec':<10}{'Version':<10}{'Rel':<5}{'File':<18}Status")
for p in sorted(pins, key=lambda x: x["spec"]):
    f = root / "src" / p["file"]
    if not f.exists():
        status, bad = "MISSING (re-run tools/spec/fetch_specs.ps1)", bad + 1
    elif hashlib.sha256(f.read_bytes()).hexdigest() != p["sha256"]:
        status, bad = "HASH MISMATCH", bad + 1
    else:
        status = "ok"
    print(f"{p['spec']:<10}{'v' + p['version']:<10}{p['release']:<5}{p['file']:<18}{status}")
print(f"\n{len(pins) - bad}/{len(pins)} pinned documents verified")
sys.exit(1 if bad else 0)
