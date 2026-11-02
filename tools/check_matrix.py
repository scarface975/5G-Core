#!/usr/bin/env python3
"""Validate docs/conformance/*.json against the repository.

Every test reference must resolve (the ctest name exists, the function is defined in the file), every cited clause must exist in
the pinned specification text, and every row claiming verified/tested/partial must have at least one test.

usage: python tools/check_matrix.py [--ctest-list FILE]
  FILE is the output of `ctest -N` (scripts/g5c_regress.sh writes build/ctest-list.txt); without it the ctest names are not checked.
Exit status 1 when anything does not resolve."""
import json
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
STATUSES = {"verified", "tested", "partial", "gap", "out-of-scope"}


def main():
    ctest_names = None
    if "--ctest-list" in sys.argv:
        path = Path(sys.argv[sys.argv.index("--ctest-list") + 1])
        ctest_names = set(re.findall(r"Test\s+#\d+:\s+(\S+)", path.read_text(encoding="utf8")))
    errors, total = [], 0
    counts = {}
    for mf in sorted((root / "docs" / "conformance").glob("*.json")):
        doc = json.loads(mf.read_text(encoding="utf8"))
        spec_text = {}
        for name, f in doc["specs"].items():
            p = root / "docs" / "specs" / "src" / "txt" / f
            if not p.exists():
                errors.append(f"{mf.name}: pinned text {f} for {name} is missing (run tools/spec_text.py)")
                continue
            spec_text[name] = p.read_text(encoding="utf8", errors="replace")
        ids = set()
        for row in doc["rows"]:
            total += 1
            rid = row["id"]
            if rid in ids:
                errors.append(f"{rid}: duplicate id")
            ids.add(rid)
            st = row["status"]
            counts[st] = counts.get(st, 0) + 1
            if st not in STATUSES:
                errors.append(f"{rid}: unknown status {st}")
            if st in ("verified", "tested", "partial") and not row["tests"]:
                errors.append(f"{rid}: status {st} but no tests")
            for t in row["tests"]:
                src = root / t["file"]
                if not src.exists():
                    errors.append(f"{rid}: {t['file']} does not exist")
                    continue
                fn = t["fn"]
                if fn not in ("-", "main"):
                    body = src.read_text(encoding="utf8", errors="replace")
                    if not re.search(r"\b" + re.escape(fn) + r"\s*\(", body):
                        errors.append(f"{rid}: {fn}() not found in {t['file']}")
                if ctest_names is not None and t["ctest"] not in ctest_names:
                    errors.append(f"{rid}: ctest {t['ctest']} is not registered")
            # clauses
            clauses = []
            if row["spec"] in spec_text and row["clause"] != "-":
                clauses.append((row["spec"], row["clause"]))
            for extra in row.get("also", []):
                if "not pinned" in extra:
                    continue
                m = re.match(r"(TS \d+\.\d+)\s+(.+)", extra)
                if m and m.group(1) in spec_text:
                    clauses.append((m.group(1), m.group(2).strip()))
                elif re.match(r"^[A-Z]?[0-9][0-9.]*$", extra) and row["spec"] in spec_text:
                    clauses.append((row["spec"], extra))
            for spec, cl in clauses:
                cl = cl.split()[0]
                if not re.search(r"(?m)^" + re.escape(cl) + r"[\t ]", spec_text[spec]):
                    errors.append(f"{rid}: clause {cl} not found in {spec}")
    for e in errors:
        print("FAIL", e)
    print("%d rows, %s" % (total, ", ".join("%d %s" % (v, k) for k, v in sorted(counts.items()))))
    print("matrix: %s" % ("OK" if not errors else "%d problems" % len(errors)))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
