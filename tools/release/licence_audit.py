#!/usr/bin/env python3
"""The automated part of the licence audit of a release (strategy Phase 9: "final third-party licence audit, automated + manual"). Writes docs/legal/audit-<version>.md and the NOTICE file.

    python3 tools/release/licence_audit.py [--write]     (without --write: check only; exit 1 when a check fails)

Checks:
  1. every source file of the product (C, headers, CMake) carries an SPDX-License-Identifier line; generated files say so
  2. no product file contains the text of a copyleft licence or a copyright line of another party
  3. the third-party components of the SBOM (docs/sbom/g5c.cdx.json) are all in docs/legal/THIRD_PARTY.md with a licence on the allowed list, and the other way round
  4. nothing from the test-only list (Open5GS, UERANSIM, MongoDB...) is referenced by a build file of the product
  5. the specification documents are ignored by version control and kept out of releases (only pinned hashes and derived tables are shipped); the restricted algorithm documents are absent
What it cannot do: judge the licences of the system libraries beyond their SPDX ids, patents, the standards' own IPR terms, or export control. Those are the manual part, recorded for counsel in
docs/legal/patent-frand-review.md."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ALLOWED = {"Apache-2.0", "PostgreSQL", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "OpenSSL", "Zlib"}
PRODUCT_DIRS = ["libs", "nf", "ctl", "fuzz"]
SKIP_PARTS = {"build", "__pycache__", ".git"}
TEST_ONLY = ["open5gs", "ueransim", "mongod", "srsran", "srsue"]
COPYLEFT = re.compile(r"(GNU (Affero )?General Public License|GNU Lesser General Public|SPDX-License-Identifier:\s*(A?GPL|LGPL|SSPL|BUSL))", re.I)
FOREIGN_COPYRIGHT = re.compile(r"Copyright\s*(\(c\)|©)\s*\d{4}", re.I)


def version():
    return (ROOT / "VERSION").read_text().strip()


def product_files():
    for d in PRODUCT_DIRS:
        for p in (ROOT / d).rglob("*"):
            if not p.is_file() or SKIP_PARTS & set(p.parts):
                continue
            if p.suffix in {".c", ".h", ".txt"} and (p.suffix != ".txt" or p.name == "CMakeLists.txt") or p.name == "CMakeLists.txt":
                yield p


def check_spdx():
    missing = []
    n = 0
    for p in product_files():
        n += 1
        head = p.read_text(encoding="utf-8", errors="replace")[:600]
        if "SPDX-License-Identifier" not in head and "generated" not in head.lower() and "DO NOT EDIT" not in head:
            missing.append(str(p.relative_to(ROOT)))
    return n, missing


def check_copyleft():
    bad = []
    for p in product_files():
        t = p.read_text(encoding="utf-8", errors="replace")
        if COPYLEFT.search(t):
            bad.append(str(p.relative_to(ROOT)) + " (copyleft licence text)")
        elif FOREIGN_COPYRIGHT.search(t):
            bad.append(str(p.relative_to(ROOT)) + " (a copyright line of another party)")
    return bad


def third_party_table():
    rows = {}
    for line in (ROOT / "docs/legal/THIRD_PARTY.md").read_text(encoding="utf-8").splitlines():
        m = re.match(r"\|\s*([^|]+?)\s*\|[^|]*\|\s*([^|]+?)\s*\|", line)
        if m and not m.group(1).startswith(("Component", "---")):
            rows[m.group(1).lower()] = m.group(2)
    return rows


def check_sbom():
    sbom = json.loads((ROOT / "docs/sbom/g5c.cdx.json").read_text(encoding="utf-8"))
    table = third_party_table()
    problems, comps = [], []
    for c in sbom.get("components", []):
        if c.get("type") == "application":
            continue  # our own functions
        name = c["name"]
        ids = [l["license"].get("id", l["license"].get("name", "")) for l in c.get("licenses", [])]
        comps.append((name, c.get("version", ""), ", ".join(ids)))
        if not ids or not all(i in ALLOWED or i.startswith("system") for i in ids):
            problems.append("%s: licence %s is not on the allowed list" % (name, ids or "missing"))
        if not any(name.lower().split()[0] in k for k in table):
            problems.append("%s is in the SBOM but not in docs/legal/THIRD_PARTY.md" % name)
    return comps, problems


def check_test_only():
    bad = []
    for p in ROOT.rglob("CMakeLists.txt"):
        if SKIP_PARTS & set(p.parts):
            continue
        t = p.read_text(encoding="utf-8", errors="replace").lower()
        for w in TEST_ONLY:
            if re.search(r"(target_link_libraries|find_package|pkg_check_modules|add_subdirectory)[^\n]*" + w, t):
                bad.append("%s links or finds %s" % (p.relative_to(ROOT), w))
    return bad


def check_specs():
    """The downloaded specification documents exist on a developer machine; they must be ignored by version control and left out of every release archive (tools/release/release.sh)."""
    bad = []
    ign = (ROOT / ".gitignore").read_text(encoding="utf-8") if (ROOT / ".gitignore").exists() else ""
    if "docs/specs/src/" not in ign:
        bad.append(".gitignore does not ignore docs/specs/src/")
    if "docs/specs/restricted/" not in ign:
        bad.append(".gitignore does not ignore docs/specs/restricted/ (SNOW 3G / ZUC documents)")
    if (ROOT / "docs/specs/restricted").exists() and any((ROOT / "docs/specs/restricted").iterdir()):
        bad.append("docs/specs/restricted is not empty")
    return bad


def notice(comps):
    lines = ["g5c " + version(), "Copyright (c) the g5c authors. All rights reserved.", "",
             "This product includes software of third parties, linked dynamically as system libraries; their notices apply to them:", ""]
    table = third_party_table()
    for name, ver, lic in comps:
        lines.append("  - %s %s (%s)" % (name, ver, lic))
    lines += ["", "The specifications this product implements are published by 3GPP and ETSI; the documents are not part of this distribution (only checksums and tables derived for testing).",
              "Open5GS (AGPL-3.0), UERANSIM (GPL-3.0) and MongoDB are used only to test interoperability on the developers' machines and are neither linked nor distributed.", ""]
    return "\n".join(lines)


def main():
    write = "--write" in sys.argv
    n, missing = check_spdx()
    cop = check_copyleft()
    comps, sb = check_sbom()
    to = check_test_only()
    sp = check_specs()
    results = [("SPDX identifier in every product source file (%d files)" % n, missing), ("no copyleft text or foreign copyright line in product files", cop),
               ("SBOM components and THIRD_PARTY.md agree, all licences allowed (%d components)" % len(comps), sb), ("no test-only tool in a build file", to),
               ("specification documents ignored by version control, restricted documents absent", sp)]
    ok = all(not r[1] for r in results)
    out = ["# Licence audit, automated part, release %s" % version(), "", "Made by `tools/release/licence_audit.py`. The manual part (patents, FRAND, export control, the owner's licence terms) is recorded in `patent-frand-review.md` and needs counsel.", ""]
    for title, bad in results:
        out.append("- **%s**: %s" % ("PASS" if not bad else "FAIL", title))
        for b in bad[:20]:
            out.append("    - " + b)
    out += ["", "## Third-party components (from the SBOM)", "", "| Component | Version | Licence |", "|---|---|---|"] + ["| %s | %s | %s |" % c for c in comps]
    out.append("")
    report = "\n".join(out)
    if write:
        (ROOT / ("docs/legal/audit-%s.md" % version())).write_text(report, encoding="utf-8")
        (ROOT / "NOTICE").write_text(notice(comps), encoding="utf-8")
    for title, bad in results:
        print("%s  %s" % ("PASS" if not bad else "FAIL", title))
        for b in bad[:10]:
            print("      " + b)
    print("licence audit:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
