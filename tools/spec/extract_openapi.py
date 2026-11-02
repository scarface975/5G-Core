#!/usr/bin/env python3
"""Extract the normative OpenAPI documents embedded in the annexes of the downloaded 3GPP specs
(docs/specs/src/txt/*.txt, produced by tools/spec/spec_text.py) into docs/specs/src/openapi/<file>.yaml.

3GPP file names follow TS<spec>_<title>.yaml and are what other documents use in `$ref`, so every block is stored
under that name. Usage: python tools/spec/extract_openapi.py
"""
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent.parent / "docs" / "specs" / "src"
txt = root / "txt"
out = root / "openapi"
out.mkdir(exist_ok=True)

SPECS = {"29503": "29503-gi0", "29509": "29509-gb0", "29510": "29510-gf0", "29512": "29512-gn0",
         "29507": "29507-gb0", "29571": "29571-gf0", "29504": "29504-ge0", "29505": "29505-gc0", "29519": "29519-ge0",
         "29500": "29500-gf0", "29501": "29501-g80", "29244": None}
count = 0
for spec, stem in SPECS.items():
    if not stem or not (txt / f"{stem}.txt").exists():
        continue
    lines = (txt / f"{stem}.txt").read_text(encoding="utf8").split("\n")
    i = 0
    while i < len(lines):
        if lines[i].strip() == "openapi: 3.0.0":
            j = i
            block = []
            while j < len(lines):
                l = lines[j].rstrip()
                # YAML ends at the next annex/clause heading or an empty paragraph followed by a heading
                if re.match(r"^(A\.\d+|Annex [A-Z]|B\.\d+)\b", l.strip()) and j > i + 3 and not l.startswith(" "):
                    break
                block.append(l)
                j += 1
            text = "\n".join(block).strip() + "\n"
            m = re.search(r"^\s*title:\s*(.+)$", text, flags=re.M)
            title = m.group(1).strip().strip("'\"") if m else f"block{i}"
            name = "CommonData" if spec == "29571" and "Common" in title else re.sub(r"[^A-Za-z0-9_]", "_", title)
            fname = f"TS{spec}_{name}.yaml"
            (out / fname).write_text(text, encoding="utf8", newline="\n")
            print(f"{fname}: {len(block)} lines")
            count += 1
            i = j
        else:
            i += 1
print(f"{count} OpenAPI documents -> {out}")
