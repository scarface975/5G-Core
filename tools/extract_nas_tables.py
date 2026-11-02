#!/usr/bin/env python3
"""Extract 'message content' tables from TS 24.501 (.docx) into JSON.

Usage: python tools/extract_nas_tables.py docs/specs/src/24501-g/24501-gf0.docx docs/specs/nas/messages.json
Each entry: {"title": "Table 8.2.6.1.1: REGISTRATION REQUEST message content", "clause": "8.2.6", "rows": [[IEI, IE, ref, presence, format, length], ...]}
"""
import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
docx, out = sys.argv[1:3]
root = ET.fromstring(zipfile.ZipFile(docx).read("word/document.xml"))
body = root.find(W + "body")


def text(el):
    parts = []
    for n in el.iter():
        if n.tag == W + "t" and n.text:
            parts.append(n.text)
        elif n.tag == W + "tab":
            parts.append(" ")
    return "".join(parts).strip()


results, last_title, last_heading = [], None, None
headings = {}  # clause number -> title, e.g. "8.2.6" -> "Registration request"
msg_type_tables = []
for child in body:
    if child.tag == W + "p":
        t = text(child)
        if re.match(r"^Table 8\.\d", t):
            last_title = t
        ps = child.find(W + "pPr/" + W + "pStyle")
        if ps is not None and ps.get(W + "val", "").startswith("Heading") and t:
            last_heading = t
            m = re.match(r"^([A-Z]?\d+(?:\.\d+)*)\s+(.*)$", t)
            if m:
                headings[m.group(1)] = m.group(2)
    elif child.tag == W + "tbl":
        rows = []
        for tr in child.findall(W + "tr"):
            rows.append([text(tc) for tc in tr.findall(W + "tc")])
        if last_heading and last_heading.startswith("9.7") and rows:
            msg_type_tables.append({"heading": last_heading, "rows": rows})
        if rows and len(rows[0]) >= 5 and "IEI" in rows[0][0] and "Presence" in " ".join(rows[0]):
            results.append({"title": last_title, "heading": last_heading, "rows": rows})
for r in results:
    clause = (r["heading"] or "").split()[0]
    r["clause"] = clause.rsplit(".", 1)[0]
    r["message"] = headings.get(r["clause"])
json.dump({"messages": results, "message_type_tables": msg_type_tables, "headings": headings},
          open(out, "w", encoding="utf8"), indent=1)
print(len(results), "tables")
for r in results:
    print(r["clause"], "|", r["message"], "|", len(r["rows"]), "rows")
print(len(msg_type_tables), "message type tables")
