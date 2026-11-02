#!/usr/bin/env python3
"""Extract the normative ASN.1 modules from a 3GPP spec .docx (e.g. TS 38.413).

Usage: python tools/extract_asn1.py docs/specs/src/38413-gi0/38413-gi0.docx docs/specs/asn1 NGAP-
Writes one <module>.asn per ASN.1 module found between "-- ASN1START" and "-- ASN1STOP".
"""
import html
import re
import sys
import zipfile

docx, outdir, prefix = sys.argv[1:4]
xml = zipfile.ZipFile(docx).read("word/document.xml").decode("utf8")
lines = []
for p in re.findall(r"<w:p[ >].*?</w:p>", xml, flags=re.S):
    parts = re.findall(r"<w:t(?: [^>]*)?>(.*?)</w:t>|(<w:tab/>)|(<w:br/>)", p, flags=re.S)
    lines.append(html.unescape("".join(t or ("\t" if tab else "\n") for t, tab, br in parts)))
text = "\n".join(lines)
blocks = re.findall(r"-- ASN1START(.*?)-- ASN1STOP", text, flags=re.S)
for b in blocks:
    m = re.search(r"^(" + re.escape(prefix) + r"[A-Za-z-]+)\s+\{", b, flags=re.M)
    if not m:
        print("skipping block without module header", file=sys.stderr)
        continue
    body = b[m.start():].rstrip() + "\n"
    open(f"{outdir}/{m.group(1)}.asn", "w", encoding="utf8", newline="\n").write(body)
    print(m.group(1), len(body.splitlines()), "lines")
