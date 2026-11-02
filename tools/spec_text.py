#!/usr/bin/env python3
"""Extract plain text from every downloaded 3GPP spec (docs/specs/src/*/ *.docx or *.doc) into docs/specs/src/txt/.

Usage: python tools/spec_text.py        (needs: pip install olefile for legacy .doc files)
"""
import html
import re
import struct
import sys
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent / "docs" / "specs" / "src"
out_dir = root / "txt"
out_dir.mkdir(exist_ok=True)


def docx_text(path):
    xml = zipfile.ZipFile(path).read("word/document.xml").decode("utf8")
    lines = []
    for p in re.findall(r"<w:p[ >].*?</w:p>", xml, flags=re.S):
        parts = re.findall(r"<w:t(?: [^>]*)?>(.*?)</w:t>|(<w:tab/>)|(<w:br/>)", p, flags=re.S)
        lines.append(html.unescape("".join(t or ("\t" if tab else "\n") for t, tab, br in parts)))
    return "\n".join(lines)


def doc_text(path):
    import olefile
    ole = olefile.OleFileIO(str(path))
    wd = ole.openstream("WordDocument").read()
    flags = struct.unpack_from("<H", wd, 0x0A)[0]
    table = ole.openstream("1Table" if flags & 0x0200 else "0Table").read()
    fc, lcb = struct.unpack_from("<II", wd, 0x1A2)
    clx = table[fc:fc + lcb]
    pos = 0
    while clx[pos] == 0x01:
        pos += 3 + struct.unpack_from("<H", clx, pos + 1)[0]
    n_bytes = struct.unpack_from("<I", clx, pos + 1)[0]
    plc = clx[pos + 5:pos + 5 + n_bytes]
    n = (n_bytes - 4) // 12
    cps = struct.unpack_from("<%dI" % (n + 1), plc, 0)
    parts = []
    for i in range(n):
        f = struct.unpack_from("<I", plc, 4 * (n + 1) + 8 * i + 2)[0]
        cnt = cps[i + 1] - cps[i]
        if f & 0x40000000:
            o = (f & ~0x40000000) // 2
            parts.append(wd[o:o + cnt].decode("cp1252", errors="replace"))
        else:
            parts.append(wd[f:f + 2 * cnt].decode("utf-16-le", errors="replace"))
    return "".join(parts).replace("\r", "\n").replace("\x07", "\t").replace("\x0b", "\n")


done = 0
for d in sorted(p for p in root.iterdir() if p.is_dir() and p.name != "txt"):
    for f in d.iterdir():
        if f.suffix.lower() not in (".docx", ".doc"):
            continue
        target = out_dir / (f.stem + ".txt")
        try:
            text = docx_text(f) if f.suffix.lower() == ".docx" else doc_text(f)
        except Exception as e:  # keep going; report at the end
            print("FAILED", f.name, e, file=sys.stderr)
            continue
        target.write_text(text, encoding="utf8", newline="\n")
        done += 1
        print(f"{f.name}: {len(text):,} chars")
print(f"{done} documents extracted to {out_dir}")
