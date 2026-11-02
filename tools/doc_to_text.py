#!/usr/bin/env python3
"""Minimal text extractor for legacy Word 97-2003 .doc files (used for the 3GPP 35.xxx / 33.401 specs).

Usage: python tools/doc_to_text.py in.doc out.txt        (needs: pip install olefile)
Reads the FIB, the CLX piece table and concatenates the text pieces. Formatting is discarded; paragraph
marks become newlines and table cell marks become tabs, which is enough to recover test-vector tables.
"""
import struct
import sys

import olefile

src, dst = sys.argv[1:3]
ole = olefile.OleFileIO(src)
wd = ole.openstream("WordDocument").read()
if struct.unpack_from("<H", wd, 0)[0] != 0xA5EC:
    sys.exit("not a Word 97+ document")
flags = struct.unpack_from("<H", wd, 0x0A)[0]
table = ole.openstream("1Table" if flags & 0x0200 else "0Table").read()
fc_clx, lcb_clx = struct.unpack_from("<II", wd, 0x1A2)
clx = table[fc_clx:fc_clx + lcb_clx]

pos = 0
while clx[pos] == 0x01:  # skip Prc entries
    pos += 3 + struct.unpack_from("<H", clx, pos + 1)[0]
assert clx[pos] == 0x02, "no Pcdt in CLX"
lcb = struct.unpack_from("<I", clx, pos + 1)[0]
plc = clx[pos + 5:pos + 5 + lcb]
n = (lcb - 4) // 12
cps = struct.unpack_from("<%dI" % (n + 1), plc, 0)
out = []
for i in range(n):
    fc = struct.unpack_from("<I", plc, 4 * (n + 1) + 8 * i + 2)[0]
    count = cps[i + 1] - cps[i]
    if fc & 0x40000000:
        off = (fc & ~0x40000000) // 2
        out.append(wd[off:off + count].decode("cp1252", errors="replace"))
    else:
        out.append(wd[fc:fc + 2 * count].decode("utf-16-le", errors="replace"))
text = "".join(out).replace("\r", "\n").replace("\x07", "\t").replace("\x0b", "\n")
open(dst, "w", encoding="utf8", newline="\n").write(text)
print(f"{src}: {len(text)} chars")
