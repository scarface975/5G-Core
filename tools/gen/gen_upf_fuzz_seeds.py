#!/usr/bin/env python3
"""Seeds for fuzz/fuzz_upf.c from the real messages in libs/pfcp/tests/pfcp_vectors.h and nf/upf/tests/gtpu_vectors.h.
Each line is "<id> <hex>": first byte selects the entry point (0 N4 from the SMF, 1 GTP-U from the gNB, 2 IP from the data network).
The harness gives the first session the SEID 1 and the TEID 0x1001.
    python3 tools/gen/gen_upf_fuzz_seeds.py"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def vec(path, name):
    m = re.search(r'#define %s "([0-9a-f]+)"' % name, (ROOT / path).read_text())
    return bytes.fromhex(m.group(1))


def patch_seid(msg, seid):
    return msg[:4] + seid.to_bytes(8, "big") + msg[12:]


lines = []
pf = "libs/pfcp/tests/pfcp_vectors.h"
est = vec(pf, "PFCPV_SESS_EST_REQ")
lines.append(b"\x00" + est)
lines.append(b"\x00" + vec(pf, "PFCPV_ASSOC_SETUP_REQ"))
lines.append(b"\x00" + patch_seid(vec(pf, "PFCPV_SESS_MOD_REQ"), 1))
lines.append(b"\x00" + patch_seid(vec(pf, "PFCPV_SESS_DEL_REQ"), 1))
gv = "nf/upf/tests/gtpu_vectors.h"
ul = bytearray(vec(gv, "GTPUV_UL"))
ul[4:8] = (0x1001).to_bytes(4, "big")
lines.append(b"\x01" + bytes(ul))
dl = vec(gv, "GTPUV_DL")
# the downlink G-PDU's inner packet is a valid downlink IP packet for the UE
off = 16
lines.append(b"\x02" + dl[off:])
lines.append(b"\x01" + bytes.fromhex("30ff000400001001deadbeef"))
lines.append(b"\x01" + bytes.fromhex("3201000400000000123400000000"))
out = "\n".join("%d %s" % (i, l.hex()) for i, l in enumerate(lines)) + "\n"
(ROOT / "tests/fixtures/fuzz/upf_seed.hex").write_text(out, encoding="utf8", newline="\n")
print(len(lines), "seeds")
