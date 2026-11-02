#!/usr/bin/env python3
"""Writes tests/fixtures/fuzz/scp_seed.hex: valid inputs of fuzz/fuzz_scp.c (one "<id> <hex>" line each; byte 0 selects the operation, byte 1 is a selector, the rest
is the value; see the table in the C file).

    python3 tools/gen/gen_scp_fuzz_seeds.py"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
seeds = []


def op(code, sel, value):
    seeds.append(bytes([code, sel]) + value.encode())


op(0, 0, "http://127.0.0.1:9")
op(0, 0, "https://127.0.0.1:9/prefix")
op(0, 0, "http://[::1]:9")
op(0, 0, "http://user@127.0.0.1:9")
op(0, 0, "http://127.0.0.1:99999")
op(0, 0, "127.0.0.1:9")
op(1, 0, "NSSF")
op(1, 3, "UDM")
op(1, 1, "")
op(1, 2, "AMF,SMF")
op(2, 0, "http://127.0.0.1:9/cb")
op(2, 0, "http://127.0.0.1:9/scp-default-sub-notify-uri")
op(3, 0, "2.0 SCP-scp-fuzz")
op(3, 0, "2.0 SCP-other, 2.0 SCP-scp-fuzz")
op(3, 0, "1.1 a, 2.0 b")
op(4, 10, "Tue, 15 Nov 2044 08:12:31 GMT")
op(4, 200, "Sun, 06 Nov 1994 08:49:37 GMT")
op(4, 0, "not a date")
op(5, 0, "nf-type=AMF&ck=abc&x=1")
op(5, 0, "ck=1&ck=2&")
op(5, 0, "%zz&=&&")
op(6, 0, "scp/nnssf-nsselection/v2/network-slice-information")
op(6, 0, "scp/scp-default-sub-notify-uri")
op(6, 0, "../..//x")
op(7, 0, '{"a":1}')
op(7, 0, "{")
op(8, 0, "AMF-1")
op(8, 0, "NRF")
op(8, 0, "-")

out = ROOT / "tests" / "fixtures" / "fuzz" / "scp_seed.hex"
out.write_text("".join(f"scp{i:02d} {s.hex()}\n" for i, s in enumerate(seeds)), encoding="utf8", newline="\n")
print(f"{len(seeds)} seeds -> {out}")
