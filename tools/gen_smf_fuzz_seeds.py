#!/usr/bin/env python3
"""Seeds for fuzz/fuzz_smf.c. Each line is "<id> <hex>": the first byte selects the entry point (see the harness), the rest is the input.

    python3 tools/gen_smf_fuzz_seeds.py"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRLF = b"\r\n"


def multipart():
    js = b'{"supi":"imsi-001010000000001","pduSessionId":5,"dnn":"internet","sNssai":{"sst":1},"n1SmMsg":{"contentId":"n1"}}'
    out = b"--fuzz" + CRLF + b"Content-Type: application/json" + CRLF + CRLF + js + CRLF
    out += b"--fuzz" + CRLF + b"Content-Type: application/vnd.3gpp.5gnas" + CRLF + b"Content-Id: n1" + CRLF + CRLF + est_request() + CRLF
    out += b"--fuzz--" + CRLF
    return out


def est_request():
    epco = bytes.fromhex("80" "000d00" "000300" "001000")
    return bytes.fromhex("2e0503c1ffff91a1") + b"\x7b" + len(epco).to_bytes(2, "big") + epco


def pfcp_est_response():
    cause = bytes.fromhex("0013000101")
    fseid = bytes.fromhex("0039000d02" "0000000000000005" "7f000001")
    pdr = bytes.fromhex("00380002" "0001") + bytes.fromhex("00150009" "01" "00001001" "7f000001")
    created = bytes.fromhex("0008") + len(pdr).to_bytes(2, "big") + pdr
    return cause + fseid + created


DECISION = (b'{"sessRules":{"s":{"authSessAmbr":{"uplink":"100 Mbps","downlink":"200 Mbps"},"authDefQos":{"5qi":9,"arp":{"priorityLevel":8}}}},'
            b'"pccRules":{"A":{"pccRuleId":"A","precedence":10,"flowInfos":[{"flowDescription":"permit out 17 from 198.51.100.0/24 5060 to assigned",'
            b'"flowDirection":"BIDIRECTIONAL"}],"refQosData":["Q"]}},"qosDecs":{"Q":{"5qi":1,"gbrUl":"1 Mbps","gbrDl":"2 Mbps","maxbrUl":"3 Mbps","maxbrDl":"4 Mbps"}}}')

OLD = (b'{"sessRules":{"s":{"authSessAmbr":{"uplink":"100 Mbps","downlink":"200 Mbps"},"authDefQos":{"5qi":9}}},'
       b'"pccRules":{"A":{"pccRuleId":"A","precedence":10,"flowInfos":[{"flowDescription":"permit out ip from 10.1.1.1 to assigned"}],"refQosData":["Q"]}},'
       b'"qosDecs":{"Q":{"5qi":1,"gbrUl":"1 Mbps","gbrDl":"1 Mbps"}}}')
NEW = (b'{"sessRules":{"s":{"authSessAmbr":{"uplink":"50 Mbps","downlink":"80 Mbps"},"authDefQos":{"5qi":9}}},'
       b'"pccRules":{"B":{"pccRuleId":"B","precedence":20,"flowInfos":[{"flowDescription":"permit out 17 from 10.2.2.2 5060 to assigned"}],"refQosData":["R"]}},'
       b'"qosDecs":{"R":{"5qi":2,"gbrUl":"2 Mbps","gbrDl":"2 Mbps"}}}')


def rs_packet():
    src = bytes.fromhex("fe80000000000000a0a1a2a3a4a5a6a7")
    dst = bytes.fromhex("ff020000000000000000000000000002")
    icmp = bytes([133, 0, 0, 0, 0, 0, 0, 0])
    s = sum(int.from_bytes(src[i:i + 2], "big") + int.from_bytes(dst[i:i + 2], "big") for i in range(0, 16, 2)) + 8 + 58
    s += int.from_bytes(icmp[0:2], "big")
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    c = (~s) & 0xffff
    icmp = bytes([133, 0, c >> 8, c & 0xff, 0, 0, 0, 0])
    return bytes([0x60, 0, 0, 0, 0, 8, 58, 255]) + src + dst + icmp


lines = [
    b"\x00" + multipart(),
    b"\x01" + est_request(),
    b"\x02" + bytes.fromhex("0003e0c0a801640000abcd04010080"),
    b"\x03" + b"permit out 17 from 198.51.100.0/24 5060 to assigned",
    b"\x03" + b"permit out ip from any to assigned",
    b"\x04" + DECISION,
    b"\x05" + b"100 Mbps",
    b"\x05" + b"1.5 Gbps",
    b"\x06" + pfcp_est_response(),
    b"\x07" + est_request(),
    b"\x08" + b'{"old":' + OLD + b',"new":' + NEW + b'}',
    b"\x09" + rs_packet(),
]
out = "\n".join("%d %s" % (i, l.hex()) for i, l in enumerate(lines)) + "\n"
(ROOT / "tests/fixtures/fuzz/smf_seed.hex").write_text(out, encoding="utf8", newline="\n")
print(len(lines), "seeds")
