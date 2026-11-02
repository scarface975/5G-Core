#!/usr/bin/env python3
"""Writes tests/fixtures/fuzz/ausf_seed.hex: valid inputs of fuzz/fuzz_ausf.c (one "<id> <hex>" line each; byte 0 selects the operation).

The EAP-AKA' seeds carry a response the stub UDM's fixed vector makes valid: RES = 0x33 x 8, CK' = 0x44 x 16, IK' = 0x55 x 16, the identity 001010000000002 and the
first EAP identifier 1 (fuzz/fuzz_ausf.c). K_aut and AT_MAC are computed here with hmac / hashlib, independently of the C implementation (RFC 5448 3.3, 3.4).

    python3 tools/gen_ausf_fuzz_seeds.py"""
import base64
import hashlib
import hmac
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def prf_prime(key, s, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(key, t + s + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


CKP, IKP, IDENT = bytes([0x44]) * 16, bytes([0x55]) * 16, b"001010000000002"
mk = prf_prime(IKP + CKP, b"EAP-AKA'" + IDENT, 208)
K_AUT = mk[16:48]


def attr(t, value):
    assert (len(value) + 2) % 4 == 0
    return bytes([t, (len(value) + 2) // 4]) + value


def eap_response(res=bytes([0x33]) * 8, result_ind=False, bad_mac=False, ident=1):
    body = attr(3, struct.pack(">H", len(res) * 8) + res)
    if result_ind:
        body += attr(135, b"\0\0")
    body += attr(11, b"\0\0" + bytes(16))
    pkt = bytes([2, ident]) + struct.pack(">H", 8 + len(body)) + bytes([50, 1, 0, 0]) + body
    mac = hmac.new(K_AUT, pkt, hashlib.sha256).digest()[:16]
    pkt = pkt[:-16] + mac
    if bad_mac:
        pkt = pkt[:-1] + bytes([pkt[-1] ^ 1])
    return pkt


start = {"supiOrSuci": "imsi-001010000000001", "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"}
cases = [
    (0, json.dumps(start).encode()),
    (0, json.dumps(dict(start, supiOrSuci="suci-0-001-01-0000-0-0-0000000001", resynchronizationInfo={"rand": "00" * 16, "auts": "11" * 14})).encode()),
    (1, json.dumps({"resStar": "11" * 16}).encode()),
    (1, json.dumps({"resStar": None}).encode()),
    (2, json.dumps({"eapPayload": base64.b64encode(eap_response()).decode()}).encode()),
    (2, json.dumps({"eapPayload": None}).encode()),
    (3, eap_response()),
    (3, eap_response(result_ind=True)),
    (3, eap_response(bad_mac=True)),
    (3, eap_response(res=bytes([0x34]) * 8)),
    (4, json.dumps({"supi": "imsi-001010000000001"}).encode()),
    (5, json.dumps({"ackInd": True, "steeringContainer": [{"plmnId": {"mcc": "310", "mnc": "260"}, "accessTechList": ["NR", "UTRAN"]}]}).encode()),
    (5, json.dumps({"ackInd": False, "steeringContainer": "AQID"}).encode()),
    (6, json.dumps({"upuDataList": [{"secPacket": "AQID", "defaultConfNssai": [{"sst": 1, "sd": "010203"}], "routingId": "1234"}], "upuHeader": "06", "upuAckInd": True}).encode()),
    (7, json.dumps({"suci": "suci-0-001-01-0000-0-0-0000000001", "authenticatedInd": True}).encode()),
]
lines = ["%d %s" % (i + 1, (bytes([sel]) + body).hex()) for i, (sel, body) in enumerate(cases)]
out = ROOT / "tests" / "fixtures" / "fuzz" / "ausf_seed.hex"
out.write_text("\n".join(lines) + "\n")
print("wrote %d seeds" % len(lines))
