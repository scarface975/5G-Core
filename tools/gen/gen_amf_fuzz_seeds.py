#!/usr/bin/env python3
"""Seeds for fuzz_amf: every NGAP PDU of the golden Open5GS / UERANSIM captures as an input of surface 0 (raw PDU) and 2 (the NAS PDU is wrapped in a valid
protected envelope of a registered UE), plus SBI bodies for the AMF's routes (surface 1). Output: tests/fixtures/fuzz/amf_seed.hex, one "<id> <hex>" per
line (the format fuzz/replay_main.c reads)."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
GOLD = os.path.join(ROOT, "tests", "fixtures", "golden")
OUT = os.path.join(ROOT, "tests", "fixtures", "fuzz", "amf_seed.hex")

lines = []
n = 0
for name in ("s1_ngap_pdus.hex", "s2_ngap_pdus.hex", "s3_ngap_pdus.hex", "ngap_handover_master_pdus.hex", "ngap_release_scenario_pdus.hex"):
    path = os.path.join(GOLD, name)
    if not os.path.exists(path):
        continue
    for ln in open(path, encoding="utf8"):
        parts = ln.split()
        if len(parts) != 2:
            continue
        for mode in ("00", "02"):
            n += 1
            lines.append(f"{n} {mode}{parts[1]}")


def sbi(route, ctype_bit, body):
    global n
    n += 1
    data = bytes([1, route, ctype_bit]) + body.encode()
    lines.append(f"{n} {data.hex()}")


sbi(0, 0, json.dumps({"pduSessionId": 1, "n1MessageContainer": {"n1MessageClass": "SM", "n1MessageContent": {"contentId": "n1SmMsg"}}}))
sbi(0, 0, json.dumps({"pduSessionId": 1, "n2InfoContainer": {"n2InformationClass": "SM", "smInfo": {"pduSessionId": 1, "n2InfoContent": {"ngapIeType": "PDU_RES_SETUP_REQ", "ngapData": {"contentId": "n2SmInfo"}}}}, "skipInd": True}))
sbi(0, 1, "--fuzz\r\ncontent-type: application/json\r\n\r\n{\"pduSessionId\":1}\r\n--fuzz--\r\n")
sbi(1, 0, json.dumps({"statusInfo": {"resourceStatus": "RELEASED", "cause": "5G_AN_NOT_RESPONDING"}}))
sbi(2, 0, json.dumps({"deregReason": "SUBSCRIPTION_WITHDRAWN", "accessType": "3GPP_ACCESS"}))
sbi(2, 0, json.dumps({"deregReason": "UE_INITIAL_REGISTRATION"}))
sbi(3, 0, json.dumps({"resourceUri": "http://pcf/npcf-am-policy-control/v1/policies/1", "rfsp": 2}))
sbi(4, 0, json.dumps({"notifyItems": [{"resourceId": "/imsi-001010000000001/am-data", "changes": [{"op": "REPLACE", "path": "/"}]}]}))
sbi(5, 0, json.dumps({"subscription": {"eventList": [{"type": "REGISTRATION_STATE_REPORT"}], "eventNotifyUri": "http://127.0.0.1:9/e", "anyUE": True}}))
sbi(5, 0, json.dumps({"subscription": {"eventList": [{"type": "LOCATION_REPORT"}], "eventNotifyUri": "http://127.0.0.1:9/e", "supi": "imsi-001010000000001"}}))

with open(OUT, "w", encoding="utf8", newline="\n") as f:
    f.write("\n".join(lines) + "\n")
print(f"{len(lines)} seeds -> {OUT}", file=sys.stderr)
