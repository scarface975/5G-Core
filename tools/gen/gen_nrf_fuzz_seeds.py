#!/usr/bin/env python3
"""Writes tests/fixtures/fuzz/nrf_seed.hex: valid inputs of fuzz/fuzz_nrf.c (one "<id> <hex>" line each; byte 0 selects the operation).

    python3 tools/gen/gen_nrf_fuzz_seeds.py"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
profile = {
    "nfInstanceId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "nfType": "SMF", "nfStatus": "REGISTERED", "heartBeatTimer": 10,
    "plmnList": [{"mcc": "001", "mnc": "01"}], "sNssais": [{"sst": 1}], "ipv4Addresses": ["10.0.0.4"], "priority": 1, "capacity": 100, "load": 5,
    "smfInfo": {"sNssaiSmfInfoList": [{"sNssai": {"sst": 1}, "dnnSmfInfoList": [{"dnn": "internet"}]}],
                "taiList": [{"plmnId": {"mcc": "001", "mnc": "01"}, "tac": "000001"}]},
    "nfServices": [{"serviceInstanceId": "1", "serviceName": "nsmf-pdusession", "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme": "http", "nfServiceStatus": "REGISTERED", "ipEndPoints": [{"ipv4Address": "10.0.0.4", "port": 7777}]}],
}
map_profile = dict(profile, nfServiceList={"1": profile["nfServices"][0]})
del map_profile["nfServices"]
cases = [
    (0, json.dumps(profile)),
    (0, json.dumps(map_profile)),
    (1, json.dumps([{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"}, {"op": "add", "path": "/load", "value": 40}])),
    (1, json.dumps([{"op": "add", "path": "/nfServices/-", "value": {"serviceInstanceId": "2", "serviceName": "nsmf-event-exposure"}}])),
    (2, json.dumps({"nfStatusNotificationUri": "http://127.0.0.1:9/cb", "subscrCond": {"nfType": "SMF"}, "reqNotifEvents": ["NF_REGISTERED"]})),
    (2, json.dumps({"nfStatusNotificationUri": "http://127.0.0.1:9/cb", "notifCondition": {"monitoredAttributes": ["/load"]},
                    "validityTime": "2099-01-01T00:00:00Z"})),
    (3, "target-nf-type=SMF&requester-nf-type=AMF&service-names=nsmf-pdusession&snssais=%5B%7B%22sst%22%3A1%7D%5D&dnn=internet"
        "&tai=%7B%22plmnId%22%3A%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D%2C%22tac%22%3A%22000001%22%7D&limit=2&preferred-locality=dc-a"),
    (3, "target-nf-type=UDM&requester-nf-type=AUSF&supi=imsi-001010000000001&supported-features=1"
        "&target-plmn-list=%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D"),
    (4, "grant_type=client_credentials&nfInstanceId=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa&nfType=SMF&scope=nudm-sdm&targetNfType=UDM"),
    (5, json.dumps(map_profile)),
]
lines = ["%d %s" % (i + 1, (bytes([sel]) + text.encode()).hex()) for i, (sel, text) in enumerate(cases)]
out = ROOT / "tests" / "fixtures" / "fuzz" / "nrf_seed.hex"
out.write_text("\n".join(lines) + "\n")
print("wrote %d seeds" % len(lines))
