#!/usr/bin/env python3
"""Writes tests/fixtures/fuzz/udr_seed.hex: valid inputs of fuzz/fuzz_udr.c (one "<id> <hex>" line each).

Byte 0 selects the operation; for operation 0 the next bytes are resource, method, query, headers (If-Match in the low
nibble, If-None-Match in the high one), content type (indexes into the tables of fuzz/fuzz_udr.c), then the body. The bodies are written by hand from the 3GPP schemas.

    python3 tools/gen_udr_fuzz_seeds.py"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = {
    "auth": 0, "status": 1, "am": 2, "sm": 3, "prov": 4, "ctx": 5, "amf": 6, "smfreg": 7, "smfregs": 8, "sdmsubs": 9, "ee": 10,
    "ident": 11, "am_gpsi": 12, "subs": 13, "subs1": 14, "shared": 15, "grp": 16, "list": 17, "ue": 18, "osd": 19, "pam": 20,
    "usage": 21, "bdt": 22, "psubs": 23, "psubs1": 24, "expo": 25, "expo_pdu": 26, "esubs": 27, "infl": 28, "inflsubs": 29,
    "pfd": 30, "asubs": 31, "v1am": 32,
}
GET, PUT, PATCH, DELETE, POST = range(5)
JSON, JPATCH, MERGE, TEXT = range(4)
seeds = []


def req(res, method, body=b"", query=0, ctype=JSON, hdr=0):
    if isinstance(body, (dict, list)):
        body = json.dumps(body, separators=(",", ":")).encode()
    elif isinstance(body, str):
        body = body.encode()
    seeds.append(bytes([0, RES[res], method, query, hdr, ctype]) + body)


plmn = {"mcc": "001", "mnc": "01"}
req("auth", PUT, {"authenticationMethod": "5G_AKA", "sequenceNumber": {"sqn": "000000000020"}})
req("auth", GET)
req("auth", PATCH, [{"op": "replace", "path": "/sequenceNumber/sqn", "value": "000000000040"}], ctype=JPATCH)
req("auth", PATCH, {"sequenceNumber": {"sqn": "000000000060"}}, ctype=MERGE)
req("auth", PATCH, [{"op": "remove", "path": "/authenticationMethod"}], ctype=JPATCH)
req("auth", PUT, {"authenticationMethod": "5G_AKA"}, hdr=0x03)
req("status", PUT, {"nfInstanceId": "c22f4910-cc36-43e1-a33e-e213b6aba908", "success": True, "timeStamp": "2026-10-22T10:00:00Z",
                    "authType": "5G_AKA", "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"})
req("am", PUT, {"gpsis": ["msisdn-1"], "subscribedUeAmbr": {"uplink": "1 Gbps", "downlink": "2 Gbps"}, "nssai": {"defaultSingleNssais": [{"sst": 1}]}})
req("am", GET, query=1)
req("am", GET, query=2)
req("am_gpsi", GET)
req("sm", PUT, [{"singleNssai": {"sst": 1}, "dnnConfigurations": {"internet": {"pduSessionTypes": {"defaultSessionType": "IPV4"}, "sscModes": {"defaultSscMode": "SSC_MODE_1"}}}}])
req("sm", GET, query=4)
req("prov", GET)
req("ctx", GET)
req("amf", PUT, {"amfInstanceId": "a", "deregCallbackUri": "http://amf/d", "guami": {"plmnId": plmn, "amfId": "010203"}, "ratType": "NR"})
req("smfreg", PUT, {"smfInstanceId": "3f1a8c1e-8b8e-4b7e-9c0a-111111111111", "pduSessionId": 1, "singleNssai": {"sst": 1}, "plmnId": plmn})
req("smfregs", GET)
req("smfreg", DELETE)
req("sdmsubs", POST, {"nfInstanceId": "c22f4910-cc36-43e1-a33e-e213b6aba908", "callbackReference": "http://udm/cb", "monitoredResourceUris": ["/nudm-sdm/v2/x/am-data"]})
req("ee", PUT, {"callbackReference": "http://nef/cb", "monitoredResourceUris": ["/x"]})
req("ident", PUT, {"supiList": ["imsi-001010000000001"], "gpsiList": ["msisdn-1"]})
req("subs", POST, {"callbackReference": "http://127.0.0.1:9/cb", "monitoredResourceUris": ["http://u/nudr-dr/v2/subscription-data/imsi-001010000000001/00101/provisioned-data/am-data"], "ueId": "imsi-001010000000001"})
req("subs", GET)
req("subs1", DELETE)
req("list", GET)
req("ue", DELETE)
req("osd", PUT, {"g5c-policy": {"dataType": "object", "value": {"rfsp": 1}}})
req("osd", PATCH, [{"op": "add", "path": "/k", "value": {"dataType": "string", "value": "x"}}], ctype=JPATCH)
req("pam", GET)
req("usage", PUT, {"limitId": "l", "scopes": {}})
req("bdt", PUT, {"bdtRefId": "b1"})
req("psubs", POST, {"notificationUri": "http://127.0.0.1:9/p", "monitoredResourceUris": ["http://u/nudr-dr/v2/policy-data/ues/imsi-001010000000001/operator-specific-data"]})
req("expo", PUT, {"rfspIndex": 3})
req("expo_pdu", PUT, {"pduSessionId": 5, "dnn": "internet"})
req("esubs", POST, {"notificationUri": "http://127.0.0.1:9/e", "monitoredResourceUris": ["http://u/nudr-dr/v2/exposure-data/imsi-001010000000001/access-and-mobility-data"]})
req("infl", PUT, {"afAppId": "app", "dnn": "internet", "supi": "imsi-001010000000001"})
req("infl", PATCH, {"dnn": "ims"}, ctype=MERGE)
req("inflsubs", POST, {"notificationUri": "http://127.0.0.1:9/t", "dnns": ["internet"]})
req("pfd", PUT, {"externalAppId": "a1", "pfds": {}})
req("asubs", POST, {"notificationUri": "http://127.0.0.1:9/a", "dataFilters": [{"dataInd": "BDT"}]})
req("v1am", GET)
req("am", PATCH, "[{", ctype=JPATCH)
req("am", PUT, "{\"gpsis\":", ctype=JSON)
req("am", PUT, "x", ctype=TEXT)
seeds.append(b"\x01subscription-data/imsi-001010000000001/00101/provisioned-data/am-data")
seeds.append(b"\x01subscription-data/%2e%2e/%2e%2e/x")
seeds.append(b"\x01policy-data/plmns/001-01/ue-policy-set")
seeds.append(b"\x02nf-type=UDM&subscriberId=imsi-001010000000001")
seeds.append(b"\x02nf-type=UDM,AUSF&subscriberId=msisdn-1")
seeds.append(b"\x02subscriberId=imsi-1")
seeds.append(b"\x03\x00" + json.dumps({"callbackReference": "http://127.0.0.1:9/cb", "monitoredResourceUris": ["http://u/nudr-dr/v2/subscription-data/imsi-1/00101/provisioned-data/am-data"]}).encode())
seeds.append(b"\x03\x01" + json.dumps({"notificationUri": "http://127.0.0.1:9/cb", "monitoredResourceUris": ["/nudr-dr/v2/policy-data/ues/imsi-1/operator-specific-data"]}).encode())

out = ROOT / "tests" / "fixtures" / "fuzz" / "udr_seed.hex"
out.write_text("".join(f"udr{i:02d} {s.hex()}\n" for i, s in enumerate(seeds)), encoding="utf8", newline="\n")
print(f"{len(seeds)} seeds -> {out}")
