#!/usr/bin/env python3
"""Writes tests/fixtures/fuzz/nssf_seed.hex: valid inputs of fuzz/fuzz_nssf.c (one "<id> <hex>" line each; byte 0 selects the operation, byte 1 the
parameter or the NF, see the table in the C file).

    python3 tools/gen_nssf_fuzz_seeds.py"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAI = {"plmnId": {"mcc": "001", "mnc": "01"}, "tac": "000001"}
seeds = []


def j(o):
    return json.dumps(o, separators=(",", ":")).encode()


def get(param, nf, doc):
    seeds.append(bytes([0, param, nf]) + j(doc))


# parameter indexes: 0 registration, 1 pdu session, 2 ue-cu, 3 pdn connection, 4 home-plmn-id, 5 tai, 6 supported-features, 7 nf-type
get(0, 0, {"requestedNssai": [{"sst": 1}, {"sst": 2}], "subscribedNssai": [{"subscribedSnssai": {"sst": 1}, "defaultIndication": True}, {"subscribedSnssai": {"sst": 2}}]})
get(0, 1, {"requestedNssai": [{"sst": 7}], "subscribedNssai": [{"subscribedSnssai": {"sst": 1}, "defaultIndication": True}], "defaultConfiguredSnssaiInd": True})
get(0, 0, {"sNssaiForMapping": [{"sst": 9}], "requestMapping": True})
get(0, 0, {"requestedNssai": [{"sst": 1}], "mappingOfNssai": [{"servingSnssai": {"sst": 1}, "homeSnssai": {"sst": 9}}],
           "subscribedNssai": [{"subscribedSnssai": {"sst": 9}, "defaultIndication": True}]})
get(1, 0, {"sNssai": {"sst": 1, "sd": "000001"}, "roamingIndication": "NON_ROAMING"})
get(1, 0, {"sNssai": {"sst": 1}, "roamingIndication": "HOME_ROUTED_ROAMING", "homeSnssai": {"sst": 9}})
get(2, 0, {"subscribedNssai": [{"subscribedSnssai": {"sst": 1}, "defaultIndication": True}], "defaultConfiguredSnssaiInd": True})
get(3, 0, [{"sst": 9}, {"sst": 8}])
get(4, 0, {"mcc": "310", "mnc": "260"})
get(5, 0, TAI)
seeds.append(bytes([0, 6, 0]) + b"7")
seeds.append(bytes([0, 7, 0]) + b"AMF")
avail = {"supportedNssaiAvailabilityData": [{"tai": TAI, "supportedSnssaiList": [{"sst": 1}, {"sst": 1, "sd": "000001"}, {"sst": 2, "wildcardSd": True}]}],
         "amfSetId": "001-01-01-001", "supportedFeatures": "7"}
seeds.append(bytes([1, 0]) + j(avail))
seeds.append(bytes([1, 1]) + j({"supportedNssaiAvailabilityData": [{"tai": TAI, "taiList": [dict(TAI, tac="000002")], "taiRangeList": [
    {"plmnId": {"mcc": "001", "mnc": "01"}, "tacRangeList": [{"start": "000003", "end": "000005"}]}], "supportedSnssaiList": [{"sst": 2}]}]}))
seeds.append(bytes([2, 0]) + j([{"op": "replace", "path": "/supportedNssaiAvailabilityData/0/supportedSnssaiList", "value": [{"sst": 1}]}]))
seeds.append(bytes([2, 0]) + j([{"op": "remove", "path": "/amfSetId"}]))
seeds.append(bytes([3, 0]) + j({"nfNssaiAvailabilityUri": "http://127.0.0.1:9/cb", "taiList": [TAI], "event": "SNSSAI_STATUS_CHANGE_REPORT", "supportedFeatures": "7"}))
seeds.append(bytes([3, 0]) + j({"nfNssaiAvailabilityUri": "http://127.0.0.1:9/cb", "taiList": [], "taiRangeList": [
    {"plmnId": {"mcc": "001", "mnc": "01"}, "tacRangeList": [{"start": "000001", "end": "000009"}]}], "event": "SNSSAI_STATUS_CHANGE_REPORT", "amfSetId": "001-01-01-001"}))
seeds.append(bytes([4, 0]) + j([{"op": "replace", "path": "/taiList", "value": [TAI]}]))
seeds.append(bytes([5, 0]))
seeds.append(bytes([1, 2]) + b"{")
seeds.append(bytes([0, 0, 0]) + b"%7Bnot")

out = ROOT / "tests" / "fixtures" / "fuzz" / "nssf_seed.hex"
out.write_text("".join(f"nssf{i:02d} {s.hex()}\n" for i, s in enumerate(seeds)), encoding="utf8", newline="\n")
print(f"{len(seeds)} seeds -> {out}")
