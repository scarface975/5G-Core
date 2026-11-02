#!/usr/bin/env python3
"""Writes tests/fixtures/fuzz/nef_seed.hex: valid inputs of fuzz/fuzz_nef.c (one "<id> <hex>" line each; byte 0 selects the operation, see the table in
the C file).

    python3 tools/gen/gen_nef_fuzz_seeds.py"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
seeds = []


def j(o):
    return json.dumps(o, separators=(",", ":")).encode()


def op(code, doc):
    seeds.append(bytes([code]) + (doc if isinstance(doc, bytes) else j(doc)))


CB = "http://127.0.0.1:9/cb"
op(0, {"afAppId": "app-1", "anyUeInd": True, "dnn": "internet", "snssai": {"sst": 1, "sd": "000001"}, "trafficRoutes": [{"dnai": "edge1", "routeProfId": "p1"}], "tfcCorrInd": True})
op(0, {"trafficFilters": [{"flowId": 1, "flowDescriptions": ["permit out ip from 10.0.0.1 to any"]}], "gpsi": "msisdn-491700000001",
       "trafficRoutes": [{"dnai": "edge2", "routeInfo": {"ipv4Addr": "10.1.0.1", "portNumber": 80}}], "subscribedEvents": ["UP_PATH_CHANGE"], "notificationDestination": CB,
       "dnaiChgType": "EARLY", "suppFeat": "3", "requestTestNotification": True, "tempValidities": [{"startTime": "2030-01-01T00:00:00Z", "stopTime": "2030-02-01T00:00:00Z"}]})
op(0, {"afAppId": "a", "ipv4Addr": "10.0.0.7", "validGeoZoneIds": ["zone-1"]})
op(0, {"afAppId": "a", "externalGroupId": "grp@example.com", "afAckInd": True, "addrPreserInd": False})
op(0, {"ethTrafficFilters": [{"fDesc": "permit out 0x0800 from any to any", "fDir": "BIDIRECTIONAL"}], "macAddr": "00:11:22:33:44:55"})
op(1, {"afAppId": "app-2", "anyUeInd": True, "appReloInd": True})
op(2, {"appReloInd": True, "tfcCorrInd": None, "trafficRoutes": [{"dnai": "edge3", "routeProfId": "p3"}]})
op(2, {"tempValidities": None, "validGeoZoneIds": ["z"]})
op(3, {"externalId": "user1@example.com", "monitoringType": "LOSS_OF_CONNECTIVITY", "maximumNumberOfReports": 2, "supportedFeatures": "1", "notificationDestination": CB})
op(3, {"msisdn": "491700000001", "monitoringType": "UE_REACHABILITY", "reachabilityType": "DATA", "monitorExpireTime": "2030-01-01T00:00:00Z",
       "maximumDetectionTime": 30, "supportedFeatures": "2", "notificationDestination": CB, "requestTestNotification": True})
op(3, {"externalId": "user1@example.com", "monitoringType": "LOCATION_REPORTING", "locationType": "LAST_KNOWN_LOCATION", "accuracy": "TA_RA",
       "maximumNumberOfReports": 1, "supportedFeatures": "4", "notificationDestination": CB})
op(3, {"externalGroupId": "g@example.com", "monitoringType": "LOSS_OF_CONNECTIVITY", "maximumNumberOfReports": 1, "notificationDestination": CB})
op(3, {"externalId": "u@e", "monitoringType": "ROAMING_STATUS", "maximumNumberOfReports": 1, "notificationDestination": CB, "idleStatusIndication": True})
op(4, {"externalId": "user1@example.com", "monitoringType": "LOSS_OF_CONNECTIVITY", "maximumNumberOfReports": 3, "supportedFeatures": "401", "notificationDestination": CB})
op(5, {"notifyCorrelationId": "00000000000000000000000000000000", "reportList": [{"type": "LOSS_OF_CONNECTIVITY", "timeStamp": "2030-01-02T03:04:05Z", "lossOfConnectReason": "UE_DEREGISTERED"}]})
op(5, {"notifyCorrelationId": "x", "reportList": [{"type": "LOCATION_REPORT", "location": {"nrLocation": {"tai": {"plmnId": {"mcc": "001", "mnc": "01"}, "tac": "000001"}, "ncgi": {"nrCellId": "000000010"}}}},
                                                  {"type": "REACHABILITY_REPORT", "reachability": "REACHABLE"}]})
op(7, {"ueIpv4Addr": "10.46.0.2", "qosReference": "voice", "flowInfo": [{"flowId": 1, "flowDescriptions": ["permit out 17 from 10.46.0.2 5004 to 192.0.2.10 5004"]}],
       "supportedFeatures": "2", "requestTestNotification": True, "notificationDestination": CB})
op(7, {"ueIpv4Addr": "10.46.0.2", "qosReference": "voice", "flowInfo": [{"flowId": 1}], "usageThreshold": {"duration": 60}, "notificationDestination": CB})
op(7, {"macAddr": "00-11-22-33-44-55", "ueIpv4Addr": "10.46.0.2", "qosReference": "q", "flowInfo": [{"flowId": 1}], "notificationDestination": CB})
op(8, {"ueIpv4Addr": "10.46.0.2", "qosReference": "streaming", "flowInfo": [{"flowId": 2, "flowDescriptions": ["permit out ip from any to any"]}], "notificationDestination": CB})
op(9, {"qosReference": "streaming", "flowInfo": [{"flowId": 3}], "disUeNotif": None})
op(10, {"evSubsUri": "http://pcf/x", "evNotifs": [{"event": "SUCCESSFUL_RESOURCES_ALLOCATION"}, {"event": "FAILED_RESOURCES_ALLOCATION", "flows": [{"medCompN": 1}]}]})
op(11, {"termCause": "PDU_SESSION_TERMINATION", "resUri": "http://pcf/npcf-policyauthorization/v1/app-sessions/x"})
seeds.append(bytes([6, 0x01]))
seeds.append(bytes([6, 0x40]))
seeds.append(bytes([6, 0x32]))
seeds.append(bytes([6, 0x13]))
seeds.append(bytes([0]) + b"{")
seeds.append(bytes([3]) + b"[]")

out = ROOT / "tests" / "fixtures" / "fuzz" / "nef_seed.hex"
out.write_text("".join(f"nef{i:02d} {s.hex()}\n" for i, s in enumerate(seeds)), encoding="utf8", newline="\n")
print(f"{len(seeds)} seeds -> {out}")
