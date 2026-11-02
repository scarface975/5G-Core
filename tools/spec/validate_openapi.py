#!/usr/bin/env python3
"""Validate the JSON our NFs produce against the official 3GPP OpenAPI schemas.

Payloads come from the dump tests (G5C_PAYLOAD_DIR); schemas from docs/specs/src/openapi (tools/spec/extract_openapi.py).
Usage: python tools/spec/validate_openapi.py <payload_dir>
Exit status is non-zero if any payload violates its schema.
"""
import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

OA = Path(__file__).resolve().parent.parent.parent / "docs" / "specs" / "src" / "openapi"
payload_dir = Path(sys.argv[1])

files, parse_errors = {}, {}
for p in sorted(OA.glob("*.yaml")):
    try:
        # Known defect of the published file: TS 29.531 (Nnssf_NSSelection) writes the MNC length of the AMF Set pattern as {2-3}, not {2,3}; as written it
        # matches no AMF Set ID at all (the NSSAIAvailability file of the same specification has {2,3}). Read as intended.
        files[p.name] = yaml.safe_load(p.read_text(encoding="utf8").replace("\t", "  ").replace("{2-3}", "{2,3}"))
    except Exception as e:  # extraction artefacts: report, keep going
        parse_errors[p.name] = str(e).splitlines()[0]

# The second known defect: TS 29.519 types the group of "any UE" (internalGroupId set to "AnyUE", 6.2.6.2.2 NOTE) as GroupId, whose pattern does not allow it.
# The same list the generators use (tools/spec/oa_pool.py ANY_UE); read as the text intends.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from oa_pool import ANY_UE  # noqa: E402
for _f, _sch, _member, _arr in ANY_UE:
    _node = ((files.get(_f) or {}).get("components", {}).get("schemas", {}).get(_sch, {}).get("properties", {}) or {}).get(_member)
    if _node is not None:
        _t = _node["items"] if _arr else _node
        _alt = {"anyOf": [{"type": "string", "enum": ["AnyUE"]}, {k: v for k, v in _t.items() if k != "description"}]}
        if _arr:
            _node["items"] = _alt
        else:
            _node.clear()
            _node.update(_alt)


def norm(n):
    return re.sub(r"[^a-z0-9]", "", n.lower().replace(".yaml", ""))

# names other documents use in $ref, mapped to the files we extracted
ALIASES = {
    "ts29509nausfueauthentication": "TS29509_AUSF_API.yaml",
    "ts29510nnrfnfmanagement": "TS29510_NRF_NFManagement_Service.yaml",
    "ts29510nnrfnfdiscovery": "TS29510_NRF_NFDiscovery_Service.yaml",
    "ts29512npcfsmpolicycontrol": "TS29512_Npcf_SMPolicyControl_API.yaml",
    "ts29507npcfampolicycontrol": "TS29507_Npcf_AMPolicyControl.yaml",
    "ts29505subscriptiondata": "TS29505_Unified_Data_Repository_Service_API_file_for_subscription_data.yaml",
    "ts29519policydata": "TS29519_Unified_Data_Repository_Service_API_file_for_policy_data.yaml",
    "ts29519applicationdata": "TS29519_Unified_Data_Repository_Service_API_file_for_Application_Data.yaml",
    "ts29519exposuredata": "TS29519_Unified_Data_Repository_Service_API_file_for_structured_data_for_exposure.yaml",
    "ts29510nnrfnfmanagement": "TS29510_NRF_NFManagement_Service.yaml",
}

def find(name):
    if name in files:
        return name
    n = norm(name)
    if n in ALIASES and ALIASES[n] in files:
        return ALIASES[n]
    for f in files:
        if norm(f).startswith(n) or n.startswith(norm(f)):
            return f
    return None

def retrieve(uri):
    f = find(uri.rsplit("/", 1)[-1])
    return Resource.from_contents(files[f] if f else {}, default_specification=DRAFT7)

registry = Registry(retrieve=retrieve)

# payload file stem (prefix) -> (document, schema)
MAP = [
    ("ausf_UEAuthenticationCtx", "TS29509_AUSF_API.yaml", "UEAuthenticationCtx"),
    ("ausf_ConfirmationDataResponse", "TS29509_AUSF_API.yaml", "ConfirmationDataResponse"),
    ("ausf_EapSession", "TS29509_AUSF_API.yaml", "EapSession"),
    ("ausf_RgAuthCtx", "TS29509_AUSF_API.yaml", "RgAuthCtx"),
    ("ausf_SorSecurityInfo", "TS29509_Nausf_SoRProtection_Service.yaml", "SorSecurityInfo"),
    ("ausf_UpuSecurityInfo", "TS29509_Nausf_UPUProtection_Service.yaml", "UpuSecurityInfo"),
    ("ausf_ProblemDetails", "TS29571_CommonData.yaml", "ProblemDetails"),
    ("udm_AuthenticationInfoResult", "TS29503_Nudm_UEAU.yaml", "AuthenticationInfoResult"),
    ("udm_AuthEvent", "TS29503_Nudm_UEAU.yaml", "AuthEvent"),
    ("udm_RgAuthCtx", "TS29503_Nudm_UEAU.yaml", "RgAuthCtx"),
    ("udm_AccessAndMobilitySubscriptionData", "TS29503_Nudm_SDM.yaml", "AccessAndMobilitySubscriptionData"),
    ("udm_SessionManagementSubscriptionData", "TS29503_Nudm_SDM.yaml", "SessionManagementSubscriptionData"),
    ("udm_Nssai", "TS29503_Nudm_SDM.yaml", "Nssai"),
    ("udm_SmfSelectionSubscriptionData", "TS29503_Nudm_SDM.yaml", "SmfSelectionSubscriptionData"),
    ("udm_UeContextInSmfData", "TS29503_Nudm_SDM.yaml", "UeContextInSmfData"),
    ("udm_SdmSubscription", "TS29503_Nudm_SDM.yaml", "SdmSubscription"),
    ("udm_ModificationNotification", "TS29503_Nudm_SDM.yaml", "ModificationNotification"),
    ("udm_SubscriptionDataSets", "TS29503_Nudm_SDM.yaml", "SubscriptionDataSets"),
    ("problem_ProblemDetails", "TS29571_CommonData.yaml", "ProblemDetails"),
    ("pcf_ProblemDetails", "TS29571_CommonData.yaml", "ProblemDetails"),
    ("udr_AuthenticationSubscription", "TS29505_Unified_Data_Repository_Service_API_file_for_subscription_data.yaml", "AuthenticationSubscription"),
    ("udr_AccessAndMobilitySubscriptionData", "TS29505_Unified_Data_Repository_Service_API_file_for_subscription_data.yaml", "AccessAndMobilitySubscriptionData"),
    ("udr_ProvisionedDataSets", "TS29505_Unified_Data_Repository_Service_API_file_for_subscription_data.yaml", "ProvisionedDataSets"),
    ("udr_ContextDataSets", "TS29505_Unified_Data_Repository_Service_API_file_for_subscription_data.yaml", "ContextDataSets"),
    ("udr_SmfRegistration", "TS29505_Unified_Data_Repository_Service_API_file_for_subscription_data.yaml", "SmfRegistration"),
    ("udr_Amf3GppAccessRegistration", "TS29505_Unified_Data_Repository_Service_API_file_for_subscription_data.yaml", "Amf3GppAccessRegistration"),
    ("udr_IdentityData", "TS29505_Unified_Data_Repository_Service_API_file_for_subscription_data.yaml", "IdentityData"),
    ("udr_SubscriptionDataSubscriptions", "TS29505_Unified_Data_Repository_Service_API_file_for_subscription_data.yaml", "SubscriptionDataSubscriptions"),
    ("udr_DataChangeNotify", "TS29505_Unified_Data_Repository_Service_API_file_for_subscription_data.yaml", "DataChangeNotify"),
    ("udr_SdmSubscription", "TS29503_Nudm_SDM.yaml", "SdmSubscription"),
    ("udr_PolicyDataSubscription", "TS29519_Unified_Data_Repository_Service_API_file_for_policy_data.yaml", "PolicyDataSubscription"),
    ("udr_PolicyDataChangeNotification", "TS29519_Unified_Data_Repository_Service_API_file_for_policy_data.yaml", "PolicyDataChangeNotification"),
    ("udr_ExposureDataSubscription", "TS29519_Unified_Data_Repository_Service_API_file_for_structured_data_for_exposure.yaml", "ExposureDataSubscription"),
    ("udr_ExposureDataChangeNotification", "TS29519_Unified_Data_Repository_Service_API_file_for_structured_data_for_exposure.yaml", "ExposureDataChangeNotification"),
    ("udr_TrafficInfluSub", "TS29519_Unified_Data_Repository_Service_API_file_for_Application_Data.yaml", "TrafficInfluSub"),
    ("udr_TrafficInfluDataNotif", "TS29519_Unified_Data_Repository_Service_API_file_for_Application_Data.yaml", "TrafficInfluDataNotif"),
    ("udr_ApplicationDataSubs", "TS29519_Unified_Data_Repository_Service_API_file_for_Application_Data.yaml", "ApplicationDataSubs"),
    ("udr_ProblemDetails", "TS29571_CommonData.yaml", "ProblemDetails"),
    ("nssf_AuthorizedNetworkSliceInfo", "TS29531_Nnssf_NSSelection.yaml", "AuthorizedNetworkSliceInfo"),
    ("nssf_AuthorizedNssaiAvailabilityInfo", "TS29531_Nnssf_NSSAIAvailability.yaml", "AuthorizedNssaiAvailabilityInfo"),
    ("nssf_NssfEventSubscriptionCreatedData", "TS29531_Nnssf_NSSAIAvailability.yaml", "NssfEventSubscriptionCreatedData"),
    ("nssf_NssfEventNotification", "TS29531_Nnssf_NSSAIAvailability.yaml", "NssfEventNotification"),
    ("nssf_ProblemDetails", "TS29571_CommonData.yaml", "ProblemDetails"),
    ("nef_TrafficInfluSub", "TS29522_TrafficInfluence.yaml", "TrafficInfluSub"),
    ("nef_TrafficInfluData", "TS29519_Unified_Data_Repository_Service_API_file_for_Application_Data.yaml", "TrafficInfluData"),
    ("nef_MonitoringEventSubscription", "TS29122_MonitoringEvent.yaml", "MonitoringEventSubscription"),
    ("nef_MonitoringNotification", "TS29122_MonitoringEvent.yaml", "MonitoringNotification"),
    ("nef_TestNotification", "TS29122_CommonData.yaml", "TestNotification"),
    ("nef_ProblemDetails", "TS29571_CommonData.yaml", "ProblemDetails"),
    ("bsf_PcfBinding", "TS29521_Nbsf_Management.yaml", "PcfBinding"),
    ("bsf_PcfBinding_discovery", "TS29521_Nbsf_Management.yaml", "PcfBinding"),
    ("bsf_PcfBinding_updated", "TS29521_Nbsf_Management.yaml", "PcfBinding"),
    ("bsf_ExtProblemDetails", "TS29521_Nbsf_Management.yaml", "ExtProblemDetails"),
    ("bsf_ProblemDetails", "TS29571_CommonData.yaml", "ProblemDetails"),
    ("bsf_ProblemDetails_invalid", "TS29571_CommonData.yaml", "ProblemDetails"),
    ("pcf_SmPolicyDecision", "TS29512_Npcf_SMPolicyControl_API.yaml", "SmPolicyDecision"),
    ("pcf_SmPolicyControl", "TS29512_Npcf_SMPolicyControl_API.yaml", "SmPolicyControl"),
    ("pcf_SmPolicyNotification", "TS29512_Npcf_SMPolicyControl_API.yaml", "SmPolicyNotification"),
    ("pcf_TerminationNotification", "TS29512_Npcf_SMPolicyControl_API.yaml", "TerminationNotification"),
    ("pcf_PolicyAssociation", "TS29507_Npcf_AMPolicyControl.yaml", "PolicyAssociation"),
    ("pcf_PolicyUpdate", "TS29507_Npcf_AMPolicyControl.yaml", "PolicyUpdate"),
    ("nrf_NFProfile", "TS29510_NRF_NFManagement_Service.yaml", "NFProfile"),
    ("nrf_SubscriptionData", "TS29510_NRF_NFManagement_Service.yaml", "SubscriptionData"),
    ("nrf_NotificationData", "TS29510_NRF_NFManagement_Service.yaml", "NotificationData"),
    ("nrf_SearchResult", "TS29510_NRF_NFDiscovery_Service.yaml", "SearchResult"),
    ("nrf_AccessTokenRsp", "TS29510_NRF_AccessToken_Service.yaml", "AccessTokenRsp"),
    ("nrf_ProblemDetails", "TS29571_CommonData.yaml", "ProblemDetails"),
]

def schema_location(doc, schema):
    d = find(doc)
    if d and schema in (files[d].get("components", {}).get("schemas", {}) or {}):
        return d
    for f, content in files.items():
        if schema in ((content or {}).get("components", {}).get("schemas", {}) or {}):
            return f
    return None

# --- self-check: a payload known to violate the schema must be rejected, otherwise "OK" would mean nothing
_bad = {"request": {"notificationUri": "http://x", "supi": "imsi-1"}, "triggers": []}  # triggers has minItems 1
_loc = schema_location("TS29507_Npcf_AMPolicyControl.yaml", "PolicyAssociation")
_v = Draft7Validator({"$ref": f"http://oa/{_loc}#/components/schemas/PolicyAssociation"}, registry=registry)
if not list(_v.iter_errors(_bad)):
    sys.exit("validator self-check FAILED: an invalid PolicyAssociation was accepted")
print("validator self-check passed (invalid sample rejected)")

total = failed = 0
print(f"{len(files)} OpenAPI documents loaded" + (f"; unparsable: {parse_errors}" if parse_errors else ""))
for payload in sorted(payload_dir.glob("*.json")):
    entry = next((m for m in MAP if payload.stem == m[0] or payload.stem.startswith(m[0] + "_")), None)
    if not entry:
        print(f"SKIP  {payload.stem}: no schema mapping")
        continue
    _, doc, schema = entry
    loc = schema_location(doc, schema)
    if not loc:
        print(f"SKIP  {payload.stem}: schema {schema} not found")
        continue
    total += 1
    validator = Draft7Validator({"$ref": f"http://oa/{loc}#/components/schemas/{schema}"}, registry=registry)
    errs = sorted(validator.iter_errors(json.loads(payload.read_text(encoding="utf8"))), key=lambda e: list(e.path))
    if errs:
        failed += 1
        print(f"FAIL  {payload.stem}  vs {loc}#{schema}")
        for e in errs[:6]:
            path = "/".join(str(p) for p in e.path) or "(root)"
            print(f"        at {path}: {e.message[:200]}")
    else:
        print(f"OK    {payload.stem}  vs {schema}")
print(f"\n{total - failed}/{total} payloads valid against the official schemas")
sys.exit(1 if failed else 0)
