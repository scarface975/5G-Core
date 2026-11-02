#!/usr/bin/env python3
"""Generate the UDR's API tables from the pinned 3GPP OpenAPI files (TS 29.505, TS 29.519).

Output (committed, nf/udr/src/):
  api_routes.gen.c   one row per operation: method, path template, operation id, request/response schema ids,
                     status codes, content types, query parameters, the storage key template
  api_schemas.gen.c  the schemas reachable from those operations, flattened to a compact JSON document that the UDR's
                     validator (nf/udr/src/schema.c) interprets at start-up
Nothing is typed from memory: paths, parameters, schemas and status codes come from docs/specs/src/openapi.
Usage: python tools/spec/gen_udr_api.py [--check]   (--check fails when the committed files differ from a fresh run)
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oa_pool import Pool  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
OA = ROOT / "docs" / "specs" / "src" / "openapi"
OUT = ROOT / "nf" / "udr" / "src"

# document -> the API root the UDR serves it under (the version segment is added at run time)
SOURCES = [
    "TS29505_Unified_Data_Repository_Service_API_file_for_subscription_data.yaml",
    "TS29519_Unified_Data_Repository_Service_API_file_for_Application_Data.yaml",
    "TS29519_Unified_Data_Repository_Service_API_file_for_policy_data.yaml",
    "TS29519_Unified_Data_Repository_Service_API_file_for_structured_data_for_exposure.yaml",
]

ALIASES = {  # the names other documents use for the files extracted under longer names
    "ts29505subscriptiondata": SOURCES[0],
    "ts29519applicationdata": SOURCES[1],
    "ts29519policydata": SOURCES[2],
    "ts29519exposuredata": SOURCES[3],
    "ts29510nnrfnfmanagement": "TS29510_NRF_NFManagement_Service.yaml",
}
P = Pool(ALIASES)
files, pool, pool_ix, unresolved = P.files, P.pool, P.ix, P.unresolved
simplify, schema_id, find, is_array = P.simplify, P.schema_id, P.find, P.is_array


def content_schema(content, cur_file, *ctypes):
    for ct in ctypes:
        if ct in content and "schema" in content[ct]:
            return schema_id(content[ct]["schema"], cur_file)
    return -1


def deref_param(p, doc):
    if "$ref" in p:
        return resolve_ptr(doc, p["$ref"].partition("#")[2])
    return p


routes = []
for src in SOURCES:
    doc = files[src]
    for path, item in doc["paths"].items():
        common = item.get("parameters", [])
        for m in ("get", "put", "post", "patch", "delete"):
            op = item.get(m)
            if op is None:
                continue
            params = [deref_param(p, doc) for p in common + op.get("parameters", [])]
            query = [p["name"] for p in params if p.get("in") == "query"]
            headers = [p["name"].lower() for p in params if p.get("in") == "header"]
            req_ct, req_schema = 0, -1
            body = op.get("requestBody")
            if body:
                body = deref_param(body, doc)
                content = body.get("content", {})
                if "application/json-patch+json" in content:
                    req_ct |= 2
                if "application/merge-patch+json" in content:
                    req_ct |= 4
                if "application/json" in content:
                    req_ct |= 1
                req_schema = content_schema(content, src, "application/json", "application/merge-patch+json")
            ok, resp_schema, resp_codes = [], -1, {}
            for code, r in op.get("responses", {}).items():
                if not str(code).startswith("2"):
                    continue
                ok.append(int(code))
                r = deref_param(r, doc)
                sch = content_schema(r.get("content", {}), src, "application/json")
                resp_codes[int(code)] = sch
                if sch >= 0 and resp_schema < 0:
                    resp_schema = sch
            routes.append({
                "method": m.upper(), "path": path, "op": op.get("operationId", ""), "src": src[:6],
                "api": re.sub(r"^/", "", path).split("/")[0],
                "query": query, "headers": headers, "req_ct": req_ct, "req_schema": req_schema,
                "ok": sorted(ok), "resp_schema": resp_schema, "resp_codes": resp_codes,
            })

# Ordering: the router takes the first match, so the more literal template goes first.
def spec_key(r):
    segs = [s for s in r["path"].split("/") if s]
    return (-len(segs), [1 if s.startswith("{") else 0 for s in segs], r["path"], r["method"])


routes.sort(key=spec_key)

# Storage keys. The partition of a resource is the subscriber ({ueId}), the group ({ueGroupId}) or the global one;
# the serving PLMN of provisioned data is not part of the key (a repository holds one PLMN's subscription).
templates = {r["path"] for r in routes}
for r in routes:
    segs = [s for s in r["path"].split("/") if s]
    part = "global"
    key = []
    for s in segs:
        if s == "{ueId}":
            part = "ue"
        elif s == "{ueGroupId}":
            part = "group"
        elif s == "{servingPlmnId}":
            pass
        else:
            key.append(s)
    r["part"] = part
    r["key"] = "/".join(key)
    r["coll"] = any(t.startswith(r["path"] + "/{") and t.count("/") == r["path"].count("/") + 1 for t in templates)
    # a path with children is a collection only when its GET answers a list; SM policy data answers a document and also has
    # per-usage-monitoring children
    if r["coll"] and r["method"] == "GET" and r["resp_schema"] >= 0 and not is_array(r["resp_schema"]):
        r["coll"] = False
    r["post_create"] = r["method"] == "POST"

# ---- emit -----------------------------------------------------------------------------------------------------------

def cstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit_routes():
    lines = ["/* Generated by tools/spec/gen_udr_api.py from the pinned TS 29.505 / TS 29.519 OpenAPI files. Do not edit. */",
             '#include "api.h"', "", "const udr_op_def udr_ops[] = {"]
    for r in routes:
        codes = sorted(set(r["ok"]))
        mask = 0
        for c in codes:
            mask |= {200: 1, 201: 2, 204: 4, 202: 8, 307: 16, 308: 32}.get(c, 0)
        resp201 = r["resp_codes"].get(201, -1)
        lines.append("    {%s, %s, %s, %s, %d, %d, %d, %d, %d, 0x%02x, %s, %s, %s, %s, %s}," % (
            cstr(r["method"]), cstr(r["path"]), cstr(r["op"]), cstr(r["src"]),
            r["req_schema"], r["resp_schema"], resp201, r["req_ct"], 1 if "fields" in r["query"] else 0, mask,
            {"ue": "UDR_PART_UE", "group": "UDR_PART_GROUP", "global": "UDR_PART_GLOBAL"}[r["part"]],
            cstr(r["key"]), "true" if r["coll"] else "false", "true" if r["post_create"] else "false",
            cstr(",".join(r["query"]))))
    lines += ["};", "", "const size_t udr_ops_count = %d;" % len(routes), ""]
    return "\n".join(lines) + "\n" + emit_composites()


# GET of a parent resource assembles the children (TS 29.505 ProvisionedDataSets / ContextDataSets): the member of the
# composite, the storage key of the child, whether the child is a collection. The names are checked against the schema.
COMPOSITES = [
    ("ProvisionedDataSets", "subscription-data/provisioned-data", [
        ("amData", "am-data", False), ("smfSelData", "smf-selection-subscription-data", False),
        ("smsSubsData", "sms-data", False), ("smData", "sm-data", False), ("traceData", "trace-data", False),
        ("smsMngData", "sms-mng-data", False), ("lcsBcaData", "lcs-bca-data", False)]),
    ("ProvisionedDataSets", "subscription-data/provisioned-data", [
        ("lcsPrivacyData", "../lcs-privacy-data", False), ("lcsMoData", "../lcs-mo-data", False),
        ("v2xData", "../v2x-data", False)]),
    ("ContextDataSets", "subscription-data/context-data", [
        ("amf3Gpp", "amf-3gpp-access", False), ("amfNon3Gpp", "amf-non-3gpp-access", False),
        ("sdmSubscriptions", "sdm-subscriptions", True), ("eeSubscriptions", "ee-subscriptions", True),
        ("smsf3GppAccess", "smsf-3gpp-access", False), ("smsfNon3GppAccess", "smsf-non-3gpp-access", False),
        ("smfRegistrations", "smf-registrations", True), ("ipSmGw", "ip-sm-gw", False)]),
]


def emit_composites():
    schema_by_name = {}
    for key, ix in pool_ix.items():
        schema_by_name[key.rsplit("/", 1)[-1]] = pool[ix]
    rows = []
    for schema, parent, members in COMPOSITES:
        props = schema_by_name[schema]["properties"]
        for prop, child, lst in members:
            assert prop in props, f"{schema} has no member {prop}"
            ck = parent + "/" + child if not child.startswith("../") else "subscription-data/" + child[3:]
            rows.append('    {%s, %s, %s, %s},' % (cstr(parent), cstr(prop), cstr(ck), "true" if lst else "false"))
    return "const udr_composite udr_composites[] = {\n%s\n};\n\nconst size_t udr_composites_count = %d;\n" % (
        "\n".join(rows), len(rows))


def emit_schemas():
    text = json.dumps(pool, separators=(",", ":"), sort_keys=False)
    chunks = [text[i:i + 100] for i in range(0, len(text), 100)]
    body = ",\n".join("    " + cstr(c) for c in chunks)
    return ("/* Generated by tools/spec/gen_udr_api.py from the pinned TS 29.505 / TS 29.519 OpenAPI files. Do not edit. */\n"
            '#include "api.h"\n\n/* the JSON text of the schema pool in pieces: one literal would exceed the portable limit */\n'
            "const char *const udr_schema_chunks[] = {\n%s\n};\n\nconst size_t udr_schema_nchunks = %d;\n"
            "const size_t udr_schema_count = %d;\n" % (body, len(chunks), len(pool)))


outputs = {OUT / "api_routes.gen.c": emit_routes(), OUT / "api_schemas.gen.c": emit_schemas()}
if "--check" in sys.argv:
    bad = [str(p) for p, t in outputs.items() if not p.exists() or p.read_text(encoding="utf8") != t]
    if bad:
        print("stale:", *bad)
        sys.exit(1)
    print("udr api tables up to date")
else:
    OUT.mkdir(parents=True, exist_ok=True)
    for p, t in outputs.items():
        p.write_text(t, encoding="utf8", newline="\n")
    print(f"{len(routes)} operations, {len(pool)} schemas ({len(json.dumps(pool))} bytes); unresolved refs: {len(unresolved)}")
    for u in sorted(unresolved)[:20]:
        print("  unresolved:", u)
