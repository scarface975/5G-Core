/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The UDR's Nudr_DataRepository behaviour, in process (no sockets) */
#include <stdlib.h>
#include <string.h>

#include "g5c/testkit.h"
#include "g5c/udr.h"
#include "store_env.h"

typedef struct {
    int status;
    g5c_json *json;
    char etag[64], last_modified[64], location[256], cause[64];
} R;

static g5c_json *J(const char *s)
{
    g5c_json *j = g5c_json_parse(s, strlen(s), NULL, 0);
    TK_ASSERT(j != NULL);
    return j;
}

static void expect_json(const g5c_json *j, const char *want)
{
    g5c_json *w = J(want);
    if (!g5c_json_equal(j, w)) {
        char *a = g5c_json_to_string(j, NULL);
        TK_FAIL("json differs: got %s want %s", a, want);
    }
    g5c_json_free(w);
}

static void copy_hdr(char *dst, size_t cap, const g5c_resp *r, const char *name)
{
    const char *v = g5c_resp_header_get(r, name);
    snprintf(dst, cap, "%s", v ? v : "");
}

/* one request through the router; the optional header pairs are NULL-terminated */
static R rq_h(g5c_router *rt, const char *method, const char *target, const char *ctype, const char *body, const char *const *hdrs)
{
    g5c_req req;
    g5c_resp resp;
    const char *q = strchr(target, '?');
    R out;
    memset(&out, 0, sizeof out);
    g5c_req_init(&req);
    req.method = g5c_xstrdup(method);
    req.path = q ? g5c_xstrndup(target, (size_t)(q - target)) : g5c_xstrdup(target);
    req.query = q ? g5c_xstrdup(q + 1) : NULL;
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("udr.test:80");
    if (ctype != NULL)
        g5c_req_add_header(&req, "content-type", ctype);
    for (size_t i = 0; hdrs != NULL && hdrs[i] != NULL; i += 2)
        g5c_req_add_header(&req, hdrs[i], hdrs[i + 1]);
    if (body != NULL)
        g5c_req_set_body(&req, body, strlen(body));
    g5c_resp_init(&resp);
    g5c_router_dispatch(rt, &req, &resp);
    out.status = resp.status;
    out.json = g5c_resp_parse_json(&resp);
    copy_hdr(out.etag, sizeof out.etag, &resp, "etag");
    copy_hdr(out.last_modified, sizeof out.last_modified, &resp, "last-modified");
    copy_hdr(out.location, sizeof out.location, &resp, "location");
    if (out.json != NULL && g5c_json_get_str(out.json, "cause") != NULL)
        snprintf(out.cause, sizeof out.cause, "%s", g5c_json_get_str(out.json, "cause"));
    g5c_resp_free(&resp);
    g5c_req_free(&req);
    return out;
}

static R rq(g5c_router *rt, const char *method, const char *target, const char *body)
{
    return rq_h(rt, method, target, body ? "application/json" : NULL, body, NULL);
}

static void done(R *r)
{
    g5c_json_free(r->json);
    r->json = NULL;
}

#define SUB "/nudr-dr/v1/subscription-data/"
#define AUTH_BODY "{\"authenticationMethod\":\"5G_AKA\",\"sequenceNumber\":{\"sqn\":\"000000000020\"}}"
#define SNSSAI_SM_BODY                                                                                           \
    "[{\"singleNssai\":{\"sst\":1,\"sd\":\"0000AB\"},\"dnnConfigurations\":{\"internet\":"                       \
    "{\"pduSessionTypes\":{\"defaultSessionType\":\"IPV4\"},\"sscModes\":{\"defaultSscMode\":\"SSC_MODE_1\"}},"  \
    "\"ims\":{\"pduSessionTypes\":{\"defaultSessionType\":\"IPV4\"},\"sscModes\":{\"defaultSscMode\":\"SSC_MODE_1\"}}}},"  \
    "{\"singleNssai\":{\"sst\":2},\"dnnConfigurations\":{\"x\":{\"pduSessionTypes\":{\"defaultSessionType\":\"IPV4\"},"    \
    "\"sscModes\":{\"defaultSscMode\":\"SSC_MODE_1\"}}}}]"

static void test_validation_and_status(void)
{
    g5c_udr_store *st = test_store_new();
    g5c_router *r = g5c_udr_router(st);
    R x;

    x = rq(r, "GET", SUB "imsi-1/authentication-data/authentication-subscription", NULL);
    TK_ASSERT(x.status == 404 && strcmp(x.cause, "USER_NOT_FOUND") == 0);
    done(&x);
    /* a body that breaks the schema is refused with the member that is wrong */
    x = rq(r, "PUT", SUB "imsi-1/authentication-data/authentication-subscription", "{\"sequenceNumber\":{\"sqn\":\"000000000020\"}}");
    TK_ASSERT(x.status == 400 && strcmp(x.cause, "MANDATORY_IE_INCORRECT") == 0);
    TK_ASSERT(strstr(g5c_json_get_str(x.json, "detail"), "authenticationMethod") != NULL);
    done(&x);
    x = rq(r, "PUT", SUB "imsi-1/authentication-data/authentication-subscription",
           "{\"authenticationMethod\":\"5G_AKA\",\"authenticationManagementField\":\"zz\"}");
    TK_ASSERT(x.status == 400 && strstr(g5c_json_get_str(x.json, "detail"), "authenticationManagementField") != NULL);
    done(&x);
    x = rq(r, "PUT", SUB "imsi-1/authentication-data/authentication-subscription", "{\"authenticationMethod\":5}");
    TK_ASSERT(x.status == 400);
    done(&x);
    x = rq(r, "PUT", SUB "imsi-1/authentication-data/authentication-subscription", "{not json");
    TK_ASSERT(x.status == 400);
    done(&x);

    x = rq(r, "PUT", SUB "imsi-1/authentication-data/authentication-subscription", AUTH_BODY);
    TK_ASSERT(x.status == 201 && x.etag[0] == '"' && x.last_modified[0] != '\0');
    done(&x);
    x = rq(r, "PUT", SUB "imsi-1/authentication-data/authentication-subscription", AUTH_BODY);
    TK_ASSERT(x.status == 204);
    done(&x);

    /* methods and paths the API does not have */
    x = rq(r, "POST", SUB "imsi-1/authentication-data/authentication-subscription", "{}");
    TK_ASSERT(x.status == 405 || x.status == 404);
    done(&x);
    x = rq(r, "GET", SUB "imsi-1/no-such-resource", NULL);
    TK_ASSERT(x.status == 404);
    done(&x);
    x = rq(r, "GET", "/nudr-dr/v3/subscription-data/imsi-1/authentication-data/authentication-subscription", NULL);
    TK_ASSERT(x.status == 404);
    done(&x);
    /* a path parameter with a separator in it is refused, not stored */
    x = rq(r, "GET", SUB "imsi-1%2Fx/authentication-data/authentication-subscription", NULL);
    TK_ASSERT(x.status == 400);
    done(&x);

    g5c_router_free(r);
    g5c_udr_store_free(st);
}

static void test_etag_and_patch(void)
{
    g5c_udr_store *st = test_store_new();
    g5c_router *r = g5c_udr_router(st);
    const char *A = SUB "imsi-1/authentication-data/authentication-subscription";
    char etag1[64], etag2[64];
    R x = rq(r, "PUT", A, AUTH_BODY);
    TK_ASSERT(x.status == 201);
    done(&x);

    x = rq(r, "GET", A, NULL);
    TK_ASSERT(x.status == 200);
    snprintf(etag1, sizeof etag1, "%s", x.etag);
    done(&x);
    {   /* a conditional GET with the current entity tag is 304, with another one it is a full answer */
        const char *h1[] = {"if-none-match", etag1, NULL};
        const char *h2[] = {"if-none-match", "\"deadbeef\"", NULL};
        const char *h3[] = {"if-none-match", "*", NULL};
        x = rq_h(r, "GET", A, NULL, NULL, h1);
        TK_ASSERT(x.status == 304 && strcmp(x.etag, etag1) == 0);
        done(&x);
        x = rq_h(r, "GET", A, NULL, NULL, h2);
        TK_ASSERT(x.status == 200);
        done(&x);
        x = rq_h(r, "GET", A, NULL, NULL, h3);
        TK_ASSERT(x.status == 304);
        done(&x);
    }
    {   /* If-Modified-Since: the resource was written now, so a date in the past is a full answer */
        const char *past[] = {"if-modified-since", "Sat, 01 Jan 2000 00:00:00 GMT", NULL};
        const char *future[] = {"if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT", NULL};
        x = rq_h(r, "GET", A, NULL, NULL, past);
        TK_ASSERT(x.status == 200);
        done(&x);
        x = rq_h(r, "GET", A, NULL, NULL, future);
        TK_ASSERT(x.status == 304);
        done(&x);
    }
    {   /* a write with a stale If-Match is refused and changes nothing */
        const char *stale[] = {"if-match", "\"ffff\"", NULL};
        const char *cur[] = {"if-match", etag1, NULL};
        const char *bad[] = {"if-match", "garbage", NULL};
        x = rq_h(r, "PATCH", A, "application/json-patch+json",
                 "[{\"op\":\"replace\",\"path\":\"/sequenceNumber/sqn\",\"value\":\"000000000040\"}]", stale);
        TK_ASSERT(x.status == 412);
        done(&x);
        x = rq_h(r, "PATCH", A, "application/json-patch+json", "[]", bad);
        TK_ASSERT(x.status == 412);
        done(&x);
        x = rq_h(r, "PATCH", A, "application/json-patch+json",
                 "[{\"op\":\"replace\",\"path\":\"/sequenceNumber/sqn\",\"value\":\"000000000040\"}]", cur);
        TK_ASSERT(x.status == 204 && strcmp(x.etag, etag1) != 0);
        snprintf(etag2, sizeof etag2, "%s", x.etag);
        done(&x);
        x = rq_h(r, "PUT", A, "application/json", AUTH_BODY, cur); /* etag1 is stale now */
        TK_ASSERT(x.status == 412);
        done(&x);
    }
    {   /* create-only: If-None-Match: * on an existing resource */
        const char *nm[] = {"if-none-match", "*", NULL};
        x = rq_h(r, "PUT", A, "application/json", AUTH_BODY, nm);
        TK_ASSERT(x.status == 412);
        done(&x);
        x = rq_h(r, "PUT", SUB "imsi-2/authentication-data/authentication-subscription", "application/json", AUTH_BODY, nm);
        TK_ASSERT(x.status == 201);
        done(&x);
    }
    x = rq(r, "GET", A, NULL);
    expect_json(x.json, "{\"authenticationMethod\":\"5G_AKA\",\"sequenceNumber\":{\"sqn\":\"000000000040\"}}");
    done(&x);

    /* a patch that breaks the schema, or does not apply, leaves the document as it was */
    x = rq_h(r, "PATCH", A, "application/json-patch+json", "[{\"op\":\"remove\",\"path\":\"/authenticationMethod\"}]", NULL);
    TK_ASSERT(x.status == 400 && strcmp(x.cause, "MODIFICATION_NOT_ALLOWED") == 0);
    done(&x);
    x = rq_h(r, "PATCH", A, "application/json-patch+json", "[{\"op\":\"replace\",\"path\":\"/nope\",\"value\":1}]", NULL);
    TK_ASSERT(x.status == 400);
    done(&x);
    x = rq_h(r, "PATCH", A, "application/json-patch+json", "{\"op\":\"remove\"}", NULL);
    TK_ASSERT(x.status == 400);
    done(&x);
    x = rq_h(r, "PATCH", A, "text/plain", "[]", NULL);
    TK_ASSERT(x.status == 415);
    done(&x);
    x = rq(r, "GET", A, NULL);
    expect_json(x.json, "{\"authenticationMethod\":\"5G_AKA\",\"sequenceNumber\":{\"sqn\":\"000000000040\"}}");
    done(&x);
    /* merge patch (RFC 7396): null removes, objects merge */
    x = rq_h(r, "PATCH", A, "application/merge-patch+json", "{\"sequenceNumber\":{\"sqn\":\"000000000060\",\"difSign\":\"POSITIVE\"}}", NULL);
    TK_ASSERT(x.status == 204);
    done(&x);
    x = rq(r, "GET", A, NULL);
    expect_json(x.json, "{\"authenticationMethod\":\"5G_AKA\",\"sequenceNumber\":{\"sqn\":\"000000000060\",\"difSign\":\"POSITIVE\"}}");
    done(&x);
    x = rq_h(r, "PATCH", SUB "imsi-9/authentication-data/authentication-subscription", "application/json-patch+json", "[]", NULL);
    TK_ASSERT(x.status == 404);
    done(&x);

    /* DELETE with preconditions */
    {
        const char *stale[] = {"if-match", "\"ffff\"", NULL};
        x = rq_h(r, "DELETE", SUB "imsi-2/authentication-data/authentication-status", NULL, NULL, stale);
        TK_ASSERT(x.status == 404);
        done(&x);
    }
    g5c_router_free(r);
    g5c_udr_store_free(st);
}

static void test_fields_filters_composites(void)
{
    g5c_udr_store *st = test_store_new();
    g5c_router *r = g5c_udr_router(st);
    R x;
    x = rq(r, "PUT", SUB "imsi-1/00101/provisioned-data/sm-data", SNSSAI_SM_BODY);
    TK_ASSERT(x.status == 201 || x.status == 204);
    done(&x);
    x = rq(r, "GET", SUB "imsi-1/00101/provisioned-data/sm-data", NULL);
    TK_ASSERT(x.status == 200 && g5c_json_len(x.json) == 2);
    done(&x);
    x = rq(r, "GET", SUB "imsi-1/00101/provisioned-data/sm-data?single-nssai=%7B%22sst%22%3A1%2C%22sd%22%3A%220000ab%22%7D&dnn=ims", NULL);
    TK_ASSERT(x.status == 200 && g5c_json_len(x.json) == 1);
    TK_ASSERT(g5c_json_len(g5c_json_get(g5c_json_at(x.json, 0), "dnnConfigurations")) == 1);
    TK_ASSERT(g5c_json_get(g5c_json_get(g5c_json_at(x.json, 0), "dnnConfigurations"), "ims") != NULL);
    done(&x);
    x = rq(r, "GET", SUB "imsi-1/00101/provisioned-data/sm-data?single-nssai=%7B%22sst%22%3A9%7D", NULL);
    TK_ASSERT(x.status == 404 && strcmp(x.cause, "DATA_NOT_FOUND") == 0);
    done(&x);
    x = rq(r, "GET", SUB "nobody/00101/provisioned-data/sm-data", NULL);
    TK_ASSERT(x.status == 404 && strcmp(x.cause, "USER_NOT_FOUND") == 0);
    done(&x);

    x = rq(r, "PUT", SUB "imsi-1/00101/provisioned-data/am-data",
           "{\"gpsis\":[\"msisdn-1\"],\"subscribedUeAmbr\":{\"uplink\":\"1 Gbps\",\"downlink\":\"2 Gbps\"},"
           "\"nssai\":{\"defaultSingleNssais\":[{\"sst\":1}]}}");
    TK_ASSERT(x.status == 201);
    done(&x);
    /* ?fields keeps only the pointed members */
    x = rq(r, "GET", SUB "imsi-1/00101/provisioned-data/am-data?fields=/subscribedUeAmbr/uplink,/gpsis", NULL);
    TK_ASSERT(x.status == 200);
    expect_json(x.json, "{\"subscribedUeAmbr\":{\"uplink\":\"1 Gbps\"},\"gpsis\":[\"msisdn-1\"]}");
    done(&x);

    /* the parent resource assembles what is there */
    x = rq(r, "GET", SUB "imsi-1/00101/provisioned-data", NULL);
    TK_ASSERT(x.status == 200 && g5c_json_get(x.json, "amData") != NULL && g5c_json_len(g5c_json_get(x.json, "smData")) == 2);
    TK_ASSERT(g5c_json_get(x.json, "smfSelData") == NULL);
    done(&x);
    x = rq(r, "PUT", SUB "imsi-1/context-data/smf-registrations/1",
           "{\"smfInstanceId\":\"3f1a8c1e-8b8e-4b7e-9c0a-111111111111\",\"pduSessionId\":1,\"singleNssai\":{\"sst\":1},"
           "\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"}}");
    TK_ASSERT(x.status == 201 && strstr(x.location, "/smf-registrations/1") != NULL);
    done(&x);
    x = rq(r, "PUT", SUB "imsi-1/context-data/smf-registrations/2",
           "{\"smfInstanceId\":\"3f1a8c1e-8b8e-4b7e-9c0a-111111111111\",\"pduSessionId\":2,\"singleNssai\":{\"sst\":1},"
           "\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"}}");
    TK_ASSERT(x.status == 201);
    done(&x);
    x = rq(r, "GET", SUB "imsi-1/context-data/smf-registrations", NULL);
    TK_ASSERT(x.status == 200 && g5c_json_len(x.json) == 2);
    done(&x);
    x = rq(r, "GET", SUB "imsi-1/context-data", NULL);
    TK_ASSERT(x.status == 200 && g5c_json_len(g5c_json_get(x.json, "smfRegistrations")) == 2);
    done(&x);
    x = rq(r, "DELETE", SUB "imsi-1/context-data/smf-registrations/1", NULL);
    TK_ASSERT(x.status == 204);
    done(&x);
    x = rq(r, "DELETE", SUB "imsi-1/context-data/smf-registrations/1", NULL);
    TK_ASSERT(x.status == 404);
    done(&x);
    x = rq(r, "PUT", SUB "imsi-1/context-data/smf-registrations/3", "{\"pduSessionId\":3}"); /* required members missing */
    TK_ASSERT(x.status == 400);
    done(&x);
    x = rq(r, "PUT", SUB "imsi-1/context-data/amf-3gpp-access",
           "{\"amfInstanceId\":\"a\",\"deregCallbackUri\":\"http://amf/dereg\",\"guami\":{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},"
           "\"amfId\":\"010203\"},\"ratType\":\"NR\"}");
    TK_ASSERT(x.status == 201);
    done(&x);
    x = rq(r, "GET", SUB "imsi-1/context-data", NULL);
    TK_ASSERT(g5c_json_get(x.json, "amf3Gpp") != NULL && g5c_json_get(x.json, "amfNon3Gpp") == NULL);
    done(&x);
    x = rq(r, "DELETE", SUB "imsi-1/context-data/amf-3gpp-access", NULL);
    TK_ASSERT(x.status == 204);
    done(&x);
    g5c_router_free(r);
    g5c_udr_store_free(st);
}

static void test_aliases_and_policy(void)
{
    g5c_udr_store *st = test_store_new();
    g5c_router *r = g5c_udr_router(st);
    R x;
    x = rq(r, "PUT", SUB "imsi-1/00101/provisioned-data/am-data", "{\"gpsis\":[\"msisdn-123\"]}");
    TK_ASSERT(x.status == 201);
    done(&x);
    /* before the identity data names the GPSI, it is nobody */
    x = rq(r, "GET", SUB "msisdn-123/00101/provisioned-data/am-data", NULL);
    TK_ASSERT(x.status == 404);
    done(&x);
    x = rq(r, "PUT", SUB "imsi-1/identity-data", "{\"supiList\":[\"imsi-1\"],\"gpsiList\":[\"msisdn-123\",\"msisdn-124\"]}");
    TK_ASSERT(x.status == 201);
    done(&x);
    x = rq(r, "GET", SUB "msisdn-123/00101/provisioned-data/am-data", NULL);
    TK_ASSERT(x.status == 200 && g5c_json_get(x.json, "gpsis") != NULL);
    done(&x);
    x = rq(r, "PUT", SUB "imsi-1/identity-data", "{\"supiList\":[\"imsi-1\"],\"gpsiList\":[\"msisdn-124\"]}"); /* 123 dropped */
    TK_ASSERT(x.status == 204);
    done(&x);
    x = rq(r, "GET", SUB "msisdn-123/00101/provisioned-data/am-data", NULL);
    TK_ASSERT(x.status == 404);
    done(&x);
    x = rq(r, "GET", SUB "msisdn-124/00101/provisioned-data/am-data", NULL);
    TK_ASSERT(x.status == 200);
    done(&x);
    x = rq(r, "DELETE", SUB "imsi-1", NULL); /* removing the subscriber removes its aliases */
    TK_ASSERT(x.status == 204);
    done(&x);
    x = rq(r, "GET", SUB "msisdn-124/00101/provisioned-data/am-data", NULL);
    TK_ASSERT(x.status == 404);
    done(&x);

    /* the PCF's per-subscriber policy: operator-specific policy data (TS 29.519) */
    x = rq(r, "PUT", "/nudr-dr/v1/policy-data/ues/imsi-5/operator-specific-data", "{\"g5c-policy\":{\"dataType\":\"object\",\"value\":{\"a\":1}}}");
    TK_ASSERT(x.status == 201 || x.status == 204);
    done(&x);
    x = rq(r, "GET", "/nudr-dr/v1/policy-data/ues/imsi-5/operator-specific-data", NULL);
    TK_ASSERT(x.status == 200);
    expect_json(x.json, "{\"g5c-policy\":{\"dataType\":\"object\",\"value\":{\"a\":1}}}");
    done(&x);
    x = rq(r, "PUT", "/nudr-dr/v1/policy-data/ues/imsi-5/operator-specific-data", "{\"k\":{\"dataType\":\"bogus\",\"value\":1}}");
    TK_ASSERT(x.status == 400);
    done(&x);
    x = rq(r, "DELETE", "/nudr-dr/v1/policy-data/ues/imsi-5/operator-specific-data", NULL);
    TK_ASSERT(x.status == 204);
    done(&x);
    g5c_router_free(r);
    g5c_udr_store_free(st);
}

static void test_provisioning_access(void)
{
    g5c_udr_store *st = test_store_new();
    udr_opts o;
    g5c_router *r;
    R x;
    const char *good[] = {"authorization", "Bearer 0123456789abcdef-token", NULL};
    const char *bad[] = {"authorization", "Bearer wrong-token-wrong-token", NULL};
    memset(&o, 0, sizeof o);
    o.provisioning_token = "0123456789abcdef-token";
    r = g5c_udr_router_opts(st, &o);

    /* a spec operation needs no token; an extension (creating provisioned data) does */
    x = rq(r, "PUT", SUB "imsi-1/00101/provisioned-data/am-data", "{\"gpsis\":[\"msisdn-1\"]}");
    TK_ASSERT(x.status == 401);
    done(&x);
    x = rq_h(r, "PUT", SUB "imsi-1/00101/provisioned-data/am-data", "application/json", "{\"gpsis\":[\"msisdn-1\"]}", bad);
    TK_ASSERT(x.status == 403);
    done(&x);
    x = rq_h(r, "PUT", SUB "imsi-1/00101/provisioned-data/am-data", "application/json", "{\"gpsis\":[\"msisdn-1\"]}", good);
    TK_ASSERT(x.status == 201);
    done(&x);
    x = rq(r, "GET", SUB "imsi-1/00101/provisioned-data/am-data", NULL);
    TK_ASSERT(x.status == 200);
    done(&x);
    x = rq(r, "PUT", SUB "imsi-1/context-data/amf-3gpp-access", "{}");
    TK_ASSERT(x.status == 400); /* spec operation: validated, no token needed */
    done(&x);
    x = rq(r, "GET", SUB, NULL);
    TK_ASSERT(x.status == 401 || x.status == 404);
    done(&x);
    x = rq(r, "GET", "/nudr-dr/v1/subscription-data", NULL);
    TK_ASSERT(x.status == 401);
    done(&x);
    x = rq_h(r, "GET", "/nudr-dr/v1/subscription-data", NULL, NULL, good);
    TK_ASSERT(x.status == 200);
    expect_json(x.json, "[\"imsi-1\"]");
    done(&x);
    x = rq(r, "DELETE", SUB "imsi-1", NULL);
    TK_ASSERT(x.status == 401);
    done(&x);
    g5c_router_free(r);
    g5c_udr_store_free(st);

    /* no token configured and not open: provisioning is off */
    st = test_store_new();
    memset(&o, 0, sizeof o);
    r = g5c_udr_router_opts(st, &o);
    x = rq(r, "PUT", SUB "imsi-1/00101/provisioned-data/am-data", "{}");
    TK_ASSERT(x.status == 403 && strcmp(x.cause, "PROVISIONING_DISABLED") == 0);
    done(&x);
    g5c_router_free(r);
    g5c_udr_store_free(st);

    /* validation can be switched off */
    st = test_store_new();
    memset(&o, 0, sizeof o);
    o.ext_open = true;
    o.no_validation = true;
    r = g5c_udr_router_opts(st, &o);
    x = rq(r, "PUT", SUB "imsi-1/authentication-data/authentication-subscription", "{\"anything\":1}");
    TK_ASSERT(x.status == 201);
    done(&x);
    g5c_router_free(r);
    g5c_udr_store_free(st);
}

int main(void)
{
    g5c_log_init("error", false);
    test_validation_and_status();
    test_etag_and_patch();
    test_fields_filters_composites();
    test_aliases_and_policy();
    test_provisioning_access();
    puts("udr api: ok");
    return 0;
}
