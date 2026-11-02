/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The BSF in process: configuration, register / discover / update / deregister (TS 29.521) by IPv4 address, IPv6 prefix (longest prefix match) and MAC address, framed
 * routes, overlapping addresses, the SamePcf check, feature negotiation, the replacement and clean-up rules, the state file, and many bindings from many threads. */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "g5c/bsf.h"
#include "g5c/testkit.h"

typedef struct {
    int status;
    g5c_json *json;
    char location[256], cause[64], accept_patch[64];
} R;

static R rq(g5c_router *rt, const char *method, const char *target, const char *body, const char *ctype)
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
    req.authority = g5c_xstrdup("bsf.test:80");
    if (body != NULL) {
        g5c_req_add_header(&req, "content-type", ctype != NULL ? ctype : "application/json");
        g5c_req_set_body(&req, body, strlen(body));
    }
    g5c_resp_init(&resp);
    g5c_router_dispatch(rt, &req, &resp);
    out.status = resp.status;
    out.json = g5c_resp_parse_json(&resp);
    snprintf(out.location, sizeof out.location, "%s", g5c_resp_header_get(&resp, "location") ? g5c_resp_header_get(&resp, "location") : "");
    snprintf(out.accept_patch, sizeof out.accept_patch, "%s", g5c_resp_header_get(&resp, "accept-patch") ? g5c_resp_header_get(&resp, "accept-patch") : "");
    if (out.json != NULL && g5c_json_get_str(out.json, "cause") != NULL)
        snprintf(out.cause, sizeof out.cause, "%s", g5c_json_get_str(out.json, "cause"));
    g5c_resp_free(&resp);
    g5c_req_free(&req);
    return out;
}

static void done(R *r)
{
    g5c_json_free(r->json);
    r->json = NULL;
}

#define BASE "/nbsf-management/v1/pcfBindings"
#define PCF "\"pcfFqdn\":\"pcf.example.org\",\"pcfIpEndPoints\":[{\"ipv4Address\":\"127.0.0.13\",\"transport\":\"TCP\",\"port\":7777}]"
#define SN1 "{\"sst\":1,\"sd\":\"000001\"}"

static bsf *make(const char *yaml, g5c_router **rt)
{
    char err[200];
    g5c_json *root = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    bsf_cfg *c;
    bsf *b;
    if (root == NULL)
        TK_FAIL("yaml: %s", err);
    c = bsf_cfg_parse(root, err, sizeof err);
    if (c == NULL)
        TK_FAIL("config: %s", err);
    g5c_json_free(root);
    b = bsf_new(c, NULL);
    TK_ASSERT(b != NULL);
    *rt = bsf_router(b);
    return b;
}

static void bye(bsf *b, g5c_router *rt)
{
    g5c_router_free(rt);
    bsf_destroy(b);
}

/* the features a registration offers (without ExtendedSamePcf an address is required) */
static const char *g_feat = "1f";

/* a registration body: extra members are inserted as given */
static char *reg(const char *supi, const char *addr_members, const char *extra)
{
    return g5c_xasprintf("{\"supi\":\"%s\",\"dnn\":\"internet\",\"snssai\":" SN1 ",%s,\"suppFeat\":\"%s\"%s%s}", supi, addr_members, g_feat, extra ? "," : "", extra ? extra : "");
}

static char *post(g5c_router *rt, const char *supi, const char *addr, const char *extra, int want)
{
    char *body = reg(supi, addr, extra), *id = NULL;
    R r = rq(rt, "POST", BASE, body, NULL);
    free(body);
    if (r.status != want)
        TK_FAIL("register %s: %d, want %d (%s)", addr, r.status, want, r.cause);
    if (want == 201) {
        const char *slash = strrchr(r.location, '/');
        TK_ASSERT(slash != NULL && strncmp(r.location, "http://bsf.test:80" BASE "/", sizeof "http://bsf.test:80" BASE) == 0);
        id = g5c_xstrdup(slash + 1);
    }
    done(&r);
    return id;
}

static R get(g5c_router *rt, const char *query)
{
    char *t = g5c_xasprintf(BASE "?%s", query);
    R r = rq(rt, "GET", t, NULL, NULL);
    free(t);
    return r;
}

#define EXPECT_GET(rt, query, want)                                                                                                                  \
    do {                                                                                                                                             \
        R r_ = get(rt, query);                                                                                                                       \
        if (r_.status != (want))                                                                                                                     \
            TK_FAIL("GET ?%s: %d, want %d (%s)", query, r_.status, (want), r_.cause);                                                                \
        done(&r_);                                                                                                                                   \
    } while (0)

static void test_config(void)
{
    static const struct {
        const char *yaml, *want;
    } bad[] = {
        {"bsf: 5\n", "bsf"},
        {"bsf: { surprise: 1 }\n", "bsf"},
        {"bsf: { max_bindings: 0 }\n", "max_bindings"},
        {"bsf: { features: [ Nope ] }\n", "features"},
        {"bsf: { features: [ ExtendedSamePcf ] }\n", "requires SamePcf"},
        {"bsf: { purge_on_recovery: 3 }\n", "purge_on_recovery"},
        {"bsf: { state_file: '' }\n", "state_file"},
        {"bsf: { info: { dnn_list: [] } }\n", "dnn_list"},
        {"bsf: { info: { ipv4_address_ranges: [ { start: 10.0.0.9, end: 10.0.0.1 } ] } }\n", "ipv4_address_ranges"},
        {"bsf: { info: { ipv6_prefix_ranges: [ { start: nope, end: nope } ] } }\n", "ipv6_prefix_ranges"},
        {"bsf: { info: {} }\n", "empty"},
    };
    char err[200];
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        g5c_json *root = g5c_yaml_parse(bad[i].yaml, strlen(bad[i].yaml), err, sizeof err);
        bsf_cfg *c;
        TK_ASSERT(root != NULL);
        c = bsf_cfg_parse(root, err, sizeof err);
        if (c != NULL || strstr(err, bad[i].want) == NULL)
            TK_FAIL("config %zu: want an error with [%s], got [%s]", i, bad[i].want, err);
        g5c_json_free(root);
    }
    {
        g5c_json *root = g5c_yaml_parse("name: x\n", 8, err, sizeof err);
        bsf_cfg *c = bsf_cfg_parse(root, err, sizeof err);
        TK_ASSERT(c != NULL);
        bsf_cfg_free(c);
        g5c_json_free(root);
    }
    {
        g5c_router *rt;
        bsf *b = make("bsf: { info: { dnn_list: [ internet ], ip_domain_list: [ d1 ], ipv4_address_ranges: [ { start: 10.45.0.0, end: 10.45.255.255 } ], ipv6_prefix_ranges: [ { start: '2001:db8::/48', end: '2001:db8:ffff::/48' } ] } }\n", &rt);
        const g5c_json *info = bsf_nrf_info(b);
        TK_ASSERT(info != NULL && g5c_json_get(info, "dnnList") != NULL && g5c_json_len(g5c_json_get(info, "ipv4AddressRanges")) == 1 &&
                  g5c_json_get(info, "ipv6PrefixRanges") != NULL && g5c_json_get(info, "ipDomainList") != NULL);
        bye(b, rt);
    }
}

static void test_ipv4(void)
{
    g5c_router *rt;
    bsf *b = make("bsf: {}\n", &rt);
    char *id = post(rt, "imsi-001010000000001", "\"ipv4Addr\":\"10.45.0.2\"," PCF, NULL, 201);
    R r;
    /* the answer of the registration is the binding with the features that were negotiated, and the discovery gives it back */
    {
        char *body = reg("imsi-001010000000009", "\"ipv4Addr\":\"10.45.0.9\"," PCF, NULL);
        r = rq(rt, "POST", BASE, body, NULL);
        free(body);
        TK_ASSERT(r.status == 201 && strcmp(g5c_json_get_str(r.json, "ipv4Addr"), "10.45.0.9") == 0 && strcmp(g5c_json_get_str(r.json, "suppFeat"), "17") == 0);
        done(&r);
    }
    r = get(rt, "ipv4Addr=10.45.0.2");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "pcfFqdn"), "pcf.example.org") == 0 && g5c_json_get(r.json, "pcfIpEndPoints") != NULL &&
              strcmp(g5c_json_get_str(r.json, "supi"), "imsi-001010000000001") == 0 && g5c_json_get(r.json, "suppFeat") == NULL);
    done(&r);
    r = get(rt, "ipv4Addr=10.45.0.2&supp-feat=3");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "suppFeat"), "3") == 0);
    done(&r);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2&dnn=internet&supi=imsi-001010000000001&snssai=%7B%22sst%22%3A1%2C%22sd%22%3A%22000001%22%7D", 200);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2&snssai=%7B%22sst%22%3A2%7D", 204);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2&dnn=ims", 204);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2&supi=imsi-001010000000002", 204);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2&gpsi=msisdn-1", 204);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2&ipDomain=d1", 204);
    EXPECT_GET(rt, "ipv4Addr=10.45.7.7", 204);
    /* what a consumer gets wrong */
    r = get(rt, "dnn=internet");
    TK_ASSERT(r.status == 400 && strcmp(r.cause, "MANDATORY_QUERY_PARAM_MISSING") == 0 && g5c_json_get(r.json, "invalidParams") != NULL);
    done(&r);
    r = get(rt, "ipv4Addr=10.45.0.2&macAddr48=00-11-22-33-44-55");
    TK_ASSERT(r.status == 400 && strcmp(r.cause, "MANDATORY_QUERY_PARAM_INCORRECT") == 0);
    done(&r);
    r = get(rt, "ipv4Addr=10.45.0");
    TK_ASSERT(r.status == 400 && strcmp(r.cause, "MANDATORY_QUERY_PARAM_INCORRECT") == 0);
    done(&r);
    r = get(rt, "ipv4Addr=10.45.0.2&colour=red");
    TK_ASSERT(r.status == 400 && strcmp(r.cause, "INVALID_QUERY_PARAM") == 0);
    done(&r);
    r = get(rt, "ipv4Addr=10.45.0.2&snssai=notjson");
    TK_ASSERT(r.status == 400 && strcmp(r.cause, "OPTIONAL_QUERY_PARAM_INCORRECT") == 0);
    done(&r);
    r = get(rt, "ipv4Addr=10.45.0.2&supp-feat=xyz");
    TK_ASSERT(r.status == 400 && strcmp(r.cause, "OPTIONAL_QUERY_PARAM_INCORRECT") == 0);
    done(&r);
    /* deregister */
    {
        char *path = g5c_xasprintf(BASE "/%s", id);
        r = rq(rt, "DELETE", path, NULL, NULL);
        TK_ASSERT(r.status == 204);
        done(&r);
        r = rq(rt, "DELETE", path, NULL, NULL);
        TK_ASSERT(r.status == 404);
        done(&r);
        free(path);
    }
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2", 204);
    r = rq(rt, "DELETE", BASE "/no-such-binding", NULL, NULL);
    TK_ASSERT(r.status == 404);
    done(&r);
    free(id);
    bye(b, rt);
}

static void test_ipv6_mac_framed(void)
{
    g5c_router *rt;
    bsf *b = make("bsf: {}\n", &rt);
    R r;
    char *a = post(rt, "imsi-001010000000001", "\"ipv6Prefix\":\"2001:db8:1:2::/64\"," PCF, NULL, 201);
    char *wide = post(rt, "imsi-001010000000002", "\"ipv6Prefix\":\"2001:db8:1::/48\"," PCF, NULL, 201);
    char *host = post(rt, "imsi-001010000000003", "\"ipv6Prefix\":\"2001:db8:1:2::77/128\"," PCF, NULL, 201);
    char *mac = post(rt, "imsi-001010000000004", "\"macAddr48\":\"00-11-22-33-44-55\"," PCF, NULL, 201);
    char *fr = post(rt, "imsi-001010000000005", "\"ipv4Addr\":\"10.46.0.5\"," PCF, "\"ipv4FrameRouteList\":[\"192.168.50.0/24\"],\"ipv6FrameRouteList\":[\"2001:db8:f::/48\"]", 201);
    char *shortp = post(rt, "imsi-001010000000006", "\"ipv6Prefix\":\"2001:db9::/32\"," PCF, NULL, 201);
    /* the longest prefix wins: the /128 over the /64 over the /48 */
    r = get(rt, "ipv6Prefix=2001%3Adb8%3A1%3A2%3A%3A77%2F128");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "supi"), "imsi-001010000000003") == 0);
    done(&r);
    r = get(rt, "ipv6Prefix=2001%3Adb8%3A1%3A2%3A%3A8a2e%2F128");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "supi"), "imsi-001010000000001") == 0);
    done(&r);
    r = get(rt, "ipv6Prefix=2001%3Adb8%3A1%3A9%3A%3A1%2F128");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "supi"), "imsi-001010000000002") == 0);
    done(&r);
    r = get(rt, "ipv6Prefix=2001%3Adb9%3A5%3A%3A1%2F128"); /* a prefix shorter than /64 */
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "supi"), "imsi-001010000000006") == 0);
    done(&r);
    r = get(rt, "ipv6Prefix=2001%3Adb8%3A1%3A2%3A%3A8a2e"); /* no length: a /128 */
    TK_ASSERT(r.status == 200);
    done(&r);
    EXPECT_GET(rt, "ipv6Prefix=2001%3Adb8%3A7%3A%3A1%2F128", 204);
    EXPECT_GET(rt, "ipv6Prefix=nope%2F128", 400);
    /* the MAC address */
    r = get(rt, "macAddr48=00-11-22-33-44-55");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "supi"), "imsi-001010000000004") == 0);
    done(&r);
    EXPECT_GET(rt, "macAddr48=00-11-22-33-44-56", 204);
    EXPECT_GET(rt, "macAddr48=0011.2233.4455", 400);
    /* framed routes: the binding is found for an address in its route, the address itself is better */
    r = get(rt, "ipv4Addr=192.168.50.9");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "supi"), "imsi-001010000000005") == 0);
    done(&r);
    r = get(rt, "ipv6Prefix=2001%3Adb8%3Af%3A1%3A%3A2%2F128");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "supi"), "imsi-001010000000005") == 0);
    done(&r);
    EXPECT_GET(rt, "ipv4Addr=192.168.51.9", 204);
    free(post(rt, "imsi-001010000000007", "\"ipv4Addr\":\"192.168.50.9\"," PCF, NULL, 201));
    r = get(rt, "ipv4Addr=192.168.50.9");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "supi"), "imsi-001010000000007") == 0);
    done(&r);
    free(a);
    free(wide);
    free(host);
    free(mac);
    free(fr);
    free(shortp);
    bye(b, rt);
}

static void test_overlap(void)
{
    g5c_router *rt;
    bsf *b = make("bsf: {}\n", &rt);
    R r;
    char *one = post(rt, "imsi-001010000000001", "\"ipv4Addr\":\"10.45.0.2\"," PCF, NULL, 201);
    char *body = g5c_xasprintf("{\"supi\":\"imsi-001010000000002\",\"dnn\":\"internet\",\"snssai\":{\"sst\":2},\"ipv4Addr\":\"10.45.0.2\",\"ipDomain\":\"d2\"," PCF "}");
    R r2 = rq(rt, "POST", BASE, body, NULL);
    free(body);
    TK_ASSERT(r2.status == 201);
    done(&r2);
    /* the same address twice: the consumer has to say which (TS 29.521 4.2.4.2) */
    r = get(rt, "ipv4Addr=10.45.0.2");
    TK_ASSERT(r.status == 400 && strcmp(r.cause, "MULTIPLE_BINDING_INFO_FOUND") == 0);
    done(&r);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2&snssai=%7B%22sst%22%3A2%7D", 200);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2&ipDomain=d2", 200);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2&snssai=%7B%22sst%22%3A1%2C%22sd%22%3A%22000001%22%7D", 200);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2&snssai=%7B%22sst%22%3A3%7D", 204);
    free(one);
    bye(b, rt);
}

static void test_update(void)
{
    g5c_router *rt;
    bsf *b = make("bsf: {}\n", &rt);
    R r;
    char *id, *path, *nofeat, *nopath;
    g_feat = "7"; /* MultiUeAddr, BindingUpdate and SamePcf: an address is required */
    id = post(rt, "imsi-001010000000001", "\"ipv4Addr\":\"10.45.0.2\"," PCF, NULL, 201);
    path = g5c_xasprintf(BASE "/%s", id);
    g_feat = "1f";
    nofeat = post(rt, "imsi-001010000000002", "\"ipv4Addr\":\"10.45.0.3\"," PCF, NULL, 201);
    nopath = g5c_xasprintf(BASE "/%s", nofeat);
    /* the address changes: the old one is gone, the new one is found; other members stay */
    r = rq(rt, "PATCH", path, "{\"ipv4Addr\":\"10.45.0.44\",\"ipv6Prefix\":\"2001:db8:44::/64\"}", "application/merge-patch+json");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "ipv4Addr"), "10.45.0.44") == 0 && strcmp(g5c_json_get_str(r.json, "dnn"), "internet") == 0 &&
              strcmp(g5c_json_get_str(r.json, "supi"), "imsi-001010000000001") == 0);
    done(&r);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2", 204);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.44", 200);
    EXPECT_GET(rt, "ipv6Prefix=2001%3Adb8%3A44%3A%3A5%2F128", 200);
    /* null removes a member, but not the last address */
    r = rq(rt, "PATCH", path, "{\"ipv4Addr\":null}", "application/merge-patch+json");
    TK_ASSERT(r.status == 200 && g5c_json_get(r.json, "ipv4Addr") == NULL);
    done(&r);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.44", 204);
    r = rq(rt, "PATCH", path, "{\"ipv6Prefix\":null}", "application/merge-patch+json");
    TK_ASSERT(r.status == 400 && strcmp(r.cause, "MANDATORY_IE_MISSING") == 0);
    done(&r);
    r = rq(rt, "PATCH", path, "{\"pcfFqdn\":\"pcf2.example.org\",\"pcfId\":\"5b8c1e5e-9a38-4f6a-9a38-0123456789ab\"}", "application/merge-patch+json");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "pcfFqdn"), "pcf2.example.org") == 0);
    done(&r);
    /* what cannot be modified, a wrong document, a wrong media type, an unknown binding, a binding without the feature */
    r = rq(rt, "PATCH", path, "{\"dnn\":\"ims\"}", "application/merge-patch+json");
    TK_ASSERT(r.status == 403 && strcmp(r.cause, "MODIFICATION_NOT_ALLOWED") == 0);
    done(&r);
    r = rq(rt, "PATCH", path, "{\"ipv4Addr\":\"10.45.0.300\"}", "application/merge-patch+json");
    TK_ASSERT(r.status == 400);
    done(&r);
    r = rq(rt, "PATCH", path, "{\"ipv4Addr\":\"10.45.0.5\"}", "text/plain");
    TK_ASSERT(r.status == 415 && strcmp(r.accept_patch, "application/merge-patch+json") == 0);
    done(&r);
    r = rq(rt, "PATCH", BASE "/no-such-binding", "{\"ipv4Addr\":\"10.45.0.5\"}", "application/merge-patch+json");
    TK_ASSERT(r.status == 404);
    done(&r);
    {
        char *body = g5c_xasprintf("{\"supi\":\"imsi-001010000000003\",\"dnn\":\"internet\",\"snssai\":" SN1 ",\"ipv4Addr\":\"10.45.0.30\"," PCF ",\"suppFeat\":\"5\"}");
        r = rq(rt, "POST", BASE, body, NULL); /* BindingUpdate is not among the features this consumer offered */
        free(body);
        TK_ASSERT(r.status == 201 && strcmp(g5c_json_get_str(r.json, "suppFeat"), "5") == 0);
        {
            char *p2 = g5c_xasprintf(BASE "/%s", strrchr(r.location, '/') + 1);
            R u;
            done(&r);
            u = rq(rt, "PATCH", p2, "{\"ipv4Addr\":\"10.45.0.31\"}", "application/merge-patch+json");
            TK_ASSERT(u.status == 501);
            done(&u);
            free(p2);
        }
    }
    free(id);
    free(path);
    free(nofeat);
    free(nopath);
    bye(b, rt);
}

static void test_registration_rules(void)
{
    g5c_router *rt;
    bsf *b = make("bsf: { max_bindings: 3 }\n", &rt);
    R r;
    static const struct {
        const char *body, *cause;
    } bad[] = {
        {"{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv4Addr\":\"10.0.0.1\"," PCF "}", NULL}, /* a good one, used as the control below */
        {"{\"snssai\":{\"sst\":1},\"ipv4Addr\":\"10.0.0.1\"," PCF "}", "MANDATORY_IE_INCORRECT"},
        {"{\"dnn\":\"internet\",\"ipv4Addr\":\"10.0.0.1\"," PCF "}", "MANDATORY_IE_INCORRECT"},
        {"{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv4Addr\":\"10.0.0.256\"," PCF "}", "MANDATORY_IE_INCORRECT"},
        {"{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv6Prefix\":\"2001:db8::/129\"," PCF "}", "MANDATORY_IE_INCORRECT"},
        {"{\"dnn\":\"internet\",\"snssai\":{\"sst\":1}," PCF "}", "MANDATORY_IE_MISSING"},                                                /* no UE address */
        {"{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv4Addr\":\"10.0.0.1\"}", "MANDATORY_IE_MISSING"},                              /* no PCF address */
        {"{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv4Addr\":\"10.0.0.1\",\"pcfDiamHost\":\"host1.example.org\"}", "MANDATORY_IE_MISSING"},      /* a Diameter host without a realm */
        {"{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv6Prefix\":\"2001:db8::/64\",\"ipDomain\":\"d\"," PCF "}", "OPTIONAL_IE_INCORRECT"}, /* a domain needs IPv4 */
        {"{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv4Addr\":\"10.0.0.1\",\"addIpv6Prefixes\":[\"2001:db8::/64\"]," PCF "}", "OPTIONAL_IE_INCORRECT"}, /* MultiUeAddr is not negotiated */
        {"{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv4Addr\":\"10.0.0.1\",\"paraCom\":{\"dnn\":\"internet\"}," PCF "}", "OPTIONAL_IE_INCORRECT"},        /* SamePcf is not negotiated */
        {"{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv4Addr\":\"10.0.0.1\",\"recoveryTime\":\"yesterday\"," PCF "}", "MANDATORY_IE_INCORRECT"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        r = rq(rt, "POST", BASE, bad[i].body, NULL);
        if (bad[i].cause == NULL ? r.status != 201 : (r.status != 400 || strcmp(r.cause, bad[i].cause) != 0))
            TK_FAIL("registration %zu: %d %s, want %s", i, r.status, r.cause, bad[i].cause ? bad[i].cause : "201");
        done(&r);
    }
    r = rq(rt, "POST", BASE, "{not json", NULL);
    TK_ASSERT(r.status == 400);
    done(&r);
    /* the limit */
    free(post(rt, "imsi-001010000000002", "\"ipv4Addr\":\"10.0.0.2\"," PCF, NULL, 201));
    free(post(rt, "imsi-001010000000003", "\"ipv4Addr\":\"10.0.0.3\"," PCF, NULL, 201));
    r = rq(rt, "POST", BASE, "{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv4Addr\":\"10.0.0.4\"," PCF "}", NULL);
    TK_ASSERT(r.status == 503 && strcmp(r.cause, "NF_CONGESTION") == 0);
    done(&r);
    TK_ASSERT(bsf_binding_count(b) == 3);
    bye(b, rt);
    /* ExtendedSamePcf: the addresses are optional */
    b = make("bsf: {}\n", &rt);
    free(post(rt, "imsi-001010000000001", "\"gpsi\":\"msisdn-1\"", NULL, 201)); /* 1f offers ExtendedSamePcf: no address is needed */
    r = rq(rt, "POST", BASE, "{\"supi\":\"imsi-001010000000001\",\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"suppFeat\":\"10\"}", NULL);
    TK_ASSERT(r.status == 400); /* ExtendedSamePcf alone is not negotiated: it needs SamePcf (TS 29.521 5.8) */
    done(&r);
    r = rq(rt, "POST", BASE, "{\"supi\":\"imsi-001010000000001\",\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"suppFeat\":\"14\"}", NULL);
    TK_ASSERT(r.status == 201 && strcmp(g5c_json_get_str(r.json, "suppFeat"), "14") == 0);
    done(&r);
    bye(b, rt);
    /* a BSF that offers fewer features */
    b = make("bsf: { features: [ BindingUpdate ] }\n", &rt);
    r = rq(rt, "POST", BASE, "{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv4Addr\":\"10.0.0.1\"," PCF ",\"suppFeat\":\"1f\"}", NULL);
    TK_ASSERT(r.status == 201 && strcmp(g5c_json_get_str(r.json, "suppFeat"), "2") == 0);
    done(&r);
    bye(b, rt);
}

static void test_same_pcf(void)
{
    g5c_router *rt;
    bsf *b = make("bsf: {}\n", &rt);
    R r;
    static const char SM[] = "\"pcfSmFqdn\":\"pcf-sm.example.org\",\"pcfSmIpEndPoints\":[{\"ipv4Address\":\"127.0.0.14\",\"transport\":\"TCP\",\"port\":7777}]";
    char *first, *body;
    body = g5c_xasprintf("{\"supi\":\"imsi-001010000000001\",\"dnn\":\"internet\",\"snssai\":" SN1 ",\"ipv4Addr\":\"10.45.0.2\"," PCF ",%s,\"paraCom\":{\"supi\":\"imsi-001010000000001\",\"dnn\":\"internet\",\"snssai\":" SN1 "},\"suppFeat\":\"4\"}", SM);
    r = rq(rt, "POST", BASE, body, NULL);
    TK_ASSERT(r.status == 201 && strcmp(g5c_json_get_str(r.json, "suppFeat"), "4") == 0);
    first = g5c_xstrdup(strrchr(r.location, '/') + 1);
    done(&r);
    /* the same UE, DNN and slice from another PCF: refused, with where the first PCF is (TS 29.521 4.2.2.2) */
    free(body);
    body = g5c_xasprintf("{\"supi\":\"imsi-001010000000001\",\"dnn\":\"internet\",\"snssai\":" SN1 ",\"ipv4Addr\":\"10.45.0.3\"," PCF ",\"pcfSmFqdn\":\"other.example.org\",\"paraCom\":{\"supi\":\"imsi-001010000000001\",\"dnn\":\"internet\",\"snssai\":" SN1 "},\"suppFeat\":\"4\"}");
    r = rq(rt, "POST", BASE, body, NULL);
    TK_ASSERT(r.status == 403 && strcmp(r.cause, "EXISTING_BINDING_INFO_FOUND") == 0 && strcmp(g5c_json_get_str(r.json, "pcfSmFqdn"), "pcf-sm.example.org") == 0 &&
              g5c_json_get(r.json, "pcfSmIpEndPoints") != NULL);
    done(&r);
    free(body);
    /* a partial combination matches as well; another SUPI, another DNN or another slice does not */
    body = g5c_xasprintf("{\"dnn\":\"internet\",\"snssai\":" SN1 ",\"ipv4Addr\":\"10.45.0.4\"," PCF ",%s,\"paraCom\":{\"dnn\":\"internet\"},\"suppFeat\":\"4\"}", SM);
    r = rq(rt, "POST", BASE, body, NULL);
    TK_ASSERT(r.status == 403);
    done(&r);
    free(body);
    body = g5c_xasprintf("{\"dnn\":\"internet\",\"snssai\":" SN1 ",\"ipv4Addr\":\"10.45.0.5\"," PCF ",%s,\"paraCom\":{\"supi\":\"imsi-001010000000002\",\"dnn\":\"internet\"},\"suppFeat\":\"4\"}", SM);
    r = rq(rt, "POST", BASE, body, NULL);
    TK_ASSERT(r.status == 201);
    done(&r);
    free(body);
    body = g5c_xasprintf("{\"dnn\":\"ims\",\"snssai\":" SN1 ",\"ipv4Addr\":\"10.45.0.6\"," PCF ",%s,\"paraCom\":{\"supi\":\"imsi-001010000000001\",\"dnn\":\"ims\"},\"suppFeat\":\"4\"}", SM);
    r = rq(rt, "POST", BASE, body, NULL);
    TK_ASSERT(r.status == 201);
    done(&r);
    free(body);
    /* an empty combination is not one */
    body = g5c_xasprintf("{\"dnn\":\"internet\",\"snssai\":" SN1 ",\"ipv4Addr\":\"10.45.0.7\"," PCF ",\"paraCom\":{},\"suppFeat\":\"4\"}");
    r = rq(rt, "POST", BASE, body, NULL);
    TK_ASSERT(r.status == 400);
    done(&r);
    free(body);
    /* once the first binding is gone, the combination is free */
    {
        char *path = g5c_xasprintf(BASE "/%s", first);
        r = rq(rt, "DELETE", path, NULL, NULL);
        TK_ASSERT(r.status == 204);
        done(&r);
        free(path);
    }
    body = g5c_xasprintf("{\"supi\":\"imsi-001010000000001\",\"dnn\":\"internet\",\"snssai\":" SN1 ",\"ipv4Addr\":\"10.45.0.8\"," PCF ",%s,\"paraCom\":{\"supi\":\"imsi-001010000000001\",\"dnn\":\"internet\",\"snssai\":" SN1 "},\"suppFeat\":\"4\"}", SM);
    r = rq(rt, "POST", BASE, body, NULL);
    TK_ASSERT(r.status == 201);
    done(&r);
    free(body);
    free(first);
    bye(b, rt);
}

static void test_replace_and_purge(void)
{
    g5c_router *rt;
    bsf *b = make("bsf: {}\n", &rt);
    R r;
    static const char PCFA[] = "\"pcfId\":\"11111111-1111-4111-8111-111111111111\",\"recoveryTime\":\"2030-01-01T00:00:00Z\"";
    static const char PCFB[] = "\"pcfId\":\"22222222-2222-4222-8222-222222222222\",\"recoveryTime\":\"2030-01-01T00:00:00Z\"";
    char *first = post(rt, "imsi-001010000000001", "\"ipv4Addr\":\"10.45.0.2\"," PCF, PCFA, 201), *path = g5c_xasprintf(BASE "/%s", first);
    /* the same PCF registers the same UE again (it lost its state): the earlier binding is replaced, not kept as a second one */
    char *second = post(rt, "imsi-001010000000001", "\"ipv4Addr\":\"10.45.0.2\"," PCF, PCFA, 201);
    TK_ASSERT(bsf_binding_count(b) == 1);
    r = rq(rt, "DELETE", path, NULL, NULL);
    TK_ASSERT(r.status == 404);
    done(&r);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2", 200);
    /* another PCF registers the same address, DNN and slice: the earlier binding is stale and goes (the UE address is unique there) */
    free(post(rt, "imsi-001010000000009", "\"ipv4Addr\":\"10.45.0.2\"," PCF, PCFB, 201));
    TK_ASSERT(bsf_binding_count(b) == 1);
    r = get(rt, "ipv4Addr=10.45.0.2");
    TK_ASSERT(r.status == 200 && strcmp(g5c_json_get_str(r.json, "supi"), "imsi-001010000000009") == 0);
    done(&r);
    /* a PCF that comes back with a newer recovery time: what it registered before is stale */
    free(post(rt, "imsi-001010000000003", "\"ipv4Addr\":\"10.45.0.3\"," PCF, PCFA, 201));
    free(post(rt, "imsi-001010000000004", "\"ipv4Addr\":\"10.45.0.4\"," PCF, PCFA, 201));
    TK_ASSERT(bsf_binding_count(b) == 3);
    free(post(rt, "imsi-001010000000005", "\"ipv4Addr\":\"10.45.0.5\"," PCF, "\"pcfId\":\"11111111-1111-4111-8111-111111111111\",\"recoveryTime\":\"2031-01-01T00:00:00Z\"", 201));
    TK_ASSERT(bsf_binding_count(b) == 2); /* the other PCF's binding and the new one */
    EXPECT_GET(rt, "ipv4Addr=10.45.0.3", 204);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.5", 200);
    /* an older recovery time purges nothing */
    free(post(rt, "imsi-001010000000006", "\"ipv4Addr\":\"10.45.0.6\"," PCF, "\"pcfId\":\"11111111-1111-4111-8111-111111111111\",\"recoveryTime\":\"2030-06-01T00:00:00Z\"", 201));
    TK_ASSERT(bsf_binding_count(b) == 3);
    free(first);
    free(second);
    free(path);
    bye(b, rt);
    /* both rules can be turned off */
    b = make("bsf: { purge_on_recovery: false, replace_stale: false }\n", &rt);
    free(post(rt, "imsi-001010000000001", "\"ipv4Addr\":\"10.45.0.2\"," PCF, PCFA, 201));
    free(post(rt, "imsi-001010000000001", "\"ipv4Addr\":\"10.45.0.2\"," PCF, PCFA, 201));
    TK_ASSERT(bsf_binding_count(b) == 2);
    r = get(rt, "ipv4Addr=10.45.0.2");
    TK_ASSERT(r.status == 400 && strcmp(r.cause, "MULTIPLE_BINDING_INFO_FOUND") == 0);
    done(&r);
    bye(b, rt);
}

static void test_state(void)
{
    char path[64], yaml[200], err[200];
    g5c_router *rt;
    bsf *b;
    snprintf(path, sizeof path, "/tmp/bsf-state-%d.json", (int)getpid());
    (void)remove(path);
    snprintf(yaml, sizeof yaml, "bsf: { state_file: %s }\n", path);
    b = make(yaml, &rt);
    TK_ASSERT(bsf_start(b, err, sizeof err) == 0);
    free(post(rt, "imsi-001010000000001", "\"ipv4Addr\":\"10.45.0.2\"," PCF, NULL, 201));
    free(post(rt, "imsi-001010000000002", "\"ipv6Prefix\":\"2001:db8::/64\"," PCF, "\"addMacAddrs\":[\"00-11-22-33-44-55\"],\"ipv4FrameRouteList\":[\"192.168.50.0/24\"]", 201));
    bye(b, rt); /* writes the file */
    b = make(yaml, &rt);
    TK_ASSERT(bsf_start(b, err, sizeof err) == 0 && bsf_binding_count(b) == 2);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2", 200);
    EXPECT_GET(rt, "ipv6Prefix=2001%3Adb8%3A%3A5%2F128", 200);
    EXPECT_GET(rt, "macAddr48=00-11-22-33-44-55", 200);
    EXPECT_GET(rt, "ipv4Addr=192.168.50.4", 200);
    bye(b, rt);
    /* a file that is not JSON is refused, a binding that is not valid is dropped */
    {
        FILE *f = fopen(path, "wb");
        fputs("{\"bindings\":[{\"id\":\"00000000-0000-4000-8000-000000000001\",\"binding\":{\"dnn\":\"x\"}},{\"id\":\"short\"}]}", f);
        fclose(f);
        b = make(yaml, &rt);
        TK_ASSERT(bsf_start(b, err, sizeof err) == 0 && bsf_binding_count(b) == 0);
        bye(b, rt);
        f = fopen(path, "wb");
        fputs("not json", f);
        fclose(f);
        b = make(yaml, &rt);
        TK_ASSERT(bsf_start(b, err, sizeof err) != 0);
        bye(b, rt);
    }
    (void)remove(path);
}

/* many bindings from several threads at once, found afterwards */
#define THREADS 8
#define PER_THREAD 2500
typedef struct {
    g5c_router *rt;
    int t, failures;
} work_t;

static void *worker(void *arg)
{
    work_t *w = arg;
    for (int i = 0; i < PER_THREAD; i++) {
        int n = w->t * PER_THREAD + i;
        char supi[40], addr[120];
        char *body;
        R r;
        snprintf(supi, sizeof supi, "imsi-0010100%08d", n);
        snprintf(addr, sizeof addr, "\"ipv4Addr\":\"10.%d.%d.%d\"", 64 + n / 65536, (n / 256) % 256, n % 256);
        body = reg(supi, addr, NULL);
        {
            char *with_pcf = g5c_xasprintf("%.*s," PCF "}", (int)strlen(body) - 1, body);
            r = rq(w->rt, "POST", BASE, with_pcf, NULL);
            free(with_pcf);
        }
        free(body);
        if (r.status != 201)
            w->failures++;
        done(&r);
    }
    return NULL;
}

static void test_many(void)
{
    g5c_router *rt;
    bsf *b = make("bsf: {}\n", &rt);
    pthread_t th[THREADS];
    work_t w[THREADS];
    int bad = 0;
    for (int t = 0; t < THREADS; t++) {
        w[t].rt = rt;
        w[t].t = t;
        w[t].failures = 0;
        pthread_create(&th[t], NULL, worker, &w[t]);
    }
    for (int t = 0; t < THREADS; t++) {
        pthread_join(th[t], NULL);
        bad += w[t].failures;
    }
    TK_ASSERT(bad == 0 && bsf_binding_count(b) == (size_t)THREADS * PER_THREAD);
    for (int n = 0; n < THREADS * PER_THREAD; n += 997) {
        char q[64];
        R r;
        snprintf(q, sizeof q, "ipv4Addr=10.%d.%d.%d", 64 + n / 65536, (n / 256) % 256, n % 256);
        r = get(rt, q);
        TK_ASSERT(r.status == 200);
        done(&r);
    }
    bye(b, rt);
}

static void test_metrics(void)
{
    g5c_registry *reg_ = g5c_registry_new();
    g5c_router *rt;
    char err[100];
    g5c_json *root = g5c_yaml_parse("bsf: {}\n", 8, err, sizeof err);
    bsf_cfg *c = bsf_cfg_parse(root, err, sizeof err);
    bsf *b = bsf_new(c, reg_);
    char *text;
    R r;
    g5c_json_free(root);
    rt = bsf_router(b);
    free(post(rt, "imsi-001010000000001", "\"ipv4Addr\":\"10.45.0.2\"," PCF, NULL, 201));
    EXPECT_GET(rt, "ipv4Addr=10.45.0.2", 200);
    EXPECT_GET(rt, "ipv4Addr=10.45.0.3", 204);
    r = get(rt, "dnn=x");
    done(&r);
    text = g5c_registry_render(reg_);
    TK_ASSERT(strstr(text, "g5c_bsf_requests_total{operation=\"register\",result=\"ok\"} 1") != NULL &&
              strstr(text, "g5c_bsf_requests_total{operation=\"discovery\",result=\"ok\"} 1") != NULL &&
              strstr(text, "g5c_bsf_requests_total{operation=\"discovery\",result=\"no_match\"} 1") != NULL &&
              strstr(text, "g5c_bsf_requests_total{operation=\"discovery\",result=\"rejected\"} 1") != NULL && strstr(text, "g5c_bsf_bindings 1") != NULL);
    free(text);
    g5c_router_free(rt);
    bsf_destroy(b);
    g5c_registry_free(reg_);
}

int main(void)
{
    g5c_log_init("error", false);
    test_config();
    test_ipv4();
    test_ipv6_mac_framed();
    test_overlap();
    test_update();
    test_registration_rules();
    test_same_pcf();
    test_replace_and_purge();
    test_state();
    test_many();
    test_metrics();
    puts("bsf: ok");
    return 0;
}
