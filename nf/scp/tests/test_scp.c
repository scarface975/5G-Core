/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The SCP end to end, in process, over real HTTP/2 connections */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "g5c/testkit.h"
#include "priv.h"

/* ---- scripted producers and NRF ---- */

typedef struct {
    pthread_mutex_t mu;
    char name[16], id[40];
    int calls, status, first_status, first_n;
    _Atomic int delay_ms; /* set while a slow request is still in flight */
    g5c_json *last;
    g5c_router *r;
    g5c_server *srv;
    char root[64];
} prod_t;

static void prod_handler(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    prod_t *p = ctx;
    g5c_json *rec = g5c_json_new_obj(), *h = g5c_json_set(rec, "headers", g5c_json_new_obj());
    g5c_json *body = g5c_json_new_obj();
    int st;
    g5c_json_set_str(rec, "method", req->method);
    g5c_json_set_str(rec, "path", req->path);
    g5c_json_set_str(rec, "query", req->query != NULL ? req->query : "");
    g5c_json_set_str(rec, "authority", req->authority != NULL ? req->authority : "");
    g5c_json_set_str(rec, "body", req->body_len > 0 ? (const char *)req->body : "");
    for (size_t i = 0; i < req->nheaders; i++)
        g5c_json_set_str(h, req->headers[i].name, req->headers[i].value);
    pthread_mutex_lock(&p->mu);
    p->calls++;
    g5c_json_free(p->last);
    p->last = rec;
    st = (p->first_n > 0 && p->calls <= p->first_n) ? p->first_status : p->status;
    pthread_mutex_unlock(&p->mu);
    if (p->delay_ms > 0)
        usleep((useconds_t)p->delay_ms * 1000);
    g5c_json_set_str(body, "producer", p->name);
    g5c_resp_json(resp, st, body);
    g5c_json_free(body);
    g5c_resp_header(resp, "x-from", p->name);
    if (st == 429)
        g5c_resp_header(resp, "retry-after", "2");
    if (g5c_req_header(req, "if-match") != NULL)
        g5c_resp_header(resp, "x-echo", g5c_req_header(req, "if-match"));
    if (st == 201) {
        char loc[128];
        snprintf(loc, sizeof loc, "http://%s/res/1", req->authority != NULL ? req->authority : "?");
        g5c_resp_header(resp, "location", loc);
    }
}

static void prod_start(prod_t *p, const char *name)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[160];
    memset(p, 0, sizeof *p);
    pthread_mutex_init(&p->mu, NULL);
    snprintf(p->name, sizeof p->name, "%s", name);
    snprintf(p->id, sizeof p->id, "00000000-0000-4000-8000-0000000000%02x", (unsigned)strlen(name) + (unsigned)name[strlen(name) - 1]);
    p->status = 200;
    p->r = g5c_router_new();
    g5c_router_set_fallback(p->r, prod_handler, p);
    p->srv = g5c_server_start(&cfg, p->r, err, sizeof err);
    TK_ASSERT(p->srv != NULL);
    snprintf(p->root, sizeof p->root, "http://127.0.0.1:%u", g5c_server_port(p->srv));
}

static void prod_stop(prod_t *p)
{
    g5c_server_stop(p->srv);
    p->srv = NULL;
    g5c_router_free(p->r);
    g5c_json_free(p->last);
    p->last = NULL;
}

static int prod_calls(prod_t *p)
{
    int n;
    pthread_mutex_lock(&p->mu);
    n = p->calls;
    pthread_mutex_unlock(&p->mu);
    return n;
}

static const g5c_json *prod_header(prod_t *p, const char *name)
{
    return g5c_json_get(g5c_json_get(p->last, "headers"), name);
}

typedef struct {
    pthread_mutex_t mu;
    int calls;
    char query[512];
    char *instances; /* the nfInstances array (JSON text) the NRF answers with */
    int status;
    g5c_router *r;
    g5c_server *srv;
    char root[64];
} nrf_t;

static void nrf_handler(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf_t *n = ctx;
    char *text;
    pthread_mutex_lock(&n->mu);
    n->calls++;
    snprintf(n->query, sizeof n->query, "%s", req->query != NULL ? req->query : "");
    text = g5c_xasprintf("{\"validityPeriod\":60,\"nfInstances\":%s}", n->instances != NULL ? n->instances : "[]");
    pthread_mutex_unlock(&n->mu);
    if (n->status != 200) {
        g5c_resp_problem_simple(resp, n->status, "SYSTEM_FAILURE", NULL);
    } else {
        g5c_resp_content(resp, 200, "application/json", text, strlen(text));
    }
    free(text);
}

static void nrf_start(nrf_t *n)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[160];
    memset(n, 0, sizeof *n);
    pthread_mutex_init(&n->mu, NULL);
    n->status = 200;
    n->r = g5c_router_new();
    g5c_router_route(n->r, "GET", "/nnrf-disc/v1/nf-instances", nrf_handler, n);
    n->srv = g5c_server_start(&cfg, n->r, err, sizeof err);
    TK_ASSERT(n->srv != NULL);
    snprintf(n->root, sizeof n->root, "http://127.0.0.1:%u", g5c_server_port(n->srv));
}

static void nrf_set(nrf_t *n, const char *instances_json)
{
    pthread_mutex_lock(&n->mu);
    free(n->instances);
    n->instances = g5c_xstrdup(instances_json);
    pthread_mutex_unlock(&n->mu);
}

static void nrf_stop(nrf_t *n)
{
    g5c_server_stop(n->srv);
    g5c_router_free(n->r);
    free(n->instances);
}

/* a profile for the NRF's answer: an UDM at `root` with the given priority, capacity and load */
static char *profile(const prod_t *p, int priority, int capacity, int load)
{
    return g5c_xasprintf(
        "{\"nfInstanceId\":\"%s\",\"nfType\":\"UDM\",\"nfStatus\":\"REGISTERED\",\"priority\":%d,\"capacity\":%d,\"load\":%d,\"nfServices\":[{\"serviceInstanceId\":\"1\","
        "\"serviceName\":\"nudm-sdm\",\"versions\":[{\"apiVersionInUri\":\"v2\",\"apiFullVersion\":\"2.0.0\"}],\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\","
        "\"ipEndPoints\":[{\"ipv4Address\":\"127.0.0.1\",\"port\":%s}]}]}",
        p->id, priority, capacity, load, strrchr(p->root, ':') + 1);
}

/* ---- the SCP ---- */

typedef struct {
    scp *s;
    g5c_client *up;
    g5c_router *r;
    g5c_server *srv;
    char base[64];
} scp_env;

static void scp_env_start(scp_env *e, const char *name, const char *nrf, const char *yaml)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[200];
    g5c_json *root = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    scp_cfg *c;
    TK_ASSERT(root != NULL);
    c = scp_cfg_parse(root, name, nrf, err, sizeof err);
    if (c == NULL)
        TK_FAIL("scp config: %s", err);
    g5c_json_free(root);
    e->up = g5c_client_new((int)c->timeout_ms, NULL);
    e->s = scp_new(c, e->up, NULL);
    e->r = scp_router(e->s);
    e->srv = g5c_server_start(&cfg, e->r, err, sizeof err);
    TK_ASSERT(e->srv != NULL);
    snprintf(e->base, sizeof e->base, "http://127.0.0.1:%u", g5c_server_port(e->srv));
}

static void scp_env_stop(scp_env *e)
{
    g5c_server_stop(e->srv);
    g5c_router_free(e->r);
    scp_destroy(e->s);
    g5c_client_free(e->up);
}

typedef struct {
    int status;
    g5c_resp r;
    g5c_json *json;
} reply_t;

/* one request to `url` with the given headers (name, value pairs, NULL ended) */
static reply_t call(g5c_client *c, const char *method, const char *url, const char *const *hdrs, const char *body)
{
    g5c_kv kv[16];
    size_t n = 0;
    reply_t x;
    char err[160];
    memset(&x, 0, sizeof x);
    for (size_t i = 0; hdrs != NULL && hdrs[i] != NULL && n < 16; i += 2, n++) {
        kv[n].name = hdrs[i];
        kv[n].value = hdrs[i + 1];
    }
    TK_ASSERT(g5c_client_request(c, method, url, kv, n, "application/json", body, body != NULL ? strlen(body) : 0, &x.r, err, sizeof err) == 0);
    x.status = x.r.status;
    x.json = g5c_resp_parse_json(&x.r);
    return x;
}

static void reply_free(reply_t *x)
{
    g5c_json_free(x->json);
    g5c_resp_free(&x->r);
}

static const char *rh(const reply_t *x, const char *name)
{
    return g5c_resp_header_get(&x->r, name);
}

static const char *cause_of(const reply_t *x)
{
    return g5c_json_get_str(x->json, "cause") != NULL ? g5c_json_get_str(x->json, "cause") : "";
}

#define EXPECT(x, code)                                                                                                                              \
    do {                                                                                                                                             \
        if ((x).status != (code))                                                                                                                    \
            fprintf(stderr, "expected %d, got %d %s\n", (code), (x).status, (x).json ? g5c_json_to_string((x).json, NULL) : "-");                       \
        TK_ASSERT((x).status == (code));                                                                                                             \
    } while (0)

static const char *BASIC = "scp: {}\n";

/* ---- tests ---- */

static void test_config(void)
{
    static const struct {
        const char *yaml, *want;
    } bad[] = {
        {"scp: { surprise: 1 }\n", "scp"},
        {"scp: { prefix: 'x' }\n", "prefix"},
        {"scp: { prefix: '/x/' }\n", "prefix"},
        {"scp: { next: { uri: 'ftp://x' } }\n", "next.uri"},
        {"scp: { next: { uri: 'http://x', delegate_discovery: 3 } }\n", "delegate_discovery"},
        {"scp: { discovery: { delegated: 2 } }\n", "delegated"},
        {"scp: { discovery: { cache_ttl_s: -1 } }\n", "cache_ttl_s"},
        {"scp: { routing: { attempts: 0 } }\n", "attempts"},
        {"scp: { routing: { timeout_ms: 1 } }\n", "timeout_ms"},
        {"scp: { routing: { workers: 9999 } }\n", "workers"},
        {"scp: { routing: { quarantine: { failures: 0 } } }\n", "failures"},
        {"scp: { routing: { retry_on_503: maybe } }\n", "retry_on_503"},
        {"scp: { targets: { allow: [ 'a b' ] } }\n", "allow[0]"},
        {"scp: { targets: { allow: x } }\n", "allow"},
        {"scp: { routing: { extra: 1 } }\n", "scp.routing"},
    };
    char err[256];
    scp_cfg *c;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        g5c_json *root = g5c_yaml_parse(bad[i].yaml, strlen(bad[i].yaml), err, sizeof err);
        TK_ASSERT(root != NULL);
        c = scp_cfg_parse(root, "scp1", NULL, err, sizeof err);
        if (c != NULL || strstr(err, bad[i].want) == NULL)
            TK_FAIL("config case %zu: wanted an error naming %s, got: %s", i, bad[i].want, c ? "accepted" : err);
        g5c_json_free(root);
    }
    {
        g5c_json *root = g5c_yaml_parse("other: 1\n", 9, err, sizeof err);
        c = scp_cfg_parse(root, "scp1", NULL, err, sizeof err);
        TK_ASSERT(c != NULL && c->attempts == 3 && c->prefix[0] == '\0' && c->delegated);
        scp_cfg_free(c);
        g5c_json_free(root);
    }
    TK_ASSERT(apiroot_ok("http://a:1") && apiroot_ok("https://a/b/c") && !apiroot_ok("http://a?x") && !apiroot_ok("http://u@a") && !apiroot_ok("ftp://a") && !apiroot_ok("http:///x"));
    {
        scp_cfg k;
        char *allow[] = {"10.0.0.0/8", "*.5gc.test", "udm.test", "127.0.0.1:7777"};
        memset(&k, 0, sizeof k);
        k.allow = allow;
        k.nallow = 4;
        TK_ASSERT(target_allowed(&k, "http://10.1.2.3:80") && !target_allowed(&k, "http://11.1.2.3") && target_allowed(&k, "https://x.5gc.test") && !target_allowed(&k, "https://5gc.test") &&
                  target_allowed(&k, "http://UDM.test/p") && !target_allowed(&k, "http://other.test") && target_allowed(&k, "http://127.0.0.1:7777") && !target_allowed(&k, "http://127.0.0.1:7778"));
        k.nallow = 0;
        TK_ASSERT(target_allowed(&k, "http://anything"));
    }
}

static void test_model_c(void)
{
    prod_t p;
    scp_env e;
    g5c_client *cl = g5c_client_new(3000, NULL);
    reply_t x;
    char url[200], root_hdr[100];
    prod_start(&p, "p1");
    scp_env_start(&e, "scp1.test", NULL, BASIC);
    snprintf(root_hdr, sizeof root_hdr, "%s", p.root);

    /* a GET: the producer sees the path and the query without the cache key and no SCP headers; the consumer's headers and the producer's answer go through */
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/imsi-001010000000001/am-data?plmn-id=%%7B%%7D&ck=abc", e.base);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", root_hdr, "user-agent", "AMF-1234", "authorization", "Bearer tok", "if-match", "\"7\"", "3gpp-sbi-discovery-target-nf-type", "UDM",
                           "3gpp-sbi-nrf-uri", "nnrf-disc: \"http://x/nnrf-disc/v1/\"", "3gpp-sbi-message-priority", "5", NULL};
        x = call(cl, "GET", url, h, NULL);
    }
    EXPECT(x, 200);
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "producer"), "p1") == 0 && strcmp(rh(&x, "x-from"), "p1") == 0 && strcmp(rh(&x, "x-echo"), "\"7\"") == 0);
    TK_ASSERT(rh(&x, "3gpp-sbi-producer-id") == NULL && rh(&x, "via") == NULL); /* the consumer selected the producer: nothing to tell it, no error to attribute */
    TK_ASSERT(strcmp(g5c_json_get_str(p.last, "path"), "/nudm-sdm/v2/imsi-001010000000001/am-data") == 0 && strcmp(g5c_json_get_str(p.last, "query"), "plmn-id=%7B%7D") == 0);
    TK_ASSERT(prod_header(&p, "3gpp-sbi-target-apiroot") == NULL && prod_header(&p, "3gpp-sbi-discovery-target-nf-type") == NULL && prod_header(&p, "3gpp-sbi-nrf-uri") == NULL);
    TK_ASSERT(strcmp(g5c_json_str(prod_header(&p, "user-agent")), "AMF-1234") == 0 && strcmp(g5c_json_str(prod_header(&p, "authorization")), "Bearer tok") == 0 &&
              strcmp(g5c_json_str(prod_header(&p, "3gpp-sbi-message-priority")), "5") == 0);
    TK_ASSERT(strstr(g5c_json_str(prod_header(&p, "via")), "2.0 SCP-scp1.test") != NULL);
    TK_ASSERT(strncmp(g5c_json_get_str(p.last, "authority"), "127.0.0.1:", 10) == 0); /* the producer is addressed as itself */
    reply_free(&x);

    /* a POST with a body that creates a resource: the Location is the producer's */
    snprintf(url, sizeof url, "%s/nsmf-pdusession/v1/sm-contexts", e.base);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", root_hdr, NULL};
        p.status = 201;
        x = call(cl, "POST", url, h, "{\"a\":1}");
        p.status = 200;
    }
    EXPECT(x, 201);
    TK_ASSERT(rh(&x, "location") != NULL && strstr(rh(&x, "location"), p.root + 7) != NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(p.last, "body"), "{\"a\":1}") == 0);
    reply_free(&x);

    /* a notification (3gpp-Sbi-Callback) is forwarded the same way */
    snprintf(url, sizeof url, "%s/callbacks/sdm/1", e.base);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", root_hdr, "3gpp-sbi-callback", "Nudm_SDM_Notification; apiversion=2", NULL};
        x = call(cl, "POST", url, h, "{}");
    }
    EXPECT(x, 200);
    TK_ASSERT(strcmp(g5c_json_str(prod_header(&p, "3gpp-sbi-callback")), "Nudm_SDM_Notification; apiversion=2") == 0);
    reply_free(&x);

    /* an error of the producer is relayed with a Via header, its own Server header (when it has one) stays */
    p.status = 404;
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", e.base);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", root_hdr, NULL};
        x = call(cl, "GET", url, h, NULL);
    }
    EXPECT(x, 404);
    TK_ASSERT(rh(&x, "via") != NULL && strcmp(rh(&x, "via"), "SCP-scp1.test") == 0 && strcmp(rh(&x, "x-from"), "p1") == 0);
    reply_free(&x);
    p.status = 200;

    /* what the SCP refuses itself */
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", e.base);
    x = call(cl, "GET", url, NULL, NULL);
    EXPECT(x, 400);
    TK_ASSERT(strcmp(cause_of(&x), "MANDATORY_IE_MISSING") == 0 && strcmp(rh(&x, "server"), "SCP-scp1.test") == 0 && g5c_json_get(x.json, "invalidParams") != NULL);
    reply_free(&x);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", "ftp://nowhere", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 400);
        TK_ASSERT(strcmp(cause_of(&x), "MANDATORY_IE_INCORRECT") == 0);
        reply_free(&x);
    }
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", root_hdr, "via", "1.1 other, 2.0 SCP-scp1.test", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 508);
        reply_free(&x);
    }
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", root_hdr, "3gpp-sbi-sender-timestamp", "Tue, 04 Feb 2020 08:49:37.123 GMT", "3gpp-sbi-max-rsp-time", "500", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 504);
        TK_ASSERT(strcmp(cause_of(&x), "TIMED_OUT_REQUEST") == 0);
        reply_free(&x);
    }
    snprintf(url, sizeof url, "%s/scp-default-sub-notify-uri", e.base);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", root_hdr, NULL};
        x = call(cl, "POST", url, h, "{}");
        EXPECT(x, 404);
        reply_free(&x);
    }
    /* the producer is unreachable and the request says nothing about alternatives */
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", e.base);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", "http://127.0.0.1:1", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 504);
        TK_ASSERT(strcmp(cause_of(&x), "TARGET_NF_NOT_REACHABLE") == 0 && strcmp(rh(&x, "server"), "SCP-scp1.test") == 0);
        reply_free(&x);
    }
    scp_env_stop(&e);
    prod_stop(&p);
    g5c_client_free(cl);
}

static void test_limits_and_targets(void)
{
    prod_t p;
    scp_env e;
    g5c_client *cl = g5c_client_new(3000, NULL);
    reply_t x;
    char url[200], root_hdr[100], big[3000];
    prod_start(&p, "p1");
    snprintf(root_hdr, sizeof root_hdr, "%s", p.root);
    scp_env_start(&e, "scp1.test", NULL, "scp:\n  prefix: /scp/1\n  routing: { max_body: 1024 }\n  targets: { allow: [ 127.0.0.0/8 ] }\n");
    /* the SCP's own prefix comes off the path */
    snprintf(url, sizeof url, "%s/scp/1/nudm-sdm/v2/x/am-data", e.base);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", root_hdr, NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 200);
        TK_ASSERT(strcmp(g5c_json_get_str(p.last, "path"), "/nudm-sdm/v2/x/am-data") == 0);
        reply_free(&x);
        snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", e.base);
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 404);
        reply_free(&x);
    }
    /* a target outside the allowed ones */
    snprintf(url, sizeof url, "%s/scp/1/x", e.base);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", "http://192.0.2.1:80", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 403);
        TK_ASSERT(strcmp(cause_of(&x), "TARGET_NOT_ALLOWED") == 0);
        reply_free(&x);
    }
    /* a body that is too large */
    memset(big, 'x', sizeof big - 1);
    big[sizeof big - 1] = '\0';
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", root_hdr, NULL};
        x = call(cl, "POST", url, h, big);
        EXPECT(x, 413);
        reply_free(&x);
    }
    scp_env_stop(&e);
    prod_stop(&p);
    g5c_client_free(cl);
}

static void test_model_d(void)
{
    prod_t p1, p2;
    nrf_t nrf;
    scp_env e;
    g5c_client *cl = g5c_client_new(3000, NULL);
    reply_t x;
    char url[200], *i1, *i2, *both;
    prod_start(&p1, "p1");
    prod_start(&p2, "p2");
    nrf_start(&nrf);
    scp_env_start(&e, "scp1.test", nrf.root, BASIC);
    i1 = profile(&p1, 1, 100, 0);
    both = g5c_xasprintf("[%s]", i1);
    nrf_set(&nrf, both);
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/imsi-001010000000001/nssai", e.base);

    /* the discovery factors become the query to the NRF; the requester's type comes from the User-Agent; the producer is named in the answer */
    {
        const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-sdm", "3gpp-sbi-discovery-snssais", "[{\"sst\":1,\"sd\":\"000001\"}]",
                           "user-agent", "AMF-abc", NULL};
        x = call(cl, "GET", url, h, NULL);
    }
    EXPECT(x, 200);
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "producer"), "p1") == 0);
    TK_ASSERT(rh(&x, "3gpp-sbi-producer-id") != NULL && strcmp(rh(&x, "3gpp-sbi-producer-id") + 7, p1.id) == 0);
    TK_ASSERT(strstr(nrf.query, "target-nf-type=UDM") != NULL && strstr(nrf.query, "service-names=nudm-sdm") != NULL && strstr(nrf.query, "requester-nf-type=AMF") != NULL &&
              strstr(nrf.query, "snssais=%5B%7B%22sst%22%3A1,%22sd%22%3A%22000001%22%7D%5D") != NULL);
    TK_ASSERT(prod_header(&p1, "3gpp-sbi-discovery-target-nf-type") == NULL && strcmp(g5c_json_str(prod_header(&p1, "user-agent")), "AMF-abc") == 0);
    TK_ASSERT(nrf.calls == 1 && scp_cached_discoveries(e.s) == 1);
    reply_free(&x);
    /* the same factors again: the answer of the NRF is cached */
    {
        const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-sdm", "3gpp-sbi-discovery-snssais", "[{\"sst\":1,\"sd\":\"000001\"}]",
                           "user-agent", "AMF-abc", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 200);
        TK_ASSERT(nrf.calls == 1);
        reply_free(&x);
    }
    /* what the request lacks */
    {
        const char *h[] = {"3gpp-sbi-discovery-service-names", "nudm-sdm", "user-agent", "AMF-abc", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 400);
        TK_ASSERT(strcmp(cause_of(&x), "MANDATORY_IE_MISSING") == 0);
        reply_free(&x);
        const char *h2[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", NULL};
        x = call(cl, "GET", url, h2, NULL); /* no requester type: neither the header nor the User-Agent */
        EXPECT(x, 400);
        reply_free(&x);
        const char *h3[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-bad_name", "x", "user-agent", "AMF-1", NULL};
        x = call(cl, "GET", url, h3, NULL);
        EXPECT(x, 400);
        TK_ASSERT(strcmp(cause_of(&x), "INVALID_DISCOVERY_PARAM") == 0);
        reply_free(&x);
    }
    /* nobody matches */
    nrf_set(&nrf, "[]");
    {
        const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-uecm", "user-agent", "AMF-abc", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 400);
        TK_ASSERT(strcmp(cause_of(&x), "NF_DISCOVERY_FAILURE") == 0 && strcmp(rh(&x, "server"), "SCP-scp1.test") == 0);
        reply_free(&x);
    }
    /* the NRF is down */
    nrf.status = 500;
    {
        const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-ueau", "user-agent", "AMF-abc", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 504);
        reply_free(&x);
    }
    nrf.status = 200;

    /* priority: the producer with the lower priority number is the one while it is healthy; with the same priority capacity and load weigh */
    i2 = profile(&p2, 2, 100, 0);
    free(both);
    both = g5c_xasprintf("[%s,%s]", i1, i2);
    nrf_set(&nrf, both);
    for (int i = 0; i < 20; i++) {
        const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-sdm", "3gpp-sbi-discovery-dnn", "prio", "user-agent", "AMF-abc", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 200);
        TK_ASSERT(strcmp(g5c_json_get_str(x.json, "producer"), "p1") == 0);
        reply_free(&x);
    }
    free(i1);
    free(i2);
    i1 = profile(&p1, 1, 100, 0);
    i2 = profile(&p2, 1, 300, 0);
    free(both);
    both = g5c_xasprintf("[%s,%s]", i1, i2);
    nrf_set(&nrf, both);
    {
        int c1 = 0, c2 = 0;
        for (int i = 0; i < 400; i++) {
            const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-sdm", "3gpp-sbi-discovery-dnn", "weights", "user-agent", "AMF-abc", NULL};
            x = call(cl, "GET", url, h, NULL);
            EXPECT(x, 200);
            if (strcmp(g5c_json_get_str(x.json, "producer"), "p1") == 0)
                c1++;
            else
                c2++;
            reply_free(&x);
        }
        TK_ASSERT(c1 > 50 && c1 < 160 && c2 > 240); /* about 1 : 3 */
    }
    /* a producer under load gets less */
    free(i1);
    free(i2);
    i1 = profile(&p1, 1, 100, 90);
    i2 = profile(&p2, 1, 100, 10);
    free(both);
    both = g5c_xasprintf("[%s,%s]", i1, i2);
    nrf_set(&nrf, both);
    {
        int c1 = 0;
        for (int i = 0; i < 300; i++) {
            const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-sdm", "3gpp-sbi-discovery-dnn", "load", "user-agent", "AMF-abc", NULL};
            x = call(cl, "GET", url, h, NULL);
            EXPECT(x, 200);
            c1 += strcmp(g5c_json_get_str(x.json, "producer"), "p1") == 0;
            reply_free(&x);
        }
        TK_ASSERT(c1 < 60);
    }
    free(i1);
    free(i2);
    free(both);

    /* a request for the NRF itself (a function that delegates its registration) goes to the NRF of the SCP */
    {
        const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "NRF", "3gpp-sbi-discovery-service-names", "nnrf-disc", "user-agent", "UDM-1", NULL};
        snprintf(url, sizeof url, "%s/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF", e.base);
        nrf.calls = 0;
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 200);
        TK_ASSERT(nrf.calls == 1);
        reply_free(&x);
    }
    scp_env_stop(&e);
    nrf_stop(&nrf);
    prod_stop(&p1);
    prod_stop(&p2);
    g5c_client_free(cl);
}

static void test_retries_and_health(void)
{
    prod_t p1, p2;
    nrf_t nrf;
    scp_env e;
    g5c_client *cl = g5c_client_new(5000, NULL);
    reply_t x;
    char url[200], *i1, *i2, *both, root1[100];
    prod_start(&p1, "p1");
    prod_start(&p2, "p2");
    nrf_start(&nrf);
    scp_env_start(&e, "scp1.test", nrf.root, "scp:\n  routing: { attempts: 3, timeout_ms: 400, quarantine: { failures: 2, seconds: 1 } }\n");
    i1 = profile(&p1, 1, 100, 0);
    i2 = profile(&p2, 2, 100, 0);
    both = g5c_xasprintf("[%s,%s]", i1, i2);
    nrf_set(&nrf, both);
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/nssai", e.base);
    snprintf(root1, sizeof root1, "%s", p1.root);

    /* the better producer answers 503: the next one is tried */
    p1.first_status = 503;
    p1.first_n = 1;
    {
        const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-sdm", "user-agent", "AMF-abc", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 200);
        TK_ASSERT(strcmp(g5c_json_get_str(x.json, "producer"), "p2") == 0 && prod_calls(&p1) == 1);
        reply_free(&x);
    }
    /* the only producer answers 503: its answer is the answer */
    p1.first_n = 0;
    p1.status = 503;
    p2.status = 503;
    {
        const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-sdm", "user-agent", "AMF-abc", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 503);
        TK_ASSERT(rh(&x, "via") != NULL);
        reply_free(&x);
    }
    p1.status = 200;
    p2.status = 200;
    /* the better producer is gone: the next is used and, after repeated failures, the first is left alone (no attempts are wasted on it) */
    prod_stop(&p1);
    for (int i = 0; i < 4; i++) {
        const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-sdm", "3gpp-sbi-discovery-dnn", "gone", "user-agent", "AMF-abc", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 200);
        TK_ASSERT(strcmp(g5c_json_get_str(x.json, "producer"), "p2") == 0);
        reply_free(&x);
    }
    TK_ASSERT(scp_quarantined(e.s) == 1);

    /* Model C with the producer gone and alternatives in the discovery factors: reselected, and the consumer is told where the answer came from */
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", root1, "3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-sdm", "user-agent", "AMF-abc", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 200);
        TK_ASSERT(strcmp(g5c_json_get_str(x.json, "producer"), "p2") == 0 && rh(&x, "3gpp-sbi-target-apiroot") != NULL && strcmp(rh(&x, "3gpp-sbi-target-apiroot"), p2.root) == 0);
        reply_free(&x);
    }
    /* ... or a Routing Binding Indication that names the instance */
    {
        char rb[200];
        snprintf(rb, sizeof rb, "bl=nf-instance; nfinst=%s", p2.id);
        const char *h[] = {"3gpp-sbi-target-apiroot", root1, "3gpp-sbi-routing-binding", rb, "3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-sdm", "user-agent", "AMF-abc", NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 200);
        TK_ASSERT(strstr(nrf.query, "target-nf-instance-id=") != NULL);
        reply_free(&x);
    }
    /* quarantine ends */
    sleep(2);
    TK_ASSERT(scp_quarantined(e.s) == 0);

    /* a request that is not idempotent is not repeated after a timeout; a GET is */
    p2.delay_ms = 1200;
    {
        int before = prod_calls(&p2);
        const char *h[] = {"3gpp-sbi-target-apiroot", p2.root, NULL};
        snprintf(url, sizeof url, "%s/nsmf-pdusession/v1/sm-contexts", e.base);
        x = call(cl, "POST", url, h, "{}");
        EXPECT(x, 504);
        TK_ASSERT(strcmp(cause_of(&x), "TARGET_NF_NOT_REACHABLE") == 0);
        reply_free(&x);
        sleep(2); /* the slow producer finishes */
        TK_ASSERT(prod_calls(&p2) == before + 1);
    }
    p2.delay_ms = 0;
    free(i1);
    free(i2);
    free(both);
    scp_env_stop(&e);
    nrf_stop(&nrf);
    prod_stop(&p2);
    g5c_client_free(cl);
}

/* a producer that asks for relief (429 with Retry-After): the SCP takes the request to another one, does not count it as broken, stops asking it for the time given, and tells the consumer
 * the same when every producer is asking (TS 29.500 5.2.7.2, 6.4) */
static void test_overload_backpressure(void)
{
    prod_t p1, p2;
    nrf_t nrf;
    scp_env e;
    g5c_client *cl = g5c_client_new(5000, NULL);
    reply_t x;
    char url[200], *i1, *i2, *both;
    const char *h[] = {"3gpp-sbi-discovery-target-nf-type", "UDM", "3gpp-sbi-discovery-service-names", "nudm-sdm", "user-agent", "AMF-abc", NULL};
    int c1, c2;
    prod_start(&p1, "p1");
    prod_start(&p2, "p2");
    nrf_start(&nrf);
    scp_env_start(&e, "scp1.test", nrf.root, "scp:\n  routing: { attempts: 3, timeout_ms: 400, quarantine: { failures: 2, seconds: 1 } }\n");
    i1 = profile(&p1, 1, 100, 0);
    i2 = profile(&p2, 2, 100, 0);
    both = g5c_xasprintf("[%s,%s]", i1, i2);
    nrf_set(&nrf, both);
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/nssai", e.base);

    p1.status = 429;
    x = call(cl, "GET", url, h, NULL);
    EXPECT(x, 200); /* the better producer said 429: the other one answered */
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "producer"), "p2") == 0 && prod_calls(&p1) == 1);
    reply_free(&x);
    TK_ASSERT(scp_quarantined(e.s) == 0); /* busy is not broken */
    c1 = prod_calls(&p1);
    for (int i = 0; i < 3; i++) { /* for the two seconds it asked for, nothing is sent to it */
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 200);
        TK_ASSERT(strcmp(g5c_json_get_str(x.json, "producer"), "p2") == 0);
        reply_free(&x);
    }
    TK_ASSERT(prod_calls(&p1) == c1);

    p2.status = 429; /* the second asks for relief too: the last answer is the producer's own 429, with its Retry-After */
    x = call(cl, "GET", url, h, NULL);
    EXPECT(x, 429);
    TK_ASSERT(rh(&x, "retry-after") != NULL && strcmp(rh(&x, "retry-after"), "2") == 0);
    reply_free(&x);
    g5c_client_free(cl); /* this client now honours the Retry-After it was given: a new consumer asks */
    cl = g5c_client_new(5000, NULL);
    c1 = prod_calls(&p1);
    c2 = prod_calls(&p2);
    x = call(cl, "GET", url, h, NULL); /* now neither is asked: the SCP answers itself, 429 and not 504 */
    EXPECT(x, 429);
    TK_ASSERT(strcmp(cause_of(&x), "TOO_MANY_REQUESTS") == 0 && rh(&x, "retry-after") != NULL);
    reply_free(&x);
    TK_ASSERT(prod_calls(&p1) == c1 && prod_calls(&p2) == c2 && scp_quarantined(e.s) == 0);
    g5c_client_free(cl);
    cl = g5c_client_new(5000, NULL);

    p1.status = 200;
    p2.status = 200;
    sleep(3); /* the periods are over */
    x = call(cl, "GET", url, h, NULL);
    EXPECT(x, 200);
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "producer"), "p1") == 0); /* the better one again */
    reply_free(&x);
    free(i1);
    free(i2);
    free(both);
    scp_env_stop(&e);
    nrf_stop(&nrf);
    prod_stop(&p1);
    prod_stop(&p2);
    g5c_client_free(cl);
}

static void test_chain(void)
{
    prod_t p;
    scp_env a, b;
    g5c_client *cl = g5c_client_new(3000, NULL);
    reply_t x;
    char url[200], yaml[300];
    prod_start(&p, "p1");
    scp_env_start(&b, "scp-b.test", NULL, "scp:\n  prefix: /b\n");
    snprintf(yaml, sizeof yaml, "scp:\n  next: { uri: '%s/b' }\n", b.base);
    scp_env_start(&a, "scp-a.test", NULL, yaml);
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", a.base);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", p.root, "user-agent", "AMF-1", NULL};
        x = call(cl, "GET", url, h, NULL);
    }
    EXPECT(x, 200);
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "producer"), "p1") == 0);
    TK_ASSERT(strstr(g5c_json_str(prod_header(&p, "via")), "SCP-scp-a.test") != NULL && strstr(g5c_json_str(prod_header(&p, "via")), "SCP-scp-b.test") != NULL);
    reply_free(&x);
    /* an error comes back through both with the Via of each */
    p.status = 404;
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", p.root, NULL};
        x = call(cl, "GET", url, h, NULL);
    }
    EXPECT(x, 404);
    reply_free(&x);
    p.status = 200;
    /* the next hop is down */
    scp_env_stop(&b);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", p.root, NULL};
        x = call(cl, "GET", url, h, NULL);
    }
    EXPECT(x, 504);
    reply_free(&x);
    scp_env_stop(&a);
    prod_stop(&p);
    g5c_client_free(cl);
}

static void test_client_side(void)
{
    prod_t p;
    nrf_t nrf;
    scp_env e;
    g5c_client *cl = g5c_client_new(3000, NULL);
    reply_t x;
    char url[200], scp_uri[100];
    g5c_json *j;
    g5c_resp r;
    char err[160];
    prod_start(&p, "p1");
    nrf_start(&nrf);
    scp_env_start(&e, "scp1.test", nrf.root, BASIC);
    snprintf(scp_uri, sizeof scp_uri, "%s", e.base);
    /* a consumer with an SCP configured: its request to the producer's URL goes through the SCP; to the NRF and to the SCP itself it does not */
    g5c_client_set_scp(cl, scp_uri, nrf.root);
    g5c_client_set_user_agent(cl, "UDM-test-1");
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/nssai?a=b", p.root);
    TK_ASSERT(g5c_client_request(cl, "GET", url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) == 0 && r.status == 200);
    j = g5c_resp_parse_json(&r);
    TK_ASSERT(strcmp(g5c_json_get_str(j, "producer"), "p1") == 0);
    g5c_json_free(j);
    g5c_resp_free(&r);
    TK_ASSERT(strstr(g5c_json_str(prod_header(&p, "via")), "SCP-scp1.test") != NULL && strcmp(g5c_json_str(prod_header(&p, "user-agent")), "UDM-test-1") == 0 &&
              strcmp(g5c_json_get_str(p.last, "query"), "a=b") == 0);
    {
        char nurl[200];
        snprintf(nurl, sizeof nurl, "%s/nnrf-disc/v1/nf-instances", nrf.root);
        nrf_set(&nrf, "[]");
        TK_ASSERT(g5c_client_request(cl, "GET", nurl, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) == 0 && r.status == 200);
        g5c_resp_free(&r);
        TK_ASSERT(prod_header(&p, "via") != NULL); /* unchanged: the NRF was reached directly (the producer saw nothing new) */
    }
    x = call(cl, "GET", scp_uri, NULL, NULL); /* the SCP itself: not sent to itself */
    TK_ASSERT(x.status == 400);
    reply_free(&x);
    g5c_client_set_scp(cl, NULL, NULL);
    g5c_client_set_user_agent(cl, NULL);
    /* a bad SCP address switches it off */
    g5c_client_set_scp(cl, "nonsense", NULL);
    snprintf(url, sizeof url, "%s/direct", p.root);
    TK_ASSERT(g5c_client_request(cl, "GET", url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) == 0 && r.status == 200);
    g5c_resp_free(&r);
    TK_ASSERT(prod_header(&p, "via") == NULL);
    scp_env_stop(&e);
    nrf_stop(&nrf);
    prod_stop(&p);
    g5c_client_free(cl);
}

typedef struct {
    g5c_client *c;
    char url[200], root[100];
    int status;
} par_t;

static void *par_run(void *v)
{
    par_t *ar = v;
    const char *h[] = {"3gpp-sbi-target-apiroot", ar->root, NULL};
    reply_t y = call(ar->c, "GET", ar->url, h, NULL);
    ar->status = y.status;
    reply_free(&y);
    return NULL;
}

static void test_metrics_and_concurrency(void)
{
    prod_t p;
    scp_env e;
    g5c_client *cl = g5c_client_new(3000, NULL);
    reply_t x;
    char url[200], *text;
    prod_start(&p, "p1");
    scp_env_start(&e, "scp1.test", NULL, "scp:\n  routing: { max_inflight: 2 }\n");
    snprintf(url, sizeof url, "%s/x", e.base);
    {
        const char *h[] = {"3gpp-sbi-target-apiroot", p.root, NULL};
        x = call(cl, "GET", url, h, NULL);
        EXPECT(x, 200);
        reply_free(&x);
        x = call(cl, "GET", url, NULL, NULL);
        EXPECT(x, 400);
        reply_free(&x);
    }
    text = g5c_registry_render(e.s->metrics);
    TK_ASSERT(strstr(text, "g5c_scp_requests_total{model=\"C\"} 1") != NULL && strstr(text, "g5c_scp_responses_total{class=\"scp_error\"} 1") != NULL &&
              strstr(text, "g5c_scp_responses_total{class=\"2xx\"} 1") != NULL && strstr(text, "g5c_scp_request_seconds") != NULL);
    free(text);
    /* more at once than the SCP may handle: the excess is refused */
    p.delay_ms = 600;
    {
        pthread_t th[4];
        par_t a[4];
        int ok = 0, busy = 0;
        for (int i = 0; i < 4; i++) {
            a[i].c = g5c_client_new(3000, NULL);
            snprintf(a[i].url, sizeof a[i].url, "%s", url);
            snprintf(a[i].root, sizeof a[i].root, "%s", p.root);
            pthread_create(&th[i], NULL, par_run, &a[i]);
        }
        for (int i = 0; i < 4; i++) {
            pthread_join(th[i], NULL);
            ok += a[i].status == 200;
            busy += a[i].status == 503;
            g5c_client_free(a[i].c);
        }
        TK_ASSERT(ok >= 2 && busy >= 1 && ok + busy == 4);
    }
    p.delay_ms = 0;
    scp_env_stop(&e);
    prod_stop(&p);
    g5c_client_free(cl);
}

int main(void)
{
    g5c_log_init("error", false);
    test_config();
    test_model_c();
    test_limits_and_targets();
    test_model_d();
    test_retries_and_health();
    test_overload_backpressure();
    test_chain();
    test_client_side();
    test_metrics_and_concurrency();
    puts("scp: ok");
    return 0;
}
