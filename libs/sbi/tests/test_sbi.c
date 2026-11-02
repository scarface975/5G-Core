/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "certgen.h"
#include "g5c/sbi.h"
#include "g5c/testkit.h"

/* ---- handlers ---- */

static atomic_int observed;
static char last_route[128];
static pthread_mutex_t route_mu = PTHREAD_MUTEX_INITIALIZER; /* the observer runs on every worker thread */

static void h_echo(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *o = g5c_json_new_obj();
    char *q = g5c_req_query(req, "a");
    (void)ctx;
    g5c_json_set_str(o, "supi", g5c_req_param(req, "supi"));
    g5c_json_set_str(o, "authority", req->authority);
    g5c_json_set_str(o, "scheme", req->scheme);
    if (q)
        g5c_json_set_str(o, "a", q);
    free(q);
    g5c_resp_json(resp, 200, o);
    g5c_json_free(o);
}

static void h_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    g5c_resp_status(resp, 204);
}

static void h_post(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *j;
    (void)ctx;
    j = g5c_req_json(req, resp);
    if (j == NULL)
        return;
    g5c_json_set_int(j, "len", (int64_t)req->body_len);
    g5c_resp_json(resp, 201, j);
    g5c_resp_header(resp, "location", "http://x/y");
    g5c_json_free(j);
}

static void h_slow(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    usleep(400 * 1000);
    g5c_resp_status(resp, 204);
}

static void observer(void *ctx, const char *method, const char *route, int status, double secs)
{
    (void)ctx;
    (void)method;
    (void)status;
    (void)secs;
    pthread_mutex_lock(&route_mu);
    snprintf(last_route, sizeof last_route, "%s", route);
    pthread_mutex_unlock(&route_mu);
    atomic_fetch_add(&observed, 1);
}

static bool verify_tok(void *u, const char *t)
{
    (void)u;
    return strcmp(t, "good") == 0;
}

static g5c_router *make_router(void)
{
    static g5c_bearer_cfg bearer = {verify_tok, NULL};
    g5c_router *r = g5c_router_new();
    g5c_router_route(r, "GET", "/nudm-sdm/v1/{supi}/am-data", h_echo, NULL);
    g5c_router_route(r, "DELETE", "/nudm-sdm/v1/{supi}/am-data", h_delete, NULL);
    g5c_router_route(r, "POST", "/post", h_post, NULL);
    g5c_router_route(r, "GET", "/slow", h_slow, NULL);
    g5c_router_set_observer(r, observer, NULL);
    (void)bearer;
    return r;
}

/* ---- router unit tests ---- */

static void make_req(g5c_req *q, const char *method, const char *path)
{
    g5c_req_init(q);
    q->method = g5c_xstrdup(method);
    q->path = g5c_xstrdup(path);
    q->scheme = g5c_xstrdup("http");
    q->authority = g5c_xstrdup("127.0.0.1:7777");
    g5c_req_set_body(q, "", 0);
}

static void test_router(void)
{
    g5c_router *r = make_router();
    g5c_req q;
    g5c_resp p;
    char *c;
    g5c_json *j;

    make_req(&q, "GET", "/nudm-sdm/v1/imsi-001010000000001/am-data");
    g5c_resp_init(&p);
    g5c_router_dispatch(r, &q, &p);
    TK_ASSERT(p.status == 200);
    j = g5c_resp_parse_json(&p);
    TK_ASSERT(strcmp(g5c_json_get_str(j, "supi"), "imsi-001010000000001") == 0);
    g5c_json_free(j);
    g5c_resp_free(&p);
    g5c_req_free(&q);

    make_req(&q, "GET", "/nope");
    g5c_resp_init(&p);
    g5c_router_dispatch(r, &q, &p);
    c = g5c_resp_problem_cause(&p);
    TK_ASSERT(p.status == 404 && c && strcmp(c, "RESOURCE_NOT_FOUND") == 0);
    free(c);
    g5c_resp_free(&p);
    g5c_req_free(&q);

    make_req(&q, "POST", "/nudm-sdm/v1/x/am-data");
    g5c_resp_init(&p);
    g5c_router_dispatch(r, &q, &p);
    TK_ASSERT(p.status == 405 && strcmp(g5c_resp_header_get(&p, "allow"), "GET, DELETE") == 0);
    TK_ASSERT(strcmp(g5c_resp_header_get(&p, "content-type"), G5C_PROBLEM_TYPE) == 0);
    pthread_mutex_lock(&route_mu);
    TK_ASSERT(strcmp(last_route, "unmatched") == 0);
    pthread_mutex_unlock(&route_mu);
    g5c_resp_free(&p);
    g5c_req_free(&q);

    make_req(&q, "POST", "/post");
    g5c_req_set_body(&q, "{", 1);
    g5c_resp_init(&p);
    g5c_router_dispatch(r, &q, &p);
    TK_ASSERT(p.status == 400);
    g5c_resp_free(&p);
    g5c_req_free(&q);

    make_req(&q, "GET", "/x");
    free(q.query);
    q.query = g5c_xstrdup("a=1&flag&b=two");
    c = g5c_req_query(&q, "a");
    TK_ASSERT(c && strcmp(c, "1") == 0);
    free(c);
    c = g5c_req_query(&q, "flag");
    TK_ASSERT(c && strcmp(c, "") == 0);
    free(c);
    c = g5c_req_query(&q, "b");
    TK_ASSERT(c && strcmp(c, "two") == 0);
    free(c);
    TK_ASSERT(g5c_req_query(&q, "c") == NULL && g5c_req_query(&q, "fla") == NULL);
    c = g5c_req_url(&q, "/a/b");
    TK_ASSERT(strcmp(c, "http://127.0.0.1:7777/a/b") == 0);
    free(c);
    g5c_req_free(&q);
    g5c_router_free(r);

    {   /* bearer guard */
        g5c_bearer_cfg cfg = {verify_tok, NULL};
        g5c_req gq;
        g5c_resp gp;
        make_req(&gq, "GET", "/x");
        g5c_resp_init(&gp);
        TK_ASSERT(g5c_bearer_guard(&cfg, &gq, &gp) != 0 && gp.status == 401);
        c = g5c_resp_problem_cause(&gp);
        TK_ASSERT(strcmp(c, "MISSING_TOKEN") == 0);
        free(c);
        g5c_resp_free(&gp);
        g5c_req_add_header(&gq, "Authorization", "Bearer bad");
        g5c_resp_init(&gp);
        TK_ASSERT(g5c_bearer_guard(&cfg, &gq, &gp) != 0);
        c = g5c_resp_problem_cause(&gp);
        TK_ASSERT(strcmp(c, "INVALID_TOKEN") == 0);
        free(c);
        TK_ASSERT(strcmp(g5c_resp_header_get(&gp, "www-authenticate"), "Bearer") == 0);
        g5c_resp_free(&gp);
        g5c_req_free(&gq);
        make_req(&gq, "GET", "/x");
        g5c_req_add_header(&gq, "authorization", "Bearer good");
        g5c_resp_init(&gp);
        TK_ASSERT(g5c_bearer_guard(&cfg, &gq, &gp) == 0);
        g5c_resp_free(&gp);
        g5c_req_free(&gq);
    }
}

/* ---- loopback ---- */

static char *url_for(const g5c_server *s, const char *scheme, const char *path)
{
    return g5c_xasprintf("%s://127.0.0.1:%u%s", scheme, g5c_server_port(s), path);
}

static void test_plain(void)
{
    g5c_router *r = make_router();
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[200];
    g5c_server *s = g5c_server_start(&cfg, r, err, sizeof err);
    g5c_client *c = g5c_client_new(2000, NULL);
    g5c_resp out;
    char *u;
    g5c_json *j;
    TK_ASSERT(s != NULL);

    u = url_for(s, "http", "/nudm-sdm/v1/imsi-1/am-data?a=7");
    TK_ASSERT(g5c_client_get(c, u, &out, err, sizeof err) == 0);
    TK_ASSERT(out.status == 200);
    j = g5c_resp_parse_json(&out);
    TK_ASSERT(strcmp(g5c_json_get_str(j, "supi"), "imsi-1") == 0 && strcmp(g5c_json_get_str(j, "a"), "7") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(j, "scheme"), "http") == 0 && strstr(g5c_json_get_str(j, "authority"), "127.0.0.1:") != NULL);
    g5c_json_free(j);
    TK_ASSERT(strcmp(g5c_resp_header_get(&out, "content-type"), G5C_JSON_TYPE) == 0);
    g5c_resp_free(&out);
    free(u);

    /* second request reuses the pooled connection */
    u = url_for(s, "http", "/nudm-sdm/v1/imsi-2/am-data");
    TK_ASSERT(g5c_client_request(c, "DELETE", u, NULL, 0, NULL, NULL, 0, &out, err, sizeof err) == 0 && out.status == 204);
    g5c_resp_free(&out);
    free(u);

    /* JSON POST + Location */
    {
        g5c_json *b = g5c_json_new_obj();
        g5c_json_set_str(b, "k", "v");
        u = url_for(s, "http", "/post");
        TK_ASSERT(g5c_client_send_json(c, "POST", u, b, &out, err, sizeof err) == 0);
        TK_ASSERT(out.status == 201 && strcmp(g5c_resp_header_get(&out, "location"), "http://x/y") == 0);
        j = g5c_resp_parse_json(&out);
        TK_ASSERT(strcmp(g5c_json_get_str(j, "k"), "v") == 0);
        g5c_json_free(j);
        g5c_resp_free(&out);
        free(u);
        g5c_json_free(b);
    }

    /* 404 / 405 over the wire */
    u = url_for(s, "http", "/nothing");
    TK_ASSERT(g5c_client_get(c, u, &out, err, sizeof err) == 0 && out.status == 404);
    g5c_resp_free(&out);
    free(u);

    /* oversized body -> 413 */
    {
        size_t n = G5C_SBI_MAX_BODY + 4096;
        char *big = malloc(n);
        memset(big, 'a', n);
        u = url_for(s, "http", "/post");
        TK_ASSERT(g5c_client_request(c, "POST", u, NULL, 0, G5C_JSON_TYPE, big, n, &out, err, sizeof err) == 0);
        TK_ASSERT(out.status == 413);
        g5c_resp_free(&out);
        free(u);
        free(big);
    }

    /* timeout, then the client still works */
    {
        g5c_client *fast = g5c_client_new(100, NULL);
        u = url_for(s, "http", "/slow");
        TK_ASSERT(g5c_client_get(fast, u, &out, err, sizeof err) == G5C_SBI_E_TIMEOUT);
        free(u);
        u = url_for(s, "http", "/nudm-sdm/v1/imsi-3/am-data");
        TK_ASSERT(g5c_client_get(fast, u, &out, err, sizeof err) == 0 && out.status == 200);
        g5c_resp_free(&out);
        free(u);
        g5c_client_free(fast);
    }

    /* bad URL, refused connection */
    TK_ASSERT(g5c_client_get(c, "ftp://x", &out, err, sizeof err) == G5C_SBI_E_URL);
    TK_ASSERT(g5c_client_get(c, "http://127.0.0.1:1/", &out, err, sizeof err) != 0);
    TK_ASSERT(g5c_client_get(c, "https://127.0.0.1:1/", &out, err, sizeof err) != 0); /* no TLS context */
    TK_ASSERT(atomic_load(&observed) > 0);

    g5c_client_free(c);
    g5c_server_stop(s);
    g5c_router_free(r);
}

typedef struct {
    const char *url;
    int n, ok;
    g5c_client *c;
} bulk_t;

static void *bulk(void *a)
{
    bulk_t *b = a;
    for (int i = 0; i < b->n; i++) {
        g5c_resp out;
        char err[100];
        if (g5c_client_get(b->c, b->url, &out, err, sizeof err) == 0) {
            if (out.status == 200)
                b->ok++;
            g5c_resp_free(&out);
        }
    }
    return NULL;
}

static void test_concurrency(void)
{
    g5c_router *r = make_router();
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_server *s = g5c_server_start(&cfg, r, NULL, 0);
    g5c_client *c = g5c_client_new(5000, NULL);
    char *u = url_for(s, "http", "/nudm-sdm/v1/imsi-9/am-data");
    pthread_t th[8];
    bulk_t b[8];
    int total = 0;
    TK_ASSERT(s != NULL);
    for (int i = 0; i < 8; i++) {
        b[i] = (bulk_t){u, 100, 0, c};
        pthread_create(&th[i], NULL, bulk, &b[i]);
    }
    for (int i = 0; i < 8; i++) {
        pthread_join(th[i], NULL);
        total += b[i].ok;
    }
    TK_ASSERT(total == 800);
    free(u);
    g5c_client_free(c);
    g5c_server_stop(s);
    g5c_router_free(r);
}

static void test_tls(void)
{
    cg_id ca = cg_make("test-ca", NULL, true, NULL, 1), other_ca = cg_make("other-ca", NULL, true, NULL, 2);
    cg_id srv = cg_make("server", &ca, false, "IP:127.0.0.1,DNS:localhost", 3);
    cg_id cli = cg_make("client", &ca, false, NULL, 4);
    char err[200];
    g5c_router *r = make_router();
    g5c_resp out;
    char *u;

    /* plain TLS: any client trusting the CA works */
    {
        SSL_CTX *sctx = g5c_tls_server_ctx_pem(srv.cert_pem, srv.key_pem, NULL, err, sizeof err);
        g5c_server_cfg cfg = {"127.0.0.1", 0, sctx};
        g5c_server *s;
        g5c_client *good, *bad;
        TK_ASSERT(sctx != NULL);
        s = g5c_server_start(&cfg, r, err, sizeof err);
        TK_ASSERT(s != NULL);
        good = g5c_client_new(3000, g5c_tls_client_ctx_pem(ca.cert_pem, NULL, NULL, err, sizeof err));
        bad = g5c_client_new(3000, g5c_tls_client_ctx_pem(other_ca.cert_pem, NULL, NULL, err, sizeof err));
        u = url_for(s, "https", "/nudm-sdm/v1/imsi-5/am-data");
        TK_ASSERT(g5c_client_get(good, u, &out, err, sizeof err) == 0 && out.status == 200);
        {
            g5c_json *j = g5c_resp_parse_json(&out);
            TK_ASSERT(strcmp(g5c_json_get_str(j, "scheme"), "https") == 0);
            g5c_json_free(j);
        }
        g5c_resp_free(&out);
        TK_ASSERT(g5c_client_get(good, u, &out, err, sizeof err) == 0); /* pooled TLS connection */
        g5c_resp_free(&out);
        TK_ASSERT(g5c_client_get(bad, u, &out, err, sizeof err) == G5C_SBI_E_TLS); /* untrusted server */
        free(u);
        g5c_client_free(good);
        g5c_client_free(bad);
        g5c_server_stop(s);
        SSL_CTX_free(sctx);
    }

    /* mutual TLS: client certificate required */
    {
        SSL_CTX *sctx = g5c_tls_server_ctx_pem(srv.cert_pem, srv.key_pem, ca.cert_pem, err, sizeof err);
        g5c_server_cfg cfg = {"127.0.0.1", 0, sctx};
        g5c_server *s = g5c_server_start(&cfg, r, err, sizeof err);
        g5c_client *withcert, *nocert;
        TK_ASSERT(s != NULL);
        withcert = g5c_client_new(3000, g5c_tls_client_ctx_pem(ca.cert_pem, cli.cert_pem, cli.key_pem, err, sizeof err));
        nocert = g5c_client_new(3000, g5c_tls_client_ctx_pem(ca.cert_pem, NULL, NULL, err, sizeof err));
        u = url_for(s, "https", "/nudm-sdm/v1/imsi-6/am-data");
        TK_ASSERT(g5c_client_get(withcert, u, &out, err, sizeof err) == 0 && out.status == 200);
        g5c_resp_free(&out);
        TK_ASSERT(g5c_client_get(nocert, u, &out, err, sizeof err) != 0); /* rejected during/after handshake */
        free(u);
        g5c_client_free(withcert);
        g5c_client_free(nocert);
        g5c_server_stop(s);
        SSL_CTX_free(sctx);
    }
    g5c_router_free(r);
    cg_free(&ca);
    cg_free(&other_ca);
    cg_free(&srv);
    cg_free(&cli);
}

/* certificate rotation: the server swaps its context, new connections see the new certificate, the old CA stops working; the client swaps likewise */
static void test_tls_rotation(void)
{
    cg_id ca1 = cg_make("ca-1", NULL, true, NULL, 11), ca2 = cg_make("ca-2", NULL, true, NULL, 12);
    cg_id srv1 = cg_make("server", &ca1, false, "IP:127.0.0.1", 13), srv2 = cg_make("server", &ca2, false, "IP:127.0.0.1", 14);
    cg_id cli1 = cg_make("client", &ca1, false, NULL, 15), cli2 = cg_make("client", &ca2, false, NULL, 16);
    char err[200], *u;
    g5c_router *r = make_router();
    SSL_CTX *s1 = g5c_tls_server_ctx_pem(srv1.cert_pem, srv1.key_pem, ca1.cert_pem, err, sizeof err), *s2, *old;
    g5c_server_cfg cfg = {"127.0.0.1", 0, s1};
    g5c_server *s = g5c_server_start(&cfg, r, err, sizeof err);
    g5c_client *c;
    g5c_resp out;
    TK_ASSERT(s1 != NULL && s != NULL);
    u = url_for(s, "https", "/nudm-sdm/v1/imsi-7/am-data");
    c = g5c_client_new(3000, g5c_tls_client_ctx_pem(ca1.cert_pem, cli1.cert_pem, cli1.key_pem, err, sizeof err));
    TK_ASSERT(g5c_client_get(c, u, &out, err, sizeof err) == 0 && out.status == 200); /* generation 1 both sides */
    g5c_resp_free(&out);
    s2 = g5c_tls_server_ctx_pem(srv2.cert_pem, srv2.key_pem, ca2.cert_pem, err, sizeof err);
    old = g5c_server_swap_tls(s, s2);
    TK_ASSERT(old == s1);
    SSL_CTX_free(old);
    TK_ASSERT(g5c_client_get(c, u, &out, err, sizeof err) == 0); /* the connection that is already open keeps what it negotiated */
    g5c_resp_free(&out);
    {
        g5c_client *fresh = g5c_client_new(3000, g5c_tls_client_ctx_pem(ca1.cert_pem, cli1.cert_pem, cli1.key_pem, err, sizeof err));
        TK_ASSERT(g5c_client_get(fresh, u, &out, err, sizeof err) != 0); /* a new connection with CA 1 only: refused, the server serves generation 2 */
        g5c_client_free(fresh);
    }
    g5c_client_swap_tls(c, g5c_tls_client_ctx_pem(ca2.cert_pem, cli2.cert_pem, cli2.key_pem, err, sizeof err));
    TK_ASSERT(g5c_client_get(c, u, &out, err, sizeof err) == 0 && out.status == 200); /* generation 2 both sides */
    g5c_resp_free(&out);
    free(u);
    g5c_client_free(c);
    g5c_server_stop(s);
    SSL_CTX_free(s2);
    g5c_router_free(r);
    cg_free(&ca1);
    cg_free(&ca2);
    cg_free(&srv1);
    cg_free(&srv2);
    cg_free(&cli1);
    cg_free(&cli2);
}

/* C-03: the trace id of a request reaches the handler, goes on with the requests the handler sends, and a request without one starts a trace */
static void h_trace(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const g5c_trace_ctx *t = g5c_trace_current();
    g5c_json *o = g5c_json_new_obj();
    (void)ctx;
    g5c_json_set_str(o, "trace", t != NULL ? t->trace_id : "");
    g5c_json_set_str(o, "parent", t != NULL ? t->parent_id : "");
    g5c_json_set_str(o, "span", t != NULL ? t->span_id : "");
    g5c_json_set_str(o, "incoming", g5c_req_header(req, "traceparent") != NULL ? g5c_req_header(req, "traceparent") : "");
    g5c_resp_json(resp, 200, o);
    g5c_json_free(o);
}

/* relays to the server it was given in ctx: the request it sends carries the trace it is handling */
static void h_trace_relay(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_client *c = g5c_client_new(3000, NULL);
    g5c_resp out;
    char err[100];
    (void)req;
    if (g5c_client_get(c, ctx, &out, err, sizeof err) == 0) {
        g5c_resp_content(resp, 200, "application/json", out.body, out.body_len);
        g5c_resp_free(&out);
    } else {
        g5c_resp_status(resp, 502);
    }
    g5c_client_free(c);
}

static void test_trace(void)
{
    g5c_router *r1 = g5c_router_new(), *r2 = g5c_router_new();
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_server *s1, *s2;
    g5c_client *c = g5c_client_new(3000, NULL);
    g5c_resp out;
    g5c_json *j;
    char err[100], *u1, *u2, id[33] = "";
    g5c_router_route(r1, "GET", "/t", h_trace, NULL);
    s1 = g5c_server_start(&cfg, r1, err, sizeof err);
    u1 = url_for(s1, "http", "/t");
    g5c_router_route(r2, "GET", "/relay", h_trace_relay, u1);
    s2 = g5c_server_start(&cfg, r2, err, sizeof err);
    u2 = url_for(s2, "http", "/relay");
    TK_ASSERT(s1 != NULL && s2 != NULL);
    /* no trace on the client: the server starts one (32 hex) and has no parent */
    TK_ASSERT(g5c_client_get(c, u1, &out, err, sizeof err) == 0);
    j = g5c_resp_parse_json(&out);
    TK_ASSERT(strlen(g5c_json_get_str(j, "trace")) == 32 && g5c_json_get_str(j, "parent")[0] == 0 && g5c_json_get_str(j, "incoming")[0] == 0);
    g5c_json_free(j);
    g5c_resp_free(&out);
    /* a trace on the calling thread goes out as traceparent and is continued by the server, with the caller's span as parent */
    g5c_trace_enter(id);
    TK_ASSERT(strlen(id) == 32 && g5c_trace_current() != NULL);
    TK_ASSERT(g5c_client_get(c, u1, &out, err, sizeof err) == 0);
    j = g5c_resp_parse_json(&out);
    TK_ASSERT(strcmp(g5c_json_get_str(j, "trace"), id) == 0 && strlen(g5c_json_get_str(j, "parent")) == 16 && strncmp(g5c_json_get_str(j, "incoming"), "00-", 3) == 0);
    g5c_json_free(j);
    g5c_resp_free(&out);
    /* through a relay: the second hop carries the same trace id */
    TK_ASSERT(g5c_client_get(c, u2, &out, err, sizeof err) == 0);
    j = g5c_resp_parse_json(&out);
    TK_ASSERT(strcmp(g5c_json_get_str(j, "trace"), id) == 0);
    g5c_json_free(j);
    g5c_resp_free(&out);
    g5c_trace_leave();
    TK_ASSERT(g5c_trace_current() == NULL);
    /* the header: only the exact form is taken */
    {
        g5c_kv h = {"traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"};
        g5c_kv bad = {"traceparent", "00-ZZ-nonsense"};
        TK_ASSERT(g5c_client_request(c, "GET", u1, &h, 1, NULL, NULL, 0, &out, err, sizeof err) == 0);
        j = g5c_resp_parse_json(&out);
        TK_ASSERT(strcmp(g5c_json_get_str(j, "trace"), "0af7651916cd43dd8448eb211c80319c") == 0 && strcmp(g5c_json_get_str(j, "parent"), "b7ad6b7169203331") == 0);
        g5c_json_free(j);
        g5c_resp_free(&out);
        TK_ASSERT(g5c_client_request(c, "GET", u1, &bad, 1, NULL, NULL, 0, &out, err, sizeof err) == 0);
        j = g5c_resp_parse_json(&out);
        TK_ASSERT(strlen(g5c_json_get_str(j, "trace")) == 32 && g5c_json_get_str(j, "parent")[0] == 0); /* malformed: a new trace, not the garbage */
        g5c_json_free(j);
        g5c_resp_free(&out);
    }
    free(u1);
    free(u2);
    g5c_client_free(c);
    g5c_server_stop(s1);
    g5c_server_stop(s2);
    g5c_router_free(r1);
    g5c_router_free(r2);
}

/* D-02: who may connect (identity pinning by certificate name) and revocation (CRL) */
static char *make_crl(const cg_id *ca, const cg_id *revoked)
{
    X509_CRL *crl = X509_CRL_new();
    ASN1_TIME *last = ASN1_TIME_adj(NULL, time(NULL) - 60, 0, 0), *next = ASN1_TIME_adj(NULL, time(NULL), 7, 0);
    BIO *b = BIO_new(BIO_s_mem());
    char *out;
    X509_CRL_set_version(crl, 1);
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca->cert));
    X509_CRL_set1_lastUpdate(crl, last);
    X509_CRL_set1_nextUpdate(crl, next);
    if (revoked != NULL) {
        X509_REVOKED *rv = X509_REVOKED_new();
        X509_REVOKED_set_serialNumber(rv, X509_get_serialNumber(revoked->cert));
        X509_REVOKED_set_revocationDate(rv, last);
        X509_CRL_add0_revoked(crl, rv);
    }
    X509_CRL_sort(crl);
    TK_ASSERT(X509_CRL_sign(crl, ca->key, EVP_sha256()) > 0);
    PEM_write_bio_X509_CRL(b, crl);
    out = cg_bio_str(b);
    BIO_free(b);
    X509_CRL_free(crl);
    ASN1_STRING_free(last);
    ASN1_STRING_free(next);
    return out;
}

/* one request from `cli` to a server built with the given policy; true when it was answered */
static bool policy_request(const cg_id *ca, const cg_id *srv, const cg_id *cli, const char *const *allowed, size_t nallowed, const char *crl)
{
    char err[200], *u;
    g5c_router *r = make_router();
    SSL_CTX *sctx = g5c_tls_server_ctx_pem(srv->cert_pem, srv->key_pem, ca->cert_pem, err, sizeof err);
    g5c_server_cfg cfg = {"127.0.0.1", 0, sctx};
    g5c_server *s;
    g5c_client *c;
    g5c_resp out;
    bool ok = false;
    TK_ASSERT(sctx != NULL && g5c_tls_server_policy(sctx, allowed, nallowed, crl, err, sizeof err) == 0);
    s = g5c_server_start(&cfg, r, err, sizeof err);
    TK_ASSERT(s != NULL);
    c = g5c_client_new(3000, g5c_tls_client_ctx_pem(ca->cert_pem, cli->cert_pem, cli->key_pem, err, sizeof err));
    u = url_for(s, "https", "/nudm-sdm/v1/imsi-9/am-data");
    if (g5c_client_get(c, u, &out, err, sizeof err) == 0) {
        ok = out.status == 200;
        g5c_resp_free(&out);
    }
    free(u);
    g5c_client_free(c);
    g5c_server_stop(s);
    SSL_CTX_free(sctx);
    g5c_router_free(r);
    return ok;
}

static void test_tls_policy(void)
{
    cg_id ca = cg_make("policy-ca", NULL, true, NULL, 31), other = cg_make("other-ca", NULL, true, NULL, 32);
    cg_id srv = cg_make("server", &ca, false, "IP:127.0.0.1", 33);
    cg_id good = cg_make("smf", &ca, false, NULL, 34), peer2 = cg_make("amf-2", &ca, false, NULL, 35), evil = cg_make("nssf", &ca, false, NULL, 36);
    const char *allow[] = {"smf", "amf-*"};
    char *crl_none = make_crl(&ca, NULL), *crl_good = make_crl(&ca, &good), *crl_foreign = make_crl(&other, NULL);

    /* identity pinning: exact and wildcard names pass, any other certificate of the same CA is refused */
    TK_ASSERT(policy_request(&ca, &srv, &good, allow, 2, NULL));
    TK_ASSERT(policy_request(&ca, &srv, &peer2, allow, 2, NULL));
    TK_ASSERT(!policy_request(&ca, &srv, &evil, allow, 2, NULL));
    TK_ASSERT(policy_request(&ca, &srv, &evil, NULL, 0, NULL)); /* no list: any certificate of the CA, as before */
    /* revocation: a certificate the CRL lists is refused, the others pass; a CRL of another CA leaves the CA without one: refused */
    TK_ASSERT(policy_request(&ca, &srv, &good, NULL, 0, crl_none));
    TK_ASSERT(!policy_request(&ca, &srv, &good, NULL, 0, crl_good));
    TK_ASSERT(policy_request(&ca, &srv, &peer2, NULL, 0, crl_good));
    TK_ASSERT(!policy_request(&ca, &srv, &good, NULL, 0, crl_foreign));
    /* both together */
    TK_ASSERT(policy_request(&ca, &srv, &peer2, allow, 2, crl_good));
    TK_ASSERT(!policy_request(&ca, &srv, &good, allow, 2, crl_good));
    {
        char err[100];
        SSL_CTX *c = g5c_tls_server_ctx_pem(srv.cert_pem, srv.key_pem, ca.cert_pem, err, sizeof err);
        TK_ASSERT(g5c_tls_server_policy(c, NULL, 0, "not a crl", err, sizeof err) == -1); /* unusable CRL text is an error, not silently ignored */
        SSL_CTX_free(c);
    }
    free(crl_none);
    free(crl_good);
    free(crl_foreign);
    cg_free(&ca);
    cg_free(&other);
    cg_free(&srv);
    cg_free(&good);
    cg_free(&peer2);
    cg_free(&evil);
}

/* G5C_TLS_KEYLOG: secrets of both sides land in an NSS key log (0600) for Wireshark; nothing is written when the variable is unset */
static void test_tls_keylog(void)
{
    cg_id ca = cg_make("test-ca", NULL, true, NULL, 21), srv = cg_make("server", &ca, false, "IP:127.0.0.1", 22);
    char err[200], path[] = "/tmp/g5c-keylog-XXXXXX", *u, *txt;
    g5c_router *r = make_router();
    g5c_resp out;
    struct stat st;
    int fd = mkstemp(path);
    TK_ASSERT(fd >= 0);
    close(fd);
    unlink(path);
    setenv("G5C_TLS_KEYLOG", path, 1);
    {
        SSL_CTX *sctx = g5c_tls_server_ctx_pem(srv.cert_pem, srv.key_pem, NULL, err, sizeof err);
        g5c_server_cfg cfg = {"127.0.0.1", 0, sctx};
        g5c_server *s = g5c_server_start(&cfg, r, err, sizeof err);
        g5c_client *c = g5c_client_new(3000, g5c_tls_client_ctx_pem(ca.cert_pem, NULL, NULL, err, sizeof err));
        TK_ASSERT(s != NULL);
        u = url_for(s, "https", "/nudm-sdm/v1/imsi-8/am-data");
        TK_ASSERT(g5c_client_get(c, u, &out, err, sizeof err) == 0 && out.status == 200);
        g5c_resp_free(&out);
        free(u);
        g5c_client_free(c);
        g5c_server_stop(s);
        SSL_CTX_free(sctx);
    }
    unsetenv("G5C_TLS_KEYLOG");
    TK_ASSERT(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    {
        FILE *f = fopen(path, "rb");
        txt = calloc(1, 8192);
        TK_ASSERT(f != NULL && txt != NULL);
        TK_ASSERT(fread(txt, 1, 8191, f) > 0);
        fclose(f);
    }
    TK_ASSERT(strstr(txt, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ") != NULL); /* TLS 1.3 */
    TK_ASSERT(strstr(txt, "SERVER_TRAFFIC_SECRET_0 ") != NULL);
    free(txt);
    unlink(path);
    /* unset: a handshake leaves no file behind */
    {
        SSL_CTX *sctx = g5c_tls_server_ctx_pem(srv.cert_pem, srv.key_pem, NULL, err, sizeof err);
        g5c_server_cfg cfg = {"127.0.0.1", 0, sctx};
        g5c_server *s = g5c_server_start(&cfg, r, err, sizeof err);
        g5c_client *c = g5c_client_new(3000, g5c_tls_client_ctx_pem(ca.cert_pem, NULL, NULL, err, sizeof err));
        u = url_for(s, "https", "/nudm-sdm/v1/imsi-8/am-data");
        TK_ASSERT(g5c_client_get(c, u, &out, err, sizeof err) == 0);
        g5c_resp_free(&out);
        free(u);
        g5c_client_free(c);
        g5c_server_stop(s);
        SSL_CTX_free(sctx);
    }
    TK_ASSERT(stat(path, &st) != 0);
    g5c_router_free(r);
    cg_free(&ca);
    cg_free(&srv);
}

/* TLS negative paths: identities the server must refuse, certificates the client must refuse, and unusable key material. */
static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    TK_ASSERT(f != NULL);
    TK_ASSERT(fputs(text, f) >= 0);
    TK_ASSERT(fclose(f) == 0);
}

static void test_tls_negative(void)
{
    cg_id ca = cg_make("test-ca", NULL, true, NULL, 11), other_ca = cg_make("other-ca", NULL, true, NULL, 12);
    cg_id srv = cg_make("server", &ca, false, "IP:127.0.0.1,DNS:localhost", 13);
    cg_id srv_wrong_name = cg_make("server2", &ca, false, "IP:10.9.9.9", 14);
    cg_id cli = cg_make("client", &ca, false, NULL, 15), rogue = cg_make("rogue", &other_ca, false, NULL, 16);
    char err[200], dir[] = "/tmp/g5c-tls-XXXXXX", p_cert[128], p_key[128], p_ca[128], p_bad[128];
    g5c_router *r = make_router();
    g5c_resp out;
    char *u;
    SSL_CTX *c;

    /* an mTLS server refuses a client certificate issued by a different CA */
    {
        SSL_CTX *sctx = g5c_tls_server_ctx_pem(srv.cert_pem, srv.key_pem, ca.cert_pem, err, sizeof err);
        g5c_server_cfg cfg = {"127.0.0.1", 0, sctx};
        g5c_server *s = g5c_server_start(&cfg, r, err, sizeof err);
        g5c_client *rogue_cl = g5c_client_new(3000, g5c_tls_client_ctx_pem(ca.cert_pem, rogue.cert_pem, rogue.key_pem, err, sizeof err));
        TK_ASSERT(s != NULL && rogue_cl != NULL);
        u = url_for(s, "https", "/nudm-sdm/v1/imsi-7/am-data");
        TK_ASSERT(g5c_client_get(rogue_cl, u, &out, err, sizeof err) != 0);
        free(u);
        g5c_client_free(rogue_cl);
        g5c_server_stop(s);
        SSL_CTX_free(sctx);
    }
    /* a client refuses a server whose certificate does not cover the address it dialled */
    {
        SSL_CTX *sctx = g5c_tls_server_ctx_pem(srv_wrong_name.cert_pem, srv_wrong_name.key_pem, NULL, err, sizeof err);
        g5c_server_cfg cfg = {"127.0.0.1", 0, sctx};
        g5c_server *s = g5c_server_start(&cfg, r, err, sizeof err);
        g5c_client *cl = g5c_client_new(3000, g5c_tls_client_ctx_pem(ca.cert_pem, NULL, NULL, err, sizeof err));
        TK_ASSERT(s != NULL && cl != NULL);
        u = url_for(s, "https", "/nudm-sdm/v1/imsi-8/am-data");
        TK_ASSERT(g5c_client_get(cl, u, &out, err, sizeof err) == G5C_SBI_E_TLS);
        free(u);
        g5c_client_free(cl);
        g5c_server_stop(s);
        SSL_CTX_free(sctx);
    }
    /* an https:// URL on a client built without TLS is an error, not a plaintext fallback */
    {
        SSL_CTX *sctx = g5c_tls_server_ctx_pem(srv.cert_pem, srv.key_pem, NULL, err, sizeof err);
        g5c_server_cfg cfg = {"127.0.0.1", 0, sctx};
        g5c_server *s = g5c_server_start(&cfg, r, err, sizeof err);
        g5c_client *plain = g5c_client_new(2000, NULL);
        TK_ASSERT(s != NULL);
        u = url_for(s, "https", "/nudm-sdm/v1/imsi-9/am-data");
        TK_ASSERT(g5c_client_get(plain, u, &out, err, sizeof err) != 0);
        free(u);
        u = url_for(s, "http", "/nudm-sdm/v1/imsi-9/am-data"); /* and plaintext to a TLS port fails too */
        TK_ASSERT(g5c_client_get(plain, u, &out, err, sizeof err) != 0);
        free(u);
        g5c_client_free(plain);
        g5c_server_stop(s);
        SSL_CTX_free(sctx);
    }

    /* PEM loaders refuse garbage and mismatched keys */
    TK_ASSERT(g5c_tls_server_ctx_pem("garbage", srv.key_pem, NULL, err, sizeof err) == NULL && err[0]);
    TK_ASSERT(g5c_tls_server_ctx_pem(srv.cert_pem, "garbage", NULL, err, sizeof err) == NULL);
    TK_ASSERT(g5c_tls_server_ctx_pem(srv.cert_pem, cli.key_pem, NULL, err, sizeof err) == NULL); /* key does not match */
    TK_ASSERT(g5c_tls_server_ctx_pem(srv.cert_pem, srv.key_pem, "garbage", err, sizeof err) == NULL);
    TK_ASSERT(g5c_tls_client_ctx_pem("garbage", NULL, NULL, err, sizeof err) == NULL);
    TK_ASSERT(g5c_tls_client_ctx_pem(ca.cert_pem, cli.cert_pem, srv.key_pem, err, sizeof err) == NULL);
    TK_ASSERT(g5c_tls_client_ctx_pem(ca.cert_pem, "garbage", cli.key_pem, err, sizeof err) == NULL);

    /* file-based loaders (what the NF configuration uses) */
    TK_ASSERT(mkdtemp(dir) != NULL);
    snprintf(p_cert, sizeof p_cert, "%s/srv.crt", dir);
    snprintf(p_key, sizeof p_key, "%s/srv.key", dir);
    snprintf(p_ca, sizeof p_ca, "%s/ca.crt", dir);
    snprintf(p_bad, sizeof p_bad, "%s/bad.pem", dir);
    write_file(p_cert, srv.cert_pem);
    write_file(p_key, srv.key_pem);
    write_file(p_ca, ca.cert_pem);
    write_file(p_bad, "-----BEGIN CERTIFICATE-----\nnot base64 !!!\n-----END CERTIFICATE-----\n");
    c = g5c_tls_server_ctx(p_cert, p_key, NULL, err, sizeof err);
    TK_ASSERT(c != NULL);
    SSL_CTX_free(c);
    c = g5c_tls_server_ctx(p_cert, p_key, p_ca, err, sizeof err);
    TK_ASSERT(c != NULL);
    SSL_CTX_free(c);
    TK_ASSERT(g5c_tls_server_ctx("/nonexistent/c.pem", p_key, NULL, err, sizeof err) == NULL && strstr(err, "/nonexistent/c.pem") != NULL);
    TK_ASSERT(g5c_tls_server_ctx(p_cert, "/nonexistent/k.pem", NULL, err, sizeof err) == NULL);
    TK_ASSERT(g5c_tls_server_ctx(p_cert, p_key, "/nonexistent/ca.pem", err, sizeof err) == NULL);
    TK_ASSERT(g5c_tls_server_ctx(p_bad, p_key, NULL, err, sizeof err) == NULL);
    TK_ASSERT(g5c_tls_server_ctx(p_cert, p_cert, NULL, err, sizeof err) == NULL); /* a certificate is not a key */
    c = g5c_tls_client_ctx(p_ca, NULL, NULL, err, sizeof err);
    TK_ASSERT(c != NULL);
    SSL_CTX_free(c);
    c = g5c_tls_client_ctx(p_ca, p_cert, p_key, err, sizeof err);
    TK_ASSERT(c != NULL);
    SSL_CTX_free(c);
    TK_ASSERT(g5c_tls_client_ctx("/nonexistent/ca.pem", NULL, NULL, err, sizeof err) == NULL);
    TK_ASSERT(g5c_tls_client_ctx(p_bad, NULL, NULL, err, sizeof err) == NULL);
    TK_ASSERT(g5c_tls_client_ctx(p_ca, "/nonexistent/c.pem", p_key, err, sizeof err) == NULL);
    TK_ASSERT(g5c_tls_client_ctx(p_ca, p_cert, "/nonexistent/k.pem", err, sizeof err) == NULL);
    (void)remove(p_cert);
    (void)remove(p_key);
    (void)remove(p_ca);
    (void)remove(p_bad);
    (void)rmdir(dir);

    g5c_router_free(r);
    cg_free(&ca);
    cg_free(&other_ca);
    cg_free(&srv);
    cg_free(&srv_wrong_name);
    cg_free(&cli);
    cg_free(&rogue);
}

int main(void)
{
    g5c_log_init("error", false);
    test_router();
    test_plain();
    test_concurrency();
    test_tls();
    test_tls_negative();
    test_tls_rotation();
    test_tls_keylog();
    test_tls_policy();
    test_trace();
    puts("sbi: ok");
    return 0;
}
