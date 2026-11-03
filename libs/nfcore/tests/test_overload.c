/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Overload and rate control: a bucket per client address, 429 + Retry-After + 3gpp-Sbi-Oci, 3gpp-Sbi-Lci on the answers, health and metrics never limited, the guard order, the configuration,
 * a function started from its configuration, and a client that backs off for as long as the producer asks (over a real HTTP/2 connection). */
#define _DEFAULT_SOURCE
#include <stdatomic.h>
#include <unistd.h>

#include "g5c/nfcore.h"
#include "g5c/testkit.h"

static atomic_int handled;

static void h_ok(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    atomic_fetch_add(&handled, 1);
    g5c_resp_status(resp, 200);
}

static void h_busy(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    atomic_fetch_add(&handled, 1);
    g5c_resp_problem_simple(resp, 503, "SYSTEM_FAILURE", "busy");
    g5c_resp_header(resp, "retry-after", "1");
}

static int needs_token(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    if (g5c_req_header(req, "authorization") != NULL)
        return 0;
    g5c_resp_problem_simple(resp, 401, "UNAUTHORIZED", "token needed");
    return 1;
}

static int call(g5c_router *r, const char *peer, const char *path, g5c_resp *resp, const char *auth)
{
    g5c_req req;
    g5c_req_init(&req);
    req.method = g5c_xstrdup("GET");
    req.path = g5c_xstrdup(path);
    snprintf(req.peer, sizeof req.peer, "%s", peer);
    if (auth != NULL)
        g5c_req_add_header(&req, "authorization", auth);
    g5c_resp_init(resp);
    g5c_router_dispatch(r, &req, resp);
    g5c_req_free(&req);
    return resp->status;
}

static g5c_overload_cfg cfg(unsigned rate, unsigned burst, unsigned retry, unsigned capacity)
{
    g5c_overload_cfg c = {0};
    c.enabled = true;
    c.rate_per_source = rate;
    c.burst = burst;
    c.retry_after_s = retry;
    c.capacity_rps = capacity;
    return c;
}

static void test_buckets(void)
{
    g5c_router *r = g5c_router_new();
    g5c_registry *reg = g5c_registry_new();
    g5c_overload_cfg c = cfg(10, 3, 2, 100);
    g5c_overload *o;
    g5c_resp resp;
    unsigned validity = 0, reduction = 0, load = 0;
    int ok_a = 0, bad_a = 0, ok_b = 0;
    g5c_router_route(r, "GET", "/x", h_ok, NULL);
    g5c_router_route(r, "GET", "/health/live", h_ok, NULL);
    g5c_router_route(r, "GET", "/metrics", h_ok, NULL);
    o = g5c_overload_new(&c, "11111111-2222-3333-4444-555555555555", reg);
    g5c_overload_attach(o, r);

    for (int i = 0; i < 8; i++) { /* one client: the bucket of 3, then 429 */
        int st = call(r, "10.0.0.1", "/x", &resp, NULL);
        if (st == 200) {
            ok_a++;
            TK_ASSERT(g5c_sbi_parse_lci(g5c_resp_header_get(&resp, "3gpp-sbi-lci"), &load) && load <= 100); /* the answers carry the load */
            TK_ASSERT(strstr(g5c_resp_header_get(&resp, "3gpp-sbi-lci"), "NF-Instance: 11111111-2222-3333-4444-555555555555") != NULL);
        } else {
            TK_ASSERT(st == 429);
            bad_a++;
            TK_ASSERT(strcmp(g5c_resp_header_get(&resp, "retry-after"), "2") == 0);
            TK_ASSERT(g5c_sbi_parse_oci(g5c_resp_header_get(&resp, "3gpp-sbi-oci"), &validity, &reduction) && validity == 2 && reduction >= 1 && reduction <= 100);
            TK_ASSERT(strstr((char *)resp.body, "TOO_MANY_REQUESTS") != NULL);
        }
        g5c_resp_free(&resp);
    }
    TK_ASSERT(ok_a == 3 && bad_a == 5);
    for (int i = 0; i < 3; i++) { /* another client has a bucket of its own */
        if (call(r, "10.0.0.2", "/x", &resp, NULL) == 200)
            ok_b++;
        g5c_resp_free(&resp);
    }
    TK_ASSERT(ok_b == 3);
    for (int i = 0; i < 20; i++) { /* health and metrics are never limited, not even for the client that is */
        TK_ASSERT(call(r, "10.0.0.1", "/health/live", &resp, NULL) == 200);
        g5c_resp_free(&resp);
        TK_ASSERT(call(r, "10.0.0.1", "/metrics", &resp, NULL) == 200);
        g5c_resp_free(&resp);
    }
    usleep(400000); /* 10/s: four tokens, the bucket holds three */
    ok_a = 0;
    for (int i = 0; i < 6; i++) {
        if (call(r, "10.0.0.1", "/x", &resp, NULL) == 200)
            ok_a++;
        g5c_resp_free(&resp);
    }
    TK_ASSERT(ok_a >= 3 && ok_a <= 4);
    {
        char *m = g5c_registry_render(reg);
        TK_ASSERT(strstr(m, "g5c_overload_rejected_total{reason=\"rate\"}") != NULL && strstr(m, "g5c_overload_load_percent") != NULL);
        free(m);
    }
    g5c_router_free(r);
    g5c_overload_free(o);
    g5c_registry_free(reg);
}

/* the overload check is outermost: a client over its rate is turned away before its token is looked at */
static void test_guard_order(void)
{
    g5c_router *r = g5c_router_new();
    g5c_registry *reg = g5c_registry_new();
    g5c_overload_cfg c = cfg(5, 2, 1, 0);
    g5c_overload *o;
    g5c_resp resp;
    g5c_router_route(r, "GET", "/x", h_ok, NULL);
    g5c_router_set_guard(r, needs_token, NULL); /* the token check was there first */
    o = g5c_overload_new(&c, NULL, reg);
    g5c_overload_attach(o, r);
    TK_ASSERT(call(r, "10.0.0.1", "/x", &resp, "Bearer t") == 200);
    g5c_resp_free(&resp);
    TK_ASSERT(call(r, "10.0.0.1", "/x", &resp, "Bearer t") == 200);
    g5c_resp_free(&resp);
    TK_ASSERT(call(r, "10.0.0.1", "/x", &resp, "Bearer t") == 429);
    TK_ASSERT(g5c_resp_header_get(&resp, "3gpp-sbi-lci") == NULL); /* no capacity configured: no load header */
    g5c_resp_free(&resp);
    TK_ASSERT(call(r, "10.0.0.1", "/x", &resp, NULL) == 429); /* over the rate and without a token: 429, not 401 */
    g5c_resp_free(&resp);
    TK_ASSERT(call(r, "10.0.0.9", "/x", &resp, NULL) == 401); /* within its rate, the next guard speaks */
    g5c_resp_free(&resp);
    g5c_router_free(r);
    g5c_overload_free(o);
    g5c_registry_free(reg);
}

/* many sources: the table recycles idle entries and never fails */
static void test_many_sources(void)
{
    g5c_router *r = g5c_router_new();
    g5c_registry *reg = g5c_registry_new();
    g5c_overload_cfg c = cfg(1, 1, 1, 0);
    g5c_overload *o;
    g5c_resp resp;
    char peer[48];
    int ok = 0;
    g5c_router_route(r, "GET", "/x", h_ok, NULL);
    o = g5c_overload_new(&c, NULL, reg);
    g5c_overload_attach(o, r);
    for (int i = 0; i < 20000; i++) {
        snprintf(peer, sizeof peer, "10.%d.%d.%d", (i >> 16) & 255, (i >> 8) & 255, i & 255);
        if (call(r, peer, "/x", &resp, NULL) == 200)
            ok++;
        g5c_resp_free(&resp);
    }
    TK_ASSERT(ok > 15000); /* every new source starts with a full bucket */
    g5c_router_free(r);
    g5c_overload_free(o);
    g5c_registry_free(reg);
}

static int parse_overload(const char *section, char *err, size_t errcap, g5c_common *out)
{
    char yaml[1024];
    g5c_json *j;
    int rc;
    snprintf(yaml, sizeof yaml, "name: x\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 7777 }\n%s\n", section);
    j = g5c_yaml_parse(yaml, strlen(yaml), err, errcap);
    TK_ASSERT(j != NULL);
    rc = g5c_common_parse(j, out, err, errcap);
    g5c_json_free(j);
    return rc;
}

static void test_config(void)
{
    g5c_common c;
    char err[200];
    TK_ASSERT(parse_overload("overload: { rate_per_source: 100, retry_after_s: 3, capacity_rps: 5000 }", err, sizeof err, &c) == 0);
    TK_ASSERT(c.overload.enabled && c.overload.rate_per_source == 100 && c.overload.burst == 200 && c.overload.retry_after_s == 3 && c.overload.capacity_rps == 5000);
    g5c_common_free(&c);
    TK_ASSERT(parse_overload("overload: { capacity_rps: 10 }", err, sizeof err, &c) == 0 && c.overload.burst == 1 && c.overload.retry_after_s == 1);
    g5c_common_free(&c);
    TK_ASSERT(parse_overload("log: { level: info }", err, sizeof err, &c) == 0 && !c.overload.enabled);
    g5c_common_free(&c);
    {
        static const struct {
            const char *y, *want;
        } bad[] = {
            {"overload: {}", "needs `rate_per_source` or `capacity_rps`"},
            {"overload: 5", "must be a mapping"},
            {"overload: { rate_per_source: 0 }", "overload.rate_per_source"},
            {"overload: { rate_per_source: 5, burst: 0 }", "overload.burst"},
            {"overload: { rate_per_source: 5, retry_after_s: 61 }", "overload.retry_after_s"},
            {"overload: { rate_per_source: 5, capacity_rps: -1 }", "overload.capacity_rps"},
            {"overload: { rate_per_source: five }", "overload.rate_per_source"},
            {"overload: { rate_per_source: 5, surprise: 1 }", "overload"},
        };
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
            TK_ASSERT(parse_overload(bad[i].y, err, sizeof err, &c) != 0);
            if (strstr(err, bad[i].want) == NULL)
                TK_FAIL("config %zu: `%s` not in `%s`", i, bad[i].want, err);
        }
    }
}

/* the configuration reaches a running function: /hello is limited, health and metrics are not, the counter is on /metrics */
static void test_function(void)
{
    char yaml[400], err[200], url[96], base[48];
    g5c_json *j;
    g5c_common c;
    g5c_nf *nf;
    g5c_nf_inst *run;
    g5c_router *routes = g5c_router_new();
    g5c_nrf_reg reg = {"UDM", NULL, 0, NULL};
    g5c_client *cl = g5c_client_new(2000, NULL);
    g5c_resp out;
    int limited = 0, passed = 0;
    snprintf(yaml, sizeof yaml, "name: udm-ov\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\noverload: { rate_per_source: 5, burst: 5, capacity_rps: 50 }\n");
    j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    TK_ASSERT(j != NULL && g5c_common_parse(j, &c, err, sizeof err) == 0);
    g5c_json_free(j);
    c.port = 0;
    free(c.address);
    c.address = g5c_xstrdup("127.0.0.1");
    nf = g5c_nf_new(&c, err, sizeof err);
    TK_ASSERT(nf != NULL);
    g5c_router_route(routes, "GET", "/hello", h_ok, NULL);
    run = g5c_nf_start(nf, routes, &reg, err, sizeof err);
    TK_ASSERT(run != NULL);
    snprintf(base, sizeof base, "http://127.0.0.1:%u", g5c_nf_inst_port(run));
    snprintf(url, sizeof url, "%s/hello", base);
    for (int i = 0; i < 25; i++) {
        TK_ASSERT(g5c_client_get(cl, url, &out, err, sizeof err) == 0 || strstr(err, "back off") != NULL);
        if (out.status == 429)
            limited++;
        else if (out.status == 200)
            passed++;
        g5c_resp_free(&out);
        g5c_client_free(cl);
        cl = g5c_client_new(2000, NULL); /* each request on its own: the back-off is the client's, not what is tested here */
    }
    TK_ASSERT(passed >= 5 && passed <= 7 && limited >= 15);
    snprintf(url, sizeof url, "%s/metrics", base);
    TK_ASSERT(g5c_client_get(cl, url, &out, err, sizeof err) == 0 && out.status == 200);
    TK_ASSERT(strstr((char *)out.body, "g5c_overload_rejected_total{reason=\"rate\"}") != NULL);
    g5c_resp_free(&out);
    snprintf(url, sizeof url, "%s/health/ready", base);
    TK_ASSERT(g5c_client_get(cl, url, &out, err, sizeof err) == 0 && out.status == 200);
    g5c_resp_free(&out);
    g5c_client_free(cl);
    g5c_nf_stop(run);
    g5c_nf_free(nf);
}

/* a client that obeys: after a 429 with an overload reduction it stops sending part of its requests, after a 503 with Retry-After it sends none until the time is up */
static void test_client_backs_off(void)
{
    g5c_router *r = g5c_router_new();
    g5c_registry *reg = g5c_registry_new();
    g5c_overload_cfg c = cfg(5, 5, 1, 0);
    g5c_overload *o = g5c_overload_new(&c, NULL, reg);
    g5c_server_cfg sc = {.address = "127.0.0.1", .port = 0, .tls = NULL};
    g5c_server *srv;
    g5c_client *cl = g5c_client_new(2000, NULL);
    g5c_counter *k = g5c_counter_get(reg, "g5c_sbi_client_backoff_total", "x", NULL, 0);
    g5c_resp resp;
    char err[200], url[96], busy[96];
    int ok = 0, st429 = 0, skipped = 0;
    g5c_router_route(r, "GET", "/x", h_ok, NULL);
    g5c_router_route(r, "GET", "/busy", h_busy, NULL);
    g5c_overload_attach(o, r);
    srv = g5c_server_start(&sc, r, err, sizeof err);
    TK_ASSERT(srv != NULL);
    snprintf(url, sizeof url, "http://127.0.0.1:%u/x", g5c_server_port(srv));
    snprintf(busy, sizeof busy, "http://127.0.0.1:%u/busy", g5c_server_port(srv));
    g5c_client_set_backoff_counter(cl, k);
    atomic_store(&handled, 0);

    for (int i = 0; i < 40; i++) {
        int rc = g5c_client_get(cl, url, &resp, err, sizeof err);
        if (rc == G5C_SBI_E_OVERLOAD) {
            skipped++;
            continue;
        }
        TK_ASSERT(rc == 0);
        if (resp.status == 200)
            ok++;
        else if (resp.status == 429)
            st429++;
        g5c_resp_free(&resp);
    }
    TK_ASSERT(ok >= 5 && ok <= 7);        /* the bucket of 5 (and a refill) */
    TK_ASSERT(st429 >= 1 && skipped >= 1); /* the server said no, and then the client stopped asking for part of the time */
    TK_ASSERT(atomic_load(&handled) == ok);
    TK_ASSERT(g5c_counter_value(k) == (uint64_t)skipped);
    TK_ASSERT(st429 + skipped + ok == 40);

    usleep(1300000); /* the period of validity is over and the bucket is full again */
    TK_ASSERT(g5c_client_get(cl, url, &resp, err, sizeof err) == 0 && resp.status == 200);
    g5c_resp_free(&resp);

    TK_ASSERT(g5c_client_get(cl, busy, &resp, err, sizeof err) == 0 && resp.status == 503); /* Retry-After: 1 and no overload header */
    g5c_resp_free(&resp);
    TK_ASSERT(g5c_client_get(cl, busy, &resp, err, sizeof err) == G5C_SBI_E_OVERLOAD && strstr(err, "back off") != NULL); /* nothing is sent for a second */
    TK_ASSERT(g5c_client_get(cl, url, &resp, err, sizeof err) == G5C_SBI_E_OVERLOAD); /* the producer, not the path, asked for the pause */
    usleep(1200000);
    TK_ASSERT(g5c_client_get(cl, url, &resp, err, sizeof err) == 0 && resp.status == 200);
    g5c_resp_free(&resp);

    g5c_client_free(cl);
    g5c_server_stop(srv);
    g5c_router_free(r);
    g5c_overload_free(o);
    g5c_registry_free(reg);
}

int main(void)
{
    test_buckets();
    test_guard_order();
    test_many_sources();
    test_config();
    test_function();
    test_client_backs_off();
    printf("overload: PASS\n");
    return 0;
}
