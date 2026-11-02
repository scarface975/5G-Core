/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NF runtime end to end: health/readiness, metrics, and registration + heartbeat + deregistration against a mock NRF
 * built from the same SBI library. */
#define _DEFAULT_SOURCE
#include <stdatomic.h>
#include <unistd.h>

#include "g5c/nfcore.h"
#include "g5c/testkit.h"

static atomic_int registrations, heartbeats, deregistrations;
static g5c_json *last_profile;
static pthread_mutex_t pmu = PTHREAD_MUTEX_INITIALIZER;

static void nrf_put(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *p = g5c_req_json(req, resp);
    (void)ctx;
    if (p == NULL)
        return;
    g5c_json_set_int(p, "heartBeatTimer", 1);
    pthread_mutex_lock(&pmu);
    g5c_json_free(last_profile);
    last_profile = g5c_json_dup(p);
    pthread_mutex_unlock(&pmu);
    atomic_fetch_add(&registrations, 1);
    g5c_resp_json(resp, 201, p);
    g5c_json_free(p);
}

static void nrf_patch(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    TK_ASSERT(strcmp(g5c_req_header(req, "content-type"), "application/json-patch+json") == 0);
    atomic_fetch_add(&heartbeats, 1);
    g5c_resp_status(resp, 204);
}

static void nrf_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    atomic_fetch_add(&deregistrations, 1);
    g5c_resp_status(resp, 204);
}

static void hello(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *o = g5c_json_new_obj();
    (void)ctx;
    g5c_json_set_str(o, "hello", g5c_req_param(req, "who"));
    g5c_resp_json(resp, 200, o);
    g5c_json_free(o);
}

static g5c_nf *make_nf(const char *nrf_uri)
{
    char yaml[512], err[200];
    g5c_json *j;
    g5c_common c;
    g5c_nf *nf;
    snprintf(yaml, sizeof yaml,
             "name: udm-test\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\n%s%s%s\n",
             nrf_uri ? "nrf: { uri: '" : "", nrf_uri ? nrf_uri : "", nrf_uri ? "' }" : "");
    j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    TK_ASSERT(j != NULL && g5c_common_parse(j, &c, err, sizeof err) == 0);
    g5c_json_free(j);
    c.port = 0; /* the server picks a free port */
    free(c.address);
    c.address = g5c_xstrdup("127.0.0.1");
    nf = g5c_nf_new(&c, err, sizeof err);
    TK_ASSERT(nf != NULL);
    return nf;
}

static void test_health_and_metrics(void)
{
    g5c_nf *nf = make_nf(NULL);
    g5c_router *routes = g5c_router_new();
    g5c_nrf_reg reg = {"UDM", NULL, 0, NULL};
    g5c_nf_inst *run;
    g5c_client *c = g5c_client_new(2000, NULL);
    char base[64], url[128], err[200];
    g5c_resp out;
    g5c_router_route(routes, "GET", "/hello/{who}", hello, NULL);
    /* a port of 0 is rejected by validation in real configs; the server may still pick one */
    run = g5c_nf_start(nf, routes, &reg, err, sizeof err);
    TK_ASSERT(run != NULL);
    snprintf(base, sizeof base, "http://127.0.0.1:%u", g5c_nf_inst_port(run));

#define GET(path, want)                                                                           \
    do {                                                                                          \
        snprintf(url, sizeof url, "%s%s", base, path);                                            \
        TK_ASSERT(g5c_client_get(c, url, &out, err, sizeof err) == 0);                            \
        TK_ASSERT(out.status == (want));                                                          \
    } while (0)
    GET("/health/live", 200);
    g5c_resp_free(&out);
    GET("/health/ready", 200);
    g5c_resp_free(&out);
    GET("/hello/world", 200);
    g5c_resp_free(&out);
    GET("/nope", 404);
    g5c_resp_free(&out);
    GET("/metrics", 200);
    TK_ASSERT(strstr((char *)out.body, "g5c_sbi_requests_total{method=\"GET\",route=\"/hello/{who}\",status=\"200\"} 1") !=
              NULL);
    TK_ASSERT(strstr((char *)out.body, "route=\"unmatched\"") != NULL);
    TK_ASSERT(strstr((char *)out.body, "g5c_sbi_request_duration_seconds_count") != NULL);
    g5c_resp_free(&out);
    atomic_store(&nf->ready, false);
    GET("/health/ready", 503);
    g5c_resp_free(&out);
#undef GET
    g5c_nf_stop(run);
    g5c_client_free(c);
    g5c_nf_free(nf);
}

static void test_nrf_registration(void)
{
    g5c_router *mock = g5c_router_new();
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_server *nrf;
    char nrf_uri[64], err[200];
    g5c_nf *nf;
    g5c_router *routes = g5c_router_new();
    static const g5c_svc svcs[] = {{"nudm-ueau", "v1"}, {"nudm-sdm", "v2"}};
    g5c_nrf_reg reg = {"UDM", svcs, 2, NULL};
    g5c_nf_inst *run;
    g5c_router_route(mock, "PUT", "/nnrf-nfm/v1/nf-instances/{id}", nrf_put, NULL);
    g5c_router_route(mock, "PATCH", "/nnrf-nfm/v1/nf-instances/{id}", nrf_patch, NULL);
    g5c_router_route(mock, "DELETE", "/nnrf-nfm/v1/nf-instances/{id}", nrf_delete, NULL);
    nrf = g5c_server_start(&cfg, mock, err, sizeof err);
    TK_ASSERT(nrf != NULL);
    snprintf(nrf_uri, sizeof nrf_uri, "http://127.0.0.1:%u", g5c_server_port(nrf));

    nf = make_nf(nrf_uri);
    run = g5c_nf_start(nf, routes, &reg, err, sizeof err);
    TK_ASSERT(run != NULL);
    for (int i = 0; i < 100 && atomic_load(&heartbeats) < 2; i++)
        usleep(50 * 1000);
    TK_ASSERT(atomic_load(&registrations) == 1);
    TK_ASSERT(atomic_load(&heartbeats) >= 2); /* heartBeatTimer 1 s -> 0.8 s interval */
    pthread_mutex_lock(&pmu);
    TK_ASSERT(last_profile != NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(last_profile, "nfType"), "UDM") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(last_profile, "nfInstanceId"), nf->instance_id) == 0);
    TK_ASSERT(g5c_json_len(g5c_json_get(last_profile, "nfServices")) == 2);
    {
        const g5c_json *s0 = g5c_json_at(g5c_json_get(last_profile, "nfServices"), 1);
        TK_ASSERT(strcmp(g5c_json_get_str(s0, "serviceName"), "nudm-sdm") == 0);
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(s0, "versions"), 0), "apiFullVersion"), "2.0.0") == 0);
    }
    pthread_mutex_unlock(&pmu);
    g5c_nf_stop(run);
    TK_ASSERT(atomic_load(&deregistrations) == 1);
    g5c_nf_free(nf);
    g5c_server_stop(nrf);
    g5c_router_free(mock);
    g5c_json_free(last_profile);
}

/* The same service in two API versions is one service of the profile with two versions (the UDR serves nudr-dr v1 and v2). */
static void test_profile_versions(void)
{
    static const g5c_svc svcs[] = {{"nudr-dr", "v1"}, {"nudr-dr", "v2"}, {"nudr-group-id-map", "v1"}};
    g5c_json *p = g5c_nrf_profile("c22f4910-cc36-43e1-a33e-e213b6aba908", "UDR", "127.0.0.1", 7790, "http", "001", "01", svcs, 3);
    const g5c_json *services = g5c_json_get(p, "nfServices"), *dr, *vers;
    TK_ASSERT(g5c_json_len(services) == 2);
    dr = g5c_json_at(services, 0);
    TK_ASSERT(strcmp(g5c_json_get_str(dr, "serviceName"), "nudr-dr") == 0);
    vers = g5c_json_get(dr, "versions");
    TK_ASSERT(g5c_json_len(vers) == 2);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(vers, 0), "apiVersionInUri"), "v1") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(vers, 1), "apiVersionInUri"), "v2") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(vers, 1), "apiFullVersion"), "2.0.0") == 0);
    TK_ASSERT(g5c_json_len(g5c_json_get(g5c_json_at(services, 1), "versions")) == 1);
    g5c_json_free(p);
}

static void test_secret(void)
{
    char err[100], *s;
    setenv("G5C_TEST_SECRET", "from-env", 1);
    s = g5c_secret_from_env_or_file("G5C_TEST_SECRET", "/nonexistent", err, sizeof err);
    TK_ASSERT(s && strcmp(s, "from-env") == 0);
    free(s);
    unsetenv("G5C_TEST_SECRET");
    TK_ASSERT(g5c_secret_from_env_or_file("G5C_TEST_SECRET", "/nonexistent", err, sizeof err) == NULL && err[0] != 0);
    TK_ASSERT(g5c_secret_from_env_or_file("G5C_TEST_SECRET", NULL, err, sizeof err) == NULL && err[0] == 0);
}

int main(void)
{
    g5c_log_init("error", false);
    test_health_and_metrics();
    test_nrf_registration();
    test_secret();
    test_profile_versions();
    puts("nfcore: ok");
    return 0;
}
