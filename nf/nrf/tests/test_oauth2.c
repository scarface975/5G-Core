/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* OAuth2 access tokens between functions (TS 33.501 13.4.1) end to end */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "g5c/jwt.h"
#include "g5c/nrf.h"
#include "g5c/oauth.h"
#include "g5c/testkit.h"

static const char *UDM1 = "11111111-1111-4111-8111-111111111111";
static const char *AMF1 = "44444444-4444-4444-8444-444444444444";
static const char *AUSF1 = "55555555-5555-4555-8555-555555555555";

typedef struct {
    g5c_nf *nf;
    nrf *n;
    g5c_router *r;
    g5c_server *srv;
    char base[64];
} nrf_env;

static void nrf_up(nrf_env *e, unsigned lifetime)
{
    char yaml[400], err[300];
    g5c_json *j;
    g5c_common common;
    g5c_server_cfg sc = {"127.0.0.1", 0, NULL};
    memset(e, 0, sizeof *e);
    snprintf(yaml, sizeof yaml, "name: nrf-test\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\nregistry:\n  heartbeat_timer: 600\n  oauth2: { enabled: true, token_lifetime: %u }\n", lifetime);
    j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    TK_ASSERT(j != NULL && g5c_common_parse(j, &common, err, sizeof err) == 0);
    common.port = 0;
    e->nf = g5c_nf_new(&common, err, sizeof err);
    TK_ASSERT(e->nf != NULL);
    e->n = nrf_from_config(j, e->nf, err, sizeof err);
    TK_ASSERT(e->n != NULL);
    g5c_json_free(j);
    e->r = nrf_router(e->n);
    e->srv = g5c_server_start(&sc, e->r, err, sizeof err);
    TK_ASSERT(e->srv != NULL);
    snprintf(e->base, sizeof e->base, "http://127.0.0.1:%u", g5c_server_port(e->srv));
    nrf_set_self_uri(e->n, e->base);
    TK_ASSERT(nrf_start(e->n, err, sizeof err) == 0);
}

static void nrf_down(nrf_env *e)
{
    g5c_server_stop(e->srv);
    nrf_destroy(e->n);
    g5c_router_free(e->r);
    g5c_nf_free(e->nf);
}

static void register_nf(g5c_client *c, const nrf_env *e, const char *id, const char *type, const g5c_svc *svcs, size_t n)
{
    g5c_json *p = g5c_nrf_profile(id, type, "127.0.0.1", 7777, "http", "001", "01", svcs, n);
    TK_ASSERT(g5c_nrf_register(c, e->base, p, NULL) == 0);
    g5c_json_free(p);
}

/* ---- the producer: a router with two services, things the check leaves alone, and a guard of its own ---- */

static int g_own_guard_calls, g_fail_once;

static int own_guard(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    g_own_guard_calls++;
    if (g_fail_once > 0) { /* a producer that does not take the token this once (its key changed, say) */
        g_fail_once--;
        g5c_resp_problem_simple(resp, 401, "UNAUTHORIZED", "not this token");
        return 1;
    }
    if (g5c_req_header(req, "x-deny") != NULL) {
        g5c_resp_problem_simple(resp, 418, "TEAPOT", "the guard of the function itself says no");
        return 1;
    }
    return 0;
}

static void ok_handler(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    g5c_resp_status(resp, 200);
}

typedef struct {
    g5c_client *plain;
    g5c_router *r;
    g5c_server *srv;
    g5c_oauth_rs *rs;
    g5c_registry *metrics;
    char base[64];
} prod_env;

static void prod_up(prod_env *p, g5c_client *plain, const char *nrf_base, const char *own_id, unsigned leeway)
{
    static const char *const svcs[] = {"nudm-sdm", "nudm-uecm"};
    g5c_server_cfg sc = {"127.0.0.1", 0, NULL};
    char err[200];
    memset(p, 0, sizeof *p);
    p->plain = plain;
    p->r = g5c_router_new();
    g5c_router_route(p->r, "GET", "/nudm-sdm/v2/{id}/am-data", ok_handler, NULL);
    g5c_router_route(p->r, "GET", "/nudm-uecm/v1/{id}/registrations", ok_handler, NULL);
    g5c_router_route_flags(p->r, "PUT", "/nudm-sdm/v2/{id}/own", ok_handler, NULL, G5C_ROUTE_OWN_AUTH);
    g5c_router_route(p->r, "GET", "/health/live", ok_handler, NULL);
    g5c_router_route(p->r, "POST", "/nudm-callback/v1/notify", ok_handler, NULL);
    g5c_router_route(p->r, "GET", "/admin/v1/x", ok_handler, NULL);
    g5c_router_set_guard(p->r, own_guard, NULL);
    p->metrics = g5c_registry_new();
    p->rs = g5c_oauth_rs_new(plain, nrf_base, "UDM", own_id, svcs, 2, leeway, 600, p->metrics);
    g5c_oauth_rs_attach(p->rs, p->r);
    p->srv = g5c_server_start(&sc, p->r, err, sizeof err);
    TK_ASSERT(p->srv != NULL);
    snprintf(p->base, sizeof p->base, "http://127.0.0.1:%u", g5c_server_port(p->srv));
}

static void prod_down(prod_env *p)
{
    g5c_server_stop(p->srv);
    g5c_router_free(p->r);
    g5c_oauth_rs_free(p->rs);
    g5c_registry_free(p->metrics);
}

typedef struct {
    int status;
    char www[200], cause[40];
} A;

static A req_with(g5c_client *c, const char *method, const char *url, const char *token)
{
    char auth[1400], err[100];
    g5c_kv h = {"authorization", auth};
    g5c_resp r;
    A a;
    memset(&a, 0, sizeof a);
    snprintf(auth, sizeof auth, "Bearer %s", token != NULL ? token : "");
    TK_ASSERT(g5c_client_request(c, method, url, token != NULL ? &h : NULL, token != NULL ? 1 : 0, NULL, NULL, 0, &r, err, sizeof err) == 0);
    a.status = r.status;
    snprintf(a.www, sizeof a.www, "%s", g5c_resp_header_get(&r, "www-authenticate") ? g5c_resp_header_get(&r, "www-authenticate") : "");
    {
        char *c2 = g5c_resp_problem_cause(&r);
        snprintf(a.cause, sizeof a.cause, "%s", c2 ? c2 : "");
        free(c2);
    }
    g5c_resp_free(&r);
    return a;
}

/* a token straight from the NRF */
static char *nrf_token(g5c_client *c, const char *nrf_base, const char *id, const char *type, const char *target_type, const char *target_id, const char *scope)
{
    char *url = g5c_xasprintf("%s/oauth2/token", nrf_base), *body, err[100];
    g5c_resp r;
    g5c_json *j;
    char *tok = NULL;
    body = target_id != NULL ? g5c_xasprintf("grant_type=client_credentials&nfInstanceId=%s&nfType=%s&targetNfInstanceId=%s&scope=%s", id, type, target_id, scope)
                             : g5c_xasprintf("grant_type=client_credentials&nfInstanceId=%s&nfType=%s&targetNfType=%s&scope=%s", id, type, target_type, scope);
    TK_ASSERT(g5c_client_request(c, "POST", url, NULL, 0, "application/x-www-form-urlencoded", body, strlen(body), &r, err, sizeof err) == 0);
    j = r.status == 200 ? g5c_resp_parse_json(&r) : NULL;
    if (j != NULL && g5c_json_get_str(j, "access_token") != NULL)
        tok = g5c_xstrdup(g5c_json_get_str(j, "access_token"));
    g5c_json_free(j);
    g5c_resp_free(&r);
    free(url);
    free(body);
    return tok;
}

static void sleep_ms(int ms)
{
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&t, NULL);
}

static void test_service_table(void)
{
    TK_ASSERT(strcmp(g5c_oauth_service_nf_type("nudm-sdm"), "UDM") == 0 && strcmp(g5c_oauth_service_nf_type("nsmf-pdusession"), "SMF") == 0 &&
              strcmp(g5c_oauth_service_nf_type("nbsf-management"), "BSF") == 0 && strcmp(g5c_oauth_service_nf_type("nnrf-disc"), "NRF") == 0 &&
              strcmp(g5c_oauth_service_nf_type("npcf-policyauthorization"), "PCF") == 0 && strcmp(g5c_oauth_service_nf_type("nudr-dr"), "UDR") == 0);
    TK_ASSERT(g5c_oauth_service_nf_type("namf-callback") == NULL && g5c_oauth_service_nf_type("admin") == NULL && g5c_oauth_service_nf_type(NULL) == NULL &&
              g5c_oauth_service_nf_type("3gpp-traffic-influence") == NULL);
}

static void test_guard_and_tokens(void)
{
    static const g5c_svc udm_svcs[] = {{"nudm-sdm", "v2"}, {"nudm-uecm", "v1"}};
    static const g5c_svc ausf_svcs[] = {{"nausf-auth", "v1"}};
    nrf_env e;
    prod_env p;
    g5c_client *plain = g5c_client_new(3000, NULL), *amf_client = g5c_client_new(3000, NULL);
    g5c_registry *amf_metrics = g5c_registry_new();
    g5c_oauth_client *oc;
    char url[200], *tok, *tok_ausf, *text;
    A a;
    nrf_up(&e, 5);
    register_nf(plain, &e, UDM1, "UDM", udm_svcs, 2);
    register_nf(plain, &e, AUSF1, "AUSF", ausf_svcs, 1);
    register_nf(plain, &e, AMF1, "AMF", NULL, 0);
    prod_up(&p, plain, e.base, UDM1, 0);
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/imsi-001010000000001/am-data", p.base);

    /* no token, a damaged one, one that is not a JWT */
    a = req_with(plain, "GET", url, NULL);
    TK_ASSERT(a.status == 401 && strstr(a.www, "Bearer") != NULL && strstr(a.www, "invalid_request") != NULL && strcmp(a.cause, "UNAUTHORIZED") == 0);
    a = req_with(plain, "GET", url, "not-a-token");
    TK_ASSERT(a.status == 401 && strstr(a.www, "invalid_token") != NULL);
    a = req_with(plain, "GET", url, "eyJhbGciOiJub25lIn0.e30."); /* alg none */
    TK_ASSERT(a.status == 401);
    TK_ASSERT(g_own_guard_calls == 0); /* the guard of the function itself is not reached by what was refused */

    /* the real thing: the consumer's client gets a token by itself and sends it; it is asked for once and kept */
    oc = g5c_oauth_client_new(amf_client, e.base, "AMF", AMF1, amf_metrics);
    g5c_client_set_token_provider(amf_client, g5c_oauth_client_token, g5c_oauth_client_reject, oc);
    for (int i = 0; i < 20; i++) {
        a = req_with(amf_client, "GET", url, NULL);
        TK_ASSERT(a.status == 200);
    }
    text = g5c_registry_render(amf_metrics);
    TK_ASSERT(strstr(text, "g5c_oauth_token_requests_total{result=\"issued\"} 1") != NULL);
    free(text);
    TK_ASSERT(g_own_guard_calls == 20);
    /* the key id is the thumbprint of the key, so it is the same after the NRF restarts with the same key */
    {
        g5c_json *jw;
        char *u2 = g5c_xasprintf("%s/oauth2/jwks", e.base), err[100], *sum;
        g5c_resp rr;
        TK_ASSERT(g5c_client_get(plain, u2, &rr, err, sizeof err) == 0 && rr.status == 200);
        jw = g5c_resp_parse_json(&rr);
        g5c_resp_free(&rr);
        {
            g5c_jwt_key *pub = g5c_jwt_key_from_jwk(g5c_json_at(g5c_json_get(jw, "keys"), 0), err, sizeof err);
            TK_ASSERT(pub != NULL);
            sum = g5c_jwt_key_thumbprint(pub);
            TK_ASSERT(sum != NULL && strcmp(sum, g5c_json_get_str(g5c_json_at(g5c_json_get(jw, "keys"), 0), "kid")) == 0 && strlen(sum) == 43);
            free(sum);
            g5c_jwt_key_free(pub);
        }
        g5c_json_free(jw);
        free(u2);
        g_fail_once = 1;
        a = req_with(amf_client, "GET", url, NULL);
        TK_ASSERT(a.status == 200 && g_fail_once == 0);
        text = g5c_registry_render(amf_metrics);
        TK_ASSERT(strstr(text, "g5c_oauth_token_requests_total{result=\"issued\"} 2") != NULL);
        free(text);
    }
    /* a second service of the same producer needs its own token */
    snprintf(url + strlen(p.base), sizeof url - strlen(p.base), "/nudm-uecm/v1/imsi-001010000000001/registrations");
    a = req_with(amf_client, "GET", url, NULL);
    TK_ASSERT(a.status == 200);
    text = g5c_registry_render(amf_metrics);
    TK_ASSERT(strstr(text, "g5c_oauth_token_requests_total{result=\"issued\"} 3") != NULL);
    free(text);

    /* the guard of the function itself still runs for what passes */
    {
        char auth[1400], err[100];
        g5c_kv h[2] = {{"authorization", auth}, {"x-deny", "1"}};
        g5c_resp r;
        tok = nrf_token(plain, e.base, AMF1, "AMF", "UDM", NULL, "nudm-sdm");
        TK_ASSERT(tok != NULL);
        snprintf(auth, sizeof auth, "Bearer %s", tok);
        snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", p.base);
        TK_ASSERT(g5c_client_request(plain, "GET", url, h, 2, NULL, NULL, 0, &r, err, sizeof err) == 0 && r.status == 418);
        g5c_resp_free(&r);
    }

    /* scope: a token for nudm-sdm does not open nudm-uecm; audience: a token for the AUSF does not open the UDM */
    snprintf(url, sizeof url, "%s/nudm-uecm/v1/x/registrations", p.base);
    a = req_with(plain, "GET", url, tok);
    TK_ASSERT(a.status == 403 && strstr(a.www, "insufficient_scope") != NULL && strstr(a.www, "nudm-uecm") != NULL);
    tok_ausf = nrf_token(plain, e.base, AMF1, "AMF", "AUSF", NULL, "nausf-auth");
    TK_ASSERT(tok_ausf != NULL);
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", p.base);
    a = req_with(plain, "GET", url, tok_ausf);
    TK_ASSERT(a.status == 403 && strstr(a.www, "invalid_token") != NULL);
    free(tok_ausf);

    /* a token for this very instance (the audience is the instance id) opens it */
    {
        char *t2 = nrf_token(plain, e.base, AMF1, "AMF", NULL, UDM1, "nudm-sdm");
        TK_ASSERT(t2 != NULL);
        a = req_with(plain, "GET", url, t2);
        TK_ASSERT(a.status == 200);
        free(t2);
    }

    /* a damaged signature, the payload of another token, and a token signed by a key the NRF does not publish */
    {
        char bad[1400], *dot1, *dot2;
        g5c_jwt_key *other = g5c_jwt_key_generate(NULL, 0);
        g5c_json *claims = g5c_json_new_obj();
        char *forged;
        snprintf(bad, sizeof bad, "%s", tok);
        bad[strlen(bad) - 4] = bad[strlen(bad) - 4] == 'A' ? 'B' : 'A';
        a = req_with(plain, "GET", url, bad);
        TK_ASSERT(a.status == 401);
        dot1 = strchr(tok, '.');
        dot2 = strchr(dot1 + 1, '.');
        snprintf(bad, sizeof bad, "%.*s.%.*s.%s", (int)(dot1 - tok), tok, (int)(dot2 - dot1 - 1), dot1 + 1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        a = req_with(plain, "GET", url, bad);
        TK_ASSERT(a.status == 401);
        g5c_json_set_str(claims, "iss", "x");
        g5c_json_set_str(claims, "sub", AMF1);
        g5c_json_set_str(claims, "aud", "UDM");
        g5c_json_set_str(claims, "scope", "nudm-sdm");
        g5c_json_set_int(claims, "exp", (int64_t)time(NULL) + 300);
        forged = g5c_jwt_sign(other, "forged-key", claims);
        a = req_with(plain, "GET", url, forged);
        TK_ASSERT(a.status == 401);
        free(forged);
        g5c_json_free(claims);
        g5c_jwt_key_free(other);
    }

    /* what the check leaves alone */
    snprintf(url, sizeof url, "%s/health/live", p.base);
    a = req_with(plain, "GET", url, NULL);
    TK_ASSERT(a.status == 200);
    snprintf(url, sizeof url, "%s/nudm-callback/v1/notify", p.base);
    a = req_with(plain, "POST", url, NULL);
    TK_ASSERT(a.status == 200);
    snprintf(url, sizeof url, "%s/admin/v1/x", p.base);
    a = req_with(plain, "GET", url, NULL);
    TK_ASSERT(a.status == 200);
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/own", p.base); /* a route that authenticates its callers itself */
    a = req_with(plain, "PUT", url, NULL);
    TK_ASSERT(a.status == 200);
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", p.base);
    a = req_with(plain, "GET", url, NULL);
    TK_ASSERT(a.status == 401); /* while the route next to it is not */

    /* the consumer sends no token for what is not a service of a function, and leaves an Authorization header that is there */
    TK_ASSERT(g5c_oauth_client_token(oc, "POST", "http://127.0.0.1:1/namf-callback/v1/notify") == NULL);
    TK_ASSERT(g5c_oauth_client_token(oc, "GET", "http://127.0.0.1:1/health/live") == NULL);
    {
        char *t3 = g5c_oauth_client_token(oc, "GET", "http://127.0.0.1:1/nnrf-disc/v1/nf-instances?target-nf-type=UDM");
        TK_ASSERT(t3 != NULL); /* the NRF's own services take a token as well (optional, TS 33.501 13.3.1.3) */
        free(t3);
        TK_ASSERT(g5c_oauth_client_token(oc, "PUT", "http://127.0.0.1:1/nnrf-nfm/v1/nf-instances/abc") == NULL); /* the registration needs none */
    }
    {
        char auth[40], err[100];
        g5c_kv h = {"authorization", auth};
        g5c_resp r;
        snprintf(auth, sizeof auth, "Bearer static-provisioning-token");
        snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", p.base);
        TK_ASSERT(g5c_client_request(amf_client, "GET", url, &h, 1, NULL, NULL, 0, &r, err, sizeof err) == 0 && r.status == 401); /* sent as it was, not replaced */
        g5c_resp_free(&r);
    }

    /* the lifetime: a token lasts 5 s, the producer takes none past it; the consumer asks for another before it runs out */
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", p.base);
    sleep_ms(5300);
    a = req_with(plain, "GET", url, tok);
    TK_ASSERT(a.status == 401); /* tok is more than 5 s old */
    a = req_with(amf_client, "GET", url, NULL);
    TK_ASSERT(a.status == 200);
    text = g5c_registry_render(amf_metrics);
    TK_ASSERT(strstr(text, "g5c_oauth_token_requests_total{result=\"issued\"} 4") != NULL || strstr(text, "g5c_oauth_token_requests_total{result=\"issued\"} 5") != NULL);
    free(text);

    /* the counts the producer keeps */
    text = g5c_registry_render(p.metrics);
    TK_ASSERT(strstr(text, "g5c_oauth_checks_total{result=\"ok\"}") != NULL && strstr(text, "g5c_oauth_checks_total{result=\"missing\"}") != NULL &&
              strstr(text, "g5c_oauth_checks_total{result=\"scope\"} 1") != NULL && strstr(text, "g5c_oauth_checks_total{result=\"audience\"} 1") != NULL &&
              strstr(text, "g5c_oauth_checks_total{result=\"expired\"} 1") != NULL);
    free(text);

    free(tok);
    g5c_client_set_token_provider(amf_client, NULL, NULL, NULL);
    g5c_oauth_client_free(oc);
    prod_down(&p);
    nrf_down(&e);
    g5c_registry_free(amf_metrics);
    g5c_client_free(amf_client);
    g5c_client_free(plain);
}

/* a consumer whose token the NRF refuses sends none, and does not ask again for every request */
static void test_refused_and_unreachable(void)
{
    static const g5c_svc udm_svcs[] = {{"nudm-sdm", "v2"}};
    nrf_env e;
    prod_env p;
    g5c_client *plain = g5c_client_new(1500, NULL), *c = g5c_client_new(1500, NULL), *c2 = g5c_client_new(1500, NULL);
    g5c_registry *m = g5c_registry_new();
    g5c_oauth_client *oc, *dead;
    char url[200], *text;
    A a;
    nrf_up(&e, 60);
    register_nf(plain, &e, UDM1, "UDM", udm_svcs, 1);
    /* the AMF is not registered: the NRF answers invalid_client */
    prod_up(&p, plain, e.base, UDM1, 5);
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", p.base);
    oc = g5c_oauth_client_new(c, e.base, "AMF", AMF1, m);
    g5c_client_set_token_provider(c, g5c_oauth_client_token, g5c_oauth_client_reject, oc);
    for (int i = 0; i < 6; i++) {
        a = req_with(c, "GET", url, NULL);
        TK_ASSERT(a.status == 401);
    }
    text = g5c_registry_render(m);
    TK_ASSERT(strstr(text, "g5c_oauth_token_requests_total{result=\"failed\"} 1") != NULL); /* once, then it waits */
    free(text);
    g5c_client_set_token_provider(c, NULL, NULL, NULL);
    g5c_oauth_client_free(oc);
    prod_down(&p);
    /* the NRF cannot be reached: a token cannot be checked (503), and a consumer gets none */
    nrf_down(&e);
    prod_up(&p, plain, "http://127.0.0.1:1", UDM1, 5);
    snprintf(url, sizeof url, "%s/nudm-sdm/v2/x/am-data", p.base);
    a = req_with(plain, "GET", url, "aaaa.bbbb.cccc");
    TK_ASSERT(a.status == 503 || a.status == 401);
    dead = g5c_oauth_client_new(c2, "http://127.0.0.1:1", "AMF", AMF1, NULL);
    TK_ASSERT(g5c_oauth_client_token(dead, "GET", url) == NULL);
    g5c_oauth_client_free(dead);
    prod_down(&p);
    g5c_registry_free(m);
    g5c_client_free(c2);
    g5c_client_free(c);
    g5c_client_free(plain);
}

static void test_config(void)
{
    static const struct {
        const char *yaml, *want;
    } bad[] = {
        {"oauth2: 5\n", "oauth2"},
        {"oauth2: { surprise: 1 }\n", "oauth2"},
        {"oauth2: { enforce: maybe }\n", "oauth2.enforce"},
        {"oauth2: { enforce: true, leeway_s: 9000 }\nnrf: { uri: 'http://n:1' }\n", "oauth2.leeway_s"},
        {"oauth2: { acquire: true, jwks_refresh_s: 1 }\nnrf: { uri: 'http://n:1' }\n", "oauth2.jwks_refresh_s"},
        {"oauth2: { enforce: true }\n", "needs `nrf.uri`"},
        {"oauth2: { acquire: true }\n", "needs `nrf.uri`"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        char y[400], err[200];
        g5c_json *root;
        g5c_common c;
        int rc;
        snprintf(y, sizeof y, "name: x\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 7777 }\n%s", bad[i].yaml);
        root = g5c_yaml_parse(y, strlen(y), err, sizeof err);
        TK_ASSERT(root != NULL);
        rc = g5c_common_parse(root, &c, err, sizeof err);
        if (rc == 0) {
            rc = g5c_common_validate(&c, err, sizeof err);
            g5c_common_free(&c);
        }
        if (rc == 0 || strstr(err, bad[i].want) == NULL)
            TK_FAIL("config %zu: want an error with [%s], got [%s]", i, bad[i].want, err);
        g5c_json_free(root);
    }
    {
        char err[200];
        g5c_common c;
        static const char y[] = "name: x\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 7777 }\nnrf: { uri: 'http://n:1' }\noauth2: { enforce: true, acquire: true, leeway_s: 0, jwks_refresh_s: 30 }\n";
        g5c_json *root = g5c_yaml_parse(y, sizeof y - 1, err, sizeof err);
        TK_ASSERT(root != NULL && g5c_common_parse(root, &c, err, sizeof err) == 0 && g5c_common_validate(&c, err, sizeof err) == 0);
        TK_ASSERT(c.oauth2_enforce && c.oauth2_acquire && c.oauth2_leeway_s == 0 && c.oauth2_jwks_refresh_s == 30);
        g5c_common_free(&c);
        g5c_json_free(root);
    }
}

int main(void)
{
    g5c_log_init("error", false);
    test_service_table();
    test_config();
    test_guard_and_tokens();
    test_refused_and_unreachable();
    puts("oauth2: ok");
    return 0;
}
