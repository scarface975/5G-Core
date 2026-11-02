/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The NEF end to end, in process: configuration, the TrafficInfluence API against a real UDR (and the UDM that resolves GPSIs), the MonitoringEvent API against
 * a real UDM and a scripted AMF (Namf_EventExposure), the notifications to an AF (a real HTTP/2 callback server), the access control of the AFs, the state
 * file. */
#define _DEFAULT_SOURCE
#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "g5c/testkit.h"
#include "g5c/bsf.h"
#include "g5c/pcf.h"
#include "g5c/udm.h"
#include "g5c/udr.h"
#include "priv.h"

#define SUPI1 "imsi-001010000000001"
#define SUPI2 "imsi-001010000000002"
#define K_HEX "465b5ce8b199b49faa5f0a2ee238a6bc"
#define OP_HEX "cdc202d5123e20f62b6d676ac72cb318"
#define ADMIN "admin-token-0123456789"
#define PROV "provisioning-token-0123456789"
#define AF2_TOKEN "af2-bearer-token-0123456789"

/* ---- requests ------------------------------------------------------------------------------------------------------------ */

typedef struct {
    int status;
    g5c_json *json;
    char location[256], cause[64];
} R;

static R rq_h(g5c_router *rt, const char *method, const char *target, const char *body, const char *const *hdrs)
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
    req.authority = g5c_xstrdup("nef.test:80");
    if (body != NULL)
        g5c_req_add_header(&req, "content-type", "application/json");
    for (size_t i = 0; hdrs != NULL && hdrs[i] != NULL; i += 2)
        g5c_req_add_header(&req, hdrs[i], hdrs[i + 1]);
    if (body != NULL)
        g5c_req_set_body(&req, body, strlen(body));
    g5c_resp_init(&resp);
    g5c_router_dispatch(rt, &req, &resp);
    out.status = resp.status;
    out.json = g5c_resp_parse_json(&resp);
    snprintf(out.location, sizeof out.location, "%s", g5c_resp_header_get(&resp, "location") ? g5c_resp_header_get(&resp, "location") : "");
    if (out.json != NULL && g5c_json_get_str(out.json, "cause") != NULL)
        snprintf(out.cause, sizeof out.cause, "%s", g5c_json_get_str(out.json, "cause"));
    g5c_resp_free(&resp);
    g5c_req_free(&req);
    return out;
}

#define EXPECT(r, code)                                                                                                    \
    do {                                                                                                                   \
        if ((r).status != (code))                                                                                          \
            fprintf(stderr, "expected %d, got %d %s %s\n", (code), (r).status, (r).cause, (r).json ? g5c_json_to_string((r).json, NULL) : "-"); \
        TK_ASSERT((r).status == (code));                                                                                   \
    } while (0)

static void done(R *r)
{
    g5c_json_free(r->json);
    r->json = NULL;
}

/* a request over a real connection; the status, and the body in *out when asked for */
static int http(const char *method, const char *url, const char *body, const char *auth, g5c_json **out)
{
    g5c_client *c = g5c_client_new(3000, NULL);
    g5c_resp r;
    char *a = auth != NULL ? g5c_xasprintf("Bearer %s", auth) : NULL, err[160];
    g5c_kv h = {"authorization", a};
    int st = -1;
    if (g5c_client_request(c, method, url, a != NULL ? &h : NULL, a != NULL ? 1 : 0, "application/json", body, body != NULL ? strlen(body) : 0, &r, err, sizeof err) == 0) {
        st = r.status;
        if (out != NULL)
            *out = g5c_resp_parse_json(&r);
        g5c_resp_free(&r);
    }
    free(a);
    g5c_client_free(c);
    return st;
}

/* ---- scripted peers ----------------------------------------------------------------------------------------------------------- */

typedef struct {
    pthread_mutex_t mu;
    g5c_json *items[64];
    size_t n;
    int answer;
    char *immediate; /* the reportList (JSON text) the AMF answers a subscription with when it is asked for an immediate report */
    size_t deleted;
    char last_deleted[64];
    unsigned seq;
} sink_t;

static void sink_init(sink_t *s)
{
    memset(s, 0, sizeof *s);
    pthread_mutex_init(&s->mu, NULL);
    s->answer = 204;
}

static void sink_clear(sink_t *s)
{
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->n; i++)
        g5c_json_free(s->items[i]);
    s->n = 0;
    s->deleted = 0;
    pthread_mutex_unlock(&s->mu);
}

static void cb_handler(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    sink_t *s = ctx;
    g5c_json *j = g5c_req_json(req, resp);
    pthread_mutex_lock(&s->mu);
    if (j != NULL && s->n < 64)
        s->items[s->n++] = j;
    else
        g5c_json_free(j);
    pthread_mutex_unlock(&s->mu);
    g5c_resp_init(resp);
    g5c_resp_status(resp, s->answer);
}

static void amf_create(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    sink_t *s = ctx;
    g5c_json *j = g5c_req_json(req, resp), *o;
    bool imm = false;
    char id[32], loc[96];
    if (j == NULL)
        return;
    (void)g5c_json_get_bool(g5c_json_at(g5c_json_get(g5c_json_get(j, "subscription"), "eventList"), 0), "immediateFlag", &imm);
    pthread_mutex_lock(&s->mu);
    snprintf(id, sizeof id, "amfsub-%u", ++s->seq);
    if (s->n < 64)
        s->items[s->n++] = j;
    else
        g5c_json_free(j);
    pthread_mutex_unlock(&s->mu);
    o = g5c_json_new_obj();
    g5c_json_set_str(o, "subscriptionId", id);
    if (imm && s->immediate != NULL) {
        g5c_json *rl = g5c_json_parse(s->immediate, strlen(s->immediate), NULL, 0);
        g5c_json_set(o, "reportList", rl);
    }
    snprintf(loc, sizeof loc, "/namf-evts/v1/subscriptions/%s", id);
    g5c_resp_json(resp, 201, o);
    g5c_resp_header(resp, "location", loc);
    g5c_json_free(o);
}

static void amf_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    sink_t *s = ctx;
    pthread_mutex_lock(&s->mu);
    s->deleted++;
    snprintf(s->last_deleted, sizeof s->last_deleted, "%s", g5c_req_param(req, "subscriptionId") ? g5c_req_param(req, "subscriptionId") : "");
    pthread_mutex_unlock(&s->mu);
    g5c_resp_status(resp, 204);
}

static bool wait_n(sink_t *s, size_t n, int ms)
{
    for (int i = 0; i < ms / 5; i++) {
        pthread_mutex_lock(&s->mu);
        if (s->n >= n) {
            pthread_mutex_unlock(&s->mu);
            return true;
        }
        pthread_mutex_unlock(&s->mu);
        usleep(5000);
    }
    return false;
}

static bool wait_deleted(sink_t *s, size_t n, int ms)
{
    for (int i = 0; i < ms / 5; i++) {
        pthread_mutex_lock(&s->mu);
        if (s->deleted >= n) {
            pthread_mutex_unlock(&s->mu);
            return true;
        }
        pthread_mutex_unlock(&s->mu);
        usleep(5000);
    }
    return false;
}

/* ---- the stack ---------------------------------------------------------------------------------------------------------------- */

typedef struct {
    g5c_client *client;
    g5c_udr_store *store;
    g5c_router *udr_r, *udm_r, *amf_r, *af_r, *pcf_r, *smf_r;
    g5c_server *udr_s, *udm_s, *amf_s, *af_s, *pcf_s, *smf_s, *nef_s;
    g5c_registry *metrics_udm, *metrics_pcf;
    udm u;
    pcf pcf;
    sink_t af, amf, smf;
    char udr[64], udm[64], amf_url[64], pcf_url[64], smf_url[64], af_cb[96], token_file[128], state_file[128];
    nef *n;
    g5c_router *r;
} S;

/* when set, the configuration names this BSF instead of a PCF */
static const char *g_bsf_url;

static void stop_nef(S *s)
{
    g5c_server_stop(s->nef_s);
    s->nef_s = NULL;
    g5c_router_free(s->r);
    s->r = NULL;
    nef_destroy(s->n);
    s->n = NULL;
}

static char *config_text(S *s, const char *extra_nef)
{
    return g5c_xasprintf(
        "nef:\n"
        "  afs:\n"
        "    - { id: af1, no_auth: true, notify_hosts: ['127.0.0.1'], max_subscriptions: 6 }\n"
        "    - { id: af2, token_file: %s, notify_hosts: ['127.0.0.1'], apis: [traffic-influence] }\n"
        "    - { id: af3, no_auth: true, apis: [traffic-influence] }\n"
        "  callback_uri: http://nef.test:80\n"
        "  udr: { uri: '%s' }\n"
        "  udm: { uri: '%s' }\n"
        "  amf: { uri: '%s' }\n"
        "  pcf: { uri: '%s' }\n"
        "  subscriptions: { notify_retries: 0, max_reports: 5, max_lifetime_s: 3600 }\n"
        "  state_file: %s\n"
        "%s",
        s->token_file, s->udr, s->udm, s->amf_url, s->pcf_url, s->state_file, extra_nef != NULL ? extra_nef : "");
}

static void start_nef(S *s, const char *extra_nef)
{
    char err[200];
    char *y = config_text(s, extra_nef);
    g5c_json *root = g5c_yaml_parse(y, strlen(y), err, sizeof err);
    nef_cfg *c;
    TK_ASSERT(root != NULL);
    if (g_bsf_url != NULL) {
        g5c_json *nefb = g5c_json_get_mut(root, "nef");
        g5c_json_remove(nefb, "pcf");
        g5c_json_set_str(g5c_json_set(nefb, "bsf", g5c_json_new_obj()), "uri", g_bsf_url);
    }
    c = nef_cfg_parse(root, "001", "01", NULL, err, sizeof err);
    if (c == NULL)
        TK_FAIL("config: %s", err);
    s->n = nef_new(c, s->client, NULL, NULL);
    TK_ASSERT(s->n != NULL);
    TK_ASSERT(nef_start(s->n, err, sizeof err) == 0);
    s->r = nef_router(s->n);
    {   /* the PCF and the AMF call the NEF back: its router is served, and its callback address is the one of the server */
        g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
        s->nef_s = g5c_server_start(&cfg, s->r, err, sizeof err);
        TK_ASSERT(s->nef_s != NULL);
        free(s->n->cfg->callback_uri);
        s->n->cfg->callback_uri = g5c_xasprintf("http://127.0.0.1:%u", g5c_server_port(s->nef_s));
    }
    g5c_json_free(root);
    free(y);
}

static void stack(S *s)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[160];
    udm_keys keys;
    udr_opts uo;
    FILE *f;
    memset(s, 0, sizeof *s);
    sink_init(&s->af);
    sink_init(&s->amf);
    s->client = g5c_client_new(3000, NULL);
    s->store = g5c_udr_store_memory();
    memset(&uo, 0, sizeof uo);
    uo.provisioning_token = PROV;
    s->udr_r = g5c_udr_router_opts(s->store, &uo);
    s->udr_s = g5c_server_start(&cfg, s->udr_r, err, sizeof err);
    TK_ASSERT(s->udr_s != NULL);
    snprintf(s->udr, sizeof s->udr, "http://127.0.0.1:%u", g5c_server_port(s->udr_s));
    udm_keys_none(&keys);
    s->metrics_udm = g5c_registry_new();
    udm_init(&s->u, s->client, s->udr, &keys, NULL, 0, "00101", "udm-test", s->metrics_udm);
    s->u.admin_token = g5c_xstrdup(ADMIN);
    udm_udr_set_token(&s->u.udr, PROV);
    s->udm_r = udm_router(&s->u);
    s->udm_s = g5c_server_start(&cfg, s->udm_r, err, sizeof err);
    TK_ASSERT(s->udm_s != NULL);
    snprintf(s->udm, sizeof s->udm, "http://127.0.0.1:%u", g5c_server_port(s->udm_s));
    s->u.ee_self_uri = g5c_xstrdup(s->udm); /* the notification address the UDM gives the AMF (Nudm_EE) */
    s->amf_r = g5c_router_new();
    g5c_router_route(s->amf_r, "POST", "/namf-evts/v1/subscriptions", amf_create, &s->amf);
    g5c_router_route(s->amf_r, "DELETE", "/namf-evts/v1/subscriptions/{subscriptionId}", amf_delete, &s->amf);
    s->amf_s = g5c_server_start(&cfg, s->amf_r, err, sizeof err);
    TK_ASSERT(s->amf_s != NULL);
    snprintf(s->amf_url, sizeof s->amf_url, "http://127.0.0.1:%u", g5c_server_port(s->amf_s));
    s->af_r = g5c_router_new();
    g5c_router_route(s->af_r, "POST", "/cb", cb_handler, &s->af);
    s->af_s = g5c_server_start(&cfg, s->af_r, err, sizeof err);
    TK_ASSERT(s->af_s != NULL);
    snprintf(s->af_cb, sizeof s->af_cb, "http://127.0.0.1:%u/cb", g5c_server_port(s->af_s));
    /* a PCF (with QoS references) and the SMF it pushes decisions to */
    {
        pcf_policy pol;
        g5c_json *pc;
        static const char refs[] = "policy_authorization:\n  qos_references:\n    voice: { qi5: 1, gbr_ul: '128 Kbps', gbr_dl: '128 Kbps' }\n    streaming: { qi5: 7 }\n";
        sink_init(&s->smf);
        s->metrics_pcf = g5c_registry_new();
        TK_ASSERT(pcf_policy_parse(NULL, true, &pol, err, sizeof err) == 0);
        pcf_init(&s->pcf, &pol, s->client, s->udr, s->metrics_pcf);
        pc = g5c_yaml_parse(refs, sizeof refs - 1, err, sizeof err);
        TK_ASSERT(pc != NULL && pcf_policyauth_config(&s->pcf, pc, err, sizeof err) == 0);
        g5c_json_free(pc);
        s->pcf_r = pcf_router(&s->pcf);
        s->pcf_s = g5c_server_start(&cfg, s->pcf_r, err, sizeof err);
        TK_ASSERT(s->pcf_s != NULL);
        snprintf(s->pcf_url, sizeof s->pcf_url, "http://127.0.0.1:%u", g5c_server_port(s->pcf_s));
        s->smf_r = g5c_router_new();
        g5c_router_route(s->smf_r, "POST", "/smf/{id}/update", cb_handler, &s->smf);
        g5c_router_route(s->smf_r, "POST", "/smf/{id}/terminate", cb_handler, &s->smf);
        s->smf_s = g5c_server_start(&cfg, s->smf_r, err, sizeof err);
        TK_ASSERT(s->smf_s != NULL);
        snprintf(s->smf_url, sizeof s->smf_url, "http://127.0.0.1:%u/smf/x", g5c_server_port(s->smf_s));
    }
    snprintf(s->token_file, sizeof s->token_file, "/tmp/g5c-nef-token-%d", (int)getpid());
    snprintf(s->state_file, sizeof s->state_file, "/tmp/g5c-nef-state-%d.json", (int)getpid());
    f = fopen(s->token_file, "w");
    TK_ASSERT(f != NULL);
    fputs(AF2_TOKEN "\n", f);
    fclose(f);
    unlink(s->state_file);
}

static void unstack(S *s)
{
    if (s->n != NULL)
        stop_nef(s);
    g5c_server_stop(s->af_s);
    g5c_server_stop(s->smf_s);
    g5c_server_stop(s->pcf_s);
    g5c_server_stop(s->amf_s);
    g5c_server_stop(s->udm_s);
    g5c_server_stop(s->udr_s);
    g5c_router_free(s->af_r);
    g5c_router_free(s->smf_r);
    g5c_router_free(s->pcf_r);
    pcf_destroy(&s->pcf);
    g5c_registry_free(s->metrics_pcf);
    g5c_router_free(s->amf_r);
    g5c_router_free(s->udm_r);
    g5c_router_free(s->udr_r);
    udm_destroy(&s->u);
    g5c_client_free(s->client);
    g5c_registry_free(s->metrics_udm);
    g5c_udr_store_free(s->store);
    sink_clear(&s->af);
    sink_clear(&s->amf);
    sink_clear(&s->smf);
    free(s->amf.immediate);
    unlink(s->token_file);
    unlink(s->state_file);
}

/* a subscriber with its external identities, optionally registered at an AMF */
static void provision(S *s, const char *supi, const char *gpsi_json, bool registered)
{
    char url[160], *body;
    g5c_json *o = NULL;
    snprintf(url, sizeof url, "%s/admin/v1/subscribers", s->udm);
    body = g5c_xasprintf("{\"supi\":\"%s\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[{\"sst\":1}]%s%s}", supi, gpsi_json != NULL ? "," : "", gpsi_json != NULL ? gpsi_json : "");
    TK_ASSERT(http("POST", url, body, ADMIN, &o) == 201);
    g5c_json_free(o);
    free(body);
    if (registered) {
        snprintf(url, sizeof url, "%s/nudm-uecm/v1/%s/registrations/amf-3gpp-access", s->udm, supi);
        TK_ASSERT(http("PUT", url,
                       "{\"amfInstanceId\":\"3a29fd6c-cdee-41f1-a39b-af55908ebd32\",\"deregCallbackUri\":\"http://127.0.0.1:9/dereg\","
                       "\"guami\":{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"amfId\":\"020040\"},\"ratType\":\"NR\"}",
                       NULL, NULL) < 300);
    }
}

static g5c_json *udr_influence(S *s, const char *id, int *status)
{
    char url[256];
    g5c_json *j = NULL;
    g5c_json *one = NULL;
    snprintf(url, sizeof url, "%s/nudr-dr/v1/application-data/influenceData?influence-Ids=%s", s->udr, id);
    *status = http("GET", url, NULL, NULL, &j); /* the individual resource has no GET: the collection filtered by identifier */
    if (*status == 200) {
        *status = 404;
        for (size_t i = 0; i < g5c_json_len(j); i++) { /* the NEF names the resource in resUri */
            const char *res = g5c_json_get_str(g5c_json_at(j, i), "resUri");
            if (res != NULL && strstr(res, id) != NULL) {
                one = g5c_json_dup(g5c_json_at(j, i));
                *status = 200;
            }
        }
        g5c_json_free(j);
        return one;
    }
    return j;
}

static const char *id_of(const char *location)
{
    const char *p = strrchr(location, '/');
    return p != NULL ? p + 1 : location;
}

#define TI "/3gpp-traffic-influence/v1"
#define ME "/3gpp-monitoring-event/v1"
#define AQ "/3gpp-as-session-with-qos/v1"

/* ---- configuration ------------------------------------------------------------------------------------------------------------ */

static void test_config(void)
{
    static const struct {
        const char *yaml, *want;
    } bad[] = {
        {"nef:\n  afs: []\n", "nef.afs"},
        {"nef:\n  afs: [ { id: 'a b', no_auth: true } ]\n", "nef.afs[0].id"},
        {"nef:\n  afs: [ { id: a } ]\n", "no bearer token"},
        {"nef:\n  afs: [ { id: a, no_auth: true }, { id: a, no_auth: true } ]\n", "listed twice"},
        {"nef:\n  afs: [ { id: a, no_auth: true, apis: [ nope ] } ]\n", "nef.afs[0].apis"},
        {"nef:\n  afs: [ { id: a, no_auth: true, notify_hosts: [ 'a/b' ] } ]\n", "notify_hosts[0]"},
        {"nef:\n  afs: [ { id: a, no_auth: true, max_subscriptions: 0 } ]\n", "max_subscriptions"},
        {"nef:\n  afs: [ { id: a, no_auth: true, extra: 1 } ]\n", "extra"},
        {"nef:\n  afs: [ { id: a, no_auth: true } ]\n  udr: { uri: 'ftp://x' }\n", "nef.udr.uri"},
        {"nef:\n  afs: [ { id: a, no_auth: true } ]\n  callback_uri: 'nope'\n", "callback_uri"},
        {"nef:\n  afs: [ { id: a, no_auth: true } ]\n  subscriptions: { notify_retries: 99 }\n", "notify_retries"},
        {"nef:\n  afs: [ { id: a, no_auth: true } ]\n  validate: 3\n", "validate"},
        {"nef:\n  afs: [ { id: a, token_file: /nonexistent/token } ]\n", "token_file"},
        {"nef:\n  afs: [ { id: a, no_auth: true } ]\n  unknown: 1\n", "unknown"},
        {"other: 1\n", "nef"},
    };
    char err[256];
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        g5c_json *root = g5c_yaml_parse(bad[i].yaml, strlen(bad[i].yaml), err, sizeof err);
        nef_cfg *c = NULL;
        TK_ASSERT(root != NULL);
        c = nef_cfg_parse(root, "001", "01", NULL, err, sizeof err);
        if (c != NULL || strstr(err, bad[i].want) == NULL)
            TK_FAIL("config case %zu: wanted an error naming %s, got: %s", i, bad[i].want, c ? "accepted" : err);
        g5c_json_free(root);
    }
    {
        static const char ok[] = "nef:\n  afs: [ { id: a, no_auth: true, notify_hosts: [ af.example.com, '192.0.2.1' ] } ]\n  callback_uri: http://nef:7777\n";
        g5c_json *root = g5c_yaml_parse(ok, sizeof ok - 1, err, sizeof err);
        nef_cfg *c = nef_cfg_parse(root, "001", "01", NULL, err, sizeof err);
        TK_ASSERT(c != NULL && c->nafs == 1 && c->afs[0].nhosts == 2 && c->afs[0].apis == 7 && c->max_reports == 1000000);
        nef_cfg_free(c);
        g5c_json_free(root);
    }
    TK_ASSERT(uri_ok("http://a:1/x") && uri_ok("https://[::1]:80/") && !uri_ok("ftp://a") && !uri_ok("http://u:p@a/") && !uri_ok("http://a b/") && !uri_ok("http:///x"));
    {
        char *h = uri_host("https://[2001:db8::1]:8080/p");
        TK_ASSERT(h != NULL && strcmp(h, "2001:db8::1") == 0);
        free(h);
    }
    TK_ASSERT(parse_rfc3339("2030-01-02T03:04:05Z") == 1893553445000LL && parse_rfc3339("2030-01-02T04:04:05+01:00") == 1893553445000LL && parse_rfc3339("2030-01-02") < 0);
}

/* ---- traffic influence ------------------------------------------------------------------------------------------------------- */

static void test_traffic_influence(void)
{
    S s;
    R x, y;
    char id[64], url[160], *body;
    int st;
    g5c_json *j;
    const char *tok[] = {"authorization", "Bearer " AF2_TOKEN, NULL};
    const char *bad_tok[] = {"authorization", "Bearer not-the-token-0123456789", NULL};
    stack(&s);
    provision(&s, SUPI1, "\"msisdn\":\"491700000001\",\"gpsi\":\"extid-user1@example.com\"", false);
    start_nef(&s, NULL);

    /* any UE, by application */
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"afAppId\":\"app-1\",\"anyUeInd\":true,\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"trafficRoutes\":[{\"dnai\":\"edge1\",\"routeProfId\":\"p1\"}],\"tfcCorrInd\":true}", NULL);
    TK_ASSERT(x.status == 201 && strstr(x.location, TI "/af1/subscriptions/") != NULL);
    snprintf(id, sizeof id, "%s", id_of(x.location));
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "self"), x.location) == 0 || strstr(g5c_json_get_str(x.json, "self"), id) != NULL);
    done(&x);
    j = udr_influence(&s, id, &st);
    TK_ASSERT(st == 200 && j != NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(j, "interGroupId"), "AnyUE") == 0 && strcmp(g5c_json_get_str(j, "afAppId"), "app-1") == 0 && strcmp(g5c_json_get_str(j, "dnn"), "internet") == 0);
    {
        bool b = false;
        TK_ASSERT(g5c_json_get_bool(j, "traffCorreInd", &b) && b); /* tfcCorrInd of the northbound API is traffCorreInd in the UDR */
        TK_ASSERT(g5c_json_get(j, "supi") == NULL && g5c_json_get(j, "tfcCorrInd") == NULL);
    }
    g5c_json_free(j);
    TK_ASSERT(nef_subscription_count(s.n, NEF_API_TRAFFIC_INFLUENCE) == 1);

    /* one UE by its GPSI: the UDM resolves the SUPI */
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"trafficFilters\":[{\"flowId\":1,\"flowDescriptions\":[\"permit out ip from 10.0.0.1 to any\"]}],\"gpsi\":\"msisdn-491700000001\",\"trafficRoutes\":[{\"dnai\":\"edge2\",\"routeProfId\":\"p2\"}]}", NULL);
    if (x.status != 201)
        fprintf(stderr, "DBG %d %s %s\n", x.status, x.cause, x.json ? g5c_json_to_string(x.json, NULL) : "-");
    EXPECT(x, 201);
    j = udr_influence(&s, id_of(x.location), &st);
    TK_ASSERT(st == 200 && strcmp(g5c_json_get_str(j, "supi"), SUPI1) == 0 && g5c_json_get(j, "interGroupId") == NULL);
    g5c_json_free(j);
    done(&x);
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"afAppId\":\"a\",\"gpsi\":\"extid-user1@example.com\"}", NULL);
    EXPECT(x, 201); /* the external identifier works as well */
    done(&x);
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"afAppId\":\"a\",\"gpsi\":\"msisdn-499999999999\"}", NULL);
    TK_ASSERT(x.status == 404 && strcmp(x.cause, "USER_NOT_FOUND") == 0);
    done(&x);

    /* requests the NEF does not serve, and bad ones */
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"afAppId\":\"a\",\"ipv4Addr\":\"10.0.0.7\"}", NULL);
    TK_ASSERT(x.status == 501 && strcmp(x.cause, "NOT_SUPPORTED") == 0);
    done(&x);
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"afAppId\":\"a\",\"externalGroupId\":\"grp@example.com\"}", NULL);
    EXPECT(x, 501);
    done(&x);
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"anyUeInd\":true}", NULL); /* neither an application nor a filter */
    EXPECT(x, 400);
    done(&x);
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"afAppId\":\"a\",\"anyUeInd\":true,\"dnn\":7}", NULL);
    TK_ASSERT(x.status == 400 && g5c_json_get(x.json, "invalidParams") != NULL);
    done(&x);
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "not json", NULL);
    EXPECT(x, 400);
    done(&x);
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"afAppId\":\"a\",\"anyUeInd\":true,\"subscribedEvents\":[\"UP_PATH_CHANGE\"]}", NULL);
    EXPECT(x, 400); /* events need a destination */
    done(&x);
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"afAppId\":\"a\",\"anyUeInd\":true,\"subscribedEvents\":[\"UP_PATH_CHANGE\"],\"notificationDestination\":\"http://evil.example/cb\"}", NULL);
    TK_ASSERT(x.status == 403 && strcmp(x.cause, "NOTIFICATION_DESTINATION_NOT_ALLOWED") == 0);
    done(&x);

    /* read, replace, patch, delete */
    snprintf(url, sizeof url, TI "/af1/subscriptions/%s", id);
    x = rq_h(s.r, "GET", url, NULL, NULL);
    TK_ASSERT(x.status == 200 && strcmp(g5c_json_get_str(x.json, "afAppId"), "app-1") == 0);
    done(&x);
    x = rq_h(s.r, "PATCH", url, "{\"appReloInd\":true,\"tfcCorrInd\":null}", NULL);
    EXPECT(x, 200);
    {
        bool b = false;
        TK_ASSERT(g5c_json_get_bool(x.json, "appReloInd", &b) && b && g5c_json_get(x.json, "tfcCorrInd") == NULL && strcmp(g5c_json_get_str(x.json, "afAppId"), "app-1") == 0);
    }
    done(&x);
    j = udr_influence(&s, id, &st);
    {
        bool b = false;
        TK_ASSERT(st == 200 && g5c_json_get_bool(j, "appReloInd", &b) && b && g5c_json_get(j, "traffCorreInd") == NULL);
    }
    g5c_json_free(j);
    x = rq_h(s.r, "PATCH", url, "{\"trafficRoutes\":[]}", NULL); /* minItems 1 */
    EXPECT(x, 400);
    done(&x);
    x = rq_h(s.r, "PUT", url, "{\"afAppId\":\"app-2\",\"anyUeInd\":true}", NULL);
    TK_ASSERT(x.status == 200 && strcmp(g5c_json_get_str(x.json, "afAppId"), "app-2") == 0 && g5c_json_get(x.json, "trafficRoutes") == NULL);
    done(&x);
    j = udr_influence(&s, id, &st);
    TK_ASSERT(st == 200 && strcmp(g5c_json_get_str(j, "afAppId"), "app-2") == 0 && g5c_json_get(j, "trafficRoutes") == NULL);
    g5c_json_free(j);
    x = rq_h(s.r, "PUT", TI "/af1/subscriptions/nope", "{\"afAppId\":\"a\",\"anyUeInd\":true}", NULL);
    EXPECT(x, 404);
    done(&x);
    x = rq_h(s.r, "GET", TI "/af1/subscriptions", NULL, NULL);
    TK_ASSERT(x.status == 200 && g5c_json_len(x.json) == 3);
    done(&x);
    x = rq_h(s.r, "DELETE", url, NULL, NULL);
    EXPECT(x, 204);
    done(&x);
    j = udr_influence(&s, id, &st);
    TK_ASSERT(st == 404);
    g5c_json_free(j);
    x = rq_h(s.r, "DELETE", url, NULL, NULL);
    EXPECT(x, 404);
    done(&x);
    x = rq_h(s.r, "GET", url, NULL, NULL);
    EXPECT(x, 404);
    done(&x);

    /* the test notification (feature 2) */
    body = g5c_xasprintf("{\"afAppId\":\"a\",\"anyUeInd\":true,\"suppFeat\":\"3\",\"requestTestNotification\":true,\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", body, NULL);
    TK_ASSERT(x.status == 201 && strcmp(g5c_json_get_str(x.json, "suppFeat"), "2") == 0); /* the NEF supports feature 2 of the offered 1 and 2 */
    TK_ASSERT(wait_n(&s.af, 1, 3000));
    TK_ASSERT(strstr(g5c_json_get_str(s.af.items[0], "subscription"), id_of(x.location)) != NULL);
    done(&x);
    free(body);

    /* the access of the AFs */
    x = rq_h(s.r, "POST", TI "/af2/subscriptions", "{\"afAppId\":\"a\",\"anyUeInd\":true}", NULL);
    EXPECT(x, 401);
    done(&x);
    x = rq_h(s.r, "POST", TI "/af2/subscriptions", "{\"afAppId\":\"a\",\"anyUeInd\":true}", bad_tok);
    EXPECT(x, 401);
    done(&x);
    x = rq_h(s.r, "POST", TI "/af2/subscriptions", "{\"afAppId\":\"a\",\"anyUeInd\":true}", tok);
    EXPECT(x, 201);
    snprintf(id, sizeof id, "%s", id_of(x.location));
    done(&x);
    snprintf(url, sizeof url, TI "/af1/subscriptions/%s", id);
    x = rq_h(s.r, "GET", url, NULL, NULL); /* af1 cannot see af2's subscription */
    EXPECT(x, 404);
    done(&x);
    snprintf(url, sizeof url, TI "/af2/subscriptions/%s", id);
    x = rq_h(s.r, "GET", url, NULL, tok);
    EXPECT(x, 200);
    done(&x);
    x = rq_h(s.r, "GET", url, NULL, bad_tok);
    EXPECT(x, 401);
    done(&x);
    x = rq_h(s.r, "POST", ME "/af2/subscriptions", "{}", tok); /* af2 may not use the monitoring API */
    EXPECT(x, 403);
    done(&x);
    x = rq_h(s.r, "GET", TI "/nobody/subscriptions", NULL, NULL);
    EXPECT(x, 403);
    done(&x);
    x = rq_h(s.r, "POST", TI "/af3/subscriptions", "{\"afAppId\":\"a\",\"anyUeInd\":true,\"subscribedEvents\":[\"UP_PATH_CHANGE\"],\"notificationDestination\":\"http://127.0.0.1:1/x\"}", NULL);
    EXPECT(x, 403); /* af3 has no hosts it may name */
    done(&x);

    /* the limit of af1: it has 3 subscriptions of the earlier steps (max 6) */
    for (int i = 0; i < 3; i++) {
        x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"afAppId\":\"a\",\"anyUeInd\":true}", NULL);
        EXPECT(x, 201);
        done(&x);
    }
    y = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"afAppId\":\"a\",\"anyUeInd\":true}", NULL);
    EXPECT(y, 429);
    done(&y);

    /* the UDR is down: nothing is stored */
    g5c_server_stop(s.udr_s);
    s.udr_s = NULL;
    x = rq_h(s.r, "DELETE", TI "/af2/subscriptions/x", NULL, tok);
    EXPECT(x, 404);
    done(&x);
    x = rq_h(s.r, "DELETE", url, NULL, tok);
    TK_ASSERT(x.status == 500 && strcmp(x.cause, "SYSTEM_FAILURE") == 0);
    done(&x);
    x = rq_h(s.r, "GET", url, NULL, tok);
    EXPECT(x, 200); /* a failed delete leaves the subscription */
    done(&x);
    s.udr_s = g5c_server_start(&(g5c_server_cfg){"127.0.0.1", 0, NULL}, s.udr_r, NULL, 0);
    unstack(&s);
}

/* ---- monitoring events ----------------------------------------------------------------------------------------------------------- */

/* what the AMF would send to the NEF: the callback of the subscription the NEF made at the AMF `which` (index into the AMF's log) */
static R amf_notifies(S *s, size_t which, const char *corr_override, const char *report_list)
{
    const g5c_json *sub;
    const char *uri, *path, *corr;
    char *body, target[200];
    R x;
    TK_ASSERT(wait_n(&s->amf, which + 1, 3000));
    sub = g5c_json_get(s->amf.items[which], "subscription");
    uri = g5c_json_get_str(sub, "eventNotifyUri");
    corr = corr_override != NULL ? corr_override : g5c_json_get_str(sub, "notifyCorrelationId");
    TK_ASSERT(uri != NULL && strstr(uri, "/nnef-callback/") != NULL);
    path = strstr(uri, "/nnef-callback/");
    snprintf(target, sizeof target, "%s", path);
    body = g5c_xasprintf("{\"reportList\":%s,\"notifyCorrelationId\":\"%s\"}", report_list, corr);
    x = rq_h(s->r, "POST", target, body, NULL);
    free(body);
    return x;
}

static void test_monitoring(void)
{
    S s;
    R x, y;
    char *body, id[64], url[160], ts[32];
    stack(&s);
    provision(&s, SUPI1, "\"gpsi\":\"extid-user1@example.com\",\"msisdn\":\"491700000001\"", true);
    provision(&s, SUPI2, "\"gpsi\":\"extid-user2@example.com\"", false);
    start_nef(&s, NULL);

    /* loss of connectivity: two reports end the subscription */
    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":2,\"supportedFeatures\":\"1\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    TK_ASSERT(x.status == 201 && strstr(x.location, ME "/af1/subscriptions/") != NULL);
    snprintf(id, sizeof id, "%s", id_of(x.location));
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "supportedFeatures"), "1") == 0 && g5c_json_get(x.json, "self") != NULL);
    done(&x);
    TK_ASSERT(wait_n(&s.amf, 1, 3000));
    {
        const g5c_json *sub = g5c_json_get(s.amf.items[0], "subscription"), *ev = g5c_json_at(g5c_json_get(sub, "eventList"), 0);
        bool imm = true;
        TK_ASSERT(strcmp(g5c_json_get_str(ev, "type"), "LOSS_OF_CONNECTIVITY") == 0 && g5c_json_get_bool(ev, "immediateFlag", &imm) && !imm);
        TK_ASSERT(strcmp(g5c_json_get_str(sub, "supi"), SUPI1) == 0 && g5c_json_get_str(sub, "notifyCorrelationId") != NULL && strlen(g5c_json_get_str(sub, "notifyCorrelationId")) == 32);
        TK_ASSERT(strstr(g5c_json_get_str(sub, "eventNotifyUri"), id) != NULL);
    }
    y = amf_notifies(&s, 0, "wrong", "[{\"type\":\"LOSS_OF_CONNECTIVITY\",\"lossOfConnectReason\":\"UE_DEREGISTERED\"}]");
    EXPECT(y, 403);
    done(&y);
    y = amf_notifies(&s, 0, NULL, "[{\"type\":\"LOSS_OF_CONNECTIVITY\",\"timeStamp\":\"2030-01-02T03:04:05Z\",\"lossOfConnectReason\":\"UE_DEREGISTERED\"}]");
    EXPECT(y, 204);
    done(&y);
    TK_ASSERT(wait_n(&s.af, 1, 3000));
    {
        const g5c_json *n = s.af.items[0], *rep = g5c_json_at(g5c_json_get(n, "monitoringEventReports"), 0);
        int64_t v = 0;
        TK_ASSERT(strstr(g5c_json_get_str(n, "subscription"), id) != NULL && strcmp(g5c_json_get_str(rep, "monitoringType"), "LOSS_OF_CONNECTIVITY") == 0);
        TK_ASSERT(g5c_json_get_int(rep, "lossOfConnectReason", &v) && v == 6 && strcmp(g5c_json_get_str(rep, "eventTime"), "2030-01-02T03:04:05Z") == 0);
        TK_ASSERT(strcmp(g5c_json_get_str(rep, "externalId"), "user1@example.com") == 0);
    }
    snprintf(url, sizeof url, ME "/af1/subscriptions/%s", id);
    x = rq_h(s.r, "GET", url, NULL, NULL);
    EXPECT(x, 200);
    done(&x);
    y = amf_notifies(&s, 0, NULL, "[{\"type\":\"LOSS_OF_CONNECTIVITY\",\"lossOfConnectReason\":\"MAX_DETECTION_TIME_EXPIRED\"}]");
    EXPECT(y, 204);
    done(&y);
    TK_ASSERT(wait_n(&s.af, 2, 3000));
    {
        int64_t v = 0;
        TK_ASSERT(g5c_json_get_int(g5c_json_at(g5c_json_get(s.af.items[1], "monitoringEventReports"), 0), "lossOfConnectReason", &v) && v == 7);
    }
    TK_ASSERT(wait_deleted(&s.amf, 1, 3000)); /* the second report was the last one: the subscription at the AMF goes */
    TK_ASSERT(strcmp(s.amf.last_deleted, "amfsub-1") == 0);
    x = rq_h(s.r, "GET", url, NULL, NULL);
    EXPECT(x, 404);
    done(&x);
    y = amf_notifies(&s, 0, NULL, "[]");
    EXPECT(y, 404);
    done(&y);
    free(body);

    /* reachability: only REACHABLE is reported, with the type the AF asked for */
    sink_clear(&s.af);
    sink_clear(&s.amf);
    body = g5c_xasprintf("{\"msisdn\":\"491700000001\",\"monitoringType\":\"UE_REACHABILITY\",\"reachabilityType\":\"DATA\",\"maximumNumberOfReports\":5,\"supportedFeatures\":\"2\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    EXPECT(x, 201);
    snprintf(id, sizeof id, "%s", id_of(x.location));
    done(&x);
    free(body);
    TK_ASSERT(wait_n(&s.amf, 1, 3000));
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(g5c_json_get(s.amf.items[0], "subscription"), "eventList"), 0), "type"), "REACHABILITY_REPORT") == 0);
    y = amf_notifies(&s, 0, NULL, "[{\"type\":\"REACHABILITY_REPORT\",\"reachability\":\"UNREACHABLE\"}]");
    EXPECT(y, 204);
    done(&y);
    y = amf_notifies(&s, 0, NULL, "[{\"type\":\"REACHABILITY_REPORT\",\"reachability\":\"REACHABLE\",\"timeStamp\":\"2030-01-02T03:04:05Z\"}]");
    EXPECT(y, 204);
    done(&y);
    TK_ASSERT(wait_n(&s.af, 1, 3000));
    usleep(100000);
    TK_ASSERT(s.af.n == 1 && strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(s.af.items[0], "monitoringEventReports"), 0), "reachabilityType"), "DATA") == 0);
    snprintf(url, sizeof url, ME "/af1/subscriptions/%s", id);
    x = rq_h(s.r, "DELETE", url, NULL, NULL);
    TK_ASSERT(x.status == 204 && wait_deleted(&s.amf, 1, 3000));
    done(&x);
    x = rq_h(s.r, "DELETE", url, NULL, NULL);
    EXPECT(x, 404);
    done(&x);

    /* one-time location: the AMF's immediate report is the answer and nothing is kept */
    sink_clear(&s.af);
    sink_clear(&s.amf);
    s.amf.immediate = g5c_xstrdup("[{\"type\":\"LOCATION_REPORT\",\"timeStamp\":\"2030-01-02T03:04:05Z\",\"location\":{\"nrLocation\":{\"tai\":{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"tac\":\"000a01\"},\"ncgi\":{\"nrCellId\":\"000000010\"}}}}]");
    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"LOCATION_REPORTING\",\"locationType\":\"CURRENT_LOCATION\",\"maximumNumberOfReports\":1,\"supportedFeatures\":\"4\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    EXPECT(x, 200);
    {
        const g5c_json *rep = g5c_json_get(x.json, "monitoringEventReport"), *li = g5c_json_get(rep, "locationInfo");
        bool imm = false;
        TK_ASSERT(strcmp(g5c_json_get_str(rep, "monitoringType"), "LOCATION_REPORTING") == 0 && strcmp(g5c_json_get_str(li, "trackingAreaId"), "000a01") == 0);
        TK_ASSERT(strcmp(g5c_json_get_str(li, "plmnId"), "00101") == 0 && strcmp(g5c_json_get_str(li, "cellId"), "000000010") == 0);
        TK_ASSERT(g5c_json_get_bool(g5c_json_at(g5c_json_get(g5c_json_get(s.amf.items[0], "subscription"), "eventList"), 0), "immediateFlag", &imm) && imm);
    }
    done(&x);
    free(body);
    TK_ASSERT(wait_deleted(&s.amf, 1, 3000));
    TK_ASSERT(nef_subscription_count(s.n, NEF_API_MONITORING_EVENT) == 0);
    /* a last known location is a one-time request whatever the AF said */
    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"LOCATION_REPORTING\",\"locationType\":\"LAST_KNOWN_LOCATION\",\"monitorExpireTime\":\"2999-01-01T00:00:00Z\",\"supportedFeatures\":\"4\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    EXPECT(x, 200);
    {
        int64_t v = 0;
        TK_ASSERT(g5c_json_get_int(g5c_json_get(x.json, "monitoringEventReport") ? x.json : x.json, "maximumNumberOfReports", &v) && v == 1);
    }
    done(&x);
    free(body);

    /* refusals */
    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":1,\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL); /* no supportedFeatures: the feature of the event is not indicated */
    TK_ASSERT(x.status == 400 && strcmp(x.cause, "EVENT_FEATURE_MISMATCH") == 0);
    done(&x);
    free(body);
    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"ROAMING_STATUS\",\"maximumNumberOfReports\":1,\"supportedFeatures\":\"1f\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    TK_ASSERT(x.status == 500 && strcmp(x.cause, "EVENT_UNSUPPORTED") == 0);
    done(&x);
    free(body);
    body = g5c_xasprintf("{\"externalGroupId\":\"g@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":1,\"supportedFeatures\":\"1\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    TK_ASSERT(x.status == 500 && strcmp(x.cause, "EVENT_UNSUPPORTED") == 0);
    done(&x);
    free(body);
    body = g5c_xasprintf("{\"externalId\":\"ghost@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":1,\"supportedFeatures\":\"1\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    TK_ASSERT(x.status == 404 && strcmp(x.cause, "USER_NOT_FOUND") == 0);
    done(&x);
    free(body);
    body = g5c_xasprintf("{\"externalId\":\"user2@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":1,\"supportedFeatures\":\"1\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL); /* known, but not served by an AMF */
    TK_ASSERT(x.status == 404 && strcmp(x.cause, "CONTEXT_NOT_FOUND") == 0);
    done(&x);
    free(body);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", "{\"externalId\":\"user1@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":1,\"supportedFeatures\":\"1\",\"notificationDestination\":\"http://evil.example/cb\"}", NULL);
    TK_ASSERT(x.status == 403 && strcmp(x.cause, "NOTIFICATION_DESTINATION_NOT_ALLOWED") == 0);
    done(&x);
    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"UE_REACHABILITY\",\"idleStatusIndication\":true,\"maximumNumberOfReports\":1,\"supportedFeatures\":\"2\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    TK_ASSERT(x.status == 403 && strcmp(x.cause, "IDLE_STATUS_UNSUPPORTED") == 0);
    done(&x);
    free(body);
    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"monitorExpireTime\":\"2001-01-01T00:00:00Z\",\"supportedFeatures\":\"1\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    TK_ASSERT(x.status == 403 && strcmp(x.cause, "PARAMETER_OUT_OF_RANGE") == 0);
    done(&x);
    free(body);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", "{\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":1}", NULL);
    EXPECT(x, 400); /* no notification destination */
    done(&x);
    body = g5c_xasprintf("{\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":1,\"supportedFeatures\":\"1\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL); /* no UE */
    EXPECT(x, 400);
    done(&x);
    free(body);

    /* limits of the operator policy are applied, a modification keeps the UE */
    sink_clear(&s.amf);
    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":999,\"supportedFeatures\":\"401\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    EXPECT(x, 201);
    {
        int64_t v = 0;
        TK_ASSERT(g5c_json_get_int(x.json, "maximumNumberOfReports", &v) && v == 5); /* max_reports: 5 */
    }
    snprintf(id, sizeof id, "%s", id_of(x.location));
    done(&x);
    free(body);
    snprintf(url, sizeof url, ME "/af1/subscriptions/%s", id);
    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":3,\"supportedFeatures\":\"401\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "PUT", url, body, NULL);
    {
        int64_t v = 0;
        TK_ASSERT(x.status == 200 && g5c_json_get_int(x.json, "maximumNumberOfReports", &v) && v == 3);
    }
    done(&x);
    free(body);
    body = g5c_xasprintf("{\"externalId\":\"user2@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":3,\"supportedFeatures\":\"401\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "PUT", url, body, NULL);
    TK_ASSERT(x.status == 403 && strcmp(x.cause, "OPERATION_PROHIBITED") == 0);
    done(&x);
    free(body);
    x = rq_h(s.r, "PUT", ME "/af1/subscriptions/nope", "{\"externalId\":\"a@b\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":3,\"notificationDestination\":\"http://127.0.0.1:1/\"}", NULL);
    EXPECT(x, 404);
    done(&x);
    x = rq_h(s.r, "GET", ME "/af1/subscriptions", NULL, NULL);
    TK_ASSERT(x.status == 200 && g5c_json_len(x.json) == 1);
    done(&x);

    /* the end of the monitoring time removes the subscription here and at the AMF */
    sink_clear(&s.amf);
    format_rfc3339(g5c_unix_millis() + 2500, ts);
    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"monitorExpireTime\":\"%s\",\"supportedFeatures\":\"1\",\"notificationDestination\":\"%s\"}", ts, s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    EXPECT(x, 201);
    snprintf(id, sizeof id, "%s", id_of(x.location));
    done(&x);
    free(body);
    TK_ASSERT(nef_subscription_count(s.n, NEF_API_MONITORING_EVENT) == 2);
    TK_ASSERT(wait_deleted(&s.amf, 1, 6000));
    TK_ASSERT(nef_subscription_count(s.n, NEF_API_MONITORING_EVENT) == 1);
    snprintf(url, sizeof url, ME "/af1/subscriptions/%s", id);
    x = rq_h(s.r, "GET", url, NULL, NULL);
    EXPECT(x, 404);
    done(&x);
    unstack(&s);
}

/* ---- the state file ------------------------------------------------------------------------------------------------------------- */

/* With `nef.events_via_udm` the NEF subscribes at the UDM (Nudm_EE); the UDM subscribes at the AMF and relays the AMF's reports as MonitoringReports. */
static void test_monitoring_via_udm(void)
{
    S s;
    R x, y;
    char *body, id[64], url[160], notify[200], reg[300];
    const char *uri;
    stack(&s);
    provision(&s, SUPI1, "\"gpsi\":\"extid-user1@example.com\",\"msisdn\":\"491700000001\"", true);
    snprintf(url, sizeof url, "%s/nudm-uecm/v1/%s/registrations/amf-3gpp-access", s.udm, SUPI1);
    snprintf(reg, sizeof reg, /* the AMF's callback address names the AMF the UDM subscribes at */
             "{\"amfInstanceId\":\"3a29fd6c-cdee-41f1-a39b-af55908ebd32\",\"deregCallbackUri\":\"%s/dereg\","
             "\"guami\":{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"amfId\":\"020040\"},\"ratType\":\"NR\"}", s.amf_url);
    TK_ASSERT(http("PUT", url, reg, NULL, NULL) < 300);
    start_nef(&s, "  events_via_udm: true\n");

    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":1,\"supportedFeatures\":\"1\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    TK_ASSERT(x.status == 201);
    snprintf(id, sizeof id, "%s", id_of(x.location));
    done(&x);
    free(body);
    /* the AMF was asked by the UDM, not by the NEF */
    TK_ASSERT(wait_n(&s.amf, 1, 3000));
    uri = g5c_json_get_str(g5c_json_get(s.amf.items[0], "subscription"), "eventNotifyUri");
    TK_ASSERT(uri != NULL && strstr(uri, "/nudm-ee/v1/amf-notify/") != NULL && strstr(uri, "/nnef-callback/") == NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(s.amf.items[0], "subscription"), "supi"), SUPI1) == 0);
    snprintf(notify, sizeof notify, "%s", strstr(uri, "/nudm-ee/"));
    /* a UE that becomes unreachable is not a reachability report; the loss of connectivity is relayed through the UDM to the NEF to the AF */
    y = rq_h(s.udm_r, "POST", notify, "{\"reportList\":[{\"type\":\"LOSS_OF_CONNECTIVITY\",\"timeStamp\":\"2030-01-02T03:04:05Z\",\"lossOfConnectReason\":\"UE_DEREGISTERED\"}]}", NULL);
    EXPECT(y, 204);
    done(&y);
    TK_ASSERT(wait_n(&s.af, 1, 3000));
    {
        const g5c_json *rep = g5c_json_at(g5c_json_get(s.af.items[0], "monitoringEventReports"), 0);
        int64_t v = 0;
        TK_ASSERT(strcmp(g5c_json_get_str(rep, "monitoringType"), "LOSS_OF_CONNECTIVITY") == 0 && g5c_json_get_int(rep, "lossOfConnectReason", &v) && v == 6);
        TK_ASSERT(strcmp(g5c_json_get_str(rep, "eventTime"), "2030-01-02T03:04:05Z") == 0 && strcmp(g5c_json_get_str(rep, "externalId"), "user1@example.com") == 0);
    }
    /* one report was all the AF asked for: the NEF removes its subscription at the UDM, which removes the one at the AMF */
    TK_ASSERT(wait_deleted(&s.amf, 1, 3000));
    TK_ASSERT(strcmp(s.amf.last_deleted, "amfsub-1") == 0);
    snprintf(url, sizeof url, ME "/af1/subscriptions/%s", id);
    x = rq_h(s.r, "GET", url, NULL, NULL);
    EXPECT(x, 404);
    done(&x);
    unstack(&s);
}

static void test_state(void)
{
    S s;
    R x;
    char id_ti[64], id_me[64], url[200], *body;
    stack(&s);
    provision(&s, SUPI1, "\"gpsi\":\"extid-user1@example.com\"", true);
    start_nef(&s, NULL);
    x = rq_h(s.r, "POST", TI "/af1/subscriptions", "{\"afAppId\":\"a\",\"anyUeInd\":true}", NULL);
    EXPECT(x, 201);
    snprintf(id_ti, sizeof id_ti, "%s", id_of(x.location));
    done(&x);
    body = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"UE_REACHABILITY\",\"maximumNumberOfReports\":9,\"supportedFeatures\":\"2\",\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", ME "/af1/subscriptions", body, NULL);
    EXPECT(x, 201);
    snprintf(id_me, sizeof id_me, "%s", id_of(x.location));
    done(&x);
    free(body);
    stop_nef(&s); /* writes the state */
    start_nef(&s, NULL);
    TK_ASSERT(nef_subscription_count(s.n, NULL) == 2);
    snprintf(url, sizeof url, TI "/af1/subscriptions/%s", id_ti);
    x = rq_h(s.r, "GET", url, NULL, NULL);
    TK_ASSERT(x.status == 200 && strcmp(g5c_json_get_str(x.json, "afAppId"), "a") == 0);
    done(&x);
    TK_ASSERT(wait_n(&s.amf, 1, 3000));
    /* the AMF's report still finds its subscription (the correlation identifier was kept) */
    x = amf_notifies(&s, 0, NULL, "[{\"type\":\"REACHABILITY_REPORT\",\"reachability\":\"REACHABLE\"}]");
    EXPECT(x, 204);
    done(&x);
    TK_ASSERT(wait_n(&s.af, 1, 3000));
    snprintf(url, sizeof url, ME "/af1/subscriptions/%s", id_me);
    x = rq_h(s.r, "DELETE", url, NULL, NULL);
    EXPECT(x, 204);
    done(&x);
    stop_nef(&s);
    {   /* a damaged state file is refused, not ignored */
        FILE *f = fopen(s.state_file, "w");
        char err[200];
        g5c_json *root;
        nef_cfg *c;
        char *y = config_text(&s, NULL);
        TK_ASSERT(f != NULL);
        fputs("{ not json", f);
        fclose(f);
        root = g5c_yaml_parse(y, strlen(y), err, sizeof err);
        c = nef_cfg_parse(root, "001", "01", NULL, err, sizeof err);
        TK_ASSERT(c != NULL);
        s.n = nef_new(c, s.client, NULL, NULL);
        TK_ASSERT(nef_start(s.n, err, sizeof err) != 0 && strstr(err, "damaged") != NULL);
        g5c_json_free(root);
        free(y);
    }
    unstack(&s);
}

/* ---- AS session with QoS ---------------------------------------------------------------------------------------------------------- */

static bool wait_sink(sink_t *k, size_t n, int ms)
{
    return wait_n(k, n, ms);
}

static void test_as_qos(void)
{
    S s;
    R x;
    char *body, id[64], url[200], *sm, smresp[200] = "";
    g5c_json *v = NULL;
    const char *tok[] = {"authorization", "Bearer " AF2_TOKEN, NULL};
    (void)tok;
    stack(&s);
    start_nef(&s, NULL);
    /* the PDU session of the UE: an SM policy at the PCF with the UE's address */
    sm = g5c_xasprintf("{\"supi\":\"" SUPI1 "\",\"pduSessionId\":1,\"pduSessionType\":\"IPV4\",\"dnn\":\"internet\",\"ipv4Address\":\"10.46.0.2\","
                       "\"notificationUri\":\"%s\",\"sliceInfo\":{\"sst\":1},\"accessType\":\"3GPP_ACCESS\",\"ratType\":\"NR\","
                       "\"subsSessAmbr\":{\"uplink\":\"100 Mbps\",\"downlink\":\"200 Mbps\"},"
                       "\"subsDefQos\":{\"5qi\":9,\"arp\":{\"priorityLevel\":8,\"preemptCap\":\"NOT_PREEMPT\",\"preemptVuln\":\"NOT_PREEMPTABLE\"},\"priorityLevel\":80},"
                       "\"servingNetwork\":{\"mcc\":\"001\",\"mnc\":\"01\"}}", s.smf_url);
    snprintf(url, sizeof url, "%s/npcf-smpolicycontrol/v1/sm-policies", s.pcf_url);
    TK_ASSERT(http("POST", url, sm, NULL, &v) == 201);
    g5c_json_free(v);
    v = NULL;
    (void)smresp;

    /* the AF asks for a QoS for a flow; the PCF installs it at the SMF, the AF is told it was allocated */
    body = g5c_xasprintf("{\"ueIpv4Addr\":\"10.46.0.2\",\"qosReference\":\"voice\",\"flowInfo\":[{\"flowId\":1,\"flowDescriptions\":[\"permit out 17 from 10.46.0.2 5004 to 192.0.2.10 5004\"]}],"
                         "\"supportedFeatures\":\"2\",\"requestTestNotification\":true,\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", AQ "/af1/subscriptions", body, NULL);
    EXPECT(x, 201);
    snprintf(id, sizeof id, "%s", id_of(x.location));
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "supportedFeatures"), "2") == 0 && g5c_json_get(x.json, "self") != NULL);
    done(&x);
    free(body);
    TK_ASSERT(wait_sink(&s.smf, 1, 3000));
    {
        const g5c_json *dec = g5c_json_get(s.smf.items[0], "smPolicyDecision"), *rules = g5c_json_get(dec, "pccRules"), *qd = g5c_json_val_at(g5c_json_get(dec, "qosDecs"), 0);
        int64_t q = 0;
        TK_ASSERT(g5c_json_len(rules) == 1 && g5c_json_len(g5c_json_get(g5c_json_val_at(rules, 0), "flowInfos")) == 1);
        TK_ASSERT(g5c_json_get_int(qd, "5qi", &q) && q == 1 && strcmp(g5c_json_get_str(qd, "gbrUl"), "128 Kbps") == 0);
    }
    TK_ASSERT(wait_sink(&s.af, 2, 3000)); /* the test notification and the outcome of the allocation */
    {
        int test = 0, alloc = 0;
        for (size_t i = 0; i < s.af.n; i++) {
            const g5c_json *rep = g5c_json_at(g5c_json_get(s.af.items[i], "eventReports"), 0);
            if (g5c_json_get(s.af.items[i], "transaction") != NULL && strcmp(g5c_json_get_str(rep, "event"), "SUCCESSFUL_RESOURCES_ALLOCATION") == 0) {
                alloc++;
                TK_ASSERT(strstr(g5c_json_get_str(s.af.items[i], "transaction"), id) != NULL && g5c_json_len(g5c_json_get(rep, "flowIds")) == 1);
            } else if (g5c_json_get(s.af.items[i], "subscription") != NULL) {
                test++;
            }
        }
        TK_ASSERT(test == 1 && alloc == 1);
    }
    TK_ASSERT(pcf_app_session_count(&s.pcf) == 1 && nef_subscription_count(s.n, NEF_API_AS_SESSION_WITH_QOS) == 1);

    /* modify: a new QoS reference and flow (PATCH), then everything replaced (PUT) */
    snprintf(url, sizeof url, AQ "/af1/subscriptions/%s", id);
    x = rq_h(s.r, "PATCH", url, "{\"qosReference\":\"streaming\",\"flowInfo\":[{\"flowId\":2,\"flowDescriptions\":[\"permit out 17 from 192.0.2.10 to 10.46.0.2\"]}]}", NULL);
    EXPECT(x, 200);
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "qosReference"), "streaming") == 0 && strcmp(g5c_json_get_str(x.json, "ueIpv4Addr"), "10.46.0.2") == 0);
    done(&x);
    TK_ASSERT(wait_sink(&s.smf, 2, 3000));
    {
        const g5c_json *dec = g5c_json_get(s.smf.items[1], "smPolicyDecision"), *rules = g5c_json_get(dec, "pccRules"), *qd = g5c_json_val_at(g5c_json_get(dec, "qosDecs"), 0);
        int64_t q = 0;
        TK_ASSERT(g5c_json_len(rules) == 1 && g5c_json_len(g5c_json_get(g5c_json_val_at(rules, 0), "flowInfos")) == 1);
        TK_ASSERT(g5c_json_get_int(qd, "5qi", &q) && q == 7);
        TK_ASSERT(strstr(g5c_json_get_str(g5c_json_at(g5c_json_get(g5c_json_val_at(rules, 0), "flowInfos"), 0), "flowDescription"), "from 192.0.2.10 to") != NULL); /* the old flow is gone */
    }
    body = g5c_xasprintf("{\"ueIpv4Addr\":\"10.46.0.2\",\"qosReference\":\"voice\",\"flowInfo\":[{\"flowId\":3,\"flowDescriptions\":[\"permit out 17 from any to assigned\"]}],\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "PUT", url, body, NULL);
    EXPECT(x, 200);
    done(&x);
    TK_ASSERT(wait_sink(&s.smf, 3, 3000));
    free(body);
    body = g5c_xasprintf("{\"ueIpv4Addr\":\"10.46.0.99\",\"qosReference\":\"voice\",\"flowInfo\":[{\"flowId\":3,\"flowDescriptions\":[\"permit out 17 from any to assigned\"]}],\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "PUT", url, body, NULL); /* the UE address stays */
    EXPECT(x, 403);
    done(&x);
    free(body);
    x = rq_h(s.r, "GET", url, NULL, NULL);
    TK_ASSERT(x.status == 200 && strcmp(g5c_json_get_str(x.json, "qosReference"), "voice") == 0);
    done(&x);

    /* refusals: by the NEF, by the PCF */
    body = g5c_xasprintf("{\"ueIpv4Addr\":\"10.46.0.2\",\"qosReference\":\"unknown\",\"flowInfo\":[{\"flowId\":1,\"flowDescriptions\":[\"permit out 17 from any to assigned\"]}],\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", AQ "/af1/subscriptions", body, NULL);
    TK_ASSERT(x.status == 403 && strcmp(x.cause, "REQUESTED_SERVICE_NOT_AUTHORIZED") == 0);
    done(&x);
    free(body);
    body = g5c_xasprintf("{\"ueIpv4Addr\":\"10.46.7.7\",\"qosReference\":\"voice\",\"flowInfo\":[{\"flowId\":1,\"flowDescriptions\":[\"permit out 17 from any to assigned\"]}],\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", AQ "/af1/subscriptions", body, NULL);
    TK_ASSERT(x.status == 404 && strcmp(x.cause, "PDU_SESSION_NOT_AVAILABLE") == 0);
    done(&x);
    free(body);
    x = rq_h(s.r, "POST", AQ "/af1/subscriptions", "{\"ueIpv4Addr\":\"10.46.0.2\",\"qosReference\":\"voice\",\"flowInfo\":[{\"flowId\":1}],\"notificationDestination\":\"http://evil.example/\"}", NULL);
    TK_ASSERT(x.status == 403 && strcmp(x.cause, "NOTIFICATION_DESTINATION_NOT_ALLOWED") == 0);
    done(&x);
    body = g5c_xasprintf("{\"macAddr\":\"00-11-22-33-44-55\",\"ueIpv4Addr\":\"10.46.0.2\",\"qosReference\":\"voice\",\"flowInfo\":[{\"flowId\":1}],\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", AQ "/af1/subscriptions", body, NULL);
    EXPECT(x, 501);
    done(&x);
    free(body);
    body = g5c_xasprintf("{\"ueIpv4Addr\":\"10.46.0.2\",\"qosReference\":\"voice\",\"usageThreshold\":{\"duration\":60},\"flowInfo\":[{\"flowId\":1}],\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", AQ "/af1/subscriptions", body, NULL);
    EXPECT(x, 501);
    done(&x);
    free(body);
    x = rq_h(s.r, "POST", AQ "/af1/subscriptions", "{\"qosReference\":\"voice\",\"notificationDestination\":\"http://127.0.0.1:1/\"}", NULL);
    EXPECT(x, 400);
    done(&x);
    x = rq_h(s.r, "POST", AQ "/af2/subscriptions", "{}", NULL);
    EXPECT(x, 403); /* af2 may not use this API */
    done(&x);

    /* delete: the rule goes from the SMF */
    {
        size_t n0 = s.smf.n;
        x = rq_h(s.r, "DELETE", url, NULL, NULL);
        EXPECT(x, 204);
        done(&x);
        TK_ASSERT(wait_sink(&s.smf, n0 + 1, 3000));
        TK_ASSERT(g5c_json_get(g5c_json_get(s.smf.items[n0], "smPolicyDecision"), "pccRules") == NULL);
        TK_ASSERT(pcf_app_session_count(&s.pcf) == 0 && nef_subscription_count(s.n, NEF_API_AS_SESSION_WITH_QOS) == 0);
        x = rq_h(s.r, "DELETE", url, NULL, NULL);
        EXPECT(x, 404);
        done(&x);
    }

    /* the PDU session ends: the AF is told and the subscription is gone */
    sink_clear(&s.af);
    body = g5c_xasprintf("{\"ueIpv4Addr\":\"10.46.0.2\",\"qosReference\":\"streaming\",\"flowInfo\":[{\"flowId\":1,\"flowDescriptions\":[\"permit out 17 from any to assigned\"]}],\"notificationDestination\":\"%s\"}", s.af_cb);
    x = rq_h(s.r, "POST", AQ "/af1/subscriptions", body, NULL);
    EXPECT(x, 201);
    snprintf(id, sizeof id, "%s", id_of(x.location));
    done(&x);
    free(body);
    {
        g5c_json *sessions = NULL;
        (void)sessions;
        /* the SMF ends the SM policy (it asks the PCF to delete it) */
        snprintf(url, sizeof url, "%s/npcf-smpolicycontrol/v1/sm-policies", s.pcf_url);
        {
            const g5c_json *first = s.smf.items[0];
            const char *res = g5c_json_get_str(first, "resourceUri");
            char *dl = g5c_xasprintf("%s/delete", res);
            TK_ASSERT(http("POST", dl, "{}", NULL, NULL) == 204);
            free(dl);
        }
    }
    TK_ASSERT(wait_sink(&s.af, 2, 3000));
    {
        bool term = false;
        for (size_t i = 0; i < s.af.n; i++)
            if (strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(s.af.items[i], "eventReports"), 0), "event") != NULL ? g5c_json_get_str(g5c_json_at(g5c_json_get(s.af.items[i], "eventReports"), 0), "event") : "", "SESSION_TERMINATION") == 0)
                term = true;
        TK_ASSERT(term);
    }
    snprintf(url, sizeof url, AQ "/af1/subscriptions/%s", id);
    x = rq_h(s.r, "GET", url, NULL, NULL);
    EXPECT(x, 404);
    done(&x);
    free(sm);
    unstack(&s);
}

/* ---- the PCF of a UE address through the BSF (TS 29.521 4.2.4): no `pcf:` in the configuration, the NEF asks the BSF ---------------------------------------------- */

static void test_as_qos_via_bsf(void)
{
    S s;
    R x;
    char *body, *sm, url[200], bsf_url[64], err[200];
    g5c_json *v = NULL;
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_json *r2 = g5c_yaml_parse("bsf: {}\n", 8, err, sizeof err);
    bsf_cfg *bc = bsf_cfg_parse(r2, err, sizeof err);
    bsf *b;
    g5c_router *br;
    g5c_server *bs;
    char *text;
    g5c_json_free(r2);
    TK_ASSERT(bc != NULL);
    b = bsf_new(bc, NULL);
    br = bsf_router(b);
    bs = g5c_server_start(&cfg, br, err, sizeof err);
    TK_ASSERT(bs != NULL);
    snprintf(bsf_url, sizeof bsf_url, "http://127.0.0.1:%u", g5c_server_port(bs));
    stack(&s);
    g_bsf_url = bsf_url;
    start_nef(&s, NULL);
    TK_ASSERT(s.n->cfg->pcf_uri == NULL && s.n->cfg->bsf_uri != NULL);
    sm = g5c_xasprintf("{\"supi\":\"" SUPI1 "\",\"pduSessionId\":1,\"pduSessionType\":\"IPV4\",\"dnn\":\"internet\",\"ipv4Address\":\"10.46.0.2\","
                       "\"notificationUri\":\"%s\",\"sliceInfo\":{\"sst\":1},\"accessType\":\"3GPP_ACCESS\",\"ratType\":\"NR\","
                       "\"subsSessAmbr\":{\"uplink\":\"100 Mbps\",\"downlink\":\"200 Mbps\"},"
                       "\"subsDefQos\":{\"5qi\":9,\"arp\":{\"priorityLevel\":8,\"preemptCap\":\"NOT_PREEMPT\",\"preemptVuln\":\"NOT_PREEMPTABLE\"},\"priorityLevel\":80},"
                       "\"servingNetwork\":{\"mcc\":\"001\",\"mnc\":\"01\"}}", s.smf_url);
    snprintf(url, sizeof url, "%s/npcf-smpolicycontrol/v1/sm-policies", s.pcf_url);
    TK_ASSERT(http("POST", url, sm, NULL, &v) == 201);
    g5c_json_free(v);
    body = g5c_xasprintf("{\"ueIpv4Addr\":\"10.46.0.2\",\"qosReference\":\"voice\",\"flowInfo\":[{\"flowId\":1,\"flowDescriptions\":[\"permit out 17 from 10.46.0.2 5004 to 192.0.2.10 5004\"]}],"
                         "\"supportedFeatures\":\"2\",\"notificationDestination\":\"%s\"}", s.af_cb);
    /* the BSF knows no PCF for the address, and there is no NRF to ask: no PCF */
    x = rq_h(s.r, "POST", AQ "/af1/subscriptions", body, NULL);
    EXPECT(x, 500);
    done(&x);
    text = g5c_registry_render(s.n->metrics);
    TK_ASSERT(strstr(text, "g5c_nef_bsf_discoveries_total{result=\"none\"} 1") != NULL);
    free(text);
    /* the PCF registers the binding (what the PCF does itself when its BSF is configured): the NEF is sent to it */
    {
        char *reg = g5c_xasprintf("{\"supi\":\"" SUPI1 "\",\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"ipv4Addr\":\"10.46.0.2\",\"pcfIpEndPoints\":[{\"ipv4Address\":\"127.0.0.1\",\"transport\":\"TCP\",\"port\":%u}]}",
                                  g5c_server_port(s.pcf_s));
        char *burl = g5c_xasprintf("%s/nbsf-management/v1/pcfBindings", bsf_url);
        TK_ASSERT(http("POST", burl, reg, NULL, NULL) == 201);
        free(reg);
        free(burl);
    }
    x = rq_h(s.r, "POST", AQ "/af1/subscriptions", body, NULL);
    EXPECT(x, 201);
    done(&x);
    TK_ASSERT(wait_sink(&s.smf, 1, 3000)); /* the PCC rule reached the SMF through the PCF the BSF named */
    TK_ASSERT(pcf_app_session_count(&s.pcf) == 1);
    text = g5c_registry_render(s.n->metrics);
    TK_ASSERT(strstr(text, "g5c_nef_bsf_discoveries_total{result=\"binding\"} 1") != NULL);
    free(text);
    free(body);
    free(sm);
    stop_nef(&s);
    g5c_server_stop(bs);
    g5c_router_free(br);
    bsf_destroy(b);
    g_bsf_url = NULL;
    unstack(&s);
}

int main(void)
{
    g5c_log_init("error", false);
    test_config();
    test_traffic_influence();
    test_monitoring();
    test_monitoring_via_udm();
    test_as_qos();
    test_as_qos_via_bsf();
    test_state();
    puts("nef: ok");
    return 0;
}
