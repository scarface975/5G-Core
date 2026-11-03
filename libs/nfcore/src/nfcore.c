/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _POSIX_C_SOURCE 200809L
#include "g5c/nfcore.h"

#include <openssl/crypto.h>

#include <errno.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- NRF client ---- */

g5c_json *g5c_nrf_profile(const char *instance_id, const char *nf_type, const char *addr, uint16_t port,
                          const char *scheme, const char *mcc, const char *mnc, const g5c_svc *svcs, size_t nsvcs)
{
    g5c_json *p = g5c_json_new_obj(), *arr;
    g5c_json_set_str(p, "nfInstanceId", instance_id);
    g5c_json_set_str(p, "nfType", nf_type);
    g5c_json_set_str(p, "nfStatus", "REGISTERED");
    if (mcc != NULL && mnc != NULL) {
        g5c_json *pl = g5c_json_set(p, "plmnList", g5c_json_new_arr());
        g5c_json *e = g5c_json_push(pl, g5c_json_new_obj());
        g5c_json_set_str(e, "mcc", mcc);
        g5c_json_set_str(e, "mnc", mnc);
    }
    arr = g5c_json_set(p, "ipv4Addresses", g5c_json_new_arr());
    g5c_json_push_str(arr, addr);
    if (nsvcs > 0) {
        arr = g5c_json_set(p, "nfServices", g5c_json_new_arr());
        g5c_json *last_versions = NULL;
        for (size_t i = 0; i < nsvcs; i++) {
            g5c_json *s, *vs, *v, *eps, *ep;
            const char *ver = svcs[i].version;
            char *sid, *full = g5c_xasprintf("%s.0.0", ver[0] == 'v' ? ver + 1 : ver);
            if (i > 0 && last_versions != NULL && strcmp(svcs[i].name, svcs[i - 1].name) == 0) {
                /* the same service in another API version: one service with several versions */
                v = g5c_json_push(last_versions, g5c_json_new_obj());
                g5c_json_set_str(v, "apiVersionInUri", ver);
                g5c_json_set_str(v, "apiFullVersion", full);
                free(full);
                continue;
            }
            s = g5c_json_push(arr, g5c_json_new_obj());
            sid = g5c_xasprintf("%s-%zu", instance_id, i);
            g5c_json_set_str(s, "serviceInstanceId", sid);
            g5c_json_set_str(s, "serviceName", svcs[i].name);
            vs = g5c_json_set(s, "versions", g5c_json_new_arr());
            last_versions = vs;
            v = g5c_json_push(vs, g5c_json_new_obj());
            g5c_json_set_str(v, "apiVersionInUri", ver);
            g5c_json_set_str(v, "apiFullVersion", full);
            g5c_json_set_str(s, "scheme", scheme);
            g5c_json_set_str(s, "nfServiceStatus", "REGISTERED");
            eps = g5c_json_set(s, "ipEndPoints", g5c_json_new_arr());
            ep = g5c_json_push(eps, g5c_json_new_obj());
            g5c_json_set_str(ep, "ipv4Address", addr);
            g5c_json_set_str(ep, "transport", "TCP");
            g5c_json_set_int(ep, "port", port);
            free(sid);
            free(full);
        }
    }
    return p;
}

static char *nrf_url(const char *nrf, const char *id)
{
    size_t n = strlen(nrf);
    while (n > 0 && nrf[n - 1] == '/')
        n--;
    return g5c_xasprintf("%.*s/nnrf-nfm/v1/nf-instances/%s", (int)n, nrf, id);
}

int g5c_nrf_register(g5c_client *c, const char *nrf_uri, const g5c_json *profile, g5c_json **stored)
{
    char *u = nrf_url(nrf_uri, g5c_json_get_str(profile, "nfInstanceId") ? g5c_json_get_str(profile, "nfInstanceId") : "");
    g5c_resp r;
    int rc = g5c_client_send_json(c, "PUT", u, profile, &r, NULL, 0);
    free(u);
    if (rc != 0)
        return rc;
    rc = (r.status == 200 || r.status == 201) ? 0 : r.status;
    if (rc == 0 && stored != NULL) {
        *stored = g5c_resp_parse_json(&r);
        if (*stored == NULL)
            *stored = g5c_json_dup(profile);
    }
    g5c_resp_free(&r);
    return rc;
}

int g5c_nrf_heartbeat(g5c_client *c, const char *nrf_uri, const char *instance_id)
{
    static const char body[] = "[{\"op\":\"replace\",\"path\":\"/nfStatus\",\"value\":\"REGISTERED\"}]";
    char *u = nrf_url(nrf_uri, instance_id);
    g5c_resp r;
    int rc = g5c_client_request(c, "PATCH", u, NULL, 0, "application/json-patch+json", body, sizeof body - 1, &r, NULL, 0);
    free(u);
    if (rc != 0)
        return rc;
    rc = (r.status == 200 || r.status == 204) ? 0 : r.status;
    g5c_resp_free(&r);
    return rc;
}

int g5c_nrf_deregister(g5c_client *c, const char *nrf_uri, const char *instance_id)
{
    char *u = nrf_url(nrf_uri, instance_id);
    g5c_resp r;
    int rc = g5c_client_request(c, "DELETE", u, NULL, 0, NULL, NULL, 0, &r, NULL, 0);
    free(u);
    if (rc != 0)
        return rc;
    rc = (r.status == 200 || r.status == 204 || r.status == 404) ? 0 : r.status;
    g5c_resp_free(&r);
    return rc;
}

/* ---- keep registered ---- */

typedef struct {
    g5c_client *client;
    char *nrf;
    g5c_json *profile;
    pthread_t th;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool stop;
} keeper_t;

/* Wait up to ms; returns true if asked to stop. */
static bool keeper_wait(keeper_t *k, long ms)
{
    struct timespec ts;
    bool stop;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&k->mu);
    while (!k->stop && pthread_cond_timedwait(&k->cv, &k->mu, &ts) != ETIMEDOUT)
        ;
    stop = k->stop;
    pthread_mutex_unlock(&k->mu);
    return stop;
}

static void *keeper_main(void *arg)
{
    keeper_t *k = arg;
    const char *id = g5c_json_get_str(k->profile, "nfInstanceId"), *type = g5c_json_get_str(k->profile, "nfType");
    long interval = 8000;
    bool registered = false;
    for (;;) {
        long wait;
        pthread_mutex_lock(&k->mu);
        bool stop = k->stop;
        pthread_mutex_unlock(&k->mu);
        if (stop)
            break;
        if (!registered) {
            g5c_json *stored = NULL;
            int rc = g5c_nrf_register(k->client, k->nrf, k->profile, &stored);
            if (rc == 0) {
                int64_t t = 0;
                registered = true;
                if (g5c_json_get_int(stored, "heartBeatTimer", &t) && t > 0)
                    interval = (long)t * 800;
                G5C_LOGI("g5c_nrf", "%s %s registered with NRF", type, id);
                wait = interval;
            } else {
                G5C_LOGW("g5c_nrf", "NRF registration failed (%d), retrying", rc);
                wait = 2000;
            }
            g5c_json_free(stored);
        } else {
            int rc = g5c_nrf_heartbeat(k->client, k->nrf, id);
            if (rc != 0) {
                G5C_LOGW("g5c_nrf", "NRF heartbeat failed (%d), re-registering", rc);
                registered = false;
            }
            wait = registered ? interval : 100;
        }
        if (keeper_wait(k, wait))
            break;
    }
    if (registered)
        (void)g5c_nrf_deregister(k->client, k->nrf, id);
    return NULL;
}

/* ---- context ---- */

g5c_nf *g5c_nf_new(g5c_common *common, char *err, size_t errcap)
{
    g5c_nf *nf = g5c_xcalloc(1, sizeof *nf);
    SSL_CTX *tls = NULL;
    nf->common = *common;
    memset(common, 0, sizeof *common);
    atomic_init(&nf->ready, false);
    if (g5c_uuid_v4(nf->instance_id) != 0) {
        if (err && errcap)
            snprintf(err, errcap, "no randomness available");
        g5c_common_free(&nf->common);
        free(nf);
        return NULL;
    }
    if (nf->common.has_tls && nf->common.tls.ca != NULL) {
        tls = g5c_tls_client_ctx(nf->common.tls.ca, nf->common.tls.cert, nf->common.tls.key, err, errcap);
        if (tls == NULL) {
            g5c_common_free(&nf->common);
            free(nf);
            return NULL;
        }
    }
    nf->client = g5c_client_new(5000, tls);
    g5c_client_set_scp(nf->client, nf->common.scp_uri, nf->common.nrf_uri); /* the NRF is reached directly */
    nf->metrics = g5c_registry_new();
    g5c_client_set_backoff_counter(nf->client, g5c_counter_get(nf->metrics, "g5c_sbi_client_backoff_total", "Requests not sent because the producer asked for back-off.", NULL, 0));
    {   /* what runs: the version of the release and the function */
        g5c_label bi[] = {{"version", G5C_VERSION}, {"function", nf->common.name != NULL ? nf->common.name : ""}};
        g5c_gauge_set(g5c_gauge_get(nf->metrics, "g5c_build_info", "Version of the release that runs.", bi, 2), 1);
        G5C_LOGI("g5c_nfcore", "g5c %s: %s starting", G5C_VERSION, nf->common.name != NULL ? nf->common.name : "function");
    }
    if (nf->common.events.enabled) {
        nf->events = g5c_events_start(&nf->common.events, nf->common.name, nf->instance_id, nf->metrics, err, errcap);
        if (nf->events == NULL) {
            g5c_client_free(nf->client);
            g5c_registry_free(nf->metrics);
            g5c_common_free(&nf->common);
            free(nf);
            return NULL;
        }
    }
    nf->overload = g5c_overload_new(&nf->common.overload, nf->instance_id, nf->metrics);
    g5c_reload_init(nf);
    return nf;
}

void g5c_nf_free(g5c_nf *nf)
{
    if (nf == NULL)
        return;
    g5c_reload_free(nf);
    g5c_overload_free(nf->overload);
    g5c_events_stop(nf->events); /* before the registry and the configuration it points into */
    g5c_client_set_token_provider(nf->client, NULL, NULL, NULL);
    g5c_oauth_client_free(nf->oauth_client);
    g5c_client_free(nf->client);
    g5c_registry_free(nf->metrics);
    g5c_common_free(&nf->common);
    free(nf);
}

/* ---- health, metrics, instrumentation ---- */

static void h_live(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *o = g5c_json_new_obj();
    (void)ctx;
    (void)req;
    g5c_json_set_str(o, "status", "UP");
    g5c_resp_json(resp, 200, o);
    g5c_json_free(o);
}

static void h_ready(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_nf *nf = ctx;
    bool up = atomic_load(&nf->ready);
    g5c_json *o = g5c_json_new_obj();
    (void)req;
    g5c_json_set_str(o, "status", up ? "UP" : "STARTING");
    g5c_resp_json(resp, up ? 200 : 503, o);
    g5c_json_free(o);
}

static void h_metrics(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_nf *nf = ctx;
    char *t = g5c_registry_render(nf->metrics);
    (void)req;
    g5c_resp_content(resp, 200, "text/plain; version=0.0.4", t, strlen(t));
    free(t);
}

/* GET /openapi.json: the routes this function serves as an OpenAPI 3.0 document (paths, methods, path parameters) */
typedef struct {
    const g5c_nf *nf;
    const g5c_router *router;
} openapi_ctx;

static void h_openapi(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const openapi_ctx *r = ctx;
    g5c_json *doc = g5c_json_new_obj(), *info, *paths;
    (void)req;
    g5c_json_set_str(doc, "openapi", "3.0.3");
    info = g5c_json_set(doc, "info", g5c_json_new_obj());
    g5c_json_set_str(info, "title", r->nf->common.name != NULL ? r->nf->common.name : "g5c function");
    g5c_json_set_str(info, "version", G5C_VERSION);
    paths = g5c_json_set(doc, "paths", g5c_json_new_obj());
    for (size_t i = 0, n = g5c_router_count(r->router); i < n; i++) {
        const char *method, *tmpl;
        g5c_json *item, *op, *params, *resps;
        char *lm, opid[160];
        size_t k = 0;
        if (!g5c_router_route_at(r->router, i, &method, &tmpl) || strcmp(tmpl, "/openapi.json") == 0)
            continue;
        item = g5c_json_get_mut(paths, tmpl);
        if (item == NULL)
            item = g5c_json_set(paths, tmpl, g5c_json_new_obj());
        lm = g5c_xstrdup(method);
        for (char *p = lm; *p; p++)
            if (*p >= 'A' && *p <= 'Z')
                *p = (char)(*p - 'A' + 'a');
        op = g5c_json_set(item, lm, g5c_json_new_obj());
        for (const char *p = tmpl; *p && k + 1 < sizeof opid - 8; p++)
            opid[k++] = (char)((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ? *p : '_');
        opid[k] = 0;
        {
            char full[200];
            snprintf(full, sizeof full, "%s%s", lm, opid);
            g5c_json_set_str(op, "operationId", full);
        }
        params = g5c_json_new_arr();
        for (const char *p = tmpl; (p = strchr(p, '{')) != NULL;) {
            const char *e = strchr(p, '}');
            g5c_json *pa;
            if (e == NULL)
                break;
            pa = g5c_json_push(params, g5c_json_new_obj());
            g5c_json_set_str(pa, "name", "");
            {
                char *nm = g5c_xasprintf("%.*s", (int)(e - p - 1), p + 1);
                g5c_json_set_str(pa, "name", nm);
                free(nm);
            }
            g5c_json_set_str(pa, "in", "path");
            g5c_json_set_bool(pa, "required", true);
            g5c_json_set_str(g5c_json_set(pa, "schema", g5c_json_new_obj()), "type", "string");
            p = e + 1;
        }
        if (g5c_json_len(params) > 0)
            g5c_json_set(op, "parameters", params);
        else
            g5c_json_free(params);
        resps = g5c_json_set(op, "responses", g5c_json_new_obj());
        g5c_json_set_str(g5c_json_set(resps, "default", g5c_json_new_obj()), "description", "see the 3GPP service specification");
        free(lm);
    }
    g5c_resp_json(resp, 200, doc);
    g5c_json_free(doc);
}

static void observe(void *ctx, const char *method, const char *route, int status, double secs)
{
    g5c_nf *nf = ctx;
    char st[8];
    g5c_label l3[3], l1[1];
    snprintf(st, sizeof st, "%d", status);
    if (status >= 500)
        atomic_fetch_add(&nf->server_errors, 1);
    l3[0] = (g5c_label){"method", method};
    l3[1] = (g5c_label){"route", route};
    l3[2] = (g5c_label){"status", st};
    g5c_counter_inc(g5c_counter_get(nf->metrics, "g5c_sbi_requests_total", "SBI requests served.", l3, 3));
    l1[0] = (g5c_label){"route", route};
    g5c_histogram_observe(g5c_histogram_get(nf->metrics, "g5c_sbi_request_duration_seconds", "SBI request latency.", l1, 1),
                          secs);
}

/* allowed_peers and crl of `sbi.tls` on a freshly made server context; the revocation list is read again with the certificates on SIGHUP */
static int apply_tls_policy(SSL_CTX *ctx, const g5c_common *c, char *err, size_t errcap)
{
    char *crl = NULL;
    int rc;
    if (c->tls.crl != NULL) {
        size_t n = 0;
        crl = g5c_read_file(c->tls.crl, 1u << 22, &n);
        if (crl == NULL) {
            if (err && errcap)
                snprintf(err, errcap, "cannot read the revocation list %s", c->tls.crl);
            return -1;
        }
    }
    rc = g5c_tls_server_policy(ctx, (const char *const *)c->tls.allowed_peers, c->tls.nallowed, crl, err, errcap);
    free(crl);
    return rc;
}

int g5c_nf_check(const g5c_nf *nf, char *err, size_t errcap)
{
    const g5c_common *c = &nf->common;
    if (c->has_tls) {
        SSL_CTX *ctx = g5c_tls_server_ctx(c->tls.cert, c->tls.key, c->tls.ca, err, errcap);
        if (ctx == NULL)
            return -1;
        if (apply_tls_policy(ctx, c, err, errcap) != 0) {
            SSL_CTX_free(ctx);
            return -1;
        }
        SSL_CTX_free(ctx);
    }
    return 0;
}

struct g5c_nf_inst {
    g5c_nf *nf;
    g5c_router *router;
    g5c_server *server;
    SSL_CTX *tls;
    keeper_t *keeper;
    g5c_oauth_rs *oauth_rs; /* `oauth2.enforce` */
    openapi_ctx *oa;        /* the context of GET /openapi.json */
};

g5c_nf_inst *g5c_nf_start(g5c_nf *nf, g5c_router *nf_routes, const g5c_nrf_reg *reg, char *err, size_t errcap)
{
    g5c_nf_inst *r = g5c_xcalloc(1, sizeof *r);
    g5c_server_cfg cfg;
    const g5c_common *c = &nf->common;
    const char *scheme = c->has_tls ? "https" : "http";
    g5c_router *base = g5c_router_new();
    char *ua = g5c_xasprintf("%s-%s", reg->nf_type, nf->instance_id);

    g5c_client_set_user_agent(nf->client, ua); /* the SCP derives the type of the consumer from it */
    free(ua);
    r->nf = nf;
    r->router = nf_routes;
    if (c->oauth2_acquire && c->nrf_uri != NULL && nf->oauth_client == NULL) { /* as a consumer: the NRF's access token goes with every request for a service of another */
        nf->oauth_client = g5c_oauth_client_new(nf->client, c->nrf_uri, reg->nf_type, nf->instance_id, nf->metrics);
        g5c_client_set_token_provider(nf->client, g5c_oauth_client_token, g5c_oauth_client_reject, nf->oauth_client);
    }
    if (c->oauth2_enforce && c->nrf_uri != NULL) { /* as a producer: no service without one (TS 33.501 13.4.1.1.2) */
        const char **names = g5c_xcalloc(reg->nservices ? reg->nservices : 1, sizeof *names);
        for (size_t i = 0; i < reg->nservices; i++)
            names[i] = reg->services[i].name;
        r->oauth_rs = g5c_oauth_rs_new(nf->client, c->nrf_uri, reg->nf_type, nf->instance_id, names, reg->nservices, c->oauth2_leeway_s, c->oauth2_jwks_refresh_s, nf->metrics);
        free(names);
        g5c_oauth_rs_attach(r->oauth_rs, r->router);
        if (!c->has_tls)
            G5C_LOGW("g5c_nfcore", "%s requires access tokens but its SBI has no TLS: TS 33.501 13.3.2.1 wants transport protection with token based authorization", c->name);
    }
    g5c_overload_attach(nf->overload, r->router); /* outermost: a rejected request costs no token check */
    g5c_reload_routes(nf, base);
    g5c_router_route(base, "GET", "/health/live", h_live, nf);
    g5c_router_route(base, "GET", "/health/ready", h_ready, nf);
    g5c_router_route(base, "GET", "/metrics", h_metrics, nf);
    r->oa = g5c_xcalloc(1, sizeof *r->oa);
    r->oa->nf = nf;
    r->oa->router = r->router;
    g5c_router_route(base, "GET", "/openapi.json", h_openapi, r->oa);
    g5c_router_merge(r->router, base);
    g5c_router_set_observer(r->router, observe, nf);

    if (c->has_tls) {
        r->tls = g5c_tls_server_ctx(c->tls.cert, c->tls.key, c->tls.ca, err, errcap);
        if (r->tls == NULL)
            goto bad;
        if (apply_tls_policy(r->tls, c, err, errcap) != 0)
            goto bad;
    }
    cfg.address = c->address;
    cfg.port = c->port;
    cfg.tls = r->tls;
    r->server = g5c_server_start(&cfg, r->router, err, errcap);
    if (r->server == NULL)
        goto bad;
    if (c->nrf_uri != NULL) {
        keeper_t *k = g5c_xcalloc(1, sizeof *k);
        pthread_condattr_t ca;
        k->client = nf->client;
        k->nrf = g5c_xstrdup(c->nrf_uri);
        k->profile = g5c_nrf_profile(nf->instance_id, reg->nf_type, c->address, g5c_server_port(r->server), scheme, c->mcc,
                                     c->mnc, reg->services, reg->nservices);
        for (size_t i = 0; i < g5c_json_len(reg->extra); i++)
            g5c_json_set(k->profile, g5c_json_key_at(reg->extra, i), g5c_json_dup(g5c_json_val_at(reg->extra, i)));
        pthread_mutex_init(&k->mu, NULL);
        pthread_condattr_init(&ca);
        pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
        pthread_cond_init(&k->cv, &ca);
        pthread_condattr_destroy(&ca);
        pthread_create(&k->th, NULL, keeper_main, k);
        r->keeper = k;
    }
    G5C_LOGI("g5c_nfcore", "%s SBI listening on %s:%u (%s)", c->name, c->address, g5c_server_port(r->server), scheme);
    atomic_store(&nf->ready, true);
    return r;
bad:
    g5c_server_stop(r->server);
    g5c_router_free(r->router);
    g5c_oauth_rs_free(r->oauth_rs);
    free(r->oa);
    if (r->tls)
        SSL_CTX_free(r->tls);
    free(r);
    return NULL;
}

int g5c_nf_inst_reload_tls(g5c_nf_inst *r, char *err, size_t errcap)
{
    const g5c_common *c = &r->nf->common;
    SSL_CTX *srv, *cli = NULL, *old;
    if (!c->has_tls) {
        if (err && errcap)
            snprintf(err, errcap, "no TLS configured");
        return -1;
    }
    srv = g5c_tls_server_ctx(c->tls.cert, c->tls.key, c->tls.ca, err, errcap); /* both are built before either is used: a bad file changes nothing */
    if (srv == NULL)
        return -1;
    if (apply_tls_policy(srv, c, err, errcap) != 0) {
        SSL_CTX_free(srv);
        return -1;
    }
    if (c->tls.ca != NULL) {
        cli = g5c_tls_client_ctx(c->tls.ca, c->tls.cert, c->tls.key, err, errcap);
        if (cli == NULL) {
            SSL_CTX_free(srv);
            return -1;
        }
    }
    old = g5c_server_swap_tls(r->server, srv);
    r->tls = srv;
    if (old != NULL)
        SSL_CTX_free(old);
    if (cli != NULL)
        g5c_client_swap_tls(r->nf->client, cli);
    return 0;
}

uint16_t g5c_nf_inst_port(const g5c_nf_inst *r)
{
    return g5c_server_port(r->server);
}

void g5c_nf_stop(g5c_nf_inst *r)
{
    if (r == NULL)
        return;
    atomic_store(&r->nf->ready, false);
    if (r->keeper != NULL) {
        keeper_t *k = r->keeper;
        pthread_mutex_lock(&k->mu);
        k->stop = true;
        pthread_cond_signal(&k->cv);
        pthread_mutex_unlock(&k->mu);
        pthread_join(k->th, NULL);
        g5c_json_free(k->profile);
        free(k->nrf);
        pthread_mutex_destroy(&k->mu);
        pthread_cond_destroy(&k->cv);
        free(k);
    }
    g5c_server_stop(r->server);
    g5c_router_free(r->router);
    g5c_oauth_rs_free(r->oauth_rs);
    free(r->oa);
    if (r->tls)
        SSL_CTX_free(r->tls);
    free(r);
}

int g5c_nf_run(g5c_nf *nf, g5c_router *nf_routes, const g5c_nrf_reg *reg, char *err, size_t errcap)
{
    sigset_t set;
    int sig = 0;
    g5c_nf_inst *r;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* threads started below inherit the block */
    r = g5c_nf_start(nf, nf_routes, reg, err, errcap);
    if (r == NULL)
        return -1;
    for (;;) {
        char rerr[200];
        sigwait(&set, &sig);
        if (sig == SIGUSR1 || sig == SIGUSR2) {
            g5c_log_set_level(sig == SIGUSR1 ? G5C_LOG_DEBUG : g5c_log_baseline());
            G5C_LOGW("g5c_nfcore", "%s: SIG%s: log level is now %s", nf->common.name, sig == SIGUSR1 ? "USR1" : "USR2", sig == SIGUSR1 ? "debug" : "the configured one");
            continue;
        }
        if (sig != SIGHUP)
            break;
        if (g5c_nf_inst_reload_tls(r, rerr, sizeof rerr) == 0)
            G5C_LOGI("g5c_nfcore", "%s: SIGHUP: certificates reloaded", nf->common.name);
        else
            G5C_LOGE("g5c_nfcore", "%s: SIGHUP: certificate reload failed, the old ones stay in use: %s", nf->common.name, rerr);
        {   /* the configuration file: validated, diffed, applied where it can be, watched, taken back if the function suffers */
            g5c_json *rep = g5c_nf_reload(nf, false);
            const char *res = g5c_json_get_str(rep, "result");
            G5C_LOGI("g5c_nfcore", "%s: SIGHUP: configuration %s%s%s", nf->common.name, res != NULL ? res : "?", g5c_json_get_str(rep, "error") != NULL ? ": " : "",
                     g5c_json_get_str(rep, "error") != NULL ? g5c_json_get_str(rep, "error") : "");
            g5c_json_free(rep);
        }
    }
    G5C_LOGI("g5c_nfcore", "signal %d received, shutting down", sig);
    g5c_nf_stop(r);
    return 0;
}

/* A secret from a command (`exec:/absolute/path arg arg`): the hook for a key-management service, a vault agent or an HSM client */
static char *secret_from_command(const char *cmdline, char *err, size_t errcap)
{
    char *dup = g5c_xstrdup(cmdline), *argv[16], *save = NULL, *tok, *out = NULL;
    size_t argc = 0, n = 0;
    int fds[2], status = 0;
    pid_t pid;
    double deadline = g5c_now_seconds() + 10.0;
    for (tok = strtok_r(dup, " \t", &save); tok != NULL && argc < 15; tok = strtok_r(NULL, " \t", &save))
        argv[argc++] = tok;
    argv[argc] = NULL;
    if (argc == 0 || argv[0][0] != '/') {
        snprintf(err, errcap, "exec: the command needs an absolute path");
        goto done;
    }
    if (pipe(fds) != 0) {
        snprintf(err, errcap, "exec: cannot create a pipe");
        goto done;
    }
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        snprintf(err, errcap, "exec: cannot start %s", argv[0]);
        goto done;
    }
    if (pid == 0) {
        dup2(fds[1], 1);
        close(fds[0]);
        close(fds[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    out = g5c_xmalloc(65537);
    for (;;) {
        struct pollfd p = {fds[0], POLLIN, 0};
        double left = deadline - g5c_now_seconds();
        ssize_t r;
        if (left <= 0 || poll(&p, 1, (int)(left * 1000)) <= 0) {
            kill(pid, SIGKILL);
            n = (size_t)-1;
            break;
        }
        r = read(fds[0], out + n, 65536 - n);
        if (r <= 0)
            break;
        n += (size_t)r;
        if (n >= 65536) {
            n = (size_t)-1;
            kill(pid, SIGKILL);
            break;
        }
    }
    close(fds[0]);
    (void)waitpid(pid, &status, 0);
    if (n == (size_t)-1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        snprintf(err, errcap, "exec: %s failed (timeout, too much output or a non-zero exit)", argv[0]);
        OPENSSL_cleanse(out, 65537);
        free(out);
        out = NULL;
        goto done;
    }
    out[n] = 0;
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' ' || out[n - 1] == '\t'))
        out[--n] = 0;
done:
    free(dup);
    return out;
}

char *g5c_secret_from_env_or_file(const char *env_name, const char *path, char *err, size_t errcap)
{
    const char *e = env_name ? getenv(env_name) : NULL;
    if (err != NULL && errcap > 0)
        err[0] = 0;
    if (e != NULL && *e)
        return g5c_xstrdup(e);
    if (path != NULL && strncmp(path, "exec:", 5) == 0)
        return secret_from_command(path + 5, err, errcap);
    if (path != NULL) {
        size_t n = 0;
        char *t = g5c_read_file(path, 1U << 16, &n);
        if (t == NULL) {
            if (err != NULL && errcap > 0)
                snprintf(err, errcap, "%s: cannot read", path);
            return NULL;
        }
        while (n > 0 && (t[n - 1] == '\n' || t[n - 1] == '\r' || t[n - 1] == ' ' || t[n - 1] == '\t'))
            t[--n] = 0;
        return t;
    }
    return NULL;
}
