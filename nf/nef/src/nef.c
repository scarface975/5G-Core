#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The NEF: construction, the resource table, calls to the other functions, the delivery queue and the state file. The APIs are in ti.c (traffic
 * influence) and me.c (monitoring event). */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "priv.h"

/* ---- resources ----------------------------------------------------------------------------------------------------- */

char *nef_key(int api, const char *af, const char *id)
{
    return g5c_xasprintf("%s/%s/%s", nef_api_names[api], af, id);
}

res_t *res_find(nef *n, int api, const char *af, const char *id)
{
    for (size_t i = 0; i < n->nres; i++)
        if (n->res[i]->api == api && strcmp(n->res[i]->af, af) == 0 && strcmp(n->res[i]->id, id) == 0)
            return n->res[i];
    return NULL;
}

static void res_free(res_t *r)
{
    free(r->af);
    free(r->id);
    g5c_json_free(r->doc);
    g5c_json_free(r->ctx);
    free(r);
}

res_t *res_add(nef *n, int api, const char *af, const char *id, g5c_json *doc, g5c_json *ctx)
{
    res_t *r = g5c_xcalloc(1, sizeof *r);
    r->api = api;
    r->af = g5c_xstrdup(af);
    r->id = g5c_xstrdup(id);
    r->doc = doc;
    r->ctx = ctx != NULL ? ctx : g5c_json_new_obj();
    if (n->nres == n->capres) {
        n->capres = n->capres == 0 ? 64 : n->capres * 2;
        n->res = g5c_xrealloc(n->res, n->capres * sizeof *n->res);
    }
    n->res[n->nres++] = r;
    g5c_gauge_set(n->g_subs[api], (int64_t)res_count(n, api, NULL));
    return r;
}

void res_remove(nef *n, res_t *r)
{
    int api = r->api;
    for (size_t i = 0; i < n->nres; i++)
        if (n->res[i] == r) {
            n->res[i] = n->res[--n->nres];
            break;
        }
    res_free(r);
    g5c_gauge_set(n->g_subs[api], (int64_t)res_count(n, api, NULL));
}

size_t res_count(nef *n, int api, const char *af)
{
    size_t k = 0;
    for (size_t i = 0; i < n->nres; i++)
        if (n->res[i]->api == api && (af == NULL || strcmp(n->res[i]->af, af) == 0))
            k++;
    return k;
}

size_t nef_subscription_count(nef *n, const char *api)
{
    size_t k = 0;
    pthread_mutex_lock(&n->mu);
    for (int a = 0; a < API_COUNT; a++)
        if (api == NULL || strcmp(api, nef_api_names[a]) == 0 ||
            (strcmp(api, NEF_API_TRAFFIC_INFLUENCE) == 0 && a == API_TI) || (strcmp(api, NEF_API_MONITORING_EVENT) == 0 && a == API_ME) || (strcmp(api, NEF_API_AS_SESSION_WITH_QOS) == 0 && a == API_AQ))
            k += res_count(n, a, NULL);
    pthread_mutex_unlock(&n->mu);
    return k;
}

void nef_dirty(nef *n)
{
    pthread_mutex_lock(&n->qmu);
    n->dirty = true;
    pthread_cond_signal(&n->qcv);
    pthread_mutex_unlock(&n->qmu);
}

bool nef_body_ok(nef *n, const g5c_json *body, int schema, g5c_resp *resp)
{
    char err[200];
    if (!n->cfg->validate)
        return true;
    if (oa_validate(n->sch, schema, body, err, sizeof err) == 0)
        return true;
    {
        char *colon = strstr(err, ": ");
        if (colon != NULL) {
            *colon = '\0';
            nef_invalid(resp, 400, "INVALID_REQUEST", err[0] != '\0' ? err : "/", colon + 2);
        } else {
            nef_invalid(resp, 400, "INVALID_REQUEST", "/", err);
        }
    }
    return false;
}

/* The representation of a resource, with its location when it was just created. */
void nef_reply_res(g5c_resp *resp, int status, const res_t *r, const g5c_req *req, const char *base)
{
    g5c_resp_json(resp, status, r->doc);
    if (status == 201) {
        char *path = g5c_xasprintf("%s/%s/subscriptions/%s", base, r->af, r->id), *loc = g5c_req_url(req, path);
        g5c_resp_header(resp, "location", loc);
        free(path);
        free(loc);
    }
}

/* ---- the other functions -------------------------------------------------------------------------------------------- */

char *nef_root(nef *n, const char *configured, const char *type, const char *service)
{
    if (configured != NULL)
        return g5c_xstrdup(configured);
    if (n->disc != NULL)
        return g5c_disc_root(n->disc, type, service, NULL);
    return NULL;
}

/* the address a PCF binding gives for Npcf_PolicyAuthorization: an IP endpoint (the first with an IPv4 address, else an IPv6 one), else the FQDN; the scheme is the BSF's */
static char *binding_root(const g5c_json *b, const char *bsf_root)
{
    const g5c_json *eps = g5c_json_get(b, "pcfIpEndPoints");
    const char *scheme = strncmp(bsf_root, "https://", 8) == 0 ? "https" : "http";
    for (int pass = 0; pass < 2; pass++)
        for (size_t i = 0; i < g5c_json_len(eps); i++) {
            const g5c_json *e = g5c_json_at(eps, i);
            const char *a = g5c_json_get_str(e, pass == 0 ? "ipv4Address" : "ipv6Address");
            int64_t port = 0;
            if (a == NULL)
                continue;
            (void)g5c_json_get_int(e, "port", &port);
            if (port > 0 && port < 65536)
                return pass == 0 ? g5c_xasprintf("%s://%s:%lld", scheme, a, (long long)port) : g5c_xasprintf("%s://[%s]:%lld", scheme, a, (long long)port);
            return pass == 0 ? g5c_xasprintf("%s://%s", scheme, a) : g5c_xasprintf("%s://[%s]", scheme, a);
        }
    if (g5c_json_get_str(b, "pcfFqdn") != NULL)
        return g5c_xasprintf("%s://%s", scheme, g5c_json_get_str(b, "pcfFqdn"));
    return NULL;
}

char *nef_pcf_root(nef *n, const g5c_json *req)
{
    char *bsf, *root = NULL;
    const char *v4 = g5c_json_get_str(req, "ueIpv4Addr");
    if (n->cfg->pcf_uri != NULL)
        return g5c_xstrdup(n->cfg->pcf_uri);
    bsf = v4 != NULL ? nef_root(n, n->cfg->bsf_uri, "BSF", "nbsf-management") : NULL;
    if (bsf != NULL) {
        g5c_bytes q;
        char *e = pct_encode(v4), *url, err[160];
        g5c_resp r;
        g5c_bytes_init(&q);
        g5c_bytes_printf(&q, "ipv4Addr=%s", e);
        free(e);
        if (g5c_json_get_str(req, "ipDomain") != NULL) {
            e = pct_encode(g5c_json_get_str(req, "ipDomain"));
            g5c_bytes_printf(&q, "&ipDomain=%s", e);
            free(e);
        }
        if (g5c_json_get_str(req, "dnn") != NULL) {
            e = pct_encode(g5c_json_get_str(req, "dnn"));
            g5c_bytes_printf(&q, "&dnn=%s", e);
            free(e);
        }
        if (g5c_json_get(req, "snssai") != NULL) {
            char *sj = g5c_json_to_string(g5c_json_get(req, "snssai"), NULL);
            e = sj != NULL ? pct_encode(sj) : NULL;
            if (e != NULL)
                g5c_bytes_printf(&q, "&snssai=%s", e);
            free(e);
            free(sj);
        }
        url = g5c_xasprintf("%s/nbsf-management/v1/pcfBindings?%.*s", bsf, (int)q.len, (const char *)q.data);
        g5c_bytes_free(&q);
        if (g5c_client_get(n->client, url, &r, err, sizeof err) == 0) {
            if (r.status == 200) {
                g5c_json *b = g5c_resp_parse_json(&r);
                root = b != NULL ? binding_root(b, bsf) : NULL;
                g5c_json_free(b);
                g5c_counter_inc(root != NULL ? n->c_bsf_hit : n->c_bsf_fail);
            } else if (r.status == 204) {
                g5c_counter_inc(n->c_bsf_none);
            } else {
                G5C_LOGW("g5c_nef", "the BSF answered %d to the discovery of the PCF of %s", r.status, v4);
                g5c_counter_inc(n->c_bsf_fail);
            }
            g5c_resp_free(&r);
        } else {
            G5C_LOGW("g5c_nef", "cannot ask the BSF for the PCF of %s: %s", v4, err);
            g5c_counter_inc(n->c_bsf_fail);
            nef_call_failed(n, 4);
        }
        free(url);
        free(bsf);
    }
    return root != NULL ? root : nef_root(n, NULL, "PCF", "npcf-policyauthorization");
}

void nef_call_failed(nef *n, int api_peer)
{
    static const char *const types[] = {"UDR", "UDM", "AMF", "PCF", "BSF"};
    if (n->disc != NULL && api_peer >= 0 && api_peer < 5)
        g5c_disc_forget(n->disc, types[api_peer]);
}

int nef_peer(nef *n, const char *root, const char *method, const char *path, const g5c_json *body, g5c_resp *out, char *err, size_t errcap)
{
    char *url = g5c_xasprintf("%s%s", root, path);
    int rc = g5c_client_send_json(n->client, method, url, body, out, err, errcap);
    free(url);
    return rc;
}

char *nef_self_url(const nef *n, const char *path)
{
    return n->cfg->callback_uri != NULL ? g5c_xasprintf("%s%s", n->cfg->callback_uri, path) : NULL;
}

/* ---- delivery ------------------------------------------------------------------------------------------------------------ */

#define MAX_QUEUE 10000

void nef_enqueue(nef *n, const char *url, char *body, const char *res_key, double delay_s)
{
    job_t *j = g5c_xcalloc(1, sizeof *j), **pp;
    j->url = g5c_xstrdup(url);
    j->body = body;
    j->res_key = g5c_xstrdup(res_key);
    j->not_before = g5c_now_seconds() + delay_s;
    pthread_mutex_lock(&n->qmu);
    if (n->qlen >= MAX_QUEUE) {
        pthread_mutex_unlock(&n->qmu);
        g5c_counter_inc(n->c_dropped);
        free(j->url);
        free(j->body);
        free(j->res_key);
        free(j);
        return;
    }
    for (pp = &n->q; *pp != NULL; pp = &(*pp)->next)
        ;
    *pp = j;
    n->qlen++;
    pthread_cond_signal(&n->qcv);
    pthread_mutex_unlock(&n->qmu);
}

static void job_free(job_t *j)
{
    free(j->url);
    free(j->body);
    free(j->res_key);
    free(j);
}

static void deliver(nef *n, job_t *j)
{
    g5c_resp r;
    char err[160];
    g5c_kv hdr = {"accept", "application/json"};
    bool ok = false;
    if (n->client != NULL && g5c_client_request(n->client, "POST", j->url, &hdr, 1, "application/json", j->body, strlen(j->body), &r, err, sizeof err) == 0) {
        ok = r.status >= 200 && r.status <= 299;
        if (!ok)
            G5C_LOGW(NEF_LOG, "notification of %s to %s answered %d", j->res_key, j->url, r.status);
        g5c_resp_free(&r);
    } else {
        G5C_LOGW(NEF_LOG, "notification of %s to %s: %s", j->res_key, j->url, n->client != NULL ? err : "no client");
    }
    if (ok) {
        g5c_counter_inc(n->c_ok);
        job_free(j);
        return;
    }
    g5c_counter_inc(n->c_failed);
    if (j->attempts < n->cfg->notify_retries) {
        job_t **pp;
        j->not_before = g5c_now_seconds() + (double)(1u << j->attempts);
        j->attempts++;
        j->next = NULL;
        pthread_mutex_lock(&n->qmu);
        for (pp = &n->q; *pp != NULL; pp = &(*pp)->next)
            ;
        *pp = j;
        n->qlen++;
        pthread_mutex_unlock(&n->qmu);
        return;
    }
    g5c_counter_inc(n->c_dropped);
    job_free(j);
}

static void *worker_main(void *arg)
{
    nef *n = arg;
    double last_sweep = 0;
    pthread_mutex_lock(&n->qmu);
    while (!n->stop) {
        double now = g5c_now_seconds();
        job_t *due = NULL, **pp;
        for (pp = &n->q; *pp != NULL; pp = &(*pp)->next)
            if ((*pp)->not_before <= now) {
                due = *pp;
                *pp = due->next;
                n->qlen--;
                break;
            }
        if (due != NULL) {
            pthread_mutex_unlock(&n->qmu);
            deliver(n, due);
            pthread_mutex_lock(&n->qmu);
            continue;
        }
        if (n->dirty) {
            n->dirty = false;
            pthread_mutex_unlock(&n->qmu);
            nef_state_save(n);
            pthread_mutex_lock(&n->qmu);
            continue;
        }
        if (now - last_sweep >= 1.0) {
            last_sweep = now;
            pthread_mutex_unlock(&n->qmu);
            me_sweep(n);
            pthread_mutex_lock(&n->qmu);
            continue;
        }
        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 250 * 1000000L;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
            pthread_cond_timedwait(&n->qcv, &n->qmu, &ts);
        }
    }
    pthread_mutex_unlock(&n->qmu);
    return NULL;
}

void nef_worker_start(nef *n)
{
    if (!n->worker_on && pthread_create(&n->worker, NULL, worker_main, n) == 0)
        n->worker_on = true;
}

void nef_worker_stop(nef *n)
{
    job_t *j;
    if (n->worker_on) {
        pthread_mutex_lock(&n->qmu);
        n->stop = true;
        pthread_cond_broadcast(&n->qcv);
        pthread_mutex_unlock(&n->qmu);
        pthread_join(n->worker, NULL);
        n->worker_on = false;
    }
    while ((j = n->q) != NULL) {
        n->q = j->next;
        job_free(j);
    }
    n->qlen = 0;
}

/* ---- state file ------------------------------------------------------------------------------------------------------- */

void nef_state_save(nef *n)
{
    g5c_json *root, *arr;
    char *text, *tmp;
    FILE *f;
    int fd;
    if (n->cfg->state_file == NULL)
        return;
    root = g5c_json_new_obj();
    g5c_json_set_int(root, "version", 1);
    arr = g5c_json_set(root, "resources", g5c_json_new_arr());
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < n->nres; i++) {
        const res_t *r = n->res[i];
        g5c_json *o = g5c_json_push(arr, g5c_json_new_obj());
        g5c_json_set_str(o, "api", nef_api_names[r->api]);
        g5c_json_set_str(o, "af", r->af);
        g5c_json_set_str(o, "id", r->id);
        g5c_json_set(o, "doc", g5c_json_dup(r->doc));
        g5c_json_set(o, "ctx", g5c_json_dup(r->ctx));
        g5c_json_set_int(o, "expiry", r->expiry_ms);
        g5c_json_set_int(o, "reports", r->reports);
    }
    pthread_mutex_unlock(&n->mu);
    text = g5c_json_to_string(root, NULL);
    g5c_json_free(root);
    tmp = g5c_xasprintf("%s.tmp", n->cfg->state_file);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    f = fd >= 0 ? fdopen(fd, "w") : NULL;
    if (f == NULL) {
        G5C_LOGW(NEF_LOG, "cannot write the state file %s: %s", tmp, strerror(errno));
        if (fd >= 0)
            close(fd);
    } else {
        bool ok = fputs(text, f) >= 0 && fflush(f) == 0 && fsync(fileno(f)) == 0;
        ok = fclose(f) == 0 && ok;
        if (!ok || rename(tmp, n->cfg->state_file) != 0) {
            G5C_LOGW(NEF_LOG, "cannot write the state file %s: %s", n->cfg->state_file, strerror(errno));
            unlink(tmp);
        }
    }
    free(tmp);
    free(text);
}

int nef_state_load(nef *n, char *err, size_t errcap)
{
    char *text;
    size_t len = 0;
    g5c_json *root;
    const g5c_json *arr;
    if (n->cfg->state_file == NULL)
        return 0;
    text = g5c_read_file(n->cfg->state_file, 256u << 20, &len);
    if (text == NULL) {
        if (errno == ENOENT || access(n->cfg->state_file, F_OK) != 0)
            return 0;
        snprintf(err, errcap, "cannot read the state file %s", n->cfg->state_file);
        return -1;
    }
    root = g5c_json_parse(text, len, err, errcap);
    free(text);
    if (root == NULL) {
        char tmp[200];
        snprintf(tmp, sizeof tmp, "the state file %s is damaged: %s", n->cfg->state_file, err);
        snprintf(err, errcap, "%s", tmp);
        return -1;
    }
    arr = g5c_json_get(root, "resources");
    if (!g5c_json_is(arr, G5C_J_ARRAY) || g5c_json_get(root, "version") == NULL) {
        snprintf(err, errcap, "the state file %s is not a NEF state file", n->cfg->state_file);
        g5c_json_free(root);
        return -1;
    }
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const g5c_json *o = g5c_json_at(arr, i);
        const char *api = g5c_json_get_str(o, "api"), *af = g5c_json_get_str(o, "af"), *id = g5c_json_get_str(o, "id");
        int a = -1;
        int64_t v;
        res_t *r;
        for (int k = 0; api != NULL && k < API_COUNT; k++)
            if (strcmp(api, nef_api_names[k]) == 0)
                a = k;
        if (a < 0 || af == NULL || id == NULL || !g5c_json_is(g5c_json_get(o, "doc"), G5C_J_OBJECT) || res_find(n, a, af, id) != NULL)
            continue;
        r = res_add(n, a, af, id, g5c_json_dup(g5c_json_get(o, "doc")), g5c_json_is(g5c_json_get(o, "ctx"), G5C_J_OBJECT) ? g5c_json_dup(g5c_json_get(o, "ctx")) : NULL);
        if (g5c_json_get_int(o, "expiry", &v))
            r->expiry_ms = v;
        if (g5c_json_get_int(o, "reports", &v) && v >= 0)
            r->reports = (unsigned)v;
    }
    pthread_mutex_unlock(&n->mu);
    g5c_json_free(root);
    return 0;
}

/* ---- construction -------------------------------------------------------------------------------------------------------- */

nef *nef_new(nef_cfg *cfg, g5c_client *client, g5c_disc *disc, g5c_registry *metrics)
{
    nef *n = g5c_xcalloc(1, sizeof *n);
    char err[160];
    n->cfg = cfg;
    n->client = client;
    n->disc = disc;
    n->sch = oa_schemas_load(nef_schema_chunks, nef_schema_nchunks, nef_schema_count, err, sizeof err);
    if (n->sch == NULL) {
        G5C_LOGE(NEF_LOG, "the generated schema pool is unusable: %s", err);
        nef_cfg_free(cfg);
        free(n);
        return NULL;
    }
    if (metrics == NULL) {
        n->metrics = g5c_registry_new();
        n->own_metrics = true;
    } else {
        n->metrics = metrics;
    }
    pthread_mutex_init(&n->mu, NULL);
    pthread_mutex_init(&n->qmu, NULL);
    pthread_cond_init(&n->qcv, NULL);
    for (int a = 0; a < API_COUNT; a++) {
        g5c_label l[] = {{"api", nef_api_names[a]}};
        n->c_req[a] = g5c_counter_get(n->metrics, "g5c_nef_requests_total", "northbound requests by API", l, 1);
        n->c_reject[a] = g5c_counter_get(n->metrics, "g5c_nef_rejections_total", "northbound requests answered with an error by API", l, 1);
        n->g_subs[a] = g5c_gauge_get(n->metrics, "g5c_nef_subscriptions", "active subscriptions by API", l, 1);
    }
    {
        g5c_label ok[] = {{"result", "delivered"}}, fl[] = {{"result", "failed"}}, dr[] = {{"result", "dropped"}};
        n->c_ok = g5c_counter_get(n->metrics, "g5c_nef_notifications_total", "notifications to AFs by outcome", ok, 1);
        n->c_failed = g5c_counter_get(n->metrics, "g5c_nef_notifications_total", "notifications to AFs by outcome", fl, 1);
        n->c_dropped = g5c_counter_get(n->metrics, "g5c_nef_notifications_total", "notifications to AFs by outcome", dr, 1);
    }
    {
        g5c_label u[] = {{"peer", "udr"}}, m[] = {{"peer", "amf"}}, pc[] = {{"peer", "pcf"}};
        n->c_udr_fail = g5c_counter_get(n->metrics, "g5c_nef_peer_failures_total", "calls to other functions that failed", u, 1);
        n->c_amf_fail = g5c_counter_get(n->metrics, "g5c_nef_peer_failures_total", "calls to other functions that failed", m, 1);
        n->c_pcf_fail = g5c_counter_get(n->metrics, "g5c_nef_peer_failures_total", "calls to other functions that failed", pc, 1);
    }
    {
        g5c_label h[] = {{"result", "binding"}}, no[] = {{"result", "none"}}, f[] = {{"result", "failed"}};
        n->c_bsf_hit = g5c_counter_get(n->metrics, "g5c_nef_bsf_discoveries_total", "Nbsf_Management_Discovery requests by result", h, 1);
        n->c_bsf_none = g5c_counter_get(n->metrics, "g5c_nef_bsf_discoveries_total", "Nbsf_Management_Discovery requests by result", no, 1);
        n->c_bsf_fail = g5c_counter_get(n->metrics, "g5c_nef_bsf_discoveries_total", "Nbsf_Management_Discovery requests by result", f, 1);
    }
    return n;
}

nef *nef_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap)
{
    char *def_cb = g5c_xasprintf("%s://%s:%u", nf->common.has_tls ? "https" : "http", nf->common.address, (unsigned)nf->common.port);
    nef_cfg *c = nef_cfg_parse(root, nf->common.mcc, nf->common.mnc, def_cb, err, errcap);
    g5c_disc *disc = NULL;
    nef *n;
    free(def_cb);
    if (c == NULL)
        return NULL;
    if (nf->common.nrf_uri != NULL) {
        c->nrf_uri = g5c_xstrdup(nf->common.nrf_uri);
        disc = g5c_disc_new(nf->client, nf->common.nrf_uri, "NEF", nf->instance_id);
    }
    n = nef_new(c, nf->client, disc, nf->metrics);
    if (n == NULL) {
        g5c_disc_free(disc);
        snprintf(err, errcap, "cannot create the NEF");
        return NULL;
    }
    return n;
}

int nef_start(nef *n, char *err, size_t errcap)
{
    if (nef_state_load(n, err, errcap) != 0)
        return -1;
    me_state_restored(n);
    nef_worker_start(n);
    return 0;
}

g5c_router *nef_router(nef *n)
{
    g5c_router *r = g5c_router_new();
    ti_routes(r, n);
    me_routes(r, n);
    as_routes(r, n);
    return r;
}

void nef_destroy(nef *n)
{
    if (n == NULL)
        return;
    nef_worker_stop(n);
    nef_state_save(n);
    while (n->nres > 0)
        res_remove(n, n->res[0]);
    free(n->res);
    oa_schemas_free(n->sch);
    g5c_disc_free(n->disc);
    if (n->own_metrics)
        g5c_registry_free(n->metrics);
    nef_cfg_free(n->cfg);
    pthread_mutex_destroy(&n->mu);
    pthread_mutex_destroy(&n->qmu);
    pthread_cond_destroy(&n->qcv);
    free(n);
}

/* ---- the AF ----------------------------------------------------------------------------------------------------------- */

static bool token_equal(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b), n = la > lb ? la : lb;
    unsigned char d = la != lb;
    for (size_t i = 0; i < n; i++)
        d |= (unsigned char)((i < la ? a[i] : 0) ^ (i < lb ? b[i] : 0));
    return d == 0;
}

const nef_af *af_auth(nef *n, const g5c_req *req, g5c_resp *resp, int api)
{
    const nef_af *af = cfg_af(n->cfg, g5c_req_param(req, "afId"));
    if (af == NULL || (af->apis & (1u << api)) == 0) {
        nef_problem(resp, 403, "AF_NOT_AUTHORIZED", "the AF may not use this API");
        g5c_counter_inc(n->c_reject[api]);
        return NULL;
    }
    if (af->token != NULL) {
        const char *t = g5c_bearer_token(req);
        if (t == NULL || !token_equal(t, af->token)) {
            nef_problem(resp, 401, "UNAUTHENTICATED", "a valid bearer token is required");
            g5c_resp_header(resp, "www-authenticate", "Bearer");
            g5c_counter_inc(n->c_reject[api]);
            return NULL;
        }
    }
    return af;
}
