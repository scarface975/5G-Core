#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The PCF as a consumer of Nbsf_Management (TS 29.521 4.1.3.2, 4.2.2, 4.2.3): when the SM policy association of a PDU session is created with an IPv4 address or an IPv6
 * prefix, the PCF registers a binding at the BSF (the DNN, the S-NSSAI, the UE address and where this PCF can be reached), and removes it when the association ends, so
 * that an NEF or AF that asks the BSF for "the PCF of this UE address" is sent here.
 *
 * It is done by a thread of its own and from a queue in order: the SMF's request never waits for the BSF, and the removal of a binding always comes after its
 * registration. A BSF that is not there, or that refuses, costs a log line and a counter, never the PDU session. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "g5c/pcf.h"

#define MGMT "/nbsf-management/v1/pcfBindings"
#define MAX_QUEUE 20000

typedef struct bjob {
    bool reg;
    char *sm_id;
    g5c_json *body;
    struct bjob *next;
} bjob_t;

typedef struct {
    char sm_id[37];
    char *url; /* the binding at the BSF (its Location) */
} bent_t;

struct pcf_bsf {
    pcf *p;
    char *uri;   /* the BSF named in the configuration, or NULL: found through the NRF */
    g5c_disc *disc;
    char *fqdn;  /* pcfFqdn, optional */
    char *addr;  /* where this PCF can be reached (pcfIpEndPoints) */
    uint16_t port;
    char instance_id[37];
    char started[32]; /* recoveryTime */
    double no_bsf_until;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bjob_t *head, *tail;
    size_t qlen;
    bool stop, on;
    pthread_t th;
    bent_t *ents; /* the worker's alone */
    size_t nents, capents;
    g5c_counter *c_reg, *c_reg_fail, *c_dereg, *c_dereg_fail, *c_no_bsf, *c_dropped;
};

static char *bsf_root(struct pcf_bsf *b)
{
    char *root = NULL;
    size_t n;
    if (b->uri != NULL)
        return g5c_xstrdup(b->uri);
    if (b->disc == NULL || g5c_now_seconds() < b->no_bsf_until)
        return NULL;
    root = g5c_disc_root(b->disc, "BSF", "nbsf-management", NULL);
    if (root == NULL) {
        b->no_bsf_until = g5c_now_seconds() + 30; /* none registered: do not ask the NRF for every session */
        return NULL;
    }
    n = strlen(root);
    while (n > 0 && root[n - 1] == '/')
        root[--n] = '\0';
    return root;
}

static bent_t *find_ent(struct pcf_bsf *b, const char *sm_id)
{
    for (size_t i = 0; i < b->nents; i++)
        if (strcmp(b->ents[i].sm_id, sm_id) == 0)
            return &b->ents[i];
    return NULL;
}

static void drop_ent(struct pcf_bsf *b, bent_t *e)
{
    free(e->url);
    *e = b->ents[--b->nents];
}

static void do_register(struct pcf_bsf *b, bjob_t *j)
{
    char *root = bsf_root(b), *url, err[160];
    g5c_resp r;
    int rc = -1;
    if (root == NULL) {
        g5c_counter_inc(b->c_no_bsf);
        return;
    }
    url = g5c_xasprintf("%s" MGMT, root);
    for (int attempt = 0; attempt < 2 && rc != 0; attempt++) {
        rc = g5c_client_send_json(b->p->client, "POST", url, j->body, &r, err, sizeof err);
        if (rc == 0 && r.status >= 500) {
            g5c_resp_free(&r);
            rc = -1;
        }
        if (rc != 0 && attempt == 0) {
            struct timespec d = {0, 300 * 1000000L};
            nanosleep(&d, NULL);
        }
    }
    if (rc == 0) {
        const char *loc = g5c_resp_header_get(&r, "location");
        if (r.status == 201 && loc != NULL) {
            bent_t *e = find_ent(b, j->sm_id);
            if (e != NULL) {
                free(e->url);
            } else {
                if (b->nents == b->capents) {
                    b->capents = b->capents ? b->capents * 2 : 256;
                    b->ents = g5c_xrealloc(b->ents, b->capents * sizeof *b->ents);
                }
                e = &b->ents[b->nents++];
                snprintf(e->sm_id, sizeof e->sm_id, "%s", j->sm_id);
            }
            e->url = g5c_xstrdup(loc);
            g5c_counter_inc(b->c_reg);
        } else {
            G5C_LOGW("g5c_pcf", "the BSF refused the binding of SM policy %s: %d", j->sm_id, r.status);
            g5c_counter_inc(b->c_reg_fail);
        }
        g5c_resp_free(&r);
    } else {
        G5C_LOGW("g5c_pcf", "cannot register the binding of SM policy %s at the BSF: %s", j->sm_id, err);
        g5c_counter_inc(b->c_reg_fail);
        if (b->disc != NULL)
            g5c_disc_forget(b->disc, "BSF");
    }
    free(url);
    free(root);
}

static void do_deregister(struct pcf_bsf *b, bjob_t *j)
{
    bent_t *e = find_ent(b, j->sm_id);
    g5c_resp r;
    char err[160];
    if (e == NULL)
        return; /* nothing was registered (no BSF, no address, or it failed) */
    if (g5c_client_request(b->p->client, "DELETE", e->url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) == 0) {
        if (r.status == 204 || r.status == 404)
            g5c_counter_inc(b->c_dereg);
        else
            g5c_counter_inc(b->c_dereg_fail);
        g5c_resp_free(&r);
    } else {
        G5C_LOGW("g5c_pcf", "cannot remove the binding of SM policy %s at the BSF: %s", j->sm_id, err);
        g5c_counter_inc(b->c_dereg_fail);
        if (b->disc != NULL)
            g5c_disc_forget(b->disc, "BSF");
    }
    drop_ent(b, e);
}

static void *worker(void *arg)
{
    struct pcf_bsf *b = arg;
    pthread_mutex_lock(&b->mu);
    for (;;) {
        bjob_t *j;
        while (b->head == NULL && !b->stop)
            pthread_cond_wait(&b->cv, &b->mu);
        if (b->head == NULL)
            break; /* stopped and drained */
        j = b->head;
        b->head = j->next;
        if (b->head == NULL)
            b->tail = NULL;
        b->qlen--;
        pthread_mutex_unlock(&b->mu);
        if (j->reg)
            do_register(b, j);
        else
            do_deregister(b, j);
        g5c_json_free(j->body);
        free(j->sm_id);
        free(j);
        pthread_mutex_lock(&b->mu);
    }
    pthread_mutex_unlock(&b->mu);
    return NULL;
}

static void enqueue(struct pcf_bsf *b, bool reg, const char *sm_id, g5c_json *body)
{
    bjob_t *j = g5c_xcalloc(1, sizeof *j);
    j->reg = reg;
    j->sm_id = g5c_xstrdup(sm_id);
    j->body = body;
    pthread_mutex_lock(&b->mu);
    if (b->qlen >= MAX_QUEUE) {
        pthread_mutex_unlock(&b->mu);
        g5c_counter_inc(b->c_dropped);
        g5c_json_free(body);
        free(j->sm_id);
        free(j);
        return;
    }
    if (b->tail != NULL)
        b->tail->next = j;
    else
        b->head = j;
    b->tail = j;
    b->qlen++;
    pthread_cond_signal(&b->cv);
    pthread_mutex_unlock(&b->mu);
}

/* the PcfBinding of an SM policy association (TS 29.521 5.6.2.2), or NULL when it has no UE address */
static g5c_json *make_binding(struct pcf_bsf *b, const g5c_json *ctx)
{
    const char *v4 = g5c_json_get_str(ctx, "ipv4Address"), *v6 = g5c_json_get_str(ctx, "ipv6AddressPrefix"), *dnn = g5c_json_get_str(ctx, "dnn");
    const g5c_json *sn = g5c_json_get(ctx, "sliceInfo");
    g5c_json *o, *eps, *ep;
    if ((v4 == NULL && v6 == NULL) || dnn == NULL || sn == NULL)
        return NULL;
    o = g5c_json_new_obj();
    if (g5c_json_get_str(ctx, "supi") != NULL)
        g5c_json_set_str(o, "supi", g5c_json_get_str(ctx, "supi"));
    if (g5c_json_get_str(ctx, "gpsi") != NULL)
        g5c_json_set_str(o, "gpsi", g5c_json_get_str(ctx, "gpsi"));
    if (v4 != NULL)
        g5c_json_set_str(o, "ipv4Addr", v4);
    if (v6 != NULL)
        g5c_json_set_str(o, "ipv6Prefix", v6);
    if (v4 != NULL && g5c_json_get_str(ctx, "ipDomain") != NULL)
        g5c_json_set_str(o, "ipDomain", g5c_json_get_str(ctx, "ipDomain"));
    g5c_json_set_str(o, "dnn", dnn);
    g5c_json_set(o, "snssai", g5c_json_dup(sn));
    g5c_json_set_str(o, "pcfId", b->instance_id);
    if (b->fqdn != NULL)
        g5c_json_set_str(o, "pcfFqdn", b->fqdn);
    eps = g5c_json_set(o, "pcfIpEndPoints", g5c_json_new_arr());
    ep = g5c_json_push(eps, g5c_json_new_obj());
    g5c_json_set_str(ep, "ipv4Address", b->addr);
    g5c_json_set_str(ep, "transport", "TCP");
    g5c_json_set_int(ep, "port", b->port);
    g5c_json_set_str(o, "recoveryTime", b->started);
    g5c_json_set_str(o, "suppFeat", "0");
    return o;
}

void pcf_bsf_registered(pcf *p, const char *sm_id, const g5c_json *context)
{
    g5c_json *body;
    if (p->bsf == NULL)
        return;
    body = make_binding(p->bsf, context);
    if (body != NULL)
        enqueue(p->bsf, true, sm_id, body);
}

void pcf_bsf_gone(pcf *p, const char *sm_id)
{
    if (p->bsf != NULL)
        enqueue(p->bsf, false, sm_id, NULL);
}

size_t pcf_bsf_pending(pcf *p)
{
    size_t n = 0;
    if (p->bsf != NULL) {
        pthread_mutex_lock(&p->bsf->mu);
        n = p->bsf->qlen;
        pthread_mutex_unlock(&p->bsf->mu);
    }
    return n;
}

int pcf_bsf_config(pcf *p, const g5c_json *cfg, g5c_nf *nf, char *err, size_t errcap)
{
    static const char *const keys[] = {"enabled", "uri", "fqdn", "address", NULL};
    const g5c_json *blk = g5c_json_get(cfg, "bsf");
    bool enabled = true;
    struct pcf_bsf *b;
    const char *uri = NULL, *fqdn = NULL, *addr = NULL;
    time_t now = time(NULL);
    struct tm tmv;
    if (blk != NULL) {
        if (!g5c_json_is(blk, G5C_J_OBJECT) || g5c_json_check_keys(blk, keys, "bsf", err, errcap) != 0) {
            if (err[0] == '\0')
                snprintf(err, errcap, "invalid config: `bsf` must be a mapping");
            return -1;
        }
        if (g5c_json_get(blk, "enabled") != NULL && !g5c_json_get_bool(blk, "enabled", &enabled)) {
            snprintf(err, errcap, "invalid config: `bsf.enabled` must be true or false");
            return -1;
        }
        uri = g5c_json_get_str(blk, "uri");
        fqdn = g5c_json_get_str(blk, "fqdn");
        addr = g5c_json_get_str(blk, "address");
        if ((g5c_json_get(blk, "uri") != NULL && (uri == NULL || (strncmp(uri, "http://", 7) != 0 && strncmp(uri, "https://", 8) != 0))) ||
            (g5c_json_get(blk, "fqdn") != NULL && (fqdn == NULL || fqdn[0] == '\0' || strlen(fqdn) > 200)) ||
            (g5c_json_get(blk, "address") != NULL && (addr == NULL || strlen(addr) > 15 || strchr(addr, '.') == NULL))) {
            snprintf(err, errcap, "invalid config: `bsf.uri` must be an http(s) URI, `bsf.fqdn` a host name and `bsf.address` an IPv4 address");
            return -1;
        }
    }
    if (!enabled || (uri == NULL && nf->common.nrf_uri == NULL))
        return 0; /* nothing to register at: no BSF named and no NRF to find one */
    b = g5c_xcalloc(1, sizeof *b);
    b->p = p;
    if (uri != NULL) {
        size_t n = strlen(uri);
        while (n > 0 && uri[n - 1] == '/')
            n--;
        b->uri = g5c_xstrndup(uri, n);
    } else {
        b->disc = g5c_disc_new(nf->client, nf->common.nrf_uri, "PCF", nf->instance_id);
    }
    b->fqdn = fqdn != NULL ? g5c_xstrdup(fqdn) : NULL;
    b->addr = g5c_xstrdup(addr != NULL ? addr : nf->common.address);
    b->port = nf->common.port;
    snprintf(b->instance_id, sizeof b->instance_id, "%s", nf->instance_id);
    gmtime_r(&now, &tmv);
    strftime(b->started, sizeof b->started, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    pthread_mutex_init(&b->mu, NULL);
    pthread_cond_init(&b->cv, NULL);
    {
        g5c_label ok[] = {{"operation", "register"}, {"result", "ok"}}, fl[] = {{"operation", "register"}, {"result", "failed"}},
                  dok[] = {{"operation", "deregister"}, {"result", "ok"}}, dfl[] = {{"operation", "deregister"}, {"result", "failed"}},
                  nb[] = {{"operation", "register"}, {"result", "no_bsf"}}, dr[] = {{"operation", "any"}, {"result", "dropped"}};
        b->c_reg = g5c_counter_get(p->metrics, "g5c_pcf_bsf_requests_total", "Nbsf_Management requests of the PCF by operation and result", ok, 2);
        b->c_reg_fail = g5c_counter_get(p->metrics, "g5c_pcf_bsf_requests_total", "Nbsf_Management requests of the PCF by operation and result", fl, 2);
        b->c_dereg = g5c_counter_get(p->metrics, "g5c_pcf_bsf_requests_total", "Nbsf_Management requests of the PCF by operation and result", dok, 2);
        b->c_dereg_fail = g5c_counter_get(p->metrics, "g5c_pcf_bsf_requests_total", "Nbsf_Management requests of the PCF by operation and result", dfl, 2);
        b->c_no_bsf = g5c_counter_get(p->metrics, "g5c_pcf_bsf_requests_total", "Nbsf_Management requests of the PCF by operation and result", nb, 2);
        b->c_dropped = g5c_counter_get(p->metrics, "g5c_pcf_bsf_requests_total", "Nbsf_Management requests of the PCF by operation and result", dr, 2);
    }
    b->on = pthread_create(&b->th, NULL, worker, b) == 0;
    p->bsf = b;
    return 0;
}

void pcf_bsf_free(pcf *p)
{
    struct pcf_bsf *b = p->bsf;
    if (b == NULL)
        return;
    pthread_mutex_lock(&b->mu);
    b->stop = true;
    pthread_cond_broadcast(&b->cv);
    pthread_mutex_unlock(&b->mu);
    if (b->on)
        pthread_join(b->th, NULL); /* the queue is drained first: the bindings of the sessions that ended are removed */
    for (size_t i = 0; i < b->nents; i++)
        free(b->ents[i].url);
    free(b->ents);
    g5c_disc_free(b->disc);
    free(b->uri);
    free(b->fqdn);
    free(b->addr);
    pthread_mutex_destroy(&b->mu);
    pthread_cond_destroy(&b->cv);
    free(b);
    p->bsf = NULL;
}
