/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _GNU_SOURCE
#include "g5c/overload.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "g5c/base.h"

#define SLOTS 4096 /* sources tracked; an idle one is reused when the table is full */
#define IDLE_S 60.0

typedef struct {
    char key[48];
    double tokens, last;
    bool used;
} src_t;

struct g5c_overload {
    g5c_overload_cfg cfg;
    char instance[40];
    pthread_mutex_t mu;
    src_t tab[SLOTS];
    time_t sec;                                   /* the second `offered` / `rejected` count */
    unsigned offered, rejected, prev_offered, prev_rejected;
    g5c_guard_fn next;
    void *next_ctx;
    g5c_counter *c_rejected;
    g5c_gauge *g_load;
};

static double mono(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static size_t hash(const char *s)
{
    size_t h = 1469598103934665603ULL;
    for (; *s; s++)
        h = (h ^ (unsigned char)*s) * 1099511628211ULL;
    return h;
}

static void imf_date(char out[40])
{
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(out, 40, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

static void roll(g5c_overload *o)
{
    time_t now = time(NULL);
    if (now == o->sec)
        return;
    if (now == o->sec + 1) {
        o->prev_offered = o->offered;
        o->prev_rejected = o->rejected;
    } else {
        o->prev_offered = o->prev_rejected = 0;
    }
    o->offered = o->rejected = 0;
    o->sec = now;
}

/* the bucket of this source; a full table gives up the entry that has been idle longest */
static src_t *find(g5c_overload *o, const char *key, double now)
{
    size_t i = hash(key) % SLOTS, victim = i;
    double oldest = 1e18;
    for (size_t n = 0; n < 16; n++, i = (i + 1) % SLOTS) {
        src_t *s = &o->tab[i];
        if (s->used && strcmp(s->key, key) == 0)
            return s;
        if (!s->used || now - s->last > IDLE_S) {
            victim = i;
            break;
        }
        if (s->last < oldest) {
            oldest = s->last;
            victim = i;
        }
    }
    memset(&o->tab[victim], 0, sizeof o->tab[victim]);
    snprintf(o->tab[victim].key, sizeof o->tab[victim].key, "%s", key);
    o->tab[victim].used = true;
    o->tab[victim].tokens = o->cfg.burst;
    o->tab[victim].last = now;
    return &o->tab[victim];
}

static int guard(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_overload *o = ctx;
    bool pass = true, counted = strncmp(req->path, "/health/", 8) != 0 && strcmp(req->path, "/metrics") != 0;
    unsigned reduction, load, cur_pct, prev_pct;
    double now;
    g5c_overload_cfg cf;
    pthread_mutex_lock(&o->mu);
    cf = o->cfg;
    if (!cf.enabled) { /* off (or switched off by a reload): the request goes on */
        pthread_mutex_unlock(&o->mu);
        return o->next != NULL ? o->next(o->next_ctx, req, resp) : 0;
    }
    now = mono();
    roll(o);
    if (counted) {
        o->offered++;
        if (cf.rate_per_source > 0) {
            src_t *s = find(o, req->peer[0] ? req->peer : "unknown", now);
            s->tokens += (now - s->last) * cf.rate_per_source;
            if (s->tokens > cf.burst)
                s->tokens = cf.burst;
            s->last = now;
            if (s->tokens >= 1.0) {
                s->tokens -= 1.0;
            } else {
                pass = false;
                o->rejected++;
            }
        }
    }
    cur_pct = o->offered > 0 ? 100u * o->rejected / o->offered : 0; /* the share of requests turned away: this second and the one before */
    prev_pct = o->prev_offered > 0 ? 100u * o->prev_rejected / o->prev_offered : 0;
    reduction = cur_pct > prev_pct ? cur_pct : prev_pct;
    load = cf.capacity_rps > 0 ? (unsigned)(100.0 * (o->prev_offered > o->offered ? o->prev_offered : o->offered) / cf.capacity_rps) : 0;
    pthread_mutex_unlock(&o->mu);
    if (load > 100)
        load = 100;
    g5c_gauge_set(o->g_load, load);
    if (!pass) {
        char ts[40], hv[200], ra[16];
        imf_date(ts);
        snprintf(ra, sizeof ra, "%u", cf.retry_after_s);
        snprintf(hv, sizeof hv, "Timestamp: %s; Period-of-Validity: %us; Overload-Reduction-Metric: %u%%%s%s", ts, cf.retry_after_s, reduction > 0 ? reduction : 1,
                 o->instance[0] ? "; NF-Instance: " : "", o->instance);
        g5c_resp_problem_simple(resp, 429, "TOO_MANY_REQUESTS", "the rate allowed for this client is exceeded");
        g5c_resp_header(resp, "retry-after", ra);
        g5c_resp_header(resp, "3gpp-sbi-oci", hv);
        g5c_counter_inc(o->c_rejected);
        return 1;
    }
    if (cf.capacity_rps > 0) {
        char ts[40], hv[160];
        imf_date(ts);
        snprintf(hv, sizeof hv, "Timestamp: %s; Load-Metric: %u%%%s%s", ts, load, o->instance[0] ? "; NF-Instance: " : "", o->instance);
        g5c_resp_header(resp, "3gpp-sbi-lci", hv);
    }
    return o->next != NULL ? o->next(o->next_ctx, req, resp) : 0;
}

g5c_overload *g5c_overload_new(const g5c_overload_cfg *cfg, const char *instance_id, g5c_registry *metrics)
{
    g5c_overload *o = g5c_xcalloc(1, sizeof *o);
    g5c_label l[1] = {{"reason", "rate"}};
    o->cfg = *cfg;
    if (instance_id != NULL)
        snprintf(o->instance, sizeof o->instance, "%s", instance_id);
    pthread_mutex_init(&o->mu, NULL);
    o->c_rejected = g5c_counter_get(metrics, "g5c_overload_rejected_total", "Requests answered 429 because the client exceeded its rate.", l, 1);
    o->g_load = g5c_gauge_get(metrics, "g5c_overload_load_percent", "Load metric reported to consumers (needs overload.capacity_rps).", NULL, 0);
    return o;
}

void g5c_overload_reconfigure(g5c_overload *o, const g5c_overload_cfg *cfg)
{
    pthread_mutex_lock(&o->mu);
    o->cfg = *cfg;
    pthread_mutex_unlock(&o->mu);
}

void g5c_overload_attach(g5c_overload *o, g5c_router *router)
{
    g5c_router_get_guard(router, &o->next, &o->next_ctx);
    g5c_router_set_guard(router, guard, o);
}

void g5c_overload_free(g5c_overload *o)
{
    if (o == NULL)
        return;
    pthread_mutex_destroy(&o->mu);
    free(o);
}
