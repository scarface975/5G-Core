/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* AMF construction, configuration, UE / connection tables, worker pool and timers. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "priv.h"

/* ---- worker pool ---- */

void amf_post(amf *a, amf_task_fn fn, void *arg)
{
    amf_task *t = g5c_xcalloc(1, sizeof *t);
    t->fn = fn;
    t->arg = arg;
    pthread_mutex_lock(&a->qmu);
    if (a->qt != NULL)
        a->qt->next = t;
    else
        a->qh = t;
    a->qt = t;
    pthread_cond_broadcast(&a->qcv);
    pthread_mutex_unlock(&a->qmu);
}

static void *worker_main(void *arg)
{
    amf *a = arg;
    pthread_mutex_lock(&a->qmu);
    for (;;) {
        amf_task *t = a->qh;
        if (t != NULL) {
            a->qh = t->next;
            if (a->qh == NULL)
                a->qt = NULL;
            a->active++;
            pthread_mutex_unlock(&a->qmu);
            t->fn(a, t->arg);
            free(t);
            pthread_mutex_lock(&a->qmu);
            a->active--;
            pthread_cond_broadcast(&a->qcv);
            continue;
        }
        if (a->stop)
            break;
        pthread_cond_wait(&a->qcv, &a->qmu);
    }
    pthread_mutex_unlock(&a->qmu);
    return NULL;
}

int amf_workers_start(amf *a)
{
    a->workers = g5c_xcalloc(a->cfg.workers, sizeof *a->workers);
    for (unsigned i = 0; i < a->cfg.workers; i++) {
        if (pthread_create(&a->workers[a->nworkers], NULL, worker_main, a) != 0)
            return -1;
        a->nworkers++;
    }
    return 0;
}

void amf_workers_stop(amf *a)
{
    pthread_mutex_lock(&a->qmu);
    a->stop = true;
    pthread_cond_broadcast(&a->qcv);
    pthread_mutex_unlock(&a->qmu);
    for (unsigned i = 0; i < a->nworkers; i++)
        pthread_join(a->workers[i], NULL);
    a->nworkers = 0;
    free(a->workers);
    a->workers = NULL;
    while (a->qh != NULL) {
        amf_task *t = a->qh;
        a->qh = t->next;
        free(t);
    }
    a->qt = NULL;
}

/* ---- timers ---- */

typedef struct {
    int target, kind;
    uint64_t id;
    uint32_t gen;
} fire_arg;

static void fire_task(amf *a, void *arg)
{
    fire_arg *f = arg;
    if (f->kind == AMF_TIMER_PERSIST)
        amf_persist_timer(a);
    else
        gmm_timer(a, f->target, f->kind, f->id, f->gen);
    free(f);
}

/* The timers are a binary min-heap on the due time */
static void heap_swap(amf_tmr *x, amf_tmr *y)
{
    amf_tmr t = *x;
    *x = *y;
    *y = t;
}

static void heap_push(amf *a, const amf_tmr *t)
{
    size_t i;
    if (a->ntmrs == a->captmrs) {
        a->captmrs = a->captmrs != 0 ? a->captmrs * 2 : 64;
        a->tmrs = g5c_xrealloc(a->tmrs, a->captmrs * sizeof *a->tmrs);
    }
    i = a->ntmrs++;
    a->tmrs[i] = *t;
    while (i > 0 && a->tmrs[(i - 1) / 2].due > a->tmrs[i].due) {
        heap_swap(&a->tmrs[(i - 1) / 2], &a->tmrs[i]);
        i = (i - 1) / 2;
    }
}

static amf_tmr heap_pop(amf *a)
{
    amf_tmr top = a->tmrs[0];
    size_t i = 0;
    a->tmrs[0] = a->tmrs[--a->ntmrs];
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, m = i;
        if (l < a->ntmrs && a->tmrs[l].due < a->tmrs[m].due)
            m = l;
        if (r < a->ntmrs && a->tmrs[r].due < a->tmrs[m].due)
            m = r;
        if (m == i)
            break;
        heap_swap(&a->tmrs[m], &a->tmrs[i]);
        i = m;
    }
    return top;
}

static void *timer_main(void *arg)
{
    amf *a = arg;
    pthread_mutex_lock(&a->tm_mu);
    for (;;) {
        double now = g5c_now_seconds();
        while (a->ntmrs > 0 && a->tmrs[0].due <= now) {
            amf_tmr t = heap_pop(a);
            fire_arg *f = g5c_xcalloc(1, sizeof *f);
            f->target = t.target;
            f->kind = t.kind;
            f->id = t.id;
            f->gen = t.gen;
            amf_post(a, fire_task, f);
        }
        if (a->stop)
            break;
        if (a->ntmrs > 0) {
            struct timespec ts;
            double wait = g5c_real_wait(a->tmrs[0].due - now); /* virtual seconds to the deadline, real seconds to sleep */
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (time_t)wait;
            ts.tv_nsec += (long)((wait - (double)(time_t)wait) * 1e9);
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
            pthread_cond_timedwait(&a->tm_cv, &a->tm_mu, &ts);
        } else {
            pthread_cond_wait(&a->tm_cv, &a->tm_mu);
        }
    }
    pthread_mutex_unlock(&a->tm_mu);
    return NULL;
}

void amf_timer_start(amf *a, unsigned ms, int target, int kind, uint64_t id, uint32_t gen)
{
    amf_tmr t;
    bool earliest;
    t.due = g5c_now_seconds() + (double)ms / 1000.0;
    t.target = (uint8_t)target;
    t.kind = (uint8_t)kind;
    t.id = id;
    t.gen = gen;
    pthread_mutex_lock(&a->tm_mu);
    earliest = a->ntmrs == 0 || t.due < a->tmrs[0].due;
    heap_push(a, &t);
    if (earliest) /* the thread sleeps until the old top; anything later needs no wake-up */
        pthread_cond_broadcast(&a->tm_cv);
    pthread_mutex_unlock(&a->tm_mu);
}

static int timers_start(amf *a)
{
    if (pthread_create(&a->tm_th, NULL, timer_main, a) != 0)
        return -1;
    a->tm_on = true;
    return 0;
}

static void timers_stop(amf *a)
{
    if (!a->tm_on)
        return;
    pthread_mutex_lock(&a->tm_mu);
    a->stop = true;
    pthread_cond_broadcast(&a->tm_cv);
    pthread_mutex_unlock(&a->tm_mu);
    pthread_join(a->tm_th, NULL);
    a->tm_on = false;
}

/* waits until no task is queued or running (timers that are not yet due do not count) */
void amf_drain_tasks(amf *a)
{
    pthread_mutex_lock(&a->qmu);
    while (a->qh != NULL || a->active != 0)
        pthread_cond_wait(&a->qcv, &a->qmu);
    pthread_mutex_unlock(&a->qmu);
}

/* ---- UE table ---- */

void amf_ue_ref(amf_ue *u)
{
    pthread_mutex_lock(&u->a->tmu);
    u->refs++;
    pthread_mutex_unlock(&u->a->tmu);
}

static void ue_free(amf_ue *u)
{
    amf_pend_clear(u);
    free(u->radio_cap);
    pthread_mutex_destroy(&u->mu);
    free(u);
}

void amf_ue_unref(amf_ue *u)
{
    bool last;
    pthread_mutex_lock(&u->a->tmu);
    last = --u->refs == 0 && u->removed;
    pthread_mutex_unlock(&u->a->tmu);
    if (last)
        ue_free(u);
}

amf_ue *amf_ue_find_supi(amf *a, const char *supi)
{
    amf_ue *u;
    pthread_mutex_lock(&a->tmu);
    u = smap_get(a->ues_by_supi, supi);
    if (u != NULL)
        u->refs++;
    pthread_mutex_unlock(&a->tmu);
    return u;
}

amf_ue *amf_ue_find_tmsi(amf *a, uint32_t tmsi)
{
    amf_ue *u;
    pthread_mutex_lock(&a->tmu);
    u = amap_get(a->ues_by_tmsi, tmsi);
    if (u != NULL)
        u->refs++;
    pthread_mutex_unlock(&a->tmu);
    return u;
}

amf_ue *amf_ue_find_uid(amf *a, uint64_t uid)
{
    amf_ue *u;
    pthread_mutex_lock(&a->tmu);
    u = amap_get(a->ues_by_uid, uid);
    if (u != NULL)
        u->refs++;
    pthread_mutex_unlock(&a->tmu);
    return u;
}

static void ue_link(amf *a, amf_ue *u)
{
    u->next_all = a->ues;
    u->prev_all = NULL;
    if (a->ues != NULL)
        a->ues->prev_all = u;
    a->ues = u;
    a->nues++;
}

/* A new context (returned referenced) unless one for this SUPI exists, in which case that one is returned. */
amf_ue *amf_ue_get_or_create(amf *a, const char *supi)
{
    amf_ue *u;
    pthread_mutex_lock(&a->tmu);
    u = smap_get(a->ues_by_supi, supi);
    if (u == NULL) {
        u = g5c_xcalloc(1, sizeof *u);
        u->a = a;
        pthread_mutex_init(&u->mu, NULL);
        u->uid = ++a->next_uid;
        snprintf(u->supi, sizeof u->supi, "%s", supi);
        u->refs = 1; /* the table's */
        smap_put(a->ues_by_supi, u->supi, u);
        amap_put(a->ues_by_uid, u->uid, u);
        ue_link(a, u);
    }
    u->refs++;
    pthread_mutex_unlock(&a->tmu);
    return u;
}

/* The caller holds u->mu. The context stays alive while references exist. */
void amf_ue_remove(amf_ue *u)
{
    amf *a = u->a;
    int i;
    for (i = 0; i < UT_COUNT; i++)
        u->ut[i].gen++;
    pthread_mutex_lock(&a->tmu);
    if (!u->removed) {
        u->removed = true;
        if (smap_get(a->ues_by_supi, u->supi) == u)
            smap_del(a->ues_by_supi, u->supi);
        amap_del(a->ues_by_uid, u->uid);
        if (u->tmsi != 0 && amap_get(a->ues_by_tmsi, u->tmsi) == u)
            amap_del(a->ues_by_tmsi, u->tmsi);
        if (u->tmsi_new != 0 && amap_get(a->ues_by_tmsi, u->tmsi_new) == u)
            amap_del(a->ues_by_tmsi, u->tmsi_new);
        if (u->prev_all != NULL)
            u->prev_all->next_all = u->next_all;
        else
            a->ues = u->next_all;
        if (u->next_all != NULL)
            u->next_all->prev_all = u->prev_all;
        a->nues--;
        u->refs--; /* the table's reference */
    }
    pthread_mutex_unlock(&a->tmu);
    amf_persist_request(a);
}

uint32_t amf_ue_alloc_tmsi(amf *a, amf_ue *u)
{
    uint32_t t = 0;
    pthread_mutex_lock(&a->tmu);
    for (int tries = 0; tries < 32; tries++) {
        (void)g5c_random(&t, sizeof t);
        if (t != 0 && t != 0xffffffffu && amap_get(a->ues_by_tmsi, t) == NULL)
            break;
        t = 0;
    }
    if (t != 0) {
        if (u->tmsi_new != 0 && amap_get(a->ues_by_tmsi, u->tmsi_new) == u)
            amap_del(a->ues_by_tmsi, u->tmsi_new);
        u->tmsi_new = t;
        amap_put(a->ues_by_tmsi, t, u);
    }
    pthread_mutex_unlock(&a->tmu);
    return t;
}

/* Makes tmsi the current one and drops the previous mapping. */
void amf_ue_set_tmsi(amf_ue *u, uint32_t tmsi)
{
    amf *a = u->a;
    pthread_mutex_lock(&a->tmu);
    if (u->tmsi != 0 && u->tmsi != tmsi && amap_get(a->ues_by_tmsi, u->tmsi) == u)
        amap_del(a->ues_by_tmsi, u->tmsi);
    if (tmsi != 0)
        amap_put(a->ues_by_tmsi, tmsi, u);
    u->tmsi = tmsi;
    if (u->tmsi_new == tmsi)
        u->tmsi_new = 0;
    pthread_mutex_unlock(&a->tmu);
}

/* ---- connections ---- */

amf_conn *amf_conn_new(amf *a, uint32_t gnb, uint16_t stream, uint32_t ran_id)
{
    amf_conn *c = g5c_xcalloc(1, sizeof *c);
    c->a = a;
    c->gnb = gnb;
    c->stream = stream;
    c->ran_id = ran_id;
    pthread_mutex_init(&c->mu, NULL);
    pthread_mutex_lock(&a->tmu);
    c->gnb_gen = a->gnbs[gnb].gen;
    c->amf_id = ++a->next_amf_id;
    c->refs = 2; /* the table's and the caller's */
    amap_put(a->conns_by_id, c->amf_id, c);
    c->next_all = a->conns;
    if (a->conns != NULL)
        a->conns->prev_all = c;
    a->conns = c;
    a->nconns++;
    a->npreauth++;
    c->pre_auth = true;
    a->gnbs[gnb].nconns++;
    pthread_mutex_unlock(&a->tmu);
    return c;
}

amf_conn *amf_conn_find(amf *a, uint64_t amf_id)
{
    amf_conn *c;
    pthread_mutex_lock(&a->tmu);
    c = amap_get(a->conns_by_id, amf_id);
    if (c != NULL)
        c->refs++;
    pthread_mutex_unlock(&a->tmu);
    return c;
}

void amf_conn_ref(amf_conn *c)
{
    pthread_mutex_lock(&c->a->tmu);
    c->refs++;
    pthread_mutex_unlock(&c->a->tmu);
}

static void conn_free(amf_conn *c)
{
    while (c->qh != NULL) {
        amf_ev *e = c->qh;
        c->qh = e->next;
        g5c_json_free(e->pdu);
        free(e);
    }
    free(c->init_nas);
    free(c->last_nas);
    free(c->ho_container);
    free(c->reg_status_pdu);
    pthread_mutex_destroy(&c->mu);
    free(c);
}

void amf_conn_unref(amf_conn *c)
{
    bool last;
    pthread_mutex_lock(&c->a->tmu);
    last = --c->refs == 0;
    pthread_mutex_unlock(&c->a->tmu);
    if (last)
        conn_free(c);
}

/* Takes the connection out of the table (drops the table's reference). Idempotent. */
void amf_conn_unlink(amf_conn *c)
{
    amf *a = c->a;
    bool did = false;
    pthread_mutex_lock(&a->tmu);
    if (!c->closed) {
        c->closed = true;
        did = true;
        amap_del(a->conns_by_id, c->amf_id);
        if (c->prev_all != NULL)
            c->prev_all->next_all = c->next_all;
        else
            a->conns = c->next_all;
        if (c->next_all != NULL)
            c->next_all->prev_all = c->prev_all;
        a->nconns--;
        if (c->pre_auth && a->npreauth > 0)
            a->npreauth--;
        c->pre_auth = false;
        if (a->gnbs[c->gnb].nconns > 0)
            a->gnbs[c->gnb].nconns--;
        for (int i = 0; i < CT_COUNT; i++)
            c->t[i].gen++;
    }
    pthread_mutex_unlock(&a->tmu);
    if (did)
        amf_conn_unref(c);
}

void amf_conn_authenticated(amf_conn *c)
{
    amf *a = c->a;
    pthread_mutex_lock(&a->tmu);
    if (c->pre_auth) {
        c->pre_auth = false;
        if (a->npreauth > 0)
            a->npreauth--;
    }
    pthread_mutex_unlock(&a->tmu);
}

/* ---- connection mailbox ---- */

static void conn_run(amf *a, void *arg)
{
    amf_conn *c = arg;
    (void)a;
    for (;;) {
        amf_ev *e;
        pthread_mutex_lock(&c->mu);
        e = c->qh;
        if (e == NULL) {
            c->running = false;
            pthread_mutex_unlock(&c->mu);
            break;
        }
        c->qh = e->next;
        if (c->qh == NULL)
            c->qt = NULL;
        pthread_mutex_unlock(&c->mu);
        c->rx_gnb = e->rx_gnb;
        c->rx_gen = e->rx_gen;
        c->rx_stream = e->rx_stream;
        if (e->kind == EV_NGAP)
            ngap_conn_event(c, e->pdu);
        else if (e->kind == EV_TIMER)
            ngap_conn_timer(c, e->tkind, e->tgen);
        else
            ngap_conn_lost(c);
        g5c_json_free(e->pdu);
        free(e);
    }
    amf_conn_unref(c);
}

static void post_ev(amf_conn *c, amf_ev *e)
{
    bool start = false;
    pthread_mutex_lock(&c->mu);
    if (c->qt != NULL)
        c->qt->next = e;
    else
        c->qh = e;
    c->qt = e;
    if (!c->running) {
        c->running = true;
        start = true;
    }
    pthread_mutex_unlock(&c->mu);
    if (start) {
        amf_conn_ref(c);
        amf_post(c->a, conn_run, c);
    }
}

void amf_conn_post(amf_conn *c, int kind, g5c_json *pdu)
{
    amf_ev *e = g5c_xcalloc(1, sizeof *e);
    e->kind = kind;
    e->pdu = pdu;
    post_ev(c, e);
}

void amf_conn_post_rx(amf_conn *c, g5c_json *pdu, uint32_t gnb, uint32_t gen, uint16_t stream)
{
    amf_ev *e = g5c_xcalloc(1, sizeof *e);
    e->kind = EV_NGAP;
    e->pdu = pdu;
    e->rx_gnb = gnb;
    e->rx_gen = gen;
    e->rx_stream = stream;
    post_ev(c, e);
}

void amf_conn_post_timer(amf_conn *c, int kind, uint32_t gen)
{
    amf_ev *e = g5c_xcalloc(1, sizeof *e);
    e->kind = EV_TIMER;
    e->tkind = kind;
    e->tgen = gen;
    post_ev(c, e);
}

/* ---- gauges ---- */

void amf_gauges(amf *a)
{
    size_t reg = 0, conn = 0;
    pthread_mutex_lock(&a->tmu);
    for (amf_ue *u = a->ues; u != NULL; u = u->next_all) {
        if (u->mm == MM_REGISTERED)
            reg++;
        if (u->cm == CM_CONNECTED)
            conn++;
    }
    g5c_gauge_set(g5c_gauge_get(a->metrics, "g5c_amf_registered_ues", "UEs in 5GMM-REGISTERED.", NULL, 0), (int64_t)reg);
    g5c_gauge_set(g5c_gauge_get(a->metrics, "g5c_amf_connected_ues", "UEs in CM-CONNECTED.", NULL, 0), (int64_t)conn);
    g5c_gauge_set(g5c_gauge_get(a->metrics, "g5c_amf_ue_contexts", "UE contexts held.", NULL, 0), (int64_t)a->nues);
    {
        size_t n = 0;
        for (size_t i = 0; i < AMF_MAX_GNB; i++)
            if (a->gnbs[i].used && a->gnbs[i].setup)
                n++;
        g5c_gauge_set(g5c_gauge_get(a->metrics, "g5c_amf_gnbs", "gNBs with a completed NG Setup.", NULL, 0), (int64_t)n);
    }
    pthread_mutex_unlock(&a->tmu);
}

/* ---- configuration ---- */

static bool http_uri(const char *u)
{
    return u != NULL && (strncmp(u, "http://", 7) == 0 || strncmp(u, "https://", 8) == 0) && strlen(u) > 9;
}

static char *peer_uri(const g5c_json *cfg, const char *name, char *err, size_t cap)
{
    const g5c_json *o = g5c_json_get(cfg, name);
    const char *u;
    char *r;
    size_t n;
    if (o == NULL)
        return NULL;
    u = g5c_json_get_str(o, "uri");
    if (!http_uri(u)) {
        snprintf(err, cap, "invalid config: `amf.%s.uri` must be an http(s) URI", name);
        return NULL;
    }
    r = g5c_xstrdup(u);
    n = strlen(r);
    while (n > 0 && r[n - 1] == '/')
        r[--n] = 0;
    return r;
}

static int parse_alg_list(const g5c_json *arr, bool integrity, uint8_t *out, size_t *n, char *err, size_t cap)
{
    *n = 0;
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const char *s = g5c_json_str(g5c_json_at(arr, i));
        int id = -1;
        if (s != NULL) {
            if (integrity && strcmp(s, "NIA2") == 0)
                id = 2;
            else if (integrity && strcmp(s, "NIA0") == 0)
                id = 0;
            else if (!integrity && strcmp(s, "NEA2") == 0)
                id = 2;
            else if (!integrity && strcmp(s, "NEA0") == 0)
                id = 0;
            else if (s[0] == 'N' && (s[3] == '1' || s[3] == '3')) {
                snprintf(err, cap, "invalid config: `%s` is not available (SNOW 3G / ZUC are not implemented, ADR-0012)", s);
                return -1;
            }
        }
        if (id < 0 || *n >= 3) {
            snprintf(err, cap, "invalid config: unknown or surplus %s algorithm", integrity ? "integrity" : "ciphering");
            return -1;
        }
        out[(*n)++] = (uint8_t)id;
    }
    return 0;
}

static int parse_tac(const g5c_json *v, uint32_t *tac)
{
    int64_t i;
    if (g5c_json_get_int(v, "tac", &i) && i >= 0 && i <= 0xffffff) {
        *tac = (uint32_t)i;
        return 0;
    }
    {
        const char *s = g5c_json_get_str(v, "tac");
        char *end;
        unsigned long u;
        if (s == NULL || strlen(s) != 6)
            return -1;
        u = strtoul(s, &end, 16);
        if (*end != 0)
            return -1;
        *tac = (uint32_t)u;
        return 0;
    }
}

static int get_uint(const g5c_json *o, const char *key, int64_t lo, int64_t hi, unsigned *out, const char *where, char *err, size_t cap)
{
    int64_t v;
    if (g5c_json_get(o, key) == NULL)
        return 0;
    if (!g5c_json_get_int(o, key, &v) || v < lo || v > hi) {
        snprintf(err, cap, "invalid config: `%s.%s` must be %lld..=%lld", where, key, (long long)lo, (long long)hi);
        return -1;
    }
    *out = (unsigned)v;
    return 0;
}

static void cfg_free(amf_cfg *c)
{
    free(c->name);
    free(c->ausf);
    free(c->udm);
    free(c->pcf);
    free(c->smf);
    free(c->nrf);
    free(c->nssf);
    free(c->default_dnn);
    free(c->full_name);
    free(c->short_name);
    free(c->state_file);
}

/* `overload: { registrations_per_s, per_gnb_per_s, burst_s, t3346_s }` into cf (NULL: off) */
static int parse_overload(const g5c_json *ov, amf_cfg *cf, char *err, size_t cap)
{
    static const char *const k_ov[] = {"registrations_per_s", "per_gnb_per_s", "burst_s", "t3346_s", NULL};
    cf->ov_regs_per_s = cf->ov_gnb_regs_per_s = 0;
    cf->ov_burst_s = 1;
    cf->ov_t3346 = 30;
    if (ov == NULL)
        return 0;
    if (!g5c_json_is(ov, G5C_J_OBJECT) || g5c_json_check_keys(ov, k_ov, "amf.overload", err, cap) != 0) {
        if (err[0] == 0)
            snprintf(err, cap, "invalid config: `amf.overload` must be a mapping");
        return -1;
    }
    if (get_uint(ov, "registrations_per_s", 1, 1000000, &cf->ov_regs_per_s, "amf.overload", err, cap) != 0 ||
        get_uint(ov, "per_gnb_per_s", 1, 1000000, &cf->ov_gnb_regs_per_s, "amf.overload", err, cap) != 0 ||
        get_uint(ov, "burst_s", 1, 60, &cf->ov_burst_s, "amf.overload", err, cap) != 0 ||
        get_uint(ov, "t3346_s", 2, 11160, &cf->ov_t3346, "amf.overload", err, cap) != 0)
        return -1;
    if (cf->ov_regs_per_s == 0 && cf->ov_gnb_regs_per_s == 0) {
        snprintf(err, cap, "invalid config: `amf.overload` needs `registrations_per_s` or `per_gnb_per_s`");
        return -1;
    }
    return 0;
}

/* configuration reload of `amf.overload`: the new limits apply from the next registration, with full buckets */
static int amf_reload_overload(void *ctx, const g5c_json *from, const g5c_json *to, char *err, size_t cap)
{
    amf *a = ctx;
    amf_cfg tmp;
    (void)from;
    memset(&tmp, 0, sizeof tmp);
    if (parse_overload(to, &tmp, err, cap) != 0)
        return -1;
    pthread_mutex_lock(&a->tmu);
    a->cfg.ov_regs_per_s = tmp.ov_regs_per_s;
    a->cfg.ov_gnb_regs_per_s = tmp.ov_gnb_regs_per_s;
    a->cfg.ov_burst_s = tmp.ov_burst_s;
    a->cfg.ov_t3346 = tmp.ov_t3346;
    a->ov_tokens = a->ov_last = 0;
    for (size_t i = 0; i < AMF_MAX_GNB; i++)
        a->gnbs[i].ov_tokens = a->gnbs[i].ov_last = 0;
    pthread_mutex_unlock(&a->tmu);
    G5C_LOGI(AMF_LOG, "amf.overload is now %u/s for the AMF, %u/s for each gNB", tmp.ov_regs_per_s, tmp.ov_gnb_regs_per_s);
    return 0;
}

amf *amf_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t cap)
{
    static const char *const k_amf[] = {"name", "guami", "ngap", "capacity", "tais", "slices", "security", "ausf", "udm", "pcf", "smf", "nssf", "default_dnn",
                                        "network_name", "timers", "paging_tries", "workers", "self_uri", "state_file", "reachable_grace",
                                        "max_unauthenticated", "inject", "overload", NULL};
    static const char *const k_guami[] = {"region", "set", "pointer", NULL};
    static const char *const k_ngap[] = {"address", "port", NULL};
    static const char *const k_sec[] = {"integrity", "ciphering", NULL};
    static const char *const k_timers[] = {"t3502", "t3510", "t3512", "t3513", "t3522", "t3550", "t3555", "t3560", "t3570", NULL};
    static const char *const k_name[] = {"full", "short", NULL};
    const g5c_json *c = g5c_json_get(root, "amf"), *g, *n, *t, *sl, *sec, *tm, *nn;
    amf *a;
    amf_cfg *cf;
    int64_t v;
    unsigned u;

    if (!g5c_json_is(c, G5C_J_OBJECT)) {
        snprintf(err, cap, "invalid config: the `amf` section is required");
        return NULL;
    }
    if (g5c_json_check_keys(c, k_amf, "amf", err, cap) != 0)
        return NULL;
    a = g5c_xcalloc(1, sizeof *a);
    cf = &a->cfg;
    a->nf = nf;
    a->client = nf->client;
    a->metrics = nf->metrics;
    snprintf(a->instance_id, sizeof a->instance_id, "%s", nf->instance_id);
    pthread_mutex_init(&a->tmu, NULL);
    pthread_mutex_init(&a->qmu, NULL);
    pthread_cond_init(&a->qcv, NULL);
    pthread_mutex_init(&a->tm_mu, NULL);
    pthread_cond_init(&a->tm_cv, NULL);
    pthread_mutex_init(&a->emu, NULL);
    pthread_mutex_init(&a->pmu, NULL);
    for (size_t i = 0; i < AMF_MAX_GNB; i++) {
        pthread_mutex_init(&a->gnbs[i].smu, NULL);
        a->gnbs[i].fd = -1;
    }
    a->conns_by_id = amap_new();
    a->ues_by_uid = amap_new();
    a->ues_by_tmsi = amap_new();
    a->ues_by_supi = smap_new();
    a->lfd = a->epfd = a->wakefd = -1;
    a->next_amf_id = 0;

    snprintf(cf->mcc, sizeof cf->mcc, "%s", nf->common.mcc);
    snprintf(cf->mnc, sizeof cf->mnc, "%s", nf->common.mnc);
    if (nas_plmn_encode(cf->mcc, cf->mnc, cf->plmn) != 0) {
        snprintf(err, cap, "invalid config: the PLMN is not usable");
        goto fail;
    }
    if (g5c_serving_network_name(cf->mcc, cf->mnc, a->snn, sizeof a->snn) < 0) {
        snprintf(err, cap, "invalid config: cannot build the serving network name");
        goto fail;
    }
    cf->name = g5c_xstrdup(g5c_json_get_str(c, "name") != NULL ? g5c_json_get_str(c, "name") : nf->common.name != NULL ? nf->common.name : "amf");
    cf->id.region = 1;
    cf->id.set = 1;
    cf->id.pointer = 0;
    g = g5c_json_get(c, "guami");
    if (g != NULL) {
        if (g5c_json_check_keys(g, k_guami, "amf.guami", err, cap) != 0)
            goto fail;
        if (g5c_json_get(g, "region") != NULL && (!g5c_json_get_int(g, "region", &v) || v < 0 || v > 255)) {
            snprintf(err, cap, "invalid config: `amf.guami.region` must be 0..=255");
            goto fail;
        } else if (g5c_json_get(g, "region") != NULL) {
            cf->id.region = (uint8_t)v;
        }
        if (g5c_json_get(g, "set") != NULL && (!g5c_json_get_int(g, "set", &v) || v < 0 || v > 1023)) {
            snprintf(err, cap, "invalid config: `amf.guami.set` must be 0..=1023");
            goto fail;
        } else if (g5c_json_get(g, "set") != NULL) {
            cf->id.set = (uint16_t)v;
        }
        if (g5c_json_get(g, "pointer") != NULL && (!g5c_json_get_int(g, "pointer", &v) || v < 0 || v > 63)) {
            snprintf(err, cap, "invalid config: `amf.guami.pointer` must be 0..=63");
            goto fail;
        } else if (g5c_json_get(g, "pointer") != NULL) {
            cf->id.pointer = (uint8_t)v;
        }
    }
    snprintf(cf->ngap_addr, sizeof cf->ngap_addr, "127.0.0.5");
    cf->ngap_port = 38412;
    n = g5c_json_get(c, "ngap");
    if (n != NULL) {
        const char *ad;
        if (g5c_json_check_keys(n, k_ngap, "amf.ngap", err, cap) != 0)
            goto fail;
        ad = g5c_json_get_str(n, "address");
        if (ad != NULL) {
            if (strlen(ad) >= sizeof cf->ngap_addr) {
                snprintf(err, cap, "invalid config: `amf.ngap.address` is too long");
                goto fail;
            }
            snprintf(cf->ngap_addr, sizeof cf->ngap_addr, "%s", ad);
        }
        if (g5c_json_get(n, "port") != NULL) {
            if (!g5c_json_get_int(n, "port", &v) || v < 0 || v > 65535) {
                snprintf(err, cap, "invalid config: `amf.ngap.port` must be 0..=65535");
                goto fail;
            }
            cf->ngap_port = (uint16_t)v;
        }
    }
    cf->capacity = 255;
    if (g5c_json_get(c, "capacity") != NULL) {
        if (!g5c_json_get_int(c, "capacity", &v) || v < 0 || v > 255) {
            snprintf(err, cap, "invalid config: `amf.capacity` must be 0..=255");
            goto fail;
        }
        cf->capacity = (uint16_t)v;
    }
    t = g5c_json_get(c, "tais");
    if (t == NULL) {
        cf->tai[0].tac = 1;
        memcpy(cf->tai[0].plmn, cf->plmn, 3);
        cf->ntai = 1;
    } else {
        if (!g5c_json_is(t, G5C_J_ARRAY) || g5c_json_len(t) == 0 || g5c_json_len(t) > AMF_MAX_TAI) {
            snprintf(err, cap, "invalid config: `amf.tais` must list 1 to %d tracking areas", AMF_MAX_TAI);
            goto fail;
        }
        for (size_t i = 0; i < g5c_json_len(t); i++) {
            const g5c_json *e = g5c_json_at(t, i);
            static const char *const k_tai[] = {"tac", NULL};
            if (g5c_json_check_keys(e, k_tai, "amf.tais[]", err, cap) != 0)
                goto fail;
            if (parse_tac(e, &cf->tai[i].tac) != 0) {
                snprintf(err, cap, "invalid config: `amf.tais[].tac` must be 0..=16777215 or 6 hex digits");
                goto fail;
            }
            memcpy(cf->tai[i].plmn, cf->plmn, 3);
            cf->ntai++;
        }
    }
    sl = g5c_json_get(c, "slices");
    if (sl == NULL) {
        cf->slices[0].sst = 1;
        cf->nslices = 1;
    } else {
        if (!g5c_json_is(sl, G5C_J_ARRAY) || g5c_json_len(sl) == 0 || g5c_json_len(sl) > AMF_MAX_SLICE) {
            snprintf(err, cap, "invalid config: `amf.slices` must list 1 to %d slices", AMF_MAX_SLICE);
            goto fail;
        }
        for (size_t i = 0; i < g5c_json_len(sl); i++) {
            if (!amf_snssai_from_json(g5c_json_at(sl, i), &cf->slices[i])) {
                snprintf(err, cap, "invalid config: `amf.slices[]` needs `sst` 0..=255 and optionally a 6 hex digit `sd`");
                goto fail;
            }
            cf->nslices++;
        }
    }
    cf->int_pref[0] = 2;
    cf->nint = 1;
    cf->enc_pref[0] = 2;
    cf->enc_pref[1] = 0;
    cf->nenc = 2;
    sec = g5c_json_get(c, "security");
    if (sec != NULL) {
        if (g5c_json_check_keys(sec, k_sec, "amf.security", err, cap) != 0)
            goto fail;
        if (g5c_json_get(sec, "integrity") != NULL &&
            (parse_alg_list(g5c_json_get(sec, "integrity"), true, cf->int_pref, &cf->nint, err, cap) != 0 || cf->nint == 0)) {
            if (err[0] == 0)
                snprintf(err, cap, "invalid config: `amf.security.integrity` must not be empty");
            goto fail;
        }
        if (g5c_json_get(sec, "ciphering") != NULL &&
            (parse_alg_list(g5c_json_get(sec, "ciphering"), false, cf->enc_pref, &cf->nenc, err, cap) != 0 || cf->nenc == 0)) {
            if (err[0] == 0)
                snprintf(err, cap, "invalid config: `amf.security.ciphering` must not be empty");
            goto fail;
        }
    }
    err[0] = 0;
    cf->ausf = peer_uri(c, "ausf", err, cap);
    if (err[0] != 0)
        goto fail;
    cf->udm = peer_uri(c, "udm", err, cap);
    if (err[0] != 0)
        goto fail;
    cf->pcf = peer_uri(c, "pcf", err, cap);
    if (err[0] != 0)
        goto fail;
    cf->smf = peer_uri(c, "smf", err, cap);
    if (err[0] != 0)
        goto fail;
    {
        const g5c_json *ns = g5c_json_get(c, "nssf");
        bool en = true;
        if (ns != NULL) {
            static const char *const k_nssf[] = {"uri", "enabled", NULL};
            if (!g5c_json_is(ns, G5C_J_OBJECT) || g5c_json_check_keys(ns, k_nssf, "amf.nssf", err, cap) != 0) {
                if (err[0] == 0)
                    snprintf(err, cap, "invalid config: `amf.nssf` must be a mapping");
                goto fail;
            }
            (void)g5c_json_get_bool(ns, "enabled", &en);
            if (en && g5c_json_get_str(ns, "uri") != NULL) {
                cf->nssf = peer_uri(c, "nssf", err, cap);
                if (err[0] != 0)
                    goto fail;
            }
            cf->use_nssf = en;
        }
    }
    if (nf->common.nrf_uri != NULL) {
        size_t nl;
        cf->nrf = g5c_xstrdup(nf->common.nrf_uri);
        nl = strlen(cf->nrf);
        while (nl > 0 && cf->nrf[nl - 1] == '/')
            cf->nrf[--nl] = 0;
        a->nrf_disc = g5c_disc_new(nf->client, cf->nrf, "AMF", nf->instance_id);
    }
    if ((cf->ausf == NULL && cf->nrf == NULL) || (cf->udm == NULL && cf->nrf == NULL) || (cf->smf == NULL && cf->nrf == NULL)) {
        snprintf(err, cap, "invalid config: `amf.ausf`, `amf.udm` and `amf.smf` (or an `nrf`) are required");
        goto fail;
    }
    cf->default_dnn = g5c_xstrdup(g5c_json_get_str(c, "default_dnn") != NULL ? g5c_json_get_str(c, "default_dnn") : "internet");
    nn = g5c_json_get(c, "network_name");
    cf->full_name = g5c_xstrdup("g5c");
    cf->short_name = g5c_xstrdup("g5c");
    if (nn != NULL) {
        cf->send_names = true;
        if (g5c_json_check_keys(nn, k_name, "amf.network_name", err, cap) != 0)
            goto fail;
        if (g5c_json_get_str(nn, "full") != NULL) {
            free(cf->full_name);
            cf->full_name = g5c_xstrdup(g5c_json_get_str(nn, "full"));
        }
        if (g5c_json_get_str(nn, "short") != NULL) {
            free(cf->short_name);
            cf->short_name = g5c_xstrdup(g5c_json_get_str(nn, "short"));
        }
    }
    cf->t3512 = 3240;
    cf->t3502 = 720;
    cf->t3510 = 15;
    cf->t3513 = 6;
    cf->t3522 = 6;
    cf->t3550 = 6;
    cf->t3555 = 6;
    cf->t3560 = 6;
    cf->t3570 = 6;
    tm = g5c_json_get(c, "timers");
    if (tm != NULL) {
        if (g5c_json_check_keys(tm, k_timers, "amf.timers", err, cap) != 0)
            goto fail;
        if (get_uint(tm, "t3502", 1, 100000, &cf->t3502, "amf.timers", err, cap) != 0 || get_uint(tm, "t3510", 1, 3600, &cf->t3510, "amf.timers", err, cap) != 0 ||
            get_uint(tm, "t3512", 1, 1152000, &cf->t3512, "amf.timers", err, cap) != 0 || get_uint(tm, "t3513", 1, 3600, &cf->t3513, "amf.timers", err, cap) != 0 ||
            get_uint(tm, "t3522", 1, 3600, &cf->t3522, "amf.timers", err, cap) != 0 || get_uint(tm, "t3550", 1, 3600, &cf->t3550, "amf.timers", err, cap) != 0 ||
            get_uint(tm, "t3555", 1, 3600, &cf->t3555, "amf.timers", err, cap) != 0 || get_uint(tm, "t3560", 1, 3600, &cf->t3560, "amf.timers", err, cap) != 0 ||
            get_uint(tm, "t3570", 1, 3600, &cf->t3570, "amf.timers", err, cap) != 0)
            goto fail;
    }
    cf->paging_tries = 4;
    cf->workers = 4;
    cf->reach_grace = 240;
    cf->unauth_ue_max = 4096;
    u = 0;
    if (get_uint(c, "paging_tries", 1, 10, &cf->paging_tries, "amf", err, cap) != 0 || get_uint(c, "workers", 1, 256, &cf->workers, "amf", err, cap) != 0 ||
        get_uint(c, "reachable_grace", 0, 86400, &cf->reach_grace, "amf", err, cap) != 0 ||
        get_uint(c, "max_unauthenticated", 1, 1000000, &cf->unauth_ue_max, "amf", err, cap) != 0)
        goto fail;
    (void)u;
    if (parse_overload(g5c_json_get(c, "overload"), cf, err, cap) != 0)
        goto fail;
    g5c_nf_on_reload(nf, "amf.overload", amf_reload_overload, a);
    if (g5c_json_get(c, "inject") != NULL) { /* `inject: { registration_reject: [{ supi: imsi-0010100, cause: 11 }], accept_delay_ms */
        static const char *const k_inj[] = {"registration_reject", "accept_delay_ms", NULL}, *const k_rej[] = {"supi", "cause", NULL};
        const g5c_json *inj = g5c_json_get(c, "inject"), *rl = g5c_json_get(inj, "registration_reject");
        int64_t d = 0;
        if (!g5c_json_is(inj, G5C_J_OBJECT) || g5c_json_check_keys(inj, k_inj, "amf.inject", err, cap) != 0) {
            if (err[0] == 0)
                snprintf(err, cap, "invalid config: `amf.inject` must be a mapping");
            goto fail;
        }
        for (size_t i = 0; rl != NULL && i < g5c_json_len(rl); i++) {
            const g5c_json *e = g5c_json_at(rl, i);
            int64_t cause = 0;
            if (i >= 8 || !g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, k_rej, "amf.inject.registration_reject", err, cap) != 0 || g5c_json_get_str(e, "supi") == NULL ||
                strlen(g5c_json_get_str(e, "supi")) >= sizeof cf->inject_reject[0].supi || !g5c_json_get_int(e, "cause", &cause) || cause < 1 || cause > 255) {
                if (err[0] == 0)
                    snprintf(err, cap, "invalid config: `amf.inject.registration_reject` takes up to 8 entries { supi: <prefix>, cause: 1..255 }");
                goto fail;
            }
            snprintf(cf->inject_reject[cf->ninject_reject].supi, sizeof cf->inject_reject[0].supi, "%s", g5c_json_get_str(e, "supi"));
            cf->inject_reject[cf->ninject_reject++].cause = (uint8_t)cause;
        }
        if (g5c_json_get(inj, "accept_delay_ms") != NULL && (!g5c_json_get_int(inj, "accept_delay_ms", &d) || d < 0 || d > 60000)) {
            snprintf(err, cap, "invalid config: `amf.inject.accept_delay_ms` must be 0..=60000");
            goto fail;
        }
        cf->inject_delay_ms = (unsigned)d;
        G5C_LOGW(AMF_LOG, "FAILURE INJECTION is configured (amf.inject): this function misbehaves on purpose");
    }
    if (g5c_json_get(c, "self_uri") != NULL) {
        const char *su = g5c_json_get_str(c, "self_uri");
        if (!http_uri(su)) {
            snprintf(err, cap, "invalid config: `amf.self_uri` must be an http(s) URI");
            goto fail;
        }
        a->self_uri = g5c_xstrdup(su);
    }
    if (g5c_json_get(c, "state_file") != NULL) {
        const char *sf = g5c_json_get_str(c, "state_file");
        if (sf == NULL || *sf == 0 || strlen(sf) > 4000) {
            snprintf(err, cap, "invalid config: `amf.state_file` must be a path");
            goto fail;
        }
        cf->state_file = g5c_xstrdup(sf);
    }
    return a;
fail:
    amf_destroy(a);
    return NULL;
}

/* ---- lifecycle ---- */

void amf_set_self_uri(amf *a, const char *uri)
{
    free(a->self_uri);
    a->self_uri = uri != NULL ? g5c_xstrdup(uri) : NULL;
}

int amf_start(amf *a, char *err, size_t cap)
{
    if (amf_workers_start(a) != 0) {
        snprintf(err, cap, "cannot start the worker threads");
        return -1;
    }
    if (timers_start(a) != 0) {
        snprintf(err, cap, "cannot start the timer thread");
        return -1;
    }
    (void)amf_persist_restore(a);
    if (amf_sctp_start(a, err, cap) != 0)
        return -1;
    return 0;
}

void amf_routes(g5c_router *r, amf *a)
{
    amf_n1n2_routes(r, a);
    amf_callbacks_routes(r, a);
    amf_events_routes(r, a);
}

g5c_router *amf_router(amf *a)
{
    g5c_router *r = g5c_router_new();
    amf_routes(r, a);
    return r;
}

void amf_destroy(amf *a)
{
    if (a == NULL)
        return;
    a->stop = true;
    amf_sctp_stop(a);
    timers_stop(a);
    if (a->nworkers > 0 || a->workers != NULL) {
        amf_persist_flush(a);
        amf_workers_stop(a);
    }
    while (a->conns != NULL) {
        amf_conn *c = a->conns;
        if (c->ue != NULL) {
            amf_ue *u = c->ue;
            c->ue = NULL;
            if (u->conn == c)
                u->conn = NULL;
            if (u->ho_conn == c)
                u->ho_conn = NULL;
            amf_ue_unref(u);
        }
        amf_conn_unlink(c);
    }
    while (a->ues != NULL) {
        amf_ue *u = a->ues;
        amf_ue_ref(u);
        pthread_mutex_lock(&u->mu);
        amf_ue_remove(u);
        pthread_mutex_unlock(&u->mu);
        amf_ue_unref(u);
    }
    amf_events_free(a);
    amap_free(a->conns_by_id);
    amap_free(a->ues_by_uid);
    amap_free(a->ues_by_tmsi);
    smap_free(a->ues_by_supi);
    free(a->tmrs);
    for (size_t i = 0; i < AMF_MAX_GNB; i++)
        pthread_mutex_destroy(&a->gnbs[i].smu);
    cfg_free(&a->cfg);
    free(a->self_uri);
    pthread_mutex_destroy(&a->tmu);
    pthread_mutex_destroy(&a->qmu);
    pthread_cond_destroy(&a->qcv);
    pthread_mutex_destroy(&a->tm_mu);
    pthread_cond_destroy(&a->tm_cv);
    g5c_disc_free(a->nrf_disc);
    pthread_mutex_destroy(&a->emu);
    pthread_mutex_destroy(&a->pmu);
    free(a);
}

/* ---- introspection ---- */

uint16_t amf_ngap_port(const amf *a)
{
    return a->bound_port;
}

size_t amf_gnb_count(amf *a)
{
    size_t n = 0;
    pthread_mutex_lock(&a->tmu);
    for (size_t i = 0; i < AMF_MAX_GNB; i++)
        if (a->gnbs[i].used && a->gnbs[i].setup)
            n++;
    pthread_mutex_unlock(&a->tmu);
    return n;
}

size_t amf_ue_count(amf *a)
{
    size_t n;
    pthread_mutex_lock(&a->tmu);
    n = a->nues;
    pthread_mutex_unlock(&a->tmu);
    return n;
}

bool amf_ue_lookup(amf *a, const char *supi, amf_ue_info *out)
{
    amf_ue *u = amf_ue_find_supi(a, supi);
    memset(out, 0, sizeof *out);
    if (u == NULL)
        return false;
    pthread_mutex_lock(&u->mu);
    out->known = true;
    out->registered = u->mm == MM_REGISTERED;
    out->connected = u->cm == CM_CONNECTED;
    out->tmsi = u->tmsi;
    out->npdu = amf_pdu_count(u);
    out->nallowed = (unsigned)u->nallowed;
    out->int_alg = u->sec.int_alg;
    out->enc_alg = u->sec.enc_alg;
    out->ul_count = u->sec.ul_count;
    out->dl_count = u->sec.dl_count;
    pthread_mutex_unlock(&u->mu);
    amf_ue_unref(u);
    return true;
}

void amf_get_stats(amf *a, amf_stats *out)
{
    out->registrations = atomic_load(&a->st_registrations);
    out->auth_ok = atomic_load(&a->st_auth_ok);
    out->auth_fail = atomic_load(&a->st_auth_fail);
    out->deregistrations = atomic_load(&a->st_dereg);
    out->service_requests = atomic_load(&a->st_service);
    out->pagings = atomic_load(&a->st_paging);
    out->handovers = atomic_load(&a->st_handover);
    out->path_switches = atomic_load(&a->st_pathswitch);
    out->releases = atomic_load(&a->st_release);
}

int amf_ue_deregister(amf *a, const char *supi, bool reregister)
{
    amf_ue *u = amf_ue_find_supi(a, supi);
    int rc;
    if (u == NULL)
        return -1;
    pthread_mutex_lock(&u->mu);
    rc = gmm_start_dereg(u, reregister);
    pthread_mutex_unlock(&u->mu);
    amf_ue_unref(u);
    return rc;
}

int amf_ue_config_update(amf *a, const char *supi, bool new_guti)
{
    amf_ue *u = amf_ue_find_supi(a, supi);
    int rc;
    if (u == NULL)
        return -1;
    pthread_mutex_lock(&u->mu);
    rc = gmm_start_config_update(u, new_guti);
    pthread_mutex_unlock(&u->mu);
    amf_ue_unref(u);
    return rc;
}

/* What this AMF tells the NRF about itself (TS 29.510 6.1.6.2.9 AmfInfo). Caller frees. */
g5c_json *amf_nrf_info(const amf *a)
{
    g5c_json *o = g5c_json_new_obj(), *ai = g5c_json_set(o, "amfInfo", g5c_json_new_obj()), *gl, *tl;
    char buf[16];
    snprintf(buf, sizeof buf, "%03X", a->cfg.id.set & 0x3ffu);
    g5c_json_set_str(ai, "amfSetId", buf);
    snprintf(buf, sizeof buf, "%02X", a->cfg.id.region);
    g5c_json_set_str(ai, "amfRegionId", buf);
    gl = g5c_json_set(ai, "guamiList", g5c_json_new_arr());
    {
        g5c_json *e = g5c_json_push(gl, g5c_json_new_obj()), *p = g5c_json_set(e, "plmnId", g5c_json_new_obj());
        g5c_json_set_str(p, "mcc", a->cfg.mcc);
        g5c_json_set_str(p, "mnc", a->cfg.mnc);
        snprintf(buf, sizeof buf, "%06X", (uint32_t)a->cfg.id.region << 16 | (uint32_t)a->cfg.id.set << 6 | a->cfg.id.pointer);
        g5c_json_set_str(e, "amfId", buf);
    }
    tl = g5c_json_set(ai, "taiList", g5c_json_new_arr());
    for (size_t i = 0; i < a->cfg.ntai; i++) {
        g5c_json *e = g5c_json_push(tl, g5c_json_new_obj()), *p = g5c_json_set(e, "plmnId", g5c_json_new_obj());
        g5c_json_set_str(p, "mcc", a->cfg.mcc);
        g5c_json_set_str(p, "mnc", a->cfg.mnc);
        snprintf(buf, sizeof buf, "%06X", a->cfg.tai[i].tac & 0xffffffu);
        g5c_json_set_str(e, "tac", buf);
    }
    return o;
}

/* ---- test hooks ---- */

int amf_test_start(amf *a)
{
    if (amf_workers_start(a) != 0)
        return -1;
    return timers_start(a);
}

void amf_test_gnb(amf *a, unsigned slot, uint32_t tac)
{
    amf_gnb *g;
    if (slot >= AMF_MAX_GNB)
        return;
    g = &a->gnbs[slot];
    pthread_mutex_lock(&a->tmu);
    g->used = true;
    g->fd = -1;
    g->setup = true;
    g->ntas = 1;
    memcpy(g->tas[0].plmn, a->cfg.plmn, 3);
    g->tas[0].tac = tac;
    snprintf(g->peer, sizeof g->peer, "test-gnb-%u", slot);
    pthread_mutex_unlock(&a->tmu);
}

void amf_test_inject(amf *a, unsigned slot, const uint8_t *pdu, size_t len)
{
    if (slot >= AMF_MAX_GNB)
        return;
    ngap_reader_dispatch(a, slot, a->gnbs[slot].gen, 1, pdu, len);
}

void amf_test_add_ue(amf *a, const char *supi, uint32_t tmsi, const uint8_t kamf[32])
{
    g5c_json *j = g5c_json_new_obj(), *s, *arr, *t;
    char *h;
    amf_ue *u;
    g5c_json_set_str(j, "supi", supi);
    g5c_json_set_int(j, "tmsi", tmsi);
    s = g5c_json_set(j, "sec", g5c_json_new_obj());
    g5c_json_set_int(s, "ngksi", 0);
    h = g5c_hex_encode(kamf, 32);
    g5c_json_set_str(s, "kamf", h);
    free(h);
    g5c_json_set_str(s, "abba", "0000");
    g5c_json_set_int(s, "int", 2);
    g5c_json_set_int(s, "enc", 2);
    g5c_json_set_int(s, "ul", 0);
    g5c_json_set_int(s, "dl", 0);
    g5c_json_set_str(s, "cap", "f0f0f0f0");
    arr = g5c_json_set(j, "allowed", g5c_json_new_arr());
    g5c_json_set_int(g5c_json_push(arr, g5c_json_new_obj()), "sst", 1);
    arr = g5c_json_set(j, "tais", g5c_json_new_arr());
    t = g5c_json_push(arr, g5c_json_new_obj());
    g5c_json_set_str(t, "plmn", "00f110");
    g5c_json_set_int(t, "tac", 1);
    u = amf_ue_from_json(a, j);
    g5c_json_free(j);
    if (u != NULL)
        amf_ue_unref(u);
}

void amf_test_sbi(amf *a, g5c_router *r, const char *method, const char *path, const char *ctype, const uint8_t *body, size_t len)
{
    g5c_req req;
    g5c_resp resp;
    (void)a;
    g5c_req_init(&req);
    g5c_resp_init(&resp);
    req.method = g5c_xstrdup(method);
    req.path = g5c_xstrdup(path);
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("amf.test");
    if (ctype != NULL)
        g5c_req_add_header(&req, "content-type", ctype);
    g5c_req_set_body(&req, body, len);
    g5c_router_dispatch(r, &req, &resp);
    g5c_req_free(&req);
    g5c_resp_free(&resp);
}

void amf_test_drain(amf *a)
{
    amf_drain_tasks(a);
}
