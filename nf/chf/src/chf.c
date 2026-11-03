/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _POSIX_C_SOURCE 200809L
/* The CHF: Nchf_ConvergedCharging (TS 32.291) with online credit control. A charging session reserves a volume quota against the subscriber's balance (TS 32.290 5.2),
 * updates debit what was used and reserve the next quota, a release closes the session and writes the charging data record.
 *
 *   chf:
 *     default_balance_bytes: 1073741824   what a subscriber without an entry in `accounts` holds; omit for unlimited
 *     accounts: [ { supi: 'imsi-0010100', balance_bytes: 5000000 } ]   by SUPI prefix, the first entry that matches counts
 *     max_grant_bytes: 10485760           most a single grant hands out
 *     validity_s: 300                     how long a grant is valid
 *     max_sessions: 200000                more: 503
 *     cdr_file: /var/lib/g5c/chf-cdr.jsonl   one JSON record per closed session
 *
 * State is held in memory: a restart forgets sessions and balances (balances start again from the configuration). */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "g5c/chf.h"

#define BUCKETS 1024
#define UNLIMITED UINT64_MAX

typedef struct acct {
    char supi[64];
    uint64_t balance; /* UNLIMITED: no limit */
    uint64_t reserved;
    struct acct *next;
} acct;

typedef struct csess {
    char ref[37];
    acct *ac;
    int64_t rating_group;
    uint64_t granted; /* the reservation outstanding */
    uint64_t used, ul, dl, time_s;
    time_t start;
    char dnn[64];
    struct csess *next;
} csess;

struct chf {
    uint64_t default_balance;
    struct {
        char prefix[64];
        uint64_t balance;
    } accounts[64];
    size_t naccounts;
    uint64_t max_grant;
    unsigned validity_s, max_sessions;
    char *cdr_file;
    pthread_mutex_t mu;
    acct *accts;
    csess *tab[BUCKETS];
    size_t nsessions;
    unsigned long long cdr_seq;
    g5c_registry *metrics;
    bool own_metrics;
};

static unsigned hash_ref(const char *s)
{
    unsigned h = 5381;
    for (; *s != 0; s++)
        h = h * 33 + (unsigned char)*s;
    return h % BUCKETS;
}

static acct *acct_for(chf *c, const char *supi)
{
    acct *a;
    for (a = c->accts; a != NULL; a = a->next)
        if (strcmp(a->supi, supi) == 0)
            return a;
    a = g5c_xcalloc(1, sizeof *a);
    snprintf(a->supi, sizeof a->supi, "%s", supi);
    a->balance = c->default_balance;
    for (size_t i = 0; i < c->naccounts; i++)
        if (strncmp(supi, c->accounts[i].prefix, strlen(c->accounts[i].prefix)) == 0) {
            a->balance = c->accounts[i].balance;
            break;
        }
    a->next = c->accts;
    c->accts = a;
    return a;
}

static csess *find(chf *c, const char *ref)
{
    for (csess *s = ref != NULL ? c->tab[hash_ref(ref)] : NULL; s != NULL; s = s->next)
        if (strcmp(s->ref, ref) == 0)
            return s;
    return NULL;
}

static void drop(chf *c, csess *s)
{
    csess **pp = &c->tab[hash_ref(s->ref)];
    while (*pp != NULL && *pp != s)
        pp = &(*pp)->next;
    if (*pp != NULL)
        *pp = s->next;
    c->nsessions--;
    free(s);
}

static void count(chf *c, const char *op, const char *result)
{
    g5c_label l[] = {{"operation", op}, {"result", result}};
    g5c_counter_inc(g5c_counter_get(c->metrics, "g5c_chf_requests_total", "Nchf_ConvergedCharging requests by operation and result.", l, 2));
}

static void gauge(chf *c)
{
    g5c_gauge_set(g5c_gauge_get(c->metrics, "g5c_chf_sessions", "Charging sessions open.", NULL, 0), (int64_t)c->nsessions);
}

/* ---- what the consumer reports ---- */

typedef struct {
    int64_t rg;
    uint64_t requested, used, ul, dl, time_s;
    bool has_rg;
} unit_req;

static uint64_t uint_of(const g5c_json *o, const char *key)
{
    int64_t v = 0;
    return g5c_json_get_int(o, key, &v) && v > 0 ? (uint64_t)v : 0;
}

/* the first multipleUnitUsage entry: the rating group, the volume asked for, the volume used (all containers added up) */
static void read_units(const g5c_json *body, unit_req *u)
{
    const g5c_json *e = g5c_json_at(g5c_json_get(body, "multipleUnitUsage"), 0), *uc = g5c_json_get(e, "usedUnitContainer");
    memset(u, 0, sizeof *u);
    u->has_rg = g5c_json_get_int(e, "ratingGroup", &u->rg);
    u->requested = uint_of(g5c_json_get(e, "requestedUnit"), "totalVolume");
    for (size_t i = 0; i < g5c_json_len(uc); i++) {
        const g5c_json *c = g5c_json_at(uc, i);
        uint64_t t = uint_of(c, "totalVolume"), up = uint_of(c, "uplinkVolume"), dn = uint_of(c, "downlinkVolume");
        u->used += t != 0 ? t : up + dn;
        u->ul += up;
        u->dl += dn;
        u->time_s += uint_of(c, "time");
    }
}

static void debit(acct *a, uint64_t used)
{
    if (a->balance != UNLIMITED)
        a->balance -= used < a->balance ? used : a->balance;
}

static void release_reservation(csess *s)
{
    s->ac->reserved -= s->granted < s->ac->reserved ? s->granted : s->ac->reserved;
    s->granted = 0;
}

/* The next grant: what was asked for, cut to the grant ceiling and to what the balance leaves after the other reservations. */
static uint64_t next_grant(chf *c, csess *s, uint64_t requested)
{
    uint64_t avail, g;
    if (s->ac->balance == UNLIMITED)
        avail = UNLIMITED;
    else
        avail = s->ac->balance > s->ac->reserved ? s->ac->balance - s->ac->reserved : 0;
    g = requested != 0 ? requested : c->max_grant;
    if (g > c->max_grant)
        g = c->max_grant;
    if (g > avail)
        g = avail;
    s->ac->reserved += g;
    s->granted = g;
    return g;
}

static g5c_json *answer(chf *c, const csess *s, uint64_t granted, uint64_t requested, uint32_t seq)
{
    g5c_json *r = g5c_json_new_obj(), *mi = g5c_json_push(g5c_json_set(r, "multipleUnitInformation", g5c_json_new_arr()), g5c_json_new_obj());
    char ts[40];
    struct tm tmv;
    time_t now = time(NULL);
    gmtime_r(&now, &tmv);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    g5c_json_set_str(r, "invocationTimeStamp", ts);
    g5c_json_set_int(r, "invocationSequenceNumber", seq);
    g5c_json_set_int(mi, "ratingGroup", s->rating_group);
    if (granted == 0) {
        g5c_json_set_str(mi, "resultCode", "END_USER_SERVICE_DENIED");
        return r;
    }
    g5c_json_set_str(mi, "resultCode", "SUCCESS");
    g5c_json_set_int(g5c_json_set(mi, "grantedUnit", g5c_json_new_obj()), "totalVolume", (int64_t)granted);
    g5c_json_set_int(mi, "validityTime", c->validity_s);
    if (s->ac->balance != UNLIMITED && (granted < (requested != 0 ? requested : c->max_grant) && s->ac->balance <= s->ac->reserved))
        g5c_json_set_str(g5c_json_set(mi, "finalUnitIndication", g5c_json_new_obj()), "finalUnitAction", "TERMINATE"); /* the last quota the balance holds */
    return r;
}

/* ---- the charging data record ---- */

static void write_cdr(chf *c, const csess *s, const char *cause)
{
    FILE *f;
    g5c_json *o;
    char *txt, t0[40], t1[40];
    struct tm tmv;
    time_t end = time(NULL);
    if (c->cdr_file == NULL)
        return;
    o = g5c_json_new_obj();
    gmtime_r(&s->start, &tmv);
    strftime(t0, sizeof t0, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    gmtime_r(&end, &tmv);
    strftime(t1, sizeof t1, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    g5c_json_set_int(o, "seq", (int64_t)++c->cdr_seq);
    g5c_json_set_str(o, "chargingRef", s->ref);
    g5c_json_set_str(o, "supi", s->ac->supi);
    g5c_json_set_int(o, "ratingGroup", s->rating_group);
    g5c_json_set_str(o, "dnn", s->dnn);
    g5c_json_set_str(o, "start", t0);
    g5c_json_set_str(o, "end", t1);
    g5c_json_set_int(o, "totalVolume", (int64_t)s->used);
    g5c_json_set_int(o, "uplinkVolume", (int64_t)s->ul);
    g5c_json_set_int(o, "downlinkVolume", (int64_t)s->dl);
    g5c_json_set_int(o, "time", (int64_t)s->time_s);
    g5c_json_set_str(o, "cause", cause);
    txt = g5c_json_to_string(o, NULL);
    f = fopen(c->cdr_file, "a");
    if (f != NULL) {
        fprintf(f, "%s\n", txt);
        fclose(f);
    } else {
        G5C_LOGE("g5c_chf", "cannot append to %s: %s", c->cdr_file, strerror(errno));
    }
    free(txt);
    g5c_json_free(o);
}

/* ---- operations ---- */

static void h_create(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    chf *c = ctx;
    g5c_json *body = g5c_req_json(req, resp), *out;
    const char *supi, *dnn;
    unit_req u;
    csess *s;
    uint64_t g;
    char *path, *loc;
    if (body == NULL) {
        count(c, "create", "bad_request");
        return;
    }
    supi = g5c_json_get_str(body, "subscriberIdentifier");
    read_units(body, &u);
    if (supi == NULL || strlen(supi) >= 64 || !u.has_rg) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", supi == NULL ? "subscriberIdentifier" : "multipleUnitUsage", "needed to open a charging session");
        count(c, "create", "bad_request");
        g5c_json_free(body);
        return;
    }
    pthread_mutex_lock(&c->mu);
    if (c->nsessions >= c->max_sessions) {
        pthread_mutex_unlock(&c->mu);
        g5c_resp_problem_simple(resp, 503, "INSUFFICIENT_RESOURCES", "too many charging sessions");
        count(c, "create", "rejected");
        g5c_json_free(body);
        return;
    }
    s = g5c_xcalloc(1, sizeof *s);
    (void)g5c_uuid_v4(s->ref);
    s->ac = acct_for(c, supi);
    s->rating_group = u.rg;
    s->start = time(NULL);
    dnn = g5c_json_get_str(g5c_json_get(g5c_json_get(body, "pduSessionChargingInformation"), "pduSessionInformation"), "dnn");
    snprintf(s->dnn, sizeof s->dnn, "%s", dnn != NULL ? dnn : "");
    g = next_grant(c, s, u.requested);
    s->next = c->tab[hash_ref(s->ref)];
    c->tab[hash_ref(s->ref)] = s;
    c->nsessions++;
    out = answer(c, s, g, u.requested, 0);
    gauge(c);
    path = g5c_xasprintf("/nchf-convergedcharging/v3/chargingdata/%s", s->ref);
    loc = g5c_req_url(req, path);
    pthread_mutex_unlock(&c->mu);
    g5c_resp_json(resp, 201, out);
    g5c_resp_header(resp, "location", loc);
    if (g == 0)
        g5c_counter_inc(g5c_counter_get(c->metrics, "g5c_chf_denied_total", "Quota requests answered with no grant (balance exhausted).", NULL, 0));
    else
        g5c_counter_add(g5c_counter_get(c->metrics, "g5c_chf_granted_bytes_total", "Volume granted.", NULL, 0), g);
    count(c, "create", g == 0 ? "denied" : "ok");
    free(loc);
    free(path);
    g5c_json_free(out);
    g5c_json_free(body);
}

static void h_update(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    chf *c = ctx;
    g5c_json *body = g5c_req_json(req, resp), *out;
    unit_req u;
    csess *s;
    uint64_t g;
    if (body == NULL) {
        count(c, "update", "bad_request");
        return;
    }
    read_units(body, &u);
    pthread_mutex_lock(&c->mu);
    s = find(c, g5c_req_param(req, "ref"));
    if (s == NULL) {
        pthread_mutex_unlock(&c->mu);
        g5c_resp_problem_simple(resp, 404, "CHARGING_SESSION_NOT_FOUND", "no charging session with this reference");
        count(c, "update", "not_found");
        g5c_json_free(body);
        return;
    }
    release_reservation(s);
    debit(s->ac, u.used);
    s->used += u.used;
    s->ul += u.ul;
    s->dl += u.dl;
    s->time_s += u.time_s;
    g = next_grant(c, s, u.requested);
    out = answer(c, s, g, u.requested, 0);
    pthread_mutex_unlock(&c->mu);
    g5c_resp_json(resp, 200, out);
    if (g == 0)
        g5c_counter_inc(g5c_counter_get(c->metrics, "g5c_chf_denied_total", "Quota requests answered with no grant (balance exhausted).", NULL, 0));
    else
        g5c_counter_add(g5c_counter_get(c->metrics, "g5c_chf_granted_bytes_total", "Volume granted.", NULL, 0), g);
    count(c, "update", g == 0 ? "denied" : "ok");
    g5c_json_free(out);
    g5c_json_free(body);
}

static void h_release(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    chf *c = ctx;
    g5c_json *body = g5c_req_json(req, resp);
    unit_req u;
    csess *s;
    if (body == NULL) {
        count(c, "release", "bad_request");
        return;
    }
    read_units(body, &u);
    pthread_mutex_lock(&c->mu);
    s = find(c, g5c_req_param(req, "ref"));
    if (s == NULL) {
        pthread_mutex_unlock(&c->mu);
        g5c_resp_problem_simple(resp, 404, "CHARGING_SESSION_NOT_FOUND", "no charging session with this reference");
        count(c, "release", "not_found");
        g5c_json_free(body);
        return;
    }
    release_reservation(s);
    debit(s->ac, u.used);
    s->used += u.used;
    s->ul += u.ul;
    s->dl += u.dl;
    s->time_s += u.time_s;
    write_cdr(c, s, "release");
    g5c_counter_add(g5c_counter_get(c->metrics, "g5c_chf_charged_bytes_total", "Volume charged (reported as used).", NULL, 0), u.used);
    drop(c, s);
    gauge(c);
    pthread_mutex_unlock(&c->mu);
    g5c_resp_status(resp, 204);
    count(c, "release", "ok");
    g5c_json_free(body);
}

/* ---- construction ---- */

static bool read_bytes(const g5c_json *o, const char *key, uint64_t *out, const char *where, char *err, size_t cap)
{
    int64_t v;
    if (g5c_json_get(o, key) == NULL)
        return true;
    if (!g5c_json_get_int(o, key, &v) || v < 0) {
        snprintf(err, cap, "invalid config: `%s.%s` must be a number of bytes, 0 or more", where, key);
        return false;
    }
    *out = (uint64_t)v;
    return true;
}

chf *chf_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap)
{
    static const char *const top[] = {"default_balance_bytes", "accounts", "max_grant_bytes", "validity_s", "max_sessions", "cdr_file", NULL};
    static const char *const ak[] = {"supi", "balance_bytes", NULL};
    const g5c_json *blk = g5c_json_get(root, "chf"), *acc;
    chf *c = g5c_xcalloc(1, sizeof *c);
    int64_t v;
    c->default_balance = UNLIMITED;
    c->max_grant = 10u * 1024 * 1024;
    c->validity_s = 300;
    c->max_sessions = 200000;
    if (blk != NULL) {
        if (!g5c_json_is(blk, G5C_J_OBJECT) || g5c_json_check_keys(blk, top, "chf", err, errcap) != 0) {
            if (err[0] == 0)
                snprintf(err, errcap, "invalid config: `chf` must be a mapping");
            goto bad;
        }
        if (!read_bytes(blk, "default_balance_bytes", &c->default_balance, "chf", err, errcap) || !read_bytes(blk, "max_grant_bytes", &c->max_grant, "chf", err, errcap))
            goto bad;
        if (c->max_grant == 0) {
            snprintf(err, errcap, "invalid config: `chf.max_grant_bytes` must be above 0");
            goto bad;
        }
        if (g5c_json_get(blk, "validity_s") != NULL) {
            if (!g5c_json_get_int(blk, "validity_s", &v) || v < 1 || v > 86400) {
                snprintf(err, errcap, "invalid config: `chf.validity_s` must be 1..=86400");
                goto bad;
            }
            c->validity_s = (unsigned)v;
        }
        if (g5c_json_get(blk, "max_sessions") != NULL) {
            if (!g5c_json_get_int(blk, "max_sessions", &v) || v < 1 || v > 10000000) {
                snprintf(err, errcap, "invalid config: `chf.max_sessions` must be 1..=10000000");
                goto bad;
            }
            c->max_sessions = (unsigned)v;
        }
        if (g5c_json_get(blk, "cdr_file") != NULL) {
            const char *p = g5c_json_get_str(blk, "cdr_file");
            if (p == NULL || *p == 0) {
                snprintf(err, errcap, "invalid config: `chf.cdr_file` must be a file name");
                goto bad;
            }
            c->cdr_file = g5c_xstrdup(p);
        }
        acc = g5c_json_get(blk, "accounts");
        if (acc != NULL && (!g5c_json_is(acc, G5C_J_ARRAY) || g5c_json_len(acc) > sizeof c->accounts / sizeof *c->accounts)) {
            snprintf(err, errcap, "invalid config: `chf.accounts` must be a list of up to 64 entries");
            goto bad;
        }
        for (size_t i = 0; acc != NULL && i < g5c_json_len(acc); i++) {
            const g5c_json *e = g5c_json_at(acc, i);
            const char *p = g5c_json_get_str(e, "supi");
            uint64_t b = 0;
            if (!g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, ak, "chf.accounts", err, errcap) != 0 || p == NULL || strlen(p) >= sizeof c->accounts[0].prefix ||
                g5c_json_get(e, "balance_bytes") == NULL || !read_bytes(e, "balance_bytes", &b, "chf.accounts[]", err, errcap)) {
                if (err[0] == 0)
                    snprintf(err, errcap, "invalid config: `chf.accounts[]` needs `supi` (a prefix) and `balance_bytes`");
                goto bad;
            }
            snprintf(c->accounts[i].prefix, sizeof c->accounts[i].prefix, "%s", p);
            c->accounts[i].balance = b;
            c->naccounts = i + 1;
        }
    }
    pthread_mutex_init(&c->mu, NULL);
    if (nf != NULL && nf->metrics != NULL) {
        c->metrics = nf->metrics;
    } else {
        c->metrics = g5c_registry_new();
        c->own_metrics = true;
    }
    gauge(c);
    return c;
bad:
    free(c->cdr_file);
    free(c);
    return NULL;
}

g5c_router *chf_router(chf *c)
{
    g5c_router *r = g5c_router_new();
    g5c_router_route(r, "POST", "/nchf-convergedcharging/v3/chargingdata", h_create, c);
    g5c_router_route(r, "POST", "/nchf-convergedcharging/v3/chargingdata/{ref}/update", h_update, c);
    g5c_router_route(r, "POST", "/nchf-convergedcharging/v3/chargingdata/{ref}/release", h_release, c);
    return r;
}

size_t chf_session_count(chf *c)
{
    size_t n;
    pthread_mutex_lock(&c->mu);
    n = c->nsessions;
    pthread_mutex_unlock(&c->mu);
    return n;
}

unsigned long long chf_balance(chf *c, const char *supi)
{
    unsigned long long b;
    pthread_mutex_lock(&c->mu);
    b = acct_for(c, supi)->balance;
    pthread_mutex_unlock(&c->mu);
    return b;
}

void chf_destroy(chf *c)
{
    if (c == NULL)
        return;
    for (size_t i = 0; i < BUCKETS; i++)
        while (c->tab[i] != NULL) {
            csess *s = c->tab[i];
            c->tab[i] = s->next;
            free(s);
        }
    while (c->accts != NULL) {
        acct *a = c->accts;
        c->accts = a->next;
        free(a);
    }
    if (c->own_metrics)
        g5c_registry_free(c->metrics);
    free(c->cdr_file);
    pthread_mutex_destroy(&c->mu);
    free(c);
}
