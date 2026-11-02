/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nnssf_NSSAIAvailability (TS 29.531 5.3, 6.2) */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "priv.h"

#define F_ONSSAI 0x1u
#define F_SUMOD 0x2u
#define F_EANAN 0x4u
#define F_OURS (F_ONSSAI | F_SUMOD | F_EANAN)
#define BASE "/nnssf-nssaiavailability/v1"
#define MAXSL 64

/* ---- parsing what the AMF sent ---- */

static void group_free(avail_group_t *g)
{
    free(g->tais);
    free(g->ranges);
    for (size_t i = 0; i < g->nsn; i++)
        ext_sn_free(&g->sn[i]);
    free(g->sn);
    memset(g, 0, sizeof *g);
}

static void entry_free(nf_entry_t *e)
{
    for (size_t i = 0; i < e->ngroups; i++)
        group_free(&e->groups[i]);
    free(e->groups);
    free(e->nf_id);
    free(e->amf_set);
    g5c_json_free(e->doc);
    memset(e, 0, sizeof *e);
}

static void sub_free(sub_t *s)
{
    free(s->id);
    free(s->uri);
    free(s->amf_set);
    free(s->tais);
    free(s->ranges);
    g5c_json_free(s->create);
    g5c_json_free(s->last);
    memset(s, 0, sizeof *s);
}

static bool range_from_taurange(const g5c_json *tr, trange_t **out, size_t *n)
{
    char mcc[4], mnc[4];
    const g5c_json *rl = g5c_json_get(tr, "tacRangeList");
    if (!plmn_from_json(g5c_json_get(tr, "plmnId"), mcc, mnc))
        return false;
    for (size_t i = 0; i < g5c_json_len(rl); i++) {
        trange_t r;
        const g5c_json *e = g5c_json_at(rl, i);
        if (!parse_tac(g5c_json_get_str(e, "start"), &r.lo) || !parse_tac(g5c_json_get_str(e, "end"), &r.hi) || r.lo > r.hi)
            continue; /* a pattern based range is not supported */
        snprintf(r.mcc, sizeof r.mcc, "%s", mcc);
        snprintf(r.mnc, sizeof r.mnc, "%s", mnc);
        *out = g5c_xrealloc(*out, (*n + 1) * sizeof **out);
        (*out)[(*n)++] = r;
    }
    return true;
}

static bool tais_and_ranges(const g5c_json *tai, const g5c_json *list, const g5c_json *ranges, tai_t **tais, size_t *ntais, trange_t **rg, size_t *nrg)
{
    tai_t t;
    if (tai != NULL) {
        if (!tai_from_json(tai, &t))
            return false;
        *tais = g5c_xrealloc(*tais, (*ntais + 1) * sizeof **tais);
        (*tais)[(*ntais)++] = t;
    }
    for (size_t i = 0; i < g5c_json_len(list); i++) {
        if (!tai_from_json(g5c_json_at(list, i), &t))
            return false;
        *tais = g5c_xrealloc(*tais, (*ntais + 1) * sizeof **tais);
        (*tais)[(*ntais)++] = t;
    }
    for (size_t i = 0; i < g5c_json_len(ranges); i++)
        if (!range_from_taurange(g5c_json_at(ranges, i), rg, nrg))
            return false;
    return true;
}

static bool entry_parse(nf_entry_t *e, const g5c_json *doc)
{
    const g5c_json *data = g5c_json_get(doc, "supportedNssaiAvailabilityData");
    const char *set = g5c_json_get_str(doc, "amfSetId");
    e->doc = g5c_json_dup(doc);
    e->amf_set = set != NULL ? g5c_xstrdup(set) : NULL;
    e->features = features_parse(g5c_json_get_str(doc, "supportedFeatures")) & F_OURS;
    e->groups = g5c_xcalloc(g5c_json_len(data) + 1, sizeof *e->groups);
    for (size_t i = 0; i < g5c_json_len(data); i++) {
        const g5c_json *d = g5c_json_at(data, i), *sl = g5c_json_get(d, "supportedSnssaiList");
        avail_group_t *g = &e->groups[e->ngroups++];
        if (!tais_and_ranges(g5c_json_get(d, "tai"), g5c_json_get(d, "taiList"), g5c_json_get(d, "taiRangeList"), &g->tais, &g->ntais, &g->ranges, &g->nranges))
            return false;
        g->sn = g5c_xcalloc(g5c_json_len(sl) + 1, sizeof *g->sn);
        for (size_t k = 0; k < g5c_json_len(sl); k++) {
            if (!ext_sn_from_json(g5c_json_at(sl, k), &g->sn[g->nsn]))
                return false;
            g->nsn++;
        }
    }
    return true;
}

static bool group_has_tai(const avail_group_t *g, const tai_t *t)
{
    for (size_t i = 0; i < g->ntais; i++)
        if (tai_equal(&g->tais[i], t))
            return true;
    for (size_t i = 0; i < g->nranges; i++)
        if (strcmp(g->ranges[i].mcc, t->mcc) == 0 && strcmp(g->ranges[i].mnc, t->mnc) == 0 && t->tac >= g->ranges[i].lo && t->tac <= g->ranges[i].hi)
            return true;
    return false;
}

/* ---- authorization ---- */

static bool sup_matches(const sn_ext_t *sup, size_t nsup, const sn_t *s)
{
    for (size_t i = 0; i < nsup; i++)
        if (ext_sn_matches(&sup[i], s))
            return true;
    return false;
}

static void add_slice(const slice_t **l, size_t *n, const slice_t *s)
{
    for (size_t i = 0; i < *n; i++)
        if (l[i] == s)
            return;
    if (*n < MAXSL)
        l[(*n)++] = s;
}

/* AuthorizedNssaiAvailabilityData for the slices that are authorized in a tracking area (or a TAC range): NULL when there are none */
static g5c_json *build_entry(const tai_t *t, const trange_t *range, const slice_t **sl, size_t n)
{
    g5c_json *o, *sup, *rs = NULL;
    char (*plmns)[8] = g5c_xcalloc(n * 4 + 1, sizeof *plmns);
    size_t np = 0;
    if (n == 0) {
        free(plmns);
        return NULL;
    }
    o = g5c_json_new_obj();
    g5c_json_set(o, "tai", tai_json(t));
    if (range != NULL) {
        g5c_json *tr = g5c_json_push(g5c_json_set(o, "taiRangeList", g5c_json_new_arr()), g5c_json_new_obj()), *l;
        char a[7], b[7];
        format_tac(range->lo, a);
        format_tac(range->hi, b);
        g5c_json_set(tr, "plmnId", plmn_json(range->mcc, range->mnc));
        l = g5c_json_push(g5c_json_set(tr, "tacRangeList", g5c_json_new_arr()), g5c_json_new_obj());
        g5c_json_set_str(l, "start", a);
        g5c_json_set_str(l, "end", b);
    }
    sup = g5c_json_set(o, "supportedSnssaiList", g5c_json_new_arr());
    for (size_t i = 0; i < n; i++) {
        g5c_json_push(sup, sn_json(&sl[i]->sn));
        for (size_t k = 0; k < sl[i]->nrestricted; k++) {
            bool seen = false;
            for (size_t z = 0; z < np; z++)
                seen = seen || strcmp(plmns[z], sl[i]->restricted_for[k]) == 0;
            if (!seen)
                snprintf(plmns[np++], sizeof plmns[0], "%s", sl[i]->restricted_for[k]);
        }
    }
    for (size_t z = 0; z < np; z++) {
        char mcc[4], mnc[4];
        g5c_json *e, *l;
        if (!plmn_from_str(plmns[z], mcc, mnc))
            continue;
        if (rs == NULL)
            rs = g5c_json_set(o, "restrictedSnssaiList", g5c_json_new_arr());
        e = g5c_json_push(rs, g5c_json_new_obj());
        g5c_json_set(e, "homePlmnId", plmn_json(mcc, mnc));
        l = g5c_json_set(e, "sNssaiList", g5c_json_new_arr());
        for (size_t i = 0; i < n; i++)
            for (size_t k = 0; k < sl[i]->nrestricted; k++)
                if (strcmp(sl[i]->restricted_for[k], plmns[z]) == 0)
                    g5c_json_push(l, sn_json(&sl[i]->sn));
    }
    free(plmns);
    return o;
}

/* the configured slices that a list of supported S-NSSAIs covers in a tracking area */
static size_t slices_for(const nssf_cfg *c, const tai_t *t, const trange_t *range, const sn_ext_t *sup, size_t nsup, const slice_t **out)
{
    size_t n = 0;
    for (size_t i = 0; i < c->nslices; i++) {
        const slice_t *s = &c->slices[i];
        bool in = range != NULL ? slice_in_range(s, range) : slice_in_tai(s, t);
        if (in && sup_matches(sup, nsup, &s->sn))
            add_slice(out, &n, s);
    }
    return n;
}

/* the authorized data of one group of an AMF's report: one entry per tracking area, one per TAC range */
static void group_authorized(const nssf_cfg *c, const avail_group_t *g, g5c_json *arr)
{
    const slice_t *sl[MAXSL];
    for (size_t i = 0; i < g->ntais; i++) {
        size_t n = slices_for(c, &g->tais[i], NULL, g->sn, g->nsn, sl);
        g5c_json *e = build_entry(&g->tais[i], NULL, sl, n);
        if (e != NULL)
            g5c_json_push(arr, e);
    }
    for (size_t i = 0; i < g->nranges; i++) {
        tai_t rep;
        size_t n;
        g5c_json *e;
        snprintf(rep.mcc, sizeof rep.mcc, "%s", g->ranges[i].mcc);
        snprintf(rep.mnc, sizeof rep.mnc, "%s", g->ranges[i].mnc);
        rep.tac = g->ranges[i].lo;
        n = slices_for(c, &rep, &g->ranges[i], g->sn, g->nsn, sl);
        e = build_entry(&rep, &g->ranges[i], sl, n);
        if (e != NULL)
            g5c_json_push(arr, e);
    }
}

/* what the subscription is told */
static g5c_json *sub_authorized(nssf *n, const sub_t *s)
{
    g5c_json *arr = g5c_json_new_arr();
    const slice_t *sl[MAXSL];
    for (size_t i = 0; i < s->ntais + s->nranges; i++) {
        const tai_t *t = NULL;
        tai_t rep;
        const trange_t *r = NULL;
        size_t cnt = 0;
        g5c_json *e;
        if (i < s->ntais) {
            t = &s->tais[i];
        } else {
            r = &s->ranges[i - s->ntais];
            snprintf(rep.mcc, sizeof rep.mcc, "%s", r->mcc);
            snprintf(rep.mnc, sizeof rep.mnc, "%s", r->mnc);
            rep.tac = r->lo;
            t = &rep;
        }
        for (size_t k = 0; k < n->nnfs; k++) {
            const nf_entry_t *nf = &n->nfs[k];
            if (s->amf_set != NULL && (nf->amf_set == NULL || strcmp(nf->amf_set, s->amf_set) != 0))
                continue;
            for (size_t g = 0; g < nf->ngroups; g++)
                if (group_has_tai(&nf->groups[g], t)) {
                    const slice_t *tmp[MAXSL];
                    size_t m = slices_for(n->cfg, t, r, nf->groups[g].sn, nf->groups[g].nsn, tmp);
                    for (size_t z = 0; z < m; z++)
                        add_slice(sl, &cnt, tmp[z]);
                }
        }
        e = build_entry(t, r, sl, cnt);
        if (e != NULL)
            g5c_json_push(arr, e);
    }
    return arr;
}

/* ---- the AMF queries of NSSelection ---- */

static nf_entry_t *find_nf(nssf *n, const char *id)
{
    for (size_t i = 0; i < n->nnfs; i++)
        if (strcmp(n->nfs[i].nf_id, id) == 0)
            return &n->nfs[i];
    return NULL;
}

static bool covers(const nf_entry_t *nf, const tai_t *t, const sn_t *need, size_t nneed)
{
    for (size_t k = 0; k < nneed; k++) {
        bool ok = false;
        for (size_t g = 0; g < nf->ngroups && !ok; g++)
            ok = group_has_tai(&nf->groups[g], t) && sup_matches(nf->groups[g].sn, nf->groups[g].nsn, &need[k]);
        if (!ok)
            return false;
    }
    return true;
}

int nssf_amf_supports(nssf *n, const char *nf_id, const tai_t *t, const sn_t *need, size_t nneed, char **amf_set_out)
{
    int r = 0;
    pthread_mutex_lock(&n->mu);
    {
        const nf_entry_t *nf = find_nf(n, nf_id);
        if (nf != NULL) {
            r = covers(nf, t, need, nneed) ? 1 : 2;
            if (amf_set_out != NULL && nf->amf_set != NULL)
                *amf_set_out = g5c_xstrdup(nf->amf_set);
        }
    }
    pthread_mutex_unlock(&n->mu);
    return r;
}

/* does the union of what the AMFs of set `id` report cover `need` at `t`? */
static bool set_covers_dynamic(const nssf *n, const char *id, const tai_t *t, const sn_t *need, size_t nneed)
{
    for (size_t k = 0; k < nneed; k++) {
        bool ok = false;
        for (size_t i = 0; i < n->nnfs && !ok; i++) {
            const nf_entry_t *nf = &n->nfs[i];
            if (nf->amf_set == NULL || strcmp(nf->amf_set, id) != 0)
                continue;
            for (size_t g = 0; g < nf->ngroups && !ok; g++)
                ok = group_has_tai(&nf->groups[g], t) && sup_matches(nf->groups[g].sn, nf->groups[g].nsn, &need[k]);
        }
        if (!ok)
            return false;
    }
    return true;
}

bool nssf_find_set(nssf *n, const tai_t *t, const sn_t *need, size_t nneed, const amfset_t **cfg_set, char **dyn_set_id)
{
    bool found = false;
    *cfg_set = NULL;
    *dyn_set_id = NULL;
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < n->cfg->nsets && !found; i++) {
        const amfset_t *s = &n->cfg->sets[i];
        bool all = true;
        for (size_t k = 0; k < nneed && all; k++)
            all = sn_in(s->snssais, s->nsnssais, &need[k]);
        if ((s->nsnssais > 0 && all) || set_covers_dynamic(n, s->id, t, need, nneed)) {
            *cfg_set = s;
            found = true;
        }
    }
    for (size_t i = 0; i < n->nnfs && !found; i++) {
        const char *id = n->nfs[i].amf_set;
        if (id != NULL && set_covers_dynamic(n, id, t, need, nneed)) {
            *dyn_set_id = g5c_xstrdup(id);
            found = true;
        }
    }
    pthread_mutex_unlock(&n->mu);
    return found;
}

/* ---- the worker: notifications, the state file, expiry ---- */

static void enqueue(nssf *n, const char *url, char *body, const char *sub_id, unsigned attempts, double delay)
{
    job_t *j = g5c_xcalloc(1, sizeof *j), **pp;
    j->url = g5c_xstrdup(url);
    j->body = body;
    j->sub_id = g5c_xstrdup(sub_id);
    j->attempts = attempts;
    j->not_before = g5c_now_seconds() + delay;
    pthread_mutex_lock(&n->qmu);
    if (n->qlen >= 4096) {
        pthread_mutex_unlock(&n->qmu);
        g5c_counter_inc(n->c_dropped);
        free(j->url);
        free(j->body);
        free(j->sub_id);
        free(j);
        return;
    }
    for (pp = &n->q; *pp != NULL && (*pp)->not_before <= j->not_before; pp = &(*pp)->next)
        ;
    j->next = *pp;
    *pp = j;
    n->qlen++;
    pthread_cond_broadcast(&n->qcv);
    pthread_mutex_unlock(&n->qmu);
}

void nssf_kick(nssf *n)
{
    pthread_mutex_lock(&n->qmu);
    n->dirty = true;
    pthread_cond_broadcast(&n->qcv);
    pthread_mutex_unlock(&n->qmu);
}

static void job_free(job_t *j)
{
    free(j->url);
    free(j->body);
    free(j->sub_id);
    free(j);
}

static void sweep_expired(nssf *n)
{
    int64_t now = (int64_t)time(NULL);
    bool changed = false;
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < n->nsubs;) {
        if (n->subs[i].expiry != 0 && n->subs[i].expiry <= now) {
            sub_free(&n->subs[i]);
            memmove(&n->subs[i], &n->subs[i + 1], (n->nsubs - i - 1) * sizeof *n->subs);
            n->nsubs--;
            changed = true;
        } else {
            i++;
        }
    }
    if (n->g_subs != NULL)
        g5c_gauge_set(n->g_subs, (int64_t)n->nsubs);
    pthread_mutex_unlock(&n->mu);
    if (changed)
        nssf_kick(n);
}

static void *worker_main(void *arg)
{
    nssf *n = arg;
    double next_sweep = g5c_now_seconds() + 30;
    pthread_mutex_lock(&n->qmu);
    for (;;) {
        job_t *j = NULL;
        bool save = false;
        struct timespec ts;
        double now = g5c_now_seconds(), wait = 1.0;
        if (n->stop)
            break;
        if (n->q != NULL && n->q->not_before <= now) {
            j = n->q;
            n->q = j->next;
            n->qlen--;
        } else if (n->dirty) {
            n->dirty = false;
            save = true;
        } else {
            if (n->q != NULL && n->q->not_before - now < wait)
                wait = n->q->not_before - now;
            if (next_sweep - now < wait)
                wait = next_sweep - now > 0 ? next_sweep - now : 0;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (time_t)wait;
            ts.tv_nsec += (long)((wait - (double)(time_t)wait) * 1e9);
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
            pthread_cond_timedwait(&n->qcv, &n->qmu, &ts);
            if (g5c_now_seconds() >= next_sweep) {
                pthread_mutex_unlock(&n->qmu);
                sweep_expired(n);
                pthread_mutex_lock(&n->qmu);
                next_sweep = g5c_now_seconds() + 30;
            }
            continue;
        }
        pthread_mutex_unlock(&n->qmu);
        if (save) {
            struct timespec gap = {0, 100 * 1000000L};
            nanosleep(&gap, NULL); /* let a burst of changes coalesce */
            nssf_state_save(n);
        } else {
            g5c_resp r;
            char err[160] = "";
            int rc = n->client != NULL ? g5c_client_request(n->client, "POST", j->url, NULL, 0, G5C_JSON_TYPE, j->body, strlen(j->body), &r, err, sizeof err) : -1;
            bool ok = false;
            if (rc == 0) {
                ok = r.status >= 200 && r.status < 300;
                if (!ok)
                    snprintf(err, sizeof err, "HTTP %d", r.status);
                g5c_resp_free(&r);
            }
            if (ok) {
                g5c_counter_inc(n->c_ok);
            } else if (n->client == NULL) {
                g5c_counter_inc(n->c_dropped);
            } else if (j->attempts < n->cfg->notify_retries) {
                char *body = j->body;
                j->body = NULL;
                enqueue(n, j->url, body, j->sub_id, j->attempts + 1, j->attempts == 0 ? 0.5 : 2.0);
            } else {
                G5C_LOGW("g5c_nssf", "notification of subscription %s to %s failed (%s): giving up", j->sub_id, j->url, err);
                g5c_counter_inc(n->c_failed);
            }
            job_free(j);
        }
        pthread_mutex_lock(&n->qmu);
    }
    pthread_mutex_unlock(&n->qmu);
    return NULL;
}

void nssf_worker_start(nssf *n)
{
    if (!n->worker_on && pthread_create(&n->worker, NULL, worker_main, n) == 0)
        n->worker_on = true;
}

void nssf_worker_stop(nssf *n)
{
    if (!n->worker_on)
        return;
    pthread_mutex_lock(&n->qmu);
    n->stop = true;
    pthread_cond_broadcast(&n->qcv);
    pthread_mutex_unlock(&n->qmu);
    pthread_join(n->worker, NULL);
    n->worker_on = false;
    while (n->q != NULL) {
        job_t *j = n->q;
        n->q = j->next;
        job_free(j);
    }
    n->qlen = 0;
}

/* ---- notifying the subscriptions of a change ---- */

/* After a change of the availability: the subscriptions whose authorized data differs are told (caller holds mu) */
static void notify_changes(nssf *n)
{
    for (size_t i = 0; i < n->nsubs; i++) {
        sub_t *s = &n->subs[i];
        g5c_json *cur = sub_authorized(n, s);
        if (s->last != NULL && g5c_json_equal(s->last, cur)) {
            g5c_json_free(cur);
            continue;
        }
        if (g5c_json_len(cur) == 0 && !(s->features & F_EANAN)) { /* nothing is authorized any more: only a consumer that asked for it is told */
            g5c_json_free(s->last);
            s->last = cur;
            continue;
        }
        {
            g5c_json *body = g5c_json_new_obj();
            g5c_json_set_str(body, "subscriptionId", s->id);
            g5c_json_set(body, "authorizedNssaiAvailabilityData", g5c_json_dup(cur));
            enqueue(n, s->uri, g5c_json_to_string(body, NULL), s->id, 0, 0);
            g5c_json_free(body);
        }
        g5c_json_free(s->last);
        s->last = cur;
    }
}

/* ---- the resources ---- */

static bool nf_id_ok(const char *s)
{
    size_t n = s != NULL ? strlen(s) : 0;
    if (n == 0 || n > 64)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!(isalnum((unsigned char)s[i]) || s[i] == '-' || s[i] == '_' || s[i] == '.'))
            return false;
    return true;
}

static bool content_encoding_ok(const g5c_req *req, g5c_resp *resp)
{
    const char *ce = g5c_req_header(req, "content-encoding");
    if (ce == NULL || strcasecmp(ce, "identity") == 0)
        return true;
    nssf_problem(resp, 415, "UNSUPPORTED_MEDIA_TYPE", "only identity content coding is supported");
    return false;
}

static bool body_ok(nssf *n, const g5c_json *body, int schema, g5c_resp *resp)
{
    char err[200];
    if (!n->cfg->validate || oa_validate(n->sch, schema, body, err, sizeof err) == 0)
        return true;
    nssf_problem(resp, 400, "MANDATORY_IE_INCORRECT", err);
    return false;
}

/* the answer to a PUT or PATCH of the availability of an AMF: 204 when nothing is authorized, else 200 with what is */
static void reply_authorized(nssf *n, const nf_entry_t *e, g5c_resp *resp)
{
    g5c_json *arr = g5c_json_new_arr();
    for (size_t g = 0; g < e->ngroups; g++)
        group_authorized(n->cfg, &e->groups[g], arr);
    if (g5c_json_len(arr) == 0) {
        g5c_json_free(arr);
        g5c_resp_status(resp, 204);
    } else {
        g5c_json *o = g5c_json_new_obj();
        char *f = features_str(e->features);
        g5c_json_set(o, "authorizedNssaiAvailabilityData", arr);
        g5c_json_set_str(o, "supportedFeatures", f);
        free(f);
        g5c_resp_json(resp, 200, o);
        g5c_json_free(o);
    }
}

static void store_entry(nssf *n, nf_entry_t *fresh)
{
    nf_entry_t *old = find_nf(n, fresh->nf_id);
    if (old != NULL) {
        entry_free(old);
        *old = *fresh;
    } else {
        if (n->nnfs == n->capnfs) {
            n->capnfs = n->capnfs ? n->capnfs * 2 : 16;
            n->nfs = g5c_xrealloc(n->nfs, n->capnfs * sizeof *n->nfs);
        }
        n->nfs[n->nnfs++] = *fresh;
    }
    if (n->g_nfs != NULL)
        g5c_gauge_set(n->g_nfs, (int64_t)n->nnfs);
}

static void h_put(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nssf *n = ctx;
    const char *id = g5c_req_param(req, "nfId");
    g5c_json *body;
    nf_entry_t fresh;
    if (!nf_id_ok(id)) {
        nssf_problem(resp, 400, "MANDATORY_IE_INCORRECT", "malformed nfId");
        return;
    }
    if (!content_encoding_ok(req, resp))
        return;
    body = g5c_req_json(req, resp);
    if (body == NULL)
        return;
    memset(&fresh, 0, sizeof fresh);
    if (!body_ok(n, body, NSSF_SCH_NSSAI_AVAILABILITY_INFO, resp))
        goto done;
    if (!entry_parse(&fresh, body)) {
        nssf_problem(resp, 400, "MANDATORY_IE_INCORRECT", "a tracking area or S-NSSAI of the document is malformed");
        goto done;
    }
    fresh.nf_id = g5c_xstrdup(id);
    pthread_mutex_lock(&n->mu);
    store_entry(n, &fresh);
    notify_changes(n);
    reply_authorized(n, find_nf(n, id), resp);
    pthread_mutex_unlock(&n->mu);
    nssf_kick(n);
    fresh.nf_id = NULL;
    memset(&fresh, 0, sizeof fresh);
    g5c_json_free(body);
    return;
done:
    entry_free(&fresh);
    g5c_json_free(body);
}

static void h_patch(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nssf *n = ctx;
    const char *id = g5c_req_param(req, "nfId");
    g5c_json *patch, *doc;
    nf_entry_t fresh, *old;
    char perr[160];
    if (!nf_id_ok(id)) {
        nssf_problem(resp, 400, "MANDATORY_IE_INCORRECT", "malformed nfId");
        return;
    }
    if (!content_encoding_ok(req, resp))
        return;
    patch = g5c_req_json(req, resp);
    if (patch == NULL)
        return;
    memset(&fresh, 0, sizeof fresh);
    if (!body_ok(n, patch, NSSF_SCH_PATCH_DOCUMENT, resp))
        goto done_patch;
    pthread_mutex_lock(&n->mu);
    old = find_nf(n, id);
    if (old == NULL) {
        pthread_mutex_unlock(&n->mu);
        nssf_problem(resp, 404, "DATA_NOT_FOUND", "no NSSAI availability information is stored for this NF");
        goto done_patch;
    }
    doc = g5c_json_dup(old->doc);
    pthread_mutex_unlock(&n->mu);
    if (g5c_json_patch(&doc, patch, perr, sizeof perr) != 0 || !body_ok(n, doc, NSSF_SCH_NSSAI_AVAILABILITY_INFO, resp) || !entry_parse(&fresh, doc)) {
        if (resp->status < 400)
            nssf_problem(resp, 400, "MODIFICATION_NOT_ALLOWED", perr[0] ? perr : "the patched document is malformed");
        g5c_json_free(doc);
        goto done_patch;
    }
    g5c_json_free(doc);
    fresh.nf_id = g5c_xstrdup(id);
    pthread_mutex_lock(&n->mu);
    store_entry(n, &fresh);
    notify_changes(n);
    reply_authorized(n, find_nf(n, id), resp);
    pthread_mutex_unlock(&n->mu);
    nssf_kick(n);
    memset(&fresh, 0, sizeof fresh);
    g5c_json_free(patch);
    return;
done_patch:
    entry_free(&fresh);
    g5c_json_free(patch);
}

static void h_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nssf *n = ctx;
    const char *id = g5c_req_param(req, "nfId");
    nf_entry_t *e;
    if (!nf_id_ok(id)) {
        nssf_problem(resp, 400, "MANDATORY_IE_INCORRECT", "malformed nfId");
        return;
    }
    pthread_mutex_lock(&n->mu);
    e = find_nf(n, id);
    if (e == NULL) {
        pthread_mutex_unlock(&n->mu);
        nssf_problem(resp, 404, "DATA_NOT_FOUND", "no NSSAI availability information is stored for this NF");
        return;
    }
    entry_free(e);
    memmove(e, e + 1, (size_t)(&n->nfs[n->nnfs - 1] - e) * sizeof *e);
    n->nnfs--;
    if (n->g_nfs != NULL)
        g5c_gauge_set(n->g_nfs, (int64_t)n->nnfs);
    notify_changes(n);
    pthread_mutex_unlock(&n->mu);
    nssf_kick(n);
    g5c_resp_status(resp, 204);
}

static void h_options(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    g5c_resp_header(resp, "accept-encoding", "identity"); /* RFC 7694: no content coding is supported */
    g5c_resp_status(resp, 200);
}

/* ---- subscriptions ---- */

static int64_t parse_expiry_rfc3339(const char *s)
{
    int y, mo, d, hh, mm, ss, n = 0;
    struct tm tm;
    time_t t;
    if (s == NULL || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &mo, &d, &hh, &mm, &ss, &n) != 6)
        return -1;
    memset(&tm, 0, sizeof tm);
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = hh;
    tm.tm_min = mm;
    tm.tm_sec = ss;
    t = timegm(&tm);
    return t == (time_t)-1 ? -1 : (int64_t)t;
}

static void format_expiry(int64_t t, char *out, size_t cap)
{
    time_t tt = (time_t)t;
    struct tm tm;
    out[0] = '\0';
    if (gmtime_r(&tt, &tm) != NULL)
        (void)strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static sub_t *find_sub(nssf *n, const char *id)
{
    for (size_t i = 0; i < n->nsubs; i++)
        if (strcmp(n->subs[i].id, id) == 0)
            return &n->subs[i];
    return NULL;
}

/* fill a subscription from its (validated) create data */
static bool sub_parse(sub_t *s, const g5c_json *create)
{
    const char *u = g5c_json_get_str(create, "nfNssaiAvailabilityUri"), *set = g5c_json_get_str(create, "amfSetId"), *ex = g5c_json_get_str(create, "expiry");
    free(s->uri);
    free(s->amf_set);
    free(s->tais);
    free(s->ranges);
    s->tais = NULL;
    s->ranges = NULL;
    s->ntais = s->nranges = 0;
    s->uri = g5c_xstrdup(u != NULL ? u : "");
    s->amf_set = set != NULL ? g5c_xstrdup(set) : NULL;
    s->expiry = ex != NULL ? parse_expiry_rfc3339(ex) : 0;
    if (s->expiry < 0)
        s->expiry = 0;
    s->features = features_parse(g5c_json_get_str(create, "supportedFeatures")) & F_OURS;
    if (strncmp(s->uri, "http://", 7) != 0 && strncmp(s->uri, "https://", 8) != 0)
        return false;
    return tais_and_ranges(NULL, g5c_json_get(create, "taiList"), g5c_json_get(create, "taiRangeList"), &s->tais, &s->ntais, &s->ranges, &s->nranges);
}

static g5c_json *created_data(nssf *n, sub_t *s)
{
    g5c_json *o = g5c_json_new_obj(), *auth = sub_authorized(n, s);
    char *f = features_str(s->features);
    g5c_json_set_str(o, "subscriptionId", s->id);
    if (g5c_json_get_str(s->create, "expiry") != NULL)
        g5c_json_set_str(o, "expiry", g5c_json_get_str(s->create, "expiry"));
    if (g5c_json_len(auth) > 0)
        g5c_json_set(o, "authorizedNssaiAvailabilityData", auth);
    else
        g5c_json_free(auth);
    g5c_json_set_str(o, "supportedFeatures", f);
    free(f);
    return o;
}

static void h_subscribe(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nssf *n = ctx;
    g5c_json *body, *out;
    sub_t s;
    char uuid[37], stamp[32], *loc;
    int64_t now = (int64_t)time(NULL), max = n->cfg->sub_lifetime_s, want = now + max;
    const char *ex;
    uint32_t r = 0;
    if (!content_encoding_ok(req, resp))
        return;
    body = g5c_req_json(req, resp);
    if (body == NULL)
        return;
    memset(&s, 0, sizeof s);
    if (!body_ok(n, body, NSSF_SCH_EVENT_SUBSCRIPTION_CREATE, resp))
        goto done;
    if (g5c_json_len(g5c_json_get(body, "taiList")) == 0 && g5c_json_len(g5c_json_get(body, "taiRangeList")) == 0) {
        nssf_problem(resp, 400, "MANDATORY_IE_INCORRECT", "the subscription names no tracking area");
        goto done;
    }
    /* the NSSF decides how long it lasts (TS 29.531 5.3.2.3.1): the consumer's expiry is a hint, never more than the maximum, and spread */
    ex = g5c_json_get_str(body, "expiry");
    if (ex != NULL) {
        int64_t t = parse_expiry_rfc3339(ex);
        if (t > now && t < want)
            want = t;
    }
    (void)g5c_random(&r, sizeof r);
    want -= (int64_t)((double)(want - now) * 0.05 * ((double)r / 4294967295.0));
    format_expiry(want, stamp, sizeof stamp);
    g5c_json_set_str(body, "expiry", stamp);
    if (!sub_parse(&s, body)) {
        nssf_problem(resp, 400, "MANDATORY_IE_INCORRECT", "the notification URI or a tracking area is malformed");
        goto done;
    }
    g5c_uuid_v4(uuid);
    s.id = g5c_xstrdup(uuid);
    s.create = g5c_json_dup(body);
    pthread_mutex_lock(&n->mu);
    if (n->nsubs >= n->cfg->sub_max) {
        pthread_mutex_unlock(&n->mu);
        nssf_problem(resp, 429, "TOO_MANY_SUBSCRIPTIONS", "the NSSF holds the maximum number of subscriptions");
        goto done;
    }
    if (n->nsubs == n->capsubs) {
        n->capsubs = n->capsubs ? n->capsubs * 2 : 16;
        n->subs = g5c_xrealloc(n->subs, n->capsubs * sizeof *n->subs);
    }
    n->subs[n->nsubs] = s;
    s = n->subs[n->nsubs++];
    out = created_data(n, &n->subs[n->nsubs - 1]);
    n->subs[n->nsubs - 1].last = sub_authorized(n, &n->subs[n->nsubs - 1]);
    if (n->g_subs != NULL)
        g5c_gauge_set(n->g_subs, (int64_t)n->nsubs);
    pthread_mutex_unlock(&n->mu);
    nssf_kick(n);
    loc = g5c_req_url(req, req->path);
    {
        char *full = g5c_xasprintf("%s/%s", loc, uuid);
        g5c_resp_header(resp, "location", full);
        free(full);
    }
    free(loc);
    g5c_resp_json(resp, 201, out);
    g5c_json_free(out);
    memset(&s, 0, sizeof s);
done:
    sub_free(&s);
    g5c_json_free(body);
}

static void h_unsubscribe(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nssf *n = ctx;
    const char *id = g5c_req_param(req, "subscriptionId");
    sub_t *s;
    pthread_mutex_lock(&n->mu);
    s = id != NULL ? find_sub(n, id) : NULL;
    if (s == NULL) {
        pthread_mutex_unlock(&n->mu);
        nssf_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such subscription");
        return;
    }
    sub_free(s);
    memmove(s, s + 1, (size_t)(&n->subs[n->nsubs - 1] - s) * sizeof *s);
    n->nsubs--;
    if (n->g_subs != NULL)
        g5c_gauge_set(n->g_subs, (int64_t)n->nsubs);
    pthread_mutex_unlock(&n->mu);
    nssf_kick(n);
    g5c_resp_status(resp, 204);
}

static void h_sub_patch(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nssf *n = ctx;
    const char *id = g5c_req_param(req, "subscriptionId");
    g5c_json *patch, *doc = NULL, *out;
    sub_t *s;
    char perr[160] = "", serr[200];
    if (!content_encoding_ok(req, resp))
        return;
    patch = g5c_req_json(req, resp);
    if (patch == NULL)
        return;
    if (!body_ok(n, patch, NSSF_SCH_PATCH_DOCUMENT, resp))
        goto done;
    pthread_mutex_lock(&n->mu);
    s = id != NULL ? find_sub(n, id) : NULL;
    if (s == NULL) {
        pthread_mutex_unlock(&n->mu);
        nssf_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such subscription");
        goto done;
    }
    doc = g5c_json_dup(s->create);
    if (g5c_json_patch(&doc, patch, perr, sizeof perr) != 0 || !g5c_json_is(doc, G5C_J_OBJECT) ||
        (n->cfg->validate && oa_validate(n->sch, NSSF_SCH_EVENT_SUBSCRIPTION_CREATE, doc, serr, sizeof serr) != 0) ||
        !g5c_json_equal(g5c_json_get(doc, "event"), g5c_json_get(s->create, "event"))) { /* the event cannot be changed */
        pthread_mutex_unlock(&n->mu);
        nssf_problem(resp, 400, "MODIFICATION_NOT_ALLOWED", perr[0] ? perr : "the patched subscription is not valid or changes the event");
        goto done;
    }
    {
        sub_t keep = *s;
        g5c_json_free(s->create);
        s->create = doc;
        doc = NULL;
        if (!sub_parse(s, s->create)) {
            g5c_json_free(s->create);
            s->create = keep.create;
            s->uri = keep.uri;
            s->amf_set = keep.amf_set;
            s->tais = keep.tais;
            s->ranges = keep.ranges;
            s->ntais = keep.ntais;
            s->nranges = keep.nranges;
            s->expiry = keep.expiry;
            s->features = keep.features;
            pthread_mutex_unlock(&n->mu);
            nssf_problem(resp, 400, "MODIFICATION_NOT_ALLOWED", "the patched subscription is not valid");
            goto done;
        }
        g5c_json_free(s->last);
        s->last = sub_authorized(n, s);
    }
    out = created_data(n, s);
    pthread_mutex_unlock(&n->mu);
    nssf_kick(n);
    g5c_resp_json(resp, 200, out);
    g5c_json_free(out);
done:
    g5c_json_free(doc);
    g5c_json_free(patch);
}

/* ---- routes, introspection ---- */

void nssf_avail_routes(g5c_router *r, nssf *n)
{
    g5c_router_route(r, "PUT", BASE "/nssai-availability/{nfId}", h_put, n);
    g5c_router_route(r, "PATCH", BASE "/nssai-availability/{nfId}", h_patch, n);
    g5c_router_route(r, "DELETE", BASE "/nssai-availability/{nfId}", h_delete, n);
    g5c_router_route(r, "POST", BASE "/nssai-availability/subscriptions", h_subscribe, n);
    g5c_router_route(r, "DELETE", BASE "/nssai-availability/subscriptions/{subscriptionId}", h_unsubscribe, n);
    g5c_router_route(r, "PATCH", BASE "/nssai-availability/subscriptions/{subscriptionId}", h_sub_patch, n);
    g5c_router_route(r, "OPTIONS", BASE "/nssai-availability", h_options, n);
}

void nssf_avail_free(nssf *n)
{
    for (size_t i = 0; i < n->nnfs; i++)
        entry_free(&n->nfs[i]);
    free(n->nfs);
    for (size_t i = 0; i < n->nsubs; i++)
        sub_free(&n->subs[i]);
    free(n->subs);
    n->nfs = NULL;
    n->subs = NULL;
    n->nnfs = n->nsubs = 0;
}

size_t nssf_nf_count(nssf *n)
{
    size_t c;
    pthread_mutex_lock(&n->mu);
    c = n->nnfs;
    pthread_mutex_unlock(&n->mu);
    return c;
}

size_t nssf_subscription_count(nssf *n)
{
    size_t c;
    pthread_mutex_lock(&n->mu);
    c = n->nsubs;
    pthread_mutex_unlock(&n->mu);
    return c;
}

/* ---- state file ---- */

void nssf_state_save(nssf *n)
{
    g5c_json *root, *nfs, *subs;
    char *text, *tmp;
    FILE *f;
    size_t len = 0;
    bool ok = false;
    if (n->cfg->state_file == NULL)
        return;
    root = g5c_json_new_obj();
    nfs = g5c_json_set(root, "nfs", g5c_json_new_arr());
    subs = g5c_json_set(root, "subscriptions", g5c_json_new_arr());
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < n->nnfs; i++) {
        g5c_json *e = g5c_json_push(nfs, g5c_json_new_obj());
        g5c_json_set_str(e, "nfId", n->nfs[i].nf_id);
        g5c_json_set(e, "info", g5c_json_dup(n->nfs[i].doc));
    }
    for (size_t i = 0; i < n->nsubs; i++) {
        g5c_json *e = g5c_json_push(subs, g5c_json_new_obj());
        g5c_json_set_str(e, "id", n->subs[i].id);
        g5c_json_set(e, "create", g5c_json_dup(n->subs[i].create));
        if (n->subs[i].last != NULL)
            g5c_json_set(e, "last", g5c_json_dup(n->subs[i].last));
    }
    pthread_mutex_unlock(&n->mu);
    text = g5c_json_to_string(root, &len);
    g5c_json_free(root);
    tmp = g5c_xasprintf("%s.tmp", n->cfg->state_file);
    f = text != NULL ? fopen(tmp, "wb") : NULL;
    if (f != NULL) {
        ok = fwrite(text, 1, len, f) == len && fflush(f) == 0;
        if (fclose(f) != 0)
            ok = false;
        ok = ok && rename(tmp, n->cfg->state_file) == 0;
        if (!ok)
            (void)remove(tmp);
    }
    if (!ok)
        G5C_LOGE("g5c_nssf", "cannot write the state file %s", n->cfg->state_file);
    free(tmp);
    free(text);
}

int nssf_state_load(nssf *n, char *err, size_t errcap)
{
    size_t len = 0;
    char *text;
    g5c_json *root;
    const g5c_json *nfs, *subs;
    if (n->cfg->state_file == NULL)
        return 0;
    text = g5c_read_file(n->cfg->state_file, 256U << 20, &len);
    if (text == NULL) { /* first start: the file is created when something changes */
        FILE *f = fopen(n->cfg->state_file, "ab");
        if (f == NULL) {
            snprintf(err, errcap, "cannot create the state file %s", n->cfg->state_file);
            return -1;
        }
        fclose(f);
        return 0;
    }
    root = len > 0 ? g5c_json_parse(text, len, err, errcap) : g5c_json_new_obj();
    free(text);
    if (root == NULL || !g5c_json_is(root, G5C_J_OBJECT)) {
        if (root != NULL)
            snprintf(err, errcap, "%s: not a JSON object", n->cfg->state_file);
        g5c_json_free(root);
        return -1;
    }
    nfs = g5c_json_get(root, "nfs");
    for (size_t i = 0; i < g5c_json_len(nfs); i++) {
        nf_entry_t e;
        const g5c_json *x = g5c_json_at(nfs, i);
        memset(&e, 0, sizeof e);
        if (nf_id_ok(g5c_json_get_str(x, "nfId")) && entry_parse(&e, g5c_json_get(x, "info"))) {
            e.nf_id = g5c_xstrdup(g5c_json_get_str(x, "nfId"));
            store_entry(n, &e);
        } else {
            entry_free(&e);
        }
    }
    subs = g5c_json_get(root, "subscriptions");
    for (size_t i = 0; i < g5c_json_len(subs); i++) {
        sub_t s;
        const g5c_json *x = g5c_json_at(subs, i);
        memset(&s, 0, sizeof s);
        s.id = g5c_xstrdup(g5c_json_get_str(x, "id") != NULL ? g5c_json_get_str(x, "id") : "");
        s.create = g5c_json_dup(g5c_json_get(x, "create"));
        s.last = g5c_json_get(x, "last") != NULL ? g5c_json_dup(g5c_json_get(x, "last")) : NULL;
        if (s.id[0] != '\0' && s.create != NULL && sub_parse(&s, s.create) && (s.expiry == 0 || s.expiry > (int64_t)time(NULL))) {
            if (n->nsubs == n->capsubs) {
                n->capsubs = n->capsubs ? n->capsubs * 2 : 16;
                n->subs = g5c_xrealloc(n->subs, n->capsubs * sizeof *n->subs);
            }
            n->subs[n->nsubs++] = s;
        } else {
            sub_free(&s);
        }
    }
    g5c_json_free(root);
    if (n->g_nfs != NULL)
        g5c_gauge_set(n->g_nfs, (int64_t)n->nnfs);
    if (n->g_subs != NULL)
        g5c_gauge_set(n->g_subs, (int64_t)n->nsubs);
    return 0;
}
