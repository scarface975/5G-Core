/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Subscriptions to data changes and the notifications sent for them (TS 29.504 5.2.2.6 - 5.2.2.8, TS 29.505, TS 29.519).
 *
 * A subscription is a document under <data set>/subs-to-notify/<id> in the global partition, created through the
 * ordinary POST. Every successful write calls udr_notify(); the subscriptions of the data set the changed key belongs to
 * are matched against it (by monitored resource URI for subscription-, policy- and exposure-data, by filter for
 * application data and influence data) and a notification is queued. Worker threads deliver with retries, so a slow or
 * dead consumer never delays the request that changed the data. */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "g5c/base.h"
#include "g5c/sbi.h"
#include "priv.h"

enum { K_SD, K_PD, K_ED, K_AD, K_TI, K_N };
static const char *const SUBS_KEY[K_N] = {"subscription-data/subs-to-notify", "policy-data/subs-to-notify",
                                          "exposure-data/subs-to-notify", "application-data/subs-to-notify",
                                          "application-data/influenceData/subs-to-notify"};
#define CACHE_TTL_S 2 /* another replica may have written a subscription: refresh at least this often */
#define SWEEP_PERIOD_S 30
#define NWORKERS 2

typedef struct {
    char *id;
    g5c_json *doc;
    char **parts, **keys; /* the monitored resources, resolved to storage addresses (URI based subscriptions) */
    char **uris;
    size_t nmon;
    int64_t expiry; /* epoch seconds, 0: none */
} sub_t;

typedef struct {
    sub_t *subs;
    size_t n;
    int64_t loaded;
    bool dirty;
} fam_t;

typedef struct job {
    char *url, *body, *sub_id;
    unsigned attempts;
    double not_before; /* monotonic */
    struct job *next;
} job_t;

struct udr_notifier {
    g5c_udr *u;
    pthread_mutex_t mu;  /* the delivery queue */
    pthread_cond_t cv;
    pthread_mutex_t cmu; /* the subscription caches (taken before mu, never after) */
    fam_t fam[K_N];
    job_t *q;     /* ordered by not_before */
    size_t qlen;
    bool stop;
    pthread_t workers[NWORKERS], sweeper;
    size_t nworkers;
    bool sweeper_on;
    g5c_counter *c_ok, *c_failed, *c_dropped, *c_queued;
    g5c_gauge *g_queue, *g_subs;
};

/* ---- subscriptions: the cache ---- */

static void sub_free(sub_t *s)
{
    for (size_t i = 0; i < s->nmon; i++) {
        free(s->parts[i]);
        free(s->keys[i]);
        free(s->uris[i]);
    }
    free(s->parts);
    free(s->keys);
    free(s->uris);
    free(s->id);
    g5c_json_free(s->doc);
}

static void fam_clear(fam_t *f)
{
    for (size_t i = 0; i < f->n; i++)
        sub_free(&f->subs[i]);
    free(f->subs);
    f->subs = NULL;
    f->n = 0;
}

static const char *notif_uri_of(int kind, const g5c_json *doc)
{
    return g5c_json_get_str(doc, kind == K_SD ? "callbackReference" : "notificationUri");
}

/* read the subscriptions of one data set from the store */
static void fam_load(udr_notifier *n, int kind, fam_t *out)
{
    g5c_udr *u = n->u;
    udr_db *db = udr_db_get(u);
    udr_list l;
    int64_t now = (int64_t)time(NULL);
    size_t pl = strlen(SUBS_KEY[kind]) + 1;
    memset(out, 0, sizeof *out);
    if (db->ops->list(db->self, UDR_GLOBAL_PART, SUBS_KEY[kind], &l) != 0)
        return;
    out->subs = g5c_xcalloc(l.n + 1, sizeof *out->subs);
    for (size_t i = 0; i < l.n; i++) {
        sub_t *s = &out->subs[out->n];
        const g5c_json *mon = g5c_json_get(l.recs[i].doc, "monitoredResourceUris");
        const char *exp = g5c_json_get_str(l.recs[i].doc, "expiry");
        if (strchr(l.keys[i] + pl, '/') != NULL || notif_uri_of(kind, l.recs[i].doc) == NULL)
            continue;
        s->expiry = exp != NULL ? udr_parse_rfc3339(exp) : 0;
        if (s->expiry < 0)
            s->expiry = 0;
        if (s->expiry != 0 && s->expiry <= now)
            continue; /* expired: the sweeper removes the document */
        s->id = g5c_xstrdup(l.keys[i] + pl);
        s->doc = l.recs[i].doc;
        l.recs[i].doc = NULL;
        if (kind == K_SD || kind == K_PD || kind == K_ED) {
            s->parts = g5c_xcalloc(g5c_json_len(mon) + 1, sizeof *s->parts);
            s->keys = g5c_xcalloc(g5c_json_len(mon) + 1, sizeof *s->keys);
            s->uris = g5c_xcalloc(g5c_json_len(mon) + 1, sizeof *s->uris);
            for (size_t k = 0; k < g5c_json_len(mon); k++) {
                const char *uri = g5c_json_str(g5c_json_at(mon, k));
                char *part, *key;
                if (uri != NULL && udr_resolve_uri(u, uri, &part, &key)) {
                    s->parts[s->nmon] = part;
                    s->keys[s->nmon] = key;
                    s->uris[s->nmon] = g5c_xstrdup(uri);
                    s->nmon++;
                }
            }
        }
        out->n++;
    }
    out->loaded = now;
    udr_list_free(&l);
}

static void refresh_if_stale(udr_notifier *n, int kind)
{
    bool stale;
    fam_t fresh;
    pthread_mutex_lock(&n->cmu);
    stale = n->fam[kind].dirty || (int64_t)time(NULL) - n->fam[kind].loaded >= CACHE_TTL_S;
    pthread_mutex_unlock(&n->cmu);
    if (!stale)
        return;
    fam_load(n, kind, &fresh);
    pthread_mutex_lock(&n->cmu);
    fam_clear(&n->fam[kind]);
    n->fam[kind] = fresh;
    if (n->g_subs != NULL) {
        size_t total = 0;
        for (int k = 0; k < K_N; k++)
            total += n->fam[k].n;
        g5c_gauge_set(n->g_subs, (int64_t)total);
    }
    pthread_mutex_unlock(&n->cmu);
}

void udr_subscriptions_changed(g5c_udr *u)
{
    udr_notifier *n = udr_notifier_of(u);
    if (n == NULL)
        return;
    pthread_mutex_lock(&n->cmu);
    for (int k = 0; k < K_N; k++)
        n->fam[k].dirty = true;
    pthread_mutex_unlock(&n->cmu);
}

bool udr_is_subscription_key(const char *key)
{
    return strstr(key, "subs-to-notify") != NULL;
}

size_t udr_subscription_count(g5c_udr *u, const char *collection_key)
{
    udr_db *db = udr_db_get(u);
    udr_list l;
    size_t n = 0, pl = strlen(collection_key) + 1;
    if (db->ops->list(db->self, UDR_GLOBAL_PART, collection_key, &l) != 0)
        return 0;
    for (size_t i = 0; i < l.n; i++)
        if (strchr(l.keys[i] + pl, '/') == NULL)
            n++;
    udr_list_free(&l);
    return n;
}

/* ---- delivery ---- */

static void enqueue(udr_notifier *n, char *url, char *body, const char *sub_id, unsigned attempts, double delay)
{
    job_t *j = g5c_xcalloc(1, sizeof *j), **pp;
    j->url = url;
    j->body = body;
    j->sub_id = g5c_xstrdup(sub_id);
    j->attempts = attempts;
    j->not_before = g5c_now_seconds() + delay;
    pthread_mutex_lock(&n->mu);
    if (n->qlen >= 8192) { /* a consumer that does not answer must not exhaust the memory */
        pthread_mutex_unlock(&n->mu);
        G5C_LOGW("g5c_udr", "notification queue full: dropping a notification for subscription %s", sub_id);
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
    if (n->g_queue != NULL)
        g5c_gauge_set(n->g_queue, (int64_t)n->qlen);
    pthread_cond_broadcast(&n->cv);
    pthread_mutex_unlock(&n->mu);
}

static void job_free(job_t *j)
{
    free(j->url);
    free(j->body);
    free(j->sub_id);
    free(j);
}

static void *worker_main(void *arg)
{
    udr_notifier *n = arg;
    const udr_opts *o = udr_opts_get(n->u);
    unsigned max_retries = o->notify_retries ? o->notify_retries : 2;
    pthread_mutex_lock(&n->mu);
    for (;;) {
        job_t *j;
        double now;
        while (!n->stop && (n->q == NULL || n->q->not_before > g5c_now_seconds())) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            if (n->q != NULL) {
                double wait = n->q->not_before - g5c_now_seconds();
                ts.tv_sec += (time_t)wait;
                ts.tv_nsec += (long)((wait - (double)(time_t)wait) * 1e9);
            } else {
                ts.tv_sec += 1;
            }
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
            pthread_cond_timedwait(&n->cv, &n->mu, &ts);
        }
        if (n->stop && (n->q == NULL))
            break;
        if (n->stop) { /* shutting down: what is left is not delivered */
            while (n->q != NULL) {
                j = n->q;
                n->q = j->next;
                job_free(j);
            }
            n->qlen = 0;
            break;
        }
        j = n->q;
        n->q = j->next;
        n->qlen--;
        now = g5c_now_seconds();
        (void)now;
        if (n->g_queue != NULL)
            g5c_gauge_set(n->g_queue, (int64_t)n->qlen);
        pthread_mutex_unlock(&n->mu);
        {
            g5c_resp r;
            char err[160] = "";
            int rc = o->client != NULL ? g5c_client_request(o->client, "POST", j->url, NULL, 0, G5C_JSON_TYPE, j->body,
                                                            strlen(j->body), &r, err, sizeof err)
                                       : -1;
            bool ok = false;
            if (rc == 0) {
                ok = r.status >= 200 && r.status < 300;
                if (!ok)
                    snprintf(err, sizeof err, "HTTP %d", r.status);
                g5c_resp_free(&r);
            }
            if (ok) {
                g5c_counter_inc(n->c_ok);
            } else if (o->client == NULL) {
                g5c_counter_inc(n->c_dropped);
            } else if (j->attempts < max_retries) {
                double delay = j->attempts == 0 ? 0.5 : 2.0;
                G5C_LOGD("g5c_udr", "notification to %s failed (%s): retry %u", j->url, err, j->attempts + 1);
                enqueue(n, j->url, j->body, j->sub_id, j->attempts + 1, delay);
                j->url = j->body = NULL;
            } else {
                G5C_LOGW("g5c_udr", "notification of subscription %s to %s failed (%s): giving up", j->sub_id, j->url, err);
                g5c_counter_inc(n->c_failed);
            }
        }
        job_free(j);
        pthread_mutex_lock(&n->mu);
    }
    pthread_mutex_unlock(&n->mu);
    return NULL;
}

/* remove the subscriptions that have expired (the cache already ignores them) */
static void sweep(udr_notifier *n)
{
    udr_db *db = udr_db_get(n->u);
    int64_t now = (int64_t)time(NULL);
    for (int kind = 0; kind < K_N; kind++) {
        udr_list l;
        size_t pl = strlen(SUBS_KEY[kind]) + 1;
        if (db->ops->list(db->self, UDR_GLOBAL_PART, SUBS_KEY[kind], &l) != 0)
            continue;
        for (size_t i = 0; i < l.n; i++) {
            const char *exp = g5c_json_get_str(l.recs[i].doc, "expiry");
            int64_t e = exp != NULL ? udr_parse_rfc3339(exp) : 0;
            if (e > 0 && e <= now && strchr(l.keys[i] + pl, '/') == NULL) {
                udr_cond c = {UDR_COND_MATCH, l.recs[i].rev};
                (void)db->ops->del(db->self, UDR_GLOBAL_PART, l.keys[i], &c, NULL);
            }
        }
        udr_list_free(&l);
    }
    udr_subscriptions_changed(n->u);
}

static void *sweeper_main(void *arg)
{
    udr_notifier *n = arg;
    pthread_mutex_lock(&n->mu);
    while (!n->stop) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += SWEEP_PERIOD_S;
        pthread_cond_timedwait(&n->cv, &n->mu, &ts);
        if (n->stop)
            break;
        pthread_mutex_unlock(&n->mu);
        sweep(n);
        pthread_mutex_lock(&n->mu);
    }
    pthread_mutex_unlock(&n->mu);
    return NULL;
}

udr_notifier *udr_notifier_new(g5c_udr *u)
{
    udr_notifier *n = g5c_xcalloc(1, sizeof *n);
    const udr_opts *o = udr_opts_get(u);
    n->u = u;
    pthread_mutex_init(&n->mu, NULL);
    pthread_mutex_init(&n->cmu, NULL);
    pthread_cond_init(&n->cv, NULL);
    {
        g5c_label ok[] = {{"result", "delivered"}}, fl[] = {{"result", "failed"}}, dr[] = {{"result", "dropped"}};
        n->c_ok = g5c_counter_get(o->metrics, "g5c_udr_notifications_total", "notifications by outcome", ok, 1);
        n->c_failed = g5c_counter_get(o->metrics, "g5c_udr_notifications_total", "notifications by outcome", fl, 1);
        n->c_dropped = g5c_counter_get(o->metrics, "g5c_udr_notifications_total", "notifications by outcome", dr, 1);
        n->c_queued = g5c_counter_get(o->metrics, "g5c_udr_notifications_queued_total", "notifications queued for delivery", NULL, 0);
        n->g_queue = g5c_gauge_get(o->metrics, "g5c_udr_notification_queue", "notifications waiting for delivery", NULL, 0);
        n->g_subs = g5c_gauge_get(o->metrics, "g5c_udr_subscriptions", "active subscriptions to data changes", NULL, 0);
    }
    for (int k = 0; k < K_N; k++)
        n->fam[k].dirty = true;
    for (size_t i = 0; i < NWORKERS; i++)
        if (pthread_create(&n->workers[n->nworkers], NULL, worker_main, n) == 0)
            n->nworkers++;
    n->sweeper_on = pthread_create(&n->sweeper, NULL, sweeper_main, n) == 0;
    return n;
}

void udr_notifier_free(udr_notifier *n)
{
    if (n == NULL)
        return;
    pthread_mutex_lock(&n->mu);
    n->stop = true;
    pthread_cond_broadcast(&n->cv);
    pthread_mutex_unlock(&n->mu);
    for (size_t i = 0; i < n->nworkers; i++)
        pthread_join(n->workers[i], NULL);
    if (n->sweeper_on)
        pthread_join(n->sweeper, NULL);
    for (int k = 0; k < K_N; k++)
        fam_clear(&n->fam[k]);
    pthread_cond_destroy(&n->cv);
    pthread_mutex_destroy(&n->mu);
    pthread_mutex_destroy(&n->cmu);
    free(n);
}

/* ---- matching and bodies ---- */

/* The changes of a document as ChangeItems (TS 29.571 NotifyItem) */
static g5c_json *change_items(const g5c_json *before, const g5c_json *after)
{
    g5c_json *arr = g5c_json_new_arr(), *c;
    if (before == NULL || after == NULL || !g5c_json_is(before, G5C_J_OBJECT) || !g5c_json_is(after, G5C_J_OBJECT)) {
        c = g5c_json_push(arr, g5c_json_new_obj());
        g5c_json_set_str(c, "op", before == NULL ? "ADD" : after == NULL ? "REMOVE" : "REPLACE");
        g5c_json_set_str(c, "path", "");
        if (before != NULL)
            g5c_json_set(c, "origValue", g5c_json_dup(before));
        if (after != NULL)
            g5c_json_set(c, "newValue", g5c_json_dup(after));
        return arr;
    }
    for (size_t i = 0; i < g5c_json_len(after); i++) {
        const char *k = g5c_json_key_at(after, i);
        const g5c_json *b = g5c_json_get(before, k), *a = g5c_json_val_at(after, i);
        if (b != NULL && g5c_json_equal(a, b))
            continue;
        c = g5c_json_push(arr, g5c_json_new_obj());
        {
            char *p = g5c_xasprintf("/%s", k);
            g5c_json_set_str(c, "op", b == NULL ? "ADD" : "REPLACE");
            g5c_json_set_str(c, "path", p);
            free(p);
        }
        if (b != NULL)
            g5c_json_set(c, "origValue", g5c_json_dup(b));
        g5c_json_set(c, "newValue", g5c_json_dup(a));
    }
    for (size_t i = 0; i < g5c_json_len(before); i++) {
        const char *k = g5c_json_key_at(before, i);
        if (g5c_json_get(after, k) == NULL) {
            char *p = g5c_xasprintf("/%s", k);
            c = g5c_json_push(arr, g5c_json_new_obj());
            g5c_json_set_str(c, "op", "REMOVE");
            g5c_json_set_str(c, "path", p);
            g5c_json_set(c, "origValue", g5c_json_dup(g5c_json_val_at(before, i)));
            free(p);
        }
    }
    return arr;
}

static bool starts(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* policy data: which member of PolicyDataChangeNotification carries the document at `key` (and the identifier in its path) */
static const char *pd_member(const char *key, char **idname, char **id)
{
    *idname = NULL;
    *id = NULL;
    if (starts(key, "policy-data/ues/")) {
        const char *r = key + strlen("policy-data/ues/");
        if (strcmp(r, "am-data") == 0)
            return "amPolicyData";
        if (strcmp(r, "ue-policy-set") == 0)
            return "uePolicySet";
        if (strcmp(r, "sm-data") == 0)
            return "smPolicyData";
        if (strcmp(r, "operator-specific-data") == 0)
            return "opSpecDataMap";
        if (starts(r, "sm-data/")) {
            *idname = "usageMonId";
            *id = g5c_xstrdup(r + strlen("sm-data/"));
            return "usageMonData";
        }
    } else if (starts(key, "policy-data/sponsor-connectivity-data/")) {
        *idname = "sponsorId";
        *id = g5c_xstrdup(key + strlen("policy-data/sponsor-connectivity-data/"));
        return "SponsorConnectivityData";
    } else if (starts(key, "policy-data/bdt-data/")) {
        *idname = "bdtRefId";
        *id = g5c_xstrdup(key + strlen("policy-data/bdt-data/"));
        return "bdtData";
    } else if (starts(key, "policy-data/plmns/")) {
        const char *r = key + strlen("policy-data/plmns/");
        const char *slash = strchr(r, '/');
        if (slash != NULL && strcmp(slash, "/ue-policy-set") == 0) {
            *idname = "plmnId";
            *id = g5c_xstrndup(r, (size_t)(slash - r));
            return "plmnUePolicySet";
        }
    }
    return NULL;
}

static g5c_json *plmn_obj(const char *s)
{
    g5c_json *o = g5c_json_new_obj();
    size_t n = strlen(s);
    if (n >= 5 && n <= 6) {
        char mcc[4], mnc[4];
        memcpy(mcc, s, 3);
        mcc[3] = '\0';
        memcpy(mnc, s + 3, n - 3);
        mnc[n - 3] = '\0';
        g5c_json_set_str(o, "mcc", mcc);
        g5c_json_set_str(o, "mnc", mnc);
    }
    return o;
}

static bool arr_has_str(const g5c_json *arr, const char *s)
{
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const char *e = g5c_json_str(g5c_json_at(arr, i));
        if (e != NULL && s != NULL && strcmp(e, s) == 0)
            return true;
    }
    return false;
}

static bool snssai_in(const g5c_json *arr, const g5c_json *one)
{
    for (size_t i = 0; i < g5c_json_len(arr); i++)
        if (udr_snssai_equal(g5c_json_at(arr, i), one))
            return true;
    return false;
}

/* A filter of an application-data / influence-data subscription (dnns, snssais, internalGroupIds, supis, appIds) against a stored document */
static bool filter_match(const g5c_json *f, const g5c_json *doc)
{
    const g5c_json *x;
    if (g5c_json_len(g5c_json_get(f, "dnns")) > 0 && g5c_json_get_str(doc, "dnn") != NULL &&
        !arr_has_str(g5c_json_get(f, "dnns"), g5c_json_get_str(doc, "dnn")))
        return false;
    if (g5c_json_len(g5c_json_get(f, "snssais")) > 0 && (x = g5c_json_get(doc, "snssai")) != NULL &&
        !snssai_in(g5c_json_get(f, "snssais"), x))
        return false;
    if (g5c_json_len(g5c_json_get(f, "internalGroupIds")) > 0 && g5c_json_get_str(doc, "interGroupId") != NULL &&
        !arr_has_str(g5c_json_get(f, "internalGroupIds"), g5c_json_get_str(doc, "interGroupId")))
        return false;
    if (g5c_json_len(g5c_json_get(f, "supis")) > 0) {
        const char *one = g5c_json_get_str(doc, "supi");
        const g5c_json *many = g5c_json_get(doc, "supis");
        if (one != NULL && !arr_has_str(g5c_json_get(f, "supis"), one))
            return false;
        if (one == NULL && many != NULL) {
            bool any = false;
            for (size_t i = 0; i < g5c_json_len(many) && !any; i++)
                any = arr_has_str(g5c_json_get(f, "supis"), g5c_json_str(g5c_json_at(many, i)));
            if (!any)
                return false;
        }
    }
    if (g5c_json_len(g5c_json_get(f, "appIds")) > 0 && g5c_json_get_str(doc, "afAppId") != NULL &&
        !arr_has_str(g5c_json_get(f, "appIds"), g5c_json_get_str(doc, "afAppId")))
        return false;
    return true;
}

static bool suppressed(const char *list, const char *sub_id)
{
    size_t n = strlen(sub_id);
    for (const char *p = list; p != NULL && *p;) {
        while (*p == ' ' || *p == ',')
            p++;
        if (strncmp(p, sub_id, n) == 0 && (p[n] == '\0' || p[n] == ',' || p[n] == ' '))
            return true;
        p += strcspn(p, ", ");
    }
    return false;
}

static char *res_uri(g5c_udr *u, const char *key)
{
    const udr_opts *o = udr_opts_get(u);
    return g5c_xasprintf("%s/nudr-dr/v2/%s", o->api_root != NULL ? o->api_root : "http://127.0.0.1", key);
}

static void emit(udr_notifier *n, const char *url, g5c_json *body, const char *sub_id)
{
    char *text = g5c_json_to_string(body, NULL);
    g5c_json_free(body);
    g5c_counter_inc(n->c_queued);
    enqueue(n, g5c_xstrdup(url), text, sub_id, 0, 0);
}

static void notify_uri_based(udr_notifier *n, int kind, const sub_t *s, const char *part, const char *key,
                             const g5c_json *before, const g5c_json *after, bool ue_part)
{
    const char *url = notif_uri_of(kind, s->doc), *want_ue = g5c_json_get_str(s->doc, "ueId");
    const char *matched = NULL;
    size_t kl = strlen(key);
    if (want_ue != NULL && ue_part && strcmp(want_ue, part) != 0)
        return;
    for (size_t i = 0; i < s->nmon && matched == NULL; i++) {
        size_t ml = strlen(s->keys[i]);
        if (strcmp(s->parts[i], part) == 0 && (strcmp(s->keys[i], key) == 0 || (kl > ml && strncmp(key, s->keys[i], ml) == 0 && key[ml] == '/')))
            matched = s->uris[i];
    }
    if (matched == NULL)
        return;
    if (kind == K_SD) {
        g5c_json *b = g5c_json_new_obj(), *items = g5c_json_set(b, "notifyItems", g5c_json_new_arr()), *it;
        const char *orig = g5c_json_get_str(s->doc, "originalCallbackReference");
        if (ue_part)
            g5c_json_set_str(b, "ueId", part);
        if (orig != NULL)
            g5c_json_push_str(g5c_json_set(b, "originalCallbackReference", g5c_json_new_arr()), orig);
        it = g5c_json_push(items, g5c_json_new_obj());
        g5c_json_set_str(it, "resourceId", matched);
        g5c_json_set(it, "changes", change_items(before, after));
        if (g5c_json_get(s->doc, "sdmSubscription") != NULL)
            g5c_json_set(b, "sdmSubscription", g5c_json_dup(g5c_json_get(s->doc, "sdmSubscription")));
        emit(n, url, b, s->id);
    } else if (kind == K_PD) {
        char *idname, *id;
        const char *member = pd_member(key, &idname, &id);
        g5c_json *arr = g5c_json_new_arr(), *b = g5c_json_push(arr, g5c_json_new_obj());
        if (member == NULL) {
            g5c_json_free(arr);
            free(id);
            return;
        }
        if (ue_part)
            g5c_json_set_str(b, "ueId", part);
        if (g5c_json_get_str(s->doc, "notifId") != NULL)
            g5c_json_set_str(b, "notifId", g5c_json_get_str(s->doc, "notifId"));
        if (id != NULL) {
            if (strcmp(idname, "plmnId") == 0)
                g5c_json_set(b, "plmnId", plmn_obj(id));
            else
                g5c_json_set_str(b, idname, id);
        }
        if (after != NULL)
            g5c_json_set(b, member, g5c_json_dup(after));
        else
            g5c_json_push_str(g5c_json_set(b, "delResources", g5c_json_new_arr()), matched);
        free(id);
        emit(n, url, arr, s->id);
    } else { /* K_ED */
        g5c_json *arr = g5c_json_new_arr(), *b = g5c_json_push(arr, g5c_json_new_obj());
        if (ue_part)
            g5c_json_set_str(b, "ueId", part);
        if (strcmp(key, "exposure-data/access-and-mobility-data") == 0) {
            if (after != NULL)
                g5c_json_set(b, "accessAndMobilityData", g5c_json_dup(after));
        } else if (starts(key, "exposure-data/session-management-data/")) {
            if (after != NULL)
                g5c_json_push(g5c_json_set(b, "pduSessionManagementData", g5c_json_new_arr()), g5c_json_dup(after));
        } else {
            g5c_json_free(arr);
            return;
        }
        if (after == NULL)
            g5c_json_push_str(g5c_json_set(b, "delResources", g5c_json_new_arr()), matched);
        emit(n, url, arr, s->id);
    }
}

static const char *data_ind_of(const char *key)
{
    if (starts(key, "application-data/iptvConfigData/"))
        return "IPTV";
    if (starts(key, "application-data/bdtPolicyData/"))
        return "BDT";
    if (starts(key, "application-data/serviceParamData/"))
        return "SVC_PARAM";
    if (starts(key, "application-data/pfds/"))
        return "PFD";
    return NULL;
}

static void notify_application(udr_notifier *n, int kind, const sub_t *s, const char *key, const g5c_json *before,
                               const g5c_json *after)
{
    const char *url = notif_uri_of(kind, s->doc);
    const g5c_json *doc = after != NULL ? after : before;
    g5c_json *arr, *b;
    char *uri;
    if (kind == K_TI) {
        if (!starts(key, "application-data/influenceData/") || doc == NULL)
            return;
        /* the subscription is one filter: the first of dnns, snssais, internalGroupIds, supis that it names must match */
        if (!filter_match(s->doc, doc))
            return;
        uri = res_uri(n->u, key);
        arr = g5c_json_new_arr();
        b = g5c_json_push(arr, g5c_json_new_obj());
        g5c_json_set_str(b, "resUri", uri);
        if (after != NULL)
            g5c_json_set(b, "trafficInfluData", g5c_json_dup(after));
        free(uri);
        emit(n, url, arr, s->id);
        return;
    }
    {
        const char *ind = data_ind_of(key);
        const g5c_json *filters = g5c_json_get(s->doc, "dataFilters");
        bool match = filters == NULL || g5c_json_len(filters) == 0;
        const char *member;
        if (ind == NULL || strcmp(ind, "PFD") == 0 || doc == NULL) /* PFD change notifications need TS 29.551, not pinned */
            return;
        for (size_t i = 0; i < g5c_json_len(filters) && !match; i++) {
            const g5c_json *f = g5c_json_at(filters, i);
            const char *di = g5c_json_get_str(f, "dataInd");
            if (di != NULL && strcmp(di, ind) == 0 && filter_match(f, doc))
                match = true;
        }
        if (!match)
            return;
        member = strcmp(ind, "IPTV") == 0 ? "iptvConfigData" : strcmp(ind, "BDT") == 0 ? "bdtPolicyData" : "serParamData";
        uri = res_uri(n->u, key);
        arr = g5c_json_new_arr();
        b = g5c_json_push(arr, g5c_json_new_obj());
        g5c_json_set_str(b, "resUri", uri);
        if (after != NULL)
            g5c_json_set(b, member, g5c_json_dup(after));
        free(uri);
        emit(n, url, arr, s->id);
    }
}

void udr_notify(g5c_udr *u, const char *part, const char *key, const g5c_json *before, const g5c_json *after,
                const char *suppress)
{
    udr_notifier *n = udr_notifier_of(u);
    int kind;
    bool ue_part;
    if (n == NULL || key == NULL || (before == NULL && after == NULL))
        return;
    if (udr_is_subscription_key(key)) { /* a subscription was created, changed or removed */
        udr_subscriptions_changed(u);
        return;
    }
    if (starts(key, "subscription-data/"))
        kind = K_SD;
    else if (starts(key, "policy-data/"))
        kind = K_PD;
    else if (starts(key, "exposure-data/"))
        kind = K_ED;
    else if (starts(key, "application-data/influenceData/"))
        kind = K_TI;
    else if (starts(key, "application-data/"))
        kind = K_AD;
    else
        return;
    ue_part = strcmp(part, UDR_GLOBAL_PART) != 0 && !starts(part, UDR_GROUP_PREFIX);
    refresh_if_stale(n, kind);
    pthread_mutex_lock(&n->cmu);
    for (size_t i = 0; i < n->fam[kind].n; i++) {
        const sub_t *s = &n->fam[kind].subs[i];
        if (suppress != NULL && suppressed(suppress, s->id))
            continue;
        if (s->expiry != 0 && s->expiry <= (int64_t)time(NULL))
            continue;
        if (kind == K_AD || kind == K_TI)
            notify_application(n, kind, s, key, before, after);
        else
            notify_uri_based(n, kind, s, part, key, before, after, ue_part);
    }
    pthread_mutex_unlock(&n->cmu);
}
