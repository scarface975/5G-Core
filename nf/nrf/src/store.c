/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The registry: profiles and subscriptions, status-change notifications, the heart-beat monitor and the state file. */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "priv.h"

/* ---- small helpers ---- */

bool nrf_valid_uuid(const char *s)
{
    static const int dashes[] = {8, 13, 18, 23};
    if (s == NULL || strlen(s) != 36)
        return false;
    for (int i = 0; i < 36; i++) {
        bool dash = i == dashes[0] || i == dashes[1] || i == dashes[2] || i == dashes[3];
        if (dash ? s[i] != '-' : !isxdigit((unsigned char)s[i]))
            return false;
    }
    return true;
}

void nrf_iso8601(double wall, char out[24])
{
    time_t t = (time_t)wall;
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, 24, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

void nrf_count(nrf *n, const char *name, const char *help, const char *label, const char *value)
{
    if (label != NULL) {
        g5c_label l = {label, value};
        g5c_counter_inc(g5c_counter_get(n->metrics, name, help, &l, 1));
    } else {
        g5c_counter_inc(g5c_counter_get(n->metrics, name, help, NULL, 0));
    }
}

long nrf_find(const nrf *n, const char *id)
{
    for (size_t i = 0; i < n->nprofs; i++)
        if (strcmp(n->profs[i].id, id) == 0)
            return (long)i;
    return -1;
}

bool nrf_list_has(const g5c_json *arr, const char *value)
{
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const char *s = g5c_json_str(g5c_json_at(arr, i));
        if (s != NULL && strcmp(s, value) == 0)
            return true;
    }
    return false;
}

g5c_json *nrf_profile_view(const g5c_json *doc, bool service_map)
{
    g5c_json *out = g5c_json_dup(doc);
    const g5c_json *arr = g5c_json_get(out, "nfServices"), *map = g5c_json_get(out, "nfServiceList");
    if (service_map && arr != NULL && map == NULL) {
        g5c_json *m = g5c_json_new_obj();
        for (size_t i = 0; i < g5c_json_len(arr); i++) {
            const char *sid = g5c_json_get_str(g5c_json_at(arr, i), "serviceInstanceId");
            if (sid != NULL)
                g5c_json_set(m, sid, g5c_json_dup(g5c_json_at(arr, i)));
        }
        (void)g5c_json_remove(out, "nfServices");
        g5c_json_set(out, "nfServiceList", m);
    } else if (!service_map && map != NULL) {
        g5c_json *a = g5c_json_new_arr();
        for (size_t i = 0; i < g5c_json_len(map); i++)
            g5c_json_push(a, g5c_json_dup(g5c_json_val_at(map, i)));
        (void)g5c_json_remove(out, "nfServiceList");
        if (g5c_json_get(out, "nfServices") == NULL)
            g5c_json_set(out, "nfServices", a);
        else
            g5c_json_free(a);
    }
    return out;
}

bool nrf_features_service_map(const char *hex)
{
    size_t n;
    char c;
    int v;
    if (hex == NULL || (n = strlen(hex)) == 0)
        return false;
    c = hex[n - 1];
    v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
    return (v & 1) != 0;
}

/* ---- notifications ---- */

static const char *event_name(nrf_event ev)
{
    return ev == NRF_EV_REGISTERED ? "NF_REGISTERED" : ev == NRF_EV_DEREGISTERED ? "NF_DEREGISTERED" : "NF_PROFILE_CHANGED";
}

static bool has_service(const g5c_json *doc, const char *name)
{
    const g5c_json *a = g5c_json_get(doc, "nfServices"), *m = g5c_json_get(doc, "nfServiceList");
    for (size_t i = 0; i < g5c_json_len(a); i++)
        if (g5c_json_get_str(g5c_json_at(a, i), "serviceName") != NULL && strcmp(g5c_json_get_str(g5c_json_at(a, i), "serviceName"), name) == 0)
            return true;
    for (size_t i = 0; i < g5c_json_len(m); i++)
        if (g5c_json_get_str(g5c_json_val_at(m, i), "serviceName") != NULL && strcmp(g5c_json_get_str(g5c_json_val_at(m, i), "serviceName"), name) == 0)
            return true;
    return false;
}

/* the value at a JSON pointer ("/a/b"), or NULL */
static const g5c_json *at_pointer(const g5c_json *doc, const char *ptr)
{
    const g5c_json *cur = doc;
    char *copy = g5c_xstrdup(ptr), *save = NULL, *tok;
    for (tok = strtok_r(copy[0] == '/' ? copy + 1 : copy, "/", &save); tok != NULL && cur != NULL; tok = strtok_r(NULL, "/", &save)) {
        if (g5c_json_is(cur, G5C_J_ARRAY)) {
            char *end;
            unsigned long i = strtoul(tok, &end, 10);
            cur = *end == 0 ? g5c_json_at(cur, (size_t)i) : NULL;
        } else {
            cur = g5c_json_get(cur, tok);
        }
    }
    free(copy);
    return cur;
}

/* does the change touch what the subscription watches? (notifCondition, TS 29.510 6.1.6.2.16) */
static bool change_watched(const g5c_json *sub, const g5c_json *old_doc, const g5c_json *new_doc)
{
    const g5c_json *nc = g5c_json_get(sub, "notifCondition"), *mon = g5c_json_get(nc, "monitoredAttributes"), *un = g5c_json_get(nc, "unmonitoredAttributes");
    if (old_doc == NULL || new_doc == NULL)
        return true;
    if (g5c_json_len(mon) > 0) {
        for (size_t i = 0; i < g5c_json_len(mon); i++) {
            const char *p = g5c_json_str(g5c_json_at(mon, i));
            const g5c_json *a = p != NULL ? at_pointer(old_doc, p) : NULL, *b = p != NULL ? at_pointer(new_doc, p) : NULL;
            if ((a == NULL) != (b == NULL) || (a != NULL && !g5c_json_equal(a, b)))
                return true;
        }
        return false;
    }
    if (g5c_json_len(un) > 0) {
        /* everything except those attributes: compare copies without them */
        g5c_json *a = g5c_json_dup(old_doc), *b = g5c_json_dup(new_doc);
        bool differs;
        for (size_t i = 0; i < g5c_json_len(un); i++) {
            const char *p = g5c_json_str(g5c_json_at(un, i));
            if (p != NULL && p[0] == '/' && strchr(p + 1, '/') == NULL) {
                (void)g5c_json_remove(a, p + 1);
                (void)g5c_json_remove(b, p + 1);
            }
        }
        differs = !g5c_json_equal(a, b);
        g5c_json_free(a);
        g5c_json_free(b);
        return differs;
    }
    return true;
}

/* does this subscription cover the instance? (SubscrCond, TS 29.510 6.1.6.2.35 and 6.1.6.2.16) */
static bool sub_covers(const g5c_json *sub, const char *id, const g5c_json *prof)
{
    const g5c_json *c = g5c_json_get(sub, "subscrCond");
    const char *v;
    if (c == NULL || g5c_json_len(c) == 0)
        return true;
    if ((v = g5c_json_get_str(c, "nfInstanceId")) != NULL)
        return strcmp(v, id) == 0;
    if ((v = g5c_json_get_str(c, "serviceName")) != NULL)
        return has_service(prof, v);
    if ((v = g5c_json_get_str(c, "nfType")) != NULL) {
        const char *t = g5c_json_get_str(prof, "nfType"), *grp = g5c_json_get_str(c, "nfGroupId");
        if (t == NULL || strcmp(t, v) != 0)
            return false;
        if (grp != NULL) /* NfGroupCond: the group is an attribute of the type-specific info */
            return strstr(g5c_json_get_str(prof, "nfGroupId") != NULL ? g5c_json_get_str(prof, "nfGroupId") : "", grp) != NULL;
        return true;
    }
    if (g5c_json_get_str(c, "amfSetId") != NULL || g5c_json_get_str(c, "amfRegionId") != NULL) {
        const g5c_json *ai = g5c_json_get(prof, "amfInfo");
        const char *set = g5c_json_get_str(c, "amfSetId"), *reg = g5c_json_get_str(c, "amfRegionId");
        if (ai == NULL)
            return false;
        return (set == NULL || (g5c_json_get_str(ai, "amfSetId") != NULL && strcmp(g5c_json_get_str(ai, "amfSetId"), set) == 0)) &&
               (reg == NULL || (g5c_json_get_str(ai, "amfRegionId") != NULL && strcmp(g5c_json_get_str(ai, "amfRegionId"), reg) == 0));
    }
    if (g5c_json_get(c, "snssaiList") != NULL) {
        const g5c_json *want = g5c_json_get(c, "snssaiList"), *have = g5c_json_get(prof, "sNssais");
        if (g5c_json_len(have) == 0)
            return true;
        for (size_t i = 0; i < g5c_json_len(want); i++)
            for (size_t j = 0; j < g5c_json_len(have); j++)
                if (g5c_json_equal(g5c_json_at(want, i), g5c_json_at(have, j)))
                    return true;
        return false;
    }
    return true;
}

static void enqueue(nrf *n, const char *url, char *body)
{
    nrf_job *j = g5c_xcalloc(1, sizeof *j);
    j->url = g5c_xstrdup(url);
    j->body = body;
    pthread_mutex_lock(&n->qmu);
    if (n->qt != NULL)
        n->qt->next = j;
    else
        n->qh = j;
    n->qt = j;
    pthread_cond_signal(&n->qcv);
    pthread_mutex_unlock(&n->qmu);
}

static char *notification_body(nrf *n, nrf_event ev, const char *id, const g5c_json *new_doc, bool service_map)
{
    g5c_json *d = g5c_json_new_obj();
    char *iuri = g5c_xasprintf("%s/nnrf-nfm/v1/nf-instances/%s", n->self_uri, id), *body;
    g5c_json_set_str(d, "event", event_name(ev));
    g5c_json_set_str(d, "nfInstanceUri", iuri);
    if (ev != NRF_EV_DEREGISTERED && new_doc != NULL)
        g5c_json_set(d, "nfProfile", nrf_profile_view(new_doc, service_map));
    body = g5c_json_to_string(d, NULL);
    g5c_json_free(d);
    free(iuri);
    return body;
}

void nrf_notify(nrf *n, nrf_event ev, const char *id, const g5c_json *old_doc, const g5c_json *new_doc)
{
    const g5c_json *prof = new_doc != NULL ? new_doc : old_doc;
    char *body[2] = {NULL, NULL}; /* [0]: services as an array, [1]: as a map (the subscriber supports Service-Map) */
    for (size_t i = 0; i < n->nsubs; i++) {
        const g5c_json *s = n->subs[i].doc, *events = g5c_json_get(s, "reqNotifEvents");
        const char *uri = g5c_json_get_str(s, "nfStatusNotificationUri");
        int variant = nrf_features_service_map(g5c_json_get_str(s, "supportedFeatures")) ? 1 : 0;
        if (uri == NULL || prof == NULL)
            continue;
        if (g5c_json_len(events) > 0 && !nrf_list_has(events, event_name(ev)))
            continue;
        if (!sub_covers(s, id, prof))
            continue;
        if (ev == NRF_EV_PROFILE_CHANGED && !change_watched(s, old_doc, new_doc))
            continue;
        if (body[variant] == NULL)
            body[variant] = notification_body(n, ev, id, new_doc, variant == 1);
        enqueue(n, uri, g5c_xstrdup(body[variant]));
        nrf_count(n, "g5c_nrf_notifications_total", "NFStatusNotify messages queued, by event.", "event", event_name(ev));
    }
    free(body[0]);
    free(body[1]);
}

static void *worker_main(void *arg)
{
    nrf *n = arg;
    for (;;) {
        nrf_job *j;
        g5c_resp r;
        char err[120];
        bool ok = false;
        pthread_mutex_lock(&n->qmu);
        while (n->qh == NULL && !atomic_load(&n->stop))
            pthread_cond_wait(&n->qcv, &n->qmu);
        if (n->qh == NULL) {
            pthread_mutex_unlock(&n->qmu);
            return NULL;
        }
        j = n->qh;
        n->qh = j->next;
        if (n->qh == NULL)
            n->qt = NULL;
        pthread_mutex_unlock(&n->qmu);
        if (g5c_client_request(n->nf->client, "POST", j->url, NULL, 0, G5C_JSON_TYPE, j->body, strlen(j->body), &r, err, sizeof err) == 0) {
            ok = r.status / 100 == 2;
            if (!ok)
                G5C_LOGW(NRF_LOG, "notification to %s answered %d", j->url, r.status);
            g5c_resp_free(&r);
        } else {
            G5C_LOGW(NRF_LOG, "notification to %s: %s", j->url, err);
        }
        if (!ok && ++j->tries < 3 && !atomic_load(&n->stop)) {
            struct timespec ts = {0, 300000000L};
            nanosleep(&ts, NULL);
            pthread_mutex_lock(&n->qmu);
            j->next = NULL;
            if (n->qt != NULL)
                n->qt->next = j;
            else
                n->qh = j;
            n->qt = j;
            pthread_mutex_unlock(&n->qmu);
            continue;
        }
        if (!ok)
            nrf_count(n, "g5c_nrf_notification_failures_total", "Notifications dropped after three attempts.", NULL, NULL);
        free(j->url);
        free(j->body);
        free(j);
    }
}

/* ---- state file ---- */

void nrf_mark_dirty(nrf *n) /* the caller holds n->mu */
{
    n->dirty = true;
}

void nrf_flush(nrf *n)
{
    g5c_json *doc, *pa, *sa;
    char *txt, *tmp;
    FILE *f;
    double wall_now = (double)time(NULL), now = g5c_now_seconds();
    if (n->cfg.state_file == NULL)
        return;
    doc = g5c_json_new_obj();
    pa = g5c_json_set(doc, "profiles", g5c_json_new_arr());
    sa = g5c_json_set(doc, "subscriptions", g5c_json_new_arr());
    g5c_json_set_int(doc, "version", 1);
    pthread_mutex_lock(&n->mu);
    n->dirty = false;
    for (size_t i = 0; i < n->nprofs; i++)
        g5c_json_push(pa, g5c_json_dup(n->profs[i].doc));
    for (size_t i = 0; i < n->nsubs; i++) {
        g5c_json *e = g5c_json_push(sa, g5c_json_new_obj());
        g5c_json_set(e, "doc", g5c_json_dup(n->subs[i].doc));
        g5c_json_set_int(e, "exp", (int64_t)(wall_now + (n->subs[i].expires - now)));
    }
    pthread_mutex_unlock(&n->mu);
    txt = g5c_json_to_string(doc, NULL);
    g5c_json_free(doc);
    tmp = g5c_xasprintf("%s.tmp", n->cfg.state_file);
    f = fopen(tmp, "wb");
    if (f != NULL) {
        size_t l = strlen(txt);
        bool ok = fwrite(txt, 1, l, f) == l && fflush(f) == 0;
        ok = fclose(f) == 0 && ok;
        if (!ok || rename(tmp, n->cfg.state_file) != 0) {
            G5C_LOGW(NRF_LOG, "cannot write the state file %s: %s", n->cfg.state_file, strerror(errno));
            (void)unlink(tmp);
        }
    } else {
        G5C_LOGW(NRF_LOG, "cannot write the state file %s: %s", n->cfg.state_file, strerror(errno));
    }
    free(tmp);
    free(txt);
}

int nrf_restore(nrf *n)
{
    size_t len = 0;
    char *txt, perr[96];
    g5c_json *d;
    double now = g5c_now_seconds(), wall = (double)time(NULL);
    if (n->cfg.state_file == NULL)
        return 0;
    txt = g5c_read_file(n->cfg.state_file, 256u << 20, &len);
    if (txt == NULL)
        return 0;
    d = g5c_json_parse(txt, len, perr, sizeof perr);
    free(txt);
    if (d == NULL || !g5c_json_is(d, G5C_J_OBJECT)) {
        G5C_LOGE(NRF_LOG, "state file %s is unreadable (%s); starting empty", n->cfg.state_file, perr);
        g5c_json_free(d);
        return -1;
    }
    pthread_mutex_lock(&n->mu);
    {
        const g5c_json *pa = g5c_json_get(d, "profiles"), *sa = g5c_json_get(d, "subscriptions");
        for (size_t i = 0; i < g5c_json_len(pa); i++) {
            const g5c_json *p = g5c_json_at(pa, i);
            const char *id = g5c_json_get_str(p, "nfInstanceId");
            nrf_prof *x;
            if (id == NULL || !nrf_valid_uuid(id) || nrf_find(n, id) >= 0)
                continue;
            if (n->nprofs == n->capprofs) {
                n->capprofs = n->capprofs != 0 ? n->capprofs * 2 : 32;
                n->profs = g5c_xrealloc(n->profs, n->capprofs * sizeof *n->profs);
            }
            x = &n->profs[n->nprofs++];
            memset(x, 0, sizeof *x);
            snprintf(x->id, sizeof x->id, "%s", id);
            x->doc = g5c_json_dup(p);
            x->last_hb = now; /* a full interval to come back after our own restart */
            x->etag = ++n->next_etag;
            if (g5c_json_get_str(p, "nfStatus") != NULL && strcmp(g5c_json_get_str(p, "nfStatus"), "SUSPENDED") == 0)
                x->suspended_at = now;
        }
        for (size_t i = 0; i < g5c_json_len(sa); i++) {
            const g5c_json *e = g5c_json_at(sa, i), *doc = g5c_json_get(e, "doc");
            int64_t exp = 0;
            const char *sid = g5c_json_get_str(doc, "subscriptionId");
            nrf_sub *s;
            if (sid == NULL || strlen(sid) >= sizeof s->id || !g5c_json_get_int(e, "exp", &exp) || (double)exp <= wall)
                continue;
            if (n->nsubs == n->capsubs) {
                n->capsubs = n->capsubs != 0 ? n->capsubs * 2 : 32;
                n->subs = g5c_xrealloc(n->subs, n->capsubs * sizeof *n->subs);
            }
            s = &n->subs[n->nsubs++];
            memset(s, 0, sizeof *s);
            snprintf(s->id, sizeof s->id, "%s", sid);
            s->doc = g5c_json_dup(doc);
            s->expires = now + ((double)exp - wall);
            if (strtoull(sid, NULL, 10) >= n->next_sub)
                n->next_sub = strtoull(sid, NULL, 10) + 1;
        }
    }
    pthread_mutex_unlock(&n->mu);
    g5c_json_free(d);
    G5C_LOGI(NRF_LOG, "restored %zu NF profile(s) and %zu subscription(s) from %s", n->nprofs, n->nsubs, n->cfg.state_file);
    return 0;
}

/* ---- the monitor: heart-beats, subscription validity, state file ---- */

static void monitor_pass(nrf *n)
{
    double now = g5c_now_seconds();
    bool flush = false;
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < n->nprofs;) {
        nrf_prof *p = &n->profs[i];
        const char *st = g5c_json_get_str(p->doc, "nfStatus");
        int64_t hb = n->cfg.hb_timer;
        bool susp = st != NULL && strcmp(st, "SUSPENDED") == 0;
        (void)g5c_json_get_int(p->doc, "heartBeatTimer", &hb);
        if (!susp && hb > 0 && now - p->last_hb > (double)hb * n->cfg.suspend_after) {
            g5c_json *old = g5c_json_dup(p->doc);
            g5c_json_set_str(p->doc, "nfStatus", "SUSPENDED");
            p->suspended_at = now;
            p->etag = ++n->next_etag;
            G5C_LOGW(NRF_LOG, "%s %s missed its heart-beats: SUSPENDED", g5c_json_get_str(p->doc, "nfType"), p->id);
            nrf_count(n, "g5c_nrf_suspended_total", "NF instances suspended after missed heart-beats.", NULL, NULL);
            nrf_notify(n, NRF_EV_PROFILE_CHANGED, p->id, old, p->doc);
            g5c_json_free(old);
            nrf_mark_dirty(n);
        } else if (susp && n->cfg.purge_after > 0 && p->suspended_at > 0 && now - p->suspended_at > n->cfg.purge_after) {
            G5C_LOGW(NRF_LOG, "%s %s has been suspended for %d s: deregistered", g5c_json_get_str(p->doc, "nfType"), p->id, n->cfg.purge_after);
            nrf_notify(n, NRF_EV_DEREGISTERED, p->id, p->doc, NULL);
            g5c_json_free(p->doc);
            n->profs[i] = n->profs[--n->nprofs];
            nrf_count(n, "g5c_nrf_purged_total", "NF instances removed after staying suspended.", NULL, NULL);
            nrf_mark_dirty(n);
            continue;
        }
        i++;
    }
    for (size_t i = 0; i < n->nsubs;) {
        if (n->subs[i].expires <= now) {
            g5c_json_free(n->subs[i].doc);
            n->subs[i] = n->subs[--n->nsubs];
            nrf_mark_dirty(n);
            continue;
        }
        i++;
    }
    flush = n->dirty && n->cfg.state_file != NULL && (now - n->last_flush) * 1000.0 >= (double)n->flush_gap_ms;
    {
        g5c_gauge *g = g5c_gauge_get(n->metrics, "g5c_nrf_profiles", "NF profiles held by the NRF.", NULL, 0);
        g5c_gauge_set(g, (int64_t)n->nprofs);
        g5c_gauge_set(g5c_gauge_get(n->metrics, "g5c_nrf_subscriptions", "Status subscriptions held by the NRF.", NULL, 0), (int64_t)n->nsubs);
    }
    pthread_mutex_unlock(&n->mu);
    if (flush) {
        double t0 = g5c_now_seconds(), took;
        nrf_flush(n);
        took = g5c_now_seconds() - t0;
        pthread_mutex_lock(&n->mu);
        n->last_flush = g5c_now_seconds();
        /* the file is the whole registry: spend about a tenth of the thread on it however large it gets */
        n->flush_gap_ms = took * 10000.0 < 50 ? 50 : took * 10000.0 > 5000 ? 5000 : (unsigned)(took * 10000.0);
        pthread_mutex_unlock(&n->mu);
    }
}

static void *monitor_main(void *arg)
{
    nrf *n = arg;
    while (!atomic_load(&n->stop)) {
        struct timespec ts = {0, 200000000L};
        monitor_pass(n);
        nanosleep(&ts, NULL);
    }
    return NULL;
}

/* ---- lifecycle ---- */

int nrf_start(nrf *n, char *err, size_t errcap)
{
    (void)nrf_restore(n);
    for (int i = 0; i < 2; i++)
        if (pthread_create(&n->workers[i], NULL, worker_main, n) != 0) {
            snprintf(err, errcap, "cannot start the notification threads");
            return -1;
        }
    if (pthread_create(&n->monitor, NULL, monitor_main, n) != 0) {
        snprintf(err, errcap, "cannot start the monitor thread");
        return -1;
    }
    n->started = true;
    return 0;
}

void nrf_destroy(nrf *n)
{
    if (n == NULL)
        return;
    if (n->started) {
        atomic_store(&n->stop, true);
        pthread_mutex_lock(&n->qmu);
        pthread_cond_broadcast(&n->qcv);
        pthread_mutex_unlock(&n->qmu);
        pthread_join(n->monitor, NULL);
        for (int i = 0; i < 2; i++)
            pthread_join(n->workers[i], NULL);
        nrf_flush(n);
    }
    for (nrf_job *j = n->qh, *nx; j != NULL; j = nx) {
        nx = j->next;
        free(j->url);
        free(j->body);
        free(j);
    }
    for (size_t i = 0; i < n->nprofs; i++)
        g5c_json_free(n->profs[i].doc);
    for (size_t i = 0; i < n->nsubs; i++)
        g5c_json_free(n->subs[i].doc);
    free(n->profs);
    free(n->subs);
    free(n->cfg.state_file);
    free(n->cfg.key_file);
    g5c_jwt_key_free(n->key);
    pthread_mutex_destroy(&n->mu);
    pthread_mutex_destroy(&n->qmu);
    pthread_cond_destroy(&n->qcv);
    free(n);
}

size_t nrf_profile_count(nrf *n)
{
    size_t c;
    pthread_mutex_lock(&n->mu);
    c = n->nprofs;
    pthread_mutex_unlock(&n->mu);
    return c;
}

size_t nrf_subscription_count(nrf *n)
{
    size_t c;
    pthread_mutex_lock(&n->mu);
    c = n->nsubs;
    pthread_mutex_unlock(&n->mu);
    return c;
}

bool nrf_profile_status(nrf *n, const char *id, char *out, size_t cap)
{
    bool found = false;
    pthread_mutex_lock(&n->mu);
    {
        long i = nrf_find(n, id);
        if (i >= 0) {
            const char *s = g5c_json_get_str(n->profs[i].doc, "nfStatus");
            snprintf(out, cap, "%s", s != NULL ? s : "");
            found = true;
        }
    }
    pthread_mutex_unlock(&n->mu);
    return found;
}

g5c_json *nrf_jwk(nrf *n)
{
    return n->key != NULL ? g5c_jwt_key_jwk(n->key, n->kid) : NULL;
}

void nrf_set_self_uri(nrf *n, const char *uri)
{
    pthread_mutex_lock(&n->mu);
    snprintf(n->self_uri, sizeof n->self_uri, "%s", uri);
    pthread_mutex_unlock(&n->mu);
}

void nrf_set_self_uri_default(nrf *n, const char *uri)
{
    pthread_mutex_lock(&n->mu);
    if (n->self_uri[0] == 0)
        snprintf(n->self_uri, sizeof n->self_uri, "%s", uri);
    pthread_mutex_unlock(&n->mu);
}
