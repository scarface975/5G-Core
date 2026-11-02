/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nnrf_NFManagement (TS 29.510 clause 5.2, resources of 6.1.3): register, update, heart-beat, deregister, retrieve, list, status subscriptions. */
#include <stdio.h>

#include "priv.h"

/* ---- helpers ---- */

static bool valid_status(const char *s)
{
    return s != NULL && (strcmp(s, "REGISTERED") == 0 || strcmp(s, "SUSPENDED") == 0 || strcmp(s, "UNDISCOVERABLE") == 0);
}

static void etag_header(g5c_resp *resp, uint64_t etag)
{
    char v[32];
    snprintf(v, sizeof v, "\"%llu\"", (unsigned long long)etag);
    g5c_resp_header(resp, "etag", v);
}

/* the entity tag of an If-Match header equals the profile's? (a list, W/ prefixes and quotes are tolerated) */
static bool etag_matches(const char *hdr, uint64_t etag)
{
    char want[32];
    snprintf(want, sizeof want, "\"%llu\"", (unsigned long long)etag);
    if (hdr == NULL || strcmp(hdr, "*") == 0)
        return true;
    return strstr(hdr, want) != NULL;
}

/* a profile that cannot be stored: the reason, or NULL. Fills defaults. */
static const char *validate_profile(g5c_json *doc, const char *id)
{
    const char *v;
    const g5c_json *a;
    if (!g5c_json_is(doc, G5C_J_OBJECT))
        return "the NFProfile must be a JSON object";
    v = g5c_json_get_str(doc, "nfInstanceId");
    if (v != NULL && strcmp(v, id) != 0)
        return "nfInstanceId differs from the resource URI";
    g5c_json_set_str(doc, "nfInstanceId", id);
    v = g5c_json_get_str(doc, "nfType");
    if (v == NULL || *v == 0 || strlen(v) > 64)
        return "nfType is mandatory";
    v = g5c_json_get_str(doc, "nfStatus");
    if (v == NULL)
        g5c_json_set_str(doc, "nfStatus", "REGISTERED");
    else if (!valid_status(v))
        return "nfStatus must be REGISTERED, SUSPENDED or UNDISCOVERABLE";
    /* what the registry fills in when the NF did not say (as other NRFs do): the selection attributes */
    if (g5c_json_get(doc, "priority") == NULL)
        g5c_json_set_int(doc, "priority", 0);
    if (g5c_json_get(doc, "capacity") == NULL)
        g5c_json_set_int(doc, "capacity", 100);
    if (g5c_json_get(doc, "load") == NULL)
        g5c_json_set_int(doc, "load", 0);
    if (g5c_json_get(doc, "heartBeatTimer") != NULL) {
        int64_t t;
        if (!g5c_json_get_int(doc, "heartBeatTimer", &t) || t < 1 || t > 86400)
            return "heartBeatTimer must be 1..86400";
    }
    for (const char *const *k = (const char *const[]){"ipv4Addresses", "ipv6Addresses", "plmnList", "sNssais", "nfServices", NULL}; *k != NULL; k++) {
        a = g5c_json_get(doc, *k);
        if (a != NULL && !g5c_json_is(a, G5C_J_ARRAY))
            return "a list attribute is not an array";
    }
    a = g5c_json_get(doc, "nfServices");
    for (size_t i = 0; i < g5c_json_len(a); i++) {
        const g5c_json *s = g5c_json_at(a, i);
        if (!g5c_json_is(s, G5C_J_OBJECT) || g5c_json_get_str(s, "serviceInstanceId") == NULL || g5c_json_get_str(s, "serviceName") == NULL)
            return "an NFService needs serviceInstanceId and serviceName";
    }
    a = g5c_json_get(doc, "nfServiceList");
    if (a != NULL && !g5c_json_is(a, G5C_J_OBJECT))
        return "nfServiceList must be an object";
    for (size_t i = 0; i < g5c_json_len(a); i++) {
        const g5c_json *s = g5c_json_val_at(a, i);
        if (!g5c_json_is(s, G5C_J_OBJECT) || g5c_json_get_str(s, "serviceName") == NULL)
            return "an NFService needs serviceName";
    }
    return NULL;
}

static void problem_invalid(g5c_resp *resp, const char *param, const char *reason)
{
    g5c_resp_problem_invalid(resp, 400, "INVALID_PARAM", param, reason);
}

/* ---- nf-instance ---- */

static void nf_put(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf *n = ctx;
    const char *id = g5c_req_param(req, "nfInstanceID");
    g5c_json *doc, *old = NULL, *out;
    const char *why;
    long idx;
    bool created;
    int64_t hb = 0;
    char *loc;
    if (id == NULL || !nrf_valid_uuid(id)) {
        problem_invalid(resp, "nfInstanceID", "must be a UUID");
        return;
    }
    doc = g5c_req_json(req, resp);
    if (doc == NULL)
        return;
    why = validate_profile(doc, id);
    if (why != NULL) {
        problem_invalid(resp, "NFProfile", why);
        g5c_json_free(doc);
        nrf_count(n, "g5c_nrf_requests_rejected_total", "NFManagement requests refused, by operation.", "operation", "register");
        return;
    }
    if (g5c_json_get(doc, "plmnList") == NULL && n->cfg.mcc[0] != 0) { /* not provided: the PLMN of the NRF is assumed (TS 29.510 6.1.6.2.2), written out */
        g5c_json *pl = g5c_json_set(doc, "plmnList", g5c_json_new_arr()), *e = g5c_json_push(pl, g5c_json_new_obj());
        g5c_json_set_str(e, "mcc", n->cfg.mcc);
        g5c_json_set_str(e, "mnc", n->cfg.mnc);
    }
    if (!g5c_json_get_int(doc, "heartBeatTimer", &hb) || hb < 1) /* the NRF decides the interval unless the NF asked for one */
        g5c_json_set_int(doc, "heartBeatTimer", n->cfg.hb_timer);
    pthread_mutex_lock(&n->mu);
    idx = nrf_find(n, id);
    created = idx < 0;
    if (created && n->nprofs >= n->cfg.max_profiles) {
        pthread_mutex_unlock(&n->mu);
        g5c_resp_problem_simple(resp, 503, "INSUFFICIENT_RESOURCES", "the NRF holds the maximum number of NF profiles");
        g5c_json_free(doc);
        return;
    }
    if (created) {
        if (n->nprofs == n->capprofs) {
            n->capprofs = n->capprofs != 0 ? n->capprofs * 2 : 32;
            n->profs = g5c_xrealloc(n->profs, n->capprofs * sizeof *n->profs);
        }
        idx = (long)n->nprofs++;
        memset(&n->profs[idx], 0, sizeof n->profs[idx]);
        snprintf(n->profs[idx].id, sizeof n->profs[idx].id, "%s", id);
    } else {
        old = n->profs[idx].doc;
    }
    n->profs[idx].doc = doc;
    n->profs[idx].last_hb = g5c_now_seconds();
    n->profs[idx].suspended_at = 0;
    n->profs[idx].etag = ++n->next_etag;
    if (strcmp(g5c_json_get_str(doc, "nfStatus"), "SUSPENDED") == 0)
        n->profs[idx].suspended_at = n->profs[idx].last_hb;
    if (created)
        nrf_notify(n, NRF_EV_REGISTERED, id, NULL, doc);
    else if (!g5c_json_equal(old, doc))
        nrf_notify(n, NRF_EV_PROFILE_CHANGED, id, old, doc);
    nrf_mark_dirty(n);
    out = g5c_json_dup(doc);
    {
        uint64_t et = n->profs[idx].etag;
        pthread_mutex_unlock(&n->mu);
        etag_header(resp, et);
    }
    g5c_json_free(old);
    nrf_count(n, "g5c_nrf_registrations_total", "NF registrations and replacements, by type.", "nf_type", g5c_json_get_str(out, "nfType"));
    loc = g5c_req_url(req, req->path);
    g5c_resp_json(resp, created ? 201 : 200, out);
    g5c_resp_header(resp, "location", loc);
    G5C_LOGI(NRF_LOG, "%s %s %s", created ? "registered" : "replaced", g5c_json_get_str(out, "nfType"), id);
    g5c_json_free(out);
    free(loc);
}

static bool path_in(const char *p, const char *const *set)
{
    for (; *set != NULL; set++)
        if (strcmp(p, *set) == 0)
            return true;
    return false;
}

static void nf_patch(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    static const char *const hb_paths[] = {"/nfStatus", "/load", "/loadTimeStamp", NULL};
    nrf *n = ctx;
    const char *id = g5c_req_param(req, "nfInstanceID");
    g5c_json *items, *copy, *out = NULL;
    char err[120];
    long idx;
    bool hb_only = true, load_only = false, changed, revived = false;
    int rc;
    if (id == NULL || !nrf_valid_uuid(id)) {
        problem_invalid(resp, "nfInstanceID", "must be a UUID");
        return;
    }
    items = g5c_req_json(req, resp);
    if (items == NULL)
        return;
    if (!g5c_json_is(items, G5C_J_ARRAY) || g5c_json_len(items) == 0) {
        problem_invalid(resp, "body", "a JSON Patch array is required");
        g5c_json_free(items);
        return;
    }
    for (size_t i = 0; i < g5c_json_len(items); i++) {
        const char *p = g5c_json_get_str(g5c_json_at(items, i), "path"), *op = g5c_json_get_str(g5c_json_at(items, i), "op");
        if (p == NULL || op == NULL) {
            problem_invalid(resp, "body", "every item needs op and path");
            g5c_json_free(items);
            return;
        }
        if (!path_in(p, hb_paths) || (strcmp(op, "replace") != 0 && strcmp(op, "add") != 0))
            hb_only = false;
    }
    pthread_mutex_lock(&n->mu);
    idx = nrf_find(n, id);
    if (idx < 0) {
        pthread_mutex_unlock(&n->mu);
        g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "the NF instance is not registered");
        g5c_json_free(items);
        return;
    }
    if (!etag_matches(g5c_req_header(req, "if-match"), n->profs[idx].etag)) {
        pthread_mutex_unlock(&n->mu);
        g5c_resp_problem_simple(resp, 412, "PRECONDITION_FAILED", "the entity tag does not match the profile");
        g5c_json_free(items);
        return;
    }
    copy = g5c_json_dup(n->profs[idx].doc);
    rc = g5c_json_patch(&copy, items, err, sizeof err);
    g5c_json_free(items);
    if (rc != G5C_PATCH_OK) {
        pthread_mutex_unlock(&n->mu);
        g5c_resp_problem_simple(resp, rc == G5C_PATCH_PATH ? 409 : 400, rc == G5C_PATCH_PATH ? "PATCH_NOT_APPLICABLE" : "INVALID_PARAM", err);
        g5c_json_free(copy);
        return;
    }
    {
        const char *why = NULL, *oldtype = g5c_json_get_str(n->profs[idx].doc, "nfType"), *newtype = g5c_json_get_str(copy, "nfType");
        if (!g5c_json_is(copy, G5C_J_OBJECT) || g5c_json_get_str(copy, "nfInstanceId") == NULL || strcmp(g5c_json_get_str(copy, "nfInstanceId"), id) != 0)
            why = "nfInstanceId cannot change";
        else if (newtype == NULL || oldtype == NULL || strcmp(oldtype, newtype) != 0)
            why = "nfType cannot change";
        else if (!valid_status(g5c_json_get_str(copy, "nfStatus")))
            why = "nfStatus must be REGISTERED, SUSPENDED or UNDISCOVERABLE";
        if (why == NULL) {
            const g5c_json *s = g5c_json_get(copy, "nfServices");
            for (size_t i = 0; s != NULL && i < g5c_json_len(s); i++)
                if (g5c_json_get_str(g5c_json_at(s, i), "serviceName") == NULL || g5c_json_get_str(g5c_json_at(s, i), "serviceInstanceId") == NULL)
                    why = "an NFService needs serviceInstanceId and serviceName";
        }
        if (why != NULL) {
            pthread_mutex_unlock(&n->mu);
            g5c_resp_problem_simple(resp, 400, "INVALID_PARAM", why);
            g5c_json_free(copy);
            return;
        }
    }
    {   /* an NF that comes back from SUSPENDED is sent its profile */
        const char *was = g5c_json_get_str(n->profs[idx].doc, "nfStatus"), *now_st = g5c_json_get_str(copy, "nfStatus");
        revived = was != NULL && now_st != NULL && strcmp(was, "SUSPENDED") == 0 && strcmp(now_st, "SUSPENDED") != 0;
    }
    n->profs[idx].last_hb = g5c_now_seconds(); /* any update is a sign of life */
    changed = !g5c_json_equal(copy, n->profs[idx].doc);
    if (changed) {
        g5c_json *old = n->profs[idx].doc;
        const char *st = g5c_json_get_str(copy, "nfStatus");
        n->profs[idx].doc = copy;
        n->profs[idx].etag = ++n->next_etag;
        n->profs[idx].suspended_at = strcmp(st, "SUSPENDED") == 0 ? n->profs[idx].last_hb : 0;
        {   /* a change that is only the load report is not a profile change worth a notification */
            g5c_json *a = g5c_json_dup(old), *b = g5c_json_dup(n->profs[idx].doc);
            (void)g5c_json_remove(a, "load");
            (void)g5c_json_remove(a, "loadTimeStamp");
            (void)g5c_json_remove(b, "load");
            (void)g5c_json_remove(b, "loadTimeStamp");
            load_only = g5c_json_equal(a, b);
            g5c_json_free(a);
            g5c_json_free(b);
        }
        if (!load_only)
            nrf_notify(n, NRF_EV_PROFILE_CHANGED, id, old, n->profs[idx].doc);
        nrf_mark_dirty(n);
        g5c_json_free(old);
        copy = NULL;
    } else {
        g5c_json_free(copy);
    }
    if (!hb_only || revived)
        out = g5c_json_dup(n->profs[idx].doc);
    {
        uint64_t et = n->profs[idx].etag;
        pthread_mutex_unlock(&n->mu);
        etag_header(resp, et);
    }
    nrf_count(n, "g5c_nrf_updates_total", "NFUpdate operations, by kind.", "kind", hb_only ? "heartbeat" : "patch");
    {
        char *loc = g5c_req_url(req, req->path);
        if (out != NULL) {
            g5c_resp_json(resp, 200, out);
            g5c_json_free(out);
        } else {
            g5c_resp_status(resp, 204);
            g5c_resp_header(resp, "content-location", loc);
        }
        free(loc);
    }
}

static void nf_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf *n = ctx;
    const char *id = g5c_req_param(req, "nfInstanceID");
    long idx;
    if (id == NULL || !nrf_valid_uuid(id)) {
        problem_invalid(resp, "nfInstanceID", "must be a UUID");
        return;
    }
    pthread_mutex_lock(&n->mu);
    idx = nrf_find(n, id);
    if (idx < 0) {
        pthread_mutex_unlock(&n->mu);
        g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "the NF instance is not registered");
        return;
    }
    nrf_notify(n, NRF_EV_DEREGISTERED, id, n->profs[idx].doc, NULL);
    g5c_json_free(n->profs[idx].doc);
    n->profs[idx] = n->profs[--n->nprofs];
    nrf_mark_dirty(n);
    pthread_mutex_unlock(&n->mu);
    nrf_count(n, "g5c_nrf_deregistrations_total", "NF deregistrations.", NULL, NULL);
    g5c_resp_status(resp, 204);
    G5C_LOGI(NRF_LOG, "deregistered %s", id);
}

static void nf_get(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf *n = ctx;
    const char *id = g5c_req_param(req, "nfInstanceID");
    long idx;
    g5c_json *out = NULL;
    uint64_t et = 0;
    if (id == NULL || !nrf_valid_uuid(id)) {
        problem_invalid(resp, "nfInstanceID", "must be a UUID");
        return;
    }
    pthread_mutex_lock(&n->mu);
    idx = nrf_find(n, id);
    if (idx >= 0) {
        out = g5c_json_dup(n->profs[idx].doc);
        et = n->profs[idx].etag;
    }
    pthread_mutex_unlock(&n->mu);
    if (out == NULL) {
        g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "the NF instance is not registered");
        return;
    }
    {
        char *sf = g5c_req_query_decoded(req, "supported-features");
        g5c_json *view = nrf_profile_view(out, nrf_features_service_map(sf));
        free(sf);
        g5c_json_free(out);
        out = view;
    }
    g5c_resp_json(resp, 200, out);
    etag_header(resp, et);
    g5c_json_free(out);
}

/* ---- nf-instances ---- */

static void nf_list(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf *n = ctx;
    char *type = g5c_req_query_decoded(req, "nf-type"), *lim = g5c_req_query_decoded(req, "limit");
    g5c_json *out = g5c_json_new_obj(), *items = g5c_json_new_arr();
    size_t limit = (size_t)-1, count = 0;
    if (lim != NULL) {
        char *end;
        unsigned long v = strtoul(lim, &end, 10);
        if (*lim == 0 || *end != 0 || v == 0) {
            problem_invalid(resp, "limit", "must be a positive integer");
            free(type);
            free(lim);
            g5c_json_free(out);
            g5c_json_free(items);
            return;
        }
        limit = v;
    }
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < n->nprofs && count < limit; i++) {
        const char *t = g5c_json_get_str(n->profs[i].doc, "nfType");
        if (type != NULL && (t == NULL || strcmp(t, type) != 0))
            continue;
        {
            char *p = g5c_xasprintf("/nnrf-nfm/v1/nf-instances/%s", n->profs[i].id), *u = g5c_req_url(req, p);
            g5c_json *l = g5c_json_push(items, g5c_json_new_obj());
            g5c_json_set_str(l, "href", u);
            free(p);
            free(u);
        }
        count++;
    }
    pthread_mutex_unlock(&n->mu);
    g5c_json_set(g5c_json_set(out, "_links", g5c_json_new_obj()), "item", items);
    g5c_resp_json(resp, 200, out);
    g5c_json_free(out);
    free(type);
    free(lim);
}

static void nf_options(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    g5c_resp_status(resp, 204);
    g5c_resp_header(resp, "allow", "GET, OPTIONS");
    g5c_resp_header(resp, "accept-encoding", "identity");
}

/* ---- subscriptions ---- */

static const char *check_subscription(const g5c_json *d)
{
    static const char *const known[] = {"nfInstanceId", "nfType", "serviceName", "amfSetId", "amfRegionId", "snssaiList", "nfGroupId", "guamiList",
                                         "taiList", "nsiList", NULL};
    const char *u = g5c_json_get_str(d, "nfStatusNotificationUri");
    const g5c_json *c = g5c_json_get(d, "subscrCond");
    if (!g5c_json_is(d, G5C_J_OBJECT))
        return "SubscriptionData must be a JSON object";
    if (u == NULL || (strncmp(u, "http://", 7) != 0 && strncmp(u, "https://", 8) != 0) || strlen(u) > 2000)
        return "nfStatusNotificationUri must be an http(s) URI";
    if (c != NULL) {
        if (!g5c_json_is(c, G5C_J_OBJECT))
            return "subscrCond must be an object";
        for (size_t i = 0; i < g5c_json_len(c); i++)
            if (!path_in(g5c_json_key_at(c, i), known))
                return "unsupported subscription condition";
        if (g5c_json_get(c, "guamiList") != NULL || g5c_json_get(c, "taiList") != NULL || g5c_json_get(c, "nsiList") != NULL)
            return "unsupported subscription condition";
    }
    {
        const g5c_json *ev = g5c_json_get(d, "reqNotifEvents");
        for (size_t i = 0; ev != NULL && i < g5c_json_len(ev); i++) {
            const char *e = g5c_json_str(g5c_json_at(ev, i));
            if (e == NULL || (strcmp(e, "NF_REGISTERED") != 0 && strcmp(e, "NF_DEREGISTERED") != 0 && strcmp(e, "NF_PROFILE_CHANGED") != 0))
                return "unknown notification event type";
        }
    }
    return NULL;
}

/* "2026-10-15T12:00:00Z" (a fraction and a numeric offset are tolerated) -> seconds since the epoch, or -1 */
static double parse_iso(const char *s)
{
    struct tm tm;
    const char *e;
    time_t t;
    memset(&tm, 0, sizeof tm);
    e = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm);
    if (e == NULL)
        return -1;
    t = timegm(&tm);
    if (*e == '.')
        for (e++; *e >= '0' && *e <= '9'; e++)
            ;
    if ((*e == '+' || *e == '-') && strlen(e) >= 6) {
        int hh = atoi(e + 1), mm = atoi(e + 4);
        long off = hh * 3600L + mm * 60L;
        t += (*e == '+') ? -off : off;
    }
    return (double)t;
}

static void sub_post(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf *n = ctx;
    g5c_json *d = g5c_req_json(req, resp), *out;
    const char *why;
    double life = n->cfg.sub_validity, wall = (double)time(NULL);
    char id[40], iso[24], *path, *loc;
    nrf_sub *s;
    if (d == NULL)
        return;
    why = check_subscription(d);
    if (why != NULL) {
        problem_invalid(resp, "SubscriptionData", why);
        g5c_json_free(d);
        return;
    }
    if (g5c_json_get_str(d, "validityTime") != NULL) {
        double want = parse_iso(g5c_json_get_str(d, "validityTime")) - wall;
        if (want > 0 && want < life)
            life = want;
    }
    pthread_mutex_lock(&n->mu);
    if (n->nsubs >= n->cfg.max_subscriptions) {
        pthread_mutex_unlock(&n->mu);
        g5c_resp_problem_simple(resp, 503, "INSUFFICIENT_RESOURCES", "the NRF holds the maximum number of subscriptions");
        g5c_json_free(d);
        return;
    }
    snprintf(id, sizeof id, "%llu", (unsigned long long)n->next_sub++);
    nrf_iso8601(wall + life, iso);
    g5c_json_set_str(d, "subscriptionId", id);
    g5c_json_set_str(d, "validityTime", iso);
    g5c_json_set_str(d, "nrfSupportedFeatures", "1"); /* Service-Map */
    if (n->nsubs == n->capsubs) {
        n->capsubs = n->capsubs != 0 ? n->capsubs * 2 : 32;
        n->subs = g5c_xrealloc(n->subs, n->capsubs * sizeof *n->subs);
    }
    s = &n->subs[n->nsubs++];
    memset(s, 0, sizeof *s);
    snprintf(s->id, sizeof s->id, "%s", id);
    s->doc = d;
    s->expires = g5c_now_seconds() + life;
    out = g5c_json_dup(d);
    nrf_mark_dirty(n);
    pthread_mutex_unlock(&n->mu);
    nrf_count(n, "g5c_nrf_subscriptions_created_total", "Status subscriptions created.", NULL, NULL);
    path = g5c_xasprintf("/nnrf-nfm/v1/subscriptions/%s", id);
    loc = g5c_req_url(req, path);
    g5c_resp_json(resp, 201, out);
    g5c_resp_header(resp, "location", loc);
    g5c_json_free(out);
    free(path);
    free(loc);
}

static long sub_find(const nrf *n, const char *id)
{
    for (size_t i = 0; i < n->nsubs; i++)
        if (strcmp(n->subs[i].id, id) == 0)
            return (long)i;
    return -1;
}

static void sub_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf *n = ctx;
    const char *id = g5c_req_param(req, "subscriptionID");
    long i;
    pthread_mutex_lock(&n->mu);
    i = id != NULL ? sub_find(n, id) : -1;
    if (i < 0) {
        pthread_mutex_unlock(&n->mu);
        g5c_resp_problem_simple(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such subscription");
        return;
    }
    g5c_json_free(n->subs[i].doc);
    n->subs[i] = n->subs[--n->nsubs];
    nrf_mark_dirty(n);
    pthread_mutex_unlock(&n->mu);
    g5c_resp_status(resp, 204);
}

static void sub_patch(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf *n = ctx;
    const char *id = g5c_req_param(req, "subscriptionID");
    g5c_json *items = g5c_req_json(req, resp), *out;
    double life = n->cfg.sub_validity, wall = (double)time(NULL);
    char iso[24];
    long i;
    if (items == NULL)
        return;
    if (!g5c_json_is(items, G5C_J_ARRAY)) {
        problem_invalid(resp, "body", "a JSON Patch array is required");
        g5c_json_free(items);
        return;
    }
    for (size_t k = 0; k < g5c_json_len(items); k++) {
        const g5c_json *it = g5c_json_at(items, k);
        const char *p = g5c_json_get_str(it, "path"), *v = g5c_json_get_str(it, "value");
        if (p == NULL || strcmp(p, "/validityTime") != 0 || g5c_json_get_str(it, "op") == NULL || v == NULL) {
            g5c_resp_problem_simple(resp, 400, "INVALID_PARAM", "only a replace of /validityTime is supported");
            g5c_json_free(items);
            return;
        }
        {
            double want = parse_iso(v) - wall;
            if (want <= 0) {
                g5c_resp_problem_simple(resp, 400, "INVALID_PARAM", "validityTime is not a future time");
                g5c_json_free(items);
                return;
            }
            if (want < life)
                life = want;
        }
    }
    g5c_json_free(items);
    pthread_mutex_lock(&n->mu);
    i = id != NULL ? sub_find(n, id) : -1;
    if (i < 0) {
        pthread_mutex_unlock(&n->mu);
        g5c_resp_problem_simple(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such subscription");
        return;
    }
    nrf_iso8601(wall + life, iso);
    g5c_json_set_str(n->subs[i].doc, "validityTime", iso);
    n->subs[i].expires = g5c_now_seconds() + life;
    out = g5c_json_dup(n->subs[i].doc);
    nrf_mark_dirty(n);
    pthread_mutex_unlock(&n->mu);
    g5c_resp_json(resp, 200, out);
    g5c_json_free(out);
}

void nrf_mgmt_routes(g5c_router *r, nrf *n)
{
    g5c_router_route(r, "PUT", "/nnrf-nfm/v1/nf-instances/{nfInstanceID}", nf_put, n);
    g5c_router_route(r, "PATCH", "/nnrf-nfm/v1/nf-instances/{nfInstanceID}", nf_patch, n);
    g5c_router_route(r, "DELETE", "/nnrf-nfm/v1/nf-instances/{nfInstanceID}", nf_delete, n);
    g5c_router_route(r, "GET", "/nnrf-nfm/v1/nf-instances/{nfInstanceID}", nf_get, n);
    g5c_router_route(r, "GET", "/nnrf-nfm/v1/nf-instances", nf_list, n);
    g5c_router_route(r, "OPTIONS", "/nnrf-nfm/v1/nf-instances", nf_options, n);
    g5c_router_route(r, "POST", "/nnrf-nfm/v1/subscriptions", sub_post, n);
    g5c_router_route(r, "DELETE", "/nnrf-nfm/v1/subscriptions/{subscriptionID}", sub_delete, n);
    g5c_router_route(r, "PATCH", "/nnrf-nfm/v1/subscriptions/{subscriptionID}", sub_patch, n);
}
