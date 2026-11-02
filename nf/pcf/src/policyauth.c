#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Npcf_PolicyAuthorization (TS 29.514): an AF (or the NEF for an AF) asks for a QoS for the traffic of a UE. The PCF binds the request to the SM policy
 * of the UE's PDU session by the UE's IPv4 address (4.2.2.2, with the DNN and the S-NSSAI when the AF gives them), turns the media components that name a
 * QoS reference (feature AuthorizationWithRequiredQoS, 4.2.2.32: the reference is pre-defined QoS information, here the `policy_authorization.qos_references`
 * of the configuration) into PCC rules, and has them installed at the SMF: the SM policy decision is computed again, with the rules of the application
 * sessions of the PDU session, and sent as an update notification. The outcome is notified to the AF as SUCCESSFUL_RESOURCES_ALLOCATION or
 * FAILED_RESOURCES_ALLOCATION when it subscribed (4.2.2.10, 4.2.5.8); the end of the PDU session ends the application session (4.2.5.3).
 *
 * Not supported: service information that names no QoS reference (the derivation of QoS from the media type and the bandwidths is TS 29.513, which is
 * not pinned), Ethernet and IPv6 sessions, usage monitoring, sponsored connectivity, traffic routing, access network information, QoS notification control. */
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "g5c/pcf.h"

#define BASE "/npcf-policyauthorization/v1/app-sessions"
#define MAX_COMPONENTS 32
#define FEAT_REQUIRED_QOS 0x10000u /* 17 AuthorizationWithRequiredQoS */
#define FEAT_PATCH 0x8000000u      /* 28 PatchCorrection */
#define FEAT_OURS (FEAT_REQUIRED_QOS | FEAT_PATCH)

struct pcf_app {
    char *id, *sm_id, *supi;
    char *res_uri;       /* the URI of this resource as the AF knows it */
    char *notif_uri;     /* ascReqData.notifUri: where termination goes */
    char *ev_notif_uri;  /* evSubsc.notifUri: where events go */
    bool ev_succ, ev_fail;
    unsigned feat;
    g5c_json *req;       /* ascReqData as stored */
    pcf_rule *rules;
    size_t nrules;
};

/* ---- configuration ------------------------------------------------------------------------------------------------------------ */

static void qref_free(pcf_qos_ref *q)
{
    free(q->name);
    free(q->gbr_ul);
    free(q->gbr_dl);
    free(q->mbr_ul);
    free(q->mbr_dl);
}

static bool bitrate_member(const g5c_json *o, const char *key, char **out, char *err, size_t errcap, const char *name)
{
    const char *v;
    if (g5c_json_get(o, key) == NULL)
        return true;
    v = g5c_json_get_str(o, key);
    if (v == NULL || !pcf_valid_bitrate(v)) {
        snprintf(err, errcap, "invalid config: `policy_authorization.qos_references.%s.%s` must be a bit rate such as \"2 Mbps\"", name, key);
        return false;
    }
    *out = g5c_xstrdup(v);
    return true;
}

int pcf_policyauth_config(pcf *p, const g5c_json *cfg, char *err, size_t errcap)
{
    static const char *const top[] = {"qos_references", "max_app_sessions", NULL}, *const k_q[] = {"qi5", "gbr_ul", "gbr_dl", "mbr_ul", "mbr_dl", NULL};
    const g5c_json *blk = g5c_json_get(cfg, "policy_authorization"), *refs;
    int64_t v;
    p->app_max = 10000;
    if (blk == NULL)
        return 0;
    if (!g5c_json_is(blk, G5C_J_OBJECT) || g5c_json_check_keys(blk, top, "policy_authorization", err, errcap) != 0) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: `policy_authorization` must be a mapping");
        return -1;
    }
    if (g5c_json_get(blk, "max_app_sessions") != NULL) {
        if (!g5c_json_get_int(blk, "max_app_sessions", &v) || v < 1 || v > 10000000) {
            snprintf(err, errcap, "invalid config: `policy_authorization.max_app_sessions` must be an integer from 1 to 10000000");
            return -1;
        }
        p->app_max = (size_t)v;
    }
    refs = g5c_json_get(blk, "qos_references");
    if (refs != NULL && !g5c_json_is(refs, G5C_J_OBJECT)) {
        snprintf(err, errcap, "invalid config: `policy_authorization.qos_references` must be a mapping of names to QoS");
        return -1;
    }
    for (size_t i = 0; i < g5c_json_len(refs); i++) {
        const char *name = g5c_json_key_at(refs, i);
        const g5c_json *q = g5c_json_val_at(refs, i);
        pcf_qos_ref *r;
        char where[96];
        snprintf(where, sizeof where, "policy_authorization.qos_references.%s", name);
        if (strlen(name) == 0 || strlen(name) > 64 || !g5c_json_is(q, G5C_J_OBJECT) || g5c_json_check_keys(q, k_q, where, err, errcap) != 0) {
            if (err[0] == '\0')
                snprintf(err, errcap, "invalid config: `%s` must be a mapping with a 5QI (and the bit rates of a GBR flow)", where);
            return -1;
        }
        if (!g5c_json_get_int(q, "qi5", &v) || v < 1 || v > 255) {
            snprintf(err, errcap, "invalid config: `%s.qi5` must be an integer from 1 to 255", where);
            return -1;
        }
        p->qos_refs = g5c_xrealloc(p->qos_refs, (p->nqos_refs + 1) * sizeof *p->qos_refs);
        r = &p->qos_refs[p->nqos_refs];
        memset(r, 0, sizeof *r);
        r->name = g5c_xstrdup(name);
        r->qi5 = (uint8_t)v;
        p->nqos_refs++;
        if (!bitrate_member(q, "gbr_ul", &r->gbr_ul, err, errcap, name) || !bitrate_member(q, "gbr_dl", &r->gbr_dl, err, errcap, name) ||
            !bitrate_member(q, "mbr_ul", &r->mbr_ul, err, errcap, name) || !bitrate_member(q, "mbr_dl", &r->mbr_dl, err, errcap, name))
            return -1;
        if (pcf_is_gbr_5qi(r->qi5) && (r->gbr_ul == NULL || r->gbr_dl == NULL)) {
            snprintf(err, errcap, "invalid config: `%s` is a GBR 5QI and needs gbr_ul and gbr_dl", where);
            return -1;
        }
    }
    return 0;
}

static void policyauth_free(pcf *p)
{
    for (size_t i = 0; i < p->nqos_refs; i++)
        qref_free(&p->qos_refs[i]);
    free(p->qos_refs);
    p->qos_refs = NULL;
    p->nqos_refs = 0;
}

/* ---- helpers --------------------------------------------------------------------------------------------------------------- */

static void problem(g5c_resp *resp, int status, const char *cause, const char *detail)
{
    g5c_resp_problem_simple(resp, status, cause, detail);
}

static void count_app(pcf *p, const char *op)
{
    g5c_label l[] = {{"op", op}};
    if (p->metrics != NULL)
        g5c_counter_inc(g5c_counter_get(p->metrics, "g5c_pcf_app_sessions_total", "Npcf_PolicyAuthorization operations on application sessions.", l, 1));
}

static unsigned feat_negotiate(const char *hex)
{
    unsigned v = 0;
    for (size_t i = 0; hex != NULL && hex[i] != 0 && i < 8; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return 0;
        v = v * 16 + (unsigned)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    }
    return v & FEAT_OURS;
}

static void app_free(pcf_app *a)
{
    if (a == NULL)
        return;
    free(a->id);
    free(a->sm_id);
    free(a->supi);
    free(a->res_uri);
    free(a->notif_uri);
    free(a->ev_notif_uri);
    g5c_json_free(a->req);
    for (size_t i = 0; i < a->nrules; i++)
        pcf_rule_release(&a->rules[i]);
    free(a->rules);
    free(a);
}

void pcf_apps_free(pcf *p)
{
    for (size_t i = 0; i < p->napps; i++)
        app_free(p->apps[i]);
    free(p->apps);
    p->apps = NULL;
    p->napps = 0;
    policyauth_free(p);
}

static pcf_app *app_find(pcf *p, const char *id)
{
    for (size_t i = 0; id != NULL && i < p->napps; i++)
        if (strcmp(p->apps[i]->id, id) == 0)
            return p->apps[i];
    return NULL;
}

static void app_detach(pcf *p, pcf_app *a)
{
    for (size_t i = 0; i < p->napps; i++)
        if (p->apps[i] == a) {
            p->apps[i] = p->apps[--p->napps];
            return;
        }
}

static void merge_patch(g5c_json **doc, const g5c_json *patch)
{
    if (!g5c_json_is(patch, G5C_J_OBJECT)) {
        g5c_json_free(*doc);
        *doc = g5c_json_dup(patch);
        return;
    }
    if (!g5c_json_is(*doc, G5C_J_OBJECT)) {
        g5c_json_free(*doc);
        *doc = g5c_json_new_obj();
    }
    for (size_t i = 0; i < g5c_json_len(patch); i++) {
        const char *k = g5c_json_key_at(patch, i);
        const g5c_json *pv = g5c_json_val_at(patch, i);
        if (g5c_json_is(pv, G5C_J_NULL)) {
            g5c_json_remove(*doc, k);
        } else if (g5c_json_is(pv, G5C_J_OBJECT)) {
            g5c_json *cur = g5c_json_detach(*doc, k);
            merge_patch(&cur, pv);
            g5c_json_set(*doc, k, cur);
        } else {
            g5c_json_set(*doc, k, g5c_json_dup(pv));
        }
    }
}

/* ---- notifications to the AF ---------------------------------------------------------------------------------------------------- */

typedef struct {
    pcf *p;
    char *url, *body;
} note_t;

static void *note_main(void *arg)
{
    note_t *n = arg;
    g5c_resp r;
    char err[160];
    g5c_kv hdr = {"accept", "application/json"};
    if (g5c_client_request(n->p->client, "POST", n->url, &hdr, 1, "application/json", n->body, strlen(n->body), &r, err, sizeof err) == 0) {
        if (r.status < 200 || r.status > 299)
            G5C_LOGW("g5c_pcf", "AF at %s answered %d to a policy authorization notification", n->url, r.status);
        g5c_resp_free(&r);
    } else {
        G5C_LOGW("g5c_pcf", "AF unreachable at %s: %s", n->url, err);
    }
    free(n->url);
    free(n->body);
    atomic_fetch_sub(&n->p->notes_inflight, 1);
    free(n);
    return NULL;
}

/* from a thread of its own: the AF has the answer of the request that caused the notification before the notification (and the request is not held up) */
static void notify_async(pcf *p, const char *base, const char *tail, const g5c_json *body)
{
    note_t *n;
    pthread_t t;
    pthread_attr_t at;
    size_t l;
    if (base == NULL)
        return;
    n = g5c_xcalloc(1, sizeof *n);
    n->p = p;
    l = strlen(base);
    while (l > 0 && base[l - 1] == '/')
        l--;
    n->url = g5c_xasprintf("%.*s/%s", (int)l, base, tail);
    n->body = g5c_json_to_string(body, NULL);
    atomic_fetch_add(&p->notes_inflight, 1);
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &at, note_main, n) != 0) {
        atomic_fetch_sub(&p->notes_inflight, 1);
        free(n->url);
        free(n->body);
        free(n);
    }
    pthread_attr_destroy(&at);
}

/* ---- PCC rules from the service information --------------------------------------------------------------------------------- */

static const pcf_qos_ref *qref_find(const pcf *p, const char *name)
{
    for (size_t i = 0; name != NULL && i < p->nqos_refs; i++)
        if (strcmp(p->qos_refs[i].name, name) == 0)
            return &p->qos_refs[i];
    return NULL;
}

static bool disabled(const char *fs)
{
    return fs != NULL && (strcmp(fs, "DISABLED") == 0 || strcmp(fs, "REMOVED") == 0);
}

/* The rules of the media components of `req` (ascReqData). 0 on success; else the reason for a 403 REQUESTED_SERVICE_NOT_AUTHORIZED or a 400 in `reason`. */
static int build_rules(const pcf *p, const char *app_id, const g5c_json *req, pcf_rule **out, size_t *nout, int *status, char *reason, size_t rcap)
{
    const g5c_json *mc = g5c_json_get(req, "medComponents");
    pcf_rule *rules = NULL;
    size_t n = 0;
    *out = NULL;
    *nout = 0;
    *status = 0;
    if (mc == NULL)
        return 0;
    if (!g5c_json_is(mc, G5C_J_OBJECT) || g5c_json_len(mc) > MAX_COMPONENTS) {
        *status = 400;
        snprintf(reason, rcap, "medComponents must be a map of at most %d media components", MAX_COMPONENTS);
        return -1;
    }
    for (size_t i = 0; i < g5c_json_len(mc); i++) {
        const g5c_json *c = g5c_json_val_at(mc, i), *subs;
        const char *key = g5c_json_key_at(mc, i), *qr = g5c_json_get_str(c, "qosReference");
        const pcf_qos_ref *q;
        int64_t num;
        pcf_rule r;
        char **flows = NULL;
        size_t nf = 0;
        if (!g5c_json_is(c, G5C_J_OBJECT) || !g5c_json_get_int(c, "medCompN", &num) || num < 0 || num > 65535 || !g5c_is_digits(key) || atoll(key) != num) {
            *status = 400;
            snprintf(reason, rcap, "medComponents.%s: medCompN is required and is the key of the map", key);
            goto fail;
        }
        if (disabled(g5c_json_get_str(c, "fStatus")))
            continue; /* the gate of the flows is closed: no rule */
        q = qref_find(p, qr);
        if (q == NULL) {
            *status = 403;
            snprintf(reason, rcap, qr == NULL ? "medComponents.%s names no qosReference: only service information with required QoS is supported" : "medComponents.%s: the QoS reference is not known",
                     key);
            goto fail;
        }
        subs = g5c_json_get(c, "medSubComps");
        for (size_t k = 0; g5c_json_is(subs, G5C_J_OBJECT) && k < g5c_json_len(subs); k++) {
            const g5c_json *sc = g5c_json_val_at(subs, k), *fd = g5c_json_get(sc, "fDescs");
            if (g5c_json_get(sc, "ethfDescs") != NULL) {
                *status = 403;
                snprintf(reason, rcap, "medComponents.%s: Ethernet flows are not supported", key);
                goto fail;
            }
            if (disabled(g5c_json_get_str(sc, "fStatus")))
                continue;
            for (size_t m = 0; g5c_json_is(fd, G5C_J_ARRAY) && m < g5c_json_len(fd); m++) {
                const char *f = g5c_json_str(g5c_json_at(fd, m));
                if (f == NULL || strncmp(f, "permit ", 7) != 0 || strlen(f) > 255) {
                    *status = 400;
                    snprintf(reason, rcap, "medComponents.%s: a flow description must be an IPFilterRule starting \"permit \"", key);
                    goto fail;
                }
                flows = g5c_xrealloc(flows, (nf + 1) * sizeof *flows);
                flows[nf++] = g5c_xstrdup(f);
            }
        }
        if (nf == 0) {
            *status = 400;
            snprintf(reason, rcap, "medComponents.%s: no flow description (medSubComps with fDescs)", key);
            goto fail;
        }
        memset(&r, 0, sizeof r);
        r.id = g5c_xasprintf("af-%s-%s", app_id, key);
        r.flows = flows;
        r.nflows = nf;
        r.qi5 = q->qi5;
        r.gbr_ul = q->gbr_ul ? g5c_xstrdup(q->gbr_ul) : NULL;
        r.gbr_dl = q->gbr_dl ? g5c_xstrdup(q->gbr_dl) : NULL;
        r.mbr_ul = q->mbr_ul ? g5c_xstrdup(q->mbr_ul) : NULL;
        r.mbr_dl = q->mbr_dl ? g5c_xstrdup(q->mbr_dl) : NULL;
        r.precedence = 100 + (uint32_t)(num % 100);
        rules = g5c_xrealloc(rules, (n + 1) * sizeof *rules);
        rules[n++] = r;
        continue;
    fail:
        for (size_t k = 0; k < nf; k++)
            free(flows[k]);
        free(flows);
        goto bad;
    }
    *out = rules;
    *nout = n;
    return 0;
bad:
    for (size_t i = 0; i < n; i++)
        pcf_rule_release(&rules[i]);
    free(rules);
    return -1;
}

/* the rules of the application sessions of an SM policy, for the decision (called without p->mu) */
void pcf_app_rules(pcf *p, const char *sm_id, pcf_rule **out, size_t *n)
{
    *out = NULL;
    *n = 0;
    if (sm_id == NULL)
        return;
    pthread_mutex_lock(&p->mu);
    for (size_t i = 0; i < p->napps; i++) {
        const pcf_app *a = p->apps[i];
        if (strcmp(a->sm_id, sm_id) != 0)
            continue;
        for (size_t k = 0; k < a->nrules; k++) {
            *out = g5c_xrealloc(*out, (*n + 1) * sizeof **out);
            (*out)[(*n)++] = pcf_rule_copy(&a->rules[k]);
        }
    }
    pthread_mutex_unlock(&p->mu);
}

/* ---- binding ----------------------------------------------------------------------------------------------------------------- */

static bool snssai_equal(const g5c_json *a, const g5c_json *b)
{
    int64_t sa = -1, sb = -1;
    const char *da = g5c_json_get_str(a, "sd"), *db = g5c_json_get_str(b, "sd");
    (void)g5c_json_get_int(a, "sst", &sa);
    (void)g5c_json_get_int(b, "sst", &sb);
    if (da != NULL && strcasecmp(da, "ffffff") == 0)
        da = NULL;
    if (db != NULL && strcasecmp(db, "ffffff") == 0)
        db = NULL;
    return sa == sb && ((da == NULL && db == NULL) || (da != NULL && db != NULL && strcasecmp(da, db) == 0));
}

/* the SM policy of the PDU session that has the UE address (and the DNN and slice, when given); p->mu held; copies of the ids */
static bool bind_session(pcf *p, const g5c_json *req, char **sm_id, char **supi)
{
    const char *ip = g5c_json_get_str(req, "ueIpv4"), *dnn = g5c_json_get_str(req, "dnn"), *ds = g5c_json_get_str(req, "supi");
    const g5c_json *slice = g5c_json_get(req, "sliceInfo");
    if (ip == NULL)
        return false;
    for (size_t i = 0; i < p->nsessions; i++) {
        const pcf_sm_session *s = &p->sessions[i];
        const char *a = g5c_json_get_str(s->context, "ipv4Address");
        if (a == NULL || strcmp(a, ip) != 0)
            continue;
        if (dnn != NULL && (s->dnn == NULL || strcmp(s->dnn, dnn) != 0))
            continue;
        if (ds != NULL && strcmp(s->supi, ds) != 0)
            continue;
        if (slice != NULL && !snssai_equal(slice, g5c_json_get(s->context, "sliceInfo")))
            continue;
        *sm_id = g5c_xstrdup(s->id);
        *supi = g5c_xstrdup(s->supi);
        return true;
    }
    return false;
}

/* ---- the push and its outcome ---------------------------------------------------------------------------------------------- */

static g5c_json *flows_json(const g5c_json *req)
{
    g5c_json *fl = g5c_json_new_arr();
    const g5c_json *mc = g5c_json_get(req, "medComponents");
    for (size_t i = 0; g5c_json_is(mc, G5C_J_OBJECT) && i < g5c_json_len(mc); i++) {
        const g5c_json *c = g5c_json_val_at(mc, i);
        int64_t n;
        g5c_json *f = g5c_json_push(fl, g5c_json_new_obj());
        if (g5c_json_get_int(c, "medCompN", &n))
            g5c_json_set_int(f, "medCompN", n);
    }
    return fl;
}

static void notify_outcome(pcf *p, const pcf_app *a, bool ok)
{
    g5c_json *n, *list, *e;
    if (a->ev_notif_uri == NULL || (ok ? !a->ev_succ : !a->ev_fail))
        return;
    n = g5c_json_new_obj();
    g5c_json_set_str(n, "evSubsUri", a->res_uri);
    list = g5c_json_set(n, "evNotifs", g5c_json_new_arr());
    e = g5c_json_push(list, g5c_json_new_obj());
    g5c_json_set_str(e, "event", ok ? "SUCCESSFUL_RESOURCES_ALLOCATION" : "FAILED_RESOURCES_ALLOCATION");
    g5c_json_set(e, "flows", flows_json(a->req));
    if (!ok) {
        g5c_json *r = g5c_json_push(g5c_json_set(n, "failedResourcAllocReports", g5c_json_new_arr()), g5c_json_new_obj());
        g5c_json_set_str(r, "mcResourcStatus", "INACTIVE");
        g5c_json_set(r, "flows", flows_json(a->req));
    } else {
        g5c_json *r = g5c_json_push(g5c_json_set(n, "succResourcAllocReports", g5c_json_new_arr()), g5c_json_new_obj());
        g5c_json_set(r, "flows", flows_json(a->req));
    }
    notify_async(p, a->ev_notif_uri, "notify", n);
    g5c_json_free(n);
}

/* ---- the AppSessionContext --------------------------------------------------------------------------------------------------- */

static g5c_json *context_of(const pcf_app *a, bool with_events)
{
    g5c_json *c = g5c_json_new_obj(), *req = g5c_json_dup(a->req), *resp = g5c_json_set(c, "ascRespData", g5c_json_new_obj());
    char *f = g5c_xasprintf("%x", a->feat);
    g5c_json_set(c, "ascReqData", req);
    g5c_json_set_str(req, "suppFeat", f);
    g5c_json_set_str(resp, "suppFeat", f);
    free(f);
    (void)with_events;
    return c;
}

static unsigned events_of(const g5c_json *ev, bool *succ, bool *fail)
{
    unsigned n = 0;
    const g5c_json *l = g5c_json_get(ev, "events");
    *succ = *fail = false;
    for (size_t i = 0; g5c_json_is(l, G5C_J_ARRAY) && i < g5c_json_len(l); i++) {
        const char *e = g5c_json_get_str(g5c_json_at(l, i), "event");
        if (e != NULL && strcmp(e, "SUCCESSFUL_RESOURCES_ALLOCATION") == 0)
            *succ = true, n++;
        else if (e != NULL && strcmp(e, "FAILED_RESOURCES_ALLOCATION") == 0)
            *fail = true, n++;
    }
    return n;
}

static bool uri_ok(const char *u)
{
    return u != NULL && (strncmp(u, "http://", 7) == 0 || strncmp(u, "https://", 8) == 0) && strlen(u) < 512 && strchr(u, ' ') == NULL;
}

static void create(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    g5c_json *in = g5c_req_json(req, resp), *body;
    const g5c_json *asc, *ev;
    pcf_app *a = NULL;
    pcf_rule *rules = NULL;
    size_t nrules = 0, accepted = 0, rejected = 0;
    char id[37], reason[240], *sm_id = NULL, *supi = NULL, *path, *loc;
    int st;
    if (in == NULL)
        return;
    asc = g5c_json_get(in, "ascReqData");
    if (!g5c_json_is(asc, G5C_J_OBJECT) || g5c_json_get_str(asc, "suppFeat") == NULL || !uri_ok(g5c_json_get_str(asc, "notifUri"))) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", "ascReqData", "ascReqData with suppFeat and notifUri is required");
        goto out;
    }
    if (g5c_json_get_str(asc, "ueIpv4") == NULL) {
        if (g5c_json_get(asc, "ueIpv6") != NULL || g5c_json_get(asc, "ueMac") != NULL)
            problem(resp, 500, "PDU_SESSION_NOT_AVAILABLE", "only sessions with an IPv4 address of the UE can be bound");
        else
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", "ascReqData/ueIpv4", "the UE address is required");
        goto out;
    }
    ev = g5c_json_get(asc, "evSubsc");
    if (ev != NULL && (!g5c_json_is(ev, G5C_J_OBJECT) || !uri_ok(g5c_json_get_str(ev, "notifUri")) || !g5c_json_is(g5c_json_get(ev, "events"), G5C_J_ARRAY))) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "ascReqData/evSubsc", "events and notifUri are required");
        goto out;
    }
    g5c_uuid_v4(id);
    if (build_rules(p, id, asc, &rules, &nrules, &st, reason, sizeof reason) != 0) {
        if (st == 403)
            problem(resp, 403, "REQUESTED_SERVICE_NOT_AUTHORIZED", reason);
        else
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "ascReqData/medComponents", reason);
        goto out;
    }
    pthread_mutex_lock(&p->mu);
    if (p->napps >= p->app_max) {
        pthread_mutex_unlock(&p->mu);
        problem(resp, 429, "TOO_MANY_REQUESTS", "the PCF holds the most application sessions it may hold");
        goto out;
    }
    if (!bind_session(p, asc, &sm_id, &supi)) {
        pthread_mutex_unlock(&p->mu);
        problem(resp, 500, "PDU_SESSION_NOT_AVAILABLE", "no PDU session has that UE address");
        goto out;
    }
    a = g5c_xcalloc(1, sizeof *a);
    a->id = g5c_xstrdup(id);
    a->sm_id = sm_id;
    a->supi = supi;
    sm_id = supi = NULL;
    a->feat = feat_negotiate(g5c_json_get_str(asc, "suppFeat"));
    a->req = g5c_json_dup(asc);
    a->notif_uri = g5c_xstrdup(g5c_json_get_str(asc, "notifUri"));
    a->rules = rules;
    a->nrules = nrules;
    rules = NULL;
    if (g5c_json_get(asc, "evSubsc") != NULL) {
        (void)events_of(g5c_json_get(asc, "evSubsc"), &a->ev_succ, &a->ev_fail);
        a->ev_notif_uri = g5c_xstrdup(g5c_json_get_str(g5c_json_get(asc, "evSubsc"), "notifUri"));
    }
    path = g5c_xasprintf(BASE "/%s", id);
    a->res_uri = g5c_req_url(req, path);
    p->apps = g5c_xrealloc(p->apps, (p->napps + 1) * sizeof *p->apps);
    p->apps[p->napps++] = a;
    pthread_mutex_unlock(&p->mu);
    /* the rules reach the SMF; the answer to the AF does not wait for more than that */
    accepted = pcf_repush_stats(p, a->supi, &rejected);
    body = context_of(a, false);
    g5c_resp_json(resp, 201, body);
    loc = g5c_req_url(req, path);
    g5c_resp_header(resp, "location", loc);
    g5c_json_free(body);
    free(loc);
    free(path);
    if (nrules > 0 && (a->ev_succ || a->ev_fail))
        notify_outcome(p, a, rejected == 0 || accepted > 0);
    count_app(p, "created");
out:
    for (size_t i = 0; i < nrules && rules != NULL; i++)
        pcf_rule_release(&rules[i]);
    free(rules);
    free(sm_id);
    free(supi);
    g5c_json_free(in);
}

static void get(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    pcf_app *a;
    g5c_json *c = NULL;
    pthread_mutex_lock(&p->mu);
    a = app_find(p, g5c_req_param(req, "appSessionId"));
    if (a != NULL)
        c = context_of(a, true);
    pthread_mutex_unlock(&p->mu);
    if (c == NULL) {
        problem(resp, 404, "CONTEXT_NOT_FOUND", "no such application session context");
        return;
    }
    g5c_resp_json(resp, 200, c);
    g5c_json_free(c);
}

static void patch(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    g5c_json *in = g5c_req_json(req, resp), *merged = NULL, *body;
    const char *id = g5c_req_param(req, "appSessionId");
    const g5c_json *upd, *ev;
    pcf_app *a;
    pcf_rule *rules = NULL;
    size_t nrules = 0, accepted = 0, rejected = 0;
    char reason[240], app_id[40] = "", *supi = NULL;
    int st;
    bool succ = false, fail = false;
    if (in == NULL)
        return;
    upd = g5c_json_get(in, "ascReqData");
    if (!g5c_json_is(upd, G5C_J_OBJECT)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", "ascReqData", "an ascReqData to apply is required");
        goto out;
    }
    pthread_mutex_lock(&p->mu);
    a = app_find(p, id);
    if (a != NULL) {
        merged = g5c_json_dup(a->req);
        snprintf(app_id, sizeof app_id, "%s", a->id);
    }
    pthread_mutex_unlock(&p->mu);
    if (merged == NULL) {
        problem(resp, 404, "CONTEXT_NOT_FOUND", "no such application session context");
        goto out;
    }
    merge_patch(&merged, upd);
    ev = g5c_json_get(merged, "evSubsc");
    if (ev != NULL && (!g5c_json_is(ev, G5C_J_OBJECT) || !uri_ok(g5c_json_get_str(ev, "notifUri")) || !g5c_json_is(g5c_json_get(ev, "events"), G5C_J_ARRAY))) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "ascReqData/evSubsc", "events and notifUri are required");
        goto out;
    }
    if (g5c_json_get_str(merged, "ueIpv4") == NULL || g5c_json_get_str(merged, "notifUri") == NULL) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "ascReqData", "the UE address and the notification URI cannot be removed");
        goto out;
    }
    if (build_rules(p, app_id, merged, &rules, &nrules, &st, reason, sizeof reason) != 0) {
        if (st == 403)
            problem(resp, 403, "REQUESTED_SERVICE_NOT_AUTHORIZED", reason);
        else
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "ascReqData/medComponents", reason);
        goto out;
    }
    pthread_mutex_lock(&p->mu);
    a = app_find(p, id);
    if (a == NULL) {
        pthread_mutex_unlock(&p->mu);
        problem(resp, 404, "CONTEXT_NOT_FOUND", "the application session context ended meanwhile");
        goto out;
    }
    for (size_t i = 0; i < a->nrules; i++)
        pcf_rule_release(&a->rules[i]);
    free(a->rules);
    a->rules = rules;
    a->nrules = nrules;
    rules = NULL;
    g5c_json_free(a->req);
    a->req = merged;
    merged = NULL;
    free(a->ev_notif_uri);
    a->ev_notif_uri = NULL;
    ev = g5c_json_get(a->req, "evSubsc");
    if (ev != NULL) {
        (void)events_of(ev, &succ, &fail);
        a->ev_notif_uri = g5c_xstrdup(g5c_json_get_str(ev, "notifUri"));
    }
    a->ev_succ = succ;
    a->ev_fail = fail;
    supi = g5c_xstrdup(a->supi);
    pthread_mutex_unlock(&p->mu);
    accepted = pcf_repush_stats(p, supi, &rejected);
    pthread_mutex_lock(&p->mu);
    a = app_find(p, id);
    body = a != NULL ? context_of(a, true) : NULL;
    if (a != NULL && a->nrules > 0)
        notify_outcome(p, a, rejected == 0 || accepted > 0);
    pthread_mutex_unlock(&p->mu);
    if (body == NULL) {
        problem(resp, 404, "CONTEXT_NOT_FOUND", "the application session context ended meanwhile");
    } else {
        g5c_resp_json(resp, 200, body);
        g5c_json_free(body);
    }
    count_app(p, "modified");
out:
    for (size_t i = 0; i < nrules && rules != NULL; i++)
        pcf_rule_release(&rules[i]);
    free(rules);
    free(supi);
    g5c_json_free(merged);
    g5c_json_free(in);
}

static void del(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    pcf_app *a;
    char *supi = NULL;
    pthread_mutex_lock(&p->mu);
    a = app_find(p, g5c_req_param(req, "appSessionId"));
    if (a != NULL) {
        supi = g5c_xstrdup(a->supi);
        app_detach(p, a);
        app_free(a);
    }
    pthread_mutex_unlock(&p->mu);
    if (supi == NULL) {
        problem(resp, 404, "CONTEXT_NOT_FOUND", "no such application session context");
        return;
    }
    (void)pcf_repush(p, supi); /* the rules go from the SMF */
    free(supi);
    count_app(p, "deleted");
    g5c_resp_status(resp, 204);
}

static void ev_put(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    g5c_json *in = g5c_req_json(req, resp), *copy;
    pcf_app *a;
    bool succ, fail, created;
    if (in == NULL)
        return;
    if (!g5c_json_is(g5c_json_get(in, "events"), G5C_J_ARRAY) || !uri_ok(g5c_json_get_str(in, "notifUri"))) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "events", "events and notifUri are required");
        g5c_json_free(in);
        return;
    }
    (void)events_of(in, &succ, &fail);
    pthread_mutex_lock(&p->mu);
    a = app_find(p, g5c_req_param(req, "appSessionId"));
    if (a == NULL) {
        pthread_mutex_unlock(&p->mu);
        problem(resp, 404, "CONTEXT_NOT_FOUND", "no such application session context");
        g5c_json_free(in);
        return;
    }
    created = g5c_json_get(a->req, "evSubsc") == NULL;
    copy = g5c_json_dup(in);
    g5c_json_set(a->req, "evSubsc", copy);
    free(a->ev_notif_uri);
    a->ev_notif_uri = g5c_xstrdup(g5c_json_get_str(in, "notifUri"));
    a->ev_succ = succ;
    a->ev_fail = fail;
    pthread_mutex_unlock(&p->mu);
    g5c_resp_json(resp, created ? 201 : 200, in);
    g5c_json_free(in);
}

static void ev_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    pcf_app *a;
    bool had = false;
    pthread_mutex_lock(&p->mu);
    a = app_find(p, g5c_req_param(req, "appSessionId"));
    if (a != NULL) {
        had = g5c_json_get(a->req, "evSubsc") != NULL;
        g5c_json_remove(a->req, "evSubsc");
        free(a->ev_notif_uri);
        a->ev_notif_uri = NULL;
        a->ev_succ = a->ev_fail = false;
    }
    pthread_mutex_unlock(&p->mu);
    if (a == NULL || !had)
        problem(resp, 404, "CONTEXT_NOT_FOUND", "no such events subscription");
    else
        g5c_resp_status(resp, 204);
}

/* the PDU session ended: its application sessions end, and the AFs are told (4.2.5.3) */
void pcf_apps_of_sm_gone(pcf *p, const char *sm_id)
{
    pcf_app **gone = NULL;
    size_t n = 0;
    pthread_mutex_lock(&p->mu);
    for (size_t i = 0; i < p->napps;) {
        pcf_app *a = p->apps[i];
        if (strcmp(a->sm_id, sm_id) == 0) {
            gone = g5c_xrealloc(gone, (n + 1) * sizeof *gone);
            gone[n++] = a;
            p->apps[i] = p->apps[--p->napps];
        } else {
            i++;
        }
    }
    pthread_mutex_unlock(&p->mu);
    for (size_t i = 0; i < n; i++) {
        g5c_json *t = g5c_json_new_obj();
        g5c_json_set_str(t, "termCause", "PDU_SESSION_TERMINATION");
        g5c_json_set_str(t, "resUri", gone[i]->res_uri);
        notify_async(p, gone[i]->notif_uri, "terminate", t);
        g5c_json_free(t);
        app_free(gone[i]);
    }
    free(gone);
}

size_t pcf_app_session_count(pcf *p)
{
    size_t n;
    pthread_mutex_lock(&p->mu);
    n = p->napps;
    pthread_mutex_unlock(&p->mu);
    return n;
}

void pcf_policyauth_routes(g5c_router *r, pcf *p)
{
    g5c_router_route(r, "POST", BASE, create, p);
    g5c_router_route(r, "GET", BASE "/{appSessionId}", get, p);
    g5c_router_route(r, "PATCH", BASE "/{appSessionId}", patch, p);
    g5c_router_route(r, "POST", BASE "/{appSessionId}/delete", del, p);
    g5c_router_route(r, "PUT", BASE "/{appSessionId}/events-subscription", ev_put, p);
    g5c_router_route(r, "DELETE", BASE "/{appSessionId}/events-subscription", ev_delete, p);
}
