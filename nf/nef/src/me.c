#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The MonitoringEvent API (TS 29.122 5.3, procedures 4.4.2 as applied to 5GS by TS 29.522 4.4.2) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

#define F_LOSS 0x1u
#define F_REACH 0x2u
#define F_LOC 0x4u
#define F_TEST 0x200u /* Notification_test_event, feature 10 */
#define F_MOD 0x400u  /* Subscription_modification, feature 11 */
#define F_OURS (F_LOSS | F_REACH | F_LOC | F_TEST | F_MOD)

typedef struct {
    const char *mt;     /* MonitoringType */
    const char *amf_ev; /* AmfEventType */
    const char *udm_ev; /* Nudm_EE EventType */
    unsigned feature;
} mtype_t;

static const mtype_t MTYPES[] = {
    {"LOSS_OF_CONNECTIVITY", "LOSS_OF_CONNECTIVITY", "LOSS_OF_CONNECTIVITY", F_LOSS},
    {"UE_REACHABILITY", "REACHABILITY_REPORT", "UE_REACHABILITY_FOR_DATA", F_REACH},
    {"LOCATION_REPORTING", "LOCATION_REPORT", "LOCATION_REPORTING", F_LOC},
};
#define NMT (sizeof MTYPES / sizeof MTYPES[0])

static const mtype_t *mtype_find(const char *mt)
{
    for (size_t i = 0; mt != NULL && i < NMT; i++)
        if (strcmp(MTYPES[i].mt, mt) == 0)
            return &MTYPES[i];
    return NULL;
}

static char *self_url(const g5c_req *req, const char *af, const char *id)
{
    char *path = g5c_xasprintf(ME_BASE "/%s/subscriptions/%s", af, id), *u = g5c_req_url(req, path);
    free(path);
    return u;
}

/* ---- the AMF ---- */

/* The root of the namf-evts service of the AMF instance `inst`, from its profile at the NRF; NULL when it cannot be found. */
static char *amf_root_of(nef *n, const char *inst)
{
    char *root;
    char *path, err[160], *out = NULL;
    g5c_resp r;
    const g5c_json *svcs;
    if (n->cfg->amf_uri != NULL)
        return g5c_xstrdup(n->cfg->amf_uri);
    if (n->cfg->nrf_uri == NULL)
        return NULL;
    root = g5c_xstrdup(n->cfg->nrf_uri);
    path = g5c_xasprintf("/nnrf-nfm/v1/nf-instances/%s", inst);
    if (nef_peer(n, root, "GET", path, NULL, &r, err, sizeof err) != 0) {
        free(path);
        free(root);
        return NULL;
    }
    free(path);
    free(root);
    if (r.status == 200) {
        g5c_json *prof = g5c_resp_parse_json(&r);
        svcs = g5c_json_get(prof, "nfServices");
        for (size_t i = 0; g5c_json_is(svcs, G5C_J_ARRAY) && i < g5c_json_len(svcs) && out == NULL; i++) {
            const g5c_json *s = g5c_json_at(svcs, i), *ep = g5c_json_at(g5c_json_get(s, "ipEndPoints"), 0);
            const char *scheme = g5c_json_get_str(s, "scheme"), *ip = g5c_json_get_str(ep, "ipv4Address"), *fq = g5c_json_get_str(s, "fqdn");
            int64_t port = 80;
            if (g5c_json_get_str(s, "serviceName") == NULL || strcmp(g5c_json_get_str(s, "serviceName"), "namf-evts") != 0)
                continue;
            if (scheme == NULL)
                scheme = "http";
            if (ep != NULL)
                (void)g5c_json_get_int(ep, "port", &port);
            if (ip != NULL)
                out = g5c_xasprintf("%s://%s:%lld", scheme, ip, (long long)port);
            else if (fq != NULL)
                out = g5c_xasprintf("%s://%s:%lld", scheme, fq, (long long)port);
        }
        g5c_json_free(prof);
    }
    g5c_resp_free(&r);
    return out;
}

/* the SUPI of a GPSI and the AMF instance that serves it; 0 on success, else the status to answer */
static int udm_call(nef *n, const char *path, g5c_json **out, char *detail, size_t dcap)
{
    char *root = nef_root(n, n->cfg->udm_uri, "UDM", NULL), err[160];
    g5c_resp r;
    int rc, st = 0;
    *out = NULL;
    if (root == NULL) {
        snprintf(detail, dcap, "no UDM");
        return 500;
    }
    rc = nef_peer(n, root, "GET", path, NULL, &r, err, sizeof err);
    free(root);
    if (rc != 0) {
        snprintf(detail, dcap, "UDM: %s", err);
        nef_call_failed(n, 1);
        return 500;
    }
    if (r.status == 200) {
        *out = g5c_resp_parse_json(&r);
        if (*out == NULL) {
            snprintf(detail, dcap, "UDM answered a body that is not JSON");
            st = 500;
        }
    } else {
        snprintf(detail, dcap, "UDM answered %d", r.status);
        st = r.status == 404 ? 404 : 500;
    }
    g5c_resp_free(&r);
    return st;
}

static char *dup_str(const char *s)
{
    return s != NULL ? g5c_xstrdup(s) : NULL;
}

/* ---- reports ---- */

static int lost_reason(const char *r)
{
    /* TS 29.522 4.4.2: 6 deregistered, 7 maximum detection timer expired, 8 purged */
    if (r != NULL && strcmp(r, "MAX_DETECTION_TIME_EXPIRED") == 0)
        return 7;
    if (r != NULL && strcmp(r, "UE_PURGED_IN_NETWORK") == 0)
        return 8;
    return 6;
}

/* The MonitoringEventReport for an AmfEventReport of the subscription `doc`, or NULL when the report is not one the AF asked for. */
static g5c_json *event_report(const g5c_json *doc, const g5c_json *rep)
{
    const char *type = g5c_json_get_str(rep, "type"), *mt = g5c_json_get_str(doc, "monitoringType"), *ts = g5c_json_get_str(rep, "timeStamp");
    g5c_json *o;
    char now[32];
    if (type == NULL || mt == NULL)
        return NULL;
    o = g5c_json_new_obj();
    if (ts == NULL) {
        format_rfc3339(g5c_unix_millis(), now);
        ts = now;
    }
    if (strcmp(type, "LOSS_OF_CONNECTIVITY") == 0 && strcmp(mt, "LOSS_OF_CONNECTIVITY") == 0) {
        g5c_json_set_str(o, "monitoringType", mt);
        g5c_json_set_int(o, "lossOfConnectReason", lost_reason(g5c_json_get_str(rep, "lossOfConnectReason")));
    } else if (strcmp(type, "REACHABILITY_REPORT") == 0 && strcmp(mt, "UE_REACHABILITY") == 0) {
        const char *re = g5c_json_get_str(rep, "reachability");
        if (re == NULL || strcmp(re, "REACHABLE") != 0) {
            g5c_json_free(o);
            return NULL; /* the AF is told when the UE can be reached, not when it cannot */
        }
        g5c_json_set_str(o, "monitoringType", mt);
        g5c_json_set_str(o, "reachabilityType", g5c_json_get_str(doc, "reachabilityType") != NULL ? g5c_json_get_str(doc, "reachabilityType") : "DATA");
    } else if (strcmp(type, "LOCATION_REPORT") == 0 && strcmp(mt, "LOCATION_REPORTING") == 0) {
        const g5c_json *nr = g5c_json_get(g5c_json_get(rep, "location"), "nrLocation"), *tai = g5c_json_get(nr, "tai"), *pl = g5c_json_get(tai, "plmnId"),
                       *ncgi = g5c_json_get(nr, "ncgi");
        g5c_json *li = g5c_json_set(o, "locationInfo", g5c_json_new_obj());
        g5c_json_set_str(o, "monitoringType", mt);
        if (g5c_json_get_str(tai, "tac") != NULL)
            g5c_json_set_str(li, "trackingAreaId", g5c_json_get_str(tai, "tac"));
        if (g5c_json_get_str(pl, "mcc") != NULL && g5c_json_get_str(pl, "mnc") != NULL) {
            char *p = g5c_xasprintf("%s%s", g5c_json_get_str(pl, "mcc"), g5c_json_get_str(pl, "mnc"));
            g5c_json_set_str(li, "plmnId", p);
            free(p);
        }
        if (g5c_json_get_str(ncgi, "nrCellId") != NULL)
            g5c_json_set_str(li, "cellId", g5c_json_get_str(ncgi, "nrCellId"));
    } else {
        g5c_json_free(o);
        return NULL;
    }
    g5c_json_set_str(o, "eventTime", ts);
    if (g5c_json_get_str(doc, "externalId") != NULL)
        g5c_json_set_str(o, "externalId", g5c_json_get_str(doc, "externalId"));
    if (g5c_json_get_str(doc, "msisdn") != NULL)
        g5c_json_set_str(o, "msisdn", g5c_json_get_str(doc, "msisdn"));
    return o;
}

static g5c_json *reports_of(const g5c_json *doc, const g5c_json *report_list)
{
    g5c_json *arr = g5c_json_new_arr();
    for (size_t i = 0; i < g5c_json_len(report_list); i++) {
        g5c_json *e = event_report(doc, g5c_json_at(report_list, i));
        if (e != NULL)
            g5c_json_push(arr, e);
    }
    return arr;
}

/* ---- subscription at the AMF ---- */

static void amf_unsubscribe(nef *n, const char *amf_root, const char *amf_sub)
{
    char *path, err[160];
    g5c_resp r;
    if (amf_root == NULL || amf_sub == NULL)
        return;
    if (strncmp(amf_sub, "ee:", 3) == 0) { /* a Nudm_EE subscription: "ee:<encoded GPSI>|<id>" */
        const char *bar = strchr(amf_sub, '|');
        if (bar == NULL)
            return;
        path = g5c_xasprintf("/nudm-ee/v1/%.*s/ee-subscriptions/%s", (int)(bar - (amf_sub + 3)), amf_sub + 3, bar + 1);
    } else {
        path = g5c_xasprintf("/namf-evts/v1/subscriptions/%s", amf_sub);
    }
    if (nef_peer(n, amf_root, "DELETE", path, NULL, &r, err, sizeof err) == 0)
        g5c_resp_free(&r);
    else
        G5C_LOGW(NEF_LOG, "cannot remove subscription %s at the AMF: %s", amf_sub, err);
    free(path);
}

typedef struct {
    char *amf_root, *amf_sub, *supi, *corr;
    g5c_json *immediate; /* the report list the AMF answered with */
} amf_sub_t;

static void amf_sub_free(amf_sub_t *a)
{
    free(a->amf_root);
    free(a->amf_sub);
    free(a->supi);
    free(a->corr);
    g5c_json_free(a->immediate);
}

/* ---- subscription through the UDM (Nudm_EventExposure, `nef.events_via_udm`) ---- */

/* The UDM's MonitoringReports (an array) as the AMF-shaped report list the rest of this file reads. */
static g5c_json *udm_to_amf_reports(const g5c_json *arr)
{
    g5c_json *out = g5c_json_new_arr();
    for (size_t i = 0; g5c_json_is(arr, G5C_J_ARRAY) && i < g5c_json_len(arr); i++) {
        const g5c_json *m = g5c_json_at(arr, i), *rp = g5c_json_get(m, "report");
        const char *et = g5c_json_get_str(m, "eventType"), *ts = g5c_json_get_str(m, "timeStamp");
        const char *type = NULL;
        g5c_json *o;
        for (size_t k = 0; et != NULL && k < NMT; k++)
            if (strcmp(MTYPES[k].udm_ev, et) == 0)
                type = MTYPES[k].amf_ev;
        if (type == NULL)
            continue;
        o = g5c_json_push(out, g5c_json_new_obj());
        g5c_json_set_str(o, "type", type);
        if (ts != NULL)
            g5c_json_set_str(o, "timeStamp", ts);
        if (strcmp(type, "LOSS_OF_CONNECTIVITY") == 0 && g5c_json_get_str(rp, "lossOfConnectReason") != NULL)
            g5c_json_set_str(o, "lossOfConnectReason", g5c_json_get_str(rp, "lossOfConnectReason"));
        else if (strcmp(type, "REACHABILITY_REPORT") == 0)
            g5c_json_set_str(o, "reachability", "REACHABLE");
        else if (strcmp(type, "LOCATION_REPORT") == 0 && g5c_json_get(rp, "location") != NULL)
            g5c_json_set(o, "location", g5c_json_dup(g5c_json_get(rp, "location")));
    }
    return out;
}

static int udm_subscribe(nef *n, const char *id, const char *corr, const mtype_t *mt, const char *gpsi, bool immediate, amf_sub_t *out, const char **cause, char *detail, size_t dcap)
{
    char *root = nef_root(n, n->cfg->udm_uri, "UDM", NULL), *enc = pct_encode(gpsi), *path, *cb_path, *cb, err[160];
    g5c_json *body, *cfg, *rb = NULL;
    g5c_resp r;
    int st = 500;
    if (root == NULL) {
        snprintf(detail, dcap, "no UDM");
        free(enc);
        return 500;
    }
    cb_path = g5c_xasprintf(CB_BASE "/udm-events/%s/%s", id, corr);
    cb = nef_self_url(n, cb_path);
    free(cb_path);
    if (cb == NULL) {
        snprintf(detail, dcap, "the NEF has no callback address");
        free(root);
        free(enc);
        return 500;
    }
    body = g5c_json_new_obj();
    g5c_json_set_str(body, "callbackReference", cb);
    g5c_json_set_str(body, "notifyCorrelationId", corr);
    cfg = g5c_json_set(g5c_json_set(body, "monitoringConfigurations", g5c_json_new_obj()), "1", g5c_json_new_obj());
    g5c_json_set_str(cfg, "eventType", mt->udm_ev);
    if (immediate)
        g5c_json_set_bool(cfg, "immediateFlag", true);
    free(cb);
    path = g5c_xasprintf("/nudm-ee/v1/%s/ee-subscriptions", enc);
    if (nef_peer(n, root, "POST", path, body, &r, err, sizeof err) != 0) {
        snprintf(detail, dcap, "UDM: %s", err);
        nef_call_failed(n, 1);
        goto out;
    }
    if (r.status != 201) {
        g5c_json *pb = g5c_resp_parse_json(&r);
        const char *c = g5c_json_get_str(pb, "cause");
        snprintf(detail, dcap, "UDM answered %d", r.status);
        if (r.status == 404) {
            *cause = c != NULL && strcmp(c, "CONTEXT_NOT_FOUND") == 0 ? "CONTEXT_NOT_FOUND" : "USER_NOT_FOUND";
            st = 404;
        } else if (r.status == 501) {
            *cause = "EVENT_UNSUPPORTED";
            st = 500;
        } else {
            st = peer_status(r.status);
        }
        g5c_json_free(pb);
        g5c_resp_free(&r);
        goto out;
    }
    rb = g5c_resp_parse_json(&r);
    g5c_resp_free(&r);
    if (g5c_json_get_str(g5c_json_get(rb, "eeSubscription"), "subscriptionId") == NULL) {
        snprintf(detail, dcap, "UDM answered without a subscription identifier");
        goto out;
    }
    out->amf_root = root;
    root = NULL;
    out->amf_sub = g5c_xasprintf("ee:%s|%s", enc, g5c_json_get_str(g5c_json_get(rb, "eeSubscription"), "subscriptionId"));
    out->supi = g5c_xstrdup(gpsi);
    out->corr = g5c_xstrdup(corr);
    if (g5c_json_len(g5c_json_get(rb, "eventReports")) > 0)
        out->immediate = udm_to_amf_reports(g5c_json_get(rb, "eventReports"));
    st = 0;
out:
    g5c_json_free(rb);
    g5c_json_free(body);
    free(path);
    free(root);
    free(enc);
    return st;
}

/* Finds the serving AMF of the UE and subscribes there; 0 on success, else the status to answer (cause in `cause`). */
static int amf_subscribe(nef *n, const char *id, const char *corr, const mtype_t *mt, const char *gpsi, bool immediate, amf_sub_t *out, const char **cause, char *detail, size_t dcap)
{
    char *enc = pct_encode(gpsi), *path, *inst, *cb_path, *cb, nf_id[40];
    g5c_json *tr = NULL, *reg = NULL, *body, *sub, *evl, *ev, *resp_body;
    const char *supi, *inst_id;
    g5c_resp r;
    char err[160];
    int st;
    *cause = "SYSTEM_FAILURE";
    memset(out, 0, sizeof *out);
    if (n->cfg->events_via_udm) {
        int urc = udm_subscribe(n, id, corr, mt, gpsi, immediate, out, cause, detail, dcap);
        free(enc); /* encoded above for the AMF path; the UDM path encodes the identity itself */
        return urc;
    }
    path = g5c_xasprintf("/nudm-sdm/v2/%s/id-translation-result", enc);
    free(enc);
    st = udm_call(n, path, &tr, detail, dcap);
    free(path);
    if (st == 404) {
        *cause = "USER_NOT_FOUND";
        return 404;
    }
    if (st != 0)
        return st;
    supi = g5c_json_get_str(tr, "supi");
    if (supi == NULL) {
        snprintf(detail, dcap, "UDM answered without a SUPI");
        g5c_json_free(tr);
        return 500;
    }
    out->supi = g5c_xstrdup(supi);
    g5c_json_free(tr);
    path = g5c_xasprintf("/nudm-uecm/v1/%s/registrations/amf-3gpp-access", out->supi);
    st = udm_call(n, path, &reg, detail, dcap);
    free(path);
    if (st == 404) {
        snprintf(detail, dcap, "the UE is not registered in any AMF; the NEF does not subscribe at the UDM for UEs that are not served yet");
        *cause = "CONTEXT_NOT_FOUND";
        amf_sub_free(out);
        return 404;
    }
    if (st != 0) {
        amf_sub_free(out);
        return st;
    }
    inst_id = g5c_json_get_str(reg, "amfInstanceId");
    inst = inst_id != NULL ? amf_root_of(n, inst_id) : (n->cfg->amf_uri != NULL ? g5c_xstrdup(n->cfg->amf_uri) : NULL);
    g5c_json_free(reg);
    if (inst == NULL) {
        snprintf(detail, dcap, "the serving AMF of the UE cannot be found");
        amf_sub_free(out);
        return 500;
    }
    out->amf_root = inst;
    out->corr = g5c_xstrdup(corr);
    cb_path = g5c_xasprintf(CB_BASE "/amf-events/%s", id);
    cb = nef_self_url(n, cb_path);
    free(cb_path);
    if (cb == NULL) {
        snprintf(detail, dcap, "the NEF has no callback address");
        amf_sub_free(out);
        return 500;
    }
    body = g5c_json_new_obj();
    sub = g5c_json_set(body, "subscription", g5c_json_new_obj());
    evl = g5c_json_set(sub, "eventList", g5c_json_new_arr());
    ev = g5c_json_push(evl, g5c_json_new_obj());
    g5c_json_set_str(ev, "type", mt->amf_ev);
    g5c_json_set_bool(ev, "immediateFlag", immediate);
    g5c_json_set_str(sub, "eventNotifyUri", cb);
    g5c_json_set_str(sub, "notifyCorrelationId", out->corr);
    snprintf(nf_id, sizeof nf_id, "%s", "g5c-nef");
    g5c_json_set_str(sub, "nfId", nf_id);
    g5c_json_set_str(sub, "supi", out->supi);
    free(cb);
    if (nef_peer(n, out->amf_root, "POST", "/namf-evts/v1/subscriptions", body, &r, err, sizeof err) != 0) {
        snprintf(detail, dcap, "AMF: %s", err);
        g5c_counter_inc(n->c_amf_fail);
        nef_call_failed(n, 2);
        g5c_json_free(body);
        amf_sub_free(out);
        return 500;
    }
    g5c_json_free(body);
    if (r.status != 201) {
        snprintf(detail, dcap, "AMF answered %d", r.status);
        if (r.status == 501)
            *cause = "EVENT_UNSUPPORTED";
        g5c_counter_inc(n->c_amf_fail);
        st = r.status == 501 ? 500 : peer_status(r.status);
        g5c_resp_free(&r);
        amf_sub_free(out);
        return st;
    }
    resp_body = g5c_resp_parse_json(&r);
    if (g5c_json_get_str(resp_body, "subscriptionId") != NULL) {
        out->amf_sub = g5c_xstrdup(g5c_json_get_str(resp_body, "subscriptionId"));
    } else {
        const char *loc = g5c_resp_header_get(&r, "location"), *sl = loc != NULL ? strrchr(loc, '/') : NULL;
        out->amf_sub = dup_str(sl != NULL ? sl + 1 : NULL);
    }
    if (g5c_json_is(g5c_json_get(resp_body, "reportList"), G5C_J_ARRAY))
        out->immediate = g5c_json_dup(g5c_json_get(resp_body, "reportList"));
    g5c_json_free(resp_body);
    g5c_resp_free(&r);
    if (out->amf_sub == NULL) {
        snprintf(detail, dcap, "AMF answered without a subscription identifier");
        amf_sub_free(out);
        return 500;
    }
    return 0;
}

/* ---- the resource ---- */

static void drop(nef *n, res_t *r)
{
    const char *root = g5c_json_get_str(r->ctx, "amf"), *sub = g5c_json_get_str(r->ctx, "amfSub");
    char *root_c = dup_str(root), *sub_c = dup_str(sub);
    res_remove(n, r);
    pthread_mutex_unlock(&n->mu);
    amf_unsubscribe(n, root_c, sub_c);
    pthread_mutex_lock(&n->mu);
    free(root_c);
    free(sub_c);
}

void me_sweep(nef *n)
{
    int64_t now = g5c_unix_millis();
    bool changed = false;
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < n->nres;) {
        res_t *r = n->res[i];
        if (r->api == API_ME && r->expiry_ms != 0 && r->expiry_ms <= now) {
            drop(n, r);
            changed = true;
            i = 0; /* the table moved while the lock was open */
            continue;
        }
        i++;
    }
    pthread_mutex_unlock(&n->mu);
    if (changed)
        nef_dirty(n);
}

void me_state_restored(nef *n)
{
    (void)n;
}

static bool one_time(const g5c_json *doc)
{
    int64_t v;
    return g5c_json_get_int(doc, "maximumNumberOfReports", &v) && v == 1;
}

/* The checks on the request that need no other function. `feat` is what the AF offered. 0, or the status answered. */
static int check_request(nef *n, const nef_af *af, g5c_json *body, unsigned offered, const mtype_t **mt, g5c_resp *resp)
{
    const char *type = g5c_json_get_str(body, "monitoringType"), *dest = g5c_json_get_str(body, "notificationDestination"), *lt;
    int64_t v;
    int64_t now = g5c_unix_millis();
    bool b;
    *mt = mtype_find(type);
    if (*mt == NULL) {
        nef_problem(resp, 500, "EVENT_UNSUPPORTED", "the NEF supports the monitoring types LOSS_OF_CONNECTIVITY, UE_REACHABILITY and LOCATION_REPORTING");
        return 500;
    }
    if ((offered & (*mt)->feature) == 0) {
        nef_problem(resp, 400, "EVENT_FEATURE_MISMATCH", "supportedFeatures does not indicate support of the feature of this monitoring type");
        return 400;
    }
    if (g5c_json_get(body, "externalGroupId") != NULL) {
        nef_problem(resp, 500, "EVENT_UNSUPPORTED", "monitoring of a group of UEs is not supported");
        return 500;
    }
    if (g5c_json_get_str(body, "externalId") == NULL && g5c_json_get_str(body, "msisdn") == NULL) {
        nef_invalid(resp, 400, "INVALID_REQUEST", "/externalId", "one of externalId and msisdn is required for a single UE");
        return 400;
    }
    if (!notify_host_allowed(af, dest)) {
        nef_problem(resp, 403, "NOTIFICATION_DESTINATION_NOT_ALLOWED", "the notification destination is not a host this AF may name");
        return 403;
    }
    if (g5c_json_get_bool(body, "idleStatusIndication", &b) && b) {
        nef_problem(resp, 403, "IDLE_STATUS_UNSUPPORTED", "the idle status indication is not supported");
        return 403;
    }
    /* parameters within the range of the operator policy: a value out of range is replaced by the limit (TS 29.122 4.4.2.2.1) */
    if (g5c_json_get_int(body, "maximumNumberOfReports", &v)) {
        if (v < 1) {
            nef_invalid(resp, 403, "PARAMETER_OUT_OF_RANGE", "/maximumNumberOfReports", "must be at least 1");
            return 403;
        }
        if (v > (int64_t)n->cfg->max_reports)
            g5c_json_set_int(body, "maximumNumberOfReports", n->cfg->max_reports);
    }
    if (g5c_json_get_str(body, "monitorExpireTime") != NULL) {
        int64_t t = parse_rfc3339(g5c_json_get_str(body, "monitorExpireTime"));
        char ts[32];
        if (t < 0) {
            nef_invalid(resp, 400, "INVALID_REQUEST", "/monitorExpireTime", "not an RFC 3339 date and time");
            return 400;
        }
        if (t <= now) {
            nef_invalid(resp, 403, "PARAMETER_OUT_OF_RANGE", "/monitorExpireTime", "is in the past");
            return 403;
        }
        if (t > now + (int64_t)n->cfg->sub_lifetime_s * 1000) {
            format_rfc3339(now + (int64_t)n->cfg->sub_lifetime_s * 1000, ts);
            g5c_json_set_str(body, "monitorExpireTime", ts);
        }
    }
    lt = g5c_json_get_str(body, "locationType");
    if (lt != NULL && strcmp(lt, "LAST_KNOWN_LOCATION") == 0 && !one_time(body))
        g5c_json_set_int(body, "maximumNumberOfReports", 1); /* TS 29.522 4.4.2: a one-time request */
    return 0;
}

static g5c_json *representation(const g5c_json *body, unsigned negotiated, const char *self)
{
    g5c_json *doc = g5c_json_dup(body);
    char *f = feat_str(negotiated);
    g5c_json_remove(doc, "supportedFeatures");
    if (g5c_json_get(body, "supportedFeatures") != NULL)
        g5c_json_set_str(doc, "supportedFeatures", f != NULL ? f : "0");
    g5c_json_remove(doc, "monitoringEventReport");
    g5c_json_set_str(doc, "self", self);
    free(f);
    return doc;
}

/* the representation of a subscription that is already registered (for the reports of an immediate answer) */
static const g5c_json *doc_for_reports(nef *n, const char *af, const char *id)
{
    const res_t *r;
    const g5c_json *d = NULL;
    pthread_mutex_lock(&n->mu);
    r = res_find(n, API_ME, af, id);
    if (r != NULL)
        d = r->doc;
    pthread_mutex_unlock(&n->mu); /* the document is only replaced by a PUT, which an AF cannot send before it has the answer */
    return d;
}

static bool one_time_res(nef *n, const char *af, const char *id)
{
    const g5c_json *d = doc_for_reports(n, af, id);
    return d != NULL && one_time(d);
}

static void h_post(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_ME);
    g5c_json *body, *doc, *cx, *reports = NULL;
    const mtype_t *mt;
    char id[37], corr[33], detail[200], *self, *key;
    const char *cause;
    amf_sub_t as;
    unsigned offered, feat;
    bool immediate, test = false, registered = false;
    uint8_t rnd[16];
    int st;
    res_t *r;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_ME]);
    body = g5c_req_json(req, resp);
    if (body == NULL)
        return;
    if (!nef_body_ok(n, body, NEF_SCH_MONITORING_SUBSCRIPTION, resp))
        goto reject;
    offered = feat_parse(g5c_json_get_str(body, "supportedFeatures"));
    if (check_request(n, af, body, offered, &mt, resp) != 0)
        goto reject;
    pthread_mutex_lock(&n->mu);
    if (res_count(n, API_ME, af->id) >= af->max_subs) {
        pthread_mutex_unlock(&n->mu);
        nef_problem(resp, 429, "TOO_MANY_SUBSCRIPTIONS", "the AF has the most subscriptions it may have");
        goto reject;
    }
    pthread_mutex_unlock(&n->mu);
    g5c_uuid_v4(id);
    g5c_random(rnd, sizeof rnd);
    for (int i = 0; i < 16; i++)
        snprintf(corr + 2 * i, 3, "%02x", rnd[i]);
    immediate = strcmp(mt->mt, "LOCATION_REPORTING") == 0;
    {
        const char *lt = g5c_json_get_str(body, "locationType");
        if (immediate && lt != NULL && strcmp(lt, "INITIAL_LOCATION") == 0)
            immediate = false;
    }
    /* The subscription exists before the AMF hears of it: the AMF's reports can reach the NEF before the answer to the request does. */
    feat = offered & F_OURS;
    self = self_url(req, af->id, id);
    doc = representation(body, feat, self);
    cx = g5c_json_new_obj();
    g5c_json_set_str(cx, "corr", corr);
    g5c_json_set_int(cx, "features", feat);
    pthread_mutex_lock(&n->mu);
    r = res_add(n, API_ME, af->id, id, doc, cx);
    if (g5c_json_get_str(doc, "monitorExpireTime") != NULL)
        r->expiry_ms = parse_rfc3339(g5c_json_get_str(doc, "monitorExpireTime"));
    registered = true;
    pthread_mutex_unlock(&n->mu);
    {
        char *gpsi = g5c_json_get_str(body, "msisdn") != NULL ? g5c_xasprintf("msisdn-%s", g5c_json_get_str(body, "msisdn"))
                                                               : g5c_xasprintf("extid-%s", g5c_json_get_str(body, "externalId"));
        st = amf_subscribe(n, id, corr, mt, gpsi, immediate, &as, &cause, detail, sizeof detail);
        free(gpsi);
    }
    if (st != 0) {
        pthread_mutex_lock(&n->mu);
        r = res_find(n, API_ME, af->id, id);
        if (r != NULL)
            res_remove(n, r);
        pthread_mutex_unlock(&n->mu);
        nef_problem(resp, st, cause, detail);
        free(self);
        goto reject;
    }
    if (as.immediate != NULL)
        reports = reports_of(doc_for_reports(n, af->id, id), as.immediate);
    if (reports != NULL && g5c_json_len(reports) > 0 && one_time_res(n, af->id, id)) {
        /* the one-time request is answered by the report; nothing is left at the AMF */
        g5c_json *answer = NULL;
        amf_unsubscribe(n, as.amf_root, as.amf_sub);
        pthread_mutex_lock(&n->mu);
        r = res_find(n, API_ME, af->id, id);
        if (r != NULL) {
            answer = g5c_json_dup(r->doc);
            res_remove(n, r);
        }
        pthread_mutex_unlock(&n->mu);
        if (answer != NULL) {
            g5c_json_set(answer, "monitoringEventReport", g5c_json_dup(g5c_json_at(reports, 0)));
            g5c_resp_json(resp, 200, answer);
            g5c_json_free(answer);
        } else {
            nef_problem(resp, 500, "SYSTEM_FAILURE", "the subscription ended before the AMF answered");
        }
        g5c_json_free(reports);
        amf_sub_free(&as);
        free(self);
        g5c_json_free(body);
        return;
    }
    pthread_mutex_lock(&n->mu);
    r = res_find(n, API_ME, af->id, id);
    if (r == NULL) {
        pthread_mutex_unlock(&n->mu);
        nef_problem(resp, 500, "SYSTEM_FAILURE", "the subscription ended before the AMF answered");
        amf_unsubscribe(n, as.amf_root, as.amf_sub);
        goto done_fail;
    }
    g5c_json_set_str(r->ctx, "amf", as.amf_root);
    g5c_json_set_str(r->ctx, "amfSub", as.amf_sub);
    g5c_json_set_str(r->ctx, "supi", as.supi);
    if (reports != NULL && g5c_json_len(reports) > 0) {
        g5c_json *copy = g5c_json_dup(r->doc);
        char *path = g5c_xasprintf("%s/%s/subscriptions/%s", ME_BASE, af->id, id), *loc = g5c_req_url(req, path);
        g5c_json_set(copy, "monitoringEventReport", g5c_json_dup(g5c_json_at(reports, 0)));
        g5c_resp_json(resp, 201, copy);
        g5c_resp_header(resp, "location", loc);
        g5c_json_free(copy);
        free(path);
        free(loc);
        r->reports = 1;
    } else {
        nef_reply_res(resp, 201, r, req, ME_BASE);
    }
    pthread_mutex_unlock(&n->mu);
    nef_dirty(n);
    if ((feat & F_TEST) != 0 && g5c_json_get_bool(body, "requestTestNotification", &test) && test) {
        g5c_json *t = g5c_json_new_obj();
        key = nef_key(API_ME, af->id, id);
        g5c_json_set_str(t, "subscription", self);
        nef_enqueue(n, g5c_json_get_str(body, "notificationDestination"), g5c_json_to_string(t, NULL), key, 0);
        g5c_json_free(t);
        free(key);
    }
done_fail:
    g5c_json_free(reports);
    amf_sub_free(&as);
    free(self);
    g5c_json_free(body);
    (void)registered;
    return;
reject:
    g5c_counter_inc(n->c_reject[API_ME]);
    g5c_json_free(body);
}

static void h_list(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_ME);
    g5c_json *arr;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_ME]);
    arr = g5c_json_new_arr();
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < n->nres; i++)
        if (n->res[i]->api == API_ME && strcmp(n->res[i]->af, af->id) == 0)
            g5c_json_push(arr, g5c_json_dup(n->res[i]->doc));
    pthread_mutex_unlock(&n->mu);
    g5c_resp_json(resp, 200, arr);
    g5c_json_free(arr);
}

static void h_get(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_ME);
    res_t *r;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_ME]);
    pthread_mutex_lock(&n->mu);
    r = res_find(n, API_ME, af->id, g5c_req_param(req, "subscriptionId") != NULL ? g5c_req_param(req, "subscriptionId") : "");
    if (r != NULL)
        g5c_resp_json(resp, 200, r->doc);
    pthread_mutex_unlock(&n->mu);
    if (r == NULL)
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such monitoring event subscription");
}

/* PUT (Subscription_modification): what can change is what the AF asks for in terms of reporting and where; the UE and the monitoring type cannot. */
static void h_put(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_ME);
    const char *id = g5c_req_param(req, "subscriptionId");
    g5c_json *body, *old = NULL, *doc;
    const mtype_t *mt;
    unsigned feat = 0;
    int64_t f;
    res_t *r;
    char *self;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_ME]);
    body = g5c_req_json(req, resp);
    if (body == NULL)
        return;
    if (!nef_body_ok(n, body, NEF_SCH_MONITORING_SUBSCRIPTION, resp))
        goto reject;
    pthread_mutex_lock(&n->mu);
    r = id != NULL ? res_find(n, API_ME, af->id, id) : NULL;
    if (r != NULL) {
        old = g5c_json_dup(r->doc);
        if (g5c_json_get_int(r->ctx, "features", &f))
            feat = (unsigned)f;
    }
    pthread_mutex_unlock(&n->mu);
    if (old == NULL) {
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such monitoring event subscription");
        goto reject;
    }
    if ((feat & F_MOD) == 0) {
        nef_problem(resp, 403, "OPERATION_PROHIBITED", "the subscription was not made with the Subscription_modification feature");
        goto reject;
    }
    if (check_request(n, af, body, feat, &mt, resp) != 0)
        goto reject;
    if (!g5c_streq(g5c_json_get_str(body, "monitoringType"), g5c_json_get_str(old, "monitoringType")) ||
        !g5c_streq(g5c_json_get_str(body, "externalId"), g5c_json_get_str(old, "externalId")) || !g5c_streq(g5c_json_get_str(body, "msisdn"), g5c_json_get_str(old, "msisdn"))) {
        nef_problem(resp, 403, "OPERATION_PROHIBITED", "the UE and the monitoring type of a subscription cannot be changed");
        goto reject;
    }
    self = self_url(req, af->id, id);
    doc = representation(body, feat, self);
    free(self);
    pthread_mutex_lock(&n->mu);
    r = res_find(n, API_ME, af->id, id);
    if (r != NULL) {
        g5c_json_free(r->doc);
        r->doc = doc;
        r->expiry_ms = g5c_json_get_str(doc, "monitorExpireTime") != NULL ? parse_rfc3339(g5c_json_get_str(doc, "monitorExpireTime")) : 0;
        g5c_resp_json(resp, 200, r->doc);
    } else {
        g5c_json_free(doc);
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "the subscription was deleted meanwhile");
    }
    pthread_mutex_unlock(&n->mu);
    nef_dirty(n);
    g5c_json_free(old);
    g5c_json_free(body);
    return;
reject:
    g5c_counter_inc(n->c_reject[API_ME]);
    g5c_json_free(old);
    g5c_json_free(body);
}

static void h_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_ME);
    const char *id = g5c_req_param(req, "subscriptionId");
    res_t *r;
    bool found = false;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_ME]);
    pthread_mutex_lock(&n->mu);
    r = id != NULL ? res_find(n, API_ME, af->id, id) : NULL;
    if (r != NULL) {
        found = true;
        drop(n, r);
    }
    pthread_mutex_unlock(&n->mu);
    if (!found) {
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such monitoring event subscription");
        return;
    }
    nef_dirty(n);
    g5c_resp_status(resp, 204);
}

/* ---- from the AMF ---- */

static res_t *find_by_id(nef *n, const char *id)
{
    for (size_t i = 0; id != NULL && i < n->nres; i++)
        if (n->res[i]->api == API_ME && strcmp(n->res[i]->id, id) == 0)
            return n->res[i];
    return NULL;
}

static void events_common(nef *n, const char *id, g5c_json *in, g5c_resp *resp)
{
    g5c_json *reports, *note = NULL;
    res_t *r;
    char *url = NULL, *key = NULL, *self = NULL;
    bool done = false, found = false, bad = false;
    const char *corr;
    corr = g5c_json_get_str(in, "notifyCorrelationId");
    pthread_mutex_lock(&n->mu);
    r = find_by_id(n, id);
    if (r != NULL) {
        found = true;
        if (corr == NULL || !g5c_streq(corr, g5c_json_get_str(r->ctx, "corr"))) {
            bad = true;
        } else {
            reports = reports_of(r->doc, g5c_json_get(in, "reportList"));
            if (g5c_json_len(reports) > 0) {
                int64_t maxr;
                note = g5c_json_new_obj();
                self = dup_str(g5c_json_get_str(r->doc, "self"));
                g5c_json_set_str(note, "subscription", self);
                g5c_json_set(note, "monitoringEventReports", reports);
                url = dup_str(g5c_json_get_str(r->doc, "notificationDestination"));
                key = nef_key(API_ME, r->af, r->id);
                r->reports += (unsigned)g5c_json_len(g5c_json_get(note, "monitoringEventReports"));
                if (g5c_json_get_int(r->doc, "maximumNumberOfReports", &maxr) && r->reports >= (uint64_t)maxr)
                    done = true;
            } else {
                g5c_json_free(reports);
            }
            if (done)
                drop(n, r);
        }
    }
    pthread_mutex_unlock(&n->mu);
    if (!found) {
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such monitoring event subscription");
    } else if (bad) {
        nef_problem(resp, 403, "INVALID_CORRELATION_ID", "the notification correlation identifier does not match");
    } else {
        g5c_resp_status(resp, 204);
        if (note != NULL && url != NULL)
            nef_enqueue(n, url, g5c_json_to_string(note, NULL), key, 0);
        if (note != NULL || done)
            nef_dirty(n);
    }
    g5c_json_free(note);
    g5c_json_free(in);
    free(url);
    free(key);
    free(self);
}

/* Namf_EventExposure notification from the AMF */
static void h_amf_event(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *in = g5c_req_json(req, resp);
    if (in != NULL)
        events_common(ctx, g5c_req_param(req, "resId"), in, resp);
}

/* Nudm_EventExposure notification from the UDM */
static void h_udm_event(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *arr = g5c_req_json(req, resp), *in;
    if (arr == NULL)
        return;
    in = g5c_json_new_obj();
    g5c_json_set_str(in, "notifyCorrelationId", g5c_req_param(req, "corr") != NULL ? g5c_req_param(req, "corr") : "");
    g5c_json_set(in, "reportList", udm_to_amf_reports(arr));
    g5c_json_free(arr);
    events_common(ctx, g5c_req_param(req, "resId"), in, resp);
}

void me_routes(g5c_router *r, nef *n)
{
    g5c_router_route(r, "GET", ME_BASE "/{afId}/subscriptions", h_list, n);
    g5c_router_route(r, "POST", ME_BASE "/{afId}/subscriptions", h_post, n);
    g5c_router_route(r, "GET", ME_BASE "/{afId}/subscriptions/{subscriptionId}", h_get, n);
    g5c_router_route(r, "PUT", ME_BASE "/{afId}/subscriptions/{subscriptionId}", h_put, n);
    g5c_router_route(r, "DELETE", ME_BASE "/{afId}/subscriptions/{subscriptionId}", h_delete, n);
    g5c_router_route(r, "POST", CB_BASE "/amf-events/{resId}", h_amf_event, n);
    g5c_router_route(r, "POST", CB_BASE "/udm-events/{resId}/{corr}", h_udm_event, n);
}
