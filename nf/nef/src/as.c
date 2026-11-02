#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The AsSessionWithQoS API (TS 29.122 5.14, procedures 4.4.13 as applied to 5GS by TS 29.522 4.4.9): an AF asks for a QoS, named by a QoS reference, for
 * flows of a UE that it identifies by the UE's IPv4 address. The NEF acts as an AF towards the PCF (Npcf_PolicyAuthorization, TS 29.514 4.2.2.32: media
 * component with a qosReference), subscribes to the outcome of the allocation (SUCCESSFUL_ / FAILED_RESOURCES_ALLOCATION) and passes the PCF's
 * notifications on to the AF as UserPlaneNotificationData; the end of the PDU session ends the subscription (SESSION_TERMINATION).
 *
 * Not supported (answered 501, never silently ignored): Ethernet flows and the MAC address, an IPv6 address of the UE, the usage threshold and sponsored data
 * connectivity, QoS monitoring, alternative QoS references. The PCF is found through the NRF unless the configuration names it. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

#define F_TEST 0x2u /* feature 2, Notification_test_event (TS 29.122 5.14.4) */
#define F_OURS F_TEST
#define PCF_APPS "/npcf-policyauthorization/v1/app-sessions"
#define N5_FEATURES "8010000" /* AuthorizationWithRequiredQoS (17) and PatchCorrection (28) of TS 29.514 5.8 */

static char *self_url(const g5c_req *req, const char *af, const char *id)
{
    char *path = g5c_xasprintf(AQ_BASE "/%s/subscriptions/%s", af, id), *u = g5c_req_url(req, path);
    free(path);
    return u;
}

/* ---- the media component for the PCF ---------------------------------------------------------------------------------------- */

/* the one media component (medCompN 1) of a subscription: the flows and the QoS reference */
static g5c_json *media_component(const g5c_json *sub)
{
    g5c_json *c = g5c_json_new_obj(), *subs = g5c_json_set(c, "medSubComps", g5c_json_new_obj());
    const g5c_json *fi = g5c_json_get(sub, "flowInfo");
    g5c_json_set_int(c, "medCompN", 1);
    g5c_json_set_str(c, "qosReference", g5c_json_get_str(sub, "qosReference"));
    g5c_json_set_str(c, "fStatus", "ENABLED");
    for (size_t i = 0; i < g5c_json_len(fi); i++) {
        const g5c_json *f = g5c_json_at(fi, i);
        int64_t id = 0;
        char key[24];
        g5c_json *s;
        (void)g5c_json_get_int(f, "flowId", &id);
        snprintf(key, sizeof key, "%lld", (long long)id);
        s = g5c_json_set(subs, key, g5c_json_new_obj());
        g5c_json_set_int(s, "fNum", id);
        if (g5c_json_get(f, "flowDescriptions") != NULL)
            g5c_json_set(s, "fDescs", g5c_json_dup(g5c_json_get(f, "flowDescriptions")));
    }
    return c;
}

static g5c_json *ev_subsc(const char *notif)
{
    g5c_json *e = g5c_json_new_obj(), *l = g5c_json_set(e, "events", g5c_json_new_arr());
    g5c_json_set_str(g5c_json_push(l, g5c_json_new_obj()), "event", "SUCCESSFUL_RESOURCES_ALLOCATION");
    g5c_json_set_str(g5c_json_push(l, g5c_json_new_obj()), "event", "FAILED_RESOURCES_ALLOCATION");
    g5c_json_set_str(e, "notifUri", notif);
    return e;
}

/* ---- the PCF ------------------------------------------------------------------------------------------------------------------ */

/* one call to the PCF; `status` is what the AF is told when it fails (0 on success) */
static int pcf_call(nef *n, const char *root, const char *method, const char *path, const g5c_json *body, g5c_resp *out, char *detail, size_t dcap)
{
    char err[160];
    if (nef_peer(n, root, method, path, body, out, err, sizeof err) != 0) {
        snprintf(detail, dcap, "PCF: %s", err);
        nef_call_failed(n, 3);
        g5c_counter_inc(n->c_pcf_fail);
        return 500;
    }
    return 0;
}

static int map_pcf_status(const g5c_resp *r, char *cause, size_t ccap, char *detail, size_t dcap)
{
    char *c = g5c_resp_problem_cause(r);
    snprintf(detail, dcap, "PCF answered %d %s", r->status, c != NULL ? c : "");
    snprintf(cause, ccap, "SYSTEM_FAILURE");
    if (c != NULL && strcmp(c, "PDU_SESSION_NOT_AVAILABLE") == 0) {
        snprintf(cause, ccap, "PDU_SESSION_NOT_AVAILABLE");
        free(c);
        return 404;
    }
    if (r->status == 403) {
        snprintf(cause, ccap, "%s", c != NULL && c[0] != '\0' ? c : "REQUESTED_SERVICE_NOT_AUTHORIZED");
        free(c);
        return 403;
    }
    free(c);
    if (r->status == 400) {
        snprintf(cause, ccap, "INVALID_REQUEST");
        return 400;
    }
    return r->status == 429 ? 429 : 500;
}

/* ---- the resource ------------------------------------------------------------------------------------------------------------ */

static bool request_ok(const nef_af *af, g5c_json *sub, g5c_resp *resp)
{
    const char *dest = g5c_json_get_str(sub, "notificationDestination"), *qr = g5c_json_get_str(sub, "qosReference");
    if (!notify_host_allowed(af, dest)) {
        nef_problem(resp, 403, "NOTIFICATION_DESTINATION_NOT_ALLOWED", "the notification destination is not a host this AF may name");
        return false;
    }
    if (g5c_json_get(sub, "ethFlowInfo") != NULL || g5c_json_get(sub, "macAddr") != NULL || g5c_json_get(sub, "ueIpv6Addr") != NULL) {
        nef_problem(resp, 501, "NOT_SUPPORTED", "Ethernet flows and an IPv6 address of the UE are not supported");
        return false;
    }
    if (g5c_json_get(sub, "usageThreshold") != NULL || g5c_json_get(sub, "sponsorInfo") != NULL || g5c_json_get(sub, "qosMonInfo") != NULL ||
        g5c_json_get(sub, "altQoSReferences") != NULL || g5c_json_get(sub, "disUeNotif") != NULL) {
        nef_problem(resp, 501, "NOT_SUPPORTED", "usage thresholds, sponsored connectivity, QoS monitoring and alternative QoS references are not supported");
        return false;
    }
    if (g5c_json_get_str(sub, "ueIpv4Addr") == NULL) {
        nef_invalid(resp, 400, "INVALID_REQUEST", "/ueIpv4Addr", "the IPv4 address of the UE is required");
        return false;
    }
    if (qr == NULL || g5c_json_len(g5c_json_get(sub, "flowInfo")) == 0) {
        nef_invalid(resp, 400, "INVALID_REQUEST", qr == NULL ? "/qosReference" : "/flowInfo", "a QoS reference and the flows are required");
        return false;
    }
    for (size_t i = 0; i < g5c_json_len(g5c_json_get(sub, "flowInfo")); i++) {
        const g5c_json *fd = g5c_json_get(g5c_json_at(g5c_json_get(sub, "flowInfo"), i), "flowDescriptions");
        if (!g5c_json_is(fd, G5C_J_ARRAY) || g5c_json_len(fd) == 0) {
            char ptr[64];
            snprintf(ptr, sizeof ptr, "/flowInfo/%zu/flowDescriptions", i);
            nef_invalid(resp, 400, "INVALID_REQUEST", ptr, "the IP flow description is required");
            return false;
        }
    }
    if (af->nqos_refs > 0) {
        bool ok = false;
        for (size_t i = 0; i < af->nqos_refs; i++)
            if (strcmp(af->qos_refs[i], qr) == 0)
                ok = true;
        if (!ok) {
            nef_problem(resp, 403, "QOS_REFERENCE_NOT_ALLOWED", "the AF may not use that QoS reference");
            return false;
        }
    }
    return true;
}

static g5c_json *representation(const g5c_json *body, unsigned negotiated, const char *self)
{
    g5c_json *doc = g5c_json_dup(body);
    char *f = feat_str(negotiated);
    g5c_json_remove(doc, "supportedFeatures");
    if (g5c_json_get(body, "supportedFeatures") != NULL)
        g5c_json_set_str(doc, "supportedFeatures", f != NULL ? f : "0");
    g5c_json_set_str(doc, "self", self);
    free(f);
    return doc;
}

static void h_post(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_AQ);
    g5c_json *body, *doc, *cx, *asc, *ctxj, *flows;
    char id[37], corr[33], detail[200], *self, *root, *cbp, *cb, *loc_id = NULL;
    char cause[64] = "SYSTEM_FAILURE";
    unsigned feat;
    res_t *r;
    g5c_resp pr;
    int st;
    uint8_t rnd[16];
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_AQ]);
    body = g5c_req_json(req, resp);
    if (body == NULL)
        return;
    if (!nef_body_ok(n, body, NEF_SCH_AS_QOS_SUBSCRIPTION, resp) || !request_ok(af, body, resp))
        goto reject;
    pthread_mutex_lock(&n->mu);
    if (res_count(n, API_AQ, af->id) >= af->max_subs) {
        pthread_mutex_unlock(&n->mu);
        nef_problem(resp, 429, "TOO_MANY_SUBSCRIPTIONS", "the AF has the most subscriptions it may have");
        goto reject;
    }
    pthread_mutex_unlock(&n->mu);
    g5c_uuid_v4(id);
    g5c_random(rnd, sizeof rnd);
    for (int i = 0; i < 16; i++)
        snprintf(corr + 2 * i, 3, "%02x", rnd[i]);
    cbp = g5c_xasprintf(CB_BASE "/pcf-events/%s/%s", id, corr);
    cb = nef_self_url(n, cbp);
    free(cbp);
    if (cb == NULL) {
        nef_problem(resp, 500, "SYSTEM_FAILURE", "the NEF has no callback address");
        goto reject;
    }
    root = nef_pcf_root(n, body);
    if (root == NULL) {
        nef_problem(resp, 500, "SYSTEM_FAILURE", "no PCF for the authorization of the QoS");
        free(cb);
        goto reject;
    }
    /* The subscription exists before the PCF hears of it: the PCF's notifications can reach the NEF before the answer to the request does. */
    feat = feat_parse(g5c_json_get_str(body, "supportedFeatures")) & F_OURS;
    self = self_url(req, af->id, id);
    doc = representation(body, feat, self);
    cx = g5c_json_new_obj();
    g5c_json_set_str(cx, "pcf", root);
    g5c_json_set_str(cx, "corr", corr);
    g5c_json_set_int(cx, "features", feat);
    flows = g5c_json_set(cx, "flows", g5c_json_new_arr());
    for (size_t i = 0; i < g5c_json_len(g5c_json_get(body, "flowInfo")); i++) {
        int64_t fid = 0;
        (void)g5c_json_get_int(g5c_json_at(g5c_json_get(body, "flowInfo"), i), "flowId", &fid);
        g5c_json_push(flows, g5c_json_new_int(fid));
    }
    pthread_mutex_lock(&n->mu);
    (void)res_add(n, API_AQ, af->id, id, doc, cx);
    pthread_mutex_unlock(&n->mu);
    asc = g5c_json_new_obj();
    ctxj = g5c_json_new_obj();
    g5c_json_set(ctxj, "ascReqData", asc);
    g5c_json_set_str(asc, "suppFeat", N5_FEATURES);
    g5c_json_set_str(asc, "ueIpv4", g5c_json_get_str(body, "ueIpv4Addr"));
    if (g5c_json_get_str(body, "ipDomain") != NULL)
        g5c_json_set_str(asc, "ipDomain", g5c_json_get_str(body, "ipDomain"));
    g5c_json_set_str(asc, "notifUri", cb);
    g5c_json_set(g5c_json_set(asc, "medComponents", g5c_json_new_obj()), "1", media_component(body));
    g5c_json_set(asc, "evSubsc", ev_subsc(cb));
    free(cb);
    st = pcf_call(n, root, "POST", PCF_APPS, ctxj, &pr, detail, sizeof detail);
    g5c_json_free(ctxj);
    if (st == 0) {
        if (pr.status == 201) {
            const char *loc = g5c_resp_header_get(&pr, "location"), *sl = loc != NULL ? strrchr(loc, '/') : NULL;
            loc_id = sl != NULL ? g5c_xstrdup(sl + 1) : NULL;
            if (loc_id == NULL) {
                st = 500;
                snprintf(detail, sizeof detail, "the PCF answered without a Location");
            }
        } else {
            st = map_pcf_status(&pr, cause, sizeof cause, detail, sizeof detail);
        }
        g5c_resp_free(&pr);
    }
    pthread_mutex_lock(&n->mu);
    r = res_find(n, API_AQ, af->id, id);
    if (st != 0) {
        if (r != NULL)
            res_remove(n, r);
        pthread_mutex_unlock(&n->mu);
        nef_problem(resp, st, cause, detail);
        free(self);
        free(root);
        free(loc_id);
        goto reject;
    }
    if (r != NULL) {
        g5c_json_set_str(r->ctx, "app", loc_id);
        nef_reply_res(resp, 201, r, req, AQ_BASE);
    } else {
        nef_problem(resp, 500, "SYSTEM_FAILURE", "the subscription ended before the PCF answered"); /* the PDU session ended at once */
    }
    pthread_mutex_unlock(&n->mu);
    nef_dirty(n);
    {
        bool want = false;
        if ((feat & F_TEST) != 0 && g5c_json_get_bool(body, "requestTestNotification", &want) && want) {
            g5c_json *t = g5c_json_new_obj();
            char *key = nef_key(API_AQ, af->id, id);
            g5c_json_set_str(t, "subscription", self);
            nef_enqueue(n, g5c_json_get_str(body, "notificationDestination"), g5c_json_to_string(t, NULL), key, 0);
            g5c_json_free(t);
            free(key);
        }
    }
    free(self);
    free(root);
    free(loc_id);
    g5c_json_free(body);
    return;
reject:
    g5c_counter_inc(n->c_reject[API_AQ]);
    g5c_json_free(body);
}

static void h_list(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_AQ);
    g5c_json *arr;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_AQ]);
    arr = g5c_json_new_arr();
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < n->nres; i++)
        if (n->res[i]->api == API_AQ && strcmp(n->res[i]->af, af->id) == 0)
            g5c_json_push(arr, g5c_json_dup(n->res[i]->doc));
    pthread_mutex_unlock(&n->mu);
    g5c_resp_json(resp, 200, arr);
    g5c_json_free(arr);
}

static void h_get(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_AQ);
    res_t *r;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_AQ]);
    pthread_mutex_lock(&n->mu);
    r = res_find(n, API_AQ, af->id, g5c_req_param(req, "subscriptionId") != NULL ? g5c_req_param(req, "subscriptionId") : "");
    if (r != NULL)
        g5c_resp_json(resp, 200, r->doc);
    pthread_mutex_unlock(&n->mu);
    if (r == NULL)
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such AS session with QoS subscription");
}

/* PUT replaces every property (the UE address stays); PATCH changes some. Either way the media component at the PCF is brought to the new state. */
static void h_update(void *ctx, const g5c_req *req, g5c_resp *resp, bool patch)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_AQ);
    const char *id = g5c_req_param(req, "subscriptionId");
    g5c_json *body, *merged = NULL, *old = NULL, *doc, *pb, *asc, *mcs, *comp, *oldflows = NULL, *newflows;
    char *root = NULL, *app = NULL, detail[200], path[200], *self;
    char cause[64] = "SYSTEM_FAILURE";
    unsigned feat = 0;
    int64_t f;
    res_t *r;
    g5c_resp pr;
    int st;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_AQ]);
    body = g5c_req_json(req, resp);
    if (body == NULL)
        return;
    if (!nef_body_ok(n, body, patch ? NEF_SCH_AS_QOS_SUBSCRIPTION_PATCH : NEF_SCH_AS_QOS_SUBSCRIPTION, resp))
        goto reject;
    pthread_mutex_lock(&n->mu);
    r = id != NULL ? res_find(n, API_AQ, af->id, id) : NULL;
    if (r != NULL) {
        old = g5c_json_dup(r->doc);
        root = g5c_xstrdup(g5c_json_get_str(r->ctx, "pcf") != NULL ? g5c_json_get_str(r->ctx, "pcf") : "");
        app = g5c_xstrdup(g5c_json_get_str(r->ctx, "app") != NULL ? g5c_json_get_str(r->ctx, "app") : "");
        oldflows = g5c_json_dup(g5c_json_get(r->ctx, "flows"));
        if (g5c_json_get_int(r->ctx, "features", &f))
            feat = (unsigned)f;
    }
    pthread_mutex_unlock(&n->mu);
    if (old == NULL) {
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such AS session with QoS subscription");
        goto reject;
    }
    if (patch) {
        merged = g5c_json_dup(old);
        merge_patch(&merged, body);
        g5c_json_remove(merged, "self");
        if (!nef_body_ok(n, merged, NEF_SCH_AS_QOS_SUBSCRIPTION, resp))
            goto reject;
    } else {
        merged = g5c_json_dup(body);
        if (!g5c_streq(g5c_json_get_str(merged, "ueIpv4Addr"), g5c_json_get_str(old, "ueIpv4Addr"))) {
            nef_problem(resp, 403, "OPERATION_PROHIBITED", "the UE address of a subscription cannot be changed");
            goto reject;
        }
    }
    if (!request_ok(af, merged, resp))
        goto reject;
    if (!g5c_streq(g5c_json_get_str(merged, "ueIpv4Addr"), g5c_json_get_str(old, "ueIpv4Addr"))) {
        nef_problem(resp, 403, "OPERATION_PROHIBITED", "the UE address of a subscription cannot be changed");
        goto reject;
    }
    /* the media component 1 of the PCF: the new flows; the flows that are gone are removed (merge patch: null) */
    pb = g5c_json_new_obj();
    asc = g5c_json_set(pb, "ascReqData", g5c_json_new_obj());
    mcs = g5c_json_set(asc, "medComponents", g5c_json_new_obj());
    comp = g5c_json_set(mcs, "1", media_component(merged));
    {
        g5c_json *subs = g5c_json_get_mut(comp, "medSubComps");
        for (size_t i = 0; i < g5c_json_len(oldflows); i++) {
            int64_t of = 0;
            char key[24];
            bool kept = false;
            (void)g5c_json_int(g5c_json_at(oldflows, i), &of);
            snprintf(key, sizeof key, "%lld", (long long)of);
            kept = g5c_json_get(subs, key) != NULL;
            if (!kept)
                g5c_json_set(subs, key, g5c_json_new_null());
        }
    }
    snprintf(path, sizeof path, "%s/%s", PCF_APPS, app);
    st = pcf_call(n, root, "PATCH", path, pb, &pr, detail, sizeof detail);
    g5c_json_free(pb);
    if (st == 0) {
        if (pr.status == 200 || pr.status == 204)
            st = 0;
        else
            st = map_pcf_status(&pr, cause, sizeof cause, detail, sizeof detail);
        g5c_resp_free(&pr);
    }
    if (st != 0) {
        nef_problem(resp, st, cause, detail);
        goto reject;
    }
    self = self_url(req, af->id, id);
    doc = representation(merged, feat, self);
    newflows = g5c_json_new_arr();
    for (size_t i = 0; i < g5c_json_len(g5c_json_get(merged, "flowInfo")); i++) {
        int64_t fid = 0;
        (void)g5c_json_get_int(g5c_json_at(g5c_json_get(merged, "flowInfo"), i), "flowId", &fid);
        g5c_json_push(newflows, g5c_json_new_int(fid));
    }
    pthread_mutex_lock(&n->mu);
    r = res_find(n, API_AQ, af->id, id);
    if (r != NULL) {
        g5c_json_free(r->doc);
        r->doc = doc;
        g5c_json_set(r->ctx, "flows", newflows);
        g5c_resp_json(resp, 200, r->doc);
        newflows = NULL;
    } else {
        g5c_json_free(doc);
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "the subscription was deleted meanwhile");
    }
    pthread_mutex_unlock(&n->mu);
    g5c_json_free(newflows);
    nef_dirty(n);
    free(self);
    free(root);
    free(app);
    g5c_json_free(oldflows);
    g5c_json_free(old);
    g5c_json_free(merged);
    g5c_json_free(body);
    return;
reject:
    g5c_counter_inc(n->c_reject[API_AQ]);
    free(root);
    free(app);
    g5c_json_free(oldflows);
    g5c_json_free(old);
    g5c_json_free(merged);
    g5c_json_free(body);
}

static void h_put(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    h_update(ctx, req, resp, false);
}

static void h_patch(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    h_update(ctx, req, resp, true);
}

static void h_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_AQ);
    const char *id = g5c_req_param(req, "subscriptionId");
    char *root = NULL, *app = NULL, path[200], detail[200];
    res_t *r;
    g5c_resp pr;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_AQ]);
    pthread_mutex_lock(&n->mu);
    r = id != NULL ? res_find(n, API_AQ, af->id, id) : NULL;
    if (r != NULL) {
        root = g5c_xstrdup(g5c_json_get_str(r->ctx, "pcf") != NULL ? g5c_json_get_str(r->ctx, "pcf") : "");
        app = g5c_xstrdup(g5c_json_get_str(r->ctx, "app") != NULL ? g5c_json_get_str(r->ctx, "app") : "");
    }
    pthread_mutex_unlock(&n->mu);
    if (r == NULL) {
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such AS session with QoS subscription");
        return;
    }
    snprintf(path, sizeof path, "%s/%s/delete", PCF_APPS, app);
    if (pcf_call(n, root, "POST", path, NULL, &pr, detail, sizeof detail) != 0) {
        nef_problem(resp, 500, "SYSTEM_FAILURE", detail); /* the PCF still holds the session: the subscription stays */
        free(root);
        free(app);
        g5c_counter_inc(n->c_reject[API_AQ]);
        return;
    }
    if (pr.status >= 300 && pr.status != 404) {
        snprintf(detail, sizeof detail, "PCF answered %d", pr.status);
        nef_problem(resp, 500, "SYSTEM_FAILURE", detail);
        g5c_resp_free(&pr);
        free(root);
        free(app);
        g5c_counter_inc(n->c_reject[API_AQ]);
        return;
    }
    g5c_resp_free(&pr);
    pthread_mutex_lock(&n->mu);
    r = res_find(n, API_AQ, af->id, id);
    if (r != NULL)
        res_remove(n, r);
    pthread_mutex_unlock(&n->mu);
    nef_dirty(n);
    free(root);
    free(app);
    g5c_resp_status(resp, 204);
}

/* ---- from the PCF -------------------------------------------------------------------------------------------------------------- */

static res_t *find_by_id(nef *n, const char *id)
{
    for (size_t i = 0; id != NULL && i < n->nres; i++)
        if (n->res[i]->api == API_AQ && strcmp(n->res[i]->id, id) == 0)
            return n->res[i];
    return NULL;
}

static void callback(nef *n, const g5c_req *req, g5c_resp *resp, bool terminate)
{
    const char *id = g5c_req_param(req, "resId"), *corr = g5c_req_param(req, "corr");
    g5c_json *in = g5c_req_json(req, resp), *note = NULL, *reports;
    res_t *r;
    char *url = NULL, *key = NULL;
    bool found = false, bad = false;
    if (in == NULL)
        return;
    pthread_mutex_lock(&n->mu);
    r = find_by_id(n, id);
    if (r != NULL) {
        found = true;
        if (corr == NULL || !g5c_streq(corr, g5c_json_get_str(r->ctx, "corr"))) {
            bad = true;
        } else {
            note = g5c_json_new_obj();
            g5c_json_set_str(note, "transaction", g5c_json_get_str(r->doc, "self"));
            reports = g5c_json_set(note, "eventReports", g5c_json_new_arr());
            if (terminate) {
                g5c_json_set_str(g5c_json_push(reports, g5c_json_new_obj()), "event", "SESSION_TERMINATION");
            } else {
                const g5c_json *list = g5c_json_get(in, "evNotifs");
                for (size_t i = 0; i < g5c_json_len(list); i++) {
                    const char *ev = g5c_json_get_str(g5c_json_at(list, i), "event");
                    if (ev != NULL && (strcmp(ev, "SUCCESSFUL_RESOURCES_ALLOCATION") == 0 || strcmp(ev, "FAILED_RESOURCES_ALLOCATION") == 0)) {
                        g5c_json *rep = g5c_json_push(reports, g5c_json_new_obj());
                        g5c_json_set_str(rep, "event", ev);
                        if (g5c_json_get(r->ctx, "flows") != NULL)
                            g5c_json_set(rep, "flowIds", g5c_json_dup(g5c_json_get(r->ctx, "flows")));
                    }
                }
            }
            if (g5c_json_len(reports) == 0) {
                g5c_json_free(note);
                note = NULL;
            } else {
                url = g5c_xstrdup(g5c_json_get_str(r->doc, "notificationDestination"));
                key = nef_key(API_AQ, r->af, r->id);
            }
            if (terminate)
                res_remove(n, r);
        }
    }
    pthread_mutex_unlock(&n->mu);
    if (!found) {
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such AS session with QoS subscription");
    } else if (bad) {
        nef_problem(resp, 403, "INVALID_CORRELATION_ID", "the notification correlation identifier does not match");
    } else {
        g5c_resp_status(resp, 204);
        if (note != NULL && url != NULL)
            nef_enqueue(n, url, g5c_json_to_string(note, NULL), key, 0);
        if (terminate)
            nef_dirty(n);
    }
    g5c_json_free(note);
    g5c_json_free(in);
    free(url);
    free(key);
}

static void h_pcf_notify(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    callback(ctx, req, resp, false);
}

static void h_pcf_terminate(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    callback(ctx, req, resp, true);
}

void as_routes(g5c_router *r, nef *n)
{
    g5c_router_route(r, "GET", AQ_BASE "/{afId}/subscriptions", h_list, n);
    g5c_router_route(r, "POST", AQ_BASE "/{afId}/subscriptions", h_post, n);
    g5c_router_route(r, "GET", AQ_BASE "/{afId}/subscriptions/{subscriptionId}", h_get, n);
    g5c_router_route(r, "PUT", AQ_BASE "/{afId}/subscriptions/{subscriptionId}", h_put, n);
    g5c_router_route(r, "PATCH", AQ_BASE "/{afId}/subscriptions/{subscriptionId}", h_patch, n);
    g5c_router_route(r, "DELETE", AQ_BASE "/{afId}/subscriptions/{subscriptionId}", h_delete, n);
    g5c_router_route(r, "POST", CB_BASE "/pcf-events/{resId}/{corr}/notify", h_pcf_notify, n);
    g5c_router_route(r, "POST", CB_BASE "/pcf-events/{resId}/{corr}/terminate", h_pcf_terminate, n);
}
