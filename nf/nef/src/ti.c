#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The TrafficInfluence API (TS 29.522 5.4, procedures 4.4.7): an AF's requirement for the routing of the traffic of a UE, of a group of UEs or of any
 * UE. A request that is not identified by an address of the UE is stored as application (influence) data in the UDR (Nudr_DataRepository,
 * TS 29.519 6.2.6.2.2 TrafficInfluData), from where the PCF and the SMF read it (4.4.7.3). A request identified by an address of the UE goes to
 * the PCF (4.4.7.2): not supported yet, answered 501. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

#define F_TEST_EVENT 0x2u /* feature 2, Notification_test_event (TS 29.522 5.4.4) */
#define F_OURS F_TEST_EVENT
#define UDR_INFLU "/nudr-dr/v1/application-data/influenceData/"

static char *self_url(const g5c_req *req, const char *af, const char *id)
{
    char *path = g5c_xasprintf(TI_BASE "/%s/subscriptions/%s", af, id), *u = g5c_req_url(req, path);
    free(path);
    return u;
}

/* ---- the other functions ---------------------------------------------------------------------------------------------- */

/* the SUPI of a GPSI; 0 on success, else the HTTP status to answer */
static int udm_supi_of(nef *n, const char *gpsi, char **supi, char *detail, size_t dcap)
{
    char *root = nef_root(n, n->cfg->udm_uri, "UDM", "nudm-sdm"), *enc = pct_encode(gpsi), *path;
    g5c_resp r;
    char err[160];
    int rc, status = 0;
    if (root == NULL) {
        snprintf(detail, dcap, "no UDM to resolve the GPSI");
        free(enc);
        return 500;
    }
    path = g5c_xasprintf("/nudm-sdm/v2/%s/id-translation-result", enc);
    rc = nef_peer(n, root, "GET", path, NULL, &r, err, sizeof err);
    free(path);
    free(enc);
    if (rc != 0) {
        snprintf(detail, dcap, "UDM: %s", err);
        nef_call_failed(n, 1);
        status = 500;
    } else {
        if (r.status == 200) {
            g5c_json *j = g5c_resp_parse_json(&r);
            const char *s = g5c_json_get_str(j, "supi");
            if (s != NULL)
                *supi = g5c_xstrdup(s);
            else
                status = 500;
            g5c_json_free(j);
            if (status != 0)
                snprintf(detail, dcap, "UDM answered without a SUPI");
        } else {
            snprintf(detail, dcap, "UDM answered %d for the GPSI", r.status);
            status = r.status == 404 ? 404 : 500;
        }
        g5c_resp_free(&r);
    }
    free(root);
    return status;
}

static int udr_call(nef *n, const char *method, const char *id, const g5c_json *body, int *http, char *detail, size_t dcap)
{
    char *root = nef_root(n, n->cfg->udr_uri, "UDR", "nudr-dr"), *path;
    g5c_resp r;
    char err[160];
    int rc;
    *http = 0;
    if (root == NULL) {
        snprintf(detail, dcap, "no UDR to keep the influence data");
        return -1;
    }
    path = g5c_xasprintf(UDR_INFLU "%s", id);
    rc = nef_peer(n, root, method, path, body, &r, err, sizeof err);
    free(path);
    free(root);
    if (rc != 0) {
        snprintf(detail, dcap, "UDR: %s", err);
        nef_call_failed(n, 0);
        g5c_counter_inc(n->c_udr_fail);
        return -1;
    }
    *http = r.status;
    if (r.status >= 300) {
        char *cause = g5c_resp_problem_cause(&r);
        g5c_json *pj = g5c_resp_parse_json(&r);
        const g5c_json *ip = g5c_json_at(g5c_json_get(pj, "invalidParams"), 0);
        snprintf(detail, dcap, "UDR answered %d%s%s%s%s%s%s", r.status, cause != NULL ? " " : "", cause != NULL ? cause : "", ip != NULL ? " at " : "",
                 g5c_json_get_str(ip, "param") != NULL ? g5c_json_get_str(ip, "param") : "", ip != NULL ? ": " : "", g5c_json_get_str(ip, "reason") != NULL ? g5c_json_get_str(ip, "reason") : (g5c_json_get_str(pj, "detail") != NULL ? g5c_json_get_str(pj, "detail") : ""));
        g5c_json_free(pj);
        free(cause);
        g5c_counter_inc(n->c_udr_fail);
    }
    g5c_resp_free(&r);
    return 0;
}

/* ---- TrafficInfluSub -> TrafficInfluData (TS 29.519 6.2.6.2.2) ------------------------------------------------------ */

static void copy_member(g5c_json *to, const char *to_key, const g5c_json *from, const char *from_key)
{
    const g5c_json *v = g5c_json_get(from, from_key);
    if (v != NULL && !g5c_json_is(v, G5C_J_NULL))
        g5c_json_set(to, to_key, g5c_json_dup(v));
}

static g5c_json *influence_data(const g5c_json *sub, const char *supi, const char *corr_id, const char *notif_uri, const char *res_uri)
{
    g5c_json *d = g5c_json_new_obj();
    bool any = false;
    copy_member(d, "afAppId", sub, "afAppId");
    copy_member(d, "appReloInd", sub, "appReloInd");
    copy_member(d, "dnn", sub, "dnn");
    copy_member(d, "snssai", sub, "snssai");
    copy_member(d, "trafficFilters", sub, "trafficFilters");
    copy_member(d, "ethTrafficFilters", sub, "ethTrafficFilters");
    copy_member(d, "trafficRoutes", sub, "trafficRoutes");
    copy_member(d, "traffCorreInd", sub, "tfcCorrInd");
    copy_member(d, "tempValidities", sub, "tempValidities");
    copy_member(d, "subscribedEvents", sub, "subscribedEvents");
    copy_member(d, "dnaiChgType", sub, "dnaiChgType");
    copy_member(d, "afAckInd", sub, "afAckInd");
    copy_member(d, "addrPreserInd", sub, "addrPreserInd");
    copy_member(d, "supportedFeatures", sub, "suppFeat");
    if (supi != NULL)
        g5c_json_set_str(d, "supi", supi);
    else if (g5c_json_get_bool(sub, "anyUeInd", &any) && any)
        g5c_json_set_str(d, "interGroupId", "AnyUE");
    if (g5c_json_get(sub, "subscribedEvents") != NULL) {
        g5c_json_set_str(d, "upPathChgNotifCorreId", corr_id);
        g5c_json_set_str(d, "upPathChgNotifUri", notif_uri);
    }
    g5c_json_set_str(d, "resUri", res_uri);
    return d;
}

/* ---- the resource -------------------------------------------------------------------------------------------------------- */

typedef struct {
    nef *n;
    const nef_af *af;
} tictx;

static bool request_ok(nef *n, const nef_af *af, g5c_json *sub, g5c_resp *resp)
{
    bool b;
    const char *dest = g5c_json_get_str(sub, "notificationDestination");
    if (g5c_json_get(sub, "subscribedEvents") != NULL && dest == NULL) {
        nef_invalid(resp, 400, "INVALID_REQUEST", "/notificationDestination", "required when subscribedEvents is present");
        return false;
    }
    if (dest != NULL && !notify_host_allowed(af, dest)) {
        nef_problem(resp, 403, "NOTIFICATION_DESTINATION_NOT_ALLOWED", "the notification destination is not a host this AF may name");
        return false;
    }
    if (g5c_json_get_bool(sub, "anyUeInd", &b) && !b && g5c_json_get(sub, "gpsi") == NULL && g5c_json_get(sub, "externalGroupId") == NULL &&
        g5c_json_get(sub, "ipv4Addr") == NULL && g5c_json_get(sub, "ipv6Addr") == NULL && g5c_json_get(sub, "macAddr") == NULL) {
        nef_invalid(resp, 400, "INVALID_REQUEST", "/anyUeInd", "no UE is identified");
        return false;
    }
    (void)n;
    return true;
}

/* Makes (or replaces) the influence data of a subscription at the UDR. `sub` is the whole representation. 0 on success, else the status to answer
 * with the detail in `detail`. */
static int provision(nef *n, const g5c_req *req, const nef_af *af, const char *id, const g5c_json *sub, const char *corr_id, int *created, char *detail, size_t dcap)
{
    char *supi = NULL, *res = self_url(req, af->id, id), *notif = NULL;
    g5c_json *d;
    int http = 0, st;
    bool any = false;
    const char *gpsi = g5c_json_get_str(sub, "gpsi");
    *created = 0;
    if (g5c_json_get(sub, "ipv4Addr") != NULL || g5c_json_get(sub, "ipv6Addr") != NULL || g5c_json_get(sub, "macAddr") != NULL) {
        snprintf(detail, dcap, "a request identified by the address of the UE is served through the PCF, which the NEF does not reach yet");
        st = 501;
        goto done;
    }
    if (g5c_json_get(sub, "externalGroupId") != NULL) {
        snprintf(detail, dcap, "a request for a group of UEs needs the group identifier translation of the UDM, which the NEF does not use yet");
        st = 501;
        goto done;
    }
    if (gpsi != NULL && (st = udm_supi_of(n, gpsi, &supi, detail, dcap)) != 0)
        goto done;
    if (supi == NULL && !(g5c_json_get_bool(sub, "anyUeInd", &any) && any)) {
        snprintf(detail, dcap, "no UE is identified");
        st = 400;
        goto done;
    }
    if (g5c_json_get(sub, "subscribedEvents") != NULL) {
        char *p = g5c_xasprintf(CB_BASE "/up-path-change/%s", id);
        notif = nef_self_url(n, p);
        free(p);
        if (notif == NULL) {
            snprintf(detail, dcap, "the NEF has no callback address for UP path change notifications");
            st = 500;
            goto done;
        }
    }
    d = influence_data(sub, supi, corr_id, notif != NULL ? notif : "", res);
    if (udr_call(n, "PUT", id, d, &http, detail, dcap) != 0) {
        g5c_json_free(d);
        st = 500;
        goto done;
    }
    g5c_json_free(d);
    if (http == 201) {
        *created = 1;
        st = 0;
    } else if (http == 200 || http == 204) {
        st = 0;
    } else {
        st = peer_status(http);
    }
done:
    free(supi);
    free(res);
    free(notif);
    return st;
}

static g5c_json *representation(const g5c_json *body, unsigned negotiated, const char *self)
{
    g5c_json *doc = g5c_json_dup(body);
    char *f = feat_str(negotiated);
    g5c_json_remove(doc, "suppFeat");
    if (g5c_json_get(body, "suppFeat") != NULL)
        g5c_json_set_str(doc, "suppFeat", f != NULL ? f : "0");
    free(f);
    g5c_json_set_str(doc, "self", self);
    return doc;
}

static void send_test(nef *n, const char *dest, const char *self, const char *key)
{
    g5c_json *t = g5c_json_new_obj();
    g5c_json_set_str(t, "subscription", self);
    nef_enqueue(n, dest, g5c_json_to_string(t, NULL), key, 0);
    g5c_json_free(t);
}

static void h_post(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af;
    g5c_json *body, *doc, *cx;
    char id[37], corr[33], detail[200], *self, *key;
    int created, st;
    unsigned feat;
    res_t *r;
    af = af_auth(n, req, resp, API_TI);
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_TI]);
    body = g5c_req_json(req, resp);
    if (body == NULL || !nef_body_ok(n, body, NEF_SCH_TRAFFIC_INFLU_SUB, resp) || !request_ok(n, af, body, resp)) {
        if (body != NULL || resp->status != 0)
            g5c_counter_inc(n->c_reject[API_TI]);
        g5c_json_free(body);
        return;
    }
    pthread_mutex_lock(&n->mu);
    if (res_count(n, API_TI, af->id) >= af->max_subs) {
        pthread_mutex_unlock(&n->mu);
        nef_problem(resp, 429, "TOO_MANY_SUBSCRIPTIONS", "the AF has the most subscriptions it may have");
        g5c_counter_inc(n->c_reject[API_TI]);
        g5c_json_free(body);
        return;
    }
    pthread_mutex_unlock(&n->mu);
    g5c_uuid_v4(id);
    {
        uint8_t rnd[16];
        g5c_random(rnd, sizeof rnd);
        for (int i = 0; i < 16; i++)
            snprintf(corr + 2 * i, 3, "%02x", rnd[i]);
    }
    self = self_url(req, af->id, id);
    st = provision(n, req, af, id, body, corr, &created, detail, sizeof detail);
    if (st != 0) {
        nef_problem(resp, st, st == 501 ? "NOT_SUPPORTED" : st == 404 ? "USER_NOT_FOUND" : "SYSTEM_FAILURE", detail);
        g5c_counter_inc(n->c_reject[API_TI]);
        free(self);
        g5c_json_free(body);
        return;
    }
    feat = feat_parse(g5c_json_get_str(body, "suppFeat")) & F_OURS;
    doc = representation(body, feat, self);
    cx = g5c_json_new_obj();
    g5c_json_set_str(cx, "corr", corr);
    g5c_json_set_int(cx, "features", feat);
    pthread_mutex_lock(&n->mu);
    r = res_add(n, API_TI, af->id, id, doc, cx);
    nef_reply_res(resp, 201, r, req, TI_BASE);
    pthread_mutex_unlock(&n->mu);
    nef_dirty(n);
    {
        bool want = false;
        if ((feat & F_TEST_EVENT) != 0 && g5c_json_get_bool(body, "requestTestNotification", &want) && want && g5c_json_get_str(body, "notificationDestination") != NULL) {
            key = nef_key(API_TI, af->id, id);
            send_test(n, g5c_json_get_str(body, "notificationDestination"), self, key);
            free(key);
        }
    }
    free(self);
    g5c_json_free(body);
}

static void h_list(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_TI);
    g5c_json *arr;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_TI]);
    arr = g5c_json_new_arr();
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < n->nres; i++)
        if (n->res[i]->api == API_TI && strcmp(n->res[i]->af, af->id) == 0)
            g5c_json_push(arr, g5c_json_dup(n->res[i]->doc));
    pthread_mutex_unlock(&n->mu);
    g5c_resp_json(resp, 200, arr);
    g5c_json_free(arr);
}

static void h_get(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_TI);
    res_t *r;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_TI]);
    pthread_mutex_lock(&n->mu);
    r = res_find(n, API_TI, af->id, g5c_req_param(req, "subscriptionId") != NULL ? g5c_req_param(req, "subscriptionId") : "");
    if (r != NULL)
        g5c_resp_json(resp, 200, r->doc);
    pthread_mutex_unlock(&n->mu);
    if (r == NULL)
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such traffic influence subscription");
}

/* PUT (replace) and PATCH (merge patch) */
static void h_update(void *ctx, const g5c_req *req, g5c_resp *resp, bool patch)
{
    nef *n = ctx;
    const nef_af *af = af_auth(n, req, resp, API_TI);
    const char *id = g5c_req_param(req, "subscriptionId");
    g5c_json *body, *merged = NULL, *old = NULL, *doc;
    char detail[200], corr[40] = "", *self;
    res_t *r;
    int created, st;
    unsigned feat = 0;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_TI]);
    body = g5c_req_json(req, resp);
    if (body == NULL)
        return;
    if (!nef_body_ok(n, body, patch ? NEF_SCH_TRAFFIC_INFLU_SUB_PATCH : NEF_SCH_TRAFFIC_INFLU_SUB, resp))
        goto reject;
    pthread_mutex_lock(&n->mu);
    r = id != NULL ? res_find(n, API_TI, af->id, id) : NULL;
    if (r != NULL) {
        old = g5c_json_dup(r->doc);
        snprintf(corr, sizeof corr, "%s", g5c_json_get_str(r->ctx, "corr") != NULL ? g5c_json_get_str(r->ctx, "corr") : "");
        {
            int64_t f;
            if (g5c_json_get_int(r->ctx, "features", &f))
                feat = (unsigned)f;
        }
    }
    pthread_mutex_unlock(&n->mu);
    if (old == NULL) {
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such traffic influence subscription");
        goto reject;
    }
    if (patch) {
        merged = old;
        old = g5c_json_dup(merged);
        merge_patch(&merged, body);
        if (!nef_body_ok(n, merged, NEF_SCH_TRAFFIC_INFLU_SUB, resp))
            goto reject;
    } else {
        merged = g5c_json_dup(body);
    }
    if (!request_ok(n, af, merged, resp))
        goto reject;
    if (corr[0] == '\0')
        snprintf(corr, sizeof corr, "%s", "0");
    self = self_url(req, af->id, id);
    st = provision(n, req, af, id, merged, corr, &created, detail, sizeof detail);
    if (st != 0) {
        nef_problem(resp, st, st == 501 ? "NOT_SUPPORTED" : st == 404 ? "USER_NOT_FOUND" : "SYSTEM_FAILURE", detail);
        free(self);
        goto reject;
    }
    if (patch) {
        g5c_json_free(body);
        body = merged;
        merged = NULL;
    }
    doc = representation(body, feat, self);
    pthread_mutex_lock(&n->mu);
    r = res_find(n, API_TI, af->id, id);
    if (r != NULL) {
        g5c_json_free(r->doc);
        r->doc = doc;
        g5c_resp_json(resp, 200, r->doc);
    } else {
        g5c_json_free(doc);
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "the subscription was deleted meanwhile");
    }
    pthread_mutex_unlock(&n->mu);
    nef_dirty(n);
    free(self);
    g5c_json_free(old);
    g5c_json_free(merged);
    g5c_json_free(body);
    return;
reject:
    g5c_counter_inc(n->c_reject[API_TI]);
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
    const nef_af *af = af_auth(n, req, resp, API_TI);
    const char *id = g5c_req_param(req, "subscriptionId");
    char detail[200];
    int http = 0;
    res_t *r;
    bool exists;
    if (af == NULL)
        return;
    g5c_counter_inc(n->c_req[API_TI]);
    pthread_mutex_lock(&n->mu);
    exists = id != NULL && res_find(n, API_TI, af->id, id) != NULL;
    pthread_mutex_unlock(&n->mu);
    if (!exists) {
        nef_problem(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such traffic influence subscription");
        return;
    }
    if (udr_call(n, "DELETE", id, NULL, &http, detail, sizeof detail) != 0 || (http >= 300 && http != 404)) {
        nef_problem(resp, 500, "SYSTEM_FAILURE", detail);
        g5c_counter_inc(n->c_reject[API_TI]);
        return;
    }
    pthread_mutex_lock(&n->mu);
    r = res_find(n, API_TI, af->id, id);
    if (r != NULL)
        res_remove(n, r);
    pthread_mutex_unlock(&n->mu);
    nef_dirty(n);
    g5c_resp_status(resp, 204);
}

void ti_routes(g5c_router *r, nef *n)
{
    g5c_router_route(r, "GET", TI_BASE "/{afId}/subscriptions", h_list, n);
    g5c_router_route(r, "POST", TI_BASE "/{afId}/subscriptions", h_post, n);
    g5c_router_route(r, "GET", TI_BASE "/{afId}/subscriptions/{subscriptionId}", h_get, n);
    g5c_router_route(r, "PUT", TI_BASE "/{afId}/subscriptions/{subscriptionId}", h_put, n);
    g5c_router_route(r, "PATCH", TI_BASE "/{afId}/subscriptions/{subscriptionId}", h_patch, n);
    g5c_router_route(r, "DELETE", TI_BASE "/{afId}/subscriptions/{subscriptionId}", h_delete, n);
}
