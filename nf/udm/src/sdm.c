/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nudm_SubscriberDataManagement (TS 29.503 clause 5.2): subscription data retrieval and change subscriptions */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/udm.h"

typedef struct {
    udm *u;
    int which;
} sctx;

enum { S_AM, S_SM, S_NSSAI, S_SMFSEL, S_UECTX, S_MULTI, S_SUB_POST, S_SUB_DELETE, S_SUB_PATCH };

/* Resolve the SUPI path parameter; on failure fill resp and return false. */
static bool supi_of(const g5c_req *req, char *out, size_t cap, g5c_resp *resp)
{
    const char *s = g5c_req_param(req, "supi");
    if (udm_resolve(s ? s : "", NULL, 0, out, cap) != 0) {
        g5c_resp_problem_simple(resp, 400, "MANDATORY_IE_INCORRECT", "supi must be imsi-...");
        return false;
    }
    return true;
}

static void plmn_of(const udm *u, const g5c_req *req, char *out, size_t cap)
{
    char *q = g5c_req_query_decoded(req, "plmn-id");
    if (q == NULL || !udm_plmn_from_query(q, out, cap))
        snprintf(out, cap, "%s", u->plmn);
    free(q);
}

static void user_or_data(const udr_result *r, g5c_resp *resp)
{
    udm_udr_fail(r, "DATA_NOT_FOUND", resp);
}

static void reply_json(g5c_resp *resp, int code, g5c_json *j)
{
    g5c_resp_json(resp, code, j);
    g5c_json_free(j);
}

/* UeContextInSmfData built from the SMF registrations held in the UDR */
static udr_result ue_context_in_smf(udm *u, const char *supi, g5c_json **out)
{
    g5c_json *o = g5c_json_new_obj(), *sessions = g5c_json_set(o, "pduSessions", g5c_json_new_obj()), *v = NULL;
    udr_result r = udm_udr_smf_registrations(&u->udr, supi, &v);
    *out = o;
    if (r.kind != UDR_OK) {
        if (r.kind != UDR_NOT_FOUND) {
            g5c_json_free(o);
            *out = NULL;
        }
        return r;
    }
    for (size_t i = 0; i < g5c_json_len(v); i++) {
        const g5c_json *reg = g5c_json_at(v, i), *pid = g5c_json_get(reg, "pduSessionId"), *x;
        char *id = NULL, keybuf[32];
        g5c_json *e;
        int64_t n;
        if (g5c_json_str(pid) != NULL) {
            id = g5c_xstrdup(g5c_json_str(pid));
        } else if (g5c_json_int(pid, &n)) {
            snprintf(keybuf, sizeof keybuf, "%lld", (long long)n);
            id = g5c_xstrdup(keybuf);
        } else {
            id = g5c_xstrdup("");
        }
        e = g5c_json_set(sessions, id, g5c_json_new_obj());
        free(id);
        x = g5c_json_get(reg, "dnn");
        g5c_json_set(e, "dnn", x ? g5c_json_dup(x) : g5c_json_new_null());
        x = g5c_json_get(reg, "smfInstanceId");
        g5c_json_set(e, "smfInstanceId", x ? g5c_json_dup(x) : g5c_json_new_null());
        x = g5c_json_get(reg, "plmnId");
        g5c_json_set(e, "plmnId", x ? g5c_json_dup(x) : g5c_json_new_null());
    }
    g5c_json_free(v);
    return r;
}

/* Retrieval of multiple data sets (TS 29.503 5.2.2.2.9): GET /{supi}?dataset-names=AM,SM,. returns SubscriptionDataSets */
static void multi_data_sets(udm *u, const g5c_req *req, const char *supi, const char *plmn, g5c_resp *resp)
{
    char *names = g5c_req_query_decoded(req, "dataset-names");
    char *save = NULL, *tok;
    size_t distinct = 0;
    bool want_am = false, want_sel = false, want_sm = false, want_uec = false;
    g5c_json *out;
    udr_result r;
    g5c_json *v = NULL;

    if (names == NULL) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_MISSING", "dataset-names", "absent");
        return;
    }
    for (tok = strtok_r(names, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save)) {
        bool *flag = strcmp(tok, "AM") == 0 ? &want_am : strcmp(tok, "SMF_SEL") == 0 ? &want_sel
                     : strcmp(tok, "SM") == 0 ? &want_sm : strcmp(tok, "UEC_SMF") == 0 ? &want_uec : NULL;
        if (flag != NULL && *flag) {
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "dataset-names", "names must be unique");
            free(names);
            return;
        }
        if (flag != NULL)
            *flag = true;
        distinct++;
    }
    free(names);
    if (distinct < 2) { /* DatasetNames: minItems 2 */
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "dataset-names", "at least two data sets are required");
        return;
    }
    out = g5c_json_new_obj();
    if (want_am) {
        r = udm_udr_am_data(&u->udr, supi, plmn, &v);
        if (r.kind != UDR_OK)
            goto fail;
        g5c_json_set(out, "amData", v);
    }
    if (want_sel) {
        v = NULL;
        r = udm_udr_smf_selection(&u->udr, supi, plmn, &v);
        if (r.kind != UDR_OK)
            goto fail;
        g5c_json_set(out, "smfSelData", v);
    }
    if (want_sm) {
        v = NULL;
        r = udm_udr_sm_data(&u->udr, supi, plmn, NULL, NULL, &v);
        if (r.kind != UDR_OK)
            goto fail;
        g5c_json_set(out, "smData", v);
    }
    if (want_uec) {
        v = NULL;
        r = ue_context_in_smf(u, supi, &v);
        if (r.kind != UDR_OK && r.kind != UDR_NOT_FOUND)
            goto fail;
        g5c_json_set(out, "uecSmfData", v);
    }
    reply_json(resp, 200, out);
    return;
fail:
    g5c_json_free(out);
    user_or_data(&r, resp);
}

static void sdm(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    sctx *c = ctx;
    udm *u = c->u;
    char supi[48], plmn[16];
    g5c_json *v = NULL;
    udr_result r;

    if (!supi_of(req, supi, sizeof supi, resp))
        return;
    plmn_of(u, req, plmn, sizeof plmn);

    switch (c->which) {
    case S_AM:
        r = udm_udr_am_data(&u->udr, supi, plmn, &v);
        if (r.kind == UDR_OK)
            reply_json(resp, 200, v);
        else
            user_or_data(&r, resp);
        break;
    case S_SM: {
        char *nssai = g5c_req_query_decoded(req, "single-nssai"), *dnn = g5c_req_query_decoded(req, "dnn");
        r = udm_udr_sm_data(&u->udr, supi, plmn, nssai, dnn, &v);
        free(nssai);
        free(dnn);
        if (r.kind == UDR_OK)
            reply_json(resp, 200, v);
        else
            user_or_data(&r, resp);
        break;
    }
    case S_NSSAI:
        r = udm_udr_am_data(&u->udr, supi, plmn, &v);
        if (r.kind == UDR_OK) {
            const g5c_json *n = g5c_json_get(v, "nssai");
            if (n != NULL)
                g5c_resp_json(resp, 200, n);
            else
                g5c_resp_problem_simple(resp, 404, "DATA_NOT_FOUND", NULL);
            g5c_json_free(v);
        } else {
            user_or_data(&r, resp);
        }
        break;
    case S_SMFSEL:
        r = udm_udr_smf_selection(&u->udr, supi, plmn, &v);
        if (r.kind == UDR_OK)
            reply_json(resp, 200, v);
        else
            user_or_data(&r, resp);
        break;
    case S_UECTX: {
        g5c_json *out = NULL;
        r = ue_context_in_smf(u, supi, &out);
        if (r.kind == UDR_OK || r.kind == UDR_NOT_FOUND) /* no registrations is an empty, valid UeContextInSmfData */
            reply_json(resp, 200, out);
        else
            user_or_data(&r, resp);
        break;
    }
    case S_MULTI:
        multi_data_sets(u, req, supi, plmn, resp);
        break;
    case S_SUB_POST: {
        g5c_json *sub = g5c_req_json(req, resp), *auth = NULL;
        char id[24], *key, *path, *loc;
        if (sub == NULL)
            return;
        if (g5c_json_get_str(sub, "callbackReference") == NULL) {
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", "callbackReference", "absent");
            g5c_json_free(sub);
            return;
        }
        r = udm_udr_auth_subscription(&u->udr, supi, &auth); /* subscriptions only make sense for existing subscribers */
        g5c_json_free(auth);
        if (r.kind != UDR_OK) {
            udm_udr_fail(&r, "USER_NOT_FOUND", resp);
            g5c_json_free(sub);
            return;
        }
        pthread_mutex_lock(&u->mu);
        snprintf(id, sizeof id, "%llu", (unsigned long long)u->next_sub++);
        g5c_json_set_str(sub, "subscriptionId", id);
        key = g5c_xasprintf("%s/%s", supi, id);
        g5c_json_set(u->sdm_subs, key, g5c_json_dup(sub));
        pthread_mutex_unlock(&u->mu);
        path = g5c_xasprintf("/nudm-sdm/v2/%s/sdm-subscriptions/%s", supi, id);
        loc = g5c_req_url(req, path);
        g5c_resp_json(resp, 201, sub);
        g5c_resp_header(resp, "location", loc);
        free(key);
        free(path);
        free(loc);
        g5c_json_free(sub);
        break;
    }
    case S_SUB_DELETE:
    case S_SUB_PATCH: {
        const char *id = g5c_req_param(req, "subscriptionId");
        char *key = g5c_xasprintf("%s/%s", supi, id ? id : "");
        bool had;
        pthread_mutex_lock(&u->mu);
        had = c->which == S_SUB_DELETE ? g5c_json_remove(u->sdm_subs, key) : g5c_json_get(u->sdm_subs, key) != NULL;
        pthread_mutex_unlock(&u->mu);
        free(key);
        if (had)
            g5c_resp_status(resp, 204);
        else
            g5c_resp_problem_simple(resp, 404, "SUBSCRIPTION_NOT_FOUND", NULL);
        break;
    }
    }
}

static void add(g5c_router *r, udm *u, const char *method, const char *v, const char *tail, int which)
{
    sctx *c = g5c_xcalloc(1, sizeof *c);
    char *path = g5c_xasprintf("/nudm-sdm/%s/{supi}%s", v, tail);
    c->u = u;
    c->which = which;
    g5c_router_route(r, method, path, sdm, c);
    free(path);
    udm_track(u, c);
}

/* Nudm_SDM id translation (TS 29.503 5.2.2.7, IdTranslationResult): the SUPI of a GPSI, from the identity data in the UDR. */
static bool gpsi_ok(const char *s)
{
    size_t n = s == NULL ? 0 : strlen(s);
    if (n < 8 || n > 128 || (strncmp(s, "msisdn-", 7) != 0 && strncmp(s, "extid-", 6) != 0))
        return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') || s[i] == '-' || s[i] == '.' || s[i] == '_' || s[i] == '@'))
            return false;
    return true;
}

static void id_translation(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    char *ue = g5c_percent_decode(g5c_req_param(req, "ueId") != NULL ? g5c_req_param(req, "ueId") : "");
    g5c_json *id = NULL, *o;
    const char *supi;
    udr_result r;
    if (ue == NULL || !gpsi_ok(ue)) {
        g5c_resp_problem_simple(resp, 400, "MANDATORY_IE_INCORRECT", "ueId must be a GPSI (msisdn-... or extid-...)");
        free(ue);
        return;
    }
    r = udm_udr_identity(&u->udr, ue, &id);
    if (r.kind != UDR_OK) {
        udm_udr_fail(&r, "USER_NOT_FOUND", resp);
        free(ue);
        return;
    }
    supi = g5c_json_str(g5c_json_at(g5c_json_get(id, "supiList"), 0));
    if (supi == NULL) {
        g5c_resp_problem_simple(resp, 404, "USER_NOT_FOUND", "no SUPI is known for the GPSI");
        g5c_json_free(id);
        free(ue);
        return;
    }
    o = g5c_json_new_obj();
    g5c_json_set_str(o, "supi", supi);
    g5c_json_set_str(o, "gpsi", ue);
    g5c_resp_json(resp, 200, o);
    g5c_json_free(o);
    g5c_json_free(id);
    free(ue);
}

void udm_sdm_routes(g5c_router *r, udm *u)
{
    static const char *const versions[] = {"v2", "v1"};
    for (size_t i = 0; i < 2; i++) {
        const char *v = versions[i];
        {
            char *p = g5c_xasprintf("/nudm-sdm/%s/{ueId}/id-translation-result", v);
            g5c_router_route(r, "GET", p, id_translation, u);
            free(p);
        }
        add(r, u, "GET", v, "/am-data", S_AM);
        add(r, u, "GET", v, "/sm-data", S_SM);
        add(r, u, "GET", v, "/nssai", S_NSSAI);
        add(r, u, "GET", v, "/smf-select-data", S_SMFSEL);
        add(r, u, "GET", v, "/ue-context-in-smf-data", S_UECTX);
        add(r, u, "GET", v, "", S_MULTI);
        add(r, u, "POST", v, "/sdm-subscriptions", S_SUB_POST);
        add(r, u, "DELETE", v, "/sdm-subscriptions/{subscriptionId}", S_SUB_DELETE);
        add(r, u, "PATCH", v, "/sdm-subscriptions/{subscriptionId}", S_SUB_PATCH);
    }
}

/* Nudm_SDM_Notification (TS 29.503 5.2.2.4) */
void udm_sdm_notify_change(udm *u, const char *supi)
{
    char prefix[64];
    g5c_json *todo = g5c_json_new_arr();
    size_t plen;
    snprintf(prefix, sizeof prefix, "%s/", supi);
    plen = strlen(prefix);
    pthread_mutex_lock(&u->mu);
    for (size_t i = 0; i < g5c_json_len(u->sdm_subs); i++) {
        const char *k = g5c_json_key_at(u->sdm_subs, i);
        if (strncmp(k, prefix, plen) == 0)
            g5c_json_push(todo, g5c_json_dup(g5c_json_val_at(u->sdm_subs, i)));
    }
    pthread_mutex_unlock(&u->mu);
    for (size_t i = 0; i < g5c_json_len(todo); i++) {
        const g5c_json *sub = g5c_json_at(todo, i), *uris = g5c_json_get(sub, "monitoredResourceUris");
        const char *cb = g5c_json_get_str(sub, "callbackReference");
        g5c_json *body = g5c_json_new_obj(), *items = g5c_json_set(body, "notifyItems", g5c_json_new_arr());
        g5c_resp r;
        char err[160];
        const char *result = "ok";
        static const char *const dflt[] = {"/am-data", "/sm-data", "/nssai", "/smf-select-data"};
        if (cb == NULL) {
            g5c_json_free(body);
            continue;
        }
        for (size_t k = 0; k < (g5c_json_len(uris) ? g5c_json_len(uris) : 4); k++) {
            g5c_json *it = g5c_json_push(items, g5c_json_new_obj()), *chg;
            if (g5c_json_len(uris)) {
                g5c_json_set_str(it, "resourceId", g5c_json_str(g5c_json_at(uris, k)) ? g5c_json_str(g5c_json_at(uris, k)) : "/");
            } else {
                char *rid = g5c_xasprintf("/%s%s", supi, dflt[k]);
                g5c_json_set_str(it, "resourceId", rid);
                free(rid);
            }
            chg = g5c_json_push(g5c_json_set(it, "changes", g5c_json_new_arr()), g5c_json_new_obj());
            g5c_json_set_str(chg, "op", "REPLACE");
            g5c_json_set_str(chg, "path", "/");
        }
        if (g5c_client_send_json(u->client, "POST", cb, body, &r, err, sizeof err) == 0) {
            if (r.status < 200 || r.status > 299) {
                result = "rejected";
                G5C_LOGW("g5c_udm", "SDM subscriber %s rejected the change notification (%d)", cb, r.status);
            }
            g5c_resp_free(&r);
        } else {
            result = "unreachable";
            G5C_LOGW("g5c_udm", "SDM subscriber %s unreachable: %s", cb, err);
        }
        {
            g5c_label l = {"result", result};
            g5c_counter_inc(g5c_counter_get(u->metrics, "g5c_udm_sdm_notifications_total",
                                            "SDM data-change notifications sent to subscribers.", &l, 1));
        }
        g5c_json_free(body);
    }
    g5c_json_free(todo);
}
