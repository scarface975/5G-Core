/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Npcf_SMPolicyControl (TS 29.512 clause 5): SM policy associations and notifications to the SMF. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/pcf.h"

#define BASE "/npcf-smpolicycontrol/v1/sm-policies"

static void not_found(g5c_resp *resp)
{
    g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "no such SM policy association");
}

static void bad_request(g5c_resp *resp, const char *field, const char *reason)
{
    g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", field, reason);
}

static void unavailable(g5c_resp *resp)
{
    g5c_resp_problem_simple(resp, 503, "UNSPECIFIED", "policy data unavailable");
}

static void count_req(pcf *p, const char *result)
{
    g5c_label l = {"result", result};
    g5c_counter_inc(g5c_counter_get(p->metrics, "g5c_pcf_sm_policy_requests_total", "SM policy requests by result.", &l, 1));
}

static void update_gauge(pcf *p)
{
    g5c_gauge_set(g5c_gauge_get(p->metrics, "g5c_pcf_sm_policies_active", "Active SM policy associations.", NULL, 0),
                  (int64_t)pcf_session_count(p));
}

static void count_notif(pcf *p, const char *result)
{
    g5c_label l = {"result", result};
    g5c_counter_inc(g5c_counter_get(p->metrics, "g5c_pcf_sm_policy_notifications_total", "Policy notifications sent to the SMF.", &l, 1));
}

/* Load the subscriber's overrides. Returns false when the policy data is unavailable. *have: there are overrides. */
static bool load_sub(pcf *p, const char *supi, pcf_policy *sub, bool *have)
{
    pcf_store_rc rc = pcf_store_get(p, supi, sub);
    *have = rc == PCF_STORE_OK;
    return rc != PCF_STORE_ERROR;
}

static pcf_sm_session *find(pcf *p, const char *id)
{
    for (size_t i = 0; i < p->nsessions; i++)
        if (strcmp(p->sessions[i].id, id) == 0)
            return &p->sessions[i];
    return NULL;
}

static bool supi_ok(const char *s)
{
    return strncmp(s, "imsi-", 5) == 0 && g5c_is_digits(s + 5);
}

/* Usage monitoring (backlog A-03, TS 29.512 5.6.2.? UsageMonitoringData and 4.2.6.2.? usage report) */
static void usage_monitoring(pcf *p, const char *sm_id, g5c_json *d)
{
    bool throttled = false;
    g5c_json *rule;
    if (p->cfg.um_volume == 0)
        return;
    if (sm_id != NULL) {
        pthread_mutex_lock(&p->mu);
        {
            pcf_sm_session *s = find(p, sm_id);
            throttled = s != NULL && s->throttled;
        }
        pthread_mutex_unlock(&p->mu);
    }
    rule = g5c_json_get_mut(g5c_json_get_mut(d, "sessRules"), "SessRule-1");
    if (rule == NULL)
        return;
    if (throttled) {
        g5c_json *amb = g5c_json_get_mut(rule, "authSessAmbr");
        g5c_json_set_str(amb, "uplink", p->cfg.um_throttle.uplink);
        g5c_json_set_str(amb, "downlink", p->cfg.um_throttle.downlink);
    } else {
        g5c_json *um = g5c_json_set(g5c_json_set(d, "umDecs", g5c_json_new_obj()), "um1", g5c_json_new_obj());
        g5c_json_set_str(rule, "refUmData", "um1");
        g5c_json_set_str(um, "umId", "um1");
        g5c_json_set_int(um, "volumeThreshold", (int64_t)p->cfg.um_volume);
        g5c_json_push_str(g5c_json_set(d, "policyCtrlReqTriggers", g5c_json_new_arr()), "US_RE");
    }
}

static g5c_json *decide(pcf *p, const char *sm_id, const pcf_session_info *info, const pcf_policy *sub, bool have)
{
    pcf_resolved r = pcf_resolve(info, &p->cfg, have ? sub : NULL);
    pcf_rule *af = NULL;
    size_t naf = 0;
    g5c_json *d;
    pcf_app_rules(p, sm_id, &af, &naf); /* the rules of the application sessions (Npcf_PolicyAuthorization) */
    if (naf > 0) {
        r.rules = g5c_xrealloc(r.rules, (r.nrules + naf) * sizeof *r.rules);
        for (size_t i = 0; i < naf; i++)
            r.rules[r.nrules++] = af[i];
    }
    free(af);
    d = pcf_decision(&r);
    pcf_resolved_free(&r);
    usage_monitoring(p, sm_id, d);
    return d;
}

static void create(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    g5c_json *raw = g5c_req_json(req, resp), *dec;
    const char *supi, *type, *dnn, *notif, *missing = NULL;
    const g5c_json *amb, *q;
    int64_t pdu = 0;
    pcf_session_info info;
    pcf_policy sub;
    bool have = false;
    char id[37], *path, *resource_uri, err[200];
    pcf_sm_session s;

    if (raw == NULL)
        return;
    supi = g5c_json_get_str(raw, "supi");
    type = g5c_json_get_str(raw, "pduSessionType");
    dnn = g5c_json_get_str(raw, "dnn");
    notif = g5c_json_get_str(raw, "notificationUri");
    amb = g5c_json_get(raw, "subsSessAmbr");
    q = g5c_json_get(raw, "subsDefQos");
    if (supi == NULL)
        missing = "supi";
    else if (!g5c_json_get_int(raw, "pduSessionId", &pdu) || pdu < 0)
        missing = "pduSessionId";
    else if (type == NULL)
        missing = "pduSessionType";
    else if (dnn == NULL)
        missing = "dnn";
    else if (notif == NULL)
        missing = "notificationUri";
    else if (g5c_json_get(raw, "sliceInfo") == NULL)
        missing = "sliceInfo";
    memset(&info, 0, sizeof info);
    if (missing == NULL && amb != NULL && !g5c_json_is(amb, G5C_J_NULL) && pcf_ambr_parse(amb, &info.subs_ambr, err, sizeof err) != 0) {
        count_req(p, "bad_request");
        g5c_resp_problem_simple(resp, 400, "MANDATORY_IE_MISSING", err);
        g5c_json_free(raw);
        return;
    }
    info.has_ambr = info.subs_ambr.uplink != NULL;
    if (missing != NULL) {
        char *d = g5c_xasprintf("missing or invalid field `%s`", missing);
        count_req(p, "bad_request");
        g5c_resp_problem_simple(resp, 400, "MANDATORY_IE_MISSING", d);
        free(d);
        g5c_json_free(raw);
        return;
    }
    if (!supi_ok(supi)) {
        bad_request(resp, "supi", "must be imsi-<digits>");
        goto out_info;
    }
    if (pdu < 1 || pdu > 255) {
        bad_request(resp, "pduSessionId", "must be 1..=255");
        goto out_info;
    }
    if (dnn[0] == 0) {
        bad_request(resp, "dnn", "must not be empty");
        goto out_info;
    }
    if (strncmp(notif, "http://", 7) != 0 && strncmp(notif, "https://", 8) != 0) {
        bad_request(resp, "notificationUri", "must be an absolute http(s) URI");
        goto out_info;
    }
    memset(&sub, 0, sizeof sub);
    if (!load_sub(p, supi, &sub, &have)) {
        G5C_LOGE("g5c_pcf", "policy data unavailable for %s", supi);
        unavailable(resp);
        goto out_info;
    }
    info.dnn = g5c_xstrdup(dnn);
    info.subs_def_qos = (q != NULL && !g5c_json_is(q, G5C_J_NULL)) ? g5c_json_dup(q) : NULL;
    dec = decide(p, NULL, &info, &sub, have);
    if (have)
        pcf_policy_free(&sub);
    if (g5c_uuid_v4(id) != 0) {
        g5c_json_free(dec);
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "no randomness");
        goto out_info;
    }
    path = g5c_xasprintf("%s/%s", BASE, id);
    resource_uri = g5c_req_url(req, path);
    free(path);
    G5C_LOGI("g5c_pcf", "SM policy %s created for %s dnn %s pdu session %lld", id, supi, dnn, (long long)pdu);
    memset(&s, 0, sizeof s);
    s.id = g5c_xstrdup(id);
    s.supi = g5c_xstrdup(supi);
    s.dnn = g5c_xstrdup(dnn);
    s.pdu_session_id = (uint64_t)pdu;
    s.notification_uri = g5c_xstrdup(notif);
    s.resource_uri = g5c_xstrdup(resource_uri);
    s.info = info; /* moves */
    memset(&info, 0, sizeof info);
    s.context = raw;
    raw = NULL;
    s.decision = g5c_json_dup(dec);
    pthread_mutex_lock(&p->mu);
    if (p->nsessions == p->capsessions) {
        p->capsessions = p->capsessions ? p->capsessions * 2 : 16;
        p->sessions = g5c_xrealloc(p->sessions, p->capsessions * sizeof *p->sessions);
    }
    p->sessions[p->nsessions++] = s;
    pcf_bsf_registered(p, id, s.context); /* copies what it needs and queues the work */
    pthread_mutex_unlock(&p->mu);
    count_req(p, "created");
    update_gauge(p);
    g5c_resp_json(resp, 201, dec);
    g5c_resp_header(resp, "location", resource_uri);
    free(resource_uri);
    g5c_json_free(dec);
out_info:
    pcf_session_info_free(&info);
    g5c_json_free(raw);
}

static void get(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    const char *id = g5c_req_param(req, "smPolicyId");
    g5c_json *o = NULL;
    pthread_mutex_lock(&p->mu);
    {
        pcf_sm_session *s = find(p, id ? id : "");
        if (s != NULL) {
            o = g5c_json_new_obj();
            g5c_json_set(o, "policy", g5c_json_dup(s->decision));
            g5c_json_set(o, "context", g5c_json_dup(s->context));
        }
    }
    pthread_mutex_unlock(&p->mu);
    if (o == NULL) {
        not_found(resp);
        return;
    }
    g5c_resp_json(resp, 200, o);
    g5c_json_free(o);
}

static void update(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    const char *id = g5c_req_param(req, "smPolicyId");
    g5c_json *body = g5c_req_json(req, resp), *dec;
    char *supi = NULL;
    pcf_session_info info;
    pcf_policy sub;
    bool have = false;
    uint64_t reported = 0;
    bool throttled_now = false;
    if (body == NULL) /* SmPolicyUpdateContextData */
        return;
    {   /* accuUsageReports (AccuUsageReport): the volume the UPF measured since its last report */
        const g5c_json *reps = g5c_json_get(body, "accuUsageReports");
        for (size_t i = 0; g5c_json_is(reps, G5C_J_ARRAY) && i < g5c_json_len(reps); i++) {
            int64_t v = 0;
            if (g5c_json_get_int(g5c_json_at(reps, i), "volUsage", &v) && v > 0)
                reported += (uint64_t)v;
        }
    }
    g5c_json_free(body);
    memset(&info, 0, sizeof info);
    pthread_mutex_lock(&p->mu);
    {
        pcf_sm_session *s = find(p, id ? id : "");
        if (s != NULL) {
            supi = g5c_xstrdup(s->supi);
            info = pcf_session_info_dup(&s->info);
            if (reported > 0 && p->cfg.um_volume > 0) {
                s->used += reported;
                if (s->used >= p->cfg.um_volume && !s->throttled) {
                    s->throttled = true;
                    throttled_now = true;
                }
            }
        }
    }
    pthread_mutex_unlock(&p->mu);
    if (reported > 0) {
        G5C_COUNT(p->metrics, "g5c_pcf_usage_reports_total", "Usage reports received from the SMF.");
        if (throttled_now) {
            G5C_COUNT(p->metrics, "g5c_pcf_usage_throttled_total", "Sessions throttled because their volume threshold was reached.");
            G5C_LOGI("g5c_pcf", "SM policy %s: %llu octets used, threshold %llu reached: throttling", id ? id : "", (unsigned long long)reported, (unsigned long long)p->cfg.um_volume);
        }
    }
    if (supi == NULL) {
        not_found(resp);
        return;
    }
    memset(&sub, 0, sizeof sub);
    if (!load_sub(p, supi, &sub, &have)) {
        unavailable(resp);
        goto out;
    }
    dec = decide(p, id, &info, &sub, have);
    if (have)
        pcf_policy_free(&sub);
    pthread_mutex_lock(&p->mu);
    {
        pcf_sm_session *s = find(p, id);
        if (s != NULL) {
            g5c_json_free(s->decision);
            s->decision = g5c_json_dup(dec);
        }
    }
    pthread_mutex_unlock(&p->mu);
    G5C_COUNT(p->metrics, "g5c_pcf_sm_policy_updates_total", "SM policy updates requested by the SMF.");
    g5c_resp_json(resp, 200, dec);
    g5c_json_free(dec);
out:
    free(supi);
    pcf_session_info_free(&info);
}

static void del(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    const char *id = g5c_req_param(req, "smPolicyId");
    bool removed = false;
    pthread_mutex_lock(&p->mu);
    {
        pcf_sm_session *s = find(p, id ? id : "");
        if (s != NULL) {
            size_t i = (size_t)(s - p->sessions);
            free(s->notification_uri); /* session_free is private to pcf.c; free through a tiny local copy */
            free(s->id);
            free(s->supi);
            free(s->dnn);
            free(s->resource_uri);
            pcf_session_info_free(&s->info);
            g5c_json_free(s->context);
            g5c_json_free(s->decision);
            p->sessions[i] = p->sessions[--p->nsessions];
            removed = true;
        }
    }
    pthread_mutex_unlock(&p->mu);
    if (removed) {
        pcf_apps_of_sm_gone(p, id);
        pcf_bsf_gone(p, id);
    }
    if (removed)
        G5C_LOGI("g5c_pcf", "SM policy %s deleted", id);
    update_gauge(p);
    if (removed)
        g5c_resp_status(resp, 204);
    else
        not_found(resp);
}

void pcf_smpolicy_routes(g5c_router *r, pcf *p)
{
    g5c_router_route(r, "POST", BASE, create, p);
    g5c_router_route(r, "GET", BASE "/{smPolicyId}", get, p);
    g5c_router_route(r, "POST", BASE "/{smPolicyId}/update", update, p);
    g5c_router_route(r, "POST", BASE "/{smPolicyId}/delete", del, p);
}

/* ---- notifications towards the SMF ---- */

typedef struct {
    char *id, *notif_uri, *resource_uri;
    pcf_session_info info;
    g5c_json *decision;
} snap_t;

static char *trim_slash_dup(const char *s)
{
    size_t n = strlen(s);
    while (n > 0 && s[n - 1] == '/')
        n--;
    return g5c_xstrndup(s, n);
}

size_t pcf_repush(pcf *p, const char *supi)
{
    size_t rejected = 0;
    return pcf_repush_stats(p, supi, &rejected);
}

size_t pcf_repush_stats(pcf *p, const char *supi, size_t *rejected)
{
    pcf_policy sub;
    bool have = false;
    snap_t *todo = NULL;
    size_t n = 0, accepted = 0;
    memset(&sub, 0, sizeof sub);
    if (!load_sub(p, supi, &sub, &have)) {
        G5C_LOGE("g5c_pcf", "cannot reload policy for push (%s)", supi);
        return 0;
    }
    pthread_mutex_lock(&p->mu);
    for (size_t i = 0; i < p->nsessions; i++) {
        pcf_sm_session *s = &p->sessions[i];
        if (strcmp(s->supi, supi) != 0)
            continue;
        todo = g5c_xrealloc(todo, (n + 1) * sizeof *todo);
        todo[n].id = g5c_xstrdup(s->id);
        todo[n].notif_uri = g5c_xstrdup(s->notification_uri);
        todo[n].resource_uri = g5c_xstrdup(s->resource_uri);
        todo[n].info = pcf_session_info_dup(&s->info);
        todo[n].decision = g5c_json_dup(s->decision);
        n++;
    }
    pthread_mutex_unlock(&p->mu);
    for (size_t i = 0; i < n; i++) {
        g5c_json *dec = decide(p, todo[i].id, &todo[i].info, &sub, have);
        if (!g5c_json_equal(dec, todo[i].decision)) {
            char *base = trim_slash_dup(todo[i].notif_uri), *url = g5c_xasprintf("%s/update", base);
            g5c_json *body = g5c_json_new_obj();
            g5c_resp r;
            char err[160];
            g5c_json_set_str(body, "resourceUri", todo[i].resource_uri);
            g5c_json_set(body, "smPolicyDecision", g5c_json_dup(dec));
            if (g5c_client_send_json(p->client, "POST", url, body, &r, err, sizeof err) == 0) {
                if (r.status >= 200 && r.status < 300) {
                    pthread_mutex_lock(&p->mu);
                    {
                        pcf_sm_session *s = find(p, todo[i].id);
                        if (s != NULL) {
                            g5c_json_free(s->decision);
                            s->decision = g5c_json_dup(dec);
                        }
                    }
                    pthread_mutex_unlock(&p->mu);
                    count_notif(p, "ok");
                    accepted++;
                } else {
                    G5C_LOGW("g5c_pcf", "SMF rejected policy update (%d) at %s", r.status, url);
                    count_notif(p, "rejected");
                    (*rejected)++;
                }
                g5c_resp_free(&r);
            } else {
                G5C_LOGW("g5c_pcf", "SMF unreachable for policy update at %s: %s", url, err);
                count_notif(p, "unreachable");
                (*rejected)++;
            }
            g5c_json_free(body);
            free(url);
            free(base);
        }
        g5c_json_free(dec);
    }
    for (size_t i = 0; i < n; i++) {
        free(todo[i].id);
        free(todo[i].notif_uri);
        free(todo[i].resource_uri);
        pcf_session_info_free(&todo[i].info);
        g5c_json_free(todo[i].decision);
    }
    free(todo);
    if (have)
        pcf_policy_free(&sub);
    return accepted;
}

bool pcf_terminate(pcf *p, const char *id)
{
    char *notif = NULL, *resource = NULL;
    pthread_mutex_lock(&p->mu);
    {
        pcf_sm_session *s = find(p, id);
        if (s != NULL) {
            size_t i = (size_t)(s - p->sessions);
            notif = s->notification_uri;
            resource = s->resource_uri;
            free(s->id);
            free(s->supi);
            free(s->dnn);
            pcf_session_info_free(&s->info);
            g5c_json_free(s->context);
            g5c_json_free(s->decision);
            p->sessions[i] = p->sessions[--p->nsessions];
        }
    }
    pthread_mutex_unlock(&p->mu);
    if (notif == NULL)
        return false;
    pcf_apps_of_sm_gone(p, id);
    pcf_bsf_gone(p, id);
    {
        char *base = trim_slash_dup(notif), *url = g5c_xasprintf("%s/terminate", base), err[160];
        g5c_json *body = g5c_json_new_obj();
        g5c_resp r;
        g5c_json_set_str(body, "resourceUri", resource);
        g5c_json_set_str(body, "cause", "PDU_SESSION_TERMINATION");
        if (g5c_client_send_json(p->client, "POST", url, body, &r, err, sizeof err) == 0)
            g5c_resp_free(&r);
        else
            G5C_LOGW("g5c_pcf", "SMF unreachable for terminate notification at %s: %s", url, err);
        g5c_json_free(body);
        free(url);
        free(base);
    }
    free(notif);
    free(resource);
    update_gauge(p);
    return true;
}
