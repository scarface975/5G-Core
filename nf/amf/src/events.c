#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Namf_EventExposure (TS 29.518 clause 5.3), basic: subscriptions for registration state, connectivity state, reachability and location reports
 * of one UE or of any UE, and the notifications that follow state changes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "priv.h"

#define BASE "/namf-evts/v1/subscriptions"

static const char *const EVT_NAMES[EVT_COUNT] = {"REGISTRATION_STATE_REPORT", "CONNECTIVITY_STATE_REPORT", "LOCATION_REPORT", "REACHABILITY_REPORT", "LOSS_OF_CONNECTIVITY"};

static int evt_from_name(const char *n)
{
    for (int i = 0; i < EVT_COUNT; i++)
        if (n != NULL && strcmp(EVT_NAMES[i], n) == 0)
            return i;
    return -1;
}

static void iso_now(char out[24])
{
    time_t t = (time_t)(g5c_unix_millis() / 1000);
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(out, 24, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

/* ---- notifications --------------------------------------------------------------------------------------------------------------------- */

typedef struct {
    char *uri;
    char *body;
} notif_job;

static void notif_task(amf *a, void *arg)
{
    notif_job *j = arg;
    g5c_resp r;
    char err[160];
    g5c_kv hdr = {"accept", "application/json"};
    if (g5c_client_request(a->client, "POST", j->uri, &hdr, 1, "application/json", j->body, strlen(j->body), &r, err, sizeof err) == 0) {
        if (r.status < 200 || r.status > 299)
            G5C_LOGW(AMF_LOG, "event notification to %s answered %d", j->uri, r.status);
        g5c_resp_free(&r);
    } else {
        G5C_LOGW(AMF_LOG, "event notification to %s: %s", j->uri, err);
    }
    amf_count(a, "g5c_amf_event_notifications_total", "Namf_EventExposure notifications sent.", NULL, NULL);
    free(j->uri);
    free(j->body);
    free(j);
}

static g5c_json *report_for(amf_ue *u, int type, const char *state, const char *sub_id)
{
    g5c_json *rep = g5c_json_new_obj(), *l;
    char ts[24];
    iso_now(ts);
    g5c_json_set_str(rep, "type", EVT_NAMES[type]);
    g5c_json_set(rep, "state", g5c_json_new_obj());
    g5c_json_set_bool(g5c_json_get_mut(rep, "state"), "active", true);
    g5c_json_set_str(rep, "timeStamp", ts);
    g5c_json_set_str(rep, "subscriptionId", sub_id);
    g5c_json_set_str(rep, "supi", u->supi);
    if (type == EVT_REG_STATE) {
        l = g5c_json_set(rep, "rmInfoList", g5c_json_new_arr());
        l = g5c_json_push(l, g5c_json_new_obj());
        g5c_json_set_str(l, "rmState", state != NULL ? state : (u->mm == MM_REGISTERED ? "REGISTERED" : "DEREGISTERED"));
        g5c_json_set_str(l, "accessType", "3GPP_ACCESS");
    } else if (type == EVT_CONNECTIVITY) {
        l = g5c_json_set(rep, "cmInfoList", g5c_json_new_arr());
        l = g5c_json_push(l, g5c_json_new_obj());
        g5c_json_set_str(l, "cmState", state != NULL ? state : (u->cm == CM_CONNECTED ? "CONNECTED" : "IDLE"));
        g5c_json_set_str(l, "accessType", "3GPP_ACCESS");
    } else if (type == EVT_REACHABILITY) {
        g5c_json_set_str(rep, "reachability", u->cm == CM_CONNECTED ? "REACHABLE" : "UNREACHABLE");
    } else if (type == EVT_LOSS) {
        g5c_json_set_str(rep, "lossOfConnectReason", state != NULL ? state : "UE_DEREGISTERED");
    } else if (type == EVT_LOCATION && u->has_loc) {
        g5c_json *ul = g5c_json_set(rep, "location", g5c_json_new_obj()), *nr = g5c_json_set(ul, "nrLocation", g5c_json_new_obj());
        amf_tai_to_json(&u->loc, nr, "tai");
    }
    return rep;
}

/* called with u->mu held; the HTTP calls happen on the worker pool */
static void dispatch_event(amf *a, amf_ue *u, int type, const char *state)
{
    g5c_json *todo[8];
    size_t n = 0;
    char *uris[8];
    pthread_mutex_lock(&a->emu);
    for (amf_evsub *s = a->subs; s != NULL && n < 8; s = s->next) {
        if (!s->types[type] || (!s->any && strcmp(s->supi, u->supi) != 0))
            continue;
        {
            g5c_json *body = g5c_json_new_obj(), *list = g5c_json_set(body, "reportList", g5c_json_new_arr());
            g5c_json_push(list, report_for(u, type, state, s->id));
            if (s->corr[0] != 0)
                g5c_json_set_str(body, "notifyCorrelationId", s->corr);
            todo[n] = body;
            uris[n] = g5c_xstrdup(s->notif_uri);
            n++;
        }
    }
    pthread_mutex_unlock(&a->emu);
    for (size_t i = 0; i < n; i++) {
        notif_job *j = g5c_xcalloc(1, sizeof *j);
        j->uri = uris[i];
        j->body = g5c_json_to_string(todo[i], NULL);
        g5c_json_free(todo[i]);
        amf_post(a, notif_task, j);
    }
}

/* One state change can be several events: a UE that is de-registered has lost its connectivity (the reason says how: TS 29.518 6.2.6.3.12; the
 * implicit de-registration is the expiry of the detection time), a UE that is connected can be reached. */
void gmm_event(amf *a, amf_ue *u, int type, const char *state)
{
    const char *loss = NULL;
    if (type == EVT_REG_STATE && state != NULL && strcmp(state, "DEREGISTERED") == 0) {
        loss = "UE_DEREGISTERED";
    } else if (type == EVT_REG_STATE && state != NULL && strcmp(state, "DEREGISTERED_IMPLICIT") == 0) {
        state = "DEREGISTERED";
        loss = "MAX_DETECTION_TIME_EXPIRED";
    }
    dispatch_event(a, u, type, state);
    if (loss != NULL)
        dispatch_event(a, u, EVT_LOSS, loss);
    if (type == EVT_CONNECTIVITY && state != NULL && strcmp(state, "CONNECTED") == 0)
        dispatch_event(a, u, EVT_REACHABILITY, NULL);
}

/* ---- the service -------------------------------------------------------------------------------------------------------------------------- */

static void create_sub(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    amf *a = ctx;
    g5c_json *in = g5c_req_json(req, resp), *out;
    const g5c_json *sub, *evl;
    amf_evsub *s;
    const char *uri, *supi;
    bool any = false;
    char id[40], *path, *loc;
    if (in == NULL)
        return;
    sub = g5c_json_get(in, "subscription");
    evl = g5c_json_get(sub, "eventList");
    uri = g5c_json_get_str(sub, "eventNotifyUri");
    if (!g5c_json_is(sub, G5C_J_OBJECT) || g5c_json_len(evl) == 0 || uri == NULL || strncmp(uri, "http", 4) != 0) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", "subscription", "eventList and eventNotifyUri are required");
        g5c_json_free(in);
        return;
    }
    (void)g5c_json_get_bool(sub, "anyUE", &any);
    supi = g5c_json_get_str(sub, "supi");
    if (!any && supi == NULL) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", "supi", "either supi or anyUE is required");
        g5c_json_free(in);
        return;
    }
    s = g5c_xcalloc(1, sizeof *s);
    for (size_t i = 0; i < g5c_json_len(evl); i++) {
        int t = evt_from_name(g5c_json_get_str(g5c_json_at(evl, i), "type"));
        if (t < 0) {
            g5c_resp_problem_invalid(resp, 501, "UNSUPPORTED_EVENT", "eventList", "only registration state, connectivity state, reachability and location reports");
            free(s);
            g5c_json_free(in);
            return;
        }
        s->types[t] = true;
    }
    snprintf(s->notif_uri, sizeof s->notif_uri, "%s", uri);
    snprintf(s->corr, sizeof s->corr, "%s", g5c_json_get_str(sub, "notifyCorrelationId") != NULL ? g5c_json_get_str(sub, "notifyCorrelationId") : "");
    snprintf(s->nf_id, sizeof s->nf_id, "%s", g5c_json_get_str(sub, "nfId") != NULL ? g5c_json_get_str(sub, "nfId") : "");
    s->any = any;
    if (supi != NULL)
        snprintf(s->supi, sizeof s->supi, "%s", supi);
    pthread_mutex_lock(&a->emu);
    snprintf(id, sizeof id, "%llu", (unsigned long long)++a->next_sub);
    snprintf(s->id, sizeof s->id, "%s", id);
    s->next = a->subs;
    a->subs = s;
    pthread_mutex_unlock(&a->emu);
    amf_count(a, "g5c_amf_event_subscriptions_total", "Event exposure subscriptions created.", NULL, NULL);
    out = g5c_json_new_obj();
    g5c_json_set(out, "subscription", g5c_json_dup(sub));
    g5c_json_set_str(out, "subscriptionId", id);
    {
        /* an immediate report of the current state of a single UE */
        bool imm = false;
        (void)g5c_json_get_bool(g5c_json_get(sub, "options"), "immediateFlag", &imm);
        if (!imm)
            (void)g5c_json_get_bool(sub, "immediateFlag", &imm);
        if (imm && supi != NULL) {
            amf_ue *u = amf_ue_find_supi(a, supi);
            if (u != NULL) {
                g5c_json *rl = g5c_json_set(out, "reportList", g5c_json_new_arr());
                pthread_mutex_lock(&u->mu);
                for (int t = 0; t < EVT_COUNT; t++)
                    if (s->types[t])
                        g5c_json_push(rl, report_for(u, t, NULL, id));
                pthread_mutex_unlock(&u->mu);
                amf_ue_unref(u);
            }
        }
    }
    path = g5c_xasprintf(BASE "/%s", id);
    loc = g5c_req_url(req, path);
    g5c_resp_json(resp, 201, out);
    g5c_resp_header(resp, "location", loc);
    free(path);
    free(loc);
    g5c_json_free(out);
    g5c_json_free(in);
}

static void delete_sub(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    amf *a = ctx;
    const char *id = g5c_req_param(req, "subscriptionId");
    bool found = false;
    pthread_mutex_lock(&a->emu);
    for (amf_evsub **pp = &a->subs; *pp != NULL; pp = &(*pp)->next)
        if (id != NULL && strcmp((*pp)->id, id) == 0) {
            amf_evsub *d = *pp;
            *pp = d->next;
            free(d);
            found = true;
            break;
        }
    pthread_mutex_unlock(&a->emu);
    if (found)
        g5c_resp_status(resp, 204);
    else
        g5c_resp_problem_simple(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such subscription");
}

static void patch_sub(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    amf *a = ctx;
    const char *id = g5c_req_param(req, "subscriptionId");
    g5c_json *ops = g5c_req_json(req, resp);
    amf_evsub *s;
    bool found = false;
    if (ops == NULL)
        return;
    pthread_mutex_lock(&a->emu);
    for (s = a->subs; s != NULL; s = s->next)
        if (id != NULL && strcmp(s->id, id) == 0) {
            found = true;
            /* the modifications that matter here: the notification URI and the events (replace/add on /eventNotifyUri, /eventList) */
            for (size_t i = 0; i < g5c_json_len(ops); i++) {
                const g5c_json *op = g5c_json_at(ops, i);
                const char *path = g5c_json_get_str(op, "path"), *v = g5c_json_str(g5c_json_get(op, "value"));
                if (path != NULL && strcmp(path, "/eventNotifyUri") == 0 && v != NULL && strncmp(v, "http", 4) == 0)
                    snprintf(s->notif_uri, sizeof s->notif_uri, "%s", v);
            }
            break;
        }
    pthread_mutex_unlock(&a->emu);
    if (found) {
        g5c_json *out = g5c_json_new_obj();
        g5c_json_set_str(out, "subscriptionId", id);
        g5c_resp_json(resp, 200, out);
        g5c_json_free(out);
    } else {
        g5c_resp_problem_simple(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such subscription");
    }
    g5c_json_free(ops);
}

void amf_events_routes(g5c_router *r, amf *a)
{
    g5c_router_route(r, "POST", BASE, create_sub, a);
    g5c_router_route(r, "DELETE", BASE "/{subscriptionId}", delete_sub, a);
    g5c_router_route(r, "PATCH", BASE "/{subscriptionId}", patch_sub, a);
}

void amf_events_free(amf *a)
{
    while (a->subs != NULL) {
        amf_evsub *n = a->subs->next;
        free(a->subs);
        a->subs = n;
    }
}
