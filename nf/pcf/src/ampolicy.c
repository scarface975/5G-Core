/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Npcf_AMPolicyControl (TS 29.507 clause 5): AM policy associations for the AMF. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/pcf.h"

#define BASE "/npcf-am-policy-control/v1/policies"

static void not_found(g5c_resp *resp)
{
    g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "no such AM policy association");
}

static void bad(g5c_resp *resp, const char *field, const char *reason)
{
    g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", field, reason);
}

static int find(const pcf *p, const char *id)
{
    for (size_t i = 0; i < p->nassocs; i++)
        if (strcmp(p->assocs[i].id, id) == 0)
            return (int)i;
    return -1;
}

static void create(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    g5c_json *request = g5c_req_json(req, resp), *body;
    const char *supi, *notif;
    char id[37], *path, *loc;
    pcf_am_assoc a;
    if (request == NULL)
        return;
    supi = g5c_json_get_str(request, "supi");
    notif = g5c_json_get_str(request, "notificationUri");
    if (supi == NULL || strncmp(supi, "imsi-", 5) != 0 || !g5c_is_digits(supi + 5)) {
        bad(resp, "supi", "must be imsi-<digits>");
        g5c_json_free(request);
        return;
    }
    if (notif == NULL || strncmp(notif, "http", 4) != 0) {
        bad(resp, "notificationUri", "must be an absolute http(s) URI");
        g5c_json_free(request);
        return;
    }
    if (g5c_uuid_v4(id) != 0) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "no randomness");
        g5c_json_free(request);
        return;
    }
    G5C_LOGI("g5c_pcf", "AM policy association %s created for %s", id, supi);
    memset(&a, 0, sizeof a);
    a.id = g5c_xstrdup(id);
    a.supi = g5c_xstrdup(supi);
    a.request = g5c_json_dup(request);
    pthread_mutex_lock(&p->mu);
    if (p->nassocs == p->capassocs) {
        p->capassocs = p->capassocs ? p->capassocs * 2 : 16;
        p->assocs = g5c_xrealloc(p->assocs, p->capassocs * sizeof *p->assocs);
    }
    p->assocs[p->nassocs++] = a;
    pthread_mutex_unlock(&p->mu);
    G5C_COUNT(p->metrics, "g5c_pcf_am_policy_associations_total", "AM policy associations created.");
    /* PolicyAssociation: the request is echoed back, plus our decisions */
    body = g5c_json_new_obj();
    g5c_json_set(body, "request", request); /* takes ownership */
    g5c_json_set_str(body, "suppFeat", "");
    if (p->cfg.has_rfsp)
        g5c_json_set_int(body, "rfsp", p->cfg.rfsp);
    path = g5c_xasprintf("%s/%s", BASE, id);
    loc = g5c_req_url(req, path);
    g5c_resp_json(resp, 201, body);
    g5c_resp_header(resp, "location", loc);
    free(path);
    free(loc);
    g5c_json_free(body);
}

static void update(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    const char *id = g5c_req_param(req, "polAssoId");
    g5c_json *in = g5c_req_json(req, resp), *body;
    bool known;
    char *path, *uri;
    if (in == NULL)
        return;
    g5c_json_free(in);
    pthread_mutex_lock(&p->mu);
    known = find(p, id ? id : "") >= 0;
    pthread_mutex_unlock(&p->mu);
    if (!known) {
        not_found(resp);
        return;
    }
    /* PolicyUpdate: `resourceUri` is mandatory (TS 29.507 5.6.2.3) */
    path = g5c_xasprintf("%s/%s", BASE, id);
    uri = g5c_req_url(req, path);
    body = g5c_json_new_obj();
    g5c_json_set_str(body, "resourceUri", uri);
    if (p->cfg.has_rfsp)
        g5c_json_set_int(body, "rfsp", p->cfg.rfsp);
    g5c_resp_json(resp, 200, body);
    g5c_json_free(body);
    free(path);
    free(uri);
}

static void del(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    const char *id = g5c_req_param(req, "polAssoId");
    bool removed = false;
    pthread_mutex_lock(&p->mu);
    {
        int i = find(p, id ? id : "");
        if (i >= 0) {
            free(p->assocs[i].id);
            free(p->assocs[i].supi);
            g5c_json_free(p->assocs[i].request);
            p->assocs[i] = p->assocs[--p->nassocs];
            removed = true;
        }
    }
    pthread_mutex_unlock(&p->mu);
    if (removed)
        g5c_resp_status(resp, 204);
    else
        not_found(resp);
}

void pcf_ampolicy_routes(g5c_router *r, pcf *p)
{
    g5c_router_route(r, "POST", BASE, create, p);
    g5c_router_route(r, "POST", BASE "/{polAssoId}/update", update, p);
    g5c_router_route(r, "DELETE", BASE "/{polAssoId}", del, p);
}
