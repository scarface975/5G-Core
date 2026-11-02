/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Policy administration (/admin/v1, not part of the 3GPP API). Disabled unless an admin token is configured */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "g5c/pcf.h"

int pcf_admin_guard(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const pcf *p = ctx;
    const char *presented;
    if (strncmp(req->path, "/admin/", 7) != 0)
        return 0;
    if (p->admin_token == NULL) {
        g5c_resp_problem_simple(resp, 404, "RESOURCE_NOT_FOUND", NULL);
        return 1;
    }
    presented = g5c_bearer_token(req);
    if (presented != NULL && strlen(presented) == strlen(p->admin_token) &&
        CRYPTO_memcmp(presented, p->admin_token, strlen(presented)) == 0)
        return 0;
    g5c_resp_problem_simple(resp, 401, "UNAUTHORIZED", NULL);
    g5c_resp_header(resp, "www-authenticate", "Bearer");
    return 1;
}

static bool supi_ok(const char *s)
{
    return strncmp(s, "imsi-", 5) == 0 && g5c_is_digits(s + 5);
}

static void bad(g5c_resp *resp, const char *detail)
{
    g5c_resp_problem_simple(resp, 400, "MANDATORY_IE_INCORRECT", detail);
}

static void unavailable(g5c_resp *resp)
{
    g5c_resp_problem_simple(resp, 503, "UNSPECIFIED", "policy data unavailable");
}

static const char *supi_param(const g5c_req *req)
{
    const char *s = g5c_req_param(req, "supi");
    return s ? s : "";
}

static void put_policy(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    const char *supi = supi_param(req);
    g5c_json *j, *o;
    pcf_policy pol;
    char err[200], field[200], reason[200];
    size_t notified;
    if (!supi_ok(supi)) {
        bad(resp, "supi must be imsi-<digits>");
        return;
    }
    j = g5c_req_json(req, resp);
    if (j == NULL)
        return;
    if (pcf_policy_parse(j, false, &pol, err, sizeof err) != 0) {
        g5c_resp_problem_simple(resp, 400, "MANDATORY_IE_INCORRECT", err);
        g5c_json_free(j);
        return;
    }
    g5c_json_free(j);
    if (pcf_policy_validate(&pol, false, field, sizeof field, reason, sizeof reason) != 0) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", field, reason);
        pcf_policy_free(&pol);
        return;
    }
    if (!pcf_store_put(p, supi, &pol)) {
        unavailable(resp);
        pcf_policy_free(&pol);
        return;
    }
    pcf_policy_free(&pol);
    notified = pcf_repush(p, supi);
    G5C_LOGI("g5c_audit", "pcf admin: policy.put supi=%s notified_sessions=%zu", supi, notified);
    o = g5c_json_new_obj();
    g5c_json_set_str(o, "supi", supi);
    g5c_json_set_int(o, "notifiedSessions", (int64_t)notified);
    g5c_resp_json(resp, 200, o);
    g5c_json_free(o);
}

static void get_policy(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    pcf_policy pol;
    pcf_store_rc rc;
    memset(&pol, 0, sizeof pol);
    rc = pcf_store_get(p, supi_param(req), &pol);
    if (rc == PCF_STORE_OK) {
        g5c_json *j = pcf_policy_to_json(&pol);
        g5c_resp_json(resp, 200, j);
        g5c_json_free(j);
        pcf_policy_free(&pol);
    } else if (rc == PCF_STORE_NONE) {
        g5c_resp_problem_simple(resp, 404, "USER_NOT_FOUND", NULL);
    } else {
        unavailable(resp);
    }
}

static void delete_policy(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    int rc = pcf_store_delete(p, supi_param(req));
    if (rc == 1) {
        pcf_repush(p, supi_param(req));
        G5C_LOGI("g5c_audit", "pcf admin: policy.delete supi=%s", supi_param(req));
        g5c_resp_status(resp, 204);
    } else if (rc == 0) {
        g5c_resp_problem_simple(resp, 404, "USER_NOT_FOUND", NULL);
    } else {
        unavailable(resp);
    }
}

static void list_sessions(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    g5c_json *list = g5c_json_new_arr();
    (void)req;
    pthread_mutex_lock(&p->mu);
    for (size_t i = 0; i < p->nsessions; i++) {
        const pcf_sm_session *s = &p->sessions[i];
        g5c_json *e = g5c_json_push(list, g5c_json_new_obj());
        g5c_json_set_str(e, "smPolicyId", s->id);
        g5c_json_set_str(e, "supi", s->supi);
        g5c_json_set_str(e, "dnn", s->dnn);
        g5c_json_set_int(e, "pduSessionId", (int64_t)s->pdu_session_id);
        g5c_json_set(e, "decision", g5c_json_dup(s->decision));
    }
    pthread_mutex_unlock(&p->mu);
    g5c_resp_json(resp, 200, list);
    g5c_json_free(list);
}

static void terminate_session(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    pcf *p = ctx;
    const char *id = g5c_req_param(req, "smPolicyId");
    if (pcf_terminate(p, id ? id : "")) {
        G5C_LOGI("g5c_audit", "pcf admin: session.terminate smPolicyId=%s", id ? id : "");
        g5c_resp_status(resp, 204);
    } else {
        g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", NULL);
    }
}

void pcf_admin_routes(g5c_router *r, pcf *p)
{
    g5c_router_route(r, "PUT", "/admin/v1/policies/{supi}", put_policy, p);
    g5c_router_route(r, "GET", "/admin/v1/policies/{supi}", get_policy, p);
    g5c_router_route(r, "DELETE", "/admin/v1/policies/{supi}", delete_policy, p);
    g5c_router_route(r, "GET", "/admin/v1/sessions", list_sessions, p);
    g5c_router_route(r, "DELETE", "/admin/v1/sessions/{smPolicyId}", terminate_session, p);
}
