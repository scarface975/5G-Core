/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The AMF's notification endpoints */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

char *amf_cb_uri(amf *a, const char *path)
{
    if (a->self_uri != NULL)
        return g5c_xasprintf("%s%s", a->self_uri, path);
    {
        const char *addr = a->nf->common.address != NULL ? a->nf->common.address : "127.0.0.1";
        if (strcmp(addr, "0.0.0.0") == 0 || strcmp(addr, "::") == 0)
            addr = "127.0.0.1";
        return g5c_xasprintf("http://%s:%u%s", addr, (unsigned)a->nf->common.port, path);
    }
}

static amf_ue *lookup(amf *a, const g5c_req *req, g5c_resp *resp)
{
    const char *supi = g5c_req_param(req, "supi");
    amf_ue *u = supi != NULL ? amf_ue_find_supi(a, supi) : NULL;
    if (u == NULL)
        g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "no such UE context");
    return u;
}

/* POST {smContextStatusUri}: the SMF released or lost a session (TS 23.502 4.3.4, 4.3.2.2.1) */
static void smf_status(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    amf *a = ctx;
    g5c_json *body = g5c_req_json(req, resp);
    const char *status, *cause;
    int64_t psi = 0;
    amf_ue *u;
    const char *p = g5c_req_param(req, "psi");
    if (body == NULL)
        return;
    status = g5c_json_get_str(g5c_json_get(body, "statusInfo"), "resourceStatus");
    cause = g5c_json_get_str(g5c_json_get(body, "statusInfo"), "cause");
    if (p != NULL)
        psi = (int64_t)strtol(p, NULL, 10);
    if (status == NULL || psi < 1 || psi > AMF_MAX_PSI) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "statusInfo", "resourceStatus and a PDU session id in the URI are required");
        g5c_json_free(body);
        return;
    }
    u = lookup(a, req, resp);
    if (u != NULL) {
        pthread_mutex_lock(&u->mu);
        if (strcmp(status, "RELEASED") == 0 && u->pdu[psi].used) {
            G5C_LOGI(AMF_LOG, "the SMF released PDU session %lld of %s (%s)", (long long)psi, u->supi, cause != NULL ? cause : "no cause");
            amf_pdu_reset(&u->pdu[psi]);
            amf_persist_request(a);
        }
        pthread_mutex_unlock(&u->mu);
        amf_ue_unref(u);
        g5c_resp_status(resp, 204);
    }
    amf_count(a, "g5c_amf_sm_status_notifications_total", "SM context status notifications received.", "status", status != NULL ? status : "none");
    g5c_json_free(body);
}

/* POST {deregCallbackUri}: the UE registered elsewhere or its subscription was withdrawn */
static void dereg_notify(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    amf *a = ctx;
    g5c_json *body = g5c_req_json(req, resp);
    const char *reason;
    amf_ue *u;
    if (body == NULL)
        return;
    reason = g5c_json_get_str(body, "deregReason");
    u = lookup(a, req, resp);
    if (u != NULL) {
        pthread_mutex_lock(&u->mu);
        G5C_LOGI(AMF_LOG, "UDM de-registration notification for %s (%s)", u->supi, reason != NULL ? reason : "no reason");
        if (reason != NULL && strcmp(reason, "SUBSCRIPTION_WITHDRAWN") == 0) {
            (void)gmm_start_dereg(u, false);
        } else if (u->mm == MM_REGISTERED) {
            /* the UE has a new serving AMF: this context goes without involving the UE (TS 23.502 4.2.2.2.2) */
            amf_conn *c = u->conn;
            amf_sm_release_all(a, u, "PDU_SESSION_HANDED_OVER");
            amf_pcf_delete(a, u);
            amf_udm_sdm_unsubscribe(a, u);
            u->uecm = false; /* the registration at the UDM now belongs to the other AMF */
            u->mm = MM_DEREGISTERED;
            atomic_fetch_add(&a->st_dereg, 1);
            amf_count(a, "g5c_amf_deregistrations_total", "De-registrations by kind.", "kind", "udm_notification");
            gmm_event(a, u, EVT_REG_STATE, "DEREGISTERED");
            if (c != NULL && !c->rel_sent)
                (void)conn_send_release_cmd(c, "nas", "deregister", REL_DELETE_UE);
            else
                amf_ue_remove(u);
        }
        pthread_mutex_unlock(&u->mu);
        amf_ue_unref(u);
        g5c_resp_status(resp, 204);
    }
    g5c_json_free(body);
}

static void am_policy_update(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    amf *a = ctx;
    g5c_json *body = g5c_req_json(req, resp);
    amf_ue *u;
    if (body == NULL)
        return;
    u = lookup(a, req, resp);
    if (u != NULL) {
        pthread_mutex_lock(&u->mu);
        {
            const char *res = g5c_json_get_str(body, "resourceUri");
            if (res != NULL)
                snprintf(u->pcf_url, sizeof u->pcf_url, "%s", res);
        }
        G5C_LOGI(AMF_LOG, "AM policy update for %s received", u->supi);
        pthread_mutex_unlock(&u->mu);
        amf_ue_unref(u);
        g5c_resp_status(resp, 204);
    }
    g5c_json_free(body);
}

static void am_policy_terminate(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    amf *a = ctx;
    amf_ue *u = lookup(a, req, resp);
    if (u != NULL) {
        pthread_mutex_lock(&u->mu);
        u->pcf_url[0] = 0; /* the association is gone; a new one is created at the next registration */
        pthread_mutex_unlock(&u->mu);
        amf_ue_unref(u);
        g5c_resp_status(resp, 204);
    }
}

/* the subscribed data changed: fetch it again and tell the UE what changed (TS 23.502 4.2.4.2) */
static void sdm_notify(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    amf *a = ctx;
    g5c_json *body = g5c_req_json(req, resp);
    amf_ue *u;
    if (body == NULL)
        return;
    u = lookup(a, req, resp);
    if (u != NULL) {
        nas_snssai before[AMF_MAX_SLICE];
        size_t nb;
        pthread_mutex_lock(&u->mu);
        memcpy(before, u->allowed, sizeof before);
        nb = u->nallowed;
        if (amf_udm_am_data(a, u) == 0) {
            nas_snssai allowed[AMF_MAX_SLICE];
            size_t n = 0;
            size_t lim = u->ndefault > 0 ? u->nsubscribed : 0;
            /* slices of the old allowed set that are still subscribed and served stay; the defaults replace an empty result */
            for (size_t i = 0; i < nb; i++)
                if (amf_snssai_in(u->subscribed, lim, &before[i]) && amf_snssai_in(a->cfg.slices, a->cfg.nslices, &before[i]))
                    allowed[n++] = before[i];
            if (n == 0)
                for (size_t i = 0; i < u->ndefault && n < AMF_MAX_SLICE; i++)
                    if (amf_snssai_in(a->cfg.slices, a->cfg.nslices, &u->subscribed[i]))
                        allowed[n++] = u->subscribed[i];
            if (n != nb || memcmp(allowed, before, n * sizeof allowed[0]) != 0) {
                memcpy(u->allowed, allowed, n * sizeof allowed[0]);
                u->nallowed = n;
                (void)gmm_start_config_update(u, false);
            }
        }
        pthread_mutex_unlock(&u->mu);
        amf_ue_unref(u);
        g5c_resp_status(resp, 204);
    }
    g5c_json_free(body);
}

void amf_callbacks_routes(g5c_router *r, amf *a)
{
    g5c_router_route(r, "POST", "/namf-callback/v1/smf-status/{supi}/{psi}", smf_status, a);
    g5c_router_route(r, "POST", "/namf-callback/v1/dereg-notify/{supi}", dereg_notify, a);
    g5c_router_route(r, "POST", "/namf-callback/v1/am-policy/{supi}/update", am_policy_update, a);
    g5c_router_route(r, "POST", "/namf-callback/v1/am-policy/{supi}/terminate", am_policy_terminate, a);
    g5c_router_route(r, "POST", "/namf-callback/v1/sdm-notify/{supi}", sdm_notify, a);
}
