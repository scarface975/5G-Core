/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nudm_UEContextManagement (TS 29.503 clause 5.3): AMF and SMF registrations. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/udm.h"

static bool supi_of(const g5c_req *req, char *out, size_t cap, g5c_resp *resp)
{
    const char *id = g5c_req_param(req, "ueId");
    if (udm_resolve(id ? id : "", NULL, 0, out, cap) != 0) {
        g5c_resp_problem_simple(resp, 400, "MANDATORY_IE_INCORRECT", "ueId must be imsi-...");
        return false;
    }
    return true;
}

static void missing(g5c_resp *resp, const char *field)
{
    g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", field, "absent");
}

/* Tell the previously registered AMF that the UE registered elsewhere (TS 29.503 5.3.2.2.2). Best effort: a dead
 * old AMF must never block the new registration. */
static void notify_old_amf(udm *u, const g5c_json *old)
{
    const char *uri = g5c_json_get_str(old, "deregCallbackUri");
    g5c_json *data;
    g5c_resp r;
    char err[160];
    if (uri == NULL)
        return;
    data = g5c_json_new_obj();
    g5c_json_set_str(data, "deregReason", "UE_INITIAL_REGISTRATION");
    g5c_json_set_str(data, "accessType", "3GPP_ACCESS");
    if (g5c_client_send_json(u->client, "POST", uri, data, &r, err, sizeof err) == 0) {
        if (r.status >= 200 && r.status < 300)
            G5C_LOGI("g5c_udm", "old AMF %s notified of re-registration", uri);
        else
            G5C_LOGW("g5c_udm", "old AMF %s rejected dereg notification (%d)", uri, r.status);
        g5c_resp_free(&r);
    } else {
        G5C_LOGW("g5c_udm", "old AMF %s unreachable for dereg notification: %s", uri, err);
    }
    g5c_json_free(data);
}

static const char *path_param(const g5c_req *req, const char *name)
{
    const char *p = g5c_req_param(req, name);
    return p ? p : "";
}

static void amf_put(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    char supi[48], *loc, *path;
    g5c_json *reg, *auth = NULL, *old = NULL;
    static const char *const req_fields[] = {"amfInstanceId", "deregCallbackUri", "guami", "ratType"};
    udr_result r;
    if (!supi_of(req, supi, sizeof supi, resp))
        return;
    reg = g5c_req_json(req, resp);
    if (reg == NULL)
        return;
    for (size_t i = 0; i < 4; i++)
        if (g5c_json_get(reg, req_fields[i]) == NULL) {
            missing(resp, req_fields[i]);
            g5c_json_free(reg);
            return;
        }
    r = udm_udr_auth_subscription(&u->udr, supi, &auth); /* the subscriber must exist */
    g5c_json_free(auth);
    if (r.kind != UDR_OK) {
        udm_udr_fail(&r, "USER_NOT_FOUND", resp);
        g5c_json_free(reg);
        return;
    }
    r = udm_udr_amf_registration(&u->udr, supi, &old);
    if (r.kind == UDR_OK && !g5c_json_equal(g5c_json_get(old, "amfInstanceId"), g5c_json_get(reg, "amfInstanceId")))
        notify_old_amf(u, old);
    g5c_json_free(old);
    r = udm_udr_put_amf_registration(&u->udr, supi, reg);
    if (r.kind != UDR_OK) {
        udm_udr_fail(&r, "CONTEXT_NOT_FOUND", resp);
        g5c_json_free(reg);
        return;
    }
    G5C_COUNT(u->metrics, "g5c_udm_amf_registrations_total", "AMF registrations stored.");
    G5C_LOGI("g5c_udm", "%s: AMF registration stored", supi);
    if (r.created) {
        path = g5c_xasprintf("/nudm-uecm/v1/%s/registrations/amf-3gpp-access", supi);
        loc = g5c_req_url(req, path);
        g5c_resp_json(resp, 201, reg);
        g5c_resp_header(resp, "location", loc);
        free(path);
        free(loc);
    } else {
        g5c_resp_json(resp, 200, reg);
    }
    g5c_json_free(reg);
}

static void amf_get(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    char supi[48];
    g5c_json *v = NULL;
    udr_result r;
    if (!supi_of(req, supi, sizeof supi, resp))
        return;
    r = udm_udr_amf_registration(&u->udr, supi, &v);
    if (r.kind == UDR_OK) {
        g5c_resp_json(resp, 200, v);
        g5c_json_free(v);
    } else {
        udm_udr_fail(&r, "CONTEXT_NOT_FOUND", resp);
    }
}

static void amf_patch(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    char supi[48];
    g5c_json *m, *items;
    static const char *const allowed[] = {"guami", "purgeFlag", "pei", "imsVoPs", "backupAmfInfo", "epsInterworkingInfo"};
    udr_result r;
    if (!supi_of(req, supi, sizeof supi, resp))
        return;
    /* Amf3GppAccessRegistrationModification: only these attributes may change */
    m = g5c_req_json(req, resp);
    if (m == NULL)
        return;
    if (!g5c_json_is(m, G5C_J_OBJECT)) {
        missing(resp, "body");
        g5c_json_free(m);
        return;
    }
    items = g5c_json_new_arr();
    for (size_t i = 0; i < g5c_json_len(m); i++) {
        const char *k = g5c_json_key_at(m, i);
        bool ok = false;
        for (size_t a = 0; a < 6; a++)
            if (strcmp(k, allowed[a]) == 0)
                ok = true;
        if (!ok) {
            char *d = g5c_xasprintf("%s cannot be modified", k);
            g5c_resp_problem_simple(resp, 403, "MODIFICATION_NOT_ALLOWED", d);
            free(d);
            g5c_json_free(items);
            g5c_json_free(m);
            return;
        }
        {
            g5c_json *op = g5c_json_push(items, g5c_json_new_obj());
            char *path = g5c_xasprintf("/%s", k);
            g5c_json_set_str(op, "op", "add");
            g5c_json_set_str(op, "path", path);
            g5c_json_set(op, "value", g5c_json_dup(g5c_json_val_at(m, i)));
            free(path);
        }
    }
    r = udm_udr_patch_amf_registration(&u->udr, supi, items);
    if (r.kind == UDR_OK)
        g5c_resp_status(resp, 204);
    else
        udm_udr_fail(&r, "CONTEXT_NOT_FOUND", resp);
    g5c_json_free(items);
    g5c_json_free(m);
}

static void amf_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    char supi[48];
    udr_result r;
    if (!supi_of(req, supi, sizeof supi, resp))
        return;
    r = udm_udr_delete_amf_registration(&u->udr, supi);
    if (r.kind == UDR_OK)
        g5c_resp_status(resp, 204);
    else
        udm_udr_fail(&r, "CONTEXT_NOT_FOUND", resp);
}

static void smf_put(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    char supi[48], *loc, *path, *end;
    const char *id = path_param(req, "pduSessionId");
    static const char *const req_fields[] = {"smfInstanceId", "pduSessionId", "singleNssai"};
    g5c_json *reg, *auth = NULL;
    long n;
    udr_result r;
    if (!supi_of(req, supi, sizeof supi, resp))
        return;
    n = strtol(id, &end, 10);
    if (*id == 0 || *end != 0 || n < 1 || n > 255 || strlen(id) > 3 || !g5c_is_digits(id)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "pduSessionId", "must be 1..=255");
        return;
    }
    reg = g5c_req_json(req, resp);
    if (reg == NULL)
        return;
    for (size_t i = 0; i < 3; i++)
        if (g5c_json_get(reg, req_fields[i]) == NULL) {
            missing(resp, req_fields[i]);
            g5c_json_free(reg);
            return;
        }
    r = udm_udr_auth_subscription(&u->udr, supi, &auth);
    g5c_json_free(auth);
    if (r.kind != UDR_OK) {
        udm_udr_fail(&r, "USER_NOT_FOUND", resp);
        g5c_json_free(reg);
        return;
    }
    r = udm_udr_put_smf_registration(&u->udr, supi, id, reg);
    if (r.kind != UDR_OK) {
        udm_udr_fail(&r, "CONTEXT_NOT_FOUND", resp);
    } else if (r.created) {
        path = g5c_xasprintf("/nudm-uecm/v1/%s/registrations/smf-registrations/%s", supi, id);
        loc = g5c_req_url(req, path);
        g5c_resp_json(resp, 201, reg);
        g5c_resp_header(resp, "location", loc);
        free(path);
        free(loc);
    } else {
        g5c_resp_json(resp, 200, reg);
    }
    g5c_json_free(reg);
}

static void smf_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    char supi[48];
    udr_result r;
    if (!supi_of(req, supi, sizeof supi, resp))
        return;
    r = udm_udr_delete_smf_registration(&u->udr, supi, path_param(req, "pduSessionId"));
    if (r.kind == UDR_OK)
        g5c_resp_status(resp, 204);
    else
        udm_udr_fail(&r, "CONTEXT_NOT_FOUND", resp);
}

void udm_uecm_routes(g5c_router *r, udm *u)
{
    const char *amf = "/nudm-uecm/v1/{ueId}/registrations/amf-3gpp-access";
    const char *smf = "/nudm-uecm/v1/{ueId}/registrations/smf-registrations/{pduSessionId}";
    g5c_router_route(r, "PUT", amf, amf_put, u);
    g5c_router_route(r, "GET", amf, amf_get, u);
    g5c_router_route(r, "PATCH", amf, amf_patch, u);
    g5c_router_route(r, "DELETE", amf, amf_delete, u);
    g5c_router_route(r, "PUT", smf, smf_put, u);
    g5c_router_route(r, "DELETE", smf, smf_delete, u);
}
