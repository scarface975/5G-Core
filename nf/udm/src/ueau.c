/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nudm_UEAuthentication (TS 29.503 clause 5.4): generate authentication data and record auth events. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "g5c/udm.h"

static void reject(g5c_resp *resp, int status, const char *cause, const char *detail)
{
    g5c_resp_problem_simple(resp, status, cause, detail);
}

static void count(udm *u, const char *name, const char *help, const char *lk, const char *lv)
{
    g5c_label l = {lk, lv};
    g5c_counter_inc(g5c_counter_get(u->metrics, name, help, lk ? &l : NULL, lk ? 1 : 0));
}

static void vec_count(udm *u, const char *result)
{
    count(u, "g5c_udm_auth_vectors_total", "Authentication vector requests by result.", "result", result);
}

/* hex string of exactly 2*n characters -> n bytes */
static bool hex_n(const char *h, uint8_t *out, size_t n)
{
    return h != NULL && strlen(h) == 2 * n && g5c_hex_decode(h, out, n) == (long)n;
}

static const char *path_param(const g5c_req *req, const char *name)
{
    const char *p = g5c_req_param(req, name);
    return p ? p : "";
}

static void vector_for(udm *u, const char *supi, const char *snn, const g5c_json *resync_info, g5c_resp *resp)
{
    g5c_json *sub = NULL;
    udr_result ur = udm_udr_auth_subscription(&u->udr, supi, &sub);
    uint8_t k[16], opc[16], amf[2] = {0x80, 0x00}, rand[16];
    size_t kl = 0, ol = 0;
    const char *scheme, *enc_k, *enc_opc, *amf_hex, *sqn_hex, *method;
    bool prime = false;
    udm_hep hp;
    uint64_t sqn = 0, new_sqn;
    udm_heav av;
    g5c_json *patch = NULL, *res = NULL, *vec;
    char hex[13];
    int rc;

    if (ur.kind != UDR_OK) {
        udm_udr_fail(&ur, "USER_NOT_FOUND", resp);
        return;
    }
    method = g5c_json_get_str(sub, "authenticationMethod");
    if (g5c_streq(method, "EAP_AKA_PRIME")) {
        prime = true;
    } else if (!g5c_streq(method, "5G_AKA")) {
        /* EAP-TLS and anything else: the home network cannot run it (TS 29.509 6.1.7.3: AUTHENTICATION_REJECTED, the user cannot be authenticated with this method) */
        reject(resp, 403, "AUTHENTICATION_REJECTED", "the subscribed authentication method is not supported");
        goto done;
    }
    scheme = g5c_json_get_str(sub, "protectionParameterId");
    enc_k = g5c_json_get_str(sub, "encPermanentKey");
    enc_opc = g5c_json_get_str(sub, "encOpcKey");
    if (enc_k == NULL || enc_opc == NULL || udm_unprotect(&u->keys, enc_k, scheme, supi, k, sizeof k, &kl) != 0 ||
        kl != 16 || udm_unprotect(&u->keys, enc_opc, scheme, supi, opc, sizeof opc, &ol) != 0 || ol != 16) {
        G5C_LOGE("g5c_udm", "%s: stored credentials unusable (wrong master key, corruption or missing OPc)", supi);
        reject(resp, 500, "SYSTEM_FAILURE", "credentials unavailable");
        goto done;
    }
    amf_hex = g5c_json_get_str(sub, "authenticationManagementField");
    if (amf_hex != NULL)
        (void)hex_n(amf_hex, amf, 2); /* keeps the 0x8000 default when malformed */
    sqn_hex = g5c_json_get_str(g5c_json_get(sub, "sequenceNumber"), "sqn");
    if (sqn_hex == NULL || !udm_sqn_from_hex(sqn_hex, &sqn)) {
        reject(resp, 500, "SYSTEM_FAILURE", "stored SQN malformed");
        goto done;
    }

    if (resync_info != NULL) {
        uint8_t rnd[16], auts[14];
        uint64_t sqn_ms = 0;
        if (!hex_n(g5c_json_get_str(resync_info, "rand"), rnd, 16) || !hex_n(g5c_json_get_str(resync_info, "auts"), auts, 14)) {
            reject(resp, 400, "MANDATORY_IE_INCORRECT", "malformed resynchronizationInfo");
            goto done;
        }
        rc = udm_resync(k, opc, rnd, auts, &sqn_ms);
        if (rc == 1) {
            reject(resp, 403, "AUTHENTICATION_REJECTED", "AUTS MAC-S verification failed");
            goto done;
        }
        if (rc != 0) {
            reject(resp, 500, "SYSTEM_FAILURE", "crypto failure");
            goto done;
        }
        G5C_LOGI("g5c_udm", "%s: resynchronised SQN to %llu", supi, (unsigned long long)sqn_ms);
        sqn = sqn_ms;
    }

    /* advance and persist SQN *before* handing out the vector so a crash can never cause reuse */
    new_sqn = udm_next_sqn(sqn);
    udm_sqn_to_hex(new_sqn, hex);
    patch = g5c_json_new_arr();
    {
        g5c_json *op = g5c_json_push(patch, g5c_json_new_obj());
        g5c_json_set_str(op, "op", "replace");
        g5c_json_set_str(op, "path", "/sequenceNumber/sqn");
        g5c_json_set_str(op, "value", hex);
    }
    ur = udm_udr_patch_auth_subscription(&u->udr, supi, patch);
    if (ur.kind != UDR_OK) {
        udm_udr_fail(&ur, "USER_NOT_FOUND", resp);
        goto done;
    }
    if (prime) {
        /* RFC 5448 3.3: an EAP-AKA' vector carries the AMF separation bit; the SIM-provisioned AMF value may not have it */
        uint8_t amf_p[2] = {(uint8_t)(amf[0] | 0x80), amf[1]};
        char *h;
        if (u->rand_fn(u->rand_ctx, rand) != 0 || udm_generate_av_prime(k, opc, new_sqn, amf_p, rand, snn, &hp) != 0) {
            reject(resp, 500, "SYSTEM_FAILURE", "cannot generate vector");
            goto done;
        }
        res = g5c_json_new_obj();
        g5c_json_set_str(res, "authType", "EAP_AKA_PRIME");
        vec = g5c_json_set(res, "authenticationVector", g5c_json_new_obj());
        g5c_json_set_str(vec, "avType", "EAP_AKA_PRIME");
        h = g5c_hex_encode(hp.rand, 16);
        g5c_json_set_str(vec, "rand", h);
        free(h);
        h = g5c_hex_encode(hp.xres, 8);
        g5c_json_set_str(vec, "xres", h);
        free(h);
        h = g5c_hex_encode(hp.autn, 16);
        g5c_json_set_str(vec, "autn", h);
        free(h);
        h = g5c_hex_encode(hp.ck_prime, 16);
        g5c_json_set_str(vec, "ckPrime", h);
        free(h);
        h = g5c_hex_encode(hp.ik_prime, 16);
        g5c_json_set_str(vec, "ikPrime", h);
        free(h);
        g5c_json_set_str(res, "supi", supi);
        g5c_resp_json(resp, 200, res);
        goto done;
    }
    if (u->rand_fn(u->rand_ctx, rand) != 0 || udm_generate_av(k, opc, new_sqn, amf, rand, snn, &av) != 0) {
        reject(resp, 500, "SYSTEM_FAILURE", "cannot generate vector");
        goto done;
    }
    res = g5c_json_new_obj();
    g5c_json_set_str(res, "authType", "5G_AKA");
    vec = g5c_json_set(res, "authenticationVector", g5c_json_new_obj());
    g5c_json_set_str(vec, "avType", "5G_HE_AKA");
    {
        char *h;
        h = g5c_hex_encode(av.rand, 16);
        g5c_json_set_str(vec, "rand", h);
        free(h);
        h = g5c_hex_encode(av.xres_star, 16);
        g5c_json_set_str(vec, "xresStar", h);
        free(h);
        h = g5c_hex_encode(av.autn, 16);
        g5c_json_set_str(vec, "autn", h);
        free(h);
        h = g5c_hex_encode(av.kausf, 32);
        g5c_json_set_str(vec, "kausf", h);
        free(h);
    }
    g5c_json_set_str(res, "supi", supi);
    g5c_resp_json(resp, 200, res);
done:
    OPENSSL_cleanse(k, sizeof k);
    OPENSSL_cleanse(opc, sizeof opc);
    OPENSSL_cleanse(&av, sizeof av);
    OPENSSL_cleanse(&hp, sizeof hp);
    g5c_json_free(res);
    g5c_json_free(patch);
    g5c_json_free(sub);
}

static void generate_auth_data(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    g5c_json *ask = g5c_req_json(req, resp);
    const char *snn, *id;
    char supi[48];
    int rc;
    udm_supi_lock *lk;
    const g5c_json *ri;

    if (ask == NULL) {
        vec_count(u, "bad_request");
        return;
    }
    snn = g5c_json_get_str(ask, "servingNetworkName");
    ri = g5c_json_get(ask, "resynchronizationInfo");
    if (snn == NULL || (ri != NULL && !g5c_json_is(ri, G5C_J_NULL) &&
                        (g5c_json_get_str(ri, "rand") == NULL || g5c_json_get_str(ri, "auts") == NULL))) {
        vec_count(u, "bad_request");
        reject(resp, 400, "MANDATORY_IE_INCORRECT", "invalid AuthenticationInfoRequest");
        g5c_json_free(ask);
        return;
    }
    if (g5c_json_is(ri, G5C_J_NULL))
        ri = NULL;
    if (!udm_valid_snn(snn)) {
        vec_count(u, "reject");
        reject(resp, 403, "SERVING_NETWORK_NOT_AUTHORIZED", "malformed serving network name");
        g5c_json_free(ask);
        return;
    }
    id = path_param(req, "supiOrSuci");
    rc = udm_resolve(id, u->hn_keys, u->nhn_keys, supi, sizeof supi);
    if (rc == UDM_ID_MALFORMED) {
        vec_count(u, "bad_request");
        reject(resp, 400, "MANDATORY_IE_INCORRECT", "malformed SUPI or SUCI");
        g5c_json_free(ask);
        return;
    }
    if (rc != 0) {
        vec_count(u, "reject");
        G5C_LOGW("g5c_udm", "SUCI resolution failed (%d)", rc);
        reject(resp, 403, "AUTHENTICATION_REJECTED", "cannot resolve subscriber identity");
        g5c_json_free(ask);
        return;
    }
    lk = udm_lock_supi(u, supi);
    vector_for(u, supi, snn, ri, resp);
    udm_unlock_supi(u, lk);
    if (resp->status == 200)
        G5C_LOGI("g5c_udm", "%s: authentication vector generated%s", supi, ri != NULL ? " (resynchronization)" : "");
    vec_count(u, resp->status == 200 ? "ok" : resp->status == 404 ? "unknown_subscriber" : resp->status == 403 ? "reject" : "error");
    g5c_json_free(ask);
}

static void auth_event(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    g5c_json *ev = g5c_req_json(req, resp), *out;
    static const char *const fields[] = {"nfInstanceId", "timeStamp", "authType", "servingNetworkName"};
    const char *supi = path_param(req, "supi");
    char tmp[48], stamp[21], *id, *loc, *path;
    bool success = false;
    udr_result ur;

    if (ev == NULL)
        return;
    for (size_t i = 0; i < sizeof fields / sizeof *fields; i++)
        if (g5c_json_get_str(ev, fields[i]) == NULL) {
            char *d = g5c_xasprintf("missing field `%s`", fields[i]);
            reject(resp, 400, "MANDATORY_IE_INCORRECT", d);
            free(d);
            g5c_json_free(ev);
            return;
        }
    if (!g5c_json_get_bool(ev, "success", &success)) {
        reject(resp, 400, "MANDATORY_IE_INCORRECT", "missing field `success`");
        g5c_json_free(ev);
        return;
    }
    if (udm_resolve(supi, NULL, 0, tmp, sizeof tmp) != 0) {
        reject(resp, 400, "MANDATORY_IE_INCORRECT", "supi must be imsi-...");
        g5c_json_free(ev);
        return;
    }
    /* store exactly the AuthEvent attributes (unknown ones are dropped) */
    out = g5c_json_new_obj();
    g5c_json_set_str(out, "nfInstanceId", g5c_json_get_str(ev, "nfInstanceId"));
    g5c_json_set_bool(out, "success", success);
    g5c_json_set_str(out, "timeStamp", g5c_json_get_str(ev, "timeStamp"));
    g5c_json_set_str(out, "authType", g5c_json_get_str(ev, "authType"));
    g5c_json_set_str(out, "servingNetworkName", g5c_json_get_str(ev, "servingNetworkName"));
    ur = udm_udr_put_auth_status(&u->udr, supi, out);
    if (ur.kind != UDR_OK) {
        udm_udr_fail(&ur, "USER_NOT_FOUND", resp);
        goto done;
    }
    count(u, "g5c_udm_auth_events_total", "Authentication events by outcome.", "success", success ? "true" : "false");
    /* the id only needs to be unique per event; the stored status is the latest one */
    udm_now_iso8601(stamp);
    {
        char *w = stamp;
        for (const char *p = stamp; *p; p++)
            if (*p != ':' && *p != '-')
                *w++ = *p;
        *w = 0;
    }
    id = g5c_xasprintf("%s-%s", stamp, success ? "true" : "false");
    path = g5c_xasprintf("/nudm-ueau/v1/%s/auth-events/%s", supi, id);
    loc = g5c_req_url(req, path);
    g5c_resp_json(resp, 201, out);
    g5c_resp_header(resp, "location", loc);
    free(id);
    free(path);
    free(loc);
done:
    g5c_json_free(out);
    g5c_json_free(ev);
}

/* Auth removal (Nudm_UEAuthentication_Delete): the AUSF tells us the authentication result is no longer needed, e.g.
 * after de-registration. Open5GS sends `PUT .../auth-events` without an id, the specification names
 * `PUT .../auth-events/{authEventId}`; accept both. */
static void auth_removal(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    const char *supi = path_param(req, "supi");
    char tmp[48];
    g5c_json *ev, *sub = NULL;
    udr_result ur;
    if (udm_resolve(supi, NULL, 0, tmp, sizeof tmp) != 0) {
        reject(resp, 400, "MANDATORY_IE_INCORRECT", "supi must be imsi-...");
        return;
    }
    ev = g5c_req_json(req, resp); /* tolerate any JSON */
    if (ev == NULL)
        return;
    ur = udm_udr_auth_subscription(&u->udr, supi, &sub);
    g5c_json_free(sub);
    if (ur.kind != UDR_OK) {
        reject(resp, 404, "USER_NOT_FOUND", "unknown subscriber");
        g5c_json_free(ev);
        return;
    }
    {
        char *t = g5c_json_to_string(ev, NULL);
        G5C_LOGI("g5c_udm", "%s: authentication removal requested: %s", supi, t ? t : "");
        free(t);
    }
    G5C_COUNT(u->metrics, "g5c_udm_auth_removals_total", "Auth removal indications received.");
    g5c_resp_status(resp, 204);
    g5c_json_free(ev);
}

/* Nudm_UEAuthentication_Get for an FN-RG (TS 29.503 6.3.3.3, TS 29.509 5.2.2.2.4): the SUPI of the gateway and whether its authentication is still needed. The W-AGF has
 * authenticated the gateway when authenticated-ind is true; then no further authentication is required (authInd true). */
static void security_information_rg(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    char *ind = g5c_req_query_decoded(req, "authenticated-ind"), supi[48];
    bool authenticated;
    g5c_json *sub = NULL, *out;
    udr_result ur;
    int rc;
    if (ind == NULL || (strcmp(ind, "true") != 0 && strcmp(ind, "false") != 0)) {
        free(ind);
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_MISSING", "authenticated-ind", "mandatory boolean");
        return;
    }
    authenticated = strcmp(ind, "true") == 0;
    free(ind);
    rc = udm_resolve(path_param(req, "supiOrSuci"), u->hn_keys, u->nhn_keys, supi, sizeof supi);
    if (rc == UDM_ID_MALFORMED) {
        reject(resp, 400, "MANDATORY_IE_INCORRECT", "malformed SUPI or SUCI");
        return;
    }
    if (rc != 0) {
        reject(resp, 403, "AUTHENTICATION_REJECTED", "cannot resolve subscriber identity");
        return;
    }
    ur = udm_udr_auth_subscription(&u->udr, supi, &sub);
    g5c_json_free(sub);
    if (ur.kind != UDR_OK) {
        udm_udr_fail(&ur, "USER_NOT_FOUND", resp);
        return;
    }
    out = g5c_json_new_obj();
    g5c_json_set_bool(out, "authInd", authenticated);
    g5c_json_set_str(out, "supi", supi);
    g5c_resp_json(resp, 200, out);
    g5c_json_free(out);
}

void udm_ueau_routes(g5c_router *r, udm *u)
{
    g5c_router_route(r, "GET", "/nudm-ueau/v1/{supiOrSuci}/security-information-rg", security_information_rg, u);
    g5c_router_route(r, "POST", "/nudm-ueau/v1/{supiOrSuci}/security-information/generate-auth-data", generate_auth_data, u);
    g5c_router_route(r, "POST", "/nudm-ueau/v1/{supi}/auth-events", auth_event, u);
    g5c_router_route(r, "PUT", "/nudm-ueau/v1/{supi}/auth-events", auth_removal, u);
    g5c_router_route(r, "PUT", "/nudm-ueau/v1/{supi}/auth-events/{authEventId}", auth_removal, u);
}
