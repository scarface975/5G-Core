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

/* ---- auth_hook (backlog G-03): the vectors come from a program ----
 * The program gets one line on its standard input: {"supi", "servingNetworkName", "resynchronizationInfo": {"rand", "auts"}} (the last only after a synchronisation failure), and answers with
 * the vector on its standard output, as the Nudm_UEAuthentication response carries it: {"authType": "5G_AKA", "authenticationVector": {"rand", "xresStar", "autn", "kausf"}} or
 * {"authType": "EAP_AKA_PRIME", "authenticationVector": {"rand", "xres", "autn", "ckPrime", "ikPrime"}}, every value in hex. Exit status 0: the vector is taken; 3: not a subscriber of
 * the program, the UDM derives the vector itself from the stored K and OPc; 4: unknown subscriber (404); 5: authentication rejected (403); anything else, a timeout or an answer that does not
 * fit is a system failure (500) and is logged without the vector. The UDM keeps no SQN for a subscriber the program serves. */
static bool hex_len_ok(const g5c_json *v, const char *key, size_t min_bytes, size_t max_bytes)
{
    const char *h = g5c_json_get_str(v, key);
    uint8_t tmp[64];
    size_t n = h != NULL ? strlen(h) : 0;
    long got;
    if (n < 2 * min_bytes || n > 2 * max_bytes || n % 2 != 0)
        return false;
    got = g5c_hex_decode(h, tmp, sizeof tmp);
    OPENSSL_cleanse(tmp, sizeof tmp);
    return got == (long)(n / 2);
}

static bool hook_vector(udm *u, const char *supi, const char *snn, const g5c_json *resync_info, g5c_resp *resp)
{
    g5c_json *rq = g5c_json_new_obj(), *ans = NULL, *res, *vec;
    char *line, out[2048], perr[100];
    const char *type;
    bool prime;
    int rc;
    g5c_json_set_str(rq, "supi", supi);
    g5c_json_set_str(rq, "servingNetworkName", snn);
    if (resync_info != NULL)
        g5c_json_set(rq, "resynchronizationInfo", g5c_json_dup(resync_info));
    line = g5c_json_to_string(rq, NULL);
    g5c_json_free(rq);
    rc = g5c_hookcall_run(u->auth_hook, line, out, sizeof out);
    free(line);
    if (rc == 3)
        return false;
    if (rc == 4) {
        reject(resp, 404, "USER_NOT_FOUND", "unknown subscriber");
        return true;
    }
    if (rc == 5) {
        reject(resp, 403, "AUTHENTICATION_REJECTED", "authentication rejected");
        return true;
    }
    if (rc == 0)
        ans = g5c_json_parse(out, strlen(out), perr, sizeof perr);
    OPENSSL_cleanse(out, strlen(out));
    type = g5c_json_get_str(ans, "authType");
    prime = g5c_streq(type, "EAP_AKA_PRIME");
    vec = (g5c_json *)(uintptr_t)g5c_json_get(ans, "authenticationVector");
    if (rc != 0 || ans == NULL || (!prime && !g5c_streq(type, "5G_AKA")) || vec == NULL || !hex_len_ok(vec, "rand", 16, 16) || !hex_len_ok(vec, "autn", 16, 16) ||
        (prime ? !(hex_len_ok(vec, "xres", 4, 16) && hex_len_ok(vec, "ckPrime", 16, 16) && hex_len_ok(vec, "ikPrime", 16, 16))
               : !(hex_len_ok(vec, "xresStar", 16, 16) && hex_len_ok(vec, "kausf", 32, 32)))) {
        G5C_LOGE("g5c_udm", "%s: the authentication hook failed (%s)", supi, rc == -2 ? "timeout" : rc != 0 ? "exit status or no answer" : "the vector does not fit");
        reject(resp, 500, "SYSTEM_FAILURE", "authentication hook failed");
        g5c_json_free(ans);
        return true;
    }
    res = g5c_json_new_obj();
    g5c_json_set_str(res, "authType", prime ? "EAP_AKA_PRIME" : "5G_AKA");
    {
        static const char *const f_aka[] = {"rand", "xresStar", "autn", "kausf", NULL};
        static const char *const f_prime[] = {"rand", "xres", "autn", "ckPrime", "ikPrime", NULL};
        const char *const *f = prime ? f_prime : f_aka;
        g5c_json *ov = g5c_json_set(res, "authenticationVector", g5c_json_new_obj());
        g5c_json_set_str(ov, "avType", prime ? "EAP_AKA_PRIME" : "5G_HE_AKA");
        for (; *f != NULL; f++)
            g5c_json_set_str(ov, *f, g5c_json_get_str(vec, *f));
    }
    g5c_json_set_str(res, "supi", supi);
    g5c_resp_json(resp, 200, res);
    g5c_json_free(res);
    g5c_json_free(ans);
    return true;
}

static void vector_local(udm *u, const char *supi, const char *snn, const g5c_json *resync_info, g5c_resp *resp)
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
        /* EAP-TLS and anything else */
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

static void vector_for(udm *u, const char *supi, const char *snn, const g5c_json *resync_info, g5c_resp *resp)
{
    if (u->auth_hook != NULL && hook_vector(u, supi, snn, resync_info, resp))
        return;
    vector_local(u, supi, snn, resync_info, resp);
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
    rc = udm_resolve_ex(id, u->hn_keys, u->nhn_keys, !u->refuse_null_scheme, supi, sizeof supi);
    if (rc == UDM_ID_MALFORMED) {
        vec_count(u, "bad_request");
        reject(resp, 400, "MANDATORY_IE_INCORRECT", "malformed SUPI or SUCI");
        g5c_json_free(ask);
        return;
    }
    if (rc != 0) {
        vec_count(u, "reject");
        G5C_LOGW("g5c_udm", "SUCI resolution failed (%d)%s", rc, rc == UDM_ID_NULL_SCHEME ? ": the null protection scheme is refused (suci.null_scheme)" : "");
        reject(resp, 403, "AUTHENTICATION_REJECTED", rc == UDM_ID_NULL_SCHEME ? "the null protection scheme is not accepted" : "cannot resolve subscriber identity");
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

/* Auth removal (Nudm_UEAuthentication_Delete): the AUSF tells us the authentication result is no longer needed, e.g. after de-registration */
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

/* Nudm_UEAuthentication_Get for an FN-RG (TS 29.503 6.3.3.3, TS 29.509 5.2.2.2.4) */
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
    rc = udm_resolve_ex(path_param(req, "supiOrSuci"), u->hn_keys, u->nhn_keys, !u->refuse_null_scheme, supi, sizeof supi);
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
