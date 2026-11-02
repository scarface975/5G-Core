/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nausf_UEAuthentication (TS 29.509 clause 5.2, 6.1): start of an authentication (5G AKA and EAP-AKA'), the 5G AKA confirmation, the removal of a result, the
 * clean-up of a security context and the FN-RG authentication. The EAP session is in eap.c. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "priv.h"

#define BASE "/nausf-auth/v1/ue-authentications"

static bool hex_n(const char *h, uint8_t *out, size_t n)
{
    return h != NULL && strlen(h) == 2 * n && g5c_hex_decode(h, out, n) == (long)n;
}

/* a link or Location value: this AUSF's configured address when there is one, else the address the consumer used */
static char *link_to(ausf *a, const g5c_req *req, const char *path)
{
    bool fixed;
    pthread_mutex_lock(&a->mu);
    fixed = a->self_uri[0] != 0;
    pthread_mutex_unlock(&a->mu);
    return fixed ? ausf_url(a, path) : g5c_req_url(req, path);
}

/* TS 33.501 6.1.1.4 / TS 24.501: "5G:mnc<3 digits>.mcc<3 digits>.3gppnetwork.org" */
static bool snn_valid(const char *s)
{
    if (s == NULL || strlen(s) != 32 || strncmp(s, "5G:mnc", 6) != 0 || strncmp(s + 9, ".mcc", 4) != 0 || strcmp(s + 16, ".3gppnetwork.org") != 0)
        return false;
    for (int i = 6; i < 9; i++)
        if (!isdigit((unsigned char)s[i]) || !isdigit((unsigned char)s[i + 7]))
            return false;
    return true;
}

static bool snn_allowed(ausf *a, const char *snn)
{
    if (a->o.n_snn_allow == 0)
        return true;
    for (size_t i = 0; i < a->o.n_snn_allow; i++)
        if (strcmp(a->o.snn_allow[i], snn) == 0)
            return true;
    return false;
}

static bool cause_in(const char *c, const char *const *set)
{
    for (; *set; set++)
        if (strcmp(c, *set) == 0)
            return true;
    return false;
}

void ausf_udm_failure(const udm_answer *u, g5c_resp *resp)
{
    static const char *const c403[] = {"AUTHENTICATION_REJECTED", "SERVING_NETWORK_NOT_AUTHORIZED", "INVALID_HN_PUBLIC_KEY_IDENTIFIER", "INVALID_SCHEME_OUTPUT", NULL};
    if (u->no_udm) {
        g5c_resp_problem_simple(resp, 504, "NETWORK_FAILURE", "no UDM is available");
    } else if (u->status == 0) {
        g5c_resp_problem_simple(resp, 504, "UPSTREAM_SERVER_ERROR", "the UDM did not answer");
    } else if (u->status == 404) {
        g5c_resp_problem_simple(resp, 404, "USER_NOT_FOUND", "the subscriber is not known");
    } else if (u->status == 403) {
        g5c_resp_problem_simple(resp, 403, cause_in(u->cause, c403) ? u->cause : "AUTHENTICATION_REJECTED", "the UDM rejected the authentication");
    } else if (u->status == 400) {
        g5c_resp_problem_simple(resp, 400, u->cause[0] ? u->cause : "MANDATORY_IE_INCORRECT", "the UDM could not process the request");
    } else if (u->status == 501) {
        g5c_resp_problem_simple(resp, 501, "UNSUPPORTED_PROTECTION_SCHEME", "the protection scheme of the SUCI is not supported");
    } else if (u->status == 503 || u->status == 429) {
        g5c_resp_problem_simple(resp, u->status, u->cause[0] ? u->cause : "UNSPECIFIED", "the UDM is overloaded");
    } else {
        g5c_resp_problem_simple(resp, 500, "AV_GENERATION_PROBLEM", "the UDM could not generate an authentication vector");
    }
}

/* ---- POST /ue-authentications --------------------------------------------------------------------------------------------------------------------- */

static void bad_request(ausf *a, g5c_resp *resp, const char *param, const char *reason)
{
    ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "unknown", "result", "bad_request");
    g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", param, reason);
}

void ausf_ueau_start(ausf *a, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *info = g5c_req_json(req, resp), *res = NULL, *out = NULL, *links, *k;
    const g5c_json *ri, *av;
    const char *id_in, *snn, *auth_type, *supi;
    udm_answer u;
    ausf_ctx *c = NULL;
    char *href, *loc, cid[37]; /* the id outlives the context: a newer start for the same UE may replace it the moment it is in the table */
    bool n5gc = false;

    memset(&u, 0, sizeof u);
    if (info == NULL) {
        ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "unknown", "result", "bad_request");
        return;
    }
    id_in = g5c_json_get_str(info, "supiOrSuci");
    snn = g5c_json_get_str(info, "servingNetworkName");
    if (id_in == NULL) {
        bad_request(a, resp, "supiOrSuci", "mandatory");
        goto done;
    }
    if (snn == NULL) {
        bad_request(a, resp, "servingNetworkName", "mandatory");
        goto done;
    }
    if (!ausf_valid_supi_or_suci(id_in)) {
        bad_request(a, resp, "supiOrSuci", "not a SUPI or SUCI");
        goto done;
    }
    ri = g5c_json_get(info, "resynchronizationInfo");
    if (g5c_json_is(ri, G5C_J_NULL))
        ri = NULL;
    if (ri != NULL) {
        uint8_t b[16];
        if (!g5c_json_is(ri, G5C_J_OBJECT) || !hex_n(g5c_json_get_str(ri, "rand"), b, 16) || !hex_n(g5c_json_get_str(ri, "auts"), b, 14)) {
            bad_request(a, resp, "resynchronizationInfo", "rand and auts are 32 and 28 hexadecimal characters");
            goto done;
        }
    }
    (void)g5c_json_get_bool(info, "n5gcInd", &n5gc);
    if (n5gc) {
        /* EAP-TLS for N5GC devices (TS 33.501 Annex O) is not offered */
        ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "eap-tls", "result", "rejected");
        g5c_resp_problem_simple(resp, 403, "AUTHENTICATION_REJECTED", "authentication of N5GC devices is not supported");
        goto done;
    }
    /* TS 33.501 6.1.2: the serving network must be entitled to use the name it claims */
    if (!snn_valid(snn) || !snn_allowed(a, snn)) {
        ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "unknown", "result", "snn_rejected");
        g5c_resp_problem_simple(resp, 403, "SERVING_NETWORK_NOT_AUTHORIZED", "the serving network name is not authorized");
        goto done;
    }

    udm_generate(a, id_in, snn, ri, &u);
    if (u.no_udm || u.status != 200) {
        ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "unknown", "result",
                    u.no_udm || u.status == 0 ? "udm_unreachable" : "udm_rejected");
        ausf_udm_failure(&u, resp);
        goto done;
    }
    res = u.body;
    u.body = NULL;
    auth_type = g5c_json_get_str(res, "authType");
    av = g5c_json_get(res, "authenticationVector");
    supi = g5c_json_get_str(res, "supi");
    if (auth_type == NULL || !g5c_json_is(av, G5C_J_OBJECT) || !ausf_valid_supi(supi) || (!g5c_starts_with(id_in, "suci-") && strcmp(id_in, supi) != 0)) {
        ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "unknown", "result", "udm_malformed");
        g5c_resp_problem_simple(resp, 500, "AV_GENERATION_PROBLEM", "malformed answer of the UDM");
        goto done;
    }
    c = ctx_new(id_in, snn);
    if (c == NULL) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot create a context");
        goto done;
    }
    c->supi = g5c_xstrdup(supi);

    if (strcmp(auth_type, "5G_AKA") == 0) {
        uint8_t rand[16], xres[16], kausf[32], hxres[16];
        const char *avt = g5c_json_get_str(av, "avType");
        c->method = M_5GAKA;
        if ((avt != NULL && strcmp(avt, "5G_HE_AKA") != 0) || !hex_n(g5c_json_get_str(av, "rand"), rand, 16) || !hex_n(g5c_json_get_str(av, "xresStar"), xres, 16) ||
            !hex_n(g5c_json_get_str(av, "kausf"), kausf, 32) || !hex_n(g5c_json_get_str(av, "autn"), c->autn, 16)) {
            ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "5g-aka", "result", "udm_malformed");
            g5c_resp_problem_simple(resp, 500, "AV_GENERATION_PROBLEM", "malformed authentication vector");
            goto done;
        }
        if (g5c_hres_star(rand, xres, hxres) != 0) {
            g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "crypto failure");
            goto done;
        }
        memcpy(c->rand, rand, 16);
        memcpy(c->xres_star, xres, 16);
        memcpy(c->kausf, kausf, 32);
        OPENSSL_cleanse(kausf, sizeof kausf);
        memcpy(cid, c->id, sizeof cid);
        if (!store_insert(a, c)) {
            ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "5g-aka", "result", "overload");
            g5c_resp_problem_simple(resp, 503, "INSUFFICIENT_RESOURCES", "too many authentications in progress");
            goto done;
        }
        out = g5c_json_new_obj();
        g5c_json_set_str(out, "authType", "5G_AKA");
        {
            g5c_json *d = g5c_json_set(out, "5gAuthData", g5c_json_new_obj());
            char *hx = g5c_hex_encode(hxres, 16);
            g5c_json_set_str(d, "rand", g5c_json_get_str(av, "rand"));
            g5c_json_set_str(d, "hxresStar", hx);
            g5c_json_set_str(d, "autn", g5c_json_get_str(av, "autn"));
            free(hx);
        }
        links = g5c_json_set(out, "_links", g5c_json_new_obj());
        k = g5c_json_set(links, "5g-aka", g5c_json_new_obj());
        {
            char *p = g5c_xasprintf(BASE "/%s/5g-aka-confirmation", cid);
            href = link_to(a, req, p);
            free(p);
        }
        g5c_json_set_str(k, "href", href);
        free(href);
        g5c_json_set_str(out, "servingNetworkName", snn);
        g5c_resp_json(resp, 201, out);
        ausf_hal(resp);
        ausf_no_store(resp);
        {
            char *p = g5c_xasprintf(BASE "/%s", cid);
            loc = link_to(a, req, p);
            free(p);
        }
        g5c_resp_header(resp, "location", loc);
        free(loc);
        ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "5g-aka", "result", "started");
        c = NULL; /* now owned by the table */
    } else if (strcmp(auth_type, "EAP_AKA_PRIME") == 0) {
        c->method = M_EAP_PRIME;
        if (!eap_start(a, c, av, resp, &out)) {
            goto done;
        }
        memcpy(cid, c->id, sizeof cid);
        if (!store_insert(a, c)) {
            ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "eap-aka-prime", "result", "overload");
            g5c_json_free(out);
            out = NULL;
            g5c_resp_problem_simple(resp, 503, "INSUFFICIENT_RESOURCES", "too many authentications in progress");
            goto done;
        }
        links = g5c_json_get_mut(out, "_links");
        k = g5c_json_get_mut(links, "eap-session");
        {
            char *p = g5c_xasprintf(BASE "/%s/eap-session", cid);
            href = link_to(a, req, p);
            free(p);
        }
        g5c_json_set_str(k, "href", href);
        free(href);
        g5c_resp_json(resp, 201, out);
        ausf_hal(resp);
        ausf_no_store(resp);
        {
            char *p = g5c_xasprintf(BASE "/%s", cid);
            loc = link_to(a, req, p);
            free(p);
        }
        g5c_resp_header(resp, "location", loc);
        free(loc);
        ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "eap-aka-prime", "result", "started");
        c = NULL;
    } else {
        ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "unknown", "result", "unsupported_method");
        g5c_resp_problem_simple(resp, 501, "UNSUPPORTED_PROTECTION_SCHEME", "the authentication method chosen by the UDM is not supported");
    }
done:
    ctx_free(c);
    g5c_json_free(out);
    g5c_json_free(res);
    udm_answer_free(&u);
    g5c_json_free(info);
}

static void start_route(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    ausf_ueau_start(ctx, req, resp);
}

/* ---- PUT .../5g-aka-confirmation ------------------------------------------------------------------------------------------------------------------ */

static void not_found(g5c_resp *resp)
{
    g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "unknown or expired authentication context");
}

/* put a context that was taken out for a request back where it was */
static void put_back(ausf *a, ausf_ctx *c)
{
    if (c->st == ST_DONE)
        store_finish(a, c);
    else if (!store_reinsert(a, c))
        ctx_free(c);
}

static void confirm(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    ausf *a = ctx;
    g5c_json *conf = g5c_req_json(req, resp), *out;
    const g5c_json *rs;
    const char *id = g5c_req_param(req, "authCtxId");
    ausf_ctx *c;
    uint8_t res_star[16];
    bool ok = false;
    char *event_id = NULL;

    if (conf == NULL)
        return;
    rs = g5c_json_get(conf, "resStar");
    /* null is the AMF's way of saying that no RES* came (TS 29.509 5.2.2.2.2 step 3); anything else must be 32 hexadecimal characters */
    if (rs == NULL || (!g5c_json_is(rs, G5C_J_NULL) && !hex_n(g5c_json_str(rs), res_star, 16))) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "resStar", rs == NULL ? "mandatory" : "32 hexadecimal characters or null");
        g5c_json_free(conf);
        return;
    }
    /* taking the context out makes the confirmation single use: a replay finds nothing (TS 29.509 6.1.3.3.1) */
    c = store_take(a, id != NULL ? id : "");
    if (c == NULL || c->method != M_5GAKA || c->st != ST_AKA_WAIT) {
        ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "5g-aka", "result", "unknown_context");
        if (c != NULL)
            put_back(a, c);
        not_found(resp);
        g5c_json_free(conf);
        return;
    }
    ok = !g5c_json_is(rs, G5C_J_NULL) && CRYPTO_memcmp(res_star, c->xres_star, 16) == 0;
    ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "5g-aka", "result", ok ? "success" : "failure");

    G5C_LOGI("g5c_ausf", "%s: 5G AKA %s", c->supi, ok ? "authentication succeeded" : "authentication FAILED");
    /* TS 33.501 6.1.4.1: the home network records the result; the answer to the AMF does not wait for it to be accepted */
    (void)udm_auth_event(a, c->supi, c->snn, "5G_AKA", ok, &event_id);

    out = g5c_json_new_obj();
    g5c_json_set_str(out, "authResult", ok ? "AUTHENTICATION_SUCCESS" : "AUTHENTICATION_FAILURE");
    g5c_json_set_str(out, "supi", c->supi);
    if (ok) {
        uint8_t kseaf[32];
        char *k;
        if (g5c_kseaf(c->kausf, c->snn, kseaf) != 0) {
            g5c_json_free(out);
            g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "crypto failure");
            free(event_id);
            ctx_free(c);
            g5c_json_free(conf);
            return;
        }
        k = g5c_hex_encode(kseaf, 32);
        g5c_json_set_str(out, "kseaf", k);
        OPENSSL_cleanse(k, strlen(k));
        free(k);
        OPENSSL_cleanse(kseaf, sizeof kseaf);
        ue_store(a, c->supi, c->snn, M_5GAKA, c->kausf, c->id); /* TS 33.501 6.1.3.2.0 step 11: the latest KAUSF is kept */
        free(c->auth_event_id);
        c->auth_event_id = event_id;
        event_id = NULL;
    }
    g5c_resp_json(resp, 200, out);
    ausf_no_store(resp); /* KSEAF */
    g5c_json_free(out);
    free(event_id);
    if (ok)
        store_finish(a, c); /* kept (without its secrets) until its result is removed */
    else
        ctx_free(c);
    g5c_json_free(conf);
}

/* ---- DELETE .../5g-aka-confirmation and .../eap-session ------------------------------------------------------------------------------------------- */

static void remove_result(ausf *a, const g5c_req *req, g5c_resp *resp, ausf_method m)
{
    const char *id = g5c_req_param(req, "authCtxId");
    ausf_ctx *c = store_take(a, id != NULL ? id : "");
    if (c == NULL || c->method != m) {
        if (c != NULL)
            put_back(a, c);
        not_found(resp);
        return;
    }
    /* TS 29.509 5.2.2.2.5 / 5.2.2.2.6: the AUSF has the UDM remove the result. Only the current result of the UE is removed: a newer authentication has replaced
     * this one in the UDM already. */
    if (c->st == ST_DONE && c->supi != NULL && c->auth_event_id != NULL && ue_is_current(a, c->supi, c->id))
        (void)udm_auth_removal(a, c->supi, c->snn, m == M_5GAKA ? "5G_AKA" : "EAP_AKA_PRIME", c->auth_event_id);
    ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", m == M_5GAKA ? "5g-aka" : "eap-aka-prime", "result", "removed");
    ctx_free(c);
    g5c_resp_status(resp, 204);
}

static void del_confirmation(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    remove_result(ctx, req, resp, M_5GAKA);
}

static void del_eap(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    remove_result(ctx, req, resp, M_EAP_PRIME);
}

/* ---- POST /ue-authentications/deregister ------------------------------------------------------------------------------------------------------------ */

static void deregister(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    ausf *a = ctx;
    g5c_json *j = g5c_req_json(req, resp);
    const char *supi;
    if (j == NULL)
        return;
    supi = g5c_json_get_str(j, "supi");
    if (supi == NULL || !ausf_valid_supi(supi)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "supi", supi == NULL ? "mandatory" : "not a SUPI");
        g5c_json_free(j);
        return;
    }
    if (ue_drop(a, supi)) {
        ausf_count(a, "g5c_ausf_deregistrations_total", "Security contexts cleared at the request of the UDM.", NULL, NULL);
        g5c_resp_status(resp, 204);
    } else {
        not_found(resp);
    }
    g5c_json_free(j);
}

/* ---- POST /rg-authentications ----------------------------------------------------------------------------------------------------------------------- */

static void rg_auth(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    ausf *a = ctx;
    g5c_json *j = g5c_req_json(req, resp), *out;
    const char *suci;
    bool ind = false;
    udm_answer u;
    char id[37], *p, *loc;
    bool auth_ok, auth_ind = false;
    const char *supi;

    if (j == NULL)
        return;
    suci = g5c_json_get_str(j, "suci");
    if (suci == NULL || !ausf_valid_supi_or_suci(suci) || !g5c_json_get_bool(j, "authenticatedInd", &ind)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", suci == NULL ? "suci" : "authenticatedInd", "mandatory or malformed");
        g5c_json_free(j);
        return;
    }
    udm_rg_auth_ctx(a, suci, ind, &u);
    if (u.no_udm || u.status != 200) {
        ausf_udm_failure(&u, resp);
        udm_answer_free(&u);
        g5c_json_free(j);
        return;
    }
    supi = g5c_json_get_str(u.body, "supi");
    (void)g5c_json_get_bool(u.body, "authInd", &auth_ind);
    /* TS 29.509 5.2.2.2.4: the W-AGF has authenticated the FN-RG, the AUSF does not authenticate it again */
    auth_ok = ind && auth_ind && ausf_valid_supi(supi);
    out = g5c_json_new_obj();
    g5c_json_set_str(out, "authResult", auth_ok ? "AUTHENTICATION_SUCCESS" : "AUTHENTICATION_FAILURE");
    if (auth_ok)
        g5c_json_set_str(out, "supi", supi);
    g5c_json_set_bool(out, "authInd", auth_ok);
    if (g5c_uuid_v4(id) != 0)
        snprintf(id, sizeof id, "00000000-0000-4000-8000-000000000000");
    p = g5c_xasprintf("/nausf-auth/v1/rg-authentications/%s", id);
    loc = link_to(a, req, p);
    free(p);
    g5c_resp_json(resp, 201, out);
    g5c_resp_header(resp, "location", loc);
    free(loc);
    ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "fn-rg", "result", auth_ok ? "success" : "failure");
    g5c_json_free(out);
    udm_answer_free(&u);
    g5c_json_free(j);
}

static void eap_route(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    eap_session_post(ctx, req, resp);
}

void ausf_ueau_routes(g5c_router *r, ausf *a)
{
    g5c_router_route(r, "POST", BASE, start_route, a);
    g5c_router_route(r, "POST", BASE "/deregister", deregister, a);
    g5c_router_route(r, "PUT", BASE "/{authCtxId}/5g-aka-confirmation", confirm, a);
    g5c_router_route(r, "DELETE", BASE "/{authCtxId}/5g-aka-confirmation", del_confirmation, a);
    g5c_router_route(r, "POST", BASE "/{authCtxId}/eap-session", eap_route, a);
    g5c_router_route(r, "DELETE", BASE "/{authCtxId}/eap-session", del_eap, a);
    g5c_router_route(r, "POST", "/nausf-auth/v1/rg-authentications", rg_auth, a);
}
