/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* EAP-AKA' on the Nausf_UEAuthentication interface (TS 29.509 5.2.2.2.3, TS 33.501 6.1.3.1 and Annex F, RFC 4187, RFC 5448, RFC 9048) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "priv.h"

#define BASE "/nausf-auth/v1/ue-authentications"
#define MAX_RESYNC 2 /* sequence number resynchronisations in one session */

static bool hex_len(const char *h, uint8_t *out, size_t *n, size_t lo, size_t hi)
{
    size_t l = h != NULL ? strlen(h) : 0;
    if (l % 2 != 0 || l / 2 < lo || l / 2 > hi)
        return false;
    for (size_t i = 0; i < l; i++)
        if (!((h[i] >= '0' && h[i] <= '9') || (h[i] >= 'a' && h[i] <= 'f') || (h[i] >= 'A' && h[i] <= 'F')))
            return false;
    *n = l / 2;
    return g5c_hex_decode(h, out, hi) == (long)(l / 2);
}

/* the identity of the key derivation: the IMSI digits (TS 33.501 Annex F.3, RFC 9048 5.3.1), the NAI of a network specific identifier */
static const char *identity_of(const char *supi)
{
    if (g5c_starts_with(supi, "imsi-"))
        return supi + 5;
    if (g5c_starts_with(supi, "nai-"))
        return supi + 4;
    return NULL;
}

/* EAP-Request/AKA'-Challenge for c (its keys, RAND and AUTN are set) into out */
static int build_challenge(const ausf_ctx *c, uint8_t *out, size_t cap, size_t *len)
{
    uint8_t rand_v[18] = {0}, autn_v[18] = {0}, kdf_v[2] = {0, 1}, mac_v[18] = {0}, ind_v[2] = {0}, kin[2 + 64];
    size_t nl = strlen(c->snn), padded = (nl + 3) & ~(size_t)3, n = 0;
    g5c_eap_attr at[6];
    if (padded > 60)
        return -1;
    memcpy(rand_v + 2, c->rand, 16);
    memcpy(autn_v + 2, c->autn, 16);
    memset(kin, 0, sizeof kin);
    kin[0] = (uint8_t)(nl >> 8);
    kin[1] = (uint8_t)nl;
    memcpy(kin + 2, c->snn, nl); /* the Network Name field: the serving network name, padded with zero octets (RFC 5448 3.1) */
    at[n++] = (g5c_eap_attr){G5C_AT_RAND, rand_v, 18};
    at[n++] = (g5c_eap_attr){G5C_AT_AUTN, autn_v, 18};
    at[n++] = (g5c_eap_attr){G5C_AT_KDF, kdf_v, 2};
    at[n++] = (g5c_eap_attr){G5C_AT_KDF_INPUT, kin, 2 + padded};
    if (c->result_ind)
        at[n++] = (g5c_eap_attr){G5C_AT_RESULT_IND, ind_v, 2};
    at[n++] = (g5c_eap_attr){G5C_AT_MAC, mac_v, 18};
    if (g5c_eap_build(G5C_EAP_REQUEST, c->eap_id, G5C_EAPAKA_CHALLENGE, at, n, out, cap, len) != 0)
        return -1;
    return g5c_eap_mac_set(out, *len, c->keys.k_aut, NULL, 0);
}

/* the vector of the UDM into c; false (and resp filled) when it is unusable */
static bool load_vector(ausf_ctx *c, const g5c_json *vec, g5c_resp *resp)
{
    uint8_t rand[16], autn[16], ckp[16], ikp[16], xres[16];
    size_t n = 0, xl = 0;
    const char *avt = g5c_json_get_str(vec, "avType"), *identity = identity_of(c->supi);
    if ((avt != NULL && strcmp(avt, "EAP_AKA_PRIME") != 0) || !hex_len(g5c_json_get_str(vec, "rand"), rand, &n, 16, 16) ||
        !hex_len(g5c_json_get_str(vec, "autn"), autn, &n, 16, 16) || !hex_len(g5c_json_get_str(vec, "ckPrime"), ckp, &n, 16, 16) ||
        !hex_len(g5c_json_get_str(vec, "ikPrime"), ikp, &n, 16, 16) || !hex_len(g5c_json_get_str(vec, "xres"), xres, &xl, 4, 16)) {
        g5c_resp_problem_simple(resp, 500, "AV_GENERATION_PROBLEM", "malformed EAP-AKA' authentication vector");
        return false;
    }
    /* RFC 5448 3.3: the AMF separation bit of AUTN (bit 0 of the AMF field, the first of its two octets read as bit 8) must be 1 */
    if ((autn[6] & 0x80) == 0 || identity == NULL) {
        g5c_resp_problem_simple(resp, 500, "AV_GENERATION_PROBLEM", "the vector cannot be used for EAP-AKA'");
        return false;
    }
    memcpy(c->rand, rand, 16);
    memcpy(c->autn, autn, 16);
    memcpy(c->xres, xres, xl);
    c->xres_len = xl;
    if (g5c_eapaka_prime_keys(ckp, ikp, identity, &c->keys) != 0) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "crypto failure");
        return false;
    }
    OPENSSL_cleanse(ckp, sizeof ckp);
    OPENSSL_cleanse(ikp, sizeof ikp);
    return true;
}

bool eap_start(ausf *a, ausf_ctx *c, const g5c_json *vec, g5c_resp *resp, g5c_json **ctx_body)
{
    uint8_t pkt[G5C_EAP_MAX_PKT], rb[1];
    size_t len = 0;
    char *b64;
    g5c_json *out, *links;
    if (!load_vector(c, vec, resp)) {
        ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "eap-aka-prime", "result", "udm_malformed");
        return false;
    }
    if (a->o.eap_first_id != 0) {
        rb[0] = a->o.eap_first_id;
    } else if (g5c_random(rb, 1) != 0) {
        rb[0] = 1;
    }
    c->eap_id = rb[0] != 0 ? rb[0] : 1;
    c->result_ind = a->o.eap_result_ind;
    if (build_challenge(c, pkt, sizeof pkt, &len) != 0) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot build the EAP challenge");
        return false;
    }
    out = g5c_json_new_obj();
    b64 = g5c_base64_encode(pkt, len);
    g5c_json_set_str(out, "authType", "EAP_AKA_PRIME");
    links = g5c_json_set(out, "_links", g5c_json_new_obj());
    g5c_json_set(links, "eap-session", g5c_json_new_obj()); /* the href is set by the caller, who knows the context id and the address */
    g5c_json_set_str(out, "5gAuthData", b64);
    g5c_json_set_str(out, "servingNetworkName", c->snn);
    free(b64);
    *ctx_body = out;
    return true;
}

/* ---- the session ---- */

static g5c_json *eap_reply(const uint8_t *pkt, size_t len, const char *result)
{
    g5c_json *o = g5c_json_new_obj();
    char *b64 = g5c_base64_encode(pkt, len);
    g5c_json_set_str(o, "eapPayload", b64);
    free(b64);
    if (result != NULL)
        g5c_json_set_str(o, "authResult", result);
    return o;
}

static void add_link(const g5c_req *req, const ausf_ctx *c, g5c_json *o, ausf *a)
{
    char *p = g5c_xasprintf(BASE "/%s/eap-session", c->id), *href;
    g5c_json *l = g5c_json_set(o, "_links", g5c_json_new_obj()), *k = g5c_json_set(l, "eap-session", g5c_json_new_obj());
    bool fixed;
    pthread_mutex_lock(&a->mu);
    fixed = a->self_uri[0] != 0;
    pthread_mutex_unlock(&a->mu);
    href = fixed ? ausf_url(a, p) : g5c_req_url(req, p);
    g5c_json_set_str(k, "href", href);
    free(href);
    free(p);
}

/* EAP-Failure as the answer; the result is reported to the UDM */
static void fail(ausf *a, ausf_ctx *c, uint8_t resp_id, const char *why, g5c_resp *resp)
{
    uint8_t pkt[4];
    g5c_json *o;
    g5c_eap_build_result(G5C_EAP_FAILURE, resp_id, pkt);
    o = eap_reply(pkt, 4, "AUTHENTICATION_FAILURE");
    g5c_resp_json(resp, 200, o);
    ausf_no_store(resp);
    g5c_json_free(o);
    (void)udm_auth_event(a, c->supi, c->snn, "EAP_AKA_PRIME", false, NULL);
    ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "eap-aka-prime", "result", "failure");
    G5C_LOGI(AUSF_LOG, "EAP-AKA' authentication of %s failed: %s", c->supi, why);
}

/* EAP-Request/AKA'-Notification: a failure code before the challenge round is verified (P bit set: no AT_MAC) */
static bool notify_failure(ausf *a, const g5c_req *req, ausf_ctx *c, g5c_resp *resp)
{
    uint8_t pkt[32], code[2] = {0x40, 0x00}; /* 16384: general failure */
    size_t len = 0;
    g5c_eap_attr at = {G5C_AT_NOTIFICATION, code, 2};
    g5c_json *o;
    c->eap_id++;
    if (g5c_eap_build(G5C_EAP_REQUEST, c->eap_id, G5C_EAPAKA_NOTIFICATION, &at, 1, pkt, sizeof pkt, &len) != 0)
        return false;
    c->st = ST_EAP_NOTIF_FAIL;
    o = eap_reply(pkt, len, "AUTHENTICATION_ONGOING");
    add_link(req, c, o, a);
    g5c_resp_json(resp, 200, o);
    ausf_hal(resp);
    ausf_no_store(resp);
    g5c_json_free(o);
    return true;
}

/* the protected success indication (RFC 4187 6.2): code 32768 with AT_MAC */
static bool notify_success(ausf *a, const g5c_req *req, ausf_ctx *c, g5c_resp *resp)
{
    uint8_t pkt[48], code[2] = {0x80, 0x00}, mac_v[18] = {0};
    size_t len = 0;
    g5c_eap_attr at[2] = {{G5C_AT_NOTIFICATION, code, 2}, {G5C_AT_MAC, mac_v, 18}};
    g5c_json *o;
    c->eap_id++;
    if (g5c_eap_build(G5C_EAP_REQUEST, c->eap_id, G5C_EAPAKA_NOTIFICATION, at, 2, pkt, sizeof pkt, &len) != 0 || g5c_eap_mac_set(pkt, len, c->keys.k_aut, NULL, 0) != 0)
        return false;
    c->st = ST_EAP_NOTIF_OK;
    o = eap_reply(pkt, len, "AUTHENTICATION_ONGOING");
    add_link(req, c, o, a);
    g5c_resp_json(resp, 200, o);
    ausf_hal(resp);
    ausf_no_store(resp);
    g5c_json_free(o);
    return true;
}

/* EAP-Success with KSEAF; false when the response could not be built (resp then holds an error) */
static bool succeed(ausf *a, ausf_ctx *c, uint8_t resp_id, g5c_resp *resp)
{
    uint8_t pkt[4], kausf[32], kseaf[32];
    g5c_json *o;
    char *k, *event_id = NULL;
    g5c_eapaka_kausf(&c->keys, kausf); /* the most significant 256 bits of the EMSK (TS 33.501 6.1.3.1 step 10) */
    if (g5c_kseaf(kausf, c->snn, kseaf) != 0) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "crypto failure");
        OPENSSL_cleanse(kausf, sizeof kausf);
        return false;
    }
    (void)udm_auth_event(a, c->supi, c->snn, "EAP_AKA_PRIME", true, &event_id);
    free(c->auth_event_id);
    c->auth_event_id = event_id;
    ue_store(a, c->supi, c->snn, M_EAP_PRIME, kausf, c->id);
    g5c_eap_build_result(G5C_EAP_SUCCESS, resp_id, pkt);
    o = eap_reply(pkt, 4, "AUTHENTICATION_SUCCESS");
    k = g5c_hex_encode(kseaf, 32);
    g5c_json_set_str(o, "kSeaf", k);
    OPENSSL_cleanse(k, strlen(k));
    free(k);
    g5c_json_set_str(o, "supi", c->supi);
    g5c_resp_json(resp, 200, o);
    ausf_no_store(resp); /* KSEAF */
    g5c_json_free(o);
    OPENSSL_cleanse(kausf, sizeof kausf);
    OPENSSL_cleanse(kseaf, sizeof kseaf);
    ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "eap-aka-prime", "result", "success");
    return true;
}

/* RES: AT_RES carries the length in bits, then RES padded to a multiple of 4 octets (RFC 4187 10.8) */
static bool res_ok(const ausf_ctx *c, const g5c_eap_attr *at)
{
    size_t bits;
    if (at == NULL || at->vlen < 2)
        return false;
    bits = ((size_t)at->val[0] << 8) | at->val[1];
    if (bits < 32 || bits > 128 || bits % 8 != 0 || bits / 8 != c->xres_len || at->vlen < 2 + bits / 8)
        return false;
    return CRYPTO_memcmp(at->val + 2, c->xres, c->xres_len) == 0;
}

/* AKA'-Synchronization-Failure: ask the UDM for a new vector with the AUTS (TS 33.501 6.1.3.3.2) and send a new challenge */
static bool resync(ausf *a, const g5c_req *req, ausf_ctx *c, const g5c_eap_pkt *p, uint8_t resp_id, g5c_resp *resp)
{
    const g5c_eap_attr *auts = g5c_eap_find(p, G5C_AT_AUTS), *kdf = g5c_eap_find(p, G5C_AT_KDF);
    g5c_json *ri, *o;
    char *hr, *ha;
    udm_answer u;
    uint8_t pkt[G5C_EAP_MAX_PKT];
    size_t len = 0;
    if (auts == NULL || auts->vlen != 14 || c->resyncs >= MAX_RESYNC || (kdf != NULL && (kdf->vlen != 2 || kdf->val[0] != 0 || kdf->val[1] != 1))) {
        fail(a, c, resp_id, "bad synchronisation failure", resp);
        return false;
    }
    c->resyncs++;
    ri = g5c_json_new_obj();
    hr = g5c_hex_encode(c->rand, 16);
    ha = g5c_hex_encode(auts->val, 14);
    g5c_json_set_str(ri, "rand", hr);
    g5c_json_set_str(ri, "auts", ha);
    free(hr);
    free(ha);
    udm_generate(a, c->id_in, c->snn, ri, &u);
    g5c_json_free(ri);
    if (u.no_udm || u.status != 200 || !g5c_json_is(g5c_json_get(u.body, "authenticationVector"), G5C_J_OBJECT) ||
        !g5c_streq(g5c_json_get_str(u.body, "authType"), "EAP_AKA_PRIME")) {
        if (u.no_udm || u.status != 200)
            ausf_udm_failure(&u, resp);
        else
            g5c_resp_problem_simple(resp, 500, "AV_GENERATION_PROBLEM", "the UDM did not send an EAP-AKA' vector");
        udm_answer_free(&u);
        return false;
    }
    if (!load_vector(c, g5c_json_get(u.body, "authenticationVector"), resp)) {
        udm_answer_free(&u);
        return false;
    }
    udm_answer_free(&u);
    c->eap_id++;
    if (build_challenge(c, pkt, sizeof pkt, &len) != 0) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot build the EAP challenge");
        return false;
    }
    o = eap_reply(pkt, len, "AUTHENTICATION_ONGOING");
    add_link(req, c, o, a);
    g5c_resp_json(resp, 200, o);
    ausf_hal(resp);
    ausf_no_store(resp);
    g5c_json_free(o);
    ausf_count(a, "g5c_ausf_resynchronisations_total", "Sequence number resynchronisations.", "method", "eap-aka-prime");
    return true;
}

typedef enum { KEEP, DROP, FINISH } outcome;

static outcome notify_or_drop(ausf *a, const g5c_req *req, ausf_ctx *c, g5c_resp *resp)
{
    if (notify_failure(a, req, c, resp))
        return KEEP;
    g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot build the EAP notification");
    return DROP;
}

void eap_session_post(ausf *a, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *j = g5c_req_json(req, resp);
    const g5c_json *pl;
    const char *id = g5c_req_param(req, "authCtxId");
    uint8_t buf[G5C_EAP_MAX_PKT + 4];
    long n = 0;
    ausf_ctx *c;
    g5c_eap_pkt p;
    bool have = false;
    uint8_t resp_id = 0;
    outcome out = KEEP;

    if (j == NULL)
        return;
    pl = g5c_json_get(j, "eapPayload");
    if (pl == NULL || (!g5c_json_is(pl, G5C_J_NULL) && g5c_json_str(pl) == NULL)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "eapPayload", "mandatory, a base64 string or null");
        g5c_json_free(j);
        return;
    }
    if (g5c_json_str(pl) != NULL) {
        n = g5c_base64_decode(g5c_json_str(pl), buf, sizeof buf);
        if (n < 0 || n > G5C_EAP_MAX_PKT) {
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "eapPayload", "not base64 of an EAP packet");
            g5c_json_free(j);
            return;
        }
    }
    c = store_take(a, id != NULL ? id : "");
    if (c == NULL || c->method != M_EAP_PRIME || c->st == ST_DONE) {
        if (c != NULL) {
            if (c->st == ST_DONE)
                store_finish(a, c);
            else if (!store_reinsert(a, c))
                ctx_free(c);
        }
        ausf_count2(a, "g5c_ausf_authentications_total", "Authentication starts and results by method and outcome.", "method", "eap-aka-prime", "result", "unknown_context");
        g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "unknown or expired EAP session");
        g5c_json_free(j);
        return;
    }
    have = n > 0 && g5c_eap_parse(buf, (size_t)n, &p);
    resp_id = have ? p.id : n >= 2 ? buf[1] : c->eap_id;

    if (n == 0) {
        /* the AMF got nothing from the UE (TS 29.509 6.1.6.2.7: null) */
        fail(a, c, resp_id, "no EAP packet from the UE", resp);
        out = DROP;
    } else if (c->st == ST_EAP_NOTIF_FAIL) {
        fail(a, c, resp_id, "failure notified", resp); /* RFC 4187 6.3.3 case 3: EAP-Failure follows the notification round */
        out = DROP;
    } else if (c->st == ST_EAP_NOTIF_OK) {
        /* RFC 4187 6.2: the contents of the response to the "Success" notification are ignored, EAP-Success follows */
        out = succeed(a, c, resp_id, resp) ? FINISH : DROP;
    } else if (!have || p.code != G5C_EAP_RESPONSE || p.method != G5C_EAP_TYPE_AKA_PRIME) {
        out = notify_or_drop(a, req, c, resp);
    } else if (p.id != c->eap_id) {
        /* not the answer to the request that is out: a stale or duplicated packet; the session goes on */
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "eapPayload", "the identifier does not match the outstanding request");
    } else if (p.subtype == G5C_EAPAKA_CLIENT_ERROR || p.subtype == G5C_EAPAKA_AUTH_REJECT) {
        fail(a, c, resp_id, p.subtype == G5C_EAPAKA_CLIENT_ERROR ? "client error" : "AUTN rejected by the UE", resp);
        out = DROP;
    } else if (p.subtype == G5C_EAPAKA_SYNC_FAILURE) {
        out = resync(a, req, c, &p, resp_id, resp) ? KEEP : DROP;
    } else if (p.subtype != G5C_EAPAKA_CHALLENGE) {
        out = notify_or_drop(a, req, c, resp);
    } else {
        /* RFC 4187 10.15: AT_MAC is checked before anything else in the message */
        const g5c_eap_attr *res = g5c_eap_find(&p, G5C_AT_RES), *kdf = g5c_eap_find(&p, G5C_AT_KDF), *ind = g5c_eap_find(&p, G5C_AT_RESULT_IND);
        bool mac = g5c_eap_mac_ok(buf, (size_t)n, c->keys.k_aut, NULL, 0);
        /* RFC 5448 3.2: the only key derivation function offered is 1, so a request for another one is as invalid as a bad MAC */
        bool kdf_bad = kdf != NULL && !(kdf->vlen == 2 && kdf->val[0] == 0 && kdf->val[1] == 1);
        if (!mac || kdf_bad || !res_ok(c, res)) {
            ausf_count2(a, "g5c_ausf_eap_failures_total", "EAP-AKA' responses that failed verification.", "reason", kdf_bad ? "kdf" : !mac ? "mac" : "res", "method", "eap-aka-prime");
            out = notify_or_drop(a, req, c, resp);
        } else if (c->result_ind && ind != NULL) {
            if (notify_success(a, req, c, resp)) {
                out = KEEP;
            } else {
                g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot build the EAP notification");
                out = DROP;
            }
        } else {
            out = succeed(a, c, resp_id, resp) ? FINISH : DROP;
        }
    }

    if (out == KEEP) {
        if (!store_reinsert(a, c))
            ctx_free(c);
    } else if (out == FINISH) {
        store_finish(a, c); /* a success: kept until its result is removed */
    } else {
        ctx_free(c);
    }
    g5c_json_free(j);
}
