/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nnrf_AccessToken (TS 29.510 clause 5.4, claims of 6.3.5.2.4; TS 33.501 clause 13.4.1): OAuth2 client credentials, ES256 JWTs. */
#include <stdio.h>

#include "priv.h"

static void oauth_error(g5c_resp *resp, const char *error, const char *desc)
{
    g5c_json *j = g5c_json_new_obj();
    g5c_json_set_str(j, "error", error);
    if (desc != NULL)
        g5c_json_set_str(j, "error_description", desc);
    g5c_resp_json(resp, 400, j);
    g5c_json_free(j);
}

static bool offers(const g5c_json *doc, const char *service, const char *requester_type)
{
    const g5c_json *a = g5c_json_get(doc, "nfServices"), *m = g5c_json_get(doc, "nfServiceList");
    const g5c_json *prof_allowed = g5c_json_get(doc, "allowedNfTypes");
    if (g5c_json_len(prof_allowed) > 0 && !nrf_list_has(prof_allowed, requester_type))
        return false;
    for (size_t i = 0; i < g5c_json_len(a) + g5c_json_len(m); i++) {
        const g5c_json *s = i < g5c_json_len(a) ? g5c_json_at(a, i) : g5c_json_val_at(m, i - g5c_json_len(a));
        const char *name = g5c_json_get_str(s, "serviceName");
        const g5c_json *al = g5c_json_get(s, "allowedNfTypes");
        if (name != NULL && strcmp(name, service) == 0 && (g5c_json_len(al) == 0 || nrf_list_has(al, requester_type)))
            return true;
    }
    return false;
}

static void token(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf *n = ctx;
    const char *form = (const char *)req->body;
    size_t k;
    char **v;
    char *grant = NULL, *id = NULL, *type = NULL, *scope = NULL, *ttype = NULL, *tid = NULL;
    g5c_json *claims, *rsp;
    char *jwt;
    long idx;
    bool ok = true;
    char *tok, *save;
    char *sc;
    const char *want_type;
#define GRAB(var, key)                                                                                                                                       \
    do {                                                                                                                                                      \
        v = nrf_form_all(form, key, &k);                                                                                                                      \
        if (k > 0) {                                                                                                                                          \
            var = v[0];                                                                                                                                       \
            v[0] = NULL;                                                                                                                                      \
        }                                                                                                                                                     \
        nrf_query_free(v, k);                                                                                                                                 \
    } while (0)
    GRAB(grant, "grant_type");
    GRAB(id, "nfInstanceId");
    GRAB(type, "nfType");
    GRAB(scope, "scope");
    GRAB(ttype, "targetNfType");
    GRAB(tid, "targetNfInstanceId");
#undef GRAB
    if (grant == NULL || strcmp(grant, "client_credentials") != 0) {
        oauth_error(resp, "unsupported_grant_type", "grant_type must be client_credentials");
        goto out;
    }
    if (id == NULL || !nrf_valid_uuid(id) || type == NULL || scope == NULL || *scope == 0 || (ttype == NULL && tid == NULL)) {
        oauth_error(resp, "invalid_request", "nfInstanceId, nfType, scope and targetNfType or targetNfInstanceId are required");
        goto out;
    }
    if (tid != NULL && !nrf_valid_uuid(tid)) {
        oauth_error(resp, "invalid_request", "targetNfInstanceId is not a UUID");
        goto out;
    }
    pthread_mutex_lock(&n->mu);
    idx = nrf_find(n, id);
    if (idx < 0 || g5c_json_get_str(n->profs[idx].doc, "nfType") == NULL || strcmp(g5c_json_get_str(n->profs[idx].doc, "nfType"), type) != 0) {
        pthread_mutex_unlock(&n->mu);
        oauth_error(resp, "invalid_client", "the requester is not a registered NF instance of that type");
        goto out;
    }
    want_type = ttype;
    sc = g5c_xstrdup(scope);
    for (tok = strtok_r(sc, " ", &save); tok != NULL && ok; tok = strtok_r(NULL, " ", &save)) {
        bool found = false;
        if ((want_type != NULL && strcmp(want_type, "NRF") == 0) || (tid != NULL && strcmp(tid, n->instance_id) == 0)) {
            found = strcmp(tok, NRF_SVC_NFM) == 0 || strcmp(tok, NRF_SVC_DISC) == 0;
        } else if (tid != NULL) {
            long t = nrf_find(n, tid);
            found = t >= 0 && offers(n->profs[t].doc, tok, type);
        } else {
            for (size_t i = 0; i < n->nprofs && !found; i++) {
                const char *t = g5c_json_get_str(n->profs[i].doc, "nfType"), *st = g5c_json_get_str(n->profs[i].doc, "nfStatus");
                if (t != NULL && strcmp(t, want_type) == 0 && st != NULL && strcmp(st, "REGISTERED") == 0 && offers(n->profs[i].doc, tok, type))
                    found = true;
            }
        }
        if (!found)
            ok = false;
    }
    free(sc);
    pthread_mutex_unlock(&n->mu);
    if (!ok) {
        oauth_error(resp, "invalid_scope", "no registered producer offers the requested service to this requester");
        nrf_count(n, "g5c_nrf_tokens_refused_total", "Access token requests refused.", NULL, NULL);
        goto out;
    }
    if (n->key == NULL) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "no signing key");
        goto out;
    }
    claims = g5c_json_new_obj();
    g5c_json_set_str(claims, "iss", n->instance_id);
    g5c_json_set_str(claims, "sub", id);
    g5c_json_set_str(claims, "aud", tid != NULL ? tid : ttype);
    g5c_json_set_str(claims, "scope", scope);
    g5c_json_set_int(claims, "iat", (int64_t)time(NULL));
    g5c_json_set_int(claims, "exp", (int64_t)time(NULL) + n->cfg.token_lifetime);
    jwt = g5c_jwt_sign(n->key, n->kid, claims);
    g5c_json_free(claims);
    if (jwt == NULL) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot sign the token");
        goto out;
    }
    rsp = g5c_json_new_obj();
    g5c_json_set_str(rsp, "access_token", jwt);
    g5c_json_set_str(rsp, "token_type", "Bearer");
    g5c_json_set_int(rsp, "expires_in", n->cfg.token_lifetime);
    g5c_json_set_str(rsp, "scope", scope);
    g5c_resp_json(resp, 200, rsp);
    g5c_resp_header(resp, "cache-control", "no-store");
    g5c_resp_header(resp, "pragma", "no-cache");
    g5c_json_free(rsp);
    free(jwt);
    nrf_count(n, "g5c_nrf_tokens_issued_total", "Access tokens issued.", NULL, NULL);
out:
    free(grant);
    free(id);
    free(type);
    free(scope);
    free(ttype);
    free(tid);
}

static void jwks(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf *n = ctx;
    g5c_json *j = g5c_json_new_obj(), *keys = g5c_json_set(j, "keys", g5c_json_new_arr());
    g5c_json *k = n->key != NULL ? g5c_jwt_key_jwk(n->key, n->kid) : NULL;
    (void)req;
    if (k != NULL)
        g5c_json_push(keys, k);
    g5c_resp_json(resp, 200, j);
    g5c_json_free(j);
}

/* ---- the guard ------------------------------------------------------------------------------------------------------------------------------ */

int nrf_guard(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf *n = ctx;
    const char *service = NULL, *tok;
    g5c_json *claims;
    char err[96];
    const char *scope;
    int64_t exp = 0;
    if (strncmp(req->path, "/nnrf-nfm/", 10) == 0)
        service = NRF_SVC_NFM;
    else if (strncmp(req->path, "/nnrf-disc/", 11) == 0)
        service = NRF_SVC_DISC;
    if (service == NULL)
        return 0; /* the token endpoint, the key set, health and metrics */
    if (strcmp(service, NRF_SVC_NFM) == 0 && strncmp(req->path, "/nnrf-nfm/v1/nf-instances/", 26) == 0 &&
        (strcmp(req->method, "PUT") == 0 || strcmp(req->method, "PATCH") == 0 || strcmp(req->method, "DELETE") == 0))
        return 0; /* an NF registers, heart-beats and deregisters itself before it can have a token (authenticated by the transport) */
    tok = g5c_bearer_token(req);
    if (tok == NULL) {
        g5c_resp_problem_simple(resp, 401, "UNAUTHORIZED", "a bearer access token is required");
        return 1;
    }
    claims = n->key != NULL ? g5c_jwt_verify(n->key, tok, err, sizeof err) : NULL;
    if (claims == NULL) {
        g5c_resp_problem_simple(resp, 401, "UNAUTHORIZED", "the access token is not valid");
        return 1;
    }
    scope = g5c_json_get_str(claims, "scope");
    (void)g5c_json_get_int(claims, "exp", &exp);
    {
        bool ok = exp > (int64_t)time(NULL) && scope != NULL;
        const g5c_json *aud = g5c_json_get(claims, "aud");
        if (ok) { /* aud: the NRF's NF type or its instance id */
            const char *a = g5c_json_str(aud);
            ok = a != NULL && (strcmp(a, "NRF") == 0 || strcmp(a, n->instance_id) == 0);
        }
        if (ok) {
            char *sc = g5c_xstrdup(scope), *save, *t;
            bool has = false;
            for (t = strtok_r(sc, " ", &save); t != NULL; t = strtok_r(NULL, " ", &save))
                if (strcmp(t, service) == 0)
                    has = true;
            free(sc);
            ok = has;
        }
        g5c_json_free(claims);
        if (!ok) {
            g5c_resp_problem_simple(resp, 403, "UNAUTHORIZED", "the access token does not cover this service");
            return 1;
        }
    }
    return 0;
}

void nrf_oauth_routes(g5c_router *r, nrf *n)
{
    if (n != NULL && !n->cfg.oauth2)
        return;
    g5c_router_route(r, "POST", "/oauth2/token", token, n);
    g5c_router_route(r, "GET", "/oauth2/jwks", jwks, n);
}
