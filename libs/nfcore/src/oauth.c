/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _DEFAULT_SOURCE
/* OAuth 2.0 access tokens of the NRF between network functions: see g5c/oauth.h. */
#include "g5c/oauth.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "g5c/base.h"
#include "g5c/jwt.h"

#define LOGT "g5c_oauth"

/* ---- the services of the 5GC and the type of the NF that offers each ---- */

static const struct {
    const char *service, *nf_type;
} SERVICES[] = {
    {"nudm-ueau", "UDM"},   {"nudm-sdm", "UDM"},        {"nudm-uecm", "UDM"},      {"nudm-ee", "UDM"},         {"nudm-pp", "UDM"},       {"nudm-mt", "UDM"},
    {"nudm-niddau", "UDM"}, {"nausf-auth", "AUSF"},     {"nausf-sorprotection", "AUSF"}, {"nausf-upuprotection", "AUSF"},
    {"namf-comm", "AMF"},   {"namf-evts", "AMF"},       {"namf-mt", "AMF"},        {"namf-loc", "AMF"},
    {"nsmf-pdusession", "SMF"}, {"nsmf-event-exposure", "SMF"},
    {"npcf-am-policy-control", "PCF"}, {"npcf-smpolicycontrol", "PCF"}, {"npcf-policyauthorization", "PCF"}, {"npcf-eventexposure", "PCF"}, {"npcf-bdtpolicycontrol", "PCF"},
    {"nudr-dr", "UDR"},     {"nudr-group-id-map", "UDR"},
    {"nnssf-nsselection", "NSSF"}, {"nnssf-nssaiavailability", "NSSF"},
    {"nbsf-management", "BSF"},
    {"nnef-eventexposure", "NEF"}, {"nnef-pfdmanagement", "NEF"},
    {"nnrf-nfm", "NRF"},    {"nnrf-disc", "NRF"},
};

const char *g5c_oauth_service_nf_type(const char *service)
{
    for (size_t i = 0; service != NULL && i < sizeof SERVICES / sizeof *SERVICES; i++)
        if (strcmp(SERVICES[i].service, service) == 0)
            return SERVICES[i].nf_type;
    return NULL;
}

/* the first segment of the path of a URL ("http://h:1/nudm-sdm/v2/x?y" -> nudm-sdm), into out */
static bool service_of(const char *url, char *out, size_t cap)
{
    const char *p = strstr(url, "://");
    size_t n;
    if (p == NULL)
        return false;
    p = strchr(p + 3, '/');
    if (p == NULL)
        return false;
    p++;
    n = strcspn(p, "/?#");
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static char *trim_slash(const char *uri)
{
    size_t n = strlen(uri);
    while (n > 0 && uri[n - 1] == '/')
        n--;
    return g5c_xstrndup(uri, n);
}

/* ---- base64url of a token header (the key id) ---- */

static int b64v(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    return c == '-' ? 62 : c == '_' ? 63 : -1;
}

/* the "kid" of the header of a compact JWS, into out ("" when there is none or the header is not a JSON object) */
static void token_kid(const char *tok, char *out, size_t cap)
{
    const char *dot = strchr(tok, '.');
    size_t n = dot != NULL ? (size_t)(dot - tok) : 0;
    uint8_t buf[512];
    size_t o = 0;
    unsigned acc = 0;
    int bits = 0;
    g5c_json *h;
    out[0] = '\0';
    if (n == 0 || n > 600)
        return;
    for (size_t i = 0; i < n; i++) {
        int v = b64v((unsigned char)tok[i]);
        if (v < 0)
            return;
        acc = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= sizeof buf)
                return;
            buf[o++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    h = g5c_json_parse((const char *)buf, o, NULL, 0);
    if (h != NULL && g5c_json_get_str(h, "kid") != NULL && strlen(g5c_json_get_str(h, "kid")) < cap)
        snprintf(out, cap, "%s", g5c_json_get_str(h, "kid"));
    g5c_json_free(h);
}

/* ================================================================================================================================================================ */
/* producer */

typedef struct {
    char kid[64];
    g5c_jwt_key *key;
} jkey_t;

typedef struct keyset {
    int refs; /* under the mutex of the resource server */
    jkey_t *keys;
    size_t n;
} keyset_t;

struct g5c_oauth_rs {
    g5c_client *client;
    char *nrf, *type, *id;
    char **services;
    size_t nservices;
    unsigned leeway_s, refresh_s;
    g5c_router *router;
    g5c_guard_fn next;
    void *next_ctx;
    pthread_mutex_t mu;
    keyset_t *set;
    double fetched_at, last_try; /* monotonic seconds */
    g5c_counter *c_result[8];
};

enum { R_OK, R_MISSING, R_INVALID, R_EXPIRED, R_AUDIENCE, R_SCOPE, R_NO_KEYS, R_OTHER };
static const char *const R_NAME[] = {"ok", "missing", "invalid", "expired", "audience", "scope", "no_keys", "other"};

static void set_free(keyset_t *s)
{
    if (s == NULL)
        return;
    for (size_t i = 0; i < s->n; i++)
        g5c_jwt_key_free(s->keys[i].key);
    free(s->keys);
    free(s);
}

static void set_unref(g5c_oauth_rs *rs, keyset_t *s)
{
    bool last;
    if (s == NULL)
        return;
    pthread_mutex_lock(&rs->mu);
    last = --s->refs == 0;
    pthread_mutex_unlock(&rs->mu);
    if (last)
        set_free(s);
}

g5c_oauth_rs *g5c_oauth_rs_new(g5c_client *client, const char *nrf_uri, const char *own_type, const char *own_instance_id, const char *const *services, size_t nservices,
                               unsigned leeway_s, unsigned jwks_refresh_s, g5c_registry *metrics)
{
    g5c_oauth_rs *rs = g5c_xcalloc(1, sizeof *rs);
    rs->client = client;
    rs->nrf = trim_slash(nrf_uri);
    rs->type = g5c_xstrdup(own_type);
    rs->id = g5c_xstrdup(own_instance_id);
    rs->services = g5c_xcalloc(nservices ? nservices : 1, sizeof *rs->services);
    for (size_t i = 0; i < nservices; i++) {
        bool dup = false;
        for (size_t k = 0; k < rs->nservices; k++)
            dup = dup || strcmp(rs->services[k], services[i]) == 0;
        if (!dup)
            rs->services[rs->nservices++] = g5c_xstrdup(services[i]);
    }
    rs->leeway_s = leeway_s;
    rs->refresh_s = jwks_refresh_s;
    pthread_mutex_init(&rs->mu, NULL);
    if (metrics != NULL)
        for (int i = 0; i < 8; i++) {
            g5c_label l[] = {{"result", R_NAME[i]}};
            rs->c_result[i] = g5c_counter_get(metrics, "g5c_oauth_checks_total", "access token checks of requests for the services of this function, by result", l, 1);
        }
    return rs;
}

void g5c_oauth_rs_free(g5c_oauth_rs *rs)
{
    if (rs == NULL)
        return;
    set_free(rs->set);
    for (size_t i = 0; i < rs->nservices; i++)
        free(rs->services[i]);
    free(rs->services);
    free(rs->nrf);
    free(rs->type);
    free(rs->id);
    pthread_mutex_destroy(&rs->mu);
    free(rs);
}

/* fetch the key set of the NRF and replace the held one (caller holds the mutex); false when the NRF cannot be asked or has no usable key */
static bool fetch_keys_locked(g5c_oauth_rs *rs)
{
    char *url = g5c_xasprintf("%s/oauth2/jwks", rs->nrf), err[160];
    g5c_resp r;
    keyset_t *ns = NULL;
    rs->last_try = g5c_now_seconds();
    if (g5c_client_get(rs->client, url, &r, err, sizeof err) != 0) {
        G5C_LOGW(LOGT, "cannot fetch the key set of the NRF: %s", err);
        free(url);
        return false;
    }
    free(url);
    if (r.status == 200) {
        g5c_json *doc = g5c_resp_parse_json(&r);
        const g5c_json *keys = g5c_json_get(doc, "keys");
        ns = g5c_xcalloc(1, sizeof *ns);
        ns->refs = 1; /* the one the resource server holds */
        ns->keys = g5c_xcalloc(g5c_json_len(keys) + 1, sizeof *ns->keys);
        for (size_t i = 0; i < g5c_json_len(keys); i++) {
            const g5c_json *jwk = g5c_json_at(keys, i);
            char perr[96];
            g5c_jwt_key *k = g5c_jwt_key_from_jwk(jwk, perr, sizeof perr);
            if (k == NULL) {
                G5C_LOGW(LOGT, "a key of the NRF's key set is unusable: %s", perr);
                continue;
            }
            snprintf(ns->keys[ns->n].kid, sizeof ns->keys[0].kid, "%s", g5c_json_get_str(jwk, "kid") != NULL ? g5c_json_get_str(jwk, "kid") : "");
            ns->keys[ns->n++].key = k;
        }
        g5c_json_free(doc);
    } else {
        G5C_LOGW(LOGT, "the NRF answered %d to the request for its key set", r.status);
    }
    g5c_resp_free(&r);
    if (ns == NULL || ns->n == 0) {
        set_free(ns);
        return false;
    }
    if (rs->set != NULL && --rs->set->refs == 0)
        set_free(rs->set);
    rs->set = ns;
    rs->fetched_at = g5c_now_seconds();
    return true;
}

/* A referenced key set that holds the key of this key id, fetching when there is none, the set is old, or the key id is not in it */
static keyset_t *get_set(g5c_oauth_rs *rs, const char *kid, const jkey_t **which)
{
    keyset_t *s = NULL;
    double now = g5c_now_seconds();
    *which = NULL;
    pthread_mutex_lock(&rs->mu);
    for (int pass = 0; pass < 2; pass++) {
        bool stale = rs->set == NULL || now - rs->fetched_at > (double)rs->refresh_s;
        const jkey_t *found = NULL;
        if (rs->set != NULL)
            for (size_t i = 0; i < rs->set->n && found == NULL; i++)
                if (kid[0] == '\0' ? rs->set->n == 1 : strcmp(rs->set->keys[i].kid, kid) == 0)
                    found = &rs->set->keys[i];
        if (found != NULL && !stale) {
            s = rs->set;
            s->refs++;
            *which = found;
            break;
        }
        if (pass == 0 && (found == NULL || stale) && now - rs->last_try > 2.0) {
            if (!fetch_keys_locked(rs) && found != NULL) { /* the NRF cannot be reached: the key held still verifies */
                s = rs->set;
                s->refs++;
                *which = found;
                break;
            }
            now = g5c_now_seconds();
            continue;
        }
        if (found != NULL) {
            s = rs->set;
            s->refs++;
            *which = found;
        }
        break;
    }
    pthread_mutex_unlock(&rs->mu);
    return s;
}

static void deny(g5c_oauth_rs *rs, g5c_resp *resp, int status, const char *error, const char *desc, const char *scope, int result)
{
    char *h = scope != NULL ? g5c_xasprintf("Bearer realm=\"%s\", error=\"%s\", scope=\"%s\"", rs->nrf, error, scope)
                            : g5c_xasprintf("Bearer realm=\"%s\", error=\"%s\"", rs->nrf, error);
    g5c_resp_problem_simple(resp, status, "UNAUTHORIZED", desc);
    g5c_resp_header(resp, "www-authenticate", h);
    free(h);
    if (rs->c_result[result] != NULL)
        g5c_counter_inc(rs->c_result[result]);
}

static bool has_word(const char *list, const char *word)
{
    size_t n = strlen(word);
    for (const char *p = list; p != NULL && *p != '\0';) {
        size_t l;
        while (*p == ' ')
            p++;
        l = strcspn(p, " ");
        if (l == n && strncmp(p, word, n) == 0)
            return true;
        p += l;
    }
    return false;
}

static bool audience_ok(const g5c_oauth_rs *rs, const g5c_json *aud)
{
    if (g5c_json_str(aud) != NULL)
        return strcmp(g5c_json_str(aud), rs->type) == 0 || strcmp(g5c_json_str(aud), rs->id) == 0;
    for (size_t i = 0; g5c_json_is(aud, G5C_J_ARRAY) && i < g5c_json_len(aud); i++) {
        const char *a = g5c_json_str(g5c_json_at(aud, i));
        if (a != NULL && (strcmp(a, rs->type) == 0 || strcmp(a, rs->id) == 0))
            return true;
    }
    return false;
}

int g5c_oauth_rs_guard(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_oauth_rs *rs = ctx;
    char svc[64], kid[64], err[100];
    const char *tok, *scope;
    const jkey_t *which = NULL;
    keyset_t *set;
    g5c_json *claims;
    int64_t exp = 0, now = (int64_t)time(NULL), iat = 0, nbf = 0, skew = (int64_t)rs->leeway_s;
    bool is_service = false, mine = false;
    {
        const char *p = req->path != NULL && req->path[0] == '/' ? req->path + 1 : "";
        size_t n = strcspn(p, "/");
        is_service = n > 0 && n < sizeof svc;
        if (is_service) {
            memcpy(svc, p, n);
            svc[n] = '\0';
        }
    }
    for (size_t i = 0; is_service && i < rs->nservices; i++)
        mine = mine || strcmp(rs->services[i], svc) == 0;
    if (!mine)
        goto pass;
    if (rs->router != NULL && (g5c_router_flags_of(rs->router, req->method, req->path) & G5C_ROUTE_OWN_AUTH) != 0)
        goto pass;
    tok = g5c_bearer_token(req);
    if (tok == NULL || tok[0] == '\0') {
        deny(rs, resp, 401, "invalid_request", "an access token of the NRF is required (Authorization: Bearer)", NULL, R_MISSING);
        return 1;
    }
    token_kid(tok, kid, sizeof kid);
    set = get_set(rs, kid, &which);
    if (set == NULL) {
        if (rs->c_result[R_NO_KEYS] != NULL)
            g5c_counter_inc(rs->c_result[R_NO_KEYS]);
        if (rs->set == NULL) {
            g5c_resp_problem_simple(resp, 503, "SYSTEM_FAILURE", "the key set of the NRF is not available, tokens cannot be checked");
            return 1;
        }
        deny(rs, resp, 401, "invalid_token", "the access token was signed with a key the NRF does not publish", NULL, R_INVALID);
        return 1;
    }
    claims = g5c_jwt_verify(which->key, tok, err, sizeof err);
    set_unref(rs, set);
    if (claims == NULL) {
        deny(rs, resp, 401, "invalid_token", "the access token is not valid", NULL, R_INVALID);
        return 1;
    }
    if (!g5c_json_get_int(claims, "exp", &exp) || exp + skew <= now) { /* RFC 7519 4.1.4: on or after exp the token is not accepted */
        g5c_json_free(claims);
        deny(rs, resp, 401, "invalid_token", "the access token has expired", NULL, R_EXPIRED);
        return 1;
    }
    if ((g5c_json_get(claims, "iat") != NULL && g5c_json_get_int(claims, "iat", &iat) && iat - skew > now) ||
        (g5c_json_get(claims, "nbf") != NULL && g5c_json_get_int(claims, "nbf", &nbf) && nbf - skew > now) || g5c_json_get_str(claims, "sub") == NULL) {
        g5c_json_free(claims);
        deny(rs, resp, 401, "invalid_token", "the access token is not valid yet or has no subject", NULL, R_INVALID);
        return 1;
    }
    if (!audience_ok(rs, g5c_json_get(claims, "aud"))) {
        g5c_json_free(claims);
        deny(rs, resp, 403, "invalid_token", "the audience of the access token is not this function", NULL, R_AUDIENCE);
        return 1;
    }
    scope = g5c_json_get_str(claims, "scope");
    if (scope == NULL || !has_word(scope, svc)) {
        g5c_json_free(claims);
        deny(rs, resp, 403, "insufficient_scope", "the scope of the access token does not cover this service", svc, R_SCOPE);
        return 1;
    }
    g5c_json_free(claims);
    if (rs->c_result[R_OK] != NULL)
        g5c_counter_inc(rs->c_result[R_OK]);
pass:
    return rs->next != NULL ? rs->next(rs->next_ctx, req, resp) : 0;
}

void g5c_oauth_rs_attach(g5c_oauth_rs *rs, g5c_router *router)
{
    g5c_router_get_guard(router, &rs->next, &rs->next_ctx);
    rs->router = router;
    g5c_router_set_guard(router, g5c_oauth_rs_guard, rs);
}

/* ================================================================================================================================================================ */
/* consumer */

typedef struct {
    char key[96]; /* "<target type>|<service>" */
    pthread_mutex_t mu;
    char *token;
    double expires_at, refresh_at, retry_after; /* monotonic seconds */
} tentry_t;

struct g5c_oauth_client {
    g5c_client *client;
    char *nrf, *type, *id;
    pthread_mutex_t mu;
    tentry_t **entries;
    size_t n, cap;
    g5c_counter *c_issued, *c_failed;
};

g5c_oauth_client *g5c_oauth_client_new(g5c_client *client, const char *nrf_uri, const char *own_type, const char *own_instance_id, g5c_registry *metrics)
{
    g5c_oauth_client *c = g5c_xcalloc(1, sizeof *c);
    c->client = client;
    c->nrf = trim_slash(nrf_uri);
    c->type = g5c_xstrdup(own_type);
    c->id = g5c_xstrdup(own_instance_id);
    pthread_mutex_init(&c->mu, NULL);
    if (metrics != NULL) {
        g5c_label ok[] = {{"result", "issued"}}, bad[] = {{"result", "failed"}};
        c->c_issued = g5c_counter_get(metrics, "g5c_oauth_token_requests_total", "access token requests to the NRF, by result", ok, 1);
        c->c_failed = g5c_counter_get(metrics, "g5c_oauth_token_requests_total", "access token requests to the NRF, by result", bad, 1);
    }
    return c;
}

void g5c_oauth_client_free(g5c_oauth_client *c)
{
    if (c == NULL)
        return;
    for (size_t i = 0; i < c->n; i++) {
        free(c->entries[i]->token);
        pthread_mutex_destroy(&c->entries[i]->mu);
        free(c->entries[i]);
    }
    free(c->entries);
    free(c->nrf);
    free(c->type);
    free(c->id);
    pthread_mutex_destroy(&c->mu);
    free(c);
}

static tentry_t *entry_for(g5c_oauth_client *c, const char *key)
{
    tentry_t *e = NULL;
    pthread_mutex_lock(&c->mu);
    for (size_t i = 0; i < c->n && e == NULL; i++)
        if (strcmp(c->entries[i]->key, key) == 0)
            e = c->entries[i];
    if (e == NULL) {
        e = g5c_xcalloc(1, sizeof *e);
        snprintf(e->key, sizeof e->key, "%s", key);
        pthread_mutex_init(&e->mu, NULL);
        if (c->n == c->cap) {
            c->cap = c->cap ? c->cap * 2 : 16;
            c->entries = g5c_xrealloc(c->entries, c->cap * sizeof *c->entries);
        }
        c->entries[c->n++] = e;
    }
    pthread_mutex_unlock(&c->mu);
    return e;
}

static char *form_enc(const char *s)
{
    size_t n = strlen(s);
    char *o = g5c_xmalloc(n * 3 + 1), *p = o;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~')
            *p++ = (char)ch;
        else
        {
            static const char hex[] = "0123456789ABCDEF";
            *p++ = '%';
            *p++ = hex[ch >> 4];
            *p++ = hex[ch & 15];
        }
    }
    *p = '\0';
    return o;
}

/* ask the NRF (the entry's mutex is held); fills the entry */
static void request_token(g5c_oauth_client *c, tentry_t *e, const char *target_type, const char *service)
{
    char *url = g5c_xasprintf("%s/oauth2/token", c->nrf), *id = form_enc(c->id), *ty = form_enc(c->type), *tt = form_enc(target_type), *sc = form_enc(service), *body, err[160];
    g5c_resp r;
    double now = g5c_now_seconds();
    body = g5c_xasprintf("grant_type=client_credentials&nfInstanceId=%s&nfType=%s&targetNfType=%s&scope=%s", id, ty, tt, sc);
    if (g5c_client_request(c->client, "POST", url, NULL, 0, "application/x-www-form-urlencoded", body, strlen(body), &r, err, sizeof err) == 0) {
        g5c_json *j = r.status == 200 ? g5c_resp_parse_json(&r) : NULL;
        const char *tok = g5c_json_get_str(j, "access_token");
        int64_t life = 0;
        if (tok != NULL && g5c_json_get_int(j, "expires_in", &life) && life > 0) {
            free(e->token);
            e->token = g5c_xstrdup(tok);
            /* exp is a whole second (the NRF truncates), so the token may be valid for a second less than expires_in says: take it off, then refresh before the end */
            e->expires_at = now + (double)(life > 1 ? life - 1 : 0);
            e->refresh_at = now + (double)(life > 1 ? life - 1 : 0) * 0.8;
            e->retry_after = 0;
            if (c->c_issued != NULL)
                g5c_counter_inc(c->c_issued);
        } else {
            G5C_LOGW(LOGT, "the NRF refused a token for %s of %s (%d)", service, target_type, r.status);
            e->retry_after = now + 2; /* do not ask for every request */
            if (c->c_failed != NULL)
                g5c_counter_inc(c->c_failed);
        }
        g5c_json_free(j);
        g5c_resp_free(&r);
    } else {
        G5C_LOGW(LOGT, "cannot ask the NRF for a token for %s of %s: %s", service, target_type, err);
        e->retry_after = now + 2;
        if (c->c_failed != NULL)
            g5c_counter_inc(c->c_failed);
    }
    free(url);
    free(id);
    free(ty);
    free(tt);
    free(sc);
    free(body);
}

char *g5c_oauth_client_token(void *client, const char *method, const char *url)
{
    g5c_oauth_client *c = client;
    char svc[64], key[96];
    const char *target;
    tentry_t *e;
    char *tok = NULL;
    double now;
    if (!service_of(url, svc, sizeof svc) || (target = g5c_oauth_service_nf_type(svc)) == NULL)
        return NULL;
    if (strcmp(target, "NRF") == 0) { /* the registration, heart-beat and deregistration of an NF instance are authenticated by */
        const char *p = strstr(url, "/nnrf-nfm/v1/nf-instances/");
        if (p != NULL && (strcmp(method, "PUT") == 0 || strcmp(method, "PATCH") == 0 || strcmp(method, "DELETE") == 0))
            return NULL;
    }
    snprintf(key, sizeof key, "%s|%s", target, svc);
    e = entry_for(c, key);
    pthread_mutex_lock(&e->mu); /* one request for a token at a time per service: the others wait for it and use it */
    now = g5c_now_seconds();
    if (e->token == NULL || now >= e->refresh_at) {
        if (e->token != NULL && now >= e->expires_at) {
            free(e->token);
            e->token = NULL;
        }
        if (now >= e->retry_after)
            request_token(c, e, target, svc);
    }
    if (e->token != NULL && g5c_now_seconds() < e->expires_at)
        tok = g5c_xstrdup(e->token);
    pthread_mutex_unlock(&e->mu);
    return tok;
}

void g5c_oauth_client_reject(void *client, const char *method, const char *url)
{
    g5c_oauth_client *c = client;
    char svc[64], key[96];
    const char *target;
    tentry_t *e;
    (void)method;
    if (!service_of(url, svc, sizeof svc) || (target = g5c_oauth_service_nf_type(svc)) == NULL)
        return;
    snprintf(key, sizeof key, "%s|%s", target, svc);
    e = entry_for(c, key);
    pthread_mutex_lock(&e->mu);
    free(e->token);
    e->token = NULL;
    e->retry_after = 0;
    pthread_mutex_unlock(&e->mu);
}
