/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Client for the Nudr_DataRepository service (TS 29.504 / 29.505) used by UDM. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "g5c/udm.h"

void udm_udr_init(udm_udr *u, g5c_client *c, const char *base)
{
    size_t n = strlen(base);
    while (n > 0 && base[n - 1] == '/')
        n--;
    u->client = c;
    u->base = g5c_xasprintf("%.*s/nudr-dr/v1/subscription-data", (int)n, base);
}

void udm_udr_use_discovery(udm_udr *u, g5c_disc *d)
{
    free(u->base);
    u->base = NULL;
    u->disc = d;
}

void udm_udr_set_token(udm_udr *u, const char *token)
{
    if (u->token != NULL) {
        OPENSSL_cleanse(u->token, strlen(u->token));
        free(u->token);
    }
    u->token = token != NULL ? g5c_xstrdup(token) : NULL;
}

void udm_udr_free(udm_udr *u)
{
    udm_udr_set_token(u, NULL);
    free(u->base);
    u->base = NULL;
    g5c_disc_free(u->disc);
    u->disc = NULL;
}

/* <udr>/nudr-dr/v1/subscription-data, or NULL when no UDR can be found */
static char *base_of(const udm_udr *u)
{
    if (u->disc != NULL) {
        char *root = g5c_disc_root(u->disc, "UDR", "nudr-dr", NULL), *b;
        if (root == NULL)
            return NULL;
        b = g5c_xasprintf("%s/nudr-dr/v1/subscription-data", root);
        free(root);
        return b;
    }
    return u->base != NULL ? g5c_xstrdup(u->base) : NULL;
}

void udm_udr_fail(const udr_result *r, const char *not_found_cause, g5c_resp *resp)
{
    switch (r->kind) {
    case UDR_NOT_FOUND:
        g5c_resp_problem_simple(resp, 404, not_found_cause, NULL);
        break;
    case UDR_STATUS:
    case UDR_MALFORMED:
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "UDR error");
        break;
    default:
        g5c_resp_problem_simple(resp, 503, "UNSPECIFIED", "UDR unavailable");
        break;
    }
}

static char *url(const udm_udr *u, const char *supi, const char *tail)
{
    char *b = base_of(u), *r;
    if (b == NULL)
        return NULL;
    r = g5c_xasprintf("%s/%s/%s", b, supi, tail);
    free(b);
    return r;
}

static udr_result classify(int rc, const g5c_resp *r)
{
    udr_result x = {UDR_OK, 0, false};
    if (rc != 0) {
        x.kind = UDR_TRANSPORT;
        return x;
    }
    x.http_status = r->status;
    if (r->status >= 200 && r->status <= 299)
        x.created = r->status == 201;
    else if (r->status == 404)
        x.kind = UDR_NOT_FOUND;
    else
        x.kind = UDR_STATUS;
    return x;
}

static udr_result do_req(const udm_udr *u, const char *method, const char *path_url, const char *ctype, const g5c_json *body,
                         g5c_json **out)
{
    g5c_resp r;
    size_t n = 0;
    char *s;
    int rc;
    udr_result x;
    if (path_url == NULL) { /* no UDR registered at the NRF */
        x.kind = UDR_TRANSPORT;
        x.http_status = 0;
        x.created = false;
        return x;
    }
    s = body ? g5c_json_to_string(body, &n) : NULL;
    {
        char *auth = u->token != NULL ? g5c_xstrdup(u->token) : NULL; /* the provisioning token has a header of its own */
        g5c_kv hdr = {"x-g5c-provisioning-token", auth};
        rc = g5c_client_request(u->client, method, path_url, auth != NULL ? &hdr : NULL, auth != NULL ? 1 : 0,
                                ctype ? ctype : G5C_JSON_TYPE, s, n, &r, NULL, 0);
        if (auth != NULL) {
            OPENSSL_cleanse(auth, strlen(auth));
            free(auth);
        }
    }
    free(s);
    if (rc != 0 && u->disc != NULL)
        g5c_disc_forget(u->disc, "UDR"); /* the instance may be gone: ask the NRF again next time */
    x = classify(rc, &r);
    if (rc == 0) {
        if (x.kind == UDR_OK && out != NULL) {
            *out = g5c_resp_parse_json(&r);
            if (*out == NULL)
                x.kind = UDR_MALFORMED;
        }
        g5c_resp_free(&r);
    }
    return x;
}

#define PATCH_TYPE "application/json-patch+json"

static udr_result get_at(const udm_udr *u, const char *supi, const char *tail, g5c_json **out)
{
    char *p = url(u, supi, tail);
    udr_result r = do_req(u, "GET", p, NULL, NULL, out);
    free(p);
    return r;
}

static udr_result send_at(const udm_udr *u, const char *method, const char *supi, const char *tail, const char *ctype,
                          const g5c_json *body)
{
    char *p = url(u, supi, tail);
    udr_result r = do_req(u, method, p, ctype, body, NULL);
    free(p);
    return r;
}

udr_result udm_udr_auth_subscription(const udm_udr *u, const char *supi, g5c_json **out)
{
    return get_at(u, supi, "authentication-data/authentication-subscription", out);
}

udr_result udm_udr_patch_auth_subscription(const udm_udr *u, const char *supi, const g5c_json *items)
{
    return send_at(u, "PATCH", supi, "authentication-data/authentication-subscription", PATCH_TYPE, items);
}

udr_result udm_udr_put_auth_subscription(const udm_udr *u, const char *supi, const g5c_json *doc)
{
    return send_at(u, "PUT", supi, "authentication-data/authentication-subscription", NULL, doc);
}

udr_result udm_udr_put_auth_status(const udm_udr *u, const char *supi, const g5c_json *ev)
{
    return send_at(u, "PUT", supi, "authentication-data/authentication-status", NULL, ev);
}

static char *plmn_tail(const char *plmn, const char *leaf)
{
    return g5c_xasprintf("%s/provisioned-data/%s", plmn, leaf);
}

static udr_result prov_get(const udm_udr *u, const char *supi, const char *plmn, const char *leaf, g5c_json **out)
{
    char *t = plmn_tail(plmn, leaf);
    udr_result r = get_at(u, supi, t, out);
    free(t);
    return r;
}

static udr_result prov_put(const udm_udr *u, const char *supi, const char *plmn, const char *leaf, const g5c_json *doc)
{
    char *t = plmn_tail(plmn, leaf);
    udr_result r = send_at(u, "PUT", supi, t, NULL, doc);
    free(t);
    return r;
}

udr_result udm_udr_identity(const udm_udr *u, const char *ueid, g5c_json **out)
{
    return get_at(u, ueid, "identity-data", out);
}

udr_result udm_udr_put_identity(const udm_udr *u, const char *supi, const g5c_json *doc)
{
    return send_at(u, "PUT", supi, "identity-data", NULL, doc);
}

udr_result udm_udr_am_data(const udm_udr *u, const char *supi, const char *plmn, g5c_json **out)
{
    return prov_get(u, supi, plmn, "am-data", out);
}

udr_result udm_udr_put_am_data(const udm_udr *u, const char *supi, const char *plmn, const g5c_json *doc)
{
    return prov_put(u, supi, plmn, "am-data", doc);
}

/* Percent-encode everything outside the URL-unreserved set. */
static char *pct(const char *s)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_' ||
            c == '.' || c == '~')
            g5c_bytes_putc(&b, (char)c);
        else
            g5c_bytes_printf(&b, "%%%02X", c);
    }
    return g5c_bytes_take(&b, NULL);
}

udr_result udm_udr_sm_data(const udm_udr *u, const char *supi, const char *plmn, const char *nssai, const char *dnn,
                           g5c_json **out)
{
    g5c_bytes tail;
    char *t = plmn_tail(plmn, "sm-data"), sep = '?';
    udr_result r;
    g5c_bytes_init(&tail);
    g5c_bytes_append_str(&tail, t);
    free(t);
    if (nssai != NULL) {
        char *e = pct(nssai);
        g5c_bytes_printf(&tail, "%csingle-nssai=%s", sep, e);
        free(e);
        sep = '&';
    }
    if (dnn != NULL) {
        char *e = pct(dnn);
        g5c_bytes_printf(&tail, "%cdnn=%s", sep, e);
        free(e);
    }
    r = get_at(u, supi, (const char *)tail.data, out);
    g5c_bytes_free(&tail);
    return r;
}

udr_result udm_udr_put_sm_data(const udm_udr *u, const char *supi, const char *plmn, const g5c_json *doc)
{
    return prov_put(u, supi, plmn, "sm-data", doc);
}

udr_result udm_udr_smf_selection(const udm_udr *u, const char *supi, const char *plmn, g5c_json **out)
{
    return prov_get(u, supi, plmn, "smf-selection-subscription-data", out);
}

udr_result udm_udr_put_smf_selection(const udm_udr *u, const char *supi, const char *plmn, const g5c_json *doc)
{
    return prov_put(u, supi, plmn, "smf-selection-subscription-data", doc);
}

udr_result udm_udr_amf_registration(const udm_udr *u, const char *supi, g5c_json **out)
{
    return get_at(u, supi, "context-data/amf-3gpp-access", out);
}

udr_result udm_udr_put_amf_registration(const udm_udr *u, const char *supi, const g5c_json *reg)
{
    return send_at(u, "PUT", supi, "context-data/amf-3gpp-access", NULL, reg);
}

udr_result udm_udr_patch_amf_registration(const udm_udr *u, const char *supi, const g5c_json *items)
{
    return send_at(u, "PATCH", supi, "context-data/amf-3gpp-access", PATCH_TYPE, items);
}

udr_result udm_udr_delete_amf_registration(const udm_udr *u, const char *supi)
{
    return send_at(u, "DELETE", supi, "context-data/amf-3gpp-access", NULL, NULL);
}

udr_result udm_udr_put_smf_registration(const udm_udr *u, const char *supi, const char *pdu_id, const g5c_json *reg)
{
    char *t = g5c_xasprintf("context-data/smf-registrations/%s", pdu_id);
    udr_result r = send_at(u, "PUT", supi, t, NULL, reg);
    free(t);
    return r;
}

udr_result udm_udr_delete_smf_registration(const udm_udr *u, const char *supi, const char *pdu_id)
{
    char *t = g5c_xasprintf("context-data/smf-registrations/%s", pdu_id);
    udr_result r = send_at(u, "DELETE", supi, t, NULL, NULL);
    free(t);
    return r;
}

udr_result udm_udr_smf_registrations(const udm_udr *u, const char *supi, g5c_json **out)
{
    return get_at(u, supi, "context-data/smf-registrations", out);
}

udr_result udm_udr_delete_subscriber(const udm_udr *u, const char *supi)
{
    char *b = base_of(u), *p = b != NULL ? g5c_xasprintf("%s/%s", b, supi) : NULL;
    udr_result r = do_req(u, "DELETE", p, NULL, NULL, NULL);
    free(p);
    free(b);
    return r;
}

udr_result udm_udr_list_subscribers(const udm_udr *u, g5c_json **out)
{
    char *b = base_of(u);
    udr_result r = do_req(u, "GET", b, NULL, NULL, out);
    free(b);
    return r;
}
