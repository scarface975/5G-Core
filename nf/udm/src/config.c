/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* UDM configuration: common NF settings plus UDR location, home-network keys and secret sources */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "g5c/config.h"
#include "g5c/udm.h"

static void seterr(char *err, size_t cap, const char *fmt, const char *a)
{
    if (err && cap)
        snprintf(err, cap, "%s", a);
    (void)fmt; /* callers pass "%s" and the message as the argument */
}

/* configuration reload of `suci`: whether a SUCI in clear is accepted */
static int udm_reload_suci(void *ctx, const g5c_json *from, const g5c_json *to, char *err, size_t errcap)
{
    udm *u = ctx;
    const char *ns = g5c_json_get_str(to, "null_scheme");
    (void)from;
    if (to != NULL && !g5c_json_is(to, G5C_J_OBJECT)) {
        seterr(err, errcap, "%s", "invalid config: `suci` must be a mapping");
        return -1;
    }
    if (ns != NULL && strcmp(ns, "allow") != 0 && strcmp(ns, "reject") != 0) {
        seterr(err, errcap, "%s", "invalid value for `suci.null_scheme`: must be allow or reject");
        return -1;
    }
    atomic_store(&u->refuse_null_scheme, ns != NULL && strcmp(ns, "reject") == 0);
    G5C_LOGI("g5c_udm", "suci.null_scheme is now %s", atomic_load(&u->refuse_null_scheme) ? "reject" : "allow");
    return 0;
}

udm *udm_from_config(const g5c_json *cfg, g5c_nf *nf, char *err, size_t errcap)
{
    static const char *const k_udr[] = {"uri", "token_file", NULL};
    static const char *const k_hn[] = {"id", "scheme", "private_key_file", NULL};
    const g5c_json *udr = g5c_json_get(cfg, "udr"), *hn = g5c_json_get(cfg, "hn_keys");
    udm_keys keys;
    udm_hnkey *hk = NULL;
    size_t nhk = 0;
    char plmn[8], *secret;
    udm *u;
    char ferr[200];
    const char *mk_file = g5c_json_get_str(cfg, "master_key_file"), *at_file = g5c_json_get_str(cfg, "admin_token_file");

    bool discover_udr = false, refuse_null = false;
    char *udr_token = NULL;
    if ((udr == NULL || (g5c_json_is(udr, G5C_J_OBJECT) && g5c_json_get_str(udr, "uri") == NULL)) && nf->common.nrf_uri != NULL) {
        discover_udr = true; /* no `udr.uri`: the UDR is found through the NRF */
        if (udr != NULL && g5c_json_check_keys(udr, k_udr, "udr", err, errcap) != 0)
            return NULL;
    } else {
        if (!g5c_json_is(udr, G5C_J_OBJECT) || g5c_json_get_str(udr, "uri") == NULL) {
            seterr(err, errcap, "%s", "invalid config: `udr.uri` is required (or `nrf.uri`, to find the UDR through the NRF)");
            return NULL;
        }
        if (g5c_json_check_keys(udr, k_udr, "udr", err, errcap) != 0)
            return NULL;
    }

    secret = g5c_secret_from_env_or_file("G5C_UDM_MASTER_KEY", mk_file, ferr, sizeof ferr);
    if (secret == NULL && ferr[0]) {
        seterr(err, errcap, "%s", ferr);
        return NULL;
    }
    if (secret != NULL) {
        int rc = udm_keys_from_hex(&keys, secret);
        OPENSSL_cleanse(secret, strlen(secret));
        free(secret);
        if (rc != 0) {
            seterr(err, errcap, "%s", "master key must be 64 hex characters");
            return NULL;
        }
    } else {
        G5C_LOGW("g5c_udm", "no master key configured: subscriber K/OPc are stored UNENCRYPTED (development only)");
        udm_keys_none(&keys);
    }
    {
        char *prev = g5c_secret_from_env_or_file("G5C_UDM_MASTER_KEY_PREVIOUS", g5c_json_get_str(cfg, "master_key_previous_file"), ferr, sizeof ferr);
        if (prev == NULL && ferr[0]) {
            seterr(err, errcap, "%s", ferr);
            return NULL;
        }
        if (prev != NULL) {
            int rc = keys.has_master ? udm_keys_set_previous_hex(&keys, prev) : UDM_KEY_NO_MASTER;
            OPENSSL_cleanse(prev, strlen(prev));
            free(prev);
            if (rc != 0) {
                seterr(err, errcap, "%s", "the previous master key needs a current one and must be 64 hex characters");
                return NULL;
            }
            G5C_LOGW("g5c_udm", "a previous master key is configured: run POST /admin/v1/keys/rewrap, then remove it");
        }
    }

    if (hn != NULL && !g5c_json_is(hn, G5C_J_NULL)) {
        if (!g5c_json_is(hn, G5C_J_ARRAY)) {
            seterr(err, errcap, "%s", "invalid config: `hn_keys` must be a list");
            return NULL;
        }
        nhk = g5c_json_len(hn);
        hk = g5c_xcalloc(nhk ? nhk : 1, sizeof *hk);
        for (size_t i = 0; i < nhk; i++) {
            const g5c_json *e = g5c_json_at(hn, i);
            const char *scheme = g5c_json_get_str(e, "scheme"), *file = g5c_json_get_str(e, "private_key_file");
            int64_t id = 0;
            char *hex;
            if (!g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, k_hn, "hn_keys", err, errcap) != 0) {
                if (err && errcap && err[0] == 0)
                    seterr(err, errcap, "%s", "invalid config: hn_keys entry must be a mapping");
                goto bad;
            }
            if (!g5c_json_get_int(e, "id", &id) || id < 0 || id > 255 || scheme == NULL || file == NULL) {
                seterr(err, errcap, "%s", "invalid config: hn_keys entries need id (0-255), scheme and private_key_file");
                goto bad;
            }
            hk[i].id = (uint8_t)id;
            if (strcmp(scheme, "profile-a") == 0) {
                hk[i].profile = G5C_PROFILE_A;
            } else if (strcmp(scheme, "profile-b") == 0) {
                hk[i].profile = G5C_PROFILE_B;
            } else {
                char m[96];
                snprintf(m, sizeof m, "hn_keys: unknown scheme \"%.40s\"", scheme);
                seterr(err, errcap, "%s", m);
                goto bad;
            }
            hex = g5c_secret_from_env_or_file(NULL, file, ferr, sizeof ferr);
            if (hex == NULL || g5c_hex_decode(hex, hk[i].secret, 32) != 32) {
                char m[256];
                snprintf(m, sizeof m, "%.200s: private key must be 32 bytes (64 hex characters)", file);
                seterr(err, errcap, "%s", m);
                if (hex)
                    OPENSSL_cleanse(hex, strlen(hex));
                free(hex);
                goto bad;
            }
            OPENSSL_cleanse(hex, strlen(hex));
            free(hex);
        }
    }

    {
        static const char *const k_suci[] = {"null_scheme", NULL};
        const g5c_json *suci = g5c_json_get(cfg, "suci");
        const char *ns = g5c_json_get_str(suci, "null_scheme");
        if (suci != NULL && (!g5c_json_is(suci, G5C_J_OBJECT) || g5c_json_check_keys(suci, k_suci, "suci", err, errcap) != 0)) {
            if (err && errcap && err[0] == 0)
                seterr(err, errcap, "%s", "invalid config: `suci` must be a mapping");
            goto bad;
        }
        if (ns != NULL && strcmp(ns, "allow") != 0 && strcmp(ns, "reject") != 0) {
            seterr(err, errcap, "%s", "invalid value for `suci.null_scheme`: must be allow or reject");
            goto bad;
        }
        refuse_null = ns != NULL && strcmp(ns, "reject") == 0;
    }
    udr_token = g5c_secret_from_env_or_file("G5C_UDM_UDR_TOKEN", udr != NULL ? g5c_json_get_str(udr, "token_file") : NULL, ferr, sizeof ferr);
    if (udr_token == NULL && ferr[0]) {
        seterr(err, errcap, "%s", ferr);
        goto bad;
    }
    snprintf(plmn, sizeof plmn, "%s%s", nf->common.mcc, nf->common.mnc);
    u = g5c_xcalloc(1, sizeof *u);
    udm_init(u, nf->client, discover_udr ? "http://unused" : g5c_json_get_str(udr, "uri"), &keys, hk, nhk, plmn, nf->instance_id, nf->metrics);
    atomic_init(&u->refuse_null_scheme, refuse_null);
    g5c_nf_on_reload(nf, "suci", udm_reload_suci, u);
    if (discover_udr)
        udm_udr_use_discovery(&u->udr, g5c_disc_new(nf->client, nf->common.nrf_uri, "UDM", nf->instance_id));
    OPENSSL_cleanse(&keys, sizeof keys);
    if (hk)
        OPENSSL_cleanse(hk, nhk * sizeof *hk);
    free(hk);
    if (udr_token != NULL) {
        udm_udr_set_token(&u->udr, udr_token);
        OPENSSL_cleanse(udr_token, strlen(udr_token));
        free(udr_token);
    }
    {
        static const char *const k_ee[] = {"amf_uri", "notify_uri", "state_file", NULL};
        const g5c_json *ee = g5c_json_get(cfg, "ee");
        const char *nu = g5c_json_get_str(ee, "notify_uri");
        if (ee != NULL && (!g5c_json_is(ee, G5C_J_OBJECT) || g5c_json_check_keys(ee, k_ee, "ee", err, errcap) != 0)) {
            if (err && errcap && err[0] == 0)
                seterr(err, errcap, "%s", "invalid config: `ee` must be a mapping");
            udm_destroy(u);
            free(u);
            return NULL;
        }
        if (g5c_json_get_str(ee, "amf_uri") != NULL)
            u->ee_amf_uri = g5c_xstrdup(g5c_json_get_str(ee, "amf_uri"));
        if (g5c_json_get_str(ee, "state_file") != NULL) {
            u->ee_state_file = g5c_xstrdup(g5c_json_get_str(ee, "state_file"));
            udm_ee_load(u);
        }
        if (nu != NULL) {
            u->ee_self_uri = g5c_xstrdup(nu);
        } else if (nf->common.address != NULL && strcmp(nf->common.address, "0.0.0.0") != 0 && strcmp(nf->common.address, "::") != 0) {
            const char *a = nf->common.address;
            u->ee_self_uri = g5c_xasprintf(strchr(a, ':') ? "%s://[%s]:%u" : "%s://%s:%u", nf->common.has_tls ? "https" : "http", a, (unsigned)nf->common.port);
        }
    }
    u->admin_token = g5c_secret_from_env_or_file("G5C_UDM_ADMIN_TOKEN", at_file, ferr, sizeof ferr);
    if (u->admin_token == NULL && ferr[0]) {
        seterr(err, errcap, "%s", ferr);
        udm_destroy(u);
        free(u);
        return NULL;
    }
    if (u->admin_token != NULL && strlen(u->admin_token) < 16) {
        seterr(err, errcap, "%s", "admin token must be at least 16 characters");
        udm_destroy(u);
        free(u);
        return NULL;
    }
    if (g5c_json_get_str(cfg, "admin_tokens_file") != NULL) { /* roles and tenants; the single token above stays the principal "admin" */
        u->authz = g5c_authz_new(g5c_json_get_str(cfg, "admin_tokens_file"), u->admin_token, err, errcap);
        if (u->authz == NULL) {
            udm_destroy(u);
            free(u);
            return NULL;
        }
    }
    return u;
bad:
    OPENSSL_cleanse(&keys, sizeof keys);
    if (hk)
        OPENSSL_cleanse(hk, nhk * sizeof *hk);
    free(hk);
    return NULL;
}
