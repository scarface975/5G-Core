/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NRF configuration: the common sections plus a `registry:` block (the top-level `nrf:` key is where an NF names the NRF it registers with). */
#include <stdio.h>

#include "priv.h"

static int get_int(const g5c_json *o, const char *key, int64_t lo, int64_t hi, int *out, char *err, size_t cap)
{
    int64_t v;
    if (g5c_json_get(o, key) == NULL)
        return 0;
    if (!g5c_json_get_int(o, key, &v) || v < lo || v > hi) {
        snprintf(err, cap, "invalid config: `registry.%s` must be an integer in %lld..%lld", key, (long long)lo, (long long)hi);
        return -1;
    }
    *out = (int)v;
    return 0;
}

static void drop(nrf *n)
{
    free(n->cfg.state_file);
    free(n->cfg.key_file);
    free(n);
}

nrf *nrf_from_config(const g5c_json *cfg, g5c_nf *nf, char *err, size_t errcap)
{
    static const char *const k_reg[] = {"heartbeat_timer", "suspend_after", "purge_after", "validity_period", "subscription_validity", "max_profiles",
                                        "max_subscriptions", "state_file", "self_uri", "oauth2", NULL};
    static const char *const k_oauth[] = {"enabled", "enforce", "key_file", "token_lifetime", NULL};
    const g5c_json *reg = g5c_json_get(cfg, "registry"), *oa;
    nrf *n;
    err[0] = 0;
    if (reg != NULL && !g5c_json_is(reg, G5C_J_OBJECT)) {
        snprintf(err, errcap, "invalid config: `registry` must be a mapping");
        return NULL;
    }
    if (reg != NULL && g5c_json_check_keys(reg, k_reg, "registry", err, errcap) != 0)
        return NULL;
    n = g5c_xcalloc(1, sizeof *n);
    n->nf = nf;
    n->metrics = nf->metrics;
    snprintf(n->instance_id, sizeof n->instance_id, "%s", nf->instance_id);
    n->cfg.hb_timer = 10;
    n->cfg.suspend_after = 3;
    n->cfg.purge_after = 3600;
    n->cfg.validity = 60;
    n->cfg.sub_validity = 86400;
    n->cfg.max_profiles = 100000;
    n->cfg.max_subscriptions = 100000;
    n->cfg.oauth2 = true;
    n->cfg.enforce = false;
    n->cfg.token_lifetime = 3600;
    n->flush_gap_ms = 50;
    n->next_sub = 1;
    snprintf(n->cfg.mcc, sizeof n->cfg.mcc, "%s", nf->common.mcc != NULL ? nf->common.mcc : "");
    snprintf(n->cfg.mnc, sizeof n->cfg.mnc, "%s", nf->common.mnc != NULL ? nf->common.mnc : "");
    if (reg != NULL) {
        int mp = (int)n->cfg.max_profiles, ms = (int)n->cfg.max_subscriptions;
        if (get_int(reg, "heartbeat_timer", 1, 3600, &n->cfg.hb_timer, err, errcap) != 0 || get_int(reg, "suspend_after", 1, 100, &n->cfg.suspend_after, err, errcap) != 0 ||
            get_int(reg, "purge_after", 0, 31536000, &n->cfg.purge_after, err, errcap) != 0 ||
            get_int(reg, "validity_period", 1, 86400, &n->cfg.validity, err, errcap) != 0 ||
            get_int(reg, "subscription_validity", 60, 31536000, &n->cfg.sub_validity, err, errcap) != 0 ||
            get_int(reg, "max_profiles", 1, 10000000, &mp, err, errcap) != 0 || get_int(reg, "max_subscriptions", 1, 10000000, &ms, err, errcap) != 0) {
            drop(n);
            return NULL;
        }
        n->cfg.max_profiles = (unsigned)mp;
        n->cfg.max_subscriptions = (unsigned)ms;
        if (g5c_json_get_str(reg, "state_file") != NULL)
            n->cfg.state_file = g5c_xstrdup(g5c_json_get_str(reg, "state_file"));
        if (g5c_json_get_str(reg, "self_uri") != NULL)
            snprintf(n->self_uri, sizeof n->self_uri, "%s", g5c_json_get_str(reg, "self_uri"));
        oa = g5c_json_get(reg, "oauth2");
        if (oa != NULL) {
            bool b;
            if (!g5c_json_is(oa, G5C_J_OBJECT)) {
                snprintf(err, errcap, "invalid config: `registry.oauth2` must be a mapping");
                drop(n);
                return NULL;
            }
            if (g5c_json_check_keys(oa, k_oauth, "registry.oauth2", err, errcap) != 0) {
                drop(n);
                return NULL;
            }
            if (g5c_json_get_bool(oa, "enabled", &b))
                n->cfg.oauth2 = b;
            if (g5c_json_get_bool(oa, "enforce", &b))
                n->cfg.enforce = b;
            if (g5c_json_get_str(oa, "key_file") != NULL)
                n->cfg.key_file = g5c_xstrdup(g5c_json_get_str(oa, "key_file"));
            if (get_int(oa, "token_lifetime", 1, 86400, &n->cfg.token_lifetime, err, errcap) != 0) {
                snprintf(err, errcap, "invalid config: `registry.oauth2.token_lifetime` must be an integer in 1..86400");
                drop(n);
                return NULL;
            }
        }
    }
    if (n->cfg.enforce && !n->cfg.oauth2) {
        snprintf(err, errcap, "invalid config: `registry.oauth2.enforce` needs `registry.oauth2.enabled`");
        drop(n);
        return NULL;
    }
    pthread_mutex_init(&n->mu, NULL);
    pthread_mutex_init(&n->qmu, NULL);
    pthread_cond_init(&n->qcv, NULL);
    if (n->cfg.oauth2) {
        char kerr[120] = {0};
        size_t kl = 0;
        char *existing = n->cfg.key_file != NULL ? g5c_read_file(n->cfg.key_file, 1 << 16, &kl) : NULL;
        if (existing != NULL) {
            free(existing);
            n->key = g5c_jwt_key_load_pem(n->cfg.key_file, kerr, sizeof kerr);
        } else {
            n->key = g5c_jwt_key_generate(kerr, sizeof kerr);
            if (n->key != NULL && n->cfg.key_file != NULL && g5c_jwt_key_save_pem(n->key, n->cfg.key_file, kerr, sizeof kerr) != 0)
                G5C_LOGW(NRF_LOG, "cannot save the token signing key to %s: tokens will not survive a restart", n->cfg.key_file);
            if (n->key != NULL && n->cfg.key_file == NULL)
                G5C_LOGW(NRF_LOG, "no registry.oauth2.key_file: the token signing key is ephemeral");
        }
        if (n->key == NULL) {
            snprintf(err, errcap, "OAuth2 signing key: %s", kerr);
            nrf_destroy(n);
            return NULL;
        }
        {
            char *tp = n->key != NULL ? g5c_jwt_key_thumbprint(n->key) : NULL; /* the same key has the same id after a restart: the tokens issued before it still verify */
            snprintf(n->kid, sizeof n->kid, "%s", tp != NULL ? tp : "nrf");
            free(tp);
        }
    }
    return n;
}

void nrf_routes(g5c_router *r, nrf *n)
{
    nrf_mgmt_routes(r, n);
    nrf_disc_routes(r, n);
    nrf_oauth_routes(r, n);
}

g5c_router *nrf_router(nrf *n)
{
    g5c_router *r = g5c_router_new();
    nrf_routes(r, n);
    if (n->cfg.enforce)
        g5c_router_set_guard(r, nrf_guard, n);
    return r;
}
