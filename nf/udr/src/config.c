/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* UDR configuration: the common sections plus
 *   store:        { type: memory | file | postgres, path, conninfo_file, pool }      (legacy: `store_path: <file>`)
 *   provisioning: { token_file }    bearer token of the provisioning extensions (or G5C_UDR_PROVISIONING_TOKEN)
 *   validate:     true | false      check bodies against the 3GPP schemas (default true)
 *   udr:          { group_id, supi_ranges, gpsi_ranges, data_sets }   what the UDR publishes in its NRF profile (udrInfo)
 *   subscriptions:{ max_per_data_set, max_lifetime_s, notify_retries }
 *   cache:        { max_age_s }     Cache-Control max-age of representations
 *   compat:       { put_no_content: true }   answer 204 to every successful PUT, also when it created the resource. TS 29.504
 *                                     5.2.2.3.2 says 201 with the representation and a Location; Open5GS's UDM, a common
 *                                     consumer, accepts only 204 for the registrations and authentication events it writes.
 *   group_ids:    [ { nf_type, nf_group_id, supi_ranges } ]                         Nudr_GroupIDmap
 * Secrets are never inline: the PostgreSQL connection string and the provisioning token come from the environment or from
 * files named here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "g5c/nfcore.h"
#include "g5c/udr.h"

#define bad(err, cap, ...) (snprintf((err), (cap), __VA_ARGS__), -1)

static bool digits(const char *s, size_t lo, size_t hi)
{
    size_t n = s != NULL ? strlen(s) : 0;
    return n >= lo && n <= hi && g5c_is_digits(s);
}

/* [{start, end}] of equal-length digit strings, start <= end */
static int check_ranges(const g5c_json *arr, const char *where, size_t lo, size_t hi, char *err, size_t cap)
{
    if (!g5c_json_is(arr, G5C_J_ARRAY) || g5c_json_len(arr) == 0)
        return bad(err, cap, "invalid config: `%s` must be a non-empty list of { start, end }", where);
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const g5c_json *r = g5c_json_at(arr, i);
        const char *s = g5c_json_get_str(r, "start"), *e = g5c_json_get_str(r, "end");
        static const char *const k[] = {"start", "end", NULL};
        char w[96];
        snprintf(w, sizeof w, "%s[%zu]", where, i);
        if (!g5c_json_is(r, G5C_J_OBJECT) || g5c_json_check_keys(r, k, w, err, cap) != 0) {
            if (err[0] == '\0')
                snprintf(err, cap, "invalid config: `%s` must be a mapping with `start` and `end`", w);
            return -1;
        }
        if (!digits(s, lo, hi) || !digits(e, lo, hi) || strlen(s) != strlen(e) || strcmp(s, e) > 0)
            return bad(err, cap, "invalid config: `%s` needs `start` and `end`, digit strings of one length, start <= end", w);
    }
    return 0;
}

static g5c_udr_store *open_store(const g5c_json *cfg, char *err, size_t errcap)
{
    static const char *const k_store[] = {"type", "path", "conninfo_file", "pool", NULL};
    const g5c_json *st = g5c_json_get(cfg, "store");
    const char *legacy = g5c_json_get_str(cfg, "store_path"), *type, *path;
    if (st == NULL)
        return legacy != NULL ? g5c_udr_store_open(legacy, err, errcap) : g5c_udr_store_memory();
    if (!g5c_json_is(st, G5C_J_OBJECT) || g5c_json_check_keys(st, k_store, "store", err, errcap) != 0) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: `store` must be a mapping");
        return NULL;
    }
    type = g5c_json_get_str(st, "type");
    path = g5c_json_get_str(st, "path");
    if (type == NULL || strcmp(type, "memory") == 0)
        return g5c_udr_store_memory();
    if (strcmp(type, "file") == 0) {
        if (path == NULL) {
            snprintf(err, errcap, "invalid config: `store.path` is required for a file store");
            return NULL;
        }
        return g5c_udr_store_open(path, err, errcap);
    }
    if (strcmp(type, "postgres") == 0) {
        const char *cf = g5c_json_get_str(st, "conninfo_file");
        int64_t pool = 4;
        char *conninfo, ferr[200] = "";
        g5c_udr_store *s;
        if (g5c_json_get(st, "pool") != NULL && (!g5c_json_get_int(st, "pool", &pool) || pool < 1 || pool > 64)) {
            snprintf(err, errcap, "invalid config: `store.pool` must be 1..64");
            return NULL;
        }
        conninfo = g5c_secret_from_env_or_file("G5C_UDR_PG_CONNINFO", cf, ferr, sizeof ferr);
        if (conninfo == NULL) {
            snprintf(err, errcap, "%s", ferr[0] ? ferr : "invalid config: postgres needs `store.conninfo_file` or G5C_UDR_PG_CONNINFO");
            return NULL;
        }
        s = g5c_udr_store_postgres(conninfo, (int)pool, err, errcap);
        OPENSSL_cleanse(conninfo, strlen(conninfo));
        free(conninfo);
        return s;
    }
    snprintf(err, errcap, "invalid config: `store.type` must be memory, file or postgres");
    return NULL;
}

/* udrInfo of TS 29.510: groupId, supiRanges, gpsiRanges, supportedDataSets */
static g5c_json *build_info(const g5c_json *u, char *err, size_t cap)
{
    static const char *const k_udr[] = {"group_id", "supi_ranges", "gpsi_ranges", "data_sets", NULL};
    static const char *const sets[] = {"SUBSCRIPTION", "POLICY", "EXPOSURE", "APPLICATION"};
    g5c_json *info = g5c_json_new_obj(), *ds;
    const g5c_json *given;
    if (u != NULL && (!g5c_json_is(u, G5C_J_OBJECT) || g5c_json_check_keys(u, k_udr, "udr", err, cap) != 0)) {
        if (err[0] == '\0')
            snprintf(err, cap, "invalid config: `udr` must be a mapping");
        g5c_json_free(info);
        return NULL;
    }
    if (g5c_json_get_str(u, "group_id") != NULL)
        g5c_json_set_str(info, "groupId", g5c_json_get_str(u, "group_id"));
    if (g5c_json_get(u, "supi_ranges") != NULL) {
        if (check_ranges(g5c_json_get(u, "supi_ranges"), "udr.supi_ranges", 5, 15, err, cap) != 0) {
            g5c_json_free(info);
            return NULL;
        }
        g5c_json_set(info, "supiRanges", g5c_json_dup(g5c_json_get(u, "supi_ranges")));
    }
    if (g5c_json_get(u, "gpsi_ranges") != NULL) {
        if (check_ranges(g5c_json_get(u, "gpsi_ranges"), "udr.gpsi_ranges", 3, 15, err, cap) != 0) {
            g5c_json_free(info);
            return NULL;
        }
        g5c_json_set(info, "gpsiRanges", g5c_json_dup(g5c_json_get(u, "gpsi_ranges")));
    }
    ds = g5c_json_set(info, "supportedDataSets", g5c_json_new_arr());
    given = g5c_json_get(u, "data_sets");
    if (given == NULL) {
        for (size_t i = 0; i < 4; i++)
            g5c_json_push_str(ds, sets[i]);
    } else {
        if (!g5c_json_is(given, G5C_J_ARRAY) || g5c_json_len(given) == 0) {
            snprintf(err, cap, "invalid config: `udr.data_sets` must be a non-empty list of SUBSCRIPTION, POLICY, EXPOSURE, APPLICATION");
            g5c_json_free(info);
            return NULL;
        }
        for (size_t i = 0; i < g5c_json_len(given); i++) {
            const char *s = g5c_json_str(g5c_json_at(given, i));
            bool known = false;
            for (size_t k = 0; s != NULL && k < 4; k++)
                known = known || strcmp(s, sets[k]) == 0;
            if (!known) {
                snprintf(err, cap, "invalid config: `udr.data_sets[%zu]` must be SUBSCRIPTION, POLICY, EXPOSURE or APPLICATION", i);
                g5c_json_free(info);
                return NULL;
            }
            g5c_json_push_str(ds, s);
        }
    }
    return info;
}

static int check_group_ids(const g5c_json *g, char *err, size_t cap)
{
    static const char *const k[] = {"nf_type", "nf_group_id", "supi_ranges", NULL};
    if (!g5c_json_is(g, G5C_J_ARRAY) || g5c_json_len(g) == 0)
        return bad(err, cap, "invalid config: `group_ids` must be a non-empty list");
    for (size_t i = 0; i < g5c_json_len(g); i++) {
        const g5c_json *e = g5c_json_at(g, i);
        const char *t = g5c_json_get_str(e, "nf_type"), *id = g5c_json_get_str(e, "nf_group_id");
        char w[64];
        snprintf(w, sizeof w, "group_ids[%zu]", i);
        if (!g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, k, w, err, cap) != 0) {
            if (err[0] == '\0')
                snprintf(err, cap, "invalid config: `%s` must be a mapping", w);
            return -1;
        }
        if (t == NULL || t[0] == '\0' || id == NULL || id[0] == '\0' || strlen(id) > 64)
            return bad(err, cap, "invalid config: `%s` needs `nf_type` and `nf_group_id`", w);
        for (const char *p = t; *p; p++)
            if (!((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_'))
                return bad(err, cap, "invalid config: `%s.nf_type` must be an NF type such as UDM", w);
        {
            char w2[80];
            snprintf(w2, sizeof w2, "%s.supi_ranges", w);
            if (check_ranges(g5c_json_get(e, "supi_ranges"), w2, 5, 15, err, cap) != 0)
                return -1;
        }
    }
    return 0;
}

static int num_in(const g5c_json *o, const char *key, const char *where, int64_t lo, int64_t hi, unsigned *out, char *err, size_t cap)
{
    int64_t v;
    if (g5c_json_get(o, key) == NULL)
        return 0;
    if (!g5c_json_get_int(o, key, &v) || v < lo || v > hi) {
        snprintf(err, cap, "invalid config: `%s.%s` must be an integer in %lld..%lld", where, key, (long long)lo, (long long)hi);
        return -1;
    }
    *out = (unsigned)v;
    return 0;
}

void udr_config_free(udr_config *c)
{
    if (c == NULL)
        return;
    if (c->opts.provisioning_token != NULL) {
        OPENSSL_cleanse((void *)(uintptr_t)c->opts.provisioning_token, strlen(c->opts.provisioning_token));
        free((void *)(uintptr_t)c->opts.provisioning_token);
    }
    g5c_json_free(c->nrf_info);
    g5c_json_free(c->group_ids);
    g5c_udr_store_free(c->store);
    memset(c, 0, sizeof *c);
}

int udr_config_parse(const g5c_json *cfg, udr_config *out, char *err, size_t errcap)
{
    static const char *const k_prov[] = {"token_file", NULL}, *const k_subs[] = {"max_per_data_set", "max_lifetime_s", "notify_retries", NULL},
                             *const k_cache[] = {"max_age_s", NULL}, *const k_compat[] = {"put_no_content", NULL};
    const g5c_json *pv = g5c_json_get(cfg, "provisioning"), *val = g5c_json_get(cfg, "validate"), *subs = g5c_json_get(cfg, "subscriptions"),
                   *cache = g5c_json_get(cfg, "cache"), *gids = g5c_json_get(cfg, "group_ids"), *compat = g5c_json_get(cfg, "compat");
    const char *tf = NULL;
    char ferr[200] = "";
    bool b = true;
    char *token;
    memset(out, 0, sizeof *out);
    err[0] = '\0';
    if (pv != NULL) {
        if (!g5c_json_is(pv, G5C_J_OBJECT) || g5c_json_check_keys(pv, k_prov, "provisioning", err, errcap) != 0) {
            if (err[0] == '\0')
                snprintf(err, errcap, "invalid config: `provisioning` must be a mapping");
            return -1;
        }
        tf = g5c_json_get_str(pv, "token_file");
    }
    if (val != NULL && !g5c_json_bool(val, &b)) {
        snprintf(err, errcap, "invalid config: `validate` must be true or false");
        return -1;
    }
    out->opts.no_validation = !b;
    if (subs != NULL) {
        if (!g5c_json_is(subs, G5C_J_OBJECT) || g5c_json_check_keys(subs, k_subs, "subscriptions", err, errcap) != 0) {
            if (err[0] == '\0')
                snprintf(err, errcap, "invalid config: `subscriptions` must be a mapping");
            return -1;
        }
        if (num_in(subs, "max_per_data_set", "subscriptions", 1, 10000000, &out->opts.max_subscriptions, err, errcap) != 0 ||
            num_in(subs, "max_lifetime_s", "subscriptions", 60, 31536000, &out->opts.subscription_max_s, err, errcap) != 0 ||
            num_in(subs, "notify_retries", "subscriptions", 0, 10, &out->opts.notify_retries, err, errcap) != 0)
            return -1;
    }
    if (cache != NULL) {
        if (!g5c_json_is(cache, G5C_J_OBJECT) || g5c_json_check_keys(cache, k_cache, "cache", err, errcap) != 0) {
            if (err[0] == '\0')
                snprintf(err, errcap, "invalid config: `cache` must be a mapping");
            return -1;
        }
        if (num_in(cache, "max_age_s", "cache", 0, 86400, &out->opts.cache_max_age_s, err, errcap) != 0)
            return -1;
    }
    if (compat != NULL) {
        bool pn = false;
        if (!g5c_json_is(compat, G5C_J_OBJECT) || g5c_json_check_keys(compat, k_compat, "compat", err, errcap) != 0) {
            if (err[0] == '\0')
                snprintf(err, errcap, "invalid config: `compat` must be a mapping");
            return -1;
        }
        if (g5c_json_get(compat, "put_no_content") != NULL && !g5c_json_bool(g5c_json_get(compat, "put_no_content"), &pn)) {
            snprintf(err, errcap, "invalid config: `compat.put_no_content` must be true or false");
            return -1;
        }
        out->opts.put_no_content = pn;
    }
    if (gids != NULL) {
        if (check_group_ids(gids, err, errcap) != 0)
            return -1;
        out->group_ids = g5c_json_dup(gids);
        out->opts.group_ids = out->group_ids;
    }
    out->nrf_info = build_info(g5c_json_get(cfg, "udr"), err, errcap);
    if (out->nrf_info == NULL) {
        udr_config_free(out);
        return -1;
    }
    token = g5c_secret_from_env_or_file("G5C_UDR_PROVISIONING_TOKEN", tf, ferr, sizeof ferr);
    if (token == NULL && ferr[0]) {
        snprintf(err, errcap, "%s", ferr);
        udr_config_free(out);
        return -1;
    }
    if (token != NULL && strlen(token) < 16) {
        snprintf(err, errcap, "the provisioning token must be at least 16 characters");
        OPENSSL_cleanse(token, strlen(token));
        free(token);
        udr_config_free(out);
        return -1;
    }
    out->opts.provisioning_token = token;
    out->store = open_store(cfg, err, errcap);
    if (out->store == NULL) {
        udr_config_free(out);
        return -1;
    }
    return 0;
}
