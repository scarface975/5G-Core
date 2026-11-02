/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include "g5c/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/base.h"

#define MAX_CONFIG_BYTES (4U << 20)

static void seterr(char *err, size_t cap, const char *fmt, ...) G5C_PRINTF(3, 4);
static void seterr(char *err, size_t cap, const char *fmt, ...)
{
    va_list ap;
    if (err == NULL || cap == 0)
        return;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

char *g5c_read_file(const char *path, size_t max_len, size_t *len)
{
    FILE *f = fopen(path, "rb");
    g5c_bytes b;
    char buf[4096];
    size_t n;
    if (f == NULL)
        return NULL;
    g5c_bytes_init(&b);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        if (b.len + n > max_len || g5c_bytes_append(&b, buf, n) != 0) {
            fclose(f);
            g5c_bytes_free(&b);
            return NULL;
        }
    }
    if (ferror(f)) {
        fclose(f);
        g5c_bytes_free(&b);
        return NULL;
    }
    fclose(f);
    return g5c_bytes_take(&b, len);
}

g5c_json *g5c_config_load(const char *path, char *err, size_t errcap)
{
    size_t len = 0;
    char *text = g5c_read_file(path, MAX_CONFIG_BYTES, &len);
    g5c_json *j;
    if (text == NULL) {
        seterr(err, errcap, "cannot read config %s", path);
        return NULL;
    }
    /* a JSON document is also valid for the YAML subset (flow style) */
    j = g5c_yaml_parse(text, len, err, errcap);
    free(text);
    if (j != NULL && !g5c_json_is(j, G5C_J_OBJECT)) {
        seterr(err, errcap, "config root must be a mapping");
        g5c_json_free(j);
        return NULL;
    }
    return j;
}

int g5c_json_check_keys(const g5c_json *obj, const char *const *allowed, const char *where, char *err,
                        size_t errcap)
{
    for (size_t i = 0; i < g5c_json_len(obj); i++) {
        const char *k = g5c_json_key_at(obj, i);
        bool ok = false;
        for (size_t a = 0; allowed[a] != NULL; a++)
            if (strcmp(k, allowed[a]) == 0) {
                ok = true;
                break;
            }
        if (!ok) {
            seterr(err, errcap, "invalid config: unknown field `%s` in %s", k, where);
            return -1;
        }
    }
    return 0;
}

static int need_str(const g5c_json *o, const char *key, const char *where, char **out, char *err, size_t cap)
{
    const char *s = g5c_json_get_str(o, key);
    if (s == NULL) {
        seterr(err, cap, "invalid config: missing or non-string `%s` in %s", key, where);
        return -1;
    }
    *out = g5c_xstrdup(s);
    return 0;
}

static char *opt_str(const g5c_json *o, const char *key)
{
    const char *s = g5c_json_get_str(o, key);
    return s ? g5c_xstrdup(s) : NULL;
}

void g5c_common_free(g5c_common *c)
{
    free(c->name);
    free(c->mcc);
    free(c->mnc);
    free(c->address);
    free(c->tls.cert);
    free(c->tls.key);
    free(c->tls.ca);
    for (size_t i = 0; i < c->tls.nallowed; i++)
        free(c->tls.allowed_peers[i]);
    free(c->tls.allowed_peers);
    free(c->tls.crl);
    free(c->log_level);
    free(c->nrf_uri);
    free(c->scp_uri);
    memset(c, 0, sizeof *c);
}

int g5c_common_parse(const g5c_json *root, g5c_common *out, char *err, size_t errcap)
{
    static const char *const k_plmn[] = {"mcc", "mnc", NULL};
    static const char *const k_sbi[] = {"address", "port", "tls", NULL};
    static const char *const k_tls[] = {"cert", "key", "ca", "allowed_peers", "crl", NULL};
    static const char *const k_log[] = {"level", "json", NULL};
    static const char *const k_nrf[] = {"uri", NULL}, *const k_scp[] = {"uri", NULL}, *const k_oauth[] = {"enforce", "acquire", "leeway_s", "jwks_refresh_s", NULL};
    const g5c_json *scp = g5c_json_get(root, "scp_client"), *oauth = g5c_json_get(root, "oauth2");
    const g5c_json *plmn = g5c_json_get(root, "plmn"), *sbi = g5c_json_get(root, "sbi");
    const g5c_json *tls = g5c_json_get(sbi, "tls"), *log = g5c_json_get(root, "log"),
                   *nrf = g5c_json_get(root, "nrf");
    int64_t port = 0;
    memset(out, 0, sizeof *out);
    out->oauth2_leeway_s = 5;
    out->oauth2_jwks_refresh_s = 600;
    if (need_str(root, "name", "config", &out->name, err, errcap) != 0)
        goto bad;
    if (!g5c_json_is(plmn, G5C_J_OBJECT) || !g5c_json_is(sbi, G5C_J_OBJECT)) {
        seterr(err, errcap, "invalid config: `plmn` and `sbi` sections are required");
        goto bad;
    }
    if (g5c_json_check_keys(plmn, k_plmn, "plmn", err, errcap) != 0 ||
        g5c_json_check_keys(sbi, k_sbi, "sbi", err, errcap) != 0)
        goto bad;
    if (need_str(plmn, "mcc", "plmn", &out->mcc, err, errcap) != 0 ||
        need_str(plmn, "mnc", "plmn", &out->mnc, err, errcap) != 0 ||
        need_str(sbi, "address", "sbi", &out->address, err, errcap) != 0)
        goto bad;
    if (!g5c_json_get_int(sbi, "port", &port) || port < 0 || port > 65535) {
        seterr(err, errcap, "invalid config: `sbi.port` must be an integer 0-65535");
        goto bad;
    }
    out->port = (uint16_t)port;
    if (tls != NULL && !g5c_json_is(tls, G5C_J_NULL)) {
        if (!g5c_json_is(tls, G5C_J_OBJECT) || g5c_json_check_keys(tls, k_tls, "sbi.tls", err, errcap) != 0) {
            if (err != NULL && errcap > 0 && err[0] == '\0')
                seterr(err, errcap, "invalid config: `sbi.tls` must be a mapping");
            goto bad;
        }
        out->has_tls = true;
        if (need_str(tls, "cert", "sbi.tls", &out->tls.cert, err, errcap) != 0 ||
            need_str(tls, "key", "sbi.tls", &out->tls.key, err, errcap) != 0)
            goto bad;
        out->tls.ca = opt_str(tls, "ca");
        out->tls.crl = opt_str(tls, "crl");
        if (g5c_json_get(tls, "allowed_peers") != NULL) {
            const g5c_json *l = g5c_json_get(tls, "allowed_peers");
            if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) == 0 || g5c_json_len(l) > 64) {
                seterr(err, errcap, "invalid config: `sbi.tls.allowed_peers` must be a list of 1 to 64 names");
                goto bad;
            }
            out->tls.allowed_peers = g5c_xcalloc(g5c_json_len(l), sizeof *out->tls.allowed_peers);
            for (size_t i = 0; i < g5c_json_len(l); i++) {
                const char *s = g5c_json_str(g5c_json_at(l, i));
                if (s == NULL || s[0] == '\0' || strlen(s) > 100) {
                    seterr(err, errcap, "invalid config: `sbi.tls.allowed_peers` holds a name that is not a short string");
                    goto bad;
                }
                out->tls.allowed_peers[out->tls.nallowed++] = g5c_xstrdup(s);
            }
        }
    }
    out->log_level = g5c_xstrdup("info");
    if (log != NULL && !g5c_json_is(log, G5C_J_NULL)) {
        if (!g5c_json_is(log, G5C_J_OBJECT) || g5c_json_check_keys(log, k_log, "log", err, errcap) != 0) {
            if (err != NULL && errcap > 0 && err[0] == '\0')
                seterr(err, errcap, "invalid config: `log` must be a mapping");
            goto bad;
        }
        if (g5c_json_get_str(log, "level") != NULL) {
            free(out->log_level);
            out->log_level = opt_str(log, "level");
        }
        (void)g5c_json_get_bool(log, "json", &out->log_json);
    }
    if (scp != NULL && !g5c_json_is(scp, G5C_J_NULL)) {
        if (!g5c_json_is(scp, G5C_J_OBJECT) || g5c_json_check_keys(scp, k_scp, "scp_client", err, errcap) != 0) {
            if (err != NULL && errcap > 0 && err[0] == '\0')
                seterr(err, errcap, "invalid config: `scp_client` must be a mapping");
            goto bad;
        }
        if (need_str(scp, "uri", "scp_client", &out->scp_uri, err, errcap) != 0)
            goto bad;
    }
    if (oauth != NULL && !g5c_json_is(oauth, G5C_J_NULL)) {
        int64_t v;
        if (!g5c_json_is(oauth, G5C_J_OBJECT) || g5c_json_check_keys(oauth, k_oauth, "oauth2", err, errcap) != 0) {
            if (err != NULL && errcap > 0 && err[0] == '\0')
                seterr(err, errcap, "invalid config: `oauth2` must be a mapping");
            goto bad;
        }
        if ((g5c_json_get(oauth, "enforce") != NULL && !g5c_json_get_bool(oauth, "enforce", &out->oauth2_enforce)) ||
            (g5c_json_get(oauth, "acquire") != NULL && !g5c_json_get_bool(oauth, "acquire", &out->oauth2_acquire))) {
            seterr(err, errcap, "invalid config: `oauth2.enforce` and `oauth2.acquire` must be true or false");
            goto bad;
        }
        if (g5c_json_get(oauth, "leeway_s") != NULL) {
            if (!g5c_json_get_int(oauth, "leeway_s", &v) || v < 0 || v > 300) {
                seterr(err, errcap, "invalid config: `oauth2.leeway_s` must be an integer from 0 to 300");
                goto bad;
            }
            out->oauth2_leeway_s = (unsigned)v;
        }
        if (g5c_json_get(oauth, "jwks_refresh_s") != NULL) {
            if (!g5c_json_get_int(oauth, "jwks_refresh_s", &v) || v < 10 || v > 86400) {
                seterr(err, errcap, "invalid config: `oauth2.jwks_refresh_s` must be an integer from 10 to 86400");
                goto bad;
            }
            out->oauth2_jwks_refresh_s = (unsigned)v;
        }
    }
    if (nrf != NULL && !g5c_json_is(nrf, G5C_J_NULL)) {
        if (!g5c_json_is(nrf, G5C_J_OBJECT) || g5c_json_check_keys(nrf, k_nrf, "nrf", err, errcap) != 0) {
            if (err != NULL && errcap > 0 && err[0] == '\0')
                seterr(err, errcap, "invalid config: `nrf` must be a mapping");
            goto bad;
        }
        if (need_str(nrf, "uri", "nrf", &out->nrf_uri, err, errcap) != 0)
            goto bad;
    }
    return 0;
bad:
    g5c_common_free(out);
    return -1;
}

int g5c_common_validate(const g5c_common *c, char *err, size_t errcap)
{
    size_t ml;
    const char *p;
    bool blank = true;
    for (p = c->name; *p; p++)
        if (*p != ' ' && *p != '\t' && *p != '\n')
            blank = false;
    if (blank) {
        seterr(err, errcap, "invalid value for `name`: must not be empty");
        return -1;
    }
    if (strlen(c->mcc) != 3 || !g5c_is_digits(c->mcc)) {
        seterr(err, errcap, "invalid value for `plmn.mcc`: must be 3 digits");
        return -1;
    }
    ml = strlen(c->mnc);
    if (ml < 2 || ml > 3 || !g5c_is_digits(c->mnc)) {
        seterr(err, errcap, "invalid value for `plmn.mnc`: must be 2 or 3 digits");
        return -1;
    }
    if (c->port == 0) {
        seterr(err, errcap, "invalid value for `sbi.port`: must be non-zero");
        return -1;
    }
    if ((c->oauth2_enforce || c->oauth2_acquire) && c->nrf_uri == NULL) {
        seterr(err, errcap, "invalid config: `oauth2` needs `nrf.uri` (the NRF issues the tokens and publishes the key that verifies them)");
        return -1;
    }
    if (c->scp_uri != NULL && strncmp(c->scp_uri, "http://", 7) != 0 && strncmp(c->scp_uri, "https://", 8) != 0) {
        seterr(err, errcap, "invalid value for `scp_client.uri`: must be an http or https URI");
        return -1;
    }
    return 0;
}
