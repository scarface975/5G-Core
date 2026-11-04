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

static char last_path[1024];

const char *g5c_config_last_path(void)
{
    return last_path;
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
    if (j != NULL)
        snprintf(last_path, sizeof last_path, "%s", path);
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
    free(c->nf_set_id);
    free(c->events.syslog_host);
    free(c->events.syslog_proto);
    free(c->events.syslog_ca);
    free(c->events.http_uri);
    free(c->events.http_ca);
    free(c->reload.token_file);
    memset(c, 0, sizeof *c);
}

static int facility_of(const char *s)
{
    static const struct {
        const char *n;
        int v;
    } f[] = {{"kern", 0}, {"user", 1}, {"daemon", 3}, {"auth", 4}, {"syslog", 5}, {"authpriv", 10}, {"local0", 16}, {"local1", 17},
             {"local2", 18}, {"local3", 19}, {"local4", 20}, {"local5", 21}, {"local6", 22}, {"local7", 23}};
    for (size_t i = 0; i < sizeof f / sizeof *f; i++)
        if (strcmp(s, f[i].n) == 0)
            return f[i].v;
    return -1;
}

static int parse_reload(const g5c_json *rl, g5c_reload_cfg *r, char *err, size_t errcap)
{
    static const char *const k_rl[] = {"token_file", "settle_ms", NULL};
    int64_t v;
    if (!g5c_json_is(rl, G5C_J_OBJECT) || g5c_json_check_keys(rl, k_rl, "reload", err, errcap) != 0) {
        if (err != NULL && errcap > 0 && err[0] == '\0')
            seterr(err, errcap, "invalid config: `reload` must be a mapping");
        return -1;
    }
    r->token_file = opt_str(rl, "token_file");
    r->settle_ms = 1000;
    if (g5c_json_get(rl, "settle_ms") != NULL) {
        if (!g5c_json_get_int(rl, "settle_ms", &v) || v < 0 || v > 60000) {
            seterr(err, errcap, "invalid value for `reload.settle_ms`: must be an integer from 0 to 60000");
            return -1;
        }
        r->settle_ms = (unsigned)v;
    }
    return 0;
}

static int parse_overload(const g5c_json *ov, g5c_overload_cfg *o, char *err, size_t errcap)
{
    static const char *const k_ov[] = {"rate_per_source", "burst", "retry_after_s", "capacity_rps", NULL};
    static const struct {
        const char *key;
        int64_t lo, hi;
    } lim[] = {{"rate_per_source", 1, 1000000}, {"burst", 1, 10000000}, {"retry_after_s", 1, 60}, {"capacity_rps", 1, 10000000}};
    unsigned *dst[] = {&o->rate_per_source, &o->burst, &o->retry_after_s, &o->capacity_rps};
    if (!g5c_json_is(ov, G5C_J_OBJECT) || g5c_json_check_keys(ov, k_ov, "overload", err, errcap) != 0) {
        if (err != NULL && errcap > 0 && err[0] == '\0')
            seterr(err, errcap, "invalid config: `overload` must be a mapping");
        return -1;
    }
    for (size_t i = 0; i < sizeof lim / sizeof *lim; i++) {
        int64_t v;
        if (g5c_json_get(ov, lim[i].key) == NULL)
            continue;
        if (!g5c_json_get_int(ov, lim[i].key, &v) || v < lim[i].lo || v > lim[i].hi) {
            seterr(err, errcap, "invalid value for `overload.%s`: must be an integer from %lld to %lld", lim[i].key, (long long)lim[i].lo, (long long)lim[i].hi);
            return -1;
        }
        *dst[i] = (unsigned)v;
    }
    if (o->rate_per_source == 0 && o->capacity_rps == 0) {
        seterr(err, errcap, "invalid config: `overload` needs `rate_per_source` or `capacity_rps`");
        return -1;
    }
    if (o->burst == 0)
        o->burst = o->rate_per_source > 0 ? 2 * o->rate_per_source : 1;
    if (o->retry_after_s == 0)
        o->retry_after_s = 1;
    o->enabled = true;
    return 0;
}

static int parse_events(const g5c_json *ev, g5c_events_cfg *e, char *err, size_t errcap)
{
    static const char *const k_ev[] = {"min_level", "syslog", "http", NULL}, *const k_sl[] = {"host", "port", "proto", "ca", "facility", NULL},
                             *const k_ht[] = {"uri", "ca", "batch", NULL};
    const g5c_json *sl = g5c_json_get(ev, "syslog"), *ht = g5c_json_get(ev, "http");
    const char *lv = g5c_json_get_str(ev, "min_level");
    int64_t v;
    if (!g5c_json_is(ev, G5C_J_OBJECT) || g5c_json_check_keys(ev, k_ev, "events", err, errcap) != 0) {
        if (err != NULL && errcap > 0 && err[0] == '\0')
            seterr(err, errcap, "invalid config: `events` must be a mapping");
        return -1;
    }
    e->min_level = 1;
    if (lv != NULL) {
        if (strcmp(lv, "error") == 0)
            e->min_level = 0;
        else if (strcmp(lv, "warn") != 0) {
            seterr(err, errcap, "invalid value for `events.min_level`: must be error or warn");
            return -1;
        }
    }
    if (sl != NULL && !g5c_json_is(sl, G5C_J_NULL)) {
        const char *fac = g5c_json_get_str(sl, "facility");
        if (!g5c_json_is(sl, G5C_J_OBJECT) || g5c_json_check_keys(sl, k_sl, "events.syslog", err, errcap) != 0) {
            if (err != NULL && errcap > 0 && err[0] == '\0')
                seterr(err, errcap, "invalid config: `events.syslog` must be a mapping");
            return -1;
        }
        if (need_str(sl, "host", "events.syslog", &e->syslog_host, err, errcap) != 0)
            return -1;
        e->syslog_proto = g5c_xstrdup(g5c_json_get_str(sl, "proto") != NULL ? g5c_json_get_str(sl, "proto") : "udp");
        if (strcmp(e->syslog_proto, "udp") != 0 && strcmp(e->syslog_proto, "tcp") != 0 && strcmp(e->syslog_proto, "tls") != 0) {
            seterr(err, errcap, "invalid value for `events.syslog.proto`: must be udp, tcp or tls");
            return -1;
        }
        e->syslog_port = strcmp(e->syslog_proto, "tls") == 0 ? 6514 : 514;
        if (g5c_json_get(sl, "port") != NULL) {
            if (!g5c_json_get_int(sl, "port", &v) || v < 1 || v > 65535) {
                seterr(err, errcap, "invalid value for `events.syslog.port`: must be 1 to 65535");
                return -1;
            }
            e->syslog_port = (uint16_t)v;
        }
        e->syslog_ca = opt_str(sl, "ca");
        if (strcmp(e->syslog_proto, "tls") == 0 && e->syslog_ca == NULL) {
            seterr(err, errcap, "invalid config: `events.syslog.proto: tls` needs `events.syslog.ca`");
            return -1;
        }
        e->syslog_facility = fac != NULL ? facility_of(fac) : 16;
        if (e->syslog_facility < 0) {
            seterr(err, errcap, "invalid value for `events.syslog.facility`: use daemon, auth, authpriv, user, syslog, kern or local0 to local7");
            return -1;
        }
    }
    if (ht != NULL && !g5c_json_is(ht, G5C_J_NULL)) {
        if (!g5c_json_is(ht, G5C_J_OBJECT) || g5c_json_check_keys(ht, k_ht, "events.http", err, errcap) != 0) {
            if (err != NULL && errcap > 0 && err[0] == '\0')
                seterr(err, errcap, "invalid config: `events.http` must be a mapping");
            return -1;
        }
        if (need_str(ht, "uri", "events.http", &e->http_uri, err, errcap) != 0)
            return -1;
        if (strncmp(e->http_uri, "http://", 7) != 0 && strncmp(e->http_uri, "https://", 8) != 0) {
            seterr(err, errcap, "invalid value for `events.http.uri`: must be an http or https URI");
            return -1;
        }
        e->http_ca = opt_str(ht, "ca");
        if (strncmp(e->http_uri, "https://", 8) == 0 && e->http_ca == NULL) {
            seterr(err, errcap, "invalid config: an https `events.http.uri` needs `events.http.ca`");
            return -1;
        }
        e->http_batch = 50;
        if (g5c_json_get(ht, "batch") != NULL) {
            if (!g5c_json_get_int(ht, "batch", &v) || v < 1 || v > 1000) {
                seterr(err, errcap, "invalid value for `events.http.batch`: must be 1 to 1000");
                return -1;
            }
            e->http_batch = (unsigned)v;
        }
    }
    if (e->syslog_host == NULL && e->http_uri == NULL) {
        seterr(err, errcap, "invalid config: `events` needs a `syslog` or an `http` target");
        return -1;
    }
    e->enabled = true;
    return 0;
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
    if (g5c_json_get(root, "nf_set_id") != NULL) {
        const char *id = g5c_json_get_str(root, "nf_set_id");
        if (id == NULL || id[0] == 0 || strlen(id) > 127) {
            seterr(err, errcap, "invalid config: `nf_set_id` must be a set identifier (TS 23.003 28.12), at most 127 characters");
            goto bad;
        }
        out->nf_set_id = g5c_xstrdup(id);
    }
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
    if (g5c_json_get(root, "events") != NULL && !g5c_json_is(g5c_json_get(root, "events"), G5C_J_NULL) &&
        parse_events(g5c_json_get(root, "events"), &out->events, err, errcap) != 0)
        goto bad;
    if (g5c_json_get(root, "overload") != NULL && !g5c_json_is(g5c_json_get(root, "overload"), G5C_J_NULL) &&
        parse_overload(g5c_json_get(root, "overload"), &out->overload, err, errcap) != 0)
        goto bad;
    out->reload.settle_ms = 1000;
    if (g5c_json_get(root, "reload") != NULL && !g5c_json_is(g5c_json_get(root, "reload"), G5C_J_NULL) &&
        parse_reload(g5c_json_get(root, "reload"), &out->reload, err, errcap) != 0)
        goto bad;
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
