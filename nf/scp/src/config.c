/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* SCP configuration: the `scp:` block (the NRF it discovers at is the common `nrf:` section).
 *
 *   scp:
 *     prefix: /scp                 the deployment-specific string of the SCP's own apiRoot (default: none)
 *     next: { uri: http://scp2:7777/x, delegate_discovery: false }    a next-hop SCP: requests go to it with the apiRoot this SCP selected, or (delegate_discovery)
 *                                                                      with the discovery headers for it to select
 *     discovery: { delegated: true, cache_ttl_s: 60, cache_max: 1024 }  delegated discovery (Model D) and the cache of the NRF's answers
 *     routing:
 *       attempts: 3                producers tried for one request
 *       timeout_ms: 5000           per attempt
 *       retry_on_503: true         try the next producer when one answers 503
 *       quarantine: { failures: 3, seconds: 10 }     a producer that fails this often is left alone for this long
 *       max_inflight: 4096         requests handled at once (more: 503 NF_CONGESTION)
 *       max_body: 1048576          largest request body (more: 413)
 *       workers: 256               threads that forward (a request waits for its producer in one of them)
 *     targets: { allow: [ 127.0.0.0/8, '*.5gc.example.org', udm.example.org ] }   where the SCP may forward to (default: anywhere) */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

#define FAIL(...)                                                                                                                                   \
    do {                                                                                                                                            \
        snprintf(err, errcap, __VA_ARGS__);                                                                                                         \
        goto bad;                                                                                                                                   \
    } while (0)

void scp_cfg_free(scp_cfg *c)
{
    if (c == NULL)
        return;
    free(c->name);
    free(c->prefix);
    free(c->nrf_uri);
    free(c->next_uri);
    for (size_t i = 0; i < c->nallow; i++)
        free(c->allow[i]);
    free(c->allow);
    free(c);
}

unsigned scp_cfg_workers(const scp_cfg *c)
{
    return c->workers;
}

static int num_in(const g5c_json *o, const char *key, const char *where, int64_t lo, int64_t hi, unsigned *out, char *err, size_t errcap)
{
    int64_t v;
    if (g5c_json_get(o, key) == NULL)
        return 0;
    if (!g5c_json_get_int(o, key, &v) || v < lo || v > hi) {
        snprintf(err, errcap, "invalid config: `%s.%s` must be an integer from %lld to %lld", where, key, (long long)lo, (long long)hi);
        return -1;
    }
    *out = (unsigned)v;
    return 0;
}

static int sub(const g5c_json *blk, const char *key, const char *const *keys, const g5c_json **out, char *err, size_t errcap)
{
    char where[48];
    *out = g5c_json_get(blk, key);
    if (*out == NULL)
        return 0;
    snprintf(where, sizeof where, "scp.%s", key);
    if (!g5c_json_is(*out, G5C_J_OBJECT) || g5c_json_check_keys(*out, keys, where, err, errcap) != 0) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: `%s` must be a mapping", where);
        return -1;
    }
    return 0;
}

static bool uri_ok(const char *u)
{
    return u != NULL && (strncmp(u, "http://", 7) == 0 || strncmp(u, "https://", 8) == 0) && strlen(u) < 256 && strchr(u, ' ') == NULL && strchr(u, '?') == NULL;
}

scp_cfg *scp_cfg_parse(const g5c_json *root, const char *name, const char *nrf_uri, char *err, size_t errcap)
{
    static const char *const top[] = {"prefix", "next", "discovery", "routing", "targets", NULL}, *const k_next[] = {"uri", "delegate_discovery", NULL},
                             *const k_disc[] = {"delegated", "cache_ttl_s", "cache_max", NULL},
                             *const k_route[] = {"attempts", "timeout_ms", "retry_on_503", "quarantine", "max_inflight", "max_body", "workers", NULL},
                             *const k_quar[] = {"failures", "seconds", NULL}, *const k_tgt[] = {"allow", NULL};
    const g5c_json *blk = g5c_json_get(root, "scp"), *o, *q, *l;
    scp_cfg *c = g5c_xcalloc(1, sizeof *c);
    err[0] = '\0';
    c->name = g5c_xstrdup(name);
    c->prefix = g5c_xstrdup("");
    c->nrf_uri = nrf_uri != NULL ? g5c_xstrdup(nrf_uri) : NULL;
    c->attempts = 3;
    c->timeout_ms = 5000;
    c->workers = 256;
    c->max_inflight = 4096;
    c->max_body = 1u << 20;
    c->quarantine_failures = 3;
    c->quarantine_s = 10;
    c->disc_ttl_s = 60;
    c->disc_max = 1024;
    c->retry_503 = true;
    c->delegated = true;
    if (blk != NULL && (!g5c_json_is(blk, G5C_J_OBJECT) || g5c_json_check_keys(blk, top, "scp", err, errcap) != 0)) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: `scp` must be a mapping");
        goto bad;
    }
    if (g5c_json_get(blk, "prefix") != NULL) {
        const char *p = g5c_json_get_str(blk, "prefix");
        size_t n = p != NULL ? strlen(p) : 0;
        if (p == NULL || (n > 0 && (p[0] != '/' || p[n - 1] == '/' || strchr(p, ' ') != NULL || strchr(p, '?') != NULL || n > 128)))
            FAIL("invalid config: `scp.prefix` must be empty or a path such as /x/y");
        free(c->prefix);
        c->prefix = g5c_xstrdup(p);
    }
    if (sub(blk, "next", k_next, &o, err, errcap) != 0)
        goto bad;
    if (o != NULL) {
        if (!uri_ok(g5c_json_get_str(o, "uri")))
            FAIL("invalid config: `scp.next.uri` must be an http(s) URI");
        c->next_uri = g5c_xstrdup(g5c_json_get_str(o, "uri"));
        if (g5c_json_get(o, "delegate_discovery") != NULL && !g5c_json_get_bool(o, "delegate_discovery", &c->next_delegates))
            FAIL("invalid config: `scp.next.delegate_discovery` must be true or false");
    }
    if (sub(blk, "discovery", k_disc, &o, err, errcap) != 0)
        goto bad;
    if (o != NULL) {
        if (g5c_json_get(o, "delegated") != NULL && !g5c_json_get_bool(o, "delegated", &c->delegated))
            FAIL("invalid config: `scp.discovery.delegated` must be true or false");
        if (num_in(o, "cache_ttl_s", "scp.discovery", 0, 86400, &c->disc_ttl_s, err, errcap) != 0 || num_in(o, "cache_max", "scp.discovery", 1, 100000, &c->disc_max, err, errcap) != 0)
            goto bad;
    }
    if (sub(blk, "routing", k_route, &o, err, errcap) != 0)
        goto bad;
    if (o != NULL) {
        if (num_in(o, "attempts", "scp.routing", 1, 10, &c->attempts, err, errcap) != 0 || num_in(o, "timeout_ms", "scp.routing", 50, 120000, &c->timeout_ms, err, errcap) != 0 ||
            num_in(o, "max_inflight", "scp.routing", 1, 1000000, &c->max_inflight, err, errcap) != 0 || num_in(o, "max_body", "scp.routing", 1024, 16u << 20, &c->max_body, err, errcap) != 0 ||
            num_in(o, "workers", "scp.routing", 1, 512, &c->workers, err, errcap) != 0)
            goto bad;
        if (g5c_json_get(o, "retry_on_503") != NULL && !g5c_json_get_bool(o, "retry_on_503", &c->retry_503))
            FAIL("invalid config: `scp.routing.retry_on_503` must be true or false");
        if (sub(o, "quarantine", k_quar, &q, err, errcap) != 0)
            goto bad;
        if (q != NULL && (num_in(q, "failures", "scp.routing.quarantine", 1, 1000, &c->quarantine_failures, err, errcap) != 0 ||
                          num_in(q, "seconds", "scp.routing.quarantine", 1, 86400, &c->quarantine_s, err, errcap) != 0))
            goto bad;
    }
    if (sub(blk, "targets", k_tgt, &o, err, errcap) != 0)
        goto bad;
    l = g5c_json_get(o, "allow");
    if (l != NULL) {
        if (!g5c_json_is(l, G5C_J_ARRAY))
            FAIL("invalid config: `scp.targets.allow` must be a list of host names, wildcard names (*.example.org) and IPv4 CIDRs");
        for (size_t i = 0; i < g5c_json_len(l); i++) {
            const char *e = g5c_json_str(g5c_json_at(l, i));
            bool good = e != NULL && e[0] != '\0' && strlen(e) < 128;
            for (const char *p = e; good && *p != 0; p++)
                good = isalnum((unsigned char)*p) || *p == '.' || *p == '-' || *p == '*' || *p == '/' || *p == ':' || *p == '_';
            if (!good)
                FAIL("invalid config: `scp.targets.allow[%zu]` is not a host name, wildcard name or CIDR", i);
            c->allow = g5c_xrealloc(c->allow, (c->nallow + 1) * sizeof *c->allow);
            c->allow[c->nallow++] = g5c_xstrdup(e);
        }
    }
    return c;
bad:
    scp_cfg_free(c);
    return NULL;
}
