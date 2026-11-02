/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NEF configuration: the `nef:` block.
 *
 *   nef:
 *     afs:                          the application functions that may use the northbound APIs (at least one)
 *       - id: af-1                  the {afId} / {scsAsId} of the resource URIs
 *         token_file: /etc/g5c/af-1.token    the bearer token the AF presents (16 characters at least), or the variable G5C_NEF_AF_<ID>_TOKEN
 *         no_auth: false            true: no token is required (development only)
 *         apis: [traffic-influence, monitoring-event, as-session-with-qos]       default: all
 *         notify_hosts: [af1.example.com, 192.0.2.10]       hosts its notification destinations may name
 *         any_notify_host: false    true: any host (development only); without either the AF cannot subscribe to notifications
 *         qos_references: [voice, video]    the QoS references it may name (AsSessionWithQoS); default: any
 *         max_subscriptions: 1000
 *     callback_uri: http://nef:7777          where the AMF reaches the NEF's callback endpoints (default: the SBI listener)
 *     udr: { uri: http://udr:7777, timeout_ms: 3000 }    default: found through the NRF (Nudr_DataRepository)
 *     udm: { uri: http://udm:7777 }                      default: found through the NRF (Nudm_SDM, Nudm_UECM)
 *     pcf: { uri: http://pcf:7777 }                      the PCF that authorizes QoS (AsSessionWithQoS) for every UE (a lab with one PCF)
 *     bsf: { uri: http://bsf:7777 }                      the BSF that says which PCF holds the PDU session of a UE address (Nbsf_Management_Discovery); default: found
 *                                                        through the NRF. Without `pcf:` the PCF is the one the BSF names; when there is no BSF or it has no binding, the NRF's
 *     amf: { uri: http://amf:7777 }                      the AMF to subscribe at for every UE (a lab with one AMF); default: the serving AMF of the UE
 *     subscriptions: { max_lifetime_s: 86400, notify_retries: 3, max_reports: 1000000 }
 *     state_file: /var/lib/g5c/nef.json
 *     validate: true                check bodies against the OpenAPI schemas of TS 29.522 / TS 29.122 */
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

const char *const nef_api_names[API_COUNT] = {"traffic-influence", "monitoring-event", "as-session-with-qos"};

static void af_free(nef_af *a)
{
    free(a->id);
    if (a->token != NULL) {
        memset(a->token, 0, strlen(a->token));
        free(a->token);
    }
    for (size_t i = 0; i < a->nhosts; i++)
        free(a->hosts[i]);
    free(a->hosts);
    for (size_t i = 0; i < a->nqos_refs; i++)
        free(a->qos_refs[i]);
    free(a->qos_refs);
}

void nef_cfg_free(nef_cfg *c)
{
    if (c == NULL)
        return;
    for (size_t i = 0; i < c->nafs; i++)
        af_free(&c->afs[i]);
    free(c->afs);
    free(c->state_file);
    free(c->callback_uri);
    free(c->udr_uri);
    free(c->udm_uri);
    free(c->amf_uri);
    free(c->pcf_uri);
    free(c->bsf_uri);
    free(c->nrf_uri);
    free(c);
}

const nef_af *cfg_af(const nef_cfg *c, const char *id)
{
    for (size_t i = 0; id != NULL && i < c->nafs; i++)
        if (strcmp(c->afs[i].id, id) == 0)
            return &c->afs[i];
    return NULL;
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

static bool host_ok(const char *h)
{
    size_t n = h == NULL ? 0 : strlen(h);
    if (n == 0 || n > 253)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)h[i]) && h[i] != '-' && h[i] != '.' && h[i] != ':')
            return false;
    return true;
}

static int optional_uri(const g5c_json *blk, const char *key, char **out, char *err, size_t errcap)
{
    const g5c_json *o = g5c_json_get(blk, key);
    const char *u;
    static const char *const k_uri[] = {"uri", "timeout_ms", NULL};
    char where[32];
    if (o == NULL)
        return 0;
    snprintf(where, sizeof where, "nef.%s", key);
    if (!g5c_json_is(o, G5C_J_OBJECT) || g5c_json_check_keys(o, k_uri, where, err, errcap) != 0) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: `%s` must be a mapping", where);
        return -1;
    }
    u = g5c_json_get_str(o, "uri");
    if (g5c_json_get(o, "uri") != NULL && !uri_ok(u)) {
        snprintf(err, errcap, "invalid config: `%s.uri` must be an http(s) URI", where);
        return -1;
    }
    if (u != NULL)
        *out = g5c_xstrdup(u);
    return 0;
}

static int parse_af(const g5c_json *e, size_t i, nef_af *a, char *err, size_t errcap)
{
    static const char *const k_af[] = {"id", "token_file", "no_auth", "apis", "notify_hosts", "any_notify_host", "max_subscriptions", "qos_references", NULL};
    char where[40], env[96], *p;
    const char *id, *tf;
    bool no_auth = false;
    int64_t v;
    snprintf(where, sizeof where, "nef.afs[%zu]", i);
    if (!g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, k_af, where, err, errcap) != 0) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: `%s` must be a mapping", where);
        return -1;
    }
    id = g5c_json_get_str(e, "id");
    if (!is_hex_id(id)) {
        snprintf(err, errcap, "invalid config: `%s.id` must be 1 to 64 characters of letters, digits, '-', '_' and '.'", where);
        return -1;
    }
    a->id = g5c_xstrdup(id);
    a->max_subs = 1000;
    if (g5c_json_get(e, "max_subscriptions") != NULL) {
        if (!g5c_json_get_int(e, "max_subscriptions", &v) || v < 1 || v > 10000000) {
            snprintf(err, errcap, "invalid config: `%s.max_subscriptions` must be an integer from 1 to 10000000", where);
            return -1;
        }
        a->max_subs = (unsigned)v;
    }
    a->apis = (1u << API_COUNT) - 1;
    if (g5c_json_get(e, "apis") != NULL) {
        const g5c_json *l = g5c_json_get(e, "apis");
        a->apis = 0;
        if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) == 0) {
            snprintf(err, errcap, "invalid config: `%s.apis` must be a non-empty list", where);
            return -1;
        }
        for (size_t k = 0; k < g5c_json_len(l); k++) {
            const char *nm = g5c_json_str(g5c_json_at(l, k));
            int found = -1;
            for (int j = 0; nm != NULL && j < API_COUNT; j++)
                if (strcmp(nm, nef_api_names[j]) == 0)
                    found = j;
            if (found < 0) {
                snprintf(err, errcap, "invalid config: `%s.apis` names an API the NEF does not have (traffic-influence, monitoring-event, as-session-with-qos)", where);
                return -1;
            }
            a->apis |= 1u << found;
        }
    }
    if (g5c_json_get(e, "notify_hosts") != NULL) {
        const g5c_json *l = g5c_json_get(e, "notify_hosts");
        if (!g5c_json_is(l, G5C_J_ARRAY)) {
            snprintf(err, errcap, "invalid config: `%s.notify_hosts` must be a list of host names or addresses", where);
            return -1;
        }
        for (size_t k = 0; k < g5c_json_len(l); k++) {
            const char *h = g5c_json_str(g5c_json_at(l, k));
            if (!host_ok(h)) {
                snprintf(err, errcap, "invalid config: `%s.notify_hosts[%zu]` is not a host name or address", where, k);
                return -1;
            }
            a->hosts = g5c_xrealloc(a->hosts, (a->nhosts + 1) * sizeof *a->hosts);
            a->hosts[a->nhosts++] = g5c_xstrdup(h);
        }
    }
    if (g5c_json_get(e, "qos_references") != NULL) {
        const g5c_json *l = g5c_json_get(e, "qos_references");
        if (!g5c_json_is(l, G5C_J_ARRAY)) {
            snprintf(err, errcap, "invalid config: `%s.qos_references` must be a list of names", where);
            return -1;
        }
        for (size_t k = 0; k < g5c_json_len(l); k++) {
            const char *q = g5c_json_str(g5c_json_at(l, k));
            if (q == NULL || q[0] == '\0' || strlen(q) > 64) {
                snprintf(err, errcap, "invalid config: `%s.qos_references[%zu]` must be a name of 1 to 64 characters", where, k);
                return -1;
            }
            a->qos_refs = g5c_xrealloc(a->qos_refs, (a->nqos_refs + 1) * sizeof *a->qos_refs);
            a->qos_refs[a->nqos_refs++] = g5c_xstrdup(q);
        }
    }
    if (g5c_json_get(e, "any_notify_host") != NULL && !g5c_json_get_bool(e, "any_notify_host", &a->any_host)) {
        snprintf(err, errcap, "invalid config: `%s.any_notify_host` must be true or false", where);
        return -1;
    }
    if (g5c_json_get(e, "no_auth") != NULL && !g5c_json_get_bool(e, "no_auth", &no_auth)) {
        snprintf(err, errcap, "invalid config: `%s.no_auth` must be true or false", where);
        return -1;
    }
    snprintf(env, sizeof env, "G5C_NEF_AF_%s_TOKEN", id);
    for (p = env; *p != 0; p++)
        *p = isalnum((unsigned char)*p) ? (char)toupper((unsigned char)*p) : '_';
    tf = g5c_json_get_str(e, "token_file");
    if (g5c_json_get(e, "token_file") != NULL && (tf == NULL || tf[0] == '\0')) {
        snprintf(err, errcap, "invalid config: `%s.token_file` must be a path", where);
        return -1;
    }
    {
        char ferr[160] = "";
        a->token = g5c_secret_from_env_or_file(env, tf, ferr, sizeof ferr);
        if (ferr[0] != '\0') {
            snprintf(err, errcap, "invalid config: `%s.token_file`: %s", where, ferr);
            return -1;
        }
    }
    if (a->token != NULL && strlen(a->token) < 16) {
        snprintf(err, errcap, "invalid config: the bearer token of AF `%s` must be at least 16 characters", id);
        return -1;
    }
    if (a->token == NULL && !no_auth) {
        snprintf(err, errcap, "invalid config: AF `%s` has no bearer token (`%s.token_file` or %s); set `no_auth: true` to run without one", id, where, env);
        return -1;
    }
    return 0;
}

nef_cfg *nef_cfg_parse(const g5c_json *root, const char *serving_mcc, const char *serving_mnc, const char *default_callback_uri, char *err, size_t errcap)
{
    static const char *const top[] = {"afs", "callback_uri", "udr", "udm", "amf", "pcf", "bsf", "subscriptions", "state_file", "validate", "events_via_udm", NULL},
                             *const k_sub[] = {"max_lifetime_s", "notify_retries", "max_reports", NULL};
    const g5c_json *blk = g5c_json_get(root, "nef"), *l, *o;
    nef_cfg *c = g5c_xcalloc(1, sizeof *c);
    err[0] = '\0';
    snprintf(c->mcc, sizeof c->mcc, "%s", serving_mcc);
    snprintf(c->mnc, sizeof c->mnc, "%s", serving_mnc);
    c->sub_lifetime_s = 86400;
    c->notify_retries = 3;
    c->max_reports = 1000000;
    c->udr_timeout_ms = 3000;
    c->validate = true;
    if (!g5c_json_is(blk, G5C_J_OBJECT) || g5c_json_check_keys(blk, top, "nef", err, errcap) != 0) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: a `nef:` block with at least one AF is required");
        goto bad;
    }
    l = g5c_json_get(blk, "afs");
    if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) == 0)
        FAIL("invalid config: `nef.afs` must be a non-empty list");
    c->afs = g5c_xcalloc(g5c_json_len(l), sizeof *c->afs);
    for (size_t i = 0; i < g5c_json_len(l); i++) {
        if (parse_af(g5c_json_at(l, i), i, &c->afs[c->nafs], err, errcap) != 0) {
            c->nafs++;
            goto bad;
        }
        c->nafs++;
        for (size_t k = 0; k + 1 < c->nafs; k++)
            if (strcmp(c->afs[k].id, c->afs[c->nafs - 1].id) == 0)
                FAIL("invalid config: AF `%s` is listed twice", c->afs[k].id);
    }
    if (g5c_json_get(blk, "callback_uri") != NULL) {
        const char *u = g5c_json_get_str(blk, "callback_uri");
        if (!uri_ok(u))
            FAIL("invalid config: `nef.callback_uri` must be an http(s) URI");
        c->callback_uri = g5c_xstrdup(u);
    } else if (default_callback_uri != NULL) {
        c->callback_uri = g5c_xstrdup(default_callback_uri);
    }
    if (optional_uri(blk, "udr", &c->udr_uri, err, errcap) != 0 || optional_uri(blk, "udm", &c->udm_uri, err, errcap) != 0 ||
        optional_uri(blk, "amf", &c->amf_uri, err, errcap) != 0 || optional_uri(blk, "pcf", &c->pcf_uri, err, errcap) != 0 ||
        optional_uri(blk, "bsf", &c->bsf_uri, err, errcap) != 0)
        goto bad;
    o = g5c_json_get(blk, "udr");
    if (o != NULL && num_in(o, "timeout_ms", "udr", 100, 60000, &c->udr_timeout_ms, err, errcap) != 0)
        goto bad;
    o = g5c_json_get(blk, "subscriptions");
    if (o != NULL) {
        if (!g5c_json_is(o, G5C_J_OBJECT) || g5c_json_check_keys(o, k_sub, "nef.subscriptions", err, errcap) != 0) {
            if (err[0] == '\0')
                FAIL("invalid config: `nef.subscriptions` must be a mapping");
            goto bad;
        }
        if (num_in(o, "max_lifetime_s", "subscriptions", 60, 31536000, &c->sub_lifetime_s, err, errcap) != 0 ||
            num_in(o, "notify_retries", "subscriptions", 0, 10, &c->notify_retries, err, errcap) != 0 ||
            num_in(o, "max_reports", "subscriptions", 1, 1000000000, &c->max_reports, err, errcap) != 0)
            goto bad;
    }
    if (g5c_json_get(blk, "state_file") != NULL) {
        const char *sf = g5c_json_get_str(blk, "state_file");
        if (sf == NULL || sf[0] == '\0')
            FAIL("invalid config: `nef.state_file` must be a path");
        c->state_file = g5c_xstrdup(sf);
    }
    if (g5c_json_get(blk, "events_via_udm") != NULL && !g5c_json_get_bool(blk, "events_via_udm", &c->events_via_udm))
        FAIL("invalid config: `nef.events_via_udm` must be true or false");
    if (g5c_json_get(blk, "validate") != NULL && !g5c_json_get_bool(blk, "validate", &c->validate))
        FAIL("invalid config: `nef.validate` must be true or false");
    return c;
bad:
    nef_cfg_free(c);
    return NULL;
}
