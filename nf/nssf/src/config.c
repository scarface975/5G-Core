/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NSSF configuration: the `nssf:` block.
 *
 *   nssf:
 *     slices:                      the network slices of the PLMN (at least one)
 *       - snssai: { sst: 1, sd: '000001' }
 *         nrf: http://nrf-slice1:7777           the NRF that serves the NFs of the slice (default: the NRF of the PLMN, `nrf.uri`)
 *         nrf_nfm: ...  nrf_access_token: ...   optional, as nrfNfMgtUri / nrfAccessTokenUri of the NSI information
 *         nsi_id: '1'                            optional
 *         tais: [ { mcc: '001', mnc: '01', tac: '000001' } ]          where the slice exists (none: the whole PLMN)
 *         tac_ranges: [ { mcc: '001', mnc: '01', start: '000001', end: '00000a' } ]
 *         restricted_for: [ '310-260' ]          home PLMNs of roamers for whom the slice is restricted
 *     amf_sets:                    AMF sets (TS 23.003 2.10.1) and what they support
 *       - { id: '001-01-01-001', nrf: ..., amfs: [<nf instance id>], snssais: [ { sst: 1 } ], return_candidates: false }
 *     mappings:                    serving S-NSSAI <-> home S-NSSAI of roamers (TS 23.501 5.15.6)
 *       - { home_plmn: '310-260', serving: { sst: 1 }, home: { sst: 2 } }
 *     policy: { include_subscribed: false, max_allowed: 8, max_configured: 16 }
 *     subscriptions: { max: 10000, max_lifetime_s: 86400, notify_retries: 2 }
 *     state_file: /var/lib/g5c/nssf.json
 *     validate: true               check bodies against the OpenAPI schemas of TS 29.531 */
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

static bool uri_ok(const char *s)
{
    return s != NULL && (strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0) && strlen(s) < 256 && strchr(s, ' ') == NULL;
}

static bool amf_set_id_ok(const char *s)
{
    /* <mcc>-<mnc>-<region 2 hex>-<set 3 hex, first digit 0-3> */
    size_t n = s != NULL ? strlen(s) : 0;
    size_t i = 0;
    if (n < 13)
        return false;
    for (int k = 0; k < 3; k++, i++)
        if (!isdigit((unsigned char)s[i]))
            return false;
    if (s[i++] != '-')
        return false;
    for (int k = 0; k < 2 || (k < 3 && isdigit((unsigned char)s[i])); k++, i++)
        if (!isdigit((unsigned char)s[i]))
            return false;
    if (s[i++] != '-' || !isxdigit((unsigned char)s[i]) || !isxdigit((unsigned char)s[i + 1]) || s[i + 2] != '-')
        return false;
    i += 3;
    return n - i == 3 && s[i] >= '0' && s[i] <= '3' && isxdigit((unsigned char)s[i + 1]) && isxdigit((unsigned char)s[i + 2]);
}

static bool sn_cfg(const g5c_json *j, sn_t *out)
{
    return sn_from_json(j, out);
}

void nssf_cfg_free(nssf_cfg *c)
{
    if (c == NULL)
        return;
    for (size_t i = 0; i < c->nslices; i++) {
        free(c->slices[i].nrf);
        free(c->slices[i].nrf_nfm);
        free(c->slices[i].nrf_token);
        free(c->slices[i].nsi_id);
        free(c->slices[i].tais);
        free(c->slices[i].ranges);
        free(c->slices[i].restricted_for);
    }
    free(c->slices);
    for (size_t i = 0; i < c->nsets; i++) {
        free(c->sets[i].id);
        free(c->sets[i].nrf);
        for (size_t k = 0; k < c->sets[i].namfs; k++)
            free(c->sets[i].amfs[k]);
        free(c->sets[i].amfs);
        free(c->sets[i].snssais);
    }
    free(c->sets);
    free(c->maps);
    free(c->state_file);
    free(c);
}

static int num_in(const g5c_json *o, const char *key, const char *where, int64_t lo, int64_t hi, unsigned *out, char *err, size_t errcap)
{
    int64_t v;
    if (g5c_json_get(o, key) == NULL)
        return 0;
    if (!g5c_json_get_int(o, key, &v) || v < lo || v > hi) {
        snprintf(err, errcap, "invalid config: `nssf.%s.%s` must be an integer in %lld..%lld", where, key, (long long)lo, (long long)hi);
        return -1;
    }
    *out = (unsigned)v;
    return 0;
}

static int parse_slice(const g5c_json *e, size_t i, const char *nrf_uri, slice_t *s, char *err, size_t errcap)
{
    static const char *const keys[] = {"snssai", "nrf", "nrf_nfm", "nrf_access_token", "nsi_id", "tais", "tac_ranges", "restricted_for", NULL};
    char where[48];
    const g5c_json *l;
    const char *v;
    snprintf(where, sizeof where, "nssf.slices[%zu]", i);
    if (!g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, keys, where, err, errcap) != 0) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: `%s` must be a mapping", where);
        return -1;
    }
    if (!sn_cfg(g5c_json_get(e, "snssai"), &s->sn)) {
        snprintf(err, errcap, "invalid config: `%s.snssai` needs sst (0..255) and, optionally, sd (6 hexadecimal digits)", where);
        return -1;
    }
    v = g5c_json_get_str(e, "nrf");
    if (v == NULL)
        v = nrf_uri;
    if (!uri_ok(v)) {
        snprintf(err, errcap, "invalid config: `%s.nrf` must be an http(s) URI (or the top-level `nrf.uri` must be set)", where);
        return -1;
    }
    s->nrf = g5c_xstrdup(v);
    for (int k = 0; k < 2; k++) {
        const char *key = k == 0 ? "nrf_nfm" : "nrf_access_token";
        if (g5c_json_get(e, key) != NULL) {
            v = g5c_json_get_str(e, key);
            if (!uri_ok(v)) {
                snprintf(err, errcap, "invalid config: `%s.%s` must be an http(s) URI", where, key);
                return -1;
            }
            if (k == 0)
                s->nrf_nfm = g5c_xstrdup(v);
            else
                s->nrf_token = g5c_xstrdup(v);
        }
    }
    if (g5c_json_get(e, "nsi_id") != NULL) {
        v = g5c_json_get_str(e, "nsi_id");
        if (v == NULL || v[0] == '\0' || strlen(v) > 64) {
            snprintf(err, errcap, "invalid config: `%s.nsi_id` must be a string of 1 to 64 characters", where);
            return -1;
        }
        s->nsi_id = g5c_xstrdup(v);
    }
    l = g5c_json_get(e, "tais");
    if (l != NULL) {
        if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) == 0) {
            snprintf(err, errcap, "invalid config: `%s.tais` must be a non-empty list of { mcc, mnc, tac }", where);
            return -1;
        }
        s->tais = g5c_xcalloc(g5c_json_len(l), sizeof *s->tais);
        for (size_t k = 0; k < g5c_json_len(l); k++) {
            const g5c_json *t = g5c_json_at(l, k);
            if (!plmn_from_json(t, s->tais[k].mcc, s->tais[k].mnc) || !parse_tac(g5c_json_get_str(t, "tac"), &s->tais[k].tac)) {
                snprintf(err, errcap, "invalid config: `%s.tais[%zu]` needs mcc, mnc and tac (4 or 6 hexadecimal digits)", where, k);
                return -1;
            }
            s->ntais++;
        }
    }
    l = g5c_json_get(e, "tac_ranges");
    if (l != NULL) {
        if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) == 0) {
            snprintf(err, errcap, "invalid config: `%s.tac_ranges` must be a non-empty list of { mcc, mnc, start, end }", where);
            return -1;
        }
        s->ranges = g5c_xcalloc(g5c_json_len(l), sizeof *s->ranges);
        for (size_t k = 0; k < g5c_json_len(l); k++) {
            const g5c_json *t = g5c_json_at(l, k);
            if (!plmn_from_json(t, s->ranges[k].mcc, s->ranges[k].mnc) || !parse_tac(g5c_json_get_str(t, "start"), &s->ranges[k].lo) ||
                !parse_tac(g5c_json_get_str(t, "end"), &s->ranges[k].hi) || s->ranges[k].lo > s->ranges[k].hi) {
                snprintf(err, errcap, "invalid config: `%s.tac_ranges[%zu]` needs mcc, mnc, start and end (TACs, start <= end)", where, k);
                return -1;
            }
            s->nranges++;
        }
    }
    l = g5c_json_get(e, "restricted_for");
    if (l != NULL) {
        if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) == 0) {
            snprintf(err, errcap, "invalid config: `%s.restricted_for` must be a non-empty list of \"mcc-mnc\"", where);
            return -1;
        }
        s->restricted_for = g5c_xcalloc(g5c_json_len(l), sizeof *s->restricted_for);
        for (size_t k = 0; k < g5c_json_len(l); k++) {
            char a[4], b[4];
            const char *p = g5c_json_str(g5c_json_at(l, k));
            if (!plmn_from_str(p, a, b)) {
                snprintf(err, errcap, "invalid config: `%s.restricted_for[%zu]` must look like 310-260", where, k);
                return -1;
            }
            snprintf(s->restricted_for[k], sizeof s->restricted_for[k], "%s-%s", a, b);
            s->nrestricted++;
        }
    }
    return 0;
}

nssf_cfg *nssf_cfg_parse(const g5c_json *root, const char *serving_mcc, const char *serving_mnc, const char *nrf_uri, char *err, size_t errcap)
{
    static const char *const top[] = {"slices", "amf_sets", "mappings", "policy", "subscriptions", "state_file", "validate", NULL},
                             *const k_set[] = {"id", "nrf", "amfs", "snssais", "return_candidates", NULL}, *const k_map[] = {"home_plmn", "serving", "home", NULL},
                             *const k_pol[] = {"include_subscribed", "max_allowed", "max_configured", NULL},
                             *const k_sub[] = {"max", "max_lifetime_s", "notify_retries", NULL};
    const g5c_json *blk = g5c_json_get(root, "nssf"), *l, *o;
    nssf_cfg *c = g5c_xcalloc(1, sizeof *c);
    err[0] = '\0';
    snprintf(c->mcc, sizeof c->mcc, "%s", serving_mcc);
    snprintf(c->mnc, sizeof c->mnc, "%s", serving_mnc);
    c->max_allowed = 8;
    c->max_configured = 16;
    c->sub_max = 10000;
    c->sub_lifetime_s = 86400;
    c->notify_retries = 2;
    c->validate = true;
    if (!g5c_json_is(blk, G5C_J_OBJECT) || g5c_json_check_keys(blk, top, "nssf", err, errcap) != 0) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: an `nssf:` block with at least one slice is required");
        goto bad;
    }
    l = g5c_json_get(blk, "slices");
    if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) == 0)
        FAIL("invalid config: `nssf.slices` must be a non-empty list");
    c->slices = g5c_xcalloc(g5c_json_len(l), sizeof *c->slices);
    for (size_t i = 0; i < g5c_json_len(l); i++) {
        if (parse_slice(g5c_json_at(l, i), i, nrf_uri, &c->slices[i], err, errcap) != 0) {
            c->nslices = i + 1; /* what was allocated so far is freed */
            goto bad;
        }
        c->nslices = i + 1;
        for (size_t k = 0; k < i; k++)
            if (sn_equal(&c->slices[k].sn, &c->slices[i].sn))
                FAIL("invalid config: `nssf.slices[%zu].snssai` repeats slice %zu", i, k);
    }
    l = g5c_json_get(blk, "amf_sets");
    if (l != NULL) {
        if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) == 0)
            FAIL("invalid config: `nssf.amf_sets` must be a non-empty list");
        c->sets = g5c_xcalloc(g5c_json_len(l), sizeof *c->sets);
        for (size_t i = 0; i < g5c_json_len(l); i++) {
            const g5c_json *e = g5c_json_at(l, i), *a, *sn;
            amfset_t *s = &c->sets[i];
            char where[48];
            c->nsets = i + 1;
            snprintf(where, sizeof where, "nssf.amf_sets[%zu]", i);
            if (!g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, k_set, where, err, errcap) != 0) {
                if (err[0] == '\0')
                    FAIL("invalid config: `%s` must be a mapping", where);
                goto bad;
            }
            if (!amf_set_id_ok(g5c_json_get_str(e, "id")))
                FAIL("invalid config: `%s.id` must be an AMF Set ID such as 001-01-01-001", where);
            s->id = g5c_xstrdup(g5c_json_get_str(e, "id"));
            if (g5c_json_get(e, "nrf") != NULL) {
                if (!uri_ok(g5c_json_get_str(e, "nrf")))
                    FAIL("invalid config: `%s.nrf` must be an http(s) URI", where);
                s->nrf = g5c_xstrdup(g5c_json_get_str(e, "nrf"));
            } else if (nrf_uri != NULL) {
                s->nrf = g5c_xstrdup(nrf_uri);
            }
            a = g5c_json_get(e, "amfs");
            if (a != NULL) {
                if (!g5c_json_is(a, G5C_J_ARRAY))
                    FAIL("invalid config: `%s.amfs` must be a list of NF instance ids", where);
                s->amfs = g5c_xcalloc(g5c_json_len(a) + 1, sizeof *s->amfs);
                for (size_t k = 0; k < g5c_json_len(a); k++) {
                    const char *id = g5c_json_str(g5c_json_at(a, k));
                    if (id == NULL || id[0] == '\0' || strlen(id) > 64)
                        FAIL("invalid config: `%s.amfs[%zu]` must be an NF instance id", where, k);
                    s->amfs[s->namfs++] = g5c_xstrdup(id);
                }
            }
            sn = g5c_json_get(e, "snssais");
            if (sn != NULL) {
                if (!g5c_json_is(sn, G5C_J_ARRAY))
                    FAIL("invalid config: `%s.snssais` must be a list of S-NSSAIs", where);
                s->snssais = g5c_xcalloc(g5c_json_len(sn) + 1, sizeof *s->snssais);
                for (size_t k = 0; k < g5c_json_len(sn); k++) {
                    if (!sn_cfg(g5c_json_at(sn, k), &s->snssais[s->nsnssais]))
                        FAIL("invalid config: `%s.snssais[%zu]` is not an S-NSSAI", where, k);
                    s->nsnssais++;
                }
            }
            if (g5c_json_get(e, "return_candidates") != NULL && !g5c_json_get_bool(e, "return_candidates", &s->return_candidates))
                FAIL("invalid config: `%s.return_candidates` must be true or false", where);
            for (size_t k = 0; k < i; k++)
                if (strcmp(c->sets[k].id, s->id) == 0)
                    FAIL("invalid config: `%s.id` repeats amf_sets[%zu]", where, k);
        }
    }
    l = g5c_json_get(blk, "mappings");
    if (l != NULL) {
        if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) == 0)
            FAIL("invalid config: `nssf.mappings` must be a non-empty list");
        c->maps = g5c_xcalloc(g5c_json_len(l), sizeof *c->maps);
        for (size_t i = 0; i < g5c_json_len(l); i++) {
            const g5c_json *e = g5c_json_at(l, i);
            mapping_t *m = &c->maps[i];
            char where[48];
            snprintf(where, sizeof where, "nssf.mappings[%zu]", i);
            if (!g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, k_map, where, err, errcap) != 0) {
                if (err[0] == '\0')
                    FAIL("invalid config: `%s` must be a mapping", where);
                goto bad;
            }
            if (!plmn_from_str(g5c_json_get_str(e, "home_plmn"), m->home_mcc, m->home_mnc))
                FAIL("invalid config: `%s.home_plmn` must look like 310-260", where);
            if (!sn_cfg(g5c_json_get(e, "serving"), &m->serving) || !sn_cfg(g5c_json_get(e, "home"), &m->home))
                FAIL("invalid config: `%s` needs `serving` and `home` S-NSSAIs", where);
            if (cfg_slice(c, &m->serving) == NULL)
                FAIL("invalid config: `%s.serving` is not one of the slices of this PLMN", where);
            c->nmaps = i + 1;
        }
    }
    o = g5c_json_get(blk, "policy");
    if (o != NULL) {
        if (!g5c_json_is(o, G5C_J_OBJECT) || g5c_json_check_keys(o, k_pol, "nssf.policy", err, errcap) != 0) {
            if (err[0] == '\0')
                FAIL("invalid config: `nssf.policy` must be a mapping");
            goto bad;
        }
        if (g5c_json_get(o, "include_subscribed") != NULL && !g5c_json_get_bool(o, "include_subscribed", &c->include_subscribed))
            FAIL("invalid config: `nssf.policy.include_subscribed` must be true or false");
        if (num_in(o, "max_allowed", "policy", 1, 8, &c->max_allowed, err, errcap) != 0 ||
            num_in(o, "max_configured", "policy", 1, 16, &c->max_configured, err, errcap) != 0)
            goto bad;
    }
    o = g5c_json_get(blk, "subscriptions");
    if (o != NULL) {
        if (!g5c_json_is(o, G5C_J_OBJECT) || g5c_json_check_keys(o, k_sub, "nssf.subscriptions", err, errcap) != 0) {
            if (err[0] == '\0')
                FAIL("invalid config: `nssf.subscriptions` must be a mapping");
            goto bad;
        }
        if (num_in(o, "max", "subscriptions", 1, 10000000, &c->sub_max, err, errcap) != 0 ||
            num_in(o, "max_lifetime_s", "subscriptions", 60, 31536000, &c->sub_lifetime_s, err, errcap) != 0 ||
            num_in(o, "notify_retries", "subscriptions", 0, 10, &c->notify_retries, err, errcap) != 0)
            goto bad;
    }
    if (g5c_json_get(blk, "state_file") != NULL) {
        const char *sf = g5c_json_get_str(blk, "state_file");
        if (sf == NULL || sf[0] == '\0')
            FAIL("invalid config: `nssf.state_file` must be a path");
        c->state_file = g5c_xstrdup(sf);
    }
    if (g5c_json_get(blk, "validate") != NULL && !g5c_json_get_bool(blk, "validate", &c->validate))
        FAIL("invalid config: `nssf.validate` must be true or false");
    return c;
bad:
    nssf_cfg_free(c);
    return NULL;
}

/* ---- lookups ---------------------------------------------------------------------------------------------------------- */

const slice_t *cfg_slice(const nssf_cfg *c, const sn_t *s)
{
    for (size_t i = 0; i < c->nslices; i++)
        if (sn_equal(&c->slices[i].sn, s))
            return &c->slices[i];
    return NULL;
}

bool slice_in_tai(const slice_t *s, const tai_t *t)
{
    if (s->ntais == 0 && s->nranges == 0)
        return true;
    for (size_t i = 0; i < s->ntais; i++)
        if (tai_equal(&s->tais[i], t))
            return true;
    for (size_t i = 0; i < s->nranges; i++)
        if (strcmp(s->ranges[i].mcc, t->mcc) == 0 && strcmp(s->ranges[i].mnc, t->mnc) == 0 && t->tac >= s->ranges[i].lo && t->tac <= s->ranges[i].hi)
            return true;
    return false;
}

/* the whole range lies inside what the slice is configured for (a slice without a tracking area list exists everywhere) */
bool slice_in_range(const slice_t *s, const trange_t *r)
{
    if (s->ntais == 0 && s->nranges == 0)
        return true;
    for (size_t i = 0; i < s->nranges; i++)
        if (strcmp(s->ranges[i].mcc, r->mcc) == 0 && strcmp(s->ranges[i].mnc, r->mnc) == 0 && r->lo >= s->ranges[i].lo && r->hi <= s->ranges[i].hi)
            return true;
    return false;
}
