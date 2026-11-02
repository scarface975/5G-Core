/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* BSF configuration: the `bsf:` block (optional).
 *
 *   bsf:
 *     max_bindings: 200000          most bindings held at once (more: 503)
 *     features: [ MultiUeAddr, BindingUpdate, SamePcf, ExtendedSamePcf ]    what is offered to the consumers (TS 29.521 5.8); default: all four
 *     purge_on_recovery: true       a PCF that registers with a newer recoveryTime has its older bindings removed
 *     replace_stale: true           a binding for a UE address, DNN, S-NSSAI and IP domain that another binding holds replaces it (the address is unique there)
 *     info:                         the bsfInfo of the NF profile at the NRF (what this BSF serves; default: everything)
 *       dnn_list: [ internet ]
 *       ip_domain_list: [ domain1 ]
 *       ipv4_address_ranges: [ { start: 10.45.0.0, end: 10.45.255.255 } ]
 *       ipv6_prefix_ranges: [ { start: '2001:db8::/48', end: '2001:db8:ffff::/48' } ]
 *     state_file: /var/lib/g5c/bsf.json
 *     validate: true                check bodies against the OpenAPI schemas of TS 29.521 */
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

void bsf_cfg_free(bsf_cfg *c)
{
    if (c == NULL)
        return;
    free(c->state_file);
    g5c_json_free(c->info);
    free(c);
}

static const struct {
    const char *name;
    unsigned bit;
} FEATURES[] = {{"MultiUeAddr", BSF_F_MULTI_UE_ADDR}, {"BindingUpdate", BSF_F_BINDING_UPDATE}, {"SamePcf", BSF_F_SAME_PCF}, {"ExtendedSamePcf", BSF_F_EXT_SAME_PCF}};

static bool name_ok(const char *s, size_t max)
{
    size_t n = s != NULL ? strlen(s) : 0;
    if (n == 0 || n > max)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!(isalnum((unsigned char)s[i]) || s[i] == '.' || s[i] == '-' || s[i] == '_'))
            return false;
    return true;
}

/* info: -> the bsfInfo object */
static g5c_json *parse_info(const g5c_json *o, char *err, size_t errcap)
{
    static const char *const keys[] = {"dnn_list", "ip_domain_list", "ipv4_address_ranges", "ipv6_prefix_ranges", NULL};
    g5c_json *out = g5c_json_new_obj();
    const g5c_json *l;
    if (!g5c_json_is(o, G5C_J_OBJECT) || g5c_json_check_keys(o, keys, "bsf.info", err, errcap) != 0) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: `bsf.info` must be a mapping");
        goto bad;
    }
    for (int k = 0; k < 2; k++) {
        const char *key = k == 0 ? "dnn_list" : "ip_domain_list", *to = k == 0 ? "dnnList" : "ipDomainList";
        g5c_json *arr;
        l = g5c_json_get(o, key);
        if (l == NULL)
            continue;
        if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) == 0)
            FAIL("invalid config: `bsf.info.%s` must be a non-empty list of names", key);
        arr = g5c_json_set(out, to, g5c_json_new_arr());
        for (size_t i = 0; i < g5c_json_len(l); i++) {
            const char *s = g5c_json_str(g5c_json_at(l, i));
            if (!name_ok(s, 100))
                FAIL("invalid config: `bsf.info.%s[%zu]` is not a name", key, i);
            g5c_json_push_str(arr, s);
        }
    }
    for (int k = 0; k < 2; k++) {
        const char *key = k == 0 ? "ipv4_address_ranges" : "ipv6_prefix_ranges", *to = k == 0 ? "ipv4AddressRanges" : "ipv6PrefixRanges";
        g5c_json *arr;
        l = g5c_json_get(o, key);
        if (l == NULL)
            continue;
        if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) == 0)
            FAIL("invalid config: `bsf.info.%s` must be a non-empty list of { start, end }", key);
        arr = g5c_json_set(out, to, g5c_json_new_arr());
        for (size_t i = 0; i < g5c_json_len(l); i++) {
            const g5c_json *r = g5c_json_at(l, i);
            const char *st = g5c_json_get_str(r, "start"), *en = g5c_json_get_str(r, "end");
            uint32_t a, b;
            pfx6_t pa, pb;
            bool good = g5c_json_is(r, G5C_J_OBJECT) && st != NULL && en != NULL;
            if (good && k == 0)
                good = bsf_parse_ipv4(st, &a) && bsf_parse_ipv4(en, &b) && a <= b;
            else if (good)
                good = bsf_parse_pfx6(st, &pa) && bsf_parse_pfx6(en, &pb);
            if (!good)
                FAIL("invalid config: `bsf.info.%s[%zu]` needs a valid start and end%s", key, i, k == 0 ? " (start not above end)" : " (IPv6 prefixes)");
            {
                g5c_json *e = g5c_json_push(arr, g5c_json_new_obj());
                g5c_json_set_str(e, "start", st);
                g5c_json_set_str(e, "end", en);
            }
        }
    }
    if (g5c_json_len(out) == 0)
        FAIL("invalid config: `bsf.info` is empty");
    return out;
bad:
    g5c_json_free(out);
    return NULL;
}

bsf_cfg *bsf_cfg_parse(const g5c_json *root, char *err, size_t errcap)
{
    static const char *const top[] = {"max_bindings", "features", "purge_on_recovery", "replace_stale", "info", "state_file", "validate", NULL};
    const g5c_json *blk = g5c_json_get(root, "bsf"), *l;
    bsf_cfg *c = g5c_xcalloc(1, sizeof *c);
    int64_t v;
    err[0] = '\0';
    c->max_bindings = 200000;
    c->features = BSF_F_MULTI_UE_ADDR | BSF_F_BINDING_UPDATE | BSF_F_SAME_PCF | BSF_F_EXT_SAME_PCF;
    c->purge_on_recovery = true;
    c->replace_stale = true;
    c->validate = true;
    if (blk == NULL)
        return c;
    if (!g5c_json_is(blk, G5C_J_OBJECT) || g5c_json_check_keys(blk, top, "bsf", err, errcap) != 0) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: `bsf` must be a mapping");
        goto bad;
    }
    if (g5c_json_get(blk, "max_bindings") != NULL) {
        if (!g5c_json_get_int(blk, "max_bindings", &v) || v < 1 || v > 10000000)
            FAIL("invalid config: `bsf.max_bindings` must be an integer from 1 to 10000000");
        c->max_bindings = (unsigned)v;
    }
    l = g5c_json_get(blk, "features");
    if (l != NULL) {
        c->features = 0;
        if (!g5c_json_is(l, G5C_J_ARRAY))
            FAIL("invalid config: `bsf.features` must be a list of MultiUeAddr, BindingUpdate, SamePcf, ExtendedSamePcf");
        for (size_t i = 0; i < g5c_json_len(l); i++) {
            const char *s = g5c_json_str(g5c_json_at(l, i));
            bool found = false;
            for (size_t k = 0; s != NULL && k < sizeof FEATURES / sizeof *FEATURES; k++)
                if (strcmp(s, FEATURES[k].name) == 0) {
                    c->features |= FEATURES[k].bit;
                    found = true;
                }
            if (!found)
                FAIL("invalid config: `bsf.features[%zu]` is not a feature this BSF supports (MultiUeAddr, BindingUpdate, SamePcf, ExtendedSamePcf)", i);
        }
        if ((c->features & BSF_F_EXT_SAME_PCF) && !(c->features & BSF_F_SAME_PCF))
            FAIL("invalid config: the feature ExtendedSamePcf requires SamePcf (TS 29.521 5.8)");
    }
    if (g5c_json_get(blk, "purge_on_recovery") != NULL && !g5c_json_get_bool(blk, "purge_on_recovery", &c->purge_on_recovery))
        FAIL("invalid config: `bsf.purge_on_recovery` must be true or false");
    if (g5c_json_get(blk, "replace_stale") != NULL && !g5c_json_get_bool(blk, "replace_stale", &c->replace_stale))
        FAIL("invalid config: `bsf.replace_stale` must be true or false");
    if (g5c_json_get(blk, "validate") != NULL && !g5c_json_get_bool(blk, "validate", &c->validate))
        FAIL("invalid config: `bsf.validate` must be true or false");
    if (g5c_json_get(blk, "state_file") != NULL) {
        const char *s = g5c_json_get_str(blk, "state_file");
        if (s == NULL || s[0] == '\0' || strlen(s) > 400)
            FAIL("invalid config: `bsf.state_file` must be a file name");
        c->state_file = g5c_xstrdup(s);
    }
    if (g5c_json_get(blk, "info") != NULL) {
        c->info = parse_info(g5c_json_get(blk, "info"), err, errcap);
        if (c->info == NULL)
            goto bad;
    }
    return c;
bad:
    bsf_cfg_free(c);
    return NULL;
}
