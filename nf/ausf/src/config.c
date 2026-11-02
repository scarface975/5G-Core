/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* AUSF configuration: the common sections, `udm: { uri }` (omitted: the UDM is found through the NRF) and an `ausf:` block. The KAUSF values in the state file are wrapped with a
 * master key that comes from G5C_AUSF_MASTER_KEY or from `ausf.master_key_file` (64 hexadecimal characters); it is never in the configuration itself. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "priv.h"

static int num(const g5c_json *o, const char *key, double lo, double hi, double *out, char *err, size_t cap)
{
    const g5c_json *v = g5c_json_get(o, key);
    double d;
    if (v == NULL)
        return 0;
    if (!g5c_json_num(v, &d) || d < lo || d > hi) {
        snprintf(err, cap, "invalid config: `ausf.%s` must be a number in %g..%g", key, lo, hi);
        return -1;
    }
    *out = d;
    return 0;
}

static bool digits_n(const char *s, size_t lo, size_t hi)
{
    size_t n = s != NULL ? strlen(s) : 0;
    return n >= lo && n <= hi && g5c_is_digits(s);
}

/* ausfInfo of TS 29.510 6.1.6.2.? : supiRanges, routingIndicators, groupId */
static g5c_json *build_info(const g5c_json *as, char *err, size_t cap)
{
    const g5c_json *ranges = g5c_json_get(as, "supi_ranges"), *ri = g5c_json_get(as, "routing_indicators");
    const char *grp = g5c_json_get_str(as, "group_id");
    g5c_json *info;
    if (ranges == NULL && ri == NULL && grp == NULL)
        return NULL;
    info = g5c_json_new_obj();
    if (grp != NULL)
        g5c_json_set_str(info, "groupId", grp);
    if (ranges != NULL) {
        g5c_json *arr;
        if (!g5c_json_is(ranges, G5C_J_ARRAY) || g5c_json_len(ranges) == 0) {
            snprintf(err, cap, "invalid config: `ausf.supi_ranges` must be a non-empty list of { start, end }");
            g5c_json_free(info);
            return NULL;
        }
        arr = g5c_json_set(info, "supiRanges", g5c_json_new_arr());
        for (size_t i = 0; i < g5c_json_len(ranges); i++) {
            const g5c_json *r = g5c_json_at(ranges, i);
            const char *s = g5c_json_get_str(r, "start"), *e = g5c_json_get_str(r, "end");
            g5c_json *o;
            if (!digits_n(s, 5, 15) || !digits_n(e, 5, 15) || strcmp(s, e) > 0 || strlen(s) != strlen(e)) {
                snprintf(err, cap, "invalid config: `ausf.supi_ranges[%zu]` needs `start` and `end`, IMSI digit strings of one length, start <= end", i);
                g5c_json_free(info);
                return NULL;
            }
            o = g5c_json_push(arr, g5c_json_new_obj());
            g5c_json_set_str(o, "start", s);
            g5c_json_set_str(o, "end", e);
        }
    }
    if (ri != NULL) {
        g5c_json *arr;
        if (!g5c_json_is(ri, G5C_J_ARRAY) || g5c_json_len(ri) == 0) {
            snprintf(err, cap, "invalid config: `ausf.routing_indicators` must be a non-empty list of 1 to 4 digit strings");
            g5c_json_free(info);
            return NULL;
        }
        arr = g5c_json_set(info, "routingIndicators", g5c_json_new_arr());
        for (size_t i = 0; i < g5c_json_len(ri); i++) {
            const char *s = g5c_json_str(g5c_json_at(ri, i));
            if (!digits_n(s, 1, 4)) {
                snprintf(err, cap, "invalid config: `ausf.routing_indicators[%zu]` must be 1 to 4 digits", i);
                g5c_json_free(info);
                return NULL;
            }
            g5c_json_push_str(arr, s);
        }
    }
    return info;
}

ausf *ausf_from_config(const g5c_json *cfg, g5c_nf *nf, char *err, size_t errcap)
{
    static const char *const k_ausf[] = {"context_lifetime", "result_retention", "max_contexts", "max_ue_contexts", "serving_networks", "eap", "state_file", "master_key_file",
                                         "self_uri", "supi_ranges", "routing_indicators", "group_id", NULL};
    static const char *const k_eap[] = {"result_indication", NULL};
    static const char *const k_udm[] = {"uri", NULL};
    const g5c_json *as = g5c_json_get(cfg, "ausf"), *udm = g5c_json_get(cfg, "udm"), *sn, *eap;
    ausf_opts o;
    const char *udm_uri = NULL, *self = NULL;
    g5c_disc *disc = NULL;
    ausf *a;
    double d;
    err[0] = 0;
    ausf_opts_default(&o);
    if (udm != NULL) {
        if (!g5c_json_is(udm, G5C_J_OBJECT) || g5c_json_get_str(udm, "uri") == NULL) {
            snprintf(err, errcap, "invalid config: `udm.uri` must be a string");
            return NULL;
        }
        if (g5c_json_check_keys(udm, k_udm, "udm", err, errcap) != 0)
            return NULL;
        udm_uri = g5c_json_get_str(udm, "uri");
    } else if (nf->common.nrf_uri == NULL) {
        snprintf(err, errcap, "invalid config: `udm.uri` is required (or `nrf.uri`, to find the UDM through the NRF)");
        return NULL;
    }
    if (as != NULL) {
        char serr[200];
        char *secret;
        if (!g5c_json_is(as, G5C_J_OBJECT)) {
            snprintf(err, errcap, "invalid config: `ausf` must be a mapping");
            return NULL;
        }
        if (g5c_json_check_keys(as, k_ausf, "ausf", err, errcap) != 0)
            return NULL;
        d = o.ctx_lifetime_s;
        if (num(as, "context_lifetime", 1, 600, &d, err, errcap) != 0)
            return NULL;
        o.ctx_lifetime_s = d;
        d = o.result_retention_s;
        if (num(as, "result_retention", 1, 31536000, &d, err, errcap) != 0)
            return NULL;
        o.result_retention_s = d;
        d = (double)o.max_contexts;
        if (num(as, "max_contexts", 1, 100000000, &d, err, errcap) != 0)
            return NULL;
        o.max_contexts = (size_t)d;
        d = (double)o.max_ue_contexts;
        if (num(as, "max_ue_contexts", 1, 100000000, &d, err, errcap) != 0)
            return NULL;
        o.max_ue_contexts = (size_t)d;
        sn = g5c_json_get(as, "serving_networks");
        if (sn != NULL) {
            if (!g5c_json_is(sn, G5C_J_ARRAY) || g5c_json_len(sn) == 0) {
                snprintf(err, errcap, "invalid config: `ausf.serving_networks` must be a non-empty list of serving network names");
                return NULL;
            }
            o.snn_allow = g5c_xcalloc(g5c_json_len(sn), sizeof *o.snn_allow);
            for (size_t i = 0; i < g5c_json_len(sn); i++) {
                const char *s = g5c_json_str(g5c_json_at(sn, i));
                /* the same shape a request must have: 5G:mnc<3>.mcc<3>.3gppnetwork.org */
                {
                    bool ok = s != NULL && strlen(s) == 32 && strncmp(s, "5G:mnc", 6) == 0 && strncmp(s + 9, ".mcc", 4) == 0 && strcmp(s + 16, ".3gppnetwork.org") == 0;
                    for (int k = 0; ok && k < 3; k++)
                        ok = s[6 + k] >= '0' && s[6 + k] <= '9' && s[13 + k] >= '0' && s[13 + k] <= '9';
                    if (!ok) {
                        snprintf(err, errcap, "invalid config: `ausf.serving_networks[%zu]` is not a serving network name (5G:mnc<3 digits>.mcc<3 digits>.3gppnetwork.org)", i);
                        ausf_opts_free(&o);
                        return NULL;
                    }
                }
                o.snn_allow[o.n_snn_allow++] = g5c_xstrdup(s);
            }
        }
        eap = g5c_json_get(as, "eap");
        if (eap != NULL) {
            bool b;
            if (!g5c_json_is(eap, G5C_J_OBJECT) || g5c_json_check_keys(eap, k_eap, "ausf.eap", err, errcap) != 0) {
                if (err[0] == 0)
                    snprintf(err, errcap, "invalid config: `ausf.eap` must be a mapping");
                ausf_opts_free(&o);
                return NULL;
            }
            if (g5c_json_get(eap, "result_indication") != NULL) {
                if (!g5c_json_get_bool(eap, "result_indication", &b)) {
                    snprintf(err, errcap, "invalid config: `ausf.eap.result_indication` must be true or false");
                    ausf_opts_free(&o);
                    return NULL;
                }
                o.eap_result_ind = b;
            }
        }
        if (g5c_json_get(as, "state_file") != NULL) {
            if (g5c_json_get_str(as, "state_file") == NULL || g5c_json_get_str(as, "state_file")[0] == 0) {
                snprintf(err, errcap, "invalid config: `ausf.state_file` must be a path");
                ausf_opts_free(&o);
                return NULL;
            }
            o.state_file = g5c_xstrdup(g5c_json_get_str(as, "state_file"));
        }
        serr[0] = 0;
        secret = g5c_secret_from_env_or_file("G5C_AUSF_MASTER_KEY", g5c_json_get_str(as, "master_key_file"), serr, sizeof serr);
        if (secret == NULL && serr[0]) {
            snprintf(err, errcap, "%s", serr);
            ausf_opts_free(&o);
            return NULL;
        }
        if (secret != NULL) {
            long n = strlen(secret) == 64 ? g5c_hex_decode(secret, o.master_key, 32) : -1;
            OPENSSL_cleanse(secret, strlen(secret));
            free(secret);
            if (n != 32) {
                snprintf(err, errcap, "invalid config: the master key must be 64 hexadecimal characters");
                ausf_opts_free(&o);
                return NULL;
            }
            o.has_master_key = true;
        }
        if (o.state_file != NULL && !o.has_master_key) {
            snprintf(err, errcap, "invalid config: `ausf.state_file` needs a master key (G5C_AUSF_MASTER_KEY or `ausf.master_key_file`): the KAUSF values in it are encrypted");
            ausf_opts_free(&o);
            return NULL;
        }
        o.nrf_info = build_info(as, err, errcap);
        if (o.nrf_info == NULL && err[0] != 0) {
            ausf_opts_free(&o);
            return NULL;
        }
        self = g5c_json_get_str(as, "self_uri");
        if (g5c_json_get(as, "self_uri") != NULL && (self == NULL || (strncmp(self, "http://", 7) != 0 && strncmp(self, "https://", 8) != 0))) {
            snprintf(err, errcap, "invalid config: `ausf.self_uri` must be an http:// or https:// URI");
            ausf_opts_free(&o);
            return NULL;
        }
    }
    if (udm_uri == NULL)
        disc = g5c_disc_new(nf->client, nf->common.nrf_uri, "AUSF", nf->instance_id);
    a = ausf_new(nf->client, udm_uri, disc, self != NULL ? self : "", nf->instance_id, nf->metrics, &o);
    ausf_opts_free(&o);
    return a;
}
