/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Policy model and decision engine (TS 23.503, TS 29.512 clause 5.6): turn a session context into an SmPolicyDecision.
 * No I/O. JSON field names of the stored/configured documents are snake_case (session_ambr, pcc_rules, ...). */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/config.h"
#include "g5c/pcf.h"

static void E(char *err, size_t cap, const char *a, const char *b)
{
    if (err != NULL && cap > 0)
        snprintf(err, cap, "%s%s", a, b);
}

/* ---- free ------------------------------------------------------------------------------------------------------------ */

static void rule_free(pcf_rule *r)
{
    free(r->id);
    for (size_t i = 0; i < r->nflows; i++)
        free(r->flows[i]);
    free(r->flows);
    free(r->gbr_ul);
    free(r->gbr_dl);
    free(r->mbr_ul);
    free(r->mbr_dl);
}

void pcf_profile_free(pcf_profile *p)
{
    free(p->ambr.uplink);
    free(p->ambr.downlink);
    for (size_t i = 0; i < p->nrules; i++)
        rule_free(&p->rules[i]);
    free(p->rules);
    memset(p, 0, sizeof *p);
}

void pcf_policy_free(pcf_policy *p)
{
    pcf_profile_free(&p->default_profile);
    for (size_t i = 0; i < p->ndnns; i++) {
        free(p->dnn_names[i]);
        pcf_profile_free(&p->dnns[i]);
    }
    free(p->dnn_names);
    free(p->dnns);
    free(p->um_throttle.uplink);
    free(p->um_throttle.downlink);
    memset(p, 0, sizeof *p);
}

/* ---- parsing ------------------------------------------------------------------------------------------------------------ */

static bool is_null(const g5c_json *j)
{
    return j == NULL || g5c_json_is(j, G5C_J_NULL);
}

static int check_keys(const g5c_json *o, const char *const *allowed, const char *where, char *err, size_t cap)
{
    return g5c_json_check_keys(o, allowed, where, err, cap);
}

/* optional unsigned integer in [0, max]; absent/null leaves *out and returns 0, *present says whether it was set */
static int opt_uint(const g5c_json *o, const char *key, int64_t max, int64_t *out, bool *present, char *err, size_t cap)
{
    const g5c_json *v = g5c_json_get(o, key);
    int64_t n;
    if (present)
        *present = false;
    if (is_null(v))
        return 0;
    if (!g5c_json_int(v, &n) || n < 0 || n > max) {
        E(err, cap, "invalid value for field ", key);
        return -1;
    }
    *out = n;
    if (present)
        *present = true;
    return 0;
}

static int opt_str(const g5c_json *o, const char *key, char **out, char *err, size_t cap)
{
    const g5c_json *v = g5c_json_get(o, key);
    if (is_null(v))
        return 0;
    if (g5c_json_str(v) == NULL) {
        E(err, cap, "invalid type for field ", key);
        return -1;
    }
    *out = g5c_xstrdup(g5c_json_str(v));
    return 0;
}

int pcf_ambr_parse(const g5c_json *j, pcf_ambr *a, char *err, size_t cap)
{
    static const char *const keys[] = {"uplink", "downlink", NULL};
    const char *u = g5c_json_get_str(j, "uplink"), *d = g5c_json_get_str(j, "downlink");
    if (!g5c_json_is(j, G5C_J_OBJECT) || check_keys(j, keys, "Ambr", err, cap) != 0) {
        if (err && cap && err[0] == 0)
            E(err, cap, "invalid type: expected an Ambr object", "");
        return -1;
    }
    if (u == NULL || d == NULL) {
        E(err, cap, "missing field ", u == NULL ? "`uplink`" : "`downlink`");
        return -1;
    }
    a->uplink = g5c_xstrdup(u);
    a->downlink = g5c_xstrdup(d);
    return 0;
}

static int parse_qos(const g5c_json *j, pcf_qos *q, char *err, size_t cap)
{
    static const char *const keys[] = {"qi5", "arp_priority", "preempt_cap", "preempt_vuln", "priority_level", NULL};
    int64_t v = 0;
    bool present;
    const g5c_json *b;
    if (!g5c_json_is(j, G5C_J_OBJECT) || check_keys(j, keys, "DefaultQos", err, cap) != 0) {
        if (err && cap && err[0] == 0)
            E(err, cap, "invalid type: expected a DefaultQos object", "");
        return -1;
    }
    memset(q, 0, sizeof *q);
    q->arp_priority = 8;
    if (g5c_json_get(j, "qi5") == NULL) {
        E(err, cap, "missing field `qi5`", "");
        return -1;
    }
    if (opt_uint(j, "qi5", 255, &v, &present, err, cap) != 0 || !present) {
        if (err && cap && err[0] == 0)
            E(err, cap, "invalid value for field qi5", "");
        return -1;
    }
    q->qi5 = (uint8_t)v;
    if (opt_uint(j, "arp_priority", 255, &v, &present, err, cap) != 0)
        return -1;
    if (present)
        q->arp_priority = (uint8_t)v;
    b = g5c_json_get(j, "preempt_cap");
    if (!is_null(b) && !g5c_json_bool(b, &q->preempt_cap)) {
        E(err, cap, "invalid type for field ", "preempt_cap");
        return -1;
    }
    b = g5c_json_get(j, "preempt_vuln");
    if (!is_null(b) && !g5c_json_bool(b, &q->preempt_vuln)) {
        E(err, cap, "invalid type for field ", "preempt_vuln");
        return -1;
    }
    if (opt_uint(j, "priority_level", 255, &v, &present, err, cap) != 0)
        return -1;
    if (present) {
        q->has_priority_level = true;
        q->priority_level = (uint8_t)v;
    }
    return 0;
}

static int parse_rule(const g5c_json *j, pcf_rule *r, char *err, size_t cap)
{
    static const char *const keys[] = {"id", "flows", "qi5", "gbr_ul", "gbr_dl", "mbr_ul", "mbr_dl", "precedence", NULL};
    const g5c_json *flows = g5c_json_get(j, "flows");
    int64_t v = 0;
    bool present;
    memset(r, 0, sizeof *r);
    r->precedence = 100;
    if (!g5c_json_is(j, G5C_J_OBJECT) || check_keys(j, keys, "PccRuleCfg", err, cap) != 0) {
        if (err && cap && err[0] == 0)
            E(err, cap, "invalid type: expected a rule object", "");
        return -1;
    }
    if (g5c_json_get_str(j, "id") == NULL || !g5c_json_is(flows, G5C_J_ARRAY) || g5c_json_get(j, "qi5") == NULL) {
        E(err, cap, "missing or invalid field in pcc rule (id, flows, qi5)", "");
        return -1;
    }
    r->id = g5c_xstrdup(g5c_json_get_str(j, "id"));
    r->nflows = g5c_json_len(flows);
    r->flows = g5c_xcalloc(r->nflows ? r->nflows : 1, sizeof *r->flows);
    for (size_t i = 0; i < r->nflows; i++) {
        const char *f = g5c_json_str(g5c_json_at(flows, i));
        if (f == NULL) {
            E(err, cap, "flows must be strings", "");
            rule_free(r);
            return -1;
        }
        r->flows[i] = g5c_xstrdup(f);
    }
    if (opt_uint(j, "qi5", 255, &v, &present, err, cap) != 0 || !present) {
        if (err && cap && err[0] == 0)
            E(err, cap, "invalid value for field qi5", "");
        rule_free(r);
        return -1;
    }
    r->qi5 = (uint8_t)v;
    if (opt_str(j, "gbr_ul", &r->gbr_ul, err, cap) != 0 || opt_str(j, "gbr_dl", &r->gbr_dl, err, cap) != 0 ||
        opt_str(j, "mbr_ul", &r->mbr_ul, err, cap) != 0 || opt_str(j, "mbr_dl", &r->mbr_dl, err, cap) != 0 ||
        opt_uint(j, "precedence", 4294967295LL, &v, &present, err, cap) != 0) {
        rule_free(r);
        return -1;
    }
    if (present)
        r->precedence = (uint32_t)v;
    return 0;
}

static int parse_profile(const g5c_json *j, pcf_profile *p, char *err, size_t cap)
{
    static const char *const keys[] = {"session_ambr", "default_qos", "pcc_rules", NULL};
    const g5c_json *a, *q, *rl;
    memset(p, 0, sizeof *p);
    if (!g5c_json_is(j, G5C_J_OBJECT) || check_keys(j, keys, "Profile", err, cap) != 0) {
        if (err && cap && err[0] == 0)
            E(err, cap, "invalid type: expected a profile object", "");
        return -1;
    }
    a = g5c_json_get(j, "session_ambr");
    q = g5c_json_get(j, "default_qos");
    rl = g5c_json_get(j, "pcc_rules");
    if (!is_null(a)) {
        if (pcf_ambr_parse(a, &p->ambr, err, cap) != 0)
            goto bad;
        p->has_ambr = true;
    }
    if (!is_null(q)) {
        if (parse_qos(q, &p->qos, err, cap) != 0)
            goto bad;
        p->has_qos = true;
    }
    if (!is_null(rl)) {
        if (!g5c_json_is(rl, G5C_J_ARRAY)) {
            E(err, cap, "invalid type: pcc_rules must be a list", "");
            goto bad;
        }
        p->has_rules = true;
        p->nrules = g5c_json_len(rl);
        p->rules = g5c_xcalloc(p->nrules ? p->nrules : 1, sizeof *p->rules);
        for (size_t i = 0; i < p->nrules; i++)
            if (parse_rule(g5c_json_at(rl, i), &p->rules[i], err, cap) != 0) {
                p->nrules = i; /* only the rules parsed so far own memory */
                goto bad;
            }
    }
    return 0;
bad:
    pcf_profile_free(p);
    return -1;
}

static int cmp_names(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int pcf_policy_parse(const g5c_json *j, bool is_config, pcf_policy *out, char *err, size_t cap)
{
    static const char *const k_cfg[] = {"default", "dnns", "rfsp", "usage_monitoring", NULL};
    static const char *const k_sub[] = {"default", "dnns", NULL};
    const g5c_json *d, *dn;
    size_t n = 0;
    char **names;
    memset(out, 0, sizeof *out);
    if (is_null(j)) {
        out->has_default = is_config;
        return 0; /* an absent policy section is the empty policy */
    }
    if (!g5c_json_is(j, G5C_J_OBJECT) || check_keys(j, is_config ? k_cfg : k_sub, is_config ? "policy" : "SubscriberPolicy", err, cap) != 0) {
        if (err && cap && err[0] == 0)
            E(err, cap, "invalid type: expected a mapping", "");
        return -1;
    }
    d = g5c_json_get(j, "default");
    dn = g5c_json_get(j, "dnns");
    out->has_default = is_config;
    if (!is_null(d)) {
        if (parse_profile(d, &out->default_profile, err, cap) != 0)
            return -1;
        out->has_default = true;
    }
    if (!is_null(dn)) {
        if (!g5c_json_is(dn, G5C_J_OBJECT)) {
            E(err, cap, "invalid type: dnns must be a mapping", "");
            goto bad;
        }
        n = g5c_json_len(dn);
        names = g5c_xcalloc(n ? n : 1, sizeof *names);
        for (size_t i = 0; i < n; i++)
            names[i] = g5c_xstrdup(g5c_json_key_at(dn, i));
        qsort(names, n, sizeof *names, cmp_names); /* sorted, like the previous BTreeMap */
        out->dnn_names = names;
        out->dnns = g5c_xcalloc(n ? n : 1, sizeof *out->dnns);
        for (size_t i = 0; i < n; i++) {
            if (parse_profile(g5c_json_get(dn, names[i]), &out->dnns[i], err, cap) != 0) {
                out->ndnns = i;
                /* free names beyond ndnns that have no profile yet */
                for (size_t k = i; k < n; k++)
                    free(names[k]);
                n = i;
                goto bad;
            }
            out->ndnns = i + 1;
        }
    }
    if (is_config) {
        int64_t v = 0;
        bool present;
        if (opt_uint(j, "rfsp", 65535, &v, &present, err, cap) != 0)
            goto bad;
        if (present) {
            out->has_rfsp = true;
            out->rfsp = (uint16_t)v;
        }
        if (!is_null(g5c_json_get(j, "usage_monitoring"))) { /* usage monitoring (TS 29.512 UsageMonitoringData): `usage_monitoring: { volume_threshold: <bytes>, throttle: { uplink, downlink } }` */
            static const char *const k_um[] = {"volume_threshold", "throttle", NULL};
            const g5c_json *um = g5c_json_get(j, "usage_monitoring");
            int64_t th = 0;
            bool pres = false;
            if (!g5c_json_is(um, G5C_J_OBJECT) || check_keys(um, k_um, "policy.usage_monitoring", err, cap) != 0) {
                if (err && cap && err[0] == 0)
                    snprintf(err, cap, "invalid type: policy.usage_monitoring must be a mapping");
                goto bad;
            }
            if (opt_uint(um, "volume_threshold", 1000000000000000LL, &th, &pres, err, cap) != 0)
                goto bad;
            if (!pres || th < 1000) {
                snprintf(err, cap, "invalid value: policy.usage_monitoring.volume_threshold is required and at least 1000 octets");
                goto bad;
            }
            if (pcf_ambr_parse(g5c_json_get(um, "throttle"), &out->um_throttle, err, cap) != 0)
                goto bad;
            out->um_volume = (uint64_t)th;
        }
    }
    return 0;
bad:
    pcf_policy_free(out);
    return -1;
}

/* ---- serialisation ------------------------------------------------------------------------------------------------------------ */

static g5c_json *opt_str_json(const char *s)
{
    return s ? g5c_json_new_str(s) : g5c_json_new_null();
}

static g5c_json *profile_to_json(const pcf_profile *p)
{
    g5c_json *o = g5c_json_new_obj();
    if (p->has_ambr) {
        g5c_json *a = g5c_json_set(o, "session_ambr", g5c_json_new_obj());
        g5c_json_set_str(a, "uplink", p->ambr.uplink);
        g5c_json_set_str(a, "downlink", p->ambr.downlink);
    }
    if (p->has_qos) {
        g5c_json *q = g5c_json_set(o, "default_qos", g5c_json_new_obj());
        g5c_json_set_int(q, "qi5", p->qos.qi5);
        g5c_json_set_int(q, "arp_priority", p->qos.arp_priority);
        g5c_json_set_bool(q, "preempt_cap", p->qos.preempt_cap);
        g5c_json_set_bool(q, "preempt_vuln", p->qos.preempt_vuln);
        g5c_json_set(q, "priority_level", p->qos.has_priority_level ? g5c_json_new_int(p->qos.priority_level) : g5c_json_new_null());
    }
    if (p->has_rules) {
        g5c_json *arr = g5c_json_set(o, "pcc_rules", g5c_json_new_arr());
        for (size_t i = 0; i < p->nrules; i++) {
            const pcf_rule *r = &p->rules[i];
            g5c_json *e = g5c_json_push(arr, g5c_json_new_obj()), *fl;
            g5c_json_set_str(e, "id", r->id);
            fl = g5c_json_set(e, "flows", g5c_json_new_arr());
            for (size_t k = 0; k < r->nflows; k++)
                g5c_json_push_str(fl, r->flows[k]);
            g5c_json_set_int(e, "qi5", r->qi5);
            g5c_json_set(e, "gbr_ul", opt_str_json(r->gbr_ul));
            g5c_json_set(e, "gbr_dl", opt_str_json(r->gbr_dl));
            g5c_json_set(e, "mbr_ul", opt_str_json(r->mbr_ul));
            g5c_json_set(e, "mbr_dl", opt_str_json(r->mbr_dl));
            g5c_json_set_int(e, "precedence", r->precedence);
        }
    }
    return o;
}

g5c_json *pcf_policy_to_json(const pcf_policy *p)
{
    g5c_json *o = g5c_json_new_obj();
    if (p->has_default)
        g5c_json_set(o, "default", profile_to_json(&p->default_profile));
    if (p->ndnns > 0) {
        g5c_json *d = g5c_json_set(o, "dnns", g5c_json_new_obj());
        for (size_t i = 0; i < p->ndnns; i++)
            g5c_json_set(d, p->dnn_names[i], profile_to_json(&p->dnns[i]));
    }
    return o;
}

/* ---- validation ------------------------------------------------------------------------------------------------------------------ */

bool pcf_valid_bitrate(const char *s)
{
    const char *sp = strchr(s, ' '), *u;
    size_t n, dots = 0;
    if (sp == NULL)
        return false;
    n = (size_t)(sp - s);
    if (n == 0 || s[0] == '.' || s[n - 1] == '.')
        return false;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '.')
            dots++;
        else if (s[i] < '0' || s[i] > '9')
            return false;
    }
    if (dots > 1)
        return false;
    u = sp + 1;
    return strcmp(u, "bps") == 0 || strcmp(u, "Kbps") == 0 || strcmp(u, "Mbps") == 0 || strcmp(u, "Gbps") == 0 ||
           strcmp(u, "Tbps") == 0;
}

bool pcf_is_gbr_5qi(uint8_t q)
{
    return (q >= 1 && q <= 4) || q == 65 || q == 66 || q == 67 || (q >= 71 && q <= 76);
}

static int verr(char *field, size_t fcap, char *reason, size_t rcap, const char *f, const char *r)
{
    snprintf(field, fcap, "%s", f);
    snprintf(reason, rcap, "%s", r);
    return -1;
}

int pcf_profile_validate(const pcf_profile *p, const char *path, char *field, size_t fcap, char *reason, size_t rcap)
{
    char f[300];
    if (p->has_ambr) {
        if (!pcf_valid_bitrate(p->ambr.uplink)) {
            snprintf(f, sizeof f, "%s.sessionAmbr.uplink", path);
            return verr(field, fcap, reason, rcap, f, "must look like '100 Mbps'");
        }
        if (!pcf_valid_bitrate(p->ambr.downlink)) {
            snprintf(f, sizeof f, "%s.sessionAmbr.downlink", path);
            return verr(field, fcap, reason, rcap, f, "must look like '100 Mbps'");
        }
    }
    if (p->has_qos) {
        const pcf_qos *q = &p->qos;
        if (pcf_is_gbr_5qi(q->qi5)) {
            snprintf(f, sizeof f, "%s.defaultQos.qi5", path);
            return verr(field, fcap, reason, rcap, f, "the default flow must use a non-GBR 5QI");
        }
        if (q->arp_priority < 1 || q->arp_priority > 15) {
            snprintf(f, sizeof f, "%s.defaultQos.arpPriority", path);
            return verr(field, fcap, reason, rcap, f, "must be 1..=15");
        }
        if (q->has_priority_level && (q->priority_level < 1 || q->priority_level > 127)) {
            snprintf(f, sizeof f, "%s.defaultQos.priorityLevel", path);
            return verr(field, fcap, reason, rcap, f, "must be 1..=127");
        }
    }
    if (p->has_rules) {
        for (size_t i = 0; i < p->nrules; i++) {
            const pcf_rule *r = &p->rules[i];
            char rp[256];
            const char *vals[4] = {r->gbr_ul, r->gbr_dl, r->mbr_ul, r->mbr_dl};
            static const char *const names[4] = {"gbrUl", "gbrDl", "mbrUl", "mbrDl"};
            bool gbr;
            snprintf(rp, sizeof rp, "%s.pccRules[%zu]", path, i);
            if (r->id[0] == 0) {
                snprintf(f, sizeof f, "%s.id", rp);
                return verr(field, fcap, reason, rcap, f, "letters, digits, '-' and '_' only");
            }
            for (const char *c = r->id; *c; c++)
                if (!isalnum((unsigned char)*c) && *c != '-' && *c != '_') {
                    snprintf(f, sizeof f, "%s.id", rp);
                    return verr(field, fcap, reason, rcap, f, "letters, digits, '-' and '_' only");
                }
            for (size_t k = 0; k < i; k++)
                if (strcmp(p->rules[k].id, r->id) == 0) {
                    snprintf(f, sizeof f, "%s.id", rp);
                    return verr(field, fcap, reason, rcap, f, "duplicate rule id");
                }
            if (r->nflows == 0) {
                snprintf(f, sizeof f, "%s.flows", rp);
                return verr(field, fcap, reason, rcap, f, "need at least one 'permit ...' IPFilterRule");
            }
            for (size_t k = 0; k < r->nflows; k++)
                if (strncmp(r->flows[k], "permit ", 7) != 0) {
                    snprintf(f, sizeof f, "%s.flows", rp);
                    return verr(field, fcap, reason, rcap, f, "need at least one 'permit ...' IPFilterRule");
                }
            for (size_t k = 0; k < 4; k++)
                if (vals[k] != NULL && !pcf_valid_bitrate(vals[k])) {
                    snprintf(f, sizeof f, "%s.%s", rp, names[k]);
                    return verr(field, fcap, reason, rcap, f, "must look like '100 Mbps'");
                }
            gbr = r->gbr_ul != NULL || r->gbr_dl != NULL;
            if (gbr && !pcf_is_gbr_5qi(r->qi5)) {
                snprintf(f, sizeof f, "%s.qi5", rp);
                return verr(field, fcap, reason, rcap, f, "guaranteed bit rate needs a GBR 5QI");
            }
            if (pcf_is_gbr_5qi(r->qi5) && !gbr) {
                snprintf(f, sizeof f, "%s.gbrUl", rp);
                return verr(field, fcap, reason, rcap, f, "a GBR 5QI needs gbrUl/gbrDl");
            }
        }
    }
    return 0;
}

int pcf_policy_validate(const pcf_policy *p, bool is_config, char *field, size_t fcap, char *reason, size_t rcap)
{
    if (p->has_default &&
        pcf_profile_validate(&p->default_profile, is_config ? "policy.default" : "default", field, fcap, reason, rcap) != 0)
        return -1;
    for (size_t i = 0; i < p->ndnns; i++) {
        char path[300];
        if (p->dnn_names[i][0] == 0)
            return verr(field, fcap, reason, rcap, "dnns", "empty DNN name");
        snprintf(path, sizeof path, is_config ? "policy.dnns.%s" : "dnns.%s", p->dnn_names[i]);
        if (pcf_profile_validate(&p->dnns[i], path, field, fcap, reason, rcap) != 0)
            return -1;
    }
    return 0;
}

/* ---- resolution ------------------------------------------------------------------------------------------------------------------ */

static const pcf_profile *find_dnn(const pcf_policy *p, const char *dnn)
{
    if (p == NULL)
        return NULL;
    for (size_t i = 0; i < p->ndnns; i++)
        if (strcmp(p->dnn_names[i], dnn) == 0)
            return &p->dnns[i];
    return NULL;
}

void pcf_session_info_free(pcf_session_info *s)
{
    free(s->dnn);
    free(s->subs_ambr.uplink);
    free(s->subs_ambr.downlink);
    g5c_json_free(s->subs_def_qos);
    memset(s, 0, sizeof *s);
}

pcf_session_info pcf_session_info_dup(const pcf_session_info *s)
{
    pcf_session_info d;
    memset(&d, 0, sizeof d);
    d.dnn = g5c_xstrdup(s->dnn);
    if (s->has_ambr) {
        d.has_ambr = true;
        d.subs_ambr.uplink = g5c_xstrdup(s->subs_ambr.uplink);
        d.subs_ambr.downlink = g5c_xstrdup(s->subs_ambr.downlink);
    }
    d.subs_def_qos = g5c_json_dup(s->subs_def_qos);
    return d;
}

static uint8_t u8_or(const g5c_json *v, uint8_t dflt)
{
    int64_t n;
    return (g5c_json_int(v, &n) && n >= 0 && n <= 255) ? (uint8_t)n : dflt;
}

static pcf_rule rule_dup(const pcf_rule *r)
{
    pcf_rule d = *r;
    d.id = g5c_xstrdup(r->id);
    d.flows = g5c_xcalloc(r->nflows ? r->nflows : 1, sizeof *d.flows);
    for (size_t i = 0; i < r->nflows; i++)
        d.flows[i] = g5c_xstrdup(r->flows[i]);
    d.gbr_ul = r->gbr_ul ? g5c_xstrdup(r->gbr_ul) : NULL;
    d.gbr_dl = r->gbr_dl ? g5c_xstrdup(r->gbr_dl) : NULL;
    d.mbr_ul = r->mbr_ul ? g5c_xstrdup(r->mbr_ul) : NULL;
    d.mbr_dl = r->mbr_dl ? g5c_xstrdup(r->mbr_dl) : NULL;
    return d;
}

pcf_resolved pcf_resolve(const pcf_session_info *s, const pcf_policy *cfg, const pcf_policy *sub)
{
    const pcf_profile *layers[4];
    size_t nl = 0;
    pcf_resolved r;
    bool got;
    memset(&r, 0, sizeof r);
    if (sub != NULL && find_dnn(sub, s->dnn))
        layers[nl++] = find_dnn(sub, s->dnn);
    if (sub != NULL && sub->has_default)
        layers[nl++] = &sub->default_profile;
    if (find_dnn(cfg, s->dnn))
        layers[nl++] = find_dnn(cfg, s->dnn);
    layers[nl++] = &cfg->default_profile;

    got = false;
    for (size_t i = 0; i < nl && !got; i++)
        if (layers[i]->has_ambr) {
            r.ambr.uplink = g5c_xstrdup(layers[i]->ambr.uplink);
            r.ambr.downlink = g5c_xstrdup(layers[i]->ambr.downlink);
            got = true;
        }
    if (!got && s->has_ambr) {
        r.ambr.uplink = g5c_xstrdup(s->subs_ambr.uplink);
        r.ambr.downlink = g5c_xstrdup(s->subs_ambr.downlink);
        got = true;
    }
    if (!got) {
        r.ambr.uplink = g5c_xstrdup("1 Gbps");
        r.ambr.downlink = g5c_xstrdup("1 Gbps");
    }

    got = false;
    for (size_t i = 0; i < nl && !got; i++)
        if (layers[i]->has_qos) {
            r.qos = layers[i]->qos;
            got = true;
        }
    if (!got && s->subs_def_qos != NULL) {
        const g5c_json *q = s->subs_def_qos, *arp = g5c_json_get(q, "arp"), *pl = g5c_json_get(q, "priorityLevel");
        int64_t n;
        r.qos.qi5 = u8_or(g5c_json_get(q, "5qi"), 9);
        r.qos.arp_priority = u8_or(g5c_json_get(arp, "priorityLevel"), 8);
        r.qos.preempt_cap = g5c_streq(g5c_json_get_str(arp, "preemptCap"), "MAY_PREEMPT");
        r.qos.preempt_vuln = g5c_streq(g5c_json_get_str(arp, "preemptVuln"), "PREEMPTABLE");
        if (g5c_json_int(pl, &n) && n >= 0 && n <= 255) {
            r.qos.has_priority_level = true;
            r.qos.priority_level = (uint8_t)n;
        }
        got = true;
    }
    if (!got) {
        r.qos.qi5 = 9;
        r.qos.arp_priority = 8;
    }

    for (size_t i = 0; i < nl; i++)
        if (layers[i]->has_rules) {
            r.nrules = layers[i]->nrules;
            r.rules = g5c_xcalloc(r.nrules ? r.nrules : 1, sizeof *r.rules);
            for (size_t k = 0; k < r.nrules; k++)
                r.rules[k] = rule_dup(&layers[i]->rules[k]);
            break;
        }
    return r;
}

void pcf_resolved_free(pcf_resolved *r)
{
    free(r->ambr.uplink);
    free(r->ambr.downlink);
    for (size_t i = 0; i < r->nrules; i++)
        rule_free(&r->rules[i]);
    free(r->rules);
    memset(r, 0, sizeof *r);
}

static g5c_json *arp_json(unsigned priority, bool cap, bool vuln)
{
    g5c_json *a = g5c_json_new_obj();
    g5c_json_set_int(a, "priorityLevel", priority);
    g5c_json_set_str(a, "preemptCap", cap ? "MAY_PREEMPT" : "NOT_PREEMPT");
    g5c_json_set_str(a, "preemptVuln", vuln ? "PREEMPTABLE" : "NOT_PREEMPTABLE");
    return a;
}

g5c_json *pcf_decision(const pcf_resolved *r)
{
    g5c_json *d = g5c_json_new_obj(), *sr = g5c_json_set(d, "sessRules", g5c_json_new_obj()),
             *rule = g5c_json_set(sr, "SessRule-1", g5c_json_new_obj()), *amb, *dq;
    g5c_json_set_str(rule, "sessRuleId", "SessRule-1");
    amb = g5c_json_set(rule, "authSessAmbr", g5c_json_new_obj());
    g5c_json_set_str(amb, "uplink", r->ambr.uplink);
    g5c_json_set_str(amb, "downlink", r->ambr.downlink);
    dq = g5c_json_set(rule, "authDefQos", g5c_json_new_obj());
    g5c_json_set_int(dq, "5qi", r->qos.qi5);
    g5c_json_set(dq, "arp", arp_json(r->qos.arp_priority, r->qos.preempt_cap, r->qos.preempt_vuln));
    if (r->qos.has_priority_level)
        g5c_json_set_int(dq, "priorityLevel", r->qos.priority_level);
    /* NB: optional arrays with minItems 1 in the OpenAPI schemas (policyCtrlReqTriggers, ...) must be omitted rather
     * than sent empty; Open5GS rejects `[]`. */
    if (r->nrules > 0) {
        g5c_json *pcc = g5c_json_set(d, "pccRules", g5c_json_new_obj()), *qos = g5c_json_set(d, "qosDecs", g5c_json_new_obj());
        for (size_t i = 0; i < r->nrules; i++) {
            const pcf_rule *rl = &r->rules[i];
            char *pid = g5c_xasprintf("PccRule-%s", rl->id), *qid = g5c_xasprintf("QosData-%s", rl->id);
            g5c_json *p = g5c_json_set(pcc, pid, g5c_json_new_obj()), *fi, *q;
            unsigned arp_prio = rl->precedence < 1 ? 1 : rl->precedence > 15 ? 15 : rl->precedence;
            g5c_json_set_str(p, "pccRuleId", pid);
            fi = g5c_json_set(p, "flowInfos", g5c_json_new_arr());
            for (size_t k = 0; k < rl->nflows; k++) {
                g5c_json *e = g5c_json_push(fi, g5c_json_new_obj());
                g5c_json_set_str(e, "flowDescription", rl->flows[k]);
                g5c_json_set_str(e, "flowDirection", "BIDIRECTIONAL");
            }
            g5c_json_set_int(p, "precedence", rl->precedence);
            g5c_json_push_str(g5c_json_set(p, "refQosData", g5c_json_new_arr()), qid);
            q = g5c_json_set(qos, qid, g5c_json_new_obj());
            g5c_json_set_str(q, "qosId", qid);
            g5c_json_set_int(q, "5qi", rl->qi5);
            g5c_json_set(q, "arp", arp_json(arp_prio, false, true));
            if (rl->gbr_ul)
                g5c_json_set_str(q, "gbrUl", rl->gbr_ul);
            if (rl->gbr_dl)
                g5c_json_set_str(q, "gbrDl", rl->gbr_dl);
            if (rl->mbr_ul)
                g5c_json_set_str(q, "maxbrUl", rl->mbr_ul);
            if (rl->mbr_dl)
                g5c_json_set_str(q, "maxbrDl", rl->mbr_dl);
            free(pid);
            free(qid);
        }
    }
    return d;
}

pcf_rule pcf_rule_copy(const pcf_rule *r)
{
    return rule_dup(r);
}

void pcf_rule_release(pcf_rule *r)
{
    rule_free(r);
}
