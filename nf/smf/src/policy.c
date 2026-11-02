/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* SmPolicyDecision (TS 29.512 5.6.2.4) -> the SMF's flow model: one default QoS flow (QFI 1) plus one flow per distinct QoS data
 * referenced by PCC rules, and the SDF filters of those rules. */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/smf.h"

void smf_policy_free(smf_policy *p)
{
    for (size_t i = 0; i < p->nflows; i++)
        free(p->flows[i].qos_id);
    for (size_t i = 0; i < p->nrules; i++) {
        free(p->rules[i].id);
        for (size_t k = 0; k < p->rules[i].nfilters; k++)
            free(p->rules[i].filters[k]);
    }
    memset(p, 0, sizeof *p);
}

/* ---- IPFilterRule ------------------------------------------------------------------------------------------------------------------------- */

static bool parse_port_range(const char *t, uint16_t *lo, uint16_t *hi)
{
    char *end;
    long a, b;
    if (!isdigit((unsigned char)*t))
        return false;
    a = strtol(t, &end, 10);
    if (a > 65535)
        return false;
    if (*end == 0) {
        *lo = *hi = (uint16_t)a;
        return true;
    }
    if (*end != '-' || !isdigit((unsigned char)end[1]))
        return false;
    b = strtol(end + 1, &end, 10);
    if (*end != 0 || b > 65535 || b < a)
        return false;
    *lo = (uint16_t)a;
    *hi = (uint16_t)b;
    return true;
}

static bool parse_addr(const char *t, bool *any, uint8_t ip[4], uint8_t *plen, bool *v6)
{
    char buf[64], *slash;
    *any = false;
    *v6 = false;
    *plen = 32;
    if (strcmp(t, "any") == 0 || strcmp(t, "assigned") == 0) {
        *any = true;
        *plen = 0;
        return true;
    }
    if (strlen(t) >= sizeof buf)
        return false;
    memcpy(buf, t, strlen(t) + 1);
    slash = strchr(buf, '/');
    if (slash != NULL) {
        char *end;
        long l;
        *slash++ = 0;
        l = strtol(slash, &end, 10);
        if (*slash == 0 || *end != 0 || l < 0 || l > 128)
            return false;
        *plen = (uint8_t)l;
    }
    if (inet_pton(AF_INET, buf, ip) == 1) {
        if (*plen > 32)
            return false;
        return true;
    }
    {
        uint8_t v[16];
        if (inet_pton(AF_INET6, buf, v) == 1) {
            *v6 = true;
            return true;
        }
    }
    return false;
}

int smf_ipfilter_parse(const char *rule, smf_ipfilter *o)
{
    char buf[256], *tok[16];
    size_t n = 0, i = 0;
    char *save = NULL, *t;
    memset(o, 0, sizeof *o);
    if (rule == NULL || strlen(rule) >= sizeof buf)
        return -1;
    memcpy(buf, rule, strlen(rule) + 1);
    for (t = strtok_r(buf, " ", &save); t != NULL; t = strtok_r(NULL, " ", &save)) {
        if (n == 16)
            return -1;
        tok[n++] = t;
    }
    if (n < 6 || strcmp(tok[0], "permit") != 0 || strcmp(tok[1], "out") != 0)
        return -1;
    if (strcmp(tok[2], "ip") == 0) {
        o->any_proto = true;
    } else if (strcmp(tok[2], "tcp") == 0) {
        o->proto = 6;
    } else if (strcmp(tok[2], "udp") == 0) {
        o->proto = 17;
    } else {
        char *end;
        long v;
        if (!isdigit((unsigned char)*tok[2]))
            return -1;
        v = strtol(tok[2], &end, 10);
        if (*end != 0 || v > 255)
            return -1;
        o->proto = (uint8_t)v;
    }
    if (strcmp(tok[3], "from") != 0)
        return -1;
    if (!parse_addr(tok[4], &o->src_any, o->src, &o->src_plen, &o->src_v6))
        return -1;
    i = 5;
    if (i < n && strcmp(tok[i], "to") != 0) {
        if (!parse_port_range(tok[i], &o->sport_lo, &o->sport_hi))
            return -1;
        o->has_sport = true;
        i++;
    }
    if (i + 1 >= n || strcmp(tok[i], "to") != 0)
        return -1;
    if (!parse_addr(tok[i + 1], &o->dst_any, o->dst, &o->dst_plen, &o->dst_v6))
        return -1;
    i += 2;
    if (i < n) {
        if (!parse_port_range(tok[i], &o->dport_lo, &o->dport_hi))
            return -1;
        o->has_dport = true;
        i++;
    }
    if (i != n)
        return -1; /* options such as `frag`, `established` are not modelled */
    if ((o->has_sport || o->has_dport) && o->any_proto)
        return -1; /* ports need a protocol */
    return 0;
}

/* ---- decision ------------------------------------------------------------------------------------------------------------------------------- */

static bool get_rate(const g5c_json *o, const char *key, uint64_t *out, bool *present, char *err, size_t cap)
{
    const char *s = g5c_json_get_str(o, key);
    *present = false;
    if (g5c_json_get(o, key) == NULL)
        return true;
    if (s == NULL || !smf_parse_bitrate(s, out)) {
        snprintf(err, cap, "`%s` is not a valid BitRate", key);
        return false;
    }
    *present = true;
    return true;
}

static void get_arp(const g5c_json *q, smf_flow *f)
{
    const g5c_json *arp = g5c_json_get(q, "arp");
    int64_t pl = 0;
    f->arp_prio = 15;
    f->pre_cap = false;
    f->pre_vuln = true;
    if (arp == NULL)
        return;
    if (g5c_json_get_int(arp, "priorityLevel", &pl) && pl >= 1 && pl <= 15)
        f->arp_prio = (uint8_t)pl;
    f->pre_cap = g5c_streq(g5c_json_get_str(arp, "preemptCap"), "MAY_PREEMPT");
    f->pre_vuln = !g5c_streq(g5c_json_get_str(arp, "preemptVuln"), "NOT_PREEMPTABLE");
}

static int fill_flow(const g5c_json *q, smf_flow *f, char *err, size_t cap)
{
    int64_t v;
    bool p1, p2, p3, p4;
    if (!g5c_json_get_int(q, "5qi", &v) || v < 1 || v > 255) {
        snprintf(err, cap, "QoS data without a valid `5qi`");
        return -1;
    }
    f->qi5 = (uint8_t)v;
    get_arp(q, f);
    if (g5c_json_get_int(q, "priorityLevel", &v) && v >= 1 && v <= 127) {
        f->has_prio_level = true;
        f->prio_level = (uint8_t)v;
    }
    if (!get_rate(q, "gbrUl", &f->gbr_ul, &p1, err, cap) || !get_rate(q, "gbrDl", &f->gbr_dl, &p2, err, cap) ||
        !get_rate(q, "maxbrUl", &f->mbr_ul, &p3, err, cap) || !get_rate(q, "maxbrDl", &f->mbr_dl, &p4, err, cap))
        return -1;
    f->gbr = p1 || p2;
    if (f->gbr && !(p1 && p2)) {
        snprintf(err, cap, "a GBR flow needs both gbrUl and gbrDl");
        return -1;
    }
    if (f->gbr) { /* TS 29.512 5.6.2.7: the maximum bit rate defaults to the guaranteed one */
        if (!p3)
            f->mbr_ul = f->gbr_ul;
        if (!p4)
            f->mbr_dl = f->gbr_dl;
    }
    return 0;
}

int smf_policy_from_decision(const g5c_json *dec, smf_policy *out, char *err, size_t cap)
{
    const g5c_json *sr, *rule = NULL, *pcc, *qd;
    memset(out, 0, sizeof *out);
    sr = g5c_json_get(dec, "sessRules");
    if (!g5c_json_is(dec, G5C_J_OBJECT)) {
        snprintf(err, cap, "policy decision is not an object");
        return -1;
    }
    if (g5c_json_is(sr, G5C_J_OBJECT) && g5c_json_len(sr) > 0)
        rule = g5c_json_val_at(sr, 0); /* one session rule is applied; the PCF sends one */
    /* default flow */
    {
        smf_flow *f = &out->flows[0];
        const g5c_json *dq = g5c_json_get(rule, "authDefQos"), *amb = g5c_json_get(rule, "authSessAmbr");
        f->qfi = SMF_DEFAULT_QFI;
        if (dq != NULL) {
            if (fill_flow(dq, f, err, cap) != 0)
                goto fail;
            f->gbr = false; /* the default flow is non-GBR */
            f->gbr_ul = f->gbr_dl = f->mbr_ul = f->mbr_dl = 0;
        } else {
            f->qi5 = 9;
            f->arp_prio = 15;
            f->pre_vuln = true;
        }
        out->nflows = 1;
        if (amb != NULL) {
            const char *u = g5c_json_get_str(amb, "uplink"), *d = g5c_json_get_str(amb, "downlink");
            if (u == NULL || d == NULL || !smf_parse_bitrate(u, &out->ambr_ul) || !smf_parse_bitrate(d, &out->ambr_dl)) {
                snprintf(err, cap, "authSessAmbr is not a valid Ambr");
                goto fail;
            }
        }
    }
    pcc = g5c_json_get(dec, "pccRules");
    qd = g5c_json_get(dec, "qosDecs");
    if (pcc != NULL && !g5c_json_is(pcc, G5C_J_OBJECT)) {
        snprintf(err, cap, "pccRules is not an object");
        goto fail;
    }
    for (size_t i = 0; i < g5c_json_len(pcc); i++) {
        const g5c_json *r = g5c_json_val_at(pcc, i), *fi = g5c_json_get(r, "flowInfos"), *refq = g5c_json_get(r, "refQosData");
        smf_pcc *dst;
        int64_t prec = 0;
        uint8_t qfi = SMF_DEFAULT_QFI, flow_idx = 0;
        if (out->nrules == SMF_MAX_RULES) {
            snprintf(err, cap, "more than %d PCC rules", SMF_MAX_RULES);
            goto fail;
        }
        if (!g5c_json_is(r, G5C_J_OBJECT) || g5c_json_str(g5c_json_get(r, "pccRuleId")) == NULL || !g5c_json_is(fi, G5C_J_ARRAY) ||
            g5c_json_len(fi) == 0 || g5c_json_len(fi) > SMF_MAX_FILTERS) {
            snprintf(err, cap, "PCC rule %zu is malformed or has no usable flowInfos", i);
            goto fail;
        }
        if (!g5c_json_get_int(r, "precedence", &prec) || prec < 0 || prec > 254) { /* 255 is the default PDR */
            snprintf(err, cap, "PCC rule `%s` needs a precedence of 0..=254", g5c_json_get_str(r, "pccRuleId"));
            goto fail;
        }
        if (g5c_json_len(refq) > 0) {
            const char *qid = g5c_json_str(g5c_json_at(refq, 0));
            const g5c_json *q = qid != NULL ? g5c_json_get(qd, qid) : NULL;
            size_t k;
            if (q == NULL) {
                snprintf(err, cap, "PCC rule `%s` refers to unknown QoS data", g5c_json_get_str(r, "pccRuleId"));
                goto fail;
            }
            for (k = 1; k < out->nflows; k++)
                if (g5c_streq(out->flows[k].qos_id, qid))
                    break;
            if (k == out->nflows) {
                if (out->nflows == SMF_MAX_FLOWS) {
                    snprintf(err, cap, "more than %d QoS flows", SMF_MAX_FLOWS);
                    goto fail;
                }
                memset(&out->flows[k], 0, sizeof out->flows[k]);
                if (fill_flow(q, &out->flows[k], err, cap) != 0)
                    goto fail;
                out->flows[k].qfi = (uint8_t)(k + 1);
                out->flows[k].qos_id = g5c_xstrdup(qid);
                out->nflows++;
            }
            qfi = out->flows[k].qfi;
            flow_idx = (uint8_t)k;
        }
        dst = &out->rules[out->nrules++];
        memset(dst, 0, sizeof *dst);
        dst->id = g5c_xstrdup(g5c_json_get_str(r, "pccRuleId"));
        dst->precedence = (uint32_t)prec;
        dst->qfi = qfi;
        dst->flow = flow_idx;
        for (size_t k = 0; k < g5c_json_len(fi); k++) {
            const g5c_json *e = g5c_json_at(fi, k);
            const char *fd = g5c_json_get_str(e, "flowDescription"), *dir = g5c_json_get_str(e, "flowDirection");
            smf_ipfilter parsed;
            if (fd == NULL || smf_ipfilter_parse(fd, &parsed) != 0 || parsed.src_v6 || parsed.dst_v6) {
                snprintf(err, cap, "PCC rule `%s`: unsupported flow description `%s`", dst->id, fd != NULL ? fd : "");
                goto fail;
            }
            dst->filters[dst->nfilters] = g5c_xstrdup(fd);
            dst->dirs[dst->nfilters] = g5c_streq(dir, "DOWNLINK") ? 1 : g5c_streq(dir, "UPLINK") ? 2 : 0;
            dst->nfilters++;
        }
    }
    {   /* usage monitoring (umDecs): the volume threshold the UPF reports at; the first entry that has one */
        const g5c_json *um = g5c_json_get(dec, "umDecs");
        for (size_t i = 0; g5c_json_is(um, G5C_J_OBJECT) && i < g5c_json_len(um); i++) {
            int64_t th = 0;
            if (g5c_json_get_int(g5c_json_val_at(um, i), "volumeThreshold", &th) && th > 0) {
                out->um_volume = (uint64_t)th;
                break;
            }
        }
    }
    for (size_t i = 0; i < out->nflows; i++)
        out->flows[i].qer_id = 2 + (uint32_t)i;
    for (size_t k = 0; k < out->nrules; k++) {
        smf_pcc *r = &out->rules[k];
        bool ul = false, dl = false;
        r->qri = (uint8_t)(k + 2);
        for (size_t i = 0; i < r->nfilters; i++) {
            ul = ul || r->dirs[i] != 1;
            dl = dl || r->dirs[i] != 2;
        }
        r->pdr_ul = ul ? (uint16_t)(100 + 2 * k) : 0;
        r->pdr_dl = dl ? (uint16_t)(101 + 2 * k) : 0;
    }
    return 0;
fail:
    smf_policy_free(out);
    return -1;
}

static bool rule_same(const smf_policy *a, const smf_pcc *ra, const smf_policy *b, const smf_pcc *rb)
{
    if (strcmp(ra->id, rb->id) != 0 || ra->precedence != rb->precedence || ra->nfilters != rb->nfilters)
        return false;
    if (!g5c_streq(a->flows[ra->flow].qos_id, b->flows[rb->flow].qos_id))
        return false;
    for (size_t i = 0; i < ra->nfilters; i++)
        if (ra->dirs[i] != rb->dirs[i] || strcmp(ra->filters[i], rb->filters[i]) != 0)
            return false;
    return true;
}

void smf_policy_assign_ids(smf_policy *np, const smf_policy *old)
{
    bool used_qfi[64] = {false};
    uint32_t max_qer = 2;
    uint16_t max_pdr = 99;
    if (old == NULL) {
        for (size_t i = 0; i < np->nflows; i++) {
            np->flows[i].qfi = (uint8_t)(i + 1);
            np->flows[i].qer_id = 2 + (uint32_t)i;
        }
        for (size_t k = 0; k < np->nrules; k++)
            np->rules[k].qfi = np->flows[np->rules[k].flow].qfi;
        for (size_t k = 0; k < np->nrules; k++)
            np->rules[k].qri = (uint8_t)(k + 2);
        return;
    }
    for (size_t i = 0; i < old->nflows; i++) {
        used_qfi[old->flows[i].qfi & 63] = true;
        if (old->flows[i].qer_id > max_qer)
            max_qer = old->flows[i].qer_id;
    }
    for (size_t k = 0; k < old->nrules; k++) {
        if (old->rules[k].pdr_ul > max_pdr)
            max_pdr = old->rules[k].pdr_ul;
        if (old->rules[k].pdr_dl > max_pdr)
            max_pdr = old->rules[k].pdr_dl;
    }
    np->flows[0].qfi = SMF_DEFAULT_QFI;
    np->flows[0].qer_id = old->flows[0].qer_id;
    for (size_t i = 1; i < np->nflows; i++) {
        smf_flow *f = &np->flows[i];
        size_t j;
        for (j = 1; j < old->nflows; j++)
            if (g5c_streq(old->flows[j].qos_id, f->qos_id))
                break;
        if (j < old->nflows) {
            f->qfi = old->flows[j].qfi;
            f->qer_id = old->flows[j].qer_id;
        } else {
            f->qfi = 0;
            f->qer_id = 0;
        }
    }
    for (size_t i = 1; i < np->nflows; i++) {
        smf_flow *f = &np->flows[i];
        if (f->qfi == 0) {
            for (uint8_t q = 2; q < 64; q++) {
                bool taken = used_qfi[q];
                for (size_t j = 1; j < np->nflows && !taken; j++)
                    taken = np->flows[j].qfi == q;
                if (!taken) {
                    f->qfi = q;
                    break;
                }
            }
            f->qer_id = ++max_qer;
        }
    }
    for (size_t k = 0; k < np->nrules; k++) {
        smf_pcc *r = &np->rules[k];
        bool same = false;
        for (size_t j = 0; j < old->nrules && !same; j++)
            if (rule_same(np, r, old, &old->rules[j])) {
                r->qri = old->rules[j].qri;
                r->pdr_ul = old->rules[j].pdr_ul;
                r->pdr_dl = old->rules[j].pdr_dl;
                same = true;
            }
        if (!same) {
            bool ul = false, dl = false;
            for (size_t i = 0; i < r->nfilters; i++) {
                ul = ul || r->dirs[i] != 1;
                dl = dl || r->dirs[i] != 2;
            }
            r->pdr_ul = ul ? ++max_pdr : 0;
            r->pdr_dl = dl ? ++max_pdr : 0;
            r->qri = 0;
        }
        r->qfi = np->flows[r->flow].qfi;
    }
    for (size_t k = 0; k < np->nrules; k++) { /* fresh rules get the lowest identifier neither the old nor the new set uses */
        smf_pcc *r = &np->rules[k];
        if (r->qri != 0)
            continue;
        for (unsigned q = 2; q < 256; q++) {
            bool taken = false;
            for (size_t j = 0; j < old->nrules && !taken; j++)
                taken = old->rules[j].qri == q;
            for (size_t j = 0; j < np->nrules && !taken; j++)
                taken = np->rules[j].qri == q;
            if (!taken) {
                r->qri = (uint8_t)q;
                break;
            }
        }
    }
}
