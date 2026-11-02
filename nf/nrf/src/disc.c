/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nnrf_NFDiscovery (TS 29.510 clause 5.3, query parameters of table 6.2.3.2.3.1-1). */
#include <regex.h>
#include <stdio.h>

#include "priv.h"

/* ---- query string ---- */

char *nrf_pct_decode(const char *s, size_t n)
{
    char *out = g5c_xmalloc(n + 1), *w = out;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '%' && i + 2 < n) {
            int hi, lo;
            char a = s[i + 1], b = s[i + 2];
            hi = (a >= '0' && a <= '9') ? a - '0' : (a >= 'a' && a <= 'f') ? a - 'a' + 10 : (a >= 'A' && a <= 'F') ? a - 'A' + 10 : -1;
            lo = (b >= '0' && b <= '9') ? b - '0' : (b >= 'a' && b <= 'f') ? b - 'a' + 10 : (b >= 'A' && b <= 'F') ? b - 'A' + 10 : -1;
            if (hi >= 0 && lo >= 0) {
                *w++ = (char)(hi * 16 + lo);
                i += 2;
                continue;
            }
        }
        *w++ = s[i] == '+' ? ' ' : s[i];
    }
    *w = 0;
    return out;
}

char **nrf_form_all(const char *q, const char *name, size_t *n)
{
    char **v = NULL;
    size_t cnt = 0, nl = strlen(name);
    while (q != NULL && *q != 0) {
        const char *amp = strchr(q, '&'), *eq;
        size_t len = amp != NULL ? (size_t)(amp - q) : strlen(q);
        eq = memchr(q, '=', len);
        if (eq != NULL && (size_t)(eq - q) == nl && memcmp(q, name, nl) == 0) {
            v = g5c_xrealloc(v, (cnt + 1) * sizeof *v);
            v[cnt++] = nrf_pct_decode(eq + 1, len - nl - 1);
        }
        q = amp != NULL ? amp + 1 : q + len;
    }
    *n = cnt;
    return v;
}

char **nrf_query_all(const g5c_req *req, const char *name, size_t *n)
{
    return nrf_form_all(req->query, name, n);
}

void nrf_query_free(char **v, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(v[i]);
    free(v);
}

static char *query_one(const g5c_req *req, const char *name)
{
    size_t n;
    char **v = nrf_query_all(req, name, &n), *r = NULL;
    if (n > 0) {
        r = v[0];
        v[0] = NULL;
    }
    nrf_query_free(v, n);
    return r;
}

/* ---- matching ---- */

typedef struct {
    char *target_type, *requester_type, *dnn, *supi, *amf_region, *amf_set, *locality, *target_id;
    char **services;
    size_t nservices;
    g5c_json *snssais; /* array of {sst, sd?} */
    g5c_json *tai;     /* {plmnId, tac} */
    g5c_json *plmns;   /* target-plmn-list: array of {mcc, mnc} */
    g5c_json *guami;   /* {plmnId, amfId} */
    unsigned limit;
    bool service_map;
} disc_q;

static void q_free(disc_q *q)
{
    free(q->target_type);
    free(q->requester_type);
    free(q->dnn);
    free(q->supi);
    free(q->amf_region);
    free(q->amf_set);
    free(q->locality);
    free(q->target_id);
    nrf_query_free(q->services, q->nservices);
    g5c_json_free(q->snssais);
    g5c_json_free(q->tai);
    g5c_json_free(q->plmns);
    g5c_json_free(q->guami);
}

static bool snssai_eq(const g5c_json *a, const g5c_json *b)
{
    int64_t sa = -1, sb = -2;
    const char *da = g5c_json_get_str(a, "sd"), *db = g5c_json_get_str(b, "sd");
    if (!g5c_json_get_int(a, "sst", &sa) || !g5c_json_get_int(b, "sst", &sb) || sa != sb)
        return false;
    if (da == NULL || db == NULL)
        return da == db;
    return strcasecmp(da, db) == 0;
}

/* all the S-NSSAIs a profile declares (profile level, per PLMN, services and the type-specific info lists) */
static void collect_snssais(const g5c_json *doc, g5c_json *out)
{
    static const char *const lists[][2] = {{"smfInfo", "sNssaiSmfInfoList"}, {"upfInfo", "sNssaiUpfInfoList"}, {NULL, NULL}};
    const g5c_json *a = g5c_json_get(doc, "sNssais");
    for (size_t i = 0; i < g5c_json_len(a); i++)
        g5c_json_push(out, g5c_json_dup(g5c_json_at(a, i)));
    a = g5c_json_get(doc, "perPlmnSnssaiList");
    for (size_t i = 0; i < g5c_json_len(a); i++) {
        const g5c_json *l = g5c_json_get(g5c_json_at(a, i), "sNssaiList");
        for (size_t j = 0; j < g5c_json_len(l); j++)
            g5c_json_push(out, g5c_json_dup(g5c_json_at(l, j)));
    }
    for (int k = 0; lists[k][0] != NULL; k++) {
        const g5c_json *l = g5c_json_get(g5c_json_get(doc, lists[k][0]), lists[k][1]);
        for (size_t j = 0; j < g5c_json_len(l); j++) {
            const g5c_json *sn = g5c_json_get(g5c_json_at(l, j), "sNssai");
            if (sn != NULL)
                g5c_json_push(out, g5c_json_dup(sn));
        }
    }
    a = g5c_json_get(doc, "nfServices");
    for (size_t i = 0; i < g5c_json_len(a); i++) {
        const g5c_json *l = g5c_json_get(g5c_json_at(a, i), "sNssais");
        for (size_t j = 0; j < g5c_json_len(l); j++)
            g5c_json_push(out, g5c_json_dup(g5c_json_at(l, j)));
    }
}

static bool match_snssais(const g5c_json *doc, const g5c_json *want)
{
    g5c_json *have = g5c_json_new_arr();
    bool ok = false;
    collect_snssais(doc, have);
    if (g5c_json_len(have) == 0)
        ok = true; /* the profile does not restrict slices */
    for (size_t i = 0; !ok && i < g5c_json_len(want); i++)
        for (size_t j = 0; !ok && j < g5c_json_len(have); j++)
            ok = snssai_eq(g5c_json_at(want, i), g5c_json_at(have, j));
    g5c_json_free(have);
    return ok;
}

static void collect_dnns(const g5c_json *doc, g5c_json *out)
{
    static const char *const lists[][3] = {{"smfInfo", "sNssaiSmfInfoList", "dnnSmfInfoList"}, {"upfInfo", "sNssaiUpfInfoList", "dnnUpfInfoList"}, {NULL, NULL, NULL}};
    for (int k = 0; lists[k][0] != NULL; k++) {
        const g5c_json *l = g5c_json_get(g5c_json_get(doc, lists[k][0]), lists[k][1]);
        for (size_t j = 0; j < g5c_json_len(l); j++) {
            const g5c_json *d = g5c_json_get(g5c_json_at(l, j), lists[k][2]);
            for (size_t m = 0; m < g5c_json_len(d); m++)
                if (g5c_json_get_str(g5c_json_at(d, m), "dnn") != NULL)
                    g5c_json_push_str(out, g5c_json_get_str(g5c_json_at(d, m), "dnn"));
        }
    }
    {
        const g5c_json *l = g5c_json_get(g5c_json_get(doc, "pcfInfo"), "dnnList");
        for (size_t i = 0; i < g5c_json_len(l); i++)
            if (g5c_json_str(g5c_json_at(l, i)) != NULL)
                g5c_json_push_str(out, g5c_json_str(g5c_json_at(l, i)));
    }
}

static bool match_dnn(const g5c_json *doc, const char *dnn)
{
    g5c_json *have = g5c_json_new_arr();
    bool ok;
    collect_dnns(doc, have);
    ok = g5c_json_len(have) == 0;
    for (size_t i = 0; !ok && i < g5c_json_len(have); i++)
        ok = strcasecmp(g5c_json_str(g5c_json_at(have, i)), dnn) == 0;
    g5c_json_free(have);
    return ok;
}

static bool tai_eq(const g5c_json *a, const g5c_json *b)
{
    const g5c_json *pa = g5c_json_get(a, "plmnId"), *pb = g5c_json_get(b, "plmnId");
    const char *ta = g5c_json_get_str(a, "tac"), *tb = g5c_json_get_str(b, "tac");
    if (ta == NULL || tb == NULL || strcasecmp(ta, tb) != 0)
        return false;
    if (pa == NULL || pb == NULL)
        return true;
    return g5c_json_get_str(pa, "mcc") != NULL && g5c_json_get_str(pb, "mcc") != NULL && strcmp(g5c_json_get_str(pa, "mcc"), g5c_json_get_str(pb, "mcc")) == 0 &&
           g5c_json_get_str(pa, "mnc") != NULL && g5c_json_get_str(pb, "mnc") != NULL && strcmp(g5c_json_get_str(pa, "mnc"), g5c_json_get_str(pb, "mnc")) == 0;
}

static bool match_tai(const g5c_json *doc, const g5c_json *tai)
{
    static const char *const infos[] = {"amfInfo", "smfInfo", "upfInfo", NULL};
    bool restricted = false;
    for (int k = 0; infos[k] != NULL; k++) {
        const g5c_json *l = g5c_json_get(g5c_json_get(doc, infos[k]), "taiList");
        const g5c_json *rl = g5c_json_get(g5c_json_get(doc, infos[k]), "taiRangeList");
        if (g5c_json_len(l) > 0 || g5c_json_len(rl) > 0)
            restricted = true;
        for (size_t i = 0; i < g5c_json_len(l); i++)
            if (tai_eq(g5c_json_at(l, i), tai))
                return true;
        for (size_t i = 0; i < g5c_json_len(rl); i++) { /* TaiRange: plmnId and a list of tacRangeList {start, end} (6-hex-digit strings) */
            const g5c_json *r = g5c_json_get(g5c_json_at(rl, i), "tacRangeList");
            const char *t = g5c_json_get_str(tai, "tac");
            for (size_t j = 0; t != NULL && j < g5c_json_len(r); j++) {
                const char *s = g5c_json_get_str(g5c_json_at(r, j), "start"), *e = g5c_json_get_str(g5c_json_at(r, j), "end");
                if (s != NULL && e != NULL && strcasecmp(t, s) >= 0 && strcasecmp(t, e) <= 0)
                    return true;
            }
        }
    }
    return !restricted;
}

static bool match_supi(const g5c_json *doc, const char *supi)
{
    static const char *const infos[] = {"udmInfo", "ausfInfo", "udrInfo", "pcfInfo", NULL};
    const char *digits = strncmp(supi, "imsi-", 5) == 0 ? supi + 5 : supi;
    bool restricted = false;
    for (int k = 0; infos[k] != NULL; k++) {
        const g5c_json *l = g5c_json_get(g5c_json_get(doc, infos[k]), "supiRanges");
        if (g5c_json_len(l) > 0)
            restricted = true;
        for (size_t i = 0; i < g5c_json_len(l); i++) {
            const g5c_json *r = g5c_json_at(l, i);
            const char *s = g5c_json_get_str(r, "start"), *e = g5c_json_get_str(r, "end"), *pat = g5c_json_get_str(r, "pattern");
            if (s != NULL && e != NULL && strlen(digits) == strlen(s) && strcmp(digits, s) >= 0 && strcmp(digits, e) <= 0)
                return true;
            if (pat != NULL) {
                regex_t re;
                if (regcomp(&re, pat, REG_EXTENDED | REG_NOSUB) == 0) {
                    bool m = regexec(&re, digits, 0, NULL, 0) == 0 || regexec(&re, supi, 0, NULL, 0) == 0;
                    regfree(&re);
                    if (m)
                        return true;
                }
            }
        }
    }
    return !restricted;
}

static bool match_plmns(const g5c_json *doc, const nrf *n, const g5c_json *want)
{
    const g5c_json *have = g5c_json_get(doc, "plmnList");
    for (size_t i = 0; i < g5c_json_len(want); i++) {
        const char *mcc = g5c_json_get_str(g5c_json_at(want, i), "mcc"), *mnc = g5c_json_get_str(g5c_json_at(want, i), "mnc");
        if (g5c_json_len(have) == 0) {
            if (mcc != NULL && mnc != NULL && strcmp(mcc, n->cfg.mcc) == 0 && strcmp(mnc, n->cfg.mnc) == 0)
                return true; /* not provided: the PLMN of the NRF */
            continue;
        }
        for (size_t j = 0; j < g5c_json_len(have); j++) {
            const char *m1 = g5c_json_get_str(g5c_json_at(have, j), "mcc"), *m2 = g5c_json_get_str(g5c_json_at(have, j), "mnc");
            if (mcc != NULL && mnc != NULL && m1 != NULL && m2 != NULL && strcmp(mcc, m1) == 0 && strcmp(mnc, m2) == 0)
                return true;
        }
    }
    return false;
}

/* may a requester of this type discover the profile (allowedNfTypes at profile level)? */
static bool allowed_type(const g5c_json *list, const char *type)
{
    return g5c_json_len(list) == 0 || nrf_list_has(list, type);
}

/* the profile as it is returned: nfServices reduced to the requested names that the requester may use */
static g5c_json *project(const g5c_json *doc, const disc_q *q, bool *any_service)
{
    g5c_json *out = g5c_json_dup(doc);
    g5c_json *svcs = g5c_json_get_mut(out, "nfServices"), *map = g5c_json_get_mut(out, "nfServiceList");
    size_t kept = 0;
    if (svcs != NULL) {
        for (size_t i = 0; i < g5c_json_len(svcs);) {
            const g5c_json *s = g5c_json_at(svcs, i);
            const char *name = g5c_json_get_str(s, "serviceName");
            bool keep = allowed_type(g5c_json_get(s, "allowedNfTypes"), q->requester_type);
            if (keep && q->nservices > 0) {
                keep = false;
                for (size_t j = 0; j < q->nservices && name != NULL; j++)
                    if (strcmp(q->services[j], name) == 0)
                        keep = true;
            }
            const char *st = g5c_json_get_str(s, "nfServiceStatus");
            if (keep && st != NULL && strcmp(st, "REGISTERED") != 0)
                keep = false;
            if (keep) {
                kept++;
                i++;
            } else {
                g5c_json_arr_remove(svcs, i);
            }
        }
    }
    if (map != NULL) {
        for (size_t i = 0; i < g5c_json_len(map);) {
            const g5c_json *s = g5c_json_val_at(map, i);
            const char *name = g5c_json_get_str(s, "serviceName");
            bool keep = allowed_type(g5c_json_get(s, "allowedNfTypes"), q->requester_type);
            if (keep && q->nservices > 0) {
                keep = false;
                for (size_t j = 0; j < q->nservices && name != NULL; j++)
                    if (strcmp(q->services[j], name) == 0)
                        keep = true;
            }
            if (keep) {
                kept++;
                i++;
            } else {
                (void)g5c_json_remove(map, g5c_json_key_at(map, i));
            }
        }
    }
    *any_service = kept > 0 || (svcs == NULL && map == NULL && q->nservices == 0);
    return out;
}

static bool match_profile(const nrf *n, const g5c_json *doc, const char *id, const disc_q *q)
{
    const char *t = g5c_json_get_str(doc, "nfType"), *st = g5c_json_get_str(doc, "nfStatus");
    if (t == NULL || strcmp(t, q->target_type) != 0)
        return false;
    if (st == NULL || strcmp(st, "REGISTERED") != 0) /* SUSPENDED and UNDISCOVERABLE are not returned */
        return false;
    if (q->target_id != NULL && strcmp(q->target_id, id) != 0)
        return false;
    if (!allowed_type(g5c_json_get(doc, "allowedNfTypes"), q->requester_type))
        return false;
    if (q->plmns != NULL && !match_plmns(doc, n, q->plmns))
        return false;
    if (q->snssais != NULL && g5c_json_len(q->snssais) > 0 && !match_snssais(doc, q->snssais))
        return false;
    if (q->dnn != NULL && !match_dnn(doc, q->dnn))
        return false;
    if (q->tai != NULL && !match_tai(doc, q->tai))
        return false;
    if (q->supi != NULL && !match_supi(doc, q->supi))
        return false;
    if (q->guami != NULL) {
        const g5c_json *gl = g5c_json_get(g5c_json_get(doc, "amfInfo"), "guamiList");
        const char *want = g5c_json_get_str(q->guami, "amfId");
        bool found = g5c_json_len(gl) == 0 && g5c_json_get(doc, "amfInfo") != NULL;
        for (size_t i = 0; i < g5c_json_len(gl) && !found; i++) {
            const char *have = g5c_json_get_str(g5c_json_at(gl, i), "amfId");
            const g5c_json *pw = g5c_json_get(q->guami, "plmnId"), *ph = g5c_json_get(g5c_json_at(gl, i), "plmnId");
            found = want != NULL && have != NULL && strcasecmp(want, have) == 0 &&
                    (pw == NULL || ph == NULL || (g5c_json_get_str(pw, "mcc") != NULL && g5c_json_get_str(ph, "mcc") != NULL &&
                                                    strcmp(g5c_json_get_str(pw, "mcc"), g5c_json_get_str(ph, "mcc")) == 0));
        }
        if (!found)
            return false;
    }
    if (q->amf_region != NULL || q->amf_set != NULL) {
        const g5c_json *ai = g5c_json_get(doc, "amfInfo");
        if (ai == NULL)
            return false;
        if (q->amf_region != NULL && (g5c_json_get_str(ai, "amfRegionId") == NULL || strcmp(g5c_json_get_str(ai, "amfRegionId"), q->amf_region) != 0))
            return false;
        if (q->amf_set != NULL && (g5c_json_get_str(ai, "amfSetId") == NULL || strcmp(g5c_json_get_str(ai, "amfSetId"), q->amf_set) != 0))
            return false;
    }
    return true;
}

/* ---- selection order: preferred locality first, then priority (lower is better), then load ---- */

typedef struct {
    g5c_json *prof;
    int64_t priority, load;
    bool local;
} cand;

static int cand_cmp(const void *a, const void *b)
{
    const cand *x = a, *y = b;
    if (x->local != y->local)
        return x->local ? -1 : 1;
    if (x->priority != y->priority)
        return x->priority < y->priority ? -1 : 1;
    if (x->load != y->load)
        return x->load < y->load ? -1 : 1;
    return 0;
}

static void discover(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nrf *n = ctx;
    disc_q q;
    char *tmp;
    size_t ns = 0;
    char **sn;
    cand *c = NULL;
    size_t nc = 0, cap = 0;
    g5c_json *out, *arr;
    memset(&q, 0, sizeof q);
    q.target_type = query_one(req, "target-nf-type");
    q.requester_type = query_one(req, "requester-nf-type");
    if (q.target_type == NULL || *q.target_type == 0) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_MISSING", "target-nf-type", "mandatory");
        q_free(&q);
        return;
    }
    if (q.requester_type == NULL || *q.requester_type == 0) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_MISSING", "requester-nf-type", "mandatory");
        q_free(&q);
        return;
    }
    if ((tmp = g5c_req_query(req, "complexQuery")) != NULL) {
        free(tmp);
        g5c_resp_problem_invalid(resp, 400, "INVALID_QUERY_PARAM", "complexQuery", "not supported");
        q_free(&q);
        return;
    }
    {   /* style: form, explode: false - "service-names=nudm-sdm,nudm-uecm" */
        size_t raw_n = 0;
        char **raw = nrf_query_all(req, "service-names", &raw_n);
        for (size_t i = 0; i < raw_n; i++) {
            char *save = NULL, *t;
            for (t = strtok_r(raw[i], ",", &save); t != NULL; t = strtok_r(NULL, ",", &save)) {
                q.services = g5c_xrealloc(q.services, (q.nservices + 1) * sizeof *q.services);
                q.services[q.nservices++] = g5c_xstrdup(t);
            }
        }
        nrf_query_free(raw, raw_n);
    }
    q.dnn = query_one(req, "dnn");
    q.supi = query_one(req, "supi");
    q.amf_region = query_one(req, "amf-region-id");
    q.amf_set = query_one(req, "amf-set-id");
    q.locality = query_one(req, "preferred-locality");
    q.target_id = query_one(req, "target-nf-instance-id");
    q.limit = 0;
    if ((tmp = query_one(req, "supported-features")) != NULL) {
        q.service_map = nrf_features_service_map(tmp);
        free(tmp);
    }
    if ((tmp = query_one(req, "limit")) != NULL) {
        char *end;
        unsigned long v = strtoul(tmp, &end, 10);
        if (*end != 0 || v == 0 || v > 1000) {
            g5c_resp_problem_invalid(resp, 400, "INVALID_QUERY_PARAM", "limit", "must be 1..1000");
            free(tmp);
            q_free(&q);
            return;
        }
        q.limit = (unsigned)v;
        free(tmp);
    }
    sn = nrf_query_all(req, "snssais", &ns);
    if (ns > 0) {
        q.snssais = g5c_json_new_arr();
        for (size_t i = 0; i < ns; i++) {
            char perr[64];
            g5c_json *j = g5c_json_parse(sn[i], strlen(sn[i]), perr, sizeof perr);
            if (j == NULL || !g5c_json_is(j, G5C_J_ARRAY) || g5c_json_len(j) == 0) { /* content: application/json, an array of at least one Snssai */
                g5c_resp_problem_invalid(resp, 400, "INVALID_QUERY_PARAM", "snssais", "not a JSON array of S-NSSAIs");
                g5c_json_free(j);
                nrf_query_free(sn, ns);
                q_free(&q);
                return;
            }
            if (g5c_json_is(j, G5C_J_ARRAY)) {
                for (size_t k = 0; k < g5c_json_len(j); k++)
                    g5c_json_push(q.snssais, g5c_json_dup(g5c_json_at(j, k)));
                g5c_json_free(j);
            } else {
                g5c_json_push(q.snssais, j);
            }
        }
    }
    nrf_query_free(sn, ns);
    if ((tmp = query_one(req, "tai")) != NULL) {
        char perr[64];
        q.tai = g5c_json_parse(tmp, strlen(tmp), perr, sizeof perr);
        free(tmp);
        if (q.tai == NULL || !g5c_json_is(q.tai, G5C_J_OBJECT)) {
            g5c_resp_problem_invalid(resp, 400, "INVALID_QUERY_PARAM", "tai", "not a JSON TAI");
            q_free(&q);
            return;
        }
    }
    if ((tmp = query_one(req, "guami")) != NULL) {
        char perr[64];
        q.guami = g5c_json_parse(tmp, strlen(tmp), perr, sizeof perr);
        free(tmp);
        if (q.guami == NULL || !g5c_json_is(q.guami, G5C_J_OBJECT)) {
            g5c_resp_problem_invalid(resp, 400, "INVALID_QUERY_PARAM", "guami", "not a JSON GUAMI");
            q_free(&q);
            return;
        }
    }
    sn = nrf_query_all(req, "target-plmn-list", &ns);
    if (ns > 0) {
        q.plmns = g5c_json_new_arr();
        for (size_t i = 0; i < ns; i++) {
            char perr[64];
            g5c_json *j = g5c_json_parse(sn[i], strlen(sn[i]), perr, sizeof perr);
            if (j == NULL || !g5c_json_is(j, G5C_J_ARRAY) || g5c_json_len(j) == 0) {
                g5c_resp_problem_invalid(resp, 400, "INVALID_QUERY_PARAM", "target-plmn-list", "not a JSON array of PLMN IDs");
                g5c_json_free(j);
                nrf_query_free(sn, ns);
                q_free(&q);
                return;
            }
            if (g5c_json_is(j, G5C_J_ARRAY)) {
                for (size_t k = 0; k < g5c_json_len(j); k++)
                    g5c_json_push(q.plmns, g5c_json_dup(g5c_json_at(j, k)));
                g5c_json_free(j);
            } else {
                g5c_json_push(q.plmns, j);
            }
        }
    }
    nrf_query_free(sn, ns);

    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < n->nprofs; i++) {
        bool any;
        cand x;
        if (!match_profile(n, n->profs[i].doc, n->profs[i].id, &q))
            continue;
        x.prof = project(n->profs[i].doc, &q, &any);
        if (!any) {
            g5c_json_free(x.prof);
            continue;
        }
        {
            g5c_json *v = nrf_profile_view(x.prof, q.service_map);
            g5c_json_free(x.prof);
            x.prof = v;
        }
        x.priority = 0;
        x.load = 0;
        (void)g5c_json_get_int(x.prof, "priority", &x.priority);
        (void)g5c_json_get_int(x.prof, "load", &x.load);
        x.local = q.locality != NULL && g5c_json_get_str(x.prof, "locality") != NULL && strcmp(g5c_json_get_str(x.prof, "locality"), q.locality) == 0;
        if (nc == cap) {
            cap = cap != 0 ? cap * 2 : 8;
            c = g5c_xrealloc(c, cap * sizeof *c);
        }
        c[nc++] = x;
    }
    pthread_mutex_unlock(&n->mu);
    if (nc > 1)
        qsort(c, nc, sizeof *c, cand_cmp);
    out = g5c_json_new_obj();
    g5c_json_set_int(out, "validityPeriod", n->cfg.validity);
    g5c_json_set_str(out, "nrfSupportedFeatures", "1"); /* Service-Map */
    arr = g5c_json_set(out, "nfInstances", g5c_json_new_arr());
    for (size_t i = 0; i < nc; i++) {
        if (q.limit == 0 || i < q.limit)
            g5c_json_push(arr, c[i].prof);
        else
            g5c_json_free(c[i].prof);
    }
    free(c);
    g5c_resp_json(resp, 200, out);
    g5c_json_free(out);
    nrf_count(n, "g5c_nrf_discoveries_total", "NFDiscover requests answered, by target type.", "target_nf_type", q.target_type);
    q_free(&q);
}

void nrf_disc_routes(g5c_router *r, nrf *n)
{
    g5c_router_route(r, "GET", "/nnrf-disc/v1/nf-instances", discover, n);
}
