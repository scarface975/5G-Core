/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nnssf_NSSelection (TS 29.531 5.2, 6.1; the selection rules of TS 23.501 5.15.5): GET network-slice-information. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

#define MAXSN 64
#define F_RSIPCE 0x4u /* feature 3 of Nnssf_NSSelection: retrieval of slice information during PDN connection establishment */

typedef struct {
    nssf *n;
    bool roaming;
    char home_mcc[4], home_mnc[4];
    bool has_tai;
    tai_t tai;
    const g5c_json *mapping; /* mappingOfNssai of the request */
} qctx;

typedef struct {
    int status;
    const char *cause;
    char detail[200];
} qerr;

static void qfail(qerr *e, int status, const char *cause, const char *detail)
{
    e->status = status;
    e->cause = cause;
    snprintf(e->detail, sizeof e->detail, "%s", detail);
}

/* ---- parameters --------------------------------------------------------------------------------------------------------- */

/* A JSON-encoded query parameter: NULL when absent; 400 when it does not parse or break its schema */
static g5c_json *json_param(nssf *n, const g5c_req *req, const char *name, int schema, bool *bad, g5c_resp *resp)
{
    char *raw = g5c_req_query_decoded(req, name), perr[160], serr[200];
    g5c_json *j;
    if (raw == NULL)
        return NULL;
    j = g5c_json_parse(raw, strlen(raw), perr, sizeof perr);
    free(raw);
    if (j == NULL) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_INCORRECT", name, perr);
        *bad = true;
        return NULL;
    }
    if (n->cfg->validate && oa_validate(n->sch, schema, j, serr, sizeof serr) != 0) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_INCORRECT", name, serr);
        g5c_json_free(j);
        *bad = true;
        return NULL;
    }
    return j;
}

static size_t sn_list(const g5c_json *arr, sn_t *out, size_t cap)
{
    size_t n = 0;
    for (size_t i = 0; i < g5c_json_len(arr) && n < cap; i++)
        if (sn_from_json(g5c_json_at(arr, i), &out[n]))
            n++;
    return n;
}

/* the home S-NSSAI of a serving one: the mapping the request gave, else the configured one for the home PLMN */
static bool to_home(const qctx *q, const sn_t *serving, sn_t *home)
{
    for (size_t i = 0; i < g5c_json_len(q->mapping); i++) {
        sn_t s, h;
        const g5c_json *m = g5c_json_at(q->mapping, i);
        if (sn_from_json(g5c_json_get(m, "servingSnssai"), &s) && sn_from_json(g5c_json_get(m, "homeSnssai"), &h) && sn_equal(&s, serving)) {
            *home = h;
            return true;
        }
    }
    for (size_t i = 0; i < q->n->cfg->nmaps; i++) {
        const mapping_t *m = &q->n->cfg->maps[i];
        if (strcmp(m->home_mcc, q->home_mcc) == 0 && strcmp(m->home_mnc, q->home_mnc) == 0 && sn_equal(&m->serving, serving)) {
            *home = m->home;
            return true;
        }
    }
    return false;
}

static bool to_serving(const qctx *q, const sn_t *home, sn_t *serving)
{
    for (size_t i = 0; i < q->n->cfg->nmaps; i++) {
        const mapping_t *m = &q->n->cfg->maps[i];
        if (strcmp(m->home_mcc, q->home_mcc) == 0 && strcmp(m->home_mnc, q->home_mnc) == 0 && sn_equal(&m->home, home)) {
            *serving = m->serving;
            return true;
        }
    }
    return false;
}

/* The NRF named in the answers is the API URI of its NFDiscovery service (TS 29.531 6.1.6.2.4, TS 29.510 6.2.1); the configuration may give the API root. */
static void set_disc_uri(g5c_json *o, const char *key, const char *nrf)
{
    char buf[512];
    size_t n = strlen(nrf);
    if (strstr(nrf, "/nnrf-disc/") != NULL || n + 32 >= sizeof buf) {
        g5c_json_set_str(o, key, nrf);
        return;
    }
    while (n > 0 && nrf[n - 1] == '/')
        n--;
    snprintf(buf, sizeof buf, "%.*s/nnrf-disc/v1/nf-instances", (int)n, nrf);
    g5c_json_set_str(o, key, buf);
}

static g5c_json *nsi_info(const slice_t *s)
{
    g5c_json *o = g5c_json_new_obj();
    set_disc_uri(o, "nrfId", s->nrf);
    if (s->nsi_id != NULL)
        g5c_json_set_str(o, "nsiId", s->nsi_id);
    if (s->nrf_nfm != NULL)
        g5c_json_set_str(o, "nrfNfMgtUri", s->nrf_nfm);
    if (s->nrf_token != NULL)
        g5c_json_set_str(o, "nrfAccessTokenUri", s->nrf_token);
    return o;
}

/* ---- registration and UE configuration update --------------------------------------------------------------------------- */

typedef struct {
    sn_t requested[MAXSN], subscribed[MAXSN], allowed[MAXSN], allowed_home[MAXSN], rejected_plmn[MAXSN], rejected_ta[MAXSN];
    bool is_default[MAXSN];
    size_t nreq, nsub, nallowed, nrej_plmn, nrej_ta;
    bool default_cfg_ind;
    bool invalid_requested; /* a requested S-NSSAI that is not valid in the serving PLMN */
} sel_t;

static void push(sn_t *list, size_t *n, const sn_t *s)
{
    if (*n < MAXSN && !sn_in(list, *n, s))
        list[(*n)++] = *s;
}

/* The Allowed NSSAI (TS 23.501 5.15.5.2.1 (B)): the requested S-NSSAIs that the subscription permits, else the default subscribed ones, always
 * limited to the slices that exist in the PLMN and in the tracking area; what falls out is rejected in the PLMN or in the TA. */
static void select_allowed(const qctx *q, sel_t *s)
{
    const nssf_cfg *cfg = q->n->cfg;
    sn_t cand[MAXSN], cand_home[MAXSN];
    size_t ncand = 0;
    bool permitted_any = false;
    for (size_t i = 0; i < s->nreq; i++) {
        sn_t home = s->requested[i];
        bool ok;
        if (q->roaming) {
            ok = to_home(q, &s->requested[i], &home) && sn_in(s->subscribed, s->nsub, &home);
        } else {
            ok = sn_in(s->subscribed, s->nsub, &home);
        }
        if (ok) {
            permitted_any = true;
            if (ncand < MAXSN) {
                cand[ncand] = s->requested[i];
                cand_home[ncand++] = home;
            }
        } else {
            push(s->rejected_plmn, &s->nrej_plmn, &s->requested[i]);
            s->invalid_requested = true;
        }
    }
    if (!permitted_any) { /* nothing requested, or nothing the subscription permits: the default S-NSSAIs */
        for (size_t i = 0; i < s->nsub; i++)
            if (s->is_default[i]) {
                sn_t serving = s->subscribed[i];
                if (q->roaming && !to_serving(q, &s->subscribed[i], &serving))
                    continue;
                if (ncand < MAXSN) {
                    cand[ncand] = serving;
                    cand_home[ncand++] = s->subscribed[i];
                }
            }
    }
    if (cfg->include_subscribed) { /* local policy: the others too (TS 23.501 NOTE 6, a newly added subscription) */
        for (size_t i = 0; i < s->nsub; i++) {
            sn_t serving = s->subscribed[i];
            if (q->roaming && !to_serving(q, &s->subscribed[i], &serving))
                continue;
            if (!sn_in(cand, ncand, &serving) && ncand < MAXSN) {
                cand[ncand] = serving;
                cand_home[ncand++] = s->subscribed[i];
            }
        }
    }
    for (size_t i = 0; i < ncand; i++) {
        const slice_t *sl = cfg_slice(cfg, &cand[i]);
        if (sl == NULL) {
            push(s->rejected_plmn, &s->nrej_plmn, &cand[i]);
            if (sn_in(s->requested, s->nreq, &cand[i]))
                s->invalid_requested = true;
        } else if (q->has_tai && !slice_in_tai(sl, &q->tai)) {
            push(s->rejected_ta, &s->nrej_ta, &cand[i]);
        } else if (s->nallowed < cfg->max_allowed && !sn_in(s->allowed, s->nallowed, &cand[i])) {
            s->allowed[s->nallowed] = cand[i];
            s->allowed_home[s->nallowed++] = cand_home[i];
        }
    }
    /* an S-NSSAI that ended up allowed (a default one replacing a rejected request) is not rejected */
    for (size_t i = 0; i < s->nallowed; i++) {
        size_t k = 0;
        for (size_t j = 0; j < s->nrej_plmn; j++)
            if (!sn_equal(&s->rejected_plmn[j], &s->allowed[i]))
                s->rejected_plmn[k++] = s->rejected_plmn[j];
        s->nrej_plmn = k;
    }
}

static g5c_json *allowed_list(const qctx *q, const sel_t *s, const char *access)
{
    g5c_json *arr = g5c_json_new_arr(), *e = g5c_json_push(arr, g5c_json_new_obj()), *l = g5c_json_set(e, "allowedSnssaiList", g5c_json_new_arr());
    for (size_t i = 0; i < s->nallowed; i++) {
        g5c_json *a = g5c_json_push(l, g5c_json_new_obj());
        const slice_t *sl = cfg_slice(q->n->cfg, &s->allowed[i]);
        g5c_json_set(a, "allowedSnssai", sn_json(&s->allowed[i]));
        if (sl != NULL)
            g5c_json_push(g5c_json_set(a, "nsiInformationList", g5c_json_new_arr()), nsi_info(sl));
        if (q->roaming)
            g5c_json_set(a, "mappedHomeSnssai", sn_json(&s->allowed_home[i]));
    }
    g5c_json_set_str(e, "accessType", access);
    return arr;
}

static void add_sn_array(g5c_json *obj, const char *key, const sn_t *l, size_t n)
{
    g5c_json *arr;
    if (n == 0)
        return;
    arr = g5c_json_set(obj, key, g5c_json_new_arr());
    for (size_t i = 0; i < n; i++)
        g5c_json_push(arr, sn_json(&l[i]));
}

/* The Configured NSSAI of the serving PLMN: the subscribed S-NSSAIs that exist here, with the mapping to the home ones for a roamer */
static void add_configured(const qctx *q, const sel_t *s, g5c_json *out)
{
    g5c_json *arr = NULL;
    size_t n = 0;
    for (size_t i = 0; i < s->nsub && n < q->n->cfg->max_configured; i++) {
        sn_t serving = s->subscribed[i];
        if (q->roaming && !to_serving(q, &s->subscribed[i], &serving))
            continue;
        if (cfg_slice(q->n->cfg, &serving) == NULL)
            continue;
        if (arr == NULL)
            arr = g5c_json_set(out, "configuredNssai", g5c_json_new_arr());
        {
            g5c_json *e = g5c_json_push(arr, g5c_json_new_obj());
            g5c_json_set(e, "configuredSnssai", sn_json(&serving));
            if (q->roaming)
                g5c_json_set(e, "mappedHomeSnssai", sn_json(&s->subscribed[i]));
            n++;
        }
    }
}

static void add_target_amf(const qctx *q, const sel_t *s, const char *nf_id, g5c_json *out)
{
    char *own_set = NULL, *dyn = NULL;
    const amfset_t *cs = NULL;
    int r;
    if (!q->has_tai || s->nallowed == 0)
        return;
    r = nssf_amf_supports(q->n, nf_id, &q->tai, s->allowed, s->nallowed, &own_set);
    if (r == 1) { /* the requesting AMF serves all of them: its own set is the target (the AMF stays) */
        if (own_set != NULL)
            g5c_json_set_str(out, "targetAmfSet", own_set);
    } else if (nssf_find_set(q->n, &q->tai, s->allowed, s->nallowed, &cs, &dyn)) {
        g5c_json_set_str(out, "targetAmfSet", cs != NULL ? cs->id : dyn);
        if (cs != NULL && cs->nrf != NULL)
            set_disc_uri(out, "nrfAmfSet", cs->nrf);
        if (cs != NULL && cs->return_candidates && cs->namfs > 0) {
            g5c_json *l = g5c_json_set(out, "candidateAmfList", g5c_json_new_arr());
            for (size_t i = 0; i < cs->namfs; i++)
                g5c_json_push_str(l, cs->amfs[i]);
        }
    }
    free(own_set);
    free(dyn);
}

static const char *access_of(const g5c_json *cur)
{
    const char *a = g5c_json_get_str(cur, "accessType");
    return a != NULL ? a : "3GPP_ACCESS";
}

static g5c_json *procedure_registration(const qctx *q, const g5c_json *ri, const char *nf_id, qerr *e, bool ue_cu)
{
    sel_t *s = g5c_xcalloc(1, sizeof *s);
    const g5c_json *sub = g5c_json_get(ri, "subscribedNssai"), *req = g5c_json_get(ri, "requestedNssai"), *fm = g5c_json_get(ri, "sNssaiForMapping");
    bool rm = false, dci = false;
    g5c_json *out = NULL;
    (void)g5c_json_get_bool(ri, "requestMapping", &rm);
    (void)g5c_json_get_bool(ri, "defaultConfiguredSnssaiInd", &dci);
    s->default_cfg_ind = dci;

    /* the retrieval of slice mapping information only (TS 29.531 5.2.2.2.2): serving S-NSSAIs of the HPLMN ones in sNssaiForMapping */
    if (!ue_cu && rm && g5c_json_len(fm) > 0) {
        sn_t home[MAXSN];
        size_t nh = sn_list(fm, home, MAXSN);
        g5c_json *map;
        out = g5c_json_new_obj();
        s->nallowed = 0;
        map = g5c_json_new_arr();
        for (size_t i = 0; i < nh; i++) {
            sn_t serving;
            if (to_serving(q, &home[i], &serving) && s->nallowed < MAXSN) {
                g5c_json *m = g5c_json_push(map, g5c_json_new_obj());
                s->allowed[s->nallowed] = serving;
                s->allowed_home[s->nallowed++] = home[i];
                g5c_json_set(m, "servingSnssai", sn_json(&serving));
                g5c_json_set(m, "homeSnssai", sn_json(&home[i]));
            }
        }
        if (s->nallowed == 0) {
            g5c_json_free(map);
            g5c_json_free(out);
            out = NULL;
            qfail(e, 403, "SNSSAI_NOT_SUPPORTED", "none of the home S-NSSAIs maps to a slice of this PLMN");
            goto done;
        }
        {
            qctx q2 = *q;
            q2.roaming = true;
            g5c_json_set(out, "allowedNssaiList", allowed_list(&q2, s, access_of(g5c_json_get(ri, "allowedNssaiCurrentAccess"))));
        }
        g5c_json_set(out, "mappingOfNssai", map);
        goto done;
    }

    for (size_t i = 0; i < g5c_json_len(sub) && s->nsub < MAXSN; i++) {
        bool d = false;
        if (sn_from_json(g5c_json_get(g5c_json_at(sub, i), "subscribedSnssai"), &s->subscribed[s->nsub])) {
            (void)g5c_json_get_bool(g5c_json_at(sub, i), "defaultIndication", &d);
            s->is_default[s->nsub++] = d;
        }
    }
    s->nreq = sn_list(req, s->requested, MAXSN);
    select_allowed(q, s);
    if (s->nallowed == 0) {
        qfail(e, 403, "SNSSAI_NOT_SUPPORTED", "none of the requested or subscribed S-NSSAIs is available here");
        goto done;
    }
    out = g5c_json_new_obj();
    g5c_json_set(out, "allowedNssaiList", allowed_list(q, s, access_of(g5c_json_get(ri, "allowedNssaiCurrentAccess"))));
    if (s->nreq == 0 || s->invalid_requested || s->default_cfg_ind)
        add_configured(q, s, out);
    add_sn_array(out, "rejectedNssaiInPlmn", s->rejected_plmn, s->nrej_plmn);
    add_sn_array(out, "rejectedNssaiInTa", s->rejected_ta, s->nrej_ta);
    if (!ue_cu)
        add_target_amf(q, s, nf_id, out);
    if (q->roaming) { /* the mapping of the allowed S-NSSAIs to the home ones */
        g5c_json *map = g5c_json_set(out, "mappingOfNssai", g5c_json_new_arr());
        for (size_t i = 0; i < s->nallowed; i++) {
            g5c_json *m = g5c_json_push(map, g5c_json_new_obj());
            g5c_json_set(m, "servingSnssai", sn_json(&s->allowed[i]));
            g5c_json_set(m, "homeSnssai", sn_json(&s->allowed_home[i]));
        }
    }
done:
    free(s);
    return out;
}

/* ---- PDU session establishment ----------------------------------------------------------------------------------------------- */

static g5c_json *procedure_pdu_session(const qctx *q, const g5c_json *pi, qerr *e)
{
    sn_t sn;
    const slice_t *sl;
    g5c_json *out;
    if (!sn_from_json(g5c_json_get(pi, "sNssai"), &sn)) {
        qfail(e, 400, "MANDATORY_QUERY_PARAM_INCORRECT", "sNssai is not an S-NSSAI");
        return NULL;
    }
    sl = cfg_slice(q->n->cfg, &sn);
    if (sl == NULL) {
        qfail(e, 403, "SNSSAI_NOT_SUPPORTED", "the S-NSSAI is not supported in the PLMN");
        return NULL;
    }
    if (q->has_tai && !slice_in_tai(sl, &q->tai)) {
        qfail(e, 403, "SNSSAI_NOT_SUPPORTED", "the S-NSSAI is not available in the tracking area");
        return NULL;
    }
    out = g5c_json_new_obj();
    g5c_json_set(out, "nsiInformation", nsi_info(sl));
    return out;
}

/* ---- PDN connection establishment (RSIPCE) ----------------------------------------------------------------------------------- */

static g5c_json *procedure_pdn(const qctx *q, const g5c_json *list, qerr *e)
{
    g5c_json *out = g5c_json_new_obj(), *map = g5c_json_set(out, "mappingOfNssai", g5c_json_new_arr());
    size_t n = 0;
    for (size_t i = 0; i < g5c_json_len(list); i++) {
        sn_t home, serving;
        if (sn_from_json(g5c_json_at(list, i), &home) && to_serving(q, &home, &serving)) {
            g5c_json *m = g5c_json_push(map, g5c_json_new_obj());
            g5c_json_set(m, "servingSnssai", sn_json(&serving));
            g5c_json_set(m, "homeSnssai", sn_json(&home));
            n++;
        }
    }
    if (n == 0) {
        g5c_json_free(out);
        qfail(e, 403, "SNSSAI_NOT_SUPPORTED", "none of the subscribed S-NSSAIs maps to a slice of this PLMN");
        return NULL;
    }
    return out;
}

/* ---- the GET ----------------------------------------------------------------------------------------------------------------- */

void nssf_nsselection_get(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nssf *n = ctx;
    char *nf_type = g5c_req_query_decoded(req, "nf-type"), *nf_id = g5c_req_query_decoded(req, "nf-id"), *feat = g5c_req_query_decoded(req, "supported-features");
    g5c_json *reg, *pdu, *cu, *pdn, *home_plmn, *tai, *out = NULL;
    bool bad = false;
    qctx q;
    qerr e = {0, NULL, ""};
    int given;
    memset(&q, 0, sizeof q);
    q.n = n;
    g5c_counter_inc(n->c_req[0]);
    if (nf_type == NULL || nf_id == NULL || nf_type[0] == '\0' || nf_id[0] == '\0') {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_MISSING", nf_type == NULL || nf_type[0] == '\0' ? "nf-type" : "nf-id", "the query parameter is required");
        goto done;
    }
    for (const char *p = nf_type; *p; p++)
        if (!(isupper((unsigned char)*p) || isdigit((unsigned char)*p) || *p == '_')) {
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_INCORRECT", "nf-type", "not an NF type");
            goto done;
        }
    if (strlen(nf_id) > 64) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_INCORRECT", "nf-id", "too long");
        goto done;
    }
    reg = json_param(n, req, "slice-info-request-for-registration", NSSF_SCH_SLICE_INFO_REGISTRATION, &bad, resp);
    pdu = bad ? NULL : json_param(n, req, "slice-info-request-for-pdu-session", NSSF_SCH_SLICE_INFO_PDU_SESSION, &bad, resp);
    cu = bad ? NULL : json_param(n, req, "slice-info-request-for-ue-cu", NSSF_SCH_SLICE_INFO_UE_CU, &bad, resp);
    pdn = bad ? NULL : json_param(n, req, "slice-info-request-for-pdn-connection", NSSF_SCH_SNSSAI_ARRAY, &bad, resp);
    home_plmn = bad ? NULL : json_param(n, req, "home-plmn-id", NSSF_SCH_PLMN_ID, &bad, resp);
    tai = bad ? NULL : json_param(n, req, "tai", NSSF_SCH_TAI, &bad, resp);
    if (bad)
        goto cleanup;
    given = (reg != NULL) + (pdu != NULL) + (cu != NULL) + (pdn != NULL);
    if (given != 1) {
        g5c_resp_problem_invalid(resp, 400, given == 0 ? "MANDATORY_QUERY_PARAM_MISSING" : "MANDATORY_QUERY_PARAM_INCORRECT", "slice-info-request-for-registration",
                                 "exactly one of the slice-info-request-for-... parameters is required");
        goto cleanup;
    }
    if (tai != NULL) {
        q.has_tai = tai_from_json(tai, &q.tai);
        if (!q.has_tai) {
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_INCORRECT", "tai", "not a TAI");
            goto cleanup;
        }
    }
    if (home_plmn != NULL) {
        if (!plmn_from_json(home_plmn, q.home_mcc, q.home_mnc)) {
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_INCORRECT", "home-plmn-id", "not a PLMN ID");
            goto cleanup;
        }
        q.roaming = strcmp(q.home_mcc, n->cfg->mcc) != 0 || strcmp(q.home_mnc, n->cfg->mnc) != 0;
    }
    q.mapping = g5c_json_get(reg != NULL ? reg : cu, "mappingOfNssai");
    if (reg != NULL) {
        g5c_counter_inc(n->c_req[1]);
        out = procedure_registration(&q, reg, nf_id, &e, false);
    } else if (pdu != NULL) {
        g5c_counter_inc(n->c_req[2]);
        out = procedure_pdu_session(&q, pdu, &e);
    } else if (cu != NULL) {
        g5c_counter_inc(n->c_req[1]);
        out = procedure_registration(&q, cu, nf_id, &e, true);
    } else {
        g5c_counter_inc(n->c_req[3]);
        out = procedure_pdn(&q, pdn, &e);
    }
    if (out == NULL) {
        g5c_counter_inc(n->c_reject);
        nssf_problem(resp, e.status, e.cause, e.detail);
    } else {
        unsigned neg = feat != NULL ? features_parse(feat) & F_RSIPCE : 0;
        if (feat != NULL) {
            char *f = features_str(neg);
            g5c_json_set_str(out, "supportedFeatures", f);
            free(f);
        }
        g5c_resp_json(resp, 200, out);
        g5c_json_free(out);
    }
cleanup:
    g5c_json_free(reg);
    g5c_json_free(pdu);
    g5c_json_free(cu);
    g5c_json_free(pdn);
    g5c_json_free(home_plmn);
    g5c_json_free(tai);
done:
    free(nf_type);
    free(nf_id);
    free(feat);
}
