/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Persistence of PDU sessions across an SMF restart: a JSON state file rewritten (atomically, coalesced) after every change, read back before the
 * first N4 association. A session is only kept alive if its UPF still has the Recovery Time Stamp it had when the file was written; otherwise the
 * association reveals a restart and the session is released towards the AMF like any session on a restarted UPF. */
#define _DEFAULT_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "priv.h"

static char *hex64(uint64_t v)
{
    return g5c_xasprintf("%016llx", (unsigned long long)v);
}

static uint64_t unhex64(const char *s)
{
    return s != NULL ? strtoull(s, NULL, 16) : 0;
}

static void set_hex(g5c_json *o, const char *key, const uint8_t *p, size_t n)
{
    char *h = g5c_hex_encode(p, n);
    g5c_json_set_str(o, key, h);
    free(h);
}

static void set_opt_str(g5c_json *o, const char *key, const char *v)
{
    if (v != NULL)
        g5c_json_set_str(o, key, v);
}

/* the session locked; one JSON object */
static g5c_json *snapshot(const smf_sess *ss)
{
    g5c_json *o = g5c_json_new_obj(), *fl, *ru;
    char *h;
    g5c_json_set_str(o, "ref", ss->ref);
    g5c_json_set_str(o, "supi", ss->supi);
    g5c_json_set_str(o, "dnn", ss->dnn);
    g5c_json_set_int(o, "psi", ss->psi);
    g5c_json_set_int(o, "pti", ss->pti);
    g5c_json_set_int(o, "sst", ss->sst);
    if (ss->has_sd)
        g5c_json_set_int(o, "sd", ss->sd);
    g5c_json_set_int(o, "pduType", ss->pdu_type);
    g5c_json_set_int(o, "sscMode", ss->ssc_mode);
    g5c_json_set_int(o, "acceptCause", ss->accept_cause);
    g5c_json_set_bool(o, "pcoDns4", ss->req.pco_dns4);
    g5c_json_set_bool(o, "pcoDns6", ss->req.pco_dns6);
    g5c_json_set_bool(o, "pcoMtu", ss->req.pco_mtu);
    if (ss->has4)
        set_hex(o, "ue4", ss->ue4, 4);
    if (ss->has6) {
        set_hex(o, "ue6", ss->ue6, 8);
        set_hex(o, "ifid", ss->ifid, 8);
    }
    if (ss->plmn != NULL)
        g5c_json_set(o, "plmn", g5c_json_dup(ss->plmn));
    if (ss->upf != NULL)
        g5c_json_set_str(o, "upf", smf_upf_name(ss->upf));
    h = hex64(ss->cp_seid);
    g5c_json_set_str(o, "cpSeid", h);
    free(h);
    h = hex64(ss->up_seid);
    g5c_json_set_str(o, "upSeid", h);
    free(h);
    g5c_json_set_int(o, "ulTeid", ss->ul_teid);
    g5c_json_set_int(o, "rsTeid", ss->rs_teid);
    g5c_json_set_int(o, "cpTeid", ss->cp_teid);
    set_hex(o, "ulIp4", ss->ul_ip4, 4);
    g5c_json_set_int(o, "state", ss->state);
    if (ss->an_set) {
        g5c_json *an = g5c_json_set(o, "an", g5c_json_new_obj());
        set_hex(an, "ip4", ss->an.ip4, 4);
        g5c_json_set_int(an, "teid", ss->an.teid);
    }
    if (ss->decision != NULL)
        g5c_json_set(o, "decision", g5c_json_dup(ss->decision));
    fl = g5c_json_set(o, "flows", g5c_json_new_arr());
    for (size_t i = 0; i < ss->pol.nflows; i++) {
        g5c_json *f = g5c_json_push(fl, g5c_json_new_obj());
        g5c_json_set_int(f, "qfi", ss->pol.flows[i].qfi);
        g5c_json_set_int(f, "qer", ss->pol.flows[i].qer_id);
    }
    ru = g5c_json_set(o, "rules", g5c_json_new_arr());
    for (size_t k = 0; k < ss->pol.nrules; k++) {
        g5c_json *r = g5c_json_push(ru, g5c_json_new_obj());
        g5c_json_set_int(r, "qri", ss->pol.rules[k].qri);
        g5c_json_set_int(r, "pdrUl", ss->pol.rules[k].pdr_ul);
        g5c_json_set_int(r, "pdrDl", ss->pol.rules[k].pdr_dl);
    }
    set_opt_str(o, "pcfResource", ss->pcf_resource);
    set_opt_str(o, "pcfNotif", ss->pcf_notif);
    set_opt_str(o, "amfStatusUri", ss->amf_status_uri);
    set_opt_str(o, "amfN1n2Url", ss->amf_n1n2_url);
    set_opt_str(o, "servingNfId", ss->serving_nf_id);
    g5c_json_set_bool(o, "udmRegistered", ss->udm_registered);
    return o;
}

static void save_now(smf *s)
{
    g5c_json *doc = g5c_json_new_obj(), *arr, *ups;
    smf_sess *ss;
    char (*refs)[37] = NULL;
    size_t n = 0, cap = 0;
    char *tmp, *txt;
    FILE *f;
    size_t len = 0;
    pthread_mutex_lock(&s->mu);
    for (ss = s->sessions; ss != NULL; ss = ss->next) {
        if (ss->dead)
            continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 64;
            refs = g5c_xrealloc(refs, cap * sizeof *refs);
        }
        memcpy(refs[n++], ss->ref, 37);
    }
    pthread_mutex_unlock(&s->mu);
    g5c_json_set_int(doc, "version", 1);
    if (s->n4 != NULL)
        g5c_json_set_int(doc, "cpRecovery", smf_n4_recovery(s->n4));
    ups = g5c_json_set(doc, "upfs", g5c_json_new_obj());
    for (size_t i = 0; s->n4 != NULL && i < smf_n4_nupfs(s->n4); i++) {
        smf_upf *u = smf_n4_upf(s->n4, i);
        uint32_t ts;
        if (smf_upf_recovery(u, &ts))
            g5c_json_set_int(ups, smf_upf_name(u), ts);
    }
    arr = g5c_json_set(doc, "sessions", g5c_json_new_arr());
    for (size_t i = 0; i < n; i++) {
        smf_sess *x = smf_sess_find_ref(s, refs[i]);
        if (x == NULL)
            continue;
        g5c_json_push(arr, snapshot(x));
        smf_sess_unlock(x);
    }
    free(refs);
    txt = g5c_json_to_string(doc, &len);
    g5c_json_free(doc);
    tmp = g5c_xasprintf("%s.tmp", s->state_file);
    f = fopen(tmp, "wb");
    if (f != NULL) {
        bool ok = fwrite(txt, 1, len, f) == len;
        ok = fflush(f) == 0 && ok;
        if (ok)
            (void)fsync(fileno(f));
        ok = fclose(f) == 0 && ok;
        if (!ok || rename(tmp, s->state_file) != 0) {
            G5C_LOGE("g5c_smf", "cannot write the state file %s: %s", s->state_file, strerror(errno));
            (void)unlink(tmp);
        }
    } else {
        G5C_LOGE("g5c_smf", "cannot write the state file %s: %s", tmp, strerror(errno));
    }
    free(tmp);
    free(txt);
}

static void job_persist(smf *s, void *arg)
{
    double t0 = g5c_now_seconds(), took;
    (void)arg;
    pthread_mutex_lock(&s->pmu);
    s->persist_queued = false;
    pthread_mutex_unlock(&s->pmu);
    save_now(s);
    /* the file is the whole table: keep its cost to about a tenth of a worker however large the table is */
    took = g5c_now_seconds() - t0;
    pthread_mutex_lock(&s->pmu);
    s->persist_gap_ms = took * 10000.0 < 25 ? 25 : took * 10000.0 > 5000 ? 5000 : (unsigned)(took * 10000.0);
    pthread_mutex_unlock(&s->pmu);
}

/* a graceful stop writes what a pending delayed write would have */
void smf_persist_flush(smf *s)
{
    bool pending;
    if (s->state_file == NULL || s->n4 == NULL)
        return;
    pthread_mutex_lock(&s->pmu);
    pending = s->persist_queued;
    s->persist_queued = false;
    pthread_mutex_unlock(&s->pmu);
    if (pending)
        save_now(s);
}

void smf_persist_request(smf *s)
{
    bool queue;
    unsigned gap;
    if (s->state_file == NULL || s->n4 == NULL)
        return;
    pthread_mutex_lock(&s->pmu);
    queue = !s->persist_queued;
    s->persist_queued = true;
    gap = s->persist_gap_ms != 0 ? s->persist_gap_ms : 25;
    pthread_mutex_unlock(&s->pmu);
    if (queue) /* write-behind: a burst of changes becomes one rewrite of the file */
        smf_defer_after(s, job_persist, NULL, gap);
}

/* ---- restore --------------------------------------------------------------------------------------------------------------------------------- */

g5c_json *smf_state_read(smf *s)
{
    size_t len = 0;
    char *txt = g5c_read_file(s->state_file, 256u << 20, &len), err[160];
    g5c_json *d;
    if (txt == NULL)
        return NULL; /* first run */
    d = g5c_json_parse(txt, len, err, sizeof err);
    free(txt);
    if (d == NULL || !g5c_json_is(d, G5C_J_OBJECT)) {
        G5C_LOGE("g5c_smf", "state file %s is unreadable (%s); starting empty", s->state_file, err);
        g5c_json_free(d);
        return NULL;
    }
    return d;
}

void smf_state_apply_recovery(smf *s, const g5c_json *doc)
{
    const g5c_json *ups = g5c_json_get(doc, "upfs");
    int64_t cp;
    if (g5c_json_get_int(doc, "cpRecovery", &cp) && cp > 0)
        smf_n4_set_recovery(s->n4, (uint32_t)cp);
    for (size_t i = 0; i < smf_n4_nupfs(s->n4); i++) {
        smf_upf *u = smf_n4_upf(s->n4, i);
        int64_t ts;
        if (g5c_json_get_int(ups, smf_upf_name(u), &ts) && ts > 0)
            smf_upf_set_known_recovery(u, (uint32_t)ts);
    }
}

static bool get_hex(const g5c_json *o, const char *key, uint8_t *out, size_t n)
{
    const char *h = g5c_json_get_str(o, key);
    return h != NULL && g5c_hex_decode(h, out, n) == (long)n;
}

size_t smf_state_apply_sessions(smf *s, const g5c_json *doc)
{
    const g5c_json *arr = g5c_json_get(doc, "sessions");
    size_t restored = 0;
    uint64_t max_seid = 0;
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const g5c_json *o = g5c_json_at(arr, i), *fl, *ru;
        smf_sess *ss;
        const char *ref = g5c_json_get_str(o, "ref"), *dnn = g5c_json_get_str(o, "dnn"), *upfn = g5c_json_get_str(o, "upf"), *supi = g5c_json_get_str(o, "supi");
        smf_dnn_cfg *dc;
        smf_upf *upf = NULL;
        int64_t v;
        char perr[200];
        if (ref == NULL || dnn == NULL || upfn == NULL || supi == NULL || strlen(ref) != 36 || strlen(supi) >= sizeof ss->supi || strlen(dnn) >= sizeof ss->dnn)
            continue;
        dc = smf_find_dnn(s, dnn);
        for (size_t k = 0; k < smf_n4_nupfs(s->n4); k++)
            if (strcmp(smf_upf_name(smf_n4_upf(s->n4, k)), upfn) == 0)
                upf = smf_n4_upf(s->n4, k);
        if (dc == NULL || upf == NULL) {
            G5C_LOGW("g5c_smf", "dropping the saved session %s: its DNN or UPF is no longer configured", ref);
            continue;
        }
        ss = g5c_xcalloc(1, sizeof *ss);
        pthread_mutex_init(&ss->mu, NULL);
        ss->owner = s;
        ss->refs = 1;
        memcpy(ss->ref, ref, 37);
        snprintf(ss->supi, sizeof ss->supi, "%s", supi);
        snprintf(ss->dnn, sizeof ss->dnn, "%s", dnn);
        ss->dcfg = dc;
        ss->upf = upf;
        if (g5c_json_get_int(o, "psi", &v))
            ss->psi = (uint8_t)v;
        if (g5c_json_get_int(o, "pti", &v))
            ss->pti = (uint8_t)v;
        if (g5c_json_get_int(o, "sst", &v))
            ss->sst = (uint8_t)v;
        if (g5c_json_get_int(o, "sd", &v)) {
            ss->has_sd = true;
            ss->sd = (uint32_t)v;
        }
        if (g5c_json_get_int(o, "pduType", &v))
            ss->pdu_type = (uint8_t)v;
        if (g5c_json_get_int(o, "sscMode", &v))
            ss->ssc_mode = (uint8_t)v;
        if (g5c_json_get_int(o, "acceptCause", &v))
            ss->accept_cause = (uint8_t)v;
        {
            bool b;
            if (g5c_json_get_bool(o, "pcoDns4", &b))
                ss->req.pco_dns4 = b;
            if (g5c_json_get_bool(o, "pcoDns6", &b))
                ss->req.pco_dns6 = b;
            if (g5c_json_get_bool(o, "pcoMtu", &b))
                ss->req.pco_mtu = b;
            if (g5c_json_get_bool(o, "udmRegistered", &b))
                ss->udm_registered = b;
        }
        ss->has4 = get_hex(o, "ue4", ss->ue4, 4);
        ss->has6 = get_hex(o, "ue6", ss->ue6, 8);
        (void)get_hex(o, "ifid", ss->ifid, 8);
        if (ss->has4)
            ss->has4 = smf_pool_reserve4(dc->pool, ss->ue4);
        if (ss->has6)
            ss->has6 = smf_pool_reserve6(dc->pool, ss->ue6);
        if (g5c_json_is(g5c_json_get(o, "plmn"), G5C_J_OBJECT))
            ss->plmn = g5c_json_dup(g5c_json_get(o, "plmn"));
        ss->cp_seid = unhex64(g5c_json_get_str(o, "cpSeid"));
        ss->up_seid = unhex64(g5c_json_get_str(o, "upSeid"));
        if (ss->cp_seid > max_seid)
            max_seid = ss->cp_seid;
        if (g5c_json_get_int(o, "ulTeid", &v))
            ss->ul_teid = (uint32_t)v;
        (void)get_hex(o, "ulIp4", ss->ul_ip4, 4);
        if (g5c_json_get_int(o, "rsTeid", &v))
            ss->rs_teid = (uint32_t)v;
        if (g5c_json_get_int(o, "cpTeid", &v))
            ss->cp_teid = (uint32_t)v;
        if (g5c_json_get_int(o, "state", &v) && v >= 0 && v <= SMF_S_RELEASING)
            ss->state = (smf_state)v;
        if (g5c_json_is(g5c_json_get(o, "an"), G5C_J_OBJECT)) {
            const g5c_json *an = g5c_json_get(o, "an");
            ss->an_set = get_hex(an, "ip4", ss->an.ip4, 4);
            ss->an.v4 = ss->an_set;
            if (g5c_json_get_int(an, "teid", &v))
                ss->an.teid = (uint32_t)v;
        }
        if (g5c_json_is(g5c_json_get(o, "decision"), G5C_J_OBJECT)) {
            ss->decision = g5c_json_dup(g5c_json_get(o, "decision"));
            if (smf_policy_from_decision(ss->decision, &ss->pol, perr, sizeof perr) != 0) {
                G5C_LOGW("g5c_smf", "dropping the saved session %s: its policy no longer parses (%s)", ref, perr);
                goto drop;
            }
            fl = g5c_json_get(o, "flows");
            for (size_t k = 0; k < ss->pol.nflows && k < g5c_json_len(fl); k++) {
                if (g5c_json_get_int(g5c_json_at(fl, k), "qfi", &v))
                    ss->pol.flows[k].qfi = (uint8_t)v;
                if (g5c_json_get_int(g5c_json_at(fl, k), "qer", &v))
                    ss->pol.flows[k].qer_id = (uint32_t)v;
            }
            ru = g5c_json_get(o, "rules");
            for (size_t k = 0; k < ss->pol.nrules && k < g5c_json_len(ru); k++) {
                if (g5c_json_get_int(g5c_json_at(ru, k), "qri", &v))
                    ss->pol.rules[k].qri = (uint8_t)v;
                if (g5c_json_get_int(g5c_json_at(ru, k), "pdrUl", &v))
                    ss->pol.rules[k].pdr_ul = (uint16_t)v;
                if (g5c_json_get_int(g5c_json_at(ru, k), "pdrDl", &v))
                    ss->pol.rules[k].pdr_dl = (uint16_t)v;
                ss->pol.rules[k].qfi = ss->pol.flows[ss->pol.rules[k].flow].qfi;
            }
        } else {
            goto drop;
        }
        if (g5c_json_get_str(o, "pcfResource") != NULL)
            ss->pcf_resource = g5c_xstrdup(g5c_json_get_str(o, "pcfResource"));
        if (g5c_json_get_str(o, "pcfNotif") != NULL)
            ss->pcf_notif = g5c_xstrdup(g5c_json_get_str(o, "pcfNotif"));
        if (g5c_json_get_str(o, "amfStatusUri") != NULL)
            ss->amf_status_uri = g5c_xstrdup(g5c_json_get_str(o, "amfStatusUri"));
        if (g5c_json_get_str(o, "amfN1n2Url") != NULL)
            ss->amf_n1n2_url = g5c_xstrdup(g5c_json_get_str(o, "amfN1n2Url"));
        if (g5c_json_get_str(o, "servingNfId") != NULL)
            ss->serving_nf_id = g5c_xstrdup(g5c_json_get_str(o, "servingNfId"));
        pthread_mutex_lock(&s->mu);
        ss->next = s->sessions;
        s->sessions = ss;
        s->nsessions++;
        smf_ix_add(s, ss);
        pthread_mutex_unlock(&s->mu);
        restored++;
        continue;
    drop:
        if (ss->has4)
            smf_pool_release4(dc->pool, ss->ue4);
        if (ss->has6)
            smf_pool_release6(dc->pool, ss->ue6);
        smf_policy_free(&ss->pol);
        g5c_json_free(ss->decision);
        g5c_json_free(ss->plmn);
        pthread_mutex_destroy(&ss->mu);
        free(ss);
    }
    if (max_seid != 0)
        smf_n4_seed_seid(s->n4, max_seid + 1);
    return restored;
}
