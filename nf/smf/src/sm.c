/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* nsmf-pdusession (TS 29.502 clause 5.2.2): Create SM Context, Update SM Context, Release SM Context.
 *
 * Establishment (TS 23.502 4.3.2.2.1): the AMF posts the PDU Session Establishment Request as an N1 SM binary part. The SMF checks the
 * subscription (UDM), selects a UPF, allocates the UE address, registers with the UDM, creates the SM policy association (PCF),
 * establishes the N4 session, and answers 201 with the SM context reference. The accept (N1) and the N2 resource setup request travel
 * afterwards in an N1N2MessageTransfer to the AMF, from the deferred-work thread. The AMF later reports the gNB's tunnel in an
 * Update SM Context (PDU_RES_SETUP_RSP), which turns the downlink FAR from DROP to FORW. */
#define _DEFAULT_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "g5c/nas.h"
#include "priv.h"

#define BASE "/nsmf-pdusession/v1"
#define N1_ID "n1SmMsg"
#define N2_ID "n2SmInfo"

/* ---- metrics ---- */

static void count_op(smf *s, const char *op, const char *result)
{
    g5c_label l[2] = {{"op", op}, {"result", result}};
    g5c_counter_inc(g5c_counter_get(s->metrics, "g5c_smf_sm_context_requests_total", "Nsmf_PDUSession requests by operation and result.", l, 2));
}

static void update_gauge(smf *s)
{
    g5c_gauge_set(g5c_gauge_get(s->metrics, "g5c_smf_pdu_sessions_active", "PDU sessions held by the SMF.", NULL, 0), (int64_t)smf_session_count(s));
    {   /* the sessions per slice (the labels of a slice that once had sessions stay, at zero) */
        struct {
            uint8_t sst;
            bool has_sd;
            uint32_t sd;
            int64_t n;
        } cnt[16];
        unsigned nc = 0;
        pthread_mutex_lock(&s->mu);
        for (unsigned k = 0; k < s->nslice_seen && nc < 16; k++) {
            cnt[nc].sst = s->slice_seen[k].sst;
            cnt[nc].has_sd = s->slice_seen[k].has_sd;
            cnt[nc].sd = s->slice_seen[k].sd;
            cnt[nc++].n = 0;
        }
        for (const smf_sess *o = s->sessions; o != NULL; o = o->next) {
            unsigned k = 0;
            if (o->dead)
                continue;
            while (k < nc && !(cnt[k].sst == o->sst && cnt[k].has_sd == o->has_sd && (!o->has_sd || cnt[k].sd == o->sd)))
                k++;
            if (k == nc && nc < 16) {
                cnt[nc].sst = o->sst;
                cnt[nc].has_sd = o->has_sd;
                cnt[nc].sd = o->sd;
                cnt[nc++].n = 0;
            }
            if (k < nc)
                cnt[k].n++;
        }
        s->nslice_seen = 0;
        for (unsigned k = 0; k < nc; k++) {
            s->slice_seen[k].sst = cnt[k].sst;
            s->slice_seen[k].has_sd = cnt[k].has_sd;
            s->slice_seen[k].sd = cnt[k].sd;
            s->nslice_seen++;
        }
        pthread_mutex_unlock(&s->mu);
        for (unsigned k = 0; k < nc; k++) {
            char sn[24];
            g5c_label l = {"snssai", sn};
            if (cnt[k].has_sd)
                snprintf(sn, sizeof sn, "%u-%06X", cnt[k].sst, cnt[k].sd);
            else
                snprintf(sn, sizeof sn, "%u", cnt[k].sst);
            g5c_gauge_set(g5c_gauge_get(s->metrics, "g5c_smf_pdu_sessions_by_slice", "PDU sessions held by the SMF, per S-NSSAI.", &l, 1), cnt[k].n);
        }
    }
    if (s->ndnns > 0)
        for (size_t i = 0; i < s->ndnns; i++) {
            g5c_label l = {"dnn", s->dnns[i].dnn};
            g5c_gauge_set(g5c_gauge_get(s->metrics, "g5c_smf_ue_addresses_in_use", "UE IPv4 addresses allocated, per DNN.", &l, 1),
                          smf_pool_has4(s->dnns[i].pool) ? (int64_t)smf_pool_used4(s->dnns[i].pool) : 0);
        }
}

/* ---- deferred work ---- */

struct smf_job {
    smf_job_fn fn;
    void *arg;
    double due; /* monotonic seconds; 0: immediately */
    struct smf_job *next;
};

static void *worker_main(void *a)
{
    smf *s = a;
    pthread_mutex_lock(&s->qmu);
    for (;;) {
        double now = g5c_now_seconds(), min_due = 0;
        struct smf_job **pp, *j = NULL;
        for (pp = &s->jobs; *pp != NULL; pp = &(*pp)->next) {
            if ((*pp)->due <= now) {
                j = *pp;
                *pp = j->next;
                break;
            }
            if (min_due == 0 || (*pp)->due < min_due)
                min_due = (*pp)->due;
        }
        if (j != NULL) {
            s->jobs_tail = NULL;
            for (struct smf_job *t = s->jobs; t != NULL; t = t->next)
                s->jobs_tail = t;
            s->running++;
            pthread_mutex_unlock(&s->qmu);
            j->fn(s, j->arg);
            free(j);
            pthread_mutex_lock(&s->qmu);
            s->running--;
            pthread_cond_broadcast(&s->qcv);
            continue;
        }
        if (s->stop)
            break;
        if (min_due > 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            {
                double wait = g5c_real_wait(min_due - now);
                ts.tv_sec += (time_t)wait;
                ts.tv_nsec += (long)((wait - (double)(time_t)wait) * 1e9);
                if (ts.tv_nsec >= 1000000000L) {
                    ts.tv_sec++;
                    ts.tv_nsec -= 1000000000L;
                }
            }
            pthread_cond_timedwait(&s->qcv, &s->qmu, &ts);
        } else {
            pthread_cond_wait(&s->qcv, &s->qmu);
        }
    }
    pthread_mutex_unlock(&s->qmu);
    return NULL;
}

/* a pool: the deferred jobs make HTTP and PFCP calls, one thread for all of them capped the SMF at the rate of one blocking call at a time */
void smf_worker_start(smf *s)
{
    unsigned want = s->want_workers != 0 ? s->want_workers : 1;
    if (s->worker_started)
        return;
    if (want > SMF_MAX_WORKERS)
        want = SMF_MAX_WORKERS;
    for (unsigned i = 0; i < want; i++)
        if (pthread_create(&s->workers[s->nworkers], NULL, worker_main, s) == 0)
            s->nworkers++;
    s->worker_started = s->nworkers > 0;
}

void smf_worker_stop(smf *s)
{
    if (!s->worker_started)
        return;
    pthread_mutex_lock(&s->qmu);
    s->stop = true;
    pthread_cond_broadcast(&s->qcv);
    pthread_mutex_unlock(&s->qmu);
    for (unsigned i = 0; i < s->nworkers; i++)
        pthread_join(s->workers[i], NULL);
    s->nworkers = 0;
    s->worker_started = false;
    while (s->jobs != NULL) { /* jobs that never ran (delayed ones at shutdown) */
        struct smf_job *j = s->jobs;
        s->jobs = j->next;
        free(j->arg);
        free(j);
    }
    s->jobs_tail = NULL;
}

void smf_defer_after(smf *s, smf_job_fn fn, void *arg, unsigned delay_ms)
{
    struct smf_job *j = g5c_xcalloc(1, sizeof *j);
    j->fn = fn;
    j->arg = arg;
    j->due = delay_ms > 0 ? g5c_now_seconds() + (double)delay_ms / 1000.0 : 0;
    pthread_mutex_lock(&s->qmu);
    if (s->jobs_tail != NULL)
        s->jobs_tail->next = j;
    else
        s->jobs = j;
    s->jobs_tail = j;
    pthread_cond_broadcast(&s->qcv);
    pthread_mutex_unlock(&s->qmu);
}

void smf_defer(smf *s, smf_job_fn fn, void *arg)
{
    smf_defer_after(s, fn, arg, 0);
}

/* waits until nothing is running and nothing is due; jobs scheduled for later (release guards) do not hold it up */
void smf_drain(smf *s)
{
    pthread_mutex_lock(&s->qmu);
    for (;;) {
        bool ready = false;
        double now = g5c_now_seconds();
        for (struct smf_job *j = s->jobs; j != NULL; j = j->next)
            ready = ready || j->due <= now;
        if (!ready && s->running == 0)
            break;
        pthread_cond_wait(&s->qcv, &s->qmu);
    }
    pthread_mutex_unlock(&s->qmu);
}

/* ---- session table ---- */

size_t smf_session_count(smf *s)
{
    size_t n;
    pthread_mutex_lock(&s->mu);
    n = s->nsessions;
    pthread_mutex_unlock(&s->mu);
    return n;
}

static void sess_free(smf_sess *ss)
{
    smf_policy_free(&ss->pol);
    g5c_json_free(ss->decision);
    free(ss->pcf_resource);
    free(ss->chf_resource);
    free(ss->pcf_notif);
    free(ss->amf_status_uri);
    free(ss->amf_n1n2_url);
    free(ss->serving_nf_id);
    g5c_json_free(ss->plmn);
    pthread_mutex_destroy(&ss->mu);
    free(ss);
}

static void sess_unref(smf *s, smf_sess *ss)
{
    bool last;
    pthread_mutex_lock(&s->mu);
    last = --ss->refs == 0 && ss->dead;
    pthread_mutex_unlock(&s->mu);
    if (last)
        sess_free(ss);
}

void smf_sess_unlock(smf_sess *ss)
{
    smf *s = ss->owner;
    pthread_mutex_unlock(&ss->mu);
    sess_unref(s, ss);
}

/* Returns the session locked and referenced, or NULL. ref == NULL: look up by (supi, psi). */
/* the session table is a list (scans, persistence) with two hash indexes on top */
static uint32_t ix_hash(const char *a, uint8_t psi)
{
    uint32_t h = 2166136261u;
    for (; *a != 0; a++)
        h = (h ^ (uint8_t)*a) * 16777619u;
    return ((h ^ psi) * 16777619u) % SMF_IX;
}

void smf_ix_add(smf *s, smf_sess *ss) /* caller holds s->mu */
{
    uint32_t r, k;
    if (s->ix_ref == NULL) {
        s->ix_ref = g5c_xcalloc(SMF_IX, sizeof *s->ix_ref);
        s->ix_key = g5c_xcalloc(SMF_IX, sizeof *s->ix_key);
    }
    r = ix_hash(ss->ref, 0);
    k = ix_hash(ss->supi, ss->psi);
    ss->ix_ref_next = s->ix_ref[r];
    s->ix_ref[r] = ss;
    ss->ix_key_next = s->ix_key[k];
    s->ix_key[k] = ss;
}

static void ix_del(smf *s, smf_sess *ss) /* caller holds s->mu */
{
    smf_sess **pp;
    if (s->ix_ref == NULL)
        return;
    for (pp = &s->ix_ref[ix_hash(ss->ref, 0)]; *pp != NULL; pp = &(*pp)->ix_ref_next)
        if (*pp == ss) {
            *pp = ss->ix_ref_next;
            break;
        }
    for (pp = &s->ix_key[ix_hash(ss->supi, ss->psi)]; *pp != NULL; pp = &(*pp)->ix_key_next)
        if (*pp == ss) {
            *pp = ss->ix_key_next;
            break;
        }
}

static smf_sess *sess_lookup(smf *s, const char *ref, const char *supi, uint8_t psi)
{
    smf_sess *ss = NULL;
    pthread_mutex_lock(&s->mu);
    if (s->ix_ref != NULL) {
        if (ref != NULL) {
            for (ss = s->ix_ref[ix_hash(ref, 0)]; ss != NULL; ss = ss->ix_ref_next)
                if (!ss->dead && strcmp(ss->ref, ref) == 0)
                    break;
        } else {
            for (ss = s->ix_key[ix_hash(supi, psi)]; ss != NULL; ss = ss->ix_key_next)
                if (!ss->dead && ss->psi == psi && strcmp(ss->supi, supi) == 0)
                    break;
        }
    }
    if (ss != NULL)
        ss->refs++;
    pthread_mutex_unlock(&s->mu);
    if (ss == NULL)
        return NULL;
    pthread_mutex_lock(&ss->mu);
    if (ss->dead) {
        smf_sess_unlock(ss);
        return NULL;
    }
    return ss;
}

smf_sess *smf_sess_find_ref(smf *s, const char *ref)
{
    return sess_lookup(s, ref, NULL, 0);
}

static void sess_insert(smf *s, smf_sess *ss)
{
    pthread_mutex_lock(&s->mu);
    ss->next = s->sessions;
    s->sessions = ss;
    s->nsessions++;
    smf_ix_add(s, ss);
    pthread_mutex_unlock(&s->mu);
}

/* Remove from the table and drop the caller's lock and reference; the memory is freed when the last reference goes. */
static void sess_remove_and_unlock(smf *s, smf_sess *ss)
{
    smf_sess **pp;
    pthread_mutex_lock(&s->mu);
    for (pp = &s->sessions; *pp != NULL; pp = &(*pp)->next)
        if (*pp == ss) {
            *pp = ss->next;
            ix_del(s, ss);
            s->nsessions--;
            ss->refs--; /* the table no longer refers to it */
            break;
        }
    ss->dead = true;
    pthread_mutex_unlock(&s->mu);
    smf_sess_unlock(ss);
    smf_persist_request(s);
}

smf_dnn_cfg *smf_find_dnn(smf *s, const char *dnn)
{
    for (size_t i = 0; i < s->ndnns; i++)
        if (strcmp(s->dnns[i].dnn, dnn) == 0)
            return &s->dnns[i];
    return NULL;
}

/* Everything the session holds elsewhere is given back. Called with the session locked; the lock and reference are dropped. */
static void sess_teardown(smf *s, smf_sess *ss, const char *why)
{
    smf_n4_msg r;
    smf_usage usage, cusage;
    memset(&usage, 0, sizeof usage);
    memset(&cusage, 0, sizeof cusage);
    G5C_LOGI("g5c_smf", "releasing PDU session %u of %s (%s)", ss->psi, ss->supi, why);
    if (ss->upf != NULL && ss->up_seid != 0) {
        if (smf_n4_call(s->n4, ss->upf, PFCP_SESSION_DELETION_REQUEST, true, ss->up_seid, NULL, 0, &r) != 0)
            G5C_LOGW("g5c_smf", "N4 session deletion for %s/%u got no answer; the UPF will clean up on its own", ss->supi, ss->psi);
        else if (smf_n4_cause_of(&r) != PFCP_CAUSE_ACCEPTED)
            G5C_LOGW("g5c_smf", "N4 session deletion for %s/%u refused with cause %u", ss->supi, ss->psi, smf_n4_cause_of(&r));
        else {
            (void)smf_n4_parse_usage(&r, &usage);
            if (ss->chf_resource != NULL) /* what is left under the last quota: the earlier quotas were reported as they were used up */
                (void)smf_n4_parse_usage_for(r.body, r.blen, SMF_URR_CHARGING, &cusage);
        }
    }
    if (ss->up_seid != 0) /* a session that never reached the UPF has no record */
        smf_cdr_write(s, ss, &usage, why);
    if (ss->chf_resource != NULL)
        smf_chf_release(s, ss, &cusage);
    if (ss->pcf_resource != NULL)
        smf_pcf_delete(s, ss->pcf_resource);
    if (ss->udm_registered)
        (void)smf_udm_deregister(s, ss->supi, ss->psi);
    if (ss->dcfg != NULL) {
        if (ss->has4)
            smf_pool_release4(ss->dcfg->pool, ss->ue4);
        if (ss->has6)
            smf_pool_release6(ss->dcfg->pool, ss->ue6);
    }
    atomic_fetch_add(&s->released, 1);
    sess_remove_and_unlock(s, ss);
    update_gauge(s);
}

/* ---- request parsing ---- */

typedef struct {
    g5c_mp mp;
    bool is_mp;
    g5c_json *json;
    const g5c_mp_part *n1, *n2;
} parsed_req;

static void parsed_free(parsed_req *p)
{
    g5c_json_free(p->json);
    if (p->is_mp)
        g5c_mp_free(&p->mp);
    memset(p, 0, sizeof *p);
}

/* JSON part plus the binary parts named by the JSON's n1SmMsg / n2SmInfo references. false: resp is a 400/415. */
static bool parse_request(const g5c_req *req, parsed_req *p, g5c_resp *resp, bool need_body)
{
    const char *ct = g5c_req_header(req, "content-type");
    char err[160];
    const uint8_t *jd;
    size_t jl;
    const g5c_json *ref;
    memset(p, 0, sizeof *p);
    if (ct != NULL && g5c_mp_is_multipart(ct)) {
        p->is_mp = true;
        if (g5c_mp_parse(ct, req->body, req->body_len, &p->mp) != 0 || p->mp.n == 0) {
            g5c_resp_problem_simple(resp, 400, "INVALID_MSG_FORMAT", "malformed multipart/related body");
            p->is_mp = false;
            return false;
        }
        if (p->mp.parts[0].content_type == NULL || strncasecmp(p->mp.parts[0].content_type, "application/json", 16) != 0) {
            g5c_resp_problem_simple(resp, 400, "INVALID_MSG_FORMAT", "the first part must be application/json");
            g5c_mp_free(&p->mp);
            p->is_mp = false;
            return false;
        }
        jd = p->mp.parts[0].data;
        jl = p->mp.parts[0].len;
    } else {
        if (req->body_len == 0) {
            if (!need_body) {
                p->json = g5c_json_new_obj();
                return true;
            }
            g5c_resp_problem_simple(resp, 400, "MANDATORY_IE_MISSING", "empty request body");
            return false;
        }
        if (ct != NULL && strncasecmp(ct, "application/json", 16) != 0) {
            g5c_resp_problem_simple(resp, 415, "UNSUPPORTED_MEDIA_TYPE", "expected application/json or multipart/related");
            return false;
        }
        jd = req->body;
        jl = req->body_len;
    }
    p->json = g5c_json_parse((const char *)jd, jl, err, sizeof err);
    if (p->json == NULL || !g5c_json_is(p->json, G5C_J_OBJECT)) {
        g5c_resp_problem_simple(resp, 400, "INVALID_MSG_FORMAT", "the JSON part is not a JSON object");
        parsed_free(p);
        return false;
    }
    if (p->is_mp) {
        ref = g5c_json_get(p->json, "n1SmMsg");
        if (ref != NULL) {
            p->n1 = g5c_mp_find(&p->mp, g5c_json_get_str(ref, "contentId"));
            if (p->n1 == NULL) {
                g5c_resp_problem_invalid(resp, 400, "INVALID_MSG_FORMAT", "n1SmMsg", "no part with that contentId");
                parsed_free(p);
                return false;
            }
        }
        ref = g5c_json_get(p->json, "n2SmInfo");
        if (ref != NULL) {
            p->n2 = g5c_mp_find(&p->mp, g5c_json_get_str(ref, "contentId"));
            if (p->n2 == NULL) {
                g5c_resp_problem_invalid(resp, 400, "INVALID_MSG_FORMAT", "n2SmInfo", "no part with that contentId");
                parsed_free(p);
                return false;
            }
        }
    }
    return true;
}

/* A response of JSON plus optional N1 and N2 binary parts. */
static void reply_parts(g5c_resp *resp, int status, const g5c_json *j, const uint8_t *n1, size_t n1len, const uint8_t *n2, size_t n2len)
{
    g5c_mp_part parts[3];
    size_t np = 1;
    char *jt = g5c_json_to_string(j, NULL), *ct = NULL;
    g5c_bytes body;
    if (n1len == 0 && n2len == 0) {
        g5c_resp_json(resp, status, j);
        free(jt);
        return;
    }
    parts[0] = (g5c_mp_part){NULL, "application/json", (const uint8_t *)jt, strlen(jt)};
    if (n1len > 0)
        parts[np++] = (g5c_mp_part){N1_ID, "application/vnd.3gpp.5gnas", n1, n1len};
    if (n2len > 0)
        parts[np++] = (g5c_mp_part){N2_ID, "application/vnd.3gpp.ngap", n2, n2len};
    g5c_bytes_init(&body);
    if (g5c_mp_build(parts, np, &body, &ct) == 0)
        g5c_resp_content(resp, status, ct, body.data, body.len);
    else
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot build the response");
    g5c_bytes_free(&body);
    free(ct);
    free(jt);
}

/* SmContextCreateError: the ProblemDetails plus the PDU Session Establishment Reject for the UE. */
static void create_error(smf *s, g5c_resp *resp, int status, const char *cause, const char *detail, uint8_t psi, uint8_t pti, uint8_t gsm_cause)
{
    g5c_json *j = g5c_json_new_obj(), *e = g5c_json_set(j, "error", g5c_json_new_obj());
    g5c_bytes n1;
    g5c_json_set_int(e, "status", status);
    g5c_json_set_str(e, "title", detail);
    g5c_json_set_str(e, "cause", cause);
    g5c_bytes_init(&n1);
    if (pti != 0 && psi != 0 && smf_gsm_build_est_reject(psi, pti, gsm_cause, &n1) == 0)
        g5c_json_set_str(g5c_json_set(j, "n1SmMsg", g5c_json_new_obj()), "contentId", N1_ID);
    reply_parts(resp, status, j, n1.data, n1.len, NULL, 0);
    /* an error body is problem+json by convention only when it is plain JSON */
    g5c_bytes_free(&n1);
    g5c_json_free(j);
    atomic_fetch_add(&s->rejected, 1);
}

/* ---- Create SM Context ---- */

bool smf_parse_snssai(const g5c_json *j, uint8_t *sst, bool *has_sd, uint32_t *sd)
{
    int64_t v;
    const char *sdt;
    char *end;
    if (!g5c_json_get_int(j, "sst", &v) || v < 0 || v > 255)
        return false;
    *sst = (uint8_t)v;
    sdt = g5c_json_get_str(j, "sd");
    *has_sd = sdt != NULL;
    *sd = 0;
    if (sdt != NULL) {
        unsigned long u;
        if (strlen(sdt) != 6)
            return false;
        u = strtoul(sdt, &end, 16);
        if (*end != 0)
            return false;
        *sd = (uint32_t)u;
    }
    return true;
}

static bool valid_supi(const char *s)
{
    size_t n = s != NULL ? strlen(s) : 0;
    if (n < 6 || n > 63)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && s[i] != '-' && s[i] != '_' && s[i] != '.')
            return false;
    return true;
}

static uint8_t type_from_name(const char *n)
{
    if (g5c_streq(n, "IPV4"))
        return 1;
    if (g5c_streq(n, "IPV6"))
        return 2;
    if (g5c_streq(n, "IPV4V6"))
        return 3;
    return 0;
}

/* PDU session type selection (TS 23.501 5.8.1.2, TS 24.501 6.4.1.2) */
static uint8_t select_type(const g5c_json *cfg, uint8_t requested, const smf_dnn_cfg *d, uint8_t *cause)
{
    const g5c_json *pst = g5c_json_get(cfg, "pduSessionTypes"), *allowed = g5c_json_get(pst, "allowedSessionTypes");
    bool ok[4] = {false, false, false, false};
    uint8_t def = type_from_name(g5c_json_get_str(pst, "defaultSessionType"));
    *cause = 0;
    if (g5c_json_len(allowed) == 0 && def != 0)
        ok[def] = true;
    for (size_t i = 0; i < g5c_json_len(allowed); i++) {
        uint8_t t = type_from_name(g5c_json_str(g5c_json_at(allowed, i)));
        if (t != 0)
            ok[t] = true;
    }
    ok[1] = ok[1] && smf_pool_has4(d->pool);
    ok[2] = ok[2] && smf_pool_has6(d->pool);
    ok[3] = ok[3] && smf_pool_has4(d->pool) && smf_pool_has6(d->pool);
    if (requested == 0)
        requested = def != 0 ? def : 1;
    if (requested >= 1 && requested <= 3 && ok[requested])
        return requested;
    if (requested == 3) { /* dual stack asked for: give what is allowed and say so */
        if (ok[1]) {
            *cause = SMF_5GSM_PDU_TYPE_IPV4_ONLY;
            return 1;
        }
        if (ok[2]) {
            *cause = SMF_5GSM_PDU_TYPE_IPV6_ONLY;
            return 2;
        }
    }
    return 0;
}

/* scheme://authority of a URI, or NULL */
static char *api_root(const char *uri)
{
    const char *p = uri != NULL ? strstr(uri, "://") : NULL, *e;
    if (p == NULL)
        return NULL;
    e = strchr(p + 3, '/');
    return e != NULL ? g5c_xstrndup(uri, (size_t)(e - uri)) : g5c_xstrdup(uri);
}

typedef struct {
    char ref[37];
} job_ref;

static void job_n1n2(smf *s, void *arg);

/* Give back everything a session that never reached the table holds. The session is still private to the handler. */
static void create_abort(smf *s, smf_sess *ss)
{
    if (ss->up_seid != 0 && ss->upf != NULL) {
        smf_n4_msg dr;
        (void)smf_n4_call(s->n4, ss->upf, PFCP_SESSION_DELETION_REQUEST, true, ss->up_seid, NULL, 0, &dr);
    }
    if (ss->chf_resource != NULL)
        smf_chf_release(s, ss, NULL);
    if (ss->pcf_resource != NULL)
        smf_pcf_delete(s, ss->pcf_resource);
    if (ss->udm_registered)
        (void)smf_udm_deregister(s, ss->supi, ss->psi);
    if (ss->dcfg != NULL) {
        if (ss->has4)
            smf_pool_release4(ss->dcfg->pool, ss->ue4);
        if (ss->has6)
            smf_pool_release6(ss->dcfg->pool, ss->ue6);
    }
    sess_free(ss);
}

#define REJECT(http, cause, detail, gsm, result)                                                                                           \
    do {                                                                                                                                   \
        create_error(s, resp, (http), (cause), (detail), psi8, pti8, (gsm));                                                               \
        count_op(s, "create", (result));                                                                                                   \
        goto abort;                                                                                                                        \
    } while (0)

static void create_ctx(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    smf *s = ctx;
    parsed_req pr;
    smf_est_req er;
    smf_sess *ss = NULL, *old;
    smf_dnn_cfg *dcfg;
    const char *supi, *dnn, *rt, *status_uri;
    g5c_json *cfg = NULL, *decision = NULL;
    const g5c_json *plmn;
    uint8_t sst = 0, accept_cause = 0, psi8 = 0, pti8 = 0;
    bool has_sd = false;
    uint32_t sd = 0;
    int64_t psi = 0;
    int rc, gc;
    char *resource = NULL, *notif = NULL, *root, *path, *loc;
    smf_n4_est est;
    uint8_t body[2048];
    size_t blen;
    smf_n4_msg r;
    smf_n4_est_rsp er2;
    double t0 = g5c_now_seconds();

    if (!parse_request(req, &pr, resp, true)) {
        count_op(s, "create", "bad_request");
        return;
    }
    supi = g5c_json_get_str(pr.json, "supi");
    if (!valid_supi(supi)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "supi", "missing or malformed");
        goto bad;
    }
    for (unsigned k = 0; k < s->ninject_reject; k++) /* failure injection (smf.inject) */
        if (strncmp(supi, s->inject_reject[k].supi, strlen(s->inject_reject[k].supi)) == 0) {
            G5C_LOGW("g5c_smf", "%s: Create SM Context refused with %d on purpose (smf.inject)", supi, s->inject_reject[k].status);
            g5c_counter_inc(g5c_counter_get(s->metrics, "g5c_smf_injected_total", "Failures injected on purpose (smf.inject), by kind.", &(g5c_label){"kind", "pdu_session_reject"}, 1));
            g5c_resp_problem_simple(resp, s->inject_reject[k].status, "INJECTED_FAILURE", "refused on purpose (smf.inject)");
            goto bad;
        }
    if (!g5c_json_get_int(pr.json, "pduSessionId", &psi) || psi < 1 || psi > 15) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "pduSessionId", "must be 1..=15");
        goto bad;
    }
    if (pr.n1 == NULL) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", "n1SmMsg", "the PDU Session Establishment Request is required");
        goto bad;
    }
    if (!smf_parse_snssai(g5c_json_get(pr.json, "sNssai"), &sst, &has_sd, &sd)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "sNssai", "missing or malformed");
        goto bad;
    }
    rt = g5c_json_get_str(pr.json, "requestType");
    if (rt != NULL && strcmp(rt, "INITIAL_REQUEST") != 0) {
        g5c_resp_problem_invalid(resp, 501, "UNSUPPORTED_REQUEST_TYPE", "requestType", "only INITIAL_REQUEST is supported");
        goto bad;
    }
    status_uri = g5c_json_get_str(pr.json, "smContextStatusUri");
    if (s->amf == NULL && s->nrf == NULL) {
        char *probe = api_root(status_uri);
        if (probe == NULL) {
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", "smContextStatusUri", "needed to reach the AMF");
            goto bad;
        }
        free(probe);
    }
    dnn = g5c_json_get_str(pr.json, "dnn");
    if (dnn == NULL)
        dnn = g5c_json_get_str(pr.json, "selectedDnn");
    if (dnn == NULL && s->ndnns > 0)
        dnn = s->dnns[0].dnn;
    plmn = g5c_json_get(pr.json, "servingNetwork");

    {
        uint8_t mt;
        if (smf_gsm_peek(pr.n1->data, pr.n1->len, &mt, &psi8, &pti8) != 0) {
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "n1SmMsg", "not a 5GSM message");
            goto bad;
        }
        if (psi8 != (uint8_t)psi) {
            g5c_resp_problem_simple(resp, 400, "MANDATORY_IE_INCORRECT", "the PDU session id of the NAS message and of the request differ");
            goto bad;
        }
    }
    gc = smf_gsm_parse_est_req(pr.n1->data, pr.n1->len, &er);
    if (gc != 0)
        REJECT(400, "INVALID_MSG_FORMAT", "malformed PDU Session Establishment Request", (uint8_t)gc, "rejected");
    pti8 = er.pti;
    dcfg = dnn != NULL ? smf_find_dnn(s, dnn) : NULL;
    if (dcfg == NULL)
        REJECT(403, "DNN_DENIED", "unknown DNN", SMF_5GSM_MISSING_OR_UNKNOWN_DNN, "rejected");

    /* a second establishment for the same PDU session id replaces the first (TS 23.502 4.3.2.2.1); the AMF asked for it, so it is not notified */
    old = sess_lookup(s, NULL, supi, (uint8_t)psi);
    if (old != NULL)
        sess_teardown(s, old, "replaced by a new establishment of the same PDU session id");

    for (unsigned k = 0; k < s->nslice_limit; k++) { /* slice admission control: #69 insufficient resources for the specific slice (TS 24.501 Table 9.11.4.2.1) */
        size_t n = 0;
        if (s->slice_limit[k].sst != sst || s->slice_limit[k].has_sd != has_sd || (has_sd && s->slice_limit[k].sd != sd))
            continue;
        pthread_mutex_lock(&s->mu);
        for (const smf_sess *o = s->sessions; o != NULL; o = o->next)
            n += !o->dead && o->sst == sst && o->has_sd == has_sd && (!has_sd || o->sd == sd);
        pthread_mutex_unlock(&s->mu);
        if (n >= s->slice_limit[k].max_sessions) {
            g5c_counter_inc(g5c_counter_get(s->metrics, "g5c_smf_slice_admission_total", "PDU session establishments turned away because the slice is full.", &(g5c_label){"result", "rejected"}, 1));
            REJECT(403, "INSUFFICIENT_RESOURCES_SLICE", "the slice has reached its maximum number of PDU sessions", SMF_5GSM_INSUFFICIENT_RESOURCES_SLICE, "rejected");
        }
    }
    rc = smf_udm_sm_data(s, supi, plmn, sst, has_sd, sd, dnn, &cfg);
    if (rc == 404)
        REJECT(403, "DNN_DENIED", "the subscription does not allow this DNN / slice", SMF_5GSM_MISSING_OR_UNKNOWN_DNN, "rejected");
    if (rc != SMF_PEER_OK)
        REJECT(500, "SYSTEM_FAILURE", "subscription data unavailable", SMF_5GSM_NETWORK_FAILURE, "failed");

    ss = g5c_xcalloc(1, sizeof *ss);
    pthread_mutex_init(&ss->mu, NULL);
    ss->owner = s;
    ss->refs = 1;
    if (g5c_uuid_v4(ss->ref) != 0) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "no randomness");
        goto abort;
    }
    snprintf(ss->supi, sizeof ss->supi, "%s", supi);
    snprintf(ss->dnn, sizeof ss->dnn, "%s", dnn);
    ss->psi = (uint8_t)psi;
    ss->pti = er.pti;
    ss->req = er;
    ss->sst = sst;
    ss->has_sd = has_sd;
    ss->sd = sd;
    ss->ssc_mode = 1; /* only SSC mode 1 is supported; the accept tells the UE which mode was selected */
    ss->dcfg = dcfg;
    ss->plmn = plmn != NULL ? g5c_json_dup(plmn) : NULL;
    if (g5c_json_get_str(pr.json, "servingNfId") != NULL)
        ss->serving_nf_id = g5c_xstrdup(g5c_json_get_str(pr.json, "servingNfId"));
    if (status_uri != NULL)
        ss->amf_status_uri = g5c_xstrdup(status_uri);
    root = s->amf != NULL ? g5c_xstrdup(s->amf) : NULL;
    if (root == NULL && s->nrf != NULL && ss->serving_nf_id != NULL)
        root = smf_nrf_amf_root(s, ss->serving_nf_id);
    if (root == NULL)
        root = api_root(status_uri);
    if (root == NULL) {
        create_error(s, resp, 400, "MANDATORY_IE_MISSING", "the AMF cannot be reached (no smContextStatusUri, discovery failed)", psi8, er.pti,
                     SMF_5GSM_NETWORK_FAILURE);
        count_op(s, "create", "bad_request");
        goto abort;
    }
    ss->amf_n1n2_url = g5c_xasprintf("%s/namf-comm/v1/ue-contexts/%s/n1-n2-messages", root, supi);
    free(root);

    ss->pdu_type = select_type(cfg, er.pdu_type, dcfg, &accept_cause);
    ss->accept_cause = accept_cause;
    if (ss->pdu_type == 0)
        REJECT(403, "PDU_SESSION_TYPE_NOT_ALLOWED", "the requested PDU session type is not allowed", SMF_5GSM_UNKNOWN_PDU_SESSION_TYPE, "rejected");
    ss->upf = smf_n4_select(s->n4, dnn, sst, has_sd, sd);
    if (ss->upf == NULL)
        REJECT(500, "INSUFFICIENT_RESOURCES", "no UPF available", SMF_5GSM_INSUFFICIENT_RESOURCES, "failed");
    if ((ss->pdu_type & 1) && smf_pool_alloc4(dcfg->pool, ss->ue4) == 0)
        ss->has4 = true;
    if ((ss->pdu_type & 2) && smf_pool_alloc6(dcfg->pool, ss->ue6) == 0)
        ss->has6 = true;
    if (((ss->pdu_type & 1) && !ss->has4) || ((ss->pdu_type & 2) && !ss->has6))
        REJECT(500, "INSUFFICIENT_RESOURCES", "the UE address pool is exhausted", SMF_5GSM_INSUFFICIENT_RESOURCES, "failed");
    if (ss->has6) {
        (void)g5c_random(ss->ifid, sizeof ss->ifid);
        ss->ifid[0] &= 0xfc; /* a locally generated, unicast identifier */
        ss->ifid[7] |= 1;
    }
    if (smf_udm_register(s, ss, ss->plmn) != SMF_PEER_OK)
        REJECT(500, "SYSTEM_FAILURE", "UDM registration failed", SMF_5GSM_NETWORK_FAILURE, "failed");
    ss->udm_registered = true;

    root = s->self_uri != NULL ? g5c_xstrdup(s->self_uri) : g5c_req_url(req, "");
    notif = g5c_xasprintf("%s/nsmf-callback/v1/sm-policies/%s", root, ss->ref);
    free(root);
    rc = smf_pcf_create(s, ss, cfg, notif, ss->plmn, &decision, &resource);
    if (rc != 0)
        REJECT(rc == 403 ? 403 : 500, rc == 403 ? "UE_NOT_AUTHORIZED" : "SYSTEM_FAILURE", "SM policy could not be obtained",
               rc == 403 ? SMF_5GSM_USER_AUTH_FAILED : SMF_5GSM_NETWORK_FAILURE, "failed");
    ss->pcf_resource = resource;
    if (s->chf != NULL) { /* online charging: the CHF grants the first quota or the session is not set up (when charging is required) */
        int cr = smf_chf_create(s, ss, &ss->chf_resource, &ss->chf_granted, &ss->chf_final);
        g5c_counter_inc(g5c_counter_get(s->metrics, "g5c_smf_charging_total", "Nchf_ConvergedCharging session openings by result.",
                                        &(g5c_label){"result", cr == 0 ? "granted" : cr > 0 ? "refused" : "failed"}, 1));
        if (cr != 0 && s->chf_required)
            REJECT(cr > 0 ? 403 : 500, cr > 0 ? "CHARGING_DENIED" : "SYSTEM_FAILURE", cr > 0 ? "the CHF refused the charging session" : "the CHF did not answer",
                   cr > 0 ? SMF_5GSM_INSUFFICIENT_RESOURCES : SMF_5GSM_NETWORK_FAILURE, "failed");
    }
    ss->pcf_notif = notif;
    ss->decision = g5c_json_dup(decision);
    notif = NULL;
    {
        char perr[200];
        if (smf_policy_from_decision(decision, &ss->pol, perr, sizeof perr) != 0) {
            G5C_LOGE("g5c_smf", "policy decision for %s rejected: %s", supi, perr);
            REJECT(500, "SYSTEM_FAILURE", "unusable SM policy decision", SMF_5GSM_NETWORK_FAILURE, "failed");
        }
    }

    ss->cp_seid = smf_n4_new_seid(s->n4);
    if (ss->has6) { /* the TEID the UPF puts on router solicitations it sends to us */
        for (int attempt = 0; attempt < 8 && ss->rs_teid == 0; attempt++) {
            uint32_t t = 0;
            bool taken = false;
            (void)g5c_random(&t, sizeof t);
            if (t == 0)
                continue;
            pthread_mutex_lock(&s->mu);
            for (smf_sess *o = s->sessions; o != NULL; o = o->next)
                taken = taken || o->rs_teid == t;
            pthread_mutex_unlock(&s->mu);
            if (!taken)
                ss->rs_teid = t;
        }
    }
    memset(&est, 0, sizeof est);
    est.rs_teid = ss->rs_teid;
    est.cp_seid = ss->cp_seid;
    smf_n4_local_addr(s->n4, est.smf_ip4);
    est.dnn = ss->dnn;
    est.want_usage = s->cdr_path != NULL || s->chf != NULL;
    est.charging_volume = ss->chf_resource != NULL ? ss->chf_granted : 0;
    est.pdu_type = ss->pdu_type;
    est.has4 = ss->has4;
    est.has6 = ss->has6;
    memcpy(est.ue4, ss->ue4, 4);
    memcpy(est.ue6, ss->ue6, 8);
    est.has_snssai = true;
    est.sst = sst;
    est.has_sd = has_sd;
    est.sd = sd;
    est.pol = &ss->pol;
    if (smf_n4_build_est(&est, body, sizeof body, &blen) != 0)
        REJECT(500, "SYSTEM_FAILURE", "cannot build the N4 request", SMF_5GSM_NETWORK_FAILURE, "failed");
    if (smf_n4_call(s->n4, ss->upf, PFCP_SESSION_ESTABLISHMENT_REQUEST, true, 0, body, blen, &r) != 0 || smf_n4_parse_est_rsp(&r, &er2) != 0 ||
        !er2.ok) {
        G5C_LOGE("g5c_smf", "N4 session establishment on %s failed for %s/%u (cause %u)", smf_upf_name(ss->upf), supi, ss->psi, smf_n4_cause_of(&r));
        REJECT(500, "SYSTEM_FAILURE", "the UPF refused the session", SMF_5GSM_NETWORK_FAILURE, "failed");
    }
    ss->up_seid = er2.up_seid;
    ss->t_est = time(NULL);
    ss->ul_teid = er2.ul_teid;
    ss->cp_teid = er2.cp_teid;
    memcpy(ss->ul_ip4, er2.ul_ip4, 4);
    ss->state = SMF_S_CREATING;

    /* answer first, then publish: the table's reference is taken here, the handler's is dropped at the end */
    path = g5c_xasprintf(BASE "/sm-contexts/%s", ss->ref);
    loc = g5c_req_url(req, path);
    {
        g5c_json *out = g5c_json_new_obj();
        g5c_json_set_int(out, "pduSessionId", ss->psi);
        g5c_json_set_str(out, "upCnxState", "ACTIVATING");
        g5c_resp_json(resp, 201, out);
        g5c_resp_header(resp, "location", loc);
        g5c_json_free(out);
    }
    free(loc);
    free(path);
    G5C_LOGI("g5c_smf", "PDU session %u of %s created on UPF %s (dnn %s, type %u)", ss->psi, supi, smf_upf_name(ss->upf), ss->dnn, ss->pdu_type);
    {
        job_ref *jr = g5c_xcalloc(1, sizeof *jr);
        memcpy(jr->ref, ss->ref, sizeof jr->ref);
        ss->refs++;
        sess_insert(s, ss);
        smf_persist_request(s);
        smf_defer_after(s, job_n1n2, jr, s->n1n2_delay_ms); /* the AMF finishes reading the 201 first (TS 23.502 orders the response before the transfer) */
    }
    atomic_fetch_add(&s->created, 1);
    count_op(s, "create", "ok");
    g5c_histogram_observe(g5c_histogram_get(s->metrics, "g5c_smf_create_sm_context_seconds", "Create SM Context handling time.", NULL, 0),
                          g5c_now_seconds() - t0);
    update_gauge(s);
    sess_unref(s, ss);
    ss = NULL;
    goto done;

abort:
    if (ss != NULL)
        create_abort(s, ss);
    update_gauge(s);
    goto done;
bad:
    count_op(s, "create", "bad_request");
done:
    free(notif);
    g5c_json_free(cfg);
    g5c_json_free(decision);
    parsed_free(&pr);
}

/* ---- the N1N2 transfer that follows the 201 ---- */

static void notify_released(smf *s, const char *uri, const char *cause)
{
    smf_amf_status_notify(s, uri, "RELEASED", cause);
}

static void job_n1n2(smf *s, void *arg)
{
    job_ref *jr = arg;
    smf_sess *ss;
    g5c_bytes n1, n2;
    smf_est_acc acc;
    smf_n2_setup n2s;
    int rc;

    ss = sess_lookup(s, jr->ref, NULL, 0);
    free(jr);
    if (ss == NULL)
        return;
    g5c_bytes_init(&n1);
    g5c_bytes_init(&n2);
    memset(&acc, 0, sizeof acc);
    acc.psi = ss->psi;
    acc.pti = ss->pti;
    acc.pdu_type = ss->pdu_type;
    acc.ssc_mode = ss->ssc_mode;
    memcpy(acc.ip4, ss->ue4, 4);
    memcpy(acc.ifid, ss->ifid, 8);
    acc.ambr_ul = ss->pol.ambr_ul;
    acc.ambr_dl = ss->pol.ambr_dl;
    acc.pol = &ss->pol;
    acc.has_snssai = true;
    acc.sst = ss->sst;
    acc.has_sd = ss->has_sd;
    acc.sd = ss->sd;
    acc.dnn = ss->dnn;
    acc.req = ss->req;
    acc.cause = ss->accept_cause;
    acc.mtu = s->mtu;
    acc.ndns4 = ss->dcfg->ndns4;
    memcpy(acc.dns4, ss->dcfg->dns4, sizeof acc.dns4);
    acc.ndns6 = ss->dcfg->ndns6;
    memcpy(acc.dns6, ss->dcfg->dns6, sizeof acc.dns6);
    memset(&n2s, 0, sizeof n2s);
    n2s.pdu_type = ss->pdu_type;
    n2s.ambr_ul = ss->pol.ambr_ul;
    n2s.ambr_dl = ss->pol.ambr_dl;
    memcpy(n2s.upf_ip4, ss->ul_ip4, 4);
    n2s.ul_teid = ss->ul_teid;
    n2s.pol = &ss->pol;
    if (smf_gsm_build_est_accept(&acc, &n1) != 0 || smf_n2_build_setup_req(&n2s, &n2) != 0) {
        G5C_LOGE("g5c_smf", "cannot build the establishment accept for %s/%u", ss->supi, ss->psi);
        sess_teardown(s, ss, "cannot build the accept");
        g5c_bytes_free(&n1);
        g5c_bytes_free(&n2);
        return;
    }
    pthread_mutex_unlock(&ss->mu); /* the AMF may call back while it processes the transfer */
    rc = smf_amf_n1n2(s, ss, n1.data, n1.len, "PDU_RES_SETUP_REQ", n2.data, n2.len);
    pthread_mutex_lock(&ss->mu);
    g5c_bytes_free(&n1);
    g5c_bytes_free(&n2);
    if (ss->dead) {
        smf_sess_unlock(ss);
        return;
    }
    if (rc != 0) {
        char *uri = ss->amf_status_uri != NULL ? g5c_xstrdup(ss->amf_status_uri) : NULL;
        sess_teardown(s, ss, "the AMF did not accept the N1N2 transfer");
        notify_released(s, uri, "5G_AN_NOT_RESPONDING");
        free(uri);
        return;
    }
    smf_sess_unlock(ss);
}

/* ---- Update SM Context ---- */

static int n4_modify(smf *s, smf_sess *ss, const uint8_t *body, size_t blen)
{
    smf_n4_msg r;
    if (smf_n4_call(s->n4, ss->upf, PFCP_SESSION_MODIFICATION_REQUEST, true, ss->up_seid, body, blen, &r) != 0) {
        G5C_LOGE("g5c_smf", "N4 session modification for %s/%u got no answer", ss->supi, ss->psi);
        return -1;
    }
    if (smf_n4_cause_of(&r) != PFCP_CAUSE_ACCEPTED) {
        G5C_LOGE("g5c_smf", "N4 session modification for %s/%u refused with cause %u", ss->supi, ss->psi, smf_n4_cause_of(&r));
        return -1;
    }
    return 0;
}

static void no_context(g5c_resp *resp)
{
    g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "no such SM context");
}

static void modify_ctx(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    smf *s = ctx;
    parsed_req pr;
    smf_sess *ss;
    const char *n2type, *up;
    g5c_json *out = NULL;

    if (!parse_request(req, &pr, resp, true)) {
        count_op(s, "update", "bad_request");
        return;
    }
    ss = smf_sess_find_ref(s, g5c_req_param(req, "smContextRef"));
    if (ss == NULL) {
        no_context(resp);
        count_op(s, "update", "not_found");
        parsed_free(&pr);
        return;
    }
    n2type = g5c_json_get_str(pr.json, "n2SmInfoType");
    up = g5c_json_get_str(pr.json, "upCnxState");
    out = g5c_json_new_obj();

    const char *ho = g5c_json_get_str(pr.json, "hoState");
    bool ho_msg = (n2type != NULL && (strcmp(n2type, "PATH_SWITCH_REQ") == 0 || strcmp(n2type, "HANDOVER_REQUIRED") == 0 || strcmp(n2type, "HANDOVER_REQ_ACK") == 0)) ||
                  (pr.n1 == NULL && n2type == NULL && ho != NULL && (strcmp(ho, "COMPLETED") == 0 || strcmp(ho, "CANCELLED") == 0));
    if (ho_msg) {
        /* mobility (TS 23.502 4.9.1): Xn path switch and the three phases of an N2 handover */
        smf_an_tunnel t;
        char err[160];
        uint8_t b[512];
        size_t bl = 0;
        g5c_bytes tr;
        g5c_bytes_init(&tr);
        if (strcmp(n2type != NULL ? n2type : "", "PATH_SWITCH_REQ") == 0) {
            bool default_ok = false;
            if (pr.n2 == NULL || smf_n2_parse_path_switch(pr.n2->data, pr.n2->len, &t, err, sizeof err) != 0) {
                g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "n2SmInfo", pr.n2 == NULL ? "missing" : err);
                count_op(s, "update", "bad_request");
            } else {
                for (size_t i = 0; i < t.naccepted; i++)
                    default_ok = default_ok || t.accepted[i] == SMF_DEFAULT_QFI;
                if (!default_ok || smf_n4_build_mod_activate(&t, ss->dnn, b, sizeof b, &bl) != 0 || n4_modify(s, ss, b, bl) != 0 ||
                    smf_n2_build_path_switch_ack(ss->ul_ip4, ss->ul_teid, &tr) != 0) {
                    g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot switch the downlink to the new gNB tunnel");
                    count_op(s, "update", "path_switch_failed");
                } else {
                    ss->an = t;
                    ss->an_set = true;
                    ss->state = SMF_S_ACTIVE;
                    ss->paging = false;
                    smf_persist_request(s);
                    g5c_json_set_str(g5c_json_set(out, N2_ID, g5c_json_new_obj()), "contentId", N2_ID);
                    g5c_json_set_str(out, "n2SmInfoType", "PATH_SWITCH_REQ_ACK");
                    g5c_json_set_str(out, "upCnxState", "ACTIVATED");
                    reply_parts(resp, 200, out, NULL, 0, tr.data, tr.len);
                    count_op(s, "update", "path_switched");
                }
            }
        } else if (strcmp(n2type != NULL ? n2type : "", "HANDOVER_REQUIRED") == 0) {
            smf_n2_setup n2s;
            if (ss->state != SMF_S_ACTIVE) {
                g5c_resp_problem_simple(resp, 400, "INVALID_STATE", "the user plane of the session is not active");
                count_op(s, "update", "bad_request");
            } else {
                memset(&n2s, 0, sizeof n2s);
                n2s.pdu_type = ss->pdu_type;
                n2s.ambr_ul = ss->pol.ambr_ul;
                n2s.ambr_dl = ss->pol.ambr_dl;
                memcpy(n2s.upf_ip4, ss->ul_ip4, 4);
                n2s.ul_teid = ss->ul_teid;
                n2s.pol = &ss->pol;
                if (smf_n2_build_setup_req(&n2s, &tr) != 0) {
                    g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot build the handover request transfer");
                } else {
                    ss->ho_state = SMF_HO_PREPARING;
                    ss->ho_an_set = false;
                    g5c_json_set_str(g5c_json_set(out, N2_ID, g5c_json_new_obj()), "contentId", N2_ID);
                    g5c_json_set_str(out, "n2SmInfoType", "PDU_RES_SETUP_REQ");
                    g5c_json_set_str(out, "hoState", "PREPARING");
                    reply_parts(resp, 200, out, NULL, 0, tr.data, tr.len);
                    count_op(s, "update", "handover_preparing");
                }
            }
        } else if (strcmp(n2type != NULL ? n2type : "", "HANDOVER_REQ_ACK") == 0) {
            if (ss->ho_state != SMF_HO_PREPARING) {
                g5c_resp_problem_simple(resp, 400, "INVALID_STATE", "no handover is being prepared for this session");
                count_op(s, "update", "bad_request");
            } else if (pr.n2 == NULL || smf_n2_parse_ho_ack(pr.n2->data, pr.n2->len, &t, err, sizeof err) != 0) {
                g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "n2SmInfo", pr.n2 == NULL ? "missing" : err);
                count_op(s, "update", "bad_request");
            } else if (smf_n2_build_ho_command(&tr) != 0) {
                g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot build the handover command transfer");
            } else {
                ss->ho_an = t;
                ss->ho_an_set = true;
                ss->ho_state = SMF_HO_PREPARED;
                g5c_json_set_str(g5c_json_set(out, N2_ID, g5c_json_new_obj()), "contentId", N2_ID);
                g5c_json_set_str(out, "n2SmInfoType", "HANDOVER_CMD");
                g5c_json_set_str(out, "hoState", "PREPARED");
                reply_parts(resp, 200, out, NULL, 0, tr.data, tr.len);
                count_op(s, "update", "handover_prepared");
            }
        } else if (strcmp(ho, "COMPLETED") == 0) {
            if (ss->ho_state != SMF_HO_PREPARED || !ss->ho_an_set || smf_n4_build_mod_activate(&ss->ho_an, ss->dnn, b, sizeof b, &bl) != 0 ||
                n4_modify(s, ss, b, bl) != 0) {
                g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot complete the handover on the user plane");
                count_op(s, "update", "handover_failed");
            } else {
                ss->an = ss->ho_an;
                ss->an_set = true;
                ss->state = SMF_S_ACTIVE;
                ss->ho_state = SMF_HO_NONE;
                ss->ho_an_set = false;
                smf_persist_request(s);
                g5c_json_set_str(out, "hoState", "COMPLETED");
                g5c_json_set_str(out, "upCnxState", "ACTIVATED");
                g5c_resp_json(resp, 200, out);
                count_op(s, "update", "handover_completed");
            }
        } else { /* CANCELLED */
            ss->ho_state = SMF_HO_NONE;
            ss->ho_an_set = false;
            g5c_json_set_str(out, "hoState", "CANCELLED");
            g5c_resp_json(resp, 200, out);
            count_op(s, "update", "handover_cancelled");
        }
        g5c_bytes_free(&tr);
    } else
    if (pr.n1 != NULL) {
        uint8_t mt, psi, pti;
        if (smf_gsm_peek(pr.n1->data, pr.n1->len, &mt, &psi, &pti) != 0 || psi != ss->psi) {
            g5c_resp_problem_simple(resp, 400, "INVALID_MSG_FORMAT", "malformed or foreign 5GSM message");
            count_op(s, "update", "bad_request");
        } else if (mt == 0xd1) { /* PDU SESSION RELEASE REQUEST */
            g5c_bytes n1, n2;
            g5c_bytes_init(&n1);
            g5c_bytes_init(&n2);
            if (smf_gsm_build_release_cmd(ss->psi, pti, SMF_5GSM_REGULAR_DEACTIVATION, &n1) != 0 || smf_n2_build_release_cmd(&n2) != 0) {
                g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot build the release command");
            } else {
                ss->state = SMF_S_RELEASING;
                ss->release_pending_complete = true;
                g5c_json_set_str(g5c_json_set(out, "n1SmMsg", g5c_json_new_obj()), "contentId", N1_ID);
                g5c_json_set_str(g5c_json_set(out, "n2SmInfo", g5c_json_new_obj()), "contentId", N2_ID);
                g5c_json_set_str(out, "n2SmInfoType", "PDU_RES_REL_CMD");
                g5c_json_set_str(out, "upCnxState", "DEACTIVATED");
                reply_parts(resp, 200, out, n1.data, n1.len, n2.data, n2.len);
                count_op(s, "update", "release_requested");
            }
            g5c_bytes_free(&n1);
            g5c_bytes_free(&n2);
        } else if (mt == 0xd4) { /* PDU SESSION RELEASE COMPLETE */
            sess_teardown(s, ss, "released by the UE");
            ss = NULL;
            g5c_resp_status(resp, 204);
            count_op(s, "update", "released");
        } else if (mt == 0xc9) { /* modification is not in this half: refuse so the UE does not wait */
            g5c_bytes n1;
            nas_msg m;
            uint8_t cause = SMF_5GSM_REQUEST_REJECTED_UNSPECIFIED;
            g5c_bytes_init(&n1);
            if (nas_msg_init(&m, "PDU session modification reject")) {
                m.pdu_session_id = ss->psi;
                m.pti = pti;
                nas_msg_set(&m, "5GSM cause", &cause, 1);
                (void)nas_msg_encode(&m, &n1);
                nas_msg_free(&m);
            }
            g5c_json_set_str(g5c_json_set(out, "n1SmMsg", g5c_json_new_obj()), "contentId", N1_ID);
            reply_parts(resp, 200, out, n1.data, n1.len, NULL, 0);
            g5c_bytes_free(&n1);
            count_op(s, "update", "modification_rejected");
        } else if (mt == 0xcc || mt == 0xcd) {
            g5c_resp_status(resp, 204);
            count_op(s, "update", "ok");
        } else {
            g5c_resp_problem_simple(resp, 501, "UNSUPPORTED_MESSAGE", "this 5GSM message is not handled");
            count_op(s, "update", "unsupported");
        }
    } else if (n2type != NULL) {
        if (strcmp(n2type, "PDU_RES_SETUP_RSP") == 0) {
            smf_an_tunnel t;
            char err[160];
            uint8_t b[512];
            size_t bl = 0;
            bool default_ok = false;
            if (pr.n2 == NULL || smf_n2_parse_setup_rsp(pr.n2->data, pr.n2->len, &t, err, sizeof err) != 0) {
                g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "n2SmInfo", pr.n2 == NULL ? "missing" : err);
                count_op(s, "update", "bad_request");
            } else {
                for (size_t i = 0; i < t.naccepted; i++)
                    default_ok = default_ok || t.accepted[i] == SMF_DEFAULT_QFI;
                if (!default_ok || smf_n4_build_mod_activate(&t, ss->dnn, b, sizeof b, &bl) != 0 || n4_modify(s, ss, b, bl) != 0) {
                    g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot switch the downlink to the gNB tunnel");
                    count_op(s, "update", "failed");
                } else {
                    ss->an = t;
                    ss->an_set = true;
                    ss->state = SMF_S_ACTIVE;
                    ss->paging = false;
                    smf_persist_request(s);
                    g5c_json_set_str(out, "upCnxState", "ACTIVATED");
                    g5c_resp_json(resp, 200, out);
                    count_op(s, "update", "activated");
                }
            }
        } else if (strcmp(n2type, "PDU_RES_SETUP_FAIL") == 0) {
            char cause[96] = "unknown";
            if (pr.n2 != NULL)
                (void)smf_n2_parse_cause("PDUSessionResourceSetupUnsuccessfulTransfer", pr.n2->data, pr.n2->len, cause, sizeof cause);
            G5C_LOGW("g5c_smf", "the gNB could not set up PDU session %u of %s: %s", ss->psi, ss->supi, cause);
            sess_teardown(s, ss, "resource setup failed in the AN");
            ss = NULL;
            g5c_resp_status(resp, 204);
            count_op(s, "update", "setup_failed");
        } else if (strcmp(n2type, "PDU_RES_MOD_RSP") == 0) {
            g5c_resp_status(resp, 204);
            count_op(s, "update", "modified");
        } else if (strcmp(n2type, "PDU_RES_MOD_FAIL") == 0) {
            char cause[96] = "unknown";
            if (pr.n2 != NULL)
                (void)smf_n2_parse_cause("PDUSessionResourceModifyUnsuccessfulTransfer", pr.n2->data, pr.n2->len, cause, sizeof cause);
            G5C_LOGW("g5c_smf", "the gNB could not modify PDU session %u of %s: %s", ss->psi, ss->supi, cause);
            g5c_resp_status(resp, 204);
            count_op(s, "update", "modify_failed");
        } else if (strcmp(n2type, "PDU_RES_REL_RSP") == 0) {
            sess_teardown(s, ss, "released (resource release response)");
            ss = NULL;
            g5c_resp_status(resp, 204);
            count_op(s, "update", "released");
        } else {
            g5c_resp_problem_simple(resp, 501, "UNSUPPORTED_N2_INFO", "this N2 SM information type is not handled");
            count_op(s, "update", "unsupported");
        }
    } else if (up != NULL) {
        if (strcmp(up, "DEACTIVATED") == 0) {
            uint8_t b[128];
            size_t bl;
            if (ss->state == SMF_S_RELEASING) { /* already on its way out */
                g5c_json_set_str(out, "upCnxState", "DEACTIVATED");
                g5c_resp_json(resp, 200, out);
            } else if (smf_n4_build_mod_deactivate(b, sizeof b, &bl) != 0 || n4_modify(s, ss, b, bl) != 0) {
                g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot buffer the downlink");
                count_op(s, "update", "failed");
            } else {
                ss->state = SMF_S_IDLE;
                ss->an_set = false;
                smf_persist_request(s);
                g5c_json_set_str(out, "upCnxState", "DEACTIVATED");
                g5c_resp_json(resp, 200, out);
                count_op(s, "update", "deactivated");
            }
        } else if (strcmp(up, "ACTIVATING") == 0) { /* service request: hand the AN the tunnel parameters again */
            g5c_bytes n2;
            smf_n2_setup n2s;
            g5c_bytes_init(&n2);
            memset(&n2s, 0, sizeof n2s);
            n2s.pdu_type = ss->pdu_type;
            n2s.ambr_ul = ss->pol.ambr_ul;
            n2s.ambr_dl = ss->pol.ambr_dl;
            memcpy(n2s.upf_ip4, ss->ul_ip4, 4);
            n2s.ul_teid = ss->ul_teid;
            n2s.pol = &ss->pol;
            if (smf_n2_build_setup_req(&n2s, &n2) != 0) {
                g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "cannot build the resource setup request");
            } else {
                g5c_json_set_str(g5c_json_set(out, "n2SmInfo", g5c_json_new_obj()), "contentId", N2_ID);
                g5c_json_set_str(out, "n2SmInfoType", "PDU_RES_SETUP_REQ");
                g5c_json_set_str(out, "upCnxState", "ACTIVATING");
                reply_parts(resp, 200, out, NULL, 0, n2.data, n2.len);
                count_op(s, "update", "activating");
            }
            g5c_bytes_free(&n2);
        } else {
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "upCnxState", "unsupported value");
            count_op(s, "update", "bad_request");
        }
    } else {
        g5c_resp_json(resp, 200, out); /* location, time zone or access type updates: nothing for the SMF to do yet */
        count_op(s, "update", "ok");
    }
    g5c_json_free(out);
    if (ss != NULL)
        smf_sess_unlock(ss);
    parsed_free(&pr);
}

/* ---- Release SM Context ---- */

static void release_ctx(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    smf *s = ctx;
    parsed_req pr;
    smf_sess *ss;
    if (!parse_request(req, &pr, resp, false)) {
        count_op(s, "release", "bad_request");
        return;
    }
    ss = smf_sess_find_ref(s, g5c_req_param(req, "smContextRef"));
    if (ss == NULL) {
        no_context(resp);
        count_op(s, "release", "not_found");
    } else {
        sess_teardown(s, ss, "released by the AMF");
        g5c_resp_status(resp, 204);
        count_op(s, "release", "ok");
    }
    parsed_free(&pr);
}

/* ---- network-initiated procedures ---- */

static void est_ctx(const smf_sess *ss, smf_n4_est *e)
{
    memset(e, 0, sizeof *e);
    e->want_usage = ss->owner != NULL && (ss->owner->cdr_path != NULL || ss->owner->chf != NULL);
    e->charging_volume = ss->chf_resource != NULL ? ss->chf_granted : 0;
    e->dnn = ss->dnn;
    e->pdu_type = ss->pdu_type;
    e->has4 = ss->has4;
    e->has6 = ss->has6;
    memcpy(e->ue4, ss->ue4, 4);
    memcpy(e->ue6, ss->ue6, 8);
    e->has_snssai = true;
    e->sst = ss->sst;
    e->has_sd = ss->has_sd;
    e->sd = ss->sd;
}

/* Called with the session locked; the lock is released around the AMF call (the AMF may call back while it processes the transfer). */
static int tell_amf(smf *s, smf_sess *ss, const uint8_t *n1, size_t n1l, const char *n2type, const uint8_t *n2, size_t n2l)
{
    int rc;
    pthread_mutex_unlock(&ss->mu);
    rc = smf_amf_n1n2(s, ss, n1, n1l, n2type, n2, n2l);
    pthread_mutex_lock(&ss->mu);
    return rc;
}

/* PCF-initiated SM policy update (TS 29.512 4.2.4) */
/* Applies a policy decision to a session (the caller holds the session): UPF first (Update QER, Create / Remove PDR), then the UE and the gNB */
static int apply_decision(smf *s, smf_sess *ss, const g5c_json *dec, const char *op, char *perr, size_t pcap, const char **cause)
{
    smf_policy np;
    smf_n4_est e;
    uint8_t b[4096];
    size_t bl = 0;
    bool changed = false;
    g5c_bytes n1, n2;
    int n1rc, n2rc;
    if (smf_policy_from_decision(dec, &np, perr, pcap) != 0) {
        *cause = "bad_request";
        return 400;
    }
    smf_policy_assign_ids(&np, &ss->pol);
    est_ctx(ss, &e);
    if (smf_n4_build_policy_update(&e, &ss->pol, &np, b, sizeof b, &bl, &changed) != 0 || (changed && n4_modify(s, ss, b, bl) != 0)) {
        smf_policy_free(&np);
        *cause = "failed";
        return 500;
    }
    g5c_bytes_init(&n1);
    g5c_bytes_init(&n2);
    n1rc = smf_gsm_build_mod_cmd(ss->psi, &ss->pol, &np, &n1);
    n2rc = smf_n2_build_mod_req(&ss->pol, &np, &n2);
    smf_policy_free(&ss->pol);
    ss->pol = np;
    g5c_json_free(ss->decision);
    ss->decision = g5c_json_dup(dec);
    smf_persist_request(s);
    if (n1rc == 0) {
        if (tell_amf(s, ss, n1.data, n1.len, n2rc == 0 ? "PDU_RES_MOD_REQ" : NULL, n2rc == 0 ? n2.data : NULL, n2rc == 0 ? n2.len : 0) != 0)
            G5C_LOGW("g5c_smf", "policy of %s/%u changed on the UPF but the AMF did not take the modification command", ss->supi, ss->psi);
    }
    g5c_bytes_free(&n1);
    g5c_bytes_free(&n2);
    G5C_LOGI("g5c_smf", "%s applied to PDU session %u of %s (UPF %s, UE %s)", op, ss->psi, ss->supi, changed ? "modified" : "unchanged", n1rc == 0 ? "told" : "not affected");
    return 0;
}

static void policy_update(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    smf *s = ctx;
    g5c_json *body = g5c_req_json(req, resp);
    const g5c_json *dec;
    smf_sess *ss;
    char perr[200];
    const char *cause = "failed";
    int st;
    if (body == NULL) {
        count_op(s, "policy_update", "bad_request");
        return;
    }
    dec = g5c_json_get(body, "smPolicyDecision");
    if (!g5c_json_is(dec, G5C_J_OBJECT)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", "smPolicyDecision", "required");
        count_op(s, "policy_update", "bad_request");
        g5c_json_free(body);
        return;
    }
    ss = smf_sess_find_ref(s, g5c_req_param(req, "smContextRef"));
    if (ss == NULL) {
        g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "no such SM context");
        count_op(s, "policy_update", "not_found");
        g5c_json_free(body);
        return;
    }
    st = apply_decision(s, ss, dec, "SM policy update", perr, sizeof perr, &cause);
    if (st == 400)
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "smPolicyDecision", perr);
    else if (st != 0)
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "the UPF did not accept the policy update");
    else
        g5c_resp_status(resp, 204);
    count_op(s, "policy_update", st == 0 ? "ok" : cause);
    smf_sess_unlock(ss);
    g5c_json_free(body);
}

/* ---- usage monitoring (backlog A-03) ---- */

typedef struct {
    char ref[37];
    uint64_t total, ul, dl;
} usage_arg;

static void count_usage(smf *s, const char *result)
{
    g5c_label l = {"result", result};
    g5c_counter_inc(g5c_counter_get(s->metrics, "g5c_smf_usage_reports_total", "Usage monitoring reports from the UPF, by what became of them.", &l, 1));
}

/* The UPF reported that the volume threshold of the PCF has passed */
static void job_usage(smf *s, void *arg)
{
    usage_arg *a = arg;
    smf_sess *ss = sess_lookup(s, a->ref, NULL, 0);
    char *url = NULL, err[160], perr[200];
    g5c_json *b, *rep;
    g5c_resp r;
    const char *cause = "failed";
    int ok;
    if (ss == NULL) {
        free(a);
        return;
    }
    if (ss->pcf_resource == NULL || ss->pol.um_volume == 0) { /* no (longer any) usage monitoring: the report is acknowledged and nothing else */
        smf_sess_unlock(ss);
        free(a);
        count_usage(s, "ignored");
        return;
    }
    url = g5c_xasprintf("%s/update", ss->pcf_resource);
    smf_sess_unlock(ss); /* the PCF is asked without the session locked */
    b = g5c_json_new_obj();
    g5c_json_push_str(g5c_json_set(b, "repPolicyCtrlReqTriggers", g5c_json_new_arr()), "US_RE");
    rep = g5c_json_push(g5c_json_set(b, "accuUsageReports", g5c_json_new_arr()), g5c_json_new_obj());
    g5c_json_set_str(rep, "refUmIds", "um1");
    g5c_json_set_int(rep, "volUsage", (int64_t)a->total);
    g5c_json_set_int(rep, "volUsageUplink", (int64_t)a->ul);
    g5c_json_set_int(rep, "volUsageDownlink", (int64_t)a->dl);
    ok = g5c_client_send_json(s->client, "POST", url, b, &r, err, sizeof err);
    g5c_json_free(b);
    free(url);
    if (ok != 0 || r.status != 200) {
        G5C_LOGW("g5c_smf", "usage report of %s: the PCF did not answer with a decision (%s)", a->ref, ok != 0 ? err : "HTTP status");
        if (ok == 0)
            g5c_resp_free(&r);
        count_usage(s, "pcf_failed");
        free(a);
        return;
    }
    {
        g5c_json *dec = g5c_resp_parse_json(&r);
        g5c_resp_free(&r);
        ss = sess_lookup(s, a->ref, NULL, 0);
        if (ss != NULL && dec != NULL) {
            ok = apply_decision(s, ss, dec, "usage monitoring decision", perr, sizeof perr, &cause);
            count_usage(s, ok == 0 ? "applied" : "apply_failed");
            smf_sess_unlock(ss);
        } else {
            count_usage(s, "session_gone");
            if (ss != NULL)
                smf_sess_unlock(ss);
        }
        g5c_json_free(dec);
    }
    free(a);
}

/* ---- online charging: the quota in force has been used up (the UPF's usage report of URR 3) ---- */

typedef struct {
    char ref[37];
    smf_usage us;
} charge_arg;

static void net_release(smf *s, smf_sess *ss, uint8_t cause5gsm, bool final, const char *status_cause);

static void count_charging_update(smf *s, const char *result)
{
    g5c_label l = {"result", result};
    g5c_counter_inc(g5c_counter_get(s->metrics, "g5c_smf_charging_updates_total", "Quota updates to the CHF, by result.", &l, 1));
}

/* Reports the volume to the CHF and arms the next quota at the UPF; no further quota ends the session (TS 32.299 5.2: final unit TERMINATE). The session stays locked: the CHF is a short call. */
static void job_charging(smf *s, void *arg)
{
    charge_arg *a = arg;
    smf_sess *ss = sess_lookup(s, a->ref, NULL, 0);
    uint64_t g = 0;
    bool final = false;
    int cr;
    if (ss == NULL) {
        free(a);
        return;
    }
    if (ss->chf_resource == NULL) {
        smf_sess_unlock(ss);
        free(a);
        return;
    }
    if (ss->state == SMF_S_RELEASING) { /* the release is under way (the UE has not confirmed yet and traffic still reports): once is enough */
        smf_sess_unlock(ss);
        free(a);
        return;
    }
    cr = smf_chf_update(s, ss, &a->us, &g, &final);
    if (cr == 0) {
        uint8_t body[64];
        size_t bl = 0;
        if (smf_n4_build_urr_threshold(SMF_URR_CHARGING, g, body, sizeof body, &bl) == 0 && n4_modify(s, ss, body, bl) == 0) {
            ss->chf_granted = g;
            ss->chf_final = final;
            smf_persist_request(s);
            count_charging_update(s, final ? "last_quota" : "granted");
            smf_sess_unlock(ss);
            free(a);
            return;
        }
        count_charging_update(s, "rearm_failed");
        smf_sess_unlock(ss);
        free(a);
        return;
    }
    if (cr < 0) { /* the CHF did not answer: the session goes on, the UPF reports again after another quota's worth */
        count_charging_update(s, "failed");
        smf_sess_unlock(ss);
        free(a);
        return;
    }
    G5C_LOGI("g5c_smf", "no more quota for PDU session %u of %s: releasing it", ss->psi, ss->supi);
    count_charging_update(s, "denied");
    net_release(s, ss, SMF_5GSM_REGULAR_DEACTIVATION, false, NULL);
    free(a);
}

uint8_t smf_usage_report(smf *s, smf_upf *u, uint64_t cp_seid, const uint8_t *body, size_t len, uint64_t *up_seid)
{
    char ref[37] = {0};
    smf_sess *ss;
    smf_usage us;
    pthread_mutex_lock(&s->mu);
    for (ss = s->sessions; ss != NULL; ss = ss->next)
        if (ss->upf == u && ss->cp_seid == cp_seid && !ss->dead) {
            memcpy(ref, ss->ref, sizeof ref);
            break;
        }
    pthread_mutex_unlock(&s->mu);
    if (ref[0] == 0)
        return PFCP_CAUSE_SESSION_NOT_FOUND;
    ss = sess_lookup(s, ref, NULL, 0);
    if (ss == NULL)
        return PFCP_CAUSE_SESSION_NOT_FOUND;
    *up_seid = ss->up_seid;
    smf_sess_unlock(ss);
    if (smf_n4_parse_usage_for(body, len, SMF_URR_MONITOR, &us) == 0) {
        usage_arg *a = g5c_xcalloc(1, sizeof *a);
        memcpy(a->ref, ref, sizeof a->ref);
        a->total = us.total;
        a->ul = us.ul;
        a->dl = us.dl;
        count_usage(s, "received");
        smf_defer(s, job_usage, a); /* not on the N4 receive thread: the PCF call and the N4 modification need it free */
    }
    if (smf_n4_parse_usage_for(body, len, SMF_URR_CHARGING, &us) == 0) {
        charge_arg *a = g5c_xcalloc(1, sizeof *a);
        memcpy(a->ref, ref, sizeof a->ref);
        a->us = us;
        smf_defer(s, job_charging, a);
    }
    return PFCP_CAUSE_ACCEPTED;
}

typedef struct {
    char ref[37];
} guard_arg;

static void job_guard(smf *s, void *arg)
{
    guard_arg *g = arg;
    smf_sess *ss = sess_lookup(s, g->ref, NULL, 0);
    free(g);
    if (ss == NULL)
        return;
    if (ss->state == SMF_S_RELEASING && ss->release_pending_complete)
        sess_teardown(s, ss, "the UE did not confirm the release in time");
    else
        smf_sess_unlock(ss);
}

/* Ask the UE and the gNB to release the session (PDU SESSION RELEASE COMMAND + resource release command) */
static void net_release(smf *s, smf_sess *ss, uint8_t cause5gsm, bool final, const char *status_cause)
{
    g5c_bytes n1, n2;
    char *uri = ss->amf_status_uri != NULL ? g5c_xstrdup(ss->amf_status_uri) : NULL;
    int rc = -1;
    g5c_bytes_init(&n1);
    g5c_bytes_init(&n2);
    ss->state = SMF_S_RELEASING;
    if (smf_gsm_build_release_cmd(ss->psi, 0, cause5gsm, &n1) == 0 && smf_n2_build_release_cmd(&n2) == 0) {
        ss->release_pending_complete = true;
        rc = tell_amf(s, ss, n1.data, n1.len, "PDU_RES_REL_CMD", n2.data, n2.len);
    }
    g5c_bytes_free(&n1);
    g5c_bytes_free(&n2);
    if (ss->dead) {
        smf_sess_unlock(ss);
    } else if (final || rc != 0) {
        if (final)
            ss->up_seid = 0; /* nothing left to delete on the UPF */
        sess_teardown(s, ss, final ? "user plane lost" : "the AMF did not take the release command");
        if (status_cause != NULL)
            notify_released(s, uri, status_cause);
    } else {
        guard_arg *g = g5c_xcalloc(1, sizeof *g);
        memcpy(g->ref, ss->ref, sizeof g->ref);
        smf_sess_unlock(ss);
        smf_defer_after(s, job_guard, g, s->release_guard_ms);
    }
    free(uri);
}

/* PCF-initiated termination of the SM policy association: the session has to go (TS 29.512 4.2.6.2, TS 23.502 4.3.4). */
static void policy_terminate(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    smf *s = ctx;
    smf_sess *ss = smf_sess_find_ref(s, g5c_req_param(req, "smContextRef"));
    if (ss == NULL) {
        g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "no such SM context");
        count_op(s, "policy_terminate", "not_found");
        return;
    }
    G5C_LOGI("g5c_smf", "the PCF terminated the SM policy of PDU session %u of %s: releasing the session", ss->psi, ss->supi);
    net_release(s, ss, SMF_5GSM_REGULAR_DEACTIVATION, false, NULL);
    g5c_resp_status(resp, 204);
    count_op(s, "policy_terminate", "ok");
}

/* ---- IPv6 router advertisement ---- */

/* A router solicitation the UPF forwarded to us (TS 23.501 5.8.2.2.3): answer with the session's /64 so the UE can configure its address. */
void smf_cp_packet(smf *s, uint32_t teid, const uint8_t *pl, size_t len, const smf_peer *from)
{
    char ref[37] = {0};
    smf_sess *ss;
    uint8_t ra[256], prefix[8];
    size_t ralen = 0;
    uint32_t to_teid;
    if (teid == 0)
        return;
    pthread_mutex_lock(&s->mu);
    for (ss = s->sessions; ss != NULL; ss = ss->next)
        if (ss->rs_teid == teid && !ss->dead) {
            memcpy(ref, ss->ref, sizeof ref);
            break;
        }
    pthread_mutex_unlock(&s->mu);
    if (ref[0] == 0)
        return;
    ss = sess_lookup(s, ref, NULL, 0);
    if (ss == NULL)
        return;
    memcpy(prefix, ss->ue6, 8);
    to_teid = ss->cp_teid;
    smf_sess_unlock(ss);
    if (to_teid == 0 || smf_ra_build(prefix, s->mtu, pl, len, ra, sizeof ra, &ralen) != 0) {
        count_op(s, "router_solicitation", "ignored");
        return;
    }
    if (smf_n4_send_gtpu(s->n4, from, to_teid, ra, ralen) == 0)
        count_op(s, "router_solicitation", "answered");
    else
        count_op(s, "router_solicitation", "failed");
}

/* ---- UPF loss / restart ---- */

typedef struct {
    char ref[37];
} ref_arg;

static void job_lost(smf *s, void *arg)
{
    ref_arg *a = arg;
    smf_sess *ss = sess_lookup(s, a->ref, NULL, 0);
    free(a);
    if (ss == NULL)
        return;
    net_release(s, ss, SMF_5GSM_NETWORK_FAILURE, true, "INSUFFICIENT_UP_RESOURCES");
}

void smf_upf_event(smf *s, smf_upf *u, int kind)
{
    size_t n = 0;
    smf_sess *ss;
    if (kind == SMF_UPF_DOWN) {
        G5C_LOGW("g5c_smf", "UPF %s is not answering; its sessions are kept for now", smf_upf_name(u));
        return;
    }
    pthread_mutex_lock(&s->mu);
    for (ss = s->sessions; ss != NULL; ss = ss->next)
        if (ss->upf == u && !ss->dead) {
            ref_arg *a = g5c_xcalloc(1, sizeof *a);
            memcpy(a->ref, ss->ref, sizeof a->ref);
            smf_defer(s, job_lost, a);
            n++;
        }
    pthread_mutex_unlock(&s->mu);
    G5C_LOGW("g5c_smf", "UPF %s %s: releasing %zu PDU session(s) towards the AMF", smf_upf_name(u), kind == SMF_UPF_RESTART ? "restarted" : "was declared lost", n);
    g5c_counter_add(g5c_counter_get(s->metrics, "g5c_smf_sessions_released_upf_loss_total", "PDU sessions released because their UPF restarted or was lost.", NULL, 0), n);
}

/* ---- downlink data notification: page the UE ---- */

static void job_page(smf *s, void *arg)
{
    ref_arg *a = arg;
    smf_sess *ss = sess_lookup(s, a->ref, NULL, 0);
    smf_n2_setup n2s;
    g5c_bytes n2;
    int rc;
    free(a);
    if (ss == NULL)
        return;
    if (ss->state != SMF_S_IDLE) {
        ss->paging = false;
        smf_sess_unlock(ss);
        return;
    }
    memset(&n2s, 0, sizeof n2s);
    n2s.pdu_type = ss->pdu_type;
    n2s.ambr_ul = ss->pol.ambr_ul;
    n2s.ambr_dl = ss->pol.ambr_dl;
    memcpy(n2s.upf_ip4, ss->ul_ip4, 4);
    n2s.ul_teid = ss->ul_teid;
    n2s.pol = &ss->pol;
    g5c_bytes_init(&n2);
    rc = smf_n2_build_setup_req(&n2s, &n2) == 0 ? tell_amf(s, ss, NULL, 0, "PDU_RES_SETUP_REQ", n2.data, n2.len) : -1;
    g5c_bytes_free(&n2);
    if (rc != 0) {
        G5C_LOGW("g5c_smf", "paging of %s for PDU session %u failed", ss->supi, ss->psi);
        ss->paging = false; /* the next report tries again */
    } else {
        G5C_LOGI("g5c_smf", "downlink data for idle PDU session %u of %s: network-triggered service request started", ss->psi, ss->supi);
        count_op(s, "page", "ok");
    }
    smf_sess_unlock(ss);
}

/* A Session Report from the UPF: the cause for the response and the UP SEID to address it to. */
uint8_t smf_downlink_data(smf *s, smf_upf *u, uint64_t cp_seid, bool dldr, uint64_t *up_seid)
{
    char ref[37] = {0};
    smf_sess *ss;
    uint8_t cause = PFCP_CAUSE_SESSION_NOT_FOUND;
    pthread_mutex_lock(&s->mu);
    for (ss = s->sessions; ss != NULL; ss = ss->next)
        if (ss->upf == u && ss->cp_seid == cp_seid && !ss->dead) {
            memcpy(ref, ss->ref, sizeof ref);
            break;
        }
    pthread_mutex_unlock(&s->mu);
    if (ref[0] == 0)
        return cause;
    ss = sess_lookup(s, ref, NULL, 0);
    if (ss == NULL)
        return cause;
    *up_seid = ss->up_seid;
    cause = PFCP_CAUSE_ACCEPTED;
    if (dldr && ss->state == SMF_S_IDLE && !ss->paging) {
        ref_arg *a = g5c_xcalloc(1, sizeof *a);
        memcpy(a->ref, ss->ref, sizeof a->ref);
        ss->paging = true;
        smf_defer(s, job_page, a);
    }
    smf_sess_unlock(ss);
    return cause;
}

void smf_sm_routes(g5c_router *r, smf *s)
{
    g5c_router_route(r, "POST", BASE "/sm-contexts", create_ctx, s);
    g5c_router_route(r, "POST", BASE "/sm-contexts/{smContextRef}/modify", modify_ctx, s);
    g5c_router_route(r, "POST", BASE "/sm-contexts/{smContextRef}/release", release_ctx, s);
    g5c_router_route(r, "POST", "/nsmf-callback/v1/sm-policies/{smContextRef}/update", policy_update, s);
    g5c_router_route(r, "POST", "/nsmf-callback/v1/sm-policies/{smContextRef}/terminate", policy_terminate, s);
}
