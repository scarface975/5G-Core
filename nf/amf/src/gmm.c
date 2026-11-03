#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5GMM procedures of the AMF (TS 24.501 clause 5, TS 23.502 clause 4.2) */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "nasmsg.h"

#define NAS_RETRIES 4 /* the fifth expiry aborts the procedure (TS 24.501 5.4.x.6, 5.5.x.x) */

/* 5GMM message types (TS 24.501 table 9.7.1) */
enum {
    MT_REG_REQ = 0x41,
    MT_REG_COMPLETE = 0x43,
    MT_DEREG_REQ_UE = 0x45,
    MT_DEREG_ACC_UE = 0x46,
    MT_DEREG_ACC_NET = 0x48,
    MT_SERVICE_REQ = 0x4c,
    MT_CFG_COMPLETE = 0x55,
    MT_AUTH_RESP = 0x57,
    MT_AUTH_FAIL = 0x59,
    MT_ID_RESP = 0x5c,
    MT_SMC_COMPLETE = 0x5e,
    MT_SMC_REJECT = 0x5f,
    MT_MM_STATUS = 0x64,
    MT_NOTIF_RESP = 0x66,
    MT_UL_NAS = 0x67
};

typedef struct {
    const nas_protected *prot; /* NULL: the message was not protected */
    bool verified;
    uint32_t count;
} nas_auth;

typedef struct {
    uint8_t type;
    bool follow_on;
    uint8_t ngksi;
    bool has_id;
    nas_mobile_identity id;
    uint8_t ue_cap[8];
    size_t ue_cap_len;
    nas_snssai req[AMF_MAX_SLICE];
    size_t nreq;
    bool has_psi_status;
    uint16_t psi_status;
    bool has_uplink;
    uint16_t uplink;
    bool has_container;
    bool mico;
    bool has_edrx;
    uint8_t edrx;
    bool has_t3324;
    unsigned t3324;
} reg_info;

/* ---- bookkeeping ---- */

amf_ue *conn_ue_ref(amf_conn *c)
{
    amf_ue *u;
    pthread_mutex_lock(&c->a->tmu);
    u = c->ue;
    if (u != NULL)
        u->refs++;
    pthread_mutex_unlock(&c->a->tmu);
    return u;
}

void conn_unbind_ue(amf_conn *c)
{
    amf *a = c->a;
    amf_ue *u = c->ue;
    if (u == NULL)
        return;
    pthread_mutex_lock(&a->tmu);
    c->ue = NULL;
    if (u->conn == c)
        u->conn = NULL;
    if (u->ho_conn == c)
        u->ho_conn = NULL;
    pthread_mutex_unlock(&a->tmu);
    if (c->held == u) {
        pthread_mutex_unlock(&u->mu);
        c->held = NULL;
    }
    amf_ue_unref(u);
}

/* Bind the connection to the UE and take its mutex (kept until the handler returns). */
void conn_bind_ue(amf_conn *c, amf_ue *u)
{
    amf *a = c->a;
    if (c->ue == u && c->held == u)
        return;
    if (c->ue != u && c->ue != NULL)
        conn_unbind_ue(c);
    if (c->held != u) {
        if (c->held != NULL) {
            pthread_mutex_unlock(&c->held->mu);
            c->held = NULL;
        }
        pthread_mutex_lock(&u->mu);
        c->held = u;
    }
    if (c->ue != u) {
        amf_ue_ref(u);
        pthread_mutex_lock(&a->tmu);
        c->ue = u;
        pthread_mutex_unlock(&a->tmu);
    }
}

/* The connection becomes the UE's N2 association (CM-CONNECTED). A stale earlier association is released. */
static void ue_attach_conn(amf_conn *c, amf_ue *u)
{
    amf *a = c->a;
    amf_conn *old = u->conn;
    if (old == c) {
        u->cm = CM_CONNECTED;
        return;
    }
    pthread_mutex_lock(&a->tmu);
    u->conn = c;
    if (old != NULL)
        old->ue = NULL;
    pthread_mutex_unlock(&a->tmu);
    if (old != NULL) {
        conn_timer_stop(old, CT_RELCMD);
        if (!old->closed && !old->rel_sent)
            (void)conn_send_release_cmd(old, "radioNetwork", "release-due-to-5gc-generated-reason", REL_KEEP);
        amf_ue_unref(u); /* the old connection's reference */
    }
    if (u->cm != CM_CONNECTED) {
        u->cm = CM_CONNECTED;
        gmm_event(a, u, EVT_CONNECTIVITY, "CONNECTED");
    }
    ue_timer_stop(u, UT_REACH);
    u->last_active_ms = g5c_unix_millis();
}

void ue_detach_conn(amf_ue *u)
{
    amf_conn *c = u->conn;
    if (c == NULL)
        return;
    pthread_mutex_lock(&u->a->tmu);
    u->conn = NULL;
    c->ue = NULL;
    pthread_mutex_unlock(&u->a->tmu);
    amf_ue_unref(u); /* the connection's reference */
}

/* ---- timers ---- */

void conn_timer_start(amf_conn *c, int kind, unsigned secs)
{
    amf_tslot *t = &c->t[kind];
    t->gen++;
    t->on = true;
    amf_timer_start(c->a, secs * 1000, TT_CONN, kind, c->amf_id, t->gen);
}

void conn_timer_stop(amf_conn *c, int kind)
{
    c->t[kind].gen++;
    c->t[kind].on = false;
}

void ue_timer_start(amf_ue *u, int kind, unsigned secs)
{
    amf_tslot *t = &u->ut[kind];
    t->gen++;
    t->on = true;
    amf_timer_start(u->a, secs * 1000, TT_UE, kind, u->uid, t->gen);
}

void ue_timer_stop(amf_ue *u, int kind)
{
    u->ut[kind].gen++;
    u->ut[kind].on = false;
}

void conn_clear_proc(amf_conn *c)
{
    for (int k = CT_AUTH; k <= CT_DEREG; k++)
        conn_timer_stop(c, k);
    c->proc = PR_NONE;
    free(c->last_nas);
    c->last_nas = NULL;
    c->last_len = 0;
}

static void remember(amf_conn *c, const uint8_t *nas, size_t len, uint8_t sht)
{
    free(c->last_nas);
    c->last_nas = g5c_xmalloc(len);
    memcpy(c->last_nas, nas, len);
    c->last_len = len;
    c->last_sht = sht;
}

/* ---- sending ---- */

/* protection: 0 plain; 2 current context (integrity + ciphering); 3 the provisional context (integrity only, new context) */
static int protect(amf_ue *u, uint8_t sht, const uint8_t *plain, size_t len, g5c_bytes *out)
{
    if (u == NULL || sht == 0 || (sht == 2 && !u->sec.valid) || (sht == 3 && !u->sec_new_valid))
        return g5c_bytes_append(out, plain, len);
    return sec_protect_dl(sht == 3 ? &u->sec_new : &u->sec, sht, plain, len, out) == NAS_OK ? 0 : -1;
}

static int send_dl(amf_conn *c, amf_ue *u, const uint8_t *plain, size_t len, uint8_t sht)
{
    g5c_bytes b;
    int rc;
    g5c_bytes_init(&b);
    if (protect(u, sht, plain, len, &b) != 0) {
        g5c_bytes_free(&b);
        return -1;
    }
    rc = conn_send_nas(c, b.data, b.len);
    g5c_bytes_free(&b);
    return rc;
}

int gmm_send_dl(amf_conn *c, amf_ue *u, const uint8_t *plain, size_t len)
{
    return send_dl(c, u, plain, len, u != NULL && u->sec.valid ? 2 : 0);
}

int gmm_send_dl_ex(amf_conn *c, amf_ue *u, const uint8_t *plain, size_t len, bool new_ctx)
{
    return send_dl(c, u, plain, len, new_ctx ? 3 : (u != NULL && u->sec.valid ? 2 : 0));
}

void gmm_send_plain(amf_conn *c, const uint8_t *nas, size_t len)
{
    (void)conn_send_nas(c, nas, len);
}

/* A request that is sent again when its timer expires: kept in the plain form, protected afresh each time. */
static void send_procedure_msg(amf_conn *c, amf_ue *u, const uint8_t *plain, size_t len, uint8_t sht, int timer, unsigned secs, amf_proc proc)
{
    remember(c, plain, len, sht);
    c->proc = proc;
    c->t[timer].tries = 0;
    (void)send_dl(c, u, plain, len, sht);
    conn_timer_start(c, timer, secs);
}

/* ---- identities ---- */

static bool guti_is_ours(const amf *a, const nas_mobile_identity *id)
{
    char mcc[4], mnc[4];
    (void)mcc;
    (void)mnc;
    return id->kind == NAS_ID_GUTI && strcmp(id->mcc, a->cfg.mcc) == 0 && strcmp(id->mnc, a->cfg.mnc) == 0 && id->amf_region == a->cfg.id.region &&
           id->amf_set == a->cfg.id.set && id->amf_pointer == a->cfg.id.pointer;
}

static bool stmsi_is_ours(const amf *a, const nas_mobile_identity *id)
{
    return id->kind == NAS_ID_STMSI && id->amf_set == a->cfg.id.set && id->amf_pointer == a->cfg.id.pointer;
}

static uint16_t bitmap16(const uint8_t *v, size_t n)
{
    return (uint16_t)((n > 0 ? v[0] : 0) | (n > 1 ? v[1] << 8 : 0));
}

static int parse_reg(const nas_msg *m, reg_info *ri)
{
    size_t n;
    const uint8_t *v;
    memset(ri, 0, sizeof *ri);
    v = nas_msg_get(m, "5GS registration type", &n);
    if (v == NULL || n < 1)
        return -1;
    {
        nas_reg_type rt = nas_reg_type_from_nibble(v[0]);
        ri->type = rt.kind;
        ri->follow_on = rt.follow_on;
    }
    v = nas_msg_get(m, "ngKSI", &n);
    ri->ngksi = (v != NULL && n >= 1) ? (uint8_t)(v[0] & 0x0f) : 0x07;
    v = nas_msg_get(m, "5GS mobile identity", &n);
    if (v == NULL || nas_mobile_identity_decode(v, n, &ri->id) != NAS_OK)
        return -1;
    ri->has_id = true;
    v = nas_msg_get(m, "UE security capability", &n);
    if (v != NULL && n >= 2 && n <= sizeof ri->ue_cap) {
        memcpy(ri->ue_cap, v, n);
        ri->ue_cap_len = n;
    }
    v = nas_msg_get(m, "Requested NSSAI", &n);
    if (v != NULL) {
        int k = nas_nssai_decode(v, n, ri->req, AMF_MAX_SLICE);
        ri->nreq = k > 0 ? (size_t)k : 0;
    }
    v = nas_msg_get(m, "PDU session status", &n);
    if (v != NULL && n >= 2) {
        ri->has_psi_status = true;
        ri->psi_status = bitmap16(v, n);
    }
    v = nas_msg_get(m, "Uplink data status", &n);
    if (v != NULL && n >= 2) {
        ri->has_uplink = true;
        ri->uplink = bitmap16(v, n);
    }
    ri->has_container = nas_msg_get(m, "NAS message container", &n) != NULL;
    ri->mico = nas_msg_get(m, "MICO indication", &n) != NULL;
    v = nas_msg_get(m, "Requested extended DRX parameters", &n);
    if (v != NULL && n >= 1) {
        ri->has_edrx = true;
        ri->edrx = v[0];
    }
    v = nas_msg_get(m, "T3324 value", &n);
    if (v != NULL && n >= 1) {
        ri->has_t3324 = true;
        ri->t3324 = nm_gprs_timer3_secs(v[0]);
    }
    return 0;
}

static bool reg_from_bytes(const uint8_t *b, size_t len, reg_info *ri)
{
    nas_msg m;
    bool ok;
    if (nas_msg_decode(b, len, &m) != NAS_OK)
        return false;
    ok = m.def != NULL && m.def->msg_type == MT_REG_REQ && parse_reg(&m, ri) == 0;
    nas_msg_free(&m);
    return ok;
}

/* verifies an integrity protected initial message against the UE's context (committing the count) */
static bool auth_check(amf_ue *u, nas_auth *au)
{
    g5c_bytes plain;
    int rc;
    if (au->verified)
        return true;
    if (au->prot == NULL || u == NULL || !u->sec.valid)
        return false;
    g5c_bytes_init(&plain);
    rc = sec_open_ul(&u->sec, au->prot, &plain, &au->count, true);
    g5c_bytes_free(&plain);
    au->verified = rc == 0;
    return au->verified;
}

/* ---- release helpers ---- */

static void release_conn(amf_conn *c, const char *group, const char *cause, uint8_t then)
{
    if (c->closed || c->rel_sent)
        return;
    conn_clear_proc(c);
    (void)conn_send_release_cmd(c, group, cause, then);
}

/* the UE is gone (or its NAS security was refused): the AUSF has the UDM remove the authentication result (TS 29.509 5.2.2.2.5, 5.2.2.2.6) */
static void auth_result_remove(amf *a, amf_ue *u)
{
    if (u->ausf_url[0] != 0) {
        amf_ausf_remove(a, u->ausf_url);
        u->ausf_url[0] = 0;
    }
}

/* forget a context that never became a registration */
void amf_ue_gc(amf_ue *u)
{
    if (u->mm == MM_REGISTERED || amf_pdu_count(u) > 0 || u->removed)
        return;
    auth_result_remove(u->a, u);
    if (u->uecm)
        amf_udm_deregister(u->a, u);
    amf_pcf_delete(u->a, u);
    amf_udm_sdm_unsubscribe(u->a, u);
    amf_ue_remove(u);
}

static void reg_reject_t3346(amf_conn *c, amf_ue *u, uint8_t cause, const char *why, unsigned t3346_s)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    G5C_LOGI(AMF_LOG, "registration of %s rejected, cause #%u (%s)", u != NULL ? u->supi : "(unidentified)", cause, why);
    amf_count(c->a, "g5c_amf_registrations_total", "Registration requests by result.", "result", cause == MM_CAUSE_CONGESTION ? "congestion" : "rejected");
    if (nm_reg_reject_t3346(cause, t3346_s, &b) == 0) {
        if (c->sec_active && u != NULL && u->sec.valid)
            (void)send_dl(c, u, b.data, b.len, 2);
        else
            (void)conn_send_nas(c, b.data, b.len);
    }
    g5c_bytes_free(&b);
    release_conn(c, "nas", "unspecified", REL_DELETE_UE);
}

static void reg_reject(amf_conn *c, amf_ue *u, uint8_t cause, const char *why)
{
    reg_reject_t3346(c, u, cause, why, 0);
}

static double mono_now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* refill a bucket of `rate` tokens a second holding `cap`, and take one if there is one */
static bool bucket_take(double *tokens, double *last, double rate, double cap, double now, bool commit)
{
    double t = *tokens + (*last > 0 ? (now - *last) * rate : cap);
    if (t > cap)
        t = cap;
    *last = now;
    if (t < 1.0) {
        *tokens = t;
        return false;
    }
    *tokens = commit ? t - 1.0 : t;
    return true;
}

/* signalling-storm protection (TS 24.501 5.5.1.2.5, 5.3.9): registrations above the configured rate, for the AMF and for each gNB, are turned away with cause #22 and a back-off timer */
static bool admit_registration(amf_conn *c, unsigned *t3346)
{
    amf *a = c->a;
    bool ok = true;
    pthread_mutex_lock(&a->tmu); /* the limits can change while the function runs (configuration reload) */
    *t3346 = a->cfg.ov_t3346;
    if (a->cfg.ov_regs_per_s == 0 && a->cfg.ov_gnb_regs_per_s == 0) {
        pthread_mutex_unlock(&a->tmu);
        return true;
    }
    {
        double now = mono_now(), burst = a->cfg.ov_burst_s > 0 ? a->cfg.ov_burst_s : 1;
        amf_gnb *g = c->gnb < AMF_MAX_GNB ? &a->gnbs[c->gnb] : NULL;
        double all_cap = a->cfg.ov_regs_per_s * burst, gnb_cap = a->cfg.ov_gnb_regs_per_s * burst;
        bool all_ok = a->cfg.ov_regs_per_s == 0 || bucket_take(&a->ov_tokens, &a->ov_last, a->cfg.ov_regs_per_s, all_cap < 1 ? 1 : all_cap, now, false);
        bool gnb_ok = g == NULL || a->cfg.ov_gnb_regs_per_s == 0 || bucket_take(&g->ov_tokens, &g->ov_last, a->cfg.ov_gnb_regs_per_s, gnb_cap < 1 ? 1 : gnb_cap, now, false);
        ok = all_ok && gnb_ok;
        if (ok) { /* a token from each bucket in use, only when both had one */
            if (a->cfg.ov_regs_per_s > 0)
                a->ov_tokens -= 1.0;
            if (g != NULL && a->cfg.ov_gnb_regs_per_s > 0)
                g->ov_tokens -= 1.0;
        }
    }
    pthread_mutex_unlock(&a->tmu);
    return ok;
}

/* ---- registration: identification and authentication ---- */

static void start_auth(amf_conn *c, amf_ue *u, const char *id);
static void reg_proceed(amf_conn *c, amf_ue *u);

static void send_identity_request(amf_conn *c)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    if (nm_identity_request(&b) == 0)
        send_procedure_msg(c, NULL, b.data, b.len, 0, CT_IDENT, c->a->cfg.t3570, PR_IDENTITY);
    g5c_bytes_free(&b);
}

static void start_auth(amf_conn *c, amf_ue *u, const char *id)
{
    amf *a = c->a;
    amf_authv av;
    int http = 0;
    uint8_t ngksi = 0, abba[2] = {0, 0};
    g5c_bytes b;
    snprintf(c->auth_id, sizeof c->auth_id, "%s", id);
    if (amf_ausf_start(a, id, NULL, NULL, &av, &http) != 0) {
        uint8_t cause = MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED;
        if (http == 404)
            cause = MM_CAUSE_5GS_NOT_ALLOWED;
        else if (http == 403)
            cause = MM_CAUSE_PLMN_NOT_ALLOWED;
        amf_count(a, "g5c_amf_authentications_total", "5G-AKA runs by result.", "result", "ausf_error");
        reg_reject(c, u, cause, http == 0 ? "the AUSF is unreachable" : "the AUSF refused the request");
        return;
    }
    snprintf(c->auth_url, sizeof c->auth_url, "%s", av.ctx_url);
    memcpy(c->rand, av.rand, 16);
    memcpy(c->hxres, av.hxres, 16);
    memcpy(c->autn, av.autn, 16);
    while (ngksi == c->ngksi_ue || (u != NULL && u->sec.valid && ngksi == u->sec.ngksi))
        ngksi++;
    c->smc_ngksi = ngksi;
    c->auth_eap = av.eap;
    c->eap_succ_len = 0;
    g5c_bytes_init(&b);
    /* EAP-AKA' carries the EAP-Request/AKA'-Challenge in the EAP message IE instead of RAND and AUTN (TS 24.501 5.4.1.2.1) */
    if ((av.eap ? nm_auth_request_eap(ngksi, abba, av.eap_pkt, av.eap_len, &b) : nm_auth_request(ngksi, abba, c->rand, c->autn, &b)) != 0) {
        g5c_bytes_free(&b);
        reg_reject(c, u, MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED, "cannot build the authentication request");
        return;
    }
    send_procedure_msg(c, NULL, b.data, b.len, 0, CT_AUTH, a->cfg.t3560, PR_AUTH);
    g5c_bytes_free(&b);
}

static void auth_reject_eap(amf_conn *c, amf_ue *u, const uint8_t *eap, size_t eap_len)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    G5C_LOGW(AMF_LOG, "EAP authentication of %s failed", u != NULL ? u->supi : c->auth_id);
    atomic_fetch_add(&c->a->st_auth_fail, 1);
    amf_count(c->a, "g5c_amf_authentications_total", "5G-AKA runs by result.", "result", "failed");
    /* TS 24.501 5.4.1.2.1: the EAP-failure goes to the UE in the AUTHENTICATION REJECT */
    if (nm_auth_reject_eap(eap, eap_len, &b) == 0)
        (void)conn_send_nas(c, b.data, b.len);
    g5c_bytes_free(&b);
    if (u != NULL) {
        sec_clear(&u->sec_new);
        u->sec_new_valid = false;
        if (u->mm != MM_REGISTERED)
            u->sec.valid = false;
    }
    release_conn(c, "nas", "authentication-failure", REL_DELETE_UE);
}

static void auth_reject(amf_conn *c, amf_ue *u, const char *why)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    G5C_LOGW(AMF_LOG, "authentication of %s failed: %s", u != NULL ? u->supi : c->auth_id, why);
    atomic_fetch_add(&c->a->st_auth_fail, 1);
    amf_count(c->a, "g5c_amf_authentications_total", "5G-AKA runs by result.", "result", "failed");
    if (nm_auth_reject(&b) == 0)
        (void)conn_send_nas(c, b.data, b.len);
    g5c_bytes_free(&b);
    if (u != NULL) {
        sec_clear(&u->sec_new);
        u->sec_new_valid = false;
        if (u->mm != MM_REGISTERED)
            u->sec.valid = false;
    }
    release_conn(c, "nas", "authentication-failure", REL_DELETE_UE);
}

static void start_smc(amf_conn *c, amf_ue *u)
{
    amf *a = c->a;
    uint8_t ia = 0, ea = 0;
    g5c_bytes b;
    if (sec_select_algs(a, c->ue_cap, c->ue_cap_len, &ia, &ea) != 0) {
        reg_reject(c, u, MM_CAUSE_UE_SECURITY_CAP_MISMATCH, "no common NAS security algorithms");
        return;
    }
    u->sec_new.int_alg = ia;
    u->sec_new.enc_alg = ea;
    sec_derive_nas_keys(&u->sec_new);
    u->sec_new.ul_count = 0;
    u->sec_new.dl_count = 0;
    u->sec_new_valid = true;
    memcpy(u->ue_cap, c->ue_cap, c->ue_cap_len);
    u->ue_cap_len = c->ue_cap_len;
    g5c_bytes_init(&b);
    if ((c->eap_succ_len > 0 ? nm_smc_eap(ia, ea, u->sec_new.ngksi, c->ue_cap, c->ue_cap_len, u->pei[0] == 0, c->init_plain, c->eap_succ, c->eap_succ_len, (const uint8_t[2]){0, 0}, &b)
                             : nm_smc(ia, ea, u->sec_new.ngksi, c->ue_cap, c->ue_cap_len, u->pei[0] == 0, c->init_plain, &b)) != 0) {
        g5c_bytes_free(&b);
        reg_reject(c, u, MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED, "cannot build the security mode command");
        return;
    }
    send_procedure_msg(c, u, b.data, b.len, 3, CT_SMC, a->cfg.t3560, PR_SMC);
    g5c_bytes_free(&b);
}

static void on_identity_response(amf_conn *c, const nas_msg *m)
{
    size_t n;
    const uint8_t *v = nas_msg_get(m, "Mobile identity", &n);
    nas_mobile_identity id;
    char *suci;
    if (c->proc != PR_IDENTITY)
        return;
    conn_timer_stop(c, CT_IDENT);
    c->proc = PR_NONE;
    if (v == NULL || nas_mobile_identity_decode(v, n, &id) != NAS_OK || id.kind != NAS_ID_SUCI) {
        reg_reject(c, c->ue, MM_CAUSE_UE_ID_CANNOT_BE_DERIVED, "identity response without a SUCI");
        return;
    }
    suci = nas_suci_to_string(&id);
    if (suci == NULL) {
        reg_reject(c, c->ue, MM_CAUSE_UE_ID_CANNOT_BE_DERIVED, "unusable SUCI");
        return;
    }
    snprintf(c->suci, sizeof c->suci, "%s", suci);
    c->have_suci = true;
    free(suci);
    start_auth(c, c->ue, c->suci);
}

/* the AUSF has authenticated the UE (5G AKA or EAP-AKA'): bind the UE, derive KAMF from KSEAF and go on with the security mode control */
static void auth_done(amf_conn *c, const char *supi, const uint8_t kseaf_in[32])
{
    amf *a = c->a;
    uint8_t kseaf[32], kamf[32], abba[2] = {0, 0};
    char digits[32];
    amf_ue *u;
    memcpy(kseaf, kseaf_in, 32);
    atomic_fetch_add(&a->st_auth_ok, 1);
    amf_count(a, "g5c_amf_authentications_total", "5G-AKA runs by result.", "result", "success");
    u = amf_ue_get_or_create(a, supi);
    if (c->ue != NULL && c->ue != u)
        G5C_LOGW(AMF_LOG, "the GUTI of %s belongs to another subscriber than the one authenticated (%s)", c->ue->supi, supi);
    conn_bind_ue(c, u);
    snprintf(u->ausf_url, sizeof u->ausf_url, "%s", c->auth_url); /* removed with the registration */
    amf_ue_unref(u);
    amf_supi_digits(supi, digits, sizeof digits);
    if (g5c_kamf(kseaf, digits, abba, kamf) != 0) {
        reg_reject(c, u, MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED, "key derivation failed");
        return;
    }
    sec_new_context(&u->sec_new, kamf, c->smc_ngksi, abba);
    OPENSSL_cleanse(kseaf, sizeof kseaf);
    OPENSSL_cleanse(kamf, sizeof kamf);
    start_smc(c, u);
}

/* EAP-AKA': the AUTHENTICATION RESPONSE carries the EAP response of the UE; the AUSF (the EAP server) answers with the next request, the failure */
static void on_eap_response(amf_conn *c, const nas_msg *m)
{
    amf *a = c->a;
    size_t n = 0;
    const uint8_t *v = nas_msg_get(m, "EAP message", &n);
    amf_eapr r;
    int http = 0;
    const uint8_t abba[2] = {0, 0};
    g5c_bytes b;
    conn_timer_stop(c, CT_AUTH);
    c->proc = PR_NONE;
    if (amf_ausf_eap(a, c->auth_url, v, v != NULL ? n : 0, &r, &http) != 0) {
        reg_reject(c, c->ue, MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED, "the AUSF could not process the EAP message");
        return;
    }
    if (r.next_url[0] != 0)
        snprintf(c->auth_url, sizeof c->auth_url, "%s", r.next_url);
    if (r.result == 0) {
        /* another round (a synchronisation failure answered with a new challenge, the notification of the result indication) */
        g5c_bytes_init(&b);
        if (nm_auth_request_eap(c->smc_ngksi, abba, r.pkt, r.len, &b) == 0)
            send_procedure_msg(c, NULL, b.data, b.len, 0, CT_AUTH, a->cfg.t3560, PR_AUTH);
        g5c_bytes_free(&b);
        return;
    }
    if (r.result < 0) {
        auth_reject_eap(c, c->ue, r.pkt, r.len);
        return;
    }
    c->eap_succ_len = r.len < sizeof c->eap_succ ? r.len : sizeof c->eap_succ;
    memcpy(c->eap_succ, r.pkt, c->eap_succ_len);
    auth_done(c, r.supi, r.kseaf);
}

static void on_auth_response(amf_conn *c, const nas_msg *m)
{
    amf *a = c->a;
    size_t n;
    const uint8_t *v = nas_msg_get(m, "Authentication response parameter", &n);
    uint8_t hres[16], kseaf[32];
    char supi[40];
    bool ok = false;
    int http = 0;
    if (c->proc != PR_AUTH)
        return;
    if (c->auth_eap) {
        on_eap_response(c, m);
        return;
    }
    if (v == NULL || n != 16) {
        auth_reject(c, c->ue, "malformed response parameter");
        return;
    }
    conn_timer_stop(c, CT_AUTH);
    c->proc = PR_NONE;
    /* the serving network checks HRES* against HXRES* before asking the AUSF (TS 33.501 6.1.3.2.0) */
    if (g5c_hres_star(c->rand, v, hres) != 0 || CRYPTO_memcmp(hres, c->hxres, 16) != 0) {
        auth_reject(c, c->ue, "HRES* does not match HXRES*");
        return;
    }
    if (amf_ausf_confirm(a, c->auth_url, v, supi, sizeof supi, kseaf, &ok, &http) != 0) {
        reg_reject(c, c->ue, MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED, "the AUSF could not confirm the authentication");
        return;
    }
    if (!ok) {
        auth_reject(c, c->ue, "the AUSF rejected RES*");
        return;
    }
    auth_done(c, supi, kseaf);
    OPENSSL_cleanse(kseaf, sizeof kseaf);
}

static void on_auth_failure(amf_conn *c, const nas_msg *m)
{
    amf *a = c->a;
    size_t n;
    const uint8_t *cause = nas_msg_get(m, "5GMM cause", &n), *auts = nas_msg_get(m, "Authentication failure parameter", &n);
    size_t autsn = auts != NULL ? n : 0;
    amf_authv av;
    int http = 0;
    uint8_t ngksi = c->smc_ngksi, abba[2] = {0, 0};
    g5c_bytes b;
    if (c->proc != PR_AUTH)
        return;
    conn_timer_stop(c, CT_AUTH);
    c->proc = PR_NONE;
    if (c->auth_eap) {
        /* an EAP run reports its failures as EAP responses (TS 24.501 5.4.1.2.2.4); a NAS-level failure ends it */
        auth_reject(c, c->ue, "failure reported by the UE");
        return;
    }
    if (cause != NULL && cause[0] == MM_CAUSE_SYNCH_FAILURE && autsn == 14 && c->auth_syncs < 2) {
        c->auth_syncs++;
        amf_count(a, "g5c_amf_authentications_total", "5G-AKA runs by result.", "result", "resync");
        if (amf_ausf_start(a, c->auth_id, c->rand, auts, &av, &http) != 0) {
            reg_reject(c, c->ue, MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED, "resynchronisation failed at the AUSF");
            return;
        }
        snprintf(c->auth_url, sizeof c->auth_url, "%s", av.ctx_url);
        memcpy(c->rand, av.rand, 16);
        memcpy(c->hxres, av.hxres, 16);
        memcpy(c->autn, av.autn, 16);
        g5c_bytes_init(&b);
        if (nm_auth_request(ngksi, abba, c->rand, c->autn, &b) == 0)
            send_procedure_msg(c, NULL, b.data, b.len, 0, CT_AUTH, a->cfg.t3560, PR_AUTH);
        g5c_bytes_free(&b);
        return;
    }
    if (cause != NULL && cause[0] == MM_CAUSE_MAC_FAILURE && c->auth_mac_fail < 1 && c->ident.kind == NAS_ID_GUTI && !c->have_suci) {
        /* the GUTI led to a context whose subscriber the UE does not recognise: ask for the SUCI (TS 24.501 5.4.1.3.7 b) */
        c->auth_mac_fail++;
        send_identity_request(c);
        return;
    }
    auth_reject(c, c->ue, cause != NULL && cause[0] == MM_CAUSE_MAC_FAILURE ? "MAC failure reported by the UE" : "failure reported by the UE");
}

/* ---- registration: security mode control ---- */

static void on_smc_complete(amf_conn *c, amf_ue *u, const nas_msg *m, uint32_t count)
{
    size_t n;
    const uint8_t *v;
    if (c->proc != PR_SMC || !u->sec_new_valid)
        return;
    conn_timer_stop(c, CT_SMC);
    c->proc = PR_NONE;
    u->sec = u->sec_new; /* the new native context becomes the current one */
    sec_clear(&u->sec_new);
    u->sec_new_valid = false;
    u->sec.ul_count = count + 1;
    c->kgnb_ul = count;
    c->sec_active = true;
    amf_conn_authenticated(c);
    v = nas_msg_get(m, "IMEISV", &n);
    if (v != NULL && n > 0) {
        nas_mobile_identity id;
        if (nas_mobile_identity_decode(v, n, &id) == NAS_OK && id.kind == NAS_ID_IMEISV)
            snprintf(u->pei, sizeof u->pei, "imeisv-%s", id.digits);
    }
    v = nas_msg_get(m, "NAS message container", &n);
    if (v != NULL && n > 0) {
        free(c->init_nas);
        c->init_nas = g5c_xmalloc(n);
        memcpy(c->init_nas, v, n);
        c->init_len = n;
    }
    reg_proceed(c, u);
}

/* ---- registration: subscription, policy, slices, accept ---- */

static void select_slices(amf *a, amf_ue *u, const reg_info *ri, nas_snssai *allowed, size_t *nallowed, nas_snssai *rejected, size_t *nrej)
{
    *nallowed = 0;
    *nrej = 0;
    for (size_t i = 0; i < ri->nreq; i++) {
        const nas_snssai *r = &ri->req[i];
        bool sub = u->nsubscribed == 0 || amf_snssai_in(u->subscribed, u->nsubscribed, r);
        bool sup = amf_snssai_in(a->cfg.slices, a->cfg.nslices, r);
        if (sub && sup) {
            if (!amf_snssai_in(allowed, *nallowed, r) && *nallowed < AMF_MAX_SLICE)
                allowed[(*nallowed)++] = *r;
        } else if (*nrej < AMF_MAX_SLICE) {
            rejected[(*nrej)++] = *r;
        }
    }
    if (*nallowed == 0) { /* nothing requested or nothing available: the default S-NSSAIs (TS 23.501 5.15.5.2.1) */
        size_t n = u->ndefault > 0 ? u->ndefault : u->nsubscribed;
        for (size_t i = 0; i < n && *nallowed < AMF_MAX_SLICE; i++)
            if (amf_snssai_in(a->cfg.slices, a->cfg.nslices, &u->subscribed[i]))
                allowed[(*nallowed)++] = u->subscribed[i];
        if (u->nsubscribed == 0)
            for (size_t i = 0; i < a->cfg.nslices && *nallowed < AMF_MAX_SLICE; i++)
                allowed[(*nallowed)++] = a->cfg.slices[i];
    }
}

static void fill_common(amf *a, nm_regacc *ra, amf_ue *u)
{
    memset(ra, 0, sizeof *ra);
    memcpy(ra->plmn, a->cfg.plmn, 3);
    ra->id = a->cfg.id;
    memcpy(ra->tai, u->tai_list, u->ntai * sizeof u->tai_list[0]);
    ra->ntai = u->ntai;
    ra->t3512 = a->cfg.t3512;
}

/* Network slice admission control (TS 23.501 5.15.11): a slice that already holds its maximum number of registered UEs leaves the allowed NSSAI and joins the rejected one. A UE that
 * is registered already keeps the slices it has. Two registrations racing for the last place can both get it: the count is of UEs registered. The Rel-17 "Extended rejected NSSAI"
 * with its back-off timer is not in the pinned NAS tables (Rel-16), so the plain Rejected NSSAI carries the slice. */
static void admit_slices(amf *a, const amf_ue *u, nas_snssai *allowed, size_t *nallowed, nas_snssai *rejected, size_t *nrej)
{
    for (unsigned k = 0; k < a->cfg.nslice_limit && *nallowed > 0; k++) {
        const nas_snssai *lim = &a->cfg.slice_limit[k].s;
        size_t n = 0;
        if (!amf_snssai_in(allowed, *nallowed, lim) || amf_snssai_in(u->allowed, u->mm == MM_REGISTERED ? u->nallowed : 0, lim))
            continue;
        pthread_mutex_lock(&a->tmu);
        for (const amf_ue *v = a->ues; v != NULL; v = v->next_all)
            n += v != u && v->mm == MM_REGISTERED && amf_snssai_in(v->allowed, v->nallowed, lim);
        pthread_mutex_unlock(&a->tmu);
        if (n < a->cfg.slice_limit[k].max_ues)
            continue;
        for (size_t i = 0; i < *nallowed; i++)
            if (amf_snssai_in(&allowed[i], 1, lim)) {
                memmove(&allowed[i], &allowed[i + 1], (*nallowed - i - 1) * sizeof allowed[0]);
                (*nallowed)--;
                break;
            }
        if (*nrej < AMF_MAX_SLICE)
            rejected[(*nrej)++] = *lim;
        amf_count(a, "g5c_amf_slice_admission_total", "Slices left out of the allowed NSSAI because they hold their maximum number of UEs.", "result", "rejected");
    }
}

/* MICO mode, extended DRX and the active timer are granted per registration, only when the UE asked and `amf.power_saving` allows (TS 24.501 5.3.10, 5.3.11, 5.3.5).
 * The cycle is limited to what NGAP can carry (Paging-eDRX-Cycle ends at hf256); the paging time window is kept as requested. */
static void negotiate_power_saving(amf *a, amf_ue *u, const reg_info *ri, nm_regacc *ra)
{
    u->mico = ri->mico && a->cfg.ps_mico;
    ra->mico = u->mico;
    u->has_edrx = ri->has_edrx && a->cfg.ps_edrx;
    if (u->has_edrx) {
        unsigned cycle = ri->edrx & 0x0f;
        if (cycle > a->cfg.ps_edrx_max)
            cycle = a->cfg.ps_edrx_max;
        u->edrx = (uint8_t)((ri->edrx & 0xf0) | cycle);
    }
    ra->has_edrx = u->has_edrx;
    ra->edrx = u->edrx;
    u->t3324 = 0;
    if (ri->has_t3324 && ri->t3324 != 0 && a->cfg.ps_psm)
        u->t3324 = ri->t3324 < a->cfg.ps_t3324_max ? ri->t3324 : a->cfg.ps_t3324_max;
    ra->t3324 = u->t3324;
    if (u->mico)
        amf_count(a, "g5c_amf_power_saving_total", "Power saving features granted at registration, by feature.", "feature", "mico");
    if (u->has_edrx)
        amf_count(a, "g5c_amf_power_saving_total", "Power saving features granted at registration, by feature.", "feature", "edrx");
    if (u->t3324 != 0)
        amf_count(a, "g5c_amf_power_saving_total", "Power saving features granted at registration, by feature.", "feature", "psm");
}

/* Why an idle UE cannot be paged now: in MICO mode it listens only after it has sent something itself; in power saving mode only until T3324 has run out. NULL: it can be. */
static const char *unreachable_reason(const amf_ue *u)
{
    if (u->mico)
        return "mico";
    if (u->t3324 != 0 && g5c_now_seconds() - u->idle_at > u->t3324)
        return "psm";
    return NULL;
}

static void reg_proceed(amf_conn *c, amf_ue *u)
{
    amf *a = c->a;
    reg_info ri;
    nas_snssai rejected[AMF_MAX_SLICE];
    size_t nrej = 0, nallowed = 0;
    nas_snssai allowed[AMF_MAX_SLICE];
    nm_regacc ra;
    g5c_bytes b;
    g5c_json *list = NULL;
    uint16_t react = 0;
    uint32_t tmsi;
    bool via_ics;

    if (!reg_from_bytes(c->init_nas, c->init_len, &ri)) {
        reg_reject(c, u, MM_CAUSE_INVALID_MANDATORY_INFO, "unreadable registration request");
        return;
    }
    if (c->has_tai) {
        bool ok = false;
        for (size_t i = 0; i < a->cfg.ntai; i++)
            ok = ok || amf_tai_eq(&a->cfg.tai[i], &c->tai);
        if (!ok) {
            reg_reject(c, u, MM_CAUSE_TA_NOT_ALLOWED, "tracking area not served");
            return;
        }
        u->loc = c->tai;
        u->has_loc = true;
    }
    ue_attach_conn(c, u);
    u->reg_type = ri.type;

    if (!u->uecm) {
        int rc = amf_udm_register(a, u);
        if (rc != 0) {
            reg_reject(c, u, rc == 404 ? MM_CAUSE_5GS_NOT_ALLOWED : MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED, "the UDM did not accept the registration");
            return;
        }
        u->uecm = true;
    }
    if (u->nsubscribed == 0 || ri.type == 1) {
        int rc = amf_udm_am_data(a, u);
        if (rc != 0) {
            reg_reject(c, u, rc == 404 ? MM_CAUSE_5GS_NOT_ALLOWED : MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED, "no access and mobility subscription data");
            return;
        }
    }
    if (u->pcf_url[0] == 0)
        (void)amf_pcf_create(a, u);
    if (!u->sdm_subscribed)
        amf_udm_sdm_subscribe(a, u);

    if (a->cfg.use_nssf) {
        const amf_tai *where = c->has_tai ? &c->tai : &a->cfg.tai[0];
        int nrc = amf_nssf_registration(a, u, where, ri.req, ri.nreq, allowed, &nallowed, rejected, &nrej);
        if (nrc < 0) /* no answer: the AMF's own lists decide, as without an NSSF */
            select_slices(a, u, &ri, allowed, &nallowed, rejected, &nrej);
        else if (nrc == 1)
            nallowed = 0;
    } else {
        select_slices(a, u, &ri, allowed, &nallowed, rejected, &nrej);
    }
    admit_slices(a, u, allowed, &nallowed, rejected, &nrej);
    if (nallowed == 0) {
        reg_reject(c, u, MM_CAUSE_NO_SLICES_AVAILABLE, "no network slice is available to the UE");
        return;
    }
    for (unsigned k = 0; k < a->cfg.ninject_reject; k++) /* failure injection (amf.inject) */
        if (strncmp(u->supi, a->cfg.inject_reject[k].supi, strlen(a->cfg.inject_reject[k].supi)) == 0) {
            amf_count(a, "g5c_amf_injected_total", "Failures injected on purpose (amf.inject), by kind.", "kind", "registration_reject");
            reg_reject(c, u, a->cfg.inject_reject[k].cause, "injected failure (amf.inject)");
            return;
        }
    if (a->cfg.inject_delay_ms != 0) {
        amf_count(a, "g5c_amf_injected_total", "Failures injected on purpose (amf.inject), by kind.", "kind", "accept_delay");
        usleep(a->cfg.inject_delay_ms * 1000u);
    }
    memcpy(u->allowed, allowed, nallowed * sizeof allowed[0]);
    u->nallowed = nallowed;
    memcpy(u->tai_list, a->cfg.tai, a->cfg.ntai * sizeof a->cfg.tai[0]);
    u->ntai = a->cfg.ntai;

    /* PDU session status and reactivation (TS 24.501 5.5.1.2.4) */
    fill_common(a, &ra, u);
    negotiate_power_saving(a, u, &ri, &ra);
    if (ri.has_psi_status) {
        (void)amf_psi_status_reconcile(a, u, ri.psi_status);
        ra.has_psi_status = true;
        ra.psi_status = amf_psi_bitmap(u);
    }
    via_ics = !c->ics_sent && !c->ics_done;
    if (via_ics)
        sec_derive_kgnb(&u->sec, c->kgnb_ul);
    if (ri.has_uplink && ri.uplink != 0) {
        (void)amf_sm_activate(a, u, ri.uplink, &list, &react);
        ra.has_react = true;
        ra.react = react;
    }
    tmsi = u->tmsi_new != 0 ? u->tmsi_new : amf_ue_alloc_tmsi(a, u);
    if (tmsi == 0) {
        g5c_json_free(list);
        reg_reject(c, u, MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED, "no 5G-TMSI available");
        return;
    }
    ra.tmsi = tmsi;
    memcpy(ra.allowed, allowed, nallowed * sizeof allowed[0]);
    ra.nallowed = nallowed;
    memcpy(ra.rejected, rejected, nrej * sizeof rejected[0]);
    ra.nrejected = nrej;
    g5c_bytes_init(&b);
    if (nm_reg_accept(&ra, &b) != 0) {
        g5c_bytes_free(&b);
        g5c_json_free(list);
        reg_reject(c, u, MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED, "cannot build the registration accept");
        return;
    }
    remember(c, b.data, b.len, 2);
    {
        g5c_bytes prot;
        g5c_bytes_init(&prot);
        if (protect(u, 2, b.data, b.len, &prot) == 0) {
            if (via_ics) {
                (void)conn_send_ics(c, prot.data, prot.len, u, list);
            } else {
                (void)conn_send_nas(c, prot.data, prot.len);
                if (list != NULL)
                    (void)conn_send_pdu_setup(c, u, list, NULL, 0);
            }
            list = NULL;
        }
        g5c_bytes_free(&prot);
    }
    g5c_json_free(list);
    g5c_bytes_free(&b);
    c->proc = PR_REGACCEPT;
    c->t[CT_REGACC].tries = 0;
    c->reg_complete_wait = true;
    conn_timer_start(c, CT_REGACC, a->cfg.t3550);
}

static void on_reg_complete(amf_conn *c, amf_ue *u)
{
    amf *a = c->a;
    bool first = u->mm != MM_REGISTERED;
    if (c->proc != PR_REGACCEPT)
        return;
    conn_timer_stop(c, CT_REGACC);
    c->proc = PR_NONE;
    c->reg_complete_wait = false;
    if (u->tmsi_new != 0)
        amf_ue_set_tmsi(u, u->tmsi_new);
    u->mm = MM_REGISTERED;
    free(c->last_nas);
    c->last_nas = NULL;
    c->last_len = 0;
    atomic_fetch_add(&a->st_registrations, 1);
    amf_count(a, "g5c_amf_registrations_total", "Registration requests by result.", "result", "accepted");
    G5C_LOGI(AMF_LOG, "%s registered (type %u, GUTI %08x)", u->supi, u->reg_type, u->tmsi);
    if (first)
        gmm_event(a, u, EVT_REG_STATE, "REGISTERED");
    amf_persist_request(a);
    amf_gauges(a);
    if (first && a->cfg.send_names) {
        /* the network name and the time reach the UE in a configuration update, which needs no acknowledgement (TS 24.501 5.4.4.2) */
        nm_cfgupd cu;
        g5c_bytes nb;
        memset(&cu, 0, sizeof cu);
        memcpy(cu.plmn, a->cfg.plmn, 3);
        cu.id = a->cfg.id;
        cu.full_name = a->cfg.full_name;
        cu.short_name = a->cfg.short_name;
        cu.with_time = true;
        g5c_bytes_init(&nb);
        if (nm_config_update(&cu, &nb) == 0)
            (void)gmm_send_dl(c, u, nb.data, nb.len);
        g5c_bytes_free(&nb);
    }
    if (u->cfg_pending)
        (void)gmm_start_config_update(u, u->cfg_new_guti);
}

/* ---- registration request entry ---- */

static void reg_request(amf_conn *c, const nas_msg *m, nas_auth *au)
{
    amf *a = c->a;
    reg_info ri;
    g5c_bytes raw;
    amf_ue *u = NULL;
    bool reuse = false;
    if (parse_reg(m, &ri) != 0) {
        reg_reject(c, c->ue, MM_CAUSE_INVALID_MANDATORY_INFO, "malformed registration request");
        return;
    }
    if (ri.type == 4 || ri.id.kind == NAS_ID_IMEI) {
        reg_reject(c, c->ue, MM_CAUSE_PEI_NOT_ACCEPTED, "emergency registration is not supported");
        return;
    }
    if (ri.type == 5) {
        reg_reject(c, c->ue, MM_CAUSE_5GS_NOT_ALLOWED, "SNPN onboarding is not supported");
        return;
    }
    {
        unsigned t3346 = 0;
        if (!admit_registration(c, &t3346)) {
            reg_reject_t3346(c, c->ue, MM_CAUSE_CONGESTION, "the registration rate is above amf.overload", t3346);
            return;
        }
    }
    conn_clear_proc(c);
    c->sec_active = false;
    g5c_bytes_init(&raw);
    if (nas_msg_encode(m, &raw) != NAS_OK) {
        g5c_bytes_free(&raw);
        reg_reject(c, c->ue, MM_CAUSE_INVALID_MANDATORY_INFO, "malformed registration request");
        return;
    }
    free(c->init_nas);
    c->init_nas = (uint8_t *)g5c_bytes_take(&raw, &c->init_len);
    c->reg_type = ri.type;
    c->follow_on = ri.follow_on;
    c->ngksi_ue = ri.ngksi;
    c->ident = ri.id;
    c->have_suci = false;
    c->auth_syncs = 0;
    c->auth_mac_fail = 0;
    memcpy(c->ue_cap, ri.ue_cap, ri.ue_cap_len);
    c->ue_cap_len = ri.ue_cap_len;
    c->init_plain = true;

    if (ri.id.kind == NAS_ID_GUTI && guti_is_ours(a, &ri.id))
        u = amf_ue_find_tmsi(a, ri.id.tmsi);
    if (u != NULL) {
        conn_bind_ue(c, u);
        amf_ue_unref(u);
        if (au->prot != NULL || au->verified) {
            if (auth_check(u, au) && ri.ngksi == u->sec.ngksi && u->sec.valid) {
                reuse = true;
                c->init_plain = false;
            }
        }
        if (ri.ue_cap_len == 0 && u->ue_cap_len > 0) { /* a protected request may leave the capability out: the context has it */
            memcpy(c->ue_cap, u->ue_cap, u->ue_cap_len);
            c->ue_cap_len = u->ue_cap_len;
        }
        if (reuse) {
            c->kgnb_ul = au->count;
            c->sec_active = true;
            amf_conn_authenticated(c);
            reg_proceed(c, u);
            return;
        }
        if (c->ue_cap_len == 0) {
            reg_reject(c, u, MM_CAUSE_INVALID_MANDATORY_INFO, "UE security capability missing");
            return;
        }
        start_auth(c, u, u->supi);
        return;
    }
    if (ri.id.kind == NAS_ID_SUCI) {
        char *s = nas_suci_to_string(&ri.id);
        if (s == NULL || c->ue_cap_len == 0) {
            free(s);
            reg_reject(c, c->ue, MM_CAUSE_INVALID_MANDATORY_INFO, s == NULL ? "unusable SUCI" : "UE security capability missing");
            return;
        }
        snprintf(c->suci, sizeof c->suci, "%s", s);
        c->have_suci = true;
        free(s);
        start_auth(c, NULL, c->suci);
        return;
    }
    if (ri.id.kind == NAS_ID_GUTI && c->ue_cap_len > 0) {
        send_identity_request(c);
        return;
    }
    reg_reject(c, c->ue, MM_CAUSE_UE_ID_CANNOT_BE_DERIVED, "the identity cannot be resolved");
}

/* ---- service request (TS 24.501 5.6.1, TS 23.502 4.2.3) ---- */

static void service_reject(amf_conn *c, uint8_t cause, bool release_ue)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    amf_count(c->a, "g5c_amf_service_requests_total", "Service requests by result.", "result", "rejected");
    if (nm_service_reject(cause, false, 0, &b) == 0)
        (void)conn_send_nas(c, b.data, b.len);
    g5c_bytes_free(&b);
    release_conn(c, "nas", "unspecified", release_ue ? REL_DELETE_UE : REL_KEEP);
}

static void service_request(amf_conn *c, const nas_msg *m, nas_auth *au, uint32_t stmsi_ngap, bool have_ngap_stmsi)
{
    amf *a = c->a;
    size_t n;
    const uint8_t *v;
    nas_mobile_identity id;
    uint32_t tmsi = 0;
    amf_ue *u = NULL;
    uint8_t stype;
    uint16_t uplink = 0, ue_status = 0;
    bool has_uplink = false, has_status = false;
    uint8_t *inner = NULL;
    nas_msg im;
    bool inner_ok = false;
    g5c_json *list = NULL;
    uint16_t react = 0;
    g5c_bytes acc, prot;
    bool via_ics;

    v = nas_msg_get(m, "5G-S-TMSI", &n);
    if (v != NULL && nas_mobile_identity_decode(v, n, &id) == NAS_OK && stmsi_is_ours(a, &id))
        tmsi = id.tmsi;
    else if (have_ngap_stmsi)
        tmsi = stmsi_ngap;
    if (tmsi != 0)
        u = amf_ue_find_tmsi(a, tmsi);
    if (u == NULL) {
        service_reject(c, MM_CAUSE_UE_ID_CANNOT_BE_DERIVED, false);
        return;
    }
    conn_bind_ue(c, u);
    amf_ue_unref(u);
    if (!auth_check(u, au)) {
        G5C_LOGW(AMF_LOG, "service request of %s failed the integrity check", u->supi);
        amf_count(a, "g5c_amf_nas_integrity_failures_total", "Uplink NAS messages that failed the integrity check.", NULL, NULL);
        service_reject(c, MM_CAUSE_UE_ID_CANNOT_BE_DERIVED, false);
        return;
    }
    if (u->mm != MM_REGISTERED) {
        service_reject(c, MM_CAUSE_IMPLICITLY_DEREGISTERED, false);
        return;
    }
    v = nas_msg_get(m, "Service type", &n);
    stype = (v != NULL && n >= 1) ? (uint8_t)(v[0] & 0x0f) : 0;
    /* the IEs that are not cleartext IEs travel in the ciphered NAS message container (TS 33.501 6.4.6) */
    v = nas_msg_get(m, "NAS message container", &n);
    if (v != NULL && n > 0) {
        inner = g5c_xmalloc(n);
        memcpy(inner, v, n);
        if (u->sec.enc_alg != 0 && g5c_nea2(u->sec.knas_enc, au->count, NAS_BEARER_3GPP, G5C_DIR_UL, inner, n) != 0) {
            free(inner);
            inner = NULL;
        }
        if (inner != NULL && nas_msg_decode(inner, n, &im) == NAS_OK) {
            inner_ok = true;
            m = &im;
        }
    }
    v = nas_msg_get(m, "Uplink data status", &n);
    if (v != NULL && n >= 2) {
        has_uplink = true;
        uplink = bitmap16(v, n);
    }
    v = nas_msg_get(m, "PDU session status", &n);
    if (v != NULL && n >= 2) {
        has_status = true;
        ue_status = bitmap16(v, n);
    }
    ue_attach_conn(c, u);
    ue_timer_stop(u, UT_PAGING);
    u->ut[UT_PAGING].tries = 0;
    c->svc_req = true;
    c->svc_type = stype;
    c->kgnb_ul = au->count;
    amf_conn_authenticated(c);
    sec_derive_kgnb(&u->sec, au->count);
    if (has_status)
        (void)amf_psi_status_reconcile(a, u, ue_status);

    /* the user plane the UE asked for; the accept is protected before the session messages so that its NAS COUNT is the lowest */
    if (has_uplink && uplink != 0)
        (void)amf_sm_activate(a, u, uplink, &list, &react);

    g5c_bytes_init(&acc);
    if (nm_service_accept(has_status, amf_psi_bitmap(u), has_uplink, react, &acc) != 0) {
        g5c_bytes_free(&acc);
        g5c_json_free(list);
        if (inner_ok)
            nas_msg_free(&im);
        free(inner);
        service_reject(c, MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED, false);
        return;
    }
    g5c_bytes_init(&prot);
    via_ics = !c->ics_sent && !c->ics_done;
    if (protect(u, 2, acc.data, acc.len, &prot) == 0) {
        (void)amf_n1n2_deliver_pending(c, u, true, NULL, &list); /* whatever waited for the UE to become reachable */
        if (via_ics) {
            (void)conn_send_ics(c, prot.data, prot.len, u, list);
        } else {
            (void)conn_send_nas(c, prot.data, prot.len);
            if (list != NULL)
                (void)conn_send_pdu_setup(c, u, list, NULL, 0);
        }
        list = NULL;
    }
    g5c_bytes_free(&prot);
    g5c_bytes_free(&acc);
    g5c_json_free(list);
    if (inner_ok)
        nas_msg_free(&im);
    free(inner);
    c->proc = PR_NONE;
    atomic_fetch_add(&a->st_service, 1);
    amf_count(a, "g5c_amf_service_requests_total", "Service requests by result.", "result", "accepted");
    G5C_LOGI(AMF_LOG, "service request of %s accepted (type %u)", u->supi, stype);
    if (u->dereg_pending) {
        u->dereg_pending = false;
        (void)gmm_start_dereg(u, u->dereg_rereg);
    }
    if (u->cfg_pending)
        (void)gmm_start_config_update(u, u->cfg_new_guti);
}

/* ---- paging (TS 23.502 4.2.3.3) ---- */

void gmm_page_start(amf_ue *u)
{
    if (u->cm == CM_CONNECTED || u->mm != MM_REGISTERED)
        return;
    if (u->ut[UT_PAGING].on)
        return; /* already being paged: the pending work is picked up by the service request */
    {
        const char *why = unreachable_reason(u);
        if (why != NULL) { /* nobody listens: the transfer fails at once with the cause the SMF expects, a pending de-registration happens locally */
            amf_count(u->a, "g5c_amf_paging_suppressed_total", "Pagings not attempted because the UE is in a power saving state, by reason.", "reason", why);
            G5C_LOGI(AMF_LOG, "%s is not paged: %s", u->supi, why);
            gmm_page_failed(u->a, u);
            return;
        }
    }
    u->ut[UT_PAGING].tries = 1;
    amf_page_ue(u->a, u);
    ue_timer_start(u, UT_PAGING, u->a->cfg.t3513);
}

/* The UE did not answer the paging: pending transfers fail, a pending de-registration happens locally (TS 23.502 4.2.3.3, 4.2.2.3.3). */
void gmm_page_failed(amf *a, amf_ue *u)
{
    amf_pend *p = u->pend;
    u->pend = NULL;
    while (p != NULL) {
        amf_pend *n = p->next;
        if (p->notif_uri[0] != 0)
            amf_notify_n1n2_failure(a, p->notif_uri, "UE_NOT_REACHABLE");
        amf_pend_free(p);
        p = n;
    }
    G5C_LOGW(AMF_LOG, "paging of %s failed", u->supi);
    amf_count(a, "g5c_amf_paging_failures_total", "Paging procedures that ended without an answer.", NULL, NULL);
    if (u->dereg_pending) {
        u->dereg_pending = false;
        amf_sm_release_all(a, u, "UE_UNREACHABLE");
        auth_result_remove(a, u);
        amf_udm_deregister(a, u);
        amf_pcf_delete(a, u);
        amf_udm_sdm_unsubscribe(a, u);
        u->mm = MM_DEREGISTERED;
        atomic_fetch_add(&a->st_dereg, 1);
        gmm_event(a, u, EVT_REG_STATE, "DEREGISTERED");
        amf_ue_remove(u);
    }
}

static void ue_timer_fire(amf *a, amf_ue *u, int kind, uint32_t gen)
{
    amf_tslot *t = &u->ut[kind];
    if (t->gen != gen || !t->on || u->removed)
        return;
    t->on = false;
    if (kind == UT_PAGING) {
        if (u->cm == CM_CONNECTED)
            return;
        if (t->tries < a->cfg.paging_tries) {
            t->tries++;
            amf_page_ue(a, u);
            ue_timer_start(u, UT_PAGING, a->cfg.t3513);
        } else {
            t->tries = 0;
            gmm_page_failed(a, u);
        }
    } else if (kind == UT_REACH) {
        if (u->cm == CM_CONNECTED || u->mm != MM_REGISTERED)
            return;
        G5C_LOGI(AMF_LOG, "%s is no longer reachable: implicit de-registration", u->supi);
        amf_sm_release_all(a, u, "UE_UNREACHABLE");
        auth_result_remove(a, u);
        amf_udm_deregister(a, u);
        amf_pcf_delete(a, u);
        amf_udm_sdm_unsubscribe(a, u);
        u->mm = MM_DEREGISTERED;
        atomic_fetch_add(&a->st_dereg, 1);
        amf_count(a, "g5c_amf_deregistrations_total", "De-registrations by kind.", "kind", "implicit");
        gmm_event(a, u, EVT_REG_STATE, "DEREGISTERED_IMPLICIT");
        amf_ue_remove(u);
        amf_gauges(a);
    }
}

/* ---- de-registration ---- */

static void finish_dereg(amf_conn *c, amf_ue *u, const char *kind)
{
    amf *a = c->a;
    amf_sm_release_all(a, u, "UE_DEREGISTERED");
    auth_result_remove(a, u);
    amf_udm_deregister(a, u);
    amf_pcf_delete(a, u);
    amf_udm_sdm_unsubscribe(a, u);
    u->mm = MM_DEREGISTERED;
    atomic_fetch_add(&a->st_dereg, 1);
    amf_count(a, "g5c_amf_deregistrations_total", "De-registrations by kind.", "kind", kind);
    gmm_event(a, u, EVT_REG_STATE, "DEREGISTERED");
    G5C_LOGI(AMF_LOG, "%s de-registered (%s)", u->supi, kind);
    amf_gauges(a);
}

static void ue_dereg_request(amf_conn *c, const nas_msg *m, nas_auth *au)
{
    amf *a = c->a;
    size_t n;
    const uint8_t *v = nas_msg_get(m, "De-registration type", &n);
    uint8_t dt = (v != NULL && n >= 1) ? (uint8_t)(v[0] & 0x0f) : 0;
    bool switch_off = (dt & 0x08) != 0;
    amf_ue *u = c->ue;
    nas_mobile_identity id;
    g5c_bytes acc;
    if (u == NULL) {
        v = nas_msg_get(m, "5GS mobile identity", &n);
        if (v != NULL && nas_mobile_identity_decode(v, n, &id) == NAS_OK && id.kind == NAS_ID_GUTI && guti_is_ours(a, &id)) {
            u = amf_ue_find_tmsi(a, id.tmsi);
            if (u != NULL) {
                conn_bind_ue(c, u);
                amf_ue_unref(u);
            }
        }
    }
    if (u == NULL) { /* nothing to de-register: answer anyway so that the UE can proceed */
        g5c_bytes_init(&acc);
        if (!switch_off && nm_dereg_accept_ue_orig(&acc) == 0)
            (void)conn_send_nas(c, acc.data, acc.len);
        g5c_bytes_free(&acc);
        release_conn(c, "nas", "deregister", REL_DELETE_UE);
        return;
    }
    if (u->sec.valid && !auth_check(u, au) && !au->verified) {
        G5C_LOGW(AMF_LOG, "de-registration request of %s failed the integrity check: ignored", u->supi);
        amf_count(a, "g5c_amf_nas_integrity_failures_total", "Uplink NAS messages that failed the integrity check.", NULL, NULL);
        if (c->ue == u && u->conn != c)
            release_conn(c, "nas", "unspecified", REL_KEEP);
        return;
    }
    conn_clear_proc(c);
    if (u->conn != c)
        ue_attach_conn(c, u);
    finish_dereg(c, u, switch_off ? "ue_switch_off" : "ue");
    g5c_bytes_init(&acc);
    if (!switch_off && nm_dereg_accept_ue_orig(&acc) == 0)
        (void)gmm_send_dl(c, u, acc.data, acc.len);
    g5c_bytes_free(&acc);
    release_conn(c, "nas", "deregister", REL_DELETE_UE);
    /* the association may be gone already (a gNB that sends the request and closes at once) */
    if (!u->removed && u->mm == MM_DEREGISTERED && (c->closed || c->rel_sent))
        amf_ue_remove(u);
}

int gmm_start_dereg(amf_ue *u, bool reregister)
{
    amf *a = u->a;
    amf_conn *c = u->conn;
    g5c_bytes b;
    if (u->mm != MM_REGISTERED)
        return -1;
    if (c == NULL || u->cm != CM_CONNECTED) {
        u->dereg_pending = true;
        u->dereg_rereg = reregister;
        gmm_page_start(u);
        return 0;
    }
    g5c_bytes_init(&b);
    if (nm_dereg_request_ue_term(reregister, 0, &b) != 0) {
        g5c_bytes_free(&b);
        return -1;
    }
    c->dereg_reregister_flag = reregister;
    send_procedure_msg(c, u, b.data, b.len, 2, CT_DEREG, a->cfg.t3522, PR_DEREG);
    g5c_bytes_free(&b);
    return 0;
}

/* ---- configuration update (TS 24.501 5.4.4) ---- */

int gmm_start_config_update(amf_ue *u, bool new_guti)
{
    amf *a = u->a;
    amf_conn *c = u->conn;
    nm_cfgupd cu;
    g5c_bytes b;
    if (u->mm != MM_REGISTERED)
        return -1;
    if (c == NULL || u->cm != CM_CONNECTED || c->proc != PR_NONE) {
        u->cfg_pending = true;
        u->cfg_new_guti = u->cfg_new_guti || new_guti;
        return 0;
    }
    u->cfg_pending = false;
    u->cfg_new_guti = false;
    memset(&cu, 0, sizeof cu);
    memcpy(cu.plmn, a->cfg.plmn, 3);
    cu.id = a->cfg.id;
    if (new_guti) {
        uint32_t t = amf_ue_alloc_tmsi(a, u);
        if (t == 0)
            return -1;
        cu.tmsi = t;
        cu.ack = true;
    }
    memcpy(cu.tai, u->tai_list, u->ntai * sizeof u->tai_list[0]);
    cu.ntai = u->ntai;
    cu.has_allowed = u->nallowed > 0;
    memcpy(cu.allowed, u->allowed, u->nallowed * sizeof u->allowed[0]);
    cu.nallowed = u->nallowed;
    cu.full_name = a->cfg.full_name;
    cu.short_name = a->cfg.short_name;
    g5c_bytes_init(&b);
    if (nm_config_update(&cu, &b) != 0) {
        g5c_bytes_free(&b);
        return -1;
    }
    if (cu.ack)
        send_procedure_msg(c, u, b.data, b.len, 2, CT_CFG, a->cfg.t3555, PR_CFG);
    else
        (void)gmm_send_dl(c, u, b.data, b.len);
    g5c_bytes_free(&b);
    return 0;
}

/* ---- release and idle transition ---- */

/* The UE leaves CM-CONNECTED: its user plane is deactivated at the SMF, the reachability timer starts. */
void gmm_ue_idle(amf *a, amf_ue *u)
{
    if (u->cm == CM_IDLE && u->conn == NULL)
        return;
    (void)amf_sm_deactivate_all(a, u);
    u->cm = CM_IDLE;
    u->idle_at = g5c_now_seconds();
    u->sec.nh_valid = false; /* the AS keys belong to the connection that is gone */
    OPENSSL_cleanse(u->sec.kgnb, sizeof u->sec.kgnb);
    if (u->mm == MM_REGISTERED) {
        ue_timer_start(u, UT_REACH, a->cfg.t3512 + a->cfg.reach_grace);
        gmm_event(a, u, EVT_CONNECTIVITY, "IDLE");
    }
    amf_persist_request(a);
    amf_gauges(a);
}

void gmm_release_request(amf_conn *c, const char *group, const char *cause)
{
    amf_ue *u = c->ue;
    if (c->closed)
        return;
    G5C_LOGI(AMF_LOG, "release request for %s: %s/%s", u != NULL ? u->supi : "(unidentified)", group, cause);
    if (u != NULL && u->conn == c)
        (void)amf_sm_deactivate_all(c->a, u);
    release_conn(c, group, cause, u != NULL && u->mm == MM_REGISTERED ? REL_KEEP : REL_DELETE_UE);
}

/* The gNB confirmed the release (or the guard timer ran out). */
void gmm_conn_released(amf_conn *c)
{
    amf *a = c->a;
    amf_ue *u = c->ue;
    uint8_t then = c->rel_then;
    conn_timer_stop(c, CT_RELCMD);
    atomic_fetch_add(&a->st_release, 1);
    if (u != NULL && u->conn == c) {
        pthread_mutex_lock(&a->tmu);
        u->conn = NULL;
        pthread_mutex_unlock(&a->tmu);
        gmm_ue_idle(a, u);
    } else if (u != NULL && u->ho_conn == c) {
        u->ho_conn = NULL;
    }
    /* a context that never became a registration (rejected, aborted) goes with its connection */
    if (u != NULL && then == REL_DELETE_UE && u->mm != MM_REGISTERED && u->conn == NULL)
        amf_ue_gc(u);
    conn_unbind_ue(c);
    amf_conn_unlink(c);
}

/* The association vanished (SCTP failure, NG Reset). */
void gmm_conn_gone(amf_conn *c)
{
    amf *a = c->a;
    amf_ue *u = c->ue;
    if (c->closed)
        return;
    G5C_LOGI(AMF_LOG, "the association of %s is gone", u != NULL ? u->supi : "an unidentified UE");
    conn_clear_proc(c);
    if (u != NULL && u->conn == c) {
        pthread_mutex_lock(&a->tmu);
        u->conn = NULL;
        pthread_mutex_unlock(&a->tmu);
        gmm_ue_idle(a, u);
        if (u->mm != MM_REGISTERED)
            amf_ue_gc(u);
    }
    if (u != NULL && u->ho_conn == c)
        ho_abort(c, u, "association lost");
    conn_unbind_ue(c);
    amf_conn_unlink(c);
}

/* ---- timers of a connection ---- */

void gmm_conn_timer(amf_conn *c, int kind, uint32_t gen)
{
    amf *a = c->a;
    amf_tslot *t = &c->t[kind];
    amf_ue *u = c->ue;
    unsigned secs = 0;
    if (t->gen != gen || !t->on || c->closed)
        return;
    t->on = false;
    switch (kind) {
    case CT_AUTH:
        secs = a->cfg.t3560;
        break;
    case CT_SMC:
        secs = a->cfg.t3560;
        break;
    case CT_IDENT:
        secs = a->cfg.t3570;
        break;
    case CT_REGACC:
        secs = a->cfg.t3550;
        break;
    case CT_CFG:
        secs = a->cfg.t3555;
        break;
    case CT_DEREG:
        secs = a->cfg.t3522;
        break;
    case CT_RELCMD:
        G5C_LOGW(AMF_LOG, "no UE context release complete: releasing locally");
        gmm_conn_released(c);
        return;
    case CT_HOPREP:
    case CT_HOALL:
        if (u != NULL)
            ho_timer(a, c, kind);
        return;
    default:
        return;
    }
    if (t->tries + 1 < NAS_RETRIES + 1 && c->last_nas != NULL) {
        t->tries++;
        G5C_LOGD(AMF_LOG, "timer %d expired: retransmission %u", kind, t->tries);
        (void)send_dl(c, u, c->last_nas, c->last_len, c->last_sht);
        conn_timer_start(c, kind, secs);
        return;
    }
    G5C_LOGW(AMF_LOG, "procedure %d of %s aborted after %d retransmissions", c->proc, u != NULL ? u->supi : "an unidentified UE", NAS_RETRIES);
    amf_count(a, "g5c_amf_procedure_timeouts_total", "NAS procedures aborted by timer expiry.", NULL, NULL);
    switch (c->proc) {
    case PR_REGACCEPT:
        /* the UE never completed the registration: the new GUTI is not used (TS 24.501 5.5.1.2.8 d) */
        if (u != NULL && u->tmsi_new != 0) {
            pthread_mutex_lock(&a->tmu);
            if (amap_get(a->ues_by_tmsi, u->tmsi_new) == u)
                amap_del(a->ues_by_tmsi, u->tmsi_new);
            pthread_mutex_unlock(&a->tmu);
            u->tmsi_new = 0;
        }
        conn_clear_proc(c);
        release_conn(c, "nas", "unspecified", u != NULL && u->mm == MM_REGISTERED ? REL_KEEP : REL_DELETE_UE);
        break;
    case PR_DEREG:
        conn_clear_proc(c);
        if (u != NULL)
            finish_dereg(c, u, "network_timeout");
        release_conn(c, "nas", "deregister", REL_DELETE_UE);
        break;
    case PR_CFG:
        conn_clear_proc(c);
        if (u != NULL && u->tmsi_new != 0) {
            pthread_mutex_lock(&a->tmu);
            if (amap_get(a->ues_by_tmsi, u->tmsi_new) == u)
                amap_del(a->ues_by_tmsi, u->tmsi_new);
            pthread_mutex_unlock(&a->tmu);
            u->tmsi_new = 0;
        }
        break;
    default:
        conn_clear_proc(c);
        release_conn(c, "nas", "unspecified", u != NULL && u->mm == MM_REGISTERED ? REL_KEEP : REL_DELETE_UE);
        break;
    }
}

void gmm_timer(amf *a, int target, int kind, uint64_t id, uint32_t gen)
{
    if (target == TT_CONN) {
        amf_conn *c = amf_conn_find(a, id);

        if (c == NULL)
            return;
        amf_conn_post_timer(c, kind, gen);
        amf_conn_unref(c);
    } else {
        amf_ue *u = amf_ue_find_uid(a, id);
        if (u == NULL)
            return;
        pthread_mutex_lock(&u->mu);
        ue_timer_fire(a, u, kind, gen);
        pthread_mutex_unlock(&u->mu);
        amf_ue_unref(u);
    }
}

/* ---- uplink NAS demultiplexing ---- */

void gmm_initial_ue(amf_conn *c, const uint8_t *nas, size_t len, const g5c_json *msg)
{
    amf *a = c->a;
    nas_any any;
    nas_msg inner;
    bool have_inner = false;
    nas_auth au;
    uint32_t stmsi = 0;
    bool have_stmsi = false;
    const g5c_json *st = ngap_find_ie(msg, NGAP_IE_FiveG_S_TMSI);
    const nas_msg *m;
    memset(&au, 0, sizeof au);
    if (st != NULL) {
        const char *tm = g5c_json_get_str(st, "fiveG-TMSI");
        uint8_t b[4];
        if (tm != NULL && g5c_hex_decode(tm, b, 4) == 4) {
            stmsi = amf_get_be32(b);
            have_stmsi = true;
        }
    }
    if (nas_any_decode(nas, len, &any) != NAS_OK) {
        G5C_LOGW(AMF_LOG, "undecodable initial NAS message");
        amf_count(a, "g5c_amf_nas_errors_total", "Malformed uplink NAS messages.", NULL, NULL);
        release_conn(c, "protocol", "semantic-error", REL_DELETE_UE);
        return;
    }
    if (any.is_protected) {
        au.prot = &any.prot;
        if ((any.prot.sht == 1 || any.prot.sht == 3) && nas_msg_decode(any.prot.payload, any.prot.payload_len, &inner) == NAS_OK) {
            have_inner = true;
        } else if (have_stmsi) { /* a ciphered initial message: the context named by the 5G-S-TMSI deciphers it */
            amf_ue *u = amf_ue_find_tmsi(a, stmsi);
            if (u != NULL) {
                g5c_bytes plain;
                g5c_bytes_init(&plain);
                pthread_mutex_lock(&u->mu);
                if (sec_open_ul(&u->sec, &any.prot, &plain, &au.count, true) == 0 && nas_msg_decode(plain.data, plain.len, &inner) == NAS_OK) {
                    have_inner = true;
                    au.verified = true;
                }
                pthread_mutex_unlock(&u->mu);
                g5c_bytes_free(&plain);
                amf_ue_unref(u);
            }
        }
        if (!have_inner) {
            nas_any_free(&any);
            release_conn(c, "protocol", "semantic-error", REL_DELETE_UE);
            return;
        }
        m = &inner;
    } else {
        m = &any.plain;
    }
    amf_count(a, "g5c_amf_nas_rx_total", "Uplink NAS messages by 5GMM message type.", "type", nas_msg_name(m));
    switch (m->def->msg_type) {
    case MT_REG_REQ:
        reg_request(c, m, &au);
        break;
    case MT_SERVICE_REQ:
        service_request(c, m, &au, stmsi, have_stmsi);
        break;
    case MT_DEREG_REQ_UE:
        ue_dereg_request(c, m, &au);
        break;
    default:
        G5C_LOGW(AMF_LOG, "unexpected initial NAS message %s", nas_msg_name(m));
        release_conn(c, "nas", "unspecified", REL_DELETE_UE);
        break;
    }
    if (have_inner)
        nas_msg_free(&inner);
    nas_any_free(&any);
}

static void on_cfg_complete(amf_conn *c, amf_ue *u)
{
    if (c->proc != PR_CFG)
        return;
    conn_timer_stop(c, CT_CFG);
    c->proc = PR_NONE;
    if (u->tmsi_new != 0)
        amf_ue_set_tmsi(u, u->tmsi_new);
    amf_persist_request(c->a);
}

static void on_dereg_accept(amf_conn *c, amf_ue *u)
{
    bool rereg;
    if (c->proc != PR_DEREG)
        return;
    rereg = c->dereg_reregister_flag;
    conn_clear_proc(c);
    finish_dereg(c, u, "network");
    (void)rereg;
    release_conn(c, "nas", "deregister", REL_DELETE_UE);
}

void gmm_uplink_nas(amf_conn *c, const uint8_t *nas, size_t len)
{
    amf *a = c->a;
    amf_ue *u = c->ue;
    nas_any any;
    nas_msg inner;
    bool have_inner = false;
    nas_auth au;
    const nas_msg *m = NULL;
    memset(&au, 0, sizeof au);
    if (nas_any_decode(nas, len, &any) != NAS_OK) {
        amf_count(a, "g5c_amf_nas_errors_total", "Malformed uplink NAS messages.", NULL, NULL);
        return;
    }
    if (any.is_protected) {
        g5c_bytes plain;
        amf_sec *s;
        int rc;
        if (u == NULL) {
            G5C_LOGW(AMF_LOG, "protected NAS message on an unidentified connection: dropped");
            nas_any_free(&any);
            return;
        }
        s = (u->sec_new_valid && (c->proc == PR_SMC || any.prot.sht == 3 || any.prot.sht == 4)) ? &u->sec_new : &u->sec;
        g5c_bytes_init(&plain);
        rc = sec_open_ul(s, &any.prot, &plain, &au.count, s == &u->sec);
        if (rc == 0 && s == &u->sec_new) {
            /* the first message under the new context: its count is committed when the security mode completes */
        }
        if (rc == 0 && nas_msg_decode(plain.data, plain.len, &inner) == NAS_OK) {
            have_inner = true;
            au.verified = true;
            au.prot = &any.prot;
            m = &inner;
        } else if (rc == -1 && any.prot.sht == 1 && nas_msg_decode(any.prot.payload, any.prot.payload_len, &inner) == NAS_OK &&
                   inner.def->msg_type == MT_REG_REQ) {
            /* a registration request that fails the check is handled as an unprotected one: a new authentication follows */
            have_inner = true;
            m = &inner;
        } else {
            G5C_LOGW(AMF_LOG, "uplink NAS message of %s dropped (%s)", u->supi, rc == -1 ? "integrity check failed" : rc == -2 ? "replay" : "undecodable");
            amf_count(a, "g5c_amf_nas_integrity_failures_total", "Uplink NAS messages that failed the integrity check.", NULL, NULL);
            g5c_bytes_free(&plain);
            nas_any_free(&any);
            return;
        }
        g5c_bytes_free(&plain);
    } else {
        m = &any.plain;
        if (u != NULL && u->sec.valid && u->mm == MM_REGISTERED) {
            uint8_t t = m->def->msg_type;
            /* a registered UE with a security context only sends plain messages that precede a new authentication (TS 24.501 4.4.4.3) */
            if (t != MT_REG_REQ && t != MT_ID_RESP && t != MT_AUTH_RESP && t != MT_AUTH_FAIL && t != MT_DEREG_REQ_UE) {
                G5C_LOGW(AMF_LOG, "unprotected %s from %s dropped", nas_msg_name(m), u->supi);
                amf_count(a, "g5c_amf_nas_integrity_failures_total", "Uplink NAS messages that failed the integrity check.", NULL, NULL);
                nas_any_free(&any);
                return;
            }
        }
    }
    amf_count(a, "g5c_amf_nas_rx_total", "Uplink NAS messages by 5GMM message type.", "type", nas_msg_name(m));
    switch (m->def->msg_type) {
    case MT_REG_REQ:
        if (!au.verified)
            au.prot = NULL;
        reg_request(c, m, &au);
        break;
    case MT_ID_RESP:
        on_identity_response(c, m);
        break;
    case MT_AUTH_RESP:
        on_auth_response(c, m);
        break;
    case MT_AUTH_FAIL:
        on_auth_failure(c, m);
        break;
    case MT_SMC_COMPLETE:
        if (u != NULL && c->proc == PR_SMC && au.verified) {
            /* the count of the complete message is the one the AS keys derive from */
            u->sec_new.ul_count = au.count;
            on_smc_complete(c, u, m, au.count);
        }
        break;
    case MT_SMC_REJECT: {
        size_t n;
        const uint8_t *cause = nas_msg_get(m, "5GMM cause", &n);
        if (c->proc == PR_SMC) {
            G5C_LOGW(AMF_LOG, "the UE rejected the security mode command (cause #%u)", cause != NULL ? cause[0] : 0);
            amf_count(a, "g5c_amf_authentications_total", "5G-AKA runs by result.", "result", "smc_rejected");
            conn_clear_proc(c);
            if (u != NULL) {
                sec_clear(&u->sec_new);
                u->sec_new_valid = false;
                auth_result_remove(a, u); /* TS 29.509 5.2.2.2.5: the NAS SMC failed after the authentication succeeded */
            }
            reg_reject(c, u, MM_CAUSE_UE_SECURITY_CAP_MISMATCH, "security mode command rejected by the UE");
        }
        break;
    }
    case MT_REG_COMPLETE:
        if (u != NULL && au.verified)
            on_reg_complete(c, u);
        break;
    case MT_UL_NAS:
        if (u != NULL && au.verified && u->mm == MM_REGISTERED)
            (void)amf_ul_nas_transport(c, u, m);
        break;
    case MT_DEREG_REQ_UE:
        ue_dereg_request(c, m, &au);
        break;
    case MT_DEREG_ACC_NET:
        if (u != NULL && au.verified)
            on_dereg_accept(c, u);
        break;
    case MT_CFG_COMPLETE:
        if (u != NULL && au.verified)
            on_cfg_complete(c, u);
        break;
    case MT_SERVICE_REQ:
        if (au.verified || au.prot != NULL)
            service_request(c, m, &au, 0, false);
        break;
    case MT_NOTIF_RESP:
        break;
    case MT_MM_STATUS: {
        size_t n;
        const uint8_t *cause = nas_msg_get(m, "5GMM cause", &n);
        G5C_LOGW(AMF_LOG, "5GMM status from %s: cause #%u", u != NULL ? u->supi : "(unidentified)", cause != NULL ? cause[0] : 0);
        break;
    }
    default:
        G5C_LOGW(AMF_LOG, "unhandled uplink NAS message %s", nas_msg_name(m));
        break;
    }
    if (have_inner)
        nas_msg_free(&inner);
    nas_any_free(&any);
}

void gmm_reg_status_send(amf_conn *c, amf_ue *u, uint8_t cause)
{
    (void)c;
    (void)u;
    (void)cause;
}

/* a message protected with the current context (plain when there is none), for NAS PDUs carried inside NGAP messages */
int gmm_protect_dl(amf_ue *u, const uint8_t *plain, size_t len, g5c_bytes *out)
{
    return protect(u, 2, plain, len, out);
}
