/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5GSM relay: the AMF forwards session management messages between the UE and the SMF (TS 24.501 5.4.5, TS 23.502 4.3), keeps one SM context
 * reference per PDU session, and implements Namf_Communication_N1N2MessageTransfer (TS 29.518 5.2.2.3). */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nasmsg.h"

#define N1_ID "n1SmMsg"
#define N2_ID "n2SmInfo"
#define MT_PDU_EST_REQ 0xc1
#define MT_PDU_MOD_REQ 0xc9
#define MT_PDU_REL_REQ 0xd1

/* ---- small helpers ------------------------------------------------------------------------------------------------------------------------- */

void amf_pdu_reset(amf_pdu *p)
{
    memset(p, 0, sizeof *p);
}

unsigned amf_pdu_count(const amf_ue *u)
{
    unsigned n = 0;
    for (unsigned i = 1; i <= AMF_MAX_PSI; i++)
        n += u->pdu[i].used;
    return n;
}

uint16_t amf_psi_bitmap(const amf_ue *u)
{
    uint16_t m = 0;
    for (unsigned i = 1; i <= AMF_MAX_PSI; i++)
        if (u->pdu[i].used)
            m = (uint16_t)(m | (1u << i));
    return m;
}

void amf_pend_free(amf_pend *p)
{
    free(p->n1);
    free(p->n2);
    free(p);
}

void amf_pend_clear(amf_ue *u)
{
    while (u->pend != NULL) {
        amf_pend *n = u->pend->next;
        amf_pend_free(u->pend);
        u->pend = n;
    }
}

void amf_smresp_free(amf_smresp *r)
{
    g5c_json_free(r->json);
    if (r->is_mp)
        g5c_mp_free(&r->mp);
    if (r->have_raw)
        g5c_resp_free(&r->raw);
    memset(r, 0, sizeof *r);
}

/* a DL NAS TRANSPORT carrying a 5GSM message, protected with the current context */
static int dl_sm_nas(amf_ue *u, uint8_t psi, const uint8_t *n1, size_t n1l, g5c_bytes *out)
{
    g5c_bytes plain;
    int rc;
    g5c_bytes_init(&plain);
    if (nm_dl_nas_transport(1, n1, n1l, psi, 0, &plain) != 0) {
        g5c_bytes_free(&plain);
        return -1;
    }
    rc = gmm_protect_dl(u, plain.data, plain.len, out);
    g5c_bytes_free(&plain);
    return rc;
}

static int send_sm_nas(amf_conn *c, amf_ue *u, uint8_t psi, const uint8_t *n1, size_t n1l)
{
    g5c_bytes b;
    int rc;
    g5c_bytes_init(&b);
    rc = dl_sm_nas(u, psi, n1, n1l, &b);
    if (rc == 0)
        rc = conn_send_nas(c, b.data, b.len);
    g5c_bytes_free(&b);
    return rc;
}

static void send_payload_not_forwarded(amf_conn *c, amf_ue *u, uint8_t ptype, const uint8_t *payload, size_t n, uint8_t psi)
{
    g5c_bytes plain, prot;
    g5c_bytes_init(&plain);
    g5c_bytes_init(&prot);
    if (nm_dl_nas_transport(ptype, payload, n, psi, MM_CAUSE_PAYLOAD_NOT_FORWARDED, &plain) == 0 && gmm_protect_dl(u, plain.data, plain.len, &prot) == 0)
        (void)conn_send_nas(c, prot.data, prot.len);
    g5c_bytes_free(&plain);
    g5c_bytes_free(&prot);
}

/* ---- Nsmf_PDUSession client ---------------------------------------------------------------------------------------------------------------------- */

static void parse_smresp(amf_smresp *out)
{
    const char *ct = g5c_resp_header_get(&out->raw, "content-type");
    const uint8_t *jd = out->raw.body;
    size_t jl = out->raw.body_len;
    const char *loc = g5c_resp_header_get(&out->raw, "location");
    if (loc != NULL)
        snprintf(out->location, sizeof out->location, "%s", loc);
    if (ct != NULL && g5c_mp_is_multipart(ct)) {
        if (g5c_mp_parse(ct, out->raw.body, out->raw.body_len, &out->mp) != 0 || out->mp.n == 0)
            return;
        out->is_mp = true;
        jd = out->mp.parts[0].data;
        jl = out->mp.parts[0].len;
    }
    if (jl > 0) {
        char err[100];
        out->json = g5c_json_parse((const char *)jd, jl, err, sizeof err);
        if (out->is_mp && out->json != NULL) {
            const g5c_json *r = g5c_json_get(out->json, N1_ID);
            if (r != NULL)
                out->n1 = g5c_mp_find(&out->mp, g5c_json_get_str(r, "contentId"));
            r = g5c_json_get(out->json, N2_ID);
            if (r != NULL)
                out->n2 = g5c_mp_find(&out->mp, g5c_json_get_str(r, "contentId"));
        }
    }
}

/* POST `j` (plus binary parts) to url; the response is parsed into out. Returns the HTTP status or a negative g5c_sbi_err. */
static int smf_post(amf *a, const char *url, g5c_json *j, const uint8_t *n1, size_t n1l, const uint8_t *n2, size_t n2l, amf_smresp *out)
{
    g5c_mp_part parts[3];
    size_t np = 1;
    char err[160], *jt, *ct = NULL;
    g5c_bytes body;
    g5c_kv hdr = {"accept", "application/json, multipart/related"};
    int rc;
    memset(out, 0, sizeof *out);
    if (n1l > 0)
        g5c_json_set_str(g5c_json_set(j, N1_ID, g5c_json_new_obj()), "contentId", N1_ID);
    if (n2l > 0)
        g5c_json_set_str(g5c_json_set(j, N2_ID, g5c_json_new_obj()), "contentId", N2_ID);
    jt = g5c_json_to_string(j, NULL);
    parts[0] = (g5c_mp_part){NULL, "application/json", (const uint8_t *)jt, strlen(jt)};
    if (n1l > 0)
        parts[np++] = (g5c_mp_part){N1_ID, "application/vnd.3gpp.5gnas", n1, n1l};
    if (n2l > 0)
        parts[np++] = (g5c_mp_part){N2_ID, "application/vnd.3gpp.ngap", n2, n2l};
    g5c_bytes_init(&body);
    if (np == 1) {
        rc = g5c_client_request(a->client, "POST", url, &hdr, 1, "application/json", jt, strlen(jt), &out->raw, err, sizeof err);
    } else if (g5c_mp_build(parts, np, &body, &ct) == 0) {
        rc = g5c_client_request(a->client, "POST", url, &hdr, 1, ct, body.data, body.len, &out->raw, err, sizeof err);
    } else {
        rc = G5C_SBI_E_REQUEST;
        snprintf(err, sizeof err, "cannot build the multipart body");
    }
    g5c_bytes_free(&body);
    free(ct);
    free(jt);
    if (rc != 0) {
        G5C_LOGW(AMF_LOG, "SMF call to %s: %s", url, err);
        out->http = rc;
        return rc;
    }
    out->have_raw = true;
    out->http = out->raw.status;
    parse_smresp(out);
    return out->http;
}

void amf_location_json(const amf_conn *c, const amf_ue *u, g5c_json *parent)
{
    g5c_json *ul = g5c_json_set(parent, "ueLocation", g5c_json_new_obj()), *nr = g5c_json_set(ul, "nrLocation", g5c_json_new_obj());
    amf_tai t = c != NULL && c->has_tai ? c->tai : u->loc;
    amf_tai_to_json(&t, nr, "tai");
    {
        g5c_json *nc = g5c_json_set(nr, "ncgi", g5c_json_new_obj()), *p = g5c_json_set(nc, "plmnId", g5c_json_new_obj());
        char mcc[4], mnc[4], cell[16];
        size_t l = c != NULL ? strlen(c->cell) : 0;
        if (nas_plmn_decode(t.plmn, 3, mcc, mnc) == 0) {
            g5c_json_set_str(p, "mcc", mcc);
            g5c_json_set_str(p, "mnc", mnc);
        }
        /* NrCellId is 9 hex digits */
        memset(cell, '0', 9);
        cell[9] = 0;
        if (l > 0 && l <= 9 && c != NULL && c->has_cgi)
            memcpy(cell + (9 - l), c->cell, l);
        g5c_json_set_str(nc, "nrCellId", cell);
    }
}

static char *sm_root(amf *a, const nas_snssai *s, const char *dnn)
{
    return amf_nf_root(a, "SMF", "nsmf-pdusession", s, dnn);
}

/* Nsmf_PDUSession_UpdateSMContext (TS 29.502 5.2.2.3). `data` may be NULL. */
int amf_sm_update(amf *a, amf_ue *u, uint8_t psi, const g5c_json *data, const uint8_t *n1, size_t n1len, const char *n2_type, const uint8_t *n2,
                  size_t n2len, amf_smresp *out)
{
    g5c_json *j = data != NULL ? g5c_json_dup(data) : g5c_json_new_obj();
    char *url;
    int rc;
    if (psi == 0 || psi > AMF_MAX_PSI || !u->pdu[psi].used || u->pdu[psi].sm_url[0] == 0) {
        g5c_json_free(j);
        memset(out, 0, sizeof *out);
        out->http = 404;
        return 404;
    }
    if (n2_type != NULL)
        g5c_json_set_str(j, "n2SmInfoType", n2_type);
    if (u->conn != NULL && u->has_loc)
        amf_location_json(u->conn, u, j);
    g5c_json_set_str(j, "anType", "3GPP_ACCESS");
    g5c_json_set_str(j, "ratType", "NR");
    url = g5c_xasprintf("%s/modify", u->pdu[psi].sm_url);
    rc = smf_post(a, url, j, n1, n1len, n2, n2len, out);
    free(url);
    g5c_json_free(j);
    return rc;
}

int amf_sm_release(amf *a, amf_ue *u, uint8_t psi, const char *cause)
{
    g5c_json *j = g5c_json_new_obj();
    amf_smresp r;
    char *url;
    int rc;
    if (psi == 0 || psi > AMF_MAX_PSI || !u->pdu[psi].used)
        return 404;
    if (cause != NULL && cause[0] != 0)
        g5c_json_set_str(j, "cause", cause);
    if (u->conn != NULL && u->has_loc)
        amf_location_json(u->conn, u, j);
    url = g5c_xasprintf("%s/release", u->pdu[psi].sm_url);
    rc = smf_post(a, url, j, NULL, 0, NULL, 0, &r);
    if (rc != 200 && rc != 204 && rc != 404)
        G5C_LOGW(AMF_LOG, "SM context release of %s/%u answered %d", u->supi, psi, rc);
    amf_smresp_free(&r);
    free(url);
    g5c_json_free(j);
    amf_pdu_reset(&u->pdu[psi]);
    return rc;
}

void amf_sm_release_all(amf *a, amf_ue *u, const char *cause)
{
    for (uint8_t i = 1; i <= AMF_MAX_PSI; i++)
        if (u->pdu[i].used)
            (void)amf_sm_release(a, u, i, cause);
}

/* The UE is leaving CM-CONNECTED: the SMF is told per session that the access network resources are gone (TS 23.502 4.2.6). */
int amf_sm_deactivate_all(amf *a, amf_ue *u)
{
    int n = 0;
    for (uint8_t i = 1; i <= AMF_MAX_PSI; i++) {
        amf_pdu *p = &u->pdu[i];
        amf_smresp r;
        g5c_json *d;
        if (!p->used || !p->up_active)
            continue;
        d = g5c_json_new_obj();
        g5c_json_set_str(d, "upCnxState", "DEACTIVATED");
        (void)amf_sm_update(a, u, i, d, NULL, 0, NULL, NULL, 0, &r);
        if (r.http == 200 || r.http == 204 || r.http == 404) {
            p->up_active = false;
            p->n2_wait = false;
            n++;
            if (r.http == 404)
                amf_pdu_reset(p);
        } else {
            G5C_LOGW(AMF_LOG, "deactivation of %s/%u answered %d", u->supi, i, r.http);
            p->up_active = false;
        }
        amf_smresp_free(&r);
        g5c_json_free(d);
    }
    return n;
}

/* ---- PDU session establishment ------------------------------------------------------------------------------------------------------------------ */

static void sm_forward_result(amf_conn *c, amf_ue *u, uint8_t psi, amf_smresp *r);

static void sm_establish(amf_conn *c, amf_ue *u, const nas_msg *ul, uint8_t psi, const uint8_t *n1, size_t n1l)
{
    amf *a = c->a;
    size_t n;
    const uint8_t *v;
    nas_snssai sn;
    bool have_sn = false;
    char dnn[64] = "", *root, *url, mcc[4], mnc[4], idh[7], *cb;
    uint8_t rt = 1;
    g5c_json *j, *g;
    amf_smresp r;
    int http;

    v = nas_msg_get(ul, "Request type", &n);
    if (v != NULL && n >= 1)
        rt = (uint8_t)(v[0] & 0x07);
    if (rt == 3 || rt == 4) { /* emergency */
        send_payload_not_forwarded(c, u, 1, n1, n1l, psi);
        return;
    }
    v = nas_msg_get(ul, "S-NSSAI", &n);
    if (v != NULL && nas_snssai_decode(v, n, &sn) == NAS_OK)
        have_sn = true;
    if (!have_sn) { /* the UE gave none: the default of the allowed NSSAI (TS 23.501 5.15.5.3) */
        if (u->nallowed == 0) {
            send_payload_not_forwarded(c, u, 1, n1, n1l, psi);
            return;
        }
        sn = u->allowed[0];
    } else if (!amf_snssai_in(u->allowed, u->nallowed, &sn)) {
        G5C_LOGW(AMF_LOG, "%s asked for a slice outside its allowed NSSAI", u->supi);
        amf_count(a, "g5c_amf_pdu_session_requests_total", "PDU session establishment requests by result.", "result", "slice_not_allowed");
        send_payload_not_forwarded(c, u, 1, n1, n1l, psi);
        return;
    }
    v = nas_msg_get(ul, "DNN", &n);
    if (v != NULL)
        (void)nas_dnn_decode(v, n, dnn, sizeof dnn);
    if (a->cfg.use_nssf && amf_nssf_pdu_session(a, &sn, c->has_tai ? &c->tai : &a->cfg.tai[0]) == 1) {
        G5C_LOGW(AMF_LOG, "%s: the NSSF does not serve the requested slice in this tracking area", u->supi);
        amf_count(a, "g5c_amf_pdu_session_requests_total", "PDU session establishment requests by result.", "result", "slice_refused_by_nssf");
        send_payload_not_forwarded(c, u, 1, n1, n1l, psi);
        return;
    }
    {
        const char *use = dnn[0] != 0 ? dnn : a->cfg.default_dnn;
        root = sm_root(a, &sn, use);
        if (root == NULL) {
            amf_count(a, "g5c_amf_pdu_session_requests_total", "PDU session establishment requests by result.", "result", "no_smf");
            send_payload_not_forwarded(c, u, 1, n1, n1l, psi);
            return;
        }
        j = g5c_json_new_obj();
        g5c_json_set_str(j, "supi", u->supi);
        if (u->pei[0] != 0)
            g5c_json_set_str(j, "pei", u->pei);
        g5c_json_set_int(j, "pduSessionId", psi);
        if (dnn[0] != 0)
            g5c_json_set_str(j, "dnn", dnn);
        g5c_json_set_str(j, "selectedDnn", use);
        snprintf(dnn, sizeof dnn, "%s", use);
    }
    amf_snssai_json(&sn, j, "sNssai");
    g5c_json_set_str(j, "servingNfId", a->instance_id);
    g = g5c_json_set(j, "guami", g5c_json_new_obj());
    {
        g5c_json *p = g5c_json_set(g, "plmnId", g5c_json_new_obj());
        g5c_json_set_str(p, "mcc", a->cfg.mcc);
        g5c_json_set_str(p, "mnc", a->cfg.mnc);
    }
    snprintf(idh, sizeof idh, "%06X", (uint32_t)a->cfg.id.region << 16 | (uint32_t)a->cfg.id.set << 6 | a->cfg.id.pointer);
    g5c_json_set_str(g, "amfId", idh);
    {
        g5c_json *p = g5c_json_set(j, "servingNetwork", g5c_json_new_obj());
        g5c_json_set_str(p, "mcc", a->cfg.mcc);
        g5c_json_set_str(p, "mnc", a->cfg.mnc);
    }
    (void)mcc;
    (void)mnc;
    g5c_json_set_str(j, "requestType", rt == 2 ? "EXISTING_PDU_SESSION" : "INITIAL_REQUEST");
    g5c_json_set_str(j, "anType", "3GPP_ACCESS");
    g5c_json_set_str(j, "ratType", "NR");
    amf_location_json(c, u, j);
    cb = amf_cb_uri(a, "/namf-callback/v1/smf-status");
    {
        char *full = g5c_xasprintf("%s/%s/%u", cb, u->supi, psi);
        g5c_json_set_str(j, "smContextStatusUri", full);
        free(full);
    }
    free(cb);
    url = g5c_xasprintf("%s/nsmf-pdusession/v1/sm-contexts", root);
    /* an old session under the same id is replaced by the SMF (TS 23.502 4.3.2.2.1): forget our reference first */
    amf_pdu_reset(&u->pdu[psi]);
    http = smf_post(a, url, j, n1, n1l, NULL, 0, &r);
    free(url);
    free(root);
    g5c_json_free(j);
    if (http == 201 && r.location[0] != 0) {
        amf_pdu *p = &u->pdu[psi];
        p->used = true;
        snprintf(p->sm_url, sizeof p->sm_url, "%s", r.location);
        snprintf(p->dnn, sizeof p->dnn, "%s", dnn);
        p->snssai = sn;
        p->has_snssai = true;
        amf_count(a, "g5c_amf_pdu_session_requests_total", "PDU session establishment requests by result.", "result", "created");
        amf_persist_request(a);
    } else {
        amf_count(a, "g5c_amf_pdu_session_requests_total", "PDU session establishment requests by result.", "result", http > 0 ? "rejected" : "smf_error");
        if (r.n1 != NULL && r.n1->len > 0)
            (void)send_sm_nas(c, u, psi, r.n1->data, r.n1->len); /* the establishment reject the SMF built */
        else
            send_payload_not_forwarded(c, u, 1, n1, n1l, psi);
    }
    amf_smresp_free(&r);
}

/* ---- uplink NAS transport ------------------------------------------------------------------------------------------------------------------------ */

static void sm_forward(amf_conn *c, amf_ue *u, uint8_t psi, const uint8_t *n1, size_t n1l, uint8_t mt)
{
    amf *a = c->a;
    amf_smresp r;
    int http;
    if (psi == 0 || psi > AMF_MAX_PSI || !u->pdu[psi].used) {
        if (mt == 0xd4 || mt == 0xcc || mt == 0xcd || mt == 0xd6) /* completions / status for a session we no longer know */
            return;
        send_payload_not_forwarded(c, u, 1, n1, n1l, psi);
        return;
    }
    http = amf_sm_update(a, u, psi, NULL, n1, n1l, NULL, NULL, 0, &r);
    if (http == 404) {
        amf_pdu_reset(&u->pdu[psi]);
        amf_persist_request(a);
    } else if (http >= 200 && http < 300) {
        sm_forward_result(c, u, psi, &r);
    } else {
        G5C_LOGW(AMF_LOG, "SMF answered %d for a 5GSM message of %s/%u", http, u->supi, psi);
        send_payload_not_forwarded(c, u, 1, n1, n1l, psi);
    }
    if (mt == 0xd4) { /* PDU SESSION RELEASE COMPLETE: the SMF released the session */
        amf_pdu_reset(&u->pdu[psi]);
        amf_persist_request(a);
    }
    amf_smresp_free(&r);
}

int amf_ul_nas_transport(amf_conn *c, amf_ue *u, const nas_msg *m)
{
    size_t n, pn;
    const uint8_t *v = nas_msg_get(m, "Payload container type", &n), *payload = nas_msg_get(m, "Payload container", &pn);
    uint8_t ptype = (v != NULL && n >= 1) ? (uint8_t)(v[0] & 0x0f) : 0, psi = 0;
    v = nas_msg_get(m, "PDU session ID", &n);
    if (v != NULL && n >= 1)
        psi = v[0];
    if (payload == NULL || pn < 4) {
        send_payload_not_forwarded(c, u, ptype, payload != NULL ? payload : (const uint8_t *)"", payload != NULL ? pn : 0, psi);
        return -1;
    }
    if (ptype != 1) { /* SMS, LPP, SOR, UE policy, ... : not forwarded (TS 24.501 5.4.5.3.3) */
        amf_count(c->a, "g5c_amf_ul_nas_payload_total", "Uplink NAS transport payloads by container type.", "type", ptype == 5 ? "ue_policy" : "other");
        send_payload_not_forwarded(c, u, ptype, payload, pn, psi);
        return 0;
    }
    if (psi == 0 || psi > AMF_MAX_PSI) {
        send_payload_not_forwarded(c, u, 1, payload, pn, 0);
        return -1;
    }
    {
        uint8_t mt = payload[3];
        if (payload[0] != NAS_EPD_5GSM || payload[1] != psi) {
            send_payload_not_forwarded(c, u, 1, payload, pn, psi);
            return -1;
        }
        if (mt == MT_PDU_EST_REQ)
            sm_establish(c, u, m, psi, payload, pn);
        else
            sm_forward(c, u, psi, payload, pn, mt);
    }
    return 0;
}

/* ---- results of SMF calls that carry N1 / N2 for the UE and the gNB --------------------------------------------------------------------------------- */

static g5c_json *tr_item(uint8_t psi, const char *nas_key, const uint8_t *nas, size_t nas_len, const nas_snssai *sn, const char *tr_key, const uint8_t *tr,
                         size_t tr_len)
{
    g5c_json *it = g5c_json_new_obj();
    char *h;
    g5c_json_set_int(it, "pDUSessionID", psi);
    if (nas != NULL && nas_len > 0 && nas_key != NULL) {
        h = g5c_hex_encode(nas, nas_len);
        g5c_json_set_str(it, nas_key, h);
        free(h);
    }
    if (sn != NULL)
        g5c_json_set(it, "s-NSSAI", ng_snssai_json(sn));
    h = g5c_hex_encode(tr, tr_len);
    g5c_json_set_str(it, tr_key, h);
    free(h);
    return it;
}

static void sm_forward_result(amf_conn *c, amf_ue *u, uint8_t psi, amf_smresp *r)
{
    const char *type = g5c_json_get_str(r->json, "n2SmInfoType");
    amf_pdu *p = &u->pdu[psi];
    g5c_bytes nas;
    g5c_bytes_init(&nas);
    if (r->n2 != NULL && type != NULL && strcmp(type, "PDU_RES_REL_CMD") == 0) {
        g5c_json *list = g5c_json_new_arr();
        if (r->n1 != NULL)
            (void)dl_sm_nas(u, psi, r->n1->data, r->n1->len, &nas);
        g5c_json_push(list, tr_item(psi, NULL, NULL, 0, NULL, "pDUSessionResourceReleaseCommandTransfer", r->n2->data, r->n2->len));
        p->releasing = true;
        (void)conn_send_pdu_release(c, list, nas.data, nas.len);
    } else if (r->n2 != NULL && type != NULL && strcmp(type, "PDU_RES_MOD_REQ") == 0) {
        g5c_json *list = g5c_json_new_arr();
        if (r->n1 != NULL)
            (void)dl_sm_nas(u, psi, r->n1->data, r->n1->len, &nas);
        g5c_json_push(list, tr_item(psi, "nAS-PDU", nas.data, nas.len, NULL, "pDUSessionResourceModifyRequestTransfer", r->n2->data, r->n2->len));
        (void)conn_send_pdu_modify(c, list);
    } else if (r->n2 != NULL && type != NULL && strcmp(type, "PDU_RES_SETUP_REQ") == 0) {
        g5c_json *list = g5c_json_new_arr();
        if (r->n1 != NULL)
            (void)dl_sm_nas(u, psi, r->n1->data, r->n1->len, &nas);
        g5c_json_push(list, tr_item(psi, "pDUSessionNAS-PDU", nas.data, nas.len, p->has_snssai ? &p->snssai : &u->allowed[0], "pDUSessionResourceSetupRequestTransfer",
                                    r->n2->data, r->n2->len));
        p->n2_wait = true;
        (void)conn_send_pdu_setup(c, u, list, NULL, 0);
    } else if (r->n1 != NULL && r->n1->len > 0) {
        (void)send_sm_nas(c, u, psi, r->n1->data, r->n1->len);
    }
    g5c_bytes_free(&nas);
}

/* ---- reports from the gNB --------------------------------------------------------------------------------------------------------------------------- */

static uint8_t *item_bytes(const g5c_json *it, const char *key, size_t *n)
{
    const char *h = g5c_json_get_str(it, key);
    size_t len = h != NULL ? strlen(h) / 2 : 0;
    uint8_t *b;
    if (len == 0 || len > 65536)
        return NULL;
    b = g5c_xmalloc(len);
    if (g5c_hex_decode(h, b, len) != (long)len) {
        free(b);
        return NULL;
    }
    *n = len;
    return b;
}

/* report one transfer of the gNB to the SMF */
static void report(amf *a, amf_ue *u, uint8_t psi, const char *type, const uint8_t *tr, size_t trl, bool activates)
{
    amf_smresp r;
    int http = amf_sm_update(a, u, psi, NULL, NULL, 0, type, tr, trl, &r);
    amf_pdu *p = (psi >= 1 && psi <= AMF_MAX_PSI) ? &u->pdu[psi] : NULL;
    if (p != NULL && p->used) {
        if (http == 404) {
            amf_pdu_reset(p);
        } else if (http >= 200 && http < 300) {
            const char *st = g5c_json_get_str(r.json, "upCnxState");
            p->n2_wait = false;
            if (activates)
                p->up_active = st == NULL || strcmp(st, "ACTIVATED") == 0;
            if (strstr(type, "FAIL") != NULL || strcmp(type, "PDU_RES_REL_RSP") == 0) {
                p->up_active = false;
                if (strcmp(type, "PDU_RES_REL_RSP") == 0 || strcmp(type, "PDU_RES_SETUP_FAIL") == 0)
                    amf_pdu_reset(p); /* the SMF has released the session */
            }
        } else {
            G5C_LOGW(AMF_LOG, "SMF answered %d to %s for %s/%u", http, type, u->supi, psi);
        }
    }
    amf_smresp_free(&r);
}

static void handle_setup_lists(amf *a, amf_ue *u, const g5c_json *ok_list, const g5c_json *fail_list, const char *ok_key, const char *fail_key)
{
    for (size_t i = 0; i < g5c_json_len(ok_list); i++) {
        const g5c_json *it = g5c_json_at(ok_list, i);
        int64_t psi;
        size_t n = 0;
        uint8_t *b = item_bytes(it, ok_key, &n);
        if (b != NULL && g5c_json_get_int(it, "pDUSessionID", &psi) && psi >= 1 && psi <= AMF_MAX_PSI)
            report(a, u, (uint8_t)psi, "PDU_RES_SETUP_RSP", b, n, true);
        free(b);
    }
    for (size_t i = 0; i < g5c_json_len(fail_list); i++) {
        const g5c_json *it = g5c_json_at(fail_list, i);
        int64_t psi;
        size_t n = 0;
        uint8_t *b = item_bytes(it, fail_key, &n);
        if (b != NULL && g5c_json_get_int(it, "pDUSessionID", &psi) && psi >= 1 && psi <= AMF_MAX_PSI)
            report(a, u, (uint8_t)psi, "PDU_RES_SETUP_FAIL", b, n, false);
        free(b);
    }
}

void amf_handle_pdu_setup_response(amf_conn *c, amf_ue *u, const g5c_json *msg, bool failed_only)
{
    (void)failed_only;
    handle_setup_lists(c->a, u, ngap_find_ie(msg, NGAP_IE_PDUSessionResourceSetupListSURes), ngap_find_ie(msg, NGAP_IE_PDUSessionResourceFailedToSetupListSURes),
                       "pDUSessionResourceSetupResponseTransfer", "pDUSessionResourceSetupUnsuccessfulTransfer");
    amf_persist_request(c->a);
}

void amf_handle_pdu_modify_response(amf_conn *c, amf_ue *u, const g5c_json *msg)
{
    const g5c_json *ok = ngap_find_ie(msg, NGAP_IE_PDUSessionResourceModifyListModRes), *fl = ngap_find_ie(msg, NGAP_IE_PDUSessionResourceFailedToModifyListModRes);
    for (size_t i = 0; i < g5c_json_len(ok); i++) {
        const g5c_json *it = g5c_json_at(ok, i);
        int64_t psi;
        size_t n = 0;
        uint8_t *b = item_bytes(it, "pDUSessionResourceModifyResponseTransfer", &n);
        if (b != NULL && g5c_json_get_int(it, "pDUSessionID", &psi) && psi >= 1 && psi <= AMF_MAX_PSI)
            report(c->a, u, (uint8_t)psi, "PDU_RES_MOD_RSP", b, n, false);
        free(b);
    }
    for (size_t i = 0; i < g5c_json_len(fl); i++) {
        const g5c_json *it = g5c_json_at(fl, i);
        int64_t psi;
        size_t n = 0;
        uint8_t *b = item_bytes(it, "pDUSessionResourceModifyUnsuccessfulTransfer", &n);
        if (b != NULL && g5c_json_get_int(it, "pDUSessionID", &psi) && psi >= 1 && psi <= AMF_MAX_PSI)
            report(c->a, u, (uint8_t)psi, "PDU_RES_MOD_FAIL", b, n, false);
        free(b);
    }
}

void amf_handle_pdu_release_response(amf_conn *c, amf_ue *u, const g5c_json *msg)
{
    const g5c_json *list = ngap_find_ie(msg, NGAP_IE_PDUSessionResourceReleasedListRelRes);
    for (size_t i = 0; i < g5c_json_len(list); i++) {
        const g5c_json *it = g5c_json_at(list, i);
        int64_t psi;
        size_t n = 0;
        uint8_t *b = item_bytes(it, "pDUSessionResourceReleaseResponseTransfer", &n);
        if (b != NULL && g5c_json_get_int(it, "pDUSessionID", &psi) && psi >= 1 && psi <= AMF_MAX_PSI)
            report(c->a, u, (uint8_t)psi, "PDU_RES_REL_RSP", b, n, false);
        free(b);
    }
    amf_persist_request(c->a);
}

void amf_handle_pdu_notify(amf_conn *c, amf_ue *u, const g5c_json *msg)
{
    const g5c_json *list = ngap_find_ie(msg, NGAP_IE_PDUSessionResourceNotifyList), *rel = ngap_find_ie(msg, NGAP_IE_PDUSessionResourceReleasedListNot);
    for (size_t i = 0; i < g5c_json_len(list); i++) {
        const g5c_json *it = g5c_json_at(list, i);
        int64_t psi;
        size_t n = 0;
        uint8_t *b = item_bytes(it, "pDUSessionResourceNotifyTransfer", &n);
        if (b != NULL && g5c_json_get_int(it, "pDUSessionID", &psi) && psi >= 1 && psi <= AMF_MAX_PSI)
            report(c->a, u, (uint8_t)psi, "PDU_RES_NTY", b, n, false);
        free(b);
    }
    for (size_t i = 0; i < g5c_json_len(rel); i++) {
        const g5c_json *it = g5c_json_at(rel, i);
        int64_t psi;
        size_t n = 0;
        uint8_t *b = item_bytes(it, "pDUSessionResourceNotifyReleasedTransfer", &n);
        if (b != NULL && g5c_json_get_int(it, "pDUSessionID", &psi) && psi >= 1 && psi <= AMF_MAX_PSI)
            report(c->a, u, (uint8_t)psi, "PDU_RES_NTY_REL", b, n, false);
        free(b);
    }
}

void amf_handle_ics_response(amf_conn *c, amf_ue *u, const g5c_json *msg)
{
    c->ics_done = true;
    if (msg != NULL) {
        handle_setup_lists(c->a, u, ngap_find_ie(msg, NGAP_IE_PDUSessionResourceSetupListCxtRes),
                           ngap_find_ie(msg, NGAP_IE_PDUSessionResourceFailedToSetupListCxtRes), "pDUSessionResourceSetupResponseTransfer",
                           "pDUSessionResourceSetupUnsuccessfulTransfer");
        amf_persist_request(c->a);
        (void)amf_n1n2_deliver_pending(c, u, false, NULL, NULL);
    }
}

/* ---- PDU session status ------------------------------------------------------------------------------------------------------------------------------ */

/* The UE says which sessions it holds: those the AMF has that the UE does not are released (TS 24.501 5.5.1.3.4, TS 23.502 4.2.2.2.2). */
int amf_psi_status_reconcile(amf *a, amf_ue *u, uint16_t ue_status)
{
    int released = 0;
    for (uint8_t i = 1; i <= AMF_MAX_PSI; i++)
        if (u->pdu[i].used && !(ue_status & (1u << i))) {
            G5C_LOGI(AMF_LOG, "%s: PDU session %u is not in the UE's status: releasing", u->supi, i);
            (void)amf_sm_release(a, u, i, "PDU_SESSION_STATUS_MISMATCH");
            released++;
        }
    if (released > 0)
        amf_persist_request(a);
    return released;
}

/* Reactivate the user plane of the sessions in `want` (Uplink data status): the SMF's N2 request goes into the context setup (TS 23.502 4.2.3.2). */
int amf_sm_activate(amf *a, amf_ue *u, uint16_t want, g5c_json **list, uint16_t *react)
{
    int n = 0;
    *react = 0;
    for (uint8_t i = 1; i <= AMF_MAX_PSI; i++) {
        amf_pdu *p = &u->pdu[i];
        amf_smresp r;
        g5c_json *d;
        const char *type;
        if (!(want & (1u << i)) || !p->used)
            continue;
        d = g5c_json_new_obj();
        g5c_json_set_str(d, "upCnxState", "ACTIVATING");
        (void)amf_sm_update(a, u, i, d, NULL, 0, NULL, NULL, 0, &r);
        type = g5c_json_get_str(r.json, "n2SmInfoType");
        if (r.http == 200 && r.n2 != NULL && type != NULL && strcmp(type, "PDU_RES_SETUP_REQ") == 0) {
            if (*list == NULL)
                *list = g5c_json_new_arr();
            g5c_json_push(*list, tr_item(i, "nAS-PDU", NULL, 0, p->has_snssai ? &p->snssai : &u->allowed[0], "pDUSessionResourceSetupRequestTransfer",
                                         r.n2->data, r.n2->len));
            p->n2_wait = true;
            *react = (uint16_t)(*react | (1u << i));
            n++;
        } else {
            G5C_LOGW(AMF_LOG, "user plane of %s/%u could not be reactivated (status %d)", u->supi, i, r.http);
        }
        amf_smresp_free(&r);
        g5c_json_free(d);
    }
    return n;
}

/* ---- Namf_Communication_N1N2MessageTransfer ----------------------------------------------------------------------------------------------------- */

static bool in_parse(const g5c_req *req, g5c_resp *resp, g5c_json **j, g5c_mp *mp, bool *is_mp)
{
    const char *ct = g5c_req_header(req, "content-type");
    const uint8_t *jd = req->body;
    size_t jl = req->body_len;
    char err[100];
    *is_mp = false;
    *j = NULL;
    if (ct != NULL && g5c_mp_is_multipart(ct)) {
        if (g5c_mp_parse(ct, req->body, req->body_len, mp) != 0 || mp->n == 0) {
            g5c_resp_problem_simple(resp, 400, "INVALID_MSG_FORMAT", "malformed multipart/related body");
            return false;
        }
        *is_mp = true;
        jd = mp->parts[0].data;
        jl = mp->parts[0].len;
    }
    *j = g5c_json_parse((const char *)jd, jl, err, sizeof err);
    if (*j == NULL || !g5c_json_is(*j, G5C_J_OBJECT)) {
        g5c_resp_problem_simple(resp, 400, "INVALID_MSG_FORMAT", "the JSON part is not an object");
        g5c_json_free(*j);
        *j = NULL;
        if (*is_mp)
            g5c_mp_free(mp);
        *is_mp = false;
        return false;
    }
    return true;
}

static void queue_pending(amf_ue *u, uint8_t psi, const uint8_t *n1, size_t n1l, const char *type, const uint8_t *n2, size_t n2l, const nas_snssai *sn,
                          const char *notif)
{
    amf_pend *p = g5c_xcalloc(1, sizeof *p), **pp;
    p->psi = psi;
    if (n1l > 0) {
        p->n1 = g5c_xmalloc(n1l);
        memcpy(p->n1, n1, n1l);
        p->n1len = n1l;
    }
    if (n2l > 0) {
        p->n2 = g5c_xmalloc(n2l);
        memcpy(p->n2, n2, n2l);
        p->n2len = n2l;
    }
    if (type != NULL)
        snprintf(p->n2type, sizeof p->n2type, "%s", type);
    if (sn != NULL) {
        p->has_snssai = true;
        p->snssai = *sn;
    }
    if (notif != NULL)
        snprintf(p->notif_uri, sizeof p->notif_uri, "%s", notif);
    for (pp = &u->pend; *pp != NULL; pp = &(*pp)->next)
        ;
    *pp = p;
}

/* send one transfer now over the established connection */
static int deliver_now(amf_conn *c, amf_ue *u, uint8_t psi, const uint8_t *n1, size_t n1l, const char *type, const uint8_t *n2, size_t n2l, const nas_snssai *sn)
{
    amf_pdu *p = (psi >= 1 && psi <= AMF_MAX_PSI) ? &u->pdu[psi] : NULL;
    g5c_bytes nas;
    g5c_json *list;
    int rc = 0;
    g5c_bytes_init(&nas);
    if (n1l > 0)
        (void)dl_sm_nas(u, psi, n1, n1l, &nas);
    if (n2l > 0 && type != NULL && strcmp(type, "PDU_RES_SETUP_REQ") == 0) {
        const nas_snssai *use = sn != NULL ? sn : (p != NULL && p->has_snssai ? &p->snssai : (u->nallowed > 0 ? &u->allowed[0] : NULL));
        if (use == NULL) {
            rc = -1;
        } else {
            list = g5c_json_new_arr();
            g5c_json_push(list, tr_item(psi, "pDUSessionNAS-PDU", nas.data, nas.len, use, "pDUSessionResourceSetupRequestTransfer", n2, n2l));
            if (p != NULL)
                p->n2_wait = true;
            rc = conn_send_pdu_setup(c, u, list, NULL, 0);
        }
    } else if (n2l > 0 && type != NULL && strcmp(type, "PDU_RES_MOD_REQ") == 0) {
        list = g5c_json_new_arr();
        g5c_json_push(list, tr_item(psi, "nAS-PDU", nas.data, nas.len, NULL, "pDUSessionResourceModifyRequestTransfer", n2, n2l));
        rc = conn_send_pdu_modify(c, list);
    } else if (n2l > 0 && type != NULL && strcmp(type, "PDU_RES_REL_CMD") == 0) {
        list = g5c_json_new_arr();
        g5c_json_push(list, tr_item(psi, NULL, NULL, 0, NULL, "pDUSessionResourceReleaseCommandTransfer", n2, n2l));
        if (p != NULL)
            p->releasing = true;
        rc = conn_send_pdu_release(c, list, nas.data, nas.len);
    } else if (n1l > 0) {
        rc = conn_send_nas(c, nas.data, nas.len);
    } else {
        rc = -1;
    }
    g5c_bytes_free(&nas);
    return rc;
}

/* Called when the UE became reachable. In the context setup (in_ics) only the PDU session setups travel with it (appended to *ics_list); the rest is
 * sent once the connection has its AS context. */
int amf_n1n2_deliver_pending(amf_conn *c, amf_ue *u, bool in_ics, g5c_json *pdu_list, g5c_json **ics_list_out)
{
    amf_pend **pp = &u->pend;
    int n = 0;
    (void)pdu_list;
    while (*pp != NULL) {
        amf_pend *p = *pp;
        bool is_setup = p->n2len > 0 && strcmp(p->n2type, "PDU_RES_SETUP_REQ") == 0;
        if (in_ics) {
            if (!is_setup) {
                pp = &p->next;
                continue;
            }
            {
                amf_pdu *pd = (p->psi >= 1 && p->psi <= AMF_MAX_PSI) ? &u->pdu[p->psi] : NULL;
                const nas_snssai *use = p->has_snssai ? &p->snssai : (pd != NULL && pd->has_snssai ? &pd->snssai : (u->nallowed > 0 ? &u->allowed[0] : NULL));
                g5c_bytes nas;
                g5c_bytes_init(&nas);
                if (p->n1len > 0)
                    (void)dl_sm_nas(u, p->psi, p->n1, p->n1len, &nas);
                if (use != NULL && ics_list_out != NULL) {
                    if (*ics_list_out == NULL)
                        *ics_list_out = g5c_json_new_arr();
                    g5c_json_push(*ics_list_out, tr_item(p->psi, "nAS-PDU", nas.data, nas.len, use, "pDUSessionResourceSetupRequestTransfer", p->n2, p->n2len));
                    if (pd != NULL)
                        pd->n2_wait = true;
                    n++;
                }
                g5c_bytes_free(&nas);
            }
        } else {
            (void)deliver_now(c, u, p->psi, p->n1, p->n1len, p->n2type[0] != 0 ? p->n2type : NULL, p->n2, p->n2len, p->has_snssai ? &p->snssai : NULL);
            n++;
        }
        *pp = p->next;
        amf_pend_free(p);
    }
    return n;
}

void amf_notify_n1n2_failure(amf *a, const char *uri, const char *cause)
{
    g5c_json *j = g5c_json_new_obj(), *info;
    g5c_resp r;
    char err[160];
    info = g5c_json_set(j, "cause", g5c_json_new_str(cause));
    (void)info;
    g5c_json_set_str(j, "n1n2MsgDataUri", "");
    if (g5c_client_send_json(a->client, "POST", uri, j, &r, err, sizeof err) == 0)
        g5c_resp_free(&r);
    else
        G5C_LOGW(AMF_LOG, "N1N2 transfer failure notification: %s", err);
    g5c_json_free(j);
}

static void n1n2_transfer(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    amf *a = ctx;
    g5c_json *j = NULL;
    g5c_mp mp;
    bool is_mp = false;
    const char *supi = g5c_req_param(req, "ueContextId");
    const g5c_json *n1c, *n2c, *sm, *ic;
    const g5c_mp_part *n1 = NULL, *n2 = NULL;
    const char *type = NULL, *notif;
    int64_t psi = 0;
    bool skip = false;
    amf_ue *u;
    nas_snssai sn, *snp = NULL;
    amf_conn *c;
    g5c_json *out;
    int http = 200;
    const char *cause = "N1_N2_TRANSFER_INITIATED";
    bool answered = false;

    if (!in_parse(req, resp, &j, &mp, &is_mp))
        return;
    if (!g5c_json_get_int(j, "pduSessionId", &psi))
        psi = 0;
    n1c = g5c_json_get(j, "n1MessageContainer");
    n2c = g5c_json_get(j, "n2InfoContainer");
    if (n1c != NULL && is_mp) {
        n1 = g5c_mp_find(&mp, g5c_json_get_str(g5c_json_get(n1c, "n1MessageContent"), "contentId"));
        if (n1 == NULL) {
            g5c_resp_problem_invalid(resp, 400, "INVALID_MSG_FORMAT", "n1MessageContent", "no part with that contentId");
            goto done;
        }
    }
    if (n2c != NULL) {
        sm = g5c_json_get(n2c, "smInfo");
        ic = g5c_json_get(sm, "n2InfoContent");
        type = g5c_json_get_str(ic, "ngapIeType");
        if (is_mp) {
            n2 = g5c_mp_find(&mp, g5c_json_get_str(g5c_json_get(ic, "ngapData"), "contentId"));
            if (n2 == NULL) {
                g5c_resp_problem_invalid(resp, 400, "INVALID_MSG_FORMAT", "ngapData", "no part with that contentId");
                goto done;
            }
        }
        if (psi == 0)
            (void)g5c_json_get_int(sm, "pduSessionId", &psi);
        if (amf_snssai_from_json(g5c_json_get(sm, "sNssai"), &sn))
            snp = &sn;
    }
    if (n1 == NULL && n2 == NULL) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", "n1MessageContainer", "no N1 or N2 content");
        goto done;
    }
    if (psi < 1 || psi > AMF_MAX_PSI) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "pduSessionId", "must be 1..=15");
        goto done;
    }
    if (n2 != NULL && (type == NULL || (strcmp(type, "PDU_RES_SETUP_REQ") != 0 && strcmp(type, "PDU_RES_MOD_REQ") != 0 && strcmp(type, "PDU_RES_REL_CMD") != 0))) {
        g5c_resp_problem_invalid(resp, 501, "UNSUPPORTED_N2_INFO", "ngapIeType", "not handled by this AMF");
        goto done;
    }
    (void)g5c_json_get_bool(j, "skipInd", &skip);
    notif = g5c_json_get_str(j, "n1n2FailureTxfNotifURI");
    u = supi != NULL ? amf_ue_find_supi(a, supi) : NULL;
    if (u == NULL) {
        g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "no such UE context");
        amf_count(a, "g5c_amf_n1n2_transfers_total", "N1N2MessageTransfer requests by result.", "result", "unknown_ue");
        goto done;
    }
    pthread_mutex_lock(&u->mu);
    c = u->conn;
    if (u->mm != MM_REGISTERED || u->removed) {
        g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "the UE is not registered");
        answered = true;
        amf_count(a, "g5c_amf_n1n2_transfers_total", "N1N2MessageTransfer requests by result.", "result", "not_registered");
    } else if (c != NULL && u->cm == CM_CONNECTED && c->ics_done && !c->closed) {
        if (deliver_now(c, u, (uint8_t)psi, n1 != NULL ? n1->data : NULL, n1 != NULL ? n1->len : 0, type, n2 != NULL ? n2->data : NULL, n2 != NULL ? n2->len : 0,
                        snp) != 0) {
            http = 500;
            cause = "N1_MSG_NOT_TRANSFERRED";
        }
        amf_count(a, "g5c_amf_n1n2_transfers_total", "N1N2MessageTransfer requests by result.", "result", "delivered");
    } else if (c != NULL && u->cm == CM_CONNECTED && !c->closed) {
        /* the access context is still being set up: deliver as soon as the gNB confirmed it */
        queue_pending(u, (uint8_t)psi, n1 != NULL ? n1->data : NULL, n1 != NULL ? n1->len : 0, type, n2 != NULL ? n2->data : NULL, n2 != NULL ? n2->len : 0,
                      snp, notif);
        amf_count(a, "g5c_amf_n1n2_transfers_total", "N1N2MessageTransfer requests by result.", "result", "queued");
    } else if (skip) {
        cause = "N1_MSG_NOT_TRANSFERRED";
        amf_count(a, "g5c_amf_n1n2_transfers_total", "N1N2MessageTransfer requests by result.", "result", "skipped");
    } else {
        queue_pending(u, (uint8_t)psi, n1 != NULL ? n1->data : NULL, n1 != NULL ? n1->len : 0, type, n2 != NULL ? n2->data : NULL, n2 != NULL ? n2->len : 0,
                      snp, notif);
        gmm_page_start(u);
        http = 202;
        cause = "ATTEMPTING_TO_REACH_UE";
        amf_count(a, "g5c_amf_n1n2_transfers_total", "N1N2MessageTransfer requests by result.", "result", "paging");
    }
    pthread_mutex_unlock(&u->mu);
    amf_ue_unref(u);
    if (!answered) {
        out = g5c_json_new_obj();
        g5c_json_set_str(out, "cause", cause);
        g5c_resp_json(resp, http, out);
        g5c_json_free(out);
    }
done:
    g5c_json_free(j);
    if (is_mp)
        g5c_mp_free(&mp);
}

void amf_n1n2_routes(g5c_router *r, amf *a)
{
    g5c_router_route(r, "POST", "/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages", n1n2_transfer, a);
}
