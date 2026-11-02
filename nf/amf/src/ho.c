/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Mobility between gNBs: Xn handover completion by Path Switch Request (TS 38.413 8.4.4) and N2 handover (TS 38.413 8.4.1 - 8.4.5, TS 23.502
 * 4.9.1.3). The user plane is moved by the SMF; the AMF derives the next hop for the target gNB (TS 33.501 6.9.2.3) and relays the containers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nasmsg.h"

#define HO_PREP_SECS 10
#define HO_OVERALL_SECS 15

/* ---- helpers --------------------------------------------------------------------------------------------------------------------------------- */

static int send_to(amf *a, const amf_conn *c, g5c_json *pdu)
{
    int rc = amf_send_pdu(a, c->gnb, c->gnb_gen, c->stream, pdu);
    g5c_json_free(pdu);
    return rc;
}

static int send_origin(amf *a, const amf_conn *c, g5c_json *pdu)
{
    int rc = amf_send_pdu(a, c->rx_gnb, c->rx_gen, c->rx_stream, pdu);
    g5c_json_free(pdu);
    return rc;
}

static uint8_t *hex_bytes(const char *h, size_t *n)
{
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

static g5c_json *security_context_json(amf_sec *s)
{
    g5c_json *o = g5c_json_new_obj();
    g5c_json_set_int(o, "nextHopChainingCount", s->ncc & 7);
    g5c_json_set(o, "nextHopNH", ng_bits(s->nh, 256));
    return o;
}

static g5c_json *unsuccessful_transfer(const char *group, const char *cause)
{
    /* the transfer types of the failure lists all carry one Cause */
    g5c_json *t = g5c_json_new_obj();
    g5c_json_set(t, "cause", ng_cause(group, cause));
    return t;
}

static g5c_json *encoded_item(uint8_t psi, const char *type_name, const char *key, const g5c_json *tree)
{
    g5c_bytes b;
    char err[120];
    g5c_json *it = g5c_json_new_obj();
    g5c_json_set_int(it, "pDUSessionID", psi);
    g5c_bytes_init(&b);
    if (ngap_encode_as(type_name, tree, &b, err, sizeof err) == 0) {
        char *h = g5c_hex_encode(b.data, b.len);
        g5c_json_set_str(it, key, h);
        free(h);
    }
    g5c_bytes_free(&b);
    return it;
}

static void attach_target(amf_conn *tc, amf_ue *u)
{
    amf *a = tc->a;
    amf_ue_ref(u);
    pthread_mutex_lock(&a->tmu);
    tc->ue = u;
    u->ho_conn = tc;
    pthread_mutex_unlock(&a->tmu);
}

static void detach_target(amf_conn *tc, amf_ue *u)
{
    amf *a = tc->a;
    bool had = false;
    pthread_mutex_lock(&a->tmu);
    if (u->ho_conn == tc)
        u->ho_conn = NULL;
    if (tc->ue == u) {
        tc->ue = NULL;
        had = true;
    }
    pthread_mutex_unlock(&a->tmu);
    if (had)
        amf_ue_unref(u);
}

/* tell the SMF that the handover will not happen */
static void cancel_at_smf(amf *a, amf_ue *u, const char *cause)
{
    for (uint8_t i = 1; i <= AMF_MAX_PSI; i++) {
        amf_smresp r;
        g5c_json *d;
        if (!u->pdu[i].used || !u->pdu[i].up_active)
            continue;
        d = g5c_json_new_obj();
        g5c_json_set_str(d, "hoState", "CANCELLED");
        if (cause != NULL)
            g5c_json_set_str(d, "cause", cause);
        (void)amf_sm_update(a, u, i, d, NULL, 0, NULL, NULL, 0, &r);
        amf_smresp_free(&r);
        g5c_json_free(d);
    }
}

/* ---- Xn: Path Switch Request ---------------------------------------------------------------------------------------------------------- */

static void path_switch_failure(amf *a, const amf_conn *c, const g5c_json *pdu, uint64_t amf_id, const char *group, const char *cause)
{
    const g5c_json *msg = ngap_pdu_message(pdu), *list = ngap_find_ie(msg, NGAP_IE_PDUSessionResourceToBeSwitchedDLList), *ran = ngap_find_ie(msg, NGAP_IE_RAN_UE_NGAP_ID);
    g5c_json *p = ng_pdu_new("unsuccessfulOutcome", NGAP_PROC_PathSwitchRequest, "reject"), *rel = g5c_json_new_arr();
    int64_t rid = 0;
    (void)g5c_json_int(ran, &rid);
    ng_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)amf_id));
    ng_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(rid));
    for (size_t i = 0; i < g5c_json_len(list); i++) {
        int64_t psi = 0;
        g5c_json *tree = unsuccessful_transfer(group, cause);
        (void)g5c_json_get_int(g5c_json_at(list, i), "pDUSessionID", &psi);
        g5c_json_push(rel, encoded_item((uint8_t)psi, "PathSwitchRequestUnsuccessfulTransfer", "pathSwitchRequestUnsuccessfulTransfer", tree));
        g5c_json_free(tree);
    }
    ng_ie(p, NGAP_IE_PDUSessionResourceReleasedListPSFail, "ignore", rel);
    (void)send_origin(a, c, p);
    amf_count(a, "g5c_amf_path_switch_total", "Path Switch Requests by result.", "result", "failed");
}

void ho_path_switch(amf_conn *c, const g5c_json *pdu)
{
    amf *a = c->a;
    amf_ue *u = c->ue;
    const g5c_json *msg = ngap_pdu_message(pdu), *list = ngap_find_ie(msg, NGAP_IE_PDUSessionResourceToBeSwitchedDLList),
                   *caps = ngap_find_ie(msg, NGAP_IE_UESecurityCapabilities), *ran = ngap_find_ie(msg, NGAP_IE_RAN_UE_NGAP_ID);
    int64_t rid = 0, gn = 0, gg = 0, st = 0;
    g5c_json *p, *switched = g5c_json_new_arr(), *released = g5c_json_new_arr();
    size_t ok = 0;
    bool caps_differ = false;
    (void)g5c_json_int(ran, &rid);
    gn = c->rx_gnb;
    gg = c->rx_gen;
    st = c->rx_stream;
    if (u == NULL || u->conn != c || u->mm != MM_REGISTERED || !u->sec.valid) {
        path_switch_failure(a, c, pdu, c->amf_id, "radioNetwork", "unknown-local-UE-NGAP-ID");
        g5c_json_free(switched);
        g5c_json_free(released);
        return;
    }
    if (caps != NULL) { /* TS 33.501 6.7.3.1: the capabilities the gNB reports must be those the UE gave us */
        {
            g5c_json *mine = ng_ue_sec_caps(u);
            const char *a1 = g5c_json_get_str(g5c_json_get(caps, "nRencryptionAlgorithms"), "hex"), *b1 = g5c_json_get_str(g5c_json_get(mine, "nRencryptionAlgorithms"), "hex");
            const char *a2 = g5c_json_get_str(g5c_json_get(caps, "nRintegrityProtectionAlgorithms"), "hex"),
                       *b2 = g5c_json_get_str(g5c_json_get(mine, "nRintegrityProtectionAlgorithms"), "hex");
            caps_differ = !g5c_streq(a1, b1) || !g5c_streq(a2, b2);
            g5c_json_free(mine);
        }
        if (caps_differ)
            G5C_LOGW(AMF_LOG, "the security capabilities of %s reported by the target gNB differ from the stored ones", u->supi);
    }
    for (size_t i = 0; i < g5c_json_len(list); i++) {
        const g5c_json *it = g5c_json_at(list, i);
        int64_t psi = 0;
        size_t n = 0;
        uint8_t *b = hex_bytes(g5c_json_get_str(it, "pathSwitchRequestTransfer"), &n);
        amf_smresp r;
        int http;
        g5c_json *d = g5c_json_new_obj();
        (void)g5c_json_get_int(it, "pDUSessionID", &psi);
        g5c_json_set_bool(d, "toBeSwitched", true);
        if (b == NULL || psi < 1 || psi > AMF_MAX_PSI) {
            free(b);
            g5c_json_free(d);
            continue;
        }
        http = amf_sm_update(a, u, (uint8_t)psi, d, NULL, 0, "PATH_SWITCH_REQ", b, n, &r);
        if (http == 200 && r.n2 != NULL) {
            g5c_json *e = g5c_json_new_obj();
            char *h = g5c_hex_encode(r.n2->data, r.n2->len);
            g5c_json_set_int(e, "pDUSessionID", psi);
            g5c_json_set_str(e, "pathSwitchRequestAcknowledgeTransfer", h);
            free(h);
            g5c_json_push(switched, e);
            u->pdu[psi].up_active = true;
            ok++;
        } else {
            g5c_json *tree = unsuccessful_transfer("radioNetwork", "unspecified");
            G5C_LOGW(AMF_LOG, "path switch of %s/%lld refused by the SMF (%d)", u->supi, (long long)psi, http);
            g5c_json_push(released, encoded_item((uint8_t)psi, "PathSwitchRequestUnsuccessfulTransfer", "pathSwitchRequestUnsuccessfulTransfer", tree));
            g5c_json_free(tree);
        }
        amf_smresp_free(&r);
        g5c_json_free(d);
        free(b);
    }
    if (ok == 0 && g5c_json_len(list) > 0) {
        g5c_json_free(switched);
        g5c_json_free(released);
        path_switch_failure(a, c, pdu, c->amf_id, "radioNetwork", "unspecified");
        return;
    }
    /* the association now runs between the AMF and the target gNB */
    pthread_mutex_lock(&a->tmu);
    if (a->gnbs[c->gnb].nconns > 0)
        a->gnbs[c->gnb].nconns--;
    c->gnb = (uint32_t)gn;
    c->gnb_gen = (uint32_t)gg;
    c->stream = (uint16_t)st;
    c->ran_id = (uint32_t)rid;
    a->gnbs[c->gnb].nconns++;
    pthread_mutex_unlock(&a->tmu);
    {
        amf_tai t;
        char cell[12];
        const g5c_json *uli = ngap_find_ie(msg, NGAP_IE_UserLocationInformation);
        if (uli != NULL && ng_uli_parse(uli, &t, cell) == 0) {
            c->tai = t;
            c->has_tai = true;
            snprintf(c->cell, sizeof c->cell, "%s", cell);
            c->has_cgi = true;
            u->loc = t;
            u->has_loc = true;
        }
    }
    sec_next_hop(&u->sec);
    p = ng_pdu_new("successfulOutcome", NGAP_PROC_PathSwitchRequest, "reject");
    ng_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)c->amf_id));
    ng_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)c->ran_id));
    if (caps_differ)
        ng_ie(p, NGAP_IE_UESecurityCapabilities, "reject", ng_ue_sec_caps(u));
    ng_ie(p, NGAP_IE_SecurityContext, "reject", security_context_json(&u->sec));
    ng_ie(p, NGAP_IE_PDUSessionResourceSwitchedList, "ignore", switched);
    if (g5c_json_len(released) > 0)
        ng_ie(p, NGAP_IE_PDUSessionResourceReleasedListPSAck, "ignore", released);
    else
        g5c_json_free(released);
    ng_ie(p, NGAP_IE_AllowedNSSAI, "reject", ng_allowed_nssai(u->allowed, u->nallowed));
    (void)amf_send_pdu(a, c->gnb, c->gnb_gen, c->stream, p);
    g5c_json_free(p);
    atomic_fetch_add(&a->st_pathswitch, 1);
    amf_count(a, "g5c_amf_path_switch_total", "Path Switch Requests by result.", "result", "completed");
    G5C_LOGI(AMF_LOG, "path switch of %s to gNB slot %u (NCC %u)", u->supi, c->gnb, u->sec.ncc & 7);
    gmm_event(a, u, EVT_LOCATION, NULL);
    amf_persist_request(a);
}

/* ---- N2 handover ------------------------------------------------------------------------------------------------------------------------ */

static void send_prep_failure(amf *a, amf_conn *sc, const char *group, const char *cause)
{
    g5c_json *p = ng_pdu_new("unsuccessfulOutcome", NGAP_PROC_HandoverPreparation, "reject");
    ng_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)sc->amf_id));
    ng_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)sc->ran_id));
    ng_ie(p, NGAP_IE_Cause, "ignore", ng_cause(group, cause));
    (void)send_to(a, sc, p);
    amf_count(a, "g5c_amf_handover_total", "N2 handovers by result.", "result", "preparation_failed");
}

static amf_conn *ho_target_of(amf_ue *u)
{
    return u->ho_conn;
}

/* find the gNB serving the target tracking area (and, when given, the node identifier) */
static int find_target_gnb(amf *a, const g5c_json *target_id, uint32_t *idx, uint32_t *gen)
{
    const g5c_json *tn = g5c_json_get(target_id, "targetRANNodeID"), *gid = g5c_json_get(g5c_json_get(tn, "globalRANNodeID"), "globalGNB-ID");
    amf_tai tai;
    int found = -1;
    uint32_t want_id = 0;
    int64_t bits = 0;
    bool have_id = false;
    if (tn == NULL || !ng_tai_from_json(g5c_json_get(tn, "selectedTAI"), &tai))
        return -1;
    {
        const g5c_json *gnb = g5c_json_get(g5c_json_get(gid, "gNB-ID"), "gNB-ID");
        const char *hx = g5c_json_get_str(gnb, "hex");
        uint8_t b[4] = {0};
        if (hx != NULL && g5c_json_get_int(gnb, "len", &bits) && bits >= 22 && bits <= 32) {
            long n = g5c_hex_decode(hx, b, 4);
            uint32_t v = 0;
            for (long k = 0; k < n; k++)
                v = (v << 8) | b[k];
            want_id = v >> (n * 8 - bits);
            have_id = true;
        }
    }
    pthread_mutex_lock(&a->tmu);
    for (uint32_t i = 0; i < AMF_MAX_GNB && found < 0; i++) {
        const amf_gnb *g = &a->gnbs[i];
        bool tai_ok = false;
        if (!g->used || !g->setup)
            continue;
        for (size_t t = 0; t < g->ntas; t++)
            tai_ok = tai_ok || amf_tai_eq(&g->tas[t], &tai);
        if (tai_ok && (!have_id || g->gnb_id == want_id)) {
            found = (int)i;
            *idx = i;
            *gen = g->gen;
        }
    }
    pthread_mutex_unlock(&a->tmu);
    return found;
}

void ho_required(amf_conn *c, amf_ue *u, const g5c_json *pdu)
{
    amf *a = c->a;
    const g5c_json *msg = ngap_pdu_message(pdu), *type = ngap_find_ie(msg, NGAP_IE_HandoverType), *cause = ngap_find_ie(msg, NGAP_IE_Cause),
                   *target = ngap_find_ie(msg, NGAP_IE_TargetID), *list = ngap_find_ie(msg, NGAP_IE_PDUSessionResourceListHORqd),
                   *cont = ngap_find_ie(msg, NGAP_IE_SourceToTarget_TransparentContainer);
    uint32_t tg, tgen;
    amf_conn *tc;
    g5c_json *p, *items = g5c_json_new_arr();
    if (u->conn != c || u->mm != MM_REGISTERED || !u->sec.valid || c->ho_state != HO_NONE) {
        send_prep_failure(a, c, "radioNetwork", "interaction-with-other-procedure");
        g5c_json_free(items);
        return;
    }
    if (type == NULL || g5c_json_str(type) == NULL || strcmp(g5c_json_str(type), "intra5gs") != 0) {
        send_prep_failure(a, c, "radioNetwork", "ho-target-not-allowed");
        g5c_json_free(items);
        return;
    }
    if (find_target_gnb(a, target, &tg, &tgen) < 0 || tg == c->gnb || cont == NULL) {
        send_prep_failure(a, c, "radioNetwork", "unknown-targetID");
        g5c_json_free(items);
        return;
    }
    for (size_t i = 0; i < g5c_json_len(list); i++) {
        const g5c_json *it = g5c_json_at(list, i);
        int64_t psi = 0;
        size_t n = 0;
        uint8_t *b = hex_bytes(g5c_json_get_str(it, "handoverRequiredTransfer"), &n);
        amf_smresp r;
        int http;
        g5c_json *d = g5c_json_new_obj();
        (void)g5c_json_get_int(it, "pDUSessionID", &psi);
        if (psi < 1 || psi > AMF_MAX_PSI || b == NULL) {
            free(b);
            g5c_json_free(d);
            continue;
        }
        g5c_json_set_str(d, "hoState", "PREPARING");
        g5c_json_set_str(d, "targetServingNfId", a->instance_id);
        http = amf_sm_update(a, u, (uint8_t)psi, d, NULL, 0, "HANDOVER_REQUIRED", b, n, &r);
        if (http == 200 && r.n2 != NULL) {
            g5c_json *e = g5c_json_new_obj();
            char *h = g5c_hex_encode(r.n2->data, r.n2->len);
            const nas_snssai *sn = u->pdu[psi].has_snssai ? &u->pdu[psi].snssai : (u->nallowed > 0 ? &u->allowed[0] : NULL);
            g5c_json_set_int(e, "pDUSessionID", psi);
            if (sn != NULL)
                g5c_json_set(e, "s-NSSAI", ng_snssai_json(sn));
            g5c_json_set_str(e, "handoverRequestTransfer", h);
            free(h);
            g5c_json_push(items, e);
        } else {
            G5C_LOGW(AMF_LOG, "the SMF refused the handover preparation of %s/%lld (%d)", u->supi, (long long)psi, http);
        }
        amf_smresp_free(&r);
        g5c_json_free(d);
        free(b);
    }
    if (g5c_json_len(items) == 0 && g5c_json_len(list) > 0) {
        send_prep_failure(a, c, "radioNetwork", "no-radio-resources-available-in-target-cell");
        g5c_json_free(items);
        return;
    }
    tc = amf_conn_new(a, tg, 0, 0);
    amf_conn_authenticated(tc);
    tc->gnb_gen = tgen;
    tc->is_target = true;
    attach_target(tc, u);
    c->ho_state = HO_PREPARING;
    c->ho_type = 1;
    c->ho_peer_id = tc->amf_id;
    tc->ho_peer_id = c->amf_id;
    sec_next_hop(&u->sec);

    p = ng_pdu_new("initiatingMessage", NGAP_PROC_HandoverResourceAllocation, "reject");
    ng_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "reject", g5c_json_new_int((int64_t)tc->amf_id));
    ng_ie(p, NGAP_IE_HandoverType, "reject", g5c_json_new_str("intra5gs"));
    ng_ie(p, NGAP_IE_Cause, "ignore", cause != NULL ? g5c_json_dup(cause) : ng_cause("radioNetwork", "unspecified"));
    {
        g5c_json *ambr = g5c_json_new_obj();
        g5c_json_set_int(ambr, "uEAggregateMaximumBitRateDL", (int64_t)(u->ambr_dl != 0 ? u->ambr_dl : 1000000000ULL));
        g5c_json_set_int(ambr, "uEAggregateMaximumBitRateUL", (int64_t)(u->ambr_ul != 0 ? u->ambr_ul : 1000000000ULL));
        ng_ie(p, NGAP_IE_UEAggregateMaximumBitRate, "reject", ambr);
    }
    ng_ie(p, NGAP_IE_UESecurityCapabilities, "reject", ng_ue_sec_caps(u));
    ng_ie(p, NGAP_IE_SecurityContext, "reject", security_context_json(&u->sec));
    ng_ie(p, NGAP_IE_PDUSessionResourceSetupListHOReq, "reject", items);
    ng_ie(p, NGAP_IE_AllowedNSSAI, "reject", ng_allowed_nssai(u->allowed, u->nallowed));
    ng_ie(p, NGAP_IE_SourceToTarget_TransparentContainer, "reject", g5c_json_dup(cont));
    ng_ie(p, NGAP_IE_GUAMI, "reject", ng_guami(a));
    (void)send_to(a, tc, p);
    {
        const char *hx = g5c_json_str(cont);
        if (hx != NULL) {
            free(c->ho_container);
            c->ho_container = hex_bytes(hx, &c->ho_container_len);
        }
    }
    conn_timer_start(c, CT_HOPREP, HO_PREP_SECS);
    G5C_LOGI(AMF_LOG, "handover of %s prepared towards gNB slot %u", u->supi, tg);
    amf_conn_unref(tc);
}

void ho_request_ack(amf_conn *tc, amf_ue *u, const g5c_json *pdu)
{
    amf *a = tc->a;
    amf_conn *sc = u->conn;
    const g5c_json *msg = ngap_pdu_message(pdu), *adm = ngap_find_ie(msg, NGAP_IE_PDUSessionResourceAdmittedList),
                   *cont = ngap_find_ie(msg, NGAP_IE_TargetToSource_TransparentContainer), *ran = ngap_find_ie(msg, NGAP_IE_RAN_UE_NGAP_ID);
    int64_t rid = 0, gn = 0, gg = 0, st = 0;
    g5c_json *p, *items = g5c_json_new_arr();
    if (u->ho_conn != tc || sc == NULL || sc->ho_state != HO_PREPARING) {
        G5C_LOGW(AMF_LOG, "unexpected Handover Request Acknowledge for %s", u->supi);
        return;
    }
    (void)g5c_json_int(ran, &rid);
    gn = tc->rx_gnb;
    gg = tc->rx_gen;
    st = tc->rx_stream;
    tc->ran_id = (uint32_t)rid;
    tc->stream = (uint16_t)st;
    (void)gn;
    (void)gg;
    for (size_t i = 0; i < g5c_json_len(adm); i++) {
        const g5c_json *it = g5c_json_at(adm, i);
        int64_t psi = 0;
        size_t n = 0;
        uint8_t *b = hex_bytes(g5c_json_get_str(it, "handoverRequestAcknowledgeTransfer"), &n);
        amf_smresp r;
        int http;
        g5c_json *d = g5c_json_new_obj();
        (void)g5c_json_get_int(it, "pDUSessionID", &psi);
        if (psi < 1 || psi > AMF_MAX_PSI || b == NULL) {
            free(b);
            g5c_json_free(d);
            continue;
        }
        g5c_json_set_str(d, "hoState", "PREPARED");
        http = amf_sm_update(a, u, (uint8_t)psi, d, NULL, 0, "HANDOVER_REQ_ACK", b, n, &r);
        if (http == 200 && r.n2 != NULL) {
            g5c_json *e = g5c_json_new_obj();
            char *h = g5c_hex_encode(r.n2->data, r.n2->len);
            g5c_json_set_int(e, "pDUSessionID", psi);
            g5c_json_set_str(e, "handoverCommandTransfer", h);
            free(h);
            g5c_json_push(items, e);
        } else {
            G5C_LOGW(AMF_LOG, "the SMF refused the handover acknowledgement of %s/%lld (%d)", u->supi, (long long)psi, http);
        }
        amf_smresp_free(&r);
        g5c_json_free(d);
        free(b);
    }
    conn_timer_stop(sc, CT_HOPREP);
    p = ng_pdu_new("successfulOutcome", NGAP_PROC_HandoverPreparation, "reject");
    ng_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)sc->amf_id));
    ng_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)sc->ran_id));
    ng_ie(p, NGAP_IE_HandoverType, "reject", g5c_json_new_str("intra5gs"));
    if (g5c_json_len(items) > 0)
        ng_ie(p, NGAP_IE_PDUSessionResourceHandoverList, "ignore", items);
    else
        g5c_json_free(items);
    ng_ie(p, NGAP_IE_TargetToSource_TransparentContainer, "reject", cont != NULL ? g5c_json_dup(cont) : g5c_json_new_str(""));
    (void)send_to(a, sc, p);
    sc->ho_state = HO_PREPARED;
    conn_timer_start(sc, CT_HOALL, HO_OVERALL_SECS);
}

void ho_request_failure(amf_conn *tc, amf_ue *u, const g5c_json *pdu)
{
    amf *a = tc->a;
    amf_conn *sc = u->conn;
    const g5c_json *cause = ngap_find_ie(ngap_pdu_message(pdu), NGAP_IE_Cause);
    G5C_LOGW(AMF_LOG, "the target gNB refused the handover of %s", u->supi);
    cancel_at_smf(a, u, "HO_FAILURE");
    if (sc != NULL && sc->ho_state != HO_NONE) {
        g5c_json *p = ng_pdu_new("unsuccessfulOutcome", NGAP_PROC_HandoverPreparation, "reject");
        ng_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)sc->amf_id));
        ng_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)sc->ran_id));
        ng_ie(p, NGAP_IE_Cause, "ignore", cause != NULL ? g5c_json_dup(cause) : ng_cause("radioNetwork", "ho-failure-in-target-5GC-ngran-node-or-target-system"));
        (void)send_to(a, sc, p);
        sc->ho_state = HO_NONE;
        conn_timer_stop(sc, CT_HOPREP);
        conn_timer_stop(sc, CT_HOALL);
        amf_count(a, "g5c_amf_handover_total", "N2 handovers by result.", "result", "target_refused");
    }
    detach_target(tc, u);
    amf_conn_unlink(tc);
}

void ho_notify(amf_conn *tc, amf_ue *u, const g5c_json *pdu)
{
    amf *a = tc->a;
    amf_conn *sc = u->conn;
    const g5c_json *msg = ngap_pdu_message(pdu), *uli = ngap_find_ie(msg, NGAP_IE_UserLocationInformation);
    if (u->ho_conn != tc || sc == NULL || sc->ho_state != HO_PREPARED) {
        G5C_LOGW(AMF_LOG, "unexpected Handover Notify for %s", u->supi);
        return;
    }
    conn_timer_stop(sc, CT_HOALL);
    for (uint8_t i = 1; i <= AMF_MAX_PSI; i++) {
        amf_smresp r;
        g5c_json *d;
        if (!u->pdu[i].used)
            continue;
        d = g5c_json_new_obj();
        g5c_json_set_str(d, "hoState", "COMPLETED");
        (void)amf_sm_update(a, u, i, d, NULL, 0, NULL, NULL, 0, &r);
        if (r.http == 200 || r.http == 204)
            u->pdu[i].up_active = true;
        amf_smresp_free(&r);
        g5c_json_free(d);
    }
    if (uli != NULL) {
        amf_tai t;
        char cell[12];
        if (ng_uli_parse(uli, &t, cell) == 0) {
            tc->tai = t;
            tc->has_tai = true;
            snprintf(tc->cell, sizeof tc->cell, "%s", cell);
            tc->has_cgi = true;
            u->loc = t;
            u->has_loc = true;
        }
    }
    /* the target leg becomes the UE's association; the source leg is released */
    pthread_mutex_lock(&a->tmu);
    u->conn = tc;
    u->ho_conn = NULL;
    sc->ue = NULL;
    tc->is_target = false;
    pthread_mutex_unlock(&a->tmu);
    tc->ics_done = true;
    tc->ics_sent = true;
    sc->ho_state = HO_NONE;
    amf_ue_unref(u); /* the source connection's reference (the target leg took its own in attach_target) */
    (void)conn_send_release_cmd(sc, "radioNetwork", "successful-handover", REL_KEEP);
    atomic_fetch_add(&a->st_handover, 1);
    amf_count(a, "g5c_amf_handover_total", "N2 handovers by result.", "result", "completed");
    G5C_LOGI(AMF_LOG, "handover of %s completed", u->supi);
    gmm_event(a, u, EVT_LOCATION, NULL);
    amf_persist_request(a);
}

void ho_cancel(amf_conn *sc, amf_ue *u, const g5c_json *pdu)
{
    amf *a = sc->a;
    amf_conn *tc = ho_target_of(u);
    const g5c_json *cause = ngap_find_ie(ngap_pdu_message(pdu), NGAP_IE_Cause);
    g5c_json *p;
    (void)cause;
    if (sc->ho_state == HO_NONE)
        return;
    conn_timer_stop(sc, CT_HOPREP);
    conn_timer_stop(sc, CT_HOALL);
    cancel_at_smf(a, u, "HO_CANCEL");
    if (tc != NULL) {
        if (tc->ran_id != 0)
            (void)conn_send_release_cmd(tc, "radioNetwork", "handover-cancelled", REL_KEEP);
        detach_target(tc, u);
        if (tc->ran_id == 0)
            amf_conn_unlink(tc);
    }
    sc->ho_state = HO_NONE;
    p = ng_pdu_new("successfulOutcome", NGAP_PROC_HandoverCancel, "reject");
    ng_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)sc->amf_id));
    ng_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)sc->ran_id));
    (void)send_to(a, sc, p);
    amf_count(a, "g5c_amf_handover_total", "N2 handovers by result.", "result", "cancelled");
}

void ho_abort(amf_conn *c, amf_ue *u, const char *cause)
{
    amf *a = c->a;
    amf_conn *tc, *sc;
    G5C_LOGW(AMF_LOG, "handover of %s aborted: %s", u->supi, cause);
    cancel_at_smf(a, u, "HO_FAILURE");
    tc = u->ho_conn;
    sc = u->conn;
    if (tc != NULL) {
        if (tc != c && tc->ran_id != 0 && !tc->closed)
            (void)conn_send_release_cmd(tc, "radioNetwork", "tngrelocoverall-expiry", REL_KEEP);
        detach_target(tc, u);
        if (tc != c && tc->ran_id == 0)
            amf_conn_unlink(tc);
    }
    if (sc != NULL && sc->ho_state != HO_NONE && sc != c) {
        if (sc->ho_state == HO_PREPARING)
            send_prep_failure(a, sc, "radioNetwork", "tngrelocoverall-expiry");
        sc->ho_state = HO_NONE;
        conn_timer_stop(sc, CT_HOPREP);
        conn_timer_stop(sc, CT_HOALL);
    }
    amf_count(a, "g5c_amf_handover_total", "N2 handovers by result.", "result", "aborted");
}

void ho_timer(amf *a, amf_conn *c, int kind)
{
    amf_ue *u = c->ue;
    (void)a;
    if (u == NULL || c->ho_state == HO_NONE)
        return;
    G5C_LOGW(AMF_LOG, "handover timer %s expired for %s", kind == CT_HOPREP ? "TNGRELOCprep" : "TNGRELOCoverall", u->supi);
    if (c->ho_state == HO_PREPARING)
        send_prep_failure(c->a, c, "radioNetwork", "tngrelocprep-expiry");
    ho_abort(c, u, "timer expired");
    c->ho_state = HO_NONE;
}

void ho_ran_status_transfer(amf_conn *sc, amf_ue *u, const g5c_json *pdu)
{
    amf *a = sc->a;
    amf_conn *tc = u->ho_conn;
    const g5c_json *cont = ngap_find_ie(ngap_pdu_message(pdu), NGAP_IE_RANStatusTransfer_TransparentContainer);
    g5c_json *p;
    if (tc == NULL || cont == NULL || sc->ho_state == HO_NONE)
        return;
    p = ng_pdu_new("initiatingMessage", NGAP_PROC_DownlinkRANStatusTransfer, "ignore");
    ng_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "reject", g5c_json_new_int((int64_t)tc->amf_id));
    ng_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "reject", g5c_json_new_int((int64_t)tc->ran_id));
    ng_ie(p, NGAP_IE_RANStatusTransfer_TransparentContainer, "reject", g5c_json_dup(cont));
    (void)send_to(a, tc, p);
}
