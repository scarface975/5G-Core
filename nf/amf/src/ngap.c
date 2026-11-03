/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* N2 application protocol (TS 38.413) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

/* ---- JSON builders ---- */

g5c_json *ng_pdu_new(const char *kind, int proc, const char *crit)
{
    g5c_json *root = g5c_json_new_obj(), *m = g5c_json_set(root, kind, g5c_json_new_obj()), *v;
    g5c_json_set_int(m, "procedureCode", proc);
    g5c_json_set_str(m, "criticality", crit);
    v = g5c_json_set(m, "value", g5c_json_new_obj());
    g5c_json_set(v, "protocolIEs", g5c_json_new_arr());
    return root;
}

g5c_json *ng_msg_ies(g5c_json *pdu)
{
    g5c_json *m = g5c_json_get_mut(pdu, g5c_json_key_at(pdu, 0)), *v = g5c_json_get_mut(m, "value");
    return g5c_json_get_mut(v, "protocolIEs");
}

g5c_json *ng_ie(g5c_json *pdu, int id, const char *crit, g5c_json *value)
{
    g5c_json *e = g5c_json_push(ng_msg_ies(pdu), g5c_json_new_obj());
    g5c_json_set_int(e, "id", id);
    g5c_json_set_str(e, "criticality", crit);
    g5c_json_set(e, "value", value);
    return e;
}

const g5c_json *ng_get(const g5c_json *pdu, int id)
{
    return ngap_find_ie(ngap_pdu_message(pdu), id);
}

g5c_json *ng_bits(const uint8_t *p, size_t nbits)
{
    g5c_json *o = g5c_json_new_obj();
    char *hex = g5c_hex_encode(p, (nbits + 7) / 8);
    g5c_json_set_int(o, "len", (int64_t)nbits);
    g5c_json_set_str(o, "hex", hex);
    free(hex);
    return o;
}

g5c_json *ng_plmn(const uint8_t plmn[3])
{
    char *h = g5c_hex_encode(plmn, 3);
    g5c_json *j = g5c_json_new_str(h);
    free(h);
    return j;
}

g5c_json *ng_tai_json(const amf_tai *t)
{
    g5c_json *o = g5c_json_new_obj();
    uint8_t tac[3] = {(uint8_t)(t->tac >> 16), (uint8_t)(t->tac >> 8), (uint8_t)t->tac};
    char *h = g5c_hex_encode(tac, 3);
    g5c_json_set(o, "pLMNIdentity", ng_plmn(t->plmn));
    g5c_json_set_str(o, "tAC", h);
    free(h);
    return o;
}

g5c_json *ng_guami(const amf *a)
{
    g5c_json *o = g5c_json_new_obj();
    uint8_t region = a->cfg.id.region;
    uint8_t set[2] = {(uint8_t)(a->cfg.id.set >> 2), (uint8_t)((a->cfg.id.set & 3) << 6)};
    uint8_t ptr = (uint8_t)(a->cfg.id.pointer << 2);
    g5c_json_set(o, "pLMNIdentity", ng_plmn(a->cfg.plmn));
    g5c_json_set(o, "aMFRegionID", ng_bits(&region, 8));
    g5c_json_set(o, "aMFSetID", ng_bits(set, 10));
    g5c_json_set(o, "aMFPointer", ng_bits(&ptr, 6));
    return o;
}

g5c_json *ng_snssai_json(const nas_snssai *s)
{
    g5c_json *o = g5c_json_new_obj();
    uint8_t sst = s->sst;
    char *h = g5c_hex_encode(&sst, 1);
    g5c_json_set_str(o, "sST", h);
    free(h);
    if (s->has_sd) {
        uint8_t sd[3] = {(uint8_t)(s->sd >> 16), (uint8_t)(s->sd >> 8), (uint8_t)s->sd};
        h = g5c_hex_encode(sd, 3);
        g5c_json_set_str(o, "sD", h);
        free(h);
    }
    return o;
}

g5c_json *ng_allowed_nssai(const nas_snssai *l, size_t n)
{
    g5c_json *arr = g5c_json_new_arr();
    for (size_t i = 0; i < n; i++)
        g5c_json_set(g5c_json_push(arr, g5c_json_new_obj()), "s-NSSAI", ng_snssai_json(&l[i]));
    return arr;
}

g5c_json *ng_cause(const char *group, const char *value)
{
    g5c_json *c = g5c_json_new_obj();
    g5c_json_set_str(c, group, value);
    return c;
}

bool ng_tai_from_json(const g5c_json *tai, amf_tai *out)
{
    const char *p = g5c_json_get_str(tai, "pLMNIdentity"), *t = g5c_json_get_str(tai, "tAC");
    uint8_t b[3];
    if (p == NULL || t == NULL || g5c_hex_decode(p, out->plmn, 3) != 3 || g5c_hex_decode(t, b, 3) != 3)
        return false;
    out->tac = (uint32_t)b[0] << 16 | (uint32_t)b[1] << 8 | b[2];
    return true;
}

bool ng_snssai_from_json(const g5c_json *s, nas_snssai *out)
{
    const char *sst = g5c_json_get_str(s, "sST"), *sd = g5c_json_get_str(s, "sD");
    uint8_t b[3];
    memset(out, 0, sizeof *out);
    if (sst == NULL || g5c_hex_decode(sst, b, 1) != 1)
        return false;
    out->sst = b[0];
    if (sd != NULL) {
        if (g5c_hex_decode(sd, b, 3) != 3)
            return false;
        out->has_sd = true;
        out->sd = (uint32_t)b[0] << 16 | (uint32_t)b[1] << 8 | b[2];
    }
    return true;
}

/* UserLocationInformation: NR (the one we serve), E-UTRA and N3IWF alternatives give a TAI as well. */
int ng_uli_parse(const g5c_json *uli, amf_tai *tai, char cell[12])
{
    const g5c_json *nr = g5c_json_get(uli, "userLocationInformationNR"), *eu = g5c_json_get(uli, "userLocationInformationEUTRA"), *src = nr != NULL ? nr : eu;
    const g5c_json *cg;
    if (src == NULL || !ng_tai_from_json(g5c_json_get(src, "tAI"), tai))
        return -1;
    cg = g5c_json_get(src, nr != NULL ? "nR-CGI" : "eUTRA-CGI");
    cell[0] = 0;
    if (cg != NULL) {
        const g5c_json *id = g5c_json_get(cg, nr != NULL ? "nRCellIdentity" : "eUTRACellIdentity");
        const char *hex = g5c_json_get_str(id, "hex");
        int64_t bits = 0;
        if (hex != NULL && g5c_json_get_int(id, "len", &bits) && bits > 0 && bits <= 44) {
            size_t digits = ((size_t)bits + 3) / 4;
            if (digits <= strlen(hex) && digits < 12) {
                memcpy(cell, hex, digits);
                cell[digits] = 0;
            }
        }
    }
    return 0;
}

static uint8_t *hex_to_bytes(const char *h, size_t *len)
{
    size_t n = h != NULL ? strlen(h) / 2 : 0;
    uint8_t *b;
    if (n == 0 || n > 65536)
        return NULL;
    b = g5c_xmalloc(n);
    if (g5c_hex_decode(h, b, n) != (long)n) {
        free(b);
        return NULL;
    }
    *len = n;
    return b;
}

/* ---- sending ---- */

static int conn_send(amf_conn *c, g5c_json *pdu)
{
    int rc = amf_send_pdu(c->a, c->gnb, c->gnb_gen, c->stream, pdu);
    g5c_json_free(pdu);
    return rc;
}

static void conn_ids(amf_conn *c, g5c_json *pdu, const char *crit)
{
    ng_ie(pdu, NGAP_IE_AMF_UE_NGAP_ID, crit, g5c_json_new_int((int64_t)c->amf_id));
    ng_ie(pdu, NGAP_IE_RAN_UE_NGAP_ID, crit, g5c_json_new_int((int64_t)c->ran_id));
}

int conn_send_nas(amf_conn *c, const uint8_t *nas, size_t len)
{
    g5c_json *p = ng_pdu_new("initiatingMessage", NGAP_PROC_DownlinkNASTransport, "ignore");
    char *h = g5c_hex_encode(nas, len);
    conn_ids(c, p, "reject");
    ng_ie(p, NGAP_IE_NAS_PDU, "reject", g5c_json_new_str(h));
    free(h);
    return conn_send(c, p);
}

g5c_json *ng_ue_sec_caps(const amf_ue *u)
{
    g5c_json *o = g5c_json_new_obj();
    uint8_t ea[2] = {0, 0}, ia[2] = {0, 0}, eea[2] = {0, 0}, eia[2] = {0, 0};
    if (u->ue_cap_len >= 1)
        ea[0] = (uint8_t)(u->ue_cap[0] << 1);
    if (u->ue_cap_len >= 2)
        ia[0] = (uint8_t)(u->ue_cap[1] << 1);
    if (u->ue_cap_len >= 3)
        eea[0] = (uint8_t)(u->ue_cap[2] << 1);
    if (u->ue_cap_len >= 4)
        eia[0] = (uint8_t)(u->ue_cap[3] << 1);
    g5c_json_set(o, "nRencryptionAlgorithms", ng_bits(ea, 16));
    g5c_json_set(o, "nRintegrityProtectionAlgorithms", ng_bits(ia, 16));
    g5c_json_set(o, "eUTRAencryptionAlgorithms", ng_bits(eea, 16));
    g5c_json_set(o, "eUTRAintegrityProtectionAlgorithms", ng_bits(eia, 16));
    return o;
}

static g5c_json *ue_ambr_json(const amf_ue *u)
{
    g5c_json *o = g5c_json_new_obj();
    g5c_json_set_int(o, "uEAggregateMaximumBitRateDL", (int64_t)u->ambr_dl);
    g5c_json_set_int(o, "uEAggregateMaximumBitRateUL", (int64_t)u->ambr_ul);
    return o;
}

/* IMEISV with the last four digits of the serial number replaced by 0xF (TS 38.413 9.3.1.55) */
static g5c_json *masked_imeisv(const char *pei)
{
    char d[17];
    uint8_t b[8];
    if (strncmp(pei, "imeisv-", 7) != 0 || strlen(pei + 7) != 16 || !g5c_is_digits(pei + 7))
        return NULL;
    memcpy(d, pei + 7, 16);
    d[16] = 0;
    for (int i = 10; i < 14; i++)
        d[i] = 'f';
    if (g5c_hex_decode(d, b, 8) != 8)
        return NULL;
    return ng_bits(b, 64);
}

int conn_send_ics(amf_conn *c, const uint8_t *nas, size_t len, amf_ue *u, g5c_json *pdu_list)
{
    g5c_json *p = ng_pdu_new("initiatingMessage", NGAP_PROC_InitialContextSetup, "reject"), *mi;
    amf *a = c->a;
    conn_ids(c, p, "reject");
    if (u->ambr_ul != 0 || u->ambr_dl != 0)
        ng_ie(p, NGAP_IE_UEAggregateMaximumBitRate, "reject", ue_ambr_json(u));
    ng_ie(p, NGAP_IE_GUAMI, "reject", ng_guami(a));
    if (pdu_list != NULL)
        ng_ie(p, NGAP_IE_PDUSessionResourceSetupListCxtReq, "reject", pdu_list);
    ng_ie(p, NGAP_IE_AllowedNSSAI, "reject", ng_allowed_nssai(u->allowed, u->nallowed));
    ng_ie(p, NGAP_IE_UESecurityCapabilities, "reject", ng_ue_sec_caps(u));
    ng_ie(p, NGAP_IE_SecurityKey, "reject", ng_bits(u->sec.kgnb, 256));
    mi = u->pei[0] != 0 ? masked_imeisv(u->pei) : NULL;
    if (mi != NULL)
        ng_ie(p, NGAP_IE_MaskedIMEISV, "ignore", mi);
    if (u->radio_cap != NULL && u->radio_cap_len > 0) {
        char *h = g5c_hex_encode(u->radio_cap, u->radio_cap_len);
        ng_ie(p, NGAP_IE_UERadioCapability, "ignore", g5c_json_new_str(h));
        free(h);
    }
    if (nas != NULL && len > 0) {
        char *h = g5c_hex_encode(nas, len);
        ng_ie(p, NGAP_IE_NAS_PDU, "ignore", g5c_json_new_str(h));
        free(h);
    }
    c->ics_sent = true;
    return conn_send(c, p);
}

int conn_send_release_cmd(amf_conn *c, const char *group, const char *cause, uint8_t then)
{
    g5c_json *p = ng_pdu_new("initiatingMessage", NGAP_PROC_UEContextRelease, "reject"), *ids, *pair;
    ids = g5c_json_new_obj();
    pair = g5c_json_set(ids, "uE-NGAP-ID-pair", g5c_json_new_obj());
    g5c_json_set_int(pair, "aMF-UE-NGAP-ID", (int64_t)c->amf_id);
    g5c_json_set_int(pair, "rAN-UE-NGAP-ID", (int64_t)c->ran_id);
    if (c->ran_id == 0) { /* the gNB has not told us its identifier yet (a handover target) */
        g5c_json_free(ids);
        ids = g5c_json_new_obj();
        g5c_json_set_int(ids, "aMF-UE-NGAP-ID", (int64_t)c->amf_id);
    }
    ng_ie(p, NGAP_IE_UE_NGAP_IDs, "reject", ids);
    ng_ie(p, NGAP_IE_Cause, "ignore", ng_cause(group, cause));
    c->rel_sent = true;
    c->rel_then = then;
    conn_timer_start(c, CT_RELCMD, 5);
    return conn_send(c, p);
}

int conn_send_pdu_setup(amf_conn *c, amf_ue *u, g5c_json *list, const uint8_t *nas, size_t nas_len)
{
    g5c_json *p = ng_pdu_new("initiatingMessage", NGAP_PROC_PDUSessionResourceSetup, "reject");
    conn_ids(c, p, "reject");
    if (nas != NULL && nas_len > 0) {
        char *h = g5c_hex_encode(nas, nas_len);
        ng_ie(p, NGAP_IE_NAS_PDU, "reject", g5c_json_new_str(h));
        free(h);
    }
    ng_ie(p, NGAP_IE_PDUSessionResourceSetupListSUReq, "reject", list);
    if (u != NULL && (u->ambr_ul != 0 || u->ambr_dl != 0))
        ng_ie(p, NGAP_IE_UEAggregateMaximumBitRate, "ignore", ue_ambr_json(u));
    return conn_send(c, p);
}

int conn_send_pdu_modify(amf_conn *c, g5c_json *list)
{
    g5c_json *p = ng_pdu_new("initiatingMessage", NGAP_PROC_PDUSessionResourceModify, "reject");
    conn_ids(c, p, "reject");
    ng_ie(p, NGAP_IE_PDUSessionResourceModifyListModReq, "reject", list);
    return conn_send(c, p);
}

int conn_send_pdu_release(amf_conn *c, g5c_json *list, const uint8_t *nas, size_t nas_len)
{
    g5c_json *p = ng_pdu_new("initiatingMessage", NGAP_PROC_PDUSessionResourceRelease, "reject");
    conn_ids(c, p, "reject");
    if (nas != NULL && nas_len > 0) {
        char *h = g5c_hex_encode(nas, nas_len);
        ng_ie(p, NGAP_IE_NAS_PDU, "ignore", g5c_json_new_str(h));
        free(h);
    }
    ng_ie(p, NGAP_IE_PDUSessionResourceToReleaseListRelCmd, "reject", list);
    return conn_send(c, p);
}

int ng_send_error_indication(amf *a, uint32_t gnb, uint32_t gen, uint16_t stream, bool have_ids, uint64_t amf_id, uint32_t ran_id, const char *group,
                             const char *cause)
{
    g5c_json *p = ng_pdu_new("initiatingMessage", NGAP_PROC_ErrorIndication, "ignore");
    int rc;
    if (have_ids) {
        ng_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)amf_id));
        ng_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)ran_id));
    }
    ng_ie(p, NGAP_IE_Cause, "ignore", ng_cause(group, cause));
    rc = amf_send_pdu(a, gnb, gen, stream, p);
    g5c_json_free(p);
    return rc;
}

/* ---- paging (TS 38.413 8.5, TS 23.502 4.2.3.3) ---- */

/* Page the UE in its registration area. The caller holds u->mu. */
void amf_page_ue(amf *a, amf_ue *u)
{
    uint32_t idx[AMF_MAX_GNB], gens[AMF_MAX_GNB];
    amf_tai tais[AMF_MAX_GNB][AMF_MAX_TAI];
    size_t ntais[AMF_MAX_GNB], n = 0;
    uint8_t set[2] = {(uint8_t)(a->cfg.id.set >> 2), (uint8_t)((a->cfg.id.set & 3) << 6)}, ptr = (uint8_t)(a->cfg.id.pointer << 2);
    uint8_t tm[4];
    amf_put_be32(tm, u->tmsi);
    pthread_mutex_lock(&a->tmu);
    for (uint32_t i = 0; i < AMF_MAX_GNB; i++) {
        amf_gnb *g = &a->gnbs[i];
        size_t k = 0;
        if (!g->used || !g->setup)
            continue;
        for (size_t t = 0; t < u->ntai; t++)
            for (size_t s = 0; s < g->ntas; s++)
                if (amf_tai_eq(&u->tai_list[t], &g->tas[s]) && k < AMF_MAX_TAI)
                    tais[n][k++] = u->tai_list[t];
        if (k > 0) {
            idx[n] = i;
            gens[n] = g->gen;
            ntais[n] = k;
            n++;
        }
    }
    pthread_mutex_unlock(&a->tmu);
    for (size_t i = 0; i < n; i++) {
        g5c_json *p = ng_pdu_new("initiatingMessage", NGAP_PROC_Paging, "ignore"), *id, *tm_o, *list = g5c_json_new_arr();
        id = g5c_json_new_obj();
        tm_o = g5c_json_set(id, "fiveG-S-TMSI", g5c_json_new_obj());
        g5c_json_set(tm_o, "aMFSetID", ng_bits(set, 10));
        g5c_json_set(tm_o, "aMFPointer", ng_bits(&ptr, 6));
        {
            char *h = g5c_hex_encode(tm, 4);
            g5c_json_set_str(tm_o, "fiveG-TMSI", h);
            free(h);
        }
        ng_ie(p, NGAP_IE_UEPagingIdentity, "ignore", id);
        for (size_t k = 0; k < ntais[i]; k++)
            g5c_json_set(g5c_json_push(list, g5c_json_new_obj()), "tAI", ng_tai_json(&tais[i][k]));
        ng_ie(p, NGAP_IE_TAIListForPaging, "ignore", list);
        if (u->has_edrx) { /* the NAS cycle index 0..13 and the window value 0..15 are the positions in the NGAP enumerations (5.12 s * 2^n steps; 1.28 s * (n + 1)) */
            static const char *const cycle[] = {"hfhalf", "hf1", "hf2", "hf4", "hf6", "hf8", "hf10", "hf12", "hf14", "hf16", "hf32", "hf64", "hf128", "hf256"};
            char win[8];
            g5c_json *e = g5c_json_new_obj();
            snprintf(win, sizeof win, "s%u", (u->edrx >> 4) + 1u);
            g5c_json_set_str(e, "paging-eDRX-Cycle", cycle[(u->edrx & 0x0f) < 14 ? (u->edrx & 0x0f) : 13]);
            g5c_json_set_str(e, "paging-Time-Window", win);
            ng_ie(p, NGAP_IE_PagingeDRXInformation, "ignore", e);
        }
        (void)amf_send_pdu(a, idx[i], gens[i], 0, p);
        g5c_json_free(p);
    }
    atomic_fetch_add(&a->st_paging, 1);
    amf_count(a, "g5c_amf_paging_total", "Paging messages sent (per attempt).", NULL, NULL);
    G5C_LOGI(AMF_LOG, "paging %s on %zu gNB(s)", u->supi, n);
}

/* ---- non-UE-associated procedures ---- */

static void send_setup_failure(amf *a, uint32_t gnb, uint32_t gen, uint16_t stream, const char *group, const char *cause)
{
    g5c_json *p = ng_pdu_new("unsuccessfulOutcome", NGAP_PROC_NGSetup, "reject");
    ng_ie(p, NGAP_IE_Cause, "ignore", ng_cause(group, cause));
    ng_ie(p, NGAP_IE_TimeToWait, "ignore", g5c_json_new_str("v5s"));
    (void)amf_send_pdu(a, gnb, gen, stream, p);
    g5c_json_free(p);
}

/* The supported TA list intersected with our tracking areas; false when no broadcast PLMN of any TA is ours. */
static bool parse_supported_tas(amf *a, const g5c_json *list, amf_tai *out, size_t *n, bool *plmn_seen)
{
    *n = 0;
    *plmn_seen = false;
    for (size_t i = 0; i < g5c_json_len(list); i++) {
        const g5c_json *it = g5c_json_at(list, i), *bl = g5c_json_get(it, "broadcastPLMNList");
        const char *tac = g5c_json_get_str(it, "tAC");
        uint8_t tb[3];
        uint32_t tv;
        if (tac == NULL || g5c_hex_decode(tac, tb, 3) != 3)
            continue;
        tv = (uint32_t)tb[0] << 16 | (uint32_t)tb[1] << 8 | tb[2];
        for (size_t k = 0; k < g5c_json_len(bl); k++) {
            const char *pl = g5c_json_get_str(g5c_json_at(bl, k), "pLMNIdentity");
            uint8_t p3[3];
            if (pl == NULL || g5c_hex_decode(pl, p3, 3) != 3 || memcmp(p3, a->cfg.plmn, 3) != 0)
                continue;
            *plmn_seen = true;
            for (size_t t = 0; t < a->cfg.ntai; t++)
                if (a->cfg.tai[t].tac == tv && *n < AMF_MAX_TAI) {
                    out[*n].tac = tv;
                    memcpy(out[*n].plmn, p3, 3);
                    (*n)++;
                    break;
                }
        }
    }
    return *n > 0;
}

static void handle_ng_setup(amf *a, uint32_t idx, uint32_t gen, uint16_t stream, const g5c_json *pdu)
{
    amf_gnb *g = &a->gnbs[idx];
    const g5c_json *rn = ng_get(pdu, NGAP_IE_GlobalRANNodeID), *name = ng_get(pdu, NGAP_IE_RANNodeName), *tal = ng_get(pdu, NGAP_IE_SupportedTAList);
    amf_tai tas[AMF_MAX_TAI];
    size_t ntas = 0;
    bool plmn_seen = false;
    g5c_json *p, *gl, *ps, *sl;
    if (rn == NULL || tal == NULL) {
        send_setup_failure(a, idx, gen, stream, "protocol", "semantic-error");
        return;
    }
    if (!parse_supported_tas(a, tal, tas, &ntas, &plmn_seen)) {
        G5C_LOGW(AMF_LOG, "NG Setup from %s refused: %s", g->peer, plmn_seen ? "no tracking area of ours is supported" : "PLMN not served");
        send_setup_failure(a, idx, gen, stream, "misc", plmn_seen ? "unspecified" : "unknown-PLMN-or-SNPN");
        amf_count(a, "g5c_amf_ng_setup_total", "NG Setup requests by result.", "result", "refused");
        return;
    }
    pthread_mutex_lock(&a->tmu);
    snprintf(g->name, sizeof g->name, "%s", name != NULL && g5c_json_str(name) != NULL ? g5c_json_str(name) : "");
    g->ntas = ntas;
    memcpy(g->tas, tas, ntas * sizeof tas[0]);
    g->setup = true;
    g->is_ng_enb = g5c_json_get(rn, "globalNgENB-ID") != NULL;
    {
        const g5c_json *gg = g5c_json_get(rn, "globalGNB-ID");
        const char *pl = g5c_json_get_str(gg, "pLMNIdentity"), *hx = g5c_json_get_str(g5c_json_get(g5c_json_get(gg, "gNB-ID"), "gNB-ID"), "hex");
        int64_t bits = 0;
        uint8_t b[4] = {0};
        if (pl != NULL)
            (void)g5c_hex_decode(pl, g->node_plmn, 3);
        if (hx != NULL && g5c_json_get_int(g5c_json_get(g5c_json_get(gg, "gNB-ID"), "gNB-ID"), "len", &bits) && bits >= 22 && bits <= 32) {
            long n = g5c_hex_decode(hx, b, 4);
            uint32_t v = 0;
            for (long k = 0; k < n; k++)
                v = (v << 8) | b[k];
            g->gnb_id = v >> (n * 8 - bits);
            g->gnb_id_bits = (uint8_t)bits;
        }
    }
    pthread_mutex_unlock(&a->tmu);

    p = ng_pdu_new("successfulOutcome", NGAP_PROC_NGSetup, "reject");
    ng_ie(p, NGAP_IE_AMFName, "reject", g5c_json_new_str(a->cfg.name));
    gl = g5c_json_new_arr();
    g5c_json_set(g5c_json_push(gl, g5c_json_new_obj()), "gUAMI", ng_guami(a));
    ng_ie(p, NGAP_IE_ServedGUAMIList, "reject", gl);
    ng_ie(p, NGAP_IE_RelativeAMFCapacity, "ignore", g5c_json_new_int(a->cfg.capacity));
    ps = g5c_json_new_arr();
    {
        g5c_json *it = g5c_json_push(ps, g5c_json_new_obj());
        g5c_json_set(it, "pLMNIdentity", ng_plmn(a->cfg.plmn));
        sl = g5c_json_set(it, "sliceSupportList", g5c_json_new_arr());
        for (size_t i = 0; i < a->cfg.nslices; i++)
            g5c_json_set(g5c_json_push(sl, g5c_json_new_obj()), "s-NSSAI", ng_snssai_json(&a->cfg.slices[i]));
    }
    ng_ie(p, NGAP_IE_PLMNSupportList, "reject", ps);
    (void)amf_send_pdu(a, idx, gen, stream, p);
    g5c_json_free(p);
    G5C_LOGI(AMF_LOG, "NG Setup from %s (%s): %zu supported TA(s)", g->peer, g->name[0] != 0 ? g->name : "unnamed", ntas);
    amf_count(a, "g5c_amf_ng_setup_total", "NG Setup requests by result.", "result", "accepted");
    amf_gauges(a);
}

static void handle_ran_config_update(amf *a, uint32_t idx, uint32_t gen, uint16_t stream, const g5c_json *pdu)
{
    amf_gnb *g = &a->gnbs[idx];
    const g5c_json *tal = ng_get(pdu, NGAP_IE_SupportedTAList), *name = ng_get(pdu, NGAP_IE_RANNodeName);
    g5c_json *p;
    if (tal != NULL) {
        amf_tai tas[AMF_MAX_TAI];
        size_t n = 0;
        bool seen = false;
        if (!parse_supported_tas(a, tal, tas, &n, &seen)) {
            p = ng_pdu_new("unsuccessfulOutcome", NGAP_PROC_RANConfigurationUpdate, "reject");
            ng_ie(p, NGAP_IE_Cause, "ignore", ng_cause("misc", seen ? "unspecified" : "unknown-PLMN-or-SNPN"));
            ng_ie(p, NGAP_IE_TimeToWait, "ignore", g5c_json_new_str("v5s"));
            (void)amf_send_pdu(a, idx, gen, stream, p);
            g5c_json_free(p);
            return;
        }
        pthread_mutex_lock(&a->tmu);
        g->ntas = n;
        memcpy(g->tas, tas, n * sizeof tas[0]);
        pthread_mutex_unlock(&a->tmu);
    }
    if (name != NULL && g5c_json_str(name) != NULL) {
        pthread_mutex_lock(&a->tmu);
        snprintf(g->name, sizeof g->name, "%s", g5c_json_str(name));
        pthread_mutex_unlock(&a->tmu);
    }
    p = ng_pdu_new("successfulOutcome", NGAP_PROC_RANConfigurationUpdate, "reject");
    (void)amf_send_pdu(a, idx, gen, stream, p);
    g5c_json_free(p);
    amf_count(a, "g5c_amf_ran_config_update_total", "RAN Configuration Update requests accepted.", NULL, NULL);
}

static void handle_ng_reset(amf *a, uint32_t idx, uint32_t gen, uint16_t stream, const g5c_json *pdu)
{
    const g5c_json *rt = ng_get(pdu, NGAP_IE_ResetType), *part = g5c_json_get(rt, "partOfNG-Interface");
    amf_conn *hit[256];
    size_t nhit = 0;
    g5c_json *p, *ack_list = NULL;
    pthread_mutex_lock(&a->tmu);
    for (amf_conn *c = a->conns; c != NULL && nhit < 256; c = c->next_all) {
        bool match = c->gnb == idx && c->gnb_gen == gen;
        if (match && part != NULL) {
            bool listed = false;
            for (size_t i = 0; i < g5c_json_len(part) && !listed; i++) {
                const g5c_json *it = g5c_json_at(part, i);
                int64_t am = -1, rn = -1;
                (void)g5c_json_get_int(it, "aMF-UE-NGAP-ID", &am);
                (void)g5c_json_get_int(it, "rAN-UE-NGAP-ID", &rn);
                if ((am >= 0 && (uint64_t)am == c->amf_id) || (rn >= 0 && (uint32_t)rn == c->ran_id && am < 0))
                    listed = true;
            }
            match = listed;
        }
        if (match) {
            c->refs++;
            hit[nhit++] = c;
        }
    }
    pthread_mutex_unlock(&a->tmu);
    for (size_t i = 0; i < nhit; i++) {
        amf_conn_post(hit[i], EV_LOST, NULL);
        amf_conn_unref(hit[i]);
    }
    p = ng_pdu_new("successfulOutcome", NGAP_PROC_NGReset, "reject");
    if (part != NULL) {
        ack_list = g5c_json_dup(part);
        ng_ie(p, NGAP_IE_UE_associatedLogicalNG_connectionList, "ignore", ack_list);
    }
    (void)amf_send_pdu(a, idx, gen, stream, p);
    g5c_json_free(p);
    G5C_LOGI(AMF_LOG, "NG Reset from %s: %zu UE association(s) released", a->gnbs[idx].peer, nhit);
}

void ngap_gnb_lost(amf *a, uint32_t gnb)
{
    amf_conn *hit[512];
    size_t n = 0;
    pthread_mutex_lock(&a->tmu);
    for (amf_conn *c = a->conns; c != NULL; c = c->next_all)
        if (c->gnb == gnb && n < 512) {
            c->refs++;
            hit[n++] = c;
        }
    pthread_mutex_unlock(&a->tmu);
    for (size_t i = 0; i < n; i++) {
        amf_conn_post(hit[i], EV_LOST, NULL);
        amf_conn_unref(hit[i]);
    }
    amf_gauges(a);
}

/* ---- routing ---- */

static void route_ue_message(amf *a, uint32_t gnb, uint32_t gen, uint16_t stream, g5c_json *pdu, int64_t code, bool is_initial)
{
    const g5c_json *amf_ie = ng_get(pdu, NGAP_IE_AMF_UE_NGAP_ID), *ran_ie = ng_get(pdu, NGAP_IE_RAN_UE_NGAP_ID), *src_ie = ng_get(pdu, NGAP_IE_SourceAMF_UE_NGAP_ID);
    int64_t amf_id = -1, ran_id = -1;
    amf_conn *c;
    if (code == NGAP_PROC_PathSwitchRequest && src_ie != NULL)
        (void)g5c_json_int(src_ie, &amf_id);
    else
        (void)g5c_json_int(amf_ie, &amf_id);
    (void)g5c_json_int(ran_ie, &ran_id);
    (void)is_initial;
    if (amf_id < 0) {
        G5C_LOGW(AMF_LOG, "UE-associated message %lld without an AMF-UE-NGAP-ID: dropped", (long long)code);
        g5c_json_free(pdu);
        return;
    }
    c = amf_conn_find(a, (uint64_t)amf_id);
    if (c == NULL) {
        (void)ng_send_error_indication(a, gnb, gen, stream, true, (uint64_t)amf_id, ran_id >= 0 ? (uint32_t)ran_id : 0, "radioNetwork", "unknown-local-UE-NGAP-ID");
        amf_count(a, "g5c_amf_ngap_errors_total", "NGAP messages rejected, by reason.", "reason", "unknown-local-ue-id");
        g5c_json_free(pdu);
        return;
    }
    if (code != NGAP_PROC_PathSwitchRequest && (c->gnb != gnb || c->gnb_gen != gen)) {
        (void)ng_send_error_indication(a, gnb, gen, stream, true, (uint64_t)amf_id, ran_id >= 0 ? (uint32_t)ran_id : 0, "radioNetwork", "unknown-local-UE-NGAP-ID");
        amf_count(a, "g5c_amf_ngap_errors_total", "NGAP messages rejected, by reason.", "reason", "wrong-gnb");
        amf_conn_unref(c);
        g5c_json_free(pdu);
        return;
    }
    if (code != NGAP_PROC_PathSwitchRequest && ran_id >= 0 && c->ran_id != 0 && (uint32_t)ran_id != c->ran_id) {
        (void)ng_send_error_indication(a, gnb, gen, stream, true, (uint64_t)amf_id, (uint32_t)ran_id, "radioNetwork", "inconsistent-remote-UE-NGAP-ID");
        amf_count(a, "g5c_amf_ngap_errors_total", "NGAP messages rejected, by reason.", "reason", "inconsistent-ran-id");
        amf_conn_unref(c);
        g5c_json_free(pdu);
        return;
    }

    amf_conn_post_rx(c, pdu, gnb, gen, stream);
    amf_conn_unref(c);
}

void ngap_reader_dispatch(amf *a, uint32_t gnb, uint32_t gen, uint16_t stream, const uint8_t *buf, size_t len)
{
    char err[200];
    g5c_json *pdu = ngap_decode(buf, len, err, sizeof err);
    int64_t code = -1;
    const char *kind;
    bool init, succ, setup;
    if (pdu == NULL) {
        G5C_LOGW(AMF_LOG, "undecodable NGAP PDU from %s: %s", a->gnbs[gnb].peer, err);
        (void)ng_send_error_indication(a, gnb, gen, stream, false, 0, 0, "protocol", "transfer-syntax-error");
        amf_count(a, "g5c_amf_ngap_errors_total", "NGAP messages rejected, by reason.", "reason", "decode");
        return;
    }
    kind = ngap_pdu_kind(pdu);
    (void)ngap_procedure_code(pdu, &code);
    init = kind != NULL && strcmp(kind, "initiatingMessage") == 0;
    succ = kind != NULL && strcmp(kind, "successfulOutcome") == 0;
    pthread_mutex_lock(&a->tmu);
    setup = a->gnbs[gnb].setup;
    pthread_mutex_unlock(&a->tmu);
    amf_count(a, "g5c_amf_ngap_rx_total", "NGAP messages received, by procedure code.", "code", ngap_procedure_name(pdu) != NULL ? ngap_procedure_name(pdu) : "unknown");

    if (init && code == NGAP_PROC_NGSetup) {
        handle_ng_setup(a, gnb, gen, stream, pdu);
        g5c_json_free(pdu);
        return;
    }
    if (!setup) {
        G5C_LOGW(AMF_LOG, "message %lld from %s before NG Setup: error indication", (long long)code, a->gnbs[gnb].peer);
        (void)ng_send_error_indication(a, gnb, gen, stream, false, 0, 0, "protocol", "message-not-compatible-with-receiver-state");
        g5c_json_free(pdu);
        return;
    }
    if (init) {
        switch (code) {
        case NGAP_PROC_RANConfigurationUpdate:
            handle_ran_config_update(a, gnb, gen, stream, pdu);
            break;
        case NGAP_PROC_NGReset:
            handle_ng_reset(a, gnb, gen, stream, pdu);
            break;
        case NGAP_PROC_InitialUEMessage: {
            const g5c_json *ran = ng_get(pdu, NGAP_IE_RAN_UE_NGAP_ID);
            int64_t rid = -1;
            amf_conn *c;
            size_t nc;
            pthread_mutex_lock(&a->tmu);
            nc = a->npreauth;
            pthread_mutex_unlock(&a->tmu);
            if (!g5c_json_int(ran, &rid) || rid < 0 || rid > 0xffffffffLL || ng_get(pdu, NGAP_IE_NAS_PDU) == NULL) {
                (void)ng_send_error_indication(a, gnb, gen, stream, false, 0, 0, "protocol", "semantic-error");
                break;
            }
            if (nc >= a->cfg.unauth_ue_max) {
                (void)ng_send_error_indication(a, gnb, gen, stream, false, 0, 0, "misc", "control-processing-overload");
                amf_count(a, "g5c_amf_ngap_errors_total", "NGAP messages rejected, by reason.", "reason", "overload");
                break;
            }
            c = amf_conn_new(a, gnb, stream, (uint32_t)rid);

            amf_conn_post_rx(c, pdu, gnb, gen, stream);
            amf_conn_unref(c);
            return; /* ownership of pdu passed on */
        }
        case NGAP_PROC_ErrorIndication: {
            const g5c_json *cause = ng_get(pdu, NGAP_IE_Cause);
            char *s = cause != NULL ? g5c_json_to_string(cause, NULL) : NULL;
            G5C_LOGW(AMF_LOG, "error indication from %s: %s", a->gnbs[gnb].peer, s != NULL ? s : "(no cause)");
            free(s);
            break;
        }
        case NGAP_PROC_UplinkNonUEAssociatedNRPPaTransport:
        case NGAP_PROC_UplinkRANConfigurationTransfer:
        case NGAP_PROC_TraceFailureIndication:
        case NGAP_PROC_CellTrafficTrace:
            break; /* accepted and ignored */
        case NGAP_PROC_UplinkNASTransport:
        case NGAP_PROC_UEContextReleaseRequest:
        case NGAP_PROC_PDUSessionResourceNotify:
        case NGAP_PROC_PathSwitchRequest:
        case NGAP_PROC_HandoverPreparation:
        case NGAP_PROC_HandoverNotification:
        case NGAP_PROC_HandoverCancel:
        case NGAP_PROC_UplinkRANStatusTransfer:
        case NGAP_PROC_UERadioCapabilityInfoIndication:
        case NGAP_PROC_LocationReport:
        case NGAP_PROC_NASNonDeliveryIndication:
        case NGAP_PROC_RRCInactiveTransitionReport:
        case NGAP_PROC_PDUSessionResourceModifyIndication:
            route_ue_message(a, gnb, gen, stream, pdu, code, false);
            return;
        default:
            G5C_LOGW(AMF_LOG, "unsupported NGAP procedure %lld from %s", (long long)code, a->gnbs[gnb].peer);
            (void)ng_send_error_indication(a, gnb, gen, stream, false, 0, 0, "protocol", "abstract-syntax-error-reject");
            break;
        }
        g5c_json_free(pdu);
        return;
    }
    /* responses to our requests (and failures) are routed by the UE identifiers */
    switch (code) {
    case NGAP_PROC_InitialContextSetup:
    case NGAP_PROC_UEContextRelease:
    case NGAP_PROC_UEContextModification:
    case NGAP_PROC_PDUSessionResourceSetup:
    case NGAP_PROC_PDUSessionResourceModify:
    case NGAP_PROC_PDUSessionResourceRelease:
    case NGAP_PROC_HandoverResourceAllocation:
    case NGAP_PROC_NGReset:
        if (code == NGAP_PROC_NGReset) {
            g5c_json_free(pdu);
            return;
        }
        route_ue_message(a, gnb, gen, stream, pdu, code, false);
        return;
    default:
        (void)succ;
        G5C_LOGD(AMF_LOG, "outcome of procedure %lld from %s ignored", (long long)code, a->gnbs[gnb].peer);
        break;
    }
    g5c_json_free(pdu);
}

/* ---- per-connection handling (runs on a pool worker) ---- */

static void note_location(amf_conn *c, const g5c_json *msg)
{
    const g5c_json *uli = ngap_find_ie(msg, NGAP_IE_UserLocationInformation);
    amf_tai t;
    char cell[12];
    if (uli != NULL && ng_uli_parse(uli, &t, cell) == 0) {
        c->tai = t;
        c->has_tai = true;
        snprintf(c->cell, sizeof c->cell, "%s", cell);
        c->has_cgi = true;
    }
}

void ngap_conn_event(amf_conn *c, g5c_json *pdu)
{
    amf *a = c->a;
    int64_t code = -1;
    const char *kind = ngap_pdu_kind(pdu);
    bool init = kind != NULL && strcmp(kind, "initiatingMessage") == 0, succ = kind != NULL && strcmp(kind, "successfulOutcome") == 0,
         unsucc = kind != NULL && strcmp(kind, "unsuccessfulOutcome") == 0;
    amf_ue *u;

    (void)ngap_procedure_code(pdu, &code);
    if (c->closed)
        return;
    u = conn_ue_ref(c);
    if (u != NULL) {
        pthread_mutex_lock(&u->mu);
        if (c->ue != u) { /* detached while we waited */
            pthread_mutex_unlock(&u->mu);
            amf_ue_unref(u);
            u = NULL;
        } else {
            c->held = u;
        }
    }
    c->stream = c->rx_stream;
    note_location(c, ngap_pdu_message(pdu));

    if (init && code == NGAP_PROC_InitialUEMessage) {
        const char *hex = g5c_json_str(ng_get(pdu, NGAP_IE_NAS_PDU));
        size_t nl = 0;
        uint8_t *nas = hex_to_bytes(hex, &nl);
        const g5c_json *ctxreq = ng_get(pdu, NGAP_IE_UEContextRequest);
        c->ue_ctx_requested = ctxreq != NULL;
        if (nas != NULL) {
            c->trace[0] = 0;
            g5c_trace_enter(c->trace); /* one trace for everything this connection does */
            gmm_initial_ue(c, nas, nl, ngap_pdu_message(pdu));
            g5c_trace_leave();
        } else
            conn_send_release_cmd(c, "protocol", "semantic-error", REL_DELETE_UE);
        free(nas);
    } else if (init && code == NGAP_PROC_UplinkNASTransport) {
        const char *hex = g5c_json_str(ng_get(pdu, NGAP_IE_NAS_PDU));
        size_t nl = 0;
        uint8_t *nas = hex_to_bytes(hex, &nl);
        if (nas != NULL) {
            g5c_trace_enter(c->trace);
            gmm_uplink_nas(c, nas, nl);
            g5c_trace_leave();
        }
        free(nas);
    } else if (succ && code == NGAP_PROC_InitialContextSetup) {
        if (u != NULL)
            amf_handle_ics_response(c, u, ngap_pdu_message(pdu));
    } else if (unsucc && code == NGAP_PROC_InitialContextSetup) {
        const g5c_json *cause = ng_get(pdu, NGAP_IE_Cause);
        char *s = cause != NULL ? g5c_json_to_string(cause, NULL) : NULL;
        G5C_LOGW(AMF_LOG, "Initial Context Setup failed for %s: %s", u != NULL ? u->supi : "(unidentified)", s != NULL ? s : "?");
        free(s);
        amf_count(a, "g5c_amf_ics_failures_total", "Initial Context Setup failures.", NULL, NULL);
        if (u != NULL)
            amf_handle_ics_response(c, u, NULL); /* NULL: the setup failed */
        gmm_release_request(c, "radioNetwork", "failure-in-radio-interface-procedure");
    } else if (init && code == NGAP_PROC_UEContextReleaseRequest) {
        const g5c_json *cause = ng_get(pdu, NGAP_IE_Cause);
        const char *grp = "radioNetwork", *val = "unspecified";
        if (g5c_json_is(cause, G5C_J_OBJECT) && g5c_json_len(cause) == 1) {
            grp = g5c_json_key_at(cause, 0);
            if (g5c_json_str(g5c_json_val_at(cause, 0)) != NULL)
                val = g5c_json_str(g5c_json_val_at(cause, 0));
        }
        gmm_release_request(c, grp, val);
    } else if (succ && code == NGAP_PROC_UEContextRelease) {
        gmm_conn_released(c);
    } else if (succ && code == NGAP_PROC_PDUSessionResourceSetup) {
        if (u != NULL)
            amf_handle_pdu_setup_response(c, u, ngap_pdu_message(pdu), false);
    } else if (succ && code == NGAP_PROC_PDUSessionResourceModify) {
        if (u != NULL)
            amf_handle_pdu_modify_response(c, u, ngap_pdu_message(pdu));
    } else if (succ && code == NGAP_PROC_PDUSessionResourceRelease) {
        if (u != NULL)
            amf_handle_pdu_release_response(c, u, ngap_pdu_message(pdu));
    } else if (init && code == NGAP_PROC_PDUSessionResourceNotify) {
        if (u != NULL)
            amf_handle_pdu_notify(c, u, ngap_pdu_message(pdu));
    } else if ((succ || unsucc) && code == NGAP_PROC_UEContextModification) {
        G5C_LOGD(AMF_LOG, "UE context modification %s", succ ? "response" : "failure");
    } else if (init && code == NGAP_PROC_PathSwitchRequest) {
        ho_path_switch(c, pdu);
    } else if (init && code == NGAP_PROC_HandoverPreparation) {
        if (u != NULL)
            ho_required(c, u, pdu);
    } else if (succ && code == NGAP_PROC_HandoverResourceAllocation) {
        if (u != NULL)
            ho_request_ack(c, u, pdu);
    } else if (unsucc && code == NGAP_PROC_HandoverResourceAllocation) {
        if (u != NULL)
            ho_request_failure(c, u, pdu);
    } else if (init && code == NGAP_PROC_HandoverNotification) {
        if (u != NULL)
            ho_notify(c, u, pdu);
    } else if (init && code == NGAP_PROC_HandoverCancel) {
        if (u != NULL)
            ho_cancel(c, u, pdu);
    } else if (init && code == NGAP_PROC_UplinkRANStatusTransfer) {
        if (u != NULL)
            ho_ran_status_transfer(c, u, pdu);
    } else if (init && code == NGAP_PROC_UERadioCapabilityInfoIndication) {
        const char *hex = g5c_json_str(ng_get(pdu, NGAP_IE_UERadioCapability));
        size_t nl = 0;
        uint8_t *cap = hex_to_bytes(hex, &nl);
        if (cap != NULL && u != NULL && nl <= 16384) {
            free(u->radio_cap);
            u->radio_cap = cap;
            u->radio_cap_len = nl;
            cap = NULL;
        }
        free(cap);
    } else if (init && code == NGAP_PROC_LocationReport) {
        if (u != NULL && c->has_tai && (!u->has_loc || !amf_tai_eq(&u->loc, &c->tai))) {
            u->loc = c->tai;
            u->has_loc = true;
            gmm_event(a, u, EVT_LOCATION, NULL);
        }
    } else if (init && code == NGAP_PROC_NASNonDeliveryIndication) {
        G5C_LOGW(AMF_LOG, "the gNB could not deliver a NAS message to %s", u != NULL ? u->supi : "(unidentified)");
        amf_count(a, "g5c_amf_nas_non_delivery_total", "NAS messages the gNB could not deliver.", NULL, NULL);
    } else {
        G5C_LOGD(AMF_LOG, "NGAP message %lld ignored", (long long)code);
    }
    if (c->held != NULL) {
        pthread_mutex_unlock(&c->held->mu);
        c->held = NULL;
    }
    if (u != NULL)
        amf_ue_unref(u);
}

/* the SCTP association went away or the gNB reset the interface: the UE is gone from the RAN, its context is kept (CM-IDLE) */
void ngap_conn_lost(amf_conn *c)
{
    amf_ue *u = conn_ue_ref(c);
    if (u != NULL) {
        pthread_mutex_lock(&u->mu);
        if (c->ue == u)
            c->held = u;
        else
            pthread_mutex_unlock(&u->mu);
    }
    gmm_conn_gone(c);
    if (c->held != NULL) {
        pthread_mutex_unlock(&c->held->mu);
        c->held = NULL;
    }
    if (u != NULL)
        amf_ue_unref(u);
}

/* a connection timer that expired: handled in order with the connection's messages, under its UE's mutex */
void ngap_conn_timer(amf_conn *c, int kind, uint32_t gen)
{
    amf_ue *u = conn_ue_ref(c);
    if (c->closed) {
        if (u != NULL)
            amf_ue_unref(u);
        return;
    }
    if (u != NULL) {
        pthread_mutex_lock(&u->mu);
        if (c->ue == u)
            c->held = u;
        else
            pthread_mutex_unlock(&u->mu);
    }
    gmm_conn_timer(c, kind, gen);
    if (c->held != NULL) {
        pthread_mutex_unlock(&c->held->mu);
        c->held = NULL;
    }
    if (u != NULL)
        amf_ue_unref(u);
}
