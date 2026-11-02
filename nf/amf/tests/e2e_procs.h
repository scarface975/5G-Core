/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The scripted UE and gNB procedures shared by the AMF end-to-end test and the load driver */
#ifndef G5C_AMF_E2E_PROCS_H
#define G5C_AMF_E2E_PROCS_H
#include "e2e_env.h"
#pragma GCC diagnostic ignored "-Wunused-function"

/* ---- UE procedures ---- */

typedef struct {
    uint8_t rand[16], autn[16], abba[2], ngksi;
} auth_req_t;

static void nas_free(nas_msg *m)
{
    nas_msg_free(m);
}

static bool parse_auth_request(const g5c_bytes *plain, auth_req_t *a)
{
    nas_msg m;
    size_t n;
    const uint8_t *v;
    if (nas_msg_decode(plain->data, plain->len, &m) != NAS_OK)
        return false;
    if (m.def->msg_type != 0x56) {
        nas_free(&m);
        return false;
    }
    v = nas_msg_get(&m, "ngKSI", &n);
    TK_ASSERT(v != NULL && n == 1);
    a->ngksi = v[0] & 7;
    v = nas_msg_get(&m, "ABBA", &n);
    TK_ASSERT(v != NULL && n == 2);
    memcpy(a->abba, v, 2);
    v = nas_msg_get(&m, "Authentication parameter RAND (5G authentication challenge)", &n);
    TK_ASSERT(v != NULL && n == 16);
    memcpy(a->rand, v, 16);
    v = nas_msg_get(&m, "Authentication parameter AUTN (5G authentication challenge)", &n);
    TK_ASSERT(v != NULL && n == 16);
    memcpy(a->autn, v, 16);
    nas_free(&m);
    return true;
}

enum { AUTH_OK = 0, AUTH_WRONG_RES, AUTH_MAC_FAIL, AUTH_SYNC_FAIL };

/* answer an authentication request (TS 33.501 6.1.3.2, Annex A.2 - A.7) */
static void ue_answer_auth(gnb_t *g, ue_t *u, const auth_req_t *a, uint32_t tac, int mode)
{
    g5c_milenage mil;
    g5c_milenage_vector vec;
    uint8_t sqn[6], mac_a[8], mac_s[8], res_star[16], kausf[32], kseaf[32];
    nas_msg m;
    g5c_bytes out;
    char digits[24];
    g5c_milenage_init(&mil, u->k, u->opc);
    TK_ASSERT(g5c_milenage_f2345(&mil, a->rand, &vec) == 0);
    for (int i = 0; i < 6; i++)
        sqn[i] = (uint8_t)(a->autn[i] ^ vec.ak[i]);
    TK_ASSERT(g5c_milenage_f1(&mil, a->rand, sqn, a->autn + 6, mac_a, mac_s) == 0);
    TK_ASSERT(memcmp(mac_a, a->autn + 8, 8) == 0); /* the network is authentic */
    g5c_bytes_init(&out);
    if (mode == AUTH_MAC_FAIL || mode == AUTH_SYNC_FAIL) {
        uint8_t cause = mode == AUTH_MAC_FAIL ? 20 : 21, auts[14], sqn_ms[6] = {0, 0, 0, 0, 0, 5}, amf0[2] = {0, 0}, ma[8], ms[8];
        TK_ASSERT(nas_msg_init(&m, "Authentication failure"));
        nas_msg_set(&m, "5GMM cause", &cause, 1);
        if (mode == AUTH_SYNC_FAIL) {
            TK_ASSERT(g5c_milenage_f1(&mil, a->rand, sqn_ms, amf0, ma, ms) == 0);
            for (int i = 0; i < 6; i++)
                auts[i] = (uint8_t)(sqn_ms[i] ^ vec.ak_star[i]);
            memcpy(auts + 6, ms, 8);
            nas_msg_set(&m, "Authentication failure parameter", auts, 14);
        }
        TK_ASSERT(nas_msg_encode(&m, &out) == NAS_OK);
        nas_free(&m);
        gnb_uplink_nas(g, u, out.data, out.len, tac);
        g5c_bytes_free(&out);
        return;
    }
    TK_ASSERT(g5c_res_star(vec.ck, vec.ik, E.snn, a->rand, vec.res, 8, res_star) == 0);
    TK_ASSERT(g5c_kausf(vec.ck, vec.ik, E.snn, a->autn, kausf) == 0);
    TK_ASSERT(g5c_kseaf(kausf, E.snn, kseaf) == 0);
    snprintf(digits, sizeof digits, "%s", u->supi + 5);
    TK_ASSERT(g5c_kamf(kseaf, digits, a->abba, u->kamf) == 0);
    memcpy(u->abba, a->abba, 2);
    u->ngksi = a->ngksi;
    if (mode == AUTH_WRONG_RES)
        res_star[0] ^= 0xff;
    TK_ASSERT(nas_msg_init(&m, "Authentication response"));
    nas_msg_set(&m, "Authentication response parameter", res_star, 16);
    TK_ASSERT(nas_msg_encode(&m, &out) == NAS_OK);
    nas_free(&m);
    gnb_uplink_nas(g, u, out.data, out.len, tac);
    g5c_bytes_free(&out);
}

/* ---- EAP-AKA' (TS 24.501 5.4.1.2.2): the UE side, an independent peer written from RFC 5448 / RFC 4187 and TS 33.501 Annex F ---- */

typedef struct {
    uint8_t abba[2], ngksi;
    uint8_t eap[1100];
    size_t eap_len;
} eap_req_t;

static bool parse_eap_auth_request(const g5c_bytes *plain, eap_req_t *r)
{
    nas_msg m;
    size_t n;
    const uint8_t *v;
    if (nas_msg_decode(plain->data, plain->len, &m) != NAS_OK)
        return false;
    if (m.def->msg_type != 0x56) {
        nas_free(&m);
        return false;
    }
    v = nas_msg_get(&m, "ngKSI", &n);
    TK_ASSERT(v != NULL && n == 1);
    r->ngksi = v[0] & 7;
    v = nas_msg_get(&m, "ABBA", &n);
    TK_ASSERT(v != NULL && n == 2);
    memcpy(r->abba, v, 2);
    TK_ASSERT(nas_msg_get(&m, "Authentication parameter RAND (5G authentication challenge)", &n) == NULL); /* the challenge is in the EAP message */
    v = nas_msg_get(&m, "EAP message", &n);
    TK_ASSERT(v != NULL && n >= 4 && n <= sizeof r->eap);
    memcpy(r->eap, v, n);
    r->eap_len = n;
    nas_free(&m);
    return true;
}

enum { EAP_OK = 0, EAP_BAD_RES };

/* answer an AUTHENTICATION REQUEST carrying an EAP message */
static void ue_answer_eap(gnb_t *g, ue_t *u, const eap_req_t *r, uint32_t tac, int mode)
{
    g5c_eap_pkt p;
    g5c_bytes out;
    nas_msg m;
    uint8_t resp[300];
    size_t rn = 0;
    TK_ASSERT(g5c_eap_parse(r->eap, r->eap_len, &p) && p.code == G5C_EAP_REQUEST && p.method == G5C_EAP_TYPE_AKA_PRIME);
    if (p.subtype == G5C_EAPAKA_NOTIFICATION) {
        /* a failure notification (no AT_MAC, the P bit is set): acknowledge */
        TK_ASSERT(g5c_eap_build(G5C_EAP_RESPONSE, p.id, G5C_EAPAKA_NOTIFICATION, NULL, 0, resp, sizeof resp, &rn) == 0);
    } else {
        const g5c_eap_attr *ra = g5c_eap_find(&p, G5C_AT_RAND), *au = g5c_eap_find(&p, G5C_AT_AUTN), *kin = g5c_eap_find(&p, G5C_AT_KDF_INPUT);
        g5c_milenage mil;
        g5c_milenage_vector vec;
        g5c_eapaka_keys keys;
        uint8_t rand[16], autn[16], sqn[6], mac_a[8], mac_s[8], ckp[16], ikp[16], resv[18] = {0}, macv[18] = {0}, kausf[32], kseaf[32];
        char snn[64], digits[24];
        size_t nl;
        g5c_eap_attr at[2];
        TK_ASSERT(p.subtype == G5C_EAPAKA_CHALLENGE && ra && au && kin && g5c_eap_find(&p, G5C_AT_MAC) != NULL && g5c_eap_find(&p, G5C_AT_KDF) != NULL);
        memcpy(rand, ra->val + 2, 16);
        memcpy(autn, au->val + 2, 16);
        nl = ((size_t)kin->val[0] << 8) | kin->val[1];
        TK_ASSERT(nl < sizeof snn && nl + 2 <= kin->vlen);
        memcpy(snn, kin->val + 2, nl);
        snn[nl] = 0;
        TK_ASSERT(strcmp(snn, E.snn) == 0); /* TS 24.501 5.4.1.2.2.2: AT_KDF_INPUT is the serving network name */
        g5c_milenage_init(&mil, u->k, u->opc);
        TK_ASSERT(g5c_milenage_f2345(&mil, rand, &vec) == 0);
        for (int i = 0; i < 6; i++)
            sqn[i] = (uint8_t)(autn[i] ^ vec.ak[i]);
        TK_ASSERT(g5c_milenage_f1(&mil, rand, sqn, autn + 6, mac_a, mac_s) == 0);
        TK_ASSERT(memcmp(mac_a, autn + 8, 8) == 0 && (autn[6] & 0x80) != 0);
        TK_ASSERT(g5c_ck_ik_prime(vec.ck, vec.ik, snn, autn, ckp, ikp) == 0);
        snprintf(digits, sizeof digits, "%s", u->supi + 5);
        TK_ASSERT(g5c_eapaka_prime_keys(ckp, ikp, digits, &keys) == 0);
        TK_ASSERT(g5c_eap_mac_ok(r->eap, r->eap_len, keys.k_aut, NULL, 0));
        g5c_eapaka_kausf(&keys, kausf);
        TK_ASSERT(g5c_kseaf(kausf, snn, kseaf) == 0);
        TK_ASSERT(g5c_kamf(kseaf, digits, r->abba, u->kamf) == 0);
        memcpy(u->abba, r->abba, 2);
        u->ngksi = r->ngksi;
        resv[1] = 64;
        memcpy(resv + 2, vec.res, 8);
        if (mode == EAP_BAD_RES)
            resv[4] ^= 0x01;
        at[0] = (g5c_eap_attr){G5C_AT_RES, resv, 10};
        at[1] = (g5c_eap_attr){G5C_AT_MAC, macv, 18};
        TK_ASSERT(g5c_eap_build(G5C_EAP_RESPONSE, p.id, G5C_EAPAKA_CHALLENGE, at, 2, resp, sizeof resp, &rn) == 0);
        TK_ASSERT(g5c_eap_mac_set(resp, rn, keys.k_aut, NULL, 0) == 0);
    }
    g5c_bytes_init(&out);
    TK_ASSERT(nas_msg_init(&m, "Authentication response"));
    nas_msg_set(&m, "EAP message", resp, rn);
    TK_ASSERT(nas_msg_encode(&m, &out) == NAS_OK);
    nas_free(&m);
    gnb_uplink_nas(g, u, out.data, out.len, tac);
    g5c_bytes_free(&out);
}

/* the 5GS mobile identity value of an IMEISV (TS 24.501 9.11.3.4) */
static size_t imeisv_identity(const char *digits, uint8_t out[9])
{
    out[0] = (uint8_t)(((digits[0] - '0') << 4) | 5);
    for (int i = 0; i < 7; i++)
        out[1 + i] = (uint8_t)(((digits[2 + 2 * i] - '0') << 4) | (digits[1 + 2 * i] - '0'));
    out[8] = (uint8_t)(0xf0 | (digits[15] - '0'));
    return 9;
}

/* receive the SECURITY MODE COMMAND, verify it with the keys derived from KAMF and answer it. Returns the command's flags. */
typedef struct {
    bool rinmr, imeisv_req;
    uint8_t int_alg, enc_alg;
    bool eap_success; /* the command carries the EAP-success message and the ABBA (TS 24.501 5.4.1.2.1) */
} smc_info;

static smc_info ue_handle_smc(gnb_t *g, ue_t *u, uint32_t tac, int send_complete)
{
    g5c_json *p = rx_expect(g, NGAP_PROC_DownlinkNASTransport, "initiatingMessage", 3000);
    uint8_t *nas;
    size_t n, k;
    nas_any a;
    nas_msg inner;
    const uint8_t *v;
    smc_info si;
    uint8_t ngksi;
    memset(&si, 0, sizeof si);
    learn_ids(u, p);
    TK_ASSERT(nas_of(p, &nas, &n));
    g5c_json_free(p);
    TK_ASSERT(nas_any_decode(nas, n, &a) == NAS_OK);
    TK_ASSERT(a.is_protected && a.prot.sht == 3); /* integrity protected with a new security context, not ciphered */
    TK_ASSERT(nas_msg_decode(a.prot.payload, a.prot.payload_len, &inner) == NAS_OK && inner.def->msg_type == 0x5d);
    v = nas_msg_get(&inner, "Selected NAS security algorithms", &k);
    TK_ASSERT(v != NULL && k == 1);
    si.enc_alg = (uint8_t)(v[0] >> 4);
    si.int_alg = (uint8_t)(v[0] & 0xf);
    v = nas_msg_get(&inner, "ngKSI", &k);
    ngksi = (uint8_t)(v[0] & 7);
    TK_ASSERT(ngksi == u->ngksi);
    v = nas_msg_get(&inner, "Replayed UE security capabilities", &k);
    TK_ASSERT(v != NULL && k == 4 && memcmp(v, u->cap, 4) == 0);
    si.imeisv_req = nas_msg_get(&inner, "IMEISV request", &k) != NULL;
    v = nas_msg_get(&inner, "EAP message", &k);
    if (v != NULL) {
        const uint8_t *ab;
        size_t abn;
        TK_ASSERT(k == 4 && v[0] == G5C_EAP_SUCCESS && v[2] == 0 && v[3] == 4);
        ab = nas_msg_get(&inner, "ABBA", &abn);
        TK_ASSERT(ab != NULL && abn == 2 && memcmp(ab, u->abba, 2) == 0);
        si.eap_success = true;
    }
    v = nas_msg_get(&inner, "Additional 5G security information", &k);
    si.rinmr = v != NULL && k == 1 && (v[0] & 0x02) != 0;
    memset(&u->sec, 0, sizeof u->sec);
    TK_ASSERT(g5c_algo_key(u->kamf, G5C_ALG_NAS_INT, si.int_alg, u->sec.knas_int) == 0);
    TK_ASSERT(g5c_algo_key(u->kamf, G5C_ALG_NAS_ENC, si.enc_alg, u->sec.knas_enc) == 0);
    u->sec.int_alg = (nas_int_alg)si.int_alg;
    u->sec.enc_alg = (nas_enc_alg)si.enc_alg;
    u->int_alg = si.int_alg;
    u->enc_alg = si.enc_alg;
    TK_ASSERT(nas_protected_verify(&a.prot, &u->sec, G5C_DIR_DL, 0));
    TK_ASSERT(a.prot.seq == 0);
    u->dl_count = 1;
    u->ul_count = 0;
    u->have_ctx = true;
    nas_free(&inner);
    nas_any_free(&a);
    free(nas);
    if (send_complete) {
        nas_msg m;
        g5c_bytes plain, prot;
        TK_ASSERT(nas_msg_init(&m, "Security mode complete"));
        if (si.imeisv_req) {
            uint8_t id[9];
            size_t l = imeisv_identity("4370816125816151", id);
            nas_msg_set(&m, "IMEISV", id, l);
        }
        if (si.rinmr)
            nas_msg_set(&m, "NAS message container", u->reg_req, u->reg_len);
        g5c_bytes_init(&plain);
        g5c_bytes_init(&prot);
        TK_ASSERT(nas_msg_encode(&m, &plain) == NAS_OK);
        nas_free(&m);
        ue_protect(u, 4, plain.data, plain.len, &prot);
        u->smc_ul = u->last_ul;
        gnb_uplink_nas(g, u, prot.data, prot.len, tac);
        g5c_bytes_free(&plain);
        g5c_bytes_free(&prot);
    }
    return si;
}

/* the Registration accept arrives in the Initial Context Setup Request: check it, answer the setup */
typedef struct {
    bool has_guti;
    uint32_t tmsi;
    size_t ntai;
    uint8_t tai_list[64];
    size_t tai_len;
    size_t nallowed;
    nas_snssai allowed[8];
    bool has_t3512;
    uint8_t t3512;
    bool has_status;
    uint16_t status;
    bool has_react;
    uint16_t react;
    g5c_json *ics;
} accept_info;

static void parse_accept(ue_t *u, const g5c_bytes *plain, accept_info *ai)
{
    nas_msg m;
    size_t n;
    const uint8_t *v;
    TK_ASSERT(nas_msg_decode(plain->data, plain->len, &m) == NAS_OK && m.def->msg_type == 0x42);
    v = nas_msg_get(&m, "5G-GUTI", &n);
    if (v != NULL) {
        nas_mobile_identity id;
        TK_ASSERT(nas_mobile_identity_decode(v, n, &id) == NAS_OK && id.kind == NAS_ID_GUTI);
        TK_ASSERT(id.amf_region == 2 && id.amf_set == 1 && id.amf_pointer == 0);
        TK_ASSERT(strcmp(id.mcc, "001") == 0 && strcmp(id.mnc, "01") == 0);
        ai->has_guti = true;
        ai->tmsi = id.tmsi;
    }
    v = nas_msg_get(&m, "TAI list", &n);
    if (v != NULL) {
        TK_ASSERT(n <= sizeof ai->tai_list);
        memcpy(ai->tai_list, v, n);
        ai->tai_len = n;
        ai->ntai = (size_t)((v[0] & 0x1f) + 1);
    }
    v = nas_msg_get(&m, "Allowed NSSAI", &n);
    if (v != NULL) {
        int k = nas_nssai_decode(v, n, ai->allowed, 8);
        TK_ASSERT(k > 0);
        ai->nallowed = (size_t)k;
    }
    v = nas_msg_get(&m, "T3512 value", &n);
    if (v != NULL && n == 1) {
        ai->has_t3512 = true;
        ai->t3512 = v[0];
    }
    v = nas_msg_get(&m, "PDU session status", &n);
    if (v != NULL && n == 2) {
        ai->has_status = true;
        ai->status = (uint16_t)(v[0] | v[1] << 8);
    }
    v = nas_msg_get(&m, "PDU session reactivation result", &n);
    if (v != NULL && n == 2) {
        ai->has_react = true;
        ai->react = (uint16_t)(v[0] | v[1] << 8);
    }
    nas_free(&m);
    (void)u;
}

static void gnb_ics_response(gnb_t *g, ue_t *u, const char *psi_list_json)
{
    g5c_json *p = new_pdu("successfulOutcome", NGAP_PROC_InitialContextSetup, "reject");
    add_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)u->amf_id));
    add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(u->ran_id));
    (void)psi_list_json;
    gnb_tx(g, p, (uint16_t)(1 + u->ran_id % 7));
}

/* receive the ICS carrying the registration (or service) accept; verify the AS key material; open the NAS PDU */
static g5c_bytes ue_receive_ics(gnb_t *g, ue_t *u, uint32_t kgnb_count, g5c_json **ics_out)
{
    g5c_json *p = rx_expect(g, NGAP_PROC_InitialContextSetup, "initiatingMessage", 3000);
    uint8_t *nas;
    size_t n;
    g5c_bytes plain;
    const g5c_json *key = ie_of(p, NGAP_IE_SecurityKey);
    uint8_t want[32], got[32];
    g5c_bytes_init(&plain);
    learn_ids(u, p);
    TK_ASSERT(ie_of(p, NGAP_IE_GUAMI) != NULL && ie_of(p, NGAP_IE_AllowedNSSAI) != NULL && ie_of(p, NGAP_IE_UESecurityCapabilities) != NULL);
    TK_ASSERT(key != NULL && g5c_hex_decode(g5c_json_get_str(key, "hex"), got, 32) == 32);
    TK_ASSERT(g5c_kgnb(u->kamf, kgnb_count, 1, want) == 0);
    TK_ASSERT(memcmp(want, got, 32) == 0); /* the UE derives the same KgNB from KAMF and the uplink NAS COUNT */
    memcpy(u->kgnb, want, 32);
    TK_ASSERT(nas_of(p, &nas, &n));
    TK_ASSERT(ue_open(u, nas, n, &plain, NULL));
    free(nas);
    if (ics_out != NULL)
        *ics_out = p;
    else
        g5c_json_free(p);
    return plain;
}

static void ue_send_protected(gnb_t *g, ue_t *u, uint8_t sht, const uint8_t *plain, size_t n, uint32_t tac)
{
    g5c_bytes prot;
    g5c_bytes_init(&prot);
    ue_protect(u, sht, plain, n, &prot);
    gnb_uplink_nas(g, u, prot.data, prot.len, tac);
    g5c_bytes_free(&prot);
}

__attribute__((unused)) static void ue_send_simple(gnb_t *g, ue_t *u, const char *name, uint32_t tac)
{
    nas_msg m;
    g5c_bytes b;
    g5c_bytes_init(&b);
    TK_ASSERT(nas_msg_init(&m, name));
    TK_ASSERT(nas_msg_encode(&m, &b) == NAS_OK);
    nas_free(&m);
    ue_send_protected(g, u, 2, b.data, b.len, tac);
    g5c_bytes_free(&b);
}

/* poll the AMF's view of a UE; reg / conn: -1 do not care, 0 / 1 required */
static bool wait_ue(const char *supi, int reg, int conn, int npdu)
{
    double end = now_s() + 4;
    while (now_s() < end) {
        amf_ue_info i;
        if (amf_ue_lookup(E.a, supi, &i)) {
            if ((reg < 0 || i.registered == (reg != 0)) && (conn < 0 || i.connected == (conn != 0)) && (npdu < 0 || (int)i.npdu == npdu))
                return true;
        } else if (reg == 0 && conn <= 0 && npdu <= 0) {
            return true; /* the context is gone altogether */
        }
        usleep(5000);
    }
    return false;
}

static bool wait_ue_gone(const char *supi)
{
    double end = now_s() + 4;
    while (now_s() < end) {
        amf_ue_info i;
        if (!amf_ue_lookup(E.a, supi, &i))
            return true;
        usleep(5000);
    }
    return false;
}

/* initial registration (SUCI) or with a 5G-GUTI; the whole procedure up to the Registration complete */
static accept_info ue_register_ex(gnb_t *g, ue_t *u, uint32_t tac, bool with_guti, bool protect_initial, uint32_t *smc_expected)
{
    g5c_bytes req, plain, out;
    auth_req_t a;
    accept_info ai;
    g5c_json *ics = NULL;
    smc_info si;
    uint32_t kgnb_count;
    memset(&ai, 0, sizeof ai);
    g5c_bytes_init(&req);
    build_reg_request(u, 1, with_guti, &req);
    TK_ASSERT(req.len <= sizeof u->reg_req);
    memcpy(u->reg_req, req.data, req.len);
    u->reg_len = req.len;
    if (protect_initial) {
        g5c_bytes prot;
        g5c_bytes_init(&prot);
        ue_protect(u, 1, req.data, req.len, &prot);
        gnb_initial_ue(g, u, prot.data, prot.len, tac, with_guti);
        g5c_bytes_free(&prot);
        kgnb_count = u->last_ul;
        /* a context the AMF still holds needs no authentication: the accept comes straight away */
        plain = ue_receive_ics(g, u, kgnb_count, &ics);
        parse_accept(u, &plain, &ai);
        g5c_bytes_free(&plain);
        if (smc_expected != NULL)
            *smc_expected = 0;
    } else {
        gnb_initial_ue(g, u, req.data, req.len, tac, with_guti);
        plain = dl_nas(g, u);
        TK_ASSERT(parse_auth_request(&plain, &a));
        g5c_bytes_free(&plain);
        ue_answer_auth(g, u, &a, tac, AUTH_OK);
        si = ue_handle_smc(g, u, tac, 1);
        TK_ASSERT(si.rinmr); /* the initial message was not protected: the AMF asks for it again */
        TK_ASSERT(si.int_alg == 2 && (si.enc_alg == 2 || u->cap[0] == 0x80));
        plain = ue_receive_ics(g, u, u->smc_ul, &ics);
        parse_accept(u, &plain, &ai);
        g5c_bytes_free(&plain);
    }
    g5c_bytes_free(&req);
    TK_ASSERT(ai.has_guti);
    ai.ics = ics;
    gnb_ics_response(g, u, NULL);
    u->tmsi = ai.tmsi;
    u->have_guti = true;
    g5c_bytes_init(&out);
    {
        nas_msg m;
        TK_ASSERT(nas_msg_init(&m, "Registration complete"));
        TK_ASSERT(nas_msg_encode(&m, &out) == NAS_OK);
        nas_free(&m);
    }
    ue_send_protected(g, u, 2, out.data, out.len, tac);
    g5c_bytes_free(&out);
    return ai;
}

static accept_info ue_register(gnb_t *g, ue_t *u, uint32_t tac)
{
    accept_info ai = ue_register_ex(g, u, tac, false, false, NULL);
    TK_ASSERT(wait_ue(u->supi, 1, 1, -1));
    return ai;
}

static void accept_free(accept_info *ai)
{
    g5c_json_free(ai->ics);
    ai->ics = NULL;
}

/* the gNB releases the UE's connection on its own initiative (inactivity) and waits for the AMF's command */
static void gnb_release_request(gnb_t *g, ue_t *u, const char *cause)
{
    g5c_json *p = new_pdu("initiatingMessage", NGAP_PROC_UEContextReleaseRequest, "ignore"), *rp;
    add_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "reject", g5c_json_new_int((int64_t)u->amf_id));
    add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "reject", g5c_json_new_int(u->ran_id));
    add_ie(p, NGAP_IE_Cause, "ignore", ng_cause_json("radioNetwork", cause));
    gnb_tx(g, p, 1);
    rp = rx_expect(g, NGAP_PROC_UEContextRelease, "initiatingMessage", 3000);
    {
        int64_t am = -1;
        const g5c_json *ids = ie_of(rp, NGAP_IE_UE_NGAP_IDs);
        TK_ASSERT(g5c_json_get_int(g5c_json_get(ids, "uE-NGAP-ID-pair"), "aMF-UE-NGAP-ID", &am) && (uint64_t)am == u->amf_id);
    }
    g5c_json_free(rp);
    p = new_pdu("successfulOutcome", NGAP_PROC_UEContextRelease, "reject");
    add_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)u->amf_id));
    add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(u->ran_id));
    gnb_tx(g, p, 1);
}

/* the AMF-initiated release: wait for the command and confirm it with the identifiers it carries */
static void gnb_confirm_release(gnb_t *g, ue_t *u)
{
    g5c_json *rp = rx_expect(g, NGAP_PROC_UEContextRelease, "initiatingMessage", 3000), *p;
    const g5c_json *ids = ie_of(rp, NGAP_IE_UE_NGAP_IDs), *pair = g5c_json_get(ids, "uE-NGAP-ID-pair");
    int64_t am = (int64_t)u->amf_id, rn = u->ran_id;
    if (pair != NULL) {
        (void)g5c_json_get_int(pair, "aMF-UE-NGAP-ID", &am);
        (void)g5c_json_get_int(pair, "rAN-UE-NGAP-ID", &rn);
    } else {
        (void)g5c_json_get_int(ids, "aMF-UE-NGAP-ID", &am);
    }
    g5c_json_free(rp);
    p = new_pdu("successfulOutcome", NGAP_PROC_UEContextRelease, "reject");
    add_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int(am));
    add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(rn));
    gnb_tx(g, p, 1);
}

static void build_est_req(g5c_bytes *out, uint8_t psi, uint8_t pti)
{
    nas_msg m;
    uint8_t irate[2] = {0xff, 0xff}, half;
    TK_ASSERT(nas_msg_init(&m, "PDU session establishment request"));
    m.pdu_session_id = psi;
    m.pti = pti;
    nas_msg_set(&m, "Integrity protection maximum data rate", irate, 2);
    half = 1; /* IPv4 */
    nas_msg_set(&m, "PDU session type", &half, 1);
    TK_ASSERT(nas_msg_encode(&m, out) == NAS_OK);
    nas_free(&m);
}

static void build_sm_simple(g5c_bytes *out, const char *name, uint8_t psi, uint8_t pti, const uint8_t *cause)
{
    nas_msg m;
    TK_ASSERT(nas_msg_init(&m, name));
    m.pdu_session_id = psi;
    m.pti = pti;
    if (cause != NULL)
        nas_msg_set(&m, "5GSM cause", cause, 1);
    TK_ASSERT(nas_msg_encode(&m, out) == NAS_OK);
    nas_free(&m);
}

/* UL NAS TRANSPORT carrying a 5GSM message; establishment requests carry the request type, slice and DNN */
static void ue_send_sm(gnb_t *g, ue_t *u, const g5c_bytes *sm, uint8_t psi, bool establish, const char *dnn, uint32_t tac)
{
    nas_msg m;
    g5c_bytes plain, tmp;
    uint8_t half = 1;
    TK_ASSERT(nas_msg_init(&m, "UL NAS transport"));
    nas_msg_set(&m, "Payload container type", &half, 1);
    half = 0;
    nas_msg_set(&m, "Spare half octet", &half, 1);
    nas_msg_set(&m, "Payload container", sm->data, sm->len);
    nas_msg_set(&m, "PDU session ID", &psi, 1);
    if (establish) {
        static const uint8_t sn[] = {0x01};
        half = 1;
        nas_msg_set(&m, "Request type", &half, 1);
        nas_msg_set(&m, "S-NSSAI", sn, sizeof sn);
        g5c_bytes_init(&tmp);
        TK_ASSERT(nas_dnn_encode(dnn != NULL ? dnn : "internet", &tmp) == NAS_OK);
        nas_msg_set(&m, "DNN", tmp.data, tmp.len);
        g5c_bytes_free(&tmp);
    }
    g5c_bytes_init(&plain);
    TK_ASSERT(nas_msg_encode(&m, &plain) == NAS_OK);
    nas_free(&m);
    ue_send_protected(g, u, 2, plain.data, plain.len, tac);
    g5c_bytes_free(&plain);
}

/* the payload container of an opened DL NAS TRANSPORT */
static bool dl_sm_payload(const g5c_bytes *plain, uint8_t *psi, g5c_bytes *sm, uint8_t *cause5gmm)
{
    nas_msg m;
    size_t n;
    const uint8_t *v;
    bool ok = false;
    if (nas_msg_decode(plain->data, plain->len, &m) != NAS_OK)
        return false;
    if (m.def->msg_type == 0x68) {
        v = nas_msg_get(&m, "Payload container", &n);
        if (v != NULL) {
            g5c_bytes_append(sm, v, n);
            ok = true;
        }
        v = nas_msg_get(&m, "PDU session ID", &n);
        *psi = v != NULL ? v[0] : 0;
        v = nas_msg_get(&m, "5GMM cause", &n);
        if (cause5gmm != NULL)
            *cause5gmm = v != NULL ? v[0] : 0;
    }
    nas_free(&m);
    return ok;
}

typedef struct {
    uint8_t psi;
    uint8_t sm_type; /* the 5GSM message type of the payload (0 when none) */
    uint8_t ue_ip[4];
    bool has_ue_ip;
    uint8_t upf_ip[4];
    uint32_t upf_teid;
    bool has_tunnel;
    g5c_json *msg;
} sess_t;

static const g5c_json *tr_ie(const g5c_json *t, int id)
{
    const g5c_json *l = g5c_json_get(t, "protocolIEs");
    for (size_t i = 0; i < g5c_json_len(l); i++) {
        int64_t v;
        if (g5c_json_get_int(g5c_json_at(l, i), "id", &v) && v == id)
            return g5c_json_get(g5c_json_at(l, i), "value");
    }
    return NULL;
}

/* the 5GSM message (and the transfer) of the first item of a PDU session list */
static void ue_open_item(ue_t *u, const g5c_json *item, const char *nas_key, const char *tr_key, const char *tr_type, sess_t *s)
{
    uint8_t nas[1500], tr[1500];
    long nl, tl;
    int64_t psi = 0;
    char err[160];
    g5c_bytes plain, sm;
    const char *h;
    s->sm_type = 0;
    TK_ASSERT(g5c_json_get_int(item, "pDUSessionID", &psi));
    s->psi = (uint8_t)psi;
    h = g5c_json_get_str(item, nas_key);
    if (h != NULL) {
        nl = g5c_hex_decode(h, nas, sizeof nas);
        TK_ASSERT(nl > 0);
        g5c_bytes_init(&plain);
        g5c_bytes_init(&sm);
        TK_ASSERT(ue_open(u, nas, (size_t)nl, &plain, NULL));
        {
            uint8_t p2 = 0;
            TK_ASSERT(dl_sm_payload(&plain, &p2, &sm, NULL) && p2 == s->psi);
        }
        s->sm_type = sm.len >= 4 ? sm.data[3] : 0;
        if (s->sm_type == 0xc2) { /* PDU SESSION ESTABLISHMENT ACCEPT: the UE address */
            nas_msg m;
            size_t n;
            const uint8_t *v;
            TK_ASSERT(nas_msg_decode(sm.data, sm.len, &m) == NAS_OK);
            v = nas_msg_get(&m, "PDU address", &n);
            if (v != NULL && n >= 5 && v[0] == 1) {
                memcpy(s->ue_ip, v + 1, 4);
                s->has_ue_ip = true;
            }
            nas_free(&m);
        }
        g5c_bytes_free(&sm);
        g5c_bytes_free(&plain);
    }
    h = g5c_json_get_str(item, tr_key);
    if (h != NULL && tr_type != NULL) {
        g5c_json *t;
        tl = g5c_hex_decode(h, tr, sizeof tr);
        TK_ASSERT(tl > 0);
        t = ngap_decode_as(tr_type, tr, (size_t)tl, err, sizeof err);
        TK_ASSERT(t != NULL);
        {
            const g5c_json *gt = g5c_json_get(tr_ie(t, NGAP_IE_UL_NGU_UP_TNLInformation), "gTPTunnel");
            uint8_t tb[4];
            if (gt != NULL) {
                TK_ASSERT(g5c_hex_decode(g5c_json_get_str(g5c_json_get(gt, "transportLayerAddress"), "hex"), s->upf_ip, 4) == 4);
                TK_ASSERT(g5c_hex_decode(g5c_json_str(g5c_json_get(gt, "gTP-TEID")), tb, 4) == 4);
                s->upf_teid = (uint32_t)tb[0] << 24 | (uint32_t)tb[1] << 16 | (uint32_t)tb[2] << 8 | tb[3];
                s->has_tunnel = true;
            }
        }
        g5c_json_free(t);
    }
}

/* the gNB's PDUSessionResourceSetupResponseTransfer (hex) for a tunnel on gNB identity idx */
static char *setup_response_transfer(int idx, uint32_t teid, const int *qfis, int nq)
{
    g5c_json *j = g5c_json_new_obj(), *per, *gt, *fl;
    g5c_bytes b;
    char err[160], *hex;
    uint8_t tb[4] = {(uint8_t)(teid >> 24), (uint8_t)(teid >> 16), (uint8_t)(teid >> 8), (uint8_t)teid};
    per = g5c_json_set(j, "dLQosFlowPerTNLInformation", g5c_json_new_obj());
    gt = g5c_json_set(g5c_json_set(per, "uPTransportLayerInformation", g5c_json_new_obj()), "gTPTunnel", g5c_json_new_obj());
    g5c_json_set(gt, "transportLayerAddress", bits_json(E.gnb_ip4[idx], 32));
    g5c_json_set(gt, "gTP-TEID", hex_str(tb, 4));
    fl = g5c_json_set(per, "associatedQosFlowList", g5c_json_new_arr());
    for (int i = 0; i < nq; i++)
        g5c_json_set_int(g5c_json_push(fl, g5c_json_new_obj()), "qosFlowIdentifier", qfis[i]);
    g5c_bytes_init(&b);
    TK_ASSERT(ngap_encode_as("PDUSessionResourceSetupResponseTransfer", j, &b, err, sizeof err) == 0);
    hex = g5c_hex_encode(b.data, b.len);
    g5c_bytes_free(&b);
    g5c_json_free(j);
    return hex;
}

static void gnb_pdu_setup_response(gnb_t *g, ue_t *u, uint8_t psi, uint32_t gnb_teid)
{
    g5c_json *p = new_pdu("successfulOutcome", NGAP_PROC_PDUSessionResourceSetup, "reject"), *list, *it;
    int q[1] = {1};
    char *tr = setup_response_transfer(g->idx, gnb_teid, q, 1);
    add_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)u->amf_id));
    add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(u->ran_id));
    list = g5c_json_new_arr();
    it = g5c_json_push(list, g5c_json_new_obj());
    g5c_json_set_int(it, "pDUSessionID", psi);
    g5c_json_set_str(it, "pDUSessionResourceSetupResponseTransfer", tr);
    free(tr);
    add_ie(p, NGAP_IE_PDUSessionResourceSetupListSURes, "ignore", list);
    gnb_tx(g, p, (uint16_t)(1 + u->ran_id % 7));
}

/* A DL NAS TRANSPORT that carries a CONFIGURATION UPDATE COMMAND (the AMF sends one after the first registration when it has a network name to give) */
static bool ue_answer_config_update(gnb_t *g, ue_t *u, const g5c_json *pdu, uint32_t tac)
{
    uint8_t *nas;
    size_t n;
    g5c_bytes plain;
    nas_msg m;
    bool is_cmd = false;
    const uint32_t saved_dl = u->dl_count; /* a message that is not ours is opened again by the caller: leave the count where it was */
    g5c_bytes_init(&plain);
    learn_ids(u, pdu);
    if (!nas_of(pdu, &nas, &n))
        return false;
    if (ue_open(u, nas, n, &plain, NULL) && plain.len >= 3 && plain.data[0] == 0x7e && plain.data[2] == 0x54 && nas_msg_decode(plain.data, plain.len, &m) == NAS_OK) {
        size_t k;
        const uint8_t *ind = nas_msg_get(&m, "Configuration update indication", &k);
        is_cmd = true;
        nas_msg_free(&m);
        if (ind != NULL && k >= 1 && (ind[0] & 1)) { /* acknowledgement requested */
            nas_msg c;
            g5c_bytes b;
            g5c_bytes_init(&b);
            TK_ASSERT(nas_msg_init(&c, "Configuration update complete"));
            TK_ASSERT(nas_msg_encode(&c, &b) == NAS_OK);
            nas_msg_free(&c);
            ue_send_protected(g, u, 2, b.data, b.len, tac);
            g5c_bytes_free(&b);
        }
    }
    free(nas);
    g5c_bytes_free(&plain);
    if (!is_cmd)
        u->dl_count = saved_dl;
    return is_cmd;
}

/* establish a session end to end: request, accept, resource setup, response; returns the session description */
static sess_t ue_establish(gnb_t *g, ue_t *u, uint8_t psi, uint32_t gnb_teid, uint32_t tac)
{
    g5c_bytes sm;
    g5c_json *p;
    sess_t s;
    const g5c_json *list;
    memset(&s, 0, sizeof s);
    g5c_bytes_init(&sm);
    build_est_req(&sm, psi, 1);
    ue_send_sm(g, u, &sm, psi, true, "internet", tac);
    g5c_bytes_free(&sm);
    p = gnb_rx(g, 4000);
    while (p != NULL && proc_of(p) == NGAP_PROC_DownlinkNASTransport && ue_answer_config_update(g, u, p, tac)) {
        g5c_json_free(p);
        p = gnb_rx(g, 4000);
    }
    if (p != NULL && proc_of(p) == NGAP_PROC_DownlinkNASTransport) {
        /* the network answered with a NAS message instead of a resource setup: say which (a 5GSM reject, a 5GMM status ...) */
        uint8_t *nas;
        size_t n;
        g5c_bytes plain;
        g5c_bytes_init(&plain);
        if (nas_of(p, &nas, &n) && ue_open(u, nas, n, &plain, NULL)) {
            char *h = g5c_hex_encode(plain.data, plain.len);
            uint8_t dpsi = 0, c5gmm = 0;
            g5c_bytes dsm;
            g5c_bytes_init(&dsm);
            if (dl_sm_payload(&plain, &dpsi, &dsm, &c5gmm) && dsm.len >= 4)
                TK_FAIL("PDU session %u: the network answered with 5GSM message type 0x%02x (cause 0x%02x), 5GMM cause %u: %s", dpsi, dsm.data[3],
                        dsm.len > 4 ? dsm.data[4] : 0, c5gmm, h);
            TK_FAIL("PDU session %u: the network answered with a NAS message: %s", dpsi, h);
        }
        {
            char *raw = g5c_json_to_string(p, NULL);
            TK_FAIL("PDU session setup: an unreadable NAS message arrived instead of the resource setup (UE dl_count %u): %.400s", u->dl_count, raw);
        }
    }
    if (p == NULL)
        TK_FAIL("no NGAP message (wanted the PDU session resource setup)");
    if (proc_of(p) != NGAP_PROC_PDUSessionResourceSetup || !is_kind(p, "initiatingMessage"))
        TK_FAIL("wanted the PDU session resource setup, got procedure %lld", (long long)proc_of(p));
    list = ie_of(p, NGAP_IE_PDUSessionResourceSetupListSUReq);
    TK_ASSERT(g5c_json_len(list) == 1);
    {
        const g5c_json *it = g5c_json_at(list, 0);
        TK_ASSERT(g5c_json_get(it, "s-NSSAI") != NULL);
        ue_open_item(u, it, "pDUSessionNAS-PDU", "pDUSessionResourceSetupRequestTransfer", "PDUSessionResourceSetupRequestTransfer", &s);
    }
    TK_ASSERT(s.psi == psi && s.sm_type == 0xc2 && s.has_ue_ip && s.has_tunnel);
    TK_ASSERT(ie_of(p, NGAP_IE_UEAggregateMaximumBitRate) != NULL);
    g5c_json_free(p);
    gnb_pdu_setup_response(g, u, psi, gnb_teid);
    return s;
}

#endif
