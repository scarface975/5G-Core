/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* AMF end-to-end test cases (the environment and the scripted peers are in e2e_env.h). */
#include "e2e_env.h"

#include "e2e_procs.h"
#include "../src/priv.h"

/* ---- cases ---- */

static void test_ng_setup(void)
{
    gnb_t g, bad, early;
    g5c_json *r;
    const g5c_json *pl;
    gnb_open(&g, 0);
    r = gnb_ng_setup(&g, 1, 1, "00f110", "gnb-one");
    TK_ASSERT(r != NULL && is_kind(r, "successfulOutcome") && proc_of(r) == NGAP_PROC_NGSetup);
    TK_ASSERT(strcmp(g5c_json_str(ie_of(r, NGAP_IE_AMFName)), "amf-e2e") == 0);
    {
        int64_t cap = 0;
        TK_ASSERT(g5c_json_int(ie_of(r, NGAP_IE_RelativeAMFCapacity), &cap) && cap == 255);
    }
    {
        const g5c_json *gl = ie_of(r, NGAP_IE_ServedGUAMIList), *gu = g5c_json_get(g5c_json_at(gl, 0), "gUAMI");
        TK_ASSERT(g5c_json_len(gl) == 1);
        TK_ASSERT(strcmp(g5c_json_get_str(gu, "pLMNIdentity"), "00f110") == 0);
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(gu, "aMFRegionID"), "hex"), "02") == 0);
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(gu, "aMFSetID"), "hex"), "0040") == 0);
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(gu, "aMFPointer"), "hex"), "00") == 0);
    }
    pl = ie_of(r, NGAP_IE_PLMNSupportList);
    TK_ASSERT(g5c_json_len(pl) == 1 && g5c_json_len(g5c_json_get(g5c_json_at(pl, 0), "sliceSupportList")) == 2);
    g5c_json_free(r);
    TK_ASSERT(amf_gnb_count(E.a) == 1);

    /* a PLMN we do not serve, a tracking area we do not serve */
    gnb_open(&bad, 0);
    r = gnb_ng_setup(&bad, 2, 1, "00f111", "gnb-bad-plmn");
    TK_ASSERT(r != NULL && is_kind(r, "unsuccessfulOutcome") && proc_of(r) == NGAP_PROC_NGSetup);
    TK_ASSERT(strcmp(g5c_json_str(g5c_json_get(ie_of(r, NGAP_IE_Cause), "misc")), "unknown-PLMN-or-SNPN") == 0);
    g5c_json_free(r);
    r = gnb_ng_setup(&bad, 2, 9, "00f110", "gnb-bad-tac");
    TK_ASSERT(r != NULL && is_kind(r, "unsuccessfulOutcome"));
    g5c_json_free(r);
    gnb_close(&bad);
    TK_ASSERT(amf_gnb_count(E.a) == 1);

    /* a UE message before NG Setup gets an Error Indication */
    gnb_open(&early, 0);
    {
        g5c_json *p = new_pdu("initiatingMessage", NGAP_PROC_InitialUEMessage, "ignore");
        uint8_t nas[] = {0x7e, 0x00, 0x41};
        add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "reject", g5c_json_new_int(1));
        add_ie(p, NGAP_IE_NAS_PDU, "reject", hex_str(nas, sizeof nas));
        add_ie(p, NGAP_IE_UserLocationInformation, "reject", uli_json(1, 1));
        gnb_tx(&early, p, 1);
        r = gnb_rx(&early, 2000);
        TK_ASSERT(r != NULL && proc_of(r) == NGAP_PROC_ErrorIndication);
        g5c_json_free(r);
    }
    gnb_close(&early);
    /* garbage is answered with an Error Indication, the association stays */
    {
        uint8_t junk[] = {0x00, 0x15, 0xff, 0xff, 0x01};
        gnb_tx_raw(&g, junk, sizeof junk, 0);
        r = gnb_rx(&g, 2000);
        TK_ASSERT(r != NULL && proc_of(r) == NGAP_PROC_ErrorIndication);
        g5c_json_free(r);
    }
    /* RAN Configuration Update: a second tracking area, then one we do not serve */
    {
        g5c_json *p = new_pdu("initiatingMessage", NGAP_PROC_RANConfigurationUpdate, "reject"), *ta;
        uint8_t t[3] = {0, 0, 2};
        ta = g5c_json_new_arr();
        {
            g5c_json *it = g5c_json_push(ta, g5c_json_new_obj()), *bl = g5c_json_set(it, "broadcastPLMNList", g5c_json_new_arr()), *pp;
            uint8_t plmn[3] = {0x00, 0xf1, 0x10};
            g5c_json_set(it, "tAC", hex_str(t, 3));
            pp = g5c_json_push(bl, g5c_json_new_obj());
            g5c_json_set(pp, "pLMNIdentity", hex_str(plmn, 3));
            g5c_json_set_str(g5c_json_set(g5c_json_push(g5c_json_set(pp, "tAISliceSupportList", g5c_json_new_arr()), g5c_json_new_obj()), "s-NSSAI", g5c_json_new_obj()),
                             "sST", "01");
        }
        add_ie(p, NGAP_IE_SupportedTAList, "reject", ta);
        gnb_tx(&g, p, 0);
        r = gnb_rx(&g, 2000);
        TK_ASSERT(r != NULL && is_kind(r, "successfulOutcome") && proc_of(r) == NGAP_PROC_RANConfigurationUpdate);
        g5c_json_free(r);
    }
    gnb_close(&g);
    TK_ASSERT(wait_ue("none", 0, 0, 0)); /* nothing to wait for: the SCTP close is processed */
    {
        double end = now_s() + 2;
        while (amf_gnb_count(E.a) != 0 && now_s() < end)
            usleep(5000);
        TK_ASSERT(amf_gnb_count(E.a) == 0);
    }
}

static void test_registration(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    amf_ue_info info;
    ue_init(&u, "001010000000001", 1);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);

    ai = ue_register(&g, &u, 1);
    TK_ASSERT(ai.ntai == 2);                      /* both tracking areas of the AMF */
    TK_ASSERT(ai.nallowed == 1 && ai.allowed[0].sst == 1 && !ai.allowed[0].has_sd);
    TK_ASSERT(ai.has_t3512 && ai.t3512 == (uint8_t)(1 << 5 | 1)); /* 3600 s: one hour */
    TK_ASSERT(amf_ue_lookup(E.a, u.supi, &info) && info.registered && info.connected && info.tmsi == ai.tmsi);
    TK_ASSERT(info.int_alg == 2 && info.enc_alg == 2 && info.nallowed == 1);
    TK_ASSERT(info.ul_count == u.ul_count); /* both sides agree on the NAS COUNTs */
    accept_free(&ai);

    /* UE-originated de-registration with the UE switching off: no accept, the context goes */
    {
        nas_msg m;
        g5c_bytes b;
        uint8_t dt = 0x09, ng = 0; /* switch off, 3GPP access */
        g5c_bytes id;
        g5c_bytes_init(&b);
        g5c_bytes_init(&id);
        put_guti_identity(&u, &id);
        TK_ASSERT(nas_msg_init(&m, "De-registration request (UE originating de-registration)"));
        nas_msg_set(&m, "De-registration type", &dt, 1);
        ng = u.ngksi;
        nas_msg_set(&m, "ngKSI", &ng, 1);
        nas_msg_set(&m, "5GS mobile identity", id.data, id.len);
        TK_ASSERT(nas_msg_encode(&m, &b) == NAS_OK);
        nas_free(&m);
        ue_send_protected(&g, &u, 2, b.data, b.len, 1);
        g5c_bytes_free(&b);
        g5c_bytes_free(&id);
    }
    gnb_confirm_release(&g, &u);
    TK_ASSERT(wait_ue_gone(u.supi));
    {   /* the SDM subscription the AMF made at registration goes with the context (found by the soak */
        double end = now_s() + 3;
        size_t n = 1;
        while (now_s() < end && n != 0) {
            pthread_mutex_lock(&E.u.mu);
            n = g5c_json_len(E.u.sdm_subs);
            pthread_mutex_unlock(&E.u.mu);
            if (n != 0)
                usleep(5000);
        }
        TK_ASSERT(n == 0);
    }
    gnb_close(&g);
}

/* ---- privacy on N1 / N2 (TS 33.501 5.2.5, 6.12) ---- */

/* the digits as ASCII or as packed BCD (the earlier digit in the low nibble) anywhere in the recorded N2 bytes */
static bool wire_has(const char *digits)
{
    size_t n = strlen(digits), packed = (n + 1) / 2;
    uint8_t bcd[16];
    for (size_t i = 0; i < packed; i++) {
        uint8_t lo = (uint8_t)(digits[2 * i] - '0'), hi = 2 * i + 1 < n ? (uint8_t)(digits[2 * i + 1] - '0') : 0xf;
        bcd[i] = (uint8_t)(hi << 4 | lo);
    }
    for (size_t i = 0; WIRE.data != NULL && i + n <= WIRE.len; i++)
        if (memcmp(WIRE.data + i, digits, n) == 0)
            return true;
    for (size_t i = 0; WIRE.data != NULL && i + packed <= WIRE.len; i++)
        if (memcmp(WIRE.data + i, bcd, packed) == 0)
            return true;
    return false;
}

static void wire_reset(void)
{
    g5c_bytes_free(&WIRE);
    g5c_bytes_init(&WIRE);
}

static void ue_switch_off(gnb_t *g, ue_t *u)
{
    nas_msg m;
    g5c_bytes b, id;
    uint8_t dt = 0x09, ng = u->ngksi;
    g5c_bytes_init(&b);
    g5c_bytes_init(&id);
    put_guti_identity(u, &id);
    TK_ASSERT(nas_msg_init(&m, "De-registration request (UE originating de-registration)"));
    nas_msg_set(&m, "De-registration type", &dt, 1);
    nas_msg_set(&m, "ngKSI", &ng, 1);
    nas_msg_set(&m, "5GS mobile identity", id.data, id.len);
    TK_ASSERT(nas_msg_encode(&m, &b) == NAS_OK);
    nas_free(&m);
    ue_send_protected(g, u, 2, b.data, b.len, 1);
    g5c_bytes_free(&b);
    g5c_bytes_free(&id);
    gnb_confirm_release(g, u);
    TK_ASSERT(wait_ue_gone(u->supi));
}

static void test_privacy(void)
{
    gnb_t g;
    ue_t u, v, w, x;
    accept_info ai;
    g5c_bytes req, plain;
    gnb_setup_ok(&g, 0, 1, 1);
    g5c_bytes_init(&WIRE);

    /* a UE that conceals its SUCI: the subscriber's digits are nowhere on N2, the registration still completes (the UDM de-conceals) */
    ue_init(&u, "001010000000042", 42);
    u.conceal = true;
    ue_provision(&u, NULL);
    wire_reset();
    WIRE_ON = true;
    ai = ue_register(&g, &u, 1);
    TK_ASSERT(ai.has_guti && ai.nallowed == 1);
    accept_free(&ai);
    WIRE_ON = false;
    TK_ASSERT(WIRE.len > 200);                       /* the whole registration was recorded */
    TK_ASSERT(!wire_has("0000000042"));              /* the MSIN */
    TK_ASSERT(!wire_has("001010000000042"));         /* the IMSI */
    ue_switch_off(&g, &u);

    /* the control: the same registration with the null scheme shows the MSIN, so the check above can fail */
    ue_init(&v, "001010000000043", 43);
    ue_provision(&v, NULL);
    wire_reset();
    WIRE_ON = true;
    ai = ue_register(&g, &v, 1);
    accept_free(&ai);
    WIRE_ON = false;
    TK_ASSERT(wire_has("0000000043"));
    ue_switch_off(&g, &v);

    /* two SUCIs of one UE differ (a fresh ephemeral key each time), so registrations cannot be linked by them */
    {
        g5c_bytes s1, s2;
        g5c_bytes_init(&s1);
        g5c_bytes_init(&s2);
        put_msin_identity(&u, &s1);
        put_msin_identity(&u, &s2);
        TK_ASSERT(s1.len == s2.len && memcmp(s1.data, s2.data, s1.len) != 0);
        g5c_bytes_free(&s1);
        g5c_bytes_free(&s2);
    }

    /* suci.null_scheme: reject at the home network: the null-scheme UE is refused, the concealing UE is not */
    E.u.refuse_null_scheme = true;
    ue_init(&w, "001010000000044", 44);
    ue_provision(&w, NULL);
    g5c_bytes_init(&req);
    build_reg_request(&w, 1, false, &req);
    gnb_initial_ue(&g, &w, req.data, req.len, 1, false);
    plain = dl_nas(&g, &w);
    TK_ASSERT(plain.len >= 3 && (plain.data[2] == 0x44 || plain.data[2] == 0x58)); /* Registration reject or Authentication reject */
    g5c_bytes_free(&plain);
    g5c_bytes_free(&req);
    gnb_confirm_release(&g, &w);
    TK_ASSERT(wait_ue_gone(w.supi));
    ue_init(&x, "001010000000045", 45);
    x.conceal = true;
    ue_provision(&x, NULL);
    ai = ue_register(&g, &x, 1);
    TK_ASSERT(ai.has_guti);
    accept_free(&ai);
    ue_switch_off(&g, &x);
    E.u.refuse_null_scheme = false;
    g5c_bytes_free(&WIRE);
    gnb_close(&g);
}

/* ---- signalling-storm protection: amf.overload (TS 24.501 5.5.1.2.5, cause #22 with T3346) ---- */

static void expect_congestion_reject(gnb_t *g, ue_t *u, uint8_t t3346)
{
    g5c_bytes req, plain;
    g5c_bytes_init(&req);
    build_reg_request(u, 1, false, &req);
    gnb_initial_ue(g, u, req.data, req.len, 1, false);
    plain = dl_nas(g, u);
    TK_ASSERT(plain.len >= 7 && plain.data[2] == 0x44 && plain.data[3] == 22); /* Registration reject, #22 congestion */
    TK_ASSERT(plain.data[4] == 0x5f && plain.data[5] == 1 && plain.data[6] == t3346); /* T3346 */
    g5c_bytes_free(&plain);
    g5c_bytes_free(&req);
    gnb_confirm_release(g, u);
    TK_ASSERT(wait_ue_gone(u->supi));
}

static void test_congestion(void)
{
    gnb_t g;
    ue_t a, b, c, d, e;
    accept_info ai;
    gnb_setup_ok(&g, 0, 1, 1);

    /* the AMF admits one registration a second: the first goes through, the second is turned away at once with the back-off timer, a second later there is room again */
    E.a->cfg.ov_regs_per_s = 1;
    E.a->cfg.ov_burst_s = 1;
    E.a->cfg.ov_t3346 = 60;
    E.a->ov_last = 0;
    ue_init(&a, "001010000000052", 52);
    ue_provision(&a, NULL);
    ai = ue_register(&g, &a, 1);
    TK_ASSERT(ai.has_guti);
    accept_free(&ai);
    ue_init(&b, "001010000000053", 53);
    ue_provision(&b, NULL);
    expect_congestion_reject(&g, &b, 30); /* 60 s: GPRS timer 2 in units of 2 s, value 30 */
    usleep(1100000);
    ue_init(&c, "001010000000054", 54);
    ue_provision(&c, NULL);
    ai = ue_register(&g, &c, 1);
    TK_ASSERT(ai.has_guti);
    accept_free(&ai);
    ue_switch_off(&g, &a);
    ue_switch_off(&g, &c);

    /* per gNB: the AMF as a whole has room, this gNB does not */
    E.a->cfg.ov_regs_per_s = 0;
    E.a->cfg.ov_gnb_regs_per_s = 1;
    E.a->cfg.ov_t3346 = 30;
    for (size_t i = 0; i < AMF_MAX_GNB; i++)
        E.a->gnbs[i].ov_last = 0;
    ue_init(&d, "001010000000055", 55);
    ue_provision(&d, NULL);
    ai = ue_register(&g, &d, 1);
    TK_ASSERT(ai.has_guti);
    accept_free(&ai);
    ue_init(&e, "001010000000056", 56);
    ue_provision(&e, NULL);
    expect_congestion_reject(&g, &e, 15); /* 30 s: unit 2 s, value 15 */
    ue_switch_off(&g, &d);

    E.a->cfg.ov_regs_per_s = 0;
    E.a->cfg.ov_gnb_regs_per_s = 0; /* off again: later tests register freely */
    gnb_close(&g);
}

static void test_auth_failures(void)
{
    gnb_t g;
    ue_t u;
    g5c_bytes req, plain;
    auth_req_t a;
    g5c_json *p;
    accept_info ai;
    g5c_json *ics;
    ue_init(&u, "001010000000002", 2);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);

    /* a response with a wrong RES*: the serving network refuses on HXRES* alone, with an Authentication reject */
    g5c_bytes_init(&req);
    build_reg_request(&u, 1, false, &req);
    gnb_initial_ue(&g, &u, req.data, req.len, 1, false);
    plain = dl_nas(&g, &u);
    TK_ASSERT(parse_auth_request(&plain, &a));
    g5c_bytes_free(&plain);
    ue_answer_auth(&g, &u, &a, 1, AUTH_WRONG_RES);
    plain = dl_nas(&g, &u);
    TK_ASSERT(plain.len == 3 && plain.data[2] == 0x58); /* AUTHENTICATION REJECT */
    g5c_bytes_free(&plain);
    gnb_confirm_release(&g, &u);
    TK_ASSERT(wait_ue_gone(u.supi));

    /* a MAC failure reported by the UE of a SUCI registration: rejected */
    u.ran_id = 3;
    gnb_initial_ue(&g, &u, req.data, req.len, 1, false);
    plain = dl_nas(&g, &u);
    TK_ASSERT(parse_auth_request(&plain, &a));
    g5c_bytes_free(&plain);
    ue_answer_auth(&g, &u, &a, 1, AUTH_MAC_FAIL);
    plain = dl_nas(&g, &u);
    TK_ASSERT(plain.len == 3 && plain.data[2] == 0x58);
    g5c_bytes_free(&plain);
    gnb_confirm_release(&g, &u);

    /* a synchronisation failure: the AMF asks the AUSF to resynchronise and challenges again, the registration then completes */
    u.ran_id = 4;
    gnb_initial_ue(&g, &u, req.data, req.len, 1, false);
    plain = dl_nas(&g, &u);
    TK_ASSERT(parse_auth_request(&plain, &a));
    g5c_bytes_free(&plain);
    ue_answer_auth(&g, &u, &a, 1, AUTH_SYNC_FAIL);
    plain = dl_nas(&g, &u);
    {
        auth_req_t a2;
        TK_ASSERT(parse_auth_request(&plain, &a2));
        TK_ASSERT(memcmp(a.rand, a2.rand, 16) != 0);
        g5c_bytes_free(&plain);
        ue_answer_auth(&g, &u, &a2, 1, AUTH_OK);
    }
    memcpy(u.reg_req, req.data, req.len);
    u.reg_len = req.len;
    (void)ue_handle_smc(&g, &u, 1, 1);
    plain = ue_receive_ics(&g, &u, u.smc_ul, &ics);
    memset(&ai, 0, sizeof ai);
    parse_accept(&u, &plain, &ai);
    g5c_bytes_free(&plain);
    g5c_json_free(ics);
    TK_ASSERT(ai.has_guti);
    gnb_ics_response(&g, &u, NULL);
    u.tmsi = ai.tmsi;
    u.have_guti = true;
    {
        nas_msg m;
        g5c_bytes b;
        g5c_bytes_init(&b);
        TK_ASSERT(nas_msg_init(&m, "Registration complete"));
        TK_ASSERT(nas_msg_encode(&m, &b) == NAS_OK);
        nas_free(&m);
        ue_send_protected(&g, &u, 2, b.data, b.len, 1);
        g5c_bytes_free(&b);
    }
    TK_ASSERT(wait_ue(u.supi, 1, 1, -1));
    g5c_bytes_free(&req);

    /* an unknown subscriber: the AUSF has no vector, the UE is rejected (#7) */
    {
        ue_t v;
        gnb_t g2;
        g5c_bytes r2;
        nas_any an;
        ue_init(&v, "001010000000999", 9);
        gnb_setup_ok(&g2, 1, 2, 1);
        g5c_bytes_init(&r2);
        build_reg_request(&v, 1, false, &r2);
        gnb_initial_ue(&g2, &v, r2.data, r2.len, 1, false);
        plain = dl_nas(&g2, &v);
        TK_ASSERT(nas_any_decode(plain.data, plain.len, &an) == NAS_OK && an.plain.def->msg_type == 0x44);
        {
            size_t n;
            const uint8_t *c = nas_msg_get(&an.plain, "5GMM cause", &n);
            TK_ASSERT(c != NULL && c[0] == 7);
        }
        nas_any_free(&an);
        g5c_bytes_free(&plain);
        g5c_bytes_free(&r2);
        gnb_confirm_release(&g2, &v);
        gnb_close(&g2);
    }
    gnb_close(&g);
    p = NULL;
    (void)p;
}

/* ---- sessions, user plane, idle mode ---- */

static void ip4pkt(uint8_t *p, const uint8_t src[4], const uint8_t dst[4], uint8_t proto, uint16_t sport, uint16_t dport, size_t total)
{
    memset(p, 0, total);
    p[0] = 0x45;
    p[2] = (uint8_t)(total >> 8);
    p[3] = (uint8_t)total;
    p[8] = 64;
    p[9] = proto;
    memcpy(p + 12, src, 4);
    memcpy(p + 16, dst, 4);
    p[20] = (uint8_t)(sport >> 8);
    p[21] = (uint8_t)sport;
    p[22] = (uint8_t)(dport >> 8);
    p[23] = (uint8_t)dport;
}

static void n3_send_ul(int idx, uint32_t teid, uint8_t qfi, const uint8_t *ip, size_t n)
{
    uint8_t cont[2], out[1600];
    gtpu_header h;
    size_t len;
    struct sockaddr_in sa;
    gtpu_header_init(&h, GTPU_G_PDU, teid);
    gtpu_pdu_session_container(cont, 1, qfi, false);
    h.ext[0].typ = GTPU_EXT_PDU_SESSION_CONTAINER;
    h.ext[0].data = cont;
    h.ext[0].len = 2;
    h.next = 1;
    TK_ASSERT(gtpu_encode(&h, ip, n, out, sizeof out, &len) == 0);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(E.n3p);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    TK_ASSERT(sendto(E.gnb_udp[idx], out, len, 0, (struct sockaddr *)&sa, sizeof sa) == (ssize_t)len);
}

static bool n3_recv_dl(int idx, uint32_t *teid, uint8_t *qfi, size_t *plen)
{
    uint8_t buf[2000];
    ssize_t n = recv(E.gnb_udp[idx], buf, sizeof buf, 0);
    gtpu_header h;
    const uint8_t *pl;
    uint8_t t;
    bool rqi;
    if (n <= 0)
        return false;
    TK_ASSERT(gtpu_decode(buf, (size_t)n, &h, &pl, plen) == 0 && h.msg_type == GTPU_G_PDU);
    *teid = h.teid;
    *qfi = 0;
    if (h.next == 1)
        TK_ASSERT(gtpu_as_pdu_session_container(&h.ext[0], &t, qfi, &rqi));
    return true;
}

static void n3_drain(int idx)
{
    uint32_t t;
    uint8_t q;
    size_t n;
    while (n3_recv_dl(idx, &t, &q, &n))
        ;
}

static bool dn_recv(uint8_t *buf, size_t cap, size_t *n)
{
    ssize_t r = recv(E.dn, buf, cap, 0);
    if (r <= 0)
        return false;
    *n = (size_t)r;
    return true;
}

static void dn_send(const uint8_t *ip, size_t n)
{
    TK_ASSERT(write(E.dn, ip, n) == (ssize_t)n);
}

static size_t upf_sessions(void)
{
    size_t n = 0;
    upf_rt_snapshot(E.rt, NULL, &n);
    return n;
}

static bool upf_has(size_t want)
{
    double end = now_s() + 3;
    while (now_s() < end) {
        if (upf_sessions() == want)
            return true;
        usleep(5000);
    }
    return upf_sessions() == want;
}

static bool smf_has(size_t want)
{
    double end = now_s() + 3;
    while (now_s() < end) {
        if (smf_session_count(E.s) == want)
            return true;
        usleep(5000);
    }
    return smf_session_count(E.s) == want;
}

/* a packet from the UE through the UPF reaches the data network, and a packet from the data network comes back on the session's tunnel */
static void check_user_plane(int idx, const sess_t *s, uint32_t gnb_teid)
{
    static const uint8_t dst[4] = {203, 0, 113, 9};
    uint8_t pkt[100], rx[2000];
    size_t n = 0;
    uint32_t teid = 0;
    uint8_t qfi = 0;
    size_t plen = 0;
    n3_drain(idx);
    ip4pkt(pkt, s->ue_ip, dst, 17, 4000, 5000, sizeof pkt);
    n3_send_ul(idx, s->upf_teid, 1, pkt, sizeof pkt);
    TK_ASSERT(dn_recv(rx, sizeof rx, &n) && n == sizeof pkt && memcmp(rx + 12, s->ue_ip, 4) == 0);
    ip4pkt(pkt, dst, s->ue_ip, 17, 5000, 4000, sizeof pkt);
    dn_send(pkt, sizeof pkt);
    TK_ASSERT(n3_recv_dl(idx, &teid, &qfi, &plen));
    TK_ASSERT(teid == gnb_teid && plen == sizeof pkt);
}

/* EAP-AKA': the challenge in the EAP message of the Authentication request, the EAP response through the AUSF */
static void test_eap_registration(void)
{
    gnb_t g;
    ue_t u;
    g5c_bytes req, plain;
    eap_req_t er;
    accept_info ai;
    g5c_json *ics;
    amf_ue_info info;
    ue_init(&u, "001010000000071", 71);
    ue_provision(&u, ",\"auth_method\":\"EAP_AKA_PRIME\"");
    gnb_setup_ok(&g, 0, 1, 1);

    g5c_bytes_init(&req);
    build_reg_request(&u, 1, false, &req);
    gnb_initial_ue(&g, &u, req.data, req.len, 1, false);
    plain = dl_nas(&g, &u);
    TK_ASSERT(parse_eap_auth_request(&plain, &er));
    g5c_bytes_free(&plain);
    ue_answer_eap(&g, &u, &er, 1, EAP_OK);
    memcpy(u.reg_req, req.data, req.len);
    u.reg_len = req.len;
    {
        smc_info si = ue_handle_smc(&g, &u, 1, 1);
        TK_ASSERT(si.eap_success);
    }
    plain = ue_receive_ics(&g, &u, u.smc_ul, &ics); /* the AS keys derive from the KAMF of the EAP exchange: the UE and the AMF agree */
    memset(&ai, 0, sizeof ai);
    parse_accept(&u, &plain, &ai);
    g5c_bytes_free(&plain);
    g5c_json_free(ics);
    TK_ASSERT(ai.has_guti);
    gnb_ics_response(&g, &u, NULL);
    u.tmsi = ai.tmsi;
    u.have_guti = true;
    {
        nas_msg m;
        g5c_bytes b;
        g5c_bytes_init(&b);
        TK_ASSERT(nas_msg_init(&m, "Registration complete"));
        TK_ASSERT(nas_msg_encode(&m, &b) == NAS_OK);
        nas_free(&m);
        ue_send_protected(&g, &u, 2, b.data, b.len, 1);
        g5c_bytes_free(&b);
    }
    TK_ASSERT(wait_ue(u.supi, 1, 1, -1));
    TK_ASSERT(amf_ue_lookup(E.a, u.supi, &info) && info.registered);
    accept_free(&ai);
    g5c_bytes_free(&req);

    /* a wrong RES: the AUSF sends a notification, then the failure; the UE gets an Authentication reject with the EAP-failure */
    {
        ue_t v;
        eap_req_t er2;
        ue_init(&v, "001010000000072", 72);
        ue_provision(&v, ",\"auth_method\":\"EAP_AKA_PRIME\"");
        g5c_bytes_init(&req);
        build_reg_request(&v, 1, false, &req);
        gnb_initial_ue(&g, &v, req.data, req.len, 1, false);
        plain = dl_nas(&g, &v);
        TK_ASSERT(parse_eap_auth_request(&plain, &er2));
        g5c_bytes_free(&plain);
        ue_answer_eap(&g, &v, &er2, 1, EAP_BAD_RES);
        plain = dl_nas(&g, &v);
        TK_ASSERT(parse_eap_auth_request(&plain, &er2)); /* the failure notification travels as an Authentication request */
        {
            g5c_eap_pkt p;
            TK_ASSERT(g5c_eap_parse(er2.eap, er2.eap_len, &p) && p.subtype == G5C_EAPAKA_NOTIFICATION);
        }
        g5c_bytes_free(&plain);
        ue_answer_eap(&g, &v, &er2, 1, EAP_OK);
        plain = dl_nas(&g, &v);
        TK_ASSERT(plain.len >= 3 + 3 + 4 && plain.data[2] == 0x58); /* AUTHENTICATION REJECT */
        {
            nas_msg m;
            size_t n;
            const uint8_t *e;
            TK_ASSERT(nas_msg_decode(plain.data, plain.len, &m) == NAS_OK);
            e = nas_msg_get(&m, "EAP message", &n);
            TK_ASSERT(e != NULL && n == 4 && e[0] == G5C_EAP_FAILURE);
            nas_free(&m);
        }
        g5c_bytes_free(&plain);
        g5c_bytes_free(&req);
        gnb_confirm_release(&g, &v);
        TK_ASSERT(wait_ue_gone(v.supi));
    }
    gnb_close(&g);
}

static void test_sessions(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    sess_t s;
    amf_ue_info info;
    g5c_bytes sm, plain;
    g5c_json *p;
    ue_init(&u, "001010000000003", 3);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);

    s = ue_establish(&g, &u, 1, 0x1111, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1));
    TK_ASSERT(upf_has(1) && smf_has(1));
    check_user_plane(0, &s, 0x1111);
    TK_ASSERT(amf_ue_lookup(E.a, u.supi, &info) && info.npdu == 1);

    /* a policy change: the SMF turns it into a modification command for the UE and a modify request for the gNB */
    {
        g5c_resp r;
        char url[200];
        static const char pol[] = "{\"default\":{\"session_ambr\":{\"uplink\":\"1 Mbps\",\"downlink\":\"2 Mbps\"}}}";
        snprintf(url, sizeof url, "%s/admin/v1/policies/%s", E.pcf_base, u.supi);
        TK_ASSERT(http("PUT", url, G5C_JSON_TYPE, pol, strlen(pol), &r, true) / 100 == 2);
        g5c_resp_free(&r);
    }
    p = rx_expect(&g, NGAP_PROC_PDUSessionResourceModify, "initiatingMessage", 4000);
    {
        const g5c_json *list = ie_of(p, NGAP_IE_PDUSessionResourceModifyListModReq);
        sess_t m;
        TK_ASSERT(g5c_json_len(list) == 1);
        memset(&m, 0, sizeof m);
        ue_open_item(&u, g5c_json_at(list, 0), "nAS-PDU", "pDUSessionResourceModifyRequestTransfer", NULL, &m);
        TK_ASSERT(m.psi == 1 && m.sm_type == 0xcb); /* PDU SESSION MODIFICATION COMMAND */
    }
    g5c_json_free(p);
    {
        g5c_json *rp = new_pdu("successfulOutcome", NGAP_PROC_PDUSessionResourceModify, "reject"), *l, *it;
        g5c_bytes tr;
        char err[100], *h;
        g5c_json *t = g5c_json_new_obj();
        g5c_bytes_init(&tr);
        TK_ASSERT(ngap_encode_as("PDUSessionResourceModifyResponseTransfer", t, &tr, err, sizeof err) == 0);
        g5c_json_free(t);
        h = g5c_hex_encode(tr.data, tr.len);
        g5c_bytes_free(&tr);
        add_ie(rp, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)u.amf_id));
        add_ie(rp, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(u.ran_id));
        l = g5c_json_new_arr();
        it = g5c_json_push(l, g5c_json_new_obj());
        g5c_json_set_int(it, "pDUSessionID", 1);
        g5c_json_set_str(it, "pDUSessionResourceModifyResponseTransfer", h);
        free(h);
        add_ie(rp, NGAP_IE_PDUSessionResourceModifyListModRes, "ignore", l);
        gnb_tx(&g, rp, 1);
    }
    g5c_bytes_init(&sm);
    build_sm_simple(&sm, "PDU session modification complete", 1, 0, NULL);
    ue_send_sm(&g, &u, &sm, 1, false, NULL, 1);
    g5c_bytes_free(&sm);
    check_user_plane(0, &s, 0x1111);

    /* the UE releases the session: command to the UE and the resource release to the gNB, then the complete */
    g5c_bytes_init(&sm);
    build_sm_simple(&sm, "PDU session release request", 1, 2, NULL);
    ue_send_sm(&g, &u, &sm, 1, false, NULL, 1);
    g5c_bytes_free(&sm);
    p = rx_expect(&g, NGAP_PROC_PDUSessionResourceRelease, "initiatingMessage", 4000);
    {
        const g5c_json *list = ie_of(p, NGAP_IE_PDUSessionResourceToReleaseListRelCmd);
        uint8_t *nas;
        size_t n;
        uint8_t psi = 0;
        TK_ASSERT(g5c_json_len(list) == 1);
        TK_ASSERT(nas_of(p, &nas, &n));
        g5c_bytes_init(&plain);
        TK_ASSERT(ue_open(&u, nas, n, &plain, NULL));
        free(nas);
        g5c_bytes_init(&sm);
        TK_ASSERT(dl_sm_payload(&plain, &psi, &sm, NULL) && psi == 1 && sm.len >= 4 && sm.data[3] == 0xd3); /* RELEASE COMMAND */
        g5c_bytes_free(&sm);
        g5c_bytes_free(&plain);
    }
    g5c_json_free(p);
    {
        g5c_json *rp = new_pdu("successfulOutcome", NGAP_PROC_PDUSessionResourceRelease, "reject"), *l, *it;
        g5c_bytes tr;
        char err[100], *h;
        g5c_json *t = g5c_json_new_obj();
        g5c_bytes_init(&tr);
        TK_ASSERT(ngap_encode_as("PDUSessionResourceReleaseResponseTransfer", t, &tr, err, sizeof err) == 0);
        g5c_json_free(t);
        h = g5c_hex_encode(tr.data, tr.len);
        g5c_bytes_free(&tr);
        add_ie(rp, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)u.amf_id));
        add_ie(rp, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(u.ran_id));
        l = g5c_json_new_arr();
        it = g5c_json_push(l, g5c_json_new_obj());
        g5c_json_set_int(it, "pDUSessionID", 1);
        g5c_json_set_str(it, "pDUSessionResourceReleaseResponseTransfer", h);
        free(h);
        add_ie(rp, NGAP_IE_PDUSessionResourceReleasedListRelRes, "ignore", l);
        gnb_tx(&g, rp, 1);
    }
    g5c_bytes_init(&sm);
    build_sm_simple(&sm, "PDU session release complete", 1, 2, NULL);
    ue_send_sm(&g, &u, &sm, 1, false, NULL, 1);
    g5c_bytes_free(&sm);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 0));
    TK_ASSERT(smf_has(0) && upf_has(0));

    /* a request for a slice outside the allowed NSSAI is not forwarded: DL NAS TRANSPORT with 5GMM cause #90 */
    {
        nas_msg m;
        g5c_bytes b;
        uint8_t half = 1, psi = 5;
        static const uint8_t sn[] = {0x07}; /* sst 7 */
        g5c_bytes est;
        g5c_bytes_init(&est);
        build_est_req(&est, 5, 1);
        TK_ASSERT(nas_msg_init(&m, "UL NAS transport"));
        nas_msg_set(&m, "Payload container type", &half, 1);
        half = 0;
        nas_msg_set(&m, "Spare half octet", &half, 1);
        nas_msg_set(&m, "Payload container", est.data, est.len);
        nas_msg_set(&m, "PDU session ID", &psi, 1);
        nas_msg_set(&m, "S-NSSAI", sn, sizeof sn);
        g5c_bytes_init(&b);
        TK_ASSERT(nas_msg_encode(&m, &b) == NAS_OK);
        nas_free(&m);
        ue_send_protected(&g, &u, 2, b.data, b.len, 1);
        g5c_bytes_free(&b);
        g5c_bytes_free(&est);
        plain = dl_nas(&g, &u);
        {
            uint8_t ps = 0, cause = 0;
            g5c_bytes sm2;
            g5c_bytes_init(&sm2);
            TK_ASSERT(dl_sm_payload(&plain, &ps, &sm2, &cause) && cause == 90 && ps == 5);
            g5c_bytes_free(&sm2);
        }
        g5c_bytes_free(&plain);
    }
    TK_ASSERT(smf_has(0));
    gnb_close(&g);
    TK_ASSERT(wait_ue(u.supi, 1, 0, -1)); /* the association went away: CM-IDLE, still registered */
}

/* ---- idle mode, service request, paging ---- */

static void put_stmsi(const ue_t *u, g5c_bytes *out)
{
    nas_mobile_identity id;
    memset(&id, 0, sizeof id);
    id.kind = NAS_ID_STMSI;
    id.amf_set = 1;
    id.amf_pointer = 0;
    id.tmsi = u->tmsi;
    TK_ASSERT(nas_mobile_identity_encode(&id, out) == NAS_OK);
}

/* an integrity protected SERVICE REQUEST; the data status goes into the ciphered NAS message container (TS 33.501 6.4.6) or stays in the clear */
static void build_service_request(ue_t *u, uint8_t stype, uint16_t uplink, bool container, g5c_bytes *prot)
{
    nas_msg outer, inner;
    g5c_bytes sid, plain, in;
    uint8_t half, status[2] = {(uint8_t)(uplink & 0xff), (uint8_t)(uplink >> 8)};
    uint32_t count = u->ul_count;
    g5c_bytes_init(&sid);
    g5c_bytes_init(&plain);
    g5c_bytes_init(&in);
    put_stmsi(u, &sid);
    TK_ASSERT(nas_msg_init(&outer, "Service request"));
    half = u->ngksi & 7;
    nas_msg_set(&outer, "ngKSI", &half, 1);
    half = stype;
    nas_msg_set(&outer, "Service type", &half, 1);
    nas_msg_set(&outer, "5G-S-TMSI", sid.data, sid.len);
    if (uplink != 0 && !container) {
        nas_msg_set(&outer, "PDU session status", status, 2);
        nas_msg_set(&outer, "Uplink data status", status, 2);
    }
    if (container) {
        TK_ASSERT(nas_msg_init(&inner, "Service request"));
        half = u->ngksi & 7;
        nas_msg_set(&inner, "ngKSI", &half, 1);
        half = stype;
        nas_msg_set(&inner, "Service type", &half, 1);
        nas_msg_set(&inner, "5G-S-TMSI", sid.data, sid.len);
        if (uplink != 0) {
            nas_msg_set(&inner, "PDU session status", status, 2);
            nas_msg_set(&inner, "Uplink data status", status, 2);
        }
        TK_ASSERT(nas_msg_encode(&inner, &in) == NAS_OK);
        nas_free(&inner);
        if (u->enc_alg == 2)
            TK_ASSERT(g5c_nea2(u->sec.knas_enc, count, NAS_BEARER_3GPP, G5C_DIR_UL, in.data, in.len) == 0);
        nas_msg_set(&outer, "NAS message container", in.data, in.len);
    }
    TK_ASSERT(nas_msg_encode(&outer, &plain) == NAS_OK);
    nas_free(&outer);
    ue_protect(u, 1, plain.data, plain.len, prot);
    g5c_bytes_free(&sid);
    g5c_bytes_free(&plain);
    g5c_bytes_free(&in);
}

static void gnb_ics_response_sessions(gnb_t *g, ue_t *u, const uint8_t *psis, const uint32_t *teids, size_t n)
{
    g5c_json *p = new_pdu("successfulOutcome", NGAP_PROC_InitialContextSetup, "reject"), *list;
    int q[1] = {1};
    add_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)u->amf_id));
    add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(u->ran_id));
    list = g5c_json_new_arr();
    for (size_t i = 0; i < n; i++) {
        g5c_json *it = g5c_json_push(list, g5c_json_new_obj());
        char *tr = setup_response_transfer(g->idx, teids[i], q, 1);
        g5c_json_set_int(it, "pDUSessionID", psis[i]);
        g5c_json_set_str(it, "pDUSessionResourceSetupResponseTransfer", tr);
        free(tr);
    }
    if (n > 0)
        add_ie(p, NGAP_IE_PDUSessionResourceSetupListCxtRes, "ignore", list);
    else
        g5c_json_free(list);
    gnb_tx(g, p, (uint16_t)(1 + u->ran_id % 7));
}

/* the ICS of a service request: opens the service accept, returns the session items (psi list) the AMF wants set up */
typedef struct {
    bool has_status, has_react;
    uint16_t status, react;
    size_t nitems;
    uint8_t psis[4];
    sess_t items[4];
    g5c_json *ics;
} svc_info;

static void ue_receive_service_accept(gnb_t *g, ue_t *u, uint32_t kgnb_count, svc_info *si)
{
    g5c_bytes plain;
    nas_msg m;
    size_t n;
    const uint8_t *v;
    const g5c_json *list;
    memset(si, 0, sizeof *si);
    plain = ue_receive_ics(g, u, kgnb_count, &si->ics);
    TK_ASSERT(nas_msg_decode(plain.data, plain.len, &m) == NAS_OK && m.def->msg_type == 0x4e); /* SERVICE ACCEPT */
    v = nas_msg_get(&m, "PDU session status", &n);
    if (v != NULL && n == 2) {
        si->has_status = true;
        si->status = (uint16_t)(v[0] | v[1] << 8);
    }
    v = nas_msg_get(&m, "PDU session reactivation result", &n);
    if (v != NULL && n == 2) {
        si->has_react = true;
        si->react = (uint16_t)(v[0] | v[1] << 8);
    }
    nas_free(&m);
    g5c_bytes_free(&plain);
    list = ie_of(si->ics, NGAP_IE_PDUSessionResourceSetupListCxtReq);
    for (size_t i = 0; list != NULL && i < g5c_json_len(list) && i < 4; i++) {
        ue_open_item(u, g5c_json_at(list, i), "nAS-PDU", "pDUSessionResourceSetupRequestTransfer", "PDUSessionResourceSetupRequestTransfer", &si->items[i]);
        si->psis[i] = si->items[i].psi;
        si->nitems++;
    }
}

static void svc_free(svc_info *si)
{
    g5c_json_free(si->ics);
    si->ics = NULL;
}

static void test_idle_service_paging(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    sess_t s;
    svc_info si;
    g5c_bytes req;
    uint8_t psis[1] = {1};
    uint32_t teids[1] = {0x3001};
    amf_stats st0, st1;
    amf_ue_info info;
    g5c_json *p;
    ue_init(&u, "001010000000004", 4);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);
    s = ue_establish(&g, &u, 1, 0x2001, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1) && upf_has(1));
    check_user_plane(0, &s, 0x2001);

    /* the gNB releases the connection for inactivity: the AMF tells the SMF, the UE goes CM-IDLE */
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));

    /* service request with the data status in the ciphered container: the session's user plane is set up again */
    amf_get_stats(E.a, &st0);
    u.ran_id = 40;
    g5c_bytes_init(&req);
    build_service_request(&u, 1, (uint16_t)(1u << 1), true, &req);
    gnb_initial_ue(&g, &u, req.data, req.len, 1, true);
    g5c_bytes_free(&req);
    ue_receive_service_accept(&g, &u, u.last_ul, &si);
    TK_ASSERT(si.has_status && (si.status & (1u << 1)));
    TK_ASSERT(si.has_react && (si.react & (1u << 1)));
    TK_ASSERT(si.nitems == 1 && si.psis[0] == 1 && si.items[0].has_tunnel);
    TK_ASSERT(si.items[0].upf_teid == s.upf_teid); /* the same tunnel as before */
    svc_free(&si);
    gnb_ics_response_sessions(&g, &u, psis, teids, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1));
    amf_get_stats(E.a, &st1);
    TK_ASSERT(st1.service_requests == st0.service_requests + 1);
    check_user_plane(0, &s, 0x3001);

    /* idle again; downlink data from the data network triggers paging, the UE answers with a service request of type mobile terminated */
    teids[0] = 0x3002;
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));
    {
        static const uint8_t src[4] = {203, 0, 113, 9};
        uint8_t pkt[100];
        ip4pkt(pkt, src, s.ue_ip, 17, 5000, 4000, sizeof pkt);
        dn_send(pkt, sizeof pkt);
    }
    p = rx_expect(&g, NGAP_PROC_Paging, "initiatingMessage", 5000);
    {
        const g5c_json *id = g5c_json_get(ie_of(p, NGAP_IE_UEPagingIdentity), "fiveG-S-TMSI"), *tl = ie_of(p, NGAP_IE_TAIListForPaging);
        uint8_t tm[4];
        TK_ASSERT(id != NULL && g5c_hex_decode(g5c_json_get_str(id, "fiveG-TMSI"), tm, 4) == 4 && ((uint32_t)tm[0] << 24 | (uint32_t)tm[1] << 16 | (uint32_t)tm[2] << 8 | tm[3]) == u.tmsi);
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(id, "aMFSetID"), "hex"), "0040") == 0);
        TK_ASSERT(g5c_json_len(tl) >= 1);
    }
    g5c_json_free(p);
    /* the first page goes unanswered: the AMF repeats it after T3513 */
    p = rx_expect(&g, NGAP_PROC_Paging, "initiatingMessage", 3000);
    g5c_json_free(p);
    u.ran_id = 41;
    g5c_bytes_init(&req);
    build_service_request(&u, 2, 0, false, &req);
    gnb_initial_ue(&g, &u, req.data, req.len, 1, true);
    g5c_bytes_free(&req);
    ue_receive_service_accept(&g, &u, u.last_ul, &si);
    TK_ASSERT(si.nitems == 1 && si.psis[0] == 1); /* the transfer that waited for the UE was delivered with the context setup */
    svc_free(&si);
    gnb_ics_response_sessions(&g, &u, psis, teids, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1));
    {
        uint32_t teid;
        uint8_t qfi;
        size_t plen;
        TK_ASSERT(n3_recv_dl(0, &teid, &qfi, &plen) && teid == 0x3002); /* the buffered packet arrives at the new tunnel */
    }
    amf_get_stats(E.a, &st1);
    TK_ASSERT(st1.pagings >= 2);

    /* a service request that fails the integrity check is rejected with #9 */
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));
    u.ran_id = 42;
    g5c_bytes_init(&req);
    build_service_request(&u, 1, 0, false, &req);
    req.data[3] ^= 0x55; /* corrupt the MAC */
    gnb_initial_ue(&g, &u, req.data, req.len, 1, true);
    g5c_bytes_free(&req);
    p = rx_expect(&g, NGAP_PROC_DownlinkNASTransport, "initiatingMessage", 3000);
    {
        uint8_t *nas;
        size_t n;
        nas_any a;
        TK_ASSERT(nas_of(p, &nas, &n));
        TK_ASSERT(nas_any_decode(nas, n, &a) == NAS_OK && !a.is_protected && a.plain.def->msg_type == 0x4d);
        {
            size_t cn;
            const uint8_t *c = nas_msg_get(&a.plain, "5GMM cause", &cn);
            TK_ASSERT(c != NULL && c[0] == 9);
        }
        nas_any_free(&a);
        free(nas);
    }
    g5c_json_free(p);
    {
        g5c_json *r = rx_expect(&g, NGAP_PROC_UEContextRelease, "initiatingMessage", 3000);
        g5c_json_free(r);
    }
    TK_ASSERT(amf_ue_lookup(E.a, u.supi, &info) && info.registered && !info.connected);
    gnb_close(&g);
    (void)smf_has;
}

static void test_paging_failure(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    sess_t s;
    g5c_json *p;
    g5c_resp r;
    char url[300], body[900];
    int before;
    ue_init(&u, "001010000000005", 5);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);
    s = ue_establish(&g, &u, 1, 0x4001, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1));
    (void)s;
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));
    /* an SMF-like N1N2 transfer for an idle UE: 202, paging; nobody answers; the failure is reported to the notification URI */
    before = atomic_load(&cb_failure_notifs);
    snprintf(body, sizeof body,
             "{\"pduSessionId\":1,\"n1n2FailureTxfNotifURI\":\"%s/n1n2-failure\",\"n2InfoContainer\":{\"n2InformationClass\":\"SM\",\"smInfo\":{\"pduSessionId\":1,"
             "\"n2InfoContent\":{\"ngapIeType\":\"PDU_RES_SETUP_REQ\",\"ngapData\":{\"contentId\":\"n2SmInfo\"}}}}}",
             E.cb_base);
    {
        g5c_mp_part parts[2];
        g5c_bytes mp;
        char *ct;
        static const uint8_t junk[] = {0x00, 0x01, 0x02};
        parts[0] = (g5c_mp_part){NULL, "application/json", (const uint8_t *)body, strlen(body)};
        parts[1] = (g5c_mp_part){"n2SmInfo", "application/vnd.3gpp.ngap", junk, sizeof junk};
        g5c_bytes_init(&mp);
        TK_ASSERT(g5c_mp_build(parts, 2, &mp, &ct) == 0);
        snprintf(url, sizeof url, "%s/namf-comm/v1/ue-contexts/%s/n1-n2-messages", E.amf_base, u.supi);
        TK_ASSERT(http("POST", url, ct, mp.data, mp.len, &r, false) == 202);
        {
            g5c_json *j = g5c_resp_parse_json(&r);
            TK_ASSERT(strcmp(g5c_json_get_str(j, "cause"), "ATTEMPTING_TO_REACH_UE") == 0);
            g5c_json_free(j);
        }
        g5c_resp_free(&r);
        g5c_bytes_free(&mp);
        free(ct);
    }
    p = rx_expect(&g, NGAP_PROC_Paging, "initiatingMessage", 3000);
    g5c_json_free(p);
    p = rx_expect(&g, NGAP_PROC_Paging, "initiatingMessage", 3000);
    g5c_json_free(p);
    {
        double end = now_s() + 4;
        while (atomic_load(&cb_failure_notifs) == before && now_s() < end)
            usleep(10000);
        TK_ASSERT(atomic_load(&cb_failure_notifs) == before + 1);
    }
    gnb_close(&g);
}

/* ---- context reuse, identification, network-initiated procedures ---- */

static void test_context_reuse(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    uint32_t old_tmsi;
    g5c_bytes req, plain;
    auth_req_t a;
    nas_msg m;
    amf_stats st0, st1;
    ue_init(&u, "001010000000006", 6);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);
    old_tmsi = u.tmsi;
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, -1));

    /* (a) an integrity protected request under the stored context needs neither authentication nor a security mode command */
    amf_get_stats(E.a, &st0);
    u.ran_id = 61;
    ai = ue_register_ex(&g, &u, 1, true, true, NULL);
    TK_ASSERT(ai.has_guti && ai.tmsi != old_tmsi); /* every registration allocates a fresh 5G-GUTI */
    accept_free(&ai);
    TK_ASSERT(wait_ue(u.supi, 1, 1, -1));
    for (double end = now_s() + 3; now_s() < end;) {
        amf_get_stats(E.a, &st1);
        if (st1.registrations == st0.registrations + 1)
            break;
        usleep(5000);
    }
    TK_ASSERT(st1.auth_ok == st0.auth_ok && st1.registrations == st0.registrations + 1);
    TK_ASSERT(amf_ue_count(E.a) == 1 || amf_ue_count(E.a) >= 1);
    {
        amf_ue_info info;
        TK_ASSERT(amf_ue_lookup(E.a, u.supi, &info) && info.tmsi == u.tmsi && info.ul_count == u.ul_count);
    }

    /* the old GUTI is gone: a request that still uses it is not known */
    old_tmsi = u.tmsi;
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, -1));

    /* (b) an unprotected request with the known GUTI: the AMF authenticates the subscriber it knows by that GUTI */
    u.ran_id = 62;
    u.have_ctx = false;
    ai = ue_register_ex(&g, &u, 1, true, false, NULL);
    TK_ASSERT(ai.has_guti && ai.tmsi != old_tmsi);
    accept_free(&ai);
    TK_ASSERT(wait_ue(u.supi, 1, 1, -1));
    amf_get_stats(E.a, &st0);
    TK_ASSERT(st0.auth_ok == st1.auth_ok + 1);

    /* (c) a GUTI nobody knows: identity request, SUCI in the response, then authentication */
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, -1));
    u.ran_id = 63;
    u.have_ctx = false;
    u.tmsi = 0x7a7a7a7a;
    g5c_bytes_init(&req);
    build_reg_request(&u, 1, true, &req);
    memcpy(u.reg_req, req.data, req.len);
    u.reg_len = req.len;
    gnb_initial_ue(&g, &u, req.data, req.len, 1, true);
    g5c_bytes_free(&req);
    plain = dl_nas(&g, &u);
    TK_ASSERT(nas_msg_decode(plain.data, plain.len, &m) == NAS_OK && m.def->msg_type == 0x5b); /* IDENTITY REQUEST */
    {
        size_t n;
        const uint8_t *v = nas_msg_get(&m, "Identity type", &n);
        TK_ASSERT(v != NULL && (v[0] & 7) == 1); /* SUCI */
    }
    nas_free(&m);
    g5c_bytes_free(&plain);
    {
        g5c_bytes id, out;
        g5c_bytes_init(&id);
        g5c_bytes_init(&out);
        put_msin_identity(&u, &id);
        TK_ASSERT(nas_msg_init(&m, "Identity response"));
        nas_msg_set(&m, "Mobile identity", id.data, id.len);
        TK_ASSERT(nas_msg_encode(&m, &out) == NAS_OK);
        nas_free(&m);
        gnb_uplink_nas(&g, &u, out.data, out.len, 1);
        g5c_bytes_free(&id);
        g5c_bytes_free(&out);
    }
    plain = dl_nas(&g, &u);
    TK_ASSERT(parse_auth_request(&plain, &a));
    g5c_bytes_free(&plain);
    ue_answer_auth(&g, &u, &a, 1, AUTH_OK);
    (void)ue_handle_smc(&g, &u, 1, 1);
    {
        g5c_json *ics;
        accept_info a2;
        plain = ue_receive_ics(&g, &u, u.smc_ul, &ics);
        memset(&a2, 0, sizeof a2);
        parse_accept(&u, &plain, &a2);
        g5c_bytes_free(&plain);
        g5c_json_free(ics);
        TK_ASSERT(a2.has_guti);
        gnb_ics_response(&g, &u, NULL);
        u.tmsi = a2.tmsi;
        TK_ASSERT(nas_msg_init(&m, "Registration complete"));
        g5c_bytes_init(&req);
        TK_ASSERT(nas_msg_encode(&m, &req) == NAS_OK);
        nas_free(&m);
        ue_send_protected(&g, &u, 2, req.data, req.len, 1);
        g5c_bytes_free(&req);
    }
    TK_ASSERT(wait_ue(u.supi, 1, 1, -1));
    gnb_close(&g);
}

static void test_network_initiated(void)
{
    gnb_t g;
    ue_t u, v;
    accept_info ai;
    sess_t s;
    g5c_bytes plain, out;
    nas_msg m;
    uint32_t new_tmsi;
    size_t s0, u0;
    amf_ue_info info;

    /* network-initiated de-registration with re-registration required: the sessions go with it */
    ue_init(&u, "001010000000007", 7);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);
    s0 = smf_session_count(E.s);
    u0 = upf_sessions();
    s = ue_establish(&g, &u, 1, 0x5001, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1) && smf_has(s0 + 1) && upf_has(u0 + 1));
    (void)s;
    TK_ASSERT(amf_ue_deregister(E.a, u.supi, true) == 0);
    plain = dl_nas(&g, &u);
    TK_ASSERT(nas_msg_decode(plain.data, plain.len, &m) == NAS_OK && m.def->msg_type == 0x47);
    {
        size_t n;
        const uint8_t *t = nas_msg_get(&m, "De-registration type", &n);
        TK_ASSERT(t != NULL && (t[0] & 0x04) != 0 && (t[0] & 0x03) == 1); /* re-registration required, 3GPP access */
    }
    nas_free(&m);
    g5c_bytes_free(&plain);
    TK_ASSERT(nas_msg_init(&m, "De-registration accept (UE terminated de-registration)"));
    g5c_bytes_init(&out);
    TK_ASSERT(nas_msg_encode(&m, &out) == NAS_OK);
    nas_free(&m);
    ue_send_protected(&g, &u, 2, out.data, out.len, 1);
    g5c_bytes_free(&out);
    gnb_confirm_release(&g, &u);
    TK_ASSERT(wait_ue_gone(u.supi));
    TK_ASSERT(smf_has(s0) && upf_has(u0));

    /* configuration update with a new 5G-GUTI, acknowledged by the UE */
    ue_init(&v, "001010000000008", 8);
    ue_provision(&v, NULL);
    ai = ue_register(&g, &v, 1);
    accept_free(&ai);
    TK_ASSERT(amf_ue_config_update(E.a, v.supi, true) == 0);
    plain = dl_nas(&g, &v);
    TK_ASSERT(nas_msg_decode(plain.data, plain.len, &m) == NAS_OK && m.def->msg_type == 0x54);
    {
        size_t n;
        const uint8_t *gu = nas_msg_get(&m, "5G-GUTI", &n);
        nas_mobile_identity id;
        TK_ASSERT(gu != NULL && nas_mobile_identity_decode(gu, n, &id) == NAS_OK && id.kind == NAS_ID_GUTI && id.tmsi != v.tmsi);
        new_tmsi = id.tmsi;
        TK_ASSERT(nas_msg_get(&m, "TAI list", &n) != NULL && nas_msg_get(&m, "Allowed NSSAI", &n) != NULL);
        TK_ASSERT(nas_msg_get(&m, "Full name for network", &n) != NULL);
    }
    nas_free(&m);
    g5c_bytes_free(&plain);
    TK_ASSERT(nas_msg_init(&m, "Configuration update complete"));
    g5c_bytes_init(&out);
    TK_ASSERT(nas_msg_encode(&m, &out) == NAS_OK);
    nas_free(&m);
    ue_send_protected(&g, &v, 2, out.data, out.len, 1);
    g5c_bytes_free(&out);
    {
        double end = now_s() + 3;
        while (now_s() < end) {
            if (amf_ue_lookup(E.a, v.supi, &info) && info.tmsi == new_tmsi)
                break;
            usleep(5000);
        }
        TK_ASSERT(info.tmsi == new_tmsi);
    }
    /* the new GUTI works for a service request, the old one does not */
    {
        uint32_t old = v.tmsi;
        g5c_bytes req;
        g5c_json *p;
        svc_info si;
        gnb_release_request(&g, &v, "user-inactivity");
        TK_ASSERT(wait_ue(v.supi, 1, 0, -1));
        v.tmsi = old;
        v.ran_id = 81;
        g5c_bytes_init(&req);
        build_service_request(&v, 1, 0, false, &req);
        gnb_initial_ue(&g, &v, req.data, req.len, 1, true);
        g5c_bytes_free(&req);
        p = rx_expect(&g, NGAP_PROC_DownlinkNASTransport, "initiatingMessage", 3000);
        g5c_json_free(p);
        gnb_confirm_release(&g, &v);
        v.tmsi = new_tmsi;
        v.ran_id = 82;
        g5c_bytes_init(&req);
        build_service_request(&v, 1, 0, false, &req);
        gnb_initial_ue(&g, &v, req.data, req.len, 1, true);
        g5c_bytes_free(&req);
        ue_receive_service_accept(&g, &v, v.last_ul, &si);
        svc_free(&si);
        gnb_ics_response_sessions(&g, &v, NULL, NULL, 0);
        TK_ASSERT(wait_ue(v.supi, 1, 1, -1));
    }
    /* an update for an idle UE waits for it: it arrives right after the service accept */
    gnb_release_request(&g, &v, "user-inactivity");
    TK_ASSERT(wait_ue(v.supi, 1, 0, -1));
    TK_ASSERT(amf_ue_config_update(E.a, v.supi, false) == 0);
    {
        g5c_bytes req;
        svc_info si;
        v.ran_id = 83;
        g5c_bytes_init(&req);
        build_service_request(&v, 1, 0, false, &req);
        gnb_initial_ue(&g, &v, req.data, req.len, 1, true);
        g5c_bytes_free(&req);
        ue_receive_service_accept(&g, &v, v.last_ul, &si);
        svc_free(&si);
        gnb_ics_response_sessions(&g, &v, NULL, NULL, 0);
        plain = dl_nas(&g, &v);
        TK_ASSERT(nas_msg_decode(plain.data, plain.len, &m) == NAS_OK && m.def->msg_type == 0x54);
        nas_free(&m);
        g5c_bytes_free(&plain);
    }
    gnb_close(&g);
}

static void test_association_loss(void)
{
    gnb_t g, g2;
    ue_t u;
    accept_info ai;
    sess_t s;
    svc_info si;
    g5c_bytes req;
    g5c_json *p, *r;
    ue_init(&u, "001010000000009", 9);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);
    s = ue_establish(&g, &u, 1, 0x6001, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1));
    (void)s;
    gnb_close(&g); /* the SCTP association disappears: the UE becomes CM-IDLE, its session stays */
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));
    gnb_setup_ok(&g2, 0, 1, 1);
    u.ran_id = 91;
    g5c_bytes_init(&req);
    build_service_request(&u, 1, 0, false, &req);
    gnb_initial_ue(&g2, &u, req.data, req.len, 1, true);
    g5c_bytes_free(&req);
    ue_receive_service_accept(&g2, &u, u.last_ul, &si);
    svc_free(&si);
    gnb_ics_response_sessions(&g2, &u, NULL, NULL, 0);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1));

    /* NG Reset of the whole interface: every UE association of the gNB is released, the AMF acknowledges */
    p = new_pdu("initiatingMessage", NGAP_PROC_NGReset, "reject");
    add_ie(p, NGAP_IE_Cause, "ignore", ng_cause_json("misc", "unspecified"));
    {
        g5c_json *rt = g5c_json_new_obj();
        g5c_json_set_str(rt, "nG-Interface", "reset-all");
        add_ie(p, NGAP_IE_ResetType, "reject", rt);
    }
    gnb_tx(&g2, p, 0);
    r = rx_expect(&g2, NGAP_PROC_NGReset, "successfulOutcome", 3000);
    g5c_json_free(r);
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));
    gnb_close(&g2);
}

static void test_events(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    g5c_resp r;
    char url[300], body[700], sub_url[300];
    size_t before;
    ue_init(&u, "001010000000010", 10);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    snprintf(body, sizeof body,
             "{\"subscription\":{\"eventList\":[{\"type\":\"REGISTRATION_STATE_REPORT\"},{\"type\":\"CONNECTIVITY_STATE_REPORT\"},{\"type\":\"REACHABILITY_REPORT\"}],"
             "\"eventNotifyUri\":\"%s/events\",\"notifyCorrelationId\":\"corr-1\",\"nfId\":\"nf-e2e\",\"supi\":\"%s\"}}",
             E.cb_base, u.supi);
    snprintf(url, sizeof url, "%s/namf-evts/v1/subscriptions", E.amf_base);
    pthread_mutex_lock(&cb_mu);
    before = cb_n;
    pthread_mutex_unlock(&cb_mu);
    TK_ASSERT(http("POST", url, G5C_JSON_TYPE, body, strlen(body), &r, false) == 201);
    {
        const char *loc = g5c_resp_header_get(&r, "location");
        TK_ASSERT(loc != NULL);
        snprintf(sub_url, sizeof sub_url, "%s", loc);
    }
    g5c_resp_free(&r);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);
    {
        double end = now_s() + 3;
        while (now_s() < end) {
            size_t n;
            pthread_mutex_lock(&cb_mu);
            n = cb_n;
            pthread_mutex_unlock(&cb_mu);
            if (n >= before + 3)
                break;
            usleep(10000);
        }
        pthread_mutex_lock(&cb_mu);
        TK_ASSERT(cb_n >= before + 3);
        {
            bool reg = false, conn = false, reach = false;
            for (size_t i = before; i < cb_n; i++) {
                reg = reg || strstr(cb_last[i], "REGISTERED") != NULL;
                conn = conn || strstr(cb_last[i], "\"CONNECTED\"") != NULL;
                reach = reach || strstr(cb_last[i], "\"REACHABLE\"") != NULL; /* a UE that is connected can be reached */
                TK_ASSERT(strstr(cb_last[i], "corr-1") != NULL && strstr(cb_last[i], u.supi) != NULL);
            }
            TK_ASSERT(reg && conn && reach);
        }
        pthread_mutex_unlock(&cb_mu);
    }
    /* after deleting the subscription nothing more arrives */
    TK_ASSERT(http("DELETE", sub_url, NULL, NULL, 0, &r, false) == 204);
    g5c_resp_free(&r);
    pthread_mutex_lock(&cb_mu);
    before = cb_n;
    pthread_mutex_unlock(&cb_mu);
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, -1));
    usleep(300000);
    pthread_mutex_lock(&cb_mu);
    TK_ASSERT(cb_n == before);
    pthread_mutex_unlock(&cb_mu);
    TK_ASSERT(http("DELETE", sub_url, NULL, NULL, 0, &r, false) == 404);
    g5c_resp_free(&r);
    gnb_close(&g);
}

static void test_sbi_errors(void)
{
    g5c_resp r;
    char url[300];
    snprintf(url, sizeof url, "%s/namf-comm/v1/ue-contexts/imsi-001019999999999/n1-n2-messages", E.amf_base);
    TK_ASSERT(http("POST", url, G5C_JSON_TYPE, "{\"pduSessionId\":1}", 18, &r, false) == 400); /* nothing to transfer */
    g5c_resp_free(&r);
    TK_ASSERT(http("POST", url, G5C_JSON_TYPE, "{not json", 9, &r, false) == 400);
    g5c_resp_free(&r);
    {
        static const char b[] = "{\"pduSessionId\":0,\"n1MessageContainer\":{\"n1MessageClass\":\"SM\",\"n1MessageContent\":{\"contentId\":\"x\"}}}";
        TK_ASSERT(http("POST", url, G5C_JSON_TYPE, b, sizeof b - 1, &r, false) == 400);
        g5c_resp_free(&r);
    }
    {
        g5c_mp_part parts[2];
        g5c_bytes mp;
        char *ct;
        static const char js[] = "{\"pduSessionId\":1,\"n1MessageContainer\":{\"n1MessageClass\":\"SM\",\"n1MessageContent\":{\"contentId\":\"n1SmMsg\"}}}";
        static const uint8_t b[] = {0x2e, 0x01, 0x01, 0xc2};
        parts[0] = (g5c_mp_part){NULL, "application/json", (const uint8_t *)js, sizeof js - 1};
        parts[1] = (g5c_mp_part){"n1SmMsg", "application/vnd.3gpp.5gnas", b, sizeof b};
        g5c_bytes_init(&mp);
        TK_ASSERT(g5c_mp_build(parts, 2, &mp, &ct) == 0);
        TK_ASSERT(http("POST", url, ct, mp.data, mp.len, &r, false) == 404); /* no such UE */
        g5c_resp_free(&r);
        g5c_bytes_free(&mp);
        free(ct);
    }
    snprintf(url, sizeof url, "%s/namf-callback/v1/smf-status/imsi-001019999999999/1", E.amf_base);
    {
        static const char b[] = "{\"statusInfo\":{\"resourceStatus\":\"RELEASED\"}}";
        TK_ASSERT(http("POST", url, G5C_JSON_TYPE, b, sizeof b - 1, &r, false) == 404);
    }
    g5c_resp_free(&r);
    TK_ASSERT(http("POST", url, G5C_JSON_TYPE, "{}", 2, &r, false) == 400);
    g5c_resp_free(&r);
    snprintf(url, sizeof url, "%s/namf-evts/v1/subscriptions", E.amf_base);
    TK_ASSERT(http("POST", url, G5C_JSON_TYPE, "{\"subscription\":{}}", 19, &r, false) == 400);
    g5c_resp_free(&r);
    {
        static const char b[] = "{\"subscription\":{\"eventList\":[{\"type\":\"PRESENCE_IN_AOI_REPORT\"}],\"eventNotifyUri\":\"http://x/y\",\"anyUE\":true}}";
        TK_ASSERT(http("POST", url, G5C_JSON_TYPE, b, sizeof b - 1, &r, false) == 501);
        g5c_resp_free(&r);
    }
    snprintf(url, sizeof url, "%s/namf-comm/v1/ue-contexts/imsi-001019999999999/n1-n2-messages", E.amf_base);
    TK_ASSERT(http("GET", url, NULL, NULL, 0, &r, false) == 405);
    g5c_resp_free(&r);
}

/* ---- mobility: Xn path switch and N2 handover ---- */

static void test_path_switch(void)
{
    gnb_t a, b;
    ue_t u;
    accept_info ai;
    sess_t s;
    g5c_json *p, *list, *it;
    const g5c_json *sc;
    char *tr;
    uint8_t nh[32], got[32];
    amf_stats st0, st1;
    ue_init(&u, "001010000000011", 11);
    ue_provision(&u, NULL);
    gnb_setup_ok(&a, 0, 1, 1);
    gnb_setup_ok(&b, 1, 2, 1);
    ai = ue_register(&a, &u, 1);
    accept_free(&ai);
    s = ue_establish(&a, &u, 1, 0x7001, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1));
    check_user_plane(0, &s, 0x7001);
    amf_get_stats(E.a, &st0);

    /* the UE moved to gNB B by Xn handover: B asks the AMF to switch the downlink path */
    p = new_pdu("initiatingMessage", NGAP_PROC_PathSwitchRequest, "reject");
    add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(111));
    add_ie(p, NGAP_IE_SourceAMF_UE_NGAP_ID, "reject", g5c_json_new_int((int64_t)u.amf_id));
    add_ie(p, NGAP_IE_UserLocationInformation, "ignore", uli_json(1, 0x200));
    {
        g5c_json *caps = g5c_json_new_obj();
        uint8_t z[2] = {0xe0, 0x00};
        g5c_json_set(caps, "nRencryptionAlgorithms", bits_json(z, 16));
        g5c_json_set(caps, "nRintegrityProtectionAlgorithms", bits_json(z, 16));
        g5c_json_set(caps, "eUTRAencryptionAlgorithms", bits_json(z, 16));
        g5c_json_set(caps, "eUTRAintegrityProtectionAlgorithms", bits_json(z, 16));
        add_ie(p, NGAP_IE_UESecurityCapabilities, "ignore", caps);
    }
    list = g5c_json_new_arr();
    it = g5c_json_push(list, g5c_json_new_obj());
    g5c_json_set_int(it, "pDUSessionID", 1);
    {
        g5c_json *t = g5c_json_new_obj();
        g5c_json_set(t, "dL-NGU-UP-TNLInformation", gtp_tunnel_json(1, 0x7101));
        g5c_json_set(t, "qosFlowAcceptedList", flow_list(1));
        tr = encoded_hex("PathSwitchRequestTransfer", t);
        g5c_json_set_str(it, "pathSwitchRequestTransfer", tr);
        free(tr);
    }
    add_ie(p, NGAP_IE_PDUSessionResourceToBeSwitchedDLList, "reject", list);
    gnb_tx(&b, p, 0);
    p = rx_expect(&b, NGAP_PROC_PathSwitchRequest, "successfulOutcome", 4000);
    {
        int64_t am = 0, rn = 0, ncc = -1;
        TK_ASSERT(g5c_json_int(ie_of(p, NGAP_IE_AMF_UE_NGAP_ID), &am) && (uint64_t)am == u.amf_id);
        TK_ASSERT(g5c_json_int(ie_of(p, NGAP_IE_RAN_UE_NGAP_ID), &rn) && rn == 111);
        sc = ie_of(p, NGAP_IE_SecurityContext);
        TK_ASSERT(g5c_json_get_int(sc, "nextHopChainingCount", &ncc) && ncc == 2);
        TK_ASSERT(g5c_hex_decode(g5c_json_get_str(g5c_json_get(sc, "nextHopNH"), "hex"), got, 32) == 32);
        ue_nh(&u, 2, nh); /* NH(1) is derived from KgNB and never sent, the first one a gNB gets has NCC 2 */
        TK_ASSERT(memcmp(nh, got, 32) == 0);
        TK_ASSERT(g5c_json_len(ie_of(p, NGAP_IE_PDUSessionResourceSwitchedList)) == 1);
        TK_ASSERT(ie_of(p, NGAP_IE_AllowedNSSAI) != NULL);
    }
    g5c_json_free(p);
    {   /* the counter is bumped after the response has been sent: wait for it instead of racing it */
        double end = now_s() + 3;
        do {
            amf_get_stats(E.a, &st1);
            if (st1.path_switches != st0.path_switches + 1)
                usleep(5000);
        } while (st1.path_switches != st0.path_switches + 1 && now_s() < end);
    }
    TK_ASSERT(st1.path_switches == st0.path_switches + 1);
    /* the user plane now runs through gNB B */
    n3_drain(0);
    n3_drain(1);
    check_user_plane(1, &s, 0x7101);

    /* the association is B's from now on: the UE's NAS messages come from there; a second switch derives the next hop */
    u.ran_id = 111;
    {
        g5c_json *q = new_pdu("initiatingMessage", NGAP_PROC_PathSwitchRequest, "reject");
        add_ie(q, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(112));
        add_ie(q, NGAP_IE_SourceAMF_UE_NGAP_ID, "reject", g5c_json_new_int((int64_t)u.amf_id));
        add_ie(q, NGAP_IE_UserLocationInformation, "ignore", uli_json(1, 0x201));
        {
            g5c_json *caps = g5c_json_new_obj();
            uint8_t z[2] = {0xe0, 0x00};
            g5c_json_set(caps, "nRencryptionAlgorithms", bits_json(z, 16));
            g5c_json_set(caps, "nRintegrityProtectionAlgorithms", bits_json(z, 16));
            g5c_json_set(caps, "eUTRAencryptionAlgorithms", bits_json(z, 16));
            g5c_json_set(caps, "eUTRAintegrityProtectionAlgorithms", bits_json(z, 16));
            add_ie(q, NGAP_IE_UESecurityCapabilities, "ignore", caps);
        }
        list = g5c_json_new_arr();
        it = g5c_json_push(list, g5c_json_new_obj());
        g5c_json_set_int(it, "pDUSessionID", 1);
        {
            g5c_json *t = g5c_json_new_obj();
            g5c_json_set(t, "dL-NGU-UP-TNLInformation", gtp_tunnel_json(1, 0x7102));
            g5c_json_set(t, "qosFlowAcceptedList", flow_list(1));
            tr = encoded_hex("PathSwitchRequestTransfer", t);
            g5c_json_set_str(it, "pathSwitchRequestTransfer", tr);
            free(tr);
        }
        add_ie(q, NGAP_IE_PDUSessionResourceToBeSwitchedDLList, "reject", list);
        gnb_tx(&b, q, 0);
        p = rx_expect(&b, NGAP_PROC_PathSwitchRequest, "successfulOutcome", 4000);
        {
            int64_t ncc = -1;
            sc = ie_of(p, NGAP_IE_SecurityContext);
            TK_ASSERT(g5c_json_get_int(sc, "nextHopChainingCount", &ncc) && ncc == 3);
            TK_ASSERT(g5c_hex_decode(g5c_json_get_str(g5c_json_get(sc, "nextHopNH"), "hex"), got, 32) == 32);
            ue_nh(&u, 3, nh);
            TK_ASSERT(memcmp(nh, got, 32) == 0);
        }
        g5c_json_free(p);
    }
    u.ran_id = 112;
    check_user_plane(1, &s, 0x7102);

    /* a path switch for a UE the AMF does not know is refused with a Path Switch Request Failure */
    p = new_pdu("initiatingMessage", NGAP_PROC_PathSwitchRequest, "reject");
    add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(5));
    add_ie(p, NGAP_IE_SourceAMF_UE_NGAP_ID, "reject", g5c_json_new_int(999999));
    add_ie(p, NGAP_IE_UserLocationInformation, "ignore", uli_json(1, 1));
    {
        g5c_json *caps = g5c_json_new_obj();
        uint8_t z[2] = {0, 0};
        g5c_json_set(caps, "nRencryptionAlgorithms", bits_json(z, 16));
        g5c_json_set(caps, "nRintegrityProtectionAlgorithms", bits_json(z, 16));
        g5c_json_set(caps, "eUTRAencryptionAlgorithms", bits_json(z, 16));
        g5c_json_set(caps, "eUTRAintegrityProtectionAlgorithms", bits_json(z, 16));
        add_ie(p, NGAP_IE_UESecurityCapabilities, "ignore", caps);
    }
    list = g5c_json_new_arr();
    it = g5c_json_push(list, g5c_json_new_obj());
    g5c_json_set_int(it, "pDUSessionID", 1);
    {
        g5c_json *t = g5c_json_new_obj();
        g5c_json_set(t, "dL-NGU-UP-TNLInformation", gtp_tunnel_json(1, 0x7103));
        g5c_json_set(t, "qosFlowAcceptedList", flow_list(1));
        tr = encoded_hex("PathSwitchRequestTransfer", t);
        g5c_json_set_str(it, "pathSwitchRequestTransfer", tr);
        free(tr);
    }
    add_ie(p, NGAP_IE_PDUSessionResourceToBeSwitchedDLList, "reject", list);
    gnb_tx(&b, p, 0);
    p = gnb_rx(&b, 3000);
    TK_ASSERT(p != NULL && proc_of(p) == NGAP_PROC_ErrorIndication);
    g5c_json_free(p);

    /* the UE de-registers (switch off) through B: the association followed the path switch */
    {
        nas_msg m;
        g5c_bytes bb, id;
        uint8_t dt = 0x09, ng = u.ngksi;
        g5c_bytes_init(&bb);
        g5c_bytes_init(&id);
        put_guti_identity(&u, &id);
        TK_ASSERT(nas_msg_init(&m, "De-registration request (UE originating de-registration)"));
        nas_msg_set(&m, "De-registration type", &dt, 1);
        nas_msg_set(&m, "ngKSI", &ng, 1);
        nas_msg_set(&m, "5GS mobile identity", id.data, id.len);
        TK_ASSERT(nas_msg_encode(&m, &bb) == NAS_OK);
        nas_free(&m);
        {
            g5c_bytes prot;
            g5c_bytes_init(&prot);
            ue_protect(&u, 2, bb.data, bb.len, &prot);
            gnb_uplink_nas(&b, &u, prot.data, prot.len, 1);
            g5c_bytes_free(&prot);
        }
        g5c_bytes_free(&bb);
        g5c_bytes_free(&id);
    }
    gnb_confirm_release(&b, &u);
    TK_ASSERT(wait_ue_gone(u.supi));
    gnb_close(&a);
    gnb_close(&b);
}

static g5c_json *ho_required_pdu(const ue_t *u, int target_idx, uint32_t target_gnb_id, uint32_t target_tac, bool with_session)
{
    g5c_json *p = new_pdu("initiatingMessage", NGAP_PROC_HandoverPreparation, "reject"), *tid, *tn, *gid, *list;
    uint8_t id[4] = {(uint8_t)(target_gnb_id >> 24), (uint8_t)(target_gnb_id >> 16), (uint8_t)(target_gnb_id >> 8), (uint8_t)target_gnb_id};
    uint8_t plmn[3] = {0x00, 0xf1, 0x10}, cont[] = {0x0a, 0x0b, 0x0c, 0x0d};
    (void)target_idx;
    add_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "reject", g5c_json_new_int((int64_t)u->amf_id));
    add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "reject", g5c_json_new_int(u->ran_id));
    add_ie(p, NGAP_IE_HandoverType, "reject", g5c_json_new_str("intra5gs"));
    add_ie(p, NGAP_IE_Cause, "ignore", ng_cause_json("radioNetwork", "handover-desirable-for-radio-reason"));
    tid = g5c_json_new_obj();
    tn = g5c_json_set(tid, "targetRANNodeID", g5c_json_new_obj());
    gid = g5c_json_set(g5c_json_set(tn, "globalRANNodeID", g5c_json_new_obj()), "globalGNB-ID", g5c_json_new_obj());
    g5c_json_set(gid, "pLMNIdentity", hex_str(plmn, 3));
    g5c_json_set(g5c_json_set(gid, "gNB-ID", g5c_json_new_obj()), "gNB-ID", bits_json(id, 32));
    g5c_json_set(tn, "selectedTAI", tai_json(target_tac));
    add_ie(p, NGAP_IE_TargetID, "reject", tid);
    list = g5c_json_new_arr();
    if (with_session) {
        g5c_json *it = g5c_json_push(list, g5c_json_new_obj());
        char *tr = encoded_hex("HandoverRequiredTransfer", g5c_json_new_obj());
        g5c_json_set_int(it, "pDUSessionID", 1);
        g5c_json_set_str(it, "handoverRequiredTransfer", tr);
        free(tr);
    }
    add_ie(p, NGAP_IE_PDUSessionResourceListHORqd, "reject", list);
    add_ie(p, NGAP_IE_SourceToTarget_TransparentContainer, "reject", hex_str(cont, sizeof cont));
    return p;
}

static void test_n2_handover(void)
{
    gnb_t a, b;
    ue_t u;
    accept_info ai;
    sess_t s;
    g5c_json *p, *r;
    int64_t tgt_amf_id = 0, tgt_ran = 7777;
    uint8_t nh[32], got[32];
    amf_stats st0, st1;
    ue_init(&u, "001010000000012", 12);
    ue_provision(&u, NULL);
    gnb_setup_ok(&a, 0, 1, 1);
    gnb_setup_ok(&b, 1, 2, 1);
    ai = ue_register(&a, &u, 1);
    accept_free(&ai);
    s = ue_establish(&a, &u, 1, 0x8001, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1));
    check_user_plane(0, &s, 0x8001);
    amf_get_stats(E.a, &st0);

    /* a target that is not served: Handover Preparation Failure */
    gnb_tx(&a, ho_required_pdu(&u, 1, 99, 1, true), 1);
    p = rx_expect(&a, NGAP_PROC_HandoverPreparation, "unsuccessfulOutcome", 3000);
    TK_ASSERT(strcmp(g5c_json_str(g5c_json_get(ie_of(p, NGAP_IE_Cause), "radioNetwork")), "unknown-targetID") == 0);
    g5c_json_free(p);

    /* a cancelled handover: the target releases its resources, the UE stays on A */
    gnb_tx(&a, ho_required_pdu(&u, 1, 2, 1, true), 1);
    p = rx_expect(&b, NGAP_PROC_HandoverResourceAllocation, "initiatingMessage", 4000);
    {
        int64_t id = 0;
        TK_ASSERT(g5c_json_int(ie_of(p, NGAP_IE_AMF_UE_NGAP_ID), &id));
        tgt_amf_id = id;
    }
    g5c_json_free(p);
    r = new_pdu("successfulOutcome", NGAP_PROC_HandoverResourceAllocation, "reject");
    add_ie(r, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int(tgt_amf_id));
    add_ie(r, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(tgt_ran));
    {
        g5c_json *l = g5c_json_new_arr(), *it = g5c_json_push(l, g5c_json_new_obj()), *t = g5c_json_new_obj();
        char *tr;
        uint8_t cont[] = {0x01, 0x02};
        g5c_json_set(t, "dL-NGU-UP-TNLInformation", gtp_tunnel_json(1, 0x8101));
        g5c_json_set(t, "qosFlowSetupResponseList", flow_list(1));
        {
            /* qosFlowSetupResponseList items carry the identifier only (data forwarding is optional) */
        }
        tr = encoded_hex("HandoverRequestAcknowledgeTransfer", t);
        g5c_json_set_int(it, "pDUSessionID", 1);
        g5c_json_set_str(it, "handoverRequestAcknowledgeTransfer", tr);
        free(tr);
        add_ie(r, NGAP_IE_PDUSessionResourceAdmittedList, "ignore", l);
        add_ie(r, NGAP_IE_TargetToSource_TransparentContainer, "reject", hex_str(cont, sizeof cont));
    }
    gnb_tx(&b, r, 1);
    p = rx_expect(&a, NGAP_PROC_HandoverPreparation, "successfulOutcome", 3000);
    TK_ASSERT(g5c_json_len(ie_of(p, NGAP_IE_PDUSessionResourceHandoverList)) == 1);
    g5c_json_free(p);
    {
        g5c_json *c = new_pdu("initiatingMessage", NGAP_PROC_HandoverCancel, "ignore");
        add_ie(c, NGAP_IE_AMF_UE_NGAP_ID, "reject", g5c_json_new_int((int64_t)u.amf_id));
        add_ie(c, NGAP_IE_RAN_UE_NGAP_ID, "reject", g5c_json_new_int(u.ran_id));
        add_ie(c, NGAP_IE_Cause, "ignore", ng_cause_json("radioNetwork", "handover-cancelled"));
        gnb_tx(&a, c, 1);
        p = rx_expect(&a, NGAP_PROC_HandoverCancel, "successfulOutcome", 3000);
        g5c_json_free(p);
        p = rx_expect(&b, NGAP_PROC_UEContextRelease, "initiatingMessage", 3000);
        g5c_json_free(p);
        {
            g5c_json *rc = new_pdu("successfulOutcome", NGAP_PROC_UEContextRelease, "reject");
            add_ie(rc, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int(tgt_amf_id));
            add_ie(rc, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(tgt_ran));
            gnb_tx(&b, rc, 1);
        }
    }
    check_user_plane(0, &s, 0x8001);

    /* the real handover: required, request, acknowledge, command, notify */
    gnb_tx(&a, ho_required_pdu(&u, 1, 2, 1, true), 1);
    p = rx_expect(&b, NGAP_PROC_HandoverResourceAllocation, "initiatingMessage", 4000);
    {
        int64_t id = 0, ncc = -1;
        const g5c_json *sc = ie_of(p, NGAP_IE_SecurityContext), *l = ie_of(p, NGAP_IE_PDUSessionResourceSetupListHOReq);
        TK_ASSERT(g5c_json_int(ie_of(p, NGAP_IE_AMF_UE_NGAP_ID), &id));
        tgt_amf_id = id;
        TK_ASSERT(strcmp(g5c_json_str(ie_of(p, NGAP_IE_HandoverType)), "intra5gs") == 0);
        TK_ASSERT(ie_of(p, NGAP_IE_UEAggregateMaximumBitRate) != NULL && ie_of(p, NGAP_IE_UESecurityCapabilities) != NULL);
        TK_ASSERT(ie_of(p, NGAP_IE_GUAMI) != NULL && ie_of(p, NGAP_IE_AllowedNSSAI) != NULL);
        TK_ASSERT(strcmp(g5c_json_str(ie_of(p, NGAP_IE_SourceToTarget_TransparentContainer)), "0a0b0c0d") == 0);
        TK_ASSERT(g5c_json_get_int(sc, "nextHopChainingCount", &ncc));
        TK_ASSERT(g5c_hex_decode(g5c_json_get_str(g5c_json_get(sc, "nextHopNH"), "hex"), got, 32) == 32);
        ue_nh(&u, (int)ncc, nh);
        TK_ASSERT(memcmp(nh, got, 32) == 0);
        TK_ASSERT(g5c_json_len(l) == 1);
        {
            const g5c_json *it = g5c_json_at(l, 0);
            char err[100];
            uint8_t tb[200];
            long n = g5c_hex_decode(g5c_json_get_str(it, "handoverRequestTransfer"), tb, sizeof tb);
            g5c_json *t;
            TK_ASSERT(n > 0 && g5c_json_get_int(it, "pDUSessionID", &id) && id == 1 && g5c_json_get(it, "s-NSSAI") != NULL);
            t = ngap_decode_as("PDUSessionResourceSetupRequestTransfer", tb, (size_t)n, err, sizeof err);
            TK_ASSERT(t != NULL && tr_ie(t, NGAP_IE_UL_NGU_UP_TNLInformation) != NULL);
            g5c_json_free(t);
        }
    }
    g5c_json_free(p);
    r = new_pdu("successfulOutcome", NGAP_PROC_HandoverResourceAllocation, "reject");
    add_ie(r, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int(tgt_amf_id));
    add_ie(r, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(tgt_ran));
    {
        g5c_json *l = g5c_json_new_arr(), *it = g5c_json_push(l, g5c_json_new_obj()), *t = g5c_json_new_obj();
        char *tr;
        uint8_t cont[] = {0xaa, 0xbb};
        g5c_json_set(t, "dL-NGU-UP-TNLInformation", gtp_tunnel_json(1, 0x8102));
        g5c_json_set(t, "qosFlowSetupResponseList", flow_list(1));
        tr = encoded_hex("HandoverRequestAcknowledgeTransfer", t);
        g5c_json_set_int(it, "pDUSessionID", 1);
        g5c_json_set_str(it, "handoverRequestAcknowledgeTransfer", tr);
        free(tr);
        add_ie(r, NGAP_IE_PDUSessionResourceAdmittedList, "ignore", l);
        add_ie(r, NGAP_IE_TargetToSource_TransparentContainer, "reject", hex_str(cont, sizeof cont));
    }
    gnb_tx(&b, r, 1);
    p = rx_expect(&a, NGAP_PROC_HandoverPreparation, "successfulOutcome", 3000);
    TK_ASSERT(strcmp(g5c_json_str(ie_of(p, NGAP_IE_TargetToSource_TransparentContainer)), "aabb") == 0);
    g5c_json_free(p);
    r = new_pdu("initiatingMessage", NGAP_PROC_HandoverNotification, "ignore");
    add_ie(r, NGAP_IE_AMF_UE_NGAP_ID, "reject", g5c_json_new_int(tgt_amf_id));
    add_ie(r, NGAP_IE_RAN_UE_NGAP_ID, "reject", g5c_json_new_int(tgt_ran));
    add_ie(r, NGAP_IE_UserLocationInformation, "ignore", uli_json(1, 0x300));
    gnb_tx(&b, r, 1);
    /* the source association is released, the user plane is B's */
    gnb_confirm_release(&a, &u);
    {
        double end = now_s() + 3;
        amf_get_stats(E.a, &st1);
        while (st1.handovers != st0.handovers + 1 && now_s() < end) {
            usleep(5000);
            amf_get_stats(E.a, &st1);
        }
        TK_ASSERT(st1.handovers == st0.handovers + 1);
    }
    n3_drain(0);
    n3_drain(1);
    check_user_plane(1, &s, 0x8102);

    /* the UE's next NAS message arrives on the target association; the target leg's identifiers are the UE's from now on */
    u.amf_id = (uint64_t)tgt_amf_id;
    u.ran_id = (uint32_t)tgt_ran;
    {
        g5c_bytes sm;
        g5c_bytes_init(&sm);
        build_sm_simple(&sm, "PDU session release request", 1, 3, NULL);
        ue_send_sm(&b, &u, &sm, 1, false, NULL, 1);
        g5c_bytes_free(&sm);
        p = rx_expect(&b, NGAP_PROC_PDUSessionResourceRelease, "initiatingMessage", 4000);
        g5c_json_free(p);
    }
    gnb_close(&a);
    gnb_close(&b);
}

static void test_handover_failure(void)
{
    gnb_t a, b;
    ue_t u;
    accept_info ai;
    sess_t s;
    g5c_json *p, *r;
    int64_t tgt = 0;
    ue_init(&u, "001010000000013", 13);
    ue_provision(&u, NULL);
    gnb_setup_ok(&a, 0, 1, 1);
    gnb_setup_ok(&b, 1, 2, 1);
    ai = ue_register(&a, &u, 1);
    accept_free(&ai);
    s = ue_establish(&a, &u, 1, 0x9001, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1));
    gnb_tx(&a, ho_required_pdu(&u, 1, 2, 1, true), 1);
    p = rx_expect(&b, NGAP_PROC_HandoverResourceAllocation, "initiatingMessage", 4000);
    TK_ASSERT(g5c_json_int(ie_of(p, NGAP_IE_AMF_UE_NGAP_ID), &tgt));
    g5c_json_free(p);
    r = new_pdu("unsuccessfulOutcome", NGAP_PROC_HandoverResourceAllocation, "reject");
    add_ie(r, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int(tgt));
    add_ie(r, NGAP_IE_Cause, "ignore", ng_cause_json("radioNetwork", "no-radio-resources-available-in-target-cell"));
    gnb_tx(&b, r, 1);
    p = rx_expect(&a, NGAP_PROC_HandoverPreparation, "unsuccessfulOutcome", 3000);
    TK_ASSERT(strcmp(g5c_json_str(g5c_json_get(ie_of(p, NGAP_IE_Cause), "radioNetwork")), "no-radio-resources-available-in-target-cell") == 0);
    g5c_json_free(p);
    check_user_plane(0, &s, 0x9001); /* nothing changed for the UE */
    gnb_close(&a);
    gnb_close(&b);
}

/* ---- algorithm negotiation, rejects, timers, persistence ---- */

static void test_algorithms_and_rejects(void)
{
    gnb_t g;
    ue_t u, v, w;
    accept_info ai;
    amf_ue_info info;
    g5c_bytes req, plain;
    auth_req_t a;
    nas_any an;
    size_t n;
    const uint8_t *c;
    gnb_setup_ok(&g, 0, 1, 1);

    /* a UE that only offers NEA0 / NIA2 gets exactly those */
    ue_init(&u, "001010000000014", 14);
    ue_provision(&u, NULL);
    u.cap[0] = 0x80; /* 5G-EA0 */
    u.cap[1] = 0x20; /* 5G-IA2 */
    u.cap[2] = u.cap[3] = 0;
    ai = ue_register_ex(&g, &u, 1, false, false, NULL);
    accept_free(&ai);
    (void)ai;
    TK_ASSERT(wait_ue(u.supi, 1, 1, -1));
    TK_ASSERT(amf_ue_lookup(E.a, u.supi, &info) && info.enc_alg == 0 && info.int_alg == 2);
    gnb_close(&g);
    gnb_setup_ok(&g, 0, 1, 1);

    /* a UE that offers no algorithm the AMF accepts (only 128-NIA1 = SNOW 3G, which this AMF does not select): rejected with #23 */
    ue_init(&v, "001010000000015", 15);
    ue_provision(&v, NULL);
    v.cap[0] = 0xe0;
    v.cap[1] = 0x40; /* 5G-IA1 only */
    v.cap[2] = v.cap[3] = 0;
    g5c_bytes_init(&req);
    build_reg_request(&v, 1, false, &req);
    gnb_initial_ue(&g, &v, req.data, req.len, 1, false);
    plain = dl_nas(&g, &v);
    TK_ASSERT(parse_auth_request(&plain, &a));
    g5c_bytes_free(&plain);
    ue_answer_auth(&g, &v, &a, 1, AUTH_OK);
    plain = dl_nas(&g, &v);
    TK_ASSERT(nas_any_decode(plain.data, plain.len, &an) == NAS_OK && an.plain.def->msg_type == 0x44);
    c = nas_msg_get(&an.plain, "5GMM cause", &n);
    TK_ASSERT(c != NULL && c[0] == 23);
    nas_any_free(&an);
    g5c_bytes_free(&plain);
    g5c_bytes_free(&req);
    gnb_confirm_release(&g, &v);
    TK_ASSERT(wait_ue_gone(v.supi));

    /* emergency registration: not supported (#5), nothing is created */
    ue_init(&w, "001010000000016", 16);
    ue_provision(&w, NULL);
    g5c_bytes_init(&req);
    build_reg_request(&w, 4, false, &req);
    gnb_initial_ue(&g, &w, req.data, req.len, 1, false);
    plain = dl_nas(&g, &w);
    TK_ASSERT(nas_any_decode(plain.data, plain.len, &an) == NAS_OK && an.plain.def->msg_type == 0x44);
    c = nas_msg_get(&an.plain, "5GMM cause", &n);
    TK_ASSERT(c != NULL && c[0] == 5);
    nas_any_free(&an);
    g5c_bytes_free(&plain);
    g5c_bytes_free(&req);
    gnb_confirm_release(&g, &w);

    /* a tracking area the AMF does not serve: authentication and security mode complete, then the reject (#12), protected under the new context */
    w.ran_id = 17;
    g5c_bytes_init(&req);
    build_reg_request(&w, 1, false, &req);
    memcpy(w.reg_req, req.data, req.len);
    w.reg_len = req.len;
    gnb_initial_ue(&g, &w, req.data, req.len, 9, false);
    g5c_bytes_free(&req);
    plain = dl_nas(&g, &w);
    TK_ASSERT(parse_auth_request(&plain, &a));
    g5c_bytes_free(&plain);
    ue_answer_auth(&g, &w, &a, 9, AUTH_OK);
    (void)ue_handle_smc(&g, &w, 9, 1);
    plain = dl_nas(&g, &w); /* ue_open verifies the integrity protection */
    TK_ASSERT(nas_msg_decode(plain.data, plain.len, &an.plain) == NAS_OK && an.plain.def->msg_type == 0x44);
    c = nas_msg_get(&an.plain, "5GMM cause", &n);
    TK_ASSERT(c != NULL && c[0] == 12);
    nas_free(&an.plain);
    g5c_bytes_free(&plain);
    gnb_confirm_release(&g, &w);
    TK_ASSERT(wait_ue_gone(w.supi));
    gnb_close(&g);
}

static void test_uplink_protection(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    g5c_bytes sm, plain, prot;
    nas_msg m;
    g5c_json *p;
    uint8_t half = 1, psi = 4;
    static const uint8_t sn[] = {0x01};
    g5c_bytes est, ulb;
    ue_init(&u, "001010000000017", 17);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);
    (void)sm;
    (void)plain;

    /* an UL NAS TRANSPORT with a corrupted MAC is dropped: no answer, the counter does not move */
    g5c_bytes_init(&est);
    g5c_bytes_init(&ulb);
    g5c_bytes_init(&prot);
    build_est_req(&est, psi, 1);
    TK_ASSERT(nas_msg_init(&m, "UL NAS transport"));
    nas_msg_set(&m, "Payload container type", &half, 1);
    half = 0;
    nas_msg_set(&m, "Spare half octet", &half, 1);
    nas_msg_set(&m, "Payload container", est.data, est.len);
    nas_msg_set(&m, "PDU session ID", &psi, 1);
    half = 1;
    nas_msg_set(&m, "Request type", &half, 1);
    nas_msg_set(&m, "S-NSSAI", sn, sizeof sn);
    TK_ASSERT(nas_msg_encode(&m, &ulb) == NAS_OK);
    nas_free(&m);
    {
        uint32_t keep = u.ul_count;
        ue_protect(&u, 2, ulb.data, ulb.len, &prot);
        u.ul_count = keep; /* the corrupted copy is not "sent" as far as the UE's counter goes */
        prot.data[3] ^= 0x01;
        gnb_uplink_nas(&g, &u, prot.data, prot.len, 1);
        TK_ASSERT(gnb_rx(&g, 400) == NULL);
    }
    /* the genuine message with the same count is accepted afterwards, and replaying it is dropped */
    g5c_bytes_free(&prot);
    g5c_bytes_init(&prot);
    ue_protect(&u, 2, ulb.data, ulb.len, &prot);
    gnb_uplink_nas(&g, &u, prot.data, prot.len, 1);
    p = rx_expect(&g, NGAP_PROC_PDUSessionResourceSetup, "initiatingMessage", 4000);
    g5c_json_free(p);
    gnb_uplink_nas(&g, &u, prot.data, prot.len, 1); /* replay */
    TK_ASSERT(gnb_rx(&g, 400) == NULL);
    g5c_bytes_free(&prot);
    g5c_bytes_free(&ulb);
    g5c_bytes_free(&est);
    /* an unprotected message from a registered UE with a security context is ignored, too */
    {
        g5c_bytes b;
        g5c_bytes_init(&b);
        TK_ASSERT(nas_msg_init(&m, "5GMM status"));
        {
            uint8_t cause = 97;
            nas_msg_set(&m, "5GMM cause", &cause, 1);
        }
        TK_ASSERT(nas_msg_encode(&m, &b) == NAS_OK);
        nas_free(&m);
        gnb_uplink_nas(&g, &u, b.data, b.len, 1);
        g5c_bytes_free(&b);
        TK_ASSERT(gnb_rx(&g, 300) == NULL);
    }
    gnb_close(&g);
}

static void test_registration_update_and_replacement(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    sess_t s1, s2;
    g5c_bytes req, plain, out;
    nas_msg m;
    size_t s0;
    ue_init(&u, "001010000000018", 18);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);
    s0 = smf_session_count(E.s);
    s1 = ue_establish(&g, &u, 1, 0xa001, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1) && smf_has(s0 + 1));
    (void)s1;

    /* a second establishment request for the same PDU session id replaces the session (the SMF releases the first) */
    s2 = ue_establish(&g, &u, 1, 0xa002, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1) && smf_has(s0 + 1));
    check_user_plane(0, &s2, 0xa002);

    /* a periodic registration update on the established connection: protected request, accept in a DL NAS TRANSPORT (no new context setup) */
    g5c_bytes_init(&req);
    build_reg_request(&u, 3, true, &req);
    ue_send_protected(&g, &u, 1, req.data, req.len, 1);
    g5c_bytes_free(&req);
    plain = dl_nas(&g, &u);
    {
        accept_info a2;
        memset(&a2, 0, sizeof a2);
        parse_accept(&u, &plain, &a2);
        TK_ASSERT(a2.has_guti && a2.tmsi != u.tmsi && a2.ntai == 2);
        u.tmsi = a2.tmsi;
    }
    g5c_bytes_free(&plain);
    TK_ASSERT(nas_msg_init(&m, "Registration complete"));
    g5c_bytes_init(&out);
    TK_ASSERT(nas_msg_encode(&m, &out) == NAS_OK);
    nas_free(&m);
    ue_send_protected(&g, &u, 2, out.data, out.len, 1);
    g5c_bytes_free(&out);
    {
        amf_ue_info info;
        double end = now_s() + 3;
        while (now_s() < end && !(amf_ue_lookup(E.a, u.supi, &info) && info.tmsi == u.tmsi))
            usleep(5000);
        TK_ASSERT(info.tmsi == u.tmsi && info.npdu == 1);
    }
    /* the UE reports that it holds no PDU session (status IE): the AMF releases what it has */
    g5c_bytes_init(&req);
    {
        uint8_t half = 2, ng = u.ngksi;
        g5c_bytes id;
        uint8_t status[2] = {0, 0};
        g5c_bytes_init(&id);
        put_guti_identity(&u, &id);
        TK_ASSERT(nas_msg_init(&m, "Registration request"));
        nas_msg_set(&m, "5GS registration type", &half, 1);
        nas_msg_set(&m, "ngKSI", &ng, 1);
        nas_msg_set(&m, "5GS mobile identity", id.data, id.len);
        nas_msg_set(&m, "UE security capability", u.cap, 4);
        nas_msg_set(&m, "PDU session status", status, 2);
        TK_ASSERT(nas_msg_encode(&m, &req) == NAS_OK);
        nas_free(&m);
        g5c_bytes_free(&id);
    }
    ue_send_protected(&g, &u, 1, req.data, req.len, 1);
    g5c_bytes_free(&req);
    plain = dl_nas(&g, &u);
    {
        accept_info a3;
        memset(&a3, 0, sizeof a3);
        parse_accept(&u, &plain, &a3);
        TK_ASSERT(a3.has_status && a3.status == 0);
        u.tmsi = a3.tmsi;
    }
    g5c_bytes_free(&plain);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 0) && smf_has(s0));
    gnb_close(&g);
}

static void test_network_name(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    g5c_bytes plain;
    nas_msg m;
    size_t n;
    const uint8_t *v;
    /* with a network name configured the AMF follows the first registration with a configuration update carrying the name and the time */
    (void)unlink(E.amf_state);
    stop_amf();
    start_amf("  network_name: { full: 'Full Net', short: 'Net' }\n");
    ue_init(&u, "001010000000022", 22);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);
    plain = dl_nas(&g, &u);
    TK_ASSERT(nas_msg_decode(plain.data, plain.len, &m) == NAS_OK && m.def->msg_type == 0x54);
    v = nas_msg_get(&m, "Full name for network", &n);
    TK_ASSERT(v != NULL && n == 1 + 2 * 8 && v[0] == 0x90 && v[2] == 'F' && v[16] == 't');
    v = nas_msg_get(&m, "Short name for network", &n);
    TK_ASSERT(v != NULL && n == 1 + 2 * 3);
    v = nas_msg_get(&m, "Universal time and local time zone", &n);
    TK_ASSERT(v != NULL && n == 7 && v[6] == 0);
    TK_ASSERT(nas_msg_get(&m, "Local time zone", &n) != NULL);
    TK_ASSERT(nas_msg_get(&m, "5G-GUTI", &n) == NULL); /* nothing to acknowledge */
    nas_free(&m);
    g5c_bytes_free(&plain);
    gnb_close(&g);
    (void)unlink(E.amf_state);
    stop_amf();
    start_amf(NULL);
}

/* time warp (backlog B-12): the T3560 sequence of five transmissions takes 5 s of the AMF's clock; at a warp of 25 the test sees it in about a fifth of a second */
static void test_time_warp(void)
{
    gnb_t g;
    ue_t u;
    g5c_bytes req;
    g5c_json *p;
    int rx = 0;
    double t0, took;
    ue_init(&u, "001010000000061", 61);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    g5c_time_warp_set(25);
    TK_ASSERT(g5c_time_warp() == 25.0);
    t0 = now_s();
    g5c_bytes_init(&req);
    build_reg_request(&u, 1, false, &req);
    gnb_initial_ue(&g, &u, req.data, req.len, 1, false);
    g5c_bytes_free(&req);
    for (;;) {
        p = gnb_rx(&g, 3000);
        TK_ASSERT(p != NULL);
        if (proc_of(p) == NGAP_PROC_UEContextRelease) {
            g5c_json_free(p);
            break;
        }
        learn_ids(&u, p);
        g5c_json_free(p);
        rx++;
    }
    took = now_s() - t0;
    g5c_time_warp_set(1);
    TK_ASSERT(rx == 5);   /* the same behaviour: the request and four retransmissions, then the release */
    TK_ASSERT(took < 1.5); /* ... in a fraction of the 5 s it takes in real time */
    {
        g5c_json *rc = new_pdu("successfulOutcome", NGAP_PROC_UEContextRelease, "reject");
        add_ie(rc, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)u.amf_id));
        add_ie(rc, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(u.ran_id));
        gnb_tx(&g, rc, 1);
    }
    TK_ASSERT(wait_ue_gone(u.supi));
    gnb_close(&g);
}

static void test_timers(void)
{
    gnb_t g;
    ue_t u;
    g5c_bytes req, plain;
    int rx_count = 0;
    g5c_json *p;
    ue_init(&u, "001010000000019", 19);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);

    /* T3560: an authentication request that is never answered is repeated four times, then the procedure is aborted and the connection released */
    g5c_bytes_init(&req);
    build_reg_request(&u, 1, false, &req);
    gnb_initial_ue(&g, &u, req.data, req.len, 1, false);
    g5c_bytes_free(&req);
    for (;;) {
        p = gnb_rx(&g, 3000);
        TK_ASSERT(p != NULL);
        if (proc_of(p) == NGAP_PROC_UEContextRelease) {
            g5c_json_free(p);
            break;
        }
        TK_ASSERT(proc_of(p) == NGAP_PROC_DownlinkNASTransport);
        learn_ids(&u, p);
        {
            uint8_t *nas;
            size_t n;
            nas_any a;
            TK_ASSERT(nas_of(p, &nas, &n));
            TK_ASSERT(nas_any_decode(nas, n, &a) == NAS_OK && a.plain.def->msg_type == 0x56);
            nas_any_free(&a);
            free(nas);
        }
        g5c_json_free(p);
        rx_count++;
    }
    TK_ASSERT(rx_count == 5); /* the request and four retransmissions */
    {
        g5c_json *rc = new_pdu("successfulOutcome", NGAP_PROC_UEContextRelease, "reject");
        add_ie(rc, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)u.amf_id));
        add_ie(rc, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(u.ran_id));
        gnb_tx(&g, rc, 1);
    }
    (void)plain;

    /* T3550: a registration accept the UE never completes is repeated, then the registration is dropped */
    {
        auth_req_t a;
        accept_info ai;
        g5c_bytes pl;
        g5c_json *ics;
        int accepts = 0;
        u.ran_id = 20;
        g5c_bytes_init(&req);
        build_reg_request(&u, 1, false, &req);
        memcpy(u.reg_req, req.data, req.len);
        u.reg_len = req.len;
        gnb_initial_ue(&g, &u, req.data, req.len, 1, false);
        g5c_bytes_free(&req);
        pl = dl_nas(&g, &u);
        TK_ASSERT(parse_auth_request(&pl, &a));
        g5c_bytes_free(&pl);
        ue_answer_auth(&g, &u, &a, 1, AUTH_OK);
        (void)ue_handle_smc(&g, &u, 1, 1);
        pl = ue_receive_ics(&g, &u, u.smc_ul, &ics);
        memset(&ai, 0, sizeof ai);
        parse_accept(&u, &pl, &ai);
        g5c_bytes_free(&pl);
        g5c_json_free(ics);
        accepts++;
        gnb_ics_response(&g, &u, NULL);
        for (;;) {
            p = gnb_rx(&g, 3000);
            TK_ASSERT(p != NULL);
            if (proc_of(p) == NGAP_PROC_UEContextRelease) {
                g5c_json_free(p);
                break;
            }
            TK_ASSERT(proc_of(p) == NGAP_PROC_DownlinkNASTransport);
            learn_ids(&u, p);
            g5c_json_free(p);
            accepts++;
        }
        TK_ASSERT(accepts == 5);
        {
            g5c_json *rc = new_pdu("successfulOutcome", NGAP_PROC_UEContextRelease, "reject");
            add_ie(rc, NGAP_IE_AMF_UE_NGAP_ID, "ignore", g5c_json_new_int((int64_t)u.amf_id));
            add_ie(rc, NGAP_IE_RAN_UE_NGAP_ID, "ignore", g5c_json_new_int(u.ran_id));
            gnb_tx(&g, rc, 1);
        }
        TK_ASSERT(wait_ue_gone(u.supi)); /* never registered: nothing is kept */
    }
    gnb_close(&g);
}

static void test_implicit_deregistration(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    sess_t s;
    size_t s0, loss_before;
    /* a short T3512 with a one second grace: an idle UE that does not show up is de-registered implicitly */
    stop_amf();
    (void)unlink(E.amf_state);
    g_t3512 = 1;
    start_amf(NULL);
    ue_init(&u, "001010000000020", 20);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);
    {   /* a subscriber to the loss of connectivity of any UE */
        char body[400], url[300];
        g5c_resp r;
        snprintf(body, sizeof body, "{\"subscription\":{\"eventList\":[{\"type\":\"LOSS_OF_CONNECTIVITY\"}],\"eventNotifyUri\":\"%s/events\",\"notifyCorrelationId\":\"corr-loss\",\"nfId\":\"nf-e2e\",\"anyUE\":true}}", E.cb_base);
        snprintf(url, sizeof url, "%s/namf-evts/v1/subscriptions", E.amf_base);
        pthread_mutex_lock(&cb_mu);
        loss_before = cb_n;
        pthread_mutex_unlock(&cb_mu);
        TK_ASSERT(http("POST", url, G5C_JSON_TYPE, body, strlen(body), &r, false) == 201);
        g5c_resp_free(&r);
    }
    s0 = smf_session_count(E.s);
    s = ue_establish(&g, &u, 1, 0xb001, 1);
    (void)s;
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1) && smf_has(s0 + 1));
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));
    {
        double end = now_s() + 6;
        amf_ue_info info;
        while (now_s() < end && amf_ue_lookup(E.a, u.supi, &info))
            usleep(20000);
        TK_ASSERT(!amf_ue_lookup(E.a, u.supi, &info));
    }
    TK_ASSERT(smf_has(s0)); /* the session went with the context */
    {   /* the loss of connectivity was reported, with the reason of an implicit de-registration */
        bool found = false;
        double end = now_s() + 3;
        while (!found && now_s() < end) {
            pthread_mutex_lock(&cb_mu);
            for (size_t i = loss_before; i < cb_n; i++)
                if (strstr(cb_last[i], "LOSS_OF_CONNECTIVITY") != NULL && strstr(cb_last[i], "MAX_DETECTION_TIME_EXPIRED") != NULL && strstr(cb_last[i], "corr-loss") != NULL)
                    found = true;
            pthread_mutex_unlock(&cb_mu);
            if (!found)
                usleep(10000);
        }
        TK_ASSERT(found);
    }
    gnb_close(&g);
    stop_amf();
    g_t3512 = 3600;
    start_amf(NULL);
}

static void test_persistence(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    sess_t s;
    svc_info si;
    g5c_bytes req;
    amf_stats st;
    amf_ue_info info;
    uint8_t psis[1] = {1};
    uint32_t teids[1] = {0xc002};
    ue_init(&u, "001010000000021", 21);
    ue_provision(&u, NULL);
    gnb_setup_ok(&g, 0, 1, 1);
    ai = ue_register(&g, &u, 1);
    accept_free(&ai);
    s = ue_establish(&g, &u, 1, 0xc001, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1));
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));
    gnb_close(&g);
    usleep(200000); /* the state file is written by a deferred task */
    stop_amf();
    start_amf(NULL);
    TK_ASSERT(amf_ue_lookup(E.a, u.supi, &info) && info.registered && !info.connected && info.npdu == 1 && info.tmsi == u.tmsi);

    /* the restored context serves the UE's service request without authentication; the downlink count stays above what the UE expects */
    gnb_setup_ok(&g, 0, 1, 1);
    u.ran_id = 210;
    g5c_bytes_init(&req);
    build_service_request(&u, 1, (uint16_t)(1u << 1), true, &req);
    gnb_initial_ue(&g, &u, req.data, req.len, 1, true);
    g5c_bytes_free(&req);
    ue_receive_service_accept(&g, &u, u.last_ul, &si);
    TK_ASSERT(si.nitems == 1 && si.items[0].upf_teid == s.upf_teid);
    svc_free(&si);
    gnb_ics_response_sessions(&g, &u, psis, teids, 1);
    TK_ASSERT(wait_ue(u.supi, 1, 1, 1));
    check_user_plane(0, &s, 0xc002);
    amf_get_stats(E.a, &st);
    TK_ASSERT(st.auth_ok == 0 && st.service_requests == 1);
    gnb_close(&g);
}

/* ---- power saving: MICO mode, extended DRX, the active timer T3324 ---- */

/* the SMF's N1N2MessageTransfer for an idle UE, as in test_paging_failure; returns the HTTP status */
static int n1n2_transfer(const char *supi)
{
    g5c_resp r;
    char url[300], body[900];
    g5c_mp_part parts[2];
    g5c_bytes mp;
    char *ct;
    int st;
    static const uint8_t junk[] = {0x00, 0x01, 0x02};
    snprintf(body, sizeof body,
             "{\"pduSessionId\":1,\"n1n2FailureTxfNotifURI\":\"%s/n1n2-failure\",\"n2InfoContainer\":{\"n2InformationClass\":\"SM\",\"smInfo\":{\"pduSessionId\":1,"
             "\"n2InfoContent\":{\"ngapIeType\":\"PDU_RES_SETUP_REQ\",\"ngapData\":{\"contentId\":\"n2SmInfo\"}}}}}",
             E.cb_base);
    parts[0] = (g5c_mp_part){NULL, "application/json", (const uint8_t *)body, strlen(body)};
    parts[1] = (g5c_mp_part){"n2SmInfo", "application/vnd.3gpp.ngap", junk, sizeof junk};
    g5c_bytes_init(&mp);
    TK_ASSERT(g5c_mp_build(parts, 2, &mp, &ct) == 0);
    snprintf(url, sizeof url, "%s/namf-comm/v1/ue-contexts/%s/n1-n2-messages", E.amf_base, supi);
    st = http("POST", url, ct, mp.data, mp.len, &r, false);
    g5c_resp_free(&r);
    g5c_bytes_free(&mp);
    free(ct);
    return st;
}

static bool wait_failure_notif(int before, double secs)
{
    double end = now_s() + secs;
    while (atomic_load(&cb_failure_notifs) == before && now_s() < end)
        usleep(10000);
    return atomic_load(&cb_failure_notifs) == before + 1;
}

static void test_power_saving(void)
{
    gnb_t g;
    ue_t u;
    accept_info ai;
    g5c_json *p;
    int before;
    gnb_setup_ok(&g, 0, 1, 1);

    /* MICO: asked and granted; the idle UE is not paged, the SMF's transfer fails at once with UE_NOT_REACHABLE */
    ue_init(&u, "001010000000091", 91);
    ue_provision(&u, NULL);
    u.req_mico = true;
    ai = ue_register(&g, &u, 1);
    TK_ASSERT(ai.mico && !ai.has_edrx && !ai.has_t3324);
    accept_free(&ai);
    ue_establish(&g, &u, 1, 0x4001, 1);
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));
    before = atomic_load(&cb_failure_notifs);
    TK_ASSERT(n1n2_transfer(u.supi) == 202);
    TK_ASSERT(wait_failure_notif(before, 2));
    TK_ASSERT(gnb_rx(&g, 600) == NULL); /* nothing was paged */

    /* not granted when the AMF does not allow it, and the UE is paged as usual */
    E.a->cfg.ps_mico = false;
    ue_init(&u, "001010000000092", 92);
    ue_provision(&u, NULL);
    u.req_mico = true;
    ai = ue_register(&g, &u, 1);
    TK_ASSERT(!ai.mico);
    accept_free(&ai);
    ue_establish(&g, &u, 1, 0x4001, 1);
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));
    TK_ASSERT(n1n2_transfer(u.supi) == 202);
    p = rx_expect(&g, NGAP_PROC_Paging, "initiatingMessage", 3000);
    TK_ASSERT(ie_of(p, NGAP_IE_PagingeDRXInformation) == NULL);
    g5c_json_free(p);
    p = rx_expect(&g, NGAP_PROC_Paging, "initiatingMessage", 3000); /* the repetition, T3513 later */
    g5c_json_free(p);
    E.a->cfg.ps_mico = true;

    /* extended DRX: the cycle is cut to the longest the AMF grants (index 9 = 163.84 s), the window stays, and the paging carries both */
    E.a->cfg.ps_edrx_max = 9;
    ue_init(&u, "001010000000093", 93);
    ue_provision(&u, NULL);
    u.req_edrx = true;
    u.edrx = (uint8_t)(3 << 4 | 12);
    ai = ue_register(&g, &u, 1);
    TK_ASSERT(!ai.mico && ai.has_edrx && ai.edrx == (3 << 4 | 9));
    accept_free(&ai);
    ue_establish(&g, &u, 1, 0x4001, 1);
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));
    TK_ASSERT(n1n2_transfer(u.supi) == 202);
    p = rx_expect(&g, NGAP_PROC_Paging, "initiatingMessage", 3000);
    {
        const g5c_json *e = ie_of(p, NGAP_IE_PagingeDRXInformation);
        TK_ASSERT(e != NULL && strcmp(g5c_json_get_str(e, "paging-eDRX-Cycle"), "hf16") == 0 && strcmp(g5c_json_get_str(e, "paging-Time-Window"), "s4") == 0);
    }
    g5c_json_free(p);
    p = rx_expect(&g, NGAP_PROC_Paging, "initiatingMessage", 3000);
    g5c_json_free(p);
    E.a->cfg.ps_edrx_max = 13;

    /* power saving mode: T3324 of 2 s is granted; paged inside it, not after it */
    ue_init(&u, "001010000000094", 94);
    ue_provision(&u, NULL);
    u.t3324 = (uint8_t)(3 << 5 | 1);
    ai = ue_register(&g, &u, 1);
    TK_ASSERT(ai.has_t3324 && ai.t3324 == (3 << 5 | 1));
    accept_free(&ai);
    ue_establish(&g, &u, 1, 0x4001, 1);
    gnb_release_request(&g, &u, "user-inactivity");
    TK_ASSERT(wait_ue(u.supi, 1, 0, 1));
    TK_ASSERT(n1n2_transfer(u.supi) == 202);
    p = rx_expect(&g, NGAP_PROC_Paging, "initiatingMessage", 3000);
    g5c_json_free(p);
    p = rx_expect(&g, NGAP_PROC_Paging, "initiatingMessage", 3000); /* the repetition, T3513 later */
    g5c_json_free(p);
    before = atomic_load(&cb_failure_notifs);
    TK_ASSERT(wait_failure_notif(before, 5)); /* nobody answers this paging: the usual failure */
    usleep(2300000);                          /* T3324 has run out */
    before = atomic_load(&cb_failure_notifs);
    TK_ASSERT(n1n2_transfer(u.supi) == 202);
    TK_ASSERT(wait_failure_notif(before, 1));
    p = gnb_rx(&g, 600);
    if (p != NULL)
        fprintf(stderr, "STRAY %.300s\n", g5c_json_to_string(p, NULL));
    TK_ASSERT(p == NULL);

    /* the AMF's own ceiling for T3324: 60 s asked, 2 s granted */
    E.a->cfg.ps_t3324_max = 2;
    ue_init(&u, "001010000000095", 95);
    ue_provision(&u, NULL);
    u.t3324 = (uint8_t)(5 << 5 | 1);
    ai = ue_register(&g, &u, 1);
    TK_ASSERT(ai.has_t3324 && ai.t3324 == (3 << 5 | 1));
    accept_free(&ai);
    ue_switch_off(&g, &u);
    E.a->cfg.ps_t3324_max = 600;
    gnb_close(&g);
}

/* ---- network slice admission control ---- */

#define SLICES2 ",\"slices\":[{\"sst\":1},{\"sst\":2,\"sd\":\"000002\"}]"

static void test_slice_admission(void)
{
    static const uint8_t both[] = {0x01, 0x01, 0x04, 0x02, 0x00, 0x00, 0x02}; /* slice 1 and slice 2 / 000002 */
    gnb_t g;
    ue_t a, b, c;
    accept_info ai;
    size_t held = 0;
    nas_snssai s2 = {.sst = 2, .has_sd = true, .sd = 2};
    gnb_setup_ok(&g, 0, 1, 1);
    pthread_mutex_lock(&E.a->tmu);
    for (const amf_ue *v = E.a->ues; v != NULL; v = v->next_all)
        held += v->mm == MM_REGISTERED && amf_snssai_in(v->allowed, v->nallowed, &s2);
    pthread_mutex_unlock(&E.a->tmu);
    E.a->cfg.nslice_limit = 1;
    E.a->cfg.slice_limit[0].s = s2;
    E.a->cfg.slice_limit[0].max_ues = (unsigned)held + 1; /* room for exactly one more */

    ue_init(&a, "001010000000096", 96);
    ue_provision(&a, SLICES2);
    memcpy(a.nssai, both, sizeof both);
    a.nssai_len = sizeof both;
    ai = ue_register(&g, &a, 1);
    TK_ASSERT(ai.nallowed == 2);
    accept_free(&ai);

    ue_init(&b, "001010000000097", 97);
    ue_provision(&b, SLICES2);
    memcpy(b.nssai, both, sizeof both);
    b.nssai_len = sizeof both;
    ai = ue_register(&g, &b, 1);
    TK_ASSERT(ai.nallowed == 1 && ai.allowed[0].sst == 1); /* the full slice is left out */
    accept_free(&ai);

    ue_switch_off(&g, &a); /* a place is free again */
    ue_init(&c, "001010000000098", 98);
    ue_provision(&c, SLICES2);
    memcpy(c.nssai, both, sizeof both);
    c.nssai_len = sizeof both;
    ai = ue_register(&g, &c, 1);
    TK_ASSERT(ai.nallowed == 2);
    accept_free(&ai);
    E.a->cfg.nslice_limit = 0;
    gnb_close(&g);
}

int main(void)
{
    g5c_log_init("error", false);
    setup();
    test_ng_setup();
    test_registration();
    test_auth_failures();
    test_privacy();
    test_congestion();
    test_eap_registration();
    test_sessions();
    test_idle_service_paging();
    test_paging_failure();
    test_power_saving();
    test_slice_admission();
    test_context_reuse();
    test_network_initiated();
    test_association_loss();
    test_events();
    test_sbi_errors();
    test_path_switch();
    test_n2_handover();
    test_handover_failure();
    test_algorithms_and_rejects();
    test_uplink_protection();
    test_registration_update_and_replacement();
    test_network_name();
    test_time_warp();
    test_timers();
    test_implicit_deregistration();
    test_persistence();
    teardown();
    printf("amf e2e: OK\n");
    return 0;
}
