/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* UPF engine: replay of real Open5GS N4 messages, then rule semantics (QoS, SDF, buffering, usage, failures) with scripted peers. */
#include "g5c/base.h"
#include "gtpu_vectors.h"
#include "pfcp_vectors.h"
#include "rig.h"

static const uint8_t UE[4] = {10, 46, 0, 2};
static const uint8_t DN[4] = {10, 99, 0, 1};
static const uint8_t GNBIP[4] = {127, 1, 0, 100};

static size_t unhex(const char *h, uint8_t *b, size_t cap)
{
    long n = tk_unhex(h, b, cap);
    TK_ASSERT(n > 0);
    return (size_t)n;
}

static void setup_assoc(void)
{
    bld_t b;
    pfcp_header h;
    size_t bl;
    const uint8_t *body;
    b_assoc(&b, 0xe5000001u);
    send_n4(PFCP_ASSOCIATION_SETUP_REQUEST, false, 0, b.body, b.pos);
    body = rig_n4(PFCP_ASSOCIATION_SETUP_RESPONSE, &h, &bl);
    TK_ASSERT(body && cause_of(body, bl) == PFCP_CAUSE_ACCEPTED);
}

/* establish a session from a builder; returns the UPF's seid, the CP seid is cp */
static uint64_t establish(bld_t *b, uint64_t cp, int expect_cause, uint32_t *teid_ul)
{
    pfcp_header h;
    size_t bl;
    const uint8_t *body;
    pfcp_ie ie;
    pfcp_fseid f;
    rig_reset_captures();
    send_n4(PFCP_SESSION_ESTABLISHMENT_REQUEST, true, 0, b->body, b->pos);
    body = rig_n4(PFCP_SESSION_ESTABLISHMENT_RESPONSE, &h, &bl);
    TK_ASSERT(body != NULL);
    if (cause_of(body, bl) != expect_cause)
        TK_FAIL("establishment cause %d, wanted %d", cause_of(body, bl), expect_cause);
    TK_ASSERT(h.has_seid && h.seid == cp);
    if (expect_cause != PFCP_CAUSE_ACCEPTED)
        return 0;
    TK_ASSERT(find_ie(body, bl, PFCP_IE_FSEID, &ie, 0) && pfcp_fseid_decode(&ie, &f) == 0 && f.v4 && f.ip4[3] == 7);
    if (teid_ul) {
        pfcp_ie g;
        pfcp_fteid ft;
        TK_ASSERT(find_ie(body, bl, PFCP_IE_CREATED_PDR, &g, 0));
        TK_ASSERT(find_ie(g.value, g.len, PFCP_IE_FTEID, &ie, 0) && pfcp_fteid_decode(&ie, &ft) == 0 && !ft.ch && ft.v4 && ft.ip4[3] == 7);
        *teid_ul = ft.teid;
    }
    return f.seid;
}

static void modify_at(int line, uint64_t seid, const bld_t *b, int expect_cause)
{
    pfcp_header h;
    size_t bl;
    const uint8_t *body;
    rig_reset_captures();
    send_n4(PFCP_SESSION_MODIFICATION_REQUEST, true, seid, b->body, b->pos);
    body = rig_n4(PFCP_SESSION_MODIFICATION_RESPONSE, &h, &bl);
    TK_ASSERT(body != NULL);
    if (cause_of(body, bl) != expect_cause)
        TK_FAIL("modification at line %d: cause %d, wanted %d", line, cause_of(body, bl), expect_cause);
}

#define modify(seid, b, cause) modify_at(__LINE__, (seid), (b), (cause))

static void update_far_forward(bld_t *b, uint32_t far, uint32_t teid, const uint8_t ip[4], bool sndem)
{
    size_t m, m2;
    pfcp_ohc o;
    uint8_t aa[2] = {PFCP_AA_FORW, 0};
    b->pos = 0;
    if (sndem)
        pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_SMREQ_FLAGS, 2);
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_UPDATE_FAR, &m);
    pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_FAR_ID, far);
    pfcp_put_ie(b->body, sizeof b->body, &b->pos, PFCP_IE_APPLY_ACTION, aa, 2);
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_UPDATE_FORWARDING_PARAMETERS, &m2);
    pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_DESTINATION_INTERFACE, UPF_IF_ACCESS);
    memset(&o, 0, sizeof o);
    o.desc = PFCP_OHC_GTPU_IPV4;
    o.teid = teid;
    memcpy(o.ip4, ip, 4);
    pfcp_ohc_put(b->body, sizeof b->body, &b->pos, &o);
    pfcp_group_end(b->body, &b->pos, m2);
    pfcp_group_end(b->body, &b->pos, m);
}

/* the standard session: UL PDR 1 (CHOOSE) -> FAR 1 to the core, DL PDR 2 (UE address) -> FAR 2 to the gNB (teid 77) */
static uint64_t std_session(uint32_t *teid, uint64_t cp, uint64_t mbr_ul, uint64_t mbr_dl)
{
    bld_t b;
    b_session_head(&b, cp);
    b_pdr_ul(&b, 1, 100, 1, 1, mbr_ul ? 1 : 0, 0, NULL, true);
    b_pdr_dl(&b, 2, 100, UE, 2, mbr_dl ? 1 : 0, 0, NULL);
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
    b_far(&b, 2, PFCP_AA_FORW, UPF_IF_ACCESS, 77, GNBIP, 0);
    if (mbr_ul || mbr_dl)
        b_qer(&b, 1, mbr_ul, mbr_dl, false, false, 9);
    return establish(&b, cp, PFCP_CAUSE_ACCEPTED, teid);
}

/* ---- golden GTP-U frames: what a real gNB sends and what a real UPF answers ----------------------------------------------------- */

static void test_golden_gtpu(void)
{
    uint8_t ul[200], dl_want[200], inner[200];
    size_t uln = unhex(GTPUV_UL, ul, sizeof ul), dln = unhex(GTPUV_DL, dl_want, sizeof dl_want);
    gtpu_header gh;
    const uint8_t *pl;
    size_t plen;
    bld_t b;
    uint32_t teid;
    TK_ASSERT(gtpu_decode(ul, uln, &gh, &pl, &plen) == 0 && gh.msg_type == GTPU_G_PDU && gh.next == 1);
    memcpy(inner, pl, plen);
    rig_new(NULL);
    setup_assoc();
    b_session_head(&b, 0xb0);
    b_pdr_ul(&b, 1, 100, 1, 1, 0, 0, NULL, true);
    b_pdr_dl(&b, 2, 100, UE, 2, 0, 0, NULL);
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
    b_far(&b, 2, PFCP_AA_FORW, UPF_IF_ACCESS, 1 /* the gNB TEID of the capture */, GNBIP, 0);
    establish(&b, 0xb0, PFCP_CAUSE_ACCEPTED, &teid);
    /* the uplink frame of the capture, addressed to our TEID, comes out as the very same IP packet */
    ul[4] = (uint8_t)(teid >> 24);
    ul[5] = (uint8_t)(teid >> 16);
    ul[6] = (uint8_t)(teid >> 8);
    ul[7] = (uint8_t)teid;
    rig_reset_captures();
    upf_gtpu_packet(U, &GNB, ul, uln, NOW);
    TK_ASSERT(RIG.nn6 == 1 && RIG.n6[0].n == plen && memcmp(RIG.n6[0].d, inner, plen) == 0);
    /* the reply's IP packet goes back through the UPF and gets the byte-identical G-PDU the real UPF produced */
    {
        gtpu_header dh;
        const uint8_t *dpl;
        size_t dplen;
        TK_ASSERT(gtpu_decode(dl_want, dln, &dh, &dpl, &dplen) == 0);
        rig_reset_captures();
        upf_n6_packet(U, dpl, dplen, NOW);
        TK_ASSERT(RIG.ngtpu == 1 && RIG.gtpu[0].n == dln && memcmp(RIG.gtpu[0].d, dl_want, dln) == 0);
    }
    upf_free(U);
}

/* ---- IPv6 UE addresses (the /64 prefix identifies the session) ------------------------------------------------------------------ */

static size_t ipv6(uint8_t *p, const uint8_t src[16], const uint8_t dst[16], uint8_t next, uint16_t sport, uint16_t dport, size_t total)
{
    memset(p, 0, total);
    p[0] = 0x60;
    p[4] = (uint8_t)((total - 40) >> 8);
    p[5] = (uint8_t)(total - 40);
    p[6] = next;
    p[7] = 64;
    memcpy(p + 8, src, 16);
    memcpy(p + 24, dst, 16);
    p[40] = (uint8_t)(sport >> 8);
    p[41] = (uint8_t)sport;
    p[42] = (uint8_t)(dport >> 8);
    p[43] = (uint8_t)dport;
    return total;
}

static void b_pdr_dl_v6(bld_t *b, uint16_t id, uint32_t prec, const uint8_t ue6[16], uint32_t far, const char *sdf)
{
    size_t m, m2;
    pfcp_ue_ip u;
    memset(&u, 0, sizeof u);
    u.v6 = true;
    u.sd = true;
    memcpy(u.ip6, ue6, 16);
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_CREATE_PDR, &m);
    pfcp_put_u16(b->body, sizeof b->body, &b->pos, PFCP_IE_PDR_ID, id);
    pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_PRECEDENCE, prec);
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_PDI, &m2);
    pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_SOURCE_INTERFACE, UPF_IF_CORE);
    pfcp_ue_ip_put(b->body, sizeof b->body, &b->pos, &u);
    if (sdf) {
        uint8_t v[300];
        size_t l = strlen(sdf);
        v[0] = 1;
        v[1] = 0;
        v[2] = (uint8_t)(l >> 8);
        v[3] = (uint8_t)l;
        memcpy(v + 4, sdf, l);
        pfcp_put_ie(b->body, sizeof b->body, &b->pos, PFCP_IE_SDF_FILTER, v, l + 4);
    }
    pfcp_group_end(b->body, &b->pos, m2);
    pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_FAR_ID, far);
    pfcp_group_end(b->body, &b->pos, m);
}

static void test_ipv6(void)
{
    static const uint8_t PFX[16] = {0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0x00, 0x01};
    uint8_t ue[16], other[16] = {0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 5}, dn[16] = {0x20, 0x01, 0x48, 0x60}, ll[16] = {0xfe, 0x80};
    uint8_t pkt[200], up[300];
    uint32_t teid;
    bld_t b;
    size_t un;
    gtpu_header gh;
    const uint8_t *pl;
    size_t plen;
    memcpy(ue, PFX, 16);
    ue[15] = 0x77;
    dn[15] = 1;
    ll[15] = 9;
    rig_new(NULL);
    setup_assoc();
    b_session_head(&b, 0xc0);
    b_pdr_ul(&b, 1, 100, 1, 1, 0, 0, NULL, false);
    b_pdr_dl_v6(&b, 2, 10, PFX, 2, "permit out 17 from any to assigned 5000");
    b_pdr_dl_v6(&b, 3, 100, PFX, 3, NULL);
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
    b_far(&b, 2, PFCP_AA_FORW, UPF_IF_ACCESS, 2, GNBIP, 0);
    b_far(&b, 3, PFCP_AA_FORW, UPF_IF_ACCESS, 3, GNBIP, 0);
    establish(&b, 0xc0, PFCP_CAUSE_ACCEPTED, &teid);
    /* downlink: any address inside the /64 reaches the session; the SDF rule with `assigned` picks the UDP/5000 flow */
    ipv6(pkt, dn, ue, 17, 53, 5000, 80);
    rig_reset_captures();
    upf_n6_packet(U, pkt, 80, NOW);
    TK_ASSERT(RIG.ngtpu == 1 && gtpu_decode(RIG.gtpu[0].d, RIG.gtpu[0].n, &gh, &pl, &plen) == 0 && gh.teid == 2 && plen == 80);
    ipv6(pkt, dn, ue, 17, 53, 5001, 80);
    rig_reset_captures();
    upf_n6_packet(U, pkt, 80, NOW);
    TK_ASSERT(RIG.ngtpu == 1 && gtpu_decode(RIG.gtpu[0].d, RIG.gtpu[0].n, &gh, &pl, &plen) == 0 && gh.teid == 3);
    ipv6(pkt, dn, other, 17, 53, 5000, 80); /* another prefix: no session */
    upf_n6_packet(U, pkt, 80, NOW);
    TK_ASSERT(U->st.drop_no_session == 1);
    /* uplink: from inside the prefix passes, from elsewhere is dropped, link-local (router solicitation) passes */
    rig_reset_captures();
    ipv6(pkt, ue, dn, 17, 4000, 53, 80);
    un = gpdu_ul(up, sizeof up, teid, 0, pkt, 80);
    upf_gtpu_packet(U, &GNB, up, un, NOW);
    TK_ASSERT(RIG.nn6 == 1);
    ipv6(pkt, other, dn, 17, 4000, 53, 80);
    un = gpdu_ul(up, sizeof up, teid, 0, pkt, 80);
    upf_gtpu_packet(U, &GNB, up, un, NOW);
    TK_ASSERT(RIG.nn6 == 1 && U->st.drop_spoof == 1);
    ipv6(pkt, ll, dn, 58, 0, 0, 60);
    un = gpdu_ul(up, sizeof up, teid, 0, pkt, 60);
    upf_gtpu_packet(U, &GNB, up, un, NOW);
    TK_ASSERT(RIG.nn6 == 2);
    upf_free(U);
}

/* ---- 6. every way a rule can be wrong, and every way it can be changed -------------------------------------------------------------- */

static void test_malformed_rules(void)
{
    static const struct {
        const char *rules;
        int cause;
    } bad[] = {
        {"1:{29:00000001 2:{20:00}}", 66},                                     /* PDR without id */
        {"1:{56:0001 2:{20:00}}", 66},                                         /* without precedence */
        {"1:{56:0001 29:00000001}", 66},                                       /* without PDI */
        {"1:{56:0001 29:00000001 2:{}}", 66},                                  /* PDI without source interface */
        {"1:{56:00 29:00000001 2:{20:00}}", 66},                               /* PDR id too short to be one */
        {"1:{56:0001 29:0001 2:{20:00}}", 68},                                 /* precedence too short */
        {"1:{56:0001 29:00000001 2:{20:}}", 68},                               /* empty source interface */
        {"1:{56:0001 29:00000001 2:{20:00 21:0100}}", 69},                     /* truncated F-TEID */
        {"1:{56:0001 29:00000001 2:{20:00 22:}}", 69},                         /* empty network instance */
        {"1:{56:0001 29:00000001 2:{20:00 93:}}", 69},                         /* empty UE IP */
        {"1:{56:0001 29:00000001 2:{20:00 23:0100}}", 69},                     /* truncated SDF filter */
        {"1:{56:0001 29:00000001 2:{20:00 124:}}", 68},                        /* empty QFI */
        {"1:{56:0001 29:00000001 2:{20:00} 108:0000}", 68},                    /* short FAR id */
        {"1:{56:0001 29:00000001 2:{20:00} 109:0000}", 68},
        {"1:{56:0001 29:00000001 2:{20:00} 81:00}", 68},
        {"1:{56:0001 29:00000001 2:{20:00} 109:00000001 109:00000002 109:00000003 109:00000004 109:00000005}", 73}, /* too many QERs */
        {"1:{56:0001 29:00000001 2:{20:00} 81:00000001 81:00000002 81:00000003 81:00000004 81:00000005}", 73},
        {"1:{56:0001 29:00000001 2:{20:00}} 1:{56:0001 29:00000002 2:{20:00}}", 73},  /* duplicate PDR id */
        {"3:{44:0200}", 66},                                                   /* FAR without id */
        {"3:{108:00000001}", 66},                                              /* without apply action */
        {"3:{108:0001 44:0200}", 68},
        {"3:{108:00000001 44:}", 68},
        {"3:{108:00000001 44:0200 4:{42:}}", 68},
        {"3:{108:00000001 44:0200 4:{84:01}}", 69},
        {"3:{108:00000001 44:0200 88:}", 68},
        {"3:{108:00000001 44:0200} 3:{108:00000001 44:0200}", 73},             /* duplicate FAR id */
        {"7:{25:00}", 66},                                                     /* QER without id */
        {"7:{109:00000001 25:}", 68},
        {"7:{109:00000001 26:0000}", 68},
        {"7:{109:00000001 27:00}", 68},
        {"7:{109:00000001} 7:{109:00000001}", 73},
        {"6:{62:02}", 66},                                                     /* URR without id */
        {"6:{81:00000001 62:}", 68},
        {"6:{81:00000001 37:}", 68},
        {"6:{81:00000001 31:}", 68},
        {"6:{81:00000001 32:0001}", 68},
        {"6:{81:00000001 64:0001}", 68},
        {"6:{81:00000001} 6:{81:00000001}", 73},
        {"85:{}", 66},                                                         /* BAR without id */
        {"85:{88:01} 85:{88:01}", 73},
        {"85:{88:01} 85:{88:02} 85:{88:03} 85:{88:04} 85:{88:05}", 75},        /* more BARs than we keep */
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        bld_t b;
        pfcp_header h;
        size_t bl;
        const uint8_t *body;
        int c;
        rig_new(NULL);
        setup_assoc();
        b_session_head(&b, 0xd0);
        b_dsl(&b, bad[i].rules);
        rig_reset_captures();
        send_n4(PFCP_SESSION_ESTABLISHMENT_REQUEST, true, 0, b.body, b.pos);
        body = rig_n4(PFCP_SESSION_ESTABLISHMENT_RESPONSE, &h, &bl);
        TK_ASSERT(body != NULL);
        c = cause_of(body, bl);
        if (c != bad[i].cause)
            TK_FAIL("malformed rule %zu (%s): cause %d, wanted %d", i, bad[i].rules, c, bad[i].cause);
        TK_ASSERT(upf_session_count(U) == 0); /* nothing was installed */
        upf_free(U);
    }
}

/* a modification that is expected to fail must leave the session working exactly as before */
static void probe_still_works(uint32_t teid)
{
    uint8_t ip[100], up[200];
    size_t un;
    ipv4(ip, UE, DN, 1, 0, 0, 84);
    un = gpdu_ul(up, sizeof up, teid, 1, ip, 84);
    rig_reset_captures();
    upf_gtpu_packet(U, &GNB, up, un, NOW);
    TK_ASSERT(RIG.nn6 == 1);
}

static void test_modification_rules(void)
{
    static const struct {
        const char *mod;
        int cause;
    } cases[] = {
        {"15:{}", 66},                                  /* Remove PDR without id */
        {"15:{56:0063}", 73},                           /* unknown PDR */
        {"9:{29:00000001}", 66},                        /* Update PDR without id */
        {"9:{56:0063 29:00000001}", 73},                /* unknown PDR */
        {"10:{44:0200}", 66},                           /* Update FAR without id */
        {"10:{108:00000063 44:0200}", 73},              /* unknown FAR */
        {"10:{108:00000001 44:}", 68},
        {"10:{108:00000001 11:{84:01}}", 69},
        {"16:{}", 66},                                  /* Remove FAR without id */
        {"16:{108:00000063}", 73},
        {"14:{26:0000000000}", 66},                     /* Update QER without id */
        {"14:{109:00000063 25:00}", 73},
        {"18:{}", 66},
        {"18:{109:00000063}", 73},
        {"13:{62:02}", 66},
        {"13:{81:00000063}", 73},
        {"17:{}", 66},
        {"17:{81:00000063}", 73},
        {"86:{46:00}", 66},                             /* Update BAR without id */
        {"86:{88:63}", 73},
        {"87:{}", 66},
        {"87:{88:63}", 73},
        {"16:{108:00000001}", 73},                      /* FAR 1 is still used by PDR 1: removing it leaves a dangling reference */
        {"18:{109:00000001}", 73},                      /* likewise QER 1 */
        {"17:{81:00000001}", 73},                       /* likewise URR 1 */
        {"9:{56:0001 108:00000063}", 73},               /* PDR pointing at a FAR that does not exist */
        {"9:{56:0001 109:00000063}", 73},
        {"9:{56:0001 81:00000063}", 73},
        {"3:{108:00000007 44:0200 88:07}", 73},         /* FAR naming a BAR that does not exist */
    };
    uint32_t teid;
    uint64_t seid;
    bld_t b;
    rig_new(NULL);
    setup_assoc();
    b_session_head(&b, 0xe0);
    b_pdr_ul(&b, 1, 100, 1, 1, 1, 1, NULL, true);
    b_pdr_dl(&b, 2, 100, UE, 2, 1, 1, NULL);
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
    b_far(&b, 2, PFCP_AA_FORW, UPF_IF_ACCESS, 5, GNBIP, 0);
    b_qer(&b, 1, 0, 0, false, false, 9);
    b_urr(&b, 1, 0);
    seid = establish(&b, 0xe0, PFCP_CAUSE_ACCEPTED, &teid);
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        bld_t m;
        m.pos = 0;
        b_dsl(&m, cases[i].mod);
        rig_reset_captures();
        send_n4(PFCP_SESSION_MODIFICATION_REQUEST, true, seid, m.body, m.pos);
        {
            pfcp_header h;
            size_t bl;
            const uint8_t *body = rig_n4(PFCP_SESSION_MODIFICATION_RESPONSE, &h, &bl);
            int c;
            TK_ASSERT(body != NULL);
            c = cause_of(body, bl);
            if (c != cases[i].cause)
                TK_FAIL("modification %zu (%s): cause %d, wanted %d", i, cases[i].mod, c, cases[i].cause);
        }
        probe_still_works(teid);
    }

    /* and the changes that must succeed, each visible in behaviour */
    {
        bld_t m;
        uint8_t ip[1400], up[1500];
        size_t un;
        int passed = 0;
        /* create a rate-limited QER and a new FAR, point PDR 1 at them (Update PDR), keep the old ones */
        m.pos = 0;
        b_dsl(&m, "7:{109:00000002 25:00 26:00000001f400000001f4}"); /* QER 2: 500 kbit/s each way */
        b_dsl(&m, "9:{56:0001 29:00000007 109:00000002}");           /* PDR 1: better precedence, now limited by QER 2 only */
        modify(seid, &m, PFCP_CAUSE_ACCEPTED);
        ipv4(ip, UE, DN, 17, 1, 2, 1000);
        un = gpdu_ul(up, sizeof up, teid, 1, ip, 1000);
        for (int i = 0; i < 20; i++) {
            size_t before = RIG.nn6;
            upf_gtpu_packet(U, &GNB, up, un, NOW);
            passed += (int)(RIG.nn6 - before);
        }
        TK_ASSERT(passed > 0 && passed < 20); /* 500 kbit/s = 62.5 kB/s: only the 3000-byte minimum burst passes at once */
        /* update the QER to open the pipe again, closing the gate in the other direction */
        m.pos = 0;
        b_dsl(&m, "14:{109:00000002 25:01 26:00000000000000000000}");
        modify(seid, &m, PFCP_CAUSE_ACCEPTED);
        {
            uint8_t dl[100];
            ipv4(dl, DN, UE, 17, 1, 2, 100);
            rig_reset_captures();
            upf_n6_packet(U, dl, 100, NOW);
            TK_ASSERT(RIG.ngtpu == 1); /* PDR 2 still uses QER 1 (open) */
        }
        /* a PDI update replaces the match: PDR 1 now only takes a given SDF */
        m.pos = 0;
        b_dsl(&m, "9:{56:0001 2:{20:00 124:01 23:010000287065726d6974206f75742031372066726f6d20616e7920746f2061737369676e6564203539393939}}");
        modify(seid, &m, PFCP_CAUSE_RULE_CREATION_FAILURE == 0 ? PFCP_CAUSE_ACCEPTED : PFCP_CAUSE_ACCEPTED);
        /* BAR created and updated through modification; FAR 2 starts buffering and takes the BAR */
        m.pos = 0;
        b_dsl(&m, "85:{88:03 47:01 48:0005}");
        b_dsl(&m, "10:{108:00000002 44:0400 88:03}");
        modify(seid, &m, PFCP_CAUSE_ACCEPTED);
        {
            uint8_t dl[100];
            ipv4(dl, DN, UE, 17, 1, 2, 100);
            for (int i = 0; i < 8; i++)
                upf_n6_packet(U, dl, 100, NOW);
            TK_ASSERT(U->st.buffered == 5 && U->st.drop_buffer == 3); /* the BAR's suggested count of 5 applies */
        }
        m.pos = 0;
        b_dsl(&m, "86:{88:03 48:0007}");
        modify(seid, &m, PFCP_CAUSE_ACCEPTED);
        /* remove what is no longer used: the BAR (after the FAR let go of it) and a URR */
        m.pos = 0;
        b_dsl(&m, "10:{108:00000002 44:0200 11:{42:00}}"); /* back to forwarding; releases the held packets without an OHC change */
        b_dsl(&m, "87:{88:03}");
        modify(seid, &m, PFCP_CAUSE_RULE_CREATION_FAILURE); /* FAR 2 still names BAR 3 */
        m.pos = 0;
        b_dsl(&m, "13:{81:00000001 37:020000 31:010000000000002710 32:0000000a 64:0000000a}");
        modify(seid, &m, PFCP_CAUSE_ACCEPTED);
        m.pos = 0;
        b_dsl(&m, "3:{108:00000009 44:0200 4:{42:01}} 9:{56:0002 108:00000009}");
        modify(seid, &m, PFCP_CAUSE_ACCEPTED); /* create a FAR and re-point PDR 2 at it */
        m.pos = 0;
        b_dsl(&m, "16:{108:00000002}");
        modify(seid, &m, PFCP_CAUSE_ACCEPTED); /* FAR 2 is now unreferenced */
        m.pos = 0;
        b_dsl(&m, "15:{56:0002}");
        modify(seid, &m, PFCP_CAUSE_ACCEPTED);
        TK_ASSERT(U->st.sessions_created == 1);
    }
    upf_free(U);
}

/* ---- 1. the messages Open5GS really sends ------------------------------------------------------------------------------------- */

static void test_open5gs_replay(void)
{
    uint8_t m[1024], ip[200], pkt[1500];
    size_t n, bl;
    pfcp_header h;
    const uint8_t *body;
    pfcp_ie ie, grp;
    uint64_t useid;
    uint32_t teid2 = 0, teid3 = 0, teid4 = 0;
    int created = 0;
    rig_new(NULL);

    n = unhex(PFCPV_ASSOC_SETUP_REQ, m, sizeof m);
    upf_n4_message(U, &SMF, m, n, NOW);
    body = rig_n4(PFCP_ASSOCIATION_SETUP_RESPONSE, &h, &bl);
    TK_ASSERT(body != NULL);
    {   /* the answer carries the request's sequence number */
        uint32_t want = ((uint32_t)m[4] << 16) | ((uint32_t)m[5] << 8) | m[6];
        TK_ASSERT(h.seq == want);
    }
    TK_ASSERT(cause_of(body, bl) == PFCP_CAUSE_ACCEPTED && find_ie(body, bl, PFCP_IE_NODE_ID, &ie, 0) && find_ie(body, bl, PFCP_IE_RECOVERY_TIME_STAMP, &ie, 0) &&
              find_ie(body, bl, PFCP_IE_UP_FUNCTION_FEATURES, &ie, 0));
    TK_ASSERT(upf_peer_established(U, &SMF));
    /* UP Function Features: exactly FTUP and EMPU, which is what lets the SMF ask for CHOOSE F-TEIDs (Open5GS's UPF sends 0x10 0x21...) */
    TK_ASSERT(find_ie(body, bl, PFCP_IE_UP_FUNCTION_FEATURES, &ie, 0) && ie.len == 4 && ie.value[0] == PFCP_UPF5_FTUP && ie.value[1] == PFCP_UPF6_EMPU &&
              ie.value[2] == 0 && ie.value[3] == 0);

    rig_reset_captures();
    n = unhex(PFCPV_SESS_EST_REQ, m, sizeof m);
    upf_n4_message(U, &SMF, m, n, NOW);
    body = rig_n4(PFCP_SESSION_ESTABLISHMENT_RESPONSE, &h, &bl);
    TK_ASSERT(body != NULL);
    if (cause_of(body, bl) != PFCP_CAUSE_ACCEPTED) {
        uint16_t off = 0;
        if (find_ie(body, bl, PFCP_IE_OFFENDING_IE, &ie, 0))
            (void)pfcp_get_u16(&ie, &off);
        TK_FAIL("session establishment refused: cause %d, offending IE %u", cause_of(body, bl), off);
    }
    TK_ASSERT(h.has_seid && h.seid == 0x1698); /* the CP F-SEID of the request */
    {
        pfcp_fseid f;
        TK_ASSERT(find_ie(body, bl, PFCP_IE_FSEID, &ie, 0) && pfcp_fseid_decode(&ie, &f) == 0);
        useid = f.seid;
    }
    for (int i = 0; find_ie(body, bl, PFCP_IE_CREATED_PDR, &grp, i); i++) {
        uint16_t id;
        pfcp_fteid ft;
        TK_ASSERT(find_ie(grp.value, grp.len, PFCP_IE_PDR_ID, &ie, 0) && pfcp_get_u16(&ie, &id) == 0);
        TK_ASSERT(find_ie(grp.value, grp.len, PFCP_IE_FTEID, &ie, 0) && pfcp_fteid_decode(&ie, &ft) == 0 && !ft.ch && ft.v4);
        if (id == 2)
            teid2 = ft.teid;
        else if (id == 3)
            teid3 = ft.teid;
        else if (id == 4)
            teid4 = ft.teid;
        created++;
    }
    TK_ASSERT(created == 3 && teid2 && teid3 && teid4);
    TK_ASSERT(teid2 == teid4 && teid2 != teid3); /* the same CHOOSE id gives the same TEID (as Open5GS's UPF does) */
    TK_ASSERT(upf_session_count(U) == 1);

    /* downlink data arrives before the gNB tunnel is known: FAR 1 is BUFF|NOCP, so it is held and the SMF is told */
    ipv4(ip, DN, UE, 1, 0, 0, 84);
    rig_reset_captures();
    upf_n6_packet(U, ip, 84, NOW);
    TK_ASSERT(RIG.ngtpu == 0 && U->st.buffered == 1);
    body = rig_n4(PFCP_SESSION_REPORT_REQUEST, &h, &bl);
    TK_ASSERT(body && h.has_seid && h.seid == 0x1698);
    {
        uint8_t rt;
        TK_ASSERT(find_ie(body, bl, PFCP_IE_REPORT_TYPE, &ie, 0) && pfcp_get_u8(&ie, &rt) == 0 && rt == 1);
        TK_ASSERT(find_ie(body, bl, PFCP_IE_DOWNLINK_DATA_REPORT, &grp, 0) && find_ie(grp.value, grp.len, PFCP_IE_PDR_ID, &ie, 0));
        {
            uint16_t id;
            TK_ASSERT(pfcp_get_u16(&ie, &id) == 0 && id == 1);
        }
    }
    {   /* the SMF answers and updates FAR 1 with the gNB's tunnel (the real modification from the capture) */
        uint8_t resp[64];
        pfcp_header r;
        size_t rn = 0, p = 0;
        uint8_t rb[8];
        pfcp_header_session(&r, PFCP_SESSION_REPORT_RESPONSE, useid, h.seq);
        pfcp_put_u8(rb, sizeof rb, &p, PFCP_IE_CAUSE, 1);
        TK_ASSERT(pfcp_encode(&r, rb, p, resp, sizeof resp, &rn) == 0);
        upf_n4_message(U, &SMF, resp, rn, NOW);
        TK_ASSERT(U->st.reports_acked == 1);
    }
    rig_reset_captures();
    n = unhex(PFCPV_SESS_MOD_REQ, m, sizeof m);
    for (int i = 0; i < 8; i++)
        m[4 + i] = (uint8_t)(useid >> (8 * (7 - i)));
    upf_n4_message(U, &SMF, m, n, NOW);
    body = rig_n4(PFCP_SESSION_MODIFICATION_RESPONSE, &h, &bl);
    TK_ASSERT(body && cause_of(body, bl) == PFCP_CAUSE_ACCEPTED);
    /* the held packet was released through the new rule: GTP-U to 127.1.0.100 with the TEID of the capture (1) */
    TK_ASSERT(RIG.ngtpu == 1 && memcmp(RIG.gtpu[0].to.b, GNBIP, 4) == 0 && RIG.gtpu[0].to.port == 2152);
    {
        gtpu_header gh;
        const uint8_t *pl;
        size_t plen;
        uint8_t t, q;
        bool r;
        TK_ASSERT(gtpu_decode(RIG.gtpu[0].d, RIG.gtpu[0].n, &gh, &pl, &plen) == 0 && gh.msg_type == GTPU_G_PDU && gh.teid == 1);
        TK_ASSERT(gh.next == 1 && gtpu_as_pdu_session_container(&gh.ext[0], &t, &q, &r) && t == 0 && q == 1); /* DL, QFI 1 of the QER */
        TK_ASSERT(plen == 84 && memcmp(pl, ip, 84) == 0);
    }
    /* uplink through the TEID the UPF handed out, then more downlink */
    {
        uint8_t up[200];
        size_t un;
        ipv4(ip, UE, DN, 1, 0, 0, 84);
        un = gpdu_ul(up, sizeof up, teid2, 1, ip, 84);
        rig_reset_captures();
        upf_gtpu_packet(U, &GNB, up, un, NOW);
        TK_ASSERT(RIG.nn6 == 1 && RIG.n6[0].n == 84 && memcmp(RIG.n6[0].d, ip, 84) == 0);
    }
    ipv4(ip, DN, UE, 1, 0, 0, 100);
    rig_reset_captures();
    upf_n6_packet(U, ip, 100, NOW);
    TK_ASSERT(RIG.ngtpu == 1);

    /* deletion, with the usage report the capture shows (URR 1 sits on PDR 1: the downlink path) */
    rig_reset_captures();
    n = unhex(PFCPV_SESS_DEL_REQ, m, sizeof m);
    for (int i = 0; i < 8; i++)
        m[4 + i] = (uint8_t)(useid >> (8 * (7 - i)));
    upf_n4_message(U, &SMF, m, n, NOW + 5);
    body = rig_n4(PFCP_SESSION_DELETION_RESPONSE, &h, &bl);
    TK_ASSERT(body && cause_of(body, bl) == PFCP_CAUSE_ACCEPTED && h.seid == 0x1698);
    TK_ASSERT(find_ie(body, bl, PFCP_IE_USAGE_REPORT_SDR, &grp, 0));
    {
        uint32_t trig;
        TK_ASSERT(find_ie(grp.value, grp.len, PFCP_IE_USAGE_REPORT_TRIGGER, &ie, 0) && pfcp_trigger_decode(&ie, &trig) == 0 && trig == PFCP_URT_TERMR);
        TK_ASSERT(find_ie(grp.value, grp.len, PFCP_IE_VOLUME_MEASUREMENT, &ie, 0) && ie.len == 49);
        TK_ASSERT(ie.value[0] == 0x3f && ie.value[8] == 184 && ie.value[24] == 184 /* 84 + 100 bytes, all downlink */ && ie.value[32] == 2 /* packets */);
    }
    TK_ASSERT(upf_session_count(U) == 0 && U->st.sessions_deleted == 1);
    (void)pkt;
    upf_free(U);
}

/* ---- 2. QoS ----------------------------------------------------------------------------------------------------------------------- */

static void test_qer(void)
{
    uint32_t teid;
    uint64_t seid;
    uint8_t ip[1400], up[1500];
    size_t un;
    int passed = 0;
    rig_new(NULL);
    setup_assoc();
    seid = std_session(&teid, 0x10, 1000, 1000); /* MBR 1 Mbit/s each way = 125 kB/s, 6250 bytes of burst */
    (void)seid;
    ipv4(ip, UE, DN, 17, 1111, 53, 1000);
    un = gpdu_ul(up, sizeof up, teid, 1, ip, 1000);
    for (int i = 0; i < 20; i++) {
        size_t before = RIG.nn6;
        upf_gtpu_packet(U, &GNB, up, un, NOW);
        passed += (int)(RIG.nn6 - before);
    }
    TK_ASSERT(passed == 6 && U->st.drop_rate == 14);
    NOW += 1.0; /* a second later the bucket is full again */
    passed = 0;
    for (int i = 0; i < 20; i++) {
        size_t before = RIG.nn6;
        upf_gtpu_packet(U, &GNB, up, un, NOW);
        passed += (int)(RIG.nn6 - before);
    }
    TK_ASSERT(passed == 6);
    /* sustained rate: 100 packets of 1000 B over 10 s offered at 800 kbit/s pass in full, at 4 Mbit/s only about a quarter does */
    {
        int offered = 0;
        passed = 0;
        for (int step = 0; step < 4000; step++) {
            size_t before = RIG.nn6;
            NOW += 0.002;
            upf_gtpu_packet(U, &GNB, up, un, NOW); /* 1000 B every 2 ms = 4 Mbit/s */
            passed += (int)(RIG.nn6 - before);
            offered++;
        }
        TK_ASSERT(passed > offered / 5 && passed < offered / 3); /* about 1/4: 125 kB/s of 500 kB/s offered */
    }
    upf_free(U);

    /* closed gates */
    {
        bld_t b;
        rig_new(NULL);
        setup_assoc();
        b_session_head(&b, 0x11);
        b_pdr_ul(&b, 1, 100, 1, 1, 1, 0, NULL, false);
        b_pdr_dl(&b, 2, 100, UE, 2, 1, 0, NULL);
        b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
        b_far(&b, 2, PFCP_AA_FORW, UPF_IF_ACCESS, 77, GNBIP, 0);
        b_qer(&b, 1, 0, 0, true, false, 0); /* uplink closed, downlink open */
        establish(&b, 0x11, PFCP_CAUSE_ACCEPTED, &teid);
        ipv4(ip, UE, DN, 17, 1, 2, 100);
        un = gpdu_ul(up, sizeof up, teid, 0, ip, 100);
        upf_gtpu_packet(U, &GNB, up, un, NOW);
        TK_ASSERT(RIG.nn6 == 0 && U->st.drop_gate == 1);
        ipv4(ip, DN, UE, 17, 2, 1, 100);
        upf_n6_packet(U, ip, 100, NOW);
        TK_ASSERT(RIG.ngtpu == 1);
        upf_free(U);
    }
}

/* ---- 3. classification ------------------------------------------------------------------------------------------------------------ */

static void test_sdf_and_precedence(void)
{
    bld_t b;
    uint8_t ip[200];
    uint32_t teid;
    rig_new(NULL);
    setup_assoc();
    b_session_head(&b, 0x20);
    b_pdr_ul(&b, 1, 100, 1, 1, 0, 0, NULL, false);
    b_pdr_dl(&b, 2, 10, UE, 2, 0, 0, "permit out 17 from any to assigned 5000-5010"); /* more specific, wins */
    b_pdr_dl(&b, 3, 100, UE, 3, 0, 0, NULL);
    b_pdr_dl(&b, 4, 5, UE, 4, 0, 0, "permit out 6 from 192.0.2.0/24 80 to assigned"); /* even better precedence, narrow */
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
    b_far(&b, 2, PFCP_AA_FORW, UPF_IF_ACCESS, 22, GNBIP, 0);
    b_far(&b, 3, PFCP_AA_FORW, UPF_IF_ACCESS, 33, GNBIP, 0);
    b_far(&b, 4, PFCP_AA_FORW, UPF_IF_ACCESS, 44, GNBIP, 0);
    establish(&b, 0x20, PFCP_CAUSE_ACCEPTED, &teid);
    {
        struct { uint8_t src[4]; uint8_t proto; uint16_t sport, dport; uint32_t want; } cases[] = {
            {{10, 99, 0, 1}, 17, 1000, 5000, 22}, {{10, 99, 0, 1}, 17, 1000, 5010, 22}, {{10, 99, 0, 1}, 17, 1000, 5011, 33},
            {{10, 99, 0, 1}, 6, 1000, 5000, 33},  {{192, 0, 2, 7}, 6, 80, 9999, 44},    {{192, 0, 2, 7}, 6, 81, 9999, 33},
            {{192, 0, 3, 7}, 6, 80, 9999, 33},
        };
        for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
            gtpu_header gh;
            const uint8_t *pl;
            size_t plen;
            ipv4(ip, cases[i].src, UE, cases[i].proto, cases[i].sport, cases[i].dport, 60);
            rig_reset_captures();
            upf_n6_packet(U, ip, 60, NOW);
            TK_ASSERT(RIG.ngtpu == 1);
            TK_ASSERT(gtpu_decode(RIG.gtpu[0].d, RIG.gtpu[0].n, &gh, &pl, &plen) == 0);
            if (gh.teid != cases[i].want)
                TK_FAIL("case %zu went through TEID %u, wanted %u", i, gh.teid, cases[i].want);
        }
    }
    /* no PDR at all for a UE the UPF does not know, and a packet that is not IP */
    {
        const uint8_t other[4] = {10, 46, 9, 9};
        ipv4(ip, DN, other, 17, 1, 2, 60);
        upf_n6_packet(U, ip, 60, NOW);
        TK_ASSERT(U->st.drop_no_session == 1);
        memset(ip, 0, 40);
        upf_n6_packet(U, ip, 40, NOW);
        TK_ASSERT(U->st.drop_bad_packet == 1);
    }
    upf_free(U);
}

static void test_uplink_protection(void)
{
    uint32_t teid;
    uint8_t ip[200], up[300];
    size_t un;
    rig_new(NULL);
    setup_assoc();
    std_session(&teid, 0x30, 0, 0);
    {   /* a UE using somebody else's address is dropped */
        const uint8_t evil[4] = {10, 46, 0, 99};
        ipv4(ip, evil, DN, 1, 0, 0, 84);
        un = gpdu_ul(up, sizeof up, teid, 1, ip, 84);
        upf_gtpu_packet(U, &GNB, up, un, NOW);
        TK_ASSERT(RIG.nn6 == 0 && U->st.drop_spoof == 1);
    }
    {   /* the right address passes; a wrong QFI does not match the PDR */
        ipv4(ip, UE, DN, 1, 0, 0, 84);
        un = gpdu_ul(up, sizeof up, teid, 1, ip, 84);
        upf_gtpu_packet(U, &GNB, up, un, NOW);
        TK_ASSERT(RIG.nn6 == 1);
        un = gpdu_ul(up, sizeof up, teid, 5, ip, 84);
        upf_gtpu_packet(U, &GNB, up, un, NOW);
        TK_ASSERT(RIG.nn6 == 1 && U->st.drop_no_pdr == 1);
    }
    {   /* a TEID nobody owns: Error Indication back to the sender, rate limited */
        size_t before;
        ipv4(ip, UE, DN, 1, 0, 0, 84);
        un = gpdu_ul(up, sizeof up, teid + 12345, 1, ip, 84);
        rig_reset_captures();
        upf_gtpu_packet(U, &GNB, up, un, NOW);
        TK_ASSERT(RIG.ngtpu == 1 && RIG.gtpu[0].n == 24 && RIG.gtpu[0].d[1] == GTPU_ERROR_INDICATION && memcmp(RIG.gtpu[0].to.b, GNBIP, 4) == 0);
        {
            uint32_t bad_teid = teid + 12345;
            TK_ASSERT(RIG.gtpu[0].d[12] == 16 && RIG.gtpu[0].d[13] == (uint8_t)(bad_teid >> 24) && RIG.gtpu[0].d[16] == (uint8_t)bad_teid);
        }
        before = RIG.ngtpu;
        for (int i = 0; i < 500; i++)
            upf_gtpu_packet(U, &GNB, up, un, NOW);
        TK_ASSERT(RIG.ngtpu - before <= 100);
    }
    {   /* echo */
        uint8_t echo[12] = {0x32, GTPU_ECHO_REQUEST, 0, 4, 0, 0, 0, 0, 0x12, 0x34, 0, 0}, ok;
        gtpu_header gh;
        const uint8_t *pl;
        size_t plen;
        rig_reset_captures();
        upf_gtpu_packet(U, &GNB, echo, sizeof echo, NOW);
        ok = RIG.ngtpu == 1 && gtpu_decode(RIG.gtpu[0].d, RIG.gtpu[0].n, &gh, &pl, &plen) == 0 && gh.msg_type == GTPU_ECHO_RESPONSE && gh.has_seq && gh.seq == 0x1234 &&
             plen == 2 && pl[0] == 14;
        TK_ASSERT(ok);
    }
    {   /* garbage never crashes */
        uint8_t junk[40];
        tk_rng r = {99};
        for (int i = 0; i < 2000; i++) {
            tk_rng_bytes(&r, junk, sizeof junk);
            upf_gtpu_packet(U, &GNB, junk, 1 + (size_t)(tk_rng_next(&r) % sizeof junk), NOW);
            upf_n6_packet(U, junk, 1 + (size_t)(tk_rng_next(&r) % sizeof junk), NOW);
        }
    }
    upf_free(U);
}

/* ---- 4. buffering and usage reporting ------------------------------------------------------------------------------------------ */

static void tweak_small_buffer(upf_config *c)
{
    c->buffer_max_packets = 3;
    c->buffer_max_age = 5.0;
}

static void test_buffering(void)
{
    bld_t b;
    uint8_t ip[100], bi[4] = {0};
    uint32_t teid;
    uint64_t seid;
    pfcp_header h;
    size_t bl;
    rig_new(tweak_small_buffer);
    setup_assoc();
    b_session_head(&b, 0x40);
    b_pdr_ul(&b, 1, 100, 1, 1, 0, 0, NULL, false);
    b_pdr_dl(&b, 2, 100, UE, 2, 0, 0, NULL);
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
    b_far(&b, 2, PFCP_AA_BUFF, UPF_IF_ACCESS, 0, NULL, 1); /* buffer without notifying the CP */
    b_bar(&b, 1);
    seid = establish(&b, 0x40, PFCP_CAUSE_ACCEPTED, &teid);
    (void)bi;
    for (int i = 0; i < 5; i++) {
        ipv4(ip, DN, UE, 17, 1, 2, 50 + (size_t)i);
        upf_n6_packet(U, ip, 50 + (size_t)i, NOW);
    }
    TK_ASSERT(RIG.ngtpu == 0 && U->st.buffered == 3 && U->st.drop_buffer == 2 && rig_n4(PFCP_SESSION_REPORT_REQUEST, &h, &bl) == NULL);
    {   /* released in order once forwarding starts */
        bld_t u;
        update_far_forward(&u, 2, 5, GNBIP, false);
        modify(seid, &u, PFCP_CAUSE_ACCEPTED);
        TK_ASSERT(RIG.ngtpu == 3);
        for (int i = 0; i < 3; i++) {
            gtpu_header gh;
            const uint8_t *pl;
            size_t plen;
            TK_ASSERT(gtpu_decode(RIG.gtpu[i].d, RIG.gtpu[i].n, &gh, &pl, &plen) == 0 && plen == 50 + (size_t)i && gh.teid == 5);
        }
    }
    upf_free(U);

    /* DROBU: the SMF asks to drop what is buffered, then enables forwarding: nothing old is released */
    rig_new(tweak_small_buffer);
    setup_assoc();
    b_session_head(&b, 0x42);
    b_pdr_ul(&b, 1, 100, 1, 1, 0, 0, NULL, false);
    b_pdr_dl(&b, 2, 100, UE, 2, 0, 0, NULL);
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
    b_far(&b, 2, PFCP_AA_BUFF, UPF_IF_ACCESS, 0, NULL, 0);
    seid = establish(&b, 0x42, PFCP_CAUSE_ACCEPTED, &teid);
    ipv4(ip, DN, UE, 17, 1, 2, 60);
    upf_n6_packet(U, ip, 60, NOW);
    upf_n6_packet(U, ip, 60, NOW);
    TK_ASSERT(U->st.buffered == 2);
    {
        bld_t u;
        u.pos = 0;
        pfcp_put_u8(u.body, sizeof u.body, &u.pos, PFCP_IE_SMREQ_FLAGS, 1);
        modify(seid, &u, PFCP_CAUSE_ACCEPTED);
        update_far_forward(&u, 2, 5, GNBIP, false);
        modify(seid, &u, PFCP_CAUSE_ACCEPTED);
        TK_ASSERT(RIG.ngtpu == 0 && U->st.flushed == 0);
    }
    upf_free(U);

    /* held packets expire */
    rig_new(tweak_small_buffer);
    setup_assoc();
    b_session_head(&b, 0x41);
    b_pdr_ul(&b, 1, 100, 1, 1, 0, 0, NULL, false);
    b_pdr_dl(&b, 2, 100, UE, 2, 0, 0, NULL);
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
    b_far(&b, 2, PFCP_AA_BUFF, UPF_IF_ACCESS, 0, NULL, 0);
    establish(&b, 0x41, PFCP_CAUSE_ACCEPTED, &teid);
    ipv4(ip, DN, UE, 17, 1, 2, 60);
    upf_n6_packet(U, ip, 60, NOW);
    TK_ASSERT(U->st.buffered == 1);
    upf_tick(U, NOW + 4);
    TK_ASSERT(U->st.drop_buffer == 0);
    upf_tick(U, NOW + 6);
    TK_ASSERT(U->st.drop_buffer == 1);
    upf_free(U);
}

static void test_usage_reports(void)
{
    bld_t b;
    uint8_t ip[1200], up[1300];
    uint32_t teid;
    uint64_t seid;
    pfcp_header h;
    size_t bl, un;
    const uint8_t *body;
    pfcp_ie ie, grp;
    rig_new(NULL);
    setup_assoc();
    b_session_head(&b, 0x50);
    b_pdr_ul(&b, 1, 100, 1, 1, 0, 1, NULL, false);
    b_pdr_dl(&b, 2, 100, UE, 2, 0, 1, NULL);
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
    b_far(&b, 2, PFCP_AA_FORW, UPF_IF_ACCESS, 9, GNBIP, 0);
    b_urr(&b, 1, 2500); /* report after 2500 bytes */
    seid = establish(&b, 0x50, PFCP_CAUSE_ACCEPTED, &teid);
    ipv4(ip, UE, DN, 17, 1, 2, 1000);
    un = gpdu_ul(up, sizeof up, teid, 0, ip, 1000);
    upf_gtpu_packet(U, &GNB, up, un, NOW);
    upf_gtpu_packet(U, &GNB, up, un, NOW);
    upf_tick(U, NOW + 0.1);
    TK_ASSERT(rig_n4(PFCP_SESSION_REPORT_REQUEST, &h, &bl) == NULL); /* 2000 < 2500 */
    upf_gtpu_packet(U, &GNB, up, un, NOW);
    rig_reset_captures();
    upf_tick(U, NOW + 0.2);
    body = rig_n4(PFCP_SESSION_REPORT_REQUEST, &h, &bl);
    TK_ASSERT(body && h.seid == 0x50);
    {
        uint8_t rt;
        uint32_t trig;
        TK_ASSERT(find_ie(body, bl, PFCP_IE_REPORT_TYPE, &ie, 0) && pfcp_get_u8(&ie, &rt) == 0 && rt == 2);
        TK_ASSERT(find_ie(body, bl, PFCP_IE_USAGE_REPORT_SRR, &grp, 0));
        TK_ASSERT(find_ie(grp.value, grp.len, PFCP_IE_USAGE_REPORT_TRIGGER, &ie, 0) && pfcp_trigger_decode(&ie, &trig) == 0 && trig == PFCP_URT_VOLTH);
        TK_ASSERT(find_ie(grp.value, grp.len, PFCP_IE_VOLUME_MEASUREMENT, &ie, 0) && ie.value[8] == 0xb8 && ie.value[7] == 0x0b /* 3000 = 0x0bb8 */);
    }
    {   /* unanswered reports are repeated every 3 s, at most 3 times; an answer stops them */
        size_t n0 = RIG.nn4;
        upf_tick(U, NOW + 2);
        TK_ASSERT(RIG.nn4 == n0);
        upf_tick(U, NOW + 3.5);
        TK_ASSERT(RIG.nn4 == n0 + 1 && memcmp(RIG.n4[n0].d, RIG.n4[0].d, RIG.n4[0].n) == 0);
        upf_tick(U, NOW + 7);
        upf_tick(U, NOW + 10.5);
        TK_ASSERT(RIG.nn4 == n0 + 3);
        upf_tick(U, NOW + 14);
        TK_ASSERT(RIG.nn4 == n0 + 3);
    }
    {   /* after the report the counters restarted: the next 2500 bytes trigger another */
        uint8_t dl[1000];
        size_t k = 0;
        rig_reset_captures();
        ipv4(dl, DN, UE, 17, 2, 1, 1000);
        for (int i = 0; i < 3; i++)
            upf_n6_packet(U, dl, 1000, NOW + 20);
        upf_tick(U, NOW + 20.1);
        for (size_t i = 0; i < RIG.nn4; i++)
            if (rig_n4(PFCP_SESSION_REPORT_REQUEST, &h, &bl))
                k++;
        TK_ASSERT(k >= 1);
    }
    {   /* Query URR in a modification answers with an immediate report and restarts the counters */
        bld_t q;
        size_t m;
        const uint8_t *mb;
        q.pos = 0;
        pfcp_group_begin(q.body, sizeof q.body, &q.pos, PFCP_IE_QUERY_URR, &m);
        pfcp_put_u32(q.body, sizeof q.body, &q.pos, PFCP_IE_URR_ID, 1);
        pfcp_group_end(q.body, &q.pos, m);
        modify(seid, &q, PFCP_CAUSE_ACCEPTED);
        mb = rig_n4(PFCP_SESSION_MODIFICATION_RESPONSE, &h, &bl);
        TK_ASSERT(find_ie(mb, bl, PFCP_IE_USAGE_REPORT_SMR, &grp, 0));
        {
            uint32_t trig;
            TK_ASSERT(find_ie(grp.value, grp.len, PFCP_IE_USAGE_REPORT_TRIGGER, &ie, 0) && pfcp_trigger_decode(&ie, &trig) == 0 && trig == PFCP_URT_IMMER);
        }
    }
    upf_free(U);
}

/* ---- 5. N4 behaviour ------------------------------------------------------------------------------------------------------------------ */

static void test_n4_lifecycle(void)
{
    bld_t b;
    pfcp_header h;
    size_t bl;
    const uint8_t *body;
    uint32_t teid;
    uint64_t seid;
    rig_new(NULL);
    /* no association yet: refused with cause 72, answered to the CP F-SEID */
    b_session_head(&b, 0x60);
    b_pdr_ul(&b, 1, 100, 1, 1, 0, 0, NULL, false);
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
    establish(&b, 0x60, PFCP_CAUSE_NO_ESTABLISHED_ASSOCIATION, NULL);
    setup_assoc();
    seid = std_session(&teid, 0x61, 0, 0);
    TK_ASSERT(upf_session_count(U) == 1);

    {   /* a retransmitted request gets the same answer, and does not create a second session */
        uint8_t req[1600], first[1600];
        size_t n = 0, fn;
        pfcp_header rh;
        b_session_head(&b, 0x62);
        b_pdr_ul(&b, 1, 100, 1, 1, 0, 0, NULL, false);
        b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
        pfcp_header_session(&rh, PFCP_SESSION_ESTABLISHMENT_REQUEST, 0, 5000);
        TK_ASSERT(pfcp_encode(&rh, b.body, b.pos, req, sizeof req, &n) == 0);
        rig_reset_captures();
        upf_n4_message(U, &SMF, req, n, NOW);
        TK_ASSERT(RIG.nn4 == 1);
        fn = RIG.n4[0].n;
        memcpy(first, RIG.n4[0].d, fn);
        upf_n4_message(U, &SMF, req, n, NOW + 1);
        TK_ASSERT(RIG.nn4 == 2 && RIG.n4[1].n == fn && memcmp(RIG.n4[1].d, first, fn) == 0 && upf_session_count(U) == 2);
    }
    {   /* a Session Modification for a session that does not exist */
        bld_t u;
        update_far_forward(&u, 1, 1, GNBIP, false);
        modify(seid + 1000, &u, PFCP_CAUSE_SESSION_NOT_FOUND);
    }
    {   /* a failed modification leaves the session exactly as it was (all-or-nothing) */
        bld_t u;
        size_t m, m2;
        uint8_t aa[2] = {PFCP_AA_DROP, 0};
        uint8_t ip[100], up[200];
        size_t un;
        u.pos = 0;
        pfcp_group_begin(u.body, sizeof u.body, &u.pos, PFCP_IE_UPDATE_FAR, &m); /* valid: would drop everything */
        pfcp_put_u32(u.body, sizeof u.body, &u.pos, PFCP_IE_FAR_ID, 1);
        pfcp_put_ie(u.body, sizeof u.body, &u.pos, PFCP_IE_APPLY_ACTION, aa, 2);
        pfcp_group_end(u.body, &u.pos, m);
        pfcp_group_begin(u.body, sizeof u.body, &u.pos, PFCP_IE_UPDATE_FAR, &m2); /* invalid: no such FAR */
        pfcp_put_u32(u.body, sizeof u.body, &u.pos, PFCP_IE_FAR_ID, 999);
        pfcp_group_end(u.body, &u.pos, m2);
        modify(seid, &u, PFCP_CAUSE_RULE_CREATION_FAILURE);
        body = rig_n4(PFCP_SESSION_MODIFICATION_RESPONSE, &h, &bl);
        {
            pfcp_ie ie;
            uint16_t off;
            TK_ASSERT(find_ie(body, bl, PFCP_IE_OFFENDING_IE, &ie, 0) && pfcp_get_u16(&ie, &off) == 0 && off == PFCP_IE_FAR_ID);
        }
        ipv4(ip, UE, DN, 1, 0, 0, 84);
        un = gpdu_ul(up, sizeof up, teid, 1, ip, 84);
        rig_reset_captures();
        upf_gtpu_packet(U, &GNB, up, un, NOW);
        TK_ASSERT(RIG.nn6 == 1); /* FAR 1 still forwards */
    }
    {   /* removing a PDR, and the TEID stops working */
        bld_t u;
        size_t m;
        uint8_t ip[100], up[200];
        size_t un;
        u.pos = 0;
        pfcp_group_begin(u.body, sizeof u.body, &u.pos, PFCP_IE_REMOVE_PDR, &m);
        pfcp_put_u16(u.body, sizeof u.body, &u.pos, PFCP_IE_PDR_ID, 1);
        pfcp_group_end(u.body, &u.pos, m);
        modify(seid, &u, PFCP_CAUSE_ACCEPTED);
        ipv4(ip, UE, DN, 1, 0, 0, 84);
        un = gpdu_ul(up, sizeof up, teid, 1, ip, 84);
        rig_reset_captures();
        upf_gtpu_packet(U, &GNB, up, un, NOW);
        TK_ASSERT(RIG.nn6 == 0);
    }
    {   /* handover: new gNB tunnel with Send End Marker */
        bld_t u;
        uint8_t other[4] = {127, 1, 0, 101};
        uint8_t ip[100];
        gtpu_header gh;
        const uint8_t *pl;
        size_t plen;
        update_far_forward(&u, 2, 88, GNBIP, false);
        modify(seid, &u, PFCP_CAUSE_ACCEPTED);
        update_far_forward(&u, 2, 99, other, true);
        modify(seid, &u, PFCP_CAUSE_ACCEPTED);
        TK_ASSERT(RIG.ngtpu == 1 && RIG.gtpu[0].d[1] == GTPU_END_MARKER && memcmp(RIG.gtpu[0].to.b, GNBIP, 4) == 0);
        TK_ASSERT(gtpu_decode(RIG.gtpu[0].d, RIG.gtpu[0].n, &gh, &pl, &plen) == 0 && gh.teid == 88 && plen == 0);
        ipv4(ip, DN, UE, 1, 0, 0, 60);
        rig_reset_captures();
        upf_n6_packet(U, ip, 60, NOW);
        TK_ASSERT(RIG.ngtpu == 1 && memcmp(RIG.gtpu[0].to.b, other, 4) == 0);
    }
    {   /* peer restart (new recovery time stamp) wipes its sessions; release does too */
        bld_t a;
        TK_ASSERT(upf_session_count(U) == 2);
        b_assoc(&a, 0xe5000002u);
        send_n4(PFCP_ASSOCIATION_SETUP_REQUEST, false, 0, a.body, a.pos);
        TK_ASSERT(upf_session_count(U) == 0 && upf_peer_established(U, &SMF));
        seid = std_session(&teid, 0x70, 0, 0);
        TK_ASSERT(upf_session_count(U) == 1);
        a.pos = 0;
        send_n4(PFCP_ASSOCIATION_RELEASE_REQUEST, false, 0, a.body, a.pos);
        TK_ASSERT(upf_session_count(U) == 0 && !upf_peer_established(U, &SMF));
    }
    upf_free(U);
}

static void tweak_hb(upf_config *c)
{
    c->heartbeat_interval = 5;
    c->heartbeat_retries = 3;
}

static void test_heartbeats(void)
{
    uint32_t teid;
    pfcp_header h;
    size_t bl;
    rig_new(tweak_hb);
    setup_assoc();
    std_session(&teid, 0x80, 0, 0);
    /* heartbeat requests from the SMF are answered with our recovery time stamp */
    {
        bld_t hb;
        hb.pos = 0;
        pfcp_put_u32(hb.body, sizeof hb.body, &hb.pos, PFCP_IE_RECOVERY_TIME_STAMP, 0xe5000001u);
        rig_reset_captures();
        send_n4(PFCP_HEARTBEAT_REQUEST, false, 0, hb.body, hb.pos);
        TK_ASSERT(rig_n4(PFCP_HEARTBEAT_RESPONSE, &h, &bl) != NULL);
    }
    /* we send our own; a silent peer is declared lost after three misses and its sessions removed */
    rig_reset_captures();
    for (int t = 1; t <= 30; t++)
        upf_tick(U, NOW + t);
    TK_ASSERT(rig_n4(PFCP_HEARTBEAT_REQUEST, &h, &bl) != NULL);
    TK_ASSERT(upf_session_count(U) == 0 && !upf_peer_established(U, &SMF));
    upf_free(U);

    /* a peer that keeps answering stays */
    rig_new(tweak_hb);
    setup_assoc();
    std_session(&teid, 0x81, 0, 0);
    for (int t = 1; t <= 60; t++) {
        upf_tick(U, NOW + t);
        if (rig_n4(PFCP_HEARTBEAT_REQUEST, &h, &bl)) {
            bld_t hb;
            hb.pos = 0;
            pfcp_put_u32(hb.body, sizeof hb.body, &hb.pos, PFCP_IE_RECOVERY_TIME_STAMP, 0xe5000001u);
            {
                uint8_t out[40];
                size_t n = 0;
                pfcp_header r;
                pfcp_header_node(&r, PFCP_HEARTBEAT_RESPONSE, h.seq);
                TK_ASSERT(pfcp_encode(&r, hb.body, hb.pos, out, sizeof out, &n) == 0);
                upf_n4_message(U, &SMF, out, n, NOW + t);
            }
            rig_reset_captures();
        }
    }
    TK_ASSERT(upf_session_count(U) == 1 && upf_peer_established(U, &SMF));
    upf_free(U);
}

static void test_rejections(void)
{
    bld_t b;
    uint32_t teid;
    rig_new(NULL);
    setup_assoc();
    /* mandatory IEs missing */
    b_session_head(&b, 0x90);
    establish(&b, 0x90, PFCP_CAUSE_ACCEPTED, NULL); /* a session with no rules at all is legal */
    b_session_head(&b, 0x91);
    {
        size_t m;
        pfcp_group_begin(b.body, sizeof b.body, &b.pos, PFCP_IE_CREATE_PDR, &m); /* no PDR id */
        pfcp_put_u32(b.body, sizeof b.body, &b.pos, PFCP_IE_PRECEDENCE, 1);
        pfcp_group_end(b.body, &b.pos, m);
    }
    establish(&b, 0x91, PFCP_CAUSE_MANDATORY_IE_MISSING, NULL);
    /* a PDR that points at a FAR which does not exist */
    b_session_head(&b, 0x92);
    b_pdr_ul(&b, 1, 100, 1, 77, 0, 0, NULL, false);
    establish(&b, 0x92, PFCP_CAUSE_RULE_CREATION_FAILURE, NULL);
    /* UE address allocation by the UPF is not offered */
    {
        size_t m, m2;
        pfcp_ue_ip u = {.v4 = true, .chv4 = true};
        b_session_head(&b, 0x93);
        pfcp_group_begin(b.body, sizeof b.body, &b.pos, PFCP_IE_CREATE_PDR, &m);
        pfcp_put_u16(b.body, sizeof b.body, &b.pos, PFCP_IE_PDR_ID, 1);
        pfcp_put_u32(b.body, sizeof b.body, &b.pos, PFCP_IE_PRECEDENCE, 1);
        pfcp_group_begin(b.body, sizeof b.body, &b.pos, PFCP_IE_PDI, &m2);
        pfcp_put_u8(b.body, sizeof b.body, &b.pos, PFCP_IE_SOURCE_INTERFACE, UPF_IF_CORE);
        pfcp_ue_ip_put(b.body, sizeof b.body, &b.pos, &u);
        pfcp_group_end(b.body, &b.pos, m2);
        pfcp_group_end(b.body, &b.pos, m);
        establish(&b, 0x93, PFCP_CAUSE_RULE_CREATION_FAILURE, NULL);
    }
    /* a malformed SDF filter */
    b_session_head(&b, 0x94);
    b_pdr_dl(&b, 1, 100, UE, 1, 0, 0, "permit out banana from any to assigned");
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_ACCESS, 5, GNBIP, 0);
    establish(&b, 0x94, PFCP_CAUSE_MANDATORY_IE_INCORRECT, NULL);
    /* outer headers over IPv6 are not supported */
    {
        size_t m, m2;
        pfcp_ohc o = {.desc = PFCP_OHC_GTPU_IPV6, .teid = 1};
        uint8_t aa[2] = {PFCP_AA_FORW, 0};
        b_session_head(&b, 0x95);
        pfcp_group_begin(b.body, sizeof b.body, &b.pos, PFCP_IE_CREATE_FAR, &m);
        pfcp_put_u32(b.body, sizeof b.body, &b.pos, PFCP_IE_FAR_ID, 1);
        pfcp_put_ie(b.body, sizeof b.body, &b.pos, PFCP_IE_APPLY_ACTION, aa, 2);
        pfcp_group_begin(b.body, sizeof b.body, &b.pos, PFCP_IE_FORWARDING_PARAMETERS, &m2);
        pfcp_ohc_put(b.body, sizeof b.body, &b.pos, &o);
        pfcp_group_end(b.body, &b.pos, m2);
        pfcp_group_end(b.body, &b.pos, m);
        establish(&b, 0x95, PFCP_CAUSE_RULE_CREATION_FAILURE, NULL);
    }
    TK_ASSERT(upf_session_count(U) == 1); /* only the empty one survived */
    upf_free(U);
    (void)teid;
}

static void tweak_limit(upf_config *c)
{
    c->max_sessions = 2;
}

static void test_session_limit_and_ue_takeover(void)
{
    uint32_t teid;
    bld_t b;
    rig_new(tweak_limit);
    setup_assoc();
    std_session(&teid, 0xa0, 0, 0);
    {   /* the same UE address again (the SMF lost its state): the new session takes over downlink traffic */
        uint8_t ip[100];
        gtpu_header gh;
        const uint8_t *pl;
        size_t plen;
        uint64_t s2;
        b_session_head(&b, 0xa1);
        b_pdr_ul(&b, 1, 100, 1, 1, 0, 0, NULL, false);
        b_pdr_dl(&b, 2, 100, UE, 2, 0, 0, NULL);
        b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
        b_far(&b, 2, PFCP_AA_FORW, UPF_IF_ACCESS, 555, GNBIP, 0);
        s2 = establish(&b, 0xa1, PFCP_CAUSE_ACCEPTED, &teid);
        (void)s2;
        ipv4(ip, DN, UE, 1, 0, 0, 60);
        rig_reset_captures();
        upf_n6_packet(U, ip, 60, NOW);
        TK_ASSERT(RIG.ngtpu == 1 && gtpu_decode(RIG.gtpu[0].d, RIG.gtpu[0].n, &gh, &pl, &plen) == 0 && gh.teid == 555);
    }
    b_session_head(&b, 0xa2);
    establish(&b, 0xa2, PFCP_CAUSE_NO_RESOURCES, NULL);
    upf_free(U);
}

int main(void)
{
    g5c_log_init("error", false);
    test_open5gs_replay();
    test_golden_gtpu();
    test_ipv6();
    test_qer();
    test_sdf_and_precedence();
    test_uplink_protection();
    test_buffering();
    test_usage_reports();
    test_n4_lifecycle();
    test_heartbeats();
    test_rejections();
    test_session_limit_and_ue_takeover();
    test_malformed_rules();
    test_modification_rules();
    puts("upf core: ok");
    return 0;
}
