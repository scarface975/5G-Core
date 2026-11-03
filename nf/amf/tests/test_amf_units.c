/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* AMF unit tests: the 5GMM message builders against byte-exact expectations from TS 24.501 / TS 24.008, the NAS COUNT estimation */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include "g5c/testkit.h"
#include "nasmsg.h"
#include "priv.h"

/* ---- timers (TS 24.008 10.5.7.3 / 10.5.7.4a) ---- */

static void test_gprs_timers(void)
{
    /* GPRS timer 2: unit 2 s (000), 1 min (001), decihours (010) */
    TK_ASSERT(nm_gprs_timer2(2) == 0x01);
    TK_ASSERT(nm_gprs_timer2(60) == 0x1e); /* 30 x 2 s: the 2 s unit is used while it fits in 5 bits */
    TK_ASSERT(nm_gprs_timer2(720) == 0x2c); /* 12 minutes: unit 1 min, value 12 */
    /* GPRS timer 3: 10 min (000), 1 h (001), 10 h (010), 2 s (011), 30 s (100), 1 min (101), 320 h (110) */
    TK_ASSERT(nm_gprs_timer3(600) == 0x01);
    TK_ASSERT(nm_gprs_timer3(3600) == (uint8_t)(1 << 5 | 1));
    TK_ASSERT(nm_gprs_timer3(36000) == (uint8_t)(2 << 5 | 1));
    TK_ASSERT(nm_gprs_timer3(60) == (uint8_t)(5 << 5 | 1));
    TK_ASSERT(nm_gprs_timer3(3240) == 0x06); /* 54 min does not fit 5 bits in a finer unit: rounded up to 6 x 10 min */
    TK_ASSERT(nm_gprs_timer3(30) == (uint8_t)(4 << 5 | 1));
    TK_ASSERT(nm_gprs_timer3(6) == (uint8_t)(3 << 5 | 3));
    /* not representable exactly: rounded up in the smallest unit that holds it */
    TK_ASSERT(nm_gprs_timer3(1) == (uint8_t)(3 << 5 | 1));
}

/* ---- builders ---- */

static void test_builders(void)
{
    g5c_bytes b;
    uint8_t abba[2] = {0, 0}, rnd[16], autn[16];
    for (int i = 0; i < 16; i++) {
        rnd[i] = (uint8_t)i;
        autn[i] = (uint8_t)(0xa0 + i);
    }
    g5c_bytes_init(&b);
    /* IDENTITY REQUEST (SUCI) */
    TK_ASSERT(nm_identity_request(&b) == 0);
    TK_ASSERT(b.len == 4 && b.data[0] == 0x7e && b.data[1] == 0x00 && b.data[2] == 0x5b && b.data[3] == 0x01);
    g5c_bytes_clear(&b);
    /* AUTHENTICATION REQUEST: ngKSI 3 / spare, ABBA, RAND (TV 0x21), AUTN (TLV 0x20) */
    TK_ASSERT(nm_auth_request(3, abba, rnd, autn, &b) == 0);
    TK_ASSERT(b.len == 3 + 1 + 3 + 17 + 18);
    TK_ASSERT(b.data[2] == 0x56 && b.data[3] == 0x03 && b.data[4] == 0x02 && b.data[5] == 0 && b.data[6] == 0 && b.data[7] == 0x21 && b.data[8] == 0);
    TK_ASSERT(b.data[24] == 0x20 && b.data[25] == 16 && b.data[26] == 0xa0);
    g5c_bytes_clear(&b);
    /* AUTHENTICATION REJECT / REGISTRATION REJECT */
    TK_ASSERT(nm_auth_reject(&b) == 0 && b.len == 3 && b.data[2] == 0x58);
    g5c_bytes_clear(&b);
    TK_ASSERT(nm_reg_reject(7, &b) == 0 && b.len == 4 && b.data[2] == 0x44 && b.data[3] == 7);
    g5c_bytes_clear(&b);
    /* SECURITY MODE COMMAND: NEA2 | NIA2 = 0x22, ngKSI 1, the replayed capability, IMEISV request E1, RINMR 36 01 02 */
    {
        static const uint8_t cap[4] = {0xf0, 0xf0, 0xf0, 0xf0};
        static const uint8_t want[] = {0x7e, 0x00, 0x5d, 0x22, 0x01, 0x04, 0xf0, 0xf0, 0xf0, 0xf0, 0xe1, 0x36, 0x01, 0x02};
        TK_ASSERT(nm_smc(2, 2, 1, cap, 4, true, true, &b) == 0);
        TK_ASSERT(b.len == sizeof want && memcmp(b.data, want, sizeof want) == 0);
        g5c_bytes_clear(&b);
    }
    /* SERVICE ACCEPT / REJECT */
    TK_ASSERT(nm_service_accept(true, (uint16_t)(1u << 1), true, (uint16_t)(1u << 1), &b) == 0);
    {
        static const uint8_t want[] = {0x7e, 0x00, 0x4e, 0x50, 0x02, 0x02, 0x00, 0x26, 0x02, 0x02, 0x00};
        TK_ASSERT(b.len == sizeof want && memcmp(b.data, want, sizeof want) == 0);
    }
    g5c_bytes_clear(&b);
    TK_ASSERT(nm_service_reject(9, false, 0, &b) == 0 && b.len == 4 && b.data[2] == 0x4d && b.data[3] == 9);
    g5c_bytes_clear(&b);
    /* DL NAS TRANSPORT: payload container type 1, container (LV-E), PDU session id 5 (TV 0x12), 5GMM cause #90 (TV 0x58) */
    {
        static const uint8_t pl[] = {0x2e, 0x05, 0x01, 0xc2};
        static const uint8_t want[] = {0x7e, 0x00, 0x68, 0x01, 0x00, 0x04, 0x2e, 0x05, 0x01, 0xc2, 0x12, 0x05, 0x58, 0x5a};
        TK_ASSERT(nm_dl_nas_transport(1, pl, sizeof pl, 5, 90, &b) == 0);
        TK_ASSERT(b.len == sizeof want && memcmp(b.data, want, sizeof want) == 0);
        g5c_bytes_clear(&b);
    }
    /* DE-REGISTRATION REQUEST (UE terminated), re-registration required, 3GPP access */
    TK_ASSERT(nm_dereg_request_ue_term(true, 0, &b) == 0);
    TK_ASSERT(b.len == 4 && b.data[2] == 0x47 && b.data[3] == 0x05);
    g5c_bytes_clear(&b);
    TK_ASSERT(nm_dereg_accept_ue_orig(&b) == 0 && b.len == 3 && b.data[2] == 0x46);
    g5c_bytes_clear(&b);
    g5c_bytes_free(&b);
}

/* Registration reject with the back-off timer (TS 24.501 8.2.9): cause #22 and T3346 */
static void test_reg_reject_t3346(void)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    TK_ASSERT(nm_reg_reject_t3346(22, 60, &b) == 0);
    TK_ASSERT(b.len == 7 && b.data[2] == 0x44 && b.data[3] == 22 && b.data[4] == 0x5f && b.data[5] == 1 && b.data[6] == 30); /* 60 s: units of 2 s */
    g5c_bytes_free(&b);
    g5c_bytes_init(&b);
    TK_ASSERT(nm_reg_reject_t3346(22, 600, &b) == 0 && b.data[6] == (1 << 5 | 10)); /* 10 minutes */
    g5c_bytes_free(&b);
    g5c_bytes_init(&b);
    TK_ASSERT(nm_reg_reject_t3346(11, 0, &b) == 0 && b.len == 4); /* no timer */
    g5c_bytes_free(&b);
}

static void test_registration_accept(void)
{
    nm_regacc ra;
    nas_msg m;
    g5c_bytes b;
    size_t n;
    const uint8_t *v;
    memset(&ra, 0, sizeof ra);
    nas_plmn_encode("001", "01", ra.plmn);
    ra.id.region = 2;
    ra.id.set = 1;
    ra.id.pointer = 0;
    ra.tmsi = 0xc0ffee42;
    ra.tai[0].tac = 1;
    ra.tai[1].tac = 2;
    ra.tai[2].tac = 3;
    for (int i = 0; i < 3; i++)
        memcpy(ra.tai[i].plmn, ra.plmn, 3);
    ra.ntai = 3;
    ra.allowed[0].sst = 1;
    ra.allowed[1].sst = 2;
    ra.allowed[1].has_sd = true;
    ra.allowed[1].sd = 0x000002;
    ra.nallowed = 2;
    ra.rejected[0].sst = 7;
    ra.nrejected = 1;
    ra.has_psi_status = true;
    ra.psi_status = 0x0022;
    ra.t3512 = 3600;
    ra.t3502 = 720;
    g5c_bytes_init(&b);
    TK_ASSERT(nm_reg_accept(&ra, &b) == 0);
    TK_ASSERT(nas_msg_decode(b.data, b.len, &m) == NAS_OK && m.def->msg_type == 0x42);
    v = nas_msg_get(&m, "5GS registration result", &n);
    TK_ASSERT(v != NULL && n == 1 && v[0] == 0x01);
    v = nas_msg_get(&m, "5G-GUTI", &n);
    {
        static const uint8_t want[] = {0xf2, 0x00, 0xf1, 0x10, 0x02, 0x00, 0x40, 0xc0, 0xff, 0xee, 0x42};
        TK_ASSERT(v != NULL && n == sizeof want && memcmp(v, want, n) == 0);
    }
    v = nas_msg_get(&m, "TAI list", &n);
    {
        /* one partial list: type 00 (TACs of one PLMN), three elements: 0x02, PLMN, three TACs */
        static const uint8_t want[] = {0x02, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x03};
        TK_ASSERT(v != NULL && n == sizeof want && memcmp(v, want, n) == 0);
    }
    v = nas_msg_get(&m, "Allowed NSSAI", &n);
    {
        static const uint8_t want[] = {0x01, 0x01, 0x04, 0x02, 0x00, 0x00, 0x02};
        TK_ASSERT(v != NULL && n == sizeof want && memcmp(v, want, n) == 0);
    }
    v = nas_msg_get(&m, "Rejected NSSAI", &n);
    TK_ASSERT(v != NULL && n == 2 && v[0] == 0x10 && v[1] == 0x07); /* length 1, cause 0 (not available in the PLMN), SST 7 */
    v = nas_msg_get(&m, "PDU session status", &n);
    TK_ASSERT(v != NULL && n == 2 && v[0] == 0x22 && v[1] == 0x00);
    v = nas_msg_get(&m, "T3512 value", &n);
    TK_ASSERT(v != NULL && n == 1 && v[0] == (uint8_t)(1 << 5 | 1));
    v = nas_msg_get(&m, "T3502 value", &n);
    TK_ASSERT(v != NULL && n == 1);
    nas_msg_free(&m);
    g5c_bytes_free(&b);
}

/* ---- keys and counts ---- */

static void test_security(void)
{
    amf_sec s;
    uint8_t kamf[32], abba[2] = {0, 0}, nh1[32], nh2[32];
    const uint8_t *p[1];
    size_t l[1] = {32};
    memset(kamf, 0x11, sizeof kamf);
    sec_new_context(&s, kamf, 2, abba);
    TK_ASSERT(s.valid && s.ngksi == 2 && s.ul_count == 0 && s.dl_count == 0);
    sec_derive_kgnb(&s, 5);
    {
        uint8_t want[32];
        TK_ASSERT(g5c_kgnb(kamf, 5, 0x01, want) == 0 && memcmp(want, s.kgnb, 32) == 0);
    }
    /* the first pair sent has NCC 2, derived from NH(1) = KDF(KgNB), which is never sent (TS 33.501 6.9.2.3, A.10) */
    p[0] = s.kgnb;
    TK_ASSERT(g5c_kdf(kamf, 32, 0x6f, p, l, 1, nh1) == 0);
    p[0] = nh1;
    TK_ASSERT(g5c_kdf(kamf, 32, 0x6f, p, l, 1, nh2) == 0);
    sec_next_hop(&s);
    TK_ASSERT(s.ncc == 2 && memcmp(s.nh, nh2, 32) == 0);
    sec_next_hop(&s);
    TK_ASSERT(s.ncc == 3 && memcmp(s.nh, nh2, 32) != 0);
    /* a new KgNB restarts the chain */
    sec_derive_kgnb(&s, 9);
    TK_ASSERT(!s.nh_valid && s.ncc == 0);

    /* NAS protection round trip and the COUNT estimation across the 8-bit wrap */
    {
        amf_sec ue;
        g5c_bytes out, plain;
        static const uint8_t msg[] = {0x7e, 0x00, 0x43};
        nas_any a;
        uint32_t count = 0;
        sec_new_context(&s, kamf, 0, abba);
        s.int_alg = 2;
        s.enc_alg = 2;
        sec_derive_nas_keys(&s);
        ue = s;
        /* the UE sends with counts 254, 255, 256, 257: the receiver expects 254 first */
        s.ul_count = 254;
        for (uint32_t c = 254; c < 258; c++) {
            nas_sec_ctx ctx;
            sec_ctx_view(&ue, &ctx);
            g5c_bytes_init(&out);
            g5c_bytes_init(&plain);
            TK_ASSERT(nas_protect(&ctx, 2, G5C_DIR_UL, c, msg, sizeof msg, &out) == NAS_OK);
            TK_ASSERT(nas_any_decode(out.data, out.len, &a) == NAS_OK && a.is_protected);
            TK_ASSERT(sec_open_ul(&s, &a.prot, &plain, &count, true) == 0 && count == c);
            TK_ASSERT(plain.len == sizeof msg && memcmp(plain.data, msg, sizeof msg) == 0);
            TK_ASSERT(s.ul_count == c + 1);
            /* the same message again is a replay */
            g5c_bytes_clear(&plain);
            TK_ASSERT(sec_open_ul(&s, &a.prot, &plain, &count, true) != 0);
            nas_any_free(&a);
            g5c_bytes_free(&out);
            g5c_bytes_free(&plain);
        }
        /* a flipped bit fails the integrity check */
        {
            nas_sec_ctx ctx;
            sec_ctx_view(&ue, &ctx);
            g5c_bytes_init(&out);
            g5c_bytes_init(&plain);
            TK_ASSERT(nas_protect(&ctx, 2, G5C_DIR_UL, 258, msg, sizeof msg, &out) == NAS_OK);
            out.data[8] ^= 1;
            TK_ASSERT(nas_any_decode(out.data, out.len, &a) == NAS_OK);
            TK_ASSERT(sec_open_ul(&s, &a.prot, &plain, &count, true) == -1);
            TK_ASSERT(s.ul_count == 258);
            nas_any_free(&a);
            g5c_bytes_free(&out);
            g5c_bytes_free(&plain);
        }
    }
}

static void test_algorithm_selection(void)
{
    amf a;
    uint8_t ia = 9, ea = 9;
    static const uint8_t all[4] = {0xf0, 0xf0, 0xf0, 0xf0};
    static const uint8_t nea0_only[2] = {0x80, 0x20};
    static const uint8_t no_nia2[2] = {0xe0, 0x50};
    static const uint8_t snow_only[2] = {0x40, 0x40};
    memset(&a, 0, sizeof a);
    a.cfg.int_pref[0] = 2;
    a.cfg.nint = 1;
    a.cfg.enc_pref[0] = 2;
    a.cfg.enc_pref[1] = 0;
    a.cfg.nenc = 2;
    TK_ASSERT(sec_select_algs(&a, all, 4, &ia, &ea) == 0 && ia == 2 && ea == 2);
    TK_ASSERT(sec_select_algs(&a, nea0_only, 2, &ia, &ea) == 0 && ia == 2 && ea == 0);
    TK_ASSERT(sec_select_algs(&a, no_nia2, 2, &ia, &ea) != 0);  /* no integrity algorithm in common */
    TK_ASSERT(sec_select_algs(&a, snow_only, 2, &ia, &ea) != 0); /* SNOW 3G is not on offer (ADR-0012) */
    TK_ASSERT(sec_select_algs(&a, all, 1, &ia, &ea) != 0);       /* truncated capability */
    /* NIA0 is only used when configured */
    a.cfg.int_pref[1] = 0;
    a.cfg.nint = 2;
    {
        static const uint8_t ia0_ia1[2] = {0xe0, 0xc0};
        TK_ASSERT(sec_select_algs(&a, ia0_ia1, 2, &ia, &ea) == 0 && ia == 0);
    }
}

/* ---- maps and identifiers ---- */

static void test_maps(void)
{
    amf_map *m = amap_new();
    amf_smap *s = smap_new();
    static int vals[5000];
    char key[32];
    for (int i = 0; i < 5000; i++)
        amap_put(m, (uint64_t)i * 7919u + 1, &vals[i]);
    TK_ASSERT(amap_count(m) == 5000);
    for (int i = 0; i < 5000; i++)
        TK_ASSERT(amap_get(m, (uint64_t)i * 7919u + 1) == &vals[i]);
    TK_ASSERT(amap_get(m, 2) == NULL);
    for (int i = 0; i < 5000; i += 2)
        amap_del(m, (uint64_t)i * 7919u + 1);
    TK_ASSERT(amap_count(m) == 2500 && amap_get(m, 1) == NULL && amap_get(m, 7919u + 1) == &vals[1]);
    amap_put(m, 7919u + 1, &vals[0]);
    TK_ASSERT(amap_count(m) == 2500 && amap_get(m, 7919u + 1) == &vals[0]);
    for (int i = 0; i < 300; i++) {
        snprintf(key, sizeof key, "imsi-0010100000%05d", i);
        smap_put(s, key, &vals[i]);
    }
    snprintf(key, sizeof key, "imsi-0010100000%05d", 123);
    TK_ASSERT(smap_get(s, key) == &vals[123]);
    smap_del(s, key);
    TK_ASSERT(smap_get(s, key) == NULL);
    TK_ASSERT(smap_get(s, "nope") == NULL);
    amap_free(m);
    smap_free(s);
}

static void test_bitrates(void)
{
    uint64_t v = 0;
    TK_ASSERT(amf_parse_bitrate("1 Gbps", &v) && v == 1000000000ULL);
    TK_ASSERT(amf_parse_bitrate("200 Mbps", &v) && v == 200000000ULL);
    TK_ASSERT(amf_parse_bitrate("64 Kbps", &v) && v == 64000ULL);
    TK_ASSERT(amf_parse_bitrate("1.5 Gbps", &v) && v == 1500000000ULL);
    TK_ASSERT(amf_parse_bitrate("100bps", &v) && v == 100);
    TK_ASSERT(!amf_parse_bitrate("fast", &v) && !amf_parse_bitrate("5 parsecs", &v) && !amf_parse_bitrate(NULL, &v));
    TK_ASSERT(!amf_parse_bitrate("-1 Mbps", &v));
}

static void test_snssai_helpers(void)
{
    nas_snssai a = {1, false, 0}, b = {1, true, 5}, c;
    g5c_json *j = g5c_json_new_obj();
    amf_snssai_json(&b, j, "s");
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(j, "s"), "sd"), "000005") == 0);
    TK_ASSERT(amf_snssai_from_json(g5c_json_get(j, "s"), &c) && amf_snssai_eq(&b, &c));
    TK_ASSERT(!amf_snssai_eq(&a, &b));
    {
        nas_snssai l[2] = {a, b};
        TK_ASSERT(amf_snssai_in(l, 2, &b) && !amf_snssai_in(l, 1, &b));
    }
    g5c_json_free(j);
    /* bad SD length / non-hex are refused */
    j = g5c_json_new_obj();
    g5c_json_set_int(j, "sst", 1);
    g5c_json_set_str(j, "sd", "12");
    TK_ASSERT(!amf_snssai_from_json(j, &c));
    g5c_json_set_str(j, "sd", "zzzzzz");
    TK_ASSERT(!amf_snssai_from_json(j, &c));
    g5c_json_free(j);
}

/* ---- NGAP builders ---- */

static void test_ngap_builders(void)
{
    amf a;
    g5c_json *g, *p;
    g5c_bytes b;
    char err[120];
    g5c_json *back;
    memset(&a, 0, sizeof a);
    nas_plmn_encode("001", "01", a.cfg.plmn);
    a.cfg.id.region = 2;
    a.cfg.id.set = 1;
    a.cfg.id.pointer = 0;
    g = ng_guami(&a);
    TK_ASSERT(strcmp(g5c_json_get_str(g, "pLMNIdentity"), "00f110") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(g, "aMFSetID"), "hex"), "0040") == 0);
    g5c_json_free(g);
    /* a built PDU encodes and decodes */
    p = ng_pdu_new("successfulOutcome", NGAP_PROC_NGSetup, "reject");
    ng_ie(p, NGAP_IE_AMFName, "reject", g5c_json_new_str("amf"));
    g = g5c_json_new_arr();
    {
        g5c_json *it = g5c_json_push(g, g5c_json_new_obj());
        g5c_json_set(it, "gUAMI", ng_guami(&a));
    }
    ng_ie(p, NGAP_IE_ServedGUAMIList, "reject", g);
    ng_ie(p, NGAP_IE_RelativeAMFCapacity, "ignore", g5c_json_new_int(255));
    g = g5c_json_new_arr();
    {
        nas_snssai s = {1, true, 0x010203};
        g5c_json *it = g5c_json_push(g, g5c_json_new_obj()), *sl = g5c_json_set(it, "sliceSupportList", g5c_json_new_arr());
        g5c_json_set(it, "pLMNIdentity", ng_plmn(a.cfg.plmn));
        g5c_json_set(g5c_json_push(sl, g5c_json_new_obj()), "s-NSSAI", ng_snssai_json(&s));
    }
    ng_ie(p, NGAP_IE_PLMNSupportList, "reject", g);
    g5c_bytes_init(&b);
    TK_ASSERT(ngap_encode(p, &b, err, sizeof err) == 0);
    back = ngap_decode(b.data, b.len, err, sizeof err);
    TK_ASSERT(back != NULL && g5c_json_equal(g5c_json_get(g5c_json_get(back, "successfulOutcome"), "procedureCode"), g5c_json_get(g5c_json_get(p, "successfulOutcome"), "procedureCode")));
    g5c_json_free(back);
    g5c_bytes_free(&b);
    g5c_json_free(p);
    /* the user location parser reads the NR alternative */
    {
        amf_tai t;
        char cell[12];
        const char *js = "{\"userLocationInformationNR\":{\"nR-CGI\":{\"pLMNIdentity\":\"00f110\",\"nRCellIdentity\":{\"len\":36,\"hex\":\"0000000100\"}},"
                         "\"tAI\":{\"pLMNIdentity\":\"00f110\",\"tAC\":\"000001\"}}}";
        g5c_json *u = g5c_json_parse(js, strlen(js), err, sizeof err);
        TK_ASSERT(u != NULL && ng_uli_parse(u, &t, cell) == 0 && t.tac == 1 && strcmp(cell, "000000010") == 0);
        g5c_json_free(u);
    }
}

/* ---- configuration ---- */

static amf *load(const char *yaml, char *err, size_t cap, g5c_nf **nf_out)
{
    g5c_json *j = g5c_yaml_parse(yaml, strlen(yaml), err, cap);
    g5c_common common;
    g5c_nf *nf;
    amf *a;
    if (j == NULL || g5c_common_parse(j, &common, err, cap) != 0)
        return NULL;
    common.port = 0;
    nf = g5c_nf_new(&common, err, cap);
    if (nf == NULL) {
        g5c_json_free(j);
        return NULL;
    }
    a = amf_from_config(j, nf, err, cap);
    g5c_json_free(j);
    if (a == NULL) {
        g5c_nf_free(nf);
        return NULL;
    }
    *nf_out = nf;
    return a;
}

static void test_config(void)
{
    static const char good[] = "name: a\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\n"
                               "amf:\n  guami: { region: 5, set: 700, pointer: 33 }\n  ngap: { address: 127.0.0.1, port: 0 }\n  tais: [ { tac: 1 }, { tac: '00000a' } ]\n"
                               "  slices: [ { sst: 1 }, { sst: 2, sd: '0000ff' } ]\n  security: { integrity: [NIA2], ciphering: [NEA0] }\n"
                               "  ausf: { uri: 'http://a:1/' }\n  udm: { uri: 'http://u:1' }\n  smf: { uri: 'http://s:1' }\n  timers: { t3550: 3 }\n";
    char err[300] = "";
    g5c_nf *nf = NULL;
    amf *a = load(good, err, sizeof err, &nf);
    g5c_json *info;
    TK_ASSERT(a != NULL);
    TK_ASSERT(amf_ngap_port(a) == 0);
    info = amf_nrf_info(a);
    {
        const g5c_json *ai = g5c_json_get(info, "amfInfo");
        TK_ASSERT(strcmp(g5c_json_get_str(ai, "amfRegionId"), "05") == 0);
        TK_ASSERT(strcmp(g5c_json_get_str(ai, "amfSetId"), "2BC") == 0); /* 700 */
        TK_ASSERT(g5c_json_len(g5c_json_get(ai, "taiList")) == 2);
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(ai, "guamiList"), 0), "amfId"), "05AF21") == 0); /* 5<<16 | 700<<6 | 33 */
    }
    g5c_json_free(info);
    amf_destroy(a);
    g5c_nf_free(nf);

    {   /* amf.overload */
        static const char y[] = "name: a\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\n"
                                "amf: { overload: { registrations_per_s: 50, per_gnb_per_s: 20, burst_s: 3, t3346_s: 120 }, ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }\n";
        nf = NULL;
        a = load(y, err, sizeof err, &nf);
        TK_ASSERT(a != NULL && a->cfg.ov_regs_per_s == 50 && a->cfg.ov_gnb_regs_per_s == 20 && a->cfg.ov_burst_s == 3 && a->cfg.ov_t3346 == 120);
        amf_destroy(a);
        g5c_nf_free(nf);
    }

    /* every one of these must be refused, with the setting named */
    {
        static const char *const bad[][2] = {
            {"amf.guami.region", "amf: { guami: { region: 256 }, ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"},
            {"SNOW 3G", "amf: { security: { integrity: [NIA1] }, ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"},
            {"amf.tais", "amf: { tais: [], ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"},
            {"required", "amf: { ausf: { uri: 'http://a:1' } }"},
            {"amf.timers.t3560", "amf: { timers: { t3560: 99999 }, ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"},
            {"needs `registrations_per_s` or `per_gnb_per_s`", "amf: { overload: { burst_s: 2 }, ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"},
            {"amf.overload.registrations_per_s", "amf: { overload: { registrations_per_s: 0 }, ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"},
            {"amf.overload.t3346_s", "amf: { overload: { per_gnb_per_s: 5, t3346_s: 1 }, ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"},
            {"amf.overload", "amf: { overload: { per_gnb_per_s: 5, surprise: 1 }, ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"},
            {"must be a mapping", "amf: { overload: 7, ausf: { uri: 'http://a:1' }, udm: { uri: 'http://u:1' }, smf: { uri: 'http://s:1' } }"},
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            char y[900];
            snprintf(y, sizeof y, "name: a\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\n%s\n", bad[i][1]);
            err[0] = 0;
            nf = NULL;
            a = load(y, err, sizeof err, &nf);
            TK_ASSERT(a == NULL);
            if (strstr(err, bad[i][0]) == NULL)
                TK_FAIL("config case %zu: wanted [%s] in [%s]", i, bad[i][0], err);
        }
    }
}

int main(void)
{
    g5c_log_init("error", false);
    test_gprs_timers();
    test_builders();
    test_registration_accept();
    test_reg_reject_t3346();
    test_security();
    test_algorithm_selection();
    test_maps();
    test_bitrates();
    test_snssai_helpers();
    test_ngap_builders();
    test_config();
    printf("amf units: OK\n");
    return 0;
}
