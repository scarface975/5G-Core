/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NAS codec unit tests: IEs, security envelope, framing, fuzz regressions and a decode/encode round-trip property. */
#include "g5c/nas.h"
#include "g5c/testkit.h"

static void test_plmn(void)
{
    uint8_t p[3];
    char mcc[4], mnc[4];
    TK_ASSERT(nas_plmn_encode("001", "01", p) == 0 && p[0] == 0x00 && p[1] == 0xf1 && p[2] == 0x10);
    TK_ASSERT(nas_plmn_decode(p, 3, mcc, mnc) == 0 && strcmp(mcc, "001") == 0 && strcmp(mnc, "01") == 0);
    TK_ASSERT(nas_plmn_encode("310", "260", p) == 0 && p[0] == 0x13 && p[1] == 0x00 && p[2] == 0x62);
    TK_ASSERT(nas_plmn_decode(p, 3, mcc, mnc) == 0 && strcmp(mcc, "310") == 0 && strcmp(mnc, "260") == 0);
    TK_ASSERT(nas_plmn_encode("1", "01", p) != 0 && nas_plmn_encode("001", "1", p) != 0 && nas_plmn_encode("00a", "01", p) != 0);
    TK_ASSERT(nas_plmn_decode(p, 2, mcc, mnc) == NAS_E_TRUNCATED);
}

static void test_mobile_identity(void)
{
    nas_mobile_identity g, d;
    g5c_bytes b;
    uint8_t v[16];
    char msin[16], *s;
    g5c_bytes_init(&b);

    memset(&g, 0, sizeof g);
    g.kind = NAS_ID_GUTI;
    strcpy(g.mcc, "001");
    strcpy(g.mnc, "01");
    g.amf_region = 2;
    g.amf_set = 0x3ff;
    g.amf_pointer = 0x2a;
    g.tmsi = 0xdeadbeef;
    TK_ASSERT(nas_mobile_identity_encode(&g, &b) == 0 && b.len == 11);
    TK_ASSERT(nas_mobile_identity_decode(b.data, b.len, &d) == 0 && d.kind == NAS_ID_GUTI && d.amf_set == 0x3ff &&
              d.amf_pointer == 0x2a && d.tmsi == 0xdeadbeef && strcmp(d.mcc, "001") == 0 && d.amf_region == 2);
    g5c_bytes_clear(&b);

    memset(&g, 0, sizeof g);
    g.kind = NAS_ID_STMSI;
    g.amf_set = 1;
    g.amf_pointer = 1;
    g.tmsi = 7;
    TK_ASSERT(nas_mobile_identity_encode(&g, &b) == 0);
    TK_ASSERT(nas_mobile_identity_decode(b.data, b.len, &d) == 0 && d.kind == NAS_ID_STMSI && d.amf_set == 1 && d.tmsi == 7);
    g5c_bytes_free(&b);

    /* SUCI, null scheme */
    TK_ASSERT(tk_unhex("0100f110000000001032547698", v, sizeof v) == 13);
    TK_ASSERT(nas_mobile_identity_decode(v, 13, &d) == 0 && d.kind == NAS_ID_SUCI && strcmp(d.mcc, "001") == 0 &&
              strcmp(d.mnc, "01") == 0 && d.scheme == 0);
    TK_ASSERT(nas_suci_null_scheme_msin(&d, msin, sizeof msin) && strcmp(msin, "0123456789") == 0);
    s = nas_suci_to_string(&d);
    TK_ASSERT(strcmp(s, "suci-0-001-01-0000-0-0-0123456789") == 0);
    free(s);
    g5c_bytes_init(&b);
    TK_ASSERT(nas_mobile_identity_encode(&d, &b) == 0 && b.len == 13 && memcmp(b.data, v, 13) == 0);
    g5c_bytes_free(&b);
    TK_ASSERT(nas_mobile_identity_decode(v, 7, &d) == NAS_E_TRUNCATED);
}

static void test_nibbles_and_capabilities(void)
{
    nas_ngksi k = nas_ngksi_from_nibble(0x7);
    nas_reg_type r = nas_reg_type_from_nibble(0x9);
    nas_ue_sec_cap c;
    uint8_t v[2] = {0xf0, 0xe0};
    TK_ASSERT(!k.mapped && k.ksi == 7);
    k.ksi = 3;
    TK_ASSERT(nas_ngksi_to_nibble(k) == 3);
    TK_ASSERT(r.follow_on && r.kind == 1 && nas_reg_type_to_nibble(r) == 0x9);
    TK_ASSERT(nas_ue_sec_cap_decode(v, 2, &c) == 0);
    TK_ASSERT(nas_supports_ea(&c, 0) && nas_supports_ea(&c, 3) && !nas_supports_ea(&c, 4) && !nas_supports_ea(&c, 9));
    TK_ASSERT(nas_supports_ia(&c, 2) && !nas_supports_ia(&c, 3));
    TK_ASSERT(nas_selected_algorithms(0, 2) == 0x02 && nas_selected_algorithms(2, 2) == 0x22);
}

static void test_nssai_dnn(void)
{
    nas_snssai l[2] = {{1, false, 0}, {2, true, 0x010203}}, back[4];
    g5c_bytes b;
    char dnn[64];
    g5c_bytes_init(&b);
    TK_ASSERT(nas_nssai_encode(l, 2, &b) == 0);
    TK_ASSERT(nas_nssai_decode(b.data, b.len, back, 4) == 2 && back[0].sst == 1 && !back[0].has_sd && back[1].sst == 2 &&
              back[1].has_sd && back[1].sd == 0x010203);
    TK_ASSERT(nas_nssai_decode((const uint8_t[]){5, 1}, 2, back, 4) < 0);
    g5c_bytes_clear(&b);
    TK_ASSERT(nas_dnn_encode("internet", &b) == 0 && b.len == 9 && b.data[0] == 8);
    TK_ASSERT(nas_dnn_decode(b.data, b.len, dnn, sizeof dnn) == 0 && strcmp(dnn, "internet") == 0);
    g5c_bytes_clear(&b);
    TK_ASSERT(nas_dnn_encode("a.b", &b) == 0);
    TK_ASSERT(nas_dnn_decode(b.data, b.len, dnn, sizeof dnn) == 0 && strcmp(dnn, "a.b") == 0);
    g5c_bytes_free(&b);
    {
        g5c_bytes e;
        g5c_bytes_init(&e);
        TK_ASSERT(nas_dnn_encode("a..b", &e) != 0 && nas_dnn_encode("", &e) != 0);
        g5c_bytes_free(&e);
    }
}

static void test_security(void)
{
    nas_msg m;
    g5c_bytes plain;
    nas_sec_ctx c;
    static const struct {
        uint8_t sht;
        nas_enc_alg enc;
    } cases[] = {{1, NAS_EA0}, {2, NAS_EA2}, {3, NAS_EA0}, {4, NAS_EA2}};
    TK_ASSERT(nas_msg_init(&m, "Registration complete"));
    g5c_bytes_init(&plain);
    TK_ASSERT(nas_msg_encode(&m, &plain) == 0);
    nas_msg_free(&m);
    memset(c.knas_int, 0x0a, 16);
    memset(c.knas_enc, 0x0b, 16);
    c.int_alg = NAS_IA2;
    for (size_t i = 0; i < 4; i++) {
        g5c_bytes wire, opened;
        nas_any a;
        c.enc_alg = cases[i].enc;
        g5c_bytes_init(&wire);
        g5c_bytes_init(&opened);
        TK_ASSERT(nas_protect(&c, cases[i].sht, G5C_DIR_UL, 0x0102, plain.data, plain.len, &wire) == 0);
        TK_ASSERT(nas_any_decode(wire.data, wire.len, &a) == 0 && a.is_protected && a.prot.seq == 0x02);
        TK_ASSERT(nas_protected_verify(&a.prot, &c, G5C_DIR_UL, 0x0102));
        TK_ASSERT(!nas_protected_verify(&a.prot, &c, G5C_DIR_DL, 0x0102));
        TK_ASSERT(!nas_protected_verify(&a.prot, &c, G5C_DIR_UL, 0x0202));
        TK_ASSERT(nas_protected_open(&a.prot, &c, G5C_DIR_UL, 0x0102, &opened) == 0);
        TK_ASSERT(opened.len == plain.len && memcmp(opened.data, plain.data, plain.len) == 0);
        if (cases[i].sht == 2 || cases[i].sht == 4)
            TK_ASSERT(a.prot.payload_len != plain.len || memcmp(a.prot.payload, plain.data, plain.len) != 0); /* ciphered */
        nas_any_free(&a);
        g5c_bytes_free(&wire);
        g5c_bytes_free(&opened);
    }
    {   /* tampering is detected */
        g5c_bytes wire;
        nas_any a;
        const uint8_t body[4] = {0x7e, 0x00, 0x5e, 0x01};
        c.enc_alg = NAS_EA2;
        g5c_bytes_init(&wire);
        TK_ASSERT(nas_protect(&c, 2, G5C_DIR_DL, 7, body, 4, &wire) == 0);
        wire.data[wire.len - 1] ^= 1;
        TK_ASSERT(nas_any_decode(wire.data, wire.len, &a) == 0 && !nas_protected_verify(&a.prot, &c, G5C_DIR_DL, 7));
        nas_any_free(&a);
        g5c_bytes_free(&wire);
    }
    {
        nas_int_alg ia;
        nas_enc_alg ea;
        TK_ASSERT(nas_int_alg_from_id(1, &ia) != 0 && nas_enc_alg_from_id(3, &ea) != 0);
        TK_ASSERT(nas_int_alg_from_id(2, &ia) == 0 && ia == NAS_IA2 && nas_enc_alg_from_id(0, &ea) == 0 && ea == NAS_EA0);
    }
    g5c_bytes_free(&plain);
}

static void assert_roundtrip(const char *hex)
{
    uint8_t b[256];
    long n = tk_unhex(hex, b, sizeof b);
    nas_msg m, m2;
    g5c_bytes re;
    TK_ASSERT(n > 0);
    TK_ASSERT(nas_msg_decode(b, (size_t)n, &m) == 0);
    g5c_bytes_init(&re);
    TK_ASSERT(nas_msg_encode(&m, &re) == 0);
    TK_ASSERT(nas_msg_decode(re.data, re.len, &m2) == 0);
    TK_ASSERT(nas_msg_equal(&m, &m2)); /* re-encoded message decodes to the same value */
    TK_ASSERT(re.len == (size_t)n && memcmp(re.data, b, re.len) == 0); /* unknown IEs preserved byte for byte */
    nas_msg_free(&m);
    nas_msg_free(&m2);
    g5c_bytes_free(&re);
}

static void test_fuzz_regressions(void)
{
    assert_roundtrip("2e0b01ccffffffff"); /* unknown one-octet optional IEs (IEI >= 0x80) were re-encoded as two octets */
}

static void test_framing_errors(void)
{
    nas_msg m;
    uint8_t b1[] = {0x7e};
    uint8_t b2[] = {0x7e, 0x00, 0xff};
    uint8_t b3[] = {0x00, 0x00, 0x41};
    uint8_t b4[] = {0x7e, 0x02, 0x41}; /* protected header type: must go through nas_any_decode */
    TK_ASSERT(nas_msg_decode(b1, 1, &m) == NAS_E_TRUNCATED);
    TK_ASSERT(nas_msg_decode(b2, 3, &m) == NAS_E_MSGTYPE);
    TK_ASSERT(nas_msg_decode(b3, 3, &m) == NAS_E_EPD);
    TK_ASSERT(nas_msg_decode(b4, 3, &m) == NAS_E_PROTECTED);
    TK_ASSERT(nas_msg_decode(NULL, 0, &m) == NAS_E_TRUNCATED);
}

static void test_build_and_decode(void)
{
    nas_msg m, d;
    g5c_bytes wire;
    const uint8_t abba[2] = {0, 0}, rnd[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const uint8_t ksi = 0x01;
    const uint8_t *got;
    size_t gl = 0;
    TK_ASSERT(nas_msg_init(&m, "Authentication request"));
    TK_ASSERT(nas_msg_set(&m, "ngKSI", &ksi, 1));
    TK_ASSERT(nas_msg_set(&m, "Spare half octet", (const uint8_t[]){0}, 1));
    TK_ASSERT(nas_msg_set(&m, "ABBA", abba, 2));
    TK_ASSERT(nas_msg_set(&m, "Authentication parameter RAND (5G authentication challenge)", rnd, 16));
    TK_ASSERT(!nas_msg_set(&m, "No such IE", rnd, 16));
    g5c_bytes_init(&wire);
    TK_ASSERT(nas_msg_encode(&m, &wire) == 0);
    TK_ASSERT(wire.data[0] == 0x7e && wire.data[2] == 0x56 && wire.data[3] == 0x01 && wire.data[4] == 0x02);
    TK_ASSERT(nas_msg_decode(wire.data, wire.len, &d) == 0);
    got = nas_msg_get(&d, "Authentication parameter RAND (5G authentication challenge)", &gl);
    TK_ASSERT(got && gl == 16 && memcmp(got, rnd, 16) == 0);
    TK_ASSERT(nas_msg_get(&d, "Authentication parameter AUTN (5G authentication challenge)", NULL) == NULL);
    nas_msg_free(&d);
    nas_msg_free(&m);
    {   /* a mandatory IE that is absent is reported by name */
        nas_msg m2;
        g5c_bytes w2;
        g5c_bytes_init(&w2);
        TK_ASSERT(nas_msg_init(&m2, "Authentication request"));
        TK_ASSERT(nas_msg_encode(&m2, &w2) == NAS_E_MISSING);
        nas_msg_free(&m2);
        g5c_bytes_free(&w2);
        {
            uint8_t cut[] = {0x7e, 0x00, 0x56, 0x00};
            TK_ASSERT(nas_msg_decode(cut, 4, &m2) != 0);
        }
    }
    g5c_bytes_free(&wire);
}

/* Fuzz-style: arbitrary bytes behind a valid EPD must never crash and must round-trip losslessly when they decode. */
static void test_random_input(void)
{
    tk_rng rng = {1234};
    int decoded = 0;
    for (int it = 0; it < 200000; it++) {
        uint8_t b[64];
        size_t n = 3 + (size_t)(tk_rng_next(&rng) % 40);
        nas_msg m, m2;
        g5c_bytes re;
        tk_rng_bytes(&rng, b, sizeof b);
        b[0] = (tk_rng_next(&rng) & 1) ? NAS_EPD_5GMM : NAS_EPD_5GSM;
        if (b[0] == NAS_EPD_5GMM)
            b[1] = 0;
        if (nas_msg_decode(b, n, &m) != 0)
            continue;
        decoded++;
        g5c_bytes_init(&re);
        TK_ASSERT(nas_msg_encode(&m, &re) == 0);
        TK_ASSERT(nas_msg_decode(re.data, re.len, &m2) == 0 && nas_msg_equal(&m, &m2));
        nas_msg_free(&m);
        nas_msg_free(&m2);
        g5c_bytes_free(&re);
    }
    TK_ASSERT(decoded > 100); /* the generator does reach valid messages */
}

int main(void)
{
    TK_ASSERT(NAS_NMESSAGES == 48);
    test_plmn();
    test_mobile_identity();
    test_nibbles_and_capabilities();
    test_nssai_dnn();
    test_security();
    test_fuzz_regressions();
    test_framing_errors();
    test_build_and_decode();
    test_random_input();
    puts("nas: ok");
    return 0;
}
