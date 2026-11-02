/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include "g5c/crypto.h"
#include "g5c/testkit.h"

static void roundtrip(g5c_profile p)
{
    uint8_t hn_secret[32], eph[32], hn_pub[33], msin[8], out[128], back[64];
    size_t pl = 0, ml = 0, ol = 0, bl = 0;
    memset(hn_secret, 0x41, 32);
    memset(eph, 0x52, 32);
    TK_ASSERT(g5c_suci_public_key(p, hn_secret, hn_pub, sizeof hn_pub, &pl) == 0);
    TK_ASSERT(pl == g5c_suci_pubkey_len(p));
    TK_ASSERT(g5c_msin_to_bcd("0123456789", msin, sizeof msin, &ml) == 0 && ml == 5);
    TK_ASSERT(g5c_suci_conceal(p, hn_pub, pl, eph, msin, ml, out, sizeof out, &ol) == 0);
    TK_ASSERT(ol == pl + ml + G5C_SUCI_TAG_LEN);
    TK_ASSERT(g5c_suci_deconceal(p, hn_secret, out, ol, back, sizeof back, &bl) == 0);
    TK_ASSERT(bl == ml && memcmp(back, msin, ml) == 0);
    for (size_t i = 0; i < ol; i++) { /* every single-bit flip must be rejected */
        uint8_t bad[128];
        memcpy(bad, out, ol);
        bad[i] ^= 0x01;
        TK_ASSERT(g5c_suci_deconceal(p, hn_secret, bad, ol, back, sizeof back, &bl) != 0);
    }
    TK_ASSERT(g5c_suci_deconceal(p, hn_secret, out, 10, back, sizeof back, &bl) == G5C_SUCI_TOO_SHORT);
}

/* TS 33.501 Annex C.4 test data */
static void annex_c_vector(const char *name, g5c_profile p, const char *hn_priv_hex, const char *hn_pub_hex, const char *eph_hex,
                           const char *pt_hex, const char *out_hex)
{
    uint8_t priv[32], pub[33], eph[32], pt[32], want[128], out[128], back[64], derived[33];
    size_t publen = strlen(hn_pub_hex) / 2, ptlen = strlen(pt_hex) / 2, olen = strlen(out_hex) / 2, ol = 0, bl = 0, dl = 0;
    TK_ASSERT(tk_unhex(hn_priv_hex, priv, 32) == 32);
    TK_ASSERT(tk_unhex(hn_pub_hex, pub, publen) == (long)publen);
    TK_ASSERT(tk_unhex(eph_hex, eph, 32) == 32);
    TK_ASSERT(tk_unhex(pt_hex, pt, ptlen) == (long)ptlen);
    TK_ASSERT(tk_unhex(out_hex, want, olen) == (long)olen);
    TK_ASSERT(g5c_suci_public_key(p, priv, derived, sizeof derived, &dl) == 0 && dl == publen && memcmp(derived, pub, dl) == 0);
    if (g5c_suci_conceal(p, pub, publen, eph, pt, ptlen, out, sizeof out, &ol) != 0 || ol != olen || memcmp(out, want, olen) != 0)
        TK_FAIL("Annex C vector %s: scheme output differs", name);
    if (g5c_suci_deconceal(p, priv, want, olen, back, sizeof back, &bl) != 0 || bl != ptlen || memcmp(back, pt, ptlen) != 0)
        TK_FAIL("Annex C vector %s: de-concealment failed", name);
}

static void annex_c_vectors(void)
{
    /* C.4.3.2 Profile A, network-specific identifier (17 bytes of plaintext) */
    annex_c_vector("C.4.3.2", G5C_PROFILE_A, "C53C22208B61860B06C62E5406A7B330C2B577AA5558981510D128247D38BD1D",
                   "5A8D38864820197C3394B92613B20B91633CBD897119273BF8E4A6F4EEC0A650",
                   "BE9EFF3E9F22A4B42A3D236E7A6C500B3F2E7E0C7449988BA800D664BF4FCD97", "766572796C6F6E67757365726E616D6531",
                   "977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C92222"
                   "8E358A1582ADB15322C10E515141D2039A"
                   "12E1D7783A97F1AC");
    /* C.4.4.1 Profile B, IMSI-based (compressed home network and ephemeral keys) */
    annex_c_vector("C.4.4.1", G5C_PROFILE_B, "F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA",
                   "0272DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD1",
                   "99798858A1DC6A2C68637149A4B1DBFD1FDFF5ADDD62A2142F06699ED7602529", "00012080F6",
                   "039AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1"
                   "46A33FC271"
                   "6AC7DAE96AA30A4D");
    /* C.4.4.2 Profile B, network-specific identifier */
    annex_c_vector("C.4.4.2", G5C_PROFILE_B, "F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA",
                   "0272DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD1",
                   "90A5898BD29FFA3F261E00E980067C70A2B1B992A21F5B4FEF6D4DF69FE804AD", "766572796C6F6E67757365726E616D6531",
                   "03759BB22C563D9F4A6B3C1419E543FC2F39D6823F02A9D71162B39399218B244B"
                   "BE22D8B9F856A52ED381CD7EAF4CF2D525"
                   "3CDDC61A0A7882EB");
}

int main(void)
{
    uint8_t hn_priv[32], hn_pub[32], eph[32], pt[16], out[128], exp[128], pub[33], back[16];
    size_t pl = 0, ol = 0, bl = 0;
    char digits[16];

    {   /* BCD */
        uint8_t b[8];
        size_t n = 0;
        const uint8_t bad[2] = {0xf1, 0x00};
        TK_ASSERT(g5c_msin_to_bcd("123", b, sizeof b, &n) == 0 && n == 2 && b[0] == 0x21 && b[1] == 0xf3);
        TK_ASSERT(g5c_bcd_to_msin(b, 2, digits, sizeof digits) == 0 && strcmp(digits, "123") == 0);
        TK_ASSERT(g5c_msin_to_bcd("12a", b, sizeof b, &n) == G5C_SUCI_MSIN);
        TK_ASSERT(g5c_bcd_to_msin(bad, 2, digits, sizeof digits) == G5C_SUCI_MSIN);
    }

    /* TS 33.501 Annex C.4.3 Profile A vector */
    TK_ASSERT(tk_unhex("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d", hn_priv, 32) == 32);
    TK_ASSERT(tk_unhex("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650", hn_pub, 32) == 32);
    TK_ASSERT(tk_unhex("c80949f13ebe61af4ebdbd293ea4f942696b9e815d7e8f0096bbf6ed7de62256", eph, 32) == 32);
    TK_ASSERT(g5c_suci_public_key(G5C_PROFILE_A, hn_priv, pub, sizeof pub, &pl) == 0 && pl == 32);
    TK_EQ_HEX(pub, "5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650", 32);
    TK_ASSERT(g5c_suci_public_key(G5C_PROFILE_A, eph, pub, sizeof pub, &pl) == 0);
    TK_EQ_HEX(pub, "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d", 32);
    TK_ASSERT(tk_unhex("00012080f6", pt, sizeof pt) == 5);
    TK_ASSERT(g5c_suci_conceal(G5C_PROFILE_A, hn_pub, 32, eph, pt, 5, out, sizeof out, &ol) == 0);
    TK_ASSERT(tk_unhex("b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d"
                       "cb02352410"
                       "cddd9e730ef3fa87", exp, sizeof exp) == (long)ol);
    TK_ASSERT(memcmp(out, exp, ol) == 0);
    TK_ASSERT(g5c_suci_deconceal(G5C_PROFILE_A, hn_priv, out, ol, back, sizeof back, &bl) == 0);
    TK_ASSERT(bl == 5 && memcmp(back, pt, 5) == 0);

    annex_c_vectors();
    roundtrip(G5C_PROFILE_A);
    roundtrip(G5C_PROFILE_B);

    {   /* bad keys */
        uint8_t z32[32] = {0}, s7[32], one33[33], pub33[33], o[64];
        const uint8_t one[1] = {1};
        size_t n = 0;
        memset(s7, 7, 32);
        memset(one33, 1, 33);
        TK_ASSERT(g5c_suci_public_key(G5C_PROFILE_B, z32, pub33, sizeof pub33, &n) == G5C_SUCI_INVALID_KEY);
        TK_ASSERT(g5c_suci_conceal(G5C_PROFILE_A, z32, 32, s7, one, 1, o, sizeof o, &n) == G5C_SUCI_DEGENERATE);
        TK_ASSERT(g5c_suci_conceal(G5C_PROFILE_B, one33, 33, s7, one, 1, o, sizeof o, &n) ==
                  G5C_SUCI_INVALID_KEY);
    }
    puts("suci: ok");
    return 0;
}
