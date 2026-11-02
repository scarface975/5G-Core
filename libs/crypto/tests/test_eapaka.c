/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* EAP-AKA': the four test vectors of RFC 9048 Appendix D (CK', IK', K_encr, K_aut, K_re, MSK, EMSK), PRF' lengths, and EAP packet framing / AT_MAC. */
#include <stdio.h>
#include <string.h>

#include "g5c/crypto.h"
#include "g5c/eapaka.h"
#include "g5c/testkit.h"

typedef struct {
    const char *snn, *identity, *autn, *ik, *ck, *ck_p, *ik_p, *k_encr, *k_aut, *k_re, *msk, *emsk;
} vec_t;

/* Appendix D of RFC 9048, extracted from the pinned text by tools/gen/gen_eapaka_vectors.py */
static const vec_t VEC[] = {
#include "eapaka_vectors.inc"
};

#define EQ(got, want, n) TK_EQ_HEX((got), (want), (n))

static void test_vectors(void)
{
    TK_ASSERT(sizeof VEC / sizeof *VEC == 4);
    for (size_t i = 0; i < sizeof VEC / sizeof *VEC; i++) {
        const vec_t *v = &VEC[i];
        uint8_t ck[16], ik[16], autn[16], ckp[16], ikp[16];
        g5c_eapaka_keys k;
        TK_ASSERT(tk_unhex(v->ck, ck, 16) == 16);
        TK_ASSERT(tk_unhex(v->ik, ik, 16) == 16);
        TK_ASSERT(tk_unhex(v->autn, autn, 16) == 16);
        TK_ASSERT(g5c_ck_ik_prime(ck, ik, v->snn, autn, ckp, ikp) == 0); /* SQN xor AK = the first six octets of AUTN */
        EQ(ckp, v->ck_p, 16);
        EQ(ikp, v->ik_p, 16);
        TK_ASSERT(g5c_eapaka_prime_keys(ckp, ikp, v->identity, &k) == 0);
        EQ(k.k_encr, v->k_encr, 16);
        EQ(k.k_aut, v->k_aut, 32);
        EQ(k.k_re, v->k_re, 32);
        EQ(k.msk, v->msk, 64);
        EQ(k.emsk, v->emsk, 64);
    }
}

static void test_prf(void)
{
    uint8_t key[32], a[100], b[40];
    memset(key, 7, sizeof key);
    TK_ASSERT(g5c_prf_prime(key, (const uint8_t *)"abc", 3, a, sizeof a) == 0);
    TK_ASSERT(g5c_prf_prime(key, (const uint8_t *)"abc", 3, b, sizeof b) == 0);
    TK_ASSERT(memcmp(a, b, sizeof b) == 0); /* a longer output extends a shorter one */
    TK_ASSERT(g5c_prf_prime(key, (const uint8_t *)"abd", 3, b, sizeof b) == 0 && memcmp(a, b, sizeof b) != 0);
    TK_ASSERT(g5c_prf_prime(key, (const uint8_t *)"abc", 3, a, 255 * 32 + 1) != 0);
}

static void test_framing(void)
{
    uint8_t rand[18] = {0}, mac[18] = {0}, buf[200], kaut[32], bad[200];
    g5c_eap_attr at[2];
    g5c_eap_pkt p;
    size_t len, len2;
    uint8_t res[4];
    memset(kaut, 9, sizeof kaut);
    memset(rand + 2, 0xAB, 16);
    at[0] = (g5c_eap_attr){G5C_AT_RAND, rand, 18};
    at[1] = (g5c_eap_attr){G5C_AT_MAC, mac, 18};
    TK_ASSERT(g5c_eap_build(G5C_EAP_REQUEST, 7, G5C_EAPAKA_CHALLENGE, at, 2, buf, sizeof buf, &len) == 0);
    TK_ASSERT(len == 8 + 20 + 20 && buf[0] == 1 && buf[1] == 7 && buf[2] == 0 && buf[3] == len && buf[4] == 50 && buf[5] == 1);
    TK_ASSERT(g5c_eap_mac_set(buf, len, kaut, NULL, 0) == 0);
    TK_ASSERT(g5c_eap_mac_ok(buf, len, kaut, NULL, 0));
    TK_ASSERT(g5c_eap_parse(buf, len, &p) && p.nattrs == 2 && p.attrs[0].type == G5C_AT_RAND && p.attrs[0].vlen == 18 && g5c_eap_find(&p, G5C_AT_MAC) != NULL);
    TK_ASSERT(g5c_eap_find(&p, G5C_AT_AUTN) == NULL);
    /* the MAC covers the extra data too, and any flipped bit breaks it */
    TK_ASSERT(!g5c_eap_mac_ok(buf, len, kaut, (const uint8_t *)"x", 1));
    memcpy(bad, buf, len);
    bad[12] ^= 1;
    TK_ASSERT(!g5c_eap_mac_ok(bad, len, kaut, NULL, 0));
    kaut[0] ^= 1;
    TK_ASSERT(!g5c_eap_mac_ok(buf, len, kaut, NULL, 0));
    kaut[0] ^= 1;
    TK_ASSERT(g5c_eap_mac_set(buf, len, kaut, (const uint8_t *)"nonce", 5) == 0 && g5c_eap_mac_ok(buf, len, kaut, (const uint8_t *)"nonce", 5));
    /* success / failure */
    g5c_eap_build_result(G5C_EAP_SUCCESS, 9, res);
    TK_ASSERT(g5c_eap_parse(res, 4, &p) && p.code == G5C_EAP_SUCCESS && p.id == 9);
    res[3] = 5;
    TK_ASSERT(!g5c_eap_parse(res, 4, &p));
    /* malformed: length field, zero attribute length, attribute over the end, duplicates, too short */
    memcpy(bad, buf, len);
    bad[3] = (uint8_t)(len - 1);
    TK_ASSERT(!g5c_eap_parse(bad, len, &p));
    memcpy(bad, buf, len);
    bad[9] = 0;
    TK_ASSERT(!g5c_eap_parse(bad, len, &p));
    memcpy(bad, buf, len);
    bad[9] = 20;
    TK_ASSERT(!g5c_eap_parse(bad, len, &p));
    memcpy(bad, buf, len);
    bad[28] = G5C_AT_RAND; /* the second attribute becomes a second AT_RAND */
    TK_ASSERT(!g5c_eap_parse(bad, len, &p));
    TK_ASSERT(!g5c_eap_parse(buf, 3, &p) && !g5c_eap_parse(buf, 7, &p));
    /* build limits */
    TK_ASSERT(g5c_eap_build(G5C_EAP_REQUEST, 1, 1, at, 2, buf, 30, &len2) != 0);
    at[0].vlen = 17;
    TK_ASSERT(g5c_eap_build(G5C_EAP_REQUEST, 1, 1, at, 1, buf, sizeof buf, &len2) != 0);
    /* no AT_MAC: the MAC functions refuse */
    at[0].vlen = 18;
    TK_ASSERT(g5c_eap_build(G5C_EAP_REQUEST, 1, 1, at, 1, buf, sizeof buf, &len2) == 0 && g5c_eap_mac_set(buf, len2, kaut, NULL, 0) != 0 &&
              !g5c_eap_mac_ok(buf, len2, kaut, NULL, 0));
}

int main(void)
{
    test_vectors();
    test_prf();
    test_framing();
    puts("eapaka: ok");
    return 0;
}
