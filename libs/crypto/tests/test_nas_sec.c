/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* TS 33.401 Annex C EEA2/EIA2 test sets plus structural checks. */
#include "g5c/crypto.h"
#include "g5c/testkit.h"
#include "nas_sec_vectors.h"

int main(void)
{
    for (size_t i = 0; i < sizeof EEA2 / sizeof EEA2[0]; i++) {
        const eea2_set *s = &EEA2[i];
        uint8_t key[16], pt[1024], ct[1024], buf[1024];
        long n = tk_unhex(s->pt, pt, sizeof pt), m = tk_unhex(s->ct, ct, sizeof ct);
        size_t full = s->bits / 8U; /* whole octets only; a trailing partial octet is not compared */
        TK_ASSERT(tk_unhex(s->key, key, 16) == 16 && n > 0 && n == m);
        memcpy(buf, pt, (size_t)n);
        TK_ASSERT(g5c_nea2(key, s->count, (uint8_t)s->bearer, (g5c_dir)s->dir, buf, (size_t)n) == 0);
        if (memcmp(buf, ct, full) != 0)
            TK_FAIL("EEA2 set %d", s->set);
        memcpy(buf, ct, (size_t)n);
        TK_ASSERT(g5c_nea2(key, s->count, (uint8_t)s->bearer, (g5c_dir)s->dir, buf, (size_t)n) == 0);
        if (memcmp(buf, pt, full) != 0)
            TK_FAIL("EEA2 set %d decrypt", s->set);
    }
    for (size_t i = 0; i < sizeof EIA2 / sizeof EIA2[0]; i++) {
        const eia2_set *s = &EIA2[i];
        uint8_t key[16], msg[8192], mac[4];
        long n = tk_unhex(s->msg, msg, sizeof msg);
        TK_ASSERT(tk_unhex(s->key, key, 16) == 16 && n >= 0);
        TK_ASSERT(g5c_nia2(key, s->count, (uint8_t)s->bearer, (g5c_dir)s->dir, msg, (size_t)n, mac) == 0);
        TK_EQ_HEX(mac, s->mac, 4);
    }
    {   /* NEA2 is involutive; direction and count separate the keystream */
        uint8_t key[16], a[19], b[19];
        memset(key, 0x11, 16);
        memcpy(a, "registration accept", 19);
        memcpy(b, a, 19);
        g5c_nea2(key, 5, 1, G5C_DIR_DL, b, 19);
        TK_ASSERT(memcmp(a, b, 19) != 0);
        g5c_nea2(key, 5, 1, G5C_DIR_DL, b, 19);
        TK_ASSERT(memcmp(a, b, 19) == 0);
        g5c_nea2(key, 5, 1, G5C_DIR_UL, b, 19);
        g5c_nea2(key, 5, 1, G5C_DIR_DL, a, 19);
        TK_ASSERT(memcmp(a, b, 19) != 0);
    }
    {   /* NIA2 depends on every input */
        uint8_t key[16], k2[16], m0[4], m1[4];
        memset(key, 0x22, 16);
        memset(k2, 0x23, 16);
        g5c_nia2(key, 1, 1, G5C_DIR_UL, (const uint8_t *)"msg", 3, m0);
        g5c_nia2(key, 2, 1, G5C_DIR_UL, (const uint8_t *)"msg", 3, m1);
        TK_ASSERT(memcmp(m0, m1, 4) != 0);
        g5c_nia2(key, 1, 1, G5C_DIR_DL, (const uint8_t *)"msg", 3, m1);
        TK_ASSERT(memcmp(m0, m1, 4) != 0);
        g5c_nia2(key, 1, 1, G5C_DIR_UL, (const uint8_t *)"msh", 3, m1);
        TK_ASSERT(memcmp(m0, m1, 4) != 0);
        g5c_nia2(k2, 1, 1, G5C_DIR_UL, (const uint8_t *)"msg", 3, m1);
        TK_ASSERT(memcmp(m0, m1, 4) != 0);
    }
    puts("nas_sec: ok");
    return 0;
}
