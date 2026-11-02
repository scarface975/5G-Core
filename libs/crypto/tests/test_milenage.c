/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* All 20 TS 35.208 test sets. */
#include <stdio.h>
#include <string.h>

#include "g5c/crypto.h"
#include "milenage_vectors.h"

static int unhex(const char *s, uint8_t *out, size_t n)
{
    if (strlen(s) != 2 * n)
        return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        if (sscanf(s + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

#define CHECK(name, got, want, n)                                                              \
    do {                                                                                       \
        uint8_t w_[16];                                                                        \
        if (unhex((want), w_, (n)) != 0 || memcmp((got), w_, (n)) != 0) {                      \
            printf("FAIL set %zu: %s\n", i + 1, name);                                         \
            return 1;                                                                          \
        }                                                                                      \
    } while (0)

int main(void)
{
    for (size_t i = 0; i < sizeof SETS / sizeof SETS[0]; i++) {
        const char *const *v = SETS[i].v;
        uint8_t k[16], rand[16], sqn[6], amf[2], op[16], opc[16], ma[8], ms[8];
        g5c_milenage m;
        g5c_milenage_vector o;
        if (unhex(v[0], k, 16) || unhex(v[1], rand, 16) || unhex(v[2], sqn, 6) ||
            unhex(v[3], amf, 2) || unhex(v[4], op, 16)) {
            puts("FAIL: bad vector");
            return 1;
        }
        if (g5c_milenage_derive_opc(k, op, opc) != 0) {
            puts("FAIL: derive_opc");
            return 1;
        }
        CHECK("opc", opc, v[5], 16);
        g5c_milenage_init(&m, k, opc);
        if (g5c_milenage_f1(&m, rand, sqn, amf, ma, ms) != 0 ||
            g5c_milenage_f2345(&m, rand, &o) != 0) {
            puts("FAIL: crypto error");
            return 1;
        }
        CHECK("f1", ma, v[6], 8);
        CHECK("f1*", ms, v[7], 8);
        CHECK("f2", o.res, v[8], 8);
        CHECK("f3", o.ck, v[9], 16);
        CHECK("f4", o.ik, v[10], 16);
        CHECK("f5", o.ak, v[11], 6);
        CHECK("f5*", o.ak_star, v[12], 6);
    }
    puts("milenage: 20/20 TS 35.208 sets ok");
    return 0;
}
