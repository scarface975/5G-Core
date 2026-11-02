/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include "g5c/crypto.h"
#include "g5c/testkit.h"

int main(void)
{
    char snn[64];
    uint8_t k[16], op[16], opc[16], rand[16], res_a[16], res_b[16], hx[16], ka[32], ks[32], km[32];
    uint8_t zero6[6] = {0}, abba[2] = {0, 0}, a[16], b[16], g0[32], g1[32];
    g5c_milenage m;
    g5c_milenage_vector v;

    TK_ASSERT(g5c_serving_network_name("001", "01", snn, sizeof snn) > 0);
    TK_ASSERT(strcmp(snn, "5G:mnc001.mcc001.3gppnetwork.org") == 0);
    TK_ASSERT(g5c_serving_network_name("310", "260", snn, sizeof snn) > 0);
    TK_ASSERT(strcmp(snn, "5G:mnc260.mcc310.3gppnetwork.org") == 0);
    TK_ASSERT(g5c_serving_network_name("001", "01", snn, 8) < 0); /* truncation rejected */
    TK_ASSERT(g5c_serving_network_name("1", "01", snn, sizeof snn) < 0);

    {   /* AUTN layout */
        uint8_t s6[6], k6[6], am[2] = {0x80, 0}, mc[8], au[16];
        memset(s6, 1, 6);
        memset(k6, 1, 6);
        memset(mc, 9, 8);
        g5c_autn(s6, k6, am, mc, au);
        TK_ASSERT(au[0] == 0 && au[5] == 0 && au[6] == 0x80 && au[7] == 0 && au[8] == 9 && au[15] == 9);
    }

    memset(k, 7, 16);
    memset(op, 3, 16);
    memset(rand, 0x42, 16);
    TK_ASSERT(g5c_milenage_derive_opc(k, op, opc) == 0);
    g5c_milenage_init(&m, k, opc);
    TK_ASSERT(g5c_milenage_f2345(&m, rand, &v) == 0);
    g5c_serving_network_name("001", "01", snn, sizeof snn);
    TK_ASSERT(g5c_res_star(v.ck, v.ik, snn, rand, v.res, 8, res_a) == 0);
    TK_ASSERT(g5c_res_star(v.ck, v.ik, snn, rand, v.res, 8, res_b) == 0);
    TK_ASSERT(memcmp(res_a, res_b, 16) == 0);
    TK_ASSERT(g5c_hres_star(rand, res_a, hx) == 0 && memcmp(hx, res_a, 16) != 0);
    TK_ASSERT(g5c_kausf(v.ck, v.ik, snn, zero6, ka) == 0);
    TK_ASSERT(g5c_kseaf(ka, snn, ks) == 0);
    TK_ASSERT(g5c_kamf(ks, "001010000000001", abba, km) == 0);
    TK_ASSERT(g5c_algo_key(km, G5C_ALG_NAS_ENC, 2, a) == 0 && g5c_algo_key(km, G5C_ALG_NAS_INT, 2, b) == 0);
    TK_ASSERT(memcmp(a, b, 16) != 0);
    TK_ASSERT(g5c_kgnb(km, 0, 1, g0) == 0 && g5c_kgnb(km, 1, 1, g1) == 0);
    TK_ASSERT(memcmp(g0, g1, 32) != 0);
    puts("aka5g: ok");
    return 0;
}
