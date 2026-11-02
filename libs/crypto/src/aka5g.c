/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5G-AKA functions and key hierarchy (TS 33.501 Annex A, clause 6.1.3.2). */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#include "g5c/crypto.h"

int g5c_serving_network_name(const char *mcc, const char *mnc, char *out, size_t cap)
{
    size_t ml = strlen(mnc);
    int n;
    if (ml < 2 || ml > 3 || strlen(mcc) != 3)
        return -1;
    n = snprintf(out, cap, "5G:mnc%s%s.mcc%s.3gppnetwork.org", ml == 2 ? "0" : "", mnc, mcc);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

void g5c_autn(const uint8_t sqn[6], const uint8_t ak[6], const uint8_t amf[2],
              const uint8_t mac_a[8], uint8_t autn[16])
{
    for (size_t i = 0; i < 6; i++)
        autn[i] = (uint8_t)(sqn[i] ^ ak[i]);
    memcpy(autn + 6, amf, 2);
    memcpy(autn + 8, mac_a, 8);
}

static void ck_ik(const uint8_t ck[16], const uint8_t ik[16], uint8_t k[32])
{
    memcpy(k, ck, 16);
    memcpy(k + 16, ik, 16);
}

int g5c_res_star(const uint8_t ck[16], const uint8_t ik[16], const char *snn, const uint8_t rand[16],
                 const uint8_t *res, size_t res_len, uint8_t out[16])
{
    uint8_t k[32], o[32];
    const uint8_t *p[3] = {(const uint8_t *)snn, rand, res};
    const size_t l[3] = {strlen(snn), 16, res_len};
    ck_ik(ck, ik, k);
    if (g5c_kdf(k, 32, 0x6B, p, l, 3, o) != 0)
        return -1;
    memcpy(out, o + 16, 16);
    return 0;
}

int g5c_hres_star(const uint8_t rand[16], const uint8_t res_star[16], uint8_t out[16])
{
    uint8_t in[32], d[32];
    unsigned n = 0;
    memcpy(in, rand, 16);
    memcpy(in + 16, res_star, 16);
    if (EVP_Digest(in, sizeof in, d, &n, EVP_sha256(), NULL) != 1 || n != 32)
        return -1;
    memcpy(out, d + 16, 16);
    return 0;
}

int g5c_kausf(const uint8_t ck[16], const uint8_t ik[16], const char *snn,
              const uint8_t sqn_xor_ak[6], uint8_t out[32])
{
    uint8_t k[32];
    const uint8_t *p[2] = {(const uint8_t *)snn, sqn_xor_ak};
    const size_t l[2] = {strlen(snn), 6};
    ck_ik(ck, ik, k);
    return g5c_kdf(k, 32, 0x6A, p, l, 2, out);
}

int g5c_kseaf(const uint8_t kausf[32], const char *snn, uint8_t out[32])
{
    const uint8_t *p[1] = {(const uint8_t *)snn};
    const size_t l[1] = {strlen(snn)};
    return g5c_kdf(kausf, 32, 0x6C, p, l, 1, out);
}

int g5c_kamf(const uint8_t kseaf[32], const char *supi, const uint8_t abba[2], uint8_t out[32])
{
    const uint8_t *p[2] = {(const uint8_t *)supi, abba};
    const size_t l[2] = {strlen(supi), 2};
    return g5c_kdf(kseaf, 32, 0x6D, p, l, 2, out);
}

int g5c_algo_key(const uint8_t kamf[32], g5c_alg_type t, uint8_t algo_id, uint8_t out[16])
{
    uint8_t o[32];
    const uint8_t tb = (uint8_t)t;
    const uint8_t *p[2] = {&tb, &algo_id};
    const size_t l[2] = {1, 1};
    if (g5c_kdf(kamf, 32, 0x69, p, l, 2, o) != 0)
        return -1;
    memcpy(out, o + 16, 16);
    return 0;
}

int g5c_kgnb(const uint8_t kamf[32], uint32_t ul_nas_count, uint8_t access, uint8_t out[32])
{
    const uint8_t c[4] = {(uint8_t)(ul_nas_count >> 24), (uint8_t)(ul_nas_count >> 16),
                          (uint8_t)(ul_nas_count >> 8), (uint8_t)ul_nas_count};
    const uint8_t *p[2] = {c, &access};
    const size_t l[2] = {4, 1};
    return g5c_kdf(kamf, 32, 0x6E, p, l, 2, out);
}
