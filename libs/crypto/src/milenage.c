/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* MILENAGE example algorithm set (TS 35.206) for f1, f1*, f2, f3, f4, f5, f5*. */
#include <string.h>

#include <openssl/evp.h>

#include "g5c/crypto.h"

static void xor16(const uint8_t a[16], const uint8_t b[16], uint8_t o[16])
{
    for (size_t i = 0; i < 16; i++)
        o[i] = (uint8_t)(a[i] ^ b[i]);
}

/* Cyclic left rotation by `bits` (a multiple of 8 in MILENAGE). */
static void rot(const uint8_t x[16], unsigned bits, uint8_t o[16])
{
    size_t n = (bits / 8U) % 16U;
    for (size_t i = 0; i < 16; i++)
        o[i] = x[(i + n) % 16U];
}

/* AES-128 single block encryption, key k. */
static int enc(const uint8_t k[16], const uint8_t in[16], uint8_t out[16])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len = 0, ok = 0;
    if (c == NULL)
        return -1;
    if (EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, k, NULL) == 1 &&
        EVP_CIPHER_CTX_set_padding(c, 0) == 1 && EVP_EncryptUpdate(c, out, &len, in, 16) == 1 &&
        len == 16)
        ok = 1;
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

int g5c_milenage_derive_opc(const uint8_t k[16], const uint8_t op[16], uint8_t opc[16])
{
    uint8_t t[16];
    if (enc(k, op, t) != 0)
        return -1;
    xor16(t, op, opc);
    return 0;
}

void g5c_milenage_init(g5c_milenage *m, const uint8_t k[16], const uint8_t opc[16])
{
    memcpy(m->k, k, 16);
    memcpy(m->opc, opc, 16);
}

static int temp(const g5c_milenage *m, const uint8_t rand[16], uint8_t t[16])
{
    uint8_t x[16];
    xor16(rand, m->opc, x);
    return enc(m->k, x, t);
}

/* OUTn = E_K(rot(TEMP xor OPc, rn) xor cn) xor OPc, with cn = 0...0 || c_last. */
static int out_n(const g5c_milenage *m, const uint8_t t[16], unsigned r_bits, uint8_t c_last,
                 uint8_t out[16])
{
    uint8_t a[16], b[16], c[16] = {0}, e[16];
    c[15] = c_last;
    xor16(t, m->opc, a);
    rot(a, r_bits, b);
    xor16(b, c, a);
    if (enc(m->k, a, e) != 0)
        return -1;
    xor16(e, m->opc, out);
    return 0;
}

int g5c_milenage_f1(const g5c_milenage *m, const uint8_t rand[16], const uint8_t sqn[6],
                    const uint8_t amf[2], uint8_t mac_a[8], uint8_t mac_s[8])
{
    uint8_t t[16], in1[16], a[16], b[16], e[16], out1[16];
    if (temp(m, rand, t) != 0)
        return -1;
    memcpy(in1, sqn, 6);
    memcpy(in1 + 6, amf, 2);
    memcpy(in1 + 8, sqn, 6);
    memcpy(in1 + 14, amf, 2);
    /* OUT1 = E_K(TEMP xor rot(IN1 xor OPc, r1 = 64) xor c1 = 0) xor OPc */
    xor16(in1, m->opc, a);
    rot(a, 64, b);
    xor16(t, b, a);
    if (enc(m->k, a, e) != 0)
        return -1;
    xor16(e, m->opc, out1);
    memcpy(mac_a, out1, 8);
    memcpy(mac_s, out1 + 8, 8);
    return 0;
}

int g5c_milenage_f2345(const g5c_milenage *m, const uint8_t rand[16], g5c_milenage_vector *out)
{
    uint8_t t[16], o2[16], o3[16], o4[16], o5[16];
    if (temp(m, rand, t) != 0 || out_n(m, t, 0, 1, o2) != 0 || out_n(m, t, 32, 2, o3) != 0 ||
        out_n(m, t, 64, 4, o4) != 0 || out_n(m, t, 96, 8, o5) != 0)
        return -1;
    memcpy(out->res, o2 + 8, 8);
    memcpy(out->ak, o2, 6);
    memcpy(out->ck, o3, 16);
    memcpy(out->ik, o4, 16);
    memcpy(out->ak_star, o5, 6);
    return 0;
}
