/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* SUCI concealment / de-concealment with the ECIES schemes of TS 33.501 Annex C.3:
 * Profile A (X25519) and Profile B (secp256r1).
 *
 * Scheme output: ephemeral public key || ciphertext || MAC tag (8 octets).
 * Key material: ANSI X9.63 KDF (SHA-256, SharedInfo = ephemeral public key) gives enc key (16) || ICB (16) ||
 * mac key (32); ciphertext is AES-128-CTR; the tag is the first 8 octets of HMAC-SHA-256 over the ciphertext. */
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include "g5c/crypto.h"

#define P256_COMPRESSED 33U

size_t g5c_suci_pubkey_len(g5c_profile p)
{
    return p == G5C_PROFILE_A ? 32U : P256_COMPRESSED;
}

/* ---- P-256 helpers ---- */

/* Public point for secret, compressed. 0 on success. */
static int p256_pub(const uint8_t secret[32], uint8_t out[P256_COMPRESSED])
{
    int rc = G5C_SUCI_INVALID_KEY;
    EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *bc = BN_CTX_new();
    BIGNUM *d = BN_bin2bn(secret, 32, NULL);
    EC_POINT *pt = g ? EC_POINT_new(g) : NULL;
    if (g == NULL || bc == NULL || d == NULL || pt == NULL) {
        rc = G5C_SUCI_INTERNAL;
        goto done;
    }
    if (BN_is_zero(d) || BN_cmp(d, EC_GROUP_get0_order(g)) >= 0)
        goto done;
    if (EC_POINT_mul(g, pt, d, NULL, NULL, bc) != 1)
        goto done;
    if (EC_POINT_point2oct(g, pt, POINT_CONVERSION_COMPRESSED, out, P256_COMPRESSED, bc) !=
        P256_COMPRESSED)
        goto done;
    rc = 0;
done:
    BN_clear_free(d);
    EC_POINT_free(pt);
    BN_CTX_free(bc);
    EC_GROUP_free(g);
    return rc;
}

static EVP_PKEY *p256_pkey(const uint8_t *secret /* may be NULL */, const uint8_t pub[P256_COMPRESSED])
{
    EVP_PKEY *pk = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    BIGNUM *d = secret ? BN_bin2bn(secret, 32, NULL) : NULL;
    if (b == NULL || (secret != NULL && d == NULL))
        goto done;
    if (OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PUB_KEY, pub, P256_COMPRESSED) != 1)
        goto done;
    if (d != NULL && OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PRIV_KEY, d) != 1)
        goto done;
    params = OSSL_PARAM_BLD_to_param(b);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (params == NULL || ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1)
        goto done;
    if (EVP_PKEY_fromdata(ctx, &pk, d ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) != 1)
        pk = NULL;
done:
    BN_clear_free(d);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(b);
    EVP_PKEY_CTX_free(ctx);
    return pk;
}

/* ---- ECDH ---- */

static int derive(EVP_PKEY *sk, EVP_PKEY *pk, uint8_t z[32])
{
    size_t n = 0;
    int rc = -1;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(sk, NULL);
    if (c == NULL)
        return -1;
    if (EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, pk) == 1 &&
        EVP_PKEY_derive(c, NULL, &n) == 1 && n == 32 && EVP_PKEY_derive(c, z, &n) == 1 && n == 32)
        rc = 0;
    EVP_PKEY_CTX_free(c);
    return rc;
}

static int ecdh(g5c_profile p, const uint8_t secret[32], const uint8_t *peer, size_t peer_len,
                uint8_t z[32])
{
    int rc;
    if (p == G5C_PROFILE_A) {
        uint8_t zero = 0;
        EVP_PKEY *sk, *pk;
        if (peer_len != 32)
            return G5C_SUCI_INVALID_KEY;
        sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret, 32);
        pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
        if (sk == NULL || pk == NULL)
            rc = G5C_SUCI_INTERNAL;
        else if (derive(sk, pk, z) != 0)
            rc = G5C_SUCI_DEGENERATE; /* low-order peer point */
        else {
            for (size_t i = 0; i < 32; i++)
                zero |= z[i];
            rc = zero == 0 ? G5C_SUCI_DEGENERATE : 0;
        }
        EVP_PKEY_free(sk);
        EVP_PKEY_free(pk);
        return rc;
    } else {
        uint8_t pub[P256_COMPRESSED];
        EVP_PKEY *sk, *pk;
        if (peer_len != P256_COMPRESSED)
            return G5C_SUCI_INVALID_KEY;
        rc = p256_pub(secret, pub);
        if (rc != 0)
            return rc;
        sk = p256_pkey(secret, pub);
        pk = p256_pkey(NULL, peer);
        if (sk == NULL || pk == NULL)
            rc = pk == NULL ? G5C_SUCI_INVALID_KEY : G5C_SUCI_INTERNAL;
        else
            rc = derive(sk, pk, z) == 0 ? 0 : G5C_SUCI_INVALID_KEY;
        EVP_PKEY_free(sk);
        EVP_PKEY_free(pk);
        return rc;
    }
}

int g5c_suci_public_key(g5c_profile p, const uint8_t secret[32], uint8_t *out, size_t cap,
                        size_t *out_len)
{
    size_t n = g5c_suci_pubkey_len(p);
    if (cap < n)
        return G5C_SUCI_NOSPACE;
    if (p == G5C_PROFILE_A) {
        size_t l = 32;
        EVP_PKEY *sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, secret, 32);
        int rc = (sk != NULL && EVP_PKEY_get_raw_public_key(sk, out, &l) == 1 && l == 32)
                     ? 0
                     : G5C_SUCI_INTERNAL;
        EVP_PKEY_free(sk);
        if (rc != 0)
            return rc;
    } else {
        int rc = p256_pub(secret, out);
        if (rc != 0)
            return rc;
    }
    *out_len = n;
    return 0;
}

/* ---- key schedule, tag, CTR ---- */

typedef struct {
    uint8_t enc[16], icb[16], mac[32];
} keys_t;

static int x963_64(const uint8_t z[32], const uint8_t *info, size_t info_len, uint8_t out[64])
{
    for (uint32_t ctr = 1; ctr <= 2; ctr++) {
        const uint8_t c[4] = {0, 0, 0, (uint8_t)ctr};
        unsigned n = 0;
        int ok;
        EVP_MD_CTX *h = EVP_MD_CTX_new();
        if (h == NULL)
            return -1;
        ok = EVP_DigestInit_ex(h, EVP_sha256(), NULL) == 1 && EVP_DigestUpdate(h, z, 32) == 1 &&
             EVP_DigestUpdate(h, c, 4) == 1 && EVP_DigestUpdate(h, info, info_len) == 1 &&
             EVP_DigestFinal_ex(h, out + 32U * (ctr - 1U), &n) == 1 && n == 32;
        EVP_MD_CTX_free(h);
        if (!ok)
            return -1;
    }
    return 0;
}

static int derive_keys(const uint8_t z[32], const uint8_t *eph_pub, size_t eph_len, keys_t *k)
{
    uint8_t buf[64];
    if (x963_64(z, eph_pub, eph_len, buf) != 0)
        return -1;
    memcpy(k->enc, buf, 16);
    memcpy(k->icb, buf + 16, 16);
    memcpy(k->mac, buf + 32, 32);
    OPENSSL_cleanse(buf, sizeof buf);
    return 0;
}

static int tag8(const uint8_t mac_key[32], const uint8_t *ct, size_t len, uint8_t t[G5C_SUCI_TAG_LEN])
{
    uint8_t full[32];
    size_t n = 0;
    int rc = -1;
    char dg[] = "SHA256";
    OSSL_PARAM p[2];
    EVP_MAC *m = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *c = m ? EVP_MAC_CTX_new(m) : NULL;
    if (c == NULL)
        goto done;
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, dg, 0);
    p[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(c, mac_key, 32, p) != 1 || (len != 0 && EVP_MAC_update(c, ct, len) != 1) ||
        EVP_MAC_final(c, full, &n, sizeof full) != 1 || n != 32)
        goto done;
    memcpy(t, full, G5C_SUCI_TAG_LEN);
    rc = 0;
done:
    EVP_MAC_CTX_free(c);
    EVP_MAC_free(m);
    return rc;
}

static int ctr_xor(const keys_t *k, const uint8_t *in, uint8_t *out, size_t len)
{
    int outl = 0, ok = 0;
    EVP_CIPHER_CTX *c;
    if (len == 0)
        return 0;
    if (len > 0x7fffffffU)
        return -1;
    c = EVP_CIPHER_CTX_new();
    if (c == NULL)
        return -1;
    if (EVP_EncryptInit_ex(c, EVP_aes_128_ctr(), NULL, k->enc, k->icb) == 1 &&
        EVP_EncryptUpdate(c, out, &outl, in, (int)len) == 1 && (size_t)outl == len)
        ok = 1;
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

/* ---- conceal / deconceal ---- */

int g5c_suci_conceal(g5c_profile p, const uint8_t *hn_pub, size_t hn_pub_len,
                     const uint8_t eph_secret[32], const uint8_t *msin_bcd, size_t msin_len,
                     uint8_t *out, size_t cap, size_t *out_len)
{
    size_t kl = g5c_suci_pubkey_len(p), pl = 0;
    uint8_t z[32];
    keys_t k;
    int rc;
    if (msin_len > 0x10000U || cap < kl + msin_len + G5C_SUCI_TAG_LEN)
        return G5C_SUCI_NOSPACE;
    rc = g5c_suci_public_key(p, eph_secret, out, cap, &pl);
    if (rc != 0)
        return rc;
    rc = ecdh(p, eph_secret, hn_pub, hn_pub_len, z);
    if (rc != 0)
        return rc;
    rc = G5C_SUCI_INTERNAL;
    if (derive_keys(z, out, kl, &k) != 0 || ctr_xor(&k, msin_bcd, out + kl, msin_len) != 0 ||
        tag8(k.mac, out + kl, msin_len, out + kl + msin_len) != 0)
        goto done;
    *out_len = kl + msin_len + G5C_SUCI_TAG_LEN;
    rc = 0;
done:
    OPENSSL_cleanse(z, sizeof z);
    OPENSSL_cleanse(&k, sizeof k);
    return rc;
}

int g5c_suci_deconceal(g5c_profile p, const uint8_t hn_secret[32], const uint8_t *output,
                       size_t output_len, uint8_t *msin_bcd, size_t cap, size_t *msin_len)
{
    size_t kl = g5c_suci_pubkey_len(p), ct_len;
    uint8_t z[32], t[G5C_SUCI_TAG_LEN];
    keys_t k;
    int rc;
    if (output_len < kl + G5C_SUCI_TAG_LEN)
        return G5C_SUCI_TOO_SHORT;
    ct_len = output_len - kl - G5C_SUCI_TAG_LEN;
    if (cap < ct_len)
        return G5C_SUCI_NOSPACE;
    rc = ecdh(p, hn_secret, output, kl, z);
    if (rc != 0)
        return rc;
    rc = G5C_SUCI_INTERNAL;
    if (derive_keys(z, output, kl, &k) != 0 || tag8(k.mac, output + kl, ct_len, t) != 0)
        goto done;
    if (CRYPTO_memcmp(t, output + kl + ct_len, G5C_SUCI_TAG_LEN) != 0) {
        rc = G5C_SUCI_MAC_MISMATCH;
        goto done;
    }
    if (ctr_xor(&k, output + kl, msin_bcd, ct_len) != 0)
        goto done;
    *msin_len = ct_len;
    rc = 0;
done:
    OPENSSL_cleanse(z, sizeof z);
    OPENSSL_cleanse(&k, sizeof k);
    return rc;
}

/* ---- BCD ---- */

int g5c_msin_to_bcd(const char *msin, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = strlen(msin), o = (n + 1) / 2;
    if (o > cap)
        return G5C_SUCI_NOSPACE;
    for (size_t i = 0; i < n; i++)
        if (msin[i] < '0' || msin[i] > '9')
            return G5C_SUCI_MSIN;
    for (size_t i = 0; i < o; i++) {
        unsigned lo = (unsigned)(msin[2 * i] - '0');
        unsigned hi = (2 * i + 1 < n) ? (unsigned)(msin[2 * i + 1] - '0') : 0x0fU;
        out[i] = (uint8_t)(lo | (hi << 4));
    }
    *out_len = o;
    return 0;
}

int g5c_bcd_to_msin(const uint8_t *bcd, size_t len, char *out, size_t cap)
{
    size_t o = 0;
    if (cap < 2 * len + 1)
        return G5C_SUCI_NOSPACE;
    for (size_t i = 0; i < len; i++) {
        unsigned lo = bcd[i] & 0x0fU, hi = bcd[i] >> 4;
        if (lo > 9)
            return G5C_SUCI_MSIN;
        out[o++] = (char)('0' + lo);
        if (hi <= 9)
            out[o++] = (char)('0' + hi);
        else if (!(hi == 0x0f && i == len - 1))
            return G5C_SUCI_MSIN;
    }
    out[o] = '\0';
    return 0;
}
