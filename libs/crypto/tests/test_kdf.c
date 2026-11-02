/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* KDF cross-check against an independent RFC 2104 HMAC-SHA-256 built from raw SHA-256 (same test as the Rust tree). */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#include "g5c/crypto.h"

static void sha256(const uint8_t *a, size_t al, const uint8_t *b, size_t bl, uint8_t out[32])
{
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned n = 0;
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, a, al);
    EVP_DigestUpdate(c, b, bl);
    EVP_DigestFinal_ex(c, out, &n);
    EVP_MD_CTX_free(c);
}

int main(void)
{
    uint8_t key[32], out[32], expect[32], inner[32], ipad[64], opad[64];
    const uint8_t p0[] = {'a', 'b', 'c'}, p1[] = {1, 2};
    const uint8_t *params[] = {p0, p1};
    const size_t lens[] = {3, 2};
    const uint8_t s[] = {0x6A, 'a', 'b', 'c', 0, 3, 1, 2, 0, 2};

    memset(key, 'k', sizeof key);
    if (g5c_kdf(key, sizeof key, 0x6A, params, lens, 2, out) != 0) {
        puts("FAIL: kdf returned error");
        return 1;
    }
    memset(ipad, 0x36, sizeof ipad);
    memset(opad, 0x5c, sizeof opad);
    for (size_t i = 0; i < 32; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    sha256(ipad, 64, s, sizeof s, inner);
    sha256(opad, 64, inner, 32, expect);
    if (memcmp(out, expect, 32) != 0) {
        puts("FAIL: kdf differs from manual HMAC");
        return 1;
    }
    /* parameter limits */
    if (g5c_kdf(key, sizeof key, 0, params, (const size_t[]){0x10000, 2}, 2, out) == 0) {
        puts("FAIL: oversize parameter accepted");
        return 1;
    }
    puts("kdf: ok");
    return 0;
}
