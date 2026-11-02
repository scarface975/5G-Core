/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5G NAS security algorithms: 128-NEA2 (AES-CTR) and 128-NIA2 (AES-CMAC). SNOW 3G (NEA1/NIA1) is a separate,
 * licence-gated component (ADR-0012). */
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "g5c/crypto.h"

static uint8_t bearer_dir(uint8_t bearer, g5c_dir dir)
{
    return (uint8_t)(((bearer & 0x1fU) << 3) | ((unsigned)dir << 2));
}

int g5c_nea2(const uint8_t key[16], uint32_t count, uint8_t bearer, g5c_dir dir, uint8_t *data,
             size_t len)
{
    uint8_t iv[16] = {0};
    EVP_CIPHER_CTX *c;
    int outl = 0, ok = 0;
    if (len == 0)
        return 0;
    if (len > 0x7fffffffU)
        return -1;
    iv[0] = (uint8_t)(count >> 24);
    iv[1] = (uint8_t)(count >> 16);
    iv[2] = (uint8_t)(count >> 8);
    iv[3] = (uint8_t)count;
    iv[4] = bearer_dir(bearer, dir);
    c = EVP_CIPHER_CTX_new();
    if (c == NULL)
        return -1;
    if (EVP_EncryptInit_ex(c, EVP_aes_128_ctr(), NULL, key, iv) == 1 &&
        EVP_EncryptUpdate(c, data, &outl, data, (int)len) == 1 && (size_t)outl == len)
        ok = 1;
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

int g5c_nia2(const uint8_t key[16], uint32_t count, uint8_t bearer, g5c_dir dir,
             const uint8_t *msg, size_t len, uint8_t mac[4])
{
    const uint8_t head[8] = {(uint8_t)(count >> 24), (uint8_t)(count >> 16), (uint8_t)(count >> 8),
                             (uint8_t)count,         bearer_dir(bearer, dir), 0, 0, 0};
    uint8_t full[16];
    size_t outl = 0;
    int rc = -1;
    char cipher[] = "AES-128-CBC";
    OSSL_PARAM p[2];
    EVP_MAC *m = EVP_MAC_fetch(NULL, "CMAC", NULL);
    EVP_MAC_CTX *c = m ? EVP_MAC_CTX_new(m) : NULL;
    if (c == NULL)
        goto done;
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher, 0);
    p[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(c, key, 16, p) != 1 || EVP_MAC_update(c, head, sizeof head) != 1 ||
        (len != 0 && EVP_MAC_update(c, msg, len) != 1) ||
        EVP_MAC_final(c, full, &outl, sizeof full) != 1 || outl != 16)
        goto done;
    memcpy(mac, full, 4);
    rc = 0;
done:
    EVP_MAC_CTX_free(c);
    EVP_MAC_free(m);
    return rc;
}
