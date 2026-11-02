/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Generic 3GPP key derivation function (TS 33.220 Annex B.2). */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "g5c/crypto.h"

int g5c_kdf(const uint8_t *key, size_t key_len, uint8_t fc, const uint8_t *const *params,
            const size_t *param_lens, size_t nparams, uint8_t out[32])
{
    int rc = -1;
    size_t outl = 0;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM p[2];
    char digest[] = "SHA256";

    if (nparams > G5C_KDF_MAX_PARAMS)
        return -1;
    for (size_t i = 0; i < nparams; i++)
        if (param_lens[i] > 0xFFFFU)
            return -1;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL)
        return -1;
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL)
        goto done;
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
    p[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(ctx, key, key_len, p) != 1 || EVP_MAC_update(ctx, &fc, 1) != 1)
        goto done;
    for (size_t i = 0; i < nparams; i++) {
        uint8_t l[2] = {(uint8_t)(param_lens[i] >> 8), (uint8_t)(param_lens[i] & 0xFFU)};
        if ((param_lens[i] != 0 && EVP_MAC_update(ctx, params[i], param_lens[i]) != 1) ||
            EVP_MAC_update(ctx, l, 2) != 1)
            goto done;
    }
    if (EVP_MAC_final(ctx, out, &outl, 32) != 1 || outl != 32)
        goto done;
    rc = 0;
done:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return rc;
}
