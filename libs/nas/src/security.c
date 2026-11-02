/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NAS security: protected-message envelope, integrity and ciphering (TS 24.501 clause 4.4 and 9.3,
 * TS 33.501 clause 6.4 and Annex D). */
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "g5c/nas.h"

int nas_int_alg_from_id(uint8_t id, nas_int_alg *out)
{
    if (id == 0 || id == 2) {
        *out = (nas_int_alg)id;
        return NAS_OK;
    }
    return NAS_E_SECURITY; /* SNOW 3G (1) and ZUC (3) are not implemented yet */
}

int nas_enc_alg_from_id(uint8_t id, nas_enc_alg *out)
{
    if (id == 0 || id == 2) {
        *out = (nas_enc_alg)id;
        return NAS_OK;
    }
    return NAS_E_SECURITY;
}

int nas_any_decode(const uint8_t *b, size_t len, nas_any *out)
{
    memset(out, 0, sizeof *out);
    if (len > 1 && b[0] == NAS_EPD_5GMM && (b[1] & 0x0f) != 0) {
        uint8_t sht;
        if (len < 7)
            return NAS_E_TRUNCATED;
        sht = b[1] & 0x0f;
        if (sht < 1 || sht > 4)
            return NAS_E_INVALID;
        out->is_protected = true;
        out->prot.sht = sht;
        memcpy(out->prot.mac, b + 2, 4);
        out->prot.seq = b[6];
        out->prot.payload = b + 7;
        out->prot.payload_len = len - 7;
        return NAS_OK;
    }
    return nas_msg_decode(b, len, &out->plain);
}

void nas_any_free(nas_any *a)
{
    nas_msg_free(&a->plain);
    memset(a, 0, sizeof *a);
}

static int compute_mac(const nas_sec_ctx *ctx, g5c_dir dir, uint32_t count, uint8_t seq, const uint8_t *payload,
                       size_t plen, uint8_t mac[4])
{
    uint8_t *in;
    int rc;
    if (ctx->int_alg == NAS_IA0) {
        memset(mac, 0, 4);
        return 0;
    }
    in = g5c_xmalloc(1 + plen);
    in[0] = seq;
    if (plen)
        memcpy(in + 1, payload, plen);
    rc = g5c_nia2(ctx->knas_int, count, NAS_BEARER_3GPP, dir, in, 1 + plen, mac);
    free(in);
    return rc;
}

static int cipher(const nas_sec_ctx *ctx, g5c_dir dir, uint32_t count, const uint8_t *data, size_t len, g5c_bytes *out)
{
    size_t at = out->len;
    if (g5c_bytes_append(out, data, len) != 0)
        return NAS_E_SECURITY;
    if (ctx->enc_alg == NAS_EA0 || len == 0)
        return NAS_OK;
    return g5c_nea2(ctx->knas_enc, count, NAS_BEARER_3GPP, dir, out->data + at, len) == 0 ? NAS_OK : NAS_E_SECURITY;
}

bool nas_protected_verify(const nas_protected *p, const nas_sec_ctx *ctx, g5c_dir dir, uint32_t count)
{
    uint8_t mac[4];
    if (compute_mac(ctx, dir, count, p->seq, p->payload, p->payload_len, mac) != 0)
        return false;
    return CRYPTO_memcmp(mac, p->mac, 4) == 0;
}

int nas_protected_open(const nas_protected *p, const nas_sec_ctx *ctx, g5c_dir dir, uint32_t count, g5c_bytes *out)
{
    if (p->sht == 2 || p->sht == 4)
        return cipher(ctx, dir, count, p->payload, p->payload_len, out);
    return g5c_bytes_append(out, p->payload, p->payload_len) == 0 ? NAS_OK : NAS_E_SECURITY;
}

int nas_protect(const nas_sec_ctx *ctx, uint8_t sht, g5c_dir dir, uint32_t count, const uint8_t *plain, size_t plen,
                g5c_bytes *out)
{
    g5c_bytes payload;
    uint8_t mac[4], seq = (uint8_t)(count & 0xff), head[7];
    int rc;
    if (sht < 1 || sht > 4)
        return NAS_E_INVALID;
    g5c_bytes_init(&payload);
    if (sht == 2 || sht == 4)
        rc = cipher(ctx, dir, count, plain, plen, &payload);
    else
        rc = g5c_bytes_append(&payload, plain, plen) == 0 ? NAS_OK : NAS_E_SECURITY;
    if (rc != NAS_OK)
        goto done;
    if (compute_mac(ctx, dir, count, seq, payload.data, payload.len, mac) != 0) {
        rc = NAS_E_SECURITY;
        goto done;
    }
    head[0] = NAS_EPD_5GMM;
    head[1] = sht;
    memcpy(head + 2, mac, 4);
    head[6] = seq;
    if (g5c_bytes_append(out, head, 7) != 0 || g5c_bytes_append(out, payload.data, payload.len) != 0)
        rc = NAS_E_SECURITY;
done:
    g5c_bytes_free(&payload);
    return rc;
}
