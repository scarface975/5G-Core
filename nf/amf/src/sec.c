/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NAS and AS security of the AMF (TS 33.501 clauses 6.7, 6.8, 6.9 and Annex A). */
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "priv.h"

static bool ue_supports(const uint8_t *cap, size_t len, bool integrity, uint8_t id)
{
    size_t idx = integrity ? 1 : 0;
    if (len <= idx || id > 7)
        return false;
    return (cap[idx] & (0x80u >> id)) != 0;
}

/* The first algorithm of our preference list that the UE supports (TS 33.501 6.7.1.1) */
int sec_select_algs(const amf *a, const uint8_t *ue_cap, size_t len, uint8_t *int_alg, uint8_t *enc_alg)
{
    bool ok_i = false, ok_e = false;
    for (size_t i = 0; i < a->cfg.nint && !ok_i; i++)
        if (ue_supports(ue_cap, len, true, a->cfg.int_pref[i])) {
            *int_alg = a->cfg.int_pref[i];
            ok_i = true;
        }
    for (size_t i = 0; i < a->cfg.nenc && !ok_e; i++)
        if (ue_supports(ue_cap, len, false, a->cfg.enc_pref[i])) {
            *enc_alg = a->cfg.enc_pref[i];
            ok_e = true;
        }
    return ok_i && ok_e ? 0 : -1;
}

void sec_derive_nas_keys(amf_sec *s)
{
    (void)g5c_algo_key(s->kamf, G5C_ALG_NAS_INT, s->int_alg, s->knas_int);
    (void)g5c_algo_key(s->kamf, G5C_ALG_NAS_ENC, s->enc_alg, s->knas_enc);
}

void sec_new_context(amf_sec *s, const uint8_t kamf[32], uint8_t ngksi, const uint8_t abba[2])
{
    memset(s, 0, sizeof *s);
    memcpy(s->kamf, kamf, 32);
    s->ngksi = ngksi;
    memcpy(s->abba, abba, 2);
    s->valid = true;
}

void sec_derive_kgnb(amf_sec *s, uint32_t ul_count)
{
    (void)g5c_kgnb(s->kamf, ul_count, 0x01, s->kgnb);
    s->kgnb_count = ul_count;
    s->nh_valid = false;
    s->ncc = 0;
}

/* A fresh {NH, NCC} pair for a handover (TS 33.501 6.9.2.3.3 and Annex A.10): the chain starts from KgNB, the first value (NCC 1) is never sent. */
void sec_next_hop(amf_sec *s)
{
    const uint8_t *p[1];
    size_t l[1] = {32};
    uint8_t out[32];
    if (!s->nh_valid) {
        p[0] = s->kgnb;
        (void)g5c_kdf(s->kamf, 32, 0x6f, p, l, 1, out);
        memcpy(s->nh, out, 32);
        s->ncc = 1;
        s->nh_valid = true;
    }
    p[0] = s->nh;
    (void)g5c_kdf(s->kamf, 32, 0x6f, p, l, 1, out);
    memcpy(s->nh, out, 32);
    s->ncc++;
    OPENSSL_cleanse(out, sizeof out);
}

void sec_ctx_view(const amf_sec *s, nas_sec_ctx *out)
{
    memset(out, 0, sizeof *out);
    memcpy(out->knas_int, s->knas_int, 16);
    memcpy(out->knas_enc, s->knas_enc, 16);
    out->int_alg = (nas_int_alg)s->int_alg;
    out->enc_alg = (nas_enc_alg)s->enc_alg;
}

int sec_protect_dl(amf_sec *s, uint8_t sht, const uint8_t *plain, size_t len, g5c_bytes *out)
{
    nas_sec_ctx ctx;
    uint32_t count = s->dl_count;
    int rc;
    sec_ctx_view(s, &ctx);
    rc = nas_protect(&ctx, sht, G5C_DIR_DL, count, plain, len, out);
    if (rc == NAS_OK)
        s->dl_count = count + 1;
    return rc;
}

/* Estimate the 32-bit count from the 8-bit sequence number carried (TS 24.501 4.4.3.1): the overflow counter grows when the sequence number wraps. */
static uint32_t estimate_count(uint32_t expected, uint8_t sn)
{
    uint32_t est = (expected & ~0xffu) | sn;
    if (sn < (uint8_t)(expected & 0xff))
        est += 0x100;
    return est;
}

/* 0 on success. -1: integrity check failed, -2: replay (count below the expected one), -3: cannot decipher. */
int sec_open_ul(amf_sec *s, const nas_protected *p, g5c_bytes *plain, uint32_t *count_out, bool commit)
{
    nas_sec_ctx ctx;
    uint32_t est = estimate_count(s->ul_count, p->seq);
    if (!s->valid)
        return -1;
    sec_ctx_view(s, &ctx);
    if (!nas_protected_verify(p, &ctx, G5C_DIR_UL, est))
        return -1;
    if (est < s->ul_count)
        return -2;
    if (nas_protected_open(p, &ctx, G5C_DIR_UL, est, plain) != NAS_OK)
        return -3;
    if (count_out != NULL)
        *count_out = est;
    if (commit)
        s->ul_count = est + 1;
    return 0;
}

void sec_clear(amf_sec *s)
{
    OPENSSL_cleanse(s, sizeof *s);
}
