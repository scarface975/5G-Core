/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* EAP-AKA' key derivation and packet framing. See eapaka.h for the references. */
#include "g5c/eapaka.h"

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "g5c/crypto.h"

static int hmac256(const uint8_t *key, size_t klen, const uint8_t *const *parts, const size_t *lens, size_t n, uint8_t out[32])
{
    size_t ol = 0;
    int rc = -1;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *c = mac != NULL ? EVP_MAC_CTX_new(mac) : NULL;
    OSSL_PARAM p[2];
    char digest[] = "SHA256";
    if (c == NULL)
        goto done;
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
    p[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(c, key, klen, p) != 1)
        goto done;
    for (size_t i = 0; i < n; i++)
        if (lens[i] != 0 && EVP_MAC_update(c, parts[i], lens[i]) != 1)
            goto done;
    if (EVP_MAC_final(c, out, &ol, 32) != 1 || ol != 32)
        goto done;
    rc = 0;
done:
    EVP_MAC_CTX_free(c);
    EVP_MAC_free(mac);
    return rc;
}

int g5c_ck_ik_prime(const uint8_t ck[16], const uint8_t ik[16], const char *snn, const uint8_t sqn_xor_ak[6], uint8_t ck_p[16], uint8_t ik_p[16])
{
    uint8_t key[32], out[32];
    const uint8_t *p[2] = {(const uint8_t *)snn, sqn_xor_ak};
    const size_t l[2] = {strlen(snn), 6};
    memcpy(key, ck, 16);
    memcpy(key + 16, ik, 16);
    if (g5c_kdf(key, 32, 0x20, p, l, 2, out) != 0) {
        OPENSSL_cleanse(key, sizeof key);
        return -1;
    }
    memcpy(ck_p, out, 16);
    memcpy(ik_p, out + 16, 16);
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(out, sizeof out);
    return 0;
}

int g5c_prf_prime(const uint8_t key[32], const uint8_t *s, size_t s_len, uint8_t *out, size_t out_len)
{
    uint8_t t[32], ctr;
    size_t done = 0;
    bool first = true;
    if (out_len > 255 * 32)
        return -1;
    for (ctr = 1; done < out_len; ctr++) {
        const uint8_t *parts[3] = {first ? s : t, first ? &ctr : s, &ctr};
        size_t lens[3] = {first ? s_len : 32, first ? 1 : s_len, 1};
        size_t n = first ? 2 : 3, take = out_len - done < 32 ? out_len - done : 32;
        if (hmac256(key, 32, parts, lens, n, t) != 0)
            return -1;
        memcpy(out + done, t, take);
        done += take;
        first = false;
    }
    OPENSSL_cleanse(t, sizeof t);
    return 0;
}

int g5c_eapaka_prime_keys(const uint8_t ck_p[16], const uint8_t ik_p[16], const char *identity, g5c_eapaka_keys *out)
{
    static const char label[] = "EAP-AKA'";
    uint8_t key[32], mk[208]; /* 1664 bits */
    size_t il = strlen(identity);
    uint8_t *s;
    int rc;
    if (il > 512)
        return -1;
    memcpy(key, ik_p, 16);
    memcpy(key + 16, ck_p, 16);
    s = OPENSSL_malloc(8 + il);
    if (s == NULL)
        return -1;
    memcpy(s, label, 8);
    memcpy(s + 8, identity, il);
    rc = g5c_prf_prime(key, s, 8 + il, mk, sizeof mk);
    OPENSSL_free(s);
    OPENSSL_cleanse(key, sizeof key);
    if (rc != 0)
        return -1;
    memcpy(out->k_encr, mk, 16);
    memcpy(out->k_aut, mk + 16, 32);
    memcpy(out->k_re, mk + 48, 32);
    memcpy(out->msk, mk + 80, 64);
    memcpy(out->emsk, mk + 144, 64);
    OPENSSL_cleanse(mk, sizeof mk);
    return 0;
}

void g5c_eapaka_kausf(const g5c_eapaka_keys *k, uint8_t kausf[32])
{
    memcpy(kausf, k->emsk, 32);
}

/* ---- framing ---------------------------------------------------------------------------------------------------------------------------------------- */

bool g5c_eap_parse(const uint8_t *b, size_t n, g5c_eap_pkt *p)
{
    size_t len, off;
    uint8_t seen[32] = {0}; /* attribute types 0..255, one bit each */
    memset(p, 0, sizeof *p);
    if (n < 4)
        return false;
    len = ((size_t)b[2] << 8) | b[3];
    if (len != n || len > G5C_EAP_MAX_PKT)
        return false;
    p->code = b[0];
    p->id = b[1];
    if (p->code == G5C_EAP_SUCCESS || p->code == G5C_EAP_FAILURE)
        return len == 4;
    if ((p->code != G5C_EAP_REQUEST && p->code != G5C_EAP_RESPONSE) || len < 8)
        return false;
    p->method = b[4];
    p->subtype = b[5];
    off = 8; /* code, id, length, type, subtype, reserved(2) */
    while (off < len) {
        size_t al;
        if (off + 2 > len)
            return false;
        al = (size_t)b[off + 1] * 4;
        if (al < 4 || off + al > len || p->nattrs == G5C_EAP_MAX_ATTRS)
            return false;
        if (seen[b[off] >> 3] & (1U << (b[off] & 7)))
            return false;
        seen[b[off] >> 3] |= (uint8_t)(1U << (b[off] & 7));
        p->attrs[p->nattrs].type = b[off];
        p->attrs[p->nattrs].val = b + off + 2;
        p->attrs[p->nattrs].vlen = al - 2;
        p->nattrs++;
        off += al;
    }
    return true;
}

const g5c_eap_attr *g5c_eap_find(const g5c_eap_pkt *p, uint8_t type)
{
    for (size_t i = 0; i < p->nattrs; i++)
        if (p->attrs[i].type == type)
            return &p->attrs[i];
    return NULL;
}

int g5c_eap_build(uint8_t code, uint8_t id, uint8_t subtype, const g5c_eap_attr *attrs, size_t nattrs, uint8_t *out, size_t cap, size_t *len)
{
    size_t off = 8;
    if (cap < 8)
        return -1;
    out[0] = code;
    out[1] = id;
    out[4] = G5C_EAP_TYPE_AKA_PRIME;
    out[5] = subtype;
    out[6] = out[7] = 0;
    for (size_t i = 0; i < nattrs; i++) {
        size_t al = attrs[i].vlen + 2;
        if (al % 4 != 0 || al > 1024 || off + al > cap || off + al > G5C_EAP_MAX_PKT)
            return -1;
        out[off] = attrs[i].type;
        out[off + 1] = (uint8_t)(al / 4);
        if (attrs[i].vlen != 0)
            memcpy(out + off + 2, attrs[i].val, attrs[i].vlen);
        off += al;
    }
    out[2] = (uint8_t)(off >> 8);
    out[3] = (uint8_t)(off & 0xFF);
    *len = off;
    return 0;
}

void g5c_eap_build_result(uint8_t code, uint8_t id, uint8_t out[4])
{
    out[0] = code;
    out[1] = id;
    out[2] = 0;
    out[3] = 4;
}

/* offset of the 16 octets of the AT_MAC value in the packet, 0 when absent or not 20 octets long */
static size_t mac_offset(const uint8_t *pkt, size_t len)
{
    size_t off = 8;
    if (len < 8)
        return 0;
    while (off + 4 <= len) {
        size_t al = (size_t)pkt[off + 1] * 4;
        if (al < 4 || off + al > len)
            return 0;
        if (pkt[off] == G5C_AT_MAC)
            return al == 20 ? off + 4 : 0;
        off += al;
    }
    return 0;
}

static int mac_calc(const uint8_t *pkt, size_t len, size_t mo, const uint8_t k_aut[32], const uint8_t *extra, size_t extra_len, uint8_t out[16])
{
    static const uint8_t zero[16] = {0};
    const uint8_t *parts[4] = {pkt, zero, pkt + mo + 16, extra};
    size_t lens[4] = {mo, 16, len - mo - 16, extra_len};
    uint8_t full[32];
    if (hmac256(k_aut, 32, parts, lens, 4, full) != 0)
        return -1;
    memcpy(out, full, 16);
    return 0;
}

int g5c_eap_mac_set(uint8_t *pkt, size_t len, const uint8_t k_aut[32], const uint8_t *extra, size_t extra_len)
{
    size_t mo = mac_offset(pkt, len);
    uint8_t m[16];
    if (mo == 0 || mac_calc(pkt, len, mo, k_aut, extra, extra_len, m) != 0)
        return -1;
    memcpy(pkt + mo, m, 16);
    return 0;
}

bool g5c_eap_mac_ok(const uint8_t *pkt, size_t len, const uint8_t k_aut[32], const uint8_t *extra, size_t extra_len)
{
    size_t mo = mac_offset(pkt, len);
    uint8_t m[16];
    if (mo == 0 || mac_calc(pkt, len, mo, k_aut, extra, extra_len, m) != 0)
        return false;
    return CRYPTO_memcmp(m, pkt + mo, 16) == 0;
}
