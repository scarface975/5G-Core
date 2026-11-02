/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* ES256 JSON Web Tokens (see jwt.h). */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/param_build.h>

#include "g5c/base.h"
#include "g5c/jwt.h"

struct g5c_jwt_key {
    EVP_PKEY *pkey;
    bool has_private;
};

static void seterr(char *err, size_t cap, const char *msg)
{
    if (err != NULL && cap > 0)
        snprintf(err, cap, "%s", msg);
}

/* ---- base64url without padding (RFC 7515 appendix C) ---- */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *b64u_encode(const uint8_t *p, size_t n)
{
    char *out = g5c_xmalloc((n + 2) / 3 * 4 + 1), *w = out;
    size_t i = 0;
    for (; i + 2 < n; i += 3) {
        uint32_t v = (uint32_t)p[i] << 16 | (uint32_t)p[i + 1] << 8 | p[i + 2];
        *w++ = B64[v >> 18 & 63];
        *w++ = B64[v >> 12 & 63];
        *w++ = B64[v >> 6 & 63];
        *w++ = B64[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)p[i] << 16;
        *w++ = B64[v >> 18 & 63];
        *w++ = B64[v >> 12 & 63];
    } else if (n - i == 2) {
        uint32_t v = (uint32_t)p[i] << 16 | (uint32_t)p[i + 1] << 8;
        *w++ = B64[v >> 18 & 63];
        *w++ = B64[v >> 12 & 63];
        *w++ = B64[v >> 6 & 63];
    }
    *w = 0;
    return out;
}

static int b64u_val(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '-')
        return 62;
    if (c == '_')
        return 63;
    return -1;
}

/* decodes s[0..n) into a new buffer; false on a character outside the alphabet or an impossible length */
static bool b64u_decode(const char *s, size_t n, uint8_t **out, size_t *outlen)
{
    uint8_t *buf, *w;
    uint32_t acc = 0;
    int bits = 0;
    if (n % 4 == 1)
        return false;
    buf = g5c_xmalloc(n * 3 / 4 + 3);
    w = buf;
    for (size_t i = 0; i < n; i++) {
        int v = b64u_val((unsigned char)s[i]);
        if (v < 0) {
            free(buf);
            return false;
        }
        acc = acc << 6 | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            *w++ = (uint8_t)(acc >> bits);
        }
    }
    *out = buf;
    *outlen = (size_t)(w - buf);
    return true;
}

/* ---- keys ---- */

static g5c_jwt_key *wrap(EVP_PKEY *p, bool priv)
{
    g5c_jwt_key *k = g5c_xcalloc(1, sizeof *k);
    k->pkey = p;
    k->has_private = priv;
    return k;
}

void g5c_jwt_key_free(g5c_jwt_key *k)
{
    if (k == NULL)
        return;
    EVP_PKEY_free(k->pkey);
    free(k);
}

g5c_jwt_key *g5c_jwt_key_generate(char *err, size_t errcap)
{
    EVP_PKEY *p = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    if (p == NULL) {
        seterr(err, errcap, "cannot generate an EC P-256 key");
        return NULL;
    }
    return wrap(p, true);
}

g5c_jwt_key *g5c_jwt_key_load_pem(const char *path, char *err, size_t errcap)
{
    FILE *f = fopen(path, "r");
    EVP_PKEY *p;
    if (f == NULL) {
        seterr(err, errcap, "cannot open the key file");
        return NULL;
    }
    p = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (p == NULL) {
        seterr(err, errcap, "the key file is not a PEM private key");
        return NULL;
    }
    return wrap(p, true);
}

int g5c_jwt_key_save_pem(const g5c_jwt_key *k, const char *path, char *err, size_t errcap)
{
    char *tmp = g5c_xasprintf("%s.tmp", path);
    FILE *f;
    int rc = -1;
    if (!k->has_private) {
        seterr(err, errcap, "a public key cannot be saved as a private key");
        free(tmp);
        return -1;
    }
    f = fopen(tmp, "w");
    if (f != NULL) {
        (void)chmod(tmp, 0600);
        if (PEM_write_PrivateKey(f, k->pkey, NULL, NULL, 0, NULL, NULL) == 1 && fflush(f) == 0) {
            if (fclose(f) == 0 && rename(tmp, path) == 0)
                rc = 0;
            f = NULL;
        }
        if (f != NULL)
            fclose(f);
    }
    if (rc != 0) {
        seterr(err, errcap, "cannot write the key file");
        (void)remove(tmp);
    }
    free(tmp);
    return rc;
}

static bool coord(const EVP_PKEY *p, const char *name, uint8_t out[32])
{
    BIGNUM *bn = NULL;
    bool ok = false;
    if (EVP_PKEY_get_bn_param(p, name, &bn) == 1 && BN_bn2binpad(bn, out, 32) == 32)
        ok = true;
    BN_free(bn);
    return ok;
}

g5c_json *g5c_jwt_key_jwk(const g5c_jwt_key *k, const char *kid)
{
    uint8_t x[32], y[32];
    g5c_json *j;
    char *xs, *ys;
    if (!coord(k->pkey, OSSL_PKEY_PARAM_EC_PUB_X, x) || !coord(k->pkey, OSSL_PKEY_PARAM_EC_PUB_Y, y))
        return NULL;
    xs = b64u_encode(x, 32);
    ys = b64u_encode(y, 32);
    j = g5c_json_new_obj();
    g5c_json_set_str(j, "kty", "EC");
    g5c_json_set_str(j, "crv", "P-256");
    g5c_json_set_str(j, "x", xs);
    g5c_json_set_str(j, "y", ys);
    g5c_json_set_str(j, "use", "sig");
    g5c_json_set_str(j, "alg", "ES256");
    if (kid != NULL)
        g5c_json_set_str(j, "kid", kid);
    free(xs);
    free(ys);
    return j;
}

char *g5c_jwt_key_thumbprint(const g5c_jwt_key *k)
{
    uint8_t x[32], y[32], md[32];
    char *xs, *ys, *canon, *out = NULL;
    unsigned mdl = 0;
    if (!coord(k->pkey, OSSL_PKEY_PARAM_EC_PUB_X, x) || !coord(k->pkey, OSSL_PKEY_PARAM_EC_PUB_Y, y))
        return NULL;
    xs = b64u_encode(x, 32);
    ys = b64u_encode(y, 32);
    canon = g5c_xasprintf("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", xs, ys);
    if (EVP_Digest(canon, strlen(canon), md, &mdl, EVP_sha256(), NULL) == 1 && mdl == 32)
        out = b64u_encode(md, 32);
    free(xs);
    free(ys);
    free(canon);
    return out;
}

g5c_jwt_key *g5c_jwt_key_from_jwk(const g5c_json *jwk, char *err, size_t errcap)
{
    const char *kty = g5c_json_get_str(jwk, "kty"), *crv = g5c_json_get_str(jwk, "crv"), *xs = g5c_json_get_str(jwk, "x"), *ys = g5c_json_get_str(jwk, "y");
    uint8_t *x = NULL, *y = NULL, pub[65];
    size_t xl = 0, yl = 0;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *p = NULL;
    if (kty == NULL || strcmp(kty, "EC") != 0 || crv == NULL || strcmp(crv, "P-256") != 0 || xs == NULL || ys == NULL ||
        !b64u_decode(xs, strlen(xs), &x, &xl) || !b64u_decode(ys, strlen(ys), &y, &yl) || xl != 32 || yl != 32) {
        seterr(err, errcap, "not an EC P-256 JWK");
        free(x);
        free(y);
        return NULL;
    }
    pub[0] = 4;
    memcpy(pub + 1, x, 32);
    memcpy(pub + 33, y, 32);
    free(x);
    free(y);
    bld = OSSL_PARAM_BLD_new();
    if (bld != NULL && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) == 1 &&
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof pub) == 1)
        params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (params == NULL || ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1 || EVP_PKEY_fromdata(ctx, &p, EVP_PKEY_PUBLIC_KEY, params) != 1)
        p = NULL;
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    if (p == NULL) {
        seterr(err, errcap, "the JWK is not a point on P-256");
        return NULL;
    }
    return wrap(p, false);
}

/* ---- sign / verify ---- */

char *g5c_jwt_sign(const g5c_jwt_key *k, const char *kid, const g5c_json *claims)
{
    g5c_json *hdr = g5c_json_new_obj();
    char *hs, *ps, *h64, *p64, *input, *sig64 = NULL, *out = NULL;
    EVP_MD_CTX *md = NULL;
    uint8_t der[128], raw[64];
    size_t derlen = sizeof der;
    const uint8_t *dp = der;
    ECDSA_SIG *sig = NULL;
    if (!k->has_private) {
        g5c_json_free(hdr);
        return NULL;
    }
    g5c_json_set_str(hdr, "alg", "ES256");
    g5c_json_set_str(hdr, "typ", "JWT");
    if (kid != NULL)
        g5c_json_set_str(hdr, "kid", kid);
    hs = g5c_json_to_string(hdr, NULL);
    ps = g5c_json_to_string(claims, NULL);
    g5c_json_free(hdr);
    h64 = b64u_encode((const uint8_t *)hs, strlen(hs));
    p64 = b64u_encode((const uint8_t *)ps, strlen(ps));
    free(hs);
    free(ps);
    input = g5c_xasprintf("%s.%s", h64, p64);
    free(h64);
    free(p64);
    md = EVP_MD_CTX_new();
    if (md != NULL && EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, k->pkey) == 1 &&
        EVP_DigestSign(md, der, &derlen, (const uint8_t *)input, strlen(input)) == 1 && (sig = d2i_ECDSA_SIG(NULL, &dp, (long)derlen)) != NULL) {
        const BIGNUM *r, *s;
        ECDSA_SIG_get0(sig, &r, &s);
        if (BN_bn2binpad(r, raw, 32) == 32 && BN_bn2binpad(s, raw + 32, 32) == 32) {
            sig64 = b64u_encode(raw, 64);
            out = g5c_xasprintf("%s.%s", input, sig64);
        }
    }
    ECDSA_SIG_free(sig);
    EVP_MD_CTX_free(md);
    free(sig64);
    free(input);
    return out;
}

g5c_json *g5c_jwt_verify(const g5c_jwt_key *k, const char *token, char *err, size_t errcap)
{
    const char *d1, *d2;
    uint8_t *hdr = NULL, *pay = NULL, *sig = NULL;
    size_t hl = 0, pl = 0, sl = 0;
    g5c_json *h = NULL, *claims = NULL;
    ECDSA_SIG *es = NULL;
    BIGNUM *r = NULL, *s = NULL;
    uint8_t *der = NULL;
    int derlen;
    EVP_MD_CTX *md = NULL;
    char *input = NULL;
    bool ok = false;
    char perr[64];
    if (token == NULL || (d1 = strchr(token, '.')) == NULL || (d2 = strchr(d1 + 1, '.')) == NULL || strchr(d2 + 1, '.') != NULL) {
        seterr(err, errcap, "not a JWS compact serialization");
        return NULL;
    }
    if (!b64u_decode(token, (size_t)(d1 - token), &hdr, &hl) || !b64u_decode(d1 + 1, (size_t)(d2 - d1 - 1), &pay, &pl) ||
        !b64u_decode(d2 + 1, strlen(d2 + 1), &sig, &sl) || sl != 64) {
        seterr(err, errcap, "malformed token");
        goto done;
    }
    h = g5c_json_parse((const char *)hdr, hl, perr, sizeof perr);
    if (h == NULL || g5c_json_get_str(h, "alg") == NULL || strcmp(g5c_json_get_str(h, "alg"), "ES256") != 0) { /* never "none", never another algorithm */
        seterr(err, errcap, "the token is not ES256");
        goto done;
    }
    es = ECDSA_SIG_new();
    r = BN_bin2bn(sig, 32, NULL);
    s = BN_bin2bn(sig + 32, 32, NULL);
    if (es == NULL || r == NULL || s == NULL || ECDSA_SIG_set0(es, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        seterr(err, errcap, "malformed signature");
        goto done;
    }
    derlen = i2d_ECDSA_SIG(es, &der);
    input = g5c_xasprintf("%.*s", (int)(d2 - token), token);
    md = EVP_MD_CTX_new();
    if (derlen <= 0 || md == NULL || EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, k->pkey) != 1 ||
        EVP_DigestVerify(md, der, (size_t)derlen, (const uint8_t *)input, strlen(input)) != 1) {
        seterr(err, errcap, "the signature does not verify");
        goto done;
    }
    claims = g5c_json_parse((const char *)pay, pl, perr, sizeof perr);
    if (claims == NULL || !g5c_json_is(claims, G5C_J_OBJECT)) {
        seterr(err, errcap, "the payload is not a JSON object");
        g5c_json_free(claims);
        claims = NULL;
        goto done;
    }
    ok = true;
done:
    (void)ok;
    OPENSSL_free(der);
    EVP_MD_CTX_free(md);
    ECDSA_SIG_free(es);
    g5c_json_free(h);
    free(input);
    free(hdr);
    free(pay);
    free(sig);
    return claims;
}
