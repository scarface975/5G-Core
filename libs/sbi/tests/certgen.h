/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Test-only: in-memory CA and leaf certificates (P-256) for TLS/mTLS tests. */
#ifndef G5C_CERTGEN_H
#define G5C_CERTGEN_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

typedef struct {
    EVP_PKEY *key;
    X509 *cert;
    char *cert_pem, *key_pem;
} cg_id;

static char *cg_bio_str(BIO *b)
{
    char *p = NULL;
    long n = BIO_get_mem_data(b, &p);
    char *o = malloc((size_t)n + 1);
    memcpy(o, p, (size_t)n);
    o[n] = 0;
    return o;
}

static void cg_fill_pems(cg_id *id)
{
    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b, id->cert);
    id->cert_pem = cg_bio_str(b);
    BIO_free(b);
    b = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b, id->key, NULL, NULL, 0, NULL, NULL);
    id->key_pem = cg_bio_str(b);
    BIO_free(b);
}

static int cg_ext(X509 *x, X509 *issuer, int nid, const char *val)
{
    X509V3_CTX ctx;
    X509_EXTENSION *e;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, x, NULL, NULL, 0);
    e = X509V3_EXT_nconf_nid(NULL, &ctx, nid, val);
    if (e == NULL)
        return -1;
    X509_add_ext(x, e, -1);
    X509_EXTENSION_free(e);
    return 0;
}

/* issuer == NULL: self-signed CA. leaf_san: e.g. "IP:127.0.0.1,DNS:localhost" (NULL for client certs). */
static cg_id cg_make(const char *cn, const cg_id *issuer, bool ca, const char *san, long serial)
{
    cg_id id;
    X509_NAME *nm;
    id.key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    id.cert = X509_new();
    X509_set_version(id.cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(id.cert), serial);
    X509_gmtime_adj(X509_getm_notBefore(id.cert), -3600);
    X509_gmtime_adj(X509_getm_notAfter(id.cert), 3600L * 24);
    X509_set_pubkey(id.cert, id.key);
    nm = X509_get_subject_name(id.cert);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(id.cert, issuer ? X509_get_subject_name(issuer->cert) : nm);
    cg_ext(id.cert, issuer ? issuer->cert : id.cert, NID_basic_constraints, ca ? "critical,CA:TRUE" : "CA:FALSE");
    if (san)
        cg_ext(id.cert, issuer ? issuer->cert : id.cert, NID_subject_alt_name, san);
    X509_sign(id.cert, issuer ? issuer->key : id.key, EVP_sha256());
    cg_fill_pems(&id);
    return id;
}

static void cg_free(cg_id *id)
{
    EVP_PKEY_free(id->key);
    X509_free(id->cert);
    free(id->cert_pem);
    free(id->key_pem);
}

#endif
