/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* TLS / mutual-TLS configuration for the SBI (TS 33.501 clause 13.1, TS 29.500 clause 5.2.2).
 * Servers and clients negotiate ALPN "h2". A client CA on the server turns on mutual authentication. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "g5c/sbi.h"

static void seterr(char *err, size_t cap, const char *what)
{
    unsigned long e = ERR_peek_last_error();
    char buf[200] = "";
    if (err == NULL || cap == 0)
        return;
    if (e != 0)
        ERR_error_string_n(e, buf, sizeof buf);
    snprintf(err, cap, "tls: %s%s%s", what, buf[0] ? ": " : "", buf);
}

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                       unsigned inlen, void *arg)
{
    static const unsigned char h2[] = {2, 'h', '2'};
    (void)ssl;
    (void)arg;
    if (SSL_select_next_proto((unsigned char **)(uintptr_t)out, outlen, h2, sizeof h2, in, inlen) ==
        OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* G5C_TLS_KEYLOG=<file>: append the TLS secrets in the NSS key log format so Wireshark can decrypt a capture of the SBI (Edit > Preferences > TLS > (Pre)-Master-Secret log).
 * Off unless the variable is set; the file holds session secrets, so it is created 0600 and every context made while it is set logs a warning once. */
static void keylog_cb(const SSL *ssl, const char *line)
{
    const char *path = getenv("G5C_TLS_KEYLOG");
    char buf[512];
    int fd, n;
    (void)ssl;
    if (path == NULL || path[0] == '\0')
        return;
    n = snprintf(buf, sizeof buf, "%s\n", line);
    if (n <= 0 || (size_t)n >= sizeof buf)
        return;
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    if (write(fd, buf, (size_t)n) < 0) { /* one write per line keeps lines whole between processes */
    }
    close(fd);
}

static void keylog_enable(SSL_CTX *ctx)
{
    static int warned;
    const char *path = getenv("G5C_TLS_KEYLOG");
    if (path == NULL || path[0] == '\0')
        return;
    SSL_CTX_set_keylog_callback(ctx, keylog_cb);
    if (!warned) {
        warned = 1;
        fprintf(stderr, "WARNING g5c tls: G5C_TLS_KEYLOG is set, TLS session secrets are written to %s (debugging only)\n", path);
    }
}

/* ---- who may connect (identity pinning) and revocation ------------------------------------------------------------------------------------------ */

typedef struct {
    char **pat;
    size_t n;
} peer_policy;

static int policy_idx = -1;
static pthread_once_t policy_once = PTHREAD_ONCE_INIT;

static void policy_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    peer_policy *p = ptr;
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;
    if (p == NULL)
        return;
    for (size_t i = 0; i < p->n; i++)
        free(p->pat[i]);
    free(p->pat);
    free(p);
}

static void policy_make_index(void)
{
    policy_idx = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, policy_free);
}

static bool glob_match(const char *pat, const char *s)
{
    while (*pat) {
        if (*pat == '*') {
            while (*pat == '*')
                pat++;
            if (!*pat)
                return true;
            for (; *s; s++)
                if (glob_match(pat, s))
                    return true;
            return false;
        }
        if (*pat != *s)
            return false;
        pat++;
        s++;
    }
    return *s == '\0';
}

static int peer_verify_cb(int ok, X509_STORE_CTX *xs)
{
    SSL *ssl;
    const peer_policy *p;
    char cn[128] = "";
    if (!ok || X509_STORE_CTX_get_error_depth(xs) != 0) /* only the certificate of the peer itself */
        return ok;
    ssl = X509_STORE_CTX_get_ex_data(xs, SSL_get_ex_data_X509_STORE_CTX_idx());
    p = ssl != NULL ? SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), policy_idx) : NULL;
    if (p == NULL || p->n == 0)
        return 1;
    (void)X509_NAME_get_text_by_NID(X509_get_subject_name(X509_STORE_CTX_get_current_cert(xs)), NID_commonName, cn, sizeof cn);
    for (size_t i = 0; i < p->n; i++)
        if (glob_match(p->pat[i], cn))
            return 1;
    fprintf(stderr, "WARNING g5c tls: client certificate \"%.60s\" refused: its name is not in allowed_peers\n", cn);
    X509_STORE_CTX_set_error(xs, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
}

int g5c_tls_server_policy(SSL_CTX *ctx, const char *const *allowed, size_t nallowed, const char *crl_pem, char *err, size_t errcap)
{
    int mode = SSL_CTX_get_verify_mode(ctx);
    pthread_once(&policy_once, policy_make_index);
    if (nallowed > 0 && (mode & SSL_VERIFY_PEER) != 0) {
        peer_policy *p = calloc(1, sizeof *p);
        if (p == NULL)
            return -1;
        p->pat = calloc(nallowed, sizeof *p->pat);
        for (size_t i = 0; p->pat != NULL && i < nallowed; i++) {
            p->pat[p->n] = strdup(allowed[i]);
            if (p->pat[p->n] != NULL)
                p->n++;
        }
        SSL_CTX_set_ex_data(ctx, policy_idx, p);
        SSL_CTX_set_verify(ctx, mode, peer_verify_cb);
    }
    if (crl_pem != NULL && crl_pem[0] != '\0') {
        X509_STORE *st = SSL_CTX_get_cert_store(ctx);
        BIO *b = BIO_new_mem_buf(crl_pem, -1);
        X509_CRL *crl;
        int n = 0;
        if (b == NULL)
            return -1;
        while ((crl = PEM_read_bio_X509_CRL(b, NULL, NULL, NULL)) != NULL) {
            if (X509_STORE_add_crl(st, crl) == 1)
                n++;
            X509_CRL_free(crl);
        }
        ERR_clear_error();
        BIO_free(b);
        if (n == 0) {
            seterr(err, errcap, "no usable CRL in the file");
            return -1;
        }
        X509_STORE_set_flags(st, X509_V_FLAG_CRL_CHECK);
    }
    return 0;
}

static X509 *cert_from_pem(const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x = b ? PEM_read_bio_X509(b, NULL, NULL, NULL) : NULL;
    BIO_free(b);
    return x;
}

static int add_chain_pem(SSL_CTX *ctx, const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509 *x;
    int n = 0;
    if (b == NULL)
        return -1;
    while ((x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) {
        if (n == 0) {
            if (SSL_CTX_use_certificate(ctx, x) != 1) {
                X509_free(x);
                BIO_free(b);
                return -1;
            }
            X509_free(x);
        } else {
            if (SSL_CTX_add_extra_chain_cert(ctx, x) != 1) { /* takes ownership on success */
                X509_free(x);
                BIO_free(b);
                return -1;
            }
        }
        n++;
    }
    ERR_clear_error(); /* the loop ends on PEM_R_NO_START_LINE */
    BIO_free(b);
    return n > 0 ? 0 : -1;
}

static int use_key_pem(SSL_CTX *ctx, const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *k = b ? PEM_read_bio_PrivateKey(b, NULL, NULL, NULL) : NULL;
    int rc = (k != NULL && SSL_CTX_use_PrivateKey(ctx, k) == 1) ? 0 : -1;
    EVP_PKEY_free(k);
    BIO_free(b);
    return rc;
}

static int add_ca_pem(SSL_CTX *ctx, const char *pem)
{
    BIO *b = BIO_new_mem_buf(pem, -1);
    X509_STORE *st = SSL_CTX_get_cert_store(ctx);
    X509 *x;
    int n = 0;
    if (b == NULL)
        return -1;
    while ((x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) {
        if (X509_STORE_add_cert(st, x) == 1)
            n++;
        X509_free(x);
    }
    ERR_clear_error();
    BIO_free(b);
    return n > 0 ? 0 : -1;
}

SSL_CTX *g5c_tls_server_ctx_pem(const char *cert_pem, const char *key_pem, const char *ca_pem, char *err,
                                size_t errcap)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        seterr(err, errcap, "cannot create context");
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
    keylog_enable(ctx);
    if (add_chain_pem(ctx, cert_pem) != 0) {
        seterr(err, errcap, "bad certificate chain");
        goto bad;
    }
    if (use_key_pem(ctx, key_pem) != 0 || SSL_CTX_check_private_key(ctx) != 1) {
        seterr(err, errcap, "bad private key (or it does not match the certificate)");
        goto bad;
    }
    if (ca_pem != NULL) {
        if (add_ca_pem(ctx, ca_pem) != 0) {
            seterr(err, errcap, "bad client CA bundle");
            goto bad;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    return ctx;
bad:
    SSL_CTX_free(ctx);
    return NULL;
}

SSL_CTX *g5c_tls_client_ctx_pem(const char *ca_pem, const char *cert_pem, const char *key_pem, char *err,
                                size_t errcap)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    static const unsigned char alpn[] = {2, 'h', '2'};
    if (ctx == NULL) {
        seterr(err, errcap, "cannot create context");
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof alpn);
    keylog_enable(ctx);
    if (add_ca_pem(ctx, ca_pem) != 0) {
        seterr(err, errcap, "bad CA bundle");
        goto bad;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (cert_pem != NULL && key_pem != NULL) {
        if (add_chain_pem(ctx, cert_pem) != 0 || use_key_pem(ctx, key_pem) != 0 ||
            SSL_CTX_check_private_key(ctx) != 1) {
            seterr(err, errcap, "bad client certificate or key");
            goto bad;
        }
    }
    return ctx;
bad:
    SSL_CTX_free(ctx);
    return NULL;
}

static char *slurp(const char *path, char *err, size_t cap)
{
    FILE *f = fopen(path, "rb");
    g5c_bytes b;
    char buf[4096];
    size_t n;
    if (f == NULL) {
        if (err && cap)
            snprintf(err, cap, "tls: cannot read %s", path);
        return NULL;
    }
    g5c_bytes_init(&b);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        if (b.len > (1U << 20) || g5c_bytes_append(&b, buf, n) != 0) {
            fclose(f);
            g5c_bytes_free(&b);
            if (err && cap)
                snprintf(err, cap, "tls: %s too large", path);
            return NULL;
        }
    }
    fclose(f);
    return g5c_bytes_take(&b, NULL);
}

SSL_CTX *g5c_tls_server_ctx(const char *cert_path, const char *key_path, const char *ca_path, char *err,
                            size_t errcap)
{
    char *c = slurp(cert_path, err, errcap), *k = c ? slurp(key_path, err, errcap) : NULL,
         *a = (c && k && ca_path) ? slurp(ca_path, err, errcap) : NULL;
    SSL_CTX *ctx = NULL;
    if (c && k && (ca_path == NULL || a))
        ctx = g5c_tls_server_ctx_pem(c, k, a, err, errcap);
    free(c);
    if (k)
        OPENSSL_cleanse(k, strlen(k));
    free(k);
    free(a);
    return ctx;
}

SSL_CTX *g5c_tls_client_ctx(const char *ca_path, const char *cert_path, const char *key_path, char *err,
                            size_t errcap)
{
    char *a = slurp(ca_path, err, errcap), *c = (a && cert_path) ? slurp(cert_path, err, errcap) : NULL,
         *k = (a && key_path) ? slurp(key_path, err, errcap) : NULL;
    SSL_CTX *ctx = NULL;
    if (a && (cert_path == NULL || c) && (key_path == NULL || k))
        ctx = g5c_tls_client_ctx_pem(a, c, k, err, errcap);
    free(a);
    free(c);
    if (k)
        OPENSSL_cleanse(k, strlen(k));
    free(k);
    return ctx;
}

/* exported for the test helper that needs to parse PEM certificates */
X509 *g5c_tls_x509_from_pem(const char *pem);
X509 *g5c_tls_x509_from_pem(const char *pem)
{
    return cert_from_pem(pem);
}

g5c_client *g5c_client_new_env(int timeout_ms, char *err, size_t errcap)
{
    const char *ca = getenv("G5C_TLS_CA"), *cert = getenv("G5C_TLS_CERT"), *key = getenv("G5C_TLS_KEY");
    SSL_CTX *ctx = NULL;
    if (ca != NULL && *ca) {
        ctx = g5c_tls_client_ctx(ca, (cert && *cert && key && *key) ? cert : NULL, (cert && *cert && key && *key) ? key : NULL, err, errcap);
        if (ctx == NULL)
            return NULL;
    }
    return g5c_client_new(timeout_ms, ctx);
}
