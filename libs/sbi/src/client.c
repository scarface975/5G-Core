/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Pooled blocking HTTP/2 client (cleartext prior knowledge, or TLS with ALPN h2) with a per-request deadline */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "g5c/sbi.h"

#define MAX_IDLE_PER_KEY 8
#define MAX_RESP_BYTES (16U << 20)

typedef struct cconn {
    int fd;
    SSL *ssl;
    nghttp2_session *sess;
    char *key; /* scheme://authority */
    struct cconn *next;
} cconn_t;

struct g5c_client {
    int timeout_ms;
    SSL_CTX *tls;
    pthread_mutex_t mu;
    cconn_t *idle;
    char *scp_root, *scp_prefix, *scp_authority, *direct_authority, *ua; /* indirect communication, under mu */
    g5c_token_fn token_fn;                                                /* under mu */
    g5c_token_reject_fn token_reject;
    void *token_user;
};

/* per-request state shared with the nghttp2 callbacks */
typedef struct {
    g5c_resp *out;
    bool got_headers, done, failed_stream, goaway;
    size_t total;
    const uint8_t *body;
    size_t body_len, body_off;
    g5c_bytes rbody;
} rq_t;

static void seterr(char *err, size_t cap, const char *fmt, ...) G5C_PRINTF(3, 4);
static void seterr(char *err, size_t cap, const char *fmt, ...)
{
    va_list ap;
    if (err == NULL || cap == 0)
        return;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

/* ---- URL ---- */

typedef struct {
    bool https;
    char *host, *port, *authority, *path;
} url_t;

static void url_free(url_t *u)
{
    free(u->host);
    free(u->port);
    free(u->authority);
    free(u->path);
}

static int url_parse(const char *s, url_t *u)
{
    const char *p, *auth, *end, *path;
    memset(u, 0, sizeof *u);
    if (strncmp(s, "http://", 7) == 0) {
        p = s + 7;
    } else if (strncmp(s, "https://", 8) == 0) {
        u->https = true;
        p = s + 8;
    } else {
        return -1;
    }
    auth = p;
    end = strpbrk(p, "/?#");
    if (end == NULL)
        end = p + strlen(p);
    if (end == auth)
        return -1;
    u->authority = g5c_xstrndup(auth, (size_t)(end - auth));
    if (u->authority[0] == '[') { /* IPv6 literal */
        const char *rb = strchr(u->authority, ']');
        if (rb == NULL)
            goto bad;
        u->host = g5c_xstrndup(u->authority + 1, (size_t)(rb - u->authority - 1));
        u->port = g5c_xstrdup(rb[1] == ':' ? rb + 2 : (u->https ? "443" : "80"));
    } else {
        const char *colon = strrchr(u->authority, ':');
        if (colon != NULL) {
            u->host = g5c_xstrndup(u->authority, (size_t)(colon - u->authority));
            u->port = g5c_xstrdup(colon + 1);
        } else {
            u->host = g5c_xstrdup(u->authority);
            u->port = g5c_xstrdup(u->https ? "443" : "80");
        }
    }
    if (u->host[0] == '\0' || !g5c_is_digits(u->port) || strlen(u->port) > 5)
        goto bad;
    path = end;
    if (*path == '#' || *path == '\0') {
        u->path = g5c_xstrdup("/");
    } else {
        const char *frag = strchr(path, '#');
        u->path = frag ? g5c_xstrndup(path, (size_t)(frag - path)) : g5c_xstrdup(path);
        if (u->path[0] == '?') { /* "http://h?x" -> "/?x" */
            char *t = g5c_xasprintf("/%s", u->path);
            free(u->path);
            u->path = t;
        }
    }
    return 0;
bad:
    url_free(u);
    memset(u, 0, sizeof *u);
    return -1;
}

/* ---- socket I/O with a deadline ---- */

static int ms_left(double deadline)
{
    double left = deadline - g5c_now_seconds();
    return left <= 0 ? 0 : (int)(left * 1000.0) + 1;
}

/* 0 ready, 1 timeout, -1 error */
static int wait_fd(int fd, short ev, double deadline)
{
    struct pollfd p = {fd, ev, 0};
    for (;;) {
        int ms = ms_left(deadline), r;
        if (ms == 0)
            return 1;
        r = poll(&p, 1, ms);
        if (r > 0)
            return 0;
        if (r == 0)
            return 1;
        if (errno != EINTR)
            return -1;
    }
}

static void conn_destroy(cconn_t *c)
{
    if (c == NULL)
        return;
    if (c->sess)
        nghttp2_session_del(c->sess);
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->fd >= 0)
        close(c->fd);
    free(c->key);
    free(c);
}

/* Write all bytes. Returns 0 / G5C_SBI_E_* */
static int io_write(cconn_t *c, const uint8_t *p, size_t n, double deadline)
{
    while (n > 0) {
        if (c->ssl != NULL) {
            int r = SSL_write(c->ssl, p, (int)(n > 16384 ? 16384 : n));
            if (r > 0) {
                p += r;
                n -= (size_t)r;
                continue;
            }
            {
                int e = SSL_get_error(c->ssl, r), w;
                if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                    ERR_clear_error();
                    return G5C_SBI_E_TLS;
                }
                w = wait_fd(c->fd, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
                if (w != 0)
                    return w > 0 ? G5C_SBI_E_TIMEOUT : G5C_SBI_E_IO;
            }
        } else {
            ssize_t r = send(c->fd, p, n, MSG_NOSIGNAL);
            if (r > 0) {
                p += r;
                n -= (size_t)r;
                continue;
            }
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                int w = wait_fd(c->fd, POLLOUT, deadline);
                if (w != 0)
                    return w > 0 ? G5C_SBI_E_TIMEOUT : G5C_SBI_E_IO;
                continue;
            }
            return G5C_SBI_E_IO;
        }
    }
    return 0;
}

/* Read some bytes: returns >0 count, 0 EOF, or negative G5C_SBI_E_* */
static long io_read(cconn_t *c, uint8_t *buf, size_t cap, double deadline)
{
    for (;;) {
        if (c->ssl != NULL) {
            int r = SSL_read(c->ssl, buf, (int)cap), e;
            if (r > 0)
                return r;
            e = SSL_get_error(c->ssl, r);
            if (e == SSL_ERROR_ZERO_RETURN)
                return 0;
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                int w = wait_fd(c->fd, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
                if (w != 0)
                    return w > 0 ? G5C_SBI_E_TIMEOUT : G5C_SBI_E_IO;
                continue;
            }
            ERR_clear_error();
            return G5C_SBI_E_TLS;
        } else {
            ssize_t r = recv(c->fd, buf, cap, 0);
            if (r >= 0)
                return (long)r;
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                int w = wait_fd(c->fd, POLLIN, deadline);
                if (w != 0)
                    return w > 0 ? G5C_SBI_E_TIMEOUT : G5C_SBI_E_IO;
                continue;
            }
            return G5C_SBI_E_IO;
        }
    }
}

/* ---- connect ---- */

static int tcp_connect(const url_t *u, double deadline, int *fd_out, char *err, size_t errcap)
{
    struct addrinfo hints, *res = NULL, *ai;
    int rc, last = G5C_SBI_E_IO;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(u->host, u->port, &hints, &res);
    if (rc != 0) {
        seterr(err, errcap, "cannot resolve %s: %s", u->host, gai_strerror(rc));
        return G5C_SBI_E_IO;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol), one = 1;
        if (fd < 0)
            continue;
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            *fd_out = fd;
            freeaddrinfo(res);
            return 0;
        }
        if (errno == EINPROGRESS) {
            int w = wait_fd(fd, POLLOUT, deadline);
            if (w == 0) {
                int soerr = 0;
                socklen_t sl = sizeof soerr;
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
                if (soerr == 0) {
                    *fd_out = fd;
                    freeaddrinfo(res);
                    return 0;
                }
                seterr(err, errcap, "connect %s: %s", u->authority, strerror(soerr));
            } else if (w > 0) {
                last = G5C_SBI_E_TIMEOUT;
                seterr(err, errcap, "connect %s: timeout", u->authority);
            }
        } else {
            seterr(err, errcap, "connect %s: %s", u->authority, strerror(errno));
        }
        close(fd);
    }
    freeaddrinfo(res);
    return last;
}

/* ---- nghttp2 client callbacks ---- */

static int cb_header(nghttp2_session *s, const nghttp2_frame *f, const uint8_t *name, size_t nl,
                     const uint8_t *value, size_t vl, uint8_t flags, void *ud)
{
    rq_t *rq = nghttp2_session_get_stream_user_data(s, f->hd.stream_id);
    (void)flags;
    (void)ud;
    if (rq == NULL || f->hd.type != NGHTTP2_HEADERS || f->headers.cat != NGHTTP2_HCAT_RESPONSE)
        return 0;
    if (nl == 7 && memcmp(name, ":status", 7) == 0) {
        char t[8];
        size_t n = vl < 7 ? vl : 7;
        memcpy(t, value, n);
        t[n] = '\0';
        rq->out->status = atoi(t);
        rq->got_headers = true;
    } else if (nl > 0 && name[0] != ':') {
        char *n = g5c_xstrndup((const char *)name, nl), *v = g5c_xstrndup((const char *)value, vl);
        /* repeated headers: keep the last, as the callers only need single-valued ones */
        g5c_resp_header(rq->out, n, v);
        free(n);
        free(v);
    }
    return 0;
}

static int cb_data(nghttp2_session *s, uint8_t flags, int32_t id, const uint8_t *data, size_t len, void *ud)
{
    rq_t *rq = nghttp2_session_get_stream_user_data(s, id);
    (void)flags;
    (void)ud;
    if (rq == NULL)
        return 0;
    if (rq->total + len > MAX_RESP_BYTES)
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    rq->total += len;
    g5c_bytes_append(&rq->rbody, data, len);
    return 0;
}

static int cb_close(nghttp2_session *s, int32_t id, uint32_t code, void *ud)
{
    rq_t *rq = nghttp2_session_get_stream_user_data(s, id);
    (void)ud;
    if (rq != NULL) {
        rq->done = true;
        rq->failed_stream = code != 0 || !rq->got_headers;
    }
    return 0;
}

static int cb_goaway(nghttp2_session *s, const nghttp2_frame *f, void *ud)
{
    (void)s;
    (void)ud;
    (void)f;
    return 0;
}

static ssize_t body_read(nghttp2_session *s, int32_t id, uint8_t *buf, size_t length, uint32_t *flags,
                         nghttp2_data_source *src, void *ud)
{
    rq_t *rq = src->ptr;
    size_t left = rq->body_len - rq->body_off, n = left < length ? left : length;
    (void)s;
    (void)id;
    (void)ud;
    memcpy(buf, rq->body + rq->body_off, n);
    rq->body_off += n;
    if (rq->body_off == rq->body_len)
        *flags |= NGHTTP2_DATA_FLAG_EOF;
    return (ssize_t)n;
}

static nghttp2_session *new_session(void)
{
    nghttp2_session_callbacks *cbs;
    nghttp2_session *s = NULL;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_on_header_callback(cbs, cb_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, cb_data);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, cb_close);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, cb_goaway);
    nghttp2_session_client_new(&s, cbs, NULL);
    nghttp2_session_callbacks_del(cbs);
    return s;
}

static int open_conn(g5c_client *c, const url_t *u, const char *key, double deadline, cconn_t **out, char *err,
                     size_t errcap)
{
    cconn_t *cc;
    int fd = -1, rc = tcp_connect(u, deadline, &fd, err, errcap);
    if (rc != 0)
        return rc;
    cc = g5c_xcalloc(1, sizeof *cc);
    cc->fd = fd;
    cc->key = g5c_xstrdup(key);
    if (u->https) {
        struct in6_addr a6;
        struct in_addr a4;
        pthread_mutex_lock(&c->mu);
        cc->ssl = c->tls != NULL ? SSL_new(c->tls) : NULL; /* the SSL holds a reference: a swap cannot free the context under it */
        pthread_mutex_unlock(&c->mu);
        if (cc->ssl == NULL) {
            conn_destroy(cc);
            seterr(err, errcap, "https:// needs a TLS client context");
            return G5C_SBI_E_URL;
        }
        SSL_set_fd(cc->ssl, fd);
        SSL_set_connect_state(cc->ssl);
        if (inet_pton(AF_INET, u->host, &a4) == 1 || inet_pton(AF_INET6, u->host, &a6) == 1) {
            X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(cc->ssl), u->host);
        } else {
            SSL_set_tlsext_host_name(cc->ssl, u->host);
            SSL_set1_host(cc->ssl, u->host);
        }
        for (;;) {
            int r = SSL_connect(cc->ssl), e, w;
            if (r == 1)
                break;
            e = SSL_get_error(cc->ssl, r);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                char buf[160] = "";
                unsigned long oe = ERR_peek_last_error();
                if (oe)
                    ERR_error_string_n(oe, buf, sizeof buf);
                ERR_clear_error();
                seterr(err, errcap, "TLS handshake with %s failed: %s", u->authority, buf);
                conn_destroy(cc);
                return G5C_SBI_E_TLS;
            }
            w = wait_fd(fd, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
            if (w != 0) {
                conn_destroy(cc);
                return w > 0 ? G5C_SBI_E_TIMEOUT : G5C_SBI_E_IO;
            }
        }
        {
            const unsigned char *alpn = NULL;
            unsigned alen = 0;
            SSL_get0_alpn_selected(cc->ssl, &alpn, &alen);
            if (alen != 2 || memcmp(alpn, "h2", 2) != 0) {
                conn_destroy(cc);
                seterr(err, errcap, "peer did not negotiate h2");
                return G5C_SBI_E_TLS;
            }
        }
    }
    cc->sess = new_session();
    nghttp2_submit_settings(cc->sess, NGHTTP2_FLAG_NONE, NULL, 0);
    *out = cc;
    return 0;
}

/* ---- pool ---- */

static cconn_t *pool_take(g5c_client *c, const char *key)
{
    cconn_t **pp, *r = NULL;
    pthread_mutex_lock(&c->mu);
    for (pp = &c->idle; *pp != NULL; pp = &(*pp)->next) {
        if (strcmp((*pp)->key, key) == 0) {
            r = *pp;
            *pp = r->next;
            r->next = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&c->mu);
    return r;
}

static void pool_put(g5c_client *c, cconn_t *cc)
{
    size_t n = 0;
    cconn_t *p, *drop = NULL;
    pthread_mutex_lock(&c->mu);
    for (p = c->idle; p != NULL; p = p->next)
        if (strcmp(p->key, cc->key) == 0)
            n++;
    if (n >= MAX_IDLE_PER_KEY) {
        drop = cc;
    } else {
        cc->next = c->idle;
        c->idle = cc;
    }
    pthread_mutex_unlock(&c->mu);
    conn_destroy(drop);
}

g5c_client *g5c_client_new(int timeout_ms, SSL_CTX *tls)
{
    g5c_client *c = g5c_xcalloc(1, sizeof *c);
    signal(SIGPIPE, SIG_IGN); /* a peer closing mid-write must be an error return, not a process kill */
    c->timeout_ms = timeout_ms > 0 ? timeout_ms : 5000;
    c->tls = tls;
    pthread_mutex_init(&c->mu, NULL);
    return c;
}

void g5c_client_swap_tls(g5c_client *c, SSL_CTX *fresh)
{
    SSL_CTX *old;
    cconn_t *drop, *p;
    pthread_mutex_lock(&c->mu);
    old = c->tls;
    c->tls = fresh;
    drop = c->idle; /* idle connections were made with the old certificate: new requests open new ones */
    c->idle = NULL;
    pthread_mutex_unlock(&c->mu);
    while ((p = drop) != NULL) {
        drop = p->next;
        conn_destroy(p);
    }
    if (old)
        SSL_CTX_free(old);
}

void g5c_client_free(g5c_client *c)
{
    cconn_t *p;
    if (c == NULL)
        return;
    while ((p = c->idle) != NULL) {
        c->idle = p->next;
        conn_destroy(p);
    }
    if (c->tls)
        SSL_CTX_free(c->tls);
    free(c->scp_root);
    free(c->scp_prefix);
    free(c->scp_authority);
    free(c->direct_authority);
    free(c->ua);
    pthread_mutex_destroy(&c->mu);
    free(c);
}

/* ---- request ---- */

static nghttp2_nv nv_of(const char *n, const char *v)
{
    nghttp2_nv x;
    x.name = (uint8_t *)(uintptr_t)n;
    x.value = (uint8_t *)(uintptr_t)v;
    x.namelen = strlen(n);
    x.valuelen = strlen(v);
    x.flags = NGHTTP2_NV_FLAG_NONE;
    return x;
}

/* One attempt on `cc`. Returns 0 on a complete response, else an error; *reusable says the connection can be pooled. */
static int exchange(cconn_t *cc, const url_t *u, const char *method, const g5c_kv *hdrs, size_t nh, const char *ctype,
                    const void *body, size_t body_len, g5c_resp *out, double deadline, bool *reusable, char *err,
                    size_t errcap)
{
    rq_t rq;
    size_t nn = 4 + nh + (body_len ? 2 : 0), k = 0;
    nghttp2_nv *nv = g5c_xcalloc(nn, sizeof *nv);
    nghttp2_data_provider prd;
    char clen[24];
    int32_t sid;
    int rc = 0;
    uint8_t rbuf[16384];

    memset(&rq, 0, sizeof rq);
    rq.out = out;
    rq.body = body;
    rq.body_len = body_len;
    g5c_bytes_init(&rq.rbody);
    *reusable = false;

#define NVL(n_, v_) nv_of((n_), (v_))
    nv[k++] = NVL(":method", method);
    nv[k++] = NVL(":scheme", u->https ? "https" : "http");
    nv[k++] = NVL(":authority", u->authority);
    nv[k++] = NVL(":path", u->path);
    for (size_t i = 0; i < nh; i++)
        nv[k++] = NVL(hdrs[i].name, hdrs[i].value);
    if (body_len) {
        snprintf(clen, sizeof clen, "%zu", body_len);
        nv[k++] = NVL("content-type", ctype ? ctype : G5C_JSON_TYPE);
        nv[k++] = NVL("content-length", clen);
    }
#undef NVL
    prd.source.ptr = &rq;
    prd.read_callback = body_read;
    sid = nghttp2_submit_request(cc->sess, NULL, nv, k, body_len ? &prd : NULL, &rq);
    free(nv);
    if (sid < 0) {
        seterr(err, errcap, "cannot submit request: %s", nghttp2_strerror(sid));
        return G5C_SBI_E_REQUEST;
    }
    while (!rq.done) {
        for (;;) {
            const uint8_t *d;
            ssize_t n = nghttp2_session_mem_send(cc->sess, &d);
            if (n < 0) {
                rc = G5C_SBI_E_HTTP;
                goto out;
            }
            if (n == 0)
                break;
            rc = io_write(cc, d, (size_t)n, deadline);
            if (rc != 0)
                goto out;
        }
        if (rq.done)
            break;
        if (!nghttp2_session_want_read(cc->sess)) {
            rc = G5C_SBI_E_HTTP;
            goto out;
        }
        {
            long r = io_read(cc, rbuf, sizeof rbuf, deadline);
            if (r < 0) {
                rc = (int)r;
                goto out;
            }
            if (r == 0) {
                rc = G5C_SBI_E_IO;
                seterr(err, errcap, "connection closed by peer");
                goto out;
            }
            if (nghttp2_session_mem_recv(cc->sess, rbuf, (size_t)r) < 0) {
                rc = G5C_SBI_E_HTTP;
                goto out;
            }
        }
    }
    if (rq.failed_stream) {
        rc = G5C_SBI_E_HTTP;
        seterr(err, errcap, "stream failed");
        goto out;
    }
    /* flush any pending ACK/WINDOW_UPDATE frames so the connection stays healthy, then pool it */
    for (;;) {
        const uint8_t *d;
        ssize_t n = nghttp2_session_mem_send(cc->sess, &d);
        if (n <= 0)
            break;
        if (io_write(cc, d, (size_t)n, deadline) != 0)
            goto out;
    }
    *reusable = nghttp2_session_want_read(cc->sess) != 0;
    {
        size_t bl = 0;
        char *b = g5c_bytes_take(&rq.rbody, &bl);
        free(out->body);
        out->body = (uint8_t *)b;
        out->body_len = bl;
    }
    return 0;
out:
    g5c_bytes_free(&rq.rbody);
    return rc;
}

static int client_request_direct(g5c_client *c, const char *method, const char *url, const g5c_kv *headers, size_t nheaders,
                                 const char *content_type, const void *body, size_t body_len, g5c_resp *out, char *err, size_t errcap)
{
    url_t u;
    char *key;
    double deadline = g5c_now_seconds() + (double)c->timeout_ms / 1000.0;
    int rc = G5C_SBI_E_IO;
    if (err != NULL && errcap > 0)
        err[0] = 0;
    if (url_parse(url, &u) != 0) {
        seterr(err, errcap, "bad url: %s (only http:// and https:// are supported)", url);
        return G5C_SBI_E_URL;
    }
    key = g5c_xasprintf("%s://%s", u.https ? "https" : "http", u.authority);
    for (int attempt = 0; attempt < 2; attempt++) {
        cconn_t *cc = attempt == 0 ? pool_take(c, key) : NULL;
        bool reused = cc != NULL, reusable = false;
        g5c_resp tmp;
        if (cc == NULL) {
            rc = open_conn(c, &u, key, deadline, &cc, err, errcap);
            if (rc != 0)
                break;
        }
        g5c_resp_init(&tmp);
        rc = exchange(cc, &u, method, headers, nheaders, content_type, body, body_len, &tmp, deadline, &reusable, err,
                      errcap);
        if (rc == 0) {
            *out = tmp;
            if (reusable)
                pool_put(c, cc);
            else
                conn_destroy(cc);
            break;
        }
        g5c_resp_free(&tmp);
        conn_destroy(cc);
        /* a pooled connection may have been closed by the peer while idle: retry once on a fresh one */
        if (!reused || rc == G5C_SBI_E_TIMEOUT)
            break;
    }
    if (rc != 0 && err != NULL && errcap > 0 && err[0] == 0) {
        switch (rc) {
        case G5C_SBI_E_TIMEOUT: seterr(err, errcap, "timeout"); break;
        case G5C_SBI_E_TLS: seterr(err, errcap, "tls failure"); break;
        case G5C_SBI_E_HTTP: seterr(err, errcap, "http/2 protocol failure"); break;
        default: seterr(err, errcap, "io failure"); break;
        }
    }
    free(key);
    url_free(&u);
    return rc;
}

/* ---- indirect communication ---- */

/* "scheme://authority[/prefix]" into the pieces; false when it is not an http(s) URI */
static bool split_root(const char *uri, char **root, char **prefix, char **authority)
{
    url_t u;
    const char *q;
    size_t pl;
    if (url_parse(uri, &u) != 0)
        return false;
    *authority = g5c_xstrdup(u.authority);
    *root = g5c_xasprintf("%s://%s", u.https ? "https" : "http", u.authority);
    q = strpbrk(u.path, "?#");
    pl = q != NULL ? (size_t)(q - u.path) : strlen(u.path);
    while (pl > 0 && u.path[pl - 1] == '/')
        pl--;
    *prefix = pl > 1 ? g5c_xstrndup(u.path, pl) : g5c_xstrdup("");
    url_free(&u);
    return true;
}

void g5c_client_set_scp(g5c_client *c, const char *scp_uri, const char *direct_uri)
{
    char *root = NULL, *prefix = NULL, *auth = NULL, *d1 = NULL, *d2 = NULL, *d3 = NULL;
    if (scp_uri != NULL && !split_root(scp_uri, &root, &prefix, &auth)) {
        root = prefix = auth = NULL;
    }
    pthread_mutex_lock(&c->mu);
    free(c->scp_root);
    free(c->scp_prefix);
    free(c->scp_authority);
    free(c->direct_authority);
    c->scp_root = root;
    c->scp_prefix = prefix;
    c->scp_authority = auth;
    c->direct_authority = NULL;
    if (root != NULL && direct_uri != NULL && split_root(direct_uri, &d1, &d2, &d3))
        c->direct_authority = d3;
    else
        free(d3);
    pthread_mutex_unlock(&c->mu);
    free(d1);
    free(d2);
}

void g5c_client_set_timeout(g5c_client *c, int timeout_ms)
{
    pthread_mutex_lock(&c->mu);
    c->timeout_ms = timeout_ms > 0 ? timeout_ms : 5000;
    pthread_mutex_unlock(&c->mu);
}

void g5c_client_set_token_provider(g5c_client *c, g5c_token_fn fn, g5c_token_reject_fn reject, void *user)
{
    pthread_mutex_lock(&c->mu);
    c->token_fn = fn;
    c->token_reject = reject;
    c->token_user = user;
    pthread_mutex_unlock(&c->mu);
}

void g5c_client_set_user_agent(g5c_client *c, const char *ua)
{
    char *copy = ua != NULL ? g5c_xstrdup(ua) : NULL;
    pthread_mutex_lock(&c->mu);
    free(c->ua);
    c->ua = copy;
    pthread_mutex_unlock(&c->mu);
}

int g5c_client_request(g5c_client *c, const char *method, const char *url, const g5c_kv *headers, size_t nheaders,
                       const char *content_type, const void *body, size_t body_len, g5c_resp *out, char *err,
                       size_t errcap)
{
    char trace_hdr[64];
    char *scp_root, *scp_prefix, *scp_auth, *direct, *ua, *via_url = NULL, *target_root = NULL, *token = NULL, *token_hdr = NULL;
    g5c_kv *hh = NULL;
    size_t nh = nheaders;
    url_t u;
    int rc;
    bool has_ua = false, has_auth = false;
    size_t tok_ix = 0;
    g5c_token_fn token_fn;
    g5c_token_reject_fn token_reject;
    void *token_user;
    pthread_mutex_lock(&c->mu);
    scp_root = c->scp_root != NULL ? g5c_xstrdup(c->scp_root) : NULL;
    scp_prefix = c->scp_prefix != NULL ? g5c_xstrdup(c->scp_prefix) : NULL;
    scp_auth = c->scp_authority != NULL ? g5c_xstrdup(c->scp_authority) : NULL;
    direct = c->direct_authority != NULL ? g5c_xstrdup(c->direct_authority) : NULL;
    ua = c->ua != NULL ? g5c_xstrdup(c->ua) : NULL;
    token_fn = c->token_fn;
    token_reject = c->token_reject;
    token_user = c->token_user;
    pthread_mutex_unlock(&c->mu);
    if (scp_root == NULL && ua == NULL && token_fn == NULL && g5c_trace_current() == NULL) {
        rc = client_request_direct(c, method, url, headers, nheaders, content_type, body, body_len, out, err, errcap);
        goto done;
    }
    if (url_parse(url, &u) != 0) {
        rc = client_request_direct(c, method, url, headers, nheaders, content_type, body, body_len, out, err, errcap); /* reports the bad URL */
        goto done;
    }
    for (size_t i = 0; i < nheaders; i++)
    {
        if (strcmp(headers[i].name, "user-agent") == 0)
            has_ua = true;
        if (strcmp(headers[i].name, "authorization") == 0)
            has_auth = true;
    }
    hh = g5c_xcalloc(nheaders + 4, sizeof *hh);
    if (nheaders > 0)
        memcpy(hh, headers, nheaders * sizeof *hh);
    g5c_trace_header(trace_hdr);
    if (trace_hdr[0] != 0) {
        bool has_tp = false;
        for (size_t i = 0; i < nheaders; i++)
            if (strcmp(headers[i].name, "traceparent") == 0)
                has_tp = true;
        if (!has_tp) {
            hh[nh].name = "traceparent";
            hh[nh].value = trace_hdr;
            nh++;
        }
    }
    if (ua != NULL && !has_ua) {
        hh[nh].name = "user-agent";
        hh[nh].value = ua;
        nh++;
    }
    if (token_fn != NULL && !has_auth && (token = token_fn(token_user, method, url)) != NULL) {
        token_hdr = g5c_xasprintf("Bearer %s", token);
        hh[nh].name = "authorization";
        hh[nh].value = token_hdr;
        tok_ix = nh;
        nh++;
    }
    if (scp_root != NULL && (direct == NULL || strcmp(direct, u.authority) != 0) && strcmp(scp_auth, u.authority) != 0) {
        target_root = g5c_xasprintf("%s://%s", u.https ? "https" : "http", u.authority);
        via_url = g5c_xasprintf("%s%s%s", scp_root, scp_prefix, u.path);
        hh[nh].name = "3gpp-sbi-target-apiroot";
        hh[nh].value = target_root;
        nh++;
    }
    rc = client_request_direct(c, method, via_url != NULL ? via_url : url, hh, nh, content_type, body, body_len, out, err, errcap);
    if (rc == 0 && token != NULL && out->status == 401 && token_reject != NULL) { /* the token was not good: ask for another, once */
        char *fresh;
        token_reject(token_user, method, url);
        fresh = token_fn(token_user, method, url);
        if (fresh != NULL && strcmp(fresh, token) != 0) {
            free(token_hdr);
            token_hdr = g5c_xasprintf("Bearer %s", fresh);
            hh[tok_ix].value = token_hdr;
            g5c_resp_free(out);
            rc = client_request_direct(c, method, via_url != NULL ? via_url : url, hh, nh, content_type, body, body_len, out, err, errcap);
        }
        free(fresh);
    }
    url_free(&u);
done:
    free(hh);
    free(token);
    free(token_hdr);
    free(via_url);
    free(target_root);
    free(scp_root);
    free(scp_prefix);
    free(scp_auth);
    free(direct);
    free(ua);
    return rc;
}

int g5c_client_get(g5c_client *c, const char *url, g5c_resp *out, char *err, size_t errcap)
{
    return g5c_client_request(c, "GET", url, NULL, 0, NULL, NULL, 0, out, err, errcap);
}

int g5c_client_send_json(g5c_client *c, const char *method, const char *url, const g5c_json *j, g5c_resp *out,
                         char *err, size_t errcap)
{
    size_t n = 0;
    char *s = j ? g5c_json_to_string(j, &n) : NULL;
    int rc = g5c_client_request(c, method, url, NULL, 0, G5C_JSON_TYPE, s, n, out, err, errcap);
    free(s);
    return rc;
}
