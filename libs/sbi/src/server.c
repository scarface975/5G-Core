/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* HTTP/2 server: libuv for sockets, nghttp2 for the protocol, OpenSSL memory BIOs for TLS */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <uv.h>

#include "g5c/sbi.h"

#define READ_BUF 16384
#define MAX_CONNECTIONS 8192
#define MAX_HEADERS 128
#define MAX_HEADER_BYTES 16384

struct conn;

typedef struct stream {
    int32_t id;
    struct conn *conn;
    g5c_req req;
    g5c_resp resp;
    size_t sent;
    size_t hdr_bytes;
    bool overflow, closed, dispatched, bad;
    int refs; /* 1 for nghttp2 + 1 while a worker holds it */
    struct stream *prev, *next; /* per-connection list, so streams are freed even if the peer vanishes */
} stream_t;

typedef struct work {
    stream_t *st;
    struct work *next;
} work_t;

typedef struct conn {
    uv_tcp_t tcp;
    struct g5c_server *srv;
    nghttp2_session *sess;
    SSL *ssl;
    BIO *rbio, *wbio;
    char rdbuf[READ_BUF];
    stream_t *streams;
    int refs; /* outstanding asynchronous operations: pending writes and in-flight handler work */
    bool closing, handle_closed;
} conn_t;

struct g5c_server {
    uv_loop_t loop;
    uv_tcp_t listener;
    uv_async_t stop_async;
    pthread_t thread;
    const g5c_router *router;
    SSL_CTX *tls;       /* the context new connections use; replaced by g5c_server_swap_tls, under tlsmu */
    pthread_mutex_t tlsmu;
    uint16_t port;
    int active_conns;
    bool started;
    /* handler worker pool: queue of pending work; completions go back to the loop thread via done_async */
    uv_async_t done_async;
    pthread_t *workers;
    size_t nworkers;
    pthread_mutex_t wmu;
    pthread_cond_t wcv;
    work_t *qhead, *qtail; /* pending, protected by wmu */
    work_t *dhead, *dtail; /* completed, awaiting the loop thread, protected by wmu */
    size_t inflight;       /* queued + running + completed-not-yet-processed, protected by wmu */
    bool quit;             /* workers exit (protected by wmu) */
    bool stopping;         /* loop thread only */
    /* start-up handshake with the caller */
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool ready;
    char err[160];
};

/* ---- stream lifetime ---- */

static void stream_release(stream_t *s)
{
    if (--s->refs > 0)
        return;
    g5c_req_free(&s->req);
    g5c_resp_free(&s->resp);
    free(s);
}

/* ---- connection lifetime ---- */

static void conn_free(conn_t *c)
{
    while (c->streams != NULL) { /* streams nghttp2 never reported closed */
        stream_t *st = c->streams;
        c->streams = st->next;
        st->closed = true;
        stream_release(st);
    }
    if (c->sess)
        nghttp2_session_del(c->sess);
    if (c->ssl)
        SSL_free(c->ssl); /* frees the BIOs it owns */
    free(c);
}

/* A connection is freed once its libuv handle is closed and no write or handler work still refers to it. */
static void conn_unref(conn_t *c)
{
    if (--c->refs == 0 && c->handle_closed)
        conn_free(c);
}

static void on_conn_closed(uv_handle_t *h)
{
    conn_t *c = h->data;
    c->srv->active_conns--;
    c->handle_closed = true;
    if (c->refs == 0)
        conn_free(c);
}

static void conn_close(conn_t *c)
{
    if (c->closing)
        return;
    c->closing = true;
    uv_close((uv_handle_t *)&c->tcp, on_conn_closed);
}

/* ---- output path ---- */

typedef struct {
    uv_write_t req;
    conn_t *conn;
    g5c_bytes buf;
} wreq_t;

static void on_write(uv_write_t *w, int status)
{
    wreq_t *wr = (wreq_t *)w;
    conn_t *c = wr->conn;
    g5c_bytes_free(&wr->buf);
    free(wr);
    if (status < 0)
        conn_close(c);
    conn_unref(c);
}

/* Queue bytes for the peer */
static bool send_bytes(conn_t *c, g5c_bytes *out)
{
    wreq_t *wr;
    uv_buf_t b;
    if (out->len == 0 || c->closing) {
        g5c_bytes_free(out);
        return !c->closing;
    }
    wr = g5c_xcalloc(1, sizeof *wr);
    wr->conn = c;
    wr->buf = *out;
    g5c_bytes_init(out);
    c->refs++;
    b = uv_buf_init((char *)wr->buf.data, (unsigned)wr->buf.len);
    if (uv_write(&wr->req, (uv_stream_t *)&c->tcp, &b, 1, on_write) != 0) {
        g5c_bytes_free(&wr->buf);
        free(wr);
        c->refs--; /* the handle is still open (conn_close below only starts closing it) */
        conn_close(c);
        return false;
    }
    return true;
}

/* Drain encrypted bytes OpenSSL queued for the peer into `out`. */
static void drain_wbio(conn_t *c, g5c_bytes *out)
{
    char tmp[4096];
    int n;
    while ((n = BIO_read(c->wbio, tmp, sizeof tmp)) > 0)
        g5c_bytes_append(out, tmp, (size_t)n);
}

/* Push everything nghttp2 wants to send. */
static void conn_flush(conn_t *c)
{
    g5c_bytes out;
    g5c_bytes_init(&out);
    if (c->closing)
        return;
    if (c->ssl != NULL && !SSL_is_init_finished(c->ssl)) {
        drain_wbio(c, &out); /* handshake records only */
        (void)send_bytes(c, &out);
        return;
    }
    for (;;) {
        const uint8_t *data;
        ssize_t n = nghttp2_session_mem_send(c->sess, &data);
        if (n < 0) {
            conn_close(c);
            break;
        }
        if (n == 0)
            break;
        if (c->ssl != NULL) {
            if (SSL_write(c->ssl, data, (int)n) != (int)n) {
                conn_close(c);
                break;
            }
            drain_wbio(c, &out);
        } else {
            g5c_bytes_append(&out, data, (size_t)n);
        }
    }
    if (!send_bytes(c, &out))
        return;
    if (!c->closing && !nghttp2_session_want_read(c->sess) && !nghttp2_session_want_write(c->sess))
        conn_close(c);
}

/* ---- request dispatch ---- */

static ssize_t body_read(nghttp2_session *sess, int32_t id, uint8_t *buf, size_t length, uint32_t *flags,
                         nghttp2_data_source *src, void *ud)
{
    stream_t *st = src->ptr;
    size_t left = st->resp.body_len - st->sent, n = left < length ? left : length;
    (void)sess;
    (void)id;
    (void)ud;
    memcpy(buf, st->resp.body + st->sent, n);
    st->sent += n;
    if (st->sent == st->resp.body_len)
        *flags |= NGHTTP2_DATA_FLAG_EOF;
    return (ssize_t)n;
}

static void submit_response(stream_t *st)
{
    conn_t *c = st->conn;
    g5c_resp *r = &st->resp;
    size_t n = 2 + r->nheaders, k = 0;
    nghttp2_nv *nv = g5c_xcalloc(n + 1, sizeof *nv);
    char status[8], clen[24];
    nghttp2_data_provider prd;
    snprintf(status, sizeof status, "%d", r->status);
    nv[k++] = (nghttp2_nv){(uint8_t *)":status", (uint8_t *)status, 7, strlen(status), NGHTTP2_NV_FLAG_NONE};
    for (size_t i = 0; i < r->nheaders; i++) {
        if (strcmp(r->headers[i].name, "content-length") == 0)
            continue;
        nv[k++] = (nghttp2_nv){(uint8_t *)r->headers[i].name, (uint8_t *)r->headers[i].value,
                               strlen(r->headers[i].name), strlen(r->headers[i].value), NGHTTP2_NV_FLAG_NONE};
    }
    snprintf(clen, sizeof clen, "%zu", r->body_len);
    nv[k++] = (nghttp2_nv){(uint8_t *)"content-length", (uint8_t *)clen, 14, strlen(clen), NGHTTP2_NV_FLAG_NONE};
    prd.source.ptr = st;
    prd.read_callback = body_read;
    if (nghttp2_submit_response(c->sess, st->id, nv, k, r->body_len ? &prd : NULL) != 0)
        conn_close(c);
    free(nv);
}

static void *worker_main(void *arg)
{
    struct g5c_server *srv = arg;
    for (;;) {
        work_t *wk;
        pthread_mutex_lock(&srv->wmu);
        while (srv->qhead == NULL && !srv->quit)
            pthread_cond_wait(&srv->wcv, &srv->wmu);
        if (srv->qhead == NULL) {
            pthread_mutex_unlock(&srv->wmu);
            return NULL;
        }
        wk = srv->qhead;
        srv->qhead = wk->next;
        if (srv->qhead == NULL)
            srv->qtail = NULL;
        pthread_mutex_unlock(&srv->wmu);

        (void)g5c_trace_enter_header(g5c_req_header(&wk->st->req, "traceparent")); /* the trace of the caller, or a new one */
        g5c_router_dispatch(srv->router, &wk->st->req, &wk->st->resp);
        g5c_trace_leave();

        pthread_mutex_lock(&srv->wmu);
        wk->next = NULL;
        if (srv->dtail != NULL)
            srv->dtail->next = wk;
        else
            srv->dhead = wk;
        srv->dtail = wk;
        uv_async_send(&srv->done_async); /* under the lock: the loop thread closes the handle only when idle, under the lock */
        pthread_mutex_unlock(&srv->wmu);
    }
}

static void finish_work(work_t *wk)
{
    stream_t *st = wk->st;
    conn_t *c = st->conn;
    if (!st->closed && !c->closing) {
        submit_response(st);
        conn_flush(c);
    }
    stream_release(st);
    conn_unref(c);
    free(wk);
}

/* Once stop was requested and all work has drained, the completion handle can go. */
static void maybe_close_done(struct g5c_server *srv)
{
    bool idle;
    pthread_mutex_lock(&srv->wmu);
    idle = srv->stopping && srv->inflight == 0;
    pthread_mutex_unlock(&srv->wmu);
    if (idle && !uv_is_closing((uv_handle_t *)&srv->done_async))
        uv_close((uv_handle_t *)&srv->done_async, NULL);
}

static void done_cb(uv_async_t *a)
{
    struct g5c_server *srv = a->data;
    work_t *list;
    pthread_mutex_lock(&srv->wmu);
    list = srv->dhead;
    srv->dhead = srv->dtail = NULL;
    pthread_mutex_unlock(&srv->wmu);
    while (list != NULL) {
        work_t *next = list->next;
        finish_work(list);
        pthread_mutex_lock(&srv->wmu);
        srv->inflight--;
        pthread_mutex_unlock(&srv->wmu);
        list = next;
    }
    maybe_close_done(srv);
}

static void dispatch(stream_t *st)
{
    conn_t *c = st->conn;
    struct g5c_server *srv = c->srv;
    work_t *wk;
    if (st->dispatched)
        return;
    st->dispatched = true;
    if (st->overflow || st->bad) {
        if (st->overflow)
            g5c_resp_problem_simple(&st->resp, 413, "PAYLOAD_TOO_LARGE", NULL);
        else
            g5c_resp_problem_simple(&st->resp, 400, "MANDATORY_IE_INCORRECT", "malformed request");
        submit_response(st);
        return;
    }
    wk = g5c_xcalloc(1, sizeof *wk);
    wk->st = st;
    st->refs++;
    c->refs++;
    pthread_mutex_lock(&srv->wmu);
    if (srv->qtail != NULL)
        srv->qtail->next = wk;
    else
        srv->qhead = wk;
    srv->qtail = wk;
    srv->inflight++;
    pthread_cond_signal(&srv->wcv);
    pthread_mutex_unlock(&srv->wmu);
}

/* ---- nghttp2 callbacks ---- */

static int cb_begin_headers(nghttp2_session *s, const nghttp2_frame *f, void *ud)
{
    conn_t *c = ud;
    stream_t *st;
    if (f->hd.type != NGHTTP2_HEADERS || f->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    st = g5c_xcalloc(1, sizeof *st);
    st->id = f->hd.stream_id;
    st->conn = c;
    st->refs = 1;
    g5c_req_init(&st->req);
    g5c_resp_init(&st->resp);
    st->next = c->streams;
    if (c->streams != NULL)
        c->streams->prev = st;
    c->streams = st;
    st->req.scheme = g5c_xstrdup(c->ssl ? "https" : "http");
    {
        struct sockaddr_storage ss;
        int sl = (int)sizeof ss;
        if (uv_tcp_getpeername(&c->tcp, (struct sockaddr *)&ss, &sl) == 0) {
            if (ss.ss_family == AF_INET)
                inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, st->req.peer, sizeof st->req.peer);
            else if (ss.ss_family == AF_INET6)
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, st->req.peer, sizeof st->req.peer);
        }
    }
    nghttp2_session_set_stream_user_data(s, st->id, st);
    return 0;
}

static int cb_header(nghttp2_session *s, const nghttp2_frame *f, const uint8_t *name, size_t nl,
                     const uint8_t *value, size_t vl, uint8_t flags, void *ud)
{
    stream_t *st;
    (void)flags;
    (void)ud;
    if (f->hd.type != NGHTTP2_HEADERS || f->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    st = nghttp2_session_get_stream_user_data(s, f->hd.stream_id);
    if (st == NULL)
        return 0;
    st->hdr_bytes += nl + vl;
    if (st->hdr_bytes > MAX_HEADER_BYTES || st->req.nheaders >= MAX_HEADERS) {
        st->bad = true;
        return 0;
    }
    if (nl > 0 && name[0] == ':') {
        char *v = g5c_xstrndup((const char *)value, vl);
        if (nl == 7 && memcmp(name, ":method", 7) == 0) {
            free(st->req.method);
            st->req.method = v;
        } else if (nl == 5 && memcmp(name, ":path", 5) == 0) {
            char *q = strchr(v, '?');
            free(st->req.path);
            free(st->req.query);
            st->req.query = NULL;
            if (q != NULL) {
                st->req.path = g5c_xstrndup(v, (size_t)(q - v));
                st->req.query = g5c_xstrdup(q + 1);
            } else {
                st->req.path = g5c_xstrdup(v);
            }
            free(v);
        } else if (nl == 10 && memcmp(name, ":authority", 10) == 0) {
            free(st->req.authority);
            st->req.authority = v;
        } else {
            free(v);
        }
        return 0;
    }
    {
        char *n = g5c_xstrndup((const char *)name, nl), *v = g5c_xstrndup((const char *)value, vl);
        if (nl == 4 && memcmp(name, "host", 4) == 0 && st->req.authority == NULL)
            st->req.authority = g5c_xstrdup(v);
        g5c_req_add_header(&st->req, n, v);
        free(n);
        free(v);
    }
    return 0;
}

static int cb_data_chunk(nghttp2_session *s, uint8_t flags, int32_t id, const uint8_t *data, size_t len, void *ud)
{
    stream_t *st = nghttp2_session_get_stream_user_data(s, id);
    (void)flags;
    (void)ud;
    if (st == NULL || st->overflow)
        return 0;
    if (st->req.body_len + len > G5C_SBI_MAX_BODY) {
        st->overflow = true;
        return 0;
    }
    st->req.body = g5c_xrealloc(st->req.body, st->req.body_len + len + 1);
    memcpy(st->req.body + st->req.body_len, data, len);
    st->req.body_len += len;
    st->req.body[st->req.body_len] = 0;
    return 0;
}

static void finish_request(stream_t *st)
{
    if (st->req.method == NULL || st->req.path == NULL || st->req.path[0] != '/')
        st->bad = true;
    if (st->req.authority == NULL)
        st->req.authority = g5c_xstrdup("");
    if (st->req.body == NULL)
        g5c_req_set_body(&st->req, "", 0);
    dispatch(st);
}

static int cb_frame_recv(nghttp2_session *s, const nghttp2_frame *f, void *ud)
{
    stream_t *st;
    (void)ud;
    if (f->hd.type != NGHTTP2_HEADERS && f->hd.type != NGHTTP2_DATA)
        return 0;
    if (!(f->hd.flags & NGHTTP2_FLAG_END_STREAM))
        return 0;
    if (f->hd.type == NGHTTP2_HEADERS && f->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    st = nghttp2_session_get_stream_user_data(s, f->hd.stream_id);
    if (st != NULL)
        finish_request(st);
    return 0;
}

static int cb_stream_close(nghttp2_session *s, int32_t id, uint32_t code, void *ud)
{
    stream_t *st = nghttp2_session_get_stream_user_data(s, id);
    (void)code;
    (void)ud;
    if (st != NULL) {
        st->closed = true;
        if (st->prev != NULL)
            st->prev->next = st->next;
        else
            st->conn->streams = st->next;
        if (st->next != NULL)
            st->next->prev = st->prev;
        nghttp2_session_set_stream_user_data(s, id, NULL);
        stream_release(st);
    }
    return 0;
}

/* ---- input path ---- */

static int feed_plain(conn_t *c, const uint8_t *p, size_t n)
{
    ssize_t r = nghttp2_session_mem_recv(c->sess, p, n);
    return (r < 0 || (size_t)r != n) ? -1 : 0;
}

static int feed_tls(conn_t *c, const uint8_t *p, size_t n)
{
    if (BIO_write(c->rbio, p, (int)n) != (int)n)
        return -1;
    if (!SSL_is_init_finished(c->ssl)) {
        int rc = SSL_do_handshake(c->ssl);
        if (rc != 1) {
            int e = SSL_get_error(c->ssl, rc);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                ERR_clear_error();
                return -1;
            }
        }
        if (SSL_is_init_finished(c->ssl)) {
            const unsigned char *alpn = NULL;
            unsigned alen = 0;
            SSL_get0_alpn_selected(c->ssl, &alpn, &alen);
            if (alen != 2 || memcmp(alpn, "h2", 2) != 0)
                return -1; /* h2 is the only protocol we speak */
        } else {
            return 0;
        }
    }
    for (;;) {
        uint8_t plain[READ_BUF];
        int r = SSL_read(c->ssl, plain, sizeof plain);
        if (r > 0) {
            if (feed_plain(c, plain, (size_t)r) != 0)
                return -1;
            continue;
        }
        {
            int e = SSL_get_error(c->ssl, r);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                return 0;
            ERR_clear_error();
            return -1; /* includes clean close_notify */
        }
    }
}

static void alloc_cb(uv_handle_t *h, size_t suggested, uv_buf_t *buf)
{
    conn_t *c = h->data;
    (void)suggested;
    *buf = uv_buf_init(c->rdbuf, sizeof c->rdbuf);
}

static void read_cb(uv_stream_t *s, ssize_t n, const uv_buf_t *buf)
{
    conn_t *c = s->data;
    if (n < 0) {
        conn_close(c);
        return;
    }
    if (n == 0 || c->closing)
        return;
    if ((c->ssl ? feed_tls(c, (const uint8_t *)buf->base, (size_t)n) : feed_plain(c, (const uint8_t *)buf->base, (size_t)n)) !=
        0) {
        conn_close(c);
        return;
    }
    conn_flush(c);
}

static void on_connection(uv_stream_t *l, int status)
{
    struct g5c_server *srv = l->data;
    conn_t *c;
    SSL_CTX *ssl_ctx;
    nghttp2_session_callbacks *cbs;
    nghttp2_settings_entry iv[2] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 128},
                                    {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, MAX_HEADER_BYTES}};
    if (status < 0)
        return;
    c = g5c_xcalloc(1, sizeof *c);
    c->srv = srv;
    uv_tcp_init(&srv->loop, &c->tcp);
    c->tcp.data = c;
    if (uv_accept(l, (uv_stream_t *)&c->tcp) != 0 || srv->active_conns >= MAX_CONNECTIONS) {
        c->closing = true;
        srv->active_conns++;
        uv_close((uv_handle_t *)&c->tcp, on_conn_closed);
        return;
    }
    srv->active_conns++;
    uv_tcp_nodelay(&c->tcp, 1);
    pthread_mutex_lock(&srv->tlsmu);
    ssl_ctx = srv->tls;
    c->ssl = ssl_ctx != NULL ? SSL_new(ssl_ctx) : NULL; /* the new SSL holds a reference: a swap cannot free the context under it */
    pthread_mutex_unlock(&srv->tlsmu);
    if (ssl_ctx != NULL) {
        c->rbio = BIO_new(BIO_s_mem());
        c->wbio = BIO_new(BIO_s_mem());
        if (c->ssl == NULL || c->rbio == NULL || c->wbio == NULL) {
            BIO_free(c->rbio);
            BIO_free(c->wbio);
            conn_close(c);
            return;
        }
        SSL_set_bio(c->ssl, c->rbio, c->wbio); /* SSL owns both */
        SSL_set_accept_state(c->ssl);
    }
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, cb_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cbs, cb_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, cb_data_chunk);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, cb_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, cb_stream_close);
    nghttp2_session_server_new(&c->sess, cbs, c);
    nghttp2_session_callbacks_del(cbs);
    nghttp2_submit_settings(c->sess, NGHTTP2_FLAG_NONE, iv, 2);
    uv_read_start((uv_stream_t *)&c->tcp, alloc_cb, read_cb);
    if (c->ssl == NULL)
        conn_flush(c); /* send our SETTINGS right away on cleartext connections */
}

/* ---- loop thread ---- */

static void walk_close(uv_handle_t *h, void *arg)
{
    struct g5c_server *srv = arg;
    if (uv_is_closing(h) || h == (uv_handle_t *)&srv->done_async)
        return;
    if (h->type == UV_TCP && h != (uv_handle_t *)&srv->listener) {
        conn_close(h->data);
    } else {
        uv_close(h, NULL);
    }
}

static void on_stop(uv_async_t *a)
{
    struct g5c_server *srv = a->data;
    srv->stopping = true;
    uv_walk(&srv->loop, walk_close, srv);
    maybe_close_done(srv);
}

static void *loop_thread(void *arg)
{
    struct g5c_server *srv = arg;
    uv_run(&srv->loop, UV_RUN_DEFAULT);
    return NULL;
}

g5c_server *g5c_server_start(const g5c_server_cfg *cfg, const g5c_router *router, char *err, size_t errcap)
{
    struct g5c_server *srv = g5c_xcalloc(1, sizeof *srv);
    struct sockaddr_storage addr;
    int rc;
    char buf[64];

    signal(SIGPIPE, SIG_IGN);
    srv->router = router;
    srv->tls = cfg->tls;
    pthread_mutex_init(&srv->tlsmu, NULL);
    if (uv_ip4_addr(cfg->address, cfg->port, (struct sockaddr_in *)&addr) != 0 &&
        uv_ip6_addr(cfg->address, cfg->port, (struct sockaddr_in6 *)&addr) != 0) {
        if (err && errcap)
            snprintf(err, errcap, "bad listen address %s", cfg->address);
        free(srv);
        return NULL;
    }
    uv_loop_init(&srv->loop);
    uv_tcp_init(&srv->loop, &srv->listener);
    srv->listener.data = srv;
    rc = uv_tcp_bind(&srv->listener, (const struct sockaddr *)&addr, 0);
    if (rc == 0)
        rc = uv_listen((uv_stream_t *)&srv->listener, 1024, on_connection);
    if (rc != 0) {
        if (err && errcap)
            snprintf(err, errcap, "cannot listen on %s:%u: %s", cfg->address, cfg->port, uv_strerror(rc));
        uv_close((uv_handle_t *)&srv->listener, NULL);
        uv_run(&srv->loop, UV_RUN_DEFAULT);
        uv_loop_close(&srv->loop);
        free(srv);
        return NULL;
    }
    {
        struct sockaddr_storage bound;
        int len = (int)sizeof bound;
        uv_tcp_getsockname(&srv->listener, (struct sockaddr *)&bound, &len);
        srv->port = ntohs(bound.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&bound)->sin6_port
                                                      : ((struct sockaddr_in *)&bound)->sin_port);
    }
    uv_async_init(&srv->loop, &srv->stop_async, on_stop);
    srv->stop_async.data = srv;
    uv_async_init(&srv->loop, &srv->done_async, done_cb);
    srv->done_async.data = srv;
    pthread_mutex_init(&srv->wmu, NULL);
    pthread_cond_init(&srv->wcv, NULL);
    if (pthread_create(&srv->thread, NULL, loop_thread, srv) != 0) {
        if (err && errcap)
            snprintf(err, errcap, "cannot start server thread");
        uv_close((uv_handle_t *)&srv->listener, NULL);
        uv_close((uv_handle_t *)&srv->stop_async, NULL);
        uv_close((uv_handle_t *)&srv->done_async, NULL);
        uv_run(&srv->loop, UV_RUN_DEFAULT);
        uv_loop_close(&srv->loop);
        pthread_mutex_destroy(&srv->wmu);
        pthread_mutex_destroy(&srv->tlsmu);
        pthread_cond_destroy(&srv->wcv);
        free(srv);
        return NULL;
    }
    srv->started = true;
    {   /* handlers may block on other NFs */
        const char *e = getenv("G5C_SBI_WORKERS");
        long n = e ? strtol(e, NULL, 10) : 32;
        if (n < 1 || n > 512)
            n = 32;
        srv->workers = g5c_xcalloc((size_t)n, sizeof *srv->workers);
        for (long i = 0; i < n; i++)
            if (pthread_create(&srv->workers[srv->nworkers], NULL, worker_main, srv) == 0)
                srv->nworkers++;
        if (srv->nworkers == 0) {
            if (err && errcap)
                snprintf(err, errcap, "cannot start worker threads");
            g5c_server_stop(srv);
            return NULL;
        }
    }
    (void)buf;
    return srv;
}

uint16_t g5c_server_port(const g5c_server *s)
{
    return s->port;
}

SSL_CTX *g5c_server_swap_tls(g5c_server *s, SSL_CTX *fresh)
{
    SSL_CTX *old;
    pthread_mutex_lock(&s->tlsmu);
    old = s->tls;
    s->tls = fresh;
    pthread_mutex_unlock(&s->tlsmu);
    return old;
}

void g5c_server_stop(g5c_server *s)
{
    if (s == NULL)
        return;
    if (s->started) {
        uv_async_send(&s->stop_async);
        pthread_join(s->thread, NULL); /* returns once connections are closed and all in-flight handlers have finished */
        pthread_mutex_lock(&s->wmu);
        s->quit = true;
        pthread_cond_broadcast(&s->wcv);
        pthread_mutex_unlock(&s->wmu);
        for (size_t i = 0; i < s->nworkers; i++)
            pthread_join(s->workers[i], NULL);
        free(s->workers);
        pthread_mutex_destroy(&s->wmu);
        pthread_mutex_destroy(&s->tlsmu);
        pthread_cond_destroy(&s->wcv);
    }
    uv_loop_close(&s->loop);
    free(s);
}
