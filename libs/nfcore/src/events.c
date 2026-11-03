/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _GNU_SOURCE
#include "g5c/events.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include "g5c/base.h"
#include "g5c/json.h"
#include "g5c/sbi.h"

#define QCAP 2048
#define TEXT_MAX 2000
#define ATTEMPTS 5

typedef struct {
    int sev; /* syslog severity */
    const char *msgid;
    char *json;
} ev_t;

struct g5c_events {
    const g5c_events_cfg *cfg;
    char *nf, *instance, host[128];
    pthread_mutex_t mu;
    pthread_cond_t cv, idle, nap; /* nap: the retry back-off, woken only by stop (new events must not cut it short) */
    ev_t q[QCAP];
    size_t head, n;
    bool stop, busy;
    int64_t deadline_ms; /* set by stop: no waiting for a collector after it */
    pthread_t th;
    int fd; /* syslog socket, -1 when closed */
    SSL_CTX *sctx;
    SSL *ssl;
    g5c_client *http;
    g5c_counter *sent_syslog, *sent_http, *drop_queue, *drop_send;
    g5c_gauge *depth;
};

/* ---- the tap: a log line becomes an event ---- */

static const char *event_type(const char *target)
{
    static const char *const comms[] = {"g5c_nrf", "g5c_sbi", "g5c_tls", "g5c_scp", "g5c_client", "g5c_pfcp", "g5c_n4", "g5c_ngap", "g5c_sctp"};
    for (size_t i = 0; i < sizeof comms / sizeof *comms; i++)
        if (strncmp(target, comms[i], strlen(comms[i])) == 0)
            return "communicationsAlarm"; /* ITU-T X.733 event types */
    return "processingErrorAlarm";
}

static void push(g5c_events *e, int sev, const char *msgid, char *json)
{
    pthread_mutex_lock(&e->mu);
    if (e->n == QCAP) { /* the oldest goes: a flood must not hide the newest */
        free(e->q[e->head].json);
        e->head = (e->head + 1) % QCAP;
        e->n--;
        g5c_counter_inc(e->drop_queue);
    }
    e->q[(e->head + e->n++) % QCAP] = (ev_t){sev, msgid, json};
    g5c_gauge_set(e->depth, (int64_t)e->n);
    pthread_cond_signal(&e->cv);
    pthread_mutex_unlock(&e->mu);
}

static void tap(void *user, g5c_log_level l, const char *target, const char *ts, const char *msg)
{
    g5c_events *e = user;
    bool audit = strcmp(target, "g5c_audit") == 0;
    g5c_json *o = g5c_json_new_obj(), *al;
    char text[TEXT_MAX + 1], *s;
    snprintf(text, sizeof text, "%s", msg);
    g5c_json_set_str(o, "time", ts);
    g5c_json_set_str(o, "function", e->nf);
    g5c_json_set_str(o, "instance", e->instance);
    g5c_json_set_str(o, "host", e->host);
    g5c_json_set_str(o, "kind", audit ? "audit" : "alarm");
    g5c_json_set_str(o, "source", target);
    g5c_json_set_str(o, "text", text);
    if (!audit) { /* the X.733 alarm fields */
        al = g5c_json_set(o, "alarm", g5c_json_new_obj());
        g5c_json_set_str(al, "perceivedSeverity", l == G5C_LOG_ERROR ? "major" : "minor");
        g5c_json_set_str(al, "eventType", event_type(target));
        g5c_json_set_str(al, "probableCause", target);
        g5c_json_set_str(al, "specificProblem", text);
    }
    s = g5c_json_to_string(o, NULL);
    g5c_json_free(o);
    if (s != NULL)
        push(e, audit ? 5 : l == G5C_LOG_ERROR ? 3 : 4, audit ? "AUDIT" : "ALARM", s);
}

/* ---- syslog ---- */

static int64_t now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void sys_close(g5c_events *e)
{
    if (e->ssl != NULL) {
        SSL_shutdown(e->ssl);
        SSL_free(e->ssl);
        e->ssl = NULL;
    }
    if (e->fd >= 0)
        close(e->fd);
    e->fd = -1;
}

static int dial(const char *host, uint16_t port, int type)
{
    struct addrinfo hints = {.ai_socktype = type}, *res, *a;
    char ps[8];
    int fd = -1;
    snprintf(ps, sizeof ps, "%u", port);
    if (getaddrinfo(host, ps, &hints, &res) != 0)
        return -1;
    for (a = res; a != NULL && fd < 0; a = a->ai_next) {
        int s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        struct timeval tv = {3, 0};
        if (s < 0)
            continue;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        if (connect(s, a->ai_addr, a->ai_addrlen) == 0)
            fd = s;
        else
            close(s);
    }
    freeaddrinfo(res);
    return fd;
}

static int sys_open(g5c_events *e)
{
    const g5c_events_cfg *c = e->cfg;
    bool udp = strcmp(c->syslog_proto, "udp") == 0;
    e->fd = dial(c->syslog_host, c->syslog_port, udp ? SOCK_DGRAM : SOCK_STREAM);
    if (e->fd < 0)
        return -1;
    if (strcmp(c->syslog_proto, "tls") == 0) {
        unsigned char ip[16];
        X509_VERIFY_PARAM *vp;
        e->ssl = SSL_new(e->sctx);
        SSL_set_fd(e->ssl, e->fd);
        SSL_set_verify(e->ssl, SSL_VERIFY_PEER, NULL);
        vp = SSL_get0_param(e->ssl);
        if (inet_pton(AF_INET, c->syslog_host, ip) == 1 || inet_pton(AF_INET6, c->syslog_host, ip) == 1) {
            X509_VERIFY_PARAM_set1_ip_asc(vp, c->syslog_host);
        } else {
            SSL_set_tlsext_host_name(e->ssl, c->syslog_host);
            X509_VERIFY_PARAM_set1_host(vp, c->syslog_host, 0);
        }
        if (SSL_connect(e->ssl) != 1) {
            sys_close(e);
            return -1;
        }
    }
    return 0;
}

static int write_all(g5c_events *e, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w;
        if (e->ssl != NULL) {
            int r = SSL_write(e->ssl, p, (int)n);
            if (r <= 0)
                return -1;
            w = r;
        } else {
            w = send(e->fd, p, n, MSG_NOSIGNAL);
            if (w < 0 && errno == EINTR)
                continue;
            if (w <= 0)
                return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/* RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG; over a stream, RFC 6587 / 5425 octet counting */
static int sys_send(g5c_events *e, const ev_t *v)
{
    const g5c_events_cfg *c = e->cfg;
    char ts[48], *line, *frame;
    time_t now = time(NULL);
    struct tm tm;
    int rc;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tm);
    line = g5c_xasprintf("<%d>1 %s %s %s %d %s - %s", c->syslog_facility * 8 + v->sev, ts, e->host, e->nf, (int)getpid(), v->msgid, v->json);
    if (e->fd < 0 && sys_open(e) != 0) {
        free(line);
        return -1;
    }
    if (strcmp(c->syslog_proto, "udp") == 0) {
        rc = send(e->fd, line, strlen(line), MSG_NOSIGNAL) < 0 ? -1 : 0;
    } else {
        frame = g5c_xasprintf("%zu %s", strlen(line), line);
        rc = write_all(e, frame, strlen(frame));
        free(frame);
    }
    free(line);
    if (rc != 0)
        sys_close(e); /* the next attempt dials again */
    return rc;
}

/* ---- http ---- */

static int http_send(g5c_events *e, const ev_t *b, size_t n)
{
    g5c_bytes body;
    g5c_resp r;
    char err[160];
    int rc;
    g5c_bytes_init(&body);
    g5c_bytes_append_str(&body, "[");
    for (size_t i = 0; i < n; i++) {
        if (i > 0)
            g5c_bytes_append_str(&body, ",");
        g5c_bytes_append_str(&body, b[i].json);
    }
    g5c_bytes_append_str(&body, "]");
    rc = g5c_client_request(e->http, "POST", e->cfg->http_uri, NULL, 0, "application/json", body.data, body.len, &r, err, sizeof err);
    g5c_bytes_free(&body);
    if (rc != 0)
        return -1;
    rc = r.status >= 200 && r.status < 300 ? 0 : -1;
    g5c_resp_free(&r);
    return rc;
}

/* ---- the worker ---- */

static bool wait_ms(g5c_events *e, int ms)
{
    struct timespec t;
    bool stop;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += ms / 1000;
    t.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (t.tv_nsec >= 1000000000L) {
        t.tv_sec++;
        t.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&e->mu);
    if (!e->stop)
        pthread_cond_timedwait(&e->nap, &e->mu, &t);
    stop = e->stop;
    pthread_mutex_unlock(&e->mu);
    if (stop)
        usleep(100000); /* shutting down: retry quickly until the deadline */
    return !stop;
}

static void deliver(g5c_events *e, ev_t *b, size_t n)
{
    size_t sys_done = e->cfg->syslog_host != NULL ? 0 : n;
    bool http_done = e->cfg->http_uri == NULL;
    for (int attempt = 0; attempt < ATTEMPTS; attempt++) {
        while (sys_done < n && sys_send(e, &b[sys_done]) == 0) {
            sys_done++;
            g5c_counter_inc(e->sent_syslog);
        }
        if (!http_done && http_send(e, b, n) == 0) {
            http_done = true;
            g5c_counter_add(e->sent_http, n);
        }
        if (sys_done == n && http_done)
            break;
        pthread_mutex_lock(&e->mu);
        if (e->stop && now_ms() >= e->deadline_ms) {
            pthread_mutex_unlock(&e->mu);
            break;
        }
        pthread_mutex_unlock(&e->mu);
        if (attempt + 1 < ATTEMPTS)
            wait_ms(e, 1000);
    }
    if (sys_done < n)
        g5c_counter_add(e->drop_send, n - sys_done);
    if (!http_done)
        g5c_counter_add(e->drop_send, n);
}

static void *worker(void *arg)
{
    g5c_events *e = arg;
    size_t cap = e->cfg->http_uri != NULL ? e->cfg->http_batch : 50;
    ev_t *b = g5c_xcalloc(cap, sizeof *b);
    for (;;) {
        size_t n = 0;
        pthread_mutex_lock(&e->mu);
        while (!e->stop && e->n == 0)
            pthread_cond_wait(&e->cv, &e->mu);
        if (e->n == 0 || (e->stop && now_ms() >= e->deadline_ms)) {
            pthread_mutex_unlock(&e->mu);
            break;
        }
        while (e->n > 0 && n < cap) {
            b[n++] = e->q[e->head];
            e->head = (e->head + 1) % QCAP;
            e->n--;
        }
        g5c_gauge_set(e->depth, (int64_t)e->n);
        e->busy = true;
        pthread_mutex_unlock(&e->mu);
        deliver(e, b, n);
        for (size_t i = 0; i < n; i++)
            free(b[i].json);
        pthread_mutex_lock(&e->mu);
        e->busy = false;
        if (e->n == 0)
            pthread_cond_broadcast(&e->idle);
        pthread_mutex_unlock(&e->mu);
    }
    free(b);
    return NULL;
}

/* ---- lifecycle ---- */

g5c_events *g5c_events_start(const g5c_events_cfg *cfg, const char *nf_name, const char *instance_id, g5c_registry *metrics, char *err, size_t errcap)
{
    g5c_events *e = g5c_xcalloc(1, sizeof *e);
    g5c_label ls[1];
    e->cfg = cfg;
    e->nf = g5c_xstrdup(nf_name);
    e->instance = g5c_xstrdup(instance_id);
    e->fd = -1;
    if (gethostname(e->host, sizeof e->host - 1) != 0 || e->host[0] == '\0')
        snprintf(e->host, sizeof e->host, "-");
    pthread_mutex_init(&e->mu, NULL);
    pthread_cond_init(&e->cv, NULL);
    pthread_cond_init(&e->idle, NULL);
    pthread_cond_init(&e->nap, NULL);
    if (cfg->syslog_host != NULL && strcmp(cfg->syslog_proto, "tls") == 0) {
        e->sctx = g5c_tls_client_ctx(cfg->syslog_ca, NULL, NULL, err, errcap);
        if (e->sctx == NULL)
            goto bad;
    }
    if (cfg->http_uri != NULL) {
        SSL_CTX *tls = NULL;
        if (cfg->http_ca != NULL && (tls = g5c_tls_client_ctx(cfg->http_ca, NULL, NULL, err, errcap)) == NULL)
            goto bad;
        e->http = g5c_client_new(5000, tls);
    }
    ls[0] = (g5c_label){"sink", "syslog"};
    e->sent_syslog = g5c_counter_get(metrics, "g5c_events_sent_total", "Events delivered, by sink.", ls, 1);
    ls[0] = (g5c_label){"sink", "http"};
    e->sent_http = g5c_counter_get(metrics, "g5c_events_sent_total", "Events delivered, by sink.", ls, 1);
    ls[0] = (g5c_label){"reason", "queue"};
    e->drop_queue = g5c_counter_get(metrics, "g5c_events_dropped_total", "Events lost, by reason.", ls, 1);
    ls[0] = (g5c_label){"reason", "send"};
    e->drop_send = g5c_counter_get(metrics, "g5c_events_dropped_total", "Events lost, by reason.", ls, 1);
    e->depth = g5c_gauge_get(metrics, "g5c_events_queue_depth", "Events waiting for delivery.", NULL, 0);
    if (g5c_log_set_tap(tap, e, cfg->min_level == 0 ? G5C_LOG_ERROR : G5C_LOG_WARN, true) != 0) {
        if (err != NULL && errcap > 0)
            snprintf(err, errcap, "this process already streams events");
        goto bad;
    }
    if (pthread_create(&e->th, NULL, worker, e) != 0) {
        (void)g5c_log_set_tap(NULL, NULL, G5C_LOG_ERROR, false);
        if (err != NULL && errcap > 0)
            snprintf(err, errcap, "cannot start the event worker");
        goto bad;
    }
    return e;
bad:
    if (e->sctx != NULL)
        SSL_CTX_free(e->sctx);
    g5c_client_free(e->http);
    free(e->nf);
    free(e->instance);
    free(e);
    return NULL;
}

bool g5c_events_flush(g5c_events *e, int timeout_ms)
{
    struct timespec t;
    bool ok = true;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += timeout_ms / 1000;
    t.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (t.tv_nsec >= 1000000000L) {
        t.tv_sec++;
        t.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&e->mu);
    while ((e->n > 0 || e->busy) && ok)
        ok = pthread_cond_timedwait(&e->idle, &e->mu, &t) == 0;
    ok = e->n == 0 && !e->busy;
    pthread_mutex_unlock(&e->mu);
    return ok;
}

void g5c_events_stop(g5c_events *e)
{
    if (e == NULL)
        return;
    (void)g5c_log_set_tap(NULL, NULL, G5C_LOG_ERROR, false); /* from here no thread is in the tap */
    pthread_mutex_lock(&e->mu);
    e->stop = true;
    e->deadline_ms = now_ms() + 2000;
    pthread_cond_broadcast(&e->cv);
    pthread_cond_broadcast(&e->nap);
    pthread_mutex_unlock(&e->mu);
    pthread_join(e->th, NULL);
    for (size_t i = 0; i < e->n; i++)
        free(e->q[(e->head + i) % QCAP].json);
    sys_close(e);
    if (e->sctx != NULL)
        SSL_CTX_free(e->sctx);
    g5c_client_free(e->http);
    pthread_mutex_destroy(&e->mu);
    pthread_cond_destroy(&e->cv);
    pthread_cond_destroy(&e->idle);
    pthread_cond_destroy(&e->nap);
    free(e->nf);
    free(e->instance);
    free(e);
}
