/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Alarm and audit streaming: syslog over UDP, TCP and TLS (framing, priority, the X.733 fields), the HTTP collector (batches), a collector that comes up late,
 * audit lines below the log level, one tap per process, and the validation of the `events` section. */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "../../sbi/tests/certgen.h"
#include "g5c/events.h"
#include "g5c/nfcore.h"
#include "g5c/testkit.h"

#define MAXF 32

typedef struct {
    int fd;
    uint16_t port;
    bool udp;
    SSL_CTX *tls;
    atomic_bool stop;
    pthread_t th;
    pthread_mutex_t mu;
    char *frames[MAXF];
    int n;
} sink_t;

static void sink_add(sink_t *s, const char *p, size_t len)
{
    pthread_mutex_lock(&s->mu);
    if (s->n < MAXF)
        s->frames[s->n++] = strndup(p, len);
    pthread_mutex_unlock(&s->mu);
}

static int sink_count(sink_t *s)
{
    int n;
    pthread_mutex_lock(&s->mu);
    n = s->n;
    pthread_mutex_unlock(&s->mu);
    return n;
}

static bool sink_wait(sink_t *s, int want, int ms)
{
    for (int i = 0; i < ms / 20 && sink_count(s) < want; i++)
        usleep(20000);
    return sink_count(s) >= want;
}

/* octet counting (RFC 6587 / 5425): "<len> <message>" */
static void sink_frames(sink_t *s, char *buf, size_t *len)
{
    for (;;) {
        char *sp = memchr(buf, ' ', *len), *end;
        size_t n;
        if (sp == NULL)
            return;
        n = strtoul(buf, &end, 10);
        if (end != sp || n == 0 || n > 8000)
            return;
        if (*len < (size_t)(sp - buf) + 1 + n)
            return;
        sink_add(s, sp + 1, n);
        memmove(buf, sp + 1 + n, *len - (size_t)(sp - buf) - 1 - n);
        *len -= (size_t)(sp - buf) + 1 + n;
    }
}

static void *sink_run(void *arg)
{
    sink_t *s = arg;
    char buf[16384];
    while (!atomic_load(&s->stop)) {
        struct pollfd p = {s->fd, POLLIN, 0};
        if (poll(&p, 1, 50) <= 0)
            continue;
        if (s->udp) {
            ssize_t n = recv(s->fd, buf, sizeof buf, 0);
            if (n > 0)
                sink_add(s, buf, (size_t)n);
        } else {
            int c = accept(s->fd, NULL, NULL);
            size_t have = 0;
            SSL *ssl = NULL;
            if (c < 0)
                continue;
            if (s->tls != NULL) {
                ssl = SSL_new(s->tls);
                SSL_set_fd(ssl, c);
                if (SSL_accept(ssl) != 1) {
                    SSL_free(ssl);
                    close(c);
                    continue;
                }
            }
            while (!atomic_load(&s->stop)) {
                struct pollfd q = {c, POLLIN, 0};
                ssize_t n;
                if (poll(&q, 1, 50) <= 0)
                    continue;
                n = ssl != NULL ? SSL_read(ssl, buf + have, (int)(sizeof buf - have)) : recv(c, buf + have, sizeof buf - have, 0);
                if (n <= 0)
                    break;
                have += (size_t)n;
                sink_frames(s, buf, &have);
            }
            if (ssl != NULL)
                SSL_free(ssl);
            close(c);
        }
    }
    return NULL;
}

static sink_t *sink_start(bool udp, SSL_CTX *tls, uint16_t port)
{
    sink_t *s = calloc(1, sizeof *s);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    socklen_t al = sizeof a;
    int one = 1;
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    s->udp = udp;
    s->tls = tls;
    s->fd = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    TK_ASSERT(bind(s->fd, (struct sockaddr *)&a, sizeof a) == 0);
    if (!udp)
        TK_ASSERT(listen(s->fd, 4) == 0);
    getsockname(s->fd, (struct sockaddr *)&a, &al);
    s->port = ntohs(a.sin_port);
    pthread_mutex_init(&s->mu, NULL);
    pthread_create(&s->th, NULL, sink_run, s);
    return s;
}

static void sink_stop(sink_t *s)
{
    atomic_store(&s->stop, true);
    pthread_join(s->th, NULL);
    close(s->fd);
    for (int i = 0; i < s->n; i++)
        free(s->frames[i]);
    free(s);
}

static uint16_t free_port(void)
{
    sink_t *s = sink_start(false, NULL, 0);
    uint16_t p = s->port;
    sink_stop(s);
    return p;
}

static g5c_events_cfg syslog_cfg(char *proto, uint16_t port, char *ca)
{
    g5c_events_cfg c = {0};
    c.enabled = true;
    c.min_level = 1;
    c.syslog_host = (char *)"127.0.0.1";
    c.syslog_port = port;
    c.syslog_proto = proto;
    c.syslog_ca = ca;
    c.syslog_facility = 20; /* local4 */
    return c;
}

static void emit_three(void)
{
    G5C_LOGI("g5c_amf", "plain information stays in the log");
    G5C_LOGW("g5c_nrf", "NRF unreachable, retrying");
    G5C_LOGE("g5c_amf", "state file cannot be written");
    G5C_LOGI("g5c_audit", "udm admin: subscriber.delete supi=imsi-001010000000001");
}

static void check_frames(sink_t *s, bool stream)
{
    g5c_json *j;
    char err[100];
    const char *p;
    TK_ASSERT(sink_wait(s, 3, 4000));
    TK_ASSERT(sink_count(s) == 3); /* the INFO line is not an event */
    TK_ASSERT(strncmp(s->frames[0], "<164>1 ", 7) == 0); /* local4 (20) * 8 + warning (4) */
    TK_ASSERT(strncmp(s->frames[1], "<163>1 ", 7) == 0); /* error (3) */
    TK_ASSERT(strncmp(s->frames[2], "<165>1 ", 7) == 0); /* notice (5): audit */
    TK_ASSERT(strstr(s->frames[0], " ALARM - {") != NULL && strstr(s->frames[2], " AUDIT - {") != NULL);
    p = strstr(s->frames[0], "- {") + 2;
    j = g5c_json_parse(p, strlen(p), err, sizeof err);
    TK_ASSERT(j != NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(j, "kind"), "alarm") == 0 && strcmp(g5c_json_get_str(j, "function"), "amf-test") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(j, "alarm"), "perceivedSeverity"), "minor") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(j, "alarm"), "eventType"), "communicationsAlarm") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(j, "alarm"), "probableCause"), "g5c_nrf") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(j, "text"), "NRF unreachable, retrying") == 0);
    g5c_json_free(j);
    p = strstr(s->frames[1], "- {") + 2;
    j = g5c_json_parse(p, strlen(p), err, sizeof err);
    TK_ASSERT(j != NULL && strcmp(g5c_json_get_str(g5c_json_get(j, "alarm"), "perceivedSeverity"), "major") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(j, "alarm"), "eventType"), "processingErrorAlarm") == 0);
    g5c_json_free(j);
    p = strstr(s->frames[2], "- {") + 2;
    j = g5c_json_parse(p, strlen(p), err, sizeof err);
    TK_ASSERT(j != NULL && strcmp(g5c_json_get_str(j, "kind"), "audit") == 0 && g5c_json_get(j, "alarm") == NULL);
    TK_ASSERT(strstr(g5c_json_get_str(j, "text"), "subscriber.delete") != NULL);
    g5c_json_free(j);
    (void)stream;
}

static void run_syslog(char *proto, SSL_CTX *tls, char *ca)
{
    sink_t *s = sink_start(strcmp(proto, "udp") == 0, tls, 0);
    g5c_events_cfg c = syslog_cfg(proto, s->port, ca);
    g5c_registry *reg = g5c_registry_new();
    char err[200];
    g5c_events *e = g5c_events_start(&c, "amf-test", "11111111-2222-3333-4444-555555555555", reg, err, sizeof err);
    g5c_label ls[1] = {{"sink", "syslog"}};
    TK_ASSERT(e != NULL);
    emit_three();
    TK_ASSERT(g5c_events_flush(e, 4000));
    check_frames(s, strcmp(proto, "udp") != 0);
    TK_ASSERT(g5c_counter_value(g5c_counter_get(reg, "g5c_events_sent_total", "x", ls, 1)) == 3);
    g5c_events_stop(e);
    g5c_registry_free(reg);
    sink_stop(s);
}

static char *write_tmp(const char *pem)
{
    char tmpl[] = "/tmp/g5c-ev-XXXXXX", *path;
    int fd = mkstemp(tmpl);
    TK_ASSERT(fd >= 0 && write(fd, pem, strlen(pem)) == (ssize_t)strlen(pem));
    close(fd);
    path = strdup(tmpl);
    return path;
}

static void test_tls(void)
{
    cg_id ca = cg_make("test-ca", NULL, true, NULL, 1), leaf = cg_make("siem", &ca, false, "IP:127.0.0.1", 2), other = cg_make("other-ca", NULL, true, NULL, 3);
    char err[200], *ca_path = write_tmp(ca.cert_pem), *other_path = write_tmp(other.cert_pem);
    SSL_CTX *srv = g5c_tls_server_ctx_pem(leaf.cert_pem, leaf.key_pem, NULL, err, sizeof err);
    sink_t *s;
    g5c_events_cfg c;
    g5c_registry *reg = g5c_registry_new();
    g5c_events *e;
    TK_ASSERT(srv != NULL);
    run_syslog("tls", srv, ca_path);
    /* a collector whose certificate our CA did not sign receives nothing */
    s = sink_start(false, srv, 0);
    c = syslog_cfg("tls", s->port, other_path);
    e = g5c_events_start(&c, "amf-test", "11111111-2222-3333-4444-555555555555", reg, err, sizeof err);
    TK_ASSERT(e != NULL);
    G5C_LOGE("g5c_amf", "must not reach an unverified collector");
    usleep(300000);
    TK_ASSERT(sink_count(s) == 0);
    g5c_events_stop(e); /* gives up after its two seconds */
    sink_stop(s);
    g5c_registry_free(reg);
    SSL_CTX_free(srv);
    unlink(ca_path);
    unlink(other_path);
    free(ca_path);
    free(other_path);
    cg_free(&ca);
    cg_free(&leaf);
    cg_free(&other);
}

/* ---- HTTP ---- */

typedef struct {
    pthread_mutex_t mu;
    int posts, events, biggest;
    bool ok;
} http_t;

static void h_events(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    http_t *h = ctx;
    char err[100];
    g5c_json *j = g5c_json_parse((const char *)req->body, req->body_len, err, sizeof err);
    pthread_mutex_lock(&h->mu);
    h->posts++;
    if (j != NULL && g5c_json_is(j, G5C_J_ARRAY)) {
        int n = (int)g5c_json_len(j);
        h->events += n;
        if (n > h->biggest)
            h->biggest = n;
        for (int i = 0; i < n; i++)
            if (g5c_json_get_str(g5c_json_at(j, (size_t)i), "text") == NULL)
                h->ok = false;
    } else {
        h->ok = false;
    }
    pthread_mutex_unlock(&h->mu);
    g5c_json_free(j);
    g5c_resp_status(resp, 202);
}

static void test_http(void)
{
    http_t h = {.mu = PTHREAD_MUTEX_INITIALIZER, .ok = true};
    g5c_router *r = g5c_router_new();
    g5c_server_cfg sc = {.address = "127.0.0.1", .port = 0, .tls = NULL};
    g5c_server *srv;
    g5c_events_cfg c = {0};
    g5c_registry *reg = g5c_registry_new();
    g5c_events *e;
    char err[200], uri[80];
    g5c_router_route(r, "POST", "/events", h_events, &h);
    srv = g5c_server_start(&sc, r, err, sizeof err);
    TK_ASSERT(srv != NULL);
    snprintf(uri, sizeof uri, "http://127.0.0.1:%u/events", g5c_server_port(srv));
    c.enabled = true;
    c.min_level = 1;
    c.http_uri = uri;
    c.http_batch = 2;
    e = g5c_events_start(&c, "smf-test", "11111111-2222-3333-4444-555555555555", reg, err, sizeof err);
    TK_ASSERT(e != NULL);
    for (int i = 0; i < 5; i++)
        G5C_LOGW("g5c_smf", "warning number %d", i);
    TK_ASSERT(g5c_events_flush(e, 4000));
    pthread_mutex_lock(&h.mu);
    TK_ASSERT(h.events == 5 && h.biggest <= 2 && h.posts >= 3 && h.ok);
    pthread_mutex_unlock(&h.mu);
    g5c_events_stop(e);
    g5c_server_stop(srv);
    g5c_router_free(r);
    g5c_registry_free(reg);
}

/* ---- delivery under failure ---- */

static void test_collector_comes_up_late(void)
{
    uint16_t port = free_port();
    g5c_events_cfg c = syslog_cfg("tcp", port, NULL);
    g5c_registry *reg = g5c_registry_new();
    char err[200];
    g5c_events *e = g5c_events_start(&c, "upf-test", "11111111-2222-3333-4444-555555555555", reg, err, sizeof err);
    sink_t *s;
    TK_ASSERT(e != NULL);
    G5C_LOGE("g5c_upf", "first alarm while nobody listens");
    usleep(1500000);
    s = sink_start(false, NULL, port);
    TK_ASSERT(sink_wait(s, 1, 6000)); /* retried until the collector was there */
    TK_ASSERT(strstr(s->frames[0], "first alarm while nobody listens") != NULL);
    g5c_events_stop(e);
    sink_stop(s);
    g5c_registry_free(reg);
}

static void test_collector_never_comes(void)
{
    g5c_events_cfg c = syslog_cfg("tcp", free_port(), NULL);
    g5c_registry *reg = g5c_registry_new();
    char err[200];
    g5c_events *e = g5c_events_start(&c, "upf-test", "11111111-2222-3333-4444-555555555555", reg, err, sizeof err);
    g5c_label ld[1] = {{"reason", "send"}};
    TK_ASSERT(e != NULL);
    for (int i = 0; i < 3; i++)
        G5C_LOGE("g5c_upf", "lost alarm %d", i);
    g5c_events_stop(e); /* returns within its deadline, the events are counted as lost */
    TK_ASSERT(g5c_counter_value(g5c_counter_get(reg, "g5c_events_dropped_total", "x", ld, 1)) >= 1);
    g5c_registry_free(reg);
}

static void test_audit_below_level_and_single_tap(void)
{
    sink_t *s = sink_start(true, NULL, 0);
    g5c_events_cfg c = syslog_cfg("udp", s->port, NULL), c2 = syslog_cfg("udp", s->port, NULL);
    g5c_registry *reg = g5c_registry_new();
    char err[200];
    g5c_events *e, *second;
    g5c_log_init("error", false);
    e = g5c_events_start(&c, "udm-test", "11111111-2222-3333-4444-555555555555", reg, err, sizeof err);
    TK_ASSERT(e != NULL);
    second = g5c_events_start(&c2, "udm-test", "11111111-2222-3333-4444-555555555555", reg, err, sizeof err);
    TK_ASSERT(second == NULL && strstr(err, "already") != NULL);
    G5C_LOGI("g5c_audit", "udm admin: subscriber.create supi=imsi-001010000000002"); /* below the configured level, still an event */
    G5C_LOGW("g5c_amf", "a warning below the configured level goes out too");
    TK_ASSERT(g5c_events_flush(e, 3000));
    TK_ASSERT(sink_wait(s, 2, 3000));
    g5c_events_stop(e);
    /* after stop nothing more is sent, and a new run can start */
    G5C_LOGE("g5c_amf", "after the stop");
    usleep(200000);
    TK_ASSERT(sink_count(s) == 2);
    e = g5c_events_start(&c, "udm-test", "11111111-2222-3333-4444-555555555555", reg, err, sizeof err);
    TK_ASSERT(e != NULL);
    g5c_events_stop(e);
    g5c_log_init("info", false);
    g5c_registry_free(reg);
    sink_stop(s);
}

static void test_queue_overflow_drops_oldest(void)
{
    g5c_events_cfg c = syslog_cfg("tcp", free_port(), NULL);
    g5c_registry *reg = g5c_registry_new();
    char err[200];
    g5c_events *e = g5c_events_start(&c, "upf-test", "11111111-2222-3333-4444-555555555555", reg, err, sizeof err);
    g5c_label ld[1] = {{"reason", "queue"}};
    TK_ASSERT(e != NULL);
    for (int i = 0; i < 6000; i++)
        G5C_LOGE("g5c_upf", "storm %d", i);
    TK_ASSERT(g5c_counter_value(g5c_counter_get(reg, "g5c_events_dropped_total", "x", ld, 1)) > 0);
    g5c_events_stop(e);
    g5c_registry_free(reg);
}

/* ---- configuration ---- */

static int parse_events(const char *events, char *err, size_t errcap, g5c_common *out)
{
    char yaml[1024];
    g5c_json *j;
    int rc;
    snprintf(yaml, sizeof yaml, "name: x\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 7777 }\n%s\n", events);
    j = g5c_yaml_parse(yaml, strlen(yaml), err, errcap);
    TK_ASSERT(j != NULL);
    rc = g5c_common_parse(j, out, err, errcap);
    g5c_json_free(j);
    return rc;
}

static void test_config(void)
{
    g5c_common c;
    char err[200];
    TK_ASSERT(parse_events("events:\n  syslog: { host: siem.example, proto: tls, ca: /etc/ca.crt, facility: local4 }\n  http: { uri: 'http://c:8080/e', batch: 10 }\n  min_level: error", err, sizeof err, &c) == 0);
    TK_ASSERT(c.events.enabled && c.events.min_level == 0 && c.events.syslog_port == 6514 && c.events.syslog_facility == 20 && c.events.http_batch == 10);
    g5c_common_free(&c);
    TK_ASSERT(parse_events("events:\n  syslog: { host: h }", err, sizeof err, &c) == 0);
    TK_ASSERT(c.events.syslog_port == 514 && strcmp(c.events.syslog_proto, "udp") == 0 && c.events.min_level == 1 && c.events.syslog_facility == 16);
    g5c_common_free(&c);
    TK_ASSERT(parse_events("log: { level: info }", err, sizeof err, &c) == 0 && !c.events.enabled);
    g5c_common_free(&c);
    {
        static const struct {
            const char *y, *want;
        } bad[] = {
            {"events: {}", "needs a `syslog` or an `http` target"},
            {"events: 5", "must be a mapping"},
            {"events:\n  surprise: 1", "events"},
            {"events:\n  syslog: { host: h, proto: sctp }", "udp, tcp or tls"},
            {"events:\n  syslog: { host: h, proto: tls }", "needs `events.syslog.ca`"},
            {"events:\n  syslog: { host: h, port: 0 }", "events.syslog.port"},
            {"events:\n  syslog: { host: h, facility: nope }", "facility"},
            {"events:\n  syslog: { host: h, surprise: 1 }", "events.syslog"},
            {"events:\n  http: { uri: 'ftp://c' }", "http or https"},
            {"events:\n  http: { uri: 'https://c/e' }", "needs `events.http.ca`"},
            {"events:\n  http: { uri: 'http://c/e', batch: 0 }", "events.http.batch"},
            {"events:\n  min_level: info\n  http: { uri: 'http://c/e' }", "min_level"},
        };
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
            TK_ASSERT(parse_events(bad[i].y, err, sizeof err, &c) != 0);
            if (strstr(err, bad[i].want) == NULL)
                TK_FAIL("config %zu: `%s` not in `%s`", i, bad[i].want, err);
        }
    }
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    test_config();
    run_syslog("udp", NULL, NULL);
    run_syslog("tcp", NULL, NULL);
    test_tls();
    test_http();
    test_collector_comes_up_late();
    test_collector_never_comes();
    test_audit_below_level_and_single_tap();
    test_queue_overflow_drops_oldest();
    printf("events: PASS\n");
    return 0;
}
