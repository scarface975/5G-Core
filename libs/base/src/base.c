/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _POSIX_C_SOURCE 200809L
#include "g5c/base.h"

#include <ctype.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <openssl/rand.h>

/* ---- allocation ---- */

static void oom(void)
{
    static const char m[] = "g5c: out of memory, aborting\n";
    (void)!fwrite(m, 1, sizeof m - 1, stderr);
    abort();
}

void *g5c_xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (p == NULL)
        oom();
    return p;
}

void *g5c_xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (p == NULL)
        oom();
    return p;
}

void *g5c_xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (q == NULL)
        oom();
    return q;
}

char *g5c_xstrndup(const char *s, size_t n)
{
    char *p = g5c_xmalloc(n + 1);
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

char *g5c_xstrdup(const char *s)
{
    return g5c_xstrndup(s, strlen(s));
}

char *g5c_xvasprintf(const char *fmt, va_list ap)
{
    va_list c;
    int n;
    char *p;
    va_copy(c, ap);
    n = vsnprintf(NULL, 0, fmt, c);
    va_end(c);
    if (n < 0)
        oom();
    p = g5c_xmalloc((size_t)n + 1);
    vsnprintf(p, (size_t)n + 1, fmt, ap);
    return p;
}

char *g5c_xasprintf(const char *fmt, ...)
{
    va_list ap;
    char *p;
    va_start(ap, fmt);
    p = g5c_xvasprintf(fmt, ap);
    va_end(ap);
    return p;
}

/* ---- bytes ---- */

void g5c_bytes_init(g5c_bytes *b)
{
    b->data = NULL;
    b->len = b->cap = 0;
}

void g5c_bytes_free(g5c_bytes *b)
{
    free(b->data);
    g5c_bytes_init(b);
}

void g5c_bytes_clear(g5c_bytes *b)
{
    b->len = 0;
    if (b->data != NULL)
        b->data[0] = 0;
}

static int reserve(g5c_bytes *b, size_t extra)
{
    size_t need, cap;
    uint8_t *p;
    if (extra > SIZE_MAX / 2 - b->len - 1)
        return -1;
    need = b->len + extra + 1;
    if (need <= b->cap)
        return 0;
    cap = b->cap ? b->cap : 64;
    while (cap < need) {
        if (cap > SIZE_MAX / 2)
            return -1;
        cap *= 2;
    }
    p = realloc(b->data, cap);
    if (p == NULL)
        return -1;
    b->data = p;
    b->cap = cap;
    return 0;
}

int g5c_bytes_append(g5c_bytes *b, const void *p, size_t n)
{
    if (reserve(b, n) != 0)
        return -1;
    if (n != 0)
        memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = 0;
    return 0;
}

int g5c_bytes_append_str(g5c_bytes *b, const char *s)
{
    return g5c_bytes_append(b, s, strlen(s));
}

int g5c_bytes_putc(g5c_bytes *b, char c)
{
    return g5c_bytes_append(b, &c, 1);
}

int g5c_bytes_printf(g5c_bytes *b, const char *fmt, ...)
{
    va_list ap, c;
    int n;
    va_start(ap, fmt);
    va_copy(c, ap);
    n = vsnprintf(NULL, 0, fmt, c);
    va_end(c);
    if (n < 0 || reserve(b, (size_t)n) != 0) {
        va_end(ap);
        return -1;
    }
    vsnprintf((char *)b->data + b->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)n;
    return 0;
}

char *g5c_bytes_take(g5c_bytes *b, size_t *len)
{
    char *p;
    if (b->data == NULL) {
        p = g5c_xcalloc(1, 1);
        if (len)
            *len = 0;
        return p;
    }
    p = (char *)b->data;
    if (len)
        *len = b->len;
    g5c_bytes_init(b);
    return p;
}

/* ---- strings ---- */

bool g5c_streq(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
        return a == b;
    return strcmp(a, b) == 0;
}

bool g5c_starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

bool g5c_is_digits(const char *s)
{
    if (*s == '\0')
        return false;
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return false;
    return true;
}

static int hexv(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

char *g5c_percent_decode(const char *s)
{
    size_t n = strlen(s), o = 0;
    char *out = g5c_xmalloc(n + 1);
    for (size_t i = 0; i < n;) {
        if (s[i] == '%' && i + 2 < n && hexv(s[i + 1]) >= 0 && hexv(s[i + 2]) >= 0) {
            out[o++] = (char)(hexv(s[i + 1]) * 16 + hexv(s[i + 2]));
            i += 3;
        } else {
            out[o++] = s[i++];
        }
    }
    out[o] = '\0';
    return out;
}

char *g5c_hex_encode(const uint8_t *p, size_t n)
{
    static const char d[] = "0123456789abcdef";
    char *o = g5c_xmalloc(2 * n + 1);
    for (size_t i = 0; i < n; i++) {
        o[2 * i] = d[p[i] >> 4];
        o[2 * i + 1] = d[p[i] & 15];
    }
    o[2 * n] = '\0';
    return o;
}

long g5c_hex_decode(const char *s, uint8_t *out, size_t cap)
{
    size_t n = strlen(s);
    if (n % 2 != 0 || n / 2 > cap)
        return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int h = hexv(s[2 * i]), l = hexv(s[2 * i + 1]);
        if (h < 0 || l < 0)
            return -1;
        out[i] = (uint8_t)(h * 16 + l);
    }
    return (long)(n / 2);
}

/* ---- identifiers & time ---- */

int g5c_random(void *p, size_t n)
{
    if (n > 0x7fffffffU)
        return -1;
    return RAND_bytes(p, (int)n) == 1 ? 0 : -1;
}

int g5c_uuid_v4(char out[37])
{
    uint8_t b[16];
    static const char d[] = "0123456789abcdef";
    size_t o = 0;
    if (g5c_random(b, sizeof b) != 0)
        return -1;
    b[6] = (uint8_t)((b[6] & 0x0fU) | 0x40U);
    b[8] = (uint8_t)((b[8] & 0x3fU) | 0x80U);
    for (size_t i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            out[o++] = '-';
        out[o++] = d[b[i] >> 4];
        out[o++] = d[b[i] & 15];
    }
    out[o] = '\0';
    return 0;
}

double g5c_now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int64_t g5c_unix_millis(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---- logging ---- */

static pthread_mutex_t log_mu = PTHREAD_MUTEX_INITIALIZER;
static _Atomic int cur_level = G5C_LOG_INFO; /* read without a lock by every log call, written by init and by SIGUSR1 / SIGUSR2 */
static bool log_json = false;
static bool log_ready = false;
static g5c_log_level base_level = G5C_LOG_INFO;

static const char *const level_names[] = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};

static g5c_log_level parse_level(const char *s)
{
    const char *eq = strrchr(s, '=');
    if (eq != NULL)
        s = eq + 1;
    if (strcasecmp(s, "error") == 0)
        return G5C_LOG_ERROR;
    if (strcasecmp(s, "warn") == 0)
        return G5C_LOG_WARN;
    if (strcasecmp(s, "debug") == 0)
        return G5C_LOG_DEBUG;
    if (strcasecmp(s, "trace") == 0)
        return G5C_LOG_TRACE;
    return G5C_LOG_INFO;
}

bool g5c_log_init(const char *level, bool json)
{
    const char *env = getenv("G5C_LOG");
    bool first;
    pthread_mutex_lock(&log_mu);
    first = !log_ready;
    if (first) {
        base_level = parse_level(env != NULL && *env ? env : (level ? level : "info"));
        atomic_store(&cur_level, (int)base_level);
        log_json = json;
        log_ready = true;
    }
    pthread_mutex_unlock(&log_mu);
    return first;
}

void g5c_log_set_level(g5c_log_level l)
{
    pthread_mutex_lock(&log_mu);
    atomic_store(&cur_level, (int)l);
    pthread_mutex_unlock(&log_mu);
}

g5c_log_level g5c_log_baseline(void)
{
    return base_level;
}

bool g5c_log_enabled(g5c_log_level l)
{
    return (int)l <= atomic_load(&cur_level);
}

static void json_escape(g5c_bytes *b, const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            g5c_bytes_putc(b, '\\');
            g5c_bytes_putc(b, (char)c);
        } else if (c < 0x20) {
            g5c_bytes_printf(b, "\\u%04x", c);
        } else {
            g5c_bytes_putc(b, (char)c);
        }
    }
}

/* ---- request tracing ---- */

static _Thread_local g5c_trace_ctx tl_trace;

static void rand_hex(char *out, size_t nhex)
{
    uint8_t b[16];
    static const char d[] = "0123456789abcdef";
    size_t nb = nhex / 2;
    if (nb > sizeof b)
        nb = sizeof b;
    if (g5c_random(b, nb) != 0)
        memset(b, 0x5a, nb);
    for (size_t i = 0; i < nb; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * nb] = 0;
}

static bool is_hex_n(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

const g5c_trace_ctx *g5c_trace_current(void)
{
    return tl_trace.valid ? &tl_trace : NULL;
}

void g5c_trace_enter(char trace_id[33])
{
    if (trace_id[0] == 0)
        rand_hex(trace_id, 32);
    memcpy(tl_trace.trace_id, trace_id, 33);
    rand_hex(tl_trace.span_id, 16);
    tl_trace.parent_id[0] = 0;
    tl_trace.valid = true;
}

bool g5c_trace_enter_header(const char *tp)
{
    /* 00-<32 hex trace id>-<16 hex parent span>-<2 hex flags>; an all-zero id is invalid */
    if (tp != NULL && strlen(tp) == 55 && tp[2] == '-' && tp[35] == '-' && tp[52] == '-' && is_hex_n(tp + 3, 32) && is_hex_n(tp + 36, 16) && strncmp(tp + 3, "00000000000000000000000000000000", 32) != 0) {
        memcpy(tl_trace.trace_id, tp + 3, 32);
        tl_trace.trace_id[32] = 0;
        memcpy(tl_trace.parent_id, tp + 36, 16);
        tl_trace.parent_id[16] = 0;
        rand_hex(tl_trace.span_id, 16);
        tl_trace.valid = true;
        return true;
    }
    tl_trace.trace_id[0] = 0;
    g5c_trace_enter(tl_trace.trace_id);
    return false;
}

void g5c_trace_leave(void)
{
    tl_trace.valid = false;
}

void g5c_trace_header(char out[64])
{
    char span[17];
    if (!tl_trace.valid) {
        out[0] = 0;
        return;
    }
    rand_hex(span, 16);
    snprintf(out, 64, "00-%s-%s-01", tl_trace.trace_id, span);
}

void g5c_log(g5c_log_level l, const char *target, const char *fmt, ...)
{
    char ts[40];
    struct timespec t;
    struct tm tm;
    va_list ap;
    char *msg;
    g5c_bytes line;
    if (!g5c_log_enabled(l))
        return;
    clock_gettime(CLOCK_REALTIME, &t);
    gmtime_r(&t.tv_sec, &tm);
    snprintf(ts, sizeof ts, "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ", tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, t.tv_nsec / 1000);
    va_start(ap, fmt);
    msg = g5c_xvasprintf(fmt, ap);
    va_end(ap);
    g5c_bytes_init(&line);
    if (log_json) {
        g5c_bytes_printf(&line, "{\"timestamp\":\"%s\",\"level\":\"%s\",\"target\":\"", ts, level_names[l]);
        json_escape(&line, target);
        g5c_bytes_append_str(&line, "\",\"message\":\"");
        json_escape(&line, msg);
        if (tl_trace.valid)
            g5c_bytes_printf(&line, "\",\"trace_id\":\"%s\",\"span_id\":\"%s", tl_trace.trace_id, tl_trace.span_id);
        g5c_bytes_append_str(&line, "\"}\n");
    } else if (tl_trace.valid) {
        g5c_bytes_printf(&line, "%s %5s %s: %s trace=%s\n", ts, level_names[l], target, msg, tl_trace.trace_id);
    } else {
        g5c_bytes_printf(&line, "%s %5s %s: %s\n", ts, level_names[l], target, msg);
    }
    pthread_mutex_lock(&log_mu);
    if (line.data != NULL)
        (void)!fwrite(line.data, 1, line.len, stderr);
    pthread_mutex_unlock(&log_mu);
    g5c_bytes_free(&line);
    free(msg);
}
