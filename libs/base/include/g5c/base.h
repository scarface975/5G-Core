/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Base utilities: growable byte buffer, string helpers, UUID, logging. */
#ifndef G5C_BASE_H
#define G5C_BASE_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__)
#define G5C_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define G5C_PRINTF(a, b)
#endif

/* ---- allocation ------------------------------------------------------------ Small control-structure allocations abort on exhaustion */
void *g5c_xmalloc(size_t n);
void *g5c_xcalloc(size_t n, size_t sz);
void *g5c_xrealloc(void *p, size_t n);
char *g5c_xstrdup(const char *s);
char *g5c_xstrndup(const char *s, size_t n);
char *g5c_xasprintf(const char *fmt, ...) G5C_PRINTF(1, 2);
char *g5c_xvasprintf(const char *fmt, va_list ap);

/* ---- growable byte buffer (always NUL-terminated past len) ---- */
typedef struct {
    uint8_t *data;
    size_t len, cap;
} g5c_bytes;

void g5c_bytes_init(g5c_bytes *b);
void g5c_bytes_free(g5c_bytes *b);
void g5c_bytes_clear(g5c_bytes *b);
/* Returns 0, or -1 on overflow/exhaustion (buffer unchanged). */
int g5c_bytes_append(g5c_bytes *b, const void *p, size_t n);
int g5c_bytes_append_str(g5c_bytes *b, const char *s);
int g5c_bytes_putc(g5c_bytes *b, char c);
int g5c_bytes_printf(g5c_bytes *b, const char *fmt, ...) G5C_PRINTF(2, 3);
/* Detach the contents (caller frees); buffer is reset. NUL-terminated. */
char *g5c_bytes_take(g5c_bytes *b, size_t *len);

/* ---- strings ---- */
bool g5c_streq(const char *a, const char *b); /* NULL-safe: both NULL is equal */
bool g5c_starts_with(const char *s, const char *prefix);
bool g5c_is_digits(const char *s); /* non-empty, all '0'..'9' */
/* Percent-decode; invalid escapes kept literally. Caller frees. */
char *g5c_percent_decode(const char *s);
/* Lowercase hex of n bytes. Caller frees. */
char *g5c_hex_encode(const uint8_t *p, size_t n);
/* Returns decoded length or -1 (odd length, bad digit, or out too small). */
long g5c_hex_decode(const char *s, uint8_t *out, size_t cap);

/* Base64 (RFC 4648 clause 4, padded). Encode returns a heap string */
char *g5c_base64_encode(const uint8_t *p, size_t n);
long g5c_base64_decode(const char *s, uint8_t *out, size_t cap);

/* ---- identifiers & time ---- */
/* UUID v4 from the OS CSPRNG. out must hold 37 bytes. Returns 0 / -1. */
int g5c_uuid_v4(char out[37]);
/* Fill with CSPRNG bytes. Returns 0 / -1. */
int g5c_random(void *p, size_t n);
double g5c_now_seconds(void);   /* monotonic */
int64_t g5c_unix_millis(void);  /* wall clock */

/* ---- logging ---- */
typedef enum { G5C_LOG_ERROR = 0, G5C_LOG_WARN, G5C_LOG_INFO, G5C_LOG_DEBUG, G5C_LOG_TRACE } g5c_log_level;

/* level: "error|warn|info|debug|trace" (a directive such as "g5c=debug" uses the part after '='). The G5C_LOG environment variable overrides it */
bool g5c_log_init(const char *level, bool json);
bool g5c_log_enabled(g5c_log_level l);
/* The level can change while the process runs (SIGUSR1: debug, SIGUSR2: back to the configured one). g5c_log_baseline() is the level g5c_log_init set. */
void g5c_log_set_level(g5c_log_level l);
g5c_log_level g5c_log_baseline(void);
void g5c_log(g5c_log_level l, const char *target, const char *fmt, ...) G5C_PRINTF(3, 4);
/* One tap per process sees every line at `min` or more severe, and every "g5c_audit" line when `audit` is set, whatever the log level. It runs on the logging thread, must not log,
 * and is never called once g5c_log_set_tap(NULL, ...) has returned. */
typedef void (*g5c_log_tap_fn)(void *user, g5c_log_level l, const char *target, const char *ts, const char *msg);
int g5c_log_set_tap(g5c_log_tap_fn fn, void *user, g5c_log_level min, bool audit); /* 0, or -1 when another tap is set */

/* ---- request tracing (W3C trace context, backlog C-03) ---- */
/* A trace id follows one UE's procedure through the functions */
typedef struct {
    char trace_id[33]; /* 32 lower-case hex */
    char span_id[17];  /* 16 hex: this hop */
    char parent_id[17]; /* the caller's span, empty at the start of a trace */
    bool valid;
} g5c_trace_ctx;

const g5c_trace_ctx *g5c_trace_current(void); /* NULL when the calling thread is not in a trace */
void g5c_trace_enter(char trace_id[33]);      /* begin (or continue) the trace `trace_id` on this thread; an empty buffer gets a new id */
bool g5c_trace_enter_header(const char *traceparent); /* continue the trace of an incoming `traceparent` header; false */
void g5c_trace_leave(void);
void g5c_trace_header(char out[64]);          /* the `traceparent` value for an outgoing request (a new span under the current one) */

#define G5C_LOGE(t, ...) g5c_log(G5C_LOG_ERROR, t, __VA_ARGS__)
#define G5C_LOGW(t, ...) g5c_log(G5C_LOG_WARN, t, __VA_ARGS__)
#define G5C_LOGI(t, ...) g5c_log(G5C_LOG_INFO, t, __VA_ARGS__)
#define G5C_LOGD(t, ...) g5c_log(G5C_LOG_DEBUG, t, __VA_ARGS__)

#endif
