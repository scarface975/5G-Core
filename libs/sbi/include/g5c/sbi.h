/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Service-Based Interface transport (3GPP TS 29.500 / 29.501): HTTP/2 + JSON.
 *
 *  - g5c_router / g5c_server : path-template routing and an HTTP/2 server (h2c, or TLS/mTLS with ALPN h2).
 *    Handlers are plain blocking functions; the server runs them on a thread pool.
 *  - g5c_client              : pooled HTTP/2 client with a per-request timeout (blocking).
 *  - g5c_problem             : error body of TS 29.571 clause 5.2.4.1.
 * NF-specific API models live in the NF that owns the service (ADR-0007). */
#ifndef G5C_SBI_H
#define G5C_SBI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/ssl.h>

#include "g5c/base.h"
#include "g5c/json.h"
#include "g5c/metrics.h"

#define G5C_SBI_MAX_BODY (1U << 20) /* requests larger than this get 413 */
#define G5C_JSON_TYPE "application/json"
#define G5C_PROBLEM_TYPE "application/problem+json"

typedef struct {
    char *name, *value;
} g5c_header;

typedef struct {
    char *name, *value;
} g5c_param;

/* ---- request / response ---- */

typedef struct {
    char *method;
    char *path;  /* no query */
    char *query; /* raw, may be NULL */
    char *scheme;    /* "http" or "https" */
    char *authority; /* host:port the client addressed */
    char peer[48];   /* the IP address of the client as the server saw it ("" when unknown) */
    g5c_header *headers;
    size_t nheaders;
    g5c_param *params; /* {name} captures from the matched route */
    size_t nparams;
    uint8_t *body; /* NUL-terminated for convenience, body_len excludes the NUL */
    size_t body_len;
} g5c_req;

typedef struct {
    int status;
    g5c_header *headers;
    size_t nheaders;
    uint8_t *body; /* NUL-terminated, body_len excludes the NUL */
    size_t body_len;
} g5c_resp;

void g5c_req_init(g5c_req *r);
void g5c_req_free(g5c_req *r);
void g5c_req_add_header(g5c_req *r, const char *name, const char *value); /* name is lowercased */
void g5c_req_set_body(g5c_req *r, const void *p, size_t n);
const char *g5c_req_header(const g5c_req *r, const char *name); /* case-insensitive; NULL if absent */
const char *g5c_req_param(const g5c_req *r, const char *name);
/* Raw (still percent-encoded) query value, malloc'd; NULL when absent. A bare flag yields "". */
char *g5c_req_query(const g5c_req *r, const char *name);
char *g5c_req_query_decoded(const g5c_req *r, const char *name);
/* Absolute URL of `path` on this server (Location headers, TS 29.500 5.2.3.2.1). Caller frees. */
char *g5c_req_url(const g5c_req *r, const char *path);
/* Parse the body as JSON. On failure fills `err` with a 400 ProblemDetails response and returns NULL. */
g5c_json *g5c_req_json(const g5c_req *r, g5c_resp *err);

void g5c_resp_init(g5c_resp *r);
void g5c_resp_free(g5c_resp *r);
void g5c_resp_status(g5c_resp *r, int code);
void g5c_resp_header(g5c_resp *r, const char *name, const char *value); /* replaces; name lowercased */
const char *g5c_resp_header_get(const g5c_resp *r, const char *name);
void g5c_resp_content(g5c_resp *r, int code, const char *ctype, const void *body, size_t n);
void g5c_resp_json(g5c_resp *r, int code, const g5c_json *j); /* does not consume j */
g5c_json *g5c_resp_parse_json(const g5c_resp *r);                 /* NULL if not valid JSON */

/* ---- ProblemDetails ---- */

typedef struct {
    int status; /* 0 -> 500 */
    const char *type, *title, *detail, *instance, *cause;
    const char *invalid_param, *invalid_reason; /* a single invalidParams entry, if invalid_param != NULL */
} g5c_problem;

void g5c_resp_problem(g5c_resp *r, const g5c_problem *p);
/* Shorthands. */
void g5c_resp_problem_simple(g5c_resp *r, int status, const char *cause, const char *detail);
void g5c_resp_problem_invalid(g5c_resp *r, int status, const char *cause, const char *param, const char *reason);
/* The "cause" of a problem+json response body, malloc'd, or NULL. */
char *g5c_resp_problem_cause(const g5c_resp *r);

/* ---- router ---- */

typedef struct g5c_router g5c_router;
typedef void (*g5c_handler)(void *ctx, const g5c_req *req, g5c_resp *resp);
/* Return 0 to continue; non-zero after filling resp to answer without invoking a handler. */
typedef int (*g5c_guard_fn)(void *ctx, const g5c_req *req, g5c_resp *resp);
typedef void (*g5c_observer_fn)(void *ctx, const char *method, const char *route, int status, double elapsed_s);

g5c_router *g5c_router_new(void);
void g5c_router_free(g5c_router *r);
/* Template like "/nudm-ueau/v1/{supiOrSuci}/security-information/generate-auth-data". */
void g5c_router_route(g5c_router *r, const char *method, const char *tmpl, g5c_handler h, void *ctx);
/* Move all routes of `other` into r and free other (its guard/observer are dropped). */
void g5c_router_merge(g5c_router *r, g5c_router *other);
/* Introspection (used by tools/inspect to document the real route tables). */
size_t g5c_router_count(const g5c_router *r);
bool g5c_router_route_at(const g5c_router *r, size_t i, const char **method, const char **tmpl);
/* The handler of every request that no route matches (an SCP routes any path) */
void g5c_router_set_fallback(g5c_router *r, g5c_handler h, void *ctx);
void g5c_router_set_guard(g5c_router *r, g5c_guard_fn g, void *ctx);
void g5c_router_get_guard(const g5c_router *r, g5c_guard_fn *g, void **ctx);
/* Route flags */
#define G5C_ROUTE_OWN_AUTH 1u
void g5c_router_route_flags(g5c_router *r, const char *method, const char *tmpl, g5c_handler h, void *ctx, unsigned flags);
/* The flags of the route that a request with this method and path would match (0 when none). */
unsigned g5c_router_flags_of(const g5c_router *r, const char *method, const char *path);
void g5c_router_set_observer(g5c_router *r, g5c_observer_fn o, void *ctx);
/* Dispatch: 404 when no template matches, 405 (with Allow) when only the method differs. Thread-safe once the router is no longer being modified */
void g5c_router_dispatch(const g5c_router *r, g5c_req *req, g5c_resp *resp);

/* Bearer-token guard (TS 33.501 13.4.1): ctx is a `bool (*)(const char *token)`-holding g5c_bearer_cfg. */
typedef struct {
    bool (*verify)(void *user, const char *token);
    void *user;
} g5c_bearer_cfg;
const char *g5c_bearer_token(const g5c_req *r); /* pointer into the header value, or NULL */
int g5c_bearer_guard(void *ctx /* g5c_bearer_cfg* */, const g5c_req *req, g5c_resp *resp);

/* ---- TLS ---- */

/* Server context; ca_path != NULL requires and verifies client certificates (mTLS). ALPN h2. */
SSL_CTX *g5c_tls_server_ctx(const char *cert_path, const char *key_path, const char *ca_path, char *err,
                            size_t errcap);
/* Client context trusting ca_path; cert/key (both or neither) present a client certificate. */
SSL_CTX *g5c_tls_client_ctx(const char *ca_path, const char *cert_path, const char *key_path, char *err,
                            size_t errcap);
/* Same, from PEM buffers (tests, secrets managers). */
/* Who may connect and what has been revoked (backlog D-02) */
int g5c_tls_server_policy(SSL_CTX *ctx, const char *const *allowed, size_t nallowed, const char *crl_pem, char *err, size_t errcap);
SSL_CTX *g5c_tls_server_ctx_pem(const char *cert_pem, const char *key_pem, const char *ca_pem, char *err,
                                size_t errcap);
SSL_CTX *g5c_tls_client_ctx_pem(const char *ca_pem, const char *cert_pem, const char *key_pem, char *err,
                                size_t errcap);

/* ---- server ---- */

typedef struct g5c_server g5c_server;

typedef struct {
    const char *address; /* IPv4 or IPv6 literal */
    uint16_t port;       /* 0 picks a free port (see g5c_server_port) */
    SSL_CTX *tls;        /* NULL: cleartext HTTP/2 (prior knowledge); not freed by the server */
} g5c_server_cfg;

/* Starts a dedicated I/O thread. The router must outlive the server and must not be modified afterwards. */
g5c_server *g5c_server_start(const g5c_server_cfg *cfg, const g5c_router *router, char *err, size_t errcap);
uint16_t g5c_server_port(const g5c_server *s);
/* Stops accepting, closes connections, joins the thread, frees the server. */
/* Replace the TLS context that new connections use (certificate rotation, no restart). Connections already open keep the old one */
SSL_CTX *g5c_server_swap_tls(g5c_server *s, SSL_CTX *fresh);
void g5c_server_stop(g5c_server *s);

/* ---- client ---- */

typedef enum {
    G5C_SBI_OK = 0,
    G5C_SBI_E_URL = -1,
    G5C_SBI_E_IO = -2,
    G5C_SBI_E_HTTP = -3,
    G5C_SBI_E_TIMEOUT = -4,
    G5C_SBI_E_TLS = -5,
    G5C_SBI_E_REQUEST = -6,
    G5C_SBI_E_OVERLOAD = -7 /* not sent: the producer asked its consumers to back off (429 / Retry-After / 3gpp-Sbi-Oci) */
} g5c_sbi_err;

typedef struct g5c_client g5c_client;
/* The values of 3gpp-Sbi-Lci (TS 29.500 6.3.3) and 3gpp-Sbi-Oci (6.4.3): "Timestamp: ...; Load-Metric: 35%" and "...; Period-of-Validity: 5s; Overload-Reduction-Metric: 25%" */
bool g5c_sbi_parse_lci(const char *value, unsigned *load_pct);
bool g5c_sbi_parse_oci(const char *value, unsigned *validity_s, unsigned *reduction_pct);
/* Counts the requests the client did not send because of a back-off (may be NULL). */
void g5c_client_set_backoff_counter(g5c_client *c, g5c_counter *k);
typedef struct {
    const char *name, *value;
} g5c_kv;

/* tls: context for https:// URLs (ownership transfers to the client); may be NULL (http:// only). */
g5c_client *g5c_client_new(int timeout_ms, SSL_CTX *tls);
/* An operator tool's client */
g5c_client *g5c_client_new_env(int timeout_ms, char *err, size_t errcap);
/* Replace the client context (certificate rotation): new connections use it, idle ones are dropped; the old context is freed once nothing uses it. */
void g5c_client_swap_tls(g5c_client *c, SSL_CTX *fresh);
void g5c_client_free(g5c_client *c);
/* Returns 0 or a g5c_sbi_err; `out` is valid (and must be freed) only on success. err may be NULL. */
int g5c_client_request(g5c_client *c, const char *method, const char *url, const g5c_kv *headers, size_t nheaders,
                       const char *content_type, const void *body, size_t body_len, g5c_resp *out, char *err,
                       size_t errcap);
int g5c_client_get(g5c_client *c, const char *url, g5c_resp *out, char *err, size_t errcap);
/* Indirect communication (TS 29.500 6.10.2) */
void g5c_client_set_scp(g5c_client *c, const char *scp_uri, const char *direct_uri);
/* Called for every request that carries no Authorization header, before it is sent */
typedef char *(*g5c_token_fn)(void *user, const char *method, const char *url);
/* Called when a request that carried the provider's token is answered 401 */
typedef void (*g5c_token_reject_fn)(void *user, const char *method, const char *url);
void g5c_client_set_token_provider(g5c_client *c, g5c_token_fn fn, g5c_token_reject_fn reject, void *user);
/* The User-Agent of the requests ("<NFType>-<id>", TS 29.500 5.2.2.2: the SCP derives the type of the consumer from it); NULL for none. */
void g5c_client_set_user_agent(g5c_client *c, const char *ua);
/* The per-request deadline (milliseconds); applies to the requests that follow. */
void g5c_client_set_timeout(g5c_client *c, int timeout_ms);
/* Body is serialised from `j` (may be NULL for no body). */
int g5c_client_send_json(g5c_client *c, const char *method, const char *url, const g5c_json *j, g5c_resp *out,
                         char *err, size_t errcap);

#endif
