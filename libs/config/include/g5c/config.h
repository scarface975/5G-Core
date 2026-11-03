/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* YAML/JSON configuration shared by every network function. Each NF reads its own sections from the same DOM */
#ifndef G5C_CONFIG_H
#define G5C_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "g5c/json.h"

typedef struct {
    char *cert, *key, *ca; /* ca may be NULL; when set, mutual TLS is on */
    char **allowed_peers;  /* `allowed_peers`: patterns for the names of the client certificates that may connect */
    size_t nallowed;
    char *crl;             /* `crl`: file with the CA's revocation list, read again on SIGHUP */
} g5c_tls_cfg;

/* `events`: where alarms and audit events go besides the log (a SIEM, a syslog collector, an HTTP collector) */
typedef struct {
    bool enabled;
    int min_level;         /* `min_level`: 0 error, 1 warn (default): lines at least this severe are sent; every g5c_audit line is sent whatever the level */
    char *syslog_host;     /* `syslog: { host, port, proto, ca, facility }`: RFC 5424 over udp, tcp or tls (RFC 5425 framing for tcp and tls) */
    uint16_t syslog_port;
    char *syslog_proto;    /* "udp" | "tcp" | "tls" */
    char *syslog_ca;       /* tls: the CA that signed the collector's certificate */
    int syslog_facility;   /* 0..23 */
    char *http_uri;        /* `http: { uri, ca, batch }`: a JSON array of events in the body of a POST */
    char *http_ca;
    unsigned http_batch;   /* events per request (default 50) */
} g5c_events_cfg;

/* `overload`: rate control of the SBI server (TS 29.500 5.2.7.2, 6.3, 6.4) */
typedef struct {
    bool enabled;
    unsigned rate_per_source; /* requests per second one client address may send (0: no per-source limit) */
    unsigned burst;           /* bucket size (default twice the rate) */
    unsigned retry_after_s;   /* Retry-After and Period-of-Validity of a 429 (default 1) */
    unsigned capacity_rps;    /* the rate that counts as 100 % load in the 3gpp-Sbi-Lci header (0: no header) */
} g5c_overload_cfg;

/* `reload: { token_file, settle_ms }`: POST /admin/v1/reload needs the bearer token in token_file (without it only SIGHUP reloads); a change is watched for settle_ms (default 1000) before it is kept */
typedef struct {
    char *token_file;
    unsigned settle_ms;
} g5c_reload_cfg;

typedef struct {
    char *name;
    char *mcc, *mnc;
    char *address;
    uint16_t port;
    bool has_tls;
    g5c_tls_cfg tls;
    char *log_level;
    bool log_json;
    char *nrf_uri; /* NULL when no NRF */
    /* `oauth2: { enforce, acquire, leeway_s, jwks_refresh_s }` (TS 33.501 13.4.1; needs `nrf`): enforce: this function, as a producer */
    bool oauth2_enforce, oauth2_acquire;
    unsigned oauth2_leeway_s;       /* clock skew tolerated when checking exp / iat / nbf (default 5) */
    unsigned oauth2_jwks_refresh_s; /* how long the NRF's key set is trusted before it is fetched again (default 600) */
    char *scp_uri; /* `scp_client: { uri }`; NULL: direct communication */
    g5c_events_cfg events;
    g5c_overload_cfg overload;
    g5c_reload_cfg reload;
} g5c_common;

/* Read a YAML (or JSON) file into a DOM. Returns NULL and fills err on failure. */
g5c_json *g5c_config_load(const char *path, char *err, size_t errcap);
/* The path of the file g5c_config_load read last ("" before the first): a function started from a file can read it again on SIGHUP. */
const char *g5c_config_last_path(void);

/* Parse the common sections from a DOM (does not look at NF-specific keys). Returns 0 or -1 with err filled. */
int g5c_common_parse(const g5c_json *root, g5c_common *out, char *err, size_t errcap);
/* Value ranges and formats. 0 / -1 with err. */
int g5c_common_validate(const g5c_common *c, char *err, size_t errcap);
void g5c_common_free(g5c_common *c);

/* Fails (returns -1 with err) if obj has a key not in the NULL-terminated list `allowed`. */
int g5c_json_check_keys(const g5c_json *obj, const char *const *allowed, const char *where, char *err,
                        size_t errcap);

/* Read a whole file; returns heap buffer (NUL-terminated) or NULL. Refuses files over max_len. */
char *g5c_read_file(const char *path, size_t max_len, size_t *len);

#endif
