/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* YAML/JSON configuration shared by every network function. Each NF reads its own sections from the same DOM.
 * Unknown keys inside the common sections are rejected so typos fail loudly. */
#ifndef G5C_CONFIG_H
#define G5C_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "g5c/json.h"

typedef struct {
    char *cert, *key, *ca; /* ca may be NULL; when set, mutual TLS is on */
    char **allowed_peers;  /* `allowed_peers`: patterns for the names of the client certificates that may connect (mutual TLS only); NULL: any certificate of the CA */
    size_t nallowed;
    char *crl;             /* `crl`: file with the CA's revocation list, read again on SIGHUP */
} g5c_tls_cfg;

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
    /* `oauth2: { enforce, acquire, leeway_s, jwks_refresh_s }` (TS 33.501 13.4.1; needs `nrf`): enforce: this function, as a producer, requires an access token of the NRF for its services; acquire:
     * as a consumer it asks the NRF for a token for every service it calls and sends it. Both default to false (functions that do not use tokens, Open5GS's among them, work as before). */
    bool oauth2_enforce, oauth2_acquire;
    unsigned oauth2_leeway_s;       /* clock skew tolerated when checking exp / iat / nbf (default 5) */
    unsigned oauth2_jwks_refresh_s; /* how long the NRF's key set is trusted before it is fetched again (default 600) */
    char *scp_uri; /* `scp_client: { uri }`; NULL: direct communication; else every request to another function goes through this SCP (TS 29.500 6.10.2) */
} g5c_common;

/* Read a YAML (or JSON) file into a DOM. Returns NULL and fills err on failure. */
g5c_json *g5c_config_load(const char *path, char *err, size_t errcap);

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
