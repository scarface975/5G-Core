/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Roles and tenants for the admin APIs. A token file lists who may do what:
 *   { "tokens": [ { "name": "noc", "sha256": "<hex of SHA-256(token)>", "roles": ["read"] },
 *                 { "name": "acme-prov", "sha256": "...", "roles": ["read", "provision"], "tenant": "acme" } ],
 *     "tenants": { "acme": { "supi_prefixes": ["imsi-0010199"] } } }
 * The file holds hashes, never tokens. A principal with a tenant sees and changes only the subscribers whose SUPI starts with one of the tenant's prefixes. The single `admin_token_file` of
 * the functions stays what it was: one principal named "admin" with every role and no tenant. The file is read again when it changes (a token is revoked by removing its entry) */
#ifndef G5C_AUTHZ_H
#define G5C_AUTHZ_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/sbi.h"

enum { G5C_ROLE_READ = 1, G5C_ROLE_PROVISION = 2, G5C_ROLE_POLICY = 4, G5C_ROLE_KEY_ADMIN = 8, G5C_ROLE_ALL = 15 };

typedef struct {
    char name[48];
    char tenant[48]; /* "" for none */
    unsigned roles;
} g5c_principal;

typedef struct g5c_authz g5c_authz;

/* `path` may be NULL; `legacy_token` (the single admin token, may be NULL) becomes the principal "admin". NULL with err when the file is unusable. */
g5c_authz *g5c_authz_new(const char *path, const char *legacy_token, char *err, size_t errcap);
void g5c_authz_free(g5c_authz *a);
bool g5c_authz_enabled(const g5c_authz *a);
/* The principal behind the bearer token of the request: 0, or -1 for no token or an unknown one. */
int g5c_authz_identify(g5c_authz *a, const g5c_req *req, g5c_principal *out);
/* The role a request needs, by method and path (0: no admin path, passes; G5C_ROLE_ALL: only a principal with every role) */
typedef unsigned (*g5c_role_fn)(const char *method, const char *path);
/* The guard of an admin API (the router guard): 0 to go on; 401 without a known token, 403 when the principal lacks the role, with `resp` filled. `who` is the principal when it returns 0. */
int g5c_authz_check(g5c_authz *a, const g5c_req *req, g5c_role_fn need, g5c_principal *who, g5c_resp *resp);
/* The principal behind a request that has passed the guard; with no authz (the single admin token) it is "admin" with every role. */
void g5c_authz_who(g5c_authz *a, const g5c_req *req, g5c_principal *who);
/* A tenant sees only its prefixes; a principal without a tenant sees everything. */
bool g5c_authz_supi_allowed(const g5c_authz *a, const g5c_principal *p, const char *supi);
const char *g5c_role_name(unsigned role);
/* SHA-256 of a token as 64 hex characters (what the file holds) */
void g5c_authz_hash(const char *token, char out[65]);

#endif
