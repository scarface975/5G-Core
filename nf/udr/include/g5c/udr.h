/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The Unified Data Repository: Nudr_DataRepository (3GPP TS 29.504 / 29.505 / 29.519) over a storage interface.
 *
 * The API is table-driven from the pinned OpenAPI files (tools/gen_udr_api.py): every operation of the subscription-,
 * policy-, application- and exposure-data APIs is served, bodies are validated against the 3GPP schemas, ETag / If-Match
 * / If-None-Match / Last-Modified / `fields` work on every resource, and subscriptions send DataChangeNotify. Data lives
 * behind `udr_db` (ADR-0004, ADR-0020): memory with a journal for development and tests, PostgreSQL for production.
 *
 * Operations that the 3GPP API has no service operation for (creating provisioned data, removing a subscriber, listing
 * subscribers) are provisioning extensions of the same resources, protected by a bearer token. */
#ifndef G5C_UDR_H
#define G5C_UDR_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/json.h"
#include "g5c/metrics.h"
#include "g5c/sbi.h"

/* ---- storage keys of the resources the other NFs use --------------------------------------------------------------- A subscriber's data is a set of */
#define UDR_AUTH "subscription-data/authentication-data/authentication-subscription"
#define UDR_AUTH_STATUS "subscription-data/authentication-data/authentication-status"
#define UDR_AM "subscription-data/provisioned-data/am-data"
#define UDR_SM "subscription-data/provisioned-data/sm-data" /* array, one entry per S-NSSAI */
#define UDR_SMF_SELECTION "subscription-data/provisioned-data/smf-selection-subscription-data"
#define UDR_AMF_REG "subscription-data/context-data/amf-3gpp-access"
#define UDR_SMF_REGS "subscription-data/context-data/smf-registrations" /* children keyed by PDU session id */
#define UDR_POLICY_SM "policy-data/ues/sm-data"
#define UDR_POLICY_AM "policy-data/ues/am-data"

/* ---- store ---- */

typedef struct g5c_udr_store g5c_udr_store;

g5c_udr_store *g5c_udr_store_memory(void);
/* Memory with a snapshot file and a journal; NULL + err on a malformed file or an unwritable location. */
g5c_udr_store *g5c_udr_store_open(const char *path, char *err, size_t errcap);
/* PostgreSQL (libpq); NULL + err when unreachable or when this build has no libpq. `pool` connections. */
g5c_udr_store *g5c_udr_store_postgres(const char *conninfo, int pool, char *err, size_t errcap);
void g5c_udr_store_free(g5c_udr_store *s);
/* true when this build can talk to PostgreSQL */
bool g5c_udr_have_postgres(void);

/* Direct access for tests and tools (the NFs go through the API). `ue` is the partition: a SUPI. Copies; caller frees. */
g5c_json *g5c_udr_get(g5c_udr_store *s, const char *ue, const char *key);
bool g5c_udr_exists(g5c_udr_store *s, const char *ue);
/* Replace or create (takes val); true when newly created. */
bool g5c_udr_put(g5c_udr_store *s, const char *ue, const char *key, g5c_json *val);
bool g5c_udr_take(g5c_udr_store *s, const char *ue, const char *key);
/* JSON Patch: 1 ok, 0 absent, -1 patch failed (err filled); the stored document is untouched on failure. */
int g5c_udr_patch(g5c_udr_store *s, const char *ue, const char *key, const g5c_json *items, char *err, size_t errcap);
/* Children of a collection key (smf-registrations): put/get/remove one child, all children as an array. */
bool g5c_udr_map_put(g5c_udr_store *s, const char *ue, const char *key, const char *child, g5c_json *val);
g5c_json *g5c_udr_map_get(g5c_udr_store *s, const char *ue, const char *key, const char *child);
bool g5c_udr_map_remove(g5c_udr_store *s, const char *ue, const char *key, const char *child);
g5c_json *g5c_udr_map_values(g5c_udr_store *s, const char *ue, const char *key);
g5c_json *g5c_udr_ids(g5c_udr_store *s);
bool g5c_udr_remove(g5c_udr_store *s, const char *ue);
/* Hand a heap object to the store, to be freed with it. */
void g5c_udr_store_track(g5c_udr_store *s, void *owned);

/* ---- service ---- */

typedef struct g5c_udr g5c_udr;

typedef struct {
    bool no_validation;               /* accept bodies without checking them against the schemas */
    const char *provisioning_token;   /* bearer token of the extension operations; NULL: see ext_open */
    bool ext_open;                    /* extension operations without a token (tests only) */
    g5c_registry *metrics;            /* NULL: none */
    g5c_client *client;               /* sends notifications; NULL: subscriptions are stored but never notified */
    unsigned max_subscriptions;       /* per data set; 0: 10000 */
    unsigned notify_retries;          /* delivery attempts after the first; 0: 2 */
    unsigned subscription_max_s;      /* longest life of a subscription; 0: one day */
    unsigned cache_max_age_s;         /* max-age of the Cache-Control of representations (TS 29.504 6.1.2.2.3) */
    const char *api_root;             /* scheme://authority this UDR is reached at (resource URIs in notifications) */
    const g5c_json *group_ids;        /* Nudr_GroupIDmap: [{nf_type, nf_group_id, supi_ranges}]; copied; NULL: none */
    bool put_no_content;              /* compatibility: every successful PUT answers 204, also when it created the resource */
} udr_opts;

/* The service over `store` (which must outlive it). */
g5c_udr *udr_new(g5c_udr_store *store, const udr_opts *o);
void udr_free(g5c_udr *u);
/* Serves /nudr-dr/v1 and /nudr-dr/v2, and /nudr-group-id-map/v1. The router borrows the service. */
g5c_router *udr_router(g5c_udr *u);

/* Router over `store` with extension operations open and a service owned by the store (tests and tools). */
g5c_router *g5c_udr_router(g5c_udr_store *store);
/* The same with explicit options; the service is owned by the store. */
g5c_router *g5c_udr_router_opts(g5c_udr_store *store, const udr_opts *o);

/* ---- configuration (config.c) ---- */

typedef struct {
    udr_opts opts;          /* provisioning_token is heap memory owned by the config */
    g5c_udr_store *store;
    g5c_json *nrf_info;     /* udrInfo for the NF profile */
    g5c_json *group_ids;
} udr_config;

/* Parse and validate the UDR sections of a configuration document and open the store. 0, or -1 with err filled. */
int udr_config_parse(const g5c_json *cfg, udr_config *out, char *err, size_t errcap);
void udr_config_free(udr_config *c);

/* Counters for tests. */
size_t udr_record_count(g5c_udr_store *s);

#endif
