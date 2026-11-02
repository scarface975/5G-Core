/* SPDX-License-Identifier: LicenseRef-Proprietary */
#ifndef G5C_SCP_PRIV_H
#define G5C_SCP_PRIV_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "g5c/base.h"
#include "g5c/json.h"
#include "g5c/metrics.h"
#include "g5c/scp.h"
#include "g5c/sbi.h"

#define SCP_LOG "g5c_scp"

struct scp_cfg {
    char *name;       /* the identity of this SCP in Server and Via headers */
    char *prefix;     /* the deployment-specific string of the SCP's own apiRoot ("" or "/x/y") */
    char *nrf_uri;    /* discovery and the requests that name the NRF */
    char *next_uri;   /* next-hop SCP, NULL for none */
    bool next_delegates; /* forward the discovery headers to the next hop instead of selecting here */
    unsigned attempts, timeout_ms, workers, max_inflight, max_body;
    unsigned quarantine_failures, quarantine_s;
    unsigned disc_ttl_s, disc_max;
    bool retry_503, delegated;
    char **allow;     /* targets the SCP may forward to: host names and CIDRs; none: any */
    size_t nallow;
};

/* a producer (or consumer) the SCP can forward to */
typedef struct {
    char *apiroot; /* scheme://authority[/prefix] */
    char *nf_id;   /* NF instance id, NULL when unknown */
    int priority;
    unsigned capacity, load;
} cand_t;

typedef struct {
    cand_t *v;
    size_t n, cap;
} cands_t;

typedef struct {
    char *authority;
    unsigned fails;
    double until; /* monotonic seconds; 0: healthy */
} health_t;

typedef struct {
    char *key;
    cands_t c;
    double expiry;
} dcache_t;

struct scp {
    scp_cfg *cfg;
    g5c_client *client;
    g5c_registry *metrics;
    bool own_metrics;
    pthread_mutex_t mu; /* the cache and the health table */
    dcache_t *cache;
    size_t ncache;
    health_t *health;
    size_t nhealth;
    atomic_uint inflight;
    g5c_counter *c_model[3], *c_result[6], *c_attempt[3], *c_disc[4];
    g5c_gauge *g_quarantined, *g_inflight;
    g5c_histogram *h_latency;
};

enum { M_C = 0, M_D = 1, M_CB = 2 };                                /* c_model */
enum { R_2XX = 0, R_3XX, R_4XX, R_5XX, R_SCP_ERR, R_REJECTED };      /* c_result */
enum { A_OK = 0, A_RETRIED, A_FAILED };                              /* c_attempt */
enum { D_HIT = 0, D_MISS, D_FAIL, D_NONE };                          /* c_disc */

/* select.c */
void cands_free(cands_t *c);
void cands_add(cands_t *c, const char *apiroot, const char *nf_id, int priority, unsigned capacity, unsigned load);
/* the discovery query of the request's 3gpp-Sbi-Discovery-* headers; fills `out` (the candidates, in the order to try them) from the cache or the NRF.
 * 0, or the status of the error to answer (400 NF_DISCOVERY_FAILURE ..., with cause and detail). */
int scp_discover(scp *s, const g5c_req *req, const char *ua, const char *nrf_hdr, const char *extra_query, cands_t *out, char **cache_key, const char **cause, char *detail, size_t dcap);
void scp_cache_forget(scp *s, const char *query_key);
bool scp_healthy(scp *s, const char *authority);
void scp_report(scp *s, const char *authority, bool ok);
char *authority_of(const char *apiroot);
bool target_allowed(const scp_cfg *c, const char *apiroot);
bool apiroot_ok(const char *s);

/* proxy.c */
void scp_proxy(void *ctx, const g5c_req *req, g5c_resp *resp);
void scp_problem(scp *s, g5c_resp *resp, int status, const char *cause, const char *detail, const char *invalid_param);

#endif
