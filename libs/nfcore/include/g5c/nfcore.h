/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Shared runtime for every network function: config -> logging -> SBI server (optionally TLS/mTLS) -> NRF
 * registration with heartbeats -> health and metrics endpoints.
 * An NF builds its own g5c_router with its service routes and hands it to g5c_nf_start() / g5c_nf_run(). */
#ifndef G5C_NFCORE_H
#define G5C_NFCORE_H

#include <stdatomic.h>
#include <stdbool.h>

#include "g5c/config.h"
#include "g5c/metrics.h"
#include "g5c/oauth.h"
#include "g5c/sbi.h"

/* ---- NRF client (Nnrf_NFManagement, TS 29.510 clause 5.2.2) ------------------------------------ */

typedef struct {
    const char *name;    /* e.g. "nudm-ueau" */
    const char *version; /* version in the URI, e.g. "v1" */
} g5c_svc;

/* NF profile JSON: the subset we publish. Caller frees. */
g5c_json *g5c_nrf_profile(const char *instance_id, const char *nf_type, const char *addr, uint16_t port,
                          const char *scheme, const char *mcc, const char *mnc, const g5c_svc *svcs, size_t nsvcs);

/* All return 0 on success, a positive HTTP status on an unexpected answer, or a negative g5c_sbi_err. */
int g5c_nrf_register(g5c_client *c, const char *nrf_uri, const g5c_json *profile, g5c_json **stored /* opt */);
int g5c_nrf_heartbeat(g5c_client *c, const char *nrf_uri, const char *instance_id);
int g5c_nrf_deregister(g5c_client *c, const char *nrf_uri, const char *instance_id);

/* ---- NF discovery client (Nnrf_NFDiscovery, TS 29.510 clause 5.3) --------------------------------------------------------------------------- */

typedef struct g5c_disc g5c_disc;

typedef struct {
    const char *snssai_json; /* the snssais query value: a JSON S-NSSAI or array of them, e.g. [{"sst":1,"sd":"000001"}] */
    const char *dnn;
    const char *tai_json;    /* {"plmnId":{"mcc":..,"mnc":..},"tac":"000001"} */
    const char *supi;
} g5c_disc_opts;

/* The NRF's apiRoot (http://host:port); the requester type and instance id are sent with every query. */
g5c_disc *g5c_disc_new(g5c_client *c, const char *nrf_uri, const char *requester_type, const char *requester_id);
void g5c_disc_free(g5c_disc *d);
/* scheme://host:port of the first instance (the NRF orders by priority, then load) of `target_type` that offers `service` (NULL: any) and fits `o`
 * (may be NULL). A fresh answer is kept for its validityPeriod. NULL when none or on an error; the caller frees. Thread-safe. */
char *g5c_disc_root(g5c_disc *d, const char *target_type, const char *service, const g5c_disc_opts *o);
/* Drop what is cached for a target type (after a connection failure, so that the next call asks the NRF again). */
void g5c_disc_forget(g5c_disc *d, const char *target_type);

/* ---- NF context ---------------------------------------------------------------------------------- */

typedef struct {
    g5c_common common;
    g5c_registry *metrics;
    atomic_bool ready;
    char instance_id[37];
    g5c_client *client; /* outgoing SBI client (TLS/mTLS when the config gives a CA) */
    g5c_oauth_client *oauth_client; /* `oauth2.acquire`: the access tokens of the requests to other functions; set by g5c_nf_start */
} g5c_nf;

/* Takes ownership of the strings inside `common`. */
g5c_nf *g5c_nf_new(g5c_common *common, char *err, size_t errcap);
void g5c_nf_free(g5c_nf *nf);

typedef struct {
    const char *nf_type; /* e.g. "UDM" */
    const g5c_svc *services;
    size_t nservices;
    const g5c_json *extra; /* optional object whose members are added to the NF profile (e.g. smfInfo); not consumed */
} g5c_nrf_reg;

typedef struct g5c_nf_inst g5c_nf_inst;

/* Bind the SBI listener, serve `nf_routes` (consumed) plus /health/live, /health/ready, /metrics, register with the
 * NRF when configured, and mark the NF ready. Returns NULL with err on failure. */
g5c_nf_inst *g5c_nf_start(g5c_nf *nf, g5c_router *nf_routes, const g5c_nrf_reg *reg, char *err, size_t errcap);
uint16_t g5c_nf_inst_port(const g5c_nf_inst *r);
/* Certificate rotation without a restart: reads the certificate, key and CA again (the paths of `sbi.tls`) and uses them for new connections, as server and as client. -1 with err
 * filled leaves everything as it was. g5c_nf_run does this on SIGHUP. */
int g5c_nf_inst_reload_tls(g5c_nf_inst *r, char *err, size_t errcap);
/* Mark not ready, deregister from the NRF, stop serving, free. */
void g5c_nf_stop(g5c_nf_inst *r);
/* start + block until SIGINT/SIGTERM + stop. Returns 0, or -1 on start-up failure (err filled). */
int g5c_nf_run(g5c_nf *nf, g5c_router *nf_routes, const g5c_nrf_reg *reg, char *err, size_t errcap);

/* Start-up checks that need no sockets: loads the TLS certificate, key and CA. 0, or -1 with err filled. */
int g5c_nf_check(const g5c_nf *nf, char *err, size_t errcap);

/* Reads a secret from `$env_name` if set, else from the file `path` (trimmed), else from a command when `path` is `exec:<absolute command> [args]` (a key-management service or vault
 * client; no shell, 10 s, exit 0, standard output is the secret); NULL when none is configured.
 * On a file error returns NULL and fills err (err[0] != 0). */
char *g5c_secret_from_env_or_file(const char *env_name, const char *path, char *err, size_t errcap);

#endif
