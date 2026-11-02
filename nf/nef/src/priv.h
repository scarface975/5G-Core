/* SPDX-License-Identifier: LicenseRef-Proprietary */
#ifndef G5C_NEF_PRIV_H
#define G5C_NEF_PRIV_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "g5c/base.h"
#include "g5c/json.h"
#include "g5c/metrics.h"
#include "g5c/nef.h"
#include "g5c/oaschema.h"
#include "g5c/sbi.h"

#include "api_ids.gen.h"

#define NEF_LOG "g5c_nef"
#define TI_BASE "/3gpp-traffic-influence/v1"
#define ME_BASE "/3gpp-monitoring-event/v1"
#define AQ_BASE "/3gpp-as-session-with-qos/v1"
#define CB_BASE "/nnef-callback/v1"

extern const char *const nef_schema_chunks[];
extern const size_t nef_schema_nchunks, nef_schema_count;

enum { API_TI = 0, API_ME = 1, API_AQ = 2, API_COUNT = 3 };
extern const char *const nef_api_names[API_COUNT];

/* ---- configuration -------------------------------------------------------------------------------------------------- */

typedef struct {
    char *id, *token;
    unsigned apis; /* bit per API_* the AF may use */
    char **hosts;  /* hosts its notification destinations may name */
    size_t nhosts;
    bool any_host;
    unsigned max_subs;
    char **qos_refs; /* the QoS references the AF may name (none: any) */
    size_t nqos_refs;
} nef_af;

struct nef_cfg {
    char mcc[4], mnc[4];
    nef_af *afs;
    size_t nafs;
    char *state_file, *callback_uri;
    char *udr_uri, *udm_uri, *amf_uri, *pcf_uri, *bsf_uri, *nrf_uri;
    unsigned sub_lifetime_s, notify_retries, max_reports, max_wait_s;
    unsigned udr_timeout_ms;
    bool validate;
    bool events_via_udm; /* monitoring events: subscribe at the UDM (Nudm_EventExposure) instead of at the AMF directly */
};

const nef_af *cfg_af(const nef_cfg *c, const char *id);

/* ---- state ---------------------------------------------------------------------------------------------------------- */

typedef struct {
    int api;
    char *af, *id;
    g5c_json *doc; /* the representation the AF sees (with `self`) */
    g5c_json *ctx; /* what the NEF keeps about the resources it made at other functions */
    int64_t expiry_ms; /* 0: no end */
    unsigned reports;  /* reports delivered (monitoring) */
} res_t;

typedef struct job {
    char *url, *body;
    char *res_key; /* "<api>/<af>/<id>" of the subscription it belongs to, for the metrics and the log */
    unsigned attempts;
    double not_before;
    struct job *next;
} job_t;

struct nef {
    nef_cfg *cfg;
    g5c_client *client;
    g5c_disc *disc;
    g5c_registry *metrics;
    bool own_metrics;
    oa_schemas *sch;
    pthread_mutex_t mu; /* the resources */
    res_t **res;
    size_t nres, capres;
    pthread_mutex_t qmu; /* the delivery queue (taken after mu, never before it) */
    pthread_cond_t qcv;
    job_t *q;
    size_t qlen;
    bool stop, dirty;
    pthread_t worker;
    bool worker_on;
    g5c_counter *c_req[API_COUNT], *c_reject[API_COUNT], *c_ok, *c_failed, *c_dropped, *c_udr_fail, *c_amf_fail, *c_pcf_fail, *c_bsf_hit, *c_bsf_none, *c_bsf_fail;
    g5c_gauge *g_subs[API_COUNT];
};

/* ---- util.c ----------------------------------------------------------------------------------------------------------- */
void nef_problem(g5c_resp *resp, int status, const char *cause, const char *detail);
void nef_invalid(g5c_resp *resp, int status, const char *cause, const char *pointer, const char *reason);
bool uri_ok(const char *u);                                       /* http or https, a host, no userinfo, no fragment */
char *uri_host(const char *u);                                    /* host of a URI (without port or brackets), malloc'd; NULL if none */
bool notify_host_allowed(const nef_af *af, const char *uri);
void merge_patch(g5c_json **doc, const g5c_json *patch);          /* RFC 7386 */
int64_t parse_rfc3339(const char *s);                             /* unix milliseconds, -1 when malformed */
void format_rfc3339(int64_t ms, char out[32]);
unsigned feat_parse(const char *s);
char *feat_str(unsigned f);                                       /* lower-case hex without leading zeros; NULL for 0 */
bool is_hex_id(const char *s);
char *pct_encode(const char *s);
int peer_status(int upstream);

/* ---- nef.c ------------------------------------------------------------------------------------------------------------ */
char *nef_key(int api, const char *af, const char *id);
res_t *res_find(nef *n, int api, const char *af, const char *id); /* caller holds mu */
res_t *res_add(nef *n, int api, const char *af, const char *id, g5c_json *doc, g5c_json *ctx); /* takes doc and ctx; caller holds mu */
void res_remove(nef *n, res_t *r);                                 /* caller holds mu */
size_t res_count(nef *n, int api, const char *af);                 /* caller holds mu */
void nef_dirty(nef *n);                                            /* the state changed: write it */
void nef_enqueue(nef *n, const char *url, char *body, const char *res_key, double delay_s); /* takes body */
char *nef_root(nef *n, const char *configured, const char *type, const char *service);
/* The PCF that holds the PDU session of the UE of an AsSessionWithQoS request: the configured one, else the one the BSF names for the UE's address (TS 29.521 4.2.4),
 * else a PCF of the NRF. NULL when there is none. */
char *nef_pcf_root(nef *n, const g5c_json *req);
void nef_call_failed(nef *n, int api_peer);                        /* a call to another function failed: forget the discovered address */
int nef_peer(nef *n, const char *root, const char *method, const char *path, const g5c_json *body, g5c_resp *out, char *err, size_t errcap);
const nef_af *af_auth(nef *n, const g5c_req *req, g5c_resp *resp, int api); /* the AF of the request when it may use the API; else answers 401 / 403 and NULL */
char *nef_self_url(const nef *n, const char *path);                 /* an absolute URL of the NEF's own callback endpoint */
void nef_state_save(nef *n);
int nef_state_load(nef *n, char *err, size_t errcap);
void nef_worker_start(nef *n);
void nef_worker_stop(nef *n);
bool nef_body_ok(nef *n, const g5c_json *body, int schema, g5c_resp *resp);
void nef_reply_res(g5c_resp *resp, int status, const res_t *r, const g5c_req *req, const char *base);

/* ---- ti.c, me.c --------------------------------------------------------------------------------------------------------- */
void ti_routes(g5c_router *r, nef *n);
void me_routes(g5c_router *r, nef *n);
void as_routes(g5c_router *r, nef *n);
void me_sweep(nef *n);                                             /* delete subscriptions whose monitoring time is over */
void me_state_restored(nef *n);

#endif
