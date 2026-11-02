/* SPDX-License-Identifier: LicenseRef-Proprietary */
#ifndef G5C_NSSF_PRIV_H
#define G5C_NSSF_PRIV_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "g5c/base.h"
#include "g5c/nssf.h"
#include "g5c/oaschema.h"

/* ---- generated schema pool ---- */
extern const char *const nssf_schema_chunks[];
extern const size_t nssf_schema_nchunks;
extern const size_t nssf_schema_count;
#include "api_ids.gen.h"

/* ---- identifiers ---- */

typedef struct {
    int sst;
    int sd; /* -1: none (an absent sd and FFFFFF are the same, TS 23.003 28.4.2) */
} sn_t;

/* an S-NSSAI as the AMF reports it supported: with the extension (SD ranges, wildcard SD) */
typedef struct {
    sn_t sn;
    bool wildcard;
    struct {
        int lo, hi;
    } *ranges;
    size_t nranges;
} sn_ext_t;

typedef struct {
    char mcc[4], mnc[4];
    uint32_t tac;
} tai_t;

typedef struct {
    char mcc[4], mnc[4];
    uint32_t lo, hi;
} trange_t;

bool sn_from_json(const g5c_json *j, sn_t *out);
g5c_json *sn_json(const sn_t *s);
bool sn_equal(const sn_t *a, const sn_t *b);
bool sn_in(const sn_t *list, size_t n, const sn_t *s);
bool tai_from_json(const g5c_json *j, tai_t *out);
g5c_json *tai_json(const tai_t *t);
bool tai_equal(const tai_t *a, const tai_t *b);
bool parse_tac(const char *s, uint32_t *out);
void format_tac(uint32_t tac, char out[7]);
bool plmn_from_json(const g5c_json *j, char mcc[4], char mnc[4]);
bool plmn_from_str(const char *s, char mcc[4], char mnc[4]); /* "001-01" */
g5c_json *plmn_json(const char mcc[4], const char mnc[4]);
/* SupportedFeatures (hex string, TS 29.571 5.2.2) */
unsigned features_parse(const char *s);
char *features_str(unsigned f);
bool ext_sn_from_json(const g5c_json *j, sn_ext_t *out);
void ext_sn_free(sn_ext_t *e);
bool ext_sn_matches(const sn_ext_t *e, const sn_t *s); /* the configured slice `s` is covered by the supported S-NSSAI `e` */

/* ---- configuration ---- */

typedef struct {
    sn_t sn;
    char *nrf, *nrf_nfm, *nrf_token, *nsi_id;
    tai_t *tais;
    size_t ntais;
    trange_t *ranges;
    size_t nranges;
    char (*restricted_for)[8]; /* home PLMNs ("mcc-mnc") for which the slice is restricted in its tracking areas */
    size_t nrestricted;
} slice_t;

typedef struct {
    char *id;     /* AMF Set ID of TS 23.003 2.10.1: "<mcc>-<mnc>-<region>-<set>" */
    char *nrf;    /* the NRF that resolves the set (nrfAmfSet) */
    char **amfs;  /* configured candidate AMFs (NF instance ids) */
    size_t namfs;
    sn_t *snssais; /* what the set supports when its AMFs do not report it */
    size_t nsnssais;
    bool return_candidates; /* answer the list of candidate AMFs as well as the set */
} amfset_t;

typedef struct {
    char home_mcc[4], home_mnc[4];
    sn_t serving, home;
} mapping_t;

struct nssf_cfg {
    char mcc[4], mnc[4];
    slice_t *slices;
    size_t nslices;
    amfset_t *sets;
    size_t nsets;
    mapping_t *maps;
    size_t nmaps;
    bool include_subscribed; /* local policy: the Allowed NSSAI also holds subscribed S-NSSAIs that were not requested */
    unsigned max_allowed;    /* at most 8 (TS 24.501 9.11.3.37) */
    unsigned max_configured; /* at most 16 */
    char *state_file;
    unsigned sub_max, sub_lifetime_s, notify_retries;
    bool validate;
};

const slice_t *cfg_slice(const nssf_cfg *c, const sn_t *s);
bool slice_in_tai(const slice_t *s, const tai_t *t);
bool slice_in_range(const slice_t *s, const trange_t *r);

/* ---- state ---- */

typedef struct {
    tai_t *tais;
    size_t ntais;
    trange_t *ranges;
    size_t nranges;
    sn_ext_t *sn;
    size_t nsn;
} avail_group_t;

typedef struct {
    char *nf_id, *amf_set;
    g5c_json *doc; /* the NssaiAvailabilityInfo as stored */
    avail_group_t *groups;
    size_t ngroups;
    unsigned features;
} nf_entry_t;

typedef struct {
    char *id, *uri, *amf_set;
    tai_t *tais;
    size_t ntais;
    trange_t *ranges;
    size_t nranges;
    int64_t expiry;
    unsigned features;
    g5c_json *create; /* the NssfEventSubscriptionCreateData as stored (with the expiry the NSSF chose) */
    g5c_json *last;   /* the authorized data of the last answer or notification, to notify only changes */
} sub_t;

typedef struct job {
    char *url, *body, *sub_id;
    unsigned attempts;
    double not_before;
    struct job *next;
} job_t;

struct nssf {
    nssf_cfg *cfg;
    g5c_client *client;
    g5c_registry *metrics;
    bool own_metrics;
    oa_schemas *sch;
    pthread_mutex_t mu; /* the NSSAI availability and the subscriptions */
    nf_entry_t *nfs;
    size_t nnfs, capnfs;
    sub_t *subs;
    size_t nsubs, capsubs;
    pthread_mutex_t qmu; /* the delivery queue (taken after mu, never before it) */
    pthread_cond_t qcv;
    job_t *q;
    size_t qlen;
    bool stop, dirty;
    pthread_t worker;
    bool worker_on;
    g5c_counter *c_req[4], *c_reject, *c_ok, *c_failed, *c_dropped;
    g5c_gauge *g_nfs, *g_subs;
};

/* nssf.c */
void nssf_problem(g5c_resp *resp, int status, const char *cause, const char *detail);
/* nsselect.c */
void nssf_nsselection_get(void *ctx, const g5c_req *req, g5c_resp *resp);
/* avail.c */
void nssf_avail_routes(g5c_router *r, nssf *n);
void nssf_avail_free(nssf *n);
int nssf_state_load(nssf *n, char *err, size_t errcap);
void nssf_state_save(nssf *n);
void nssf_kick(nssf *n); /* state changed: write it, deliver what is queued */
size_t nssf_avail_union_supported(nssf *n, const tai_t *t, const char *amf_set, sn_t *out, size_t cap);
/* does the AMF `nf_id` report support for every S-NSSAI of `need` at `t`? 0 unknown NF, 1 yes, 2 no. Caller holds no lock. */
int nssf_amf_supports(nssf *n, const char *nf_id, const tai_t *t, const sn_t *need, size_t nneed, char **amf_set_out);
/* sets (configured, and those the AMFs report) that cover `need` at `t`; first match copied into out */
bool nssf_find_set(nssf *n, const tai_t *t, const sn_t *need, size_t nneed, const amfset_t **cfg_set, char **dyn_set_id);
void nssf_worker_start(nssf *n);
void nssf_worker_stop(nssf *n);

#endif
