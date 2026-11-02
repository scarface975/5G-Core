/* SPDX-License-Identifier: LicenseRef-Proprietary */
#ifndef G5C_NRF_PRIV_H
#define G5C_NRF_PRIV_H


#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "g5c/base.h"
#include "g5c/config.h"
#include "g5c/nrf.h"

#define NRF_LOG "g5c_nrf"

typedef struct {
    char id[37];
    g5c_json *doc;       /* the NFProfile as stored (and as returned) */
    double last_hb;      /* monotonic seconds of the last registration / heart-beat */
    double suspended_at; /* monotonic, 0 when not suspended */
    uint64_t etag;       /* changes with every modification of the profile (not with a heart-beat that changes nothing) */
} nrf_prof;

typedef struct {
    char id[40];
    g5c_json *doc;  /* the SubscriptionData as stored (with subscriptionId and validityTime) */
    double expires; /* monotonic */
} nrf_sub;

typedef struct nrf_job {
    char *url;
    char *body;
    int tries;
    struct nrf_job *next;
} nrf_job;

typedef struct {
    int hb_timer;            /* seconds the NFs are told to heart-beat at */
    int suspend_after;       /* missed heart-beats before an NF is SUSPENDED */
    int purge_after;         /* seconds SUSPENDED before the profile is removed (0: never) */
    int validity;            /* seconds a discovery result may be cached */
    int sub_validity;        /* seconds a subscription lives unless refreshed */
    unsigned max_profiles;
    unsigned max_subscriptions;
    char *state_file;
    bool oauth2;             /* the token endpoint exists */
    bool enforce;            /* discovery, list / retrieve and subscription need a bearer token */
    int token_lifetime;      /* seconds */
    char *key_file;
    char mcc[4], mnc[4];     /* the PLMN of the NRF */
} nrf_cfg;

struct nrf {
    nrf_cfg cfg;
    g5c_nf *nf;
    g5c_registry *metrics;
    char instance_id[37];
    char self_uri[160]; /* scheme://authority of this NRF, for the nfInstanceUri of notifications */

    pthread_mutex_t mu; /* profiles, subscriptions, dirty flag */
    nrf_prof *profs;
    size_t nprofs, capprofs;
    nrf_sub *subs;
    size_t nsubs, capsubs;
    uint64_t next_sub, next_etag;
    bool dirty;
    double last_flush;
    unsigned flush_gap_ms;

    pthread_mutex_t qmu; /* notification queue */
    pthread_cond_t qcv;
    nrf_job *qh, *qt;
    pthread_t workers[2];
    pthread_t monitor;
    bool started;
    atomic_bool stop;

    g5c_jwt_key *key;
    char kid[64];
};

/* ---- store.c ----------------------------------------------------------------------------------------------------------------------------- */

typedef enum { NRF_EV_REGISTERED, NRF_EV_DEREGISTERED, NRF_EV_PROFILE_CHANGED } nrf_event;

bool nrf_valid_uuid(const char *s);
/* The profile with its services in the representation the consumer understands: the nfServiceList map when it supports the Service-Map feature
 * (TS 29.510 6.1.9, feature 1), the nfServices array otherwise. Caller frees. */
g5c_json *nrf_profile_view(const g5c_json *doc, bool service_map);
/* does a supportedFeatures string (hex, feature 1 = least significant bit of the last digit) include Service-Map? */
bool nrf_features_service_map(const char *hex);
void nrf_iso8601(double wall_secs, char out[24]);
/* index of the profile or -1; the caller holds n->mu */
long nrf_find(const nrf *n, const char *id);
/* Notify the subscriptions that match; the caller holds n->mu. old / new_doc may be NULL (registration / deregistration). */
void nrf_notify(nrf *n, nrf_event ev, const char *id, const g5c_json *old_doc, const g5c_json *new_doc);
void nrf_mark_dirty(nrf *n);
void nrf_flush(nrf *n);
int nrf_restore(nrf *n);
void nrf_count(nrf *n, const char *name, const char *help, const char *label, const char *value);

/* ---- mgmt.c / disc.c / oauth.c ----------------------------------------------------------------------------------------------------------- */

void nrf_mgmt_routes(g5c_router *r, nrf *n);
void nrf_disc_routes(g5c_router *r, nrf *n);
void nrf_oauth_routes(g5c_router *r, nrf *n);
/* the bearer-token guard installed when oauth2.enforce is set */
int nrf_guard(void *ctx, const g5c_req *req, g5c_resp *resp);
/* does the JSON array / object (a profile attribute) list the value? helpers shared by discovery and tokens */
bool nrf_list_has(const g5c_json *arr, const char *value);
/* every value of a repeated query parameter, percent-decoded; *n gets the count. Free with nrf_query_free. */
char **nrf_query_all(const g5c_req *req, const char *name, size_t *n);
/* the same on an application/x-www-form-urlencoded string (the token request body) */
char **nrf_form_all(const char *form, const char *name, size_t *n);
void nrf_query_free(char **v, size_t n);
char *nrf_pct_decode(const char *s, size_t n);

#endif
