/* SPDX-License-Identifier: LicenseRef-Proprietary */
#ifndef G5C_AUSF_PRIV_H
#define G5C_AUSF_PRIV_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "g5c/ausf.h"
#include "g5c/eapaka.h"

#define AUSF_LOG "g5c_ausf"

/* ---- a small chained hash map with string keys (the tables are guarded by ausf.mu) ---- */

typedef struct hnode {
    char *key;
    void *val;
    struct hnode *next;
} hnode;

typedef struct {
    hnode **b;
    size_t nb, n;
} hmap;

void hmap_init(hmap *h);
void hmap_clear(hmap *h); /* frees the nodes and keys, not the values */
void *hmap_get(const hmap *h, const char *key);
void hmap_put(hmap *h, const char *key, void *val); /* key is copied; replaces */
void *hmap_del(hmap *h, const char *key);          /* returns the value */
/* visit every entry; the callback must not modify the map */
void hmap_each(const hmap *h, void (*fn)(const char *key, void *val, void *arg), void *arg);

/* ---- authentication contexts ---- */

typedef enum {
    M_5GAKA = 1,
    M_EAP_PRIME = 2,
} ausf_method;

typedef enum {
    ST_AKA_WAIT = 1,    /* 5G AKA: waiting for the confirmation */
    ST_EAP_CHALLENGE,   /* EAP-AKA': the challenge is out */
    ST_EAP_NOTIF_OK,    /* EAP-AKA': the protected success indication is out, waiting for its response */
    ST_EAP_NOTIF_FAIL,  /* EAP-AKA': a failure notification is out, waiting for its response */
    ST_DONE             /* finished; kept for the removal of the result */
} ausf_state;

typedef struct ausf_ctx {
    char id[37];
    char *id_in;  /* supiOrSuci as the AMF sent it */
    char *supi;
    char *snn;
    char *key;    /* id_in "|" snn: one pending context per UE and serving network */
    char *auth_event_id; /* the UDM's id of the recorded result, for its removal */
    ausf_method method;
    ausf_state st;
    double created, expires;
    uint8_t xres_star[16], kausf[32]; /* 5G AKA */
    uint8_t rand[16], autn[16], xres[16];
    size_t xres_len;
    g5c_eapaka_keys keys; /* EAP-AKA' */
    uint8_t eap_id;
    bool result_ind;
    int resyncs;
    struct ausf_ctx *lprev, *lnext;
} ausf_ctx;

typedef struct {
    ausf_ctx *head, *tail;
    size_t n;
} clist; /* oldest first: contexts expire in the order they were created */

/* ---- security contexts (the latest KAUSF per SUPI) ---- */

typedef struct ausf_ue {
    char *supi;
    char *snn;
    char *last_auth_id; /* the authentication whose result is the current one (removal applies only to it) */
    uint8_t kausf[32];
    ausf_method method;
    uint16_t counter_sor, counter_upu; /* the next value to use; 0 is never used (TS 33.501 6.14.2.3) */
    int64_t t_ms;
    uint64_t gen; /* changes with every KAUSF, so that the writer can tell what it has saved */
} ausf_ue;

struct ausf {
    g5c_client *client;
    char *udm;
    g5c_disc *disc;
    char *self_uri;
    char instance_id[37];
    g5c_registry *metrics;
    ausf_opts o;
    g5c_json *nrf_info;

    g5c_gauge *g_pending, *g_done, *g_ues; /* sizes of the tables */

    pthread_mutex_t mu;
    hmap by_id, by_key, ues;
    clist pending, done;

    /* the state file */
    pthread_t writer;
    bool writer_on, stop, dirty;
    pthread_cond_t cv;
    int gap_ms;
};

/* ---- helpers ---- */

/* the response is not to be cached (TS 29.509 6.1.3.2.3: this response shall not be cached), and a body with _links is 3GPP hypermedia (6.1.2.2.2) */
void ausf_no_store(g5c_resp *resp);
void ausf_hal(g5c_resp *resp);
void store_gauges(ausf *a); /* caller holds mu */
void ausf_count(ausf *a, const char *name, const char *help, const char *lk, const char *lv);
void ausf_count2(ausf *a, const char *name, const char *help, const char *k1, const char *v1, const char *k2, const char *v2);
char *ausf_url(ausf *a, const char *path); /* self_uri + path; caller frees */
bool ausf_valid_supi(const char *s);
bool ausf_valid_supi_or_suci(const char *s);
/* the IMSI digits of an "imsi-" SUPI, NULL for another type */
const char *ausf_imsi_digits(const char *supi);

/* contexts */
ausf_ctx *ctx_new(const char *id_in, const char *snn);
void ctx_free(ausf_ctx *c);
/* insert a started context (replaces the pending one of the same UE and serving network); false when the table is full */
bool store_insert(ausf *a, ausf_ctx *c);
/* re-insert a context that was taken out, in its list; pending contexts keep their index entries */
bool store_reinsert(ausf *a, ausf_ctx *c);
/* remove from the tables and hand over to the caller (NULL when unknown or expired) */
ausf_ctx *store_take(ausf *a, const char *id);
/* make a finished record of c: wipes its secrets and keeps it for the removal of its result; takes ownership of c */
void store_finish(ausf *a, ausf_ctx *c);
void store_reap(ausf *a, double now); /* caller holds mu */

/* UE security contexts: stores the new KAUSF of `supi` (counters back to 1) and returns the generation */
void ue_store(ausf *a, const char *supi, const char *snn, ausf_method m, const uint8_t kausf[32], const char *auth_id);
/* true when `auth_id` is the current authentication of `supi` */
bool ue_is_current(ausf *a, const char *supi, const char *auth_id);
bool ue_drop(ausf *a, const char *supi); /* deregister: the KAUSF is wiped */
void ue_mark_dirty(ausf *a);

/* the UDM */
typedef struct {
    int status;        /* HTTP status, 0 on a transport failure */
    g5c_json *body;    /* parsed answer, or NULL */
    char cause[80];    /* the cause of a problem+json answer */
    bool no_udm;       /* no UDM could be located */
} udm_answer;

void udm_answer_free(udm_answer *r);
void udm_generate(ausf *a, const char *id_in, const char *snn, const g5c_json *resync, udm_answer *out);
/* records the outcome; *event_id (heap) gets the id the UDM assigned. 0 when recorded. */
int udm_auth_event(ausf *a, const char *supi, const char *snn, const char *auth_type, bool success, char **event_id);
int udm_auth_removal(ausf *a, const char *supi, const char *snn, const char *auth_type, const char *event_id);
/* FN-RG: the UDM's answer to a SUCI of a residential gateway */
void udm_rg_auth_ctx(ausf *a, const char *suci, bool authenticated, udm_answer *out);

/* routes of the three services */
void ausf_ueau_routes(g5c_router *r, ausf *a);
void ausf_prot_routes(g5c_router *r, ausf *a);

/* what start() of both methods shares: a context for the answer of the UDM */
void ausf_ueau_start(ausf *a, const g5c_req *req, g5c_resp *resp);
/* EAP-AKA' (eap.c) */
bool eap_start(ausf *a, ausf_ctx *c, const g5c_json *vec, g5c_resp *resp, g5c_json **ctx_body);
void eap_session_post(ausf *a, const g5c_req *req, g5c_resp *resp);
/* common: the ProblemDetails for an UDM failure on the way to a vector */
void ausf_udm_failure(const udm_answer *u, g5c_resp *resp);

/* state file */
int state_load(ausf *a, char *err, size_t errcap);
int state_save(ausf *a);
void state_start_writer(ausf *a);
void state_stop_writer(ausf *a);

#endif
