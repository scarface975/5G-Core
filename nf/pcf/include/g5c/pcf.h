/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5G core Policy Control Function (PCF), Phase 2.
 *
 *  - npcf-smpolicycontrol (TS 29.512): create/update/delete/get of SM policy associations, with policy decisions
 *    resolved by the policy engine and pushed to the SMF (UpdateNotify, Terminate) when policy changes mid-session.
 *  - npcf-am-policy-control (TS 29.507): AM policy associations for the AMF.
 *  - Subscriber policy overrides live in the UDR (policy-data/ues/{supi}/operator-specific-data, TS 29.519) and are managed through
 *    a token-protected admin API (/admin/v1, disabled unless a token is configured). */
#ifndef G5C_PCF_H
#define G5C_PCF_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "g5c/json.h"
#include "g5c/metrics.h"
#include "g5c/nfcore.h"
#include "g5c/sbi.h"

/* ---- policy model (TS 23.503, TS 29.512 5.6) ---------------------------------------------------------------------- Precedence, highest first */

typedef struct {
    char *uplink, *downlink; /* "100 Mbps" style (TS 29.571 BitRate) */
} pcf_ambr;

typedef struct {
    uint8_t qi5;
    uint8_t arp_priority; /* 1..=15 */
    bool preempt_cap, preempt_vuln;
    bool has_priority_level; /* 5QI priority level override 1..=127 */
    uint8_t priority_level;
} pcf_qos;

typedef struct {
    char *id; /* letters, digits, '-' and '_' */
    char **flows;
    size_t nflows; /* IPFilterRule strings, each starting "permit " */
    uint8_t qi5;
    char *gbr_ul, *gbr_dl, *mbr_ul, *mbr_dl; /* NULL when absent */
    uint32_t precedence;                      /* default 100 */
} pcf_rule;

/* A (partial) profile; every field is optional so profiles can be layered. */
typedef struct {
    bool has_ambr;
    pcf_ambr ambr;
    bool has_qos;
    pcf_qos qos;
    bool has_rules;
    pcf_rule *rules;
    size_t nrules;
} pcf_profile;

/* Operator policy (configuration) and per-subscriber overrides share this shape. */
typedef struct {
    bool has_default; /* configuration always has a (possibly empty) default */
    pcf_profile default_profile;
    char **dnn_names;
    pcf_profile *dnns;
    size_t ndnns;
    bool has_rfsp; /* config only */
    uint16_t rfsp;
    uint64_t um_volume; /* config only, `usage_monitoring.volume_threshold` */
    pcf_ambr um_throttle; /* `usage_monitoring.throttle`: the session AMBR once the threshold is reached */
} pcf_policy;

/* Parse (strict: unknown fields and wrong types are errors). 0 / -1 with err. */
int pcf_policy_parse(const g5c_json *j, bool is_config, pcf_policy *out, char *err, size_t errcap);
g5c_json *pcf_policy_to_json(const pcf_policy *p);
/* Strict Ambr object parse ({uplink, downlink}, no other keys). 0 / -1 with err. */
int pcf_ambr_parse(const g5c_json *j, pcf_ambr *a, char *err, size_t cap);
void pcf_policy_free(pcf_policy *p);
void pcf_profile_free(pcf_profile *p);

/* Validation: 0, or -1 with the offending attribute path and reason. */
int pcf_profile_validate(const pcf_profile *p, const char *path, char *field, size_t fcap, char *reason, size_t rcap);
int pcf_policy_validate(const pcf_policy *p, bool is_config, char *field, size_t fcap, char *reason, size_t rcap);
bool pcf_valid_bitrate(const char *s);
bool pcf_is_gbr_5qi(uint8_t qi5);

typedef struct {
    char *dnn;
    bool has_ambr;
    pcf_ambr subs_ambr;
    g5c_json *subs_def_qos; /* may be NULL */
} pcf_session_info;

typedef struct {
    pcf_ambr ambr;
    pcf_qos qos;
    pcf_rule *rules;
    size_t nrules;
} pcf_resolved;

void pcf_session_info_free(pcf_session_info *s);
pcf_session_info pcf_session_info_dup(const pcf_session_info *s);
/* Resolve the policy for `s`; sub may be NULL. Deep copies, free with pcf_resolved_free. */
pcf_resolved pcf_resolve(const pcf_session_info *s, const pcf_policy *cfg, const pcf_policy *sub);
void pcf_resolved_free(pcf_resolved *r);
/* SmPolicyDecision (TS 29.512 5.6.2.4). Optional arrays with minItems 1 are omitted rather than sent empty. */
g5c_json *pcf_decision(const pcf_resolved *r);

/* ---- PCF state ---- */

typedef struct {
    char *id, *supi, *dnn;
    uint64_t pdu_session_id;
    char *notification_uri, *resource_uri;
    pcf_session_info info;
    g5c_json *context;  /* the original SmPolicyContextData */
    g5c_json *decision; /* the decision last sent to the SMF */
    uint64_t used;      /* octets reported by the SMF since the association began (usage monitoring) */
    bool throttled;     /* the threshold was reached: the throttle AMBR is part of every decision from now on */
} pcf_sm_session;

typedef struct {
    char *id, *supi;
    g5c_json *request;
} pcf_am_assoc;

/* A QoS reference of the configuration: what an AF's `qosReference` stands for (TS 29.514 4.2.2.32). */
typedef struct {
    char *name;
    uint8_t qi5;
    char *gbr_ul, *gbr_dl, *mbr_ul, *mbr_dl; /* NULL when absent; a GBR 5QI has gbr_ul and gbr_dl */
} pcf_qos_ref;

typedef struct pcf_app pcf_app; /* an application session context (Npcf_PolicyAuthorization), policyauth.c */
struct pcf_bsf;                 /* the registrar of the bindings at the BSF (Nbsf_Management), bsfreg.c */

typedef struct pcf {
    pcf_policy cfg;
    g5c_client *client;   /* not owned: UDR access and SMF notifications */
    char *udr;            /* UDR base URI (NULL when the UDR is discovered) */
    g5c_disc *udr_disc;   /* NRF discovery client used when no UDR address is configured */
    g5c_registry *metrics; /* not owned */
    char *admin_token;    /* NULL: admin API disabled */
    pthread_mutex_t mu;
    pcf_sm_session *sessions;
    size_t nsessions, capsessions;
    pcf_am_assoc *assocs;
    size_t nassocs, capassocs;
    void **owned;
    size_t nowned;
    pcf_qos_ref *qos_refs; /* policy_authorization.qos_references */
    size_t nqos_refs;
    pcf_app **apps;        /* application sessions, under mu */
    size_t napps, app_max;
    atomic_int notes_inflight; /* notifications to AFs on their way */
    struct pcf_bsf *bsf;       /* NULL: no binding is registered */
} pcf;

/* ---- the binding at the BSF (TS 29.521): registered when an SM policy association has a UE address, removed when it ends ---- */
/* bsf: { enabled, uri, fqdn, address } of the configuration; without `uri` the BSF is found through the NRF. 0 / -1 with err. */
int pcf_bsf_config(pcf *p, const g5c_json *cfg, g5c_nf *nf, char *err, size_t errcap);
void pcf_bsf_registered(pcf *p, const char *sm_id, const g5c_json *context); /* the SmPolicyContextData of the new association */
void pcf_bsf_gone(pcf *p, const char *sm_id);
size_t pcf_bsf_pending(pcf *p); /* jobs waiting for the thread that talks to the BSF */
void pcf_bsf_free(pcf *p);      /* drains the queue and stops the thread */

/* Takes ownership of *cfg (zeroed on return). */
void pcf_init(pcf *p, pcf_policy *cfg, g5c_client *client, const char *udr_uri, g5c_registry *metrics);
void pcf_destroy(pcf *p);
void pcf_track(pcf *p, void *owned);
size_t pcf_session_count(pcf *p);

g5c_router *pcf_router(pcf *p);
void pcf_smpolicy_routes(g5c_router *r, pcf *p);
void pcf_ampolicy_routes(g5c_router *r, pcf *p);
void pcf_admin_routes(g5c_router *r, pcf *p);
void pcf_policyauth_routes(g5c_router *r, pcf *p);
/* policy_authorization: {...} of the configuration; 0 / -1 with err */
int pcf_policyauth_config(pcf *p, const g5c_json *cfg, char *err, size_t errcap);
void pcf_apps_free(pcf *p);
/* The PCC rules the application sessions of an SM policy add to its decision (copies; free each with pcf_rule_release and the array with free). */
void pcf_app_rules(pcf *p, const char *sm_id, pcf_rule **out, size_t *n);
/* The PDU session of an SM policy has ended: its application sessions end and their AFs are told. */
void pcf_apps_of_sm_gone(pcf *p, const char *sm_id);
size_t pcf_app_session_count(pcf *p);
pcf_rule pcf_rule_copy(const pcf_rule *r);
void pcf_rule_release(pcf_rule *r);
/* pcf_repush with the number of updates the SMF refused or could not be given */
size_t pcf_repush_stats(pcf *p, const char *supi, size_t *rejected);
int pcf_admin_guard(void *ctx /* pcf* */, const g5c_req *req, g5c_resp *resp);

/* Recompute the policy of every active session of `supi` and push changes to the SMF (UpdateNotify) */
size_t pcf_repush(pcf *p, const char *supi);
/* Terminate an association from the PCF side. false when unknown. */
bool pcf_terminate(pcf *p, const char *id);

/* ---- policy store (UDR, TS 29.519) ---- */

typedef enum { PCF_STORE_OK = 0, PCF_STORE_NONE, PCF_STORE_ERROR } pcf_store_rc;
/* OK + *out filled, NONE when there are no overrides, ERROR on transport/status/malformed. */
pcf_store_rc pcf_store_get(pcf *p, const char *supi, pcf_policy *out);
bool pcf_store_put(pcf *p, const char *supi, const pcf_policy *pol);
/* 1 deleted, 0 none existed, -1 error */
int pcf_store_delete(pcf *p, const char *supi);

/* ---- configuration ---- */

/* Sections: udr {uri}, policy {...}, admin_token_file. Returns NULL with err on failure; free with pcf_destroy+free. */
pcf *pcf_from_config(const g5c_json *cfg, g5c_nf *nf, char *err, size_t errcap);

#endif
