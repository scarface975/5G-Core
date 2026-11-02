/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* SMF internals shared between its source files. */
#ifndef G5C_SMF_PRIV_H
#define G5C_SMF_PRIV_H

#include "g5c/smf.h"

/* ---- deferred work ---- */
typedef void (*smf_job_fn)(smf *s, void *arg);
void smf_defer(smf *s, smf_job_fn fn, void *arg);
void smf_defer_after(smf *s, smf_job_fn fn, void *arg, unsigned delay_ms);
/* Session persistence (persist.c): ask for the state file to be rewritten (coalesced), restore it at start-up. */
void smf_persist_request(smf *s);
/* start-up, between smf_n4_new() and smf_n4_start(): the UPFs' Recovery Time Stamps as of the last run, then the sessions themselves */
g5c_json *smf_state_read(smf *s);
void smf_state_apply_recovery(smf *s, const g5c_json *doc);
size_t smf_state_apply_sessions(smf *s, const g5c_json *doc);
/* UPF state changes and downlink-data notifications from the N4 threads (sm.c) */
void smf_upf_event(smf *s, smf_upf *u, int kind);
void smf_cp_packet(smf *s, uint32_t teid, const uint8_t *pl, size_t len, const smf_peer *from);
uint8_t smf_downlink_data(smf *s, smf_upf *u, uint64_t cp_seid, bool dldr, uint64_t *up_seid);

void smf_worker_start(smf *s);
void smf_worker_stop(smf *s);

/* ---- peers (peers.c) ---- */
enum { SMF_PEER_OK = 0, SMF_PEER_FAIL = -1 };

/* Subscribed session management data for (snssai, dnn): the dnnConfigurations entry, a copy for the caller to free */
int smf_udm_sm_data(smf *s, const char *supi, const g5c_json *serving_plmn, uint8_t sst, bool has_sd, uint32_t sd, const char *dnn,
                    g5c_json **dnn_cfg);
int smf_udm_register(smf *s, const smf_sess *ss, const g5c_json *serving_plmn);
int smf_udm_deregister(smf *s, const char *supi, uint8_t psi);

/* Create the SM policy association. On success *decision and *resource (the association URI) are the caller's. Returns 0, 403/404 etc */
int smf_pcf_create(smf *s, const smf_sess *ss, const g5c_json *dnn_cfg, const char *notif_uri, const g5c_json *serving_plmn, g5c_json **decision,
                   char **resource);
void smf_pcf_delete(smf *s, const char *resource);

/* Nnrf_NFDiscovery of the AMF instance `nf_instance_id` (what the AMF named as servingNfId) */
char *smf_nrf_amf_root(smf *s, const char *nf_instance_id);

/* N1N2MessageTransfer to the AMF (TS 29.518 5.2.2.3.1) with the given N1 SM message and N2 SM information (either may be empty) */
int smf_amf_n1n2(smf *s, const smf_sess *ss, const uint8_t *n1, size_t n1len, const char *n2_type, const uint8_t *n2, size_t n2len);
/* SmContextStatusNotification to the AMF (TS 29.502 5.2.2.5). */
void smf_amf_status_notify(smf *s, const char *uri, const char *status, const char *cause);

/* ---- sessions (sm.c) ---- */
void smf_persist_flush(smf *s); /* write the state file now when a delayed write is pending */
void smf_ix_add(smf *s, smf_sess *ss); /* index a session in the hash tables (caller holds s->mu) */
smf_sess *smf_sess_find_ref(smf *s, const char *ref); /* returned locked; unlock with smf_sess_unlock */
void smf_sess_unlock(smf_sess *ss);

#endif
