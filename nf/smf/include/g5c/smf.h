/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5G core Session Management Function (SMF), Phase 4 (first half).
 *
 *  - nsmf-pdusession (TS 29.502): Create / Update / Release SM Context for the AMF, with the N1 SM and N2 SM parts carried as
 *    multipart/related binary bodies; the SMF pushes the PDU Session Establishment Accept and the N2 resource setup request to the
 *    AMF with Namf_Communication N1N2MessageTransfer (TS 29.518).
 *  - 5GSM (TS 24.501 clause 8.3, 9.11.4): establishment, release; QoS rules, flow descriptions, Session-AMBR, PDU address, extended PCO.
 *  - N4 (TS 29.244) towards the UPF: association, heartbeat, session establishment / modification / deletion with PCC rules mapped
 *    to PDR / FAR / QER (clause 5.2.1A and 5.4 for the SDF filter direction rule).
 *  - UE address management per DNN (IPv4 / IPv6 prefix pools), UPF selection by DNN and S-NSSAI.
 *  - SM subscription data from the UDM (Nudm_SDM), SMF registration (Nudm_UECM), SM policy from the PCF (Npcf_SMPolicyControl).
 * Not in this half: modification procedures, UPF restart recovery, persistence, NRF discovery of peers (peers are configured). */
#ifndef G5C_SMF_H
#define G5C_SMF_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "g5c/base.h"
#include "g5c/json.h"
#include "g5c/metrics.h"
#include "g5c/multipart.h"
#include "g5c/nfcore.h"
#include "g5c/pfcp_ie.h"
#include "g5c/sbi.h"

#define SMF_DEFAULT_QFI 1
#define SMF_MAX_FLOWS 16 /* QoS flows per session including the default one */
#define SMF_MAX_RULES 16 /* PCC rules per session */
#define SMF_MAX_FILTERS 8 /* flow descriptions per PCC rule */

/* ---- bit rates (TS 29.571 BitRate: "<number> bps|Kbps|Mbps|Gbps|Tbps") ---- */
bool smf_parse_bitrate(const char *s, uint64_t *kbps); /* rounds up to whole kbit/s */
char *smf_format_bitrate(uint64_t kbps);               /* the largest unit that represents it exactly; caller frees */

/* ---- UE address pools ---- */
typedef struct smf_pool smf_pool;
/* cidr4 / cidr6 may each be NULL. IPv4: /8../30, the first host address is reserved for the gateway */
smf_pool *smf_pool_new(const char *cidr4, const char *cidr6, char *err, size_t errcap);
void smf_pool_free(smf_pool *p);
int smf_pool_alloc4(smf_pool *p, uint8_t ip[4]);     /* 0, or -1 when the pool is exhausted or has no IPv4 range */
void smf_pool_release4(smf_pool *p, const uint8_t ip[4]);
int smf_pool_alloc6(smf_pool *p, uint8_t prefix[8]); /* the /64 prefix */
void smf_pool_release6(smf_pool *p, const uint8_t prefix[8]);
/* Mark a restored session's address as taken: false when it is outside the pool or already in use. */
bool smf_pool_reserve4(smf_pool *p, const uint8_t ip[4]);
bool smf_pool_reserve6(smf_pool *p, const uint8_t prefix[8]);
size_t smf_pool_used4(smf_pool *p);
size_t smf_pool_used6(smf_pool *p);
bool smf_pool_has4(const smf_pool *p);
bool smf_pool_has6(const smf_pool *p);

/* ---- policy model (from the PCF's SmPolicyDecision, TS 29.512 5.6.2.4) ---- */
typedef struct {
    uint8_t qfi, qi5, arp_prio;
    bool pre_cap, pre_vuln;
    bool has_prio_level;
    uint8_t prio_level;
    bool gbr; /* GBR flow: gbr_* and mbr_* are set */
    uint64_t gbr_ul, gbr_dl, mbr_ul, mbr_dl; /* kbit/s; the MBR of a non-GBR flow is 0 (not enforced per flow) */
    char *qos_id;                            /* NULL for the default flow */
    uint32_t qer_id;                         /* the QER enforcing this flow on the UPF (stable for the life of the flow) */
} smf_flow;

typedef struct {
    char *id;
    uint32_t precedence;
    uint8_t qfi;  /* flow the rule is bound to */
    uint8_t flow; /* index of that flow in smf_policy.flows */
    uint16_t pdr_ul, pdr_dl; /* PDR ids on the UPF; 0 when the rule has no filter in that direction */
    uint8_t qri;             /* QoS rule identifier on the NAS side (2..=255; 1 is the default rule) */
    char *filters[SMF_MAX_FILTERS];
    uint8_t dirs[SMF_MAX_FILTERS]; /* 0 bidirectional, 1 downlink, 2 uplink */
    size_t nfilters;
} smf_pcc;

typedef struct {
    uint64_t ambr_ul, ambr_dl; /* kbit/s; 0 = unlimited */
    uint64_t um_volume;        /* octets: the volume threshold of the PCF's usage monitoring decision (umDecs; 0: none) */
    smf_flow flows[SMF_MAX_FLOWS];
    size_t nflows; /* flows[0] is the default QoS flow (QFI 1) */
    smf_pcc rules[SMF_MAX_RULES];
    size_t nrules;
} smf_policy;

/* 0, or -1 with err. Rules whose QoS data is missing or whose flows are malformed are rejected as a whole. */
int smf_policy_from_decision(const g5c_json *decision, smf_policy *out, char *err, size_t errcap);
void smf_policy_free(smf_policy *p);
/* Give the flows of `np` the QFIs / QER ids and its rules the PDR ids they had in `old` when they are unchanged, and fresh unused ones otherwise */
void smf_policy_assign_ids(smf_policy *np, const smf_policy *old);

/* IPFilterRule (TS 29.212 5.4.2) subset used in SDF filters: "permit out <proto|ip> from <addr[/len]|any|assigned> [ports] to <...> [ports]". */
typedef struct {
    bool any_proto;
    uint8_t proto;
    bool src_any, dst_any; /* "any" and "assigned" both mean unconstrained for the NAS packet filter */
    uint8_t src[4], dst[4], src_plen, dst_plen;
    bool src_v6, dst_v6;
    bool has_sport, has_dport;
    uint16_t sport_lo, sport_hi, dport_lo, dport_hi;
} smf_ipfilter;
int smf_ipfilter_parse(const char *rule, smf_ipfilter *out); /* 0, or -1 (not an IPv4 permit-out rule this code understands) */

/* ---- 5GSM NAS (TS 24.501) ---- */
typedef struct {
    uint8_t psi, pti;
    uint8_t pdu_type;  /* 0: not given (use the subscribed default), else 1 IPv4, 2 IPv6, 3 IPv4v6 */
    uint8_t ssc_mode;  /* 0: not given */
    bool pco_dns4, pco_dns6, pco_mtu; /* what the UE asked for in the extended PCO */
    bool always_on_requested;
} smf_est_req;
/* Parse a PDU SESSION ESTABLISHMENT REQUEST; 0, or the 5GSM cause to reject with (e.g. 95/96/97 for malformed messages). */
int smf_gsm_parse_est_req(const uint8_t *nas, size_t len, smf_est_req *out);

typedef struct {
    uint8_t psi, pti;
    uint8_t pdu_type, ssc_mode;
    uint8_t ip4[4];
    uint8_t ifid[8]; /* IPv6 interface identifier for the link-local address */
    uint64_t ambr_ul, ambr_dl; /* kbit/s */
    const smf_policy *pol;
    bool include_flows; /* Authorized QoS flow descriptions for the non-default flows */
    bool has_snssai;
    uint8_t sst;
    bool has_sd;
    uint32_t sd;
    const char *dnn;
    smf_est_req req;
    uint8_t dns4[2][4];
    size_t ndns4;
    uint8_t dns6[2][16];
    size_t ndns6;
    uint16_t mtu;
    uint8_t cause; /* 0: none */
} smf_est_acc;
int smf_gsm_build_est_accept(const smf_est_acc *in, g5c_bytes *out);
int smf_gsm_build_est_reject(uint8_t psi, uint8_t pti, uint8_t cause, g5c_bytes *out);
int smf_gsm_build_release_cmd(uint8_t psi, uint8_t pti, uint8_t cause, g5c_bytes *out);
/* The message type of a plain 5GSM message and its PSI / PTI. 0, or -1. */
int smf_gsm_peek(const uint8_t *nas, size_t len, uint8_t *msg_type, uint8_t *psi, uint8_t *pti);
/* Session-AMBR IE value octets (clause 9.11.4.14, without IEI and length): 6 octets. */
void smf_gsm_session_ambr(uint64_t ul_kbps, uint64_t dl_kbps, uint8_t out[6]);
/* One QoS rule (clause 9.11.4.13, Figure 9.11.4.13.2) appended to out. */
int smf_gsm_put_qos_rule(g5c_bytes *out, uint8_t qri, bool dqr, uint8_t precedence, uint8_t qfi, const char *const *filters,
                         const uint8_t *dirs, size_t nfilters);
int smf_gsm_put_qos_flow_desc(g5c_bytes *out, const smf_flow *f);
/* PDU SESSION MODIFICATION COMMAND taking the UE from `oldp` to `newp` (ids assigned) */
int smf_gsm_build_mod_cmd(uint8_t psi, const smf_policy *oldp, const smf_policy *newp, g5c_bytes *out);

/* 5GSM cause values used (TS 24.501 Table 9.11.4.2.1) */
enum {
    SMF_5GSM_INSUFFICIENT_RESOURCES = 26,
    SMF_5GSM_INSUFFICIENT_RESOURCES_SLICE = 69,
    SMF_5GSM_MISSING_OR_UNKNOWN_DNN = 27,
    SMF_5GSM_UNKNOWN_PDU_SESSION_TYPE = 28,
    SMF_5GSM_USER_AUTH_FAILED = 29,
    SMF_5GSM_REQUEST_REJECTED_UNSPECIFIED = 31,
    SMF_5GSM_SERVICE_OPTION_NOT_SUPPORTED = 32,
    SMF_5GSM_REGULAR_DEACTIVATION = 36,
    SMF_5GSM_NETWORK_FAILURE = 38,
    SMF_5GSM_PTI_ALREADY_IN_USE = 35,
    SMF_5GSM_INVALID_PDU_SESSION_IDENTITY = 43,
    SMF_5GSM_INVALID_PTI = 81,
    SMF_5GSM_INVALID_MANDATORY_INFORMATION = 96,
    SMF_5GSM_MESSAGE_TYPE_NOT_IMPLEMENTED = 97,
    SMF_5GSM_PDU_TYPE_IPV4_ONLY = 50,
    SMF_5GSM_PDU_TYPE_IPV6_ONLY = 51
};

/* ---- N2 SM information (TS 38.413 9.3.4) ---- */
typedef struct {
    uint8_t pdu_type; /* 1 IPv4, 2 IPv6, 3 IPv4v6 */
    uint64_t ambr_ul, ambr_dl;
    uint8_t upf_ip4[4];
    uint32_t ul_teid;
    const smf_policy *pol;
} smf_n2_setup;
int smf_n2_build_setup_req(const smf_n2_setup *in, g5c_bytes *out);

typedef struct {
    uint8_t ip4[4];
    bool v4, v6;
    uint8_t ip6[16];
    uint32_t teid;
    uint8_t accepted[SMF_MAX_FLOWS];
    size_t naccepted;
} smf_an_tunnel;
int smf_n2_parse_setup_rsp(const uint8_t *buf, size_t len, smf_an_tunnel *out, char *err, size_t errcap);
/* PDUSessionResourceSetupUnsuccessfulTransfer / ...ReleaseCommand cause as "group:value" text (for logs). */
int smf_n2_parse_cause(const char *type_name, const uint8_t *buf, size_t len, char *out, size_t cap);
int smf_n2_build_release_cmd(g5c_bytes *out);
/* PDUSessionResourceModifyRequestTransfer from `oldp` to `newp`: 0 and the transfer, 1 when the gNB has nothing to learn, -1 on error. */
int smf_n2_build_mod_req(const smf_policy *oldp, const smf_policy *newp, g5c_bytes *out);
/* Handover (TS 38.413 9.3.4): the downlink tunnel the target gNB announces in a PathSwitchRequestTransfer / HandoverRequestAcknowledgeTransfer. */
int smf_n2_parse_path_switch(const uint8_t *buf, size_t len, smf_an_tunnel *out, char *err, size_t errcap);
int smf_n2_parse_ho_ack(const uint8_t *buf, size_t len, smf_an_tunnel *out, char *err, size_t errcap);
/* PathSwitchRequestAcknowledgeTransfer carrying the UPF's uplink tunnel; HandoverCommandTransfer (no data forwarding). */
int smf_n2_build_path_switch_ack(const uint8_t upf_ip4[4], uint32_t ul_teid, g5c_bytes *out);
int smf_n2_build_ho_command(g5c_bytes *out);

/* ---- N4: PFCP client towards the UPFs ---- */
typedef struct smf_upf smf_upf;
typedef struct smf_n4 smf_n4;

typedef struct {
    char name[32];
    char address[46];
    uint16_t port;
    char **dnns;
    size_t ndnns; /* empty: serves every DNN */
    struct {
        uint8_t sst;
        bool has_sd;
        uint32_t sd;
    } snssai[8];
    size_t nsnssai; /* empty: serves every slice */
    bool has_known_recovery; /* the Recovery Time Stamp this UPF had when the SMF last ran (restored state) */
    uint32_t known_recovery;
} smf_upf_cfg;

typedef struct {
    char address[46]; /* the local N4 address, advertised in the Node ID and F-SEIDs */
    uint16_t port;    /* 0: ephemeral (tests) */
    unsigned t1_ms;   /* request timeout */
    unsigned n1;      /* transmissions before giving up */
    unsigned hb_interval_s, hb_failures;
    unsigned lost_after_s; /* a UPF that stays unreachable this long is declared lost (0: never) */
    unsigned inject_drop_pct; /* `smf.inject.n4_drop_responses_percent`: test knob, PFCP responses thrown away on arrival */
    uint16_t gtpu_port;    /* UDP port for GTP-U towards the UPFs (control-plane user-plane traffic */
    smf_upf_cfg *upfs;
    size_t nupfs;
} smf_n4_cfg;

typedef struct {
    pfcp_header h;
    uint8_t body[2048];
    size_t blen;
} smf_n4_msg;

typedef struct {
    uint8_t ip4[4];
    uint16_t port;
} smf_peer;

/* Called from the receive / heartbeat threads: a UPF-initiated request (Session Report) or a change of a UPF's state. */
enum { SMF_UPF_DOWN = 0, SMF_UPF_LOST = 1, SMF_UPF_RESTART = 2 };
typedef struct {
    void *user;
    void (*on_upf_event)(void *user, smf_upf *u, int kind);
    /* Returns the PFCP cause for the response (Accepted, or Session Not Found) and the UP SEID to address it to. */
    uint8_t (*on_session_report)(void *user, smf_upf *u, uint64_t cp_seid, const uint8_t *body, size_t len, uint64_t *up_seid);
    /* A G-PDU the UPF forwarded to the control plane (IPv6 router solicitations). Called from the receive thread. */
    void (*on_gtpu)(void *user, uint32_t teid, const uint8_t *payload, size_t len, const smf_peer *from);
} smf_n4_hooks;

/* Opens the socket and builds the UPF table; nothing runs until smf_n4_start() (so restored state can be in place before the first association). */
smf_n4 *smf_n4_new(const smf_n4_cfg *cfg, const smf_n4_hooks *hooks, g5c_registry *metrics, char *err, size_t errcap);
int smf_n4_start(smf_n4 *n, char *err, size_t errcap);
void smf_n4_free(smf_n4 *n);
uint16_t smf_n4_port(const smf_n4 *n);
smf_upf *smf_n4_upf(smf_n4 *n, size_t i);
size_t smf_n4_nupfs(const smf_n4 *n);
const char *smf_upf_name(const smf_upf *u);
bool smf_upf_up(const smf_upf *u);
/* Pick a UPF that is associated and serves (dnn, snssai); round-robin among the candidates. NULL when none. */
smf_upf *smf_n4_select(smf_n4 *n, const char *dnn, uint8_t sst, bool has_sd, uint32_t sd);
/* Block until every configured UPF is associated or timeout_ms elapsed. True if all are up. */
bool smf_n4_wait_up(smf_n4 *n, unsigned timeout_ms);
uint64_t smf_n4_new_seid(smf_n4 *n);
/* The SMF's own Recovery Time Stamp (what it tells UPFs about its start) */
uint32_t smf_n4_recovery(const smf_n4 *n);
void smf_n4_set_recovery(smf_n4 *n, uint32_t ts);
/* Never hand out a CP SEID below `floor` (restored sessions keep theirs). */
void smf_n4_seed_seid(smf_n4 *n, uint64_t floor);
/* The Recovery Time Stamp the UPF reported; false until it has associated. */
bool smf_upf_recovery(const smf_upf *u, uint32_t *ts);
/* Restored state: the stamp the UPF reported in the previous run; a different one on association is a restart. Call before smf_n4_start(). */
void smf_upf_set_known_recovery(smf_upf *u, uint32_t ts);
/* Send a request and wait for its response (retransmitting per T1/N1). 0, or -1 on timeout / transport failure. */
/* One G-PDU to a UPF's N3 endpoint (the source address of the packets it forwarded to us). 0 / -1. */
int smf_n4_send_gtpu(smf_n4 *n, const smf_peer *to, uint32_t teid, const uint8_t *payload, size_t len);
int smf_n4_call(smf_n4 *n, smf_upf *u, uint8_t type, bool session, uint64_t seid, const uint8_t *body, size_t blen, smf_n4_msg *resp);
void smf_n4_local_addr(const smf_n4 *n, uint8_t ip4[4]);

/* ---- N4 rule generation: sessions -> PFCP ---- */
typedef struct {
    uint64_t cp_seid;
    uint8_t smf_ip4[4];
    const char *dnn;
    uint8_t pdu_type;
    bool has4, has6;
    uint8_t ue4[4], ue6[8]; /* ue6 is the /64 prefix */
    bool has_snssai;
    uint8_t sst;
    bool has_sd;
    uint32_t sd;
    uint32_t rs_teid; /* IPv6: the TEID the UPF puts on router solicitations it forwards to us */
    const smf_policy *pol;
    bool want_usage; /* a usage reporting rule (URR 1 */
} smf_n4_est;

/* Fixed ids: default PDRs 1 (uplink) and 2 (downlink), FAR 1 = uplink, FAR 2 = downlink, QER 1 = session AMBR, BAR 1. Flows */
enum { SMF_URR_SESSION = 1, SMF_URR_MONITOR = 2, SMF_FAR_UL = 1, SMF_FAR_DL = 2, SMF_FAR_CP = 3, SMF_QER_SESSION = 1, SMF_BAR = 1, SMF_PDR_UL_DEFAULT = 1, SMF_PDR_DL_DEFAULT = 2, SMF_PDR_CP = 3,
       SMF_PDR_RS = 4 };
int smf_n4_build_est(const smf_n4_est *in, uint8_t *out, size_t cap, size_t *len);

/* What a usage report of the UPF says (TS 29.244 8.2.40 Volume Measurement, 8.2.43 Duration Measurement). */
typedef struct {
    bool have;
    uint64_t total, ul, dl, total_pkts, ul_pkts, dl_pkts;
    uint32_t duration;
} smf_usage;
/* The first usage report of a response; 0 when there is one with a volume measurement, -1 when not (or damaged). */
int smf_n4_parse_usage(const smf_n4_msg *m, smf_usage *u);
/* The same for the usage report of URR `urr_id` (0: the first one); a session can have a charging URR (1) and a usage monitoring URR (2). */
int smf_n4_parse_usage_for(const uint8_t *body, size_t blen, uint32_t urr_id, smf_usage *u);
/* Update FAR 2 so downlink goes to the gNB tunnel (activate) or is buffered with a downlink-data report (deactivate). */
int smf_n4_build_mod_activate(const smf_an_tunnel *t, const char *dnn, uint8_t *out, size_t cap, size_t *len);
int smf_n4_build_mod_deactivate(uint8_t *out, size_t cap, size_t *len);
/* The N4 modification that takes a session from policy `oldp` to `newp` (ids already assigned) */
int smf_n4_build_policy_update(const smf_n4_est *ctx, const smf_policy *oldp, const smf_policy *newp, uint8_t *out, size_t cap, size_t *len, bool *changed);

typedef struct {
    bool ok;
    uint8_t cause;
    uint64_t up_seid;
    uint32_t ul_teid;
    uint8_t ul_ip4[4];
    bool has_fteid;
    uint32_t cp_teid; /* the UPF's TEID for packets from the control plane (IPv6 sessions): 0 when absent */
    uint16_t offending_ie;
} smf_n4_est_rsp;
int smf_n4_parse_est_rsp(const smf_n4_msg *m, smf_n4_est_rsp *out);
uint8_t smf_n4_cause_of(const smf_n4_msg *m); /* 0 when absent */

/* ---- SMF configuration and state ---- */
typedef struct {
    char *dnn;
    smf_pool *pool;
    uint8_t dns4[2][4];
    size_t ndns4;
    uint8_t dns6[2][16];
    size_t ndns6;
} smf_dnn_cfg;

typedef enum { SMF_S_CREATING = 0, SMF_S_ACTIVE, SMF_S_IDLE, SMF_S_RELEASING } smf_state;
enum { SMF_HO_NONE = 0, SMF_HO_PREPARING, SMF_HO_PREPARED };

typedef struct smf_sess {
    time_t t_est; /* wall clock time the session was established (the start of its CDR); 0 when unknown */
    char ref[37]; /* smContextRef */
    char supi[64];
    char dnn[64];
    uint8_t psi, pti;
    uint8_t sst;
    bool has_sd;
    uint32_t sd;
    uint8_t pdu_type, ssc_mode;
    uint8_t accept_cause; /* 5GSM cause to put in the accept when the requested PDU session type was narrowed */
    smf_est_req req;      /* what the UE asked for (PCO) */
    bool has4, has6;
    uint8_t ue4[4], ue6[8], ifid[8];
    g5c_json *plmn; /* servingNetwork as given by the AMF */
    struct smf *owner;
    int refs; /* the table plus in-flight handlers; guarded by smf.mu */
    bool dead;
    smf_dnn_cfg *dcfg;
    smf_upf *upf;
    uint64_t cp_seid, up_seid;
    uint32_t ul_teid;
    uint8_t ul_ip4[4];
    uint32_t rs_teid, cp_teid; /* IPv6: our TEID on forwarded router solicitations / the UPF's TEID for what we send back */
    bool an_set;
    uint8_t ho_state; /* SMF_HO_*: an N2 handover of this session is in progress */
    bool ho_an_set;
    smf_an_tunnel ho_an; /* the target gNB tunnel of a prepared handover */
    smf_an_tunnel an;
    smf_state state;
    smf_policy pol;
    g5c_json *decision; /* the SmPolicyDecision pol was built from (kept for persistence) */
    bool paging;        /* a downlink-data notification is being turned into a page */
    char *pcf_resource; /* SM policy association URI */
    char *chf_resource; /* charging data resource at the CHF; NULL without online charging */
    char *pcf_notif;
    char *amf_status_uri;
    char *amf_n1n2_url;
    char *serving_nf_id;
    char *smf_status_uri;
    bool udm_registered;
    bool release_pending_complete; /* a PDU session release command was sent to the UE; waiting for the complete */
    uint8_t release_pti;
    pthread_mutex_t mu;
    struct smf_sess *next;
    struct smf_sess *ix_ref_next, *ix_key_next; /* hash chains: by smContextRef, by (SUPI, PSI) */
} smf_sess;

#define SMF_IX 16384 /* buckets of each session index */
#define SMF_MAX_WORKERS 16 /* deferred-job threads (config smf.workers) */

typedef struct smf {
    smf_n4 *n4;
    g5c_client *client; /* not owned */
    g5c_registry *metrics;
    char *udm, *pcf, *amf; /* base URIs; NULL udm / pcf */
    g5c_disc *disc;        /* NRF discovery client for the UDM and PCF when their addresses are not configured */
    char *nrf;             /* NRF base URI for discovery; NULL: none */
    pthread_mutex_t cmu;   /* guards the discovery cache */
    struct {
        char id[40];
        char *root;
        double expires;
    } amf_cache[4];
    char *instance_id;
    char *self_uri; /* scheme://host:port of our SBI server, for Location headers */
    smf_dnn_cfg *dnns;
    size_t ndnns;
    uint16_t mtu;
    g5c_json *nrf_info; /* {"smfInfo": ...} merged into the NF profile registered with the NRF */
    smf_n4_cfg n4cfg;   /* parsed N4 settings; the socket is only opened by smf_start() */
    pthread_mutex_t mu; /* the session table */
    smf_sess *sessions;
    struct smf_sess **ix_ref, **ix_key; /* hash buckets (SMF_IX), allocated with the first session; guarded by mu */
    size_t nsessions;
    /* deferred work (N1N2 transfers after the 201) */
    pthread_t workers[SMF_MAX_WORKERS];
    unsigned nworkers, want_workers;
    pthread_mutex_t qmu;
    pthread_cond_t qcv;
    struct smf_job *jobs, *jobs_tail;
    bool stop;
    bool worker_started;
    int running;
    unsigned n1n2_delay_ms;
    unsigned persist_gap_ms; /* delay of the next state-file write (adapts to the cost of writing it) */
    unsigned release_guard_ms; /* how long a network-requested release may wait for the UE's complete */
    char *state_file;          /* where sessions are persisted (NULL: nowhere) */
    struct {
        char supi[32]; /* prefix of the SUPI */
        int status;    /* HTTP status the Create SM Context is answered with */
    } inject_reject[8]; /* `smf.inject.pdu_session_reject`: test knob (failure injection for RAN tests) */
    unsigned ninject_reject;
    unsigned inject_drop_pct; /* `smf.inject.n4_drop_responses_percent`, handed to the N4 client */
    struct {
        uint8_t sst;
        bool has_sd;
        uint32_t sd;
        unsigned max_sessions;
    } slice_limit[8]; /* `smf.slice_limits`: PDU sessions admitted per S-NSSAI (network slice admission control, TS 23.501 5.15.11) */
    unsigned nslice_limit;
    char *chf;                 /* `smf.chf.uri`: the CHF of Nchf_ConvergedCharging; NULL: no charging */
    unsigned chf_rating_group; /* `smf.chf.rating_group` */
    uint64_t chf_quota;        /* `smf.chf.quota_bytes`: the volume asked for */
    bool chf_required;         /* `smf.chf.required`: a session is refused when the CHF refuses or cannot be reached */
    char *cdr_path;            /* `smf.cdr.file`: one JSON record per released PDU session */
    pthread_mutex_t cdr_mu;
    uint64_t cdr_seq;
    pthread_mutex_t pmu;
    bool persist_queued;
    atomic_uint_fast64_t created, released, rejected;
} smf;

/* A Session Report Request with a usage report (report type USAR) of the monitoring URR: tells the PCF and applies its new decision (in a deferred job). */
uint8_t smf_usage_report(smf *s, smf_upf *u, uint64_t cp_seid, const uint8_t *body, size_t len, uint64_t *up_seid);

/* Charging data records (cdr.c). */
void smf_cdr_write(smf *s, const smf_sess *ss, const smf_usage *u, const char *cause);
char *smf_cdr_format(const smf *s, const smf_sess *ss, const smf_usage *u, const char *cause, time_t end, uint64_t seq); /* one line of JSON, heap */

/* Takes ownership of cfg contents it needs; returns NULL with err. */
smf *smf_from_config(const g5c_json *cfg, g5c_nf *nf, char *err, size_t errcap);
void smf_destroy(smf *s);
/* Open the N4 socket and start the association, heartbeat and deferred-work threads. 0, or -1 with err. */
int smf_start(smf *s, char *err, size_t errcap);
g5c_router *smf_router(smf *s);
size_t smf_session_count(smf *s);
smf_dnn_cfg *smf_find_dnn(smf *s, const char *dnn);
/* The listening port is only known after the SBI server starts: tell the SMF the URL it is reachable at. */
void smf_set_self_uri(smf *s, const char *uri);
/* Test hook: wait for the deferred-work queue to drain. */
void smf_drain(smf *s);

/* IPv6 router advertisement answering a router solicitation (RFC 4861): `rs` is the whole IPv6 packet */
int smf_ra_build(const uint8_t prefix[8], uint16_t mtu, const uint8_t *rs, size_t rslen, uint8_t *out, size_t cap, size_t *len);

/* Create / Update / Release SM context (sm.c) */
void smf_sm_routes(g5c_router *r, smf *s);

#endif
