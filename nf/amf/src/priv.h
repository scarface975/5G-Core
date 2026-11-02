/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* AMF internals shared between the source files (not a public interface). */
#ifndef G5C_AMF_PRIV_H
#define G5C_AMF_PRIV_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "g5c/amf.h"
#include "g5c/crypto.h"
#include "g5c/metrics.h"
#include "g5c/multipart.h"
#include "g5c/nas.h"
#include "g5c/ngap.h"
#include "g5c/sbi.h"

#define AMF_MAX_GNB 128
#define AMF_MAX_TAI 16
#define AMF_MAX_SLICE 8
#define AMF_MAX_PSI 15
#define AMF_PPID_NGAP 60
#define AMF_LOG "g5c_amf"

/* ---- identities ------------------------------------------------------------------------------------------------------------------------- */

typedef struct {
    uint8_t plmn[3]; /* TS 24.008 encoding, the same octets NGAP carries */
    uint32_t tac;    /* 24 bits */
} amf_tai;

typedef struct {
    uint8_t region;
    uint16_t set; /* 10 bits */
    uint8_t pointer; /* 6 bits */
} amf_guami_id;

/* ---- configuration ----------------------------------------------------------------------------------------------------------------------- */

typedef struct {
    char *name;
    char mcc[4], mnc[4];
    uint8_t plmn[3];
    amf_guami_id id;
    char ngap_addr[64];
    uint16_t ngap_port;
    uint16_t capacity;
    amf_tai tai[AMF_MAX_TAI];
    size_t ntai;
    nas_snssai slices[AMF_MAX_SLICE];
    size_t nslices;
    uint8_t int_pref[3], enc_pref[3]; /* algorithm ids in order of preference; 0 = NIA0/NEA0 */
    size_t nint, nenc;
    char *ausf, *udm, *pcf, *smf, *nrf, *nssf; /* nssf: configured root, or NULL to discover it */
    bool use_nssf;                             /* slice selection by the NSSF (Nnssf_NSSelection); the local lists are the fallback */
    char *default_dnn;
    char *full_name, *short_name;
    bool send_names; /* send the network name and the time in a configuration update after the first registration */
    unsigned t3512, t3502, t3510, t3513, t3522, t3550, t3555, t3560, t3570; /* seconds (T3512 is what the UE is told) */
    unsigned paging_tries;
    unsigned workers;
    unsigned reach_grace; /* seconds added to T3512 for the mobile reachable timer */
    unsigned unauth_ue_max; /* connections that have not completed registration */
    struct {
        char supi[32]; /* prefix */
        uint8_t cause; /* 5GMM cause of the Registration Reject */
    } inject_reject[8]; /* `amf.inject.registration_reject`: failure injection for RAN tests */
    unsigned ninject_reject, inject_delay_ms; /* `amf.inject.accept_delay_ms`: the Registration Accept is held back this long */
    char *state_file;
    bool allow_null_integrity; /* NIA0 for emergency-less UEs: off by default */
} amf_cfg;

/* ---- security context -------------------------------------------------------------------------------------------------------------------- */

typedef struct {
    bool valid;
    uint8_t ngksi;
    uint8_t kamf[32];
    uint8_t abba[2];
    uint8_t int_alg, enc_alg;
    uint8_t knas_int[16], knas_enc[16];
    uint32_t ul_count; /* next uplink count we expect */
    uint32_t dl_count; /* next downlink count we use */
    uint32_t kgnb_count; /* uplink count the current KgNB was derived with */
    uint8_t kgnb[32];
    uint8_t nh[32];
    uint8_t ncc;
    bool nh_valid;
} amf_sec;

/* ---- timers ---------------------------------------------------------------------------------------------------------------------------- */

typedef struct {
    uint32_t gen;
    uint8_t tries;
    bool on;
} amf_tslot;

/* connection timers */
enum { CT_AUTH, CT_IDENT, CT_SMC, CT_REGACC, CT_CFG, CT_DEREG, CT_RELCMD, CT_HOPREP, CT_HOALL, CT_COUNT };
/* UE timers */
enum { UT_PAGING, UT_REACH, UT_IMPLICIT, UT_COUNT };
/* timer targets */
enum { TT_CONN = 1, TT_UE = 2 };

typedef struct amf_ue amf_ue;
typedef struct amf_conn amf_conn;

/* ---- UE context -------------------------------------------------------------------------------------------------------------------------- */

typedef enum { MM_DEREGISTERED = 0, MM_REGISTERED = 1 } amf_mm;
typedef enum { CM_IDLE = 0, CM_CONNECTED = 1 } amf_cm;

typedef struct {
    bool used;
    char sm_url[320];
    char dnn[64];
    bool has_snssai;
    nas_snssai snssai;
    bool up_active;   /* N2 resources are established on the gNB */
    bool n2_wait;     /* an N2 request for it is outstanding */
    bool releasing;   /* a release is in progress */
} amf_pdu;

typedef struct amf_pend {
    struct amf_pend *next;
    uint8_t psi;
    uint8_t *n1;
    size_t n1len;
    uint8_t *n2;
    size_t n2len;
    char n2type[32];
    bool has_snssai;
    nas_snssai snssai;
    char notif_uri[256]; /* n1n2FailureTxfNotifURI */
} amf_pend;

struct amf_ue {
    amf *a;
    pthread_mutex_t mu;
    uint64_t uid;
    int refs;     /* guarded by a->tmu */
    bool removed; /* no longer in the tables */
    char supi[40];
    char pei[32];
    uint32_t tmsi;     /* the 5G-TMSI of the current 5G-GUTI; 0 when none */
    uint32_t tmsi_new; /* allocated by a running registration, 0 when none */
    _Atomic amf_mm mm; /* read by the gauges without the UE mutex */
    _Atomic amf_cm cm;
    amf_conn *conn;    /* the N2 association while CM-CONNECTED */
    amf_conn *ho_conn; /* the target leg during N2 handover */
    amf_sec sec;
    amf_sec sec_new;
    bool sec_new_valid;
    uint8_t ue_cap[8]; /* the UE security capability IE value */
    size_t ue_cap_len;
    uint8_t ue_cap5g_ea, ue_cap5g_ia;
    nas_snssai allowed[AMF_MAX_SLICE];
    size_t nallowed;
    nas_snssai subscribed[AMF_MAX_SLICE];
    size_t nsubscribed;
    size_t ndefault; /* the first ndefault entries of subscribed[] are the default S-NSSAIs */
    bool dereg_pending;   /* a network-initiated de-registration waits for the UE to be reachable */
    bool dereg_rereg;
    uint64_t ambr_ul, ambr_dl; /* bit/s */
    amf_tai loc;
    bool has_loc;
    amf_tai tai_list[AMF_MAX_TAI];
    size_t ntai;
    uint8_t reg_type;
    char pcf_url[256];
    char ausf_url[320]; /* the AUSF resource of the current authentication result, deleted with the registration (TS 29.509 5.2.2.2.5, 5.2.2.2.6) */
    bool uecm;          /* registered in the UDM */
    bool sdm_subscribed;
    char sdm_sub_id[40]; /* subscriptionId the UDM gave (deleted with the context) */
    amf_pdu pdu[AMF_MAX_PSI + 1];
    amf_pend *pend;
    amf_tslot ut[UT_COUNT];
    bool cfg_pending;       /* a configuration update waits for the UE to become reachable */
    bool cfg_new_guti;
    uint8_t *radio_cap;
    size_t radio_cap_len;
    bool imeisv_requested;
    int64_t last_active_ms;
    struct amf_ue *next_all, *prev_all;
};

/* ---- N2 association of one UE ("RAN UE") -------------------------------------------------------------------------------------------------- */

typedef struct amf_ev {
    struct amf_ev *next;
    int kind; /* EV_NGAP, EV_LOST, EV_TIMER */
    uint32_t rx_gnb, rx_gen;
    uint16_t rx_stream;
    int tkind;
    uint32_t tgen;
    g5c_json *pdu;
    uint32_t gen;
} amf_ev;

enum { EV_NGAP = 1, EV_LOST = 2, EV_TIMER = 3 };

typedef enum { PR_NONE = 0, PR_IDENTITY, PR_AUTH, PR_SMC, PR_REGACCEPT, PR_SERVICE, PR_CFG, PR_DEREG } amf_proc;

struct amf_conn {
    amf *a;
    char trace[33]; /* the trace id of this connection (see g5c_trace_enter) */
    uint64_t amf_id;
    uint32_t ran_id;
    uint32_t gnb, gnb_gen;
    uint16_t stream;
    amf_ue *ue;       /* NULL until the UE is identified; written under the UE mutex and a->tmu */
    amf_ue *held;     /* the UE whose mutex the running handler holds */
    int refs;         /* guarded by a->tmu */
    bool closed;
    bool is_target;   /* the target leg of an N2 handover */
    pthread_mutex_t mu;
    amf_ev *qh, *qt;
    bool running;
    amf_tai tai;
    bool has_tai;
    char cell[12]; /* NR cell identity as hex (up to 11 digits) */
    bool has_cgi;
    uint8_t rrc_cause;
    uint32_t kgnb_ul;        /* uplink NAS COUNT the KgNB for this connection is derived with */
    uint32_t rx_gnb, rx_gen; /* origin of the message being handled (a path switch comes from another gNB) */
    uint16_t rx_stream;
    bool dereg_reregister_flag;
    bool pre_auth;   /* counted in amf.npreauth until the UE is authenticated (or the connection goes) */
    bool sec_active; /* the procedure runs under an established security context (a reject is then protected) */
    bool ue_ctx_requested;

    amf_proc proc;
    amf_tslot t[CT_COUNT];
    /* the initial NAS message being processed */
    uint8_t *init_nas;
    size_t init_len;
    uint8_t init_kind;      /* NAS message type of the initial message */
    bool init_plain;        /* the Registration Request arrived without security protection */
    uint8_t reg_type;
    bool follow_on;
    uint8_t ngksi_ue;
    nas_mobile_identity ident;
    char suci[200];
    bool have_suci;
    char known_supi[40];    /* resolved from a GUTI we know */
    uint8_t ue_cap[8];
    size_t ue_cap_len;
    /* authentication */
    char auth_url[320];
    uint8_t rand[16], hxres[16], autn[16];
    char auth_id[200];      /* supiOrSuci used for the run */
    uint8_t auth_syncs;
    uint8_t auth_mac_fail;
    uint8_t smc_ngksi;
    bool auth_eap;          /* the authentication of this run is EAP-AKA' (auth_url is the eap-session resource) */
    uint8_t eap_succ[8];    /* the EAP-Success the AUSF returned, for the Security Mode Command */
    size_t eap_succ_len;
    /* retransmission */
    uint8_t *last_nas;
    size_t last_len;
    uint8_t last_sht;
    /* release */
    bool rel_sent;
    uint8_t rel_then;       /* REL_* */
    uint32_t cause_group, cause_val;
    bool ics_sent;
    bool ics_done;
    bool svc_req;           /* the procedure is a service request */
    bool reg_complete_wait;
    uint8_t svc_type;
    uint8_t *reg_status_pdu; size_t reg_status_len; /* UE's PDU session status */
    bool has_psi_status;
    uint16_t psi_status;
    bool has_uplink_data;
    uint16_t uplink_data;
    /* handover (on the source leg) */
    uint8_t ho_state;       /* HO_* */
    uint8_t ho_type;
    uint64_t ho_peer_id;    /* the other leg's AMF-UE-NGAP-ID */
    uint8_t *ho_container;  /* source to target transparent container */
    size_t ho_container_len;
    struct amf_conn *next_all, *prev_all;
};

enum { REL_NONE = 0, REL_DELETE_UE = 1, REL_KEEP = 2, REL_REREGISTER = 3 };
enum { HO_NONE = 0, HO_PREPARING, HO_PREPARED, HO_COMPLETING };

/* ---- gNB ------------------------------------------------------------------------------------------------------------------------------- */

typedef struct {
    bool used;
    int fd;
    uint32_t gen;
    pthread_mutex_t smu; /* serialises sends against the close */
    char peer[64];
    bool setup;
    char name[64];
    uint8_t node_plmn[3];
    uint32_t gnb_id;
    uint8_t gnb_id_bits;
    bool is_ng_enb;
    amf_tai tas[AMF_MAX_TAI];
    size_t ntas;
    unsigned nconns;
    uint8_t *rxbuf;
    size_t rxlen;
} amf_gnb;

/* ---- hash maps ------------------------------------------------------------------------------------------------------------------------ */

typedef struct amf_map amf_map;
amf_map *amap_new(void);
void amap_free(amf_map *m);
void *amap_get(const amf_map *m, uint64_t key);
void amap_put(amf_map *m, uint64_t key, void *val);
void amap_del(amf_map *m, uint64_t key);
size_t amap_count(const amf_map *m);
typedef struct amf_smap amf_smap;
amf_smap *smap_new(void);
void smap_free(amf_smap *m);
void *smap_get(const amf_smap *m, const char *key);
void smap_put(amf_smap *m, const char *key, void *val);
void smap_del(amf_smap *m, const char *key);

/* ---- event exposure -------------------------------------------------------------------------------------------------------------------- */

typedef struct amf_evsub {
    struct amf_evsub *next;
    char id[40];
    char notif_uri[256];
    char corr[96];
    char nf_id[48];
    char supi[40]; /* empty: any UE */
    bool any;
    bool types[8]; /* index = EVT_* */
    bool one_shot;
} amf_evsub;
enum { EVT_REG_STATE, EVT_CONNECTIVITY, EVT_LOCATION, EVT_REACHABILITY, EVT_LOSS, EVT_COUNT };

/* ---- timers and tasks --------------------------------------------------------------------------------------------------------------------- */

typedef void (*amf_task_fn)(amf *a, void *arg);
typedef struct amf_task {
    struct amf_task *next;
    amf_task_fn fn;
    void *arg;
} amf_task;

typedef struct {
    double due;
    uint8_t target;
    uint8_t kind;
    uint64_t id;
    uint32_t gen;
} amf_tmr;

/* ---- the AMF -------------------------------------------------------------------------------------------------------------------------- */

struct amf {
    amf_cfg cfg;
    g5c_nf *nf;
    g5c_client *client;
    g5c_registry *metrics;
    char instance_id[40];
    char *self_uri;
    char snn[64];

    pthread_mutex_t tmu; /* the tables and reference counts */
    amf_map *conns_by_id, *ues_by_uid, *ues_by_tmsi;
    amf_smap *ues_by_supi;
    amf_ue *ues;
    amf_conn *conns;
    size_t nues, nconns, npreauth; /* npreauth: connections that have not (yet) passed authentication - the flood limit counts these only */
    uint64_t next_amf_id, next_uid;
    amf_gnb gnbs[AMF_MAX_GNB];

    int lfd, epfd, wakefd;
    uint16_t bound_port;
    pthread_t reader;
    bool reader_on;

    pthread_mutex_t qmu;
    pthread_cond_t qcv;
    amf_task *qh, *qt;
    unsigned active;
    pthread_t *workers;
    unsigned nworkers;
    atomic_bool stop;

    pthread_mutex_t tm_mu;
    pthread_cond_t tm_cv;
    amf_tmr *tmrs;
    size_t ntmrs, captmrs;
    pthread_t tm_th;
    bool tm_on;

    g5c_disc *nrf_disc; /* discovery client when an NRF is configured */

    pthread_mutex_t emu;
    amf_evsub *subs;
    uint64_t next_sub;

    pthread_mutex_t pmu;
    bool persist_dirty;
    unsigned persist_gap_ms; /* delay of the next state-file write (adapts to the cost of writing it) */

    atomic_uint_fast64_t st_registrations, st_auth_ok, st_auth_fail, st_dereg, st_service, st_paging, st_handover, st_pathswitch, st_release;
};

/* ---- util.c --------------------------------------------------------------------------------------------------------------------------- */

void amf_count(amf *a, const char *name, const char *help, const char *lk, const char *lv);
void amf_tai_to_json(const amf_tai *t, g5c_json *obj_plmn_parent, const char *key); /* {"plmnId":{mcc,mnc},"tac":"hex"} under key */
char *amf_hex(const uint8_t *p, size_t n);
int amf_tai_eq(const amf_tai *a, const amf_tai *b);
void amf_snssai_json(const nas_snssai *s, g5c_json *parent, const char *key); /* {"sst":n,"sd":"hex"} */
bool amf_snssai_from_json(const g5c_json *j, nas_snssai *out);
bool amf_snssai_eq(const nas_snssai *a, const nas_snssai *b);
bool amf_snssai_in(const nas_snssai *list, size_t n, const nas_snssai *s);
void amf_supi_digits(const char *supi, char *out, size_t cap);
uint32_t amf_get_be32(const uint8_t *p);
void amf_put_be32(uint8_t *p, uint32_t v);

/* ---- config / lifecycle (amf.c) --------------------------------------------------------------------------------------------------- */

void amf_post(amf *a, amf_task_fn fn, void *arg);
void amf_timer_start(amf *a, unsigned ms, int target, int kind, uint64_t id, uint32_t gen);
void amf_drain_tasks(amf *a);
int amf_workers_start(amf *a);
void amf_workers_stop(amf *a);
amf_ue *amf_ue_find_supi(amf *a, const char *supi);   /* referenced; release with amf_ue_unref */
amf_ue *amf_ue_find_tmsi(amf *a, uint32_t tmsi);
amf_ue *amf_ue_find_uid(amf *a, uint64_t uid);
amf_ue *amf_ue_get_or_create(amf *a, const char *supi);
void amf_ue_ref(amf_ue *u);
void amf_ue_unref(amf_ue *u);
void amf_ue_remove(amf_ue *u);         /* takes it out of the tables (u->mu held) */
uint32_t amf_ue_alloc_tmsi(amf *a, amf_ue *u);
void amf_ue_set_tmsi(amf_ue *u, uint32_t tmsi);
amf_conn *amf_conn_new(amf *a, uint32_t gnb, uint16_t stream, uint32_t ran_id);
amf_conn *amf_conn_find(amf *a, uint64_t amf_id); /* referenced */
void amf_conn_ref(amf_conn *c);
void amf_conn_unref(amf_conn *c);
void amf_conn_unlink(amf_conn *c);    /* out of the table */
void amf_conn_authenticated(amf_conn *c); /* leaves the unauthenticated population (idempotent) */
void amf_conn_post(amf_conn *c, int kind, g5c_json *pdu);
void amf_conn_post_rx(amf_conn *c, g5c_json *pdu, uint32_t gnb, uint32_t gen, uint16_t stream);
void amf_conn_post_timer(amf_conn *c, int kind, uint32_t gen);
void ngap_conn_timer(amf_conn *c, int kind, uint32_t gen);
void amf_gauges(amf *a);

/* ---- sctp.c ---------------------------------------------------------------------------------------------------------------------------- */

int amf_sctp_start(amf *a, char *err, size_t cap);
void amf_sctp_stop(amf *a);
int amf_gnb_send(amf *a, uint32_t gnb, uint32_t gen, uint16_t stream, const uint8_t *buf, size_t len);
int amf_send_pdu(amf *a, uint32_t gnb, uint32_t gen, uint16_t stream, const g5c_json *pdu);
void amf_gnb_drop(amf *a, uint32_t gnb);

/* ---- ngap.c (builders and N2 procedures) -------------------------------------------------------------------------------------------- */

g5c_json *ng_pdu_new(const char *kind, int proc, const char *crit);
g5c_json *ng_ie(g5c_json *pdu, int id, const char *crit, g5c_json *value);
g5c_json *ng_msg_ies(g5c_json *pdu); /* the protocolIEs array */
const g5c_json *ng_get(const g5c_json *pdu, int id);
g5c_json *ng_bits(const uint8_t *p, size_t nbits);
g5c_json *ng_plmn(const uint8_t plmn[3]);
g5c_json *ng_tai_json(const amf_tai *t);
g5c_json *ng_guami(const amf *a);
g5c_json *ng_snssai_json(const nas_snssai *s);
g5c_json *ng_allowed_nssai(const nas_snssai *l, size_t n);
g5c_json *ng_cause(const char *group, const char *value);
bool ng_tai_from_json(const g5c_json *tai, amf_tai *out);
bool ng_snssai_from_json(const g5c_json *s, nas_snssai *out);
int ng_uli_parse(const g5c_json *uli, amf_tai *tai, char cell[12]);
void ngap_reader_dispatch(amf *a, uint32_t gnb, uint32_t gen, uint16_t stream, const uint8_t *buf, size_t len);
void ngap_gnb_lost(amf *a, uint32_t gnb);
void ngap_conn_event(amf_conn *c, g5c_json *pdu);
void ngap_conn_lost(amf_conn *c);
int ng_send_error_indication(amf *a, uint32_t gnb, uint32_t gen, uint16_t stream, bool have_ids, uint64_t amf_id, uint32_t ran_id, const char *group,
                             const char *cause);
int conn_send_nas(amf_conn *c, const uint8_t *nas, size_t len);
int conn_send_ics(amf_conn *c, const uint8_t *nas, size_t len, amf_ue *u, g5c_json *pdu_list);
int conn_send_release_cmd(amf_conn *c, const char *group, const char *cause, uint8_t then);
int conn_send_pdu_setup(amf_conn *c, amf_ue *u, g5c_json *list, const uint8_t *nas, size_t nas_len);
int conn_send_pdu_modify(amf_conn *c, g5c_json *list);
int conn_send_pdu_release(amf_conn *c, g5c_json *list, const uint8_t *nas, size_t nas_len);
void amf_page_ue(amf *a, amf_ue *u);
g5c_json *ng_ue_sec_caps(const amf_ue *u);

/* ---- sec.c ------------------------------------------------------------------------------------------------------------------------------- */

int sec_select_algs(const amf *a, const uint8_t *ue_cap, size_t len, uint8_t *int_alg, uint8_t *enc_alg);
void sec_derive_nas_keys(amf_sec *s);
void sec_new_context(amf_sec *s, const uint8_t kamf[32], uint8_t ngksi, const uint8_t abba[2]);
void sec_derive_kgnb(amf_sec *s, uint32_t ul_count);
void sec_next_hop(amf_sec *s);
void sec_ctx_view(const amf_sec *s, nas_sec_ctx *out);
/* Protect a downlink message with the current context (SHT 2) or the provisional one (SHT 3 / 4); advances the DL count. */
int sec_protect_dl(amf_sec *s, uint8_t sht, const uint8_t *plain, size_t len, g5c_bytes *out);
/* Verify and open an uplink protected message; on success *count_out is the count it carried. */
int sec_open_ul(amf_sec *s, const nas_protected *p, g5c_bytes *plain, uint32_t *count_out, bool commit);
void sec_clear(amf_sec *s);

/* ---- sbi_out.c --------------------------------------------------------------------------------------------------------------------------- */

#define AMF_EAP_MAX 1100 /* the EAP MTU (RFC 3748 3) with room */

typedef struct {
    char ctx_url[320];
    uint8_t rand[16], autn[16], hxres[16];
    bool eap;                       /* EAP-AKA': ctx_url is the eap-session resource, eap_pkt the EAP-Request/AKA'-Challenge */
    uint8_t eap_pkt[AMF_EAP_MAX];
    size_t eap_len;
} amf_authv;

/* the AUSF's answer to a POST of an EAP packet (TS 29.509 6.1.6.2.7) */
typedef struct {
    uint8_t pkt[AMF_EAP_MAX];
    size_t len;
    int result; /* 0 ongoing, 1 success, -1 failure */
    char supi[40];
    uint8_t kseaf[32];
    char next_url[320]; /* the eap-session link of an ongoing exchange (empty: the same resource) */
} amf_eapr;

int amf_nssf_registration(amf *a, const amf_ue *u, const amf_tai *tai, const nas_snssai *req, size_t nreq, nas_snssai *allowed, size_t *nallowed, nas_snssai *rejected,
                          size_t *nrej); /* 0 answer filled, 1 the NSSF refused every slice, -1 no answer */
int amf_nssf_pdu_session(amf *a, const nas_snssai *sn, const amf_tai *tai); /* 0 the slice is available (and the NSI is known), 1 the NSSF refused it, -1 no answer */
char *amf_nf_root(amf *a, const char *nf_type, const char *service, const nas_snssai *s, const char *dnn); /* caller frees; NULL if none */
int amf_ausf_start(amf *a, const char *id, const uint8_t *resync_rand, const uint8_t *auts, amf_authv *out, int *http);
/* POST the EAP packet of the UE (NULL, 0: nothing came from the UE) to the eap-session resource; 0 and *out when the AUSF answered 200 with a usable body */
int amf_ausf_eap(amf *a, const char *url, const uint8_t *pkt, size_t n, amf_eapr *out, int *http);
/* DELETE the resource of an authentication result at the AUSF; best effort */
void amf_ausf_remove(amf *a, const char *url);
int amf_ausf_confirm(amf *a, const char *ctx_url, const uint8_t res_star[16], char *supi, size_t supi_cap, uint8_t kseaf[32], bool *success, int *http);
int amf_udm_register(amf *a, amf_ue *u);
void amf_udm_deregister(amf *a, amf_ue *u);
int amf_udm_am_data(amf *a, amf_ue *u);
void amf_udm_sdm_subscribe(amf *a, amf_ue *u);
void amf_udm_sdm_unsubscribe(amf *a, amf_ue *u); /* Nudm_SDM Unsubscribe; a no-op without a subscription */
int amf_pcf_create(amf *a, amf_ue *u);
void amf_pcf_delete(amf *a, amf_ue *u);
bool amf_parse_bitrate(const char *s, uint64_t *out);

/* ---- session.c (5GSM relay, SMF client, N1N2) ------------------------------------------------------------------------------------------ */

typedef struct {
    int http; /* the HTTP status, or a negative g5c_sbi_err */
    g5c_resp raw;
    bool have_raw;
    g5c_json *json;
    g5c_mp mp;
    bool is_mp;
    const g5c_mp_part *n1, *n2;
    char location[320];
} amf_smresp;

/* 5GMM cause values (TS 24.501 table 9.11.3.2.1) */
enum {
    MM_CAUSE_ILLEGAL_UE = 3,
    MM_CAUSE_PEI_NOT_ACCEPTED = 5,
    MM_CAUSE_5GS_NOT_ALLOWED = 7,
    MM_CAUSE_UE_ID_CANNOT_BE_DERIVED = 9,
    MM_CAUSE_IMPLICITLY_DEREGISTERED = 10,
    MM_CAUSE_PLMN_NOT_ALLOWED = 11,
    MM_CAUSE_TA_NOT_ALLOWED = 12,
    MM_CAUSE_MAC_FAILURE = 20,
    MM_CAUSE_SYNCH_FAILURE = 21,
    MM_CAUSE_UE_SECURITY_CAP_MISMATCH = 23,
    MM_CAUSE_NO_SLICES_AVAILABLE = 62,
    MM_CAUSE_PAYLOAD_NOT_FORWARDED = 90,
    MM_CAUSE_INVALID_MANDATORY_INFO = 96,
    MM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED = 111
};

void amf_smresp_free(amf_smresp *r);
int amf_ul_nas_transport(amf_conn *c, amf_ue *u, const nas_msg *m);
int amf_sm_update(amf *a, amf_ue *u, uint8_t psi, const g5c_json *data, const uint8_t *n1, size_t n1len, const char *n2_type, const uint8_t *n2,
                  size_t n2len, amf_smresp *out);
int amf_sm_release(amf *a, amf_ue *u, uint8_t psi, const char *cause);
void amf_sm_release_all(amf *a, amf_ue *u, const char *cause);
int amf_sm_deactivate_all(amf *a, amf_ue *u);
void amf_pdu_reset(amf_pdu *p);
void amf_location_json(const amf_conn *c, const amf_ue *u, g5c_json *parent);
unsigned amf_pdu_count(const amf_ue *u);
void amf_pend_free(amf_pend *p);
void amf_pend_clear(amf_ue *u);
int amf_psi_status_reconcile(amf *a, amf_ue *u, uint16_t ue_status);
uint16_t amf_psi_bitmap(const amf_ue *u);
void amf_n1n2_routes(g5c_router *r, amf *a);
int amf_n1n2_deliver_pending(amf_conn *c, amf_ue *u, bool in_ics, g5c_json *pdu_list, g5c_json **ics_list_out);
void amf_handle_pdu_setup_response(amf_conn *c, amf_ue *u, const g5c_json *msg, bool failed_only);
void amf_handle_pdu_modify_response(amf_conn *c, amf_ue *u, const g5c_json *msg);
void amf_handle_pdu_release_response(amf_conn *c, amf_ue *u, const g5c_json *msg);
void amf_handle_pdu_notify(amf_conn *c, amf_ue *u, const g5c_json *msg);
void amf_handle_ics_response(amf_conn *c, amf_ue *u, const g5c_json *msg);
void amf_notify_n1n2_failure(amf *a, const char *uri, const char *cause);

/* ---- gmm.c (5GMM procedures) --------------------------------------------------------------------------------------------------------- */

void gmm_initial_ue(amf_conn *c, const uint8_t *nas, size_t len, const g5c_json *msg);
void gmm_uplink_nas(amf_conn *c, const uint8_t *nas, size_t len);
void gmm_timer(amf *a, int target, int kind, uint64_t id, uint32_t gen);
void gmm_conn_released(amf_conn *c);        /* the UE context release completed */
void gmm_conn_gone(amf_conn *c);            /* the association is gone without a release procedure */
amf_ue *conn_ue_ref(amf_conn *c);
void gmm_conn_timer(amf_conn *c, int kind, uint32_t gen);
int gmm_protect_dl(amf_ue *u, const uint8_t *plain, size_t len, g5c_bytes *out);
int amf_sm_activate(amf *a, amf_ue *u, uint16_t want, g5c_json **list, uint16_t *react);
void amf_ue_gc(amf_ue *u);
void gmm_release_request(amf_conn *c, const char *group, const char *cause); /* from the gNB */
int gmm_start_dereg(amf_ue *u, bool reregister);
int gmm_start_config_update(amf_ue *u, bool new_guti);
void gmm_page_failed(amf *a, amf_ue *u);
void gmm_page_start(amf_ue *u);
void gmm_ue_idle(amf *a, amf_ue *u);
void gmm_conn_started_service(amf_conn *c, amf_ue *u);
void gmm_reg_status_send(amf_conn *c, amf_ue *u, uint8_t cause);
void conn_timer_start(amf_conn *c, int kind, unsigned secs);
void conn_timer_stop(amf_conn *c, int kind);
void ue_timer_start(amf_ue *u, int kind, unsigned secs);
void ue_timer_stop(amf_ue *u, int kind);
void conn_clear_proc(amf_conn *c);
void gmm_send_plain(amf_conn *c, const uint8_t *nas, size_t len);
int gmm_send_dl(amf_conn *c, amf_ue *u, const uint8_t *plain, size_t len);
int gmm_send_dl_ex(amf_conn *c, amf_ue *u, const uint8_t *plain, size_t len, bool new_ctx);
void gmm_event(amf *a, amf_ue *u, int type, const char *state);
void conn_bind_ue(amf_conn *c, amf_ue *u);
void conn_unbind_ue(amf_conn *c);
void ue_detach_conn(amf_ue *u);

/* ---- ho.c (path switch, N2 handover) ----------------------------------------------------------------------------------------------- */

void ho_path_switch(amf_conn *c, const g5c_json *msg);
void ho_required(amf_conn *c, amf_ue *u, const g5c_json *msg);
void ho_request_ack(amf_conn *c, amf_ue *u, const g5c_json *msg);
void ho_request_failure(amf_conn *c, amf_ue *u, const g5c_json *msg);
void ho_notify(amf_conn *c, amf_ue *u, const g5c_json *msg);
void ho_cancel(amf_conn *c, amf_ue *u, const g5c_json *msg);
void ho_ran_status_transfer(amf_conn *c, amf_ue *u, const g5c_json *msg);
void ho_timer(amf *a, amf_conn *c, int kind);
void ho_abort(amf_conn *c, amf_ue *u, const char *cause);

/* ---- events.c (Namf_EventExposure) ----------------------------------------------------------------------------------------------- */

void amf_events_routes(g5c_router *r, amf *a);
void amf_events_free(amf *a);

/* ---- callbacks.c (Namf_Communication callbacks: SMF status, UDM dereg, PCF, SDM) ---------------------------------------------- */

void amf_callbacks_routes(g5c_router *r, amf *a);
char *amf_cb_uri(amf *a, const char *path);

/* ---- persist.c ------------------------------------------------------------------------------------------------------------------------- */

void amf_persist_request(amf *a);
int amf_persist_restore(amf *a);
void amf_persist_flush(amf *a);
void amf_persist_timer(amf *a); /* the write-behind delay is over: write the state file */
#define AMF_TIMER_PERSIST 250
#define AMF_PERSIST_GAP_MS 25 /* minimum delay of a state-file write; grows with the cost of writing (amf_persist_timer) */
g5c_json *amf_ue_to_json(const amf_ue *u);
amf_ue *amf_ue_from_json(amf *a, const g5c_json *j);

#endif
