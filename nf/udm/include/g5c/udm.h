/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5G core Unified Data Management (UDM), Phase 1.
 *
 * Services (TS 29.503): nudm-ueau (5G-AKA vector generation, SQN management, resynchronisation, auth events),
 * nudm-sdm (access/mobility, session-management, NSSAI, SMF-selection and UE-context-in-SMF data, subscriptions),
 * nudm-uecm (AMF and SMF registrations with deregistration notification of the previous AMF).
 * Subscriber data lives in the UDR (nudr-dr); only UDM ever handles plaintext K/OPc (see keys).
 * A small admin API (/admin/v1, disabled unless a token is configured) provisions subscribers. */
#ifndef G5C_UDM_H
#define G5C_UDM_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "g5c/crypto.h"
#include "g5c/json.h"
#include "g5c/metrics.h"
#include "g5c/nfcore.h"
#include "g5c/sbi.h"

/* ---- AKA / SQN (TS 33.501 6.1.3.2, TS 33.102 Annex C) ------------------------------------------------------ */

#define UDM_SQN_STEP 32ULL /* SEQ advances by one; the 5-bit IND stays where resynchronisation put it */

typedef struct {
    uint8_t rand[16], autn[16], xres_star[16], kausf[32];
} udm_heav;

uint64_t udm_next_sqn(uint64_t stored);
void udm_sqn_to_hex(uint64_t sqn, char out[13]);
bool udm_sqn_from_hex(const char *s, uint64_t *out); /* exactly 12 hex characters */
/* 0 on success, -1 on crypto failure. */
int udm_generate_av(const uint8_t k[16], const uint8_t opc[16], uint64_t sqn, const uint8_t amf[2],
                    const uint8_t rand[16], const char *snn, udm_heav *out);
/* EAP-AKA' vector (TS 33.501 6.1.3.1 step 1-2): the AMF separation bit is the caller's (amf[0] bit 7 must be 1), CK' and IK' are derived with the serving network
 * name; xres is the Milenage RES (8 octets). */
typedef struct {
    uint8_t rand[16], autn[16], xres[8], ck_prime[16], ik_prime[16];
} udm_hep;
int udm_generate_av_prime(const uint8_t k[16], const uint8_t opc[16], uint64_t sqn, const uint8_t amf[2], const uint8_t rand[16], const char *snn, udm_hep *out);
/* AUTS handling (TS 33.102 6.3.5): 0 and *sqn_ms on success, 1 if MAC-S does not verify, -1 on crypto failure. */
int udm_resync(const uint8_t k[16], const uint8_t opc[16], const uint8_t rand[16], const uint8_t auts[14],
               uint64_t *sqn_ms);

/* ---- credential protection at rest ------------------------------------------------------------------------- */

#define UDM_PROT_NONE "none"
#define UDM_PROT_AES256GCM "aes-256-gcm-v1"

typedef enum {
    UDM_KEY_OK = 0,
    UDM_KEY_MALFORMED = -1,
    UDM_KEY_DECRYPT = -2,
    UDM_KEY_SCHEME = -3,
    UDM_KEY_NO_MASTER = -4,
    UDM_KEY_BAD_MASTER = -5,
    UDM_KEY_RANDOM = -6
} udm_key_err;

typedef struct {
    bool has_master;
    uint8_t master[32];
    bool has_previous; /* the master key before a rotation: credentials stored under it still decrypt until /admin/v1/keys/rewrap has re-protected them */
    uint8_t previous[32];
} udm_keys;

void udm_keys_none(udm_keys *k);
void udm_keys_with_master(udm_keys *k, const uint8_t master[32]);
int udm_keys_from_hex(udm_keys *k, const char *hex64); /* surrounding whitespace ignored */
int udm_keys_set_previous_hex(udm_keys *k, const char *hex64);
/* Like udm_unprotect, but only with the current master key: *used_previous tells that the previous key was needed (the credential still has to be re-wrapped). */
int udm_unprotect_ex(const udm_keys *k, const char *stored, const char *scheme, const char *supi, uint8_t *out, size_t cap, size_t *len, bool *used_previous);
/* Protect `plain` for `supi`: *stored is a heap hex string, *scheme a static protectionParameterId. */
int udm_protect(const udm_keys *k, const uint8_t *plain, size_t n, const char *supi, char **stored,
                const char **scheme);
/* Recover plaintext into out (capacity cap); *len gets its length. scheme may be NULL ("none"). */
int udm_unprotect(const udm_keys *k, const char *stored, const char *scheme, const char *supi, uint8_t *out,
                  size_t cap, size_t *len);

/* ---- SUPI / SUCI resolution (TS 23.003 2.2B, TS 33.501 6.12) ------------------------------------------------- */

typedef struct {
    uint8_t id;
    g5c_profile profile;
    uint8_t secret[32];
} udm_hnkey;

typedef enum {
    UDM_ID_OK = 0,
    UDM_ID_MALFORMED = -1,
    UDM_ID_UNSUPPORTED = -2,
    UDM_ID_UNKNOWN_KEY = -3,
    UDM_ID_DECONCEAL = -4
} udm_id_err;

/* supi_out must hold at least 32 bytes ("imsi-" + up to 15 digits + NUL). */
int udm_resolve(const char *id, const udm_hnkey *keys, size_t nkeys, char *supi_out, size_t cap);

/* ---- util ----------------------------------------------------------------------------------------------------- */

void udm_iso8601_utc(uint64_t secs, char out[21]);
void udm_now_iso8601(char out[21]);
/* The plmn-id query value {"mcc":"001","mnc":"01"} -> "00101"; false when malformed. */
bool udm_plmn_from_query(const char *q, char *out, size_t cap);
/* 5G:mnc<3 digits>.mcc<3 digits>.3gppnetwork.org */
bool udm_valid_snn(const char *s);

/* ---- UDR client (Nudr_DataRepository, TS 29.504/29.505) ---------------------------------------------------------- */

typedef enum { UDR_OK = 0, UDR_NOT_FOUND, UDR_STATUS, UDR_TRANSPORT, UDR_MALFORMED } udr_kind;

typedef struct {
    udr_kind kind;
    int http_status;
    bool created; /* a PUT answered 201 */
} udr_result;

typedef struct {
    g5c_client *client;
    char *base;      /* <udr>/nudr-dr/v1/subscription-data, from the configuration (NULL when the UDR is discovered) */
    g5c_disc *disc;  /* the NRF discovery client when the UDR address is not configured */
    char *token;     /* bearer token for the UDR's provisioning extension (creating provisioned data, removing a subscriber) */
} udm_udr;

void udm_udr_init(udm_udr *u, g5c_client *c, const char *base);
/* Locate the UDR through the NRF (Nnrf_NFDiscovery) instead of a configured address. Takes ownership of d. */
void udm_udr_use_discovery(udm_udr *u, g5c_disc *d);
void udm_udr_free(udm_udr *u);
/* The bearer token presented to the UDR with every request (NULL clears it). */
void udm_udr_set_token(udm_udr *u, const char *token);
/* Fill `resp` with the answer UDM gives its own client for a UDR failure. */
void udm_udr_fail(const udr_result *r, const char *not_found_cause, g5c_resp *resp);

/* GETs return the parsed body in *out (caller frees) on UDR_OK. */
udr_result udm_udr_auth_subscription(const udm_udr *u, const char *supi, g5c_json **out);
udr_result udm_udr_patch_auth_subscription(const udm_udr *u, const char *supi, const g5c_json *items);
udr_result udm_udr_put_auth_subscription(const udm_udr *u, const char *supi, const g5c_json *doc);
udr_result udm_udr_put_auth_status(const udm_udr *u, const char *supi, const g5c_json *ev);
udr_result udm_udr_am_data(const udm_udr *u, const char *supi, const char *plmn, g5c_json **out);
udr_result udm_udr_put_am_data(const udm_udr *u, const char *supi, const char *plmn, const g5c_json *doc);
udr_result udm_udr_sm_data(const udm_udr *u, const char *supi, const char *plmn, const char *nssai, const char *dnn,
                           g5c_json **out);
udr_result udm_udr_put_sm_data(const udm_udr *u, const char *supi, const char *plmn, const g5c_json *doc);
udr_result udm_udr_smf_selection(const udm_udr *u, const char *supi, const char *plmn, g5c_json **out);
udr_result udm_udr_put_smf_selection(const udm_udr *u, const char *supi, const char *plmn, const g5c_json *doc);
udr_result udm_udr_amf_registration(const udm_udr *u, const char *supi, g5c_json **out);
udr_result udm_udr_put_amf_registration(const udm_udr *u, const char *supi, const g5c_json *reg);
udr_result udm_udr_patch_amf_registration(const udm_udr *u, const char *supi, const g5c_json *items);
udr_result udm_udr_delete_amf_registration(const udm_udr *u, const char *supi);
udr_result udm_udr_put_smf_registration(const udm_udr *u, const char *supi, const char *pdu_id, const g5c_json *reg);
udr_result udm_udr_delete_smf_registration(const udm_udr *u, const char *supi, const char *pdu_id);
udr_result udm_udr_smf_registrations(const udm_udr *u, const char *supi, g5c_json **out);
/* identity data (TS 29.505 identity-data): the SUPIs and GPSIs of a subscriber; `ueid` may be a GPSI (the UDR resolves it) */
udr_result udm_udr_identity(const udm_udr *u, const char *ueid, g5c_json **out);
udr_result udm_udr_put_identity(const udm_udr *u, const char *supi, const g5c_json *doc);
udr_result udm_udr_delete_subscriber(const udm_udr *u, const char *supi);
udr_result udm_udr_list_subscribers(const udm_udr *u, g5c_json **out);

/* ---- UDM state and router ------------------------------------------------------------------------------------------ */

typedef int (*udm_rand_fn)(void *ctx, uint8_t out[16]);

typedef struct udm {
    udm_udr udr;
    udm_keys keys;
    udm_hnkey *hn_keys;
    size_t nhn_keys;
    char plmn[8]; /* mcc+mnc, e.g. "00101" */
    char instance_id[37];
    g5c_registry *metrics;
    g5c_client *client; /* callbacks (deregistration notifications) */
    udm_rand_fn rand_fn;
    void *rand_ctx;
    char *admin_token; /* NULL: admin API disabled */
    /* internals */
    pthread_mutex_t mu;
    struct supi_lock **locks;
    size_t nlocks;
    g5c_json *sdm_subs; /* "supi/id" -> subscription */
    uint64_t next_sub;
    g5c_json *ee_subs; /* Nudm_EventExposure: id -> subscription (see ee.c) */
    uint64_t next_ee;
    char *ee_amf_uri;  /* `ee.amf_uri`: the AMF to subscribe at for anyUE (or when the UE has no registration naming one) */
    char *ee_self_uri; /* where the AMF sends its notifications: `ee.notify_uri`, else this function's own address */
    char *ee_state_file; /* `ee.state_file`: the subscriptions are written here after every change and read again at start (NULL: kept in memory only) */
    void **owned; /* route contexts, freed with the UDM */
    size_t nowned;
} udm;

/* The UDM does not take ownership of `client`/`metrics`. */
void udm_init(udm *u, g5c_client *client, const char *udr_base, const udm_keys *keys, const udm_hnkey *hn_keys,
              size_t nhn_keys, const char *plmn, const char *instance_id, g5c_registry *metrics);
void udm_destroy(udm *u);
/* Internal: hand a heap object to the UDM, to be freed with it (route contexts). */
void udm_track(udm *u, void *owned);

/* Per-subscriber lock: serialises the SQN read-modify-write for one SUPI within this instance (multi-instance
 * deployments need a compare-and-swap in the UDR, Phase 8). */
typedef struct supi_lock udm_supi_lock;
udm_supi_lock *udm_lock_supi(udm *u, const char *supi);
void udm_unlock_supi(udm *u, udm_supi_lock *l);

/* Full UDM router: UEAU, SDM (v1 and v2), UECM and the admin API, guarded by the admin token. */
g5c_router *udm_router(udm *u);
void udm_ueau_routes(g5c_router *r, udm *u);
void udm_sdm_routes(g5c_router *r, udm *u);
void udm_uecm_routes(g5c_router *r, udm *u);
void udm_admin_routes(g5c_router *r, udm *u);
void udm_ee_routes(g5c_router *r, udm *u); /* Nudm_EventExposure, TS 29.503 clause 5.5 */
void udm_ee_load(udm *u);                    /* reads `ee.state_file` (a missing file is an empty start) */
/* Send Nudm_SDM data-change notifications to every sdm-subscription of `supi` (best effort). */
void udm_sdm_notify_change(udm *u, const char *supi);
int udm_admin_guard(void *ctx /* udm* */, const g5c_req *req, g5c_resp *resp);

/* ---- configuration -------------------------------------------------------------------------------------------------- */

/* Build the UDM from the parsed configuration DOM (sections: udr, hn_keys, master_key_file, admin_token_file) and the
 * NF context. Returns NULL with err on failure. The caller frees with udm_destroy + free. */
udm *udm_from_config(const g5c_json *cfg, g5c_nf *nf, char *err, size_t errcap);

#endif
