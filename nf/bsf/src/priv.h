/* SPDX-License-Identifier: LicenseRef-Proprietary */
#ifndef G5C_BSF_PRIV_H
#define G5C_BSF_PRIV_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "g5c/base.h"
#include "g5c/bsf.h"
#include "g5c/oaschema.h"

/* ---- generated schema pool ---- */
extern const char *const bsf_schema_chunks[];
extern const size_t bsf_schema_nchunks;
extern const size_t bsf_schema_count;
#include "api_ids.gen.h"

/* ---- supported features (TS 29.521 5.8), bit n-1 for feature number n ---- */
#define BSF_F_MULTI_UE_ADDR 0x01u
#define BSF_F_BINDING_UPDATE 0x02u
#define BSF_F_SAME_PCF 0x04u
#define BSF_F_ES3XX 0x08u /* not supported */
#define BSF_F_EXT_SAME_PCF 0x10u

/* more addresses than this in one binding (additional prefixes, additional MAC addresses, framed routes) are refused */
#define BSF_MAX_ADDRS 64

/* ---- addresses ---- */

typedef struct {
    uint8_t a[16]; /* masked to len */
    uint8_t len;
} pfx6_t;

typedef struct {
    uint32_t addr; /* host order, masked to len */
    uint8_t len;
} pfx4_t;

typedef struct {
    uint8_t m[6];
} mac_t;

bool bsf_parse_ipv4(const char *s, uint32_t *out);
bool bsf_parse_pfx4(const char *s, pfx4_t *out);             /* "198.51.100.0/24" */
bool bsf_parse_pfx6(const char *s, pfx6_t *out);             /* "2001:db8::/64", "2001:db8::1/128" */
bool bsf_parse_mac(const char *s, mac_t *out);               /* "00-11-22-33-44-55" */
bool bsf_pfx6_covers(const pfx6_t *p, const pfx6_t *addr);   /* every address of `addr` is in `p` */
bool bsf_pfx4_covers(const pfx4_t *p, uint32_t addr);
unsigned bsf_features_parse(const char *s);
char *bsf_features_str(unsigned f);
void bsf_merge_patch(g5c_json **doc, const g5c_json *patch); /* RFC 7396 */
int64_t bsf_parse_rfc3339(const char *s);

/* ---- configuration ---- */

struct bsf_cfg {
    unsigned max_bindings;
    unsigned features;       /* offered to the consumers: what is negotiated is the intersection */
    bool purge_on_recovery;  /* a binding of a PCF with a newer recoveryTime removes the older bindings of that PCF */
    bool replace_stale;      /* a binding for the same UE address, DNN, S-NSSAI and IP domain replaces the earlier one */
    bool validate;
    char *state_file;
    g5c_json *info; /* the bsfInfo of the NF profile, or NULL */
};

/* ---- bindings ---- */

typedef struct bind {
    char *id;
    g5c_json *doc; /* the PcfBinding as stored, with the supportedFeatures that were negotiated */
    char *supi, *gpsi, *dnn, *domain, *pcf_id;
    int sst, sd; /* the S-NSSAI; sd -1: none */
    bool has_v4;
    uint32_t v4;
    pfx6_t *v6; /* ipv6Prefix first, then addIpv6Prefixes */
    size_t nv6;
    mac_t *mac; /* macAddr48 first, then addMacAddrs */
    size_t nmac;
    pfx4_t *fr4; /* framed routes */
    size_t nfr4;
    pfx6_t *fr6;
    size_t nfr6;
    bool has_sm; /* holds Npcf_SMPolicyControl addressing information */
    unsigned features;
    int64_t recovery_s; /* recoveryTime, seconds since the epoch; 0: none */
    size_t all_ix, sm_ix; /* positions in the lists of the BSF while indexed */
} bind_t;

/* a chained hash table from a string key to bindings (several bindings may share a key: overlapping IPv4 addresses) */
typedef struct hnode {
    char *key;
    bind_t *b;
    struct hnode *next;
} hnode_t;

typedef struct {
    hnode_t **buckets;
    size_t nbuckets, count;
} ht_t;

typedef struct {
    bind_t *b;
    bool v6;
    pfx4_t p4;
    pfx6_t p6;
} route_t;

struct bsf {
    bsf_cfg *cfg;
    g5c_registry *metrics;
    bool own_metrics;
    oa_schemas *sch;
    pthread_mutex_t mu;
    ht_t by_id, by_v4, by_v6, by_mac, by_combo;
    route_t *short6; /* IPv6 prefixes shorter than /64 */
    size_t nshort6, capshort6;
    route_t *routes; /* framed routes */
    size_t nroutes, caproutes;
    bind_t **sm; /* bindings that hold SM policy addressing information (SamePcf) */
    size_t nsm, capsm;
    bind_t **all;
    size_t nall, capall;
    struct {
        char *pcf_id;
        int64_t rec;
    } *pcf_rec; /* the newest recoveryTime seen per PCF instance */
    size_t npcf_rec;
    pthread_mutex_t qmu; /* the state writer */
    pthread_cond_t qcv;
    bool stop, dirty;
    pthread_t worker;
    bool worker_on;
    g5c_counter *c_ops[4][3]; /* operation x outcome */
    g5c_counter *c_purged, *c_replaced;
    g5c_gauge *g_bindings;
};

/* bsf.c */
void bsf_problem(g5c_resp *resp, int status, const char *cause, const char *detail);
void bsf_kick(bsf *b); /* state changed */
void bsf_worker_start(bsf *b);
void bsf_worker_stop(bsf *b);
/* bindings.c */
void bsf_bindings_init(bsf *b);
void bsf_routes(g5c_router *r, bsf *b);
void bsf_bindings_free(bsf *b);
/* state.c */
int bsf_state_load(bsf *b, char *err, size_t errcap);
void bsf_state_save(bsf *b);
/* bindings.c, used by the state file */
bool bsf_insert_doc(bsf *b, const char *id, const g5c_json *doc, char *err, size_t errcap); /* parse, index, store; caller holds no lock */

#endif
