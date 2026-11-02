/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* User Plane Function (3GPP TS 23.501 6.2.3, TS 29.244 N4, TS 29.281 N3, TS 38.415).
 *
 * The engine in this library does no I/O: packets and N4 messages come in through upf_ul_packet / upf_dl_packet /
 * upf_n4_message, and everything it wants sent goes out through the callbacks in upf_io. The runtime (src/io.c) binds those to
 * UDP sockets and a TUN device; tests and fuzzers bind them to buffers. All functions are called from one thread. */
#ifndef G5C_UPF_H
#define G5C_UPF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "g5c/gtpu.h"
#include "g5c/metrics.h"
#include "g5c/pfcp.h"
#include "g5c/pfcp_ie.h"

/* ---- addresses --------------------------------------------------------------------------------------------------------------- */
typedef struct {
    bool v6;
    uint8_t b[16]; /* IPv4 in b[0..3] */
    uint16_t port;
} upf_addr;

bool upf_addr_equal_ip(const upf_addr *a, const upf_addr *b);

/* ---- SDF filters (IPFilterRule, TS 29.212 5.4.2): "permit out <proto> from <addr|any|assigned> [ports] to <...> [ports]" ---------- */
#define UPF_MAX_PORTS 8
typedef struct {
    bool any, assigned, v6;
    uint8_t addr[16], plen;
    uint16_t pmin[UPF_MAX_PORTS], pmax[UPF_MAX_PORTS];
    size_t nports; /* 0: any port */
} upf_net;

typedef struct {
    bool permit; /* "deny" rules are parsed but never match */
    int proto;   /* -1: ip (any) */
    upf_net src, dst;
} upf_sdf;

/* 0, or -1 with the problem in err */
int upf_sdf_parse(const char *rule, upf_sdf *out, char *err, size_t errcap);
/* A packet's 5-tuple, from the point of view of the rule (the rule describes the downlink direction: for uplink packets the caller
 * swaps source and destination). ue = the session's UE address for "assigned". */
typedef struct {
    int proto;
    bool v6;
    uint8_t src[16], dst[16];
    uint16_t sport, dport;
} upf_flow;
bool upf_sdf_match(const upf_sdf *r, const upf_flow *f, const upf_addr *ue4, const upf_addr *ue6);
/* Parse the IP header of a user packet into a flow (ports only for TCP, UDP, SCTP). false if it is not IP or is truncated. */
bool upf_flow_from_packet(const uint8_t *pkt, size_t len, upf_flow *f);

/* ---- rules --------------------------------------------------------------------------------------------------------------------- */
enum { UPF_IF_ACCESS = 0, UPF_IF_CORE = 1, UPF_IF_SGILAN = 2, UPF_IF_CP = 3 };

typedef struct {
    uint16_t id;
    uint32_t precedence;
    uint8_t src_if;
    bool has_fteid;
    pfcp_fteid fteid; /* as requested; when ch, `local_teid` is what we assigned */
    uint32_t local_teid;
    bool has_ue_ip;
    pfcp_ue_ip ue_ip;
    char net_inst[64];
    bool has_qfi;
    uint8_t qfi;
    upf_sdf *sdf;
    size_t nsdf;
    bool ohr; /* outer header removal requested */
    bool has_far;
    uint32_t far_id;
    uint32_t qer_ids[4];
    size_t nqer;
    uint32_t urr_ids[4];
    size_t nurr;
} upf_pdr;

typedef struct {
    uint32_t id;
    uint16_t action; /* PFCP_AA_* */
    uint8_t dest_if;
    bool has_ohc;
    pfcp_ohc ohc;
    bool has_bar;
    uint8_t bar_id;
} upf_far;

typedef struct {
    double tokens, last, rate_bytes_per_s, burst;
    bool enabled;
} upf_bucket;

typedef struct {
    uint32_t id;
    bool ul_closed, dl_closed;
    bool has_mbr, has_gbr;
    pfcp_bitrate mbr, gbr;
    bool has_qfi;
    uint8_t qfi;
    upf_bucket ul, dl;
} upf_qer;

typedef struct {
    uint64_t bytes, pkts;
} upf_count;

typedef struct {
    uint32_t id;
    uint8_t method;      /* bit0 duration, bit1 volume */
    uint32_t triggers;   /* PFCP_URT_* the SMF asked for */
    bool has_vol_thresh;
    pfcp_volume vol_thresh;
    bool has_time_thresh;
    uint32_t time_thresh; /* seconds */
    uint32_t period;      /* seconds, 0: none */
    upf_count total, ul, dl;
    double start, first_pkt, last_pkt, last_report;
    bool seen_pkt;
    uint32_t seqn;
    upf_count at_last_report; /* total at the previous report: thresholds apply to the volume since then */
    bool report_due;
    uint32_t due_trigger;
} upf_urr;

typedef struct {
    uint8_t id;
    uint32_t suggested_count;
    uint32_t buffering_duration_ms; /* 0: default */
    uint32_t notify_delay_ms;
} upf_bar;

typedef struct {
    uint8_t *data;
    size_t len;
    double t;
} upf_buffered;

typedef struct upf_session upf_session;
typedef struct upf upf;

struct upf_session {
    uint64_t local_seid, cp_seid;
    upf_addr cp_addr; /* where reports go: the CP F-SEID address, N4 port */
    uint32_t peer; /* index into upf->peers */
    upf_pdr *pdr; size_t npdr;
    upf_far *far; size_t nfar;
    upf_qer *qer; size_t nqer;
    upf_urr *urr; size_t nurr;
    upf_bar *bar; size_t nbar;
    upf_addr ue4, ue6; /* UE addresses seen in PDRs (v6 holds the /64 prefix) */
    bool has_ue4, has_ue6;
    upf_buffered *buf; size_t nbuf, capbuf, buf_bytes;
    bool dl_report_sent; /* a Downlink Data Report is outstanding */
    uint64_t created_ms;
};

/* ---- I/O the engine needs -------------------------------------------------------------------------------------------------------- */
typedef struct {
    void *ctx;
    void (*tx_gtpu)(void *ctx, const upf_addr *to, const uint8_t *pkt, size_t len);   /* N3/N9 (and CP-function) UDP datagram */
    void (*tx_n6)(void *ctx, const uint8_t *ip_pkt, size_t len);                      /* decapsulated user packet to the data network */
    void (*tx_n4)(void *ctx, const upf_addr *to, const uint8_t *msg, size_t len);     /* PFCP datagram */
} upf_io;

typedef struct {
    upf_addr n4_addr;   /* our PFCP address (Node ID, F-SEID) */
    upf_addr n3_addr;   /* our GTP-U address (F-TEID returned to the SMF) */
    bool check_source;  /* drop uplink packets whose source address is not the session's UE address */
    uint32_t heartbeat_interval; /* seconds, 0: do not send heartbeats */
    uint32_t heartbeat_retries;
    uint32_t buffer_max_packets, buffer_max_bytes;
    double buffer_max_age;       /* seconds */
    uint32_t max_sessions;
    bool delete_on_peer_loss;
} upf_config;

/* counters, readable by the runtime / tests */
typedef struct {
    uint64_t ul_pkts, ul_bytes, dl_pkts, dl_bytes;
    uint64_t drop_no_session, drop_no_pdr, drop_far, drop_gate, drop_rate, drop_spoof, drop_bad_packet, drop_buffer, drop_no_route;
    uint64_t buffered, flushed, echo, error_ind, end_marker;
    uint64_t n4_rx, n4_tx, n4_bad;
    uint64_t sessions_created, sessions_deleted, reports_sent, reports_acked;
} upf_stats;

typedef struct {
    upf_addr addr;
    bool established;
    uint32_t recovery_ts;
    uint32_t node_type;
    char node_name[64];
    double last_rx, last_hb_tx;
    uint32_t hb_missed;
    uint32_t hb_seq;
} upf_peer;

typedef struct {
    bool used;
    uint32_t seq;
    upf_addr to;
    uint8_t *msg;
    size_t len;
    double next_tx;
    unsigned tries;
    uint64_t seid;
    bool is_report;
} upf_pending;

typedef struct {
    uint32_t seq;
    upf_addr from;
    uint8_t *resp;
    size_t len;
    double t;
} upf_cached;

struct upf_ptrmap;
struct upf {
    upf_config cfg;
    upf_io io;
    upf_stats st;
    uint32_t recovery_ts;
    uint32_t next_teid, next_seq;
    uint64_t next_seid;
    double now;
    upf_session **sessions; size_t nsessions, capsessions;
    struct upf_ptrmap *by_seid, *by_teid, *by_ue4, *by_ue6;
    upf_peer *peers; size_t npeers;
    upf_pending pend[64];
    upf_cached cache[32]; size_t cache_next;
    g5c_registry *metrics;
    double last_err_ind;
    uint32_t err_ind_budget;
};

/* lifecycle */
upf *upf_new(const upf_config *cfg, const upf_io *io, g5c_registry *metrics);
void upf_free(upf *u);
void upf_config_defaults(upf_config *c);

/* inputs */
void upf_n4_message(upf *u, const upf_addr *from, const uint8_t *msg, size_t len, double now);
void upf_gtpu_packet(upf *u, const upf_addr *from, const uint8_t *pkt, size_t len, double now); /* N3/N9: G-PDU, Echo, Error Indication, End Marker */
void upf_n6_packet(upf *u, const uint8_t *ip_pkt, size_t len, double now);                        /* from the data network, downlink */
void upf_tick(upf *u, double now);                                                                 /* timers: reports, retransmission, buffers, heartbeats */

/* introspection (tests, metrics) */
size_t upf_session_count(const upf *u);
upf_session *upf_session_by_seid(const upf *u, uint64_t seid);
bool upf_peer_established(const upf *u, const upf_addr *a);

#endif
