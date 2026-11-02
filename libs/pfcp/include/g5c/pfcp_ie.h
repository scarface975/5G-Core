/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Typed PFCP information elements (3GPP TS 29.244 clause 8.2) and builders for grouped IEs. Layout rules were taken from the
 * pinned specification text and checked against messages captured from Open5GS (libs/pfcp/tests/pfcp_vectors.h).
 * Decoders take the IE value octets (as delivered by pfcp_ie_next) and return 0 or -1; they never read past `len`. */
#ifndef G5C_PFCP_IE_H
#define G5C_PFCP_IE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "g5c/pfcp.h"

/* IE type values, Table 8.1.2-1 */
enum {
    PFCP_IE_CREATE_PDR = 1, PFCP_IE_PDI = 2, PFCP_IE_CREATE_FAR = 3, PFCP_IE_FORWARDING_PARAMETERS = 4,
    PFCP_IE_CREATE_URR = 6, PFCP_IE_CREATE_QER = 7, PFCP_IE_CREATED_PDR = 8, PFCP_IE_UPDATE_PDR = 9,
    PFCP_IE_UPDATE_FAR = 10, PFCP_IE_UPDATE_FORWARDING_PARAMETERS = 11, PFCP_IE_UPDATE_BAR_RESPONSE = 12,
    PFCP_IE_UPDATE_URR = 13, PFCP_IE_UPDATE_QER = 14, PFCP_IE_REMOVE_PDR = 15, PFCP_IE_REMOVE_FAR = 16,
    PFCP_IE_REMOVE_URR = 17, PFCP_IE_REMOVE_QER = 18, PFCP_IE_CAUSE = 19, PFCP_IE_SOURCE_INTERFACE = 20,
    PFCP_IE_FTEID = 21, PFCP_IE_NETWORK_INSTANCE = 22, PFCP_IE_SDF_FILTER = 23, PFCP_IE_APPLICATION_ID = 24,
    PFCP_IE_GATE_STATUS = 25, PFCP_IE_MBR = 26, PFCP_IE_GBR = 27, PFCP_IE_QER_CORRELATION_ID = 28,
    PFCP_IE_PRECEDENCE = 29, PFCP_IE_VOLUME_THRESHOLD = 31, PFCP_IE_TIME_THRESHOLD = 32,
    PFCP_IE_MONITORING_TIME = 33, PFCP_IE_REPORTING_TRIGGERS = 37, PFCP_IE_REPORT_TYPE = 39,
    PFCP_IE_OFFENDING_IE = 40, PFCP_IE_DESTINATION_INTERFACE = 42, PFCP_IE_UP_FUNCTION_FEATURES = 43,
    PFCP_IE_APPLY_ACTION = 44, PFCP_IE_DL_DATA_NOTIFICATION_DELAY = 46, PFCP_IE_DL_BUFFERING_DURATION = 47,
    PFCP_IE_DL_BUFFERING_SUGGESTED_COUNT = 48, PFCP_IE_SMREQ_FLAGS = 49, PFCP_IE_SRRSP_FLAGS = 50,
    PFCP_IE_SEQUENCE_NUMBER = 52, PFCP_IE_PDR_ID = 56, PFCP_IE_FSEID = 57, PFCP_IE_NODE_ID = 60,
    PFCP_IE_MEASUREMENT_METHOD = 62, PFCP_IE_USAGE_REPORT_TRIGGER = 63, PFCP_IE_MEASUREMENT_PERIOD = 64,
    PFCP_IE_VOLUME_MEASUREMENT = 66, PFCP_IE_DURATION_MEASUREMENT = 67, PFCP_IE_TIME_OF_FIRST_PACKET = 69,
    PFCP_IE_TIME_OF_LAST_PACKET = 70, PFCP_IE_VOLUME_QUOTA = 73, PFCP_IE_TIME_QUOTA = 74, PFCP_IE_START_TIME = 75,
    PFCP_IE_END_TIME = 76, PFCP_IE_QUERY_URR = 77, PFCP_IE_USAGE_REPORT_SMR = 78, PFCP_IE_USAGE_REPORT_SDR = 79,
    PFCP_IE_USAGE_REPORT_SRR = 80, PFCP_IE_URR_ID = 81, PFCP_IE_DOWNLINK_DATA_REPORT = 83,
    PFCP_IE_OUTER_HEADER_CREATION = 84, PFCP_IE_CREATE_BAR = 85, PFCP_IE_UPDATE_BAR_SMR = 86,
    PFCP_IE_REMOVE_BAR = 87, PFCP_IE_BAR_ID = 88, PFCP_IE_CP_FUNCTION_FEATURES = 89, PFCP_IE_UE_IP_ADDRESS = 93,
    PFCP_IE_OUTER_HEADER_REMOVAL = 95, PFCP_IE_UR_SEQN = 104, PFCP_IE_FAR_ID = 108, PFCP_IE_QER_ID = 109,
    PFCP_IE_PDN_TYPE = 113, PFCP_IE_QFI = 124, PFCP_IE_QUERY_URR_REFERENCE = 125, PFCP_IE_RQI = 123,
    PFCP_IE_APN_DNN = 159, PFCP_IE_3GPP_INTERFACE_TYPE = 160, PFCP_IE_USER_ID = 141, PFCP_IE_SNSSAI = 257
};

/* Cause values, Table 8.2.1-1 */
enum { PFCP_CAUSE_ACCEPTED = 1, PFCP_CAUSE_REJECTED = 64, PFCP_CAUSE_SESSION_NOT_FOUND = 65, PFCP_CAUSE_MANDATORY_IE_MISSING = 66,
       PFCP_CAUSE_CONDITIONAL_IE_MISSING = 67, PFCP_CAUSE_INVALID_LENGTH = 68, PFCP_CAUSE_MANDATORY_IE_INCORRECT = 69,
       PFCP_CAUSE_INVALID_FORWARDING_POLICY = 70, PFCP_CAUSE_INVALID_FTEID_ALLOCATION = 71, PFCP_CAUSE_NO_ESTABLISHED_ASSOCIATION = 72,
       PFCP_CAUSE_RULE_CREATION_FAILURE = 73, PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION = 74, PFCP_CAUSE_NO_RESOURCES = 75,
       PFCP_CAUSE_SERVICE_NOT_SUPPORTED = 76, PFCP_CAUSE_SYSTEM_FAILURE = 77 };

/* More message types, Table 7.3-1 */
enum { PFCP_ASSOCIATION_UPDATE_REQUEST = 7, PFCP_ASSOCIATION_UPDATE_RESPONSE = 8, PFCP_ASSOCIATION_RELEASE_REQUEST = 9,
       PFCP_ASSOCIATION_RELEASE_RESPONSE = 10, PFCP_VERSION_NOT_SUPPORTED = 11, PFCP_NODE_REPORT_REQUEST = 12,
       PFCP_PFD_MANAGEMENT_REQUEST = 3, PFCP_PFD_MANAGEMENT_RESPONSE = 4,
       PFCP_SESSION_MODIFICATION_REQUEST = 52, PFCP_SESSION_MODIFICATION_RESPONSE = 53, PFCP_SESSION_DELETION_REQUEST = 54,
       PFCP_SESSION_DELETION_RESPONSE = 55, PFCP_SESSION_REPORT_REQUEST = 56, PFCP_SESSION_REPORT_RESPONSE = 57 };

/* ---- building (grouped IEs need their length patched once the content is known) ----------------------------------- */
int pfcp_group_begin(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, size_t *mark);
void pfcp_group_end(uint8_t *out, size_t *pos, size_t mark);
int pfcp_put_u8(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, uint8_t v);
int pfcp_put_u16(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, uint16_t v);
int pfcp_put_u32(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, uint32_t v);

/* ---- plain integers ------------------------------------------------------------------------------------------------ */
int pfcp_get_u8(const pfcp_ie *ie, uint8_t *v);
int pfcp_get_u16(const pfcp_ie *ie, uint16_t *v);
int pfcp_get_u32(const pfcp_ie *ie, uint32_t *v);

/* ---- Node ID (8.2.38) ----------------------------------------------------------------------------------------------- */
typedef struct {
    uint8_t type; /* 0 IPv4, 1 IPv6, 2 FQDN */
    uint8_t ip4[4], ip6[16];
    char fqdn[64];
} pfcp_node_id;
int pfcp_node_id_decode(const pfcp_ie *ie, pfcp_node_id *n);
int pfcp_node_id_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_node_id *n);

/* ---- F-SEID (8.2.37) ------------------------------------------------------------------------------------------------ */
typedef struct {
    bool v4, v6;
    uint64_t seid;
    uint8_t ip4[4], ip6[16];
} pfcp_fseid;
int pfcp_fseid_decode(const pfcp_ie *ie, pfcp_fseid *f);
int pfcp_fseid_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_fseid *f);

/* ---- F-TEID (8.2.3): either explicit, or a request for the UP function to choose (CH, optionally with a choose id) ---- */
typedef struct {
    bool v4, v6, ch, chid;
    uint32_t teid;
    uint8_t ip4[4], ip6[16];
    uint8_t choose_id;
} pfcp_fteid;
int pfcp_fteid_decode(const pfcp_ie *ie, pfcp_fteid *f);
int pfcp_fteid_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_fteid *f);

/* ---- UE IP Address (8.2.62) ------------------------------------------------------------------------------------------ */
typedef struct {
    bool v4, v6, sd /* 1: destination (downlink matching) */, ipv6d, chv4, chv6, has_prefix_len;
    uint8_t ip4[4], ip6[16], ipv6d_len, prefix_len;
} pfcp_ue_ip;
int pfcp_ue_ip_decode(const pfcp_ie *ie, pfcp_ue_ip *u);
int pfcp_ue_ip_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_ue_ip *u);

/* ---- Outer Header Creation (8.2.56) and Removal (8.2.64) ---------------------------------------------------------------- */
#define PFCP_OHC_GTPU_IPV4 0x0001
#define PFCP_OHC_GTPU_IPV6 0x0002
#define PFCP_OHC_UDP_IPV4 0x0004
#define PFCP_OHC_UDP_IPV6 0x0008
#define PFCP_OHC_IPV4 0x0010
#define PFCP_OHC_IPV6 0x0020
typedef struct {
    uint16_t desc; /* bit mask above (octet 5 in the low byte, octet 6 in the high byte) */
    uint32_t teid;
    uint8_t ip4[4], ip6[16];
    uint16_t port;
} pfcp_ohc;
int pfcp_ohc_decode(const pfcp_ie *ie, pfcp_ohc *o);
int pfcp_ohc_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_ohc *o);
enum { PFCP_OHR_GTPU_IPV4 = 0, PFCP_OHR_GTPU_IPV6 = 1, PFCP_OHR_UDP_IPV4 = 2, PFCP_OHR_UDP_IPV6 = 3, PFCP_OHR_IPV4 = 4, PFCP_OHR_IPV6 = 5,
       PFCP_OHR_GTPU_ANY = 6 };

/* ---- Apply Action (8.2.26) ---------------------------------------------------------------------------------------------- */
#define PFCP_AA_DROP 0x01
#define PFCP_AA_FORW 0x02
#define PFCP_AA_BUFF 0x04
#define PFCP_AA_NOCP 0x08
#define PFCP_AA_DUPL 0x10
int pfcp_apply_action_decode(const pfcp_ie *ie, uint16_t *aa); /* low byte = octet 5 */

/* ---- MBR / GBR (8.2.8, 8.2.9), kbit/s; Gate Status (8.2.7) --------------------------------------------------------------- */
typedef struct { uint64_t ul, dl; } pfcp_bitrate;
int pfcp_bitrate_decode(const pfcp_ie *ie, pfcp_bitrate *b);
int pfcp_bitrate_put(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, const pfcp_bitrate *b);
typedef struct { bool ul_closed, dl_closed; } pfcp_gate;
int pfcp_gate_decode(const pfcp_ie *ie, pfcp_gate *g);

/* ---- SDF Filter (8.2.5): the flow description and the optional fields ---------------------------------------------------- */
typedef struct {
    bool has_fd, has_ttc, has_spi, has_fl, has_bid;
    char flow[256]; /* NUL-terminated IPFilterRule */
    uint16_t tos_traffic_class;
    uint32_t spi, flow_label, filter_id;
} pfcp_sdf_filter;
int pfcp_sdf_filter_decode(const pfcp_ie *ie, pfcp_sdf_filter *f);

/* ---- Volume Threshold / Quota (8.2.13, 8.2.50) and Volume Measurement (8.2.40) ---------------------------------------------- */
typedef struct {
    bool has_total, has_ul, has_dl;
    uint64_t total, ul, dl;
} pfcp_volume;
int pfcp_volume_decode(const pfcp_ie *ie, pfcp_volume *v);
typedef struct {
    bool has_total, has_ul, has_dl, has_total_pkts, has_ul_pkts, has_dl_pkts;
    uint64_t total, ul, dl, total_pkts, ul_pkts, dl_pkts;
} pfcp_volume_meas;
int pfcp_volume_meas_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_volume_meas *v);

/* ---- Network Instance (8.2.4): DNS-style labels <-> dotted name ------------------------------------------------------------ */
int pfcp_network_instance_decode(const pfcp_ie *ie, char *out, size_t cap);
int pfcp_network_instance_put(uint8_t *out, size_t cap, size_t *pos, const char *name);

/* Reporting Triggers (8.2.19) / Usage Report Trigger (8.2.41) bit masks over the three octets, octet 5 in the low byte */
#define PFCP_URT_PERIO 0x000001
#define PFCP_URT_VOLTH 0x000002
#define PFCP_URT_TIMTH 0x000004
#define PFCP_URT_VOLQU 0x000100
#define PFCP_URT_TIMQU 0x000200
#define PFCP_URT_TERMR 0x000800
#define PFCP_URT_IMMER 0x000080
int pfcp_trigger_decode(const pfcp_ie *ie, uint32_t *mask);
int pfcp_trigger_put(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, uint32_t mask);

/* UP Function Features (8.2.25). Octet 5: bit 1 BUCP, 2 DDND, 3 DLBD, 4 TRST, 5 FTUP, 6 PFDM, 7 HEEU, 8 TREU.
 * Octet 6: bit 1 EMPU, 2 PDIU, 3 UDBC, 4 QUOAC, 5 TRACE, 6 FRRT, 7 PFDE, 8 EPFAR. Only the ones this code base sets are named. */
#define PFCP_UPF5_FTUP 0x10
#define PFCP_UPF6_EMPU 0x01

/* NTP-era seconds (TS 29.244 8.2.2): seconds since 1900-01-01 */
uint32_t pfcp_ntp_now(void);

#endif
