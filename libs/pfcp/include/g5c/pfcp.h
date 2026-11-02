/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* PFCP message header and IE framing (3GPP TS 29.244 clauses 7.2 and 8.1).
 * Typed IEs and message bodies are added per procedure in later phases; this library provides the transport-level
 * codec every message needs. Decoding never copies: slices point into the input datagram. */
#ifndef G5C_PFCP_H
#define G5C_PFCP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PFCP_HEARTBEAT_REQUEST 1
#define PFCP_HEARTBEAT_RESPONSE 2
#define PFCP_ASSOCIATION_SETUP_REQUEST 5
#define PFCP_ASSOCIATION_SETUP_RESPONSE 6
#define PFCP_SESSION_ESTABLISHMENT_REQUEST 50
#define PFCP_SESSION_ESTABLISHMENT_RESPONSE 51
#define PFCP_IE_RECOVERY_TIME_STAMP 96

typedef enum {
    PFCP_OK = 0,
    PFCP_E_TRUNCATED = -1,
    PFCP_E_VERSION = -2,
    PFCP_E_LENGTH = -3,
    PFCP_E_SEQUENCE = -4, /* sequence number does not fit 24 bits */
    PFCP_E_NOSPACE = -5
} pfcp_err;

typedef struct {
    bool follow_on;
    uint8_t msg_type;
    bool has_seid; /* S flag: session-related messages */
    uint64_t seid;
    uint32_t seq; /* 24 bits */
    bool has_priority;
    uint8_t priority; /* 4 bits */
} pfcp_header;

void pfcp_header_node(pfcp_header *h, uint8_t msg_type, uint32_t seq);
void pfcp_header_session(pfcp_header *h, uint8_t msg_type, uint64_t seid, uint32_t seq);

/* Encode header plus already-encoded IE body. */
int pfcp_encode(const pfcp_header *h, const uint8_t *body, size_t blen, uint8_t *out, size_t cap, size_t *outlen);
/* Decode a datagram; *body points into buf. */
int pfcp_decode(const uint8_t *buf, size_t len, pfcp_header *h, const uint8_t **body, size_t *blen);

/* A single TLV information element (TS 29.244 8.1.1). Enterprise IEs (type >= 32768) carry an enterprise id in the
 * first two value octets. */
typedef struct {
    uint16_t typ;
    const uint8_t *value;
    size_t len;
} pfcp_ie;

/* Iterate over the IEs of a message body: returns 1 with *ie set, 0 at the end, or a negative error on malformed
 * framing. *pos starts at 0. */
int pfcp_ie_next(const uint8_t *body, size_t blen, size_t *pos, pfcp_ie *ie);
/* Append one IE at out[*pos]; advances *pos. */
int pfcp_put_ie(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, const uint8_t *value, size_t len);

#endif
