/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* GTP-U v1 header codec (3GPP TS 29.281 clause 5), including extension headers and the 5G PDU Session Container (TS 38.415) */
#ifndef G5C_GTPU_H
#define G5C_GTPU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define GTPU_ECHO_REQUEST 1
#define GTPU_ECHO_RESPONSE 2
#define GTPU_ERROR_INDICATION 26
#define GTPU_END_MARKER 254
#define GTPU_G_PDU 255
#define GTPU_EXT_PDU_SESSION_CONTAINER 0x85

#define GTPU_MAX_EXT 8 /* extension headers per packet we accept or produce */

typedef enum {
    GTPU_OK = 0,
    GTPU_E_TRUNCATED = -1,
    GTPU_E_VERSION = -2,
    GTPU_E_PROTOCOL_TYPE = -3, /* PT = 0 (GTP') */
    GTPU_E_LENGTH = -4,
    GTPU_E_EXTENSION = -5,      /* zero length, overrun, or more than GTPU_MAX_EXT */
    GTPU_E_EXTENSION_SIZE = -6, /* payload cannot be padded to a multiple of four octets */
    GTPU_E_NOSPACE = -7
} gtpu_err;

typedef struct {
    uint8_t typ;
    const uint8_t *data; /* content octets, excluding the length and next-type octets */
    size_t len;
} gtpu_ext;

typedef struct {
    uint8_t msg_type;
    uint32_t teid;
    bool has_seq;
    uint16_t seq;
    bool has_npdu;
    uint8_t npdu;
    gtpu_ext ext[GTPU_MAX_EXT];
    size_t next;
} gtpu_header;

void gtpu_header_init(gtpu_header *h, uint8_t msg_type, uint32_t teid);

/* PDU Session Container content for a downlink (pdu_type 0) or uplink (1) PDU; the caller keeps `out` alive while the extension is in use. */
void gtpu_pdu_session_container(uint8_t out[2], uint8_t pdu_type, uint8_t qfi, bool rqi);
/* Interpret an extension as a PDU Session Container. */
bool gtpu_as_pdu_session_container(const gtpu_ext *e, uint8_t *pdu_type, uint8_t *qfi, bool *rqi);

/* Encode header + payload into out (capacity cap). Returns 0 and *outlen, or an error. */
int gtpu_encode(const gtpu_header *h, const uint8_t *payload, size_t plen, uint8_t *out, size_t cap, size_t *outlen);
/* Decode a datagram. *payload points into buf. */
int gtpu_decode(const uint8_t *buf, size_t len, gtpu_header *h, const uint8_t **payload, size_t *plen);

#endif
