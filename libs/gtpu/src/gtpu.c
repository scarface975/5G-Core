/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include "g5c/gtpu.h"

#include <string.h>

#define FLAG_E 0x04U
#define FLAG_S 0x02U
#define FLAG_PN 0x01U

void gtpu_header_init(gtpu_header *h, uint8_t msg_type, uint32_t teid)
{
    memset(h, 0, sizeof *h);
    h->msg_type = msg_type;
    h->teid = teid;
}

void gtpu_pdu_session_container(uint8_t out[2], uint8_t pdu_type, uint8_t qfi, bool rqi)
{
    out[0] = (uint8_t)((pdu_type & 0x0fU) << 4);
    out[1] = (uint8_t)((qfi & 0x3fU) | ((unsigned)rqi << 6));
}

bool gtpu_as_pdu_session_container(const gtpu_ext *e, uint8_t *pdu_type, uint8_t *qfi, bool *rqi)
{
    if (e->typ != GTPU_EXT_PDU_SESSION_CONTAINER || e->len < 2)
        return false;
    *pdu_type = (uint8_t)(e->data[0] >> 4);
    *qfi = (uint8_t)(e->data[1] & 0x3fU);
    *rqi = (e->data[1] & 0x40U) != 0;
    return true;
}

int gtpu_encode(const gtpu_header *h, const uint8_t *payload, size_t plen, uint8_t *out, size_t cap, size_t *outlen)
{
    bool has_opt = h->has_seq || h->has_npdu || h->next > 0;
    uint8_t flags = 0x30;
    size_t opt = 0, length, pos = 8;
    if (h->next > GTPU_MAX_EXT)
        return GTPU_E_EXTENSION;
    if (h->has_seq)
        flags |= FLAG_S;
    if (h->has_npdu)
        flags |= FLAG_PN;
    if (h->next > 0)
        flags |= FLAG_E;
    if (has_opt) {
        opt = 4;
        for (size_t i = 0; i < h->next; i++) {
            if ((h->ext[i].len + 2) % 4 != 0)
                return GTPU_E_EXTENSION_SIZE;
            if ((h->ext[i].len + 2) / 4 > 255)
                return GTPU_E_EXTENSION;
            opt += h->ext[i].len + 2;
        }
    }
    if (plen > 0xffffU || opt > 0xffffU || opt + plen > 0xffffU)
        return GTPU_E_LENGTH;
    length = opt + plen;
    if (cap < 8 + length)
        return GTPU_E_NOSPACE;
    out[0] = flags;
    out[1] = h->msg_type;
    out[2] = (uint8_t)(length >> 8);
    out[3] = (uint8_t)length;
    out[4] = (uint8_t)(h->teid >> 24);
    out[5] = (uint8_t)(h->teid >> 16);
    out[6] = (uint8_t)(h->teid >> 8);
    out[7] = (uint8_t)h->teid;
    if (has_opt) {
        out[pos++] = (uint8_t)(h->has_seq ? h->seq >> 8 : 0);
        out[pos++] = (uint8_t)(h->has_seq ? h->seq : 0);
        out[pos++] = h->has_npdu ? h->npdu : 0;
        out[pos++] = h->next > 0 ? h->ext[0].typ : 0;
        for (size_t i = 0; i < h->next; i++) {
            out[pos++] = (uint8_t)((h->ext[i].len + 2) / 4);
            if (h->ext[i].len)
                memcpy(out + pos, h->ext[i].data, h->ext[i].len);
            pos += h->ext[i].len;
            out[pos++] = i + 1 < h->next ? h->ext[i + 1].typ : 0;
        }
    }
    if (plen)
        memcpy(out + pos, payload, plen);
    *outlen = 8 + length;
    return GTPU_OK;
}

int gtpu_decode(const uint8_t *buf, size_t len, gtpu_header *h, const uint8_t **payload, size_t *plen)
{
    uint8_t flags;
    size_t length, pos;
    const uint8_t *body;
    uint8_t next;
    if (len < 8)
        return GTPU_E_TRUNCATED;
    flags = buf[0];
    if ((flags >> 5) != 1)
        return GTPU_E_VERSION;
    if ((flags & 0x10U) == 0)
        return GTPU_E_PROTOCOL_TYPE;
    length = ((size_t)buf[2] << 8) | buf[3];
    if (len < 8 + length)
        return GTPU_E_LENGTH;
    body = buf + 8;
    gtpu_header_init(h, buf[1], ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) | ((uint32_t)buf[6] << 8) | buf[7]);
    if ((flags & (FLAG_E | FLAG_S | FLAG_PN)) == 0) {
        *payload = body;
        *plen = length;
        return GTPU_OK;
    }
    if (length < 4)
        return GTPU_E_TRUNCATED;
    if (flags & FLAG_S) {
        h->has_seq = true;
        h->seq = (uint16_t)(((unsigned)body[0] << 8) | body[1]);
    }
    if (flags & FLAG_PN) {
        h->has_npdu = true;
        h->npdu = body[2];
    }
    pos = 4;
    next = body[3];
    if (flags & FLAG_E) {
        while (next != 0) {
            size_t total;
            if (pos >= length)
                return GTPU_E_EXTENSION;
            total = (size_t)body[pos] * 4;
            if (total < 2 || pos + total > length || h->next == GTPU_MAX_EXT)
                return GTPU_E_EXTENSION;
            h->ext[h->next].typ = next;
            h->ext[h->next].data = body + pos + 1;
            h->ext[h->next].len = total - 2;
            h->next++;
            next = body[pos + total - 1];
            pos += total;
        }
    }
    *payload = body + pos;
    *plen = length - pos;
    return GTPU_OK;
}
