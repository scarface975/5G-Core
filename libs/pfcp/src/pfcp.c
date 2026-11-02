/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include "g5c/pfcp.h"

#include <string.h>

void pfcp_header_node(pfcp_header *h, uint8_t msg_type, uint32_t seq)
{
    memset(h, 0, sizeof *h);
    h->msg_type = msg_type;
    h->seq = seq;
}

void pfcp_header_session(pfcp_header *h, uint8_t msg_type, uint64_t seid, uint32_t seq)
{
    pfcp_header_node(h, msg_type, seq);
    h->has_seid = true;
    h->seid = seid;
}

int pfcp_encode(const pfcp_header *h, const uint8_t *body, size_t blen, uint8_t *out, size_t cap, size_t *outlen)
{
    uint8_t flags = 0x20; /* version 1 */
    size_t after_len, pos = 4;
    if (h->seq > 0x00ffffffU)
        return PFCP_E_SEQUENCE;
    if (h->follow_on)
        flags |= 0x04;
    if (h->has_priority)
        flags |= 0x02;
    if (h->has_seid)
        flags |= 0x01;
    if (blen > 0xffffU)
        return PFCP_E_LENGTH;
    after_len = 4 + (h->has_seid ? 8U : 0U) + blen;
    if (after_len > 0xffffU)
        return PFCP_E_LENGTH;
    if (cap < 4 + after_len)
        return PFCP_E_NOSPACE;
    out[0] = flags;
    out[1] = h->msg_type;
    out[2] = (uint8_t)(after_len >> 8);
    out[3] = (uint8_t)after_len;
    if (h->has_seid) {
        for (int i = 0; i < 8; i++)
            out[pos++] = (uint8_t)(h->seid >> (8 * (7 - i)));
    }
    out[pos++] = (uint8_t)(h->seq >> 16);
    out[pos++] = (uint8_t)(h->seq >> 8);
    out[pos++] = (uint8_t)h->seq;
    out[pos++] = h->has_priority ? (uint8_t)((h->priority & 0x0fU) << 4) : 0;
    if (blen)
        memcpy(out + pos, body, blen);
    *outlen = 4 + after_len;
    return PFCP_OK;
}

int pfcp_decode(const uint8_t *buf, size_t len, pfcp_header *h, const uint8_t **body, size_t *blen)
{
    uint8_t flags;
    size_t length, fixed;
    const uint8_t *rest, *r;
    bool has_seid;
    if (len < 4)
        return PFCP_E_TRUNCATED;
    flags = buf[0];
    if ((flags >> 5) != 1)
        return PFCP_E_VERSION;
    length = ((size_t)buf[2] << 8) | buf[3];
    if (len < 4 + length)
        return PFCP_E_LENGTH;
    rest = buf + 4;
    has_seid = (flags & 0x01U) != 0;
    fixed = has_seid ? 12U : 4U;
    if (length < fixed)
        return PFCP_E_LENGTH;
    memset(h, 0, sizeof *h);
    r = rest;
    if (has_seid) {
        h->has_seid = true;
        for (int i = 0; i < 8; i++)
            h->seid = (h->seid << 8) | r[i];
        r += 8;
    }
    h->seq = ((uint32_t)r[0] << 16) | ((uint32_t)r[1] << 8) | r[2];
    if (flags & 0x02U) {
        h->has_priority = true;
        h->priority = (uint8_t)(r[3] >> 4);
    }
    h->follow_on = (flags & 0x04U) != 0;
    h->msg_type = buf[1];
    *body = r + 4;
    *blen = length - fixed;
    return PFCP_OK;
}

int pfcp_ie_next(const uint8_t *body, size_t blen, size_t *pos, pfcp_ie *ie)
{
    size_t p = *pos, len;
    if (p >= blen)
        return 0;
    if (blen - p < 4)
        return PFCP_E_TRUNCATED;
    len = ((size_t)body[p + 2] << 8) | body[p + 3];
    if (blen - p - 4 < len)
        return PFCP_E_LENGTH;
    ie->typ = (uint16_t)(((unsigned)body[p] << 8) | body[p + 1]);
    ie->value = body + p + 4;
    ie->len = len;
    *pos = p + 4 + len;
    return 1;
}

int pfcp_put_ie(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, const uint8_t *value, size_t len)
{
    size_t p = *pos;
    if (len > 0xffffU || cap < p || cap - p < 4 + len)
        return PFCP_E_NOSPACE;
    out[p] = (uint8_t)(typ >> 8);
    out[p + 1] = (uint8_t)typ;
    out[p + 2] = (uint8_t)(len >> 8);
    out[p + 3] = (uint8_t)len;
    if (len)
        memcpy(out + p + 4, value, len);
    *pos = p + 4 + len;
    return PFCP_OK;
}
