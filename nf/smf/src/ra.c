/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* IPv6 Router Advertisement for a PDU session (RFC 4861 4.1 / 4.2; TS 23.501 5.8.2.2.3, TS 29.061-style prefix: one /64 per session, on-link, SLAAC). */
#include <string.h>

#include "g5c/smf.h"

static uint16_t csum(const uint8_t src[16], const uint8_t dst[16], const uint8_t *icmp, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < 16; i += 2)
        sum += (uint32_t)(src[i] << 8 | src[i + 1]) + (uint32_t)(dst[i] << 8 | dst[i + 1]);
    sum += (uint32_t)len + 58u;
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)(icmp[i] << 8 | icmp[i + 1]);
    if (len & 1)
        sum += (uint32_t)icmp[len - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

int smf_ra_build(const uint8_t prefix[8], uint16_t mtu, const uint8_t *rs, size_t rslen, uint8_t *out, size_t cap, size_t *len)
{
    static const uint8_t all_nodes[16] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t unspec[16] = {0};
    uint8_t src[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, dst[16];
    size_t pl = 16 + 32 + (mtu != 0 ? 8 : 0), i = 0;
    uint16_t c;
    /* the solicitation: IPv6, next header ICMPv6, hop limit 255, type 133 code 0, valid checksum (RFC 4861 6.1.1) */
    if (rslen < 48 || (rs[0] >> 4) != 6 || rs[6] != 58 || rs[7] != 255 || rs[40] != 133 || rs[41] != 0)
        return -1;
    {
        size_t plen = (size_t)(rs[4] << 8 | rs[5]);
        uint16_t got = (uint16_t)(rs[42] << 8 | rs[43]);
        uint8_t tmp[1500];
        if (plen < 8 || plen + 40 > rslen || plen > sizeof tmp)
            return -1;
        memcpy(tmp, rs + 40, plen);
        tmp[2] = tmp[3] = 0;
        c = csum(rs + 8, rs + 24, tmp, plen);
        if (c != got)
            return -1;
    }
    memcpy(dst, memcmp(rs + 8, unspec, 16) == 0 ? all_nodes : rs + 8, 16);
    if (cap < 40 + pl + 8)
        return -1;
    memset(out, 0, 40 + pl);
    out[0] = 0x60;
    out[4] = (uint8_t)(pl >> 8);
    out[5] = (uint8_t)pl;
    out[6] = 58;
    out[7] = 255;
    memcpy(out + 8, src, 16);
    memcpy(out + 24, dst, 16);
    i = 40;
    out[i++] = 134; /* router advertisement */
    out[i++] = 0;
    out[i++] = 0; /* checksum, below */
    out[i++] = 0;
    out[i++] = 64;     /* current hop limit */
    out[i++] = 0;      /* M and O flags clear: addresses by SLAAC, no DHCPv6 */
    out[i++] = 0x07;   /* router lifetime 1800 s */
    out[i++] = 0x08;
    i += 8;            /* reachable time and retrans timer: unspecified */
    out[i++] = 3;      /* prefix information */
    out[i++] = 4;
    out[i++] = 64;     /* prefix length */
    out[i++] = 0xc0;   /* on-link, autonomous */
    out[i++] = 0x00; /* valid lifetime 86400 s */
    out[i++] = 0x01;
    out[i++] = 0x51;
    out[i++] = 0x80;
    out[i++] = 0x00; /* preferred lifetime 3600 s */
    out[i++] = 0x00;
    out[i++] = 0x0e;
    out[i++] = 0x10;
    i += 4;
    memcpy(out + i, prefix, 8);
    i += 16;
    if (mtu != 0) {
        out[i++] = 5; /* MTU option */
        out[i++] = 1;
        i += 2;
        out[i++] = 0;
        out[i++] = 0;
        out[i++] = (uint8_t)(mtu >> 8);
        out[i++] = (uint8_t)mtu;
    }
    c = csum(src, dst, out + 40, pl);
    out[42] = (uint8_t)(c >> 8);
    out[43] = (uint8_t)c;
    *len = 40 + pl;
    return 0;
}
