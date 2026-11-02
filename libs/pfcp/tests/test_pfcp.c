/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include "g5c/pfcp.h"
#include "g5c/testkit.h"

#define HEX(name, s)                                \
    uint8_t name[128];                              \
    long name##_n = tk_hex((s), name, sizeof name); \
    TK_ASSERT(name##_n >= 0)

static void test_heartbeat_known_bytes(void)
{
    uint8_t body[16], pkt[64];
    size_t bl = 0, n = 0, pos = 0, blen = 0;
    pfcp_header h, d;
    const uint8_t *b;
    pfcp_ie ie;
    const uint8_t ts[4] = {0xe5, 0xc8, 0x3a, 0x00};
    HEX(want, "2001000c 000001 00 0060 0004 e5c83a00");
    /* TS 29.244 7.4.2.1: node message, seq 1, Recovery Time Stamp IE (4 octets) */
    TK_ASSERT(pfcp_put_ie(body, sizeof body, &bl, PFCP_IE_RECOVERY_TIME_STAMP, ts, 4) == 0);
    pfcp_header_node(&h, PFCP_HEARTBEAT_REQUEST, 1);
    TK_ASSERT(pfcp_encode(&h, body, bl, pkt, sizeof pkt, &n) == 0);
    TK_ASSERT(n == (size_t)want_n && memcmp(pkt, want, n) == 0);
    TK_ASSERT(pfcp_decode(pkt, n, &d, &b, &blen) == 0 && d.msg_type == PFCP_HEARTBEAT_REQUEST && d.seq == 1 && !d.has_seid);
    TK_ASSERT(pfcp_ie_next(b, blen, &pos, &ie) == 1 && ie.typ == 96 && ie.len == 4 && memcmp(ie.value, ts, 4) == 0);
    TK_ASSERT(pfcp_ie_next(b, blen, &pos, &ie) == 0);
}

static void test_session_header(void)
{
    pfcp_header h, d;
    uint8_t pkt[32];
    size_t n = 0, blen = 99;
    const uint8_t *b;
    pfcp_header_session(&h, PFCP_SESSION_ESTABLISHMENT_REQUEST, 0x0102030405060708ULL, 0x00abcdef);
    h.has_priority = true;
    h.priority = 5;
    h.follow_on = true;
    TK_ASSERT(pfcp_encode(&h, NULL, 0, pkt, sizeof pkt, &n) == 0);
    TK_ASSERT(pkt[0] == 0x27 && (((unsigned)pkt[2] << 8) | pkt[3]) == 12);
    TK_ASSERT(pfcp_decode(pkt, n, &d, &b, &blen) == 0);
    TK_ASSERT(d.has_seid && d.seid == 0x0102030405060708ULL && d.seq == 0x00abcdef && d.has_priority && d.priority == 5 &&
              d.follow_on && blen == 0);
}

static void test_rejects(void)
{
    pfcp_header h;
    const uint8_t *b;
    size_t bl;
    uint8_t out[16];
    size_t n;
    HEX(a, "20");
    HEX(v2, "40010004 00000100");
    HEX(long_len, "20010010 00000100");
    HEX(short_len, "20010002 0000");
    HEX(bad_ie, "00 01 00 09 01");
    TK_ASSERT(pfcp_decode(a, (size_t)a_n, &h, &b, &bl) == PFCP_E_TRUNCATED);
    TK_ASSERT(pfcp_decode(v2, (size_t)v2_n, &h, &b, &bl) == PFCP_E_VERSION);
    TK_ASSERT(pfcp_decode(long_len, (size_t)long_len_n, &h, &b, &bl) == PFCP_E_LENGTH);
    TK_ASSERT(pfcp_decode(short_len, (size_t)short_len_n, &h, &b, &bl) == PFCP_E_LENGTH);
    pfcp_header_node(&h, 1, 0x01000000);
    TK_ASSERT(pfcp_encode(&h, NULL, 0, out, sizeof out, &n) == PFCP_E_SEQUENCE);
    pfcp_header_node(&h, 1, 1);
    TK_ASSERT(pfcp_encode(&h, NULL, 0, out, 4, &n) == PFCP_E_NOSPACE);
    {
        size_t pos = 0;
        pfcp_ie ie;
        TK_ASSERT(pfcp_ie_next(bad_ie, (size_t)bad_ie_n, &pos, &ie) < 0);
    }
}

static void test_random_input(void)
{
    tk_rng rng = {99};
    for (int it = 0; it < 200000; it++) {
        uint8_t b[48], re[160];
        pfcp_header h, h2;
        const uint8_t *body, *body2;
        size_t blen, blen2, n, pos = 0;
        pfcp_ie ie;
        tk_rng_bytes(&rng, b, sizeof b);
        b[0] = (uint8_t)(0x20 | (b[0] & 0x07));
        if (pfcp_decode(b, sizeof b, &h, &body, &blen) == 0) {
            while (pfcp_ie_next(body, blen, &pos, &ie) == 1)
                ;
            TK_ASSERT(pfcp_encode(&h, body, blen, re, sizeof re, &n) == 0);
            TK_ASSERT(pfcp_decode(re, n, &h2, &body2, &blen2) == 0);
            TK_ASSERT(h2.msg_type == h.msg_type && h2.seq == h.seq && h2.has_seid == h.has_seid && h2.seid == h.seid &&
                      h2.has_priority == h.has_priority && h2.priority == h.priority && h2.follow_on == h.follow_on &&
                      blen2 == blen && (blen == 0 || memcmp(body, body2, blen) == 0));
        }
    }
}

int main(void)
{
    test_heartbeat_known_bytes();
    test_session_header();
    test_rejects();
    test_random_input();
    puts("pfcp: ok");
    return 0;
}
