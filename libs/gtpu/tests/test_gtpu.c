/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include "g5c/gtpu.h"
#include "g5c/testkit.h"

#define HEX(name, s)                                  \
    uint8_t name[256];                                \
    long name##_n = tk_hex((s), name, sizeof name);   \
    TK_ASSERT(name##_n >= 0)

static void test_known_bytes(void)
{
    uint8_t out[64], psc[2];
    size_t n = 0, plen = 0;
    const uint8_t *p;
    gtpu_header h, d;
    uint8_t pt, qfi;
    bool rqi;
    const uint8_t payload[4] = {0xde, 0xad, 0xbe, 0xef};
    HEX(want1, "30ff0004 00000001 deadbeef");
    HEX(want2, "34ff0009 00001234 00000085 01000900 45");

    gtpu_header_init(&h, GTPU_G_PDU, 1); /* TS 29.281 5.1: flags 0x30, type 0xff, length 4, TEID 1 */
    TK_ASSERT(gtpu_encode(&h, payload, 4, out, sizeof out, &n) == 0);
    TK_ASSERT(n == (size_t)want1_n && memcmp(out, want1, n) == 0);
    TK_ASSERT(gtpu_decode(out, n, &d, &p, &plen) == 0 && d.msg_type == GTPU_G_PDU && d.teid == 1 && !d.has_seq && d.next == 0);
    TK_ASSERT(plen == 4 && memcmp(p, payload, 4) == 0);

    gtpu_header_init(&h, GTPU_G_PDU, 0x1234);
    gtpu_pdu_session_container(psc, 0, 9, false);
    h.ext[0] = (gtpu_ext){GTPU_EXT_PDU_SESSION_CONTAINER, psc, 2};
    h.next = 1;
    TK_ASSERT(gtpu_encode(&h, (const uint8_t[]){0x45}, 1, out, sizeof out, &n) == 0);
    TK_ASSERT(n == (size_t)want2_n && memcmp(out, want2, n) == 0); /* E flag -> 0x34, length = 4 + 4 + 1 */
    TK_ASSERT(gtpu_decode(out, n, &d, &p, &plen) == 0 && d.next == 1);
    TK_ASSERT(gtpu_as_pdu_session_container(&d.ext[0], &pt, &qfi, &rqi) && pt == 0 && qfi == 9 && !rqi);
    TK_ASSERT(plen == 1 && p[0] == 0x45);
}

static void test_roundtrip_seq_npdu(void)
{
    gtpu_header h, d;
    uint8_t out[32];
    size_t n = 0, plen = 99;
    const uint8_t *p;
    gtpu_header_init(&h, GTPU_ECHO_REQUEST, 0);
    h.has_seq = true;
    h.seq = 0xabcd;
    h.has_npdu = true;
    h.npdu = 3;
    TK_ASSERT(gtpu_encode(&h, NULL, 0, out, sizeof out, &n) == 0);
    TK_ASSERT(gtpu_decode(out, n, &d, &p, &plen) == 0 && d.has_seq && d.seq == 0xabcd && d.has_npdu && d.npdu == 3 && plen == 0);
}

static void test_rejects(void)
{
    gtpu_header h;
    const uint8_t *p;
    size_t plen;
    HEX(a, "30ff");
    HEX(b, "50ff0000 00000001");
    HEX(c, "20ff0000 00000001");
    HEX(d, "30ff0010 00000001");
    HEX(e, "34ff0008 00000001 00000085 00000000");
    TK_ASSERT(gtpu_decode(a, (size_t)a_n, &h, &p, &plen) == GTPU_E_TRUNCATED);
    TK_ASSERT(gtpu_decode(b, (size_t)b_n, &h, &p, &plen) == GTPU_E_VERSION);
    TK_ASSERT(gtpu_decode(c, (size_t)c_n, &h, &p, &plen) == GTPU_E_PROTOCOL_TYPE);
    TK_ASSERT(gtpu_decode(d, (size_t)d_n, &h, &p, &plen) == GTPU_E_LENGTH);
    TK_ASSERT(gtpu_decode(e, (size_t)e_n, &h, &p, &plen) == GTPU_E_EXTENSION); /* extension length 0 */
    {   /* encoding errors */
        gtpu_header x;
        uint8_t out[16], odd[3] = {1, 2, 3};
        size_t n;
        gtpu_header_init(&x, GTPU_G_PDU, 1);
        x.ext[0] = (gtpu_ext){0x85, odd, 3};
        x.next = 1;
        TK_ASSERT(gtpu_encode(&x, NULL, 0, out, sizeof out, &n) == GTPU_E_EXTENSION_SIZE);
        gtpu_header_init(&x, GTPU_G_PDU, 1);
        TK_ASSERT(gtpu_encode(&x, odd, 3, out, 8, &n) == GTPU_E_NOSPACE);
    }
}

/* Fuzz-style: arbitrary bytes must never crash; successful decodes must re-encode identically. */
static void test_random_input(void)
{
    tk_rng rng = {42};
    for (int it = 0; it < 200000; it++) {
        uint8_t b[40], re[128];
        gtpu_header h, h2;
        const uint8_t *p, *p2;
        size_t plen, plen2, n;
        tk_rng_bytes(&rng, b, sizeof b);
        b[0] = (uint8_t)(0x30 | (b[0] & 0x07));
        if (gtpu_decode(b, sizeof b, &h, &p, &plen) == 0) {
            TK_ASSERT(gtpu_encode(&h, p, plen, re, sizeof re, &n) == 0);
            TK_ASSERT(gtpu_decode(re, n, &h2, &p2, &plen2) == 0);
            TK_ASSERT(h2.msg_type == h.msg_type && h2.teid == h.teid && h2.has_seq == h.has_seq && h2.seq == h.seq &&
                      h2.has_npdu == h.has_npdu && h2.npdu == h.npdu && h2.next == h.next && plen2 == plen &&
                      (plen == 0 || memcmp(p, p2, plen) == 0));
            for (size_t i = 0; i < h.next; i++)
                TK_ASSERT(h2.ext[i].typ == h.ext[i].typ && h2.ext[i].len == h.ext[i].len &&
                          (h.ext[i].len == 0 || memcmp(h2.ext[i].data, h.ext[i].data, h.ext[i].len) == 0));
        }
    }
}

int main(void)
{
    test_known_bytes();
    test_roundtrip_seq_npdu();
    test_rejects();
    test_random_input();
    puts("gtpu: ok");
    return 0;
}
