/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Unit tests of the UPF's building blocks: the integer hash map (model-based), IPFilterRule parsing and matching, and the IP header parser. */
#include <string.h>

#include "g5c/testkit.h"
#include "g5c/upf.h"
#include "priv.h"

static void test_ptrmap(void)
{
    enum { SPACE = 500 };
    upf_ptrmap *m = ptrmap_new();
    static int vals[SPACE];
    void *model[SPACE];
    tk_rng r = {0xabcdef12345ULL};
    memset(model, 0, sizeof model);
    for (int op = 0; op < 200000; op++) {
        unsigned k = (unsigned)(tk_rng_next(&r) % SPACE), what = (unsigned)(tk_rng_next(&r) % 10);
        uint64_t key = (uint64_t)k * 7919u + (k % 7 == 0 ? 0x100000000ULL : 0); /* clusters and large keys */
        if (what < 5) {
            vals[k] = op;
            ptrmap_put(m, key, &vals[k]);
            model[k] = &vals[k];
        } else if (what < 8) {
            ptrmap_del(m, key);
            model[k] = NULL;
        } else {
            TK_ASSERT(ptrmap_get(m, key) == model[k]);
        }
        if (op % 20000 == 0) {
            size_t live = 0;
            for (unsigned i = 0; i < SPACE; i++) {
                uint64_t kk = (uint64_t)i * 7919u + (i % 7 == 0 ? 0x100000000ULL : 0);
                TK_ASSERT(ptrmap_get(m, kk) == model[i]);
                live += model[i] != NULL;
            }
            TK_ASSERT(ptrmap_len(m) == live);
        }
    }
    ptrmap_del(m, 0xdeadbeefULL); /* deleting what is absent is harmless */
    ptrmap_free(m);
}

static void test_sdf_parse(void)
{
    static const char *const good[] = {
        "permit out ip from any to any", "permit out 17 from any to assigned", "permit in 6 from 10.0.0.0/8 to assigned 80",
        "permit out 17 from 192.0.2.1 53 to assigned 1024-65535", "permit out 6 from any 80,443,8000-8010 to assigned",
        "permit out 58 from ff02::2/128 to assigned", "deny out ip from any to any", "permit out 1 from 0.0.0.0/0 to 10.46.0.0/16",
        "permit out ip from 2001:db8::/32 to assigned",
    };
    static const char *const bad[] = {
        "", "permit", "permit out ip from any", "permit out ip from any to", "allow out ip from any to any", "permit sideways ip from any to any",
        "permit out banana from any to any", "permit out 999 from any to any", "permit out ip to any from any", "permit out ip from 300.1.1.1 to any",
        "permit out ip from 10.0.0.0/33 to any", "permit out ip from 10.0.0.0/x to any", "permit out ip from any 70000 to any",
        "permit out ip from any 100-50 to any", "permit out ip from any 1,2,3,4,5,6,7,8,9 to any", "permit out ip from any 80 to any junk-port",
        "permit out ip from ::g/64 to any", "permit out ip from any x to any",
    };
    upf_sdf r;
    char err[100];
    for (size_t i = 0; i < sizeof good / sizeof *good; i++)
        if (upf_sdf_parse(good[i], &r, err, sizeof err) != 0)
            TK_FAIL("rule refused: %s (%s)", good[i], err);
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
        if (upf_sdf_parse(bad[i], &r, err, sizeof err) == 0)
            TK_FAIL("rule accepted: [%s]", bad[i]);
    TK_ASSERT(upf_sdf_parse("x", &r, NULL, 0) != 0); /* no error buffer is fine */
    {   /* a rule longer than we accept */
        char big[400];
        memset(big, 'a', sizeof big);
        big[399] = 0;
        TK_ASSERT(upf_sdf_parse(big, &r, err, sizeof err) != 0);
    }
}

static upf_flow flow4(uint8_t proto, const uint8_t s[4], const uint8_t d[4], uint16_t sp, uint16_t dp)
{
    upf_flow f;
    memset(&f, 0, sizeof f);
    f.proto = proto;
    memcpy(f.src, s, 4);
    memcpy(f.dst, d, 4);
    f.sport = sp;
    f.dport = dp;
    return f;
}

static void test_sdf_match(void)
{
    const upf_addr ue4 = {false, {10, 46, 0, 2}, 0}, ue6 = {true, {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1}, 0};
    const uint8_t A[4] = {192, 0, 2, 1}, B[4] = {10, 46, 0, 2}, C[4] = {10, 46, 0, 9}, D[4] = {8, 8, 8, 8};
    upf_sdf r;
    upf_flow f;
    TK_ASSERT(upf_sdf_parse("permit out 17 from 192.0.2.0/24 53 to assigned 1024-2048,5000", &r, NULL, 0) == 0);
    f = flow4(17, A, B, 53, 1500);
    TK_ASSERT(upf_sdf_match(&r, &f, &ue4, NULL));
    f = flow4(17, A, B, 53, 5000);
    TK_ASSERT(upf_sdf_match(&r, &f, &ue4, NULL));
    f = flow4(17, A, B, 53, 3000);
    TK_ASSERT(!upf_sdf_match(&r, &f, &ue4, NULL)); /* port outside the ranges */
    f = flow4(6, A, B, 53, 1500);
    TK_ASSERT(!upf_sdf_match(&r, &f, &ue4, NULL)); /* protocol */
    f = flow4(17, D, B, 53, 1500);
    TK_ASSERT(!upf_sdf_match(&r, &f, &ue4, NULL)); /* source network */
    f = flow4(17, A, C, 53, 1500);
    TK_ASSERT(!upf_sdf_match(&r, &f, &ue4, NULL)); /* not the assigned address */
    TK_ASSERT(!upf_sdf_match(&r, &f, NULL, NULL)); /* no UE address known */
    f = flow4(1, A, B, 0, 0);
    TK_ASSERT(upf_sdf_parse("permit out ip from any to assigned", &r, NULL, 0) == 0 && upf_sdf_match(&r, &f, &ue4, NULL)); /* ICMP: no ports to check */
    TK_ASSERT(upf_sdf_parse("permit out 1 from any 80 to assigned", &r, NULL, 0) == 0 && !upf_sdf_match(&r, &f, &ue4, NULL)); /* ports on a protocol without any */
    TK_ASSERT(upf_sdf_parse("deny out ip from any to any", &r, NULL, 0) == 0 && !upf_sdf_match(&r, &f, &ue4, NULL));
    /* prefix lengths that are not a multiple of eight */
    TK_ASSERT(upf_sdf_parse("permit out ip from 192.0.2.0/25 to any", &r, NULL, 0) == 0);
    f = flow4(17, A, B, 1, 2);
    TK_ASSERT(upf_sdf_match(&r, &f, &ue4, NULL));
    {
        const uint8_t hi[4] = {192, 0, 2, 200};
        f = flow4(17, hi, B, 1, 2);
        TK_ASSERT(!upf_sdf_match(&r, &f, &ue4, NULL));
    }
    /* IPv6 */
    TK_ASSERT(upf_sdf_parse("permit out ip from 2001:db8::/32 to assigned", &r, NULL, 0) == 0);
    memset(&f, 0, sizeof f);
    f.v6 = true;
    f.proto = 17;
    f.src[0] = 0x20;
    f.src[1] = 0x01;
    f.src[2] = 0x0d;
    f.src[3] = 0xb8;
    f.src[15] = 5;
    memcpy(f.dst, ue6.b, 8);
    f.dst[15] = 9;
    TK_ASSERT(upf_sdf_match(&r, &f, &ue4, &ue6));
    f.dst[7] = 2; /* another /64 */
    TK_ASSERT(!upf_sdf_match(&r, &f, &ue4, &ue6));
    f.dst[7] = 1;
    TK_ASSERT(!upf_sdf_match(&r, &f, &ue4, NULL)); /* no IPv6 address known */
    f.src[0] = 0x30;
    TK_ASSERT(!upf_sdf_match(&r, &f, &ue4, &ue6));
    {   /* a v4 rule never matches a v6 packet and vice versa */
        upf_sdf v4;
        TK_ASSERT(upf_sdf_parse("permit out ip from 192.0.2.0/24 to any", &v4, NULL, 0) == 0 && !upf_sdf_match(&v4, &f, &ue4, &ue6));
    }
    {
        upf_sdf same;
        upf_addr a = {false, {1, 2, 3, 4}, 7}, b = {false, {1, 2, 3, 4}, 9}, c = {true, {1, 2, 3, 4}, 7};
        TK_ASSERT(upf_addr_equal_ip(&a, &b) && !upf_addr_equal_ip(&a, &c));
        (void)same;
    }
}

static void test_flow_from_packet(void)
{
    uint8_t p[200];
    upf_flow f;
    memset(p, 0, sizeof p);
    /* IPv4 UDP with IP options (IHL 6) */
    p[0] = 0x46;
    p[9] = 17;
    p[12] = 10; p[13] = 46; p[15] = 2;
    p[16] = 8; p[17] = 8; p[18] = 8; p[19] = 8;
    p[24] = 0x04; p[25] = 0xd2; p[26] = 0x00; p[27] = 0x35;
    TK_ASSERT(upf_flow_from_packet(p, 40, &f) && !f.v6 && f.proto == 17 && f.sport == 1234 && f.dport == 53 && f.dst[0] == 8);
    /* IPv4 fragment that is not the first: ports are unknown but the packet is still classified */
    p[0] = 0x45;
    p[6] = 0x00;
    p[7] = 0x10;
    TK_ASSERT(upf_flow_from_packet(p, 40, &f) && f.sport == 0 && f.dport == 0);
    p[7] = 0;
    /* ICMP has no ports */
    p[9] = 1;
    p[20] = 8;
    TK_ASSERT(upf_flow_from_packet(p, 40, &f) && f.proto == 1 && f.sport == 0);
    /* truncations and garbage */
    TK_ASSERT(!upf_flow_from_packet(p, 19, &f));
    p[0] = 0x4f;
    TK_ASSERT(!upf_flow_from_packet(p, 40, &f)); /* IHL beyond the packet */
    p[0] = 0x41;
    TK_ASSERT(!upf_flow_from_packet(p, 40, &f)); /* IHL below the minimum */
    p[0] = 0x25;
    TK_ASSERT(!upf_flow_from_packet(p, 40, &f)); /* neither v4 nor v6 */
    /* IPv6 UDP, then behind a hop-by-hop and a destination options header */
    memset(p, 0, sizeof p);
    p[0] = 0x60;
    p[6] = 17;
    p[8] = 0x20; p[9] = 0x01; p[23] = 1;
    p[24] = 0x20; p[25] = 0x01; p[39] = 2;
    p[40] = 0x13; p[41] = 0x88; p[42] = 0x00; p[43] = 0x50;
    TK_ASSERT(upf_flow_from_packet(p, 60, &f) && f.v6 && f.proto == 17 && f.sport == 5000 && f.dport == 80);
    p[6] = 0;   /* hop-by-hop */
    p[40] = 60; /* next: destination options */
    p[41] = 0;  /* 8 bytes */
    p[48] = 17; /* next: UDP */
    p[49] = 0;
    p[56] = 0x00; p[57] = 0x35; p[58] = 0x00; p[59] = 0x35;
    TK_ASSERT(upf_flow_from_packet(p, 80, &f) && f.proto == 17 && f.sport == 53);
    TK_ASSERT(!upf_flow_from_packet(p, 39, &f)); /* shorter than the fixed header */
    {   /* a truncated chain of extension headers still yields a flow without ports */
        TK_ASSERT(upf_flow_from_packet(p, 44, &f));
    }
}

int main(void)
{
    test_ptrmap();
    test_sdf_parse();
    test_sdf_match();
    test_flow_from_packet();
    puts("upf units: ok");
    return 0;
}
