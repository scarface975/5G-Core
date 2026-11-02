/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Packet pipeline throughput of the UPF engine alone (classification, QER, FAR, URR, GTP-U encapsulation), with no sockets and no
 * kernel in the loop, so it shows the ceiling the runtime can approach. Opt-in (needs an optimised build):
 *     G5C_PERF=1 ~/g5c-cbuild/plain/nf/upf/bench_upf        Without G5C_PERF it does nothing. */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "g5c/base.h"
#include "rig.h"

static uint64_t cnt_ul, cnt_dl, bytes_ul, bytes_dl;

static void c_gtpu(void *c, const upf_addr *to, const uint8_t *p, size_t n)
{
    (void)c;
    (void)to;
    (void)p;
    cnt_dl++;
    bytes_dl += n;
}

static void c_n6(void *c, const uint8_t *p, size_t n)
{
    (void)c;
    (void)p;
    cnt_ul++;
    bytes_ul += n;
}

static void c_n4(void *c, const upf_addr *to, const uint8_t *p, size_t n)
{
    (void)c;
    (void)to;
    (void)p;
    (void)n;
}

static double secs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint32_t make_sessions(int nsessions, uint32_t *teids)
{
    bld_t b;
    pfcp_header h;
    size_t bl;
    const uint8_t *body;
    bld_t a;
    b_assoc(&a, 1);
    send_n4(PFCP_ASSOCIATION_SETUP_REQUEST, false, 0, a.body, a.pos);
    for (int i = 0; i < nsessions; i++) {
        uint8_t ue[4] = {10, 46, (uint8_t)(i >> 8), (uint8_t)(i & 255)};
        pfcp_ie ie, g;
        pfcp_fteid f;
        ue[3] = (uint8_t)(2 + (i & 0xfd));
        ue[2] = (uint8_t)(i >> 8);
        b_session_head(&b, (uint64_t)i + 1);
        b_pdr_ul(&b, 1, 100, 1, 1, 1, 1, NULL, true);
        b_pdr_dl(&b, 2, 100, ue, 2, 1, 1, NULL);
        b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
        b_far(&b, 2, PFCP_AA_FORW, UPF_IF_ACCESS, 1000 + (uint32_t)i, (const uint8_t[4]){127, 1, 0, 100}, 0);
        b_qer(&b, 1, 0, 0, false, false, 9); /* gates open, no rate limit: the cost of the checks without the limiting */
        b_urr(&b, 1, 0);
        RIG.nn4 = 0;
        send_n4(PFCP_SESSION_ESTABLISHMENT_REQUEST, true, 0, b.body, b.pos);
        body = rig_n4(PFCP_SESSION_ESTABLISHMENT_RESPONSE, &h, &bl);
        TK_ASSERT(body && find_ie(body, bl, PFCP_IE_CREATED_PDR, &g, 0) && find_ie(g.value, g.len, PFCP_IE_FTEID, &ie, 0) && pfcp_fteid_decode(&ie, &f) == 0);
        teids[i] = f.teid;
    }
    return 0;
}

static void run(const char *name, int nsessions, size_t pktlen, uint64_t iters)
{
    enum { MAXS = 1024 };
    static uint32_t teids[MAXS];
    uint8_t ul_ip[1500], dl_ip[1500], ul_gtp[1600];
    uint8_t (*dl_pkts)[1500] = malloc((size_t)nsessions * 1500);
    uint8_t (*ul_pkts)[1600] = malloc((size_t)nsessions * 1600);
    size_t ul_len[MAXS];
    double t0, t1;
    uint64_t i;
    rig_new(NULL);
    TK_ASSERT(nsessions <= MAXS && dl_pkts && ul_pkts);
    make_sessions(nsessions, teids);
    for (int s = 0; s < nsessions; s++) {
        uint8_t ue[4] = {10, 46, (uint8_t)(s >> 8), (uint8_t)(2 + (s & 0xfd))};
        const uint8_t dn[4] = {10, 99, 0, 1};
        ipv4(ul_ip, ue, dn, 17, 4000, 53, pktlen);
        ul_len[s] = gpdu_ul(ul_gtp, sizeof ul_gtp, teids[s], 1, ul_ip, pktlen);
        memcpy(ul_pkts[s], ul_gtp, ul_len[s]);
        ipv4(dl_ip, dn, ue, 17, 53, 4000, pktlen);
        memcpy(dl_pkts[s], dl_ip, pktlen);
    }
    U->io.tx_gtpu = c_gtpu;
    U->io.tx_n6 = c_n6;
    U->io.tx_n4 = c_n4;
    cnt_ul = cnt_dl = bytes_ul = bytes_dl = 0;
    t0 = secs();
    for (i = 0; i < iters; i++)
        upf_gtpu_packet(U, &GNB, ul_pkts[i % (uint64_t)nsessions], ul_len[i % (uint64_t)nsessions], 1000.0);
    t1 = secs();
    printf("%-26s uplink   %8.2f Mpps  %7.2f Gbit/s (inner payload)\n", name, (double)cnt_ul / (t1 - t0) / 1e6, (double)(cnt_ul * pktlen) * 8 / (t1 - t0) / 1e9);
    t0 = secs();
    for (i = 0; i < iters; i++)
        upf_n6_packet(U, dl_pkts[i % (uint64_t)nsessions], pktlen, 1000.0);
    t1 = secs();
    printf("%-26s downlink %8.2f Mpps  %7.2f Gbit/s (inner payload)\n", name, (double)cnt_dl / (t1 - t0) / 1e6, (double)(cnt_dl * pktlen) * 8 / (t1 - t0) / 1e9);
    TK_ASSERT(cnt_ul == iters && cnt_dl == iters);
    if (pktlen == 1400 && nsessions == 1) { /* Stage A of the plan: >= 1 Gbit/s on one host; the engine must leave plenty of room for the kernel */
        double gbps = (double)(cnt_dl * pktlen) * 8 / (t1 - t0) / 1e9;
        TK_ASSERT(gbps >= 5.0);
    }
    upf_free(U);
    free(dl_pkts);
    free(ul_pkts);
    (void)bytes_ul;
    (void)bytes_dl;
}

int main(void)
{
    g5c_log_init("error", false);
    if (getenv("G5C_PERF") == NULL) {
        puts("bench_upf: G5C_PERF not set, skipping");
        return 0;
    }
    run("64 B, 1 session", 1, 64, 5000000);
    run("512 B, 1 session", 1, 512, 5000000);
    run("1400 B, 1 session", 1, 1400, 5000000);
    run("1400 B, 1000 sessions", 1000, 1400, 5000000);
    return 0;
}
