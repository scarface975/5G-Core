/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: the whole UPF engine. A fresh engine gets the association and the session establishment of a real Open5GS SMF (so
 * TEID 0x1001 and UE 10.46.0.2 exist), then the input is delivered as one of: an N4 message from the SMF, a GTP-U datagram from the
 * gNB, or an IP packet from the data network. Timer ticks follow, so retransmission, report and buffer-expiry paths run too.
 * Input: byte 0 selects the entry point, the rest is the datagram. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/base.h"
#include "g5c/upf.h"
#include "pfcp_vectors.h"

static void io_gtpu(void *c, const upf_addr *to, const uint8_t *p, size_t n)
{
    (void)c;
    (void)to;
    (void)p;
    (void)n;
}

static void io_n6(void *c, const uint8_t *p, size_t n)
{
    (void)c;
    (void)p;
    (void)n;
}

static void io_n4(void *c, const upf_addr *to, const uint8_t *p, size_t n)
{
    (void)c;
    (void)to;
    (void)p;
    (void)n;
}

static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; h[0] && h[1] && n < cap; h += 2) {
        char b[3] = {h[0], h[1], 0};
        out[n++] = (uint8_t)strtoul(b, NULL, 16);
    }
    return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const upf_addr SMF = {false, {127, 1, 0, 4}, 8805}, GNB = {false, {127, 1, 0, 100}, 2152};
    upf_config cfg;
    upf_io io = {NULL, io_gtpu, io_n6, io_n4};
    upf *u;
    uint8_t m[1500];
    size_t n;
    double now = 1000.0;
    static bool quiet;
    if (size < 1)
        return 0;
    if (!quiet) {
        g5c_log_init("error", false);
        quiet = true;
    }
    upf_config_defaults(&cfg);
    cfg.n4_addr = (upf_addr){false, {127, 1, 0, 7}, 8805};
    cfg.n3_addr = (upf_addr){false, {127, 1, 0, 7}, 2152};
    cfg.buffer_max_packets = 8;
    u = upf_new(&cfg, &io, NULL);
    u->next_teid = 0x1000; /* deterministic TEIDs, so GTP-U seeds can hit the session */
    n = unhex(PFCPV_ASSOC_SETUP_REQ, m, sizeof m);
    upf_n4_message(u, &SMF, m, n, now);
    n = unhex(PFCPV_SESS_EST_REQ, m, sizeof m);
    upf_n4_message(u, &SMF, m, n, now);
    switch (data[0] % 3) {
    case 0:
        upf_n4_message(u, &SMF, data + 1, size - 1, now);
        break;
    case 1:
        upf_gtpu_packet(u, &GNB, data + 1, size - 1, now);
        break;
    default:
        upf_n6_packet(u, data + 1, size - 1, now);
        break;
    }
    upf_tick(u, now + 4.0);
    upf_tick(u, now + 20.0);
    upf_free(u);
    return 0;
}
