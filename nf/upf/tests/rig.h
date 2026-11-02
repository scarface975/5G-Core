/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Test rig for the UPF engine: fake SMF, gNB and data network, plus builders for PFCP requests. */
#ifndef G5C_UPF_RIG_H
#define G5C_UPF_RIG_H

#include <string.h>

#include "g5c/testkit.h"
#include "builders.h"
#include "g5c/upf.h"

typedef struct {
    upf_addr to;
    uint8_t d[2400];
    size_t n;
} cap_t;

typedef struct {
    cap_t n4[128], gtpu[256], n6[256];
    size_t nn4, ngtpu, nn6;
} rig_t;

static rig_t RIG;
static upf *U;
static double NOW = 1000.0;
static const upf_addr SMF = {false, {127, 1, 0, 4}, 8805};
static const upf_addr GNB = {false, {127, 1, 0, 100}, 2152};
static const upf_addr UPF_N4 = {false, {127, 1, 0, 7}, 8805};
static const upf_addr UPF_N3 = {false, {127, 1, 0, 7}, 2152};

static void cap_push(cap_t *arr, size_t *n, size_t max, const upf_addr *to, const uint8_t *d, size_t len)
{
    TK_ASSERT(*n < max && len <= sizeof arr[0].d);
    arr[*n].to = *to;
    memcpy(arr[*n].d, d, len);
    arr[*n].n = len;
    (*n)++;
}

/* data-plane captures keep the first 256 packets; beyond that only the count grows */
static void cap_push_lossy(cap_t *arr, size_t *n, size_t max, const upf_addr *to, const uint8_t *d, size_t len)
{
    if (*n < max) {
        cap_push(arr, n, max, to, d, len);
        return;
    }
    (*n)++;
}

static void io_gtpu(void *c, const upf_addr *to, const uint8_t *p, size_t n)
{
    (void)c;
    cap_push_lossy(RIG.gtpu, &RIG.ngtpu, 256, to, p, n);
}

static void io_n6(void *c, const uint8_t *p, size_t n)
{
    upf_addr none;
    (void)c;
    memset(&none, 0, sizeof none);
    cap_push_lossy(RIG.n6, &RIG.nn6, 256, &none, p, n);
}

static void io_n4(void *c, const upf_addr *to, const uint8_t *p, size_t n)
{
    (void)c;
    cap_push(RIG.n4, &RIG.nn4, 128, to, p, n);
}

static void rig_reset_captures(void)
{
    RIG.nn4 = RIG.ngtpu = RIG.nn6 = 0;
}

static upf *rig_new(void (*tweak)(upf_config *))
{
    upf_config c;
    upf_io io = {NULL, io_gtpu, io_n6, io_n4};
    upf_config_defaults(&c);
    c.n4_addr = UPF_N4;
    c.n3_addr = UPF_N3;
    c.heartbeat_interval = 0;
    if (tweak)
        tweak(&c);
    memset(&RIG, 0, sizeof RIG);
    NOW = 1000.0;
    U = upf_new(&c, &io, NULL);
    return U;
}

/* newest captured N4 message of a type; fills the header and returns a pointer to its body */
static const uint8_t *rig_n4(uint8_t type, pfcp_header *h, size_t *blen)
{
    for (size_t i = RIG.nn4; i > 0; i--) {
        const uint8_t *b;
        if (pfcp_decode(RIG.n4[i - 1].d, RIG.n4[i - 1].n, h, &b, blen) == 0 && h->msg_type == type)
            return b;
    }
    return NULL;
}

static int cause_of(const uint8_t *b, size_t bl)
{
    pfcp_ie ie;
    uint8_t c;
    if (!find_ie(b, bl, PFCP_IE_CAUSE, &ie, 0) || pfcp_get_u8(&ie, &c) != 0)
        return -1;
    return c;
}

static uint32_t SEQ = 100;

/* send a PFCP request body from the SMF and return the cause of the answer */
static void send_n4(uint8_t type, bool session, uint64_t seid, const uint8_t *body, size_t blen)
{
    uint8_t out[2000];
    size_t n = 0;
    pfcp_header h;
    if (session)
        pfcp_header_session(&h, type, seid, ++SEQ);
    else
        pfcp_header_node(&h, type, ++SEQ);
    TK_ASSERT(pfcp_encode(&h, body, blen, out, sizeof out, &n) == 0);
    upf_n4_message(U, &SMF, out, n, NOW);
}

#endif
