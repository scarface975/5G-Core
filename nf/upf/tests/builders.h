/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Builders for PFCP requests and user-plane packets, shared by the UPF tests. */
#ifndef G5C_UPF_BUILDERS_H
#define G5C_UPF_BUILDERS_H

#include <string.h>

#include "g5c/gtpu.h"
#include "g5c/pfcp_ie.h"
#include "g5c/testkit.h"
#include "g5c/upf.h"

#pragma GCC diagnostic ignored "-Wunused-function"

static const uint8_t *find_ie(const uint8_t *b, size_t bl, uint16_t typ, pfcp_ie *out, int skip)
{
    size_t pos = 0;
    pfcp_ie ie;
    while (pfcp_ie_next(b, bl, &pos, &ie) == 1)
        if (ie.typ == typ && skip-- == 0) {
            *out = ie;
            return ie.value;
        }
    return NULL;
}

/* ---- builders ---- */

typedef struct {
    uint8_t body[1600];
    size_t pos;
} bld_t;

static void b_assoc(bld_t *b, uint32_t recovery_ts)
{
    pfcp_node_id n;
    memset(&n, 0, sizeof n);
    n.ip4[0] = 127;
    n.ip4[1] = 1;
    n.ip4[3] = 4;
    b->pos = 0;
    pfcp_node_id_put(b->body, sizeof b->body, &b->pos, &n);
    pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_RECOVERY_TIME_STAMP, recovery_ts);
}

static void b_session_head(bld_t *b, uint64_t cp_seid)
{
    pfcp_node_id n;
    pfcp_fseid f;
    memset(&n, 0, sizeof n);
    memset(&f, 0, sizeof f);
    n.ip4[0] = 127;
    n.ip4[1] = 1;
    n.ip4[3] = 4;
    f.v4 = true;
    f.seid = cp_seid;
    memcpy(f.ip4, n.ip4, 4);
    b->pos = 0;
    pfcp_node_id_put(b->body, sizeof b->body, &b->pos, &n);
    pfcp_fseid_put(b->body, sizeof b->body, &b->pos, &f);
}

/* Create PDR for the uplink (access side, CHOOSE TEID) */
static void b_pdr_ul(bld_t *b, uint16_t id, uint32_t prec, uint8_t chid, uint32_t far, uint32_t qer, uint32_t urr, const char *sdf, bool qfi1)
{
    size_t m, m2;
    pfcp_fteid f;
    memset(&f, 0, sizeof f);
    f.v4 = true;
    f.ch = true;
    f.chid = true;
    f.choose_id = chid;
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_CREATE_PDR, &m);
    pfcp_put_u16(b->body, sizeof b->body, &b->pos, PFCP_IE_PDR_ID, id);
    pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_PRECEDENCE, prec);
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_PDI, &m2);
    pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_SOURCE_INTERFACE, UPF_IF_ACCESS);
    pfcp_fteid_put(b->body, sizeof b->body, &b->pos, &f);
    pfcp_network_instance_put(b->body, sizeof b->body, &b->pos, "internet");
    if (qfi1)
        pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_QFI, 1);
    if (sdf) {
        uint8_t v[300];
        size_t l = strlen(sdf);
        v[0] = 1;
        v[1] = 0;
        v[2] = (uint8_t)(l >> 8);
        v[3] = (uint8_t)l;
        memcpy(v + 4, sdf, l);
        pfcp_put_ie(b->body, sizeof b->body, &b->pos, PFCP_IE_SDF_FILTER, v, l + 4);
    }
    pfcp_group_end(b->body, &b->pos, m2);
    pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_OUTER_HEADER_REMOVAL, 0);
    pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_FAR_ID, far);
    if (qer)
        pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_QER_ID, qer);
    if (urr)
        pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_URR_ID, urr);
    pfcp_group_end(b->body, &b->pos, m);
}

/* Create PDR for the downlink (core side, matching the UE address as destination) */
static void b_pdr_dl(bld_t *b, uint16_t id, uint32_t prec, const uint8_t ue[4], uint32_t far, uint32_t qer, uint32_t urr, const char *sdf)
{
    size_t m, m2;
    pfcp_ue_ip u;
    memset(&u, 0, sizeof u);
    u.v4 = true;
    u.sd = true;
    memcpy(u.ip4, ue, 4);
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_CREATE_PDR, &m);
    pfcp_put_u16(b->body, sizeof b->body, &b->pos, PFCP_IE_PDR_ID, id);
    pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_PRECEDENCE, prec);
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_PDI, &m2);
    pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_SOURCE_INTERFACE, UPF_IF_CORE);
    pfcp_network_instance_put(b->body, sizeof b->body, &b->pos, "internet");
    pfcp_ue_ip_put(b->body, sizeof b->body, &b->pos, &u);
    if (sdf) {
        uint8_t v[300];
        size_t l = strlen(sdf);
        v[0] = 1;
        v[1] = 0;
        v[2] = (uint8_t)(l >> 8);
        v[3] = (uint8_t)l;
        memcpy(v + 4, sdf, l);
        pfcp_put_ie(b->body, sizeof b->body, &b->pos, PFCP_IE_SDF_FILTER, v, l + 4);
    }
    pfcp_group_end(b->body, &b->pos, m2);
    pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_FAR_ID, far);
    if (qer)
        pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_QER_ID, qer);
    if (urr)
        pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_URR_ID, urr);
    pfcp_group_end(b->body, &b->pos, m);
}

/* Create FAR; teid != 0 adds forwarding parameters towards the gNB (Outer Header Creation) */
static void b_far(bld_t *b, uint32_t id, uint16_t action, uint8_t dest_if, uint32_t teid, const uint8_t ip[4], uint32_t bar)
{
    size_t m, m2;
    pfcp_ohc o;
    uint8_t aa[2] = {(uint8_t)action, 0};
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_CREATE_FAR, &m);
    pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_FAR_ID, id);
    pfcp_put_ie(b->body, sizeof b->body, &b->pos, PFCP_IE_APPLY_ACTION, aa, 2);
    if (action & PFCP_AA_FORW) {
        pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_FORWARDING_PARAMETERS, &m2);
        pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_DESTINATION_INTERFACE, dest_if);
        if (teid) {
            memset(&o, 0, sizeof o);
            o.desc = PFCP_OHC_GTPU_IPV4;
            o.teid = teid;
            memcpy(o.ip4, ip, 4);
            pfcp_ohc_put(b->body, sizeof b->body, &b->pos, &o);
        }
        pfcp_group_end(b->body, &b->pos, m2);
    }
    if (bar)
        pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_BAR_ID, (uint8_t)bar);
    pfcp_group_end(b->body, &b->pos, m);
}

static void b_qer(bld_t *b, uint32_t id, uint64_t mbr_ul_kbps, uint64_t mbr_dl_kbps, bool ul_closed, bool dl_closed, uint8_t qfi)
{
    size_t m;
    pfcp_bitrate br = {mbr_ul_kbps, mbr_dl_kbps};
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_CREATE_QER, &m);
    pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_QER_ID, id);
    pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_GATE_STATUS, (uint8_t)(((ul_closed ? 1 : 0) << 2) | (dl_closed ? 1 : 0)));
    if (mbr_ul_kbps || mbr_dl_kbps)
        pfcp_bitrate_put(b->body, sizeof b->body, &b->pos, PFCP_IE_MBR, &br);
    if (qfi)
        pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_QFI, qfi);
    pfcp_group_end(b->body, &b->pos, m);
}

static void b_urr(bld_t *b, uint32_t id, uint64_t vol_total_threshold)
{
    size_t m;
    uint8_t vt[9] = {1};
    for (int i = 0; i < 8; i++)
        vt[1 + i] = (uint8_t)(vol_total_threshold >> (8 * (7 - i)));
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_CREATE_URR, &m);
    pfcp_put_u32(b->body, sizeof b->body, &b->pos, PFCP_IE_URR_ID, id);
    pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_MEASUREMENT_METHOD, 2);
    pfcp_trigger_put(b->body, sizeof b->body, &b->pos, PFCP_IE_REPORTING_TRIGGERS, vol_total_threshold ? PFCP_URT_VOLTH : 0);
    if (vol_total_threshold)
        pfcp_put_ie(b->body, sizeof b->body, &b->pos, PFCP_IE_VOLUME_THRESHOLD, vt, 9);
    pfcp_group_end(b->body, &b->pos, m);
}

static void b_bar(bld_t *b, uint8_t id)
{
    size_t m;
    pfcp_group_begin(b->body, sizeof b->body, &b->pos, PFCP_IE_CREATE_BAR, &m);
    pfcp_put_u8(b->body, sizeof b->body, &b->pos, PFCP_IE_BAR_ID, id);
    pfcp_group_end(b->body, &b->pos, m);
}

/* ---- packets ---- */

static size_t ipv4(uint8_t *p, const uint8_t src[4], const uint8_t dst[4], uint8_t proto, uint16_t sport, uint16_t dport, size_t total)
{
    memset(p, 0, total);
    p[0] = 0x45;
    p[2] = (uint8_t)(total >> 8);
    p[3] = (uint8_t)total;
    p[8] = 64;
    p[9] = proto;
    memcpy(p + 12, src, 4);
    memcpy(p + 16, dst, 4);
    if (proto == 6 || proto == 17) {
        p[20] = (uint8_t)(sport >> 8);
        p[21] = (uint8_t)sport;
        p[22] = (uint8_t)(dport >> 8);
        p[23] = (uint8_t)dport;
    }
    return total;
}

/* G-PDU uplink with a PDU Session Container (UL, qfi) */
static size_t gpdu_ul(uint8_t *out, size_t cap, uint32_t teid, uint8_t qfi, const uint8_t *ip, size_t iplen)
{
    gtpu_header h;
    uint8_t cont[2];
    size_t n = 0;
    gtpu_header_init(&h, GTPU_G_PDU, teid);
    if (qfi) {
        gtpu_pdu_session_container(cont, 1, qfi, false);
        h.ext[0].typ = GTPU_EXT_PDU_SESSION_CONTAINER;
        h.ext[0].data = cont;
        h.ext[0].len = 2;
        h.next = 1;
    }
    TK_ASSERT(gtpu_encode(&h, ip, iplen, out, cap, &n) == 0);
    return n;
}

/* A tiny language for raw IE trees, including malformed ones: "TYPE:HEX" is a leaf (decimal type, hex value, empty value allowed), "TYPE:{ . }" a group */
static const char *dsl_items(bld_t *b, const char *p)
{
    while (*p) {
        char *end;
        unsigned long typ;
        while (*p == ' ')
            p++;
        if (*p == '}' || *p == 0)
            return p;
        typ = strtoul(p, &end, 10);
        TK_ASSERT(end != p && *end == ':');
        p = end + 1;
        if (*p == '{') {
            size_t mark;
            pfcp_group_begin(b->body, sizeof b->body, &b->pos, (uint16_t)typ, &mark);
            p = dsl_items(b, p + 1);
            TK_ASSERT(*p == '}');
            p++;
            pfcp_group_end(b->body, &b->pos, mark);
        } else {
            uint8_t v[600];
            size_t n = 0;
            while ((p[0] >= '0' && p[0] <= '9') || (p[0] >= 'a' && p[0] <= 'f')) {
                char h[3] = {p[0], p[1], 0};
                v[n++] = (uint8_t)strtoul(h, NULL, 16);
                p += 2;
            }
            pfcp_put_ie(b->body, sizeof b->body, &b->pos, (uint16_t)typ, v, n);
        }
    }
    return p;
}

static void b_dsl(bld_t *b, const char *text)
{
    TK_ASSERT(*dsl_items(b, text) == 0);
}

#endif
