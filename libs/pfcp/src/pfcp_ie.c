/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _DEFAULT_SOURCE
#include "g5c/pfcp_ie.h"

#include <string.h>
#include <time.h>

/* ---- building ------------------------------------------------------------------------------------------------------------- */

int pfcp_group_begin(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, size_t *mark)
{
    if (cap - *pos < 4 || *pos > cap)
        return PFCP_E_NOSPACE;
    out[*pos] = (uint8_t)(typ >> 8);
    out[*pos + 1] = (uint8_t)typ;
    out[*pos + 2] = out[*pos + 3] = 0;
    *mark = *pos;
    *pos += 4;
    return 0;
}

void pfcp_group_end(uint8_t *out, size_t *pos, size_t mark)
{
    size_t len = *pos - mark - 4;
    out[mark + 2] = (uint8_t)(len >> 8);
    out[mark + 3] = (uint8_t)len;
}

int pfcp_put_u8(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, uint8_t v)
{
    return pfcp_put_ie(out, cap, pos, typ, &v, 1);
}

int pfcp_put_u16(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, uint16_t v)
{
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    return pfcp_put_ie(out, cap, pos, typ, b, 2);
}

int pfcp_put_u32(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, uint32_t v)
{
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    return pfcp_put_ie(out, cap, pos, typ, b, 4);
}

/* little cursor for the typed codecs */
typedef struct {
    const uint8_t *p;
    size_t n, i;
} rd_t;

static bool rd_have(const rd_t *r, size_t k)
{
    return r->n - r->i >= k;
}

static uint64_t rd_be(rd_t *r, size_t k)
{
    uint64_t v = 0;
    for (size_t j = 0; j < k; j++)
        v = (v << 8) | r->p[r->i++];
    return v;
}

static void rd_copy(rd_t *r, uint8_t *dst, size_t k)
{
    memcpy(dst, r->p + r->i, k);
    r->i += k;
}

typedef struct {
    uint8_t *out;
    size_t cap, *pos;
    uint8_t tmp[320];
    size_t n;
} wr_t;

static void wr_be(wr_t *w, uint64_t v, size_t k)
{
    for (size_t j = k; j > 0; j--)
        w->tmp[w->n++] = (uint8_t)(v >> (8 * (j - 1)));
}

static void wr_raw(wr_t *w, const uint8_t *p, size_t k)
{
    memcpy(w->tmp + w->n, p, k);
    w->n += k;
}

static int wr_finish(wr_t *w, uint16_t typ)
{
    return pfcp_put_ie(w->out, w->cap, w->pos, typ, w->tmp, w->n);
}

#define RD(ie) rd_t r = {(ie)->value, (ie)->len, 0}
#define WR(o, c, p) wr_t w = {(o), (c), (p), {0}, 0}

/* ---- integers --------------------------------------------------------------------------------------------------------------- */

int pfcp_get_u8(const pfcp_ie *ie, uint8_t *v)
{
    if (ie->len < 1)
        return -1;
    *v = ie->value[0];
    return 0;
}

int pfcp_get_u16(const pfcp_ie *ie, uint16_t *v)
{
    if (ie->len < 2)
        return -1;
    *v = (uint16_t)((ie->value[0] << 8) | ie->value[1]);
    return 0;
}

int pfcp_get_u32(const pfcp_ie *ie, uint32_t *v)
{
    if (ie->len < 4)
        return -1;
    *v = ((uint32_t)ie->value[0] << 24) | ((uint32_t)ie->value[1] << 16) | ((uint32_t)ie->value[2] << 8) | ie->value[3];
    return 0;
}

/* ---- Node ID ---------------------------------------------------------------------------------------------------------------- */

int pfcp_node_id_decode(const pfcp_ie *ie, pfcp_node_id *n)
{
    RD(ie);
    memset(n, 0, sizeof *n);
    if (!rd_have(&r, 1))
        return -1;
    n->type = r.p[r.i++] & 0x0f;
    if (n->type == 0 && rd_have(&r, 4))
        rd_copy(&r, n->ip4, 4);
    else if (n->type == 1 && rd_have(&r, 16))
        rd_copy(&r, n->ip6, 16);
    else if (n->type == 2 && r.n - r.i < sizeof n->fqdn) {
        memcpy(n->fqdn, r.p + r.i, r.n - r.i);
    } else
        return -1;
    return 0;
}

int pfcp_node_id_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_node_id *n)
{
    WR(out, cap, pos);
    wr_be(&w, n->type, 1);
    if (n->type == 0)
        wr_raw(&w, n->ip4, 4);
    else if (n->type == 1)
        wr_raw(&w, n->ip6, 16);
    else {
        size_t l = strnlen(n->fqdn, sizeof n->fqdn);
        wr_raw(&w, (const uint8_t *)n->fqdn, l);
    }
    return wr_finish(&w, PFCP_IE_NODE_ID);
}

/* ---- F-SEID ----------------------------------------------------------------------------------------------------------------- */

int pfcp_fseid_decode(const pfcp_ie *ie, pfcp_fseid *f)
{
    RD(ie);
    uint8_t fl;
    memset(f, 0, sizeof *f);
    if (!rd_have(&r, 9))
        return -1;
    fl = r.p[r.i++];
    f->v6 = (fl & 1) != 0;
    f->v4 = (fl & 2) != 0;
    f->seid = rd_be(&r, 8);
    if (f->v4) {
        if (!rd_have(&r, 4))
            return -1;
        rd_copy(&r, f->ip4, 4);
    }
    if (f->v6) {
        if (!rd_have(&r, 16))
            return -1;
        rd_copy(&r, f->ip6, 16);
    }
    return (f->v4 || f->v6) ? 0 : -1;
}

int pfcp_fseid_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_fseid *f)
{
    WR(out, cap, pos);
    wr_be(&w, (uint8_t)((f->v6 ? 1 : 0) | (f->v4 ? 2 : 0)), 1);
    wr_be(&w, f->seid, 8);
    if (f->v4)
        wr_raw(&w, f->ip4, 4);
    if (f->v6)
        wr_raw(&w, f->ip6, 16);
    return wr_finish(&w, PFCP_IE_FSEID);
}

/* ---- F-TEID ----------------------------------------------------------------------------------------------------------------- */

int pfcp_fteid_decode(const pfcp_ie *ie, pfcp_fteid *f)
{
    RD(ie);
    uint8_t fl;
    memset(f, 0, sizeof *f);
    if (!rd_have(&r, 1))
        return -1;
    fl = r.p[r.i++];
    f->v4 = (fl & 1) != 0;
    f->v6 = (fl & 2) != 0;
    f->ch = (fl & 4) != 0;
    f->chid = (fl & 8) != 0;
    if (!f->ch) {
        if (!rd_have(&r, 4))
            return -1;
        f->teid = (uint32_t)rd_be(&r, 4);
        if (f->v4) {
            if (!rd_have(&r, 4))
                return -1;
            rd_copy(&r, f->ip4, 4);
        }
        if (f->v6) {
            if (!rd_have(&r, 16))
                return -1;
            rd_copy(&r, f->ip6, 16);
        }
        return (f->v4 || f->v6) ? 0 : -1;
    }
    if (f->chid) {
        if (!rd_have(&r, 1))
            return -1;
        f->choose_id = r.p[r.i++];
    }
    return 0;
}

int pfcp_fteid_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_fteid *f)
{
    WR(out, cap, pos);
    wr_be(&w, (uint8_t)((f->v4 ? 1 : 0) | (f->v6 ? 2 : 0) | (f->ch ? 4 : 0) | (f->chid ? 8 : 0)), 1);
    if (!f->ch) {
        wr_be(&w, f->teid, 4);
        if (f->v4)
            wr_raw(&w, f->ip4, 4);
        if (f->v6)
            wr_raw(&w, f->ip6, 16);
    } else if (f->chid) {
        wr_be(&w, f->choose_id, 1);
    }
    return wr_finish(&w, PFCP_IE_FTEID);
}

/* ---- UE IP Address ---------------------------------------------------------------------------------------------------------- */

int pfcp_ue_ip_decode(const pfcp_ie *ie, pfcp_ue_ip *u)
{
    RD(ie);
    uint8_t fl;
    memset(u, 0, sizeof *u);
    if (!rd_have(&r, 1))
        return -1;
    fl = r.p[r.i++];
    u->v6 = (fl & 1) != 0;
    u->v4 = (fl & 2) != 0;
    u->sd = (fl & 4) != 0;
    u->ipv6d = (fl & 8) != 0;
    u->chv4 = (fl & 16) != 0;
    u->chv6 = (fl & 32) != 0;
    u->has_prefix_len = (fl & 64) != 0;
    if (u->v4) {
        if (!rd_have(&r, 4))
            return -1;
        rd_copy(&r, u->ip4, 4);
    }
    if (u->v6) {
        if (!rd_have(&r, 16))
            return -1;
        rd_copy(&r, u->ip6, 16);
    }
    if (u->ipv6d) {
        if (!rd_have(&r, 1))
            return -1;
        u->ipv6d_len = r.p[r.i++];
    }
    if (u->has_prefix_len) {
        if (!rd_have(&r, 1))
            return -1;
        u->prefix_len = r.p[r.i++];
    }
    return 0;
}

int pfcp_ue_ip_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_ue_ip *u)
{
    WR(out, cap, pos);
    wr_be(&w, (uint8_t)((u->v6 ? 1 : 0) | (u->v4 ? 2 : 0) | (u->sd ? 4 : 0) | (u->ipv6d ? 8 : 0) | (u->chv4 ? 16 : 0) |
                        (u->chv6 ? 32 : 0) | (u->has_prefix_len ? 64 : 0)), 1);
    if (u->v4)
        wr_raw(&w, u->ip4, 4);
    if (u->v6)
        wr_raw(&w, u->ip6, 16);
    if (u->ipv6d)
        wr_be(&w, u->ipv6d_len, 1);
    if (u->has_prefix_len)
        wr_be(&w, u->prefix_len, 1);
    return wr_finish(&w, PFCP_IE_UE_IP_ADDRESS);
}

/* ---- Outer Header Creation -------------------------------------------------------------------------------------------------- */

int pfcp_ohc_decode(const pfcp_ie *ie, pfcp_ohc *o)
{
    RD(ie);
    memset(o, 0, sizeof *o);
    if (!rd_have(&r, 2))
        return -1;
    /* the wire carries octet 5 first: bit 1 of octet 5 is our 0x0001, octet 6 bits go to the high byte */
    o->desc = (uint16_t)(((uint16_t)r.p[0]) | ((uint16_t)r.p[1] << 8));
    r.i = 2;
    if (o->desc & (PFCP_OHC_GTPU_IPV4 | PFCP_OHC_GTPU_IPV6)) {
        if (!rd_have(&r, 4))
            return -1;
        o->teid = (uint32_t)rd_be(&r, 4);
    }
    if (o->desc & (PFCP_OHC_GTPU_IPV4 | PFCP_OHC_UDP_IPV4 | PFCP_OHC_IPV4)) {
        if (!rd_have(&r, 4))
            return -1;
        rd_copy(&r, o->ip4, 4);
    }
    if (o->desc & (PFCP_OHC_GTPU_IPV6 | PFCP_OHC_UDP_IPV6 | PFCP_OHC_IPV6)) {
        if (!rd_have(&r, 16))
            return -1;
        rd_copy(&r, o->ip6, 16);
    }
    if (o->desc & (PFCP_OHC_UDP_IPV4 | PFCP_OHC_UDP_IPV6)) {
        if (!rd_have(&r, 2))
            return -1;
        o->port = (uint16_t)rd_be(&r, 2);
    }
    return 0;
}

int pfcp_ohc_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_ohc *o)
{
    WR(out, cap, pos);
    wr_be(&w, (uint8_t)(o->desc & 0xff), 1);
    wr_be(&w, (uint8_t)(o->desc >> 8), 1);
    if (o->desc & (PFCP_OHC_GTPU_IPV4 | PFCP_OHC_GTPU_IPV6))
        wr_be(&w, o->teid, 4);
    if (o->desc & (PFCP_OHC_GTPU_IPV4 | PFCP_OHC_UDP_IPV4 | PFCP_OHC_IPV4))
        wr_raw(&w, o->ip4, 4);
    if (o->desc & (PFCP_OHC_GTPU_IPV6 | PFCP_OHC_UDP_IPV6 | PFCP_OHC_IPV6))
        wr_raw(&w, o->ip6, 16);
    if (o->desc & (PFCP_OHC_UDP_IPV4 | PFCP_OHC_UDP_IPV6))
        wr_be(&w, o->port, 2);
    return wr_finish(&w, PFCP_IE_OUTER_HEADER_CREATION);
}

/* ---- small ones ------------------------------------------------------------------------------------------------------------- */

int pfcp_apply_action_decode(const pfcp_ie *ie, uint16_t *aa)
{
    if (ie->len < 1)
        return -1;
    *aa = ie->value[0];
    if (ie->len >= 2)
        *aa |= (uint16_t)(ie->value[1] << 8);
    return 0;
}

int pfcp_bitrate_decode(const pfcp_ie *ie, pfcp_bitrate *b)
{
    RD(ie);
    if (!rd_have(&r, 10))
        return -1;
    b->ul = rd_be(&r, 5);
    b->dl = rd_be(&r, 5);
    return 0;
}

int pfcp_bitrate_put(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, const pfcp_bitrate *b)
{
    WR(out, cap, pos);
    wr_be(&w, b->ul & 0xffffffffffULL, 5);
    wr_be(&w, b->dl & 0xffffffffffULL, 5);
    return wr_finish(&w, typ);
}

int pfcp_gate_decode(const pfcp_ie *ie, pfcp_gate *g)
{
    if (ie->len < 1)
        return -1;
    g->ul_closed = ((ie->value[0] >> 2) & 3) != 0; /* values 2 and 3 are to be read as closed */
    g->dl_closed = (ie->value[0] & 3) != 0;
    return 0;
}

int pfcp_sdf_filter_decode(const pfcp_ie *ie, pfcp_sdf_filter *f)
{
    RD(ie);
    uint8_t fl;
    memset(f, 0, sizeof *f);
    if (!rd_have(&r, 2))
        return -1;
    fl = r.p[r.i++];
    r.i++; /* spare */
    f->has_fd = (fl & 1) != 0;
    f->has_ttc = (fl & 2) != 0;
    f->has_spi = (fl & 4) != 0;
    f->has_fl = (fl & 8) != 0;
    f->has_bid = (fl & 16) != 0;
    if (f->has_fd) {
        size_t l;
        if (!rd_have(&r, 2))
            return -1;
        l = (size_t)rd_be(&r, 2);
        if (!rd_have(&r, l) || l >= sizeof f->flow)
            return -1;
        memcpy(f->flow, r.p + r.i, l);
        f->flow[l] = 0;
        r.i += l;
    }
    if (f->has_ttc) {
        if (!rd_have(&r, 2))
            return -1;
        f->tos_traffic_class = (uint16_t)rd_be(&r, 2);
    }
    if (f->has_spi) {
        if (!rd_have(&r, 4))
            return -1;
        f->spi = (uint32_t)rd_be(&r, 4);
    }
    if (f->has_fl) {
        if (!rd_have(&r, 3))
            return -1;
        f->flow_label = (uint32_t)rd_be(&r, 3);
    }
    if (f->has_bid) {
        if (!rd_have(&r, 4))
            return -1;
        f->filter_id = (uint32_t)rd_be(&r, 4);
    }
    return 0;
}

int pfcp_volume_decode(const pfcp_ie *ie, pfcp_volume *v)
{
    RD(ie);
    uint8_t fl;
    memset(v, 0, sizeof *v);
    if (!rd_have(&r, 1))
        return -1;
    fl = r.p[r.i++];
    v->has_total = (fl & 1) != 0;
    v->has_ul = (fl & 2) != 0;
    v->has_dl = (fl & 4) != 0;
    if (v->has_total) {
        if (!rd_have(&r, 8))
            return -1;
        v->total = rd_be(&r, 8);
    }
    if (v->has_ul) {
        if (!rd_have(&r, 8))
            return -1;
        v->ul = rd_be(&r, 8);
    }
    if (v->has_dl) {
        if (!rd_have(&r, 8))
            return -1;
        v->dl = rd_be(&r, 8);
    }
    return 0;
}

int pfcp_volume_meas_put(uint8_t *out, size_t cap, size_t *pos, const pfcp_volume_meas *v)
{
    WR(out, cap, pos);
    wr_be(&w, (uint8_t)((v->has_total ? 1 : 0) | (v->has_ul ? 2 : 0) | (v->has_dl ? 4 : 0) | (v->has_total_pkts ? 8 : 0) |
                        (v->has_ul_pkts ? 16 : 0) | (v->has_dl_pkts ? 32 : 0)), 1);
    if (v->has_total)
        wr_be(&w, v->total, 8);
    if (v->has_ul)
        wr_be(&w, v->ul, 8);
    if (v->has_dl)
        wr_be(&w, v->dl, 8);
    if (v->has_total_pkts)
        wr_be(&w, v->total_pkts, 8);
    if (v->has_ul_pkts)
        wr_be(&w, v->ul_pkts, 8);
    if (v->has_dl_pkts)
        wr_be(&w, v->dl_pkts, 8);
    return wr_finish(&w, PFCP_IE_VOLUME_MEASUREMENT);
}

int pfcp_network_instance_decode(const pfcp_ie *ie, char *out, size_t cap)
{
    size_t i = 0, o = 0;
    if (ie->len == 0 || ie->len >= cap)
        return -1;
    /* DNS-style: length-prefixed labels. A value that does not parse that way is taken verbatim (some peers send plain text). */
    for (; i < ie->len;) {
        size_t l = ie->value[i++];
        if (l == 0 || i + l > ie->len || o + l + 2 > cap)
            goto verbatim;
        if (o)
            out[o++] = '.';
        memcpy(out + o, ie->value + i, l);
        o += l;
        i += l;
    }
    out[o] = 0;
    return 0;
verbatim:
    memcpy(out, ie->value, ie->len);
    out[ie->len] = 0;
    return 0;
}

int pfcp_network_instance_put(uint8_t *out, size_t cap, size_t *pos, const char *name)
{
    WR(out, cap, pos);
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t l = dot ? (size_t)(dot - s) : strlen(s);
        if (l == 0 || l > 63 || w.n + l + 1 > sizeof w.tmp)
            return PFCP_E_NOSPACE;
        wr_be(&w, l, 1);
        wr_raw(&w, (const uint8_t *)s, l);
        s += l + (dot ? 1 : 0);
    }
    return wr_finish(&w, PFCP_IE_NETWORK_INSTANCE);
}

int pfcp_trigger_decode(const pfcp_ie *ie, uint32_t *mask)
{
    if (ie->len < 1)
        return -1;
    *mask = ie->value[0];
    if (ie->len >= 2)
        *mask |= (uint32_t)ie->value[1] << 8;
    if (ie->len >= 3)
        *mask |= (uint32_t)ie->value[2] << 16;
    return 0;
}

int pfcp_trigger_put(uint8_t *out, size_t cap, size_t *pos, uint16_t typ, uint32_t mask)
{
    uint8_t b[3] = {(uint8_t)mask, (uint8_t)(mask >> 8), (uint8_t)(mask >> 16)};
    return pfcp_put_ie(out, cap, pos, typ, b, 3);
}

uint32_t pfcp_ntp_now(void)
{
    return (uint32_t)((uint64_t)time(NULL) + 2208988800ULL); /* 1900-01-01 .. 1970-01-01 */
}
