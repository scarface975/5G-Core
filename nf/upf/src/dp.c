/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The packet pipeline: classify with PDRs, enforce QERs, apply FARs, count with URRs (TS 29.244 5.2, TS 23.501 5.8). */
#include <string.h>

#include "priv.h"

#define GTPU_PORT 2152
#define MAX_PKT 9200

/* ---- helpers ---------------------------------------------------------------------------------------------------------------------- */

static bool bucket_take(upf_bucket *b, size_t bytes, double now)
{
    if (!b->enabled)
        return true;
    b->tokens += (now - b->last) * b->rate_bytes_per_s;
    if (b->tokens > b->burst)
        b->tokens = b->burst;
    b->last = now;
    if (b->tokens < (double)bytes)
        return false;
    b->tokens -= (double)bytes;
    return true;
}

/* gates and rate limits of every QER the PDR points at; false = drop */
static bool qer_pass(upf *u, upf_session *s, const upf_pdr *p, bool ul, size_t len, double now)
{
    for (size_t i = 0; i < p->nqer; i++) {
        upf_qer *q = sess_find_qer(s, p->qer_ids[i]);
        if (q == NULL)
            continue;
        if (ul ? q->ul_closed : q->dl_closed) {
            u->st.drop_gate++;
            return false;
        }
        if (!bucket_take(ul ? &q->ul : &q->dl, len, now)) {
            u->st.drop_rate++;
            return false;
        }
    }
    return true;
}

static uint8_t pdr_qfi(upf_session *s, const upf_pdr *p)
{
    if (p->has_qfi)
        return p->qfi;
    for (size_t i = 0; i < p->nqer; i++) {
        upf_qer *q = sess_find_qer(s, p->qer_ids[i]);
        if (q && q->has_qfi)
            return q->qfi;
    }
    return 1;
}

/* GTP-U G-PDU towards the far end of an Outer Header Creation. With a PDU Session Container (downlink, QFI) when the
 * destination is the access network. */
static void tx_encap(upf *u, const upf_far *f, bool container, uint8_t qfi, const uint8_t *payload, size_t len)
{
    uint8_t out[MAX_PKT + 16];
    upf_addr to;
    size_t hl = container ? 16 : 8;
    uint32_t teid = f->ohc.teid;
    if (len > MAX_PKT) {
        u->st.drop_bad_packet++;
        return;
    }
    if (container) {
        out[0] = 0x34; /* v1, PT, E */
        out[1] = GTPU_G_PDU;
        out[2] = (uint8_t)((len + 8) >> 8);
        out[3] = (uint8_t)(len + 8);
        put_be32(out + 4, teid);
        out[8] = out[9] = out[10] = 0; /* seq, N-PDU */
        out[11] = GTPU_EXT_PDU_SESSION_CONTAINER;
        out[12] = 1; /* 4 octets */
        out[13] = 0; /* PDU type 0: DL PDU session information */
        out[14] = qfi & 0x3f;
        out[15] = 0;
    } else {
        out[0] = 0x30;
        out[1] = GTPU_G_PDU;
        out[2] = (uint8_t)(len >> 8);
        out[3] = (uint8_t)len;
        put_be32(out + 4, teid);
    }
    memcpy(out + hl, payload, len);
    memset(&to, 0, sizeof to);
    memcpy(to.b, f->ohc.ip4, 4);
    to.port = (f->ohc.desc & PFCP_OHC_UDP_IPV4) && f->ohc.port ? f->ohc.port : GTPU_PORT;
    u->io.tx_gtpu(u->io.ctx, &to, out, len + hl);
}

void dp_send_end_marker(upf *u, const upf_far *f)
{
    uint8_t out[8];
    upf_addr to;
    if (!f->has_ohc)
        return;
    out[0] = 0x30;
    out[1] = GTPU_END_MARKER;
    out[2] = out[3] = 0;
    put_be32(out + 4, f->ohc.teid);
    memset(&to, 0, sizeof to);
    memcpy(to.b, f->ohc.ip4, 4);
    to.port = (f->ohc.desc & PFCP_OHC_UDP_IPV4) && f->ohc.port ? f->ohc.port : GTPU_PORT;
    u->io.tx_gtpu(u->io.ctx, &to, out, 8);
    u->st.end_marker++;
}

/* ---- buffering ------------------------------------------------------------------------------------------------------------------- */

void dp_drop_buffer(upf_session *s)
{
    for (size_t i = 0; i < s->nbuf; i++)
        free(s->buf[i].data);
    s->nbuf = 0;
    s->buf_bytes = 0;
}

static void buffer_packet(upf *u, upf_session *s, const upf_far *f, const upf_pdr *p, const uint8_t *pkt, size_t len, double now)
{
    uint32_t max_pkts = u->cfg.buffer_max_packets;
    if (f->has_bar) {
        upf_bar *b = sess_find_bar(s, f->bar_id);
        if (b && b->suggested_count)
            max_pkts = b->suggested_count < max_pkts || max_pkts == 0 ? b->suggested_count : max_pkts;
    }
    if (s->nbuf >= max_pkts || s->buf_bytes + len > u->cfg.buffer_max_bytes) {
        u->st.drop_buffer++;
        return;
    }
    if (s->nbuf == s->capbuf) {
        s->capbuf = s->capbuf ? s->capbuf * 2 : 16;
        s->buf = g5c_xrealloc(s->buf, s->capbuf * sizeof *s->buf);
    }
    s->buf[s->nbuf].data = g5c_xmalloc(len);
    memcpy(s->buf[s->nbuf].data, pkt, len);
    s->buf[s->nbuf].len = len;
    s->buf[s->nbuf].t = now;
    s->nbuf++;
    s->buf_bytes += len;
    u->st.buffered++;
    if ((f->action & PFCP_AA_NOCP) && !s->dl_report_sent && s->peer < u->npeers && u->peers[s->peer].established) {
        uint16_t id = p->id;
        s->dl_report_sent = true;
        n4_send_session_report(u, s, 1 /* DLDR */, &id, NULL, 0);
    }
}

void dp_buffer_expire(upf *u, double now)
{
    for (size_t i = 0; i < u->nsessions; i++) {
        upf_session *s = u->sessions[i];
        size_t k = 0;
        if (s == NULL || s->nbuf == 0)
            continue;
        while (k < s->nbuf && now - s->buf[k].t > u->cfg.buffer_max_age) {
            free(s->buf[k].data);
            s->buf_bytes -= s->buf[k].len;
            u->st.drop_buffer++;
            k++;
        }
        if (k) {
            memmove(s->buf, s->buf + k, (s->nbuf - k) * sizeof *s->buf);
            s->nbuf -= k;
        }
    }
}

/* ---- the actions ---------------------------------------------------------------------------------------------------------------- */

static void forward(upf *u, upf_session *s, const upf_pdr *p, const upf_far *f, bool ul, const uint8_t *pkt, size_t len, double now)
{
    if (f->action & PFCP_AA_BUFF) {
        buffer_packet(u, s, f, p, pkt, len, now);
        return;
    }
    if (!(f->action & PFCP_AA_FORW)) { /* DROP, or no action at all */
        u->st.drop_far++;
        return;
    }
    if (f->has_ohc) {
        bool to_access = f->dest_if == UPF_IF_ACCESS;
        tx_encap(u, f, to_access && !ul, pdr_qfi(s, p), pkt, len);
    } else if (f->dest_if == UPF_IF_CORE || f->dest_if == UPF_IF_SGILAN) {
        if (!ul) { /* downlink traffic back out to the data network: nothing to deliver it to */
            u->st.drop_no_route++;
            return;
        }
        u->io.tx_n6(u->io.ctx, pkt, len);
    } else {
        u->st.drop_no_route++;
        return;
    }
    if (ul) {
        u->st.ul_pkts++;
        u->st.ul_bytes += len;
    } else {
        u->st.dl_pkts++;
        u->st.dl_bytes += len;
    }
    urr_account(u, s, p, ul, len, now);
}

static void apply(upf *u, upf_session *s, const upf_pdr *p, bool ul, const uint8_t *pkt, size_t len, double now)
{
    upf_far *f;
    if (!p->has_far || (f = sess_find_far(s, p->far_id)) == NULL) {
        u->st.drop_far++;
        return;
    }
    if (f->action & PFCP_AA_DROP) {
        u->st.drop_far++;
        return;
    }
    if (!qer_pass(u, s, p, ul, len, now))
        return;
    forward(u, s, p, f, ul, pkt, len, now);
}

static bool sdf_ok(const upf_session *s, const upf_pdr *p, const upf_flow *f, bool swap)
{
    upf_flow g = *f;
    if (p->nsdf == 0)
        return true;
    if (swap) {
        memcpy(g.src, f->dst, 16);
        memcpy(g.dst, f->src, 16);
        g.sport = f->dport;
        g.dport = f->sport;
    }
    for (size_t i = 0; i < p->nsdf; i++)
        if (upf_sdf_match(&p->sdf[i], &g, s->has_ue4 ? &s->ue4 : NULL, s->has_ue6 ? &s->ue6 : NULL))
            return true;
    return false;
}

/* ---- downlink: from the data network -------------------------------------------------------------------------------------------- */

static void dl_dispatch(upf *u, const uint8_t *pkt, size_t len, double now)
{
    upf_session *s = NULL;
    const upf_pdr *best = NULL;
    upf_flow flow;
    bool have_flow = false;
    if (len < 20) {
        u->st.drop_bad_packet++;
        return;
    }
    if ((pkt[0] >> 4) == 4) {
        uint32_t k = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) | ((uint32_t)pkt[18] << 8) | pkt[19];
        s = ptrmap_get(u->by_ue4, k);
    } else if ((pkt[0] >> 4) == 6 && len >= 40) {
        uint64_t k = 0;
        for (int i = 0; i < 8; i++)
            k = (k << 8) | pkt[24 + i];
        s = ptrmap_get(u->by_ue6, k);
    } else {
        u->st.drop_bad_packet++;
        return;
    }
    if (s == NULL) {
        u->st.drop_no_session++;
        return;
    }
    for (size_t i = 0; i < s->npdr; i++) {
        const upf_pdr *p = &s->pdr[i];
        if (p->src_if != UPF_IF_CORE && p->src_if != UPF_IF_SGILAN)
            continue;
        if (best && p->precedence >= best->precedence)
            continue;
        if (p->nsdf) {
            if (!have_flow) {
                if (!upf_flow_from_packet(pkt, len, &flow)) {
                    u->st.drop_bad_packet++;
                    return;
                }
                have_flow = true;
            }
            if (!sdf_ok(s, p, &flow, false))
                continue;
        }
        best = p;
    }
    if (best == NULL) {
        u->st.drop_no_pdr++;
        return;
    }
    apply(u, s, best, false, pkt, len, now);
}

void upf_n6_packet(upf *u, const uint8_t *ip_pkt, size_t len, double now)
{
    u->now = now;
    dl_dispatch(u, ip_pkt, len, now);
}

void dp_flush_buffer(upf *u, upf_session *s, double now)
{
    upf_buffered *list = s->buf;
    size_t n = s->nbuf;
    s->buf = NULL;
    s->nbuf = 0;
    s->capbuf = 0;
    s->buf_bytes = 0;
    s->dl_report_sent = false;
    for (size_t i = 0; i < n; i++) {
        u->st.flushed++;
        dl_dispatch(u, list[i].data, list[i].len, now);
        free(list[i].data);
    }
    free(list);
}

/* ---- uplink: from the access network ---------------------------------------------------------------------------------------------- */

static void send_error_indication(upf *u, const upf_addr *to, uint32_t teid)
{
    uint8_t out[24];
    double now = u->now;
    if (now - u->last_err_ind >= 1.0) { /* at most 100 per second */
        u->last_err_ind = now;
        u->err_ind_budget = 100;
    }
    if (u->err_ind_budget == 0)
        return;
    u->err_ind_budget--;
    /* TS 29.281 7.3.1: TEID data I (type 16) and GTP-U peer address (type 133) */
    out[0] = 0x32; /* v1, PT, S */
    out[1] = GTPU_ERROR_INDICATION;
    out[4] = out[5] = out[6] = out[7] = 0;
    out[8] = out[9] = out[10] = out[11] = 0; /* seq, npdu, next */
    out[12] = 16;
    put_be32(out + 13, teid);
    out[17] = 133;
    out[18] = 0;
    out[19] = (uint8_t)(to->v6 ? 16 : 4);
    memcpy(out + 20, u->cfg.n3_addr.b, 4);
    out[2] = 0;
    out[3] = (uint8_t)(4 + 5 + 3 + 4);
    u->io.tx_gtpu(u->io.ctx, to, out, 24);
    u->st.error_ind++;
}

static void ul_gpdu(upf *u, const upf_addr *from, const gtpu_header *h, const uint8_t *pl, size_t plen, double now)
{
    upf_session *s = ptrmap_get(u->by_teid, h->teid);
    const upf_pdr *best = NULL;
    uint8_t qfi = 0xff;
    upf_flow flow;
    bool have_flow = false;
    if (s == NULL) {
        u->st.drop_no_session++;
        G5C_LOGD("g5c_upf", "uplink packet for unknown TEID %08x from %u.%u.%u.%u: Error Indication", h->teid, from->b[0], from->b[1], from->b[2], from->b[3]);
        send_error_indication(u, from, h->teid);
        return;
    }
    if (plen < 20) {
        u->st.drop_bad_packet++;
        return;
    }
    for (size_t i = 0; i < h->next; i++) {
        uint8_t t, q;
        bool r;
        if (gtpu_as_pdu_session_container(&h->ext[i], &t, &q, &r))
            qfi = q;
    }
    for (size_t i = 0; i < s->npdr; i++) {
        const upf_pdr *p = &s->pdr[i];
        if (!p->has_fteid || p->local_teid != h->teid)
            continue;
        if (best && p->precedence >= best->precedence)
            continue;
        if (p->has_qfi && qfi != 0xff && p->qfi != qfi)
            continue;
        if (p->nsdf) {
            if (!have_flow) {
                if (!upf_flow_from_packet(pl, plen, &flow)) {
                    u->st.drop_bad_packet++;
                    return;
                }
                have_flow = true;
            }
            if (!sdf_ok(s, p, &flow, p->src_if == UPF_IF_ACCESS)) /* uplink packets are matched against the downlink-oriented rule */
                continue;
        }
        best = p;
    }
    if (best == NULL) {
        u->st.drop_no_pdr++;
        return;
    }
    if (u->cfg.check_source && best->src_if == UPF_IF_ACCESS) {
        bool ok = false;
        if ((pl[0] >> 4) == 4)
            ok = s->has_ue4 && memcmp(pl + 12, s->ue4.b, 4) == 0;
        else if ((pl[0] >> 4) == 6 && plen >= 40) {
            static const uint8_t zero[16] = {0};
            ok = (s->has_ue6 && memcmp(pl + 8, s->ue6.b, 8) == 0) || (pl[8] == 0xfe && (pl[9] & 0xc0) == 0x80) || memcmp(pl + 8, zero, 16) == 0;
        }
        if (!ok) {
            u->st.drop_spoof++;
            return;
        }
    }
    apply(u, s, best, true, pl, plen, now);
}

void upf_gtpu_packet(upf *u, const upf_addr *from, const uint8_t *pkt, size_t len, double now)
{
    gtpu_header h;
    const uint8_t *pl;
    size_t plen;
    u->now = now;
    if (gtpu_decode(pkt, len, &h, &pl, &plen) != 0) {
        u->st.drop_bad_packet++;
        return;
    }
    switch (h.msg_type) {
    case GTPU_G_PDU:
        ul_gpdu(u, from, &h, pl, plen, now);
        break;
    case GTPU_ECHO_REQUEST: {
        uint8_t out[16];
        size_t n = 0;
        gtpu_header r;
        static const uint8_t recovery[2] = {14, 0}; /* Recovery IE (restart counter 0) */
        gtpu_header_init(&r, GTPU_ECHO_RESPONSE, 0);
        r.has_seq = h.has_seq;
        r.seq = h.seq;
        if (gtpu_encode(&r, recovery, 2, out, sizeof out, &n) == 0) {
            u->io.tx_gtpu(u->io.ctx, from, out, n);
            u->st.echo++;
        }
        break;
    }
    case GTPU_ECHO_RESPONSE:
        break;
    case GTPU_ERROR_INDICATION:
        u->st.error_ind++;
        break;
    case GTPU_END_MARKER:
        u->st.end_marker++;
        break;
    default:
        u->st.drop_bad_packet++;
        break;
    }
}
