/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* N4 (PFCP) message handling for the UP function: TS 29.244 clauses 6 and 7. */
#include <string.h>

#include "priv.h"
#include "rules.h"

#define T1_SECONDS 3.0
#define N1_RETRIES 3
#define CACHE_SECONDS 10.0

/* rules_* return 0 on success, a PFCP cause otherwise; the handlers keep a cause value throughout */
static inline int okc(int rc)
{
    return rc == 0 ? PFCP_CAUSE_ACCEPTED : rc;
}

/* ---- peers, sending and the response cache --------------------------------------------------------------------------------------- */

upf_peer *n4_find_peer(upf *u, const upf_addr *a)
{
    for (size_t i = 0; i < u->npeers; i++)
        if (upf_addr_equal_ip(&u->peers[i].addr, a))
            return &u->peers[i];
    return NULL;
}

bool upf_peer_established(const upf *u, const upf_addr *a)
{
    for (size_t i = 0; i < u->npeers; i++)
        if (upf_addr_equal_ip(&u->peers[i].addr, a))
            return u->peers[i].established;
    return false;
}

static uint32_t peer_index(upf *u, const upf_peer *p)
{
    return (uint32_t)(p - u->peers);
}

void n4_send(upf *u, const upf_addr *to, const uint8_t *msg, size_t len)
{
    u->st.n4_tx++;
    u->io.tx_n4(u->io.ctx, to, msg, len);
}

static void cache_put(upf *u, const upf_addr *from, uint32_t seq, const uint8_t *resp, size_t len)
{
    upf_cached *c = &u->cache[u->cache_next++ % (sizeof u->cache / sizeof *u->cache)];
    free(c->resp);
    c->resp = g5c_xmalloc(len);
    memcpy(c->resp, resp, len);
    c->len = len;
    c->seq = seq;
    c->from = *from;
    c->t = u->now;
}

static bool cache_replay(upf *u, const upf_addr *from, uint32_t seq)
{
    for (size_t i = 0; i < sizeof u->cache / sizeof *u->cache; i++) {
        upf_cached *c = &u->cache[i];
        if (c->resp && c->seq == seq && upf_addr_equal_ip(&c->from, from) && u->now - c->t < CACHE_SECONDS) {
            n4_send(u, from, c->resp, c->len);
            return true;
        }
    }
    return false;
}

/* header (+ optional SEID) + body, sent and remembered for retransmitted requests */
static void reply(upf *u, const upf_addr *to, const pfcp_header *req, uint8_t type, bool session, uint64_t seid, const uint8_t *body, size_t blen)
{
    uint8_t out[1500 + 16];
    size_t n = 0;
    pfcp_header h;
    if (session)
        pfcp_header_session(&h, type, seid, req->seq);
    else
        pfcp_header_node(&h, type, req->seq);
    if (pfcp_encode(&h, body, blen, out, sizeof out, &n) != 0)
        return;
    n4_send(u, to, out, n);
    cache_put(u, to, req->seq, out, n);
}

static int put_node_id(const upf *u, uint8_t *out, size_t cap, size_t *pos)
{
    pfcp_node_id n;
    memset(&n, 0, sizeof n);
    memcpy(n.ip4, u->cfg.n4_addr.b, 4);
    return pfcp_node_id_put(out, cap, pos, &n);
}

static void put_cause(uint8_t *out, size_t cap, size_t *pos, uint8_t cause, uint16_t offending)
{
    (void)pfcp_put_u8(out, cap, pos, PFCP_IE_CAUSE, cause);
    if (offending)
        (void)pfcp_put_u16(out, cap, pos, PFCP_IE_OFFENDING_IE, offending);
}

/* ---- peer lifecycle ---------------------------------------------------------------------------------------------------------------- */

void n4_peer_down(upf *u, uint32_t pi)
{
    upf_peer *p = &u->peers[pi];
    G5C_LOGW("g5c_upf", "N4 association with %u.%u.%u.%u down: its sessions are removed", p->addr.b[0], p->addr.b[1], p->addr.b[2], p->addr.b[3]);
    p->established = false;
    for (size_t i = 0; i < u->nsessions; i++) {
        upf_session *s = u->sessions[i];
        if (s != NULL && s->peer == pi)
            upf_session_delete(u, s);
    }
}

static void handle_association_setup(upf *u, const upf_addr *from, const pfcp_header *h, const uint8_t *body, size_t blen)
{
    uint8_t out[128];
    size_t pos = 0, ipos = 0;
    pfcp_ie ie;
    pfcp_node_id node;
    bool have_node = false, have_ts = false;
    uint32_t ts = 0;
    upf_peer *p;
    memset(&node, 0, sizeof node);
    while (pfcp_ie_next(body, blen, &ipos, &ie) == 1) {
        if (ie.typ == PFCP_IE_NODE_ID && pfcp_node_id_decode(&ie, &node) == 0)
            have_node = true;
        else if (ie.typ == PFCP_IE_RECOVERY_TIME_STAMP && pfcp_get_u32(&ie, &ts) == 0)
            have_ts = true;
    }
    put_node_id(u, out, sizeof out, &pos);
    if (!have_node || !have_ts) {
        put_cause(out, sizeof out, &pos, PFCP_CAUSE_MANDATORY_IE_MISSING, have_node ? PFCP_IE_RECOVERY_TIME_STAMP : PFCP_IE_NODE_ID);
        reply(u, from, h, PFCP_ASSOCIATION_SETUP_RESPONSE, false, 0, out, pos);
        return;
    }
    p = n4_find_peer(u, from);
    if (p == NULL) {
        u->peers = g5c_xrealloc(u->peers, (u->npeers + 1) * sizeof *u->peers);
        p = &u->peers[u->npeers++];
        memset(p, 0, sizeof *p);
        p->addr = *from; /* requests we originate (heartbeats) go to where the peer's own come from */
    } else if (p->established && p->recovery_ts != ts) { /* the SMF restarted: its old sessions are gone for good */
        n4_peer_down(u, peer_index(u, p));
    }
    G5C_LOGI("g5c_upf", "N4 association with %u.%u.%u.%u established (recovery %u)", from->b[0], from->b[1], from->b[2], from->b[3], ts);
    p->established = true;
    p->recovery_ts = ts;
    p->last_rx = u->now;
    p->hb_missed = 0;
    p->node_type = node.type;
    put_cause(out, sizeof out, &pos, PFCP_CAUSE_ACCEPTED, 0);
    pfcp_put_u32(out, sizeof out, &pos, PFCP_IE_RECOVERY_TIME_STAMP, u->recovery_ts);
    {   /* UP Function Features (8.2.25): only what is implemented. FTUP: F-TEIDs are allocated here (CHOOSE). EMPU: End Marker packets are sent.
         * Not claimed: DLBD/DDND (the BAR timers of Session Report Response / notification delay), PFDM (PFD management is accepted and ignored). */
        uint8_t f[4] = {PFCP_UPF5_FTUP, PFCP_UPF6_EMPU, 0x00, 0x00};
        pfcp_put_ie(out, sizeof out, &pos, PFCP_IE_UP_FUNCTION_FEATURES, f, 4);
    }
    reply(u, from, h, PFCP_ASSOCIATION_SETUP_RESPONSE, false, 0, out, pos);
}

static void handle_association_release(upf *u, const upf_addr *from, const pfcp_header *h)
{
    uint8_t out[64];
    size_t pos = 0;
    upf_peer *p = n4_find_peer(u, from);
    put_node_id(u, out, sizeof out, &pos);
    put_cause(out, sizeof out, &pos, p && p->established ? PFCP_CAUSE_ACCEPTED : PFCP_CAUSE_NO_ESTABLISHED_ASSOCIATION, 0);
    reply(u, from, h, PFCP_ASSOCIATION_RELEASE_RESPONSE, false, 0, out, pos);
    if (p && p->established)
        n4_peer_down(u, peer_index(u, p));
}

static void handle_heartbeat(upf *u, const upf_addr *from, const pfcp_header *h, const uint8_t *body, size_t blen, bool is_request)
{
    upf_peer *p = n4_find_peer(u, from);
    size_t pos = 0;
    pfcp_ie ie;
    while (pfcp_ie_next(body, blen, &pos, &ie) == 1) {
        uint32_t ts;
        if (ie.typ == PFCP_IE_RECOVERY_TIME_STAMP && pfcp_get_u32(&ie, &ts) == 0 && p && p->established && p->recovery_ts != ts)
            n4_peer_down(u, peer_index(u, p)); /* restarted without a new association setup: drop what it left behind */
    }
    if (p)
        p->hb_missed = 0;
    if (is_request) {
        uint8_t out[16];
        size_t o = 0;
        pfcp_put_u32(out, sizeof out, &o, PFCP_IE_RECOVERY_TIME_STAMP, u->recovery_ts);
        reply(u, from, h, PFCP_HEARTBEAT_RESPONSE, false, 0, out, o);
    }
}

/* ---- sessions ---------------------------------------------------------------------------------------------------------------------- */

static void created_pdrs(const upf *u, upf_session *s, const upf_choose *ch, uint8_t *out, size_t cap, size_t *pos)
{
    for (size_t i = 0; i < ch->ncreated; i++) {
        upf_pdr *p = sess_find_pdr(s, ch->created[i]);
        size_t mark;
        pfcp_fteid f;
        if (p == NULL)
            continue;
        memset(&f, 0, sizeof f);
        f.v4 = true;
        f.teid = p->local_teid;
        memcpy(f.ip4, u->cfg.n3_addr.b, 4);
        if (pfcp_group_begin(out, cap, pos, PFCP_IE_CREATED_PDR, &mark) != 0)
            return;
        pfcp_put_u16(out, cap, pos, PFCP_IE_PDR_ID, p->id);
        pfcp_fteid_put(out, cap, pos, &f);
        pfcp_group_end(out, pos, mark);
    }
}

void upf_session_delete(upf *u, upf_session *s)
{
    for (size_t i = 0; i < u->nsessions; i++)
        if (u->sessions[i] == s) {
            u->sessions[i] = NULL;
            break;
        }
    for (size_t i = 0; i < sizeof u->pend / sizeof *u->pend; i++)
        if (u->pend[i].used && u->pend[i].seid == s->local_seid) {
            free(u->pend[i].msg);
            u->pend[i].used = false;
        }
    ptrmap_del(u->by_seid, s->local_seid);
    sess_unindex(u, s);
    sess_free(u, s);
    u->st.sessions_deleted++;
}

static void handle_session_establishment(upf *u, const upf_addr *from, const pfcp_header *h, const uint8_t *body, size_t blen)
{
    uint8_t out[1400];
    size_t pos = 0, ipos = 0;
    pfcp_ie ie;
    pfcp_fseid cp;
    bool have_cp = false, have_node = false;
    upf_session *s = NULL;
    upf_choose *ch = g5c_xcalloc(1, sizeof *ch);
    uint16_t bad = 0;
    int cause = PFCP_CAUSE_ACCEPTED;
    upf_peer *peer = n4_find_peer(u, from);
    memset(&cp, 0, sizeof cp);
    while (pfcp_ie_next(body, blen, &ipos, &ie) == 1) {
        pfcp_node_id n;
        if (ie.typ == PFCP_IE_FSEID && pfcp_fseid_decode(&ie, &cp) == 0)
            have_cp = true;
        else if (ie.typ == PFCP_IE_NODE_ID && pfcp_node_id_decode(&ie, &n) == 0)
            have_node = true;
    }
    (void)have_node;
    if (peer == NULL || !peer->established) {
        cause = PFCP_CAUSE_NO_ESTABLISHED_ASSOCIATION;
        goto fail;
    }
    if (!have_cp) {
        cause = PFCP_CAUSE_MANDATORY_IE_MISSING;
        bad = PFCP_IE_FSEID;
        goto fail;
    }
    if (u->cfg.max_sessions && ptrmap_len(u->by_seid) >= u->cfg.max_sessions) {
        cause = PFCP_CAUSE_NO_RESOURCES;
        goto fail;
    }
    s = g5c_xcalloc(1, sizeof *s);
    s->local_seid = ++u->next_seid;
    s->cp_seid = cp.seid;
    s->cp_addr = *from;
    s->peer = peer_index(u, peer);
    s->created_ms = (uint64_t)(u->now * 1000.0);
    /* rules other than PDRs first, so PDR references resolve */
    for (int pass = 0; pass < 2 && cause == PFCP_CAUSE_ACCEPTED; pass++) {
        ipos = 0;
        while (cause == PFCP_CAUSE_ACCEPTED && pfcp_ie_next(body, blen, &ipos, &ie) == 1) {
            if (pass == 0) {
                if (ie.typ == PFCP_IE_CREATE_FAR)
                    cause = okc(rules_create_far(s, &ie, &bad));
                else if (ie.typ == PFCP_IE_CREATE_QER)
                    cause = okc(rules_create_qer(s, &ie, u->now, &bad));
                else if (ie.typ == PFCP_IE_CREATE_URR)
                    cause = okc(rules_create_urr(s, &ie, u->now, &bad));
                else if (ie.typ == PFCP_IE_CREATE_BAR)
                    cause = okc(rules_create_bar(s, &ie, false, &bad));
            } else if (ie.typ == PFCP_IE_CREATE_PDR) {
                cause = okc(rules_create_pdr(u, s, &ie, ch, &bad));
            }
        }
    }
    if (cause == PFCP_CAUSE_ACCEPTED)
        cause = okc(rules_validate(s, &bad));
    if (cause != PFCP_CAUSE_ACCEPTED)
        goto fail;
    for (size_t i = 0; i < s->npdr; i++) {
        /* a UE address already served by another session belongs to a stale one (the SMF lost state): the new session wins */
        sess_index_pdr(u, s, &s->pdr[i]);
    }
    ptrmap_put(u->by_seid, s->local_seid, s);
    if (u->nsessions == u->capsessions) {
        u->capsessions = u->capsessions ? u->capsessions * 2 : 64;
        u->sessions = g5c_xrealloc(u->sessions, u->capsessions * sizeof *u->sessions);
    }
    {   /* reuse a free slot when there is one */
        size_t k;
        for (k = 0; k < u->nsessions; k++)
            if (u->sessions[k] == NULL)
                break;
        if (k == u->nsessions)
            u->nsessions++;
        u->sessions[k] = s;
    }
    u->st.sessions_created++;
    G5C_LOGI("g5c_upf", "session %llu established for CP seid %llx: %zu PDR, %zu FAR, %zu QER, %zu URR%s%u.%u.%u.%u", (unsigned long long)s->local_seid,
             (unsigned long long)cp.seid, s->npdr, s->nfar, s->nqer, s->nurr, s->has_ue4 ? ", UE " : "", s->ue4.b[0], s->ue4.b[1], s->ue4.b[2], s->ue4.b[3]);
    put_node_id(u, out, sizeof out, &pos);
    put_cause(out, sizeof out, &pos, PFCP_CAUSE_ACCEPTED, 0);
    {
        pfcp_fseid up;
        memset(&up, 0, sizeof up);
        up.v4 = true;
        up.seid = s->local_seid;
        memcpy(up.ip4, u->cfg.n4_addr.b, 4);
        pfcp_fseid_put(out, sizeof out, &pos, &up);
    }
    created_pdrs(u, s, ch, out, sizeof out, &pos);
    reply(u, from, h, PFCP_SESSION_ESTABLISHMENT_RESPONSE, true, cp.seid, out, pos);
    free(ch);
    return;
fail:
    G5C_LOGW("g5c_upf", "session establishment from %u.%u.%u.%u refused: cause %d, offending IE %u", from->b[0], from->b[1], from->b[2], from->b[3], cause, bad);
    if (s != NULL)
        sess_free(u, s);
    put_node_id(u, out, sizeof out, &pos);
    put_cause(out, sizeof out, &pos, (uint8_t)cause, bad);
    reply(u, from, h, PFCP_SESSION_ESTABLISHMENT_RESPONSE, true, have_cp ? cp.seid : 0, out, pos);
    free(ch);
}

/* a deep copy of the rules of a session, so a failed modification can be rolled back */
static upf_session *sess_snapshot(const upf_session *s)
{
    upf_session *c = g5c_xmalloc(sizeof *c);
    *c = *s;
    c->buf = NULL;
    c->nbuf = c->capbuf = c->buf_bytes = 0;
#define COPYARR(f, n, T) \
    do { \
        c->f = g5c_xmalloc((s->n ? s->n : 1) * sizeof(T)); \
        if (s->n) \
            memcpy(c->f, s->f, s->n * sizeof(T)); \
    } while (0)
    COPYARR(pdr, npdr, upf_pdr);
    COPYARR(far, nfar, upf_far);
    COPYARR(qer, nqer, upf_qer);
    COPYARR(urr, nurr, upf_urr);
    COPYARR(bar, nbar, upf_bar);
#undef COPYARR
    for (size_t i = 0; i < s->npdr; i++)
        if (s->pdr[i].nsdf) {
            c->pdr[i].sdf = g5c_xmalloc(s->pdr[i].nsdf * sizeof *s->pdr[i].sdf);
            memcpy(c->pdr[i].sdf, s->pdr[i].sdf, s->pdr[i].nsdf * sizeof *s->pdr[i].sdf);
        } else {
            c->pdr[i].sdf = NULL;
        }
    return c;
}

static void sess_release_rules(upf_session *s)
{
    for (size_t i = 0; i < s->npdr; i++)
        free(s->pdr[i].sdf);
    free(s->pdr);
    free(s->far);
    free(s->qer);
    free(s->urr);
    free(s->bar);
}

static void handle_session_modification(upf *u, const upf_addr *from, const pfcp_header *h, const uint8_t *body, size_t blen)
{
    uint8_t out[1400];
    size_t pos = 0, ipos = 0;
    pfcp_ie ie;
    upf_session *s = h->has_seid ? ptrmap_get(u->by_seid, h->seid) : NULL, *snap;
    upf_choose *ch = g5c_xcalloc(1, sizeof *ch);
    uint16_t bad = 0;
    int cause = PFCP_CAUSE_ACCEPTED;
    bool sndem = false, qaurr = false, drobu = false;
    upf_peer *peer = n4_find_peer(u, from);
    if (s == NULL || peer == NULL || !peer->established) {
        put_cause(out, sizeof out, &pos, s == NULL ? PFCP_CAUSE_SESSION_NOT_FOUND : PFCP_CAUSE_NO_ESTABLISHED_ASSOCIATION, 0);
        reply(u, from, h, PFCP_SESSION_MODIFICATION_RESPONSE, true, 0, out, pos);
        free(ch);
        return;
    }
    snap = sess_snapshot(s);
    while (pfcp_ie_next(body, blen, &ipos, &ie) == 1) {
        if (ie.typ == PFCP_IE_SMREQ_FLAGS && ie.len >= 1) {
            drobu = (ie.value[0] & 1) != 0;
            sndem = (ie.value[0] & 2) != 0;
            qaurr = (ie.value[0] & 4) != 0;
        }
    }
    if (drobu) /* SMReq flag DROBU: drop what is buffered */
        dp_drop_buffer(s);
    for (int pass = 0; pass < 3 && cause == PFCP_CAUSE_ACCEPTED; pass++) {
        ipos = 0;
        while (cause == PFCP_CAUSE_ACCEPTED && pfcp_ie_next(body, blen, &ipos, &ie) == 1) {
            switch (pass) {
            case 0: /* removals, then creation of rules other than PDRs */
                if (ie.typ == PFCP_IE_REMOVE_PDR)
                    cause = okc(rules_remove_pdr(u, s, &ie, &bad));
                else if (ie.typ == PFCP_IE_REMOVE_FAR)
                    cause = okc(rules_remove_id(s, &ie, PFCP_IE_REMOVE_FAR, PFCP_IE_FAR_ID, &bad));
                else if (ie.typ == PFCP_IE_REMOVE_QER)
                    cause = okc(rules_remove_id(s, &ie, PFCP_IE_REMOVE_QER, PFCP_IE_QER_ID, &bad));
                else if (ie.typ == PFCP_IE_REMOVE_URR)
                    cause = okc(rules_remove_id(s, &ie, PFCP_IE_REMOVE_URR, PFCP_IE_URR_ID, &bad));
                else if (ie.typ == PFCP_IE_REMOVE_BAR)
                    cause = okc(rules_remove_id(s, &ie, PFCP_IE_REMOVE_BAR, PFCP_IE_BAR_ID, &bad));
                else if (ie.typ == PFCP_IE_CREATE_FAR)
                    cause = okc(rules_create_far(s, &ie, &bad));
                else if (ie.typ == PFCP_IE_CREATE_QER)
                    cause = okc(rules_create_qer(s, &ie, u->now, &bad));
                else if (ie.typ == PFCP_IE_CREATE_URR)
                    cause = okc(rules_create_urr(s, &ie, u->now, &bad));
                else if (ie.typ == PFCP_IE_CREATE_BAR)
                    cause = okc(rules_create_bar(s, &ie, false, &bad));
                break;
            case 1: /* creates of PDRs and updates */
                if (ie.typ == PFCP_IE_CREATE_PDR)
                    cause = okc(rules_create_pdr(u, s, &ie, ch, &bad));
                else if (ie.typ == PFCP_IE_UPDATE_PDR)
                    cause = okc(rules_update_pdr(u, s, &ie, ch, &bad));
                else if (ie.typ == PFCP_IE_UPDATE_QER)
                    cause = okc(rules_update_qer(s, &ie, u->now, &bad));
                else if (ie.typ == PFCP_IE_UPDATE_URR)
                    cause = okc(rules_update_urr(s, &ie, &bad));
                else if (ie.typ == PFCP_IE_UPDATE_BAR_SMR)
                    cause = okc(rules_create_bar(s, &ie, true, &bad));
                break;
            default:
                break;
            }
        }
    }
    if (cause == PFCP_CAUSE_ACCEPTED)
        cause = okc(rules_validate(s, &bad));
    if (cause == PFCP_CAUSE_ACCEPTED) { /* FAR updates last: they may release buffered packets through the new rules */
        ipos = 0;
        while (cause == PFCP_CAUSE_ACCEPTED && pfcp_ie_next(body, blen, &ipos, &ie) == 1) {
            if (ie.typ == PFCP_IE_UPDATE_FAR)
                cause = okc(rules_update_far(u, s, &ie, sndem, &bad));
            else if (ie.typ == PFCP_IE_FSEID) {
                pfcp_fseid f;
                if (pfcp_fseid_decode(&ie, &f) == 0)
                    s->cp_seid = f.seid;
            }
        }
    }
    if (cause != PFCP_CAUSE_ACCEPTED) {
        /* roll back: the session keeps exactly what it had before this request */
        upf_buffered *keep = s->buf;
        size_t nb = s->nbuf, cb = s->capbuf, bb = s->buf_bytes;
        sess_unindex(u, s);
        sess_release_rules(s);
        *s = *snap;
        s->buf = keep;
        s->nbuf = nb;
        s->capbuf = cb;
        s->buf_bytes = bb;
        for (size_t i = 0; i < s->npdr; i++)
            sess_index_pdr(u, s, &s->pdr[i]);
        free(snap);
        G5C_LOGW("g5c_upf", "session %llu modification refused: cause %d, offending IE %u (nothing changed)", (unsigned long long)s->local_seid, cause, bad);
        put_cause(out, sizeof out, &pos, (uint8_t)cause, bad);
        reply(u, from, h, PFCP_SESSION_MODIFICATION_RESPONSE, true, s->cp_seid, out, pos);
        free(ch);
        return;
    }
    sess_release_rules(snap);
    free(snap);
    /* new or changed rules may add TEIDs / UE addresses */
    for (size_t i = 0; i < s->npdr; i++)
        sess_index_pdr(u, s, &s->pdr[i]);
    put_cause(out, sizeof out, &pos, PFCP_CAUSE_ACCEPTED, 0);
    created_pdrs(u, s, ch, out, sizeof out, &pos);
    {   /* Query URR / QAURR: usage reports in the response */
        ipos = 0;
        while (pfcp_ie_next(body, blen, &ipos, &ie) == 1)
            if (ie.typ == PFCP_IE_QUERY_URR) {
                size_t p2 = 0;
                pfcp_ie x;
                while (pfcp_ie_next(ie.value, ie.len, &p2, &x) == 1)
                    if (x.typ == PFCP_IE_URR_ID) {
                        uint32_t id;
                        upf_urr *r;
                        if (pfcp_get_u32(&x, &id) == 0 && (r = sess_find_urr(s, id)) != NULL) {
                            size_t n = urr_build_report(u, r, PFCP_IE_USAGE_REPORT_SMR, PFCP_URT_IMMER, out + pos, sizeof out - pos, true);
                            pos += n;
                        }
                    }
            }
        if (qaurr)
            for (size_t k = 0; k < s->nurr; k++)
                pos += urr_build_report(u, &s->urr[k], PFCP_IE_USAGE_REPORT_SMR, PFCP_URT_IMMER, out + pos, sizeof out - pos, true);
    }
    reply(u, from, h, PFCP_SESSION_MODIFICATION_RESPONSE, true, s->cp_seid, out, pos);
    free(ch);
}

static void handle_session_deletion(upf *u, const upf_addr *from, const pfcp_header *h)
{
    uint8_t out[1400];
    size_t pos = 0;
    upf_session *s = h->has_seid ? ptrmap_get(u->by_seid, h->seid) : NULL;
    uint64_t cp_seid;
    if (s == NULL) {
        put_cause(out, sizeof out, &pos, PFCP_CAUSE_SESSION_NOT_FOUND, 0);
        reply(u, from, h, PFCP_SESSION_DELETION_RESPONSE, true, 0, out, pos);
        return;
    }
    cp_seid = s->cp_seid;
    G5C_LOGI("g5c_upf", "session %llu deleted", (unsigned long long)s->local_seid);
    put_cause(out, sizeof out, &pos, PFCP_CAUSE_ACCEPTED, 0);
    for (size_t k = 0; k < s->nurr; k++)
        pos += urr_build_report(u, &s->urr[k], PFCP_IE_USAGE_REPORT_SDR, PFCP_URT_TERMR, out + pos, sizeof out - pos, false);
    upf_session_delete(u, s);
    reply(u, from, h, PFCP_SESSION_DELETION_RESPONSE, true, cp_seid, out, pos);
}

static void handle_report_response(upf *u, const pfcp_header *h, const uint8_t *body, size_t blen)
{
    size_t pos = 0;
    pfcp_ie ie;
    uint8_t cause = PFCP_CAUSE_ACCEPTED;
    uint64_t seid = 0;
    for (size_t i = 0; i < sizeof u->pend / sizeof *u->pend; i++)
        if (u->pend[i].used && u->pend[i].seq == h->seq) {
            seid = u->pend[i].seid;
            free(u->pend[i].msg);
            u->pend[i].used = false;
            u->st.reports_acked++;
        }
    while (pfcp_ie_next(body, blen, &pos, &ie) == 1)
        if (ie.typ == PFCP_IE_CAUSE)
            (void)pfcp_get_u8(&ie, &cause);
    if (cause == PFCP_CAUSE_SESSION_NOT_FOUND && seid) { /* the SMF has no such session: ours is an orphan */
        upf_session *s = ptrmap_get(u->by_seid, seid);
        if (s)
            upf_session_delete(u, s);
    }
}

/* ---- requests we send ------------------------------------------------------------------------------------------------------------------ */

void n4_send_session_report(upf *u, upf_session *s, uint8_t report_type, const uint16_t *dl_pdr, const upf_urr *urr, uint32_t trigger)
{
    uint8_t body[1200], out[1300];
    size_t pos = 0, n = 0, mark;
    pfcp_header h;
    upf_pending *slot = NULL;
    uint32_t seq;
    pfcp_put_u8(body, sizeof body, &pos, PFCP_IE_REPORT_TYPE, report_type);
    if (report_type == 1 && dl_pdr) {
        pfcp_group_begin(body, sizeof body, &pos, PFCP_IE_DOWNLINK_DATA_REPORT, &mark);
        pfcp_put_u16(body, sizeof body, &pos, PFCP_IE_PDR_ID, *dl_pdr);
        pfcp_group_end(body, &pos, mark);
    } else if (report_type == 2 && urr) {
        size_t k = urr_build_report(u, (upf_urr *)(uintptr_t)urr, PFCP_IE_USAGE_REPORT_SRR, trigger, body + pos, sizeof body - pos, true);
        pos += k;
    }
    seq = ++u->next_seq & 0x00ffffff;
    pfcp_header_session(&h, PFCP_SESSION_REPORT_REQUEST, s->cp_seid, seq);
    if (pfcp_encode(&h, body, pos, out, sizeof out, &n) != 0)
        return;
    n4_send(u, &s->cp_addr, out, n);
    u->st.reports_sent++;
    for (size_t i = 0; i < sizeof u->pend / sizeof *u->pend; i++)
        if (!u->pend[i].used) {
            slot = &u->pend[i];
            break;
        }
    if (slot) {
        slot->used = true;
        slot->seq = seq;
        slot->to = s->cp_addr;
        slot->msg = g5c_xmalloc(n);
        memcpy(slot->msg, out, n);
        slot->len = n;
        slot->next_tx = u->now + T1_SECONDS;
        slot->tries = 1;
        slot->seid = s->local_seid;
        slot->is_report = true;
    }
}

void n4_timers(upf *u, double now)
{
    for (size_t i = 0; i < sizeof u->pend / sizeof *u->pend; i++) {
        upf_pending *p = &u->pend[i];
        if (!p->used || now < p->next_tx)
            continue;
        if (p->tries > N1_RETRIES) { /* give up; the peer is probably gone, heartbeats will notice */
            free(p->msg);
            p->used = false;
            continue;
        }
        n4_send(u, &p->to, p->msg, p->len);
        p->tries++;
        p->next_tx = now + T1_SECONDS;
    }
    if (u->cfg.heartbeat_interval == 0)
        return;
    for (size_t i = 0; i < u->npeers; i++) {
        upf_peer *p = &u->peers[i];
        uint8_t body[16], out[32];
        size_t pos = 0, n = 0;
        pfcp_header h;
        if (!p->established || now - p->last_hb_tx < (double)u->cfg.heartbeat_interval)
            continue;
        if (p->last_hb_tx > 0 && p->last_rx < p->last_hb_tx) /* nothing heard since the previous heartbeat */
            p->hb_missed++;
        else
            p->hb_missed = 0;
        if (p->hb_missed >= u->cfg.heartbeat_retries) {
            if (u->cfg.delete_on_peer_loss)
                n4_peer_down(u, (uint32_t)i);
            else
                p->established = false;
            continue;
        }
        p->last_hb_tx = now;
        pfcp_put_u32(body, sizeof body, &pos, PFCP_IE_RECOVERY_TIME_STAMP, u->recovery_ts);
        pfcp_header_node(&h, PFCP_HEARTBEAT_REQUEST, ++u->next_seq & 0x00ffffff);
        if (pfcp_encode(&h, body, pos, out, sizeof out, &n) == 0)
            n4_send(u, &p->addr, out, n);
    }
}

/* ---- entry point ------------------------------------------------------------------------------------------------------------------------ */

void upf_n4_message(upf *u, const upf_addr *from, const uint8_t *msg, size_t len, double now)
{
    pfcp_header h;
    const uint8_t *body;
    size_t blen;
    int rc;
    upf_peer *peer;
    u->now = now;
    u->st.n4_rx++;
    rc = pfcp_decode(msg, len, &h, &body, &blen);
    if (rc == PFCP_E_VERSION && len >= 4) { /* TS 29.244 7.2.2.2: tell the sender which version we speak */
        uint8_t out[8];
        size_t n = 0;
        pfcp_header r;
        pfcp_header_node(&r, PFCP_VERSION_NOT_SUPPORTED, 0);
        if (pfcp_encode(&r, NULL, 0, out, sizeof out, &n) == 0)
            n4_send(u, from, out, n);
        return;
    }
    if (rc != 0) {
        u->st.n4_bad++;
        return;
    }
    peer = n4_find_peer(u, from);
    if (peer)
        peer->last_rx = now;
    switch (h.msg_type) {
    case PFCP_HEARTBEAT_REQUEST:
    case PFCP_ASSOCIATION_SETUP_REQUEST:
    case PFCP_ASSOCIATION_UPDATE_REQUEST:
    case PFCP_ASSOCIATION_RELEASE_REQUEST:
    case PFCP_PFD_MANAGEMENT_REQUEST:
    case PFCP_SESSION_ESTABLISHMENT_REQUEST:
    case PFCP_SESSION_MODIFICATION_REQUEST:
    case PFCP_SESSION_DELETION_REQUEST:
        if (cache_replay(u, from, h.seq)) /* a retransmission: the answer is already known */
            return;
        break;
    default:
        break;
    }
    switch (h.msg_type) {
    case PFCP_HEARTBEAT_REQUEST:
        handle_heartbeat(u, from, &h, body, blen, true);
        break;
    case PFCP_HEARTBEAT_RESPONSE:
        handle_heartbeat(u, from, &h, body, blen, false);
        break;
    case PFCP_ASSOCIATION_SETUP_REQUEST:
        handle_association_setup(u, from, &h, body, blen);
        break;
    case PFCP_ASSOCIATION_UPDATE_REQUEST: {
        uint8_t out[64];
        size_t pos = 0;
        put_node_id(u, out, sizeof out, &pos);
        put_cause(out, sizeof out, &pos, peer && peer->established ? PFCP_CAUSE_ACCEPTED : PFCP_CAUSE_NO_ESTABLISHED_ASSOCIATION, 0);
        reply(u, from, &h, PFCP_ASSOCIATION_UPDATE_RESPONSE, false, 0, out, pos);
        break;
    }
    case PFCP_ASSOCIATION_RELEASE_REQUEST:
        handle_association_release(u, from, &h);
        break;
    case PFCP_PFD_MANAGEMENT_REQUEST: {
        uint8_t out[16];
        size_t pos = 0;
        put_cause(out, sizeof out, &pos, PFCP_CAUSE_ACCEPTED, 0); /* no PFD-based detection: accepted and ignored */
        reply(u, from, &h, PFCP_PFD_MANAGEMENT_RESPONSE, false, 0, out, pos);
        break;
    }
    case PFCP_SESSION_ESTABLISHMENT_REQUEST:
        handle_session_establishment(u, from, &h, body, blen);
        break;
    case PFCP_SESSION_MODIFICATION_REQUEST:
        handle_session_modification(u, from, &h, body, blen);
        break;
    case PFCP_SESSION_DELETION_REQUEST:
        handle_session_deletion(u, from, &h);
        break;
    case PFCP_SESSION_REPORT_RESPONSE:
        handle_report_response(u, &h, body, blen);
        break;
    default:
        u->st.n4_bad++; /* message types a UP function never receives, or that are not implemented */
        break;
    }
}
