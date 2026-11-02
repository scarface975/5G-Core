/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5GSM messages of the SMF (TS 24.501 clause 8.3 and 9.11.4). Bit layouts follow the pinned TS 24.501 v16.15.0 and TS 24.008 v16.7.0. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/nas.h"
#include "g5c/smf.h"

/* ---- rates ---- */

/* Unit code u >= 1 means multiples of 4^(u-1) kbit/s (Table 9.11.4.14.1 and the QoS flow description parameters). */
static void rate_encode(uint64_t kbps, uint8_t *unit, uint16_t *val)
{
    uint64_t step = 1;
    for (uint8_t u = 1; u <= 0x19; u++, step *= 4) {
        uint64_t v = (kbps + step - 1) / step;
        if (v <= 65535) {
            *unit = u;
            *val = (uint16_t)v;
            return;
        }
    }
    *unit = 0x19;
    *val = 65535;
}

void smf_gsm_session_ambr(uint64_t ul, uint64_t dl, uint8_t out[6])
{
    uint8_t u;
    uint16_t v;
    /* 0 means unlimited here; the largest value that fits the field in Gbit/s units */
    if (dl == 0)
        dl = 65535ull * 1000000ull;
    if (ul == 0)
        ul = 65535ull * 1000000ull;
    rate_encode(dl, &u, &v);
    out[0] = u;
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)v;
    rate_encode(ul, &u, &v);
    out[3] = u;
    out[4] = (uint8_t)(v >> 8);
    out[5] = (uint8_t)v;
}

/* ---- parsing ---- */

int smf_gsm_peek(const uint8_t *nas, size_t len, uint8_t *type, uint8_t *psi, uint8_t *pti)
{
    if (len < 4 || nas[0] != NAS_EPD_5GSM)
        return -1;
    *psi = nas[1];
    *pti = nas[2];
    *type = nas[3];
    return 0;
}

/* Extended PCO (TS 24.008 10.5.6.3A): octet 3 = ext(1) spare configuration protocol(3), then {container id (2), length (1), contents}. */
static void parse_epco(const uint8_t *v, size_t n, smf_est_req *r)
{
    size_t pos = 1;
    if (n < 1 || (v[0] & 0x80) == 0)
        return;
    while (pos + 3 <= n) {
        uint16_t id = (uint16_t)((v[pos] << 8) | v[pos + 1]);
        size_t l = v[pos + 2];
        if (pos + 3 + l > n)
            return;
        if (id == 0x000d)
            r->pco_dns4 = true;
        else if (id == 0x0003)
            r->pco_dns6 = true;
        else if (id == 0x0010)
            r->pco_mtu = true;
        pos += 3 + l;
    }
}

int smf_gsm_parse_est_req(const uint8_t *nas, size_t len, smf_est_req *out)
{
    nas_msg m;
    int rc;
    const uint8_t *v;
    size_t n;
    memset(out, 0, sizeof *out);
    if (len < 4 || nas[0] != NAS_EPD_5GSM)
        return SMF_5GSM_INVALID_MANDATORY_INFORMATION;
    if (nas[3] != 0xc1)
        return SMF_5GSM_MESSAGE_TYPE_NOT_IMPLEMENTED;
    rc = nas_msg_decode(nas, len, &m);
    if (rc != NAS_OK)
        return rc == NAS_E_MSGTYPE ? SMF_5GSM_MESSAGE_TYPE_NOT_IMPLEMENTED : SMF_5GSM_INVALID_MANDATORY_INFORMATION;
    out->psi = m.pdu_session_id;
    out->pti = m.pti;
    if (out->pti == 0 || out->pti > 254) { /* 0: no procedure transaction identity assigned, 255 reserved */
        nas_msg_free(&m);
        return SMF_5GSM_INVALID_PTI;
    }
    if ((v = nas_msg_get(&m, "PDU session type", &n)) != NULL && n == 1)
        out->pdu_type = (uint8_t)(v[0] & 0x07);
    if ((v = nas_msg_get(&m, "SSC mode", &n)) != NULL && n == 1)
        out->ssc_mode = (uint8_t)(v[0] & 0x07);
    if ((v = nas_msg_get(&m, "Always-on PDU session requested", &n)) != NULL && n == 1)
        out->always_on_requested = (v[0] & 1) != 0;
    if ((v = nas_msg_get(&m, "Extended protocol configuration options", &n)) != NULL)
        parse_epco(v, n, out);
    nas_msg_free(&m);
    return 0;
}

/* ---- QoS rules and flow descriptions ---- */

static void put_u8(g5c_bytes *b, unsigned v)
{
    g5c_bytes_putc(b, (char)(uint8_t)v);
}

/* One packet filter (direction, identifier, contents). Components in the UE's view: "remote" is the other end of the flow. */
static int put_packet_filter(g5c_bytes *b, uint8_t pfid, uint8_t dir, const char *flow)
{
    uint8_t c[64];
    size_t n = 0;
    smf_ipfilter f;
    uint8_t dbits;
    if (flow == NULL) { /* the default rule: match everything in both directions */
        put_u8(b, 0x30u | (pfid & 0x0fu));
        put_u8(b, 1);
        put_u8(b, 0x01);
        return 0;
    }
    if (smf_ipfilter_parse(flow, &f) != 0 || f.src_v6 || f.dst_v6)
        return -1;
    if (!f.src_any) {
        c[n++] = 0x10;
        memcpy(c + n, f.src, 4);
        n += 4;
        {
            uint32_t mask = f.src_plen == 0 ? 0 : 0xffffffffu << (32 - f.src_plen);
            c[n++] = (uint8_t)(mask >> 24);
            c[n++] = (uint8_t)(mask >> 16);
            c[n++] = (uint8_t)(mask >> 8);
            c[n++] = (uint8_t)mask;
        }
    }
    if (!f.dst_any) {
        c[n++] = 0x11;
        memcpy(c + n, f.dst, 4);
        n += 4;
        {
            uint32_t mask = f.dst_plen == 0 ? 0 : 0xffffffffu << (32 - f.dst_plen);
            c[n++] = (uint8_t)(mask >> 24);
            c[n++] = (uint8_t)(mask >> 16);
            c[n++] = (uint8_t)(mask >> 8);
            c[n++] = (uint8_t)mask;
        }
    }
    if (!f.any_proto) {
        c[n++] = 0x30;
        c[n++] = f.proto;
    }
    if (f.has_sport) {
        c[n++] = f.sport_lo == f.sport_hi ? 0x50 : 0x51; /* single / range remote port */
        c[n++] = (uint8_t)(f.sport_lo >> 8);
        c[n++] = (uint8_t)f.sport_lo;
        if (f.sport_lo != f.sport_hi) {
            c[n++] = (uint8_t)(f.sport_hi >> 8);
            c[n++] = (uint8_t)f.sport_hi;
        }
    }
    if (f.has_dport) {
        if (f.dport_lo == f.dport_hi) {
            c[n++] = 0x40;
            c[n++] = (uint8_t)(f.dport_lo >> 8);
            c[n++] = (uint8_t)f.dport_lo;
        } else {
            c[n++] = 0x41;
            c[n++] = (uint8_t)(f.dport_lo >> 8);
            c[n++] = (uint8_t)f.dport_lo;
            c[n++] = (uint8_t)(f.dport_hi >> 8);
            c[n++] = (uint8_t)f.dport_hi;
        }
    }
    if (n == 0) {
        if (dir == 1) { /* match-all must not be used with "downlink only" (NOTE 2) */
            static const uint8_t any4[9] = {0x10, 0, 0, 0, 0, 0, 0, 0, 0};
            memcpy(c, any4, sizeof any4);
            n = sizeof any4;
        } else {
            c[n++] = 0x01;
        }
    }
    dbits = dir == 1 ? 1 : dir == 2 ? 2 : 3; /* 01 downlink only, 10 uplink only, 11 bidirectional */
    put_u8(b, (unsigned)(dbits << 4) | (pfid & 0x0fu));
    put_u8(b, (unsigned)n);
    return g5c_bytes_append(b, c, n);
}

int smf_gsm_put_qos_rule(g5c_bytes *out, uint8_t qri, bool dqr, uint8_t precedence, uint8_t qfi, const char *const *filters,
                         const uint8_t *dirs, size_t nfilters)
{
    g5c_bytes body;
    size_t nf = filters == NULL ? 1 : nfilters; /* a default rule carries one match-all filter */
    int rc = 0;
    if (nf == 0 || nf > 15 || qri == 0 || qfi == 0 || qfi > 63)
        return -1;
    g5c_bytes_init(&body);
    put_u8(&body, 0x20u | (dqr ? 0x10u : 0) | (unsigned)nf); /* operation code 001: create new QoS rule */
    for (size_t i = 0; i < nf && rc == 0; i++)
        rc = put_packet_filter(&body, (uint8_t)(i + 1), filters == NULL ? 3 : dirs[i], filters == NULL ? NULL : filters[i]);
    if (rc == 0) {
        put_u8(&body, precedence);
        put_u8(&body, qfi & 0x3fu);
        put_u8(out, qri);
        put_u8(out, (unsigned)(body.len >> 8));
        put_u8(out, (unsigned)(body.len & 0xff));
        rc = g5c_bytes_append(out, body.data, body.len);
    }
    g5c_bytes_free(&body);
    return rc;
}

static void put_rate_param(g5c_bytes *b, uint8_t id, uint64_t kbps)
{
    uint8_t unit;
    uint16_t v;
    rate_encode(kbps, &unit, &v);
    put_u8(b, id);
    put_u8(b, 3);
    put_u8(b, unit);
    put_u8(b, (unsigned)(v >> 8));
    put_u8(b, v);
}

int smf_gsm_put_qos_flow_desc(g5c_bytes *out, const smf_flow *f)
{
    unsigned np = 1;
    if (f->qfi == 0 || f->qfi > 63)
        return -1;
    if (f->gbr)
        np += 4;
    put_u8(out, f->qfi & 0x3fu);
    put_u8(out, 0x20); /* operation code 001: create new QoS flow description */
    put_u8(out, 0x40u | np); /* E bit: parameters list included */
    put_u8(out, 0x01);       /* 5QI */
    put_u8(out, 1);
    put_u8(out, f->qi5);
    if (f->gbr) {
        put_rate_param(out, 0x02, f->gbr_ul);
        put_rate_param(out, 0x03, f->gbr_dl);
        put_rate_param(out, 0x04, f->mbr_ul);
        put_rate_param(out, 0x05, f->mbr_dl);
    }
    return 0;
}

/* ---- messages ---- */

static void put_epco(g5c_bytes *b, const smf_est_acc *in)
{
    put_u8(b, 0x80);
    if (in->req.pco_dns4)
        for (size_t i = 0; i < in->ndns4; i++) {
            put_u8(b, 0x00);
            put_u8(b, 0x0d);
            put_u8(b, 4);
            g5c_bytes_append(b, in->dns4[i], 4);
        }
    if (in->req.pco_dns6)
        for (size_t i = 0; i < in->ndns6; i++) {
            put_u8(b, 0x00);
            put_u8(b, 0x03);
            put_u8(b, 16);
            g5c_bytes_append(b, in->dns6[i], 16);
        }
    if (in->req.pco_mtu && in->mtu != 0) {
        put_u8(b, 0x00);
        put_u8(b, 0x10);
        put_u8(b, 2);
        put_u8(b, (unsigned)(in->mtu >> 8));
        put_u8(b, in->mtu);
    }
}

int smf_gsm_build_est_accept(const smf_est_acc *in, g5c_bytes *out)
{
    nas_msg m;
    g5c_bytes rules, flows, addr, epco, dnn;
    uint8_t ambr[6], half;
    int rc = -1;
    if (!nas_msg_init(&m, "PDU session establishment accept"))
        return -1;
    g5c_bytes_init(&rules);
    g5c_bytes_init(&flows);
    g5c_bytes_init(&addr);
    g5c_bytes_init(&epco);
    g5c_bytes_init(&dnn);
    m.pdu_session_id = in->psi;
    m.pti = in->pti;
    half = in->pdu_type;
    nas_msg_set(&m, "Selected PDU session type", &half, 1);
    half = in->ssc_mode;
    nas_msg_set(&m, "Selected SSC mode", &half, 1);
    /* default QoS rule: the match-all rule bound to the default flow, lowest precedence */
    if (smf_gsm_put_qos_rule(&rules, 1, true, 255, SMF_DEFAULT_QFI, NULL, NULL, 0) != 0)
        goto done;
    if (in->pol != NULL)
        for (size_t i = 0; i < in->pol->nrules; i++) {
            const smf_pcc *r = &in->pol->rules[i];
            uint8_t prec = (uint8_t)(r->precedence == 80 ? 81 : r->precedence); /* 80 is reserved */
            if (smf_gsm_put_qos_rule(&rules, r->qri != 0 ? r->qri : (uint8_t)(i + 2), false, prec, r->qfi, (const char *const *)r->filters, r->dirs, r->nfilters) != 0)
                goto done;
        }
    nas_msg_set(&m, "Authorized QoS rules", rules.data, rules.len);
    smf_gsm_session_ambr(in->ambr_ul, in->ambr_dl, ambr);
    nas_msg_set(&m, "Session AMBR", ambr, sizeof ambr);
    /* PDU address (9.11.4.10): type, then the IPv4 address (IPv4), the interface identifier (IPv6) or both (IPv4v6: identifier first) */
    put_u8(&addr, in->pdu_type);
    if (in->pdu_type == 2 || in->pdu_type == 3)
        g5c_bytes_append(&addr, in->ifid, 8);
    if (in->pdu_type == 1 || in->pdu_type == 3)
        g5c_bytes_append(&addr, in->ip4, 4);
    nas_msg_set(&m, "PDU address", addr.data, addr.len);
    if (in->cause != 0)
        nas_msg_set(&m, "5GSM cause", &in->cause, 1);
    if (in->has_snssai) {
        nas_snssai s = {in->sst, in->has_sd, in->sd};
        uint8_t v[4];
        size_t n = nas_snssai_encode(&s, v);
        nas_msg_set(&m, "S-NSSAI", v, n);
    }
    if (in->pol != NULL && in->pol->nflows > 1) {
        for (size_t i = 1; i < in->pol->nflows; i++)
            if (smf_gsm_put_qos_flow_desc(&flows, &in->pol->flows[i]) != 0)
                goto done;
        nas_msg_set(&m, "Authorized QoS flow descriptions", flows.data, flows.len);
    }
    if (in->req.pco_dns4 || in->req.pco_dns6 || in->req.pco_mtu) {
        put_epco(&epco, in);
        if (epco.len > 1)
            nas_msg_set(&m, "Extended protocol configuration options", epco.data, epco.len);
    }
    if (in->dnn != NULL && nas_dnn_encode(in->dnn, &dnn) >= 0)
        nas_msg_set(&m, "DNN", dnn.data, dnn.len);
    rc = nas_msg_encode(&m, out) == NAS_OK ? 0 : -1;
done:
    g5c_bytes_free(&rules);
    g5c_bytes_free(&flows);
    g5c_bytes_free(&addr);
    g5c_bytes_free(&epco);
    g5c_bytes_free(&dnn);
    nas_msg_free(&m);
    return rc;
}

static int build_with_cause(const char *name, uint8_t psi, uint8_t pti, uint8_t cause, g5c_bytes *out)
{
    nas_msg m;
    int rc;
    if (!nas_msg_init(&m, name))
        return -1;
    m.pdu_session_id = psi;
    m.pti = pti;
    nas_msg_set(&m, "5GSM cause", &cause, 1);
    rc = nas_msg_encode(&m, out) == NAS_OK ? 0 : -1;
    nas_msg_free(&m);
    return rc;
}

int smf_gsm_build_est_reject(uint8_t psi, uint8_t pti, uint8_t cause, g5c_bytes *out)
{
    return build_with_cause("PDU session establishment reject", psi, pti, cause, out);
}

int smf_gsm_build_release_cmd(uint8_t psi, uint8_t pti, uint8_t cause, g5c_bytes *out)
{
    return build_with_cause("PDU session release command", psi, pti, cause, out);
}

/* QoS flow description with an operation code (001 create, 010 delete, 011 modify) */
static void put_flow_desc_op(g5c_bytes *out, const smf_flow *f, unsigned op)
{
    unsigned np = 0;
    if (op != 2)
        np = f->gbr ? 5 : 1;
    put_u8(out, f->qfi & 0x3fu);
    put_u8(out, op << 5);
    put_u8(out, (op == 2 ? 0 : 0x40u) | np); /* E bit: parameters list included (create) / replacement of all parameters (modify) */
    if (op == 2)
        return;
    put_u8(out, 0x01);
    put_u8(out, 1);
    put_u8(out, f->qi5);
    if (f->gbr) {
        put_rate_param(out, 0x02, f->gbr_ul);
        put_rate_param(out, 0x03, f->gbr_dl);
        put_rate_param(out, 0x04, f->mbr_ul);
        put_rate_param(out, 0x05, f->mbr_dl);
    }
}

static const smf_flow *flow_by_qer(const smf_policy *p, uint32_t qer)
{
    for (size_t i = 0; i < p->nflows; i++)
        if (p->flows[i].qer_id == qer)
            return &p->flows[i];
    return NULL;
}

static bool rule_in(const smf_policy *p, const smf_pcc *r)
{
    for (size_t k = 0; k < p->nrules; k++)
        if (p->rules[k].qri == r->qri && p->rules[k].pdr_ul == r->pdr_ul && p->rules[k].pdr_dl == r->pdr_dl && strcmp(p->rules[k].id, r->id) == 0)
            return true;
    return false;
}

int smf_gsm_build_mod_cmd(uint8_t psi, const smf_policy *oldp, const smf_policy *newp, g5c_bytes *out)
{
    nas_msg m;
    g5c_bytes rules, flows;
    int rc = -1;
    if (!nas_msg_init(&m, "PDU session modification command"))
        return -1;
    g5c_bytes_init(&rules);
    g5c_bytes_init(&flows);
    m.pdu_session_id = psi;
    m.pti = 0;
    bool ambr_changed = oldp->ambr_ul != newp->ambr_ul || oldp->ambr_dl != newp->ambr_dl;
    if (ambr_changed) {
        uint8_t a[6];
        smf_gsm_session_ambr(newp->ambr_ul, newp->ambr_dl, a);
        nas_msg_set(&m, "Session AMBR", a, sizeof a);
    }
    for (size_t k = 0; k < oldp->nrules; k++) {
        const smf_pcc *r = &oldp->rules[k];
        if (rule_in(newp, r))
            continue;
        put_u8(&rules, r->qri); /* delete existing QoS rule: length one, operation code 010, no filters */
        put_u8(&rules, 0);
        put_u8(&rules, 1);
        put_u8(&rules, 0x40);
    }
    for (size_t k = 0; k < newp->nrules; k++) {
        const smf_pcc *r = &newp->rules[k];
        uint8_t prec = (uint8_t)(r->precedence == 80 ? 81 : r->precedence);
        if (rule_in(oldp, r))
            continue;
        if (smf_gsm_put_qos_rule(&rules, r->qri, false, prec, r->qfi, (const char *const *)r->filters, r->dirs, r->nfilters) != 0)
            goto done;
    }
    for (size_t i = 1; i < oldp->nflows; i++)
        if (flow_by_qer(newp, oldp->flows[i].qer_id) == NULL)
            put_flow_desc_op(&flows, &oldp->flows[i], 2);
    for (size_t i = 1; i < newp->nflows; i++) {
        const smf_flow *f = &newp->flows[i], *o = flow_by_qer(oldp, f->qer_id);
        if (o == NULL)
            put_flow_desc_op(&flows, f, 1);
        else if (o->qi5 != f->qi5 || o->gbr != f->gbr || o->gbr_ul != f->gbr_ul || o->gbr_dl != f->gbr_dl || o->mbr_ul != f->mbr_ul || o->mbr_dl != f->mbr_dl)
            put_flow_desc_op(&flows, f, 3);
    }
    if (!ambr_changed && rules.len == 0 && flows.len == 0) { /* nothing the UE has to know */
        rc = 1;
        goto done;
    }
    if (rules.len > 0)
        nas_msg_set(&m, "Authorized QoS rules", rules.data, rules.len);
    if (flows.len > 0)
        nas_msg_set(&m, "Authorized QoS flow descriptions", flows.data, flows.len);
    rc = nas_msg_encode(&m, out) == NAS_OK ? 0 : -1;
done:
    g5c_bytes_free(&rules);
    g5c_bytes_free(&flows);
    nas_msg_free(&m);
    return rc;
}
