/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* N2 SM information (TS 38.413 clause 9.3.4): the transfer containers the SMF builds for, and reads from, the AN. Encoded with the
 * generic APER codec; the field names are those of the pinned ASN.1 (NGAP-IEs.asn). */
#include <stdio.h>
#include <string.h>

#include "g5c/ngap.h"
#include "g5c/smf.h"

static g5c_json *ie(g5c_json *list, int id, const char *crit, g5c_json *value)
{
    g5c_json *e = g5c_json_push(list, g5c_json_new_obj());
    g5c_json_set_int(e, "id", id);
    g5c_json_set_str(e, "criticality", crit);
    g5c_json_set(e, "value", value);
    return e;
}

static g5c_json *bitstring(const uint8_t *p, size_t bits)
{
    g5c_json *o = g5c_json_new_obj();
    char *hex = g5c_hex_encode(p, (bits + 7) / 8);
    g5c_json_set_int(o, "len", (int64_t)bits);
    g5c_json_set_str(o, "hex", hex);
    free(hex);
    return o;
}

static g5c_json *teid_json(uint32_t teid)
{
    uint8_t b[4] = {(uint8_t)(teid >> 24), (uint8_t)(teid >> 16), (uint8_t)(teid >> 8), (uint8_t)teid};
    char *h = g5c_hex_encode(b, 4);
    g5c_json *j = g5c_json_new_str(h);
    free(h);
    return j;
}

static g5c_json *qos_params(const smf_flow *f)
{
    g5c_json *q = g5c_json_new_obj(), *ch = g5c_json_set(q, "qosCharacteristics", g5c_json_new_obj()),
             *nd = g5c_json_set(ch, "nonDynamic5QI", g5c_json_new_obj()),
             *arp = g5c_json_set(q, "allocationAndRetentionPriority", g5c_json_new_obj());
    g5c_json_set_int(nd, "fiveQI", f->qi5);
    if (f->has_prio_level)
        g5c_json_set_int(nd, "priorityLevelQos", f->prio_level);
    g5c_json_set_int(arp, "priorityLevelARP", f->arp_prio);
    g5c_json_set_str(arp, "pre-emptionCapability", f->pre_cap ? "may-trigger-pre-emption" : "shall-not-trigger-pre-emption");
    g5c_json_set_str(arp, "pre-emptionVulnerability", f->pre_vuln ? "pre-emptable" : "not-pre-emptable");
    if (f->gbr) {
        g5c_json *g = g5c_json_set(q, "gBR-QosInformation", g5c_json_new_obj());
        g5c_json_set_int(g, "maximumFlowBitRateDL", (int64_t)(f->mbr_dl * 1000));
        g5c_json_set_int(g, "maximumFlowBitRateUL", (int64_t)(f->mbr_ul * 1000));
        g5c_json_set_int(g, "guaranteedFlowBitRateDL", (int64_t)(f->gbr_dl * 1000));
        g5c_json_set_int(g, "guaranteedFlowBitRateUL", (int64_t)(f->gbr_ul * 1000));
    }
    return q;
}

int smf_n2_build_setup_req(const smf_n2_setup *in, g5c_bytes *out)
{
    g5c_json *t = g5c_json_new_obj(), *ies = g5c_json_set(t, "protocolIEs", g5c_json_new_arr()), *v, *fl;
    char err[160];
    int rc;
    if (in->pol == NULL || in->pol->nflows == 0 || in->pdu_type < 1 || in->pdu_type > 3) {
        g5c_json_free(t);
        return -1;
    }
    v = g5c_json_new_obj();
    g5c_json_set_int(v, "pDUSessionAggregateMaximumBitRateDL", (int64_t)(in->ambr_dl * 1000));
    g5c_json_set_int(v, "pDUSessionAggregateMaximumBitRateUL", (int64_t)(in->ambr_ul * 1000));
    if (in->ambr_dl != 0 && in->ambr_ul != 0) /* 0 = unlimited: the IE is optional, so leave it out */
        ie(ies, NGAP_IE_PDUSessionAggregateMaximumBitRate, "reject", v);
    else
        g5c_json_free(v);

    v = g5c_json_new_obj();
    {
        g5c_json *gt = g5c_json_set(v, "gTPTunnel", g5c_json_new_obj());
        g5c_json_set(gt, "transportLayerAddress", bitstring(in->upf_ip4, 32));
        g5c_json_set(gt, "gTP-TEID", teid_json(in->ul_teid));
    }
    ie(ies, NGAP_IE_UL_NGU_UP_TNLInformation, "reject", v);
    ie(ies, NGAP_IE_PDUSessionType, "reject", g5c_json_new_str(in->pdu_type == 1 ? "ipv4" : in->pdu_type == 2 ? "ipv6" : "ipv4v6"));
    fl = g5c_json_new_arr();
    for (size_t i = 0; i < in->pol->nflows; i++) {
        g5c_json *item = g5c_json_push(fl, g5c_json_new_obj());
        g5c_json_set_int(item, "qosFlowIdentifier", in->pol->flows[i].qfi);
        g5c_json_set(item, "qosFlowLevelQosParameters", qos_params(&in->pol->flows[i]));
    }
    ie(ies, NGAP_IE_QosFlowSetupRequestList, "reject", fl);
    rc = ngap_encode_as("PDUSessionResourceSetupRequestTransfer", t, out, err, sizeof err);
    if (rc != 0)
        G5C_LOGE("g5c_smf", "N2 setup request transfer: %s", err);
    g5c_json_free(t);
    return rc;
}

int smf_n2_parse_setup_rsp(const uint8_t *buf, size_t len, smf_an_tunnel *o, char *err, size_t cap)
{
    g5c_json *t;
    const g5c_json *per, *gt, *addr, *flows;
    const char *hex, *teid;
    int64_t bits = 0;
    uint8_t raw[20];
    long n;
    memset(o, 0, sizeof *o);
    t = ngap_decode_as("PDUSessionResourceSetupResponseTransfer", buf, len, err, cap);
    if (t == NULL)
        return -1;
    per = g5c_json_get(t, "dLQosFlowPerTNLInformation");
    gt = g5c_json_get(g5c_json_get(per, "uPTransportLayerInformation"), "gTPTunnel");
    addr = g5c_json_get(gt, "transportLayerAddress");
    hex = g5c_json_get_str(addr, "hex");
    teid = g5c_json_str(g5c_json_get(gt, "gTP-TEID"));
    if (hex == NULL || teid == NULL || !g5c_json_get_int(addr, "len", &bits)) {
        snprintf(err, cap, "response transfer without a downlink GTP tunnel");
        g5c_json_free(t);
        return -1;
    }
    n = g5c_hex_decode(hex, raw, sizeof raw);
    if (n < 0 || (bits != 32 && bits != 128 && bits != 160) || (size_t)n != (size_t)(bits / 8)) {
        snprintf(err, cap, "transport layer address of %lld bits is not an IP address", (long long)bits);
        g5c_json_free(t);
        return -1;
    }
    if (bits == 32 || bits == 160) {
        o->v4 = true;
        memcpy(o->ip4, raw, 4);
    }
    if (bits == 128 || bits == 160) {
        o->v6 = true;
        memcpy(o->ip6, raw + (bits == 160 ? 4 : 0), 16);
    }
    {
        uint8_t tb[4];
        if (g5c_hex_decode(teid, tb, 4) != 4) {
            snprintf(err, cap, "malformed GTP-TEID");
            g5c_json_free(t);
            return -1;
        }
        o->teid = (uint32_t)tb[0] << 24 | (uint32_t)tb[1] << 16 | (uint32_t)tb[2] << 8 | tb[3];
    }
    flows = g5c_json_get(per, "associatedQosFlowList");
    for (size_t i = 0; i < g5c_json_len(flows) && o->naccepted < SMF_MAX_FLOWS; i++) {
        int64_t q;
        if (g5c_json_get_int(g5c_json_at(flows, i), "qosFlowIdentifier", &q) && q >= 0 && q <= 63)
            o->accepted[o->naccepted++] = (uint8_t)q;
    }
    g5c_json_free(t);
    return 0;
}

int smf_n2_parse_cause(const char *type_name, const uint8_t *buf, size_t len, char *out, size_t cap)
{
    char err[120];
    g5c_json *t = ngap_decode_as(type_name, buf, len, err, sizeof err);
    const g5c_json *c;
    int rc = -1;
    if (t == NULL)
        return -1;
    c = g5c_json_get(t, "cause");
    if (g5c_json_is(c, G5C_J_OBJECT) && g5c_json_len(c) == 1) {
        const char *v = g5c_json_str(g5c_json_val_at(c, 0));
        int64_t iv;
        if (v != NULL)
            snprintf(out, cap, "%s:%s", g5c_json_key_at(c, 0), v);
        else if (g5c_json_int(g5c_json_val_at(c, 0), &iv))
            snprintf(out, cap, "%s:%lld", g5c_json_key_at(c, 0), (long long)iv);
        else
            snprintf(out, cap, "%s", g5c_json_key_at(c, 0));
        rc = 0;
    }
    g5c_json_free(t);
    return rc;
}

int smf_n2_build_release_cmd(g5c_bytes *out)
{
    g5c_json *t = g5c_json_new_obj(), *c = g5c_json_set(t, "cause", g5c_json_new_obj());
    char err[120];
    int rc;
    g5c_json_set_str(c, "nas", "normal-release");
    rc = ngap_encode_as("PDUSessionResourceReleaseCommandTransfer", t, out, err, sizeof err);
    if (rc != 0)
        G5C_LOGE("g5c_smf", "N2 release command transfer: %s", err);
    g5c_json_free(t);
    return rc;
}

static const smf_flow *flow_of(const smf_policy *p, uint32_t qer)
{
    for (size_t i = 0; i < p->nflows; i++)
        if (p->flows[i].qer_id == qer)
            return &p->flows[i];
    return NULL;
}

static bool flow_qos_same(const smf_flow *a, const smf_flow *b)
{
    return a->qi5 == b->qi5 && a->arp_prio == b->arp_prio && a->pre_cap == b->pre_cap && a->pre_vuln == b->pre_vuln && a->gbr == b->gbr &&
           a->gbr_ul == b->gbr_ul && a->gbr_dl == b->gbr_dl && a->mbr_ul == b->mbr_ul && a->mbr_dl == b->mbr_dl && a->has_prio_level == b->has_prio_level &&
           a->prio_level == b->prio_level;
}

int smf_n2_build_mod_req(const smf_policy *oldp, const smf_policy *newp, g5c_bytes *out)
{
    g5c_json *t = g5c_json_new_obj(), *ies = g5c_json_set(t, "protocolIEs", g5c_json_new_arr()), *add = NULL, *rel = NULL;
    char err[160];
    int rc = 1;
    if (oldp->ambr_ul != newp->ambr_ul || oldp->ambr_dl != newp->ambr_dl) {
        if (newp->ambr_ul != 0 && newp->ambr_dl != 0) {
            g5c_json *v = g5c_json_new_obj();
            g5c_json_set_int(v, "pDUSessionAggregateMaximumBitRateDL", (int64_t)(newp->ambr_dl * 1000));
            g5c_json_set_int(v, "pDUSessionAggregateMaximumBitRateUL", (int64_t)(newp->ambr_ul * 1000));
            ie(ies, NGAP_IE_PDUSessionAggregateMaximumBitRate, "reject", v);
            rc = 0;
        }
    }
    for (size_t i = 0; i < newp->nflows; i++) {
        const smf_flow *f = &newp->flows[i], *o = flow_of(oldp, f->qer_id);
        if (o != NULL && flow_qos_same(o, f))
            continue;
        if (add == NULL)
            add = g5c_json_new_arr();
        {
            g5c_json *item = g5c_json_push(add, g5c_json_new_obj());
            g5c_json_set_int(item, "qosFlowIdentifier", f->qfi);
            g5c_json_set(item, "qosFlowLevelQosParameters", qos_params(f));
        }
    }
    for (size_t i = 0; i < oldp->nflows; i++) {
        const smf_flow *o = &oldp->flows[i];
        if (o->qfi == SMF_DEFAULT_QFI || flow_of(newp, o->qer_id) != NULL)
            continue;
        if (rel == NULL)
            rel = g5c_json_new_arr();
        {
            g5c_json *item = g5c_json_push(rel, g5c_json_new_obj());
            g5c_json_set_int(item, "qosFlowIdentifier", o->qfi);
            g5c_json_set_str(g5c_json_set(item, "cause", g5c_json_new_obj()), "nas", "normal-release");
        }
    }
    if (add != NULL) {
        ie(ies, NGAP_IE_QosFlowAddOrModifyRequestList, "reject", add);
        rc = 0;
    }
    if (rel != NULL) {
        ie(ies, NGAP_IE_QosFlowToReleaseList, "reject", rel);
        rc = 0;
    }
    if (rc == 0 && ngap_encode_as("PDUSessionResourceModifyRequestTransfer", t, out, err, sizeof err) != 0) {
        G5C_LOGE("g5c_smf", "N2 modify request transfer: %s", err);
        rc = -1;
    }
    g5c_json_free(t);
    return rc;
}

/* ---- handover transfers (TS 38.413 9.3.4.8, 9.3.4.9, 9.3.4.14, 9.3.4.15) ------------------------------------------------------------------------------ */

static int gtp_tunnel_of(const g5c_json *up, const g5c_json *flows, smf_an_tunnel *o, char *err, size_t cap)
{
    const g5c_json *gt = g5c_json_get(up, "gTPTunnel"), *addr = g5c_json_get(gt, "transportLayerAddress");
    const char *hex = g5c_json_get_str(addr, "hex"), *teid = g5c_json_str(g5c_json_get(gt, "gTP-TEID"));
    int64_t bits = 0;
    uint8_t raw[20], tb[4];
    long n;
    memset(o, 0, sizeof *o);
    if (hex == NULL || teid == NULL || !g5c_json_get_int(addr, "len", &bits)) {
        snprintf(err, cap, "transfer without a downlink GTP tunnel");
        return -1;
    }
    n = g5c_hex_decode(hex, raw, sizeof raw);
    if (n < 0 || (bits != 32 && bits != 128 && bits != 160) || (size_t)n != (size_t)(bits / 8)) {
        snprintf(err, cap, "transport layer address of %lld bits is not an IP address", (long long)bits);
        return -1;
    }
    if (bits == 32 || bits == 160) {
        o->v4 = true;
        memcpy(o->ip4, raw, 4);
    }
    if (bits == 128 || bits == 160) {
        o->v6 = true;
        memcpy(o->ip6, raw + (bits == 160 ? 4 : 0), 16);
    }
    if (g5c_hex_decode(teid, tb, 4) != 4) {
        snprintf(err, cap, "malformed GTP-TEID");
        return -1;
    }
    o->teid = (uint32_t)tb[0] << 24 | (uint32_t)tb[1] << 16 | (uint32_t)tb[2] << 8 | tb[3];
    for (size_t i = 0; i < g5c_json_len(flows) && o->naccepted < SMF_MAX_FLOWS; i++) {
        int64_t q;
        if (g5c_json_get_int(g5c_json_at(flows, i), "qosFlowIdentifier", &q) && q >= 0 && q <= 63)
            o->accepted[o->naccepted++] = (uint8_t)q;
    }
    return 0;
}

int smf_n2_parse_path_switch(const uint8_t *buf, size_t len, smf_an_tunnel *o, char *err, size_t cap)
{
    g5c_json *t = ngap_decode_as("PathSwitchRequestTransfer", buf, len, err, cap);
    int rc;
    if (t == NULL)
        return -1;
    rc = gtp_tunnel_of(g5c_json_get(t, "dL-NGU-UP-TNLInformation"), g5c_json_get(t, "qosFlowAcceptedList"), o, err, cap);
    g5c_json_free(t);
    return rc;
}

int smf_n2_parse_ho_ack(const uint8_t *buf, size_t len, smf_an_tunnel *o, char *err, size_t cap)
{
    g5c_json *t = ngap_decode_as("HandoverRequestAcknowledgeTransfer", buf, len, err, cap);
    int rc;
    if (t == NULL)
        return -1;
    rc = gtp_tunnel_of(g5c_json_get(t, "dL-NGU-UP-TNLInformation"), g5c_json_get(t, "qosFlowSetupResponseList"), o, err, cap);
    g5c_json_free(t);
    return rc;
}

int smf_n2_build_path_switch_ack(const uint8_t upf_ip4[4], uint32_t ul_teid, g5c_bytes *out)
{
    g5c_json *t = g5c_json_new_obj(), *up = g5c_json_set(t, "uL-NGU-UP-TNLInformation", g5c_json_new_obj()),
             *gt = g5c_json_set(up, "gTPTunnel", g5c_json_new_obj());
    char err[120];
    int rc;
    g5c_json_set(gt, "transportLayerAddress", bitstring(upf_ip4, 32));
    g5c_json_set(gt, "gTP-TEID", teid_json(ul_teid));
    rc = ngap_encode_as("PathSwitchRequestAcknowledgeTransfer", t, out, err, sizeof err);
    if (rc != 0)
        G5C_LOGE("g5c_smf", "N2 path switch acknowledge transfer: %s", err);
    g5c_json_free(t);
    return rc;
}

int smf_n2_build_ho_command(g5c_bytes *out)
{
    g5c_json *t = g5c_json_new_obj();
    char err[120];
    int rc = ngap_encode_as("HandoverCommandTransfer", t, out, err, sizeof err);
    if (rc != 0)
        G5C_LOGE("g5c_smf", "N2 handover command transfer: %s", err);
    g5c_json_free(t);
    return rc;
}
