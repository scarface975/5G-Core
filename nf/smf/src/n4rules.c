/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* PCC rules -> PFCP rules (TS 29.244 clause 5.2, TS 23.503/23.501 5.7). One Session Establishment Request carries, for the default
 * QoS flow and for every PCC rule: Packet Detection Rules for both directions, the shared Forwarding Action Rules, QoS Enforcement
 * Rules for the session AMBR and for each flow, and a Buffering Action Rule for idle mode.
 *
 * SDF filter direction (clause 5.2.1A.2A): a Flow Description from the PCF is written for downlink traffic and is copied unchanged into
 * the PDI of both uplink and downlink PDRs; the UPF swaps source and destination for a PDR whose source interface is ACCESS. */
#include <stdio.h>
#include <string.h>

#include "g5c/smf.h"

/* 3GPP Interface Type values (TS 29.244 Table 8.2.118-1) */
enum { IFT_N3_3GPP = 11, IFT_N6 = 17 };

#define PUT(call)                                                                                                                         \
    do {                                                                                                                                  \
        if ((call) != 0)                                                                                                                  \
            return -1;                                                                                                                    \
    } while (0)

static int put_sdf(uint8_t *out, size_t cap, size_t *pos, const char *flow)
{
    uint8_t v[300];
    size_t l = strlen(flow);
    if (l > 250)
        return -1;
    v[0] = 0x01; /* FD */
    v[1] = 0;
    v[2] = (uint8_t)(l >> 8);
    v[3] = (uint8_t)l;
    memcpy(v + 4, flow, l);
    return pfcp_put_ie(out, cap, pos, PFCP_IE_SDF_FILTER, v, l + 4);
}

static int put_ue_ip(uint8_t *out, size_t cap, size_t *pos, const smf_n4_est *in, bool dest)
{
    pfcp_ue_ip u;
    memset(&u, 0, sizeof u);
    u.v4 = in->has4;
    u.v6 = in->has6;
    u.sd = dest; /* S/D: 1 = destination address (matching downlink packets), 0 = source (uplink) */
    if (in->has4)
        memcpy(u.ip4, in->ue4, 4);
    if (in->has6) {
        memcpy(u.ip6, in->ue6, 8); /* the /64 prefix, interface identifier zero */
        u.has_prefix_len = true;
        u.prefix_len = 64;
    }
    return pfcp_ue_ip_put(out, cap, pos, &u);
}

/* Create PDR. `filters`: SDF filters to match (NULL entries are skipped); n = number of them. */
static int create_pdr_far(uint8_t *out, size_t cap, size_t *pos, const smf_n4_est *in, uint16_t id, uint32_t prec, bool uplink,
                          const char *const *filters, size_t nf, const uint32_t *qers, size_t nq, uint32_t far_id)
{
    size_t m, m2;
    PUT(pfcp_group_begin(out, cap, pos, PFCP_IE_CREATE_PDR, &m));
    PUT(pfcp_put_u16(out, cap, pos, PFCP_IE_PDR_ID, id));
    PUT(pfcp_put_u32(out, cap, pos, PFCP_IE_PRECEDENCE, prec));
    PUT(pfcp_group_begin(out, cap, pos, PFCP_IE_PDI, &m2));
    PUT(pfcp_put_u8(out, cap, pos, PFCP_IE_SOURCE_INTERFACE, uplink ? 0 : 1)); /* ACCESS / CORE */
    if (uplink) {
        pfcp_fteid f;
        memset(&f, 0, sizeof f);
        f.v4 = true;
        f.ch = true;
        f.chid = true; /* one tunnel per PDU session: every uplink PDR asks for choose id 1 */
        f.choose_id = 1;
        PUT(pfcp_fteid_put(out, cap, pos, &f));
    }
    PUT(pfcp_network_instance_put(out, cap, pos, in->dnn));
    PUT(put_ue_ip(out, cap, pos, in, !uplink));
    PUT(pfcp_put_u8(out, cap, pos, PFCP_IE_3GPP_INTERFACE_TYPE, uplink ? IFT_N3_3GPP : IFT_N6));
    for (size_t i = 0; i < nf; i++)
        if (filters[i] != NULL)
            PUT(put_sdf(out, cap, pos, filters[i]));
    pfcp_group_end(out, pos, m2);
    if (uplink)
        PUT(pfcp_put_u8(out, cap, pos, PFCP_IE_OUTER_HEADER_REMOVAL, PFCP_OHR_GTPU_ANY)); /* N3 may be IPv4 or IPv6 */
    PUT(pfcp_put_u32(out, cap, pos, PFCP_IE_FAR_ID, far_id));
    if (in->want_usage && id != SMF_PDR_RS)
        PUT(pfcp_put_u32(out, cap, pos, PFCP_IE_URR_ID, SMF_URR_SESSION));
    if (in->pol != NULL && in->pol->um_volume != 0 && id != SMF_PDR_RS)
        PUT(pfcp_put_u32(out, cap, pos, PFCP_IE_URR_ID, SMF_URR_MONITOR));
    for (size_t i = 0; i < nq; i++)
        PUT(pfcp_put_u32(out, cap, pos, PFCP_IE_QER_ID, qers[i]));
    pfcp_group_end(out, pos, m);
    return 0;
}

static int create_pdr(uint8_t *out, size_t cap, size_t *pos, const smf_n4_est *in, uint16_t id, uint32_t prec, bool uplink, const char *const *filters,
                      size_t nf, const uint32_t *qers, size_t nq)
{
    return create_pdr_far(out, cap, pos, in, id, prec, uplink, filters, nf, qers, nq, uplink ? SMF_FAR_UL : SMF_FAR_DL);
}

/* IPv6 sessions: the UE's router solicitations are forwarded to the SMF (PDR 4 -> FAR 3, GTP-U to our address with our TEID) and the advertisement comes
 * back through a PDR that matches packets from the control plane (PDR 3) and uses the downlink FAR (TS 29.244 5.8.2 / TS 23.501 5.8.2.2). */
static int create_cp_rules(uint8_t *out, size_t cap, size_t *pos, const smf_n4_est *in)
{
    size_t m, m2;
    pfcp_fteid f;
    static const char *const rs[1] = {"permit out 58 from ff02::2/128 to any"};
    memset(&f, 0, sizeof f);
    f.v4 = true;
    f.ch = true;
    f.chid = true;
    f.choose_id = 2;
    PUT(pfcp_group_begin(out, cap, pos, PFCP_IE_CREATE_PDR, &m));
    PUT(pfcp_put_u16(out, cap, pos, PFCP_IE_PDR_ID, SMF_PDR_CP));
    PUT(pfcp_put_u32(out, cap, pos, PFCP_IE_PRECEDENCE, 255));
    PUT(pfcp_group_begin(out, cap, pos, PFCP_IE_PDI, &m2));
    PUT(pfcp_put_u8(out, cap, pos, PFCP_IE_SOURCE_INTERFACE, 3)); /* CP-function */
    PUT(pfcp_fteid_put(out, cap, pos, &f));
    pfcp_group_end(out, pos, m2);
    PUT(pfcp_put_u8(out, cap, pos, PFCP_IE_OUTER_HEADER_REMOVAL, PFCP_OHR_GTPU_ANY));
    PUT(pfcp_put_u32(out, cap, pos, PFCP_IE_FAR_ID, SMF_FAR_DL));
    pfcp_group_end(out, pos, m);
    PUT(create_pdr_far(out, cap, pos, in, SMF_PDR_RS, 1, true, rs, 1, NULL, 0, SMF_FAR_CP));
    return 0;
}

static int create_cp_far(uint8_t *out, size_t cap, size_t *pos, const smf_n4_est *in)
{
    size_t m, m2;
    pfcp_ohc o;
    uint8_t aa[2] = {PFCP_AA_FORW, 0};
    memset(&o, 0, sizeof o);
    o.desc = PFCP_OHC_GTPU_IPV4;
    o.teid = in->rs_teid;
    memcpy(o.ip4, in->smf_ip4, 4);
    PUT(pfcp_group_begin(out, cap, pos, PFCP_IE_CREATE_FAR, &m));
    PUT(pfcp_put_u32(out, cap, pos, PFCP_IE_FAR_ID, SMF_FAR_CP));
    PUT(pfcp_put_ie(out, cap, pos, PFCP_IE_APPLY_ACTION, aa, 2));
    PUT(pfcp_group_begin(out, cap, pos, PFCP_IE_FORWARDING_PARAMETERS, &m2));
    PUT(pfcp_put_u8(out, cap, pos, PFCP_IE_DESTINATION_INTERFACE, 3)); /* CP-function */
    PUT(pfcp_ohc_put(out, cap, pos, &o));
    pfcp_group_end(out, pos, m2);
    pfcp_group_end(out, pos, m);
    return 0;
}

static int create_qer(uint8_t *out, size_t cap, size_t *pos, uint32_t id, uint8_t qfi, uint64_t mbr_ul, uint64_t mbr_dl, bool gbr, uint64_t gbr_ul,
                      uint64_t gbr_dl)
{
    size_t m;
    pfcp_bitrate br;
    PUT(pfcp_group_begin(out, cap, pos, PFCP_IE_CREATE_QER, &m));
    PUT(pfcp_put_u32(out, cap, pos, PFCP_IE_QER_ID, id));
    PUT(pfcp_put_u8(out, cap, pos, PFCP_IE_GATE_STATUS, 0)); /* UL and DL open */
    if (mbr_ul != 0 || mbr_dl != 0) {
        br.ul = mbr_ul;
        br.dl = mbr_dl;
        PUT(pfcp_bitrate_put(out, cap, pos, PFCP_IE_MBR, &br));
    }
    if (gbr) {
        br.ul = gbr_ul;
        br.dl = gbr_dl;
        PUT(pfcp_bitrate_put(out, cap, pos, PFCP_IE_GBR, &br));
    }
    if (qfi != 0)
        PUT(pfcp_put_u8(out, cap, pos, PFCP_IE_QFI, qfi));
    pfcp_group_end(out, pos, m);
    return 0;
}

static int create_far(uint8_t *out, size_t cap, size_t *pos, uint32_t id, uint16_t action, int dest_if, const char *dnn, bool bar)
{
    size_t m, m2;
    uint8_t aa[2] = {(uint8_t)action, 0};
    PUT(pfcp_group_begin(out, cap, pos, PFCP_IE_CREATE_FAR, &m));
    PUT(pfcp_put_u32(out, cap, pos, PFCP_IE_FAR_ID, id));
    PUT(pfcp_put_ie(out, cap, pos, PFCP_IE_APPLY_ACTION, aa, 2));
    if (dest_if >= 0) {
        PUT(pfcp_group_begin(out, cap, pos, PFCP_IE_FORWARDING_PARAMETERS, &m2));
        PUT(pfcp_put_u8(out, cap, pos, PFCP_IE_DESTINATION_INTERFACE, (uint8_t)dest_if));
        if (dnn != NULL)
            PUT(pfcp_network_instance_put(out, cap, pos, dnn));
        PUT(pfcp_put_u8(out, cap, pos, PFCP_IE_3GPP_INTERFACE_TYPE, IFT_N6));
        pfcp_group_end(out, pos, m2);
    }
    if (bar)
        PUT(pfcp_put_u8(out, cap, pos, PFCP_IE_BAR_ID, SMF_BAR));
    pfcp_group_end(out, pos, m);
    return 0;
}

int smf_n4_build_est(const smf_n4_est *in, uint8_t *out, size_t cap, size_t *len)
{
    size_t pos = 0, m;
    pfcp_node_id nid;
    pfcp_fseid fs;
    const smf_policy *pol = in->pol;
    if (pol == NULL || pol->nflows == 0 || (!in->has4 && !in->has6))
        return -1;
    memset(&nid, 0, sizeof nid);
    memcpy(nid.ip4, in->smf_ip4, 4);
    PUT(pfcp_node_id_put(out, cap, &pos, &nid));
    memset(&fs, 0, sizeof fs);
    fs.v4 = true;
    fs.seid = in->cp_seid;
    memcpy(fs.ip4, in->smf_ip4, 4);
    PUT(pfcp_fseid_put(out, cap, &pos, &fs));

    /* PDRs: the match-everything defaults at the lowest precedence, then the PCC rules */
    {
        uint32_t q[2] = {SMF_QER_SESSION, 2};
        PUT(create_pdr(out, cap, &pos, in, SMF_PDR_UL_DEFAULT, 255, true, NULL, 0, q, 2));
        PUT(create_pdr(out, cap, &pos, in, SMF_PDR_DL_DEFAULT, 255, false, NULL, 0, q, 2));
    }
    for (size_t k = 0; k < pol->nrules; k++) {
        const smf_pcc *r = &pol->rules[k];
        const char *ul[SMF_MAX_FILTERS], *dl[SMF_MAX_FILTERS];
        size_t nul = 0, ndl = 0;
        uint32_t q[2] = {SMF_QER_SESSION, pol->flows[r->flow].qer_id};
        for (size_t i = 0; i < r->nfilters; i++) {
            if (r->dirs[i] != 1)
                ul[nul++] = r->filters[i]; /* bidirectional or uplink */
            if (r->dirs[i] != 2)
                dl[ndl++] = r->filters[i];
        }
        if (nul > 0)
            PUT(create_pdr(out, cap, &pos, in, r->pdr_ul, r->precedence, true, ul, nul, q, 2));
        if (ndl > 0)
            PUT(create_pdr(out, cap, &pos, in, r->pdr_dl, r->precedence, false, dl, ndl, q, 2));
    }

    /* FARs: uplink towards the data network; downlink dropped until the AN tunnel is known */
    PUT(create_far(out, cap, &pos, SMF_FAR_UL, PFCP_AA_FORW, 1 /* CORE */, in->dnn, false));
    PUT(create_far(out, cap, &pos, SMF_FAR_DL, PFCP_AA_DROP, -1, NULL, true));
    if (in->has6 && in->rs_teid != 0) {
        PUT(create_cp_rules(out, cap, &pos, in));
        PUT(create_cp_far(out, cap, &pos, in));
    }

    /* QERs: session AMBR, then one per flow */
    PUT(create_qer(out, cap, &pos, SMF_QER_SESSION, 0, pol->ambr_ul, pol->ambr_dl, false, 0, 0));
    for (size_t i = 0; i < pol->nflows; i++) {
        const smf_flow *f = &pol->flows[i];
        PUT(create_qer(out, cap, &pos, f->qer_id, f->qfi, f->gbr ? f->mbr_ul : 0, f->gbr ? f->mbr_dl : 0, f->gbr, f->gbr_ul, f->gbr_dl));
    }

    if (in->want_usage) { /* Create URR (7.5.2.4): volume and duration, no periodic or threshold trigger; the usage report comes with the session deletion (termination report) */
        PUT(pfcp_group_begin(out, cap, &pos, PFCP_IE_CREATE_URR, &m));
        PUT(pfcp_put_u32(out, cap, &pos, PFCP_IE_URR_ID, SMF_URR_SESSION));
        PUT(pfcp_put_u8(out, cap, &pos, PFCP_IE_MEASUREMENT_METHOD, 0x03)); /* DURAT, VOLUM */
        PUT(pfcp_trigger_put(out, cap, &pos, PFCP_IE_REPORTING_TRIGGERS, 0));
        pfcp_group_end(out, &pos, m);
    }
    if (pol->um_volume != 0) { /* usage monitoring: a second URR that reports to the SMF whenever the threshold of volume has passed (Volume Threshold, trigger VOLTH; TS 29.244 8.2.13) */
        uint8_t th[9];
        uint64_t v = pol->um_volume;
        PUT(pfcp_group_begin(out, cap, &pos, PFCP_IE_CREATE_URR, &m));
        PUT(pfcp_put_u32(out, cap, &pos, PFCP_IE_URR_ID, SMF_URR_MONITOR));
        PUT(pfcp_put_u8(out, cap, &pos, PFCP_IE_MEASUREMENT_METHOD, 0x02)); /* VOLUM */
        PUT(pfcp_trigger_put(out, cap, &pos, PFCP_IE_REPORTING_TRIGGERS, PFCP_URT_VOLTH));
        th[0] = 0x01; /* TOVOL */
        for (int i = 0; i < 8; i++)
            th[1 + i] = (uint8_t)(v >> (56 - 8 * i));
        PUT(pfcp_put_ie(out, cap, &pos, PFCP_IE_VOLUME_THRESHOLD, th, sizeof th));
        pfcp_group_end(out, &pos, m);
    }
    PUT(pfcp_group_begin(out, cap, &pos, PFCP_IE_CREATE_BAR, &m));
    PUT(pfcp_put_u8(out, cap, &pos, PFCP_IE_BAR_ID, SMF_BAR));
    pfcp_group_end(out, &pos, m);

    PUT(pfcp_put_u8(out, cap, &pos, PFCP_IE_PDN_TYPE, in->pdu_type));
    {
        /* APN/DNN (8.2.103): the name as DNS labels, like the Network Instance */
        uint8_t v[80];
        size_t n = 0;
        const char *p = in->dnn;
        while (*p != 0) {
            const char *dot = strchr(p, '.');
            size_t l = dot != NULL ? (size_t)(dot - p) : strlen(p);
            if (l == 0 || l > 63 || n + l + 1 > sizeof v)
                return -1;
            v[n++] = (uint8_t)l;
            memcpy(v + n, p, l);
            n += l;
            p += l + (dot != NULL ? 1 : 0);
        }
        PUT(pfcp_put_ie(out, cap, &pos, PFCP_IE_APN_DNN, v, n));
    }
    if (in->has_snssai) { /* S-NSSAI (8.2.176): Length = 4, SST and the 3 octet SD; without an SD the SD is FFFFFF (TS 23.003 28.4.2) */
        uint32_t sd = in->has_sd ? (in->sd & 0xffffffu) : 0xffffffu;
        uint8_t v[4] = {in->sst, (uint8_t)(sd >> 16), (uint8_t)(sd >> 8), (uint8_t)sd};
        PUT(pfcp_put_ie(out, cap, &pos, PFCP_IE_SNSSAI, v, 4));
    }
    *len = pos;
    return 0;
}

int smf_n4_build_mod_activate(const smf_an_tunnel *t, const char *dnn, uint8_t *out, size_t cap, size_t *len)
{
    size_t pos = 0, m, m2;
    uint8_t aa[2] = {PFCP_AA_FORW, 0};
    pfcp_ohc o;
    if (!t->v4) /* N3 over IPv6 is not supported by the UPF yet */
        return -1;
    memset(&o, 0, sizeof o);
    o.desc = PFCP_OHC_GTPU_IPV4;
    o.teid = t->teid;
    memcpy(o.ip4, t->ip4, 4);
    PUT(pfcp_group_begin(out, cap, &pos, PFCP_IE_UPDATE_FAR, &m));
    PUT(pfcp_put_u32(out, cap, &pos, PFCP_IE_FAR_ID, SMF_FAR_DL));
    PUT(pfcp_put_ie(out, cap, &pos, PFCP_IE_APPLY_ACTION, aa, 2));
    PUT(pfcp_group_begin(out, cap, &pos, PFCP_IE_UPDATE_FORWARDING_PARAMETERS, &m2));
    PUT(pfcp_put_u8(out, cap, &pos, PFCP_IE_DESTINATION_INTERFACE, 0)); /* ACCESS */
    if (dnn != NULL)
        PUT(pfcp_network_instance_put(out, cap, &pos, dnn));
    PUT(pfcp_put_u8(out, cap, &pos, PFCP_IE_3GPP_INTERFACE_TYPE, IFT_N3_3GPP));
    PUT(pfcp_ohc_put(out, cap, &pos, &o));
    pfcp_group_end(out, &pos, m2);
    pfcp_group_end(out, &pos, m);
    *len = pos;
    return 0;
}

int smf_n4_build_mod_deactivate(uint8_t *out, size_t cap, size_t *len)
{
    size_t pos = 0, m;
    uint8_t aa[2] = {PFCP_AA_BUFF | PFCP_AA_NOCP, 0};
    PUT(pfcp_group_begin(out, cap, &pos, PFCP_IE_UPDATE_FAR, &m));
    PUT(pfcp_put_u32(out, cap, &pos, PFCP_IE_FAR_ID, SMF_FAR_DL));
    PUT(pfcp_put_ie(out, cap, &pos, PFCP_IE_APPLY_ACTION, aa, 2));
    PUT(pfcp_put_u8(out, cap, &pos, PFCP_IE_BAR_ID, SMF_BAR));
    pfcp_group_end(out, &pos, m);
    *len = pos;
    return 0;
}

/* ---- policy update (PCF-initiated, TS 29.244 7.5.4) --------------------------------------------------------------------------------------------- */

static const smf_flow *flow_by_qer(const smf_policy *p, uint32_t qer)
{
    for (size_t i = 0; i < p->nflows; i++)
        if (p->flows[i].qer_id == qer)
            return &p->flows[i];
    return NULL;
}

static bool pdr_in(const smf_policy *p, uint16_t id)
{
    if (id == 0)
        return false;
    for (size_t k = 0; k < p->nrules; k++)
        if (p->rules[k].pdr_ul == id || p->rules[k].pdr_dl == id)
            return true;
    return false;
}

static int put_remove_pdr(uint8_t *out, size_t cap, size_t *pos, uint16_t id)
{
    size_t m;
    PUT(pfcp_group_begin(out, cap, pos, PFCP_IE_REMOVE_PDR, &m));
    PUT(pfcp_put_u16(out, cap, pos, PFCP_IE_PDR_ID, id));
    pfcp_group_end(out, pos, m);
    return 0;
}

static int update_qer(uint8_t *out, size_t cap, size_t *pos, uint32_t id, uint64_t mbr_ul, uint64_t mbr_dl, bool gbr, uint64_t gbr_ul, uint64_t gbr_dl)
{
    size_t m;
    pfcp_bitrate br;
    PUT(pfcp_group_begin(out, cap, pos, PFCP_IE_UPDATE_QER, &m));
    PUT(pfcp_put_u32(out, cap, pos, PFCP_IE_QER_ID, id));
    br.ul = mbr_ul;
    br.dl = mbr_dl;
    PUT(pfcp_bitrate_put(out, cap, pos, PFCP_IE_MBR, &br));
    if (gbr) {
        br.ul = gbr_ul;
        br.dl = gbr_dl;
        PUT(pfcp_bitrate_put(out, cap, pos, PFCP_IE_GBR, &br));
    }
    pfcp_group_end(out, pos, m);
    return 0;
}

#define UNLIMITED_KBPS 0xFFFFFFFFFFull /* the largest value of the 40-bit field: "no limit" when a limit has to be lifted */

int smf_n4_build_policy_update(const smf_n4_est *ctx, const smf_policy *oldp, const smf_policy *newp, uint8_t *out, size_t cap, size_t *len, bool *changed)
{
    size_t pos = 0;
    if (oldp->ambr_ul != newp->ambr_ul || oldp->ambr_dl != newp->ambr_dl)
        PUT(update_qer(out, cap, &pos, SMF_QER_SESSION, newp->ambr_ul ? newp->ambr_ul : UNLIMITED_KBPS, newp->ambr_dl ? newp->ambr_dl : UNLIMITED_KBPS, false, 0, 0));
    for (size_t i = 0; i < newp->nflows; i++) {
        const smf_flow *f = &newp->flows[i], *o = flow_by_qer(oldp, f->qer_id);
        if (o == NULL) {
            PUT(create_qer(out, cap, &pos, f->qer_id, f->qfi, f->gbr ? f->mbr_ul : 0, f->gbr ? f->mbr_dl : 0, f->gbr, f->gbr_ul, f->gbr_dl));
        } else if (f->gbr && (o->gbr_ul != f->gbr_ul || o->gbr_dl != f->gbr_dl || o->mbr_ul != f->mbr_ul || o->mbr_dl != f->mbr_dl)) {
            PUT(update_qer(out, cap, &pos, f->qer_id, f->mbr_ul, f->mbr_dl, true, f->gbr_ul, f->gbr_dl));
        }
    }
    for (size_t k = 0; k < oldp->nrules; k++) {
        const smf_pcc *r = &oldp->rules[k];
        if (r->pdr_ul != 0 && !pdr_in(newp, r->pdr_ul))
            PUT(put_remove_pdr(out, cap, &pos, r->pdr_ul));
        if (r->pdr_dl != 0 && !pdr_in(newp, r->pdr_dl))
            PUT(put_remove_pdr(out, cap, &pos, r->pdr_dl));
    }
    for (size_t k = 0; k < newp->nrules; k++) {
        const smf_pcc *r = &newp->rules[k];
        const char *ul[SMF_MAX_FILTERS], *dl[SMF_MAX_FILTERS];
        size_t nul = 0, nd = 0;
        uint32_t q[2] = {SMF_QER_SESSION, newp->flows[r->flow].qer_id};
        for (size_t i = 0; i < r->nfilters; i++) {
            if (r->dirs[i] != 1)
                ul[nul++] = r->filters[i];
            if (r->dirs[i] != 2)
                dl[nd++] = r->filters[i];
        }
        if (nul > 0 && r->pdr_ul != 0 && !pdr_in(oldp, r->pdr_ul))
            PUT(create_pdr(out, cap, &pos, ctx, r->pdr_ul, r->precedence, true, ul, nul, q, 2));
        if (nd > 0 && r->pdr_dl != 0 && !pdr_in(oldp, r->pdr_dl))
            PUT(create_pdr(out, cap, &pos, ctx, r->pdr_dl, r->precedence, false, dl, nd, q, 2));
    }
    for (size_t i = 0; i < oldp->nflows; i++)
        if (flow_by_qer(newp, oldp->flows[i].qer_id) == NULL && oldp->flows[i].qer_id != 0) {
            size_t m;
            PUT(pfcp_group_begin(out, cap, &pos, PFCP_IE_REMOVE_QER, &m));
            PUT(pfcp_put_u32(out, cap, &pos, PFCP_IE_QER_ID, oldp->flows[i].qer_id));
            pfcp_group_end(out, &pos, m);
        }
    *len = pos;
    *changed = pos > 0;
    return 0;
}

uint8_t smf_n4_cause_of(const smf_n4_msg *m)
{
    size_t p = 0;
    pfcp_ie ie;
    uint8_t c;
    while (pfcp_ie_next(m->body, m->blen, &p, &ie) == 1)
        if (ie.typ == PFCP_IE_CAUSE && pfcp_get_u8(&ie, &c) == 0)
            return c;
    return 0;
}

int smf_n4_parse_est_rsp(const smf_n4_msg *m, smf_n4_est_rsp *o)
{
    size_t p = 0;
    pfcp_ie ie;
    memset(o, 0, sizeof *o);
    if (m->h.msg_type != PFCP_SESSION_ESTABLISHMENT_RESPONSE)
        return -1;
    while (pfcp_ie_next(m->body, m->blen, &p, &ie) == 1) {
        if (ie.typ == PFCP_IE_CAUSE) {
            if (pfcp_get_u8(&ie, &o->cause) != 0)
                return -1;
        } else if (ie.typ == PFCP_IE_OFFENDING_IE) {
            (void)pfcp_get_u16(&ie, &o->offending_ie);
        } else if (ie.typ == PFCP_IE_FSEID) {
            pfcp_fseid f;
            if (pfcp_fseid_decode(&ie, &f) != 0)
                return -1;
            o->up_seid = f.seid;
        } else if (ie.typ == PFCP_IE_CREATED_PDR) {
            size_t q = 0;
            pfcp_ie sub;
            uint16_t id = 0;
            pfcp_fteid ft;
            bool has_ft = false;
            while (pfcp_ie_next(ie.value, ie.len, &q, &sub) == 1) {
                if (sub.typ == PFCP_IE_PDR_ID && pfcp_get_u16(&sub, &id) != 0)
                    return -1;
                if (sub.typ == PFCP_IE_FTEID) {
                    if (pfcp_fteid_decode(&sub, &ft) != 0)
                        return -1;
                    has_ft = true;
                }
            }
            if (id == SMF_PDR_CP && has_ft && ft.v4 && !ft.ch)
                o->cp_teid = ft.teid;
            if (id == SMF_PDR_UL_DEFAULT && has_ft && ft.v4 && !ft.ch) {
                o->has_fteid = true;
                o->ul_teid = ft.teid;
                memcpy(o->ul_ip4, ft.ip4, 4);
            }
        }
    }
    o->ok = o->cause == PFCP_CAUSE_ACCEPTED && o->up_seid != 0 && o->has_fteid;
    return 0;
}
