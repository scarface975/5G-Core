/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* PFCP rule handling: parse Create / Update / Remove for PDR, FAR, QER, URR and BAR (TS 29.244 7.5.2 and 7.5.4) into the session. */
#include <string.h>

#include "priv.h"
#include "rules.h"

/* ---- lookups ---- */

upf_pdr *sess_find_pdr(upf_session *s, uint16_t id)
{
    for (size_t i = 0; i < s->npdr; i++)
        if (s->pdr[i].id == id)
            return &s->pdr[i];
    return NULL;
}

upf_far *sess_find_far(upf_session *s, uint32_t id)
{
    for (size_t i = 0; i < s->nfar; i++)
        if (s->far[i].id == id)
            return &s->far[i];
    return NULL;
}

upf_qer *sess_find_qer(upf_session *s, uint32_t id)
{
    for (size_t i = 0; i < s->nqer; i++)
        if (s->qer[i].id == id)
            return &s->qer[i];
    return NULL;
}

upf_urr *sess_find_urr(upf_session *s, uint32_t id)
{
    for (size_t i = 0; i < s->nurr; i++)
        if (s->urr[i].id == id)
            return &s->urr[i];
    return NULL;
}

upf_bar *sess_find_bar(upf_session *s, uint8_t id)
{
    for (size_t i = 0; i < s->nbar; i++)
        if (s->bar[i].id == id)
            return &s->bar[i];
    return NULL;
}

#define ADD(arr, n, T) ((arr) = g5c_xrealloc((arr), ((n) + 1) * sizeof(T)), memset(&(arr)[(n)], 0, sizeof(T)), &(arr)[(n)++])

/* ---- TEID and index management ---- */

static uint32_t alloc_teid(upf *u)
{
    for (int tries = 0; tries < 1000000; tries++) {
        uint32_t t = ++u->next_teid;
        if (t != 0 && ptrmap_get(u->by_teid, t) == NULL)
            return t;
    }
    return 0;
}

void sess_index_pdr(upf *u, upf_session *s, upf_pdr *p)
{
    if (p->has_fteid && p->local_teid != 0)
        ptrmap_put(u->by_teid, p->local_teid, s);
    if (p->has_ue_ip) {
        if (p->ue_ip.v4) {
            uint32_t k = ((uint32_t)p->ue_ip.ip4[0] << 24) | ((uint32_t)p->ue_ip.ip4[1] << 16) | ((uint32_t)p->ue_ip.ip4[2] << 8) | p->ue_ip.ip4[3];
            memset(&s->ue4, 0, sizeof s->ue4);
            memcpy(s->ue4.b, p->ue_ip.ip4, 4);
            s->has_ue4 = true;
            ptrmap_put(u->by_ue4, k, s);
        }
        if (p->ue_ip.v6) {
            uint64_t k = 0;
            for (int i = 0; i < 8; i++)
                k = (k << 8) | p->ue_ip.ip6[i];
            memset(&s->ue6, 0, sizeof s->ue6);
            s->ue6.v6 = true;
            memcpy(s->ue6.b, p->ue_ip.ip6, 16);
            s->has_ue6 = true;
            ptrmap_put(u->by_ue6, k, s);
        }
    }
}

void sess_unindex(upf *u, upf_session *s)
{
    for (size_t i = 0; i < s->npdr; i++) {
        upf_pdr *p = &s->pdr[i];
        if (p->has_fteid && p->local_teid && ptrmap_get(u->by_teid, p->local_teid) == s)
            ptrmap_del(u->by_teid, p->local_teid);
    }
    if (s->has_ue4) {
        uint32_t k = ((uint32_t)s->ue4.b[0] << 24) | ((uint32_t)s->ue4.b[1] << 16) | ((uint32_t)s->ue4.b[2] << 8) | s->ue4.b[3];
        if (ptrmap_get(u->by_ue4, k) == s)
            ptrmap_del(u->by_ue4, k);
    }
    if (s->has_ue6) {
        uint64_t k = 0;
        for (int i = 0; i < 8; i++)
            k = (k << 8) | s->ue6.b[i];
        if (ptrmap_get(u->by_ue6, k) == s)
            ptrmap_del(u->by_ue6, k);
    }
}

static void pdr_free(upf_pdr *p)
{
    free(p->sdf);
    p->sdf = NULL;
}

void sess_free(upf *u, upf_session *s)
{
    (void)u;
    for (size_t i = 0; i < s->npdr; i++)
        pdr_free(&s->pdr[i]);
    dp_drop_buffer(s);
    free(s->buf);
    free(s->pdr);
    free(s->far);
    free(s->qer);
    free(s->urr);
    free(s->bar);
    free(s);
}

/* ---- Create PDR ---- */

static int parse_pdi(const pfcp_ie *pdi, upf_pdr *p, uint16_t *bad)
{
    size_t pos = 0;
    pfcp_ie ie;
    bool have_if = false;
    int rc;
    while ((rc = pfcp_ie_next(pdi->value, pdi->len, &pos, &ie)) == 1) {
        switch (ie.typ) {
        case PFCP_IE_SOURCE_INTERFACE: {
            uint8_t v;
            if (pfcp_get_u8(&ie, &v) != 0) {
                *bad = PFCP_IE_SOURCE_INTERFACE;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            p->src_if = v & 0x0f;
            have_if = true;
            break;
        }
        case PFCP_IE_FTEID:
            if (pfcp_fteid_decode(&ie, &p->fteid) != 0) {
                *bad = PFCP_IE_FTEID;
                return PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            }
            p->has_fteid = true;
            break;
        case PFCP_IE_NETWORK_INSTANCE:
            if (pfcp_network_instance_decode(&ie, p->net_inst, sizeof p->net_inst) != 0) {
                *bad = PFCP_IE_NETWORK_INSTANCE;
                return PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            }
            break;
        case PFCP_IE_UE_IP_ADDRESS:
            if (pfcp_ue_ip_decode(&ie, &p->ue_ip) != 0) {
                *bad = PFCP_IE_UE_IP_ADDRESS;
                return PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            }
            if (p->ue_ip.chv4 || p->ue_ip.chv6) { /* UE address allocation by the UPF is not supported (use SMF-side allocation) */
                *bad = PFCP_IE_UE_IP_ADDRESS;
                return PFCP_CAUSE_RULE_CREATION_FAILURE;
            }
            p->has_ue_ip = true;
            break;
        case PFCP_IE_SDF_FILTER: {
            pfcp_sdf_filter f;
            upf_sdf rule;
            if (pfcp_sdf_filter_decode(&ie, &f) != 0) {
                *bad = PFCP_IE_SDF_FILTER;
                return PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            }
            if (f.has_fd) {
                if (upf_sdf_parse(f.flow, &rule, NULL, 0) != 0) {
                    *bad = PFCP_IE_SDF_FILTER;
                    return PFCP_CAUSE_MANDATORY_IE_INCORRECT;
                }
                p->sdf = g5c_xrealloc(p->sdf, (p->nsdf + 1) * sizeof *p->sdf);
                p->sdf[p->nsdf++] = rule;
            } /* filters carrying only ToS, SPI, flow label or a filter id are not matched on */
            break;
        }
        case PFCP_IE_QFI: {
            uint8_t v;
            if (pfcp_get_u8(&ie, &v) != 0) {
                *bad = PFCP_IE_QFI;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            p->has_qfi = true;
            p->qfi = v & 0x3f;
            break;
        }
        default:
            break; /* 3GPP interface type, application id, ethernet and the like do not change forwarding here */
        }
    }
    if (rc < 0) {
        *bad = PFCP_IE_PDI;
        return PFCP_CAUSE_INVALID_LENGTH;
    }
    if (!have_if) {
        *bad = PFCP_IE_SOURCE_INTERFACE;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    return 0;
}

/* apply the non-PDI members of a Create/Update PDR group */
static int parse_pdr_members(const pfcp_ie *grp, upf_pdr *p, bool create, uint16_t *bad, bool *pdi_seen)
{
    size_t pos = 0;
    pfcp_ie ie;
    int rc;
    bool qer_reset = true, urr_reset = true;
    *pdi_seen = false;
    while ((rc = pfcp_ie_next(grp->value, grp->len, &pos, &ie)) == 1) {
        switch (ie.typ) {
        case PFCP_IE_PDR_ID:
            break; /* handled by the caller */
        case PFCP_IE_PRECEDENCE:
            if (pfcp_get_u32(&ie, &p->precedence) != 0) {
                *bad = PFCP_IE_PRECEDENCE;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            break;
        case PFCP_IE_PDI: {
            upf_pdr fresh;
            int c;
            memset(&fresh, 0, sizeof fresh);
            c = parse_pdi(&ie, &fresh, bad);
            if (c != 0) {
                free(fresh.sdf);
                return c;
            }
            /* a PDI in an update replaces the previous one */
            free(p->sdf);
            p->src_if = fresh.src_if;
            p->has_fteid = fresh.has_fteid;
            p->fteid = fresh.fteid;
            if (!create && p->has_fteid && p->fteid.ch)
                p->local_teid = p->local_teid; /* keep the TEID we already assigned */
            p->has_ue_ip = fresh.has_ue_ip;
            p->ue_ip = fresh.ue_ip;
            memcpy(p->net_inst, fresh.net_inst, sizeof p->net_inst);
            p->has_qfi = fresh.has_qfi;
            p->qfi = fresh.qfi;
            p->sdf = fresh.sdf;
            p->nsdf = fresh.nsdf;
            *pdi_seen = true;
            break;
        }
        case PFCP_IE_OUTER_HEADER_REMOVAL:
            p->ohr = ie.len >= 1;
            break;
        case PFCP_IE_FAR_ID:
            if (pfcp_get_u32(&ie, &p->far_id) != 0) {
                *bad = PFCP_IE_FAR_ID;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            p->has_far = true;
            break;
        case PFCP_IE_QER_ID: {
            uint32_t id;
            if (pfcp_get_u32(&ie, &id) != 0) {
                *bad = PFCP_IE_QER_ID;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            if (qer_reset) {
                p->nqer = 0;
                qer_reset = false;
            }
            if (p->nqer == 4) {
                *bad = PFCP_IE_QER_ID;
                return PFCP_CAUSE_RULE_CREATION_FAILURE;
            }
            p->qer_ids[p->nqer++] = id;
            break;
        }
        case PFCP_IE_URR_ID: {
            uint32_t id;
            if (pfcp_get_u32(&ie, &id) != 0) {
                *bad = PFCP_IE_URR_ID;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            if (urr_reset) {
                p->nurr = 0;
                urr_reset = false;
            }
            if (p->nurr == 4) {
                *bad = PFCP_IE_URR_ID;
                return PFCP_CAUSE_RULE_CREATION_FAILURE;
            }
            p->urr_ids[p->nurr++] = id;
            break;
        }
        default:
            break;
        }
    }
    if (rc < 0) {
        *bad = grp->typ;
        return PFCP_CAUSE_INVALID_LENGTH;
    }
    return 0;
}

static bool group_pdr_id(const pfcp_ie *grp, uint16_t *id)
{
    size_t pos = 0;
    pfcp_ie ie;
    while (pfcp_ie_next(grp->value, grp->len, &pos, &ie) == 1)
        if (ie.typ == PFCP_IE_PDR_ID)
            return pfcp_get_u16(&ie, id) == 0;
    return false;
}

static bool group_has(const pfcp_ie *grp, uint16_t typ)
{
    size_t pos = 0;
    pfcp_ie ie;
    while (pfcp_ie_next(grp->value, grp->len, &pos, &ie) == 1)
        if (ie.typ == typ)
            return true;
    return false;
}

static void assign_teid(upf *u, upf_pdr *p, upf_choose *ch)
{
    if (!p->has_fteid)
        return;
    if (!p->fteid.ch) {
        p->local_teid = p->fteid.teid;
        return;
    }
    if (p->fteid.chid && ch->have[p->fteid.choose_id]) {
        p->local_teid = ch->teid[p->fteid.choose_id];
        return;
    }
    p->local_teid = alloc_teid(u);
    if (p->fteid.chid) {
        ch->have[p->fteid.choose_id] = true;
        ch->teid[p->fteid.choose_id] = p->local_teid;
    }
}

int rules_create_pdr(upf *u, upf_session *s, const pfcp_ie *grp, upf_choose *ch, uint16_t *bad)
{
    uint16_t id = 0;
    upf_pdr *p;
    bool pdi;
    int c;
    if (!group_pdr_id(grp, &id)) {
        *bad = PFCP_IE_PDR_ID;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    if (!group_has(grp, PFCP_IE_PRECEDENCE)) {
        *bad = PFCP_IE_PRECEDENCE;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    if (!group_has(grp, PFCP_IE_PDI)) {
        *bad = PFCP_IE_PDI;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    if (sess_find_pdr(s, id) != NULL) {
        *bad = PFCP_IE_PDR_ID;
        return PFCP_CAUSE_RULE_CREATION_FAILURE;
    }
    if (s->npdr >= 64) {
        *bad = PFCP_IE_CREATE_PDR;
        return PFCP_CAUSE_NO_RESOURCES;
    }
    p = ADD(s->pdr, s->npdr, upf_pdr);
    p->id = id;
    c = parse_pdr_members(grp, p, true, bad, &pdi);
    if (c != 0) {
        pdr_free(p);
        s->npdr--;
        return c;
    }
    assign_teid(u, p, ch);
    if (p->has_fteid && p->local_teid == 0) {
        *bad = PFCP_IE_FTEID;
        pdr_free(p);
        s->npdr--;
        return PFCP_CAUSE_INVALID_FTEID_ALLOCATION;
    }
    if (p->has_fteid && !p->fteid.ch) { /* explicit TEID must not collide with another session */
        upf_session *other = ptrmap_get(u->by_teid, p->local_teid);
        if (other != NULL && other != s) {
            *bad = PFCP_IE_FTEID;
            pdr_free(p);
            s->npdr--;
            return PFCP_CAUSE_INVALID_FTEID_ALLOCATION;
        }
    }
    if (ch->ncreated < sizeof ch->created / sizeof *ch->created && p->has_fteid && p->fteid.ch)
        ch->created[ch->ncreated++] = id;
    return 0;
}

int rules_update_pdr(upf *u, upf_session *s, const pfcp_ie *grp, upf_choose *ch, uint16_t *bad)
{
    uint16_t id = 0;
    upf_pdr *p;
    bool pdi;
    bool had_fteid, had_ch;
    int c;
    (void)u;
    if (!group_pdr_id(grp, &id)) {
        *bad = PFCP_IE_PDR_ID;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    p = sess_find_pdr(s, id);
    if (p == NULL) {
        *bad = PFCP_IE_PDR_ID;
        return PFCP_CAUSE_RULE_CREATION_FAILURE;
    }
    had_fteid = p->has_fteid;
    had_ch = p->has_fteid && p->fteid.ch;
    {
        uint32_t keep = p->local_teid;
        c = parse_pdr_members(grp, p, false, bad, &pdi);
        if (c != 0)
            return c;
        if (pdi && p->has_fteid && p->fteid.ch && had_ch)
            p->local_teid = keep; /* an update that repeats the CHOOSE request keeps the TEID */
        else if (pdi && p->has_fteid && (!had_fteid || (!p->fteid.ch && p->fteid.teid != keep))) {
            if (p->fteid.ch)
                assign_teid(u, p, ch);
            else
                p->local_teid = p->fteid.teid;
        } else if (!pdi) {
            p->local_teid = keep;
        }
    }
    return 0;
}

int rules_remove_pdr(upf *u, upf_session *s, const pfcp_ie *grp, uint16_t *bad)
{
    uint16_t id = 0;
    size_t i, pos = 0;
    pfcp_ie ie;
    bool have = false;
    while (pfcp_ie_next(grp->value, grp->len, &pos, &ie) == 1)
        if (ie.typ == PFCP_IE_PDR_ID && pfcp_get_u16(&ie, &id) == 0)
            have = true;
    if (!have) {
        *bad = PFCP_IE_PDR_ID;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    for (i = 0; i < s->npdr; i++)
        if (s->pdr[i].id == id)
            break;
    if (i == s->npdr) {
        *bad = PFCP_IE_PDR_ID;
        return PFCP_CAUSE_RULE_CREATION_FAILURE;
    }
    if (s->pdr[i].has_fteid && s->pdr[i].local_teid && ptrmap_get(u->by_teid, s->pdr[i].local_teid) == s) {
        bool shared = false;
        for (size_t k = 0; k < s->npdr; k++)
            if (k != i && s->pdr[k].has_fteid && s->pdr[k].local_teid == s->pdr[i].local_teid)
                shared = true;
        if (!shared)
            ptrmap_del(u->by_teid, s->pdr[i].local_teid);
    }
    pdr_free(&s->pdr[i]);
    memmove(&s->pdr[i], &s->pdr[i + 1], (s->npdr - i - 1) * sizeof *s->pdr);
    s->npdr--;
    return 0;
}

/* ---- FAR ---- */

static int parse_far_forwarding(const pfcp_ie *grp, upf_far *f, uint16_t *bad)
{
    size_t pos = 0;
    pfcp_ie ie;
    int rc;
    while ((rc = pfcp_ie_next(grp->value, grp->len, &pos, &ie)) == 1) {
        switch (ie.typ) {
        case PFCP_IE_DESTINATION_INTERFACE: {
            uint8_t v;
            if (pfcp_get_u8(&ie, &v) != 0) {
                *bad = ie.typ;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            f->dest_if = v & 0x0f;
            break;
        }
        case PFCP_IE_OUTER_HEADER_CREATION:
            if (pfcp_ohc_decode(&ie, &f->ohc) != 0) {
                *bad = ie.typ;
                return PFCP_CAUSE_MANDATORY_IE_INCORRECT;
            }
            if (f->ohc.desc & (PFCP_OHC_GTPU_IPV6 | PFCP_OHC_UDP_IPV6 | PFCP_OHC_IPV6)) { /* N3/N9 over IPv6 is not supported yet */
                *bad = ie.typ;
                return PFCP_CAUSE_RULE_CREATION_FAILURE;
            }
            f->has_ohc = true;
            break;
        default:
            break;
        }
    }
    if (rc < 0) {
        *bad = grp->typ;
        return PFCP_CAUSE_INVALID_LENGTH;
    }
    return 0;
}

int rules_create_far(upf_session *s, const pfcp_ie *grp, uint16_t *bad)
{
    size_t pos = 0;
    pfcp_ie ie;
    int rc;
    upf_far *f;
    bool have_id = false, have_aa = false;
    upf_far tmp;
    memset(&tmp, 0, sizeof tmp);
    while ((rc = pfcp_ie_next(grp->value, grp->len, &pos, &ie)) == 1) {
        if (ie.typ == PFCP_IE_FAR_ID) {
            if (pfcp_get_u32(&ie, &tmp.id) != 0) {
                *bad = PFCP_IE_FAR_ID;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            have_id = true;
        } else if (ie.typ == PFCP_IE_APPLY_ACTION) {
            if (pfcp_apply_action_decode(&ie, &tmp.action) != 0) {
                *bad = PFCP_IE_APPLY_ACTION;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            have_aa = true;
        } else if (ie.typ == PFCP_IE_FORWARDING_PARAMETERS) {
            int c = parse_far_forwarding(&ie, &tmp, bad);
            if (c != 0)
                return c;
        } else if (ie.typ == PFCP_IE_BAR_ID) {
            if (pfcp_get_u8(&ie, &tmp.bar_id) != 0) {
                *bad = PFCP_IE_BAR_ID;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            tmp.has_bar = true;
        }
    }
    if (rc < 0) {
        *bad = PFCP_IE_CREATE_FAR;
        return PFCP_CAUSE_INVALID_LENGTH;
    }
    if (!have_id) {
        *bad = PFCP_IE_FAR_ID;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    if (!have_aa) {
        *bad = PFCP_IE_APPLY_ACTION;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    if (sess_find_far(s, tmp.id) != NULL) {
        *bad = PFCP_IE_FAR_ID;
        return PFCP_CAUSE_RULE_CREATION_FAILURE;
    }
    if (s->nfar >= 64) {
        *bad = PFCP_IE_CREATE_FAR;
        return PFCP_CAUSE_NO_RESOURCES;
    }
    f = ADD(s->far, s->nfar, upf_far);
    *f = tmp;
    return 0;
}

int rules_update_far(upf *u, upf_session *s, const pfcp_ie *grp, bool sndem, uint16_t *bad)
{
    size_t pos = 0;
    pfcp_ie ie;
    int rc;
    uint32_t id = 0;
    bool have_id = false;
    upf_far *f, old;
    while (pfcp_ie_next(grp->value, grp->len, &pos, &ie) == 1)
        if (ie.typ == PFCP_IE_FAR_ID && pfcp_get_u32(&ie, &id) == 0)
            have_id = true;
    if (!have_id) {
        *bad = PFCP_IE_FAR_ID;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    f = sess_find_far(s, id);
    if (f == NULL) {
        *bad = PFCP_IE_FAR_ID;
        return PFCP_CAUSE_RULE_CREATION_FAILURE;
    }
    old = *f;
    pos = 0;
    while ((rc = pfcp_ie_next(grp->value, grp->len, &pos, &ie)) == 1) {
        if (ie.typ == PFCP_IE_APPLY_ACTION) {
            if (pfcp_apply_action_decode(&ie, &f->action) != 0) {
                *bad = PFCP_IE_APPLY_ACTION;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
        } else if (ie.typ == PFCP_IE_UPDATE_FORWARDING_PARAMETERS) {
            int c = parse_far_forwarding(&ie, f, bad);
            if (c != 0)
                return c;
        } else if (ie.typ == PFCP_IE_BAR_ID) {
            if (pfcp_get_u8(&ie, &f->bar_id) == 0)
                f->has_bar = true;
        }
    }
    if (rc < 0) {
        *bad = PFCP_IE_UPDATE_FAR;
        return PFCP_CAUSE_INVALID_LENGTH;
    }
    /* handover: tell the old tunnel endpoint that no more downlink data will come through it */
    if (sndem && old.has_ohc && f->has_ohc && (old.ohc.teid != f->ohc.teid || memcmp(old.ohc.ip4, f->ohc.ip4, 4) != 0))
        dp_send_end_marker(u, &old);
    /* data that was being held can go as soon as the action allows forwarding */
    if ((f->action & PFCP_AA_FORW) && !(f->action & PFCP_AA_BUFF) && f->has_ohc)
        dp_flush_buffer(u, s, u->now);
    return 0;
}

int rules_remove_id(upf_session *s, const pfcp_ie *grp, uint16_t type, uint16_t idtype, uint16_t *bad)
{
    size_t pos = 0;
    pfcp_ie ie;
    uint32_t id = 0;
    bool have = false;
    while (pfcp_ie_next(grp->value, grp->len, &pos, &ie) == 1) {
        if (ie.typ == idtype) {
            if (idtype == PFCP_IE_BAR_ID) {
                uint8_t b;
                if (pfcp_get_u8(&ie, &b) == 0) {
                    id = b;
                    have = true;
                }
            } else if (pfcp_get_u32(&ie, &id) == 0) {
                have = true;
            }
        }
    }
    if (!have) {
        *bad = idtype;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
#define REMOVE(arr, n, field) \
    do { \
        size_t i; \
        for (i = 0; i < (n); i++) \
            if ((arr)[i].field == id) \
                break; \
        if (i == (n)) { \
            *bad = idtype; \
            return PFCP_CAUSE_RULE_CREATION_FAILURE; \
        } \
        memmove(&(arr)[i], &(arr)[i + 1], ((n) - i - 1) * sizeof *(arr)); \
        (n)--; \
    } while (0)
    switch (type) {
    case PFCP_IE_REMOVE_FAR:
        REMOVE(s->far, s->nfar, id);
        break;
    case PFCP_IE_REMOVE_QER:
        REMOVE(s->qer, s->nqer, id);
        break;
    case PFCP_IE_REMOVE_URR:
        REMOVE(s->urr, s->nurr, id);
        break;
    case PFCP_IE_REMOVE_BAR:
        REMOVE(s->bar, s->nbar, id);
        break;
    default:
        return PFCP_CAUSE_SERVICE_NOT_SUPPORTED;
    }
#undef REMOVE
    return 0;
}

/* ---- QER ---- */

void bucket_init(upf_bucket *b, uint64_t kbps, double now)
{
    memset(b, 0, sizeof *b);
    if (kbps == 0)
        return;
    b->enabled = true;
    b->rate_bytes_per_s = (double)kbps * 1000.0 / 8.0;
    b->burst = b->rate_bytes_per_s * 0.05; /* 50 ms of traffic, but never less than a couple of full-size packets */
    if (b->burst < 3000.0)
        b->burst = 3000.0;
    b->tokens = b->burst;
    b->last = now;
}

void qer_rebuild(upf_qer *q, double now)
{
    bucket_init(&q->ul, q->has_mbr ? q->mbr.ul : 0, now);
    bucket_init(&q->dl, q->has_mbr ? q->mbr.dl : 0, now);
}

static int parse_qer_members(const pfcp_ie *grp, upf_qer *q, uint16_t *bad)
{
    size_t pos = 0;
    pfcp_ie ie;
    int rc;
    while ((rc = pfcp_ie_next(grp->value, grp->len, &pos, &ie)) == 1) {
        switch (ie.typ) {
        case PFCP_IE_GATE_STATUS: {
            pfcp_gate g;
            if (pfcp_gate_decode(&ie, &g) != 0) {
                *bad = ie.typ;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            q->ul_closed = g.ul_closed;
            q->dl_closed = g.dl_closed;
            break;
        }
        case PFCP_IE_MBR:
            if (pfcp_bitrate_decode(&ie, &q->mbr) != 0) {
                *bad = ie.typ;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            q->has_mbr = true;
            break;
        case PFCP_IE_GBR:
            if (pfcp_bitrate_decode(&ie, &q->gbr) != 0) {
                *bad = ie.typ;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            q->has_gbr = true;
            break;
        case PFCP_IE_QFI: {
            uint8_t v;
            if (pfcp_get_u8(&ie, &v) == 0) {
                q->has_qfi = true;
                q->qfi = v & 0x3f;
            }
            break;
        }
        default:
            break;
        }
    }
    if (rc < 0) {
        *bad = grp->typ;
        return PFCP_CAUSE_INVALID_LENGTH;
    }
    return 0;
}

static bool group_id32(const pfcp_ie *grp, uint16_t typ, uint32_t *id)
{
    size_t pos = 0;
    pfcp_ie ie;
    while (pfcp_ie_next(grp->value, grp->len, &pos, &ie) == 1)
        if (ie.typ == typ)
            return pfcp_get_u32(&ie, id) == 0;
    return false;
}

int rules_create_qer(upf_session *s, const pfcp_ie *grp, double now, uint16_t *bad)
{
    uint32_t id;
    upf_qer *q, tmp;
    int c;
    if (!group_id32(grp, PFCP_IE_QER_ID, &id)) {
        *bad = PFCP_IE_QER_ID;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    if (sess_find_qer(s, id) != NULL) {
        *bad = PFCP_IE_QER_ID;
        return PFCP_CAUSE_RULE_CREATION_FAILURE;
    }
    if (s->nqer >= 32) {
        *bad = PFCP_IE_CREATE_QER;
        return PFCP_CAUSE_NO_RESOURCES;
    }
    memset(&tmp, 0, sizeof tmp);
    tmp.id = id;
    c = parse_qer_members(grp, &tmp, bad);
    if (c != 0)
        return c;
    q = ADD(s->qer, s->nqer, upf_qer);
    *q = tmp;
    qer_rebuild(q, now);
    return 0;
}

int rules_update_qer(upf_session *s, const pfcp_ie *grp, double now, uint16_t *bad)
{
    uint32_t id;
    upf_qer *q;
    int c;
    if (!group_id32(grp, PFCP_IE_QER_ID, &id)) {
        *bad = PFCP_IE_QER_ID;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    q = sess_find_qer(s, id);
    if (q == NULL) {
        *bad = PFCP_IE_QER_ID;
        return PFCP_CAUSE_RULE_CREATION_FAILURE;
    }
    c = parse_qer_members(grp, q, bad);
    if (c == 0)
        qer_rebuild(q, now);
    return c;
}

/* ---- URR ---- */

static int parse_urr_members(const pfcp_ie *grp, upf_urr *r, uint16_t *bad)
{
    size_t pos = 0;
    pfcp_ie ie;
    int rc;
    while ((rc = pfcp_ie_next(grp->value, grp->len, &pos, &ie)) == 1) {
        switch (ie.typ) {
        case PFCP_IE_MEASUREMENT_METHOD: {
            uint8_t v;
            if (pfcp_get_u8(&ie, &v) != 0) {
                *bad = ie.typ;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            r->method = v;
            break;
        }
        case PFCP_IE_REPORTING_TRIGGERS:
            if (pfcp_trigger_decode(&ie, &r->triggers) != 0) {
                *bad = ie.typ;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            break;
        case PFCP_IE_VOLUME_THRESHOLD:
            if (pfcp_volume_decode(&ie, &r->vol_thresh) != 0) {
                *bad = ie.typ;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            r->has_vol_thresh = true;
            break;
        case PFCP_IE_TIME_THRESHOLD:
            if (pfcp_get_u32(&ie, &r->time_thresh) != 0) {
                *bad = ie.typ;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            r->has_time_thresh = true;
            break;
        case PFCP_IE_MEASUREMENT_PERIOD:
            if (pfcp_get_u32(&ie, &r->period) != 0) {
                *bad = ie.typ;
                return PFCP_CAUSE_INVALID_LENGTH;
            }
            break;
        default:
            break;
        }
    }
    if (rc < 0) {
        *bad = grp->typ;
        return PFCP_CAUSE_INVALID_LENGTH;
    }
    return 0;
}

int rules_create_urr(upf_session *s, const pfcp_ie *grp, double now, uint16_t *bad)
{
    uint32_t id;
    upf_urr *r, tmp;
    int c;
    if (!group_id32(grp, PFCP_IE_URR_ID, &id)) {
        *bad = PFCP_IE_URR_ID;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    if (sess_find_urr(s, id) != NULL) {
        *bad = PFCP_IE_URR_ID;
        return PFCP_CAUSE_RULE_CREATION_FAILURE;
    }
    if (s->nurr >= 32) {
        *bad = PFCP_IE_CREATE_URR;
        return PFCP_CAUSE_NO_RESOURCES;
    }
    memset(&tmp, 0, sizeof tmp);
    tmp.id = id;
    c = parse_urr_members(grp, &tmp, bad);
    if (c != 0)
        return c;
    tmp.start = tmp.last_report = now;
    r = ADD(s->urr, s->nurr, upf_urr);
    *r = tmp;
    return 0;
}

int rules_update_urr(upf_session *s, const pfcp_ie *grp, uint16_t *bad)
{
    uint32_t id;
    upf_urr *r;
    if (!group_id32(grp, PFCP_IE_URR_ID, &id)) {
        *bad = PFCP_IE_URR_ID;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    r = sess_find_urr(s, id);
    if (r == NULL) {
        *bad = PFCP_IE_URR_ID;
        return PFCP_CAUSE_RULE_CREATION_FAILURE;
    }
    return parse_urr_members(grp, r, bad);
}

/* ---- BAR ---- */

int rules_create_bar(upf_session *s, const pfcp_ie *grp, bool update, uint16_t *bad)
{
    size_t pos = 0;
    pfcp_ie ie;
    int rc;
    uint8_t id = 0;
    bool have = false;
    upf_bar *b, tmp;
    while (pfcp_ie_next(grp->value, grp->len, &pos, &ie) == 1)
        if (ie.typ == PFCP_IE_BAR_ID && pfcp_get_u8(&ie, &id) == 0)
            have = true;
    if (!have) {
        *bad = PFCP_IE_BAR_ID;
        return PFCP_CAUSE_MANDATORY_IE_MISSING;
    }
    b = sess_find_bar(s, id);
    if (b == NULL && update) {
        *bad = PFCP_IE_BAR_ID;
        return PFCP_CAUSE_RULE_CREATION_FAILURE;
    }
    if (b != NULL && !update) {
        *bad = PFCP_IE_BAR_ID;
        return PFCP_CAUSE_RULE_CREATION_FAILURE;
    }
    memset(&tmp, 0, sizeof tmp);
    if (b != NULL)
        tmp = *b;
    tmp.id = id;
    pos = 0;
    while ((rc = pfcp_ie_next(grp->value, grp->len, &pos, &ie)) == 1) {
        if (ie.typ == PFCP_IE_DL_DATA_NOTIFICATION_DELAY && ie.len >= 1)
            tmp.notify_delay_ms = (uint32_t)ie.value[0] * 50u;
        else if (ie.typ == PFCP_IE_DL_BUFFERING_DURATION && ie.len >= 1) {
            /* timer: unit in bits 6-8, value in bits 1-5 (TS 29.244 8.2.35, units of 2 s, 1 min, 10 min, 1 h, 10 h) */
            static const uint32_t unit_ms[8] = {2000u, 60000u, 600000u, 3600000u, 36000000u, 0u, 0u, 0u};
            uint32_t u = unit_ms[ie.value[0] >> 5];
            tmp.buffering_duration_ms = u ? (uint32_t)(ie.value[0] & 0x1f) * u : 0;
        } else if (ie.typ == PFCP_IE_DL_BUFFERING_SUGGESTED_COUNT && ie.len >= 1) {
            uint32_t v = 0;
            for (size_t i = 0; i < ie.len && i < 2; i++)
                v = (v << 8) | ie.value[i];
            tmp.suggested_count = v;
        }
    }
    if (rc < 0) {
        *bad = grp->typ;
        return PFCP_CAUSE_INVALID_LENGTH;
    }
    if (b != NULL) {
        *b = tmp;
    } else {
        if (s->nbar >= 4) {
            *bad = PFCP_IE_CREATE_BAR;
            return PFCP_CAUSE_NO_RESOURCES;
        }
        b = ADD(s->bar, s->nbar, upf_bar);
        *b = tmp;
    }
    return 0;
}

/* Every rule a PDR refers to must exist (checked after a full Create or Update has been applied). */
int rules_validate(upf_session *s, uint16_t *bad)
{
    for (size_t i = 0; i < s->npdr; i++) {
        upf_pdr *p = &s->pdr[i];
        if (p->has_far && sess_find_far(s, p->far_id) == NULL) {
            *bad = PFCP_IE_FAR_ID;
            return PFCP_CAUSE_RULE_CREATION_FAILURE;
        }
        for (size_t k = 0; k < p->nqer; k++)
            if (sess_find_qer(s, p->qer_ids[k]) == NULL) {
                *bad = PFCP_IE_QER_ID;
                return PFCP_CAUSE_RULE_CREATION_FAILURE;
            }
        for (size_t k = 0; k < p->nurr; k++)
            if (sess_find_urr(s, p->urr_ids[k]) == NULL) {
                *bad = PFCP_IE_URR_ID;
                return PFCP_CAUSE_RULE_CREATION_FAILURE;
            }
    }
    for (size_t i = 0; i < s->nfar; i++)
        if (s->far[i].has_bar && sess_find_bar(s, s->far[i].bar_id) == NULL) {
            *bad = PFCP_IE_BAR_ID;
            return PFCP_CAUSE_RULE_CREATION_FAILURE;
        }
    return 0;
}
