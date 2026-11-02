/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Usage reporting rules (TS 29.244 5.2.2): volume and duration counters, thresholds, and Usage Report IEs. */
#include <string.h>

#include "priv.h"

static uint32_t ntp_of(double t)
{
    return (uint32_t)((uint64_t)t + UPF_NTP_UNIX_OFFSET);
}

void urr_account(upf *u, upf_session *s, const upf_pdr *p, bool ul, size_t bytes, double now)
{
    for (size_t i = 0; i < p->nurr; i++) {
        upf_urr *r = sess_find_urr(s, p->urr_ids[i]);
        upf_count since;
        if (r == NULL)
            continue;
        r->total.bytes += bytes;
        r->total.pkts++;
        if (ul) {
            r->ul.bytes += bytes;
            r->ul.pkts++;
        } else {
            r->dl.bytes += bytes;
            r->dl.pkts++;
        }
        if (!r->seen_pkt) {
            r->seen_pkt = true;
            r->first_pkt = now;
        }
        r->last_pkt = now;
        if (r->has_vol_thresh && !r->report_due) {
            since.bytes = r->total.bytes - r->at_last_report.bytes;
            if ((r->vol_thresh.has_total && since.bytes >= r->vol_thresh.total) ||
                (r->vol_thresh.has_ul && r->ul.bytes >= r->vol_thresh.ul) || (r->vol_thresh.has_dl && r->dl.bytes >= r->vol_thresh.dl)) {
                r->report_due = true;
                r->due_trigger = PFCP_URT_VOLTH;
            }
        }
    }
    (void)u;
}

/* One Usage Report group (type 78, 79 or 80) into out; returns its length or 0 when it does not fit */
size_t urr_build_report(const upf *u, upf_urr *r, uint16_t group_type, uint32_t trigger, uint8_t *out, size_t cap, bool reset)
{
    size_t pos = 0, mark;
    pfcp_volume_meas vm = {true, true, true, true, true, true, 0, 0, 0, 0, 0, 0};
    double now = u->now;
    (void)u;
    if (pfcp_group_begin(out, cap, &pos, group_type, &mark) != 0)
        return 0;
    if (pfcp_put_u32(out, cap, &pos, PFCP_IE_URR_ID, r->id) != 0 || pfcp_put_u32(out, cap, &pos, PFCP_IE_UR_SEQN, r->seqn++) != 0 ||
        pfcp_trigger_put(out, cap, &pos, PFCP_IE_USAGE_REPORT_TRIGGER, trigger) != 0 ||
        pfcp_put_u32(out, cap, &pos, PFCP_IE_START_TIME, ntp_of(r->last_report)) != 0 ||
        pfcp_put_u32(out, cap, &pos, PFCP_IE_END_TIME, ntp_of(now)) != 0)
        return 0;
    vm.total = r->total.bytes - r->at_last_report.bytes;
    vm.ul = r->ul.bytes;
    vm.dl = r->dl.bytes;
    vm.total_pkts = r->total.pkts - r->at_last_report.pkts;
    vm.ul_pkts = r->ul.pkts;
    vm.dl_pkts = r->dl.pkts;
    if (pfcp_volume_meas_put(out, cap, &pos, &vm) != 0 ||
        pfcp_put_u32(out, cap, &pos, PFCP_IE_DURATION_MEASUREMENT, (uint32_t)(now - r->last_report < 0 ? 0 : now - r->last_report)) != 0)
        return 0;
    if (r->seen_pkt && (pfcp_put_u32(out, cap, &pos, PFCP_IE_TIME_OF_FIRST_PACKET, ntp_of(r->first_pkt)) != 0 ||
                        pfcp_put_u32(out, cap, &pos, PFCP_IE_TIME_OF_LAST_PACKET, ntp_of(r->last_pkt)) != 0))
        return 0;
    pfcp_group_end(out, &pos, mark);
    if (reset) {
        r->at_last_report = r->total;
        r->ul = (upf_count){0, 0};
        r->dl = (upf_count){0, 0};
        r->total = (upf_count){0, 0};
        r->at_last_report = (upf_count){0, 0};
        r->last_report = now;
        r->seen_pkt = false;
        r->report_due = false;
    }
    return pos;
}

void urr_tick(upf *u, double now)
{
    for (size_t i = 0; i < u->nsessions; i++) {
        upf_session *s = u->sessions[i];
        if (s == NULL)
            continue;
        for (size_t k = 0; k < s->nurr; k++) {
            upf_urr *r = &s->urr[k];
            if (!r->report_due) {
                if (r->has_time_thresh && r->seen_pkt && now - r->last_report >= (double)r->time_thresh) {
                    r->report_due = true;
                    r->due_trigger = PFCP_URT_TIMTH;
                } else if ((r->triggers & PFCP_URT_PERIO) && r->period > 0 && now - r->last_report >= (double)r->period && r->seen_pkt) {
                    r->report_due = true;
                    r->due_trigger = PFCP_URT_PERIO;
                }
            }
            if (r->report_due && s->peer < u->npeers && u->peers[s->peer].established)
                n4_send_session_report(u, s, 2 /* USAR */, NULL, r, r->due_trigger);
        }
    }
}
