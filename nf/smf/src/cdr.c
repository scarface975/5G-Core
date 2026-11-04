/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Charging data records of the SMF (the integration point of Phase 8 WP7: what a charging function, an Nchf client or a billing mediation reads) */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "g5c/smf.h"

static void iso_time(time_t t, char *out, size_t cap)
{
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

/* The usage report of URR `urr_id` (0: the first one with a volume measurement) in the body of a session deletion response or a report request */
int smf_n4_parse_usage_for(const uint8_t *mbody, size_t mblen, uint32_t urr_id, smf_usage *u)
{
    size_t p = 0;
    pfcp_ie ie;
    memset(u, 0, sizeof *u);
    while (pfcp_ie_next(mbody, mblen, &p, &ie) == 1) {
        size_t q = 0;
        pfcp_ie in;
        uint32_t id = 0;
        smf_usage g;
        if (ie.typ != PFCP_IE_USAGE_REPORT_SDR && ie.typ != PFCP_IE_USAGE_REPORT_SMR && ie.typ != PFCP_IE_USAGE_REPORT_SRR)
            continue;
        memset(&g, 0, sizeof g);
        while (pfcp_ie_next(ie.value, ie.len, &q, &in) == 1) {
            if (in.typ == PFCP_IE_URR_ID && in.len == 4) {
                id = ((uint32_t)in.value[0] << 24) | ((uint32_t)in.value[1] << 16) | ((uint32_t)in.value[2] << 8) | in.value[3];
            } else if (in.typ == PFCP_IE_VOLUME_MEASUREMENT && in.len >= 1) {
                uint8_t f = in.value[0];
                size_t o = 1;
                uint64_t v[6] = {0};
                const unsigned bit[6] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20}; /* TOVOL ULVOL DLVOL TONOP ULNOP DLNOP, each followed by an 8 octet value */
                for (int i = 0; i < 6; i++) {
                    if (f & bit[i]) {
                        if (in.len < o + 8)
                            return -1;
                        for (int k = 0; k < 8; k++)
                            v[i] = (v[i] << 8) | in.value[o + (size_t)k];
                        o += 8;
                    }
                }
                g.have = true;
                g.total = v[0];
                g.ul = v[1];
                g.dl = v[2];
                g.total_pkts = v[3];
                g.ul_pkts = v[4];
                g.dl_pkts = v[5];
            } else if (in.typ == PFCP_IE_DURATION_MEASUREMENT && in.len == 4) {
                g.duration = ((uint32_t)in.value[0] << 24) | ((uint32_t)in.value[1] << 16) | ((uint32_t)in.value[2] << 8) | in.value[3];
            }
        }
        if (g.have && (urr_id == 0 || id == urr_id)) {
            *u = g;
            return 0;
        }
    }
    return -1;
}

/* the charging usage report (URR 1) of a session deletion response */
int smf_n4_parse_usage(const smf_n4_msg *m, smf_usage *u)
{
    return smf_n4_parse_usage_for(m->body, m->blen, SMF_URR_SESSION, u);
}

/* the record as one line of JSON text (heap, caller frees) */
char *smf_cdr_format(const smf *s, const smf_sess *ss, const smf_usage *u, const char *cause, time_t end, uint64_t seq)
{
    g5c_json *o = g5c_json_new_obj(), *sn;
    char t0[32], t1[32], ip[16], *txt;
    time_t start = ss->t_est != 0 ? ss->t_est : end;
    iso_time(start, t0, sizeof t0);
    iso_time(end, t1, sizeof t1);
    g5c_json_set_str(o, "recordType", "pduSession");
    g5c_json_set_int(o, "recordSequenceNumber", (int64_t)seq);
    g5c_json_set_str(o, "smfInstanceId", s->instance_id != NULL ? s->instance_id : "");
    g5c_json_set_str(o, "supi", ss->supi);
    g5c_json_set_int(o, "pduSessionId", ss->psi);
    g5c_json_set_str(o, "dnn", ss->dnn);
    sn = g5c_json_set(o, "snssai", g5c_json_new_obj());
    g5c_json_set_int(sn, "sst", ss->sst);
    if (ss->has_sd) {
        char sd[8];
        snprintf(sd, sizeof sd, "%06X", (unsigned)(ss->sd & 0xffffffu));
        g5c_json_set_str(sn, "sd", sd);
    }
    if (ss->has4) {
        snprintf(ip, sizeof ip, "%u.%u.%u.%u", ss->ue4[0], ss->ue4[1], ss->ue4[2], ss->ue4[3]);
        g5c_json_set_str(o, "ueIpv4Address", ip);
    }
    g5c_json_set_str(o, "upf", ss->upf != NULL ? smf_upf_name(ss->upf) : "");
    g5c_json_set_str(o, "startTime", t0);
    g5c_json_set_str(o, "endTime", t1);
    g5c_json_set_int(o, "duration", u->have && u->duration > 0 ? (int64_t)u->duration : (int64_t)(end > start ? end - start : 0));
    g5c_json_set_bool(o, "usageReported", u->have);
    g5c_json_set_int(o, "uplinkOctets", (int64_t)u->ul);
    g5c_json_set_int(o, "downlinkOctets", (int64_t)u->dl);
    g5c_json_set_int(o, "totalOctets", (int64_t)(u->have ? u->total : 0));
    g5c_json_set_int(o, "uplinkPackets", (int64_t)u->ul_pkts);
    g5c_json_set_int(o, "downlinkPackets", (int64_t)u->dl_pkts);
    g5c_json_set_str(o, "closeCause", cause != NULL ? cause : "");
    txt = g5c_json_to_string(o, NULL);
    g5c_json_free(o);
    return txt;
}

void smf_cdr_write(smf *s, const smf_sess *ss, const smf_usage *u, const char *cause)
{
    char *line;
    FILE *f;
    if (s->cdr_path == NULL)
        return;
    pthread_mutex_lock(&s->cdr_mu);
    line = smf_cdr_format(s, ss, u, cause, time(NULL), ++s->cdr_seq);
    f = fopen(s->cdr_path, "a");
    if (f != NULL && line != NULL) {
        (void)fputs(line, f);
        (void)fputc('\n', f);
        if (fclose(f) != 0)
            G5C_LOGE("g5c_smf", "CDR file %s: write failed", s->cdr_path);
        else
            G5C_COUNT(s->metrics, "g5c_smf_cdrs_written_total", "Charging data records written.");
    } else {
        if (f != NULL)
            fclose(f);
        G5C_LOGE("g5c_smf", "CDR file %s cannot be written", s->cdr_path);
        G5C_COUNT(s->metrics, "g5c_smf_cdr_errors_total", "Charging data records that could not be written.");
    }
    pthread_mutex_unlock(&s->cdr_mu);
    if (line != NULL)
        g5c_hook_emit(s->cdr_hook, line);
    free(line);
}
