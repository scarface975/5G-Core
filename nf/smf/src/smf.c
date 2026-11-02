/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* SMF configuration, construction and teardown. */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

static void free_dnns(smf *s)
{
    for (size_t i = 0; i < s->ndnns; i++) {
        free(s->dnns[i].dnn);
        smf_pool_free(s->dnns[i].pool);
    }
    free(s->dnns);
    s->dnns = NULL;
    s->ndnns = 0;
}

static void free_upf_cfg(smf_n4_cfg *c)
{
    for (size_t i = 0; i < c->nupfs; i++) {
        for (size_t k = 0; k < c->upfs[i].ndnns; k++)
            free(c->upfs[i].dnns[k]);
        free(c->upfs[i].dnns);
    }
    free(c->upfs);
    c->upfs = NULL;
    c->nupfs = 0;
}

void smf_destroy(smf *s)
{
    smf_sess *ss;
    if (s == NULL)
        return;
    smf_persist_flush(s);
    smf_worker_stop(s);
    smf_n4_free(s->n4);
    free_upf_cfg(&s->n4cfg);
    free(s->ix_ref);
    free(s->ix_key);
    ss = s->sessions;
    while (ss != NULL) {
        smf_sess *n = ss->next;
        smf_policy_free(&ss->pol);
        g5c_json_free(ss->decision);
        free(ss->pcf_resource);
        free(ss->pcf_notif);
        free(ss->amf_status_uri);
        free(ss->amf_n1n2_url);
        free(ss->serving_nf_id);
        g5c_json_free(ss->plmn);
        pthread_mutex_destroy(&ss->mu);
        free(ss);
        ss = n;
    }
    free_dnns(s);
    g5c_json_free(s->nrf_info);
    for (int i = 0; i < 4; i++)
        free(s->amf_cache[i].root);
    pthread_mutex_destroy(&s->cmu);
    free(s->nrf);
    free(s->state_file);
    pthread_mutex_destroy(&s->pmu);
    free(s->udm);
    g5c_disc_free(s->disc);
    free(s->pcf);
    free(s->amf);
    free(s->instance_id);
    free(s->self_uri);
    free(s->cdr_path);
    pthread_mutex_destroy(&s->cdr_mu);
    pthread_mutex_destroy(&s->mu);
    pthread_mutex_destroy(&s->qmu);
    pthread_cond_destroy(&s->qcv);
}

void smf_set_self_uri(smf *s, const char *uri)
{
    free(s->self_uri);
    s->self_uri = uri != NULL ? g5c_xstrdup(uri) : NULL;
}

/* ---- N4 hooks ---------------------------------------------------------------------------------------------------------------------------- */

static void on_upf_event(void *user, smf_upf *u, int kind)
{
    smf_upf_event(user, u, kind);
}

static void on_gtpu(void *user, uint32_t teid, const uint8_t *pl, size_t len, const smf_peer *from)
{
    smf_cp_packet(user, teid, pl, len, from);
}

static uint8_t on_session_report(void *user, smf_upf *u, uint64_t cp_seid, const uint8_t *body, size_t len, uint64_t *up_seid)
{
    smf *s = user;
    size_t p = 0;
    pfcp_ie ie;
    uint8_t type = 0;
    while (pfcp_ie_next(body, len, &p, &ie) == 1)
        if (ie.typ == PFCP_IE_REPORT_TYPE && ie.len >= 1)
            type = ie.value[0];
    /* bit 1 of the Report Type is DLDR (downlink data report), bit 2 USAR (usage report: the usage monitoring URR reached its threshold); other reports are acknowledged */
    if ((type & 0x02) != 0) {
        uint8_t c = smf_usage_report(s, u, cp_seid, body, len, up_seid);
        if (c != PFCP_CAUSE_ACCEPTED || (type & 0x01) == 0)
            return c;
    }
    return smf_downlink_data(s, u, cp_seid, (type & 0x01) != 0, up_seid);
}

/* ---- configuration ----------------------------------------------------------------------------------------------------------------------- */

static int parse_addr_list(const g5c_json *arr, uint8_t d4[2][4], size_t *n4, uint8_t d6[2][16], size_t *n6, char *err, size_t cap)
{
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const char *a = g5c_json_str(g5c_json_at(arr, i));
        if (a == NULL) {
            snprintf(err, cap, "dns addresses must be strings");
            return -1;
        }
        if (*n4 < 2 && inet_pton(AF_INET, a, d4[*n4]) == 1) {
            (*n4)++;
        } else if (*n6 < 2 && inet_pton(AF_INET6, a, d6[*n6]) == 1) {
            (*n6)++;
        } else {
            snprintf(err, cap, "dns address `%s` is not an IP address (or there are more than two of its family)", a);
            return -1;
        }
    }
    return 0;
}

static int parse_upfs(const g5c_json *arr, smf_n4_cfg *c, char *err, size_t cap)
{
    static const char *const keys[] = {"name", "address", "port", "dnns", "slices", NULL};
    if (!g5c_json_is(arr, G5C_J_ARRAY) || g5c_json_len(arr) == 0) {
        snprintf(err, cap, "invalid config: `smf.upfs` must list at least one UPF");
        return -1;
    }
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const g5c_json *e = g5c_json_at(arr, i), *dn = g5c_json_get(e, "dnns"), *sl = g5c_json_get(e, "slices");
        smf_upf_cfg *u;
        int64_t port = 8805;
        if (g5c_json_check_keys(e, keys, "smf.upfs[]", err, cap) != 0)
            return -1;
        if (g5c_json_get_str(e, "name") == NULL || g5c_json_get_str(e, "address") == NULL) {
            snprintf(err, cap, "invalid config: every UPF needs `name` and `address`");
            return -1;
        }
        if (g5c_json_get(e, "port") != NULL && (!g5c_json_get_int(e, "port", &port) || port < 1 || port > 65535)) {
            snprintf(err, cap, "invalid config: UPF port must be 1..=65535");
            return -1;
        }
        c->upfs = g5c_xrealloc(c->upfs, (c->nupfs + 1) * sizeof *c->upfs);
        u = &c->upfs[c->nupfs++];
        memset(u, 0, sizeof *u);
        snprintf(u->name, sizeof u->name, "%s", g5c_json_get_str(e, "name"));
        snprintf(u->address, sizeof u->address, "%s", g5c_json_get_str(e, "address"));
        {
            struct in_addr a4;
            if (inet_pton(AF_INET, u->address, &a4) != 1) {
                snprintf(err, cap, "invalid config: UPF `%s` address `%s` is not an IPv4 address", u->name, u->address);
                return -1;
            }
        }
        u->port = (uint16_t)port;
        for (size_t k = 0; k < g5c_json_len(dn); k++) {
            const char *d = g5c_json_str(g5c_json_at(dn, k));
            if (d == NULL) {
                snprintf(err, cap, "invalid config: UPF dnns must be strings");
                return -1;
            }
            u->dnns = g5c_xrealloc(u->dnns, (u->ndnns + 1) * sizeof *u->dnns);
            u->dnns[u->ndnns++] = g5c_xstrdup(d);
        }
        for (size_t k = 0; k < g5c_json_len(sl); k++) {
            const g5c_json *sn = g5c_json_at(sl, k);
            int64_t sst;
            const char *sd = g5c_json_get_str(sn, "sd");
            if (u->nsnssai == 8 || !g5c_json_get_int(sn, "sst", &sst) || sst < 0 || sst > 255) {
                snprintf(err, cap, "invalid config: UPF slices need `sst` 0..=255 (at most 8)");
                return -1;
            }
            u->snssai[u->nsnssai].sst = (uint8_t)sst;
            u->snssai[u->nsnssai].has_sd = sd != NULL;
            if (sd != NULL) {
                char *end;
                unsigned long v = strtoul(sd, &end, 16);
                if (strlen(sd) != 6 || *end != 0) {
                    snprintf(err, cap, "invalid config: slice `sd` must be 6 hex digits");
                    return -1;
                }
                u->snssai[u->nsnssai].sd = (uint32_t)v;
            }
            u->nsnssai++;
        }
    }
    return 0;
}

static bool http_uri(const char *u)
{
    return u != NULL && (strncmp(u, "http://", 7) == 0 || strncmp(u, "https://", 8) == 0) && strlen(u) > 9;
}

static char *peer_uri(const g5c_json *cfg, const char *name, bool required, char *err, size_t cap)
{
    const g5c_json *o = g5c_json_get(cfg, name);
    const char *u = g5c_json_get_str(o, "uri");
    if (o == NULL && !required)
        return NULL;
    if (!http_uri(u)) {
        snprintf(err, cap, "invalid config: `smf.%s.uri` must be an http(s) URI", name);
        return NULL;
    }
    {
        char *r = g5c_xstrdup(u);
        size_t n = strlen(r);
        while (n > 0 && r[n - 1] == '/')
            r[--n] = 0;
        return r;
    }
}

smf *smf_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t cap)
{
    static const char *const k_smf[] = {"self_uri", "udm", "pcf", "amf", "mtu", "n1n2_delay_ms", "release_guard_ms", "workers", "state_file", "slices", "n4", "upfs",
                                        "dnns", "cdr", "inject", NULL};
    static const char *const k_n4[] = {"address", "port", "t1_ms", "n1", "heartbeat", "lost_after", NULL};
    static const char *const k_hb[] = {"interval", "failures", NULL};
    static const char *const k_dnn[] = {"name", "ipv4_pool", "ipv6_pool", "dns", NULL};
    const g5c_json *c = g5c_json_get(root, "smf"), *n4 = g5c_json_get(c, "n4"), *dn = g5c_json_get(c, "dnns"), *hb;
    smf *s = NULL;
    smf_n4_cfg n4c;
    int64_t v;

    memset(&n4c, 0, sizeof n4c);
    if (!g5c_json_is(c, G5C_J_OBJECT)) {
        snprintf(err, cap, "invalid config: the `smf` section is required");
        return NULL;
    }
    if (g5c_json_check_keys(c, k_smf, "smf", err, cap) != 0)
        return NULL;
    if (!g5c_json_is(n4, G5C_J_OBJECT) || g5c_json_check_keys(n4, k_n4, "smf.n4", err, cap) != 0) {
        if (err[0] == 0)
            snprintf(err, cap, "invalid config: `smf.n4` is required");
        return NULL;
    }
    s = g5c_xcalloc(1, sizeof *s);
    pthread_mutex_init(&s->mu, NULL);
    pthread_mutex_init(&s->qmu, NULL);
    pthread_cond_init(&s->qcv, NULL);
    pthread_mutex_init(&s->pmu, NULL);
    s->release_guard_ms = 10000;
    pthread_mutex_init(&s->cdr_mu, NULL);
    pthread_mutex_init(&s->cmu, NULL);
    if (nf->common.nrf_uri != NULL) {
        size_t nl;
        s->nrf = g5c_xstrdup(nf->common.nrf_uri);
        nl = strlen(s->nrf);
        while (nl > 0 && s->nrf[nl - 1] == '/')
            s->nrf[--nl] = 0;
    }
    s->client = nf->client;
    s->metrics = nf->metrics;
    s->instance_id = g5c_xstrdup(nf->instance_id);
    s->mtu = 1400;
    s->n1n2_delay_ms = 10;
    s->want_workers = 4;
    err[0] = 0;
    /* the UDM and PCF addresses may be left out when an NRF is configured: they are then discovered */
    s->udm = peer_uri(c, "udm", s->nrf == NULL, err, cap);
    if (err[0] != 0)
        goto fail;
    s->pcf = peer_uri(c, "pcf", s->nrf == NULL, err, cap);
    if (err[0] != 0)
        goto fail;
    if (s->nrf != NULL && (s->udm == NULL || s->pcf == NULL))
        s->disc = g5c_disc_new(nf->client, s->nrf, "SMF", nf->instance_id);
    s->amf = peer_uri(c, "amf", false, err, cap);
    if (err[0] != 0)
        goto fail;
    if (g5c_json_get_str(c, "self_uri") != NULL) {
        if (!http_uri(g5c_json_get_str(c, "self_uri"))) {
            snprintf(err, cap, "invalid config: `smf.self_uri` must be an http(s) URI");
            goto fail;
        }
        s->self_uri = g5c_xstrdup(g5c_json_get_str(c, "self_uri"));
    }
    if (g5c_json_get(c, "mtu") != NULL) {
        if (!g5c_json_get_int(c, "mtu", &v) || v < 576 || v > 9000) {
            snprintf(err, cap, "invalid config: `smf.mtu` must be 576..=9000");
            goto fail;
        }
        s->mtu = (uint16_t)v;
    }
    if (g5c_json_get(c, "inject") != NULL) { /* failure injection, for testing a RAN against a core that misbehaves: `inject: { pdu_session_reject: [{ supi: imsi-0010199, status: 403 }], n4_drop_responses_percent: 30 }` */
        static const char *const k_inj[] = {"pdu_session_reject", "n4_drop_responses_percent", NULL}, *const k_rej[] = {"supi", "status", NULL};
        const g5c_json *inj = g5c_json_get(c, "inject"), *rl = g5c_json_get(inj, "pdu_session_reject");
        int64_t pct = 0;
        if (!g5c_json_is(inj, G5C_J_OBJECT) || g5c_json_check_keys(inj, k_inj, "smf.inject", err, cap) != 0) {
            if (err[0] == 0)
                snprintf(err, cap, "invalid config: `smf.inject` must be a mapping");
            goto fail;
        }
        for (size_t i = 0; rl != NULL && i < g5c_json_len(rl); i++) {
            const g5c_json *e = g5c_json_at(rl, i);
            int64_t st = 0;
            if (i >= 8 || !g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, k_rej, "smf.inject.pdu_session_reject", err, cap) != 0 || g5c_json_get_str(e, "supi") == NULL ||
                strlen(g5c_json_get_str(e, "supi")) >= sizeof s->inject_reject[0].supi || !g5c_json_get_int(e, "status", &st) || st < 400 || st > 599) {
                if (err[0] == 0)
                    snprintf(err, cap, "invalid config: `smf.inject.pdu_session_reject` takes up to 8 entries { supi: <prefix>, status: 400..599 }");
                goto fail;
            }
            snprintf(s->inject_reject[s->ninject_reject].supi, sizeof s->inject_reject[0].supi, "%s", g5c_json_get_str(e, "supi"));
            s->inject_reject[s->ninject_reject++].status = (int)st;
        }
        if (g5c_json_get(inj, "n4_drop_responses_percent") != NULL && (!g5c_json_get_int(inj, "n4_drop_responses_percent", &pct) || pct < 0 || pct > 100)) {
            snprintf(err, cap, "invalid config: `smf.inject.n4_drop_responses_percent` must be 0..=100");
            goto fail;
        }
        s->inject_drop_pct = (unsigned)pct;
        G5C_LOGW("g5c_smf", "FAILURE INJECTION is configured (smf.inject): this function misbehaves on purpose");
    }
    if (g5c_json_get(c, "cdr") != NULL) { /* charging data records: `cdr: { file: <path> }` */
        static const char *const k_cdr[] = {"file", NULL};
        const g5c_json *cd = g5c_json_get(c, "cdr");
        const char *path;
        if (!g5c_json_is(cd, G5C_J_OBJECT) || g5c_json_check_keys(cd, k_cdr, "smf.cdr", err, cap) != 0) {
            if (err[0] == 0)
                snprintf(err, cap, "invalid config: `smf.cdr` must be a mapping");
            goto fail;
        }
        path = g5c_json_get_str(cd, "file");
        if (path == NULL || path[0] == 0) {
            snprintf(err, cap, "invalid config: `smf.cdr.file` is required");
            goto fail;
        }
        s->cdr_path = g5c_xstrdup(path);
    }
    if (g5c_json_get(c, "release_guard_ms") != NULL) {
        if (!g5c_json_get_int(c, "release_guard_ms", &v) || v < 100 || v > 600000) {
            snprintf(err, cap, "invalid config: `smf.release_guard_ms` must be 100..=600000");
            goto fail;
        }
        s->release_guard_ms = (unsigned)v;
    }
    if (g5c_json_get(c, "state_file") != NULL) {
        const char *sf = g5c_json_get_str(c, "state_file");
        if (sf == NULL || *sf == 0 || strlen(sf) > 4000) {
            snprintf(err, cap, "invalid config: `smf.state_file` must be a path");
            goto fail;
        }
        s->state_file = g5c_xstrdup(sf);
    }
    if (g5c_json_get(c, "workers") != NULL) {
        if (!g5c_json_get_int(c, "workers", &v) || v < 1 || v > SMF_MAX_WORKERS) {
            snprintf(err, cap, "invalid config: `smf.workers` must be 1..=%d", SMF_MAX_WORKERS);
            goto fail;
        }
        s->want_workers = (unsigned)v;
    }
    if (g5c_json_get(c, "n1n2_delay_ms") != NULL) {
        if (!g5c_json_get_int(c, "n1n2_delay_ms", &v) || v < 0 || v > 5000) {
            snprintf(err, cap, "invalid config: `smf.n1n2_delay_ms` must be 0..=5000");
            goto fail;
        }
        s->n1n2_delay_ms = (unsigned)v;
    }

    /* DNNs */
    if (!g5c_json_is(dn, G5C_J_ARRAY) || g5c_json_len(dn) == 0) {
        snprintf(err, cap, "invalid config: `smf.dnns` must list at least one DNN");
        goto fail;
    }
    for (size_t i = 0; i < g5c_json_len(dn); i++) {
        const g5c_json *e = g5c_json_at(dn, i);
        smf_dnn_cfg *d;
        if (g5c_json_check_keys(e, k_dnn, "smf.dnns[]", err, cap) != 0)
            goto fail;
        if (g5c_json_get_str(e, "name") == NULL || *g5c_json_get_str(e, "name") == 0) {
            snprintf(err, cap, "invalid config: every DNN needs a `name`");
            goto fail;
        }
        s->dnns = g5c_xrealloc(s->dnns, (s->ndnns + 1) * sizeof *s->dnns);
        d = &s->dnns[s->ndnns++];
        memset(d, 0, sizeof *d);
        d->dnn = g5c_xstrdup(g5c_json_get_str(e, "name"));
        d->pool = smf_pool_new(g5c_json_get_str(e, "ipv4_pool"), g5c_json_get_str(e, "ipv6_pool"), err, cap);
        if (d->pool == NULL)
            goto fail;
        if (parse_addr_list(g5c_json_get(e, "dns"), d->dns4, &d->ndns4, d->dns6, &d->ndns6, err, cap) != 0)
            goto fail;
    }

    /* what this SMF tells the NRF it serves: every configured DNN on every listed slice (default: SST 1) */
    {
        const g5c_json *sl = g5c_json_get(c, "slices");
        g5c_json *info = g5c_json_new_obj(), *list;
        size_t n = sl != NULL ? g5c_json_len(sl) : 1;
        if (sl != NULL && (!g5c_json_is(sl, G5C_J_ARRAY) || n == 0 || n > 8)) {
            snprintf(err, cap, "invalid config: `smf.slices` must list 1 to 8 slices");
            g5c_json_free(info);
            goto fail;
        }
        list = g5c_json_set(g5c_json_set(info, "smfInfo", g5c_json_new_obj()), "sNssaiSmfInfoList", g5c_json_new_arr());
        for (size_t i = 0; i < n; i++) {
            g5c_json *e = g5c_json_push(list, g5c_json_new_obj()), *sn = g5c_json_set(e, "sNssai", g5c_json_new_obj()),
                     *dl = g5c_json_set(e, "dnnSmfInfoList", g5c_json_new_arr());
            int64_t sst = 1;
            const char *sd = NULL;
            if (sl != NULL) {
                const g5c_json *it = g5c_json_at(sl, i);
                sd = g5c_json_get_str(it, "sd");
                if (!g5c_json_get_int(it, "sst", &sst) || sst < 0 || sst > 255 || (sd != NULL && strlen(sd) != 6)) {
                    snprintf(err, cap, "invalid config: `smf.slices` entries need `sst` 0..=255 and, optionally, a 6 hex digit `sd`");
                    g5c_json_free(info);
                    goto fail;
                }
            }
            g5c_json_set_int(sn, "sst", sst);
            if (sd != NULL)
                g5c_json_set_str(sn, "sd", sd);
            for (size_t d = 0; d < s->ndnns; d++)
                g5c_json_set_str(g5c_json_push(dl, g5c_json_new_obj()), "dnn", s->dnns[d].dnn);
        }
        s->nrf_info = info;
    }

    /* N4 */
    {
        const char *a = g5c_json_get_str(n4, "address");
        int64_t port = 8805;
        if (a == NULL) {
            snprintf(err, cap, "invalid config: `smf.n4.address` is required");
            goto fail;
        }
        {
            struct in_addr a4;
            if (inet_pton(AF_INET, a, &a4) != 1 || a4.s_addr == 0) {
                snprintf(err, cap, "invalid config: `smf.n4.address` must be a specific IPv4 address (it is advertised to the UPFs)");
                goto fail;
            }
        }
        snprintf(n4c.address, sizeof n4c.address, "%s", a);
        if (g5c_json_get(n4, "port") != NULL && (!g5c_json_get_int(n4, "port", &port) || port < 0 || port > 65535)) {
            snprintf(err, cap, "invalid config: `smf.n4.port` must be 0..=65535");
            goto fail;
        }
        n4c.port = (uint16_t)port;
        n4c.t1_ms = 1000;
        n4c.n1 = 3;
        n4c.hb_interval_s = 5;
        n4c.hb_failures = 3;
        n4c.lost_after_s = 30;
        n4c.inject_drop_pct = s->inject_drop_pct;
        if (g5c_json_get(n4, "lost_after") != NULL) {
            if (!g5c_json_get_int(n4, "lost_after", &v) || v < 0 || v > 86400) {
                snprintf(err, cap, "invalid config: `smf.n4.lost_after` must be 0..=86400 seconds (0 disables)");
                goto fail;
            }
            n4c.lost_after_s = (unsigned)v;
        }
        if (g5c_json_get(n4, "t1_ms") != NULL) {
            if (!g5c_json_get_int(n4, "t1_ms", &v) || v < 10 || v > 60000) {
                snprintf(err, cap, "invalid config: `smf.n4.t1_ms` must be 10..=60000");
                goto fail;
            }
            n4c.t1_ms = (unsigned)v;
        }
        if (g5c_json_get(n4, "n1") != NULL) {
            if (!g5c_json_get_int(n4, "n1", &v) || v < 1 || v > 10) {
                snprintf(err, cap, "invalid config: `smf.n4.n1` must be 1..=10");
                goto fail;
            }
            n4c.n1 = (unsigned)v;
        }
        hb = g5c_json_get(n4, "heartbeat");
        if (hb != NULL) {
            if (g5c_json_check_keys(hb, k_hb, "smf.n4.heartbeat", err, cap) != 0)
                goto fail;
            if (g5c_json_get(hb, "interval") != NULL) {
                if (!g5c_json_get_int(hb, "interval", &v) || v < 0 || v > 3600) {
                    snprintf(err, cap, "invalid config: heartbeat interval must be 0..=3600 seconds (0 disables)");
                    goto fail;
                }
                n4c.hb_interval_s = (unsigned)v;
            }
            if (g5c_json_get(hb, "failures") != NULL) {
                if (!g5c_json_get_int(hb, "failures", &v) || v < 1 || v > 20) {
                    snprintf(err, cap, "invalid config: heartbeat failures must be 1..=20");
                    goto fail;
                }
                n4c.hb_failures = (unsigned)v;
            }
        }
    }
    if (parse_upfs(g5c_json_get(c, "upfs"), &n4c, err, cap) != 0)
        goto fail;
    s->n4cfg = n4c;
    return s;
fail:
    free_upf_cfg(&n4c);
    smf_destroy(s);
    free(s);
    return NULL;
}

int smf_start(smf *s, char *err, size_t cap)
{
    smf_n4_hooks hooks;
    hooks.user = s;
    hooks.on_upf_event = on_upf_event;
    hooks.on_gtpu = on_gtpu;
    for (size_t i = 0; i < s->ndnns; i++)
        if (smf_pool_has6(s->dnns[i].pool))
            s->n4cfg.gtpu_port = 2152; /* IPv6 sessions need to answer router solicitations */
    hooks.on_session_report = on_session_report;
    s->n4 = smf_n4_new(&s->n4cfg, &hooks, s->metrics, err, cap);
    if (s->n4 == NULL)
        return -1;
    smf_worker_start(s);
    if (s->state_file != NULL) { /* sessions of the previous run come back before the first association, so a restarted UPF is noticed */
        g5c_json *doc = smf_state_read(s);
        if (doc != NULL) {
            size_t n;
            smf_state_apply_recovery(s, doc);
            n = smf_state_apply_sessions(s, doc);
            G5C_LOGI("g5c_smf", "restored %zu PDU session(s) from %s", n, s->state_file);
            g5c_json_free(doc);
        }
    }
    if (smf_n4_start(s->n4, err, cap) != 0)
        return -1;
    return 0;
}

g5c_router *smf_router(smf *s)
{
    g5c_router *r = g5c_router_new();
    smf_sm_routes(r, s);
    return r;
}
