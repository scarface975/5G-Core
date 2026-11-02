/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The SCP: construction, the router (every request that is not a health or metrics request is forwarded), shutdown. The forwarding is in proxy.c, the choice of the
 * producer in select.c. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

scp *scp_new(scp_cfg *cfg, g5c_client *client, g5c_registry *metrics)
{
    scp *s = g5c_xcalloc(1, sizeof *s);
    static const char *const model[3] = {"C", "D", "notification"}, *const result[6] = {"2xx", "3xx", "4xx", "5xx", "scp_error", "rejected"},
                            *const attempt[3] = {"ok", "retried", "failed"}, *const disc[4] = {"hit", "miss", "failed", "none"};
    s->cfg = cfg;
    s->client = client;
    if (metrics == NULL) {
        s->metrics = g5c_registry_new();
        s->own_metrics = true;
    } else {
        s->metrics = metrics;
    }
    pthread_mutex_init(&s->mu, NULL);
    for (int i = 0; i < 3; i++) {
        g5c_label l[] = {{"model", model[i]}};
        s->c_model[i] = g5c_counter_get(s->metrics, "g5c_scp_requests_total", "requests by communication model (C: apiRoot given, D: delegated discovery, notification)", l, 1);
    }
    for (int i = 0; i < 6; i++) {
        g5c_label l[] = {{"class", result[i]}};
        s->c_result[i] = g5c_counter_get(s->metrics, "g5c_scp_responses_total", "answers by status class (scp_error: made by the SCP)", l, 1);
    }
    for (int i = 0; i < 3; i++) {
        g5c_label l[] = {{"result", attempt[i]}};
        s->c_attempt[i] = g5c_counter_get(s->metrics, "g5c_scp_upstream_attempts_total", "attempts at a producer by outcome", l, 1);
    }
    for (int i = 0; i < 4; i++) {
        g5c_label l[] = {{"result", disc[i]}};
        s->c_disc[i] = g5c_counter_get(s->metrics, "g5c_scp_discoveries_total", "discoveries at the NRF for delegated requests", l, 1);
    }
    s->g_quarantined = g5c_gauge_get(s->metrics, "g5c_scp_quarantined", "producers that are being left alone after failures", NULL, 0);
    s->g_inflight = g5c_gauge_get(s->metrics, "g5c_scp_inflight", "requests being handled", NULL, 0);
    s->h_latency = g5c_histogram_get(s->metrics, "g5c_scp_request_seconds", "time to answer a forwarded request", NULL, 0);
    return s;
}

scp *scp_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap)
{
    scp_cfg *c = scp_cfg_parse(root, nf->common.name, nf->common.nrf_uri, err, errcap);
    scp *s;
    if (c == NULL)
        return NULL;
    s = scp_new(c, nf->client, nf->metrics);
    g5c_client_set_timeout(nf->client, (int)c->timeout_ms);
    return s;
}

g5c_router *scp_router(scp *s)
{
    g5c_router *r = g5c_router_new();
    g5c_router_set_fallback(r, scp_proxy, s);
    return r;
}

unsigned scp_workers(const scp *s)
{
    return s->cfg->workers;
}

void scp_destroy(scp *s)
{
    if (s == NULL)
        return;
    G5C_LOGI(SCP_LOG, "forwarded: model C %llu, model D %llu, notifications %llu; answers 2xx %llu, 3xx %llu, 4xx %llu, 5xx %llu, made by the SCP %llu; attempts retried %llu, failed %llu",
             (unsigned long long)g5c_counter_value(s->c_model[M_C]), (unsigned long long)g5c_counter_value(s->c_model[M_D]), (unsigned long long)g5c_counter_value(s->c_model[M_CB]),
             (unsigned long long)g5c_counter_value(s->c_result[R_2XX]), (unsigned long long)g5c_counter_value(s->c_result[R_3XX]), (unsigned long long)g5c_counter_value(s->c_result[R_4XX]),
             (unsigned long long)g5c_counter_value(s->c_result[R_5XX]), (unsigned long long)g5c_counter_value(s->c_result[R_SCP_ERR]),
             (unsigned long long)g5c_counter_value(s->c_attempt[A_RETRIED]), (unsigned long long)g5c_counter_value(s->c_attempt[A_FAILED]));
    for (size_t i = 0; i < s->ncache; i++) {
        free(s->cache[i].key);
        cands_free(&s->cache[i].c);
    }
    free(s->cache);
    for (size_t i = 0; i < s->nhealth; i++)
        free(s->health[i].authority);
    free(s->health);
    if (s->own_metrics)
        g5c_registry_free(s->metrics);
    scp_cfg_free(s->cfg);
    pthread_mutex_destroy(&s->mu);
    free(s);
}
