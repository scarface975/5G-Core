/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The NSSF: construction, routes, shutdown. The procedures are in nsselect.c (Nnssf_NSSelection) and avail.c (Nnssf_NSSAIAvailability). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

#define SEL_PATH "/nnssf-nsselection/v2/network-slice-information"

void nssf_problem(g5c_resp *resp, int status, const char *cause, const char *detail)
{
    g5c_resp_problem_simple(resp, status, cause, detail);
}

nssf *nssf_new(nssf_cfg *cfg, g5c_client *client, g5c_registry *metrics)
{
    nssf *n = g5c_xcalloc(1, sizeof *n);
    char err[160];
    static const char *const proc[4] = {"nsselection", "registration", "pdu_session", "pdn_connection"};
    n->cfg = cfg;
    n->client = client;
    n->sch = oa_schemas_load(nssf_schema_chunks, nssf_schema_nchunks, nssf_schema_count, err, sizeof err);
    if (n->sch == NULL) {
        G5C_LOGE("g5c_nssf", "the generated schema pool is unusable: %s", err);
        nssf_cfg_free(cfg);
        free(n);
        return NULL;
    }
    if (metrics == NULL) {
        n->metrics = g5c_registry_new();
        n->own_metrics = true;
    } else {
        n->metrics = metrics;
    }
    pthread_mutex_init(&n->mu, NULL);
    pthread_mutex_init(&n->qmu, NULL);
    pthread_cond_init(&n->qcv, NULL);
    for (int i = 0; i < 4; i++) {
        g5c_label l[] = {{"procedure", proc[i]}};
        n->c_req[i] = g5c_counter_get(n->metrics, "g5c_nssf_requests_total", "Nnssf_NSSelection requests by procedure", l, 1);
    }
    n->c_reject = g5c_counter_get(n->metrics, "g5c_nssf_rejections_total", "slice selection requests answered with an error", NULL, 0);
    {
        g5c_label ok[] = {{"result", "delivered"}}, fl[] = {{"result", "failed"}}, dr[] = {{"result", "dropped"}};
        n->c_ok = g5c_counter_get(n->metrics, "g5c_nssf_notifications_total", "NSSAI availability notifications by outcome", ok, 1);
        n->c_failed = g5c_counter_get(n->metrics, "g5c_nssf_notifications_total", "NSSAI availability notifications by outcome", fl, 1);
        n->c_dropped = g5c_counter_get(n->metrics, "g5c_nssf_notifications_total", "NSSAI availability notifications by outcome", dr, 1);
    }
    n->g_nfs = g5c_gauge_get(n->metrics, "g5c_nssf_nfs", "NFs that hold NSSAI availability", NULL, 0);
    n->g_subs = g5c_gauge_get(n->metrics, "g5c_nssf_subscriptions", "subscriptions to NSSAI availability changes", NULL, 0);
    return n;
}

nssf *nssf_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap)
{
    nssf_cfg *c = nssf_cfg_parse(root, nf->common.mcc, nf->common.mnc, nf->common.nrf_uri, err, errcap);
    nssf *n;
    if (c == NULL)
        return NULL;
    n = nssf_new(c, nf->client, nf->metrics);
    if (n == NULL)
        snprintf(err, errcap, "cannot create the NSSF");
    return n;
}

int nssf_start(nssf *n, char *err, size_t errcap)
{
    if (nssf_state_load(n, err, errcap) != 0)
        return -1;
    nssf_worker_start(n);
    return 0;
}

g5c_router *nssf_router(nssf *n)
{
    g5c_router *r = g5c_router_new();
    g5c_router_route(r, "GET", SEL_PATH, nssf_nsselection_get, n);
    nssf_avail_routes(r, n);
    return r;
}

void nssf_destroy(nssf *n)
{
    if (n == NULL)
        return;
    nssf_worker_stop(n);
    nssf_state_save(n);
    nssf_avail_free(n);
    oa_schemas_free(n->sch);
    if (n->own_metrics)
        g5c_registry_free(n->metrics);
    nssf_cfg_free(n->cfg);
    pthread_mutex_destroy(&n->mu);
    pthread_mutex_destroy(&n->qmu);
    pthread_cond_destroy(&n->qcv);
    free(n);
}
