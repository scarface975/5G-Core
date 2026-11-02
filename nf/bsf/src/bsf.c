/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _POSIX_C_SOURCE 200809L
/* The BSF: construction, shutdown and the thread that writes the state file. The operations are in bindings.c. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "priv.h"

void bsf_problem(g5c_resp *resp, int status, const char *cause, const char *detail)
{
    g5c_resp_problem_simple(resp, status, cause, detail);
}

bsf *bsf_new(bsf_cfg *cfg, g5c_registry *metrics)
{
    static const char *const ops[4] = {"register", "deregister", "discovery", "update"};
    static const char *const outs[3] = {"ok", "no_match", "rejected"};
    bsf *b = g5c_xcalloc(1, sizeof *b);
    char err[160];
    b->cfg = cfg;
    b->sch = oa_schemas_load(bsf_schema_chunks, bsf_schema_nchunks, bsf_schema_count, err, sizeof err);
    if (b->sch == NULL) {
        G5C_LOGE("g5c_bsf", "the generated schema pool is unusable: %s", err);
        bsf_cfg_free(cfg);
        free(b);
        return NULL;
    }
    if (metrics == NULL) {
        b->metrics = g5c_registry_new();
        b->own_metrics = true;
    } else {
        b->metrics = metrics;
    }
    bsf_bindings_init(b);
    pthread_mutex_init(&b->mu, NULL);
    pthread_mutex_init(&b->qmu, NULL);
    pthread_cond_init(&b->qcv, NULL);
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 3; j++) {
            g5c_label l[] = {{"operation", ops[i]}, {"result", outs[j]}};
            b->c_ops[i][j] = g5c_counter_get(b->metrics, "g5c_bsf_requests_total", "Nbsf_Management requests by operation and result", l, 2);
        }
    b->c_purged = g5c_counter_get(b->metrics, "g5c_bsf_bindings_purged_total", "bindings removed because their PCF registered with a newer recovery time", NULL, 0);
    b->c_replaced = g5c_counter_get(b->metrics, "g5c_bsf_bindings_replaced_total", "bindings replaced by a new registration of the same PCF for the same UE", NULL, 0);
    b->g_bindings = g5c_gauge_get(b->metrics, "g5c_bsf_bindings", "PCF session bindings held", NULL, 0);
    return b;
}

bsf *bsf_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap)
{
    bsf_cfg *c = bsf_cfg_parse(root, err, errcap);
    bsf *b;
    if (c == NULL)
        return NULL;
    b = bsf_new(c, nf->metrics);
    if (b == NULL)
        snprintf(err, errcap, "cannot create the BSF");
    return b;
}

const g5c_json *bsf_nrf_info(const bsf *b)
{
    return b->cfg->info;
}

/* ---- the state writer ---- */

void bsf_kick(bsf *b)
{
    pthread_mutex_lock(&b->qmu);
    b->dirty = true;
    pthread_cond_broadcast(&b->qcv);
    pthread_mutex_unlock(&b->qmu);
}

static void *worker_main(void *arg)
{
    bsf *b = arg;
    pthread_mutex_lock(&b->qmu);
    for (;;) {
        bool save = false;
        struct timespec ts;
        if (b->stop)
            break;
        if (b->dirty) {
            b->dirty = false;
            save = true;
        } else {
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&b->qcv, &b->qmu, &ts);
            continue;
        }
        pthread_mutex_unlock(&b->qmu);
        if (save) {
            struct timespec d = {0, 100 * 1000000L}; /* let a burst of registrations finish: one write for all of them */
            nanosleep(&d, NULL);
            bsf_state_save(b);
        }
        pthread_mutex_lock(&b->qmu);
    }
    pthread_mutex_unlock(&b->qmu);
    return NULL;
}

void bsf_worker_start(bsf *b)
{
    if (b->cfg->state_file == NULL || b->worker_on)
        return;
    b->worker_on = pthread_create(&b->worker, NULL, worker_main, b) == 0;
}

void bsf_worker_stop(bsf *b)
{
    if (!b->worker_on)
        return;
    pthread_mutex_lock(&b->qmu);
    b->stop = true;
    pthread_cond_broadcast(&b->qcv);
    pthread_mutex_unlock(&b->qmu);
    pthread_join(b->worker, NULL);
    b->worker_on = false;
}

int bsf_start(bsf *b, char *err, size_t errcap)
{
    if (bsf_state_load(b, err, errcap) != 0)
        return -1;
    bsf_worker_start(b);
    return 0;
}

g5c_router *bsf_router(bsf *b)
{
    g5c_router *r = g5c_router_new();
    bsf_routes(r, b);
    return r;
}

void bsf_destroy(bsf *b)
{
    if (b == NULL)
        return;
    bsf_worker_stop(b);
    bsf_state_save(b);
    bsf_bindings_free(b);
    oa_schemas_free(b->sch);
    if (b->own_metrics)
        g5c_registry_free(b->metrics);
    bsf_cfg_free(b->cfg);
    pthread_mutex_destroy(&b->mu);
    pthread_mutex_destroy(&b->qmu);
    pthread_cond_destroy(&b->qcv);
    free(b);
}
