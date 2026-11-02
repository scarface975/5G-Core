/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Throughput baseline for generate-auth-data (Phase 1 exit criterion: >= 1,000 vectors/s on one instance), with K/OPc encrypted at rest as in production */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/testkit.h"
#include "g5c/udm.h"
#include "g5c/udr.h"

#define SUBSCRIBERS 200
#define TOTAL 20000
#define WORKERS 64

typedef struct {
    g5c_client *c;
    const char *base;
    int w, ok;
} job_t;

static void *worker(void *a)
{
    job_t *j = a;
    for (int n = 0; n < TOTAL / WORKERS; n++) {
        char url[256], err[100];
        g5c_resp r;
        const char *body = "{\"servingNetworkName\":\"5G:mnc001.mcc001.3gppnetwork.org\"}";
        snprintf(url, sizeof url, "%s/nudm-ueau/v1/imsi-0010100000%05d/security-information/generate-auth-data", j->base,
                 (j->w + n * WORKERS) % SUBSCRIBERS);
        if (g5c_client_request(j->c, "POST", url, NULL, 0, G5C_JSON_TYPE, body, strlen(body), &r, err, sizeof err) == 0) {
            if (r.status == 200)
                j->ok++;
            g5c_resp_free(&r);
        }
    }
    return NULL;
}

int main(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_udr_store *store;
    g5c_router *udr_r, *udm_r;
    g5c_server *udr_s, *udm_s;
    g5c_client *c;
    g5c_registry *m;
    udm u;
    udm_keys keys;
    uint8_t master[32];
    char udr[64], base[64], url[128], body[256], auth[64];
    pthread_t th[WORKERS];
    job_t jobs[WORKERS];
    double t0, secs, rate;
    int ok = 0;
    g5c_kv hdr = {"authorization", auth};

    if (getenv("G5C_PERF") == NULL) {
        puts("perf_udm: G5C_PERF not set, skipping");
        return 0;
    }
    g5c_log_init("error", false);
    store = g5c_udr_store_memory();
    udr_r = g5c_udr_router(store);
    udr_s = g5c_server_start(&cfg, udr_r, NULL, 0);
    snprintf(udr, sizeof udr, "http://127.0.0.1:%u", g5c_server_port(udr_s));
    c = g5c_client_new(30000, NULL);
    m = g5c_registry_new();
    memset(master, 9, 32);
    udm_keys_with_master(&keys, master); /* encrypted at rest, as in production, so the AES-GCM cost is included */
    udm_init(&u, c, udr, &keys, NULL, 0, "00101", "perf", m);
    u.admin_token = g5c_xstrdup("admin-token-0123456789");
    udm_r = udm_router(&u);
    udm_s = g5c_server_start(&cfg, udm_r, NULL, 0);
    snprintf(base, sizeof base, "http://127.0.0.1:%u", g5c_server_port(udm_s));
    snprintf(auth, sizeof auth, "Bearer admin-token-0123456789");

    for (int i = 0; i < SUBSCRIBERS; i++) {
        g5c_resp r;
        char err[100];
        snprintf(url, sizeof url, "%s/admin/v1/subscribers", base);
        snprintf(body, sizeof body, "{\"supi\":\"imsi-0010100000%05d\",\"k\":\"465b5ce8b199b49faa5f0a2ee238a6bc\",\"op\":\"cdc202d5123e20f62b6d676ac72cb318\"}", i);
        TK_ASSERT(g5c_client_request(c, "POST", url, &hdr, 1, G5C_JSON_TYPE, body, strlen(body), &r, err, sizeof err) == 0 && r.status == 201);
        g5c_resp_free(&r);
    }
    t0 = g5c_now_seconds();
    for (int i = 0; i < WORKERS; i++) {
        jobs[i] = (job_t){c, base, i, 0};
        pthread_create(&th[i], NULL, worker, &jobs[i]);
    }
    for (int i = 0; i < WORKERS; i++) {
        pthread_join(th[i], NULL);
        ok += jobs[i].ok;
    }
    secs = g5c_now_seconds() - t0;
    rate = (double)ok / secs;
    printf("generate-auth-data: %d/%d ok in %.2fs = %.0f vectors/s (UDM + udr + load generator on one host, %d workers)\n", ok,
           TOTAL, secs, rate, WORKERS);
    TK_ASSERT(ok == TOTAL / WORKERS * WORKERS);
    TK_ASSERT(rate >= 1000.0);
    g5c_server_stop(udm_s);
    g5c_server_stop(udr_s);
    g5c_client_free(c);
    g5c_router_free(udm_r);
    g5c_router_free(udr_r);
    udm_destroy(&u);
    g5c_udr_store_free(store);
    g5c_registry_free(m);
    return 0;
}
