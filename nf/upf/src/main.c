/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* upf [--check] <config.yaml>: run the User Plane Function. */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/nfcore.h"
#include "g5c/upf_rt.h"

static upf_rt *G_RT;
static g5c_nf_inst *G_INST; /* under G_MU */
static pthread_mutex_t G_MU = PTHREAD_MUTEX_INITIALIZER;

/* SIGHUP: certificates are read again (the UPF's SBI is health and metrics only, but it is a TLS listener like every other) */
static void *hup_main(void *arg)
{
    sigset_t set;
    int sig;
    (void)arg;
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGUSR2);
    for (;;) {
        char rerr[200];
        if (sigwait(&set, &sig) != 0)
            return NULL;
        if (sig == SIGUSR1 || sig == SIGUSR2) {
            g5c_log_set_level(sig == SIGUSR1 ? G5C_LOG_DEBUG : g5c_log_baseline());
            G5C_LOGW("g5c_upf", "SIG%s: log level is now %s", sig == SIGUSR1 ? "USR1" : "USR2", sig == SIGUSR1 ? "debug" : "the configured one");
            continue;
        }
        pthread_mutex_lock(&G_MU);
        if (G_INST != NULL) {
            if (g5c_nf_inst_reload_tls(G_INST, rerr, sizeof rerr) == 0)
                G5C_LOGI("g5c_upf", "SIGHUP: certificates reloaded");
            else
                G5C_LOGE("g5c_upf", "SIGHUP: certificate reload failed, the old ones stay in use: %s", rerr);
        }
        pthread_mutex_unlock(&G_MU);
    }
}

static void on_signal(int sig)
{
    (void)sig;
    if (G_RT)
        upf_rt_stop(G_RT);
}

int main(int argc, char **argv)
{
    char err[256];
    g5c_json *cfg;
    g5c_common common;
    g5c_nf *nf;
    g5c_nf_inst *inst;
    upf_rt_config rc;
    upf_rt *rt;
    static const g5c_nrf_reg reg = {"UPF", NULL, 0, NULL};
    sigset_t hs;

    sigemptyset(&hs);
    sigaddset(&hs, SIGHUP);
    sigaddset(&hs, SIGUSR1);
    sigaddset(&hs, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &hs, NULL); /* before any thread exists: every thread inherits it and hup_main takes the signal */

    int rcode = 0;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0;
    const char *path = check ? argv[2] : argc > 1 ? argv[1] : NULL;

    if (path == NULL) {
        fprintf(stderr, "usage: upf [--check] <config.yaml>\n");
        return 2;
    }
    cfg = g5c_config_load(path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 || g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "upf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    if (upf_rt_config_parse(g5c_json_get(cfg, "upf"), &rc, err, sizeof err) != 0) {
        fprintf(stderr, "upf: %s\n", err);
        g5c_json_free(cfg);
        g5c_common_free(&common);
        return 1;
    }
    g5c_json_free(cfg);
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "upf: %s\n", err);
        return 1;
    }
    if (check) {
        rcode = g5c_nf_check(nf, err, sizeof err);
        if (rcode == 0)
            printf("upf: configuration OK\n");
        else
            fprintf(stderr, "upf: %s\n", err);
        g5c_nf_free(nf);
        return rcode == 0 ? 0 : 1;
    }
    rt = upf_rt_new(&rc, nf->metrics, err, sizeof err);
    if (rt == NULL) {
        fprintf(stderr, "upf: %s\n", err);
        g5c_nf_free(nf);
        return 1;
    }
    inst = g5c_nf_start(nf, g5c_router_new(), &reg, err, sizeof err); /* health and metrics only */
    if (inst == NULL) {
        fprintf(stderr, "upf: %s\n", err);
        upf_rt_free(rt);
        g5c_nf_free(nf);
        return 1;
    }
    G_RT = rt;
    pthread_mutex_lock(&G_MU);
    G_INST = inst;
    pthread_mutex_unlock(&G_MU);
    {
        pthread_t th;
        if (pthread_create(&th, NULL, hup_main, NULL) == 0)
            pthread_detach(th);
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    G5C_LOGI("g5c_upf", "UPF up: N4 %u.%u.%u.%u:%u, N3 %u.%u.%u.%u:%u, N6 %s", rc.engine.n4_addr.b[0], rc.engine.n4_addr.b[1], rc.engine.n4_addr.b[2],
             rc.engine.n4_addr.b[3], upf_rt_pfcp_port(rt), rc.engine.n3_addr.b[0], rc.engine.n3_addr.b[1], rc.engine.n3_addr.b[2], rc.engine.n3_addr.b[3],
             upf_rt_gtpu_port(rt), rc.n6_fd >= 0 ? "(descriptor)" : rc.tun_dev);
    rcode = upf_rt_run(rt);
    G_RT = NULL;
    pthread_mutex_lock(&G_MU);
    G_INST = NULL;
    pthread_mutex_unlock(&G_MU);
    g5c_nf_stop(inst);
    upf_rt_free(rt);
    g5c_nf_free(nf);
    return rcode == 0 ? 0 : 1;
}
