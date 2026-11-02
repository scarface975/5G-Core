/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* nrf [--check] <config.yaml>: run the NF repository function. */
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/nrf.h"

int main(int argc, char **argv)
{
    char err[256] = {0};
    g5c_json *cfg;
    g5c_common common;
    g5c_nf *nf;
    nrf *n;
    g5c_nf_inst *inst;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0;
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;
    sigset_t set;
    int sig = 0;
    static const g5c_svc svcs[] = {{NRF_SVC_NFM, "v1"}, {NRF_SVC_DISC, "v1"}};
    g5c_nrf_reg reg = {"NRF", svcs, 2, NULL};

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: nrf [--check] <config.yaml>\n");
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 || g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "nrf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    if (common.nrf_uri != NULL) {
        fprintf(stderr, "nrf: the top-level `nrf:` key names the NRF an NF registers with; this is the NRF itself, configure it under `registry:`\n");
        g5c_json_free(cfg);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "nrf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    n = nrf_from_config(cfg, nf, err, sizeof err);
    g5c_json_free(cfg);
    if (n == NULL) {
        fprintf(stderr, "nrf: %s\n", err);
        g5c_nf_free(nf);
        return 1;
    }
    if (check) {
        int rc = g5c_nf_check(nf, err, sizeof err);
        if (rc == 0)
            printf("nrf: configuration OK\n");
        else
            fprintf(stderr, "nrf: %s\n", err);
        nrf_destroy(n);
        g5c_nf_free(nf);
        return rc == 0 ? 0 : 1;
    }
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* the threads started below inherit the block; sigwait takes the signal */
    inst = g5c_nf_start(nf, nrf_router(n), &reg, err, sizeof err);
    if (inst == NULL) {
        fprintf(stderr, "nrf: %s\n", err);
        nrf_destroy(n);
        g5c_nf_free(nf);
        return 1;
    }
    {
        char self[160];
        snprintf(self, sizeof self, "%s://%s:%u", nf->common.has_tls ? "https" : "http", nf->common.address != NULL ? nf->common.address : "127.0.0.1", (unsigned)g5c_nf_inst_port(inst));
        nrf_set_self_uri_default(n, self); /* an explicit registry.self_uri wins */
    }
    if (nrf_start(n, err, sizeof err) != 0) {
        fprintf(stderr, "nrf: %s\n", err);
        g5c_nf_stop(inst);
        nrf_destroy(n);
        g5c_nf_free(nf);
        return 1;
    }
    G5C_LOGI("g5c_nrf", "NRF %s up: Nnrf_NFManagement, Nnrf_NFDiscovery%s", nf->instance_id, "");
    for (;;) {
        char rerr[200];
        sigwait(&set, &sig);
        if (sig == SIGUSR1 || sig == SIGUSR2) {
            g5c_log_set_level(sig == SIGUSR1 ? G5C_LOG_DEBUG : g5c_log_baseline());
            G5C_LOGW("g5c_nrf", "SIG%s: log level is now %s", sig == SIGUSR1 ? "USR1" : "USR2", sig == SIGUSR1 ? "debug" : "the configured one");
            continue;
        }
        if (sig != SIGHUP)
            break;
        if (g5c_nf_inst_reload_tls(inst, rerr, sizeof rerr) == 0)
            G5C_LOGI("g5c_nrf", "SIGHUP: certificates reloaded");
        else
            G5C_LOGE("g5c_nrf", "SIGHUP: certificate reload failed, the old ones stay in use: %s", rerr);
    }
    G5C_LOGI("g5c_nrf", "signal %d received, shutting down", sig);
    g5c_nf_stop(inst);
    nrf_destroy(n);
    g5c_nf_free(nf);
    return 0;
}
