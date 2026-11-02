/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* udr [--check] <config.yaml>: run the Unified Data Repository (configuration: nf/udr/src/config.c). */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/nfcore.h"
#include "g5c/udr.h"

int main(int argc, char **argv)
{
    char err[256] = "";
    g5c_json *cfg, *extra;
    g5c_common common;
    udr_config uc;
    g5c_nf *nf;
    g5c_udr *svc;
    static const g5c_svc svcs[] = {{"nudr-dr", "v1"}, {"nudr-dr", "v2"}, {"nudr-group-id-map", "v1"}};
    g5c_nrf_reg reg = {"UDR", svcs, 3, NULL};
    int rc;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0; /* validate the configuration and exit */
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: udr [--check] <config.yaml>\n");
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 ||
        g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "udr: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    if (udr_config_parse(cfg, &uc, err, sizeof err) != 0) {
        fprintf(stderr, "udr: %s\n", err);
        g5c_json_free(cfg);
        g5c_common_free(&common);
        return 1;
    }
    g5c_json_free(cfg);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "udr: %s\n", err);
        udr_config_free(&uc);
        return 1;
    }
    uc.opts.metrics = nf->metrics;
    uc.opts.client = nf->client;
    if (uc.opts.provisioning_token == NULL)
        G5C_LOGI("g5c_udr", "provisioning extension disabled (no token configured)");
    svc = udr_new(uc.store, &uc.opts);
    if (svc == NULL) {
        fprintf(stderr, "udr: cannot create the service\n");
        g5c_nf_free(nf);
        udr_config_free(&uc);
        return 1;
    }
    extra = g5c_json_new_obj();
    g5c_json_set(extra, "udrInfo", g5c_json_dup(uc.nrf_info));
    reg.extra = extra;
    if (check) {
        rc = g5c_nf_check(nf, err, sizeof err); /* also opens the TLS key material */
        if (rc == 0)
            printf("udr: configuration OK\n");
    } else {
        rc = g5c_nf_run(nf, udr_router(svc), &reg, err, sizeof err);
    }
    if (rc != 0)
        fprintf(stderr, "udr: %s\n", err);
    g5c_json_free(extra);
    udr_free(svc);
    g5c_nf_free(nf);
    udr_config_free(&uc);
    return rc == 0 ? 0 : 1;
}
