/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* udm <config.yaml>: run the Unified Data Management function. */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/udm.h"

int main(int argc, char **argv)
{
    char err[256];
    g5c_json *cfg;
    g5c_common common;
    g5c_nf *nf;
    udm *u;
    static const g5c_svc svcs[] = {{"nudm-ueau", "v1"}, {"nudm-sdm", "v2"}, {"nudm-uecm", "v1"}, {"nudm-ee", "v1"}};
    g5c_nrf_reg reg = {"UDM", svcs, 4, NULL};
    int rc;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0; /* validate the configuration and exit */
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: udm [--check] <config.yaml>\n");
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 ||
        g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "udm: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "udm: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    u = udm_from_config(cfg, nf, err, sizeof err);
    g5c_json_free(cfg);
    if (u == NULL) {
        fprintf(stderr, "udm: %s\n", err);
        g5c_nf_free(nf);
        return 1;
    }
    if (u->admin_token == NULL)
        G5C_LOGI("g5c_udm", "admin API disabled (no admin token configured)");
    if (check) {
        rc = g5c_nf_check(nf, err, sizeof err); /* also opens the TLS key material */
        if (rc == 0)
            printf("udm: configuration OK\n");
    } else {
        rc = g5c_nf_run(nf, udm_router(u), &reg, err, sizeof err);
    }
    if (rc != 0)
        fprintf(stderr, "udm: %s\n", err);
    udm_destroy(u);
    free(u);
    g5c_nf_free(nf);
    return rc == 0 ? 0 : 1;
}
