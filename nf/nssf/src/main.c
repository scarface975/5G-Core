/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* nssf [--check] <config.yaml>: run the Network Slice Selection Function (configuration: nf/nssf/src/config.c). */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/nssf.h"

int main(int argc, char **argv)
{
    char err[256] = "";
    g5c_json *cfg;
    g5c_common common;
    g5c_nf *nf;
    nssf *n;
    static const g5c_svc svcs[] = {{NSSF_SVC_NSSELECTION, "v2"}, {NSSF_SVC_NSSAIAVAILABILITY, "v1"}};
    g5c_nrf_reg reg = {"NSSF", svcs, 2, NULL};
    int rc;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0;
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: nssf [--check] <config.yaml>\n");
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 || g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "nssf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "nssf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    n = nssf_from_config(cfg, nf, err, sizeof err);
    g5c_json_free(cfg);
    if (n == NULL) {
        fprintf(stderr, "nssf: %s\n", err);
        g5c_nf_free(nf);
        return 1;
    }
    if (check) {
        rc = g5c_nf_check(nf, err, sizeof err);
        if (rc == 0)
            printf("nssf: configuration OK\n");
    } else if (nssf_start(n, err, sizeof err) != 0) {
        rc = -1;
    } else {
        rc = g5c_nf_run(nf, nssf_router(n), &reg, err, sizeof err);
    }
    if (rc != 0)
        fprintf(stderr, "nssf: %s\n", err);
    nssf_destroy(n);
    g5c_nf_free(nf);
    return rc == 0 ? 0 : 1;
}
