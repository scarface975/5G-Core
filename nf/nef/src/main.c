/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* nef [--check] <config.yaml>: run the Network Exposure Function (configuration: nf/nef/src/config.c). */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/nef.h"

int main(int argc, char **argv)
{
    char err[256] = "";
    g5c_json *cfg;
    g5c_common common;
    g5c_nf *nf;
    nef *n;
    g5c_json *extra = g5c_json_new_obj();
    g5c_nrf_reg reg = {"NEF", NULL, 0, extra};
    int rc;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0;
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;

    g5c_json_set(extra, "nefInfo", g5c_json_new_obj());

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: nef [--check] <config.yaml>\n");
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 || g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "nef: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "nef: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    n = nef_from_config(cfg, nf, err, sizeof err);
    g5c_json_free(cfg);
    if (n == NULL) {
        fprintf(stderr, "nef: %s\n", err);
        g5c_nf_free(nf);
        return 1;
    }
    if (check) {
        rc = g5c_nf_check(nf, err, sizeof err);
        if (rc == 0)
            printf("nef: configuration OK\n");
    } else if (nef_start(n, err, sizeof err) != 0) {
        rc = -1;
    } else {
        rc = g5c_nf_run(nf, nef_router(n), &reg, err, sizeof err);
    }
    if (rc != 0)
        fprintf(stderr, "nef: %s\n", err);
    nef_destroy(n);
    g5c_json_free(extra);
    g5c_nf_free(nf);
    return rc == 0 ? 0 : 1;
}
