/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* bsf [--check] <config.yaml>: run the Binding Support Function (configuration: nf/bsf/src/config.c). */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/bsf.h"

int main(int argc, char **argv)
{
    char err[256] = "";
    g5c_json *cfg, *extra = g5c_json_new_obj();
    g5c_common common;
    g5c_nf *nf;
    bsf *b;
    static const g5c_svc svcs[] = {{BSF_SVC_MANAGEMENT, "v1"}};
    g5c_nrf_reg reg = {"BSF", svcs, 1, NULL};
    int rc;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0;
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: bsf [--check] <config.yaml>\n");
        g5c_json_free(extra);
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 || g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "bsf: %s\n", err);
        g5c_json_free(cfg);
        g5c_json_free(extra);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "bsf: %s\n", err);
        g5c_json_free(cfg);
        g5c_json_free(extra);
        return 1;
    }
    b = bsf_from_config(cfg, nf, err, sizeof err);
    g5c_json_free(cfg);
    if (b == NULL) {
        fprintf(stderr, "bsf: %s\n", err);
        g5c_json_free(extra);
        g5c_nf_free(nf);
        return 1;
    }
    if (bsf_nrf_info(b) != NULL)
        g5c_json_set(extra, "bsfInfo", g5c_json_dup(bsf_nrf_info(b)));
    reg.extra = extra;
    if (check) {
        rc = g5c_nf_check(nf, err, sizeof err);
        if (rc == 0)
            printf("bsf: configuration OK\n");
    } else if (bsf_start(b, err, sizeof err) != 0) {
        rc = -1;
    } else {
        rc = g5c_nf_run(nf, bsf_router(b), &reg, err, sizeof err);
    }
    if (rc != 0)
        fprintf(stderr, "bsf: %s\n", err);
    bsf_destroy(b);
    g5c_json_free(extra);
    g5c_nf_free(nf);
    return rc == 0 ? 0 : 1;
}
