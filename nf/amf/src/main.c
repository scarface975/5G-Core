/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* amf [--check] <config.yaml>: run the Access and Mobility Management Function. */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/amf.h"

int main(int argc, char **argv)
{
    char err[256] = {0};
    g5c_json *cfg;
    g5c_common common;
    g5c_nf *nf;
    amf *a;
    static const g5c_svc svcs[] = {{"namf-comm", "v1"}, {"namf-evts", "v1"}};
    g5c_nrf_reg reg = {"AMF", svcs, 2, NULL};
    g5c_json *info = NULL;
    int rc;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0;
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: amf [--check] <config.yaml>\n");
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 || g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "amf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "amf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    a = amf_from_config(cfg, nf, err, sizeof err);
    g5c_json_free(cfg);
    if (a == NULL) {
        fprintf(stderr, "amf: %s\n", err);
        g5c_nf_free(nf);
        return 1;
    }
    if (check) {
        rc = g5c_nf_check(nf, err, sizeof err);
        if (rc == 0)
            printf("amf: configuration OK\n");
    } else if (amf_start(a, err, sizeof err) != 0) {
        rc = -1;
    } else {
        info = amf_nrf_info(a);
        reg.extra = info;
        rc = g5c_nf_run(nf, amf_router(a), &reg, err, sizeof err);
    }
    if (rc != 0)
        fprintf(stderr, "amf: %s\n", err);
    g5c_json_free(info);
    amf_destroy(a);
    g5c_nf_free(nf);
    return rc == 0 ? 0 : 1;
}
