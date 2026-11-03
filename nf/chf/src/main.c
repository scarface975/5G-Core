/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* chf [--check] <config.yaml>: run the Charging Function (configuration: nf/chf/src/chf.c). */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/chf.h"

int main(int argc, char **argv)
{
    char err[256] = "";
    g5c_json *cfg, *extra = g5c_json_new_obj();
    g5c_common common;
    g5c_nf *nf;
    chf *c;
    static const g5c_svc svcs[] = {{CHF_SVC_CHARGING, "v3"}};
    g5c_nrf_reg reg = {"CHF", svcs, 1, NULL};
    int rc;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0;
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: chf [--check] <config.yaml>\n");
        g5c_json_free(extra);
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 || g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "chf: %s\n", err);
        g5c_json_free(cfg);
        g5c_json_free(extra);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "chf: %s\n", err);
        g5c_json_free(cfg);
        g5c_json_free(extra);
        return 1;
    }
    c = chf_from_config(cfg, nf, err, sizeof err);
    g5c_json_free(cfg);
    if (c == NULL) {
        fprintf(stderr, "chf: %s\n", err);
        g5c_json_free(extra);
        g5c_nf_free(nf);
        return 1;
    }
    reg.extra = extra;
    if (check) {
        rc = g5c_nf_check(nf, err, sizeof err);
        if (rc == 0)
            printf("chf: configuration OK\n");
    } else {
        rc = g5c_nf_run(nf, chf_router(c), &reg, err, sizeof err);
    }
    if (rc != 0)
        fprintf(stderr, "chf: %s\n", err);
    chf_destroy(c);
    g5c_json_free(extra);
    g5c_nf_free(nf);
    return rc == 0 ? 0 : 1;
}
