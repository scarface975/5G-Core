/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* smf <config.yaml>: run the Session Management Function. */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/smf.h"

int main(int argc, char **argv)
{
    char err[256];
    g5c_json *cfg;
    g5c_common common;
    g5c_nf *nf;
    smf *s;
    static const g5c_svc svcs[] = {{"nsmf-pdusession", "v1"}};
    g5c_nrf_reg reg = {"SMF", svcs, 1, NULL};
    int rc;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0; /* validate the configuration and exit */
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: smf [--check] <config.yaml>\n");
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 || g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "smf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "smf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    s = smf_from_config(cfg, nf, err, sizeof err);
    g5c_json_free(cfg);
    if (s == NULL) {
        fprintf(stderr, "smf: %s\n", err);
        g5c_nf_free(nf);
        return 1;
    }
    if (check) {
        rc = g5c_nf_check(nf, err, sizeof err);
        if (rc == 0)
            printf("smf: configuration OK\n");
    } else if (smf_start(s, err, sizeof err) != 0) {
        rc = -1;
    } else {
        reg.extra = s->nrf_info;
        rc = g5c_nf_run(nf, smf_router(s), &reg, err, sizeof err);
    }
    if (rc != 0)
        fprintf(stderr, "smf: %s\n", err);
    smf_destroy(s);
    free(s);
    g5c_nf_free(nf);
    return rc == 0 ? 0 : 1;
}
