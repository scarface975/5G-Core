/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* pcf <config.yaml>: run the Policy Control Function. */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/pcf.h"

int main(int argc, char **argv)
{
    char err[256];
    g5c_json *cfg;
    g5c_common common;
    g5c_nf *nf;
    pcf *p;
    static const g5c_svc svcs[] = {{"npcf-smpolicycontrol", "v1"}, {"npcf-am-policy-control", "v1"}, {"npcf-policyauthorization", "v1"}};
    g5c_nrf_reg reg = {"PCF", svcs, 3, NULL};
    int rc;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0; /* validate the configuration and exit */
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: pcf [--check] <config.yaml>\n");
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 ||
        g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "pcf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "pcf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    p = pcf_from_config(cfg, nf, err, sizeof err);
    g5c_json_free(cfg);
    if (p == NULL) {
        fprintf(stderr, "pcf: %s\n", err);
        g5c_nf_free(nf);
        return 1;
    }
    if (p->admin_token == NULL)
        G5C_LOGI("g5c_pcf", "admin API disabled (no admin token configured)");
    if (check) {
        rc = g5c_nf_check(nf, err, sizeof err); /* also opens the TLS key material */
        if (rc == 0)
            printf("pcf: configuration OK\n");
    } else {
        rc = g5c_nf_run(nf, pcf_router(p), &reg, err, sizeof err);
    }
    if (rc != 0)
        fprintf(stderr, "pcf: %s\n", err);
    pcf_destroy(p);
    free(p);
    g5c_nf_free(nf);
    return rc == 0 ? 0 : 1;
}
