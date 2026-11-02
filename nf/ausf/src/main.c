/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* ausf [--check] <config.yaml>: run the authentication server function. */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/ausf.h"

int main(int argc, char **argv)
{
    char err[256] = {0};
    g5c_json *cfg;
    g5c_common common;
    g5c_nf *nf;
    ausf *a;
    int rc;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0; /* validate the configuration and exit */
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;
    static const g5c_svc svcs[] = {{AUSF_SVC_AUTH, "v1"}, {AUSF_SVC_SOR, "v1"}, {AUSF_SVC_UPU, "v1"}};
    g5c_nrf_reg reg = {"AUSF", svcs, 3, NULL};
    g5c_json *extra = NULL;

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: ausf [--check] <config.yaml>\n");
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 || g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "ausf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "ausf: %s\n", err);
        g5c_json_free(cfg);
        return 1;
    }
    a = ausf_from_config(cfg, nf, err, sizeof err);
    g5c_json_free(cfg);
    if (a == NULL) {
        fprintf(stderr, "ausf: %s\n", err);
        g5c_nf_free(nf);
        return 1;
    }
    if (check) {
        rc = g5c_nf_check(nf, err, sizeof err); /* also opens the TLS key material */
        if (rc == 0)
            printf("ausf: configuration OK\n");
        else
            fprintf(stderr, "ausf: %s\n", err);
        ausf_free(a);
        g5c_nf_free(nf);
        return rc == 0 ? 0 : 1;
    }
    if (ausf_start(a, err, sizeof err) != 0) {
        fprintf(stderr, "ausf: %s\n", err);
        ausf_free(a);
        g5c_nf_free(nf);
        return 1;
    }
    if (ausf_nrf_info(a) != NULL) {
        extra = g5c_json_new_obj();
        g5c_json_set(extra, "ausfInfo", g5c_json_dup(ausf_nrf_info(a)));
        reg.extra = extra;
    }
    G5C_LOGI("g5c_ausf", "AUSF %s: Nausf_UEAuthentication (5G AKA, EAP-AKA'), Nausf_SoRProtection, Nausf_UPUProtection", nf->instance_id);
    rc = g5c_nf_run(nf, ausf_router(a), &reg, err, sizeof err);
    if (rc != 0)
        fprintf(stderr, "ausf: %s\n", err);
    g5c_json_free(extra);
    ausf_free(a);
    g5c_nf_free(nf);
    return rc == 0 ? 0 : 1;
}
