#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* scp [--check] <config.yaml>: run the Service Communication Proxy (configuration: nf/scp/src/config.c). */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/scp.h"

int main(int argc, char **argv)
{
    char err[256] = "", workers[16];
    g5c_json *cfg, *extra = g5c_json_new_obj(), *info;
    g5c_common common;
    g5c_nf *nf;
    scp *s;
    g5c_nrf_reg reg = {"SCP", NULL, 0, extra};
    int rc;
    bool check = argc > 2 && strcmp(argv[1], "--check") == 0;
    const char *cfg_path = check ? argv[2] : argc > 1 ? argv[1] : NULL;

    if (cfg_path == NULL) {
        fprintf(stderr, "usage: scp [--check] <config.yaml>\n");
        return 2;
    }
    cfg = g5c_config_load(cfg_path, err, sizeof err);
    if (cfg == NULL || g5c_common_parse(cfg, &common, err, sizeof err) != 0 || g5c_common_validate(&common, err, sizeof err) != 0) {
        fprintf(stderr, "scp: %s\n", err);
        g5c_json_free(cfg);
        g5c_json_free(extra);
        return 1;
    }
    g5c_log_init(common.log_level, common.log_json);
    nf = g5c_nf_new(&common, err, sizeof err);
    if (nf == NULL) {
        fprintf(stderr, "scp: %s\n", err);
        g5c_json_free(cfg);
        g5c_json_free(extra);
        return 1;
    }
    g5c_client_set_scp(nf->client, NULL, NULL); /* the SCP forwards for the others: it does not go through an SCP of its own (a next hop is configured under scp.next) */
    s = scp_from_config(cfg, nf, err, sizeof err);
    g5c_json_free(cfg);
    if (s == NULL) {
        fprintf(stderr, "scp: %s\n", err);
        g5c_json_free(extra);
        g5c_nf_free(nf);
        return 1;
    }
    info = g5c_json_set(extra, "scpInfo", g5c_json_new_obj());
    g5c_json_set_int(g5c_json_set(info, "scpPorts", g5c_json_new_obj()), nf->common.has_tls ? "https" : "http", nf->common.port);
    snprintf(workers, sizeof workers, "%u", scp_workers(s));
    setenv("G5C_SBI_WORKERS", workers, 1);
    if (check) {
        rc = g5c_nf_check(nf, err, sizeof err);
        if (rc == 0)
            printf("scp: configuration OK\n");
    } else {
        rc = g5c_nf_run(nf, scp_router(s), &reg, err, sizeof err);
    }
    if (rc != 0)
        fprintf(stderr, "scp: %s\n", err);
    scp_destroy(s);
    g5c_json_free(extra);
    g5c_nf_free(nf);
    return rc == 0 ? 0 : 1;
}
