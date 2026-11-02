/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Opt-in interop check against the Open5GS oracle NRF (see deploy/oracle/README.md) */
#include <stdio.h>
#include <stdlib.h>

#include "g5c/sbi.h"
#include "g5c/testkit.h"

int main(void)
{
    const char *nrf = getenv("G5C_ORACLE_NRF");
    g5c_client *c;
    g5c_resp r;
    char *u, err[200];
    g5c_json *v;
    const g5c_json *nfs;
    if (nrf == NULL || *nrf == 0) {
        puts("sbi oracle interop: G5C_ORACLE_NRF not set; skipping");
        return 0;
    }
    c = g5c_client_new(5000, NULL);
    /* TS 29.510 Nnrf_NFDiscovery: find the UDM that registered with the oracle NRF */
    u = g5c_xasprintf("%s/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF", nrf);
    TK_ASSERT(g5c_client_get(c, u, &r, err, sizeof err) == 0);
    free(u);
    TK_ASSERT(r.status == 200);
    v = g5c_resp_parse_json(&r);
    nfs = g5c_json_get(v, "nfInstances");
    TK_ASSERT(g5c_json_len(nfs) > 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(nfs, 0), "nfType"), "UDM") == 0);
    g5c_json_free(v);
    g5c_resp_free(&r);
    /* an unknown resource must come back as a 3GPP problem+json from the oracle */
    u = g5c_xasprintf("%s/nnrf-nfm/v1/nf-instances/00000000-0000-0000-0000-000000000000", nrf);
    TK_ASSERT(g5c_client_get(c, u, &r, err, sizeof err) == 0);
    free(u);
    TK_ASSERT(r.status == 404);
    g5c_resp_free(&r);
    g5c_client_free(c);
    puts("sbi oracle interop: ok");
    return 0;
}
