/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: everything a peer sends the NSSF, in process (no client: notifications are counted as dropped). Byte 0 selects the operation,
 * the rest is the input:
 *   0 <param> <nf>   GET network-slice-information with the given JSON in one of the slice-info / home-plmn-id / tai parameters
 *   1 <nf>           PUT nssai-availability/<nf> with the body
 *   2 <nf>           PATCH nssai-availability/<nf> (a JSON Patch)
 *   3                POST a subscription with the body, then PUT an availability that changes what it monitors
 *   4 <which>        PATCH a subscription (the first one that exists) with the body
 *   5 <nf>           DELETE nssai-availability/<nf>
 * The NSSF is the same for the whole run (reset every few thousand inputs), so availability and subscriptions accumulate. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/nssf.h"

static nssf *g_n;
static g5c_router *g_r;
static unsigned g_runs;

static const char YAML[] =
    "nssf:\n"
    "  slices:\n"
    "    - { snssai: { sst: 1 }, nrf: 'http://nrf-a:7777', nsi_id: 'nsi-1', tais: [ { mcc: '001', mnc: '01', tac: '000001' } ] }\n"
    "    - { snssai: { sst: 1, sd: '000001' }, nrf: 'http://nrf-b:7777', restricted_for: [ '310-260' ] }\n"
    "    - { snssai: { sst: 2 }, tac_ranges: [ { mcc: '001', mnc: '01', start: '000001', end: '00000f' } ] }\n"
    "  amf_sets:\n"
    "    - { id: '001-01-01-001', amfs: [ amf-1 ], snssais: [ { sst: 1 } ], return_candidates: true }\n"
    "  mappings:\n"
    "    - { home_plmn: '310-260', serving: { sst: 1 }, home: { sst: 9 } }\n"
    "  subscriptions: { max: 50, notify_retries: 0 }\n";

static const char *const PARAMS[] = {"slice-info-request-for-registration", "slice-info-request-for-pdu-session", "slice-info-request-for-ue-cu",
                                     "slice-info-request-for-pdn-connection", "home-plmn-id", "tai", "supported-features", "nf-type"};
static const char *const NFS[] = {"amf-1", "amf-2", "x", "a.b-c_d"};

static void reset(void)
{
    char err[160];
    g5c_json *root;
    nssf_cfg *c;
    if (g_r != NULL)
        g5c_router_free(g_r);
    nssf_destroy(g_n);
    root = g5c_yaml_parse(YAML, sizeof YAML - 1, err, sizeof err);
    c = nssf_cfg_parse(root, "001", "01", "http://nrf:7777", err, sizeof err);
    g5c_json_free(root);
    g_n = nssf_new(c, NULL, NULL);
    g_r = nssf_router(g_n);
}

static char *pct(const uint8_t *d, size_t n)
{
    char *o = g5c_xmalloc(n * 3 + 1), *p = o;
    for (size_t i = 0; i < n; i++)
        p += sprintf(p, "%%%02X", d[i]);
    *p = '\0';
    return o;
}

static void dispatch(const char *method, const char *path, const char *query, const char *ctype, const uint8_t *body, size_t n)
{
    g5c_req req;
    g5c_resp resp;
    g5c_req_init(&req);
    req.method = g5c_xstrdup(method);
    req.path = g5c_xstrdup(path);
    req.query = query != NULL ? g5c_xstrdup(query) : NULL;
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("nssf.fuzz:80");
    if (ctype != NULL)
        g5c_req_add_header(&req, "content-type", ctype);
    if (n > 0)
        g5c_req_set_body(&req, body, n);
    g5c_resp_init(&resp);
    g5c_router_dispatch(g_r, &req, &resp);
    g5c_resp_free(&resp);
    g5c_req_free(&req);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char path[96];
    if (g_r == NULL || ++g_runs % 3000 == 0) {
        g5c_log_init("error", false);
        reset();
    }
    if (size < 2)
        return 0;
    snprintf(path, sizeof path, "/nnssf-nssaiavailability/v1/nssai-availability/%s", NFS[data[1] % (sizeof NFS / sizeof *NFS)]);
    switch (data[0] % 6) {
    case 0:
        if (size > 2) {
            char *v = pct(data + 3, size - 3 > 600 ? 600 : size - 3), *q;
            q = g5c_xasprintf("nf-type=AMF&nf-id=%s&%s=%s", NFS[data[2] % (sizeof NFS / sizeof *NFS)], PARAMS[data[1] % (sizeof PARAMS / sizeof *PARAMS)], v);
            dispatch("GET", "/nnssf-nsselection/v2/network-slice-information", q, NULL, NULL, 0);
            free(q);
            free(v);
        }
        break;
    case 1:
        dispatch("PUT", path, NULL, "application/json", data + 2, size - 2);
        break;
    case 2:
        dispatch("PATCH", path, NULL, "application/json-patch+json", data + 2, size - 2);
        break;
    case 3:
        dispatch("POST", "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions", NULL, "application/json", data + 2, size - 2);
        break;
    case 4:
        dispatch("PATCH", "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions/x", NULL, "application/json-patch+json", data + 2, size - 2);
        break;
    default:
        dispatch("DELETE", path, NULL, NULL, NULL, 0);
        break;
    }
    return 0;
}
