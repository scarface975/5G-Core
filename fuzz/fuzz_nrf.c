/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: everything a peer sends the NRF. Byte 0 selects the operation, the rest is the input:
 *   0 PUT   /nnrf-nfm/v1/nf-instances/{id}        NFProfile JSON (registration / replacement)
 *   1 PATCH /nnrf-nfm/v1/nf-instances/{id}        JSON Patch (heart-beat, update) on a registered profile
 *   2 POST  /nnrf-nfm/v1/subscriptions            SubscriptionData JSON
 *   3 GET   /nnrf-disc/v1/nf-instances?<input>    the query string
 *   4 POST  /oauth2/token                         application/x-www-form-urlencoded, with a registered requester
 *   5 PUT, then discovery and retrieval of it (Service-Map conversion in both directions)
 * The same registry is used for the whole run, so state accumulates the way it does in a deployment. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/nrf.h"

static nrf *g_nrf;
static g5c_router *g_router;
static g5c_nf *g_nf;

static void init_once(void)
{
    static const char yaml[] = "name: fuzz\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\n"
                               "registry:\n  heartbeat_timer: 60\n  max_profiles: 64\n  max_subscriptions: 64\n";
    char err[200];
    g5c_json *j;
    g5c_common common;
    if (g_nrf != NULL)
        return;
    j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    if (j == NULL || g5c_common_parse(j, &common, err, sizeof err) != 0)
        abort();
    g_nf = g5c_nf_new(&common, err, sizeof err);
    if (g_nf == NULL)
        abort();
    g_nrf = nrf_from_config(j, g_nf, err, sizeof err);
    g5c_json_free(j);
    if (g_nrf == NULL)
        abort();
    g_router = nrf_router(g_nrf);
}

static void send_req(const char *method, const char *path, const char *query, const char *ctype, const uint8_t *body, size_t n)
{
    g5c_req req;
    g5c_resp resp;
    g5c_req_init(&req);
    req.method = g5c_xstrdup(method);
    req.path = g5c_xstrdup(path);
    req.query = query != NULL ? g5c_xstrdup(query) : NULL;
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("nrf:7777");
    if (ctype != NULL)
        g5c_req_add_header(&req, "content-type", ctype);
    if (n > 0)
        g5c_req_set_body(&req, body, n);
    g5c_resp_init(&resp);
    g5c_router_dispatch(g_router, &req, &resp);
    g5c_resp_free(&resp);
    g5c_req_free(&req);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char ID[] = "/nnrf-nfm/v1/nf-instances/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    static const char seed[] = "{\"nfType\":\"UDM\",\"nfStatus\":\"REGISTERED\",\"ipv4Addresses\":[\"10.0.0.1\"],"
                               "\"nfServices\":[{\"serviceInstanceId\":\"s\",\"serviceName\":\"nudm-sdm\",\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\"}]}";
    char *q;
    if (size < 1)
        return 0;
    init_once();
    switch (data[0] % 6) {
    case 0:
        send_req("PUT", ID, NULL, "application/json", data + 1, size - 1);
        break;
    case 1:
        send_req("PUT", ID, NULL, "application/json", (const uint8_t *)seed, sizeof seed - 1);
        send_req("PATCH", ID, NULL, "application/json-patch+json", data + 1, size - 1);
        break;
    case 2:
        send_req("POST", "/nnrf-nfm/v1/subscriptions", NULL, "application/json", data + 1, size - 1);
        break;
    case 3:
        q = g5c_xstrndup((const char *)data + 1, size - 1);
        for (size_t i = 0; q[i] != 0; i++)
            if (q[i] == '\n' || q[i] == '\r')
                q[i] = '&';
        send_req("GET", "/nnrf-disc/v1/nf-instances", q, NULL, NULL, 0);
        free(q);
        break;
    case 4:
        send_req("PUT", ID, NULL, "application/json", (const uint8_t *)seed, sizeof seed - 1);
        send_req("POST", "/oauth2/token", NULL, "application/x-www-form-urlencoded", data + 1, size - 1);
        break;
    default:
        send_req("PUT", ID, NULL, "application/json", data + 1, size - 1);
        send_req("GET", "/nnrf-disc/v1/nf-instances", "target-nf-type=UDM&requester-nf-type=AMF&supported-features=1", NULL, NULL, 0);
        send_req("GET", "/nnrf-disc/v1/nf-instances", "target-nf-type=UDM&requester-nf-type=AMF", NULL, NULL, 0);
        send_req("GET", ID, "supported-features=1", NULL, NULL, 0);
        break;
    }
    return 0;
}
