/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: everything a consumer sends the SCP, in process. The only target the SCP may reach is 127.0.0.1:9 (nothing listens: connections are refused at
 * once), so every forwarding path ends without leaving the process. Byte 0 selects the operation, the rest is the input:
 *   0   <value> is 3gpp-Sbi-Target-apiRoot
 *   1   <value> is 3gpp-Sbi-Discovery-target-nf-type (service names, requester type and the rest are derived from the following bytes)
 *   2   <value> is 3gpp-Sbi-Callback
 *   3   <value> is Via (loop detection)
 *   4   <value> is 3gpp-Sbi-Sender-Timestamp, Max-Rsp-Time from the byte that follows
 *   5   <value> is the query string of a request with 3gpp-Sbi-Target-apiRoot set
 *   6   <value> is the path, with 3gpp-Sbi-Target-apiRoot set
 *   7   <value> is the body of a POST with 3gpp-Sbi-Target-apiRoot set
 *   8   <value> is the User-Agent of a request with discovery headers
 * The SCP is the same for the whole run (reset every few thousand inputs), so the quarantine and the discovery cache accumulate. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/scp.h"

static scp *g_s;
static g5c_client *g_c;
static g5c_router *g_r;
static unsigned g_runs;

static const char YAML[] =
    "scp:\n"
    "  prefix: '/scp'\n"
    "  routing: { attempts: 2, timeout_ms: 200, quarantine: { failures: 2, seconds: 1 }, max_body: 4096 }\n"
    "  discovery: { cache_ttl_s: 2, cache_max: 16 }\n"
    "  targets: { allow: [ '127.0.0.1:9' ] }\n";

static void reset(void)
{
    char err[160];
    g5c_json *root;
    scp_cfg *c;
    if (g_r != NULL)
        g5c_router_free(g_r);
    scp_destroy(g_s);
    if (g_c != NULL)
        g5c_client_free(g_c);
    root = g5c_yaml_parse(YAML, sizeof YAML - 1, err, sizeof err);
    c = scp_cfg_parse(root, "scp-fuzz", NULL, err, sizeof err);
    g5c_json_free(root);
    g_c = g5c_client_new(200, NULL);
    g_s = scp_new(c, g_c, NULL);
    g_r = scp_router(g_s);
}

/* a header value must not contain control characters (the transport would refuse it before the SCP sees it) */
static char *value(const uint8_t *d, size_t n)
{
    char *o = g5c_xmalloc(n + 1);
    size_t k = 0;
    for (size_t i = 0; i < n && k < 400; i++)
        if (d[i] >= 0x20 && d[i] != 0x7f)
            o[k++] = (char)d[i];
    o[k] = '\0';
    return o;
}

static void dispatch(const char *method, const char *path, const char *query, const char *h1, const char *v1, const char *h2, const char *v2, const char *h3,
                     const char *v3, const uint8_t *body, size_t n)
{
    g5c_req req;
    g5c_resp resp;
    g5c_req_init(&req);
    req.method = g5c_xstrdup(method);
    req.path = g5c_xstrdup(path);
    req.query = query != NULL ? g5c_xstrdup(query) : NULL;
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("scp.fuzz:80");
    if (h1 != NULL)
        g5c_req_add_header(&req, h1, v1);
    if (h2 != NULL)
        g5c_req_add_header(&req, h2, v2);
    if (h3 != NULL)
        g5c_req_add_header(&req, h3, v3);
    if (n > 0) {
        g5c_req_add_header(&req, "content-type", "application/json");
        g5c_req_set_body(&req, body, n);
    }
    g5c_resp_init(&resp);
    g5c_router_dispatch(g_r, &req, &resp);
    g5c_resp_free(&resp);
    g5c_req_free(&req);
}

#define NSSF_PATH "/nnssf-nsselection/v2/network-slice-information"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *v;
    if (g_r == NULL || ++g_runs % 3000 == 0) {
        g5c_log_init("error", false);
        reset();
    }
    if (size < 2)
        return 0;
    v = value(data + 2, size - 2);
    switch (data[0] % 9) {
    case 0:
        dispatch("GET", NSSF_PATH, "nf-type=AMF", "3gpp-Sbi-Target-apiRoot", v, "user-agent", "AMF-1", NULL, NULL, NULL, 0);
        break;
    case 1: {
        char *sn = g5c_xasprintf("nnssf-%s", data[1] & 1 ? "nsselection" : "nssaiavailability");
        dispatch("GET", NSSF_PATH, "nf-type=AMF", "3gpp-Sbi-Discovery-target-nf-type", v, "3gpp-Sbi-Discovery-service-names", sn,
                 data[1] & 2 ? "3gpp-Sbi-Discovery-requester-nf-type" : "user-agent", data[1] & 2 ? "AMF" : "AMF-1", NULL, 0);
        free(sn);
        break;
    }
    case 2:
        dispatch("POST", "/x", NULL, "3gpp-Sbi-Callback", v, "user-agent", "NSSF-1", NULL, NULL, (const uint8_t *)"{}", 2);
        break;
    case 3:
        dispatch("GET", NSSF_PATH, NULL, "via", v, "3gpp-Sbi-Target-apiRoot", "http://127.0.0.1:9", "user-agent", "AMF-1", NULL, 0);
        break;
    case 4: {
        char mx[16];
        snprintf(mx, sizeof mx, "%u", (unsigned)data[1] * 37u);
        dispatch("GET", NSSF_PATH, NULL, "3gpp-Sbi-Sender-Timestamp", v, "3gpp-Sbi-Max-Rsp-Time", mx, "3gpp-Sbi-Target-apiRoot", "http://127.0.0.1:9", NULL, 0);
        break;
    }
    case 5:
        dispatch("GET", NSSF_PATH, v, "3gpp-Sbi-Target-apiRoot", "http://127.0.0.1:9", "user-agent", "AMF-1", NULL, NULL, NULL, 0);
        break;
    case 6: {
        char *p = g5c_xasprintf("/%s", v);
        dispatch("GET", p, NULL, "3gpp-Sbi-Target-apiRoot", "http://127.0.0.1:9", "user-agent", "AMF-1", NULL, NULL, NULL, 0);
        free(p);
        break;
    }
    case 7:
        dispatch("POST", NSSF_PATH, NULL, "3gpp-Sbi-Target-apiRoot", "http://127.0.0.1:9", "user-agent", "AMF-1", NULL, NULL, data + 2, size - 2 > 6000 ? 6000 : size - 2);
        break;
    default:
        dispatch("GET", NSSF_PATH, NULL, "3gpp-Sbi-Discovery-target-nf-type", "NSSF", "user-agent", v, NULL, NULL, NULL, 0);
        break;
    }
    free(v);
    return 0;
}
