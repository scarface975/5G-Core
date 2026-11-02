/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: everything a consumer sends the BSF, in process. Byte 0 selects the operation, byte 1 a selector, the rest is the input:
 *   0           POST /pcfBindings with the input as the body
 *   1           POST with a registration whose UE address (the selector picks which kind) is the input
 *   2           GET /pcfBindings with the input as the value of the query parameter the selector picks
 *   3           PATCH of the binding the selector picks (one the BSF holds) with the input as the patch document
 *   4           DELETE of the binding the selector picks
 *   5           GET with the input as the whole query string
 * The BSF is the same for the whole run (reset every few thousand inputs), so bindings accumulate; the identifiers of the last bindings registered are kept for
 * the operations that need one. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/bsf.h"

static bsf *g_b;
static g5c_router *g_r;
static unsigned g_runs;
static char g_ids[8][40];
static unsigned g_nids;

static const char YAML[] = "bsf: { max_bindings: 500 }\n";
static const char *const PARAMS[] = {"ipv4Addr", "ipv6Prefix", "macAddr48", "dnn", "supi", "gpsi", "snssai", "ipDomain", "supp-feat"};

static void reset(void)
{
    char err[160];
    g5c_json *root;
    bsf_cfg *c;
    if (g_r != NULL)
        g5c_router_free(g_r);
    bsf_destroy(g_b);
    root = g5c_yaml_parse(YAML, sizeof YAML - 1, err, sizeof err);
    c = bsf_cfg_parse(root, err, sizeof err);
    g5c_json_free(root);
    g_b = bsf_new(c, NULL);
    g_r = bsf_router(g_b);
    g_nids = 0;
}

static char *pct(const uint8_t *d, size_t n)
{
    char *o = g5c_xmalloc(n * 3 + 1), *p = o;
    for (size_t i = 0; i < n; i++)
        p += sprintf(p, "%%%02X", d[i]);
    *p = '\0';
    return o;
}

/* what the BSF answered: the status; the identifier of a created binding is remembered */
static int dispatch(const char *method, const char *path, const char *query, const char *ctype, const uint8_t *body, size_t n)
{
    g5c_req req;
    g5c_resp resp;
    int st;
    g5c_req_init(&req);
    req.method = g5c_xstrdup(method);
    req.path = g5c_xstrdup(path);
    req.query = query != NULL ? g5c_xstrdup(query) : NULL;
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("bsf.fuzz:80");
    if (ctype != NULL)
        g5c_req_add_header(&req, "content-type", ctype);
    if (n > 0)
        g5c_req_set_body(&req, body, n);
    g5c_resp_init(&resp);
    g5c_router_dispatch(g_r, &req, &resp);
    st = resp.status;
    if (st == 201 && g5c_resp_header_get(&resp, "location") != NULL) {
        const char *slash = strrchr(g5c_resp_header_get(&resp, "location"), '/');
        if (slash != NULL && strlen(slash + 1) < sizeof g_ids[0]) {
            snprintf(g_ids[g_nids % 8], sizeof g_ids[0], "%s", slash + 1);
            g_nids++;
        }
    }
    g5c_resp_free(&resp);
    g5c_req_free(&req);
    return st;
}

#define BASE "/nbsf-management/v1/pcfBindings"

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
    snprintf(path, sizeof path, BASE "/%s", g_nids > 0 ? g_ids[data[1] % (g_nids < 8 ? g_nids : 8)] : "none");
    switch (data[0] % 6) {
    case 0:
        dispatch("POST", BASE, NULL, "application/json", data + 2, size - 2);
        break;
    case 1: {
        static const char *const kinds[] = {"ipv4Addr", "ipv6Prefix", "macAddr48", "ipDomain", "addIpv6Prefixes", "ipv4FrameRouteList"};
        char *v = g5c_xmalloc(size + 1), *body;
        size_t k = 0;
        for (size_t i = 2; i < size && k < 200; i++)
            if (data[i] >= 0x20 && data[i] < 0x7f && data[i] != '"' && data[i] != '\\')
                v[k++] = (char)data[i];
        v[k] = '\0';
        if (data[1] % 6 >= 4)
            body = g5c_xasprintf("{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"%s\":[\"%s\"],\"pcfFqdn\":\"pcf.example.org\",\"suppFeat\":\"1f\"}", kinds[data[1] % 6], v);
        else
            body = g5c_xasprintf("{\"dnn\":\"internet\",\"snssai\":{\"sst\":1},\"%s\":\"%s\",\"pcfFqdn\":\"pcf.example.org\",\"suppFeat\":\"1f\"}", kinds[data[1] % 6], v);
        dispatch("POST", BASE, NULL, "application/json", (const uint8_t *)body, strlen(body));
        free(body);
        free(v);
        break;
    }
    case 2: {
        char *v = pct(data + 2, size - 2 > 300 ? 300 : size - 2), *q;
        q = g5c_xasprintf("%s=%s", PARAMS[data[1] % (sizeof PARAMS / sizeof *PARAMS)], v);
        dispatch("GET", BASE, q, NULL, NULL, 0);
        free(q);
        free(v);
        break;
    }
    case 3:
        dispatch("PATCH", path, NULL, "application/merge-patch+json", data + 2, size - 2);
        break;
    case 4:
        dispatch("DELETE", path, NULL, NULL, NULL, 0);
        break;
    default: {
        char *q = g5c_xmalloc(size + 1);
        size_t k = 0;
        for (size_t i = 2; i < size && k < 400; i++)
            if (data[i] >= 0x20 && data[i] < 0x7f)
                q[k++] = (char)data[i];
        q[k] = '\0';
        dispatch("GET", BASE, q, NULL, NULL, 0);
        free(q);
        break;
    }
    }
    return 0;
}
