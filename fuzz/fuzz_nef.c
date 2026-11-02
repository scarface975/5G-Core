/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: everything an AF or the AMF sends the NEF, in process. The functions behind the NEF are not there (the calls fail at once), so
 * the target covers the parsing, the validation and the policy checks of the requests. Byte 0 selects the operation, the rest is the input:
 *   0   POST a traffic influence subscription        1  PUT one         2  PATCH one (merge patch)
 *   3   POST a monitoring event subscription          4  PUT one
 *   5   POST an AMF event report to the callback      6  GET / DELETE of subscriptions and of the names the AF does not own (byte 1 selects)
 *   7   POST an AS session with QoS subscription   8  PUT one   9  PATCH one
 *   10  POST a PCF event notification to the callback   11  POST a PCF termination to the callback
 * The NEF is the same for the whole run (reset every few thousand inputs). */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/nef.h"

static nef *g_n;
static g5c_router *g_r;
static g5c_client *g_client;
static unsigned g_runs;

static const char YAML[] =
    "nef:\n"
    "  afs:\n"
    "    - { id: af1, no_auth: true, notify_hosts: ['127.0.0.1'], max_subscriptions: 50 }\n"
    "  callback_uri: http://nef.fuzz:80\n"
    "  udr: { uri: 'http://127.0.0.1:9' }\n"
    "  udm: { uri: 'http://127.0.0.1:9' }\n"
    "  amf: { uri: 'http://127.0.0.1:9' }\n"
    "  pcf: { uri: 'http://127.0.0.1:9' }\n"
    "  subscriptions: { notify_retries: 0, max_reports: 10 }\n";

static void reset(void)
{
    char err[160];
    g5c_json *root;
    nef_cfg *c;
    if (g_r != NULL)
        g5c_router_free(g_r);
    nef_destroy(g_n);
    if (g_client == NULL)
        g_client = g5c_client_new(100, NULL);
    root = g5c_yaml_parse(YAML, sizeof YAML - 1, err, sizeof err);
    c = nef_cfg_parse(root, "001", "01", NULL, err, sizeof err);
    g5c_json_free(root);
    g_n = nef_new(c, g_client, NULL, NULL);
    g_r = nef_router(g_n);
}

static void dispatch(const char *method, const char *path, const char *ctype, const uint8_t *body, size_t n)
{
    g5c_req req;
    g5c_resp resp;
    g5c_req_init(&req);
    req.method = g5c_xstrdup(method);
    req.path = g5c_xstrdup(path);
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("nef.fuzz:80");
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
    static const char *const AFS[] = {"af1", "nobody", "af%31"};
    char path[128];
    if (g_r == NULL || ++g_runs % 3000 == 0) {
        g5c_log_init("error", false);
        reset();
    }
    if (size < 2)
        return 0;
    switch (data[0] % 12) {
    case 0:
        dispatch("POST", "/3gpp-traffic-influence/v1/af1/subscriptions", "application/json", data + 1, size - 1);
        break;
    case 1:
        dispatch("PUT", "/3gpp-traffic-influence/v1/af1/subscriptions/x", "application/json", data + 1, size - 1);
        break;
    case 2:
        dispatch("PATCH", "/3gpp-traffic-influence/v1/af1/subscriptions/x", "application/merge-patch+json", data + 1, size - 1);
        break;
    case 3:
        dispatch("POST", "/3gpp-monitoring-event/v1/af1/subscriptions", "application/json", data + 1, size - 1);
        break;
    case 4:
        dispatch("PUT", "/3gpp-monitoring-event/v1/af1/subscriptions/x", "application/json", data + 1, size - 1);
        break;
    case 5:
        dispatch("POST", "/nnef-callback/v1/amf-events/x", "application/json", data + 1, size - 1);
        break;
    case 7:
        dispatch("POST", "/3gpp-as-session-with-qos/v1/af1/subscriptions", "application/json", data + 1, size - 1);
        break;
    case 8:
        dispatch("PUT", "/3gpp-as-session-with-qos/v1/af1/subscriptions/x", "application/json", data + 1, size - 1);
        break;
    case 9:
        dispatch("PATCH", "/3gpp-as-session-with-qos/v1/af1/subscriptions/x", "application/merge-patch+json", data + 1, size - 1);
        break;
    case 10:
        dispatch("POST", "/nnef-callback/v1/pcf-events/x/y/notify", "application/json", data + 1, size - 1);
        break;
    case 11:
        dispatch("POST", "/nnef-callback/v1/pcf-events/x/y/terminate", "application/json", data + 1, size - 1);
        break;
    default:
        snprintf(path, sizeof path, "%s/%s/subscriptions%s", (data[1] & 1) ? "/3gpp-traffic-influence/v1" : (data[1] & 0x40) ? "/3gpp-as-session-with-qos/v1" : "/3gpp-monitoring-event/v1", AFS[(data[1] >> 1) % 3],
                 (data[1] & 0x10) ? "/x" : "");
        dispatch((data[1] & 0x20) ? "DELETE" : "GET", path, NULL, NULL, 0);
        break;
    }
    return 0;
}
