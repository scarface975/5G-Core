/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: everything a peer sends the AUSF, against a stub UDM in the same process (a fixed 5G AKA vector, a fixed EAP-AKA' vector with known CK' and IK', so
 * that a valid response can be built and the deep paths are reachable). Byte 0 selects the operation, the rest is the input:
 *   0 POST /ue-authentications                          AuthenticationInfo JSON
 *   1 5G AKA start, then PUT .../5g-aka-confirmation    ConfirmationData JSON
 *   2 EAP-AKA' start, then POST .../eap-session         EapSession JSON
 *   3 EAP-AKA' start, then POST .../eap-session         {"eapPayload": base64(input)}
 *   4 POST /ue-authentications/deregister               DeregistrationInfo JSON
 *   5 5G AKA run to success, then SoR protection        SorInfo JSON
 *   6 5G AKA run to success, then UPU protection        UpuInfo JSON
 *   7 POST /rg-authentications                          RgAuthenticationInfo JSON
 * The AUSF is the same for the whole run, so contexts and security contexts accumulate the way they do in a deployment. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/ausf.h"

static ausf *g_ausf;
static g5c_router *g_router, *g_udm_router;
static g5c_server *g_udm_server;
static g5c_client *g_client;
static g5c_registry *g_metrics;

#define SUPI "imsi-001010000000001"
#define SUPI_EAP "imsi-001010000000002"
#define SNN "5G:mnc001.mcc001.3gppnetwork.org"

static void h_generate(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const char *who = g5c_req_param(req, "supiOrSuci");
    static const char aka[] = "{\"authType\":\"5G_AKA\",\"supi\":\"" SUPI "\",\"authenticationVector\":{\"avType\":\"5G_HE_AKA\",\"rand\":\"000102030405060708090a0b0c0d0e0f\","
                              "\"autn\":\"101112131415161718191a1b1c1d1e1f\",\"xresStar\":\"11111111111111111111111111111111\","
                              "\"kausf\":\"2222222222222222222222222222222222222222222222222222222222222222\"}}";
    static const char eap[] = "{\"authType\":\"EAP_AKA_PRIME\",\"supi\":\"" SUPI_EAP "\",\"authenticationVector\":{\"avType\":\"EAP_AKA_PRIME\","
                              "\"rand\":\"000102030405060708090a0b0c0d0e0f\",\"autn\":\"1011121314158000b2eb311adabcc2c9\",\"xres\":\"3333333333333333\","
                              "\"ckPrime\":\"44444444444444444444444444444444\",\"ikPrime\":\"55555555555555555555555555555555\"}}";
    (void)ctx;
    if (who != NULL && strstr(who, "0000000002") != NULL)
        g5c_resp_content(resp, 200, G5C_JSON_TYPE, eap, sizeof eap - 1);
    else if (who != NULL && strstr(who, "0000000001") != NULL)
        g5c_resp_content(resp, 200, G5C_JSON_TYPE, aka, sizeof aka - 1);
    else
        g5c_resp_problem_simple(resp, 404, "USER_NOT_FOUND", NULL);
}

static void h_event(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    g5c_resp_header(resp, "location", "http://127.0.0.1/nudm-ueau/v1/x/auth-events/1");
    g5c_resp_content(resp, 201, G5C_JSON_TYPE, "{}", 2);
}

static void h_removal(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    g5c_resp_status(resp, 204);
}

static void h_rg(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    static const char b[] = "{\"authInd\":true,\"supi\":\"" SUPI "\"}";
    (void)ctx;
    (void)req;
    g5c_resp_content(resp, 200, G5C_JSON_TYPE, b, sizeof b - 1);
}

static void init_once(void)
{
    g5c_server_cfg sc = {"127.0.0.1", 0, NULL};
    char url[64], err[100];
    if (g_ausf != NULL)
        return;
    g5c_log_init("error", false);
    g_udm_router = g5c_router_new();
    g5c_router_route(g_udm_router, "POST", "/nudm-ueau/v1/{supiOrSuci}/security-information/generate-auth-data", h_generate, NULL);
    g5c_router_route(g_udm_router, "POST", "/nudm-ueau/v1/{supi}/auth-events", h_event, NULL);
    g5c_router_route(g_udm_router, "PUT", "/nudm-ueau/v1/{supi}/auth-events/{id}", h_removal, NULL);
    g5c_router_route(g_udm_router, "GET", "/nudm-ueau/v1/{supiOrSuci}/security-information-rg", h_rg, NULL);
    g_udm_server = g5c_server_start(&sc, g_udm_router, err, sizeof err);
    if (g_udm_server == NULL)
        abort();
    snprintf(url, sizeof url, "http://127.0.0.1:%u", g5c_server_port(g_udm_server));
    g_client = g5c_client_new(2000, NULL);
    g_metrics = g5c_registry_new();
    {
        ausf_opts o;
        ausf_opts_default(&o);
        o.max_contexts = 64;
        o.max_ue_contexts = 16;
        o.eap_result_ind = true;
        o.eap_first_id = 1; /* so that a valid response can be a seed */
        g_ausf = ausf_new(g_client, url, NULL, "", "fuzz", g_metrics, &o);
    }
    g_router = ausf_router(g_ausf);
}

static void send_req(const char *method, const char *path, const char *ctype, const uint8_t *body, size_t n, g5c_resp *resp)
{
    g5c_req req;
    g5c_req_init(&req);
    req.method = g5c_xstrdup(method);
    req.path = g5c_xstrdup(path);
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("ausf:7774");
    if (ctype != NULL)
        g5c_req_add_header(&req, "content-type", ctype);
    if (n > 0)
        g5c_req_set_body(&req, body, n);
    g5c_resp_init(resp);
    g5c_router_dispatch(g_router, &req, resp);
    g5c_req_free(&req);
}

static void send_free(const char *method, const char *path, const uint8_t *body, size_t n)
{
    g5c_resp r;
    send_req(method, path, "application/json", body, n, &r);
    g5c_resp_free(&r);
}

/* start a run for `supi`; the path of the created context ("/nausf-auth/v1/ue-authentications/{id}") into out, true when it was created */
static bool start(const char *supi, char *out, size_t cap)
{
    char body[200];
    g5c_resp r;
    const char *loc;
    bool ok = false;
    snprintf(body, sizeof body, "{\"supiOrSuci\":\"%s\",\"servingNetworkName\":\"" SNN "\"}", supi);
    send_req("POST", "/nausf-auth/v1/ue-authentications", "application/json", (const uint8_t *)body, strlen(body), &r);
    loc = g5c_resp_header_get(&r, "location");
    if (r.status == 201 && loc != NULL) {
        const char *p = strstr(loc, "/nausf-auth/");
        if (p != NULL) {
            snprintf(out, cap, "%s", p);
            ok = true;
        }
    }
    g5c_resp_free(&r);
    return ok;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char ctx[200], path[300], supi_path[160];
    static const char *const hex11 = "{\"resStar\":\"11111111111111111111111111111111\"}";
    if (size < 1)
        return 0;
    init_once();
    switch (data[0] % 8) {
    case 0:
        send_free("POST", "/nausf-auth/v1/ue-authentications", data + 1, size - 1);
        break;
    case 1:
        if (start(SUPI, ctx, sizeof ctx)) {
            snprintf(path, sizeof path, "%s/5g-aka-confirmation", ctx);
            send_free("PUT", path, data + 1, size - 1);
            send_free("DELETE", path, NULL, 0);
        }
        break;
    case 2:
    case 3:
        if (start(SUPI_EAP, ctx, sizeof ctx)) {
            snprintf(path, sizeof path, "%s/eap-session", ctx);
            if (data[0] % 8 == 2) {
                send_free("POST", path, data + 1, size - 1);
            } else {
                char *b64 = g5c_base64_encode(data + 1, size - 1), *body = g5c_xasprintf("{\"eapPayload\":\"%s\"}", b64);
                send_free("POST", path, (const uint8_t *)body, strlen(body));
                send_free("POST", path, (const uint8_t *)body, strlen(body)); /* a second round on whatever state the first left */
                free(body);
                free(b64);
            }
            send_free("DELETE", path, NULL, 0);
        }
        break;
    case 4:
        send_free("POST", "/nausf-auth/v1/ue-authentications/deregister", data + 1, size - 1);
        break;
    case 5:
    case 6:
        if (start(SUPI, ctx, sizeof ctx)) {
            snprintf(path, sizeof path, "%s/5g-aka-confirmation", ctx);
            send_free("PUT", path, (const uint8_t *)hex11, strlen(hex11));
        }
        snprintf(supi_path, sizeof supi_path, "/%s/v1/" SUPI "/%s", data[0] % 8 == 5 ? "nausf-sorprotection" : "nausf-upuprotection",
                 data[0] % 8 == 5 ? "ue-sor/generate-sor-data" : "ue-upu/generate-upu-data");
        send_free("POST", supi_path, data + 1, size - 1);
        break;
    default:
        send_free("POST", "/nausf-auth/v1/rg-authentications", data + 1, size - 1);
        break;
    }
    return 0;
}
