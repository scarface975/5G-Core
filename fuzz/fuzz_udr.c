/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: everything a peer sends the UDR, in process against a memory store with schema validation on and the
 * provisioning extensions open. Byte 0 selects the operation, the rest is the input:
 *   0  <resource> <method> <query> <headers> <content type> <body...>   a request to one of the resources below
 *   1  <path...>                                                 GET of /nudr-dr/v2/<path> (the router, URI parsing, key mapping)
 *   2  <query...>                                                GET /nudr-group-id-map/v1/nf-group-ids?<query>
 *   3  <body...>                                                 POST of a subscription (SD, PD, ED, TI, AD chosen by the first body
 *                                                                byte), then a write that triggers it
 * The store is replaced every few thousand inputs so that it does not grow without bound. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/udr.h"

static g5c_udr_store *g_store;
static g5c_router *g_router;
static unsigned g_runs;

#define SUPI "imsi-001010000000001"

static const char *const RESOURCES[] = {
    "/nudr-dr/v2/subscription-data/" SUPI "/authentication-data/authentication-subscription",
    "/nudr-dr/v2/subscription-data/" SUPI "/authentication-data/authentication-status",
    "/nudr-dr/v2/subscription-data/" SUPI "/00101/provisioned-data/am-data",
    "/nudr-dr/v2/subscription-data/" SUPI "/00101/provisioned-data/sm-data",
    "/nudr-dr/v2/subscription-data/" SUPI "/00101/provisioned-data",
    "/nudr-dr/v2/subscription-data/" SUPI "/context-data",
    "/nudr-dr/v2/subscription-data/" SUPI "/context-data/amf-3gpp-access",
    "/nudr-dr/v2/subscription-data/" SUPI "/context-data/smf-registrations/1",
    "/nudr-dr/v2/subscription-data/" SUPI "/context-data/smf-registrations",
    "/nudr-dr/v2/subscription-data/" SUPI "/context-data/sdm-subscriptions",
    "/nudr-dr/v2/subscription-data/" SUPI "/context-data/ee-subscriptions/e1",
    "/nudr-dr/v2/subscription-data/" SUPI "/identity-data",
    "/nudr-dr/v2/subscription-data/msisdn-1/00101/provisioned-data/am-data",
    "/nudr-dr/v2/subscription-data/subs-to-notify",
    "/nudr-dr/v2/subscription-data/subs-to-notify/s1",
    "/nudr-dr/v2/subscription-data/shared-data/sh1",
    "/nudr-dr/v2/subscription-data/group-data/g1/ee-subscriptions",
    "/nudr-dr/v2/subscription-data",
    "/nudr-dr/v2/subscription-data/" SUPI,
    "/nudr-dr/v2/policy-data/ues/" SUPI "/operator-specific-data",
    "/nudr-dr/v2/policy-data/ues/" SUPI "/am-data",
    "/nudr-dr/v2/policy-data/ues/" SUPI "/sm-data/u1",
    "/nudr-dr/v2/policy-data/bdt-data/b1",
    "/nudr-dr/v2/policy-data/subs-to-notify",
    "/nudr-dr/v2/policy-data/subs-to-notify/p1",
    "/nudr-dr/v2/exposure-data/" SUPI "/access-and-mobility-data",
    "/nudr-dr/v2/exposure-data/" SUPI "/session-management-data/5",
    "/nudr-dr/v2/exposure-data/subs-to-notify",
    "/nudr-dr/v2/application-data/influenceData/i1",
    "/nudr-dr/v2/application-data/influenceData/subs-to-notify",
    "/nudr-dr/v2/application-data/pfds/a1",
    "/nudr-dr/v2/application-data/subs-to-notify",
    "/nudr-dr/v1/subscription-data/" SUPI "/00101/provisioned-data/am-data",
};
static const char *const METHODS[] = {"GET", "PUT", "PATCH", "DELETE", "POST"};
static const char *const CTYPES[] = {"application/json", "application/json-patch+json", "application/merge-patch+json", "text/plain", NULL};
static const char *const QUERIES[] = {"", "?fields=/gpsis,/nssai/defaultSingleNssais", "?fields=", "?fields=/a~1b", "?single-nssai=%7B%22sst%22%3A1%7D&dnn=internet",
                                      "?single-nssai=%ZZ", "?supported-features=3&fields=/x"};
static const char *const HDRS[] = {"", "\"1\"", "\"ffffffff\"", "*", "W/\"2\"", "garbage"};

static void reset(void)
{
    if (g_router != NULL)
        g5c_router_free(g_router);
    if (g_store != NULL)
        g5c_udr_store_free(g_store);
    g_store = g5c_udr_store_memory();
    g_router = g5c_udr_router(g_store);
}

static void dispatch(const char *method, const char *path, const char *query, const char *ctype, const char *im, const char *inm, const uint8_t *body, size_t n)
{
    g5c_req req;
    g5c_resp resp;
    g5c_req_init(&req);
    req.method = g5c_xstrdup(method);
    req.path = g5c_xstrdup(path);
    req.query = query != NULL && query[0] == '?' && query[1] != '\0' ? g5c_xstrdup(query + 1) : NULL;
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("udr.fuzz:80");
    if (ctype != NULL)
        g5c_req_add_header(&req, "content-type", ctype);
    if (im != NULL && im[0] != '\0')
        g5c_req_add_header(&req, "if-match", im);
    if (inm != NULL && inm[0] != '\0')
        g5c_req_add_header(&req, "if-none-match", inm);
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
    if (g_router == NULL || ++g_runs % 4000 == 0) {
        g5c_log_init("error", false);
        reset();
    }
    if (size < 1)
        return 0;
    switch (data[0] % 4) {
    case 0:
        if (size >= 6) {
            dispatch(METHODS[data[2] % 5], RESOURCES[data[1] % (sizeof RESOURCES / sizeof *RESOURCES)], QUERIES[data[3] % (sizeof QUERIES / sizeof *QUERIES)],
                     CTYPES[data[5] % 4], HDRS[(data[4] & 15) % (sizeof HDRS / sizeof *HDRS)], HDRS[(data[4] >> 4) % (sizeof HDRS / sizeof *HDRS)], data + 6, size - 6);
        }
        break;
    case 1: {
        char *path = g5c_xasprintf("/nudr-dr/v2/%.*s", (int)(size - 1 > 300 ? 300 : size - 1), (const char *)data + 1);
        for (char *c = path; *c; c++)
            if (*c == '\0' || (unsigned char)*c < 0x20 || *c == '?' || *c == '#')
                *c = '_';
        dispatch("GET", path, NULL, NULL, NULL, NULL, NULL, 0);
        free(path);
        break;
    }
    case 2: {
        char *q = g5c_xasprintf("?%.*s", (int)(size - 1 > 200 ? 200 : size - 1), (const char *)data + 1);
        for (char *c = q; *c; c++)
            if ((unsigned char)*c < 0x20)
                *c = '_';
        dispatch("GET", "/nudr-group-id-map/v1/nf-group-ids", q, NULL, NULL, NULL, NULL, 0);
        free(q);
        break;
    }
    default:
        if (size >= 2) {
            static const char *const SUBS[] = {"/nudr-dr/v2/subscription-data/subs-to-notify", "/nudr-dr/v2/policy-data/subs-to-notify",
                                               "/nudr-dr/v2/exposure-data/subs-to-notify", "/nudr-dr/v2/application-data/influenceData/subs-to-notify",
                                               "/nudr-dr/v2/application-data/subs-to-notify"};
            dispatch("POST", SUBS[data[1] % 5], NULL, "application/json", NULL, NULL, data + 2, size - 2);
            dispatch("PUT", RESOURCES[(data[1] * 7u) % (sizeof RESOURCES / sizeof *RESOURCES)], NULL, "application/json", NULL, NULL, data + 2, size - 2);
        }
        break;
    }
    return 0;
}
