/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Dump the JSON our NFs really produce to $G5C_PAYLOAD_DIR, so tools/spec/validate_openapi.py can check every payload against the official 3GPP OpenAPI */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "g5c/ausf.h"
#include "g5c/bsf.h"
#include "g5c/eapaka.h"
#include "g5c/nef.h"
#include "g5c/nfcore.h"
#include "g5c/nrf.h"
#include "g5c/nssf.h"
#include "g5c/pcf.h"
#include "g5c/testkit.h"
#include "g5c/udm.h"
#include "g5c/udr.h"

#define SNN "5G:mnc001.mcc001.3gppnetwork.org"
#define SUPI "imsi-001010000000001"
#define ADMIN "admin-token-0123456789"

static const char *dir;
static g5c_client *cl;

static void dump(const char *name, const g5c_json *j)
{
    char path[512];
    FILE *f;
    char *s = g5c_json_to_string(j, NULL);
    snprintf(path, sizeof path, "%s/%s.json", dir, name);
    f = fopen(path, "wb");
    if (f == NULL)
        TK_FAIL("cannot write %s", path);
    fputs(s, f);
    fclose(f);
    free(s);
}

/* returns status; *out parsed body, *loc Location header copy */
static int rq(const char *method, const char *url, const char *body, bool admin, g5c_json **out, char **loc)
{
    char auth[64], err[160];
    g5c_kv h = {"authorization", auth};
    g5c_resp r;
    int st;
    snprintf(auth, sizeof auth, "Bearer %s", ADMIN);
    TK_ASSERT(g5c_client_request(cl, method, url, admin ? &h : NULL, admin ? 1 : 0, G5C_JSON_TYPE, body, body ? strlen(body) : 0, &r,
                                 err, sizeof err) == 0);
    st = r.status;
    if (out)
        *out = g5c_resp_parse_json(&r);
    if (loc) {
        const char *l = g5c_resp_header_get(&r, "location");
        *loc = l ? g5c_xstrdup(l) : NULL;
    }
    g5c_resp_free(&r);
    return st;
}

static char *U(const char *base, const char *path)
{
    return g5c_xasprintf("%s%s", base, path);
}

static void get_dump(const char *name, const char *base, const char *path)
{
    char *u = U(base, path);
    g5c_json *v = NULL;
    TK_ASSERT(rq("GET", u, NULL, false, &v, NULL) < 500 && v != NULL);
    dump(name, v);
    g5c_json_free(v);
    free(u);
}

/* Mock SDM consumer: records the ModificationNotification the UDM sends when subscriber data changes. */
static void h_sdm_cb(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_resp err;
    g5c_json *j = g5c_req_json(req, &err);
    (void)ctx;
    TK_ASSERT(j != NULL);
    dump("udm_ModificationNotification", j);
    g5c_json_free(j);
    g5c_resp_status(resp, 204);
}

/* ---- authentication, UDM, UDR ---- */

/* ---- AUSF: EAP-AKA', SoR and UPU protection, FN-RG ---- */

static void ausf_more_payloads(const char *ausf_uri, const char *udm_uri, const char *k_hex, const char *op_hex)
{
    char *p, body[400], *b64, href[300];
    g5c_json *v = NULL, *ctx = NULL;
    uint8_t k[16], op[16], opc[16], pkt[1100], resp[300], rand[16], autn[16], sqn[6], mac_a[8], mac_s[8], ckp[16], ikp[16], resv[18] = {0}, macv[18] = {0};
    g5c_milenage m;
    g5c_milenage_vector mv;
    g5c_eapaka_keys keys;
    g5c_eap_pkt q;
    g5c_eap_attr at[2];
    size_t rn = 0;
    const char *pl;

    /* a subscriber that authenticates with EAP-AKA' */
    snprintf(body, sizeof body, "{\"supi\":\"imsi-001010000000002\",\"k\":\"%s\",\"op\":\"%s\",\"auth_method\":\"EAP_AKA_PRIME\"}", k_hex, op_hex);
    p = U(udm_uri, "/admin/v1/subscribers");
    TK_ASSERT(rq("POST", p, body, true, NULL, NULL) == 201);
    free(p);
    p = U(ausf_uri, "/nausf-auth/v1/ue-authentications");
    TK_ASSERT(rq("POST", p, "{\"supiOrSuci\":\"imsi-001010000000002\",\"servingNetworkName\":\"" SNN "\"}", false, &ctx, NULL) == 201);
    dump("ausf_UEAuthenticationCtx_eap", ctx);
    snprintf(href, sizeof href, "%s", g5c_json_get_str(g5c_json_get(g5c_json_get(ctx, "_links"), "eap-session"), "href"));
    pl = g5c_json_get_str(ctx, "5gAuthData");
    TK_ASSERT(pl != NULL && g5c_base64_decode(pl, pkt, sizeof pkt) > 8);
    TK_ASSERT(g5c_eap_parse(pkt, (size_t)g5c_base64_decode(pl, pkt, sizeof pkt), &q));
    /* the peer's answer, derived from the same credentials */
    TK_ASSERT(tk_unhex(k_hex, k, 16) == 16 && tk_unhex(op_hex, op, 16) == 16 && g5c_milenage_derive_opc(k, op, opc) == 0);
    memcpy(rand, g5c_eap_find(&q, G5C_AT_RAND)->val + 2, 16);
    memcpy(autn, g5c_eap_find(&q, G5C_AT_AUTN)->val + 2, 16);
    g5c_milenage_init(&m, k, opc);
    TK_ASSERT(g5c_milenage_f2345(&m, rand, &mv) == 0);
    for (int i = 0; i < 6; i++)
        sqn[i] = (uint8_t)(autn[i] ^ mv.ak[i]);
    TK_ASSERT(g5c_milenage_f1(&m, rand, sqn, autn + 6, mac_a, mac_s) == 0 && memcmp(mac_a, autn + 8, 8) == 0);
    TK_ASSERT(g5c_ck_ik_prime(mv.ck, mv.ik, SNN, autn, ckp, ikp) == 0 && g5c_eapaka_prime_keys(ckp, ikp, "001010000000002", &keys) == 0);
    resv[1] = 64;
    memcpy(resv + 2, mv.res, 8);
    at[0] = (g5c_eap_attr){G5C_AT_RES, resv, 10};
    at[1] = (g5c_eap_attr){G5C_AT_MAC, macv, 18};
    TK_ASSERT(g5c_eap_build(G5C_EAP_RESPONSE, q.id, G5C_EAPAKA_CHALLENGE, at, 2, resp, sizeof resp, &rn) == 0 && g5c_eap_mac_set(resp, rn, keys.k_aut, NULL, 0) == 0);
    b64 = g5c_base64_encode(resp, rn);
    snprintf(body, sizeof body, "{\"eapPayload\":\"%s\"}", b64);
    free(b64);
    TK_ASSERT(rq("POST", href, body, false, &v, NULL) == 200);
    dump("ausf_EapSession_success", v);
    g5c_json_free(v);
    g5c_json_free(ctx);
    /* a failed session: the notification is still ongoing, then nothing from the UE */
    TK_ASSERT(rq("POST", p, "{\"supiOrSuci\":\"imsi-001010000000002\",\"servingNetworkName\":\"" SNN "\"}", false, &ctx, NULL) == 201);
    snprintf(href, sizeof href, "%s", g5c_json_get_str(g5c_json_get(g5c_json_get(ctx, "_links"), "eap-session"), "href"));
    g5c_json_free(ctx);
    TK_ASSERT(rq("POST", href, "{\"eapPayload\":\"AgEABBcB\"}", false, &v, NULL) == 200); /* not a response of the method: a failure notification */
    dump("ausf_EapSession_ongoing", v);
    snprintf(href, sizeof href, "%s", g5c_json_get_str(g5c_json_get(g5c_json_get(v, "_links"), "eap-session"), "href"));
    g5c_json_free(v);
    TK_ASSERT(rq("POST", href, "{\"eapPayload\":null}", false, &v, NULL) == 200);
    dump("ausf_EapSession_failure", v);
    g5c_json_free(v);
    free(p);

    /* SoR and UPU protection with the KAUSF of the EAP-AKA' run above */
    p = U(ausf_uri, "/nausf-sorprotection/v1/imsi-001010000000002/ue-sor/generate-sor-data");
    TK_ASSERT(rq("POST", p, "{\"ackInd\":true,\"steeringContainer\":[{\"plmnId\":{\"mcc\":\"310\",\"mnc\":\"260\"},\"accessTechList\":[\"NR\",\"EUTRAN_IN_WBS1_MODE_AND_NBS1_MODE\"]}]}", false, &v, NULL) == 200);
    dump("ausf_SorSecurityInfo", v);
    g5c_json_free(v);
    free(p);
    p = U(ausf_uri, "/nausf-upuprotection/v1/imsi-001010000000002/ue-upu/generate-upu-data");
    TK_ASSERT(rq("POST", p, "{\"upuDataList\":[{\"defaultConfNssai\":[{\"sst\":1},{\"sst\":2,\"sd\":\"010203\"}],\"routingId\":\"1234\"}],\"upuHeader\":\"06\",\"upuAckInd\":true}", false, &v, NULL) == 200);
    dump("ausf_UpuSecurityInfo", v);
    g5c_json_free(v);
    free(p);
    p = U(ausf_uri, "/nausf-sorprotection/v1/imsi-001010000000077/ue-sor/generate-sor-data");
    TK_ASSERT(rq("POST", p, "{\"ackInd\":false}", false, &v, NULL) == 404);
    dump("ausf_ProblemDetails", v);
    g5c_json_free(v);
    free(p);
    /* FN-RG: the gateway the W-AGF has authenticated */
    p = U(ausf_uri, "/nausf-auth/v1/rg-authentications");
    TK_ASSERT(rq("POST", p, "{\"suci\":\"suci-0-001-01-0000-0-0-0000000001\",\"authenticatedInd\":true}", false, &v, NULL) == 201);
    dump("ausf_RgAuthCtx", v);
    g5c_json_free(v);
    free(p);
    /* what the UDM gave the AUSF for these: the EAP-AKA' vector and the answer for the gateway */
    p = U(udm_uri, "/nudm-ueau/v1/imsi-001010000000002/security-information/generate-auth-data");
    TK_ASSERT(rq("POST", p, "{\"servingNetworkName\":\"" SNN "\",\"ausfInstanceId\":\"ausf-dump\"}", false, &v, NULL) == 200);
    dump("udm_AuthenticationInfoResult_eap", v);
    g5c_json_free(v);
    free(p);
    p = U(udm_uri, "/nudm-ueau/v1/suci-0-001-01-0000-0-0-0000000001/security-information-rg?authenticated-ind=true");
    TK_ASSERT(rq("GET", p, NULL, false, &v, NULL) == 200);
    dump("udm_RgAuthCtx", v);
    g5c_json_free(v);
    free(p);
}

static void identity_stack_payloads(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_udr_store *store = g5c_udr_store_memory();
    g5c_router *udr_r = g5c_udr_router(store), *udm_r, *ausf_r;
    g5c_server *udr_s = g5c_server_start(&cfg, udr_r, NULL, 0), *udm_s, *ausf_s;
    g5c_registry *m1 = g5c_registry_new(), *m2 = g5c_registry_new();
    udm u;
    ausf *a;
    udm_keys keys;
    uint8_t master[32];
    char udr[64], udm_uri[64], ausf_uri[64], *p, *href, *href2;
    g5c_json *v = NULL, *ctx = NULL;
    const char *k_hex = "465b5ce8b199b49faa5f0a2ee238a6bc", *op_hex = "cdc202d5123e20f62b6d676ac72cb318";
    const char *plmn = "%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D";

    memset(master, 3, 32);
    udm_keys_with_master(&keys, master);
    snprintf(udr, sizeof udr, "http://127.0.0.1:%u", g5c_server_port(udr_s));
    udm_init(&u, cl, udr, &keys, NULL, 0, "00101", "udm-dump", m1);
    u.admin_token = g5c_xstrdup(ADMIN);
    udm_r = udm_router(&u);
    udm_s = g5c_server_start(&cfg, udm_r, NULL, 0);
    snprintf(udm_uri, sizeof udm_uri, "http://127.0.0.1:%u", g5c_server_port(udm_s));
    a = ausf_new(cl, udm_uri, NULL, "", "ausf-dump", m2, NULL);
    ausf_r = ausf_router(a);
    ausf_s = g5c_server_start(&cfg, ausf_r, NULL, 0);
    snprintf(ausf_uri, sizeof ausf_uri, "http://127.0.0.1:%u", g5c_server_port(ausf_s));

    p = U(udm_uri, "/admin/v1/subscribers");
    {
        char body[512];
        snprintf(body, sizeof body,
                 "{\"supi\":\"" SUPI "\",\"k\":\"%s\",\"op\":\"%s\",\"slices\":[{\"sst\":1},{\"sst\":2,\"sd\":\"010203\"}],"
                 "\"dnns\":{\"internet\":{},\"ims\":{\"qi5\":5,\"session_types\":[\"IPV4V6\",\"IPV4\"]}}}",
                 k_hex, op_hex);
        TK_ASSERT(rq("POST", p, body, true, NULL, NULL) == 201);
    }
    free(p);

    /* AUSF: start + confirm, the UE side simulated */
    p = U(ausf_uri, "/nausf-auth/v1/ue-authentications");
    TK_ASSERT(rq("POST", p, "{\"supiOrSuci\":\"" SUPI "\",\"servingNetworkName\":\"" SNN "\"}", false, &ctx, NULL) == 201);
    dump("ausf_UEAuthenticationCtx", ctx);
    {
        uint8_t rand[16], k[16], op[16], opc[16], res_star[16];
        g5c_milenage mil;
        g5c_milenage_vector mv;
        char *hx, body[128];
        g5c_json *r2 = NULL;
        TK_ASSERT(tk_unhex(g5c_json_get_str(g5c_json_get(ctx, "5gAuthData"), "rand"), rand, 16) == 16);
        TK_ASSERT(tk_unhex(k_hex, k, 16) == 16 && tk_unhex(op_hex, op, 16) == 16);
        TK_ASSERT(g5c_milenage_derive_opc(k, op, opc) == 0);
        g5c_milenage_init(&mil, k, opc);
        TK_ASSERT(g5c_milenage_f2345(&mil, rand, &mv) == 0);
        TK_ASSERT(g5c_res_star(mv.ck, mv.ik, SNN, rand, mv.res, 8, res_star) == 0);
        href = g5c_xstrdup(g5c_json_get_str(g5c_json_get(g5c_json_get(ctx, "_links"), "5g-aka"), "href"));
        hx = g5c_hex_encode(res_star, 16);
        snprintf(body, sizeof body, "{\"resStar\":\"%s\"}", hx);
        free(hx);
        TK_ASSERT(rq("PUT", href, body, false, &r2, NULL) == 200);
        dump("ausf_ConfirmationDataResponse_success", r2);
        g5c_json_free(r2);
        free(href);
    }
    g5c_json_free(ctx);
    TK_ASSERT(rq("POST", p, "{\"supiOrSuci\":\"" SUPI "\",\"servingNetworkName\":\"" SNN "\"}", false, &ctx, NULL) == 201);
    href2 = g5c_xstrdup(g5c_json_get_str(g5c_json_get(g5c_json_get(ctx, "_links"), "5g-aka"), "href"));
    g5c_json_free(ctx);
    TK_ASSERT(rq("PUT", href2, "{\"resStar\":\"00000000000000000000000000000000\"}", false, &v, NULL) == 200);
    dump("ausf_ConfirmationDataResponse_failure", v);
    g5c_json_free(v);
    free(href2);
    free(p);

    ausf_more_payloads(ausf_uri, udm_uri, k_hex, op_hex);

    /* UDM UEAU direct */
    p = U(udm_uri, "/nudm-ueau/v1/" SUPI "/security-information/generate-auth-data");
    TK_ASSERT(rq("POST", p, "{\"servingNetworkName\":\"" SNN "\",\"ausfInstanceId\":\"ausf-dump\"}", false, &v, NULL) == 200);
    dump("udm_AuthenticationInfoResult", v);
    g5c_json_free(v);
    free(p);
    p = U(udm_uri, "/nudm-ueau/v1/" SUPI "/auth-events");
    TK_ASSERT(rq("POST", p, "{\"nfInstanceId\":\"ausf-dump\",\"success\":true,\"timeStamp\":\"2026-10-05T10:00:00Z\",\"authType\":\"5G_AKA\",\"servingNetworkName\":\"" SNN "\"}", false, &v, NULL) == 201);
    dump("udm_AuthEvent", v);
    g5c_json_free(v);
    free(p);

    /* UDM SDM */
    {
        char path[256];
        g5c_json *sm = NULL;
        snprintf(path, sizeof path, "/nudm-sdm/v2/" SUPI "/am-data?plmn-id=%s", plmn);
        get_dump("udm_AccessAndMobilitySubscriptionData", udm_uri, path);
        snprintf(path, sizeof path, "/nudm-sdm/v2/" SUPI "/sm-data?plmn-id=%s", plmn);
        p = U(udm_uri, path);
        TK_ASSERT(rq("GET", p, NULL, false, &sm, NULL) == 200);
        free(p);
        for (size_t i = 0; i < g5c_json_len(sm); i++) {
            char name[96];
            snprintf(name, sizeof name, "udm_SessionManagementSubscriptionData_%zu", i);
            dump(name, g5c_json_at(sm, i));
        }
        g5c_json_free(sm);
        snprintf(path, sizeof path, "/nudm-sdm/v2/" SUPI "?plmn-id=%s&dataset-names=AM,SMF_SEL,SM,UEC_SMF", plmn);
        get_dump("udm_SubscriptionDataSets", udm_uri, path);
        get_dump("udm_Nssai", udm_uri, "/nudm-sdm/v2/" SUPI "/nssai");
        get_dump("udm_SmfSelectionSubscriptionData", udm_uri, "/nudm-sdm/v2/" SUPI "/smf-select-data");
        p = U(udm_uri, "/nudm-uecm/v1/" SUPI "/registrations/smf-registrations/5");
        TK_ASSERT(rq("PUT", p,
                     "{\"smfInstanceId\":\"smf-1\",\"pduSessionId\":5,\"singleNssai\":{\"sst\":1},\"dnn\":\"internet\",\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"}}",
                     false, NULL, NULL) == 201);
        free(p);
        get_dump("udm_UeContextInSmfData", udm_uri, "/nudm-sdm/v2/" SUPI "/ue-context-in-smf-data");
        p = U(udm_uri, "/nudm-sdm/v2/" SUPI "/sdm-subscriptions");
        TK_ASSERT(rq("POST", p, "{\"nfInstanceId\":\"amf-1\",\"callbackReference\":\"http://127.0.0.1:1/cb\",\"monitoredResourceUris\":[\"/x\"]}", false, &v, NULL) == 201);
        dump("udm_SdmSubscription", v);
        g5c_json_free(v);
        free(p);
        get_dump("problem_ProblemDetails", udm_uri, "/nudm-sdm/v2/imsi-001010000000099/am-data");
        {   /* data-change notification: subscribe a mock consumer, then re-provision the subscriber */
            g5c_router *cbr = g5c_router_new();
            g5c_server *cbs;
            char sb[256], pb[512];
            g5c_router_route(cbr, "POST", "/sdmcb", h_sdm_cb, NULL);
            cbs = g5c_server_start(&cfg, cbr, NULL, 0);
            snprintf(sb, sizeof sb, "{\"nfInstanceId\":\"amf-2\",\"callbackReference\":\"http://127.0.0.1:%u/sdmcb\"}", g5c_server_port(cbs));
            p = U(udm_uri, "/nudm-sdm/v2/" SUPI "/sdm-subscriptions");
            TK_ASSERT(rq("POST", p, sb, false, NULL, NULL) == 201);
            free(p);
            snprintf(pb, sizeof pb, "{\"supi\":\"" SUPI "\",\"k\":\"%s\",\"op\":\"%s\",\"slices\":[{\"sst\":1}]}", k_hex, op_hex);
            p = U(udm_uri, "/admin/v1/subscribers");
            TK_ASSERT(rq("POST", p, pb, true, NULL, NULL) < 300);
            free(p);
            g5c_server_stop(cbs);
            g5c_router_free(cbr);
        }
    }

    /* UDR documents written by the UDM admin API */
    {
        char path[256];
        get_dump("udr_AuthenticationSubscription", udr, "/nudr-dr/v1/subscription-data/" SUPI "/authentication-data/authentication-subscription");
        snprintf(path, sizeof path, "/nudr-dr/v1/subscription-data/" SUPI "/00101/provisioned-data/am-data");
        get_dump("udr_AccessAndMobilitySubscriptionData", udr, path);
    }

    g5c_server_stop(ausf_s);
    g5c_server_stop(udm_s);
    g5c_server_stop(udr_s);
    g5c_router_free(ausf_r);
    g5c_router_free(udm_r);
    g5c_router_free(udr_r);
    ausf_free(a);
    udm_destroy(&u);
    g5c_udr_store_free(store);
    g5c_registry_free(m1);
    g5c_registry_free(m2);
}

/* ---- PCF ---- */

typedef struct {
    pthread_mutex_t mu;
    int n;
    char kind[8][16];
    g5c_json *body[8];
} notes_t;

static void note(notes_t *n, const char *kind, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *j = g5c_req_json(req, resp);
    if (j == NULL)
        return;
    pthread_mutex_lock(&n->mu);
    if (n->n < 8) {
        snprintf(n->kind[n->n], sizeof n->kind[0], "%s", kind);
        n->body[n->n++] = j;
    } else {
        g5c_json_free(j);
    }
    pthread_mutex_unlock(&n->mu);
    g5c_resp_status(resp, 204);
}

static void smf_update(void *c, const g5c_req *r, g5c_resp *p) { note(c, "update", r, p); }
static void smf_terminate(void *c, const g5c_req *r, g5c_resp *p) { note(c, "terminate", r, p); }

static void pcf_payloads(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_udr_store *store = g5c_udr_store_memory();
    g5c_router *udr_r = g5c_udr_router(store), *pcf_r, *smf_r = g5c_router_new();
    g5c_server *udr_s = g5c_server_start(&cfg, udr_r, NULL, 0), *pcf_s, *smf_s;
    g5c_registry *m = g5c_registry_new();
    notes_t notes;
    pcf p;
    pcf_policy pol;
    char udr[64], uri[64], smf[64], *u, *loc = NULL, body[1024], err[200];
    g5c_json *v = NULL, *y, *list = NULL;
    static const char *const policy_yaml =
        "default: { session_ambr: { uplink: \"1 Gbps\", downlink: \"1 Gbps\" } }\n"
        "dnns:\n"
        "  ims:\n"
        "    default_qos: { qi5: 5, arp_priority: 2 }\n"
        "    pcc_rules:\n"
        "      - { id: voice, flows: [\"permit out 17 from any to assigned\"], qi5: 1, gbr_ul: \"128 Kbps\", gbr_dl: \"128 Kbps\", mbr_ul: \"256 Kbps\", mbr_dl: \"256 Kbps\" }\n"
        "rfsp: 7\n";

    memset(&notes, 0, sizeof notes);
    pthread_mutex_init(&notes.mu, NULL);
    snprintf(udr, sizeof udr, "http://127.0.0.1:%u", g5c_server_port(udr_s));
    y = g5c_yaml_parse(policy_yaml, strlen(policy_yaml), err, sizeof err);
    TK_ASSERT(y != NULL && pcf_policy_parse(y, true, &pol, err, sizeof err) == 0);
    g5c_json_free(y);
    pcf_init(&p, &pol, cl, udr, m);
    p.admin_token = g5c_xstrdup(ADMIN);
    pcf_r = pcf_router(&p);
    pcf_s = g5c_server_start(&cfg, pcf_r, NULL, 0);
    snprintf(uri, sizeof uri, "http://127.0.0.1:%u", g5c_server_port(pcf_s));
    g5c_router_route(smf_r, "POST", "/cb/update", smf_update, &notes);
    g5c_router_route(smf_r, "POST", "/cb/terminate", smf_terminate, &notes);
    smf_s = g5c_server_start(&cfg, smf_r, NULL, 0);
    snprintf(smf, sizeof smf, "http://127.0.0.1:%u", g5c_server_port(smf_s));

#define CTX(dnn)                                                                                                              \
    (snprintf(body, sizeof body,                                                                                              \
              "{\"supi\":\"" SUPI "\",\"pduSessionId\":1,\"pduSessionType\":\"IPV4\",\"dnn\":\"%s\",\"notificationUri\":\"%s/cb\"," \
              "\"sliceInfo\":{\"sst\":1},\"accessType\":\"3GPP_ACCESS\",\"ratType\":\"NR\","                                   \
              "\"subsSessAmbr\":{\"uplink\":\"100 Mbps\",\"downlink\":\"200 Mbps\"},"                                         \
              "\"subsDefQos\":{\"5qi\":9,\"arp\":{\"priorityLevel\":8,\"preemptCap\":\"NOT_PREEMPT\",\"preemptVuln\":\"NOT_PREEMPTABLE\"},\"priorityLevel\":80}}", \
              (dnn), smf),                                                                                                    \
     body)

    u = U(uri, "/npcf-smpolicycontrol/v1/sm-policies");
    TK_ASSERT(rq("POST", u, CTX("internet"), false, &v, &loc) == 201);
    dump("pcf_SmPolicyDecision_internet", v);
    g5c_json_free(v);
    TK_ASSERT(rq("GET", loc, NULL, false, &v, NULL) == 200);
    dump("pcf_SmPolicyControl", v);
    g5c_json_free(v);
    {
        char *up = g5c_xasprintf("%s/update", loc);
        TK_ASSERT(rq("POST", up, "{\"repPolicyCtrlReqTriggers\":[\"PLMN_CH\"]}", false, &v, NULL) == 200);
        dump("pcf_SmPolicyDecision_update", v);
        g5c_json_free(v);
        free(up);
    }
    free(loc);
    TK_ASSERT(rq("POST", u, CTX("ims"), false, &v, NULL) == 201);
    dump("pcf_SmPolicyDecision_ims", v);
    g5c_json_free(v);

    {   /* policy change pushes an update; admin termination sends a terminate */
        char *pu = U(uri, "/admin/v1/policies/" SUPI), *su = U(uri, "/admin/v1/sessions"), *del;
        TK_ASSERT(rq("PUT", pu, "{\"default\":{\"session_ambr\":{\"uplink\":\"5 Mbps\",\"downlink\":\"10 Mbps\"}}}", true, NULL, NULL) == 200);
        TK_ASSERT(rq("GET", su, NULL, true, &list, NULL) == 200 && g5c_json_len(list) >= 1);
        del = g5c_xasprintf("%s/%s", su, g5c_json_get_str(g5c_json_at(list, 0), "smPolicyId"));
        TK_ASSERT(rq("DELETE", del, NULL, true, NULL, NULL) == 204);
        free(del);
        free(pu);
        free(su);
        g5c_json_free(list);
    }
    pthread_mutex_lock(&notes.mu);
    for (int i = 0; i < notes.n; i++)
        dump(strcmp(notes.kind[i], "update") == 0 ? "pcf_SmPolicyNotification" : "pcf_TerminationNotification", notes.body[i]);
    pthread_mutex_unlock(&notes.mu);
    free(u);

    u = U(uri, "/npcf-am-policy-control/v1/policies");
    TK_ASSERT(rq("POST", u,
                 "{\"notificationUri\":\"http://127.0.0.1:1/cb\",\"supi\":\"" SUPI "\",\"accessType\":\"3GPP_ACCESS\",\"servingPlmn\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"suppFeat\":\"\"}",
                 false, &v, &loc) == 201);
    dump("pcf_PolicyAssociation", v);
    g5c_json_free(v);
    {
        char *up = g5c_xasprintf("%s/update", loc);
        TK_ASSERT(rq("POST", up, "{\"servingPlmn\":{\"mcc\":\"001\",\"mnc\":\"01\"}}", false, &v, NULL) == 200);
        dump("pcf_PolicyUpdate", v);
        g5c_json_free(v);
        free(up);
    }
    free(loc);
    free(u);
    u = U(uri, "/npcf-smpolicycontrol/v1/sm-policies");
    TK_ASSERT(rq("POST", u, "{\"supi\":\"x\"}", false, &v, NULL) == 400);
    dump("pcf_ProblemDetails", v);
    g5c_json_free(v);
    free(u);

    g5c_server_stop(smf_s);
    g5c_server_stop(pcf_s);
    g5c_server_stop(udr_s);
    g5c_router_free(smf_r);
    g5c_router_free(pcf_r);
    g5c_router_free(udr_r);
    pcf_destroy(&p);
    g5c_udr_store_free(store);
    g5c_registry_free(m);
    for (int i = 0; i < notes.n; i++)
        g5c_json_free(notes.body[i]);
    pthread_mutex_destroy(&notes.mu);
}

/* ---- NRF: registration, heart-beat, subscription, notification, discovery, access token ---- */

static void nrf_cb(void *c, const g5c_req *q, g5c_resp *r)
{
    g5c_resp err;
    g5c_json *j = g5c_req_json(q, &err);
    (void)c;
    if (j != NULL) {
        dump(strcmp(g5c_json_get_str(j, "event"), "NF_REGISTERED") == 0 ? "nrf_NotificationData" : "nrf_NotificationData_deregistered", j);
        g5c_json_free(j);
    }
    g5c_resp_status(r, 204);
}

static int nrf_call(const char *method, const char *url, const char *ctype, const char *body, g5c_json **out)
{
    char err[160];
    g5c_resp r;
    int st;
    TK_ASSERT(g5c_client_request(cl, method, url, NULL, 0, ctype, body, body ? strlen(body) : 0, &r, err, sizeof err) == 0);
    st = r.status;
    if (out)
        *out = g5c_resp_parse_json(&r);
    g5c_resp_free(&r);
    return st;
}

static void nrf_payloads(void)
{
    static const g5c_svc svcs[] = {{"nudm-ueau", "v1"}, {"nudm-sdm", "v2"}, {"nudm-uecm", "v1"}};
    const char *udm_id = "c22f4910-cc36-43e1-a33e-e213b6aba908", *amf_id = "7a1d3b52-0a0e-4c3c-9d57-5b2a3f6f1a10";
    char yaml[400], err[300], url[300], cburl[100], *body, *amf_body;
    g5c_json *j, *rsp = NULL, *prof;
    g5c_common common;
    g5c_server_cfg sc = {"127.0.0.1", 0, NULL};
    g5c_nf *nf;
    nrf *n;
    g5c_router *r, *cbr = g5c_router_new();
    g5c_server *srv, *cbs;
    char base[64];

    snprintf(yaml, sizeof yaml,
             "name: nrf-dump\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\nregistry:\n  oauth2: { enabled: true, token_lifetime: 3600 }\n");
    j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    TK_ASSERT(j != NULL && g5c_common_parse(j, &common, err, sizeof err) == 0);
    common.port = 0;
    nf = g5c_nf_new(&common, err, sizeof err);
    TK_ASSERT(nf != NULL);
    n = nrf_from_config(j, nf, err, sizeof err);
    g5c_json_free(j);
    TK_ASSERT(n != NULL);
    r = nrf_router(n);
    srv = g5c_server_start(&sc, r, err, sizeof err);
    TK_ASSERT(srv != NULL);
    snprintf(base, sizeof base, "http://127.0.0.1:%u", g5c_server_port(srv));
    nrf_set_self_uri(n, base);
    TK_ASSERT(nrf_start(n, err, sizeof err) == 0);

    g5c_router_route(cbr, "POST", "/nfcb", nrf_cb, NULL);
    cbs = g5c_server_start(&sc, cbr, NULL, 0);
    snprintf(cburl, sizeof cburl, "http://127.0.0.1:%u/nfcb", g5c_server_port(cbs));

    /* the AMF subscribes first, so it is told about the UDM */
    body = g5c_xasprintf("{\"nfStatusNotificationUri\":\"%s\",\"subscrCond\":{\"nfType\":\"UDM\"},\"reqNotifEvents\":[\"NF_REGISTERED\",\"NF_DEREGISTERED\"]}", cburl);
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/subscriptions", base);
    TK_ASSERT(nrf_call("POST", url, G5C_JSON_TYPE, body, &rsp) == 201);
    dump("nrf_SubscriptionData", rsp);
    g5c_json_free(rsp);
    free(body);

    /* UDM registers (the profile it sends), the NRF answers with the profile and a heart-beat timer */
    prof = g5c_nrf_profile(udm_id, "UDM", "127.1.0.1", 7773, "http", "001", "01", svcs, 3);
    body = g5c_json_to_string(prof, NULL);
    g5c_json_free(prof);
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/nf-instances/%s", base, udm_id);
    TK_ASSERT(nrf_call("PUT", url, G5C_JSON_TYPE, body, &rsp) == 201);
    dump("nrf_NFProfile_registered", rsp);
    g5c_json_free(rsp);
    free(body);

    amf_body = g5c_xasprintf("{\"nfInstanceId\":\"%s\",\"nfType\":\"AMF\",\"nfStatus\":\"REGISTERED\",\"ipv4Addresses\":[\"127.1.0.8\"],\"plmnList\":[{\"mcc\":\"001\",\"mnc\":\"01\"}]}", amf_id);
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/nf-instances/%s", base, amf_id);
    TK_ASSERT(nrf_call("PUT", url, G5C_JSON_TYPE, amf_body, NULL) == 201);
    free(amf_body);

    /* heart-beat: a PATCH that sets nfStatus (and here the load) */
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/nf-instances/%s", base, udm_id);
    TK_ASSERT(nrf_call("PATCH", url, "application/json-patch+json", "[{\"op\":\"replace\",\"path\":\"/nfStatus\",\"value\":\"REGISTERED\"},{\"op\":\"replace\",\"path\":\"/load\",\"value\":12}]", &rsp) / 100 == 2);
    if (rsp != NULL) {
        dump("nrf_NFProfile_heartbeat", rsp);
        g5c_json_free(rsp);
    }

    /* discovery as the AMF does it */
    snprintf(url, sizeof url, "%s/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF&service-names=nudm-sdm", base);
    TK_ASSERT(nrf_call("GET", url, NULL, NULL, &rsp) == 200);
    dump("nrf_SearchResult", rsp);
    g5c_json_free(rsp);

    /* access token for nudm-sdm of the UDM */
    snprintf(url, sizeof url, "%s/oauth2/token", base);
    body = g5c_xasprintf("grant_type=client_credentials&nfInstanceId=%s&nfType=AMF&targetNfType=UDM&scope=nudm-sdm", amf_id);
    TK_ASSERT(nrf_call("POST", url, "application/x-www-form-urlencoded", body, &rsp) == 200);
    dump("nrf_AccessTokenRsp", rsp);
    g5c_json_free(rsp);
    free(body);

    /* a query with an unsupported filter value gives the ProblemDetails of the NRF */
    snprintf(url, sizeof url, "%s/nnrf-disc/v1/nf-instances?requester-nf-type=AMF", base);
    if (nrf_call("GET", url, NULL, NULL, &rsp) >= 400 && rsp != NULL)
        dump("nrf_ProblemDetails", rsp);
    g5c_json_free(rsp);

    /* deregistration is what the notification receiver gets last */
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/nf-instances/%s", base, udm_id);
    TK_ASSERT(nrf_call("DELETE", url, NULL, NULL, NULL) == 204);
    usleep(500 * 1000);

    g5c_server_stop(cbs);
    g5c_server_stop(srv);
    nrf_destroy(n);
    g5c_nf_free(nf);
}

/* ---- UDR: the resources, the subscriptions and the notifications it sends ---- */

/* the consumer: /cb/<payload-name> receives a DataChangeNotify (an object) or an array of the other notifications; element 0 is dumped */
static void udr_cb(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_resp err;
    g5c_json *j = g5c_req_json(req, &err);
    const char *name = g5c_req_param(req, "n");
    (void)ctx;
    if (j != NULL && name != NULL)
        dump(name, g5c_json_is(j, G5C_J_ARRAY) ? g5c_json_at(j, 0) : j);
    g5c_json_free(j);
    g5c_resp_status(resp, 204);
}

static void wait_dump(const char *name)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s.json", dir, name);
    for (int i = 0; i < 400 && access(path, F_OK) != 0; i++)
        usleep(10000);
    TK_ASSERT(access(path, F_OK) == 0);
}

#define UDRSUB(...) g5c_xasprintf(__VA_ARGS__)

static void udr_payloads(void)
{
    g5c_udr_store *store = g5c_udr_store_memory();
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    udr_opts o;
    g5c_router *r, *cbr = g5c_router_new();
    g5c_server *srv, *cbs;
    char base[64], cb[96], *u, *loc = NULL, *b;
    g5c_json *v = NULL;
    memset(&o, 0, sizeof o);
    o.ext_open = true;
    o.client = cl;
    o.api_root = "http://udr.example:7790";
    g5c_router_route(cbr, "POST", "/cb/{n}", udr_cb, NULL);
    cbs = g5c_server_start(&cfg, cbr, NULL, 0);
    TK_ASSERT(cbs != NULL);
    snprintf(cb, sizeof cb, "http://127.0.0.1:%u/cb", g5c_server_port(cbs));
    r = g5c_udr_router_opts(store, &o);
    srv = g5c_server_start(&cfg, r, NULL, 0);
    TK_ASSERT(srv != NULL);
    snprintf(base, sizeof base, "http://127.0.0.1:%u/nudr-dr/v2", g5c_server_port(srv));

#define PUT_OK(path, body)                                                                                         \
    do {                                                                                                           \
        u = U(base, path);                                                                                         \
        TK_ASSERT(rq("PUT", u, body, false, NULL, NULL) < 300);                                                    \
        free(u);                                                                                                   \
    } while (0)

    /* subscription data: a subscription to the AM data of one subscriber, then a change of it */
    b = UDRSUB("{\"callbackReference\":\"%s/udr_DataChangeNotify\",\"ueId\":\"" SUPI "\",\"monitoredResourceUris\":[\"%s/subscription-data/" SUPI "/00101/provisioned-data/am-data\"],"
               "\"originalCallbackReference\":\"http://udm.example/cb\"}", cb, base);
    u = U(base, "/subscription-data/subs-to-notify");
    TK_ASSERT(rq("POST", u, b, false, &v, &loc) == 201 && loc != NULL);
    dump("udr_SubscriptionDataSubscriptions", v);
    g5c_json_free(v);
    free(u);
    free(b);
    free(loc);
    PUT_OK("/subscription-data/" SUPI "/00101/provisioned-data/am-data",
           "{\"gpsis\":[\"msisdn-12025550100\"],\"subscribedUeAmbr\":{\"uplink\":\"1 Gbps\",\"downlink\":\"2 Gbps\"},\"nssai\":{\"defaultSingleNssais\":[{\"sst\":1}]}}");
    wait_dump("udr_DataChangeNotify");
    PUT_OK("/subscription-data/" SUPI "/identity-data", "{\"supiList\":[\"" SUPI "\"],\"gpsiList\":[\"msisdn-12025550100\"]}");
    PUT_OK("/subscription-data/" SUPI "/00101/provisioned-data/smf-selection-subscription-data", "{\"subscribedSnssaiInfos\":{\"{\\\"sst\\\":1}\":{\"dnnInfos\":[{\"dnn\":\"internet\"}]}}}");
    PUT_OK("/subscription-data/" SUPI "/context-data/smf-registrations/1",
           "{\"smfInstanceId\":\"3f1a8c1e-8b8e-4b7e-9c0a-111111111111\",\"pduSessionId\":1,\"singleNssai\":{\"sst\":1},\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"}}");
    PUT_OK("/subscription-data/" SUPI "/context-data/amf-3gpp-access",
           "{\"amfInstanceId\":\"7a1d3b52-0a0e-4c3c-9d57-5b2a3f6f1a10\",\"deregCallbackUri\":\"http://amf.example/dereg\","
           "\"guami\":{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"amfId\":\"010203\"},\"ratType\":\"NR\"}");
    get_dump("udr_ProvisionedDataSets", base, "/subscription-data/" SUPI "/00101/provisioned-data");
    get_dump("udr_ContextDataSets", base, "/subscription-data/" SUPI "/context-data");
    get_dump("udr_SmfRegistration", base, "/subscription-data/" SUPI "/context-data/smf-registrations/1");
    get_dump("udr_Amf3GppAccessRegistration", base, "/subscription-data/" SUPI "/context-data/amf-3gpp-access");
    get_dump("udr_IdentityData", base, "/subscription-data/" SUPI "/identity-data");
    get_dump("udr_AccessAndMobilitySubscriptionData_by_gpsi", base, "/subscription-data/msisdn-12025550100/00101/provisioned-data/am-data");
    {   /* an SDM subscription created through POST, as the UDM does for a stateless deployment */
        u = U(base, "/subscription-data/" SUPI "/context-data/sdm-subscriptions");
        TK_ASSERT(rq("POST", u, "{\"nfInstanceId\":\"c22f4910-cc36-43e1-a33e-e213b6aba908\",\"callbackReference\":\"http://udm.example/sdm\","
                                 "\"monitoredResourceUris\":[\"/nudm-sdm/v2/" SUPI "/am-data\"]}", false, &v, NULL) == 201);
        dump("udr_SdmSubscription", v);
        g5c_json_free(v);
        free(u);
    }

    /* errors: ProblemDetails of 404, 400 and 412 */
    u = U(base, "/subscription-data/imsi-001019999999999/00101/provisioned-data/am-data");
    TK_ASSERT(rq("GET", u, NULL, false, &v, NULL) == 404);
    dump("udr_ProblemDetails_404", v);
    g5c_json_free(v);
    free(u);
    u = U(base, "/subscription-data/" SUPI "/authentication-data/authentication-subscription");
    TK_ASSERT(rq("PUT", u, "{\"sequenceNumber\":{}}", false, &v, NULL) == 400);
    dump("udr_ProblemDetails_400", v);
    g5c_json_free(v);
    {
        g5c_kv h = {"if-match", "\"ffff\""};
        g5c_resp rr;
        char err[160];
        TK_ASSERT(g5c_client_request(cl, "PUT", u, &h, 1, G5C_JSON_TYPE, "{\"authenticationMethod\":\"5G_AKA\"}", 33, &rr, err, sizeof err) == 0);
        /* no subscriber document yet: the precondition fails on an absent resource */
        TK_ASSERT(rr.status == 412);
        v = g5c_resp_parse_json(&rr);
        dump("udr_ProblemDetails_412", v);
        g5c_json_free(v);
        g5c_resp_free(&rr);
    }
    free(u);

    /* policy data */
    b = UDRSUB("{\"notificationUri\":\"%s/udr_PolicyDataChangeNotification\",\"notifId\":\"n-1\",\"monitoredResourceUris\":[\"%s/policy-data/ues/" SUPI "/operator-specific-data\"]}", cb, base);
    u = U(base, "/policy-data/subs-to-notify");
    TK_ASSERT(rq("POST", u, b, false, &v, NULL) == 201);
    dump("udr_PolicyDataSubscription", v);
    g5c_json_free(v);
    free(u);
    free(b);
    PUT_OK("/policy-data/ues/" SUPI "/operator-specific-data", "{\"g5c-policy\":{\"dataType\":\"object\",\"value\":{\"rfsp\":1}}}");
    wait_dump("udr_PolicyDataChangeNotification");

    /* exposure data */
    b = UDRSUB("{\"notificationUri\":\"%s/udr_ExposureDataChangeNotification\",\"monitoredResourceUris\":[\"%s/exposure-data/" SUPI "/access-and-mobility-data\"]}", cb, base);
    u = U(base, "/exposure-data/subs-to-notify");
    TK_ASSERT(rq("POST", u, b, false, &v, NULL) == 201);
    dump("udr_ExposureDataSubscription", v);
    g5c_json_free(v);
    free(u);
    free(b);
    PUT_OK("/exposure-data/" SUPI "/access-and-mobility-data", "{\"rfspIndex\":3}");
    wait_dump("udr_ExposureDataChangeNotification");

    /* application data: influence data and the generic subscription */
    b = UDRSUB("{\"notificationUri\":\"%s/udr_TrafficInfluDataNotif\",\"dnns\":[\"internet\"]}", cb);
    u = U(base, "/application-data/influenceData/subs-to-notify");
    TK_ASSERT(rq("POST", u, b, false, &v, NULL) == 201);
    dump("udr_TrafficInfluSub", v);
    g5c_json_free(v);
    free(u);
    free(b);
    PUT_OK("/application-data/influenceData/i1", "{\"afAppId\":\"app\",\"dnn\":\"internet\",\"supi\":\"" SUPI "\"}");
    wait_dump("udr_TrafficInfluDataNotif");
    b = UDRSUB("{\"notificationUri\":\"%s/udr_ApplicationDataChangeNotif\",\"dataFilters\":[{\"dataInd\":\"BDT\"}]}", cb);
    u = U(base, "/application-data/subs-to-notify");
    TK_ASSERT(rq("POST", u, b, false, &v, NULL) == 201);
    dump("udr_ApplicationDataSubs", v);
    g5c_json_free(v);
    free(u);
    free(b);
#undef PUT_OK
    g5c_server_stop(srv);
    g5c_router_free(r);
    g5c_udr_store_free(store);
    g5c_server_stop(cbs);
    g5c_router_free(cbr);
}

/* ---- NSSF: slice selection, NSSAI availability, subscriptions, notifications ---- */

static char *url_encode(const char *in)
{
    size_t n = strlen(in);
    char *o = g5c_xmalloc(n * 3 + 1), *w = o;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)in[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')
            *w++ = (char)c;
        else
            w += sprintf(w, "%%%02X", c);
    }
    *w = '\0';
    return o;
}

static void nssf_cb(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_resp err;
    g5c_json *j = g5c_req_json(req, &err);
    (void)ctx;
    if (j != NULL)
        dump("nssf_NssfEventNotification", j);
    g5c_json_free(j);
    g5c_resp_status(resp, 204);
}

static void nssf_payloads(void)
{
    static const char yaml[] =
        "nssf:\n"
        "  slices:\n"
        "    - { snssai: { sst: 1 }, nrf: 'http://nrf-a:7777', nsi_id: 'nsi-1', tais: [ { mcc: '001', mnc: '01', tac: '000001' } ] }\n"
        "    - { snssai: { sst: 1, sd: '000001' }, nrf: 'http://nrf-b:7777', restricted_for: [ '310-260' ] }\n"
        "    - { snssai: { sst: 2 }, nrf: 'http://nrf-c:7777' }\n"
        "  amf_sets:\n"
        "    - { id: '001-01-01-001', nrf: 'http://nrf:7777', amfs: [ amf-1 ], snssais: [ { sst: 1 }, { sst: 2 } ], return_candidates: true }\n"
        "  mappings:\n"
        "    - { home_plmn: '310-260', serving: { sst: 1 }, home: { sst: 9 } }\n";
    char err[200], sel[3000], base[96], cb[96], *e, *b;
    g5c_json *root = g5c_yaml_parse(yaml, sizeof yaml - 1, err, sizeof err), *v = NULL;
    nssf_cfg *c = nssf_cfg_parse(root, "001", "01", "http://nrf:7777", err, sizeof err);
    nssf *n;
    g5c_router *r, *cbr = g5c_router_new();
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_server *srv, *cbs;
    const char *tai = "{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"tac\":\"000001\"}";
    TK_ASSERT(c != NULL);
    g5c_json_free(root);
    g5c_router_route(cbr, "POST", "/cb", nssf_cb, NULL);
    cbs = g5c_server_start(&cfg, cbr, NULL, 0);
    TK_ASSERT(cbs != NULL);
    snprintf(cb, sizeof cb, "http://127.0.0.1:%u/cb", g5c_server_port(cbs));
    n = nssf_new(c, cl, NULL);
    TK_ASSERT(n != NULL && nssf_start(n, err, sizeof err) == 0);
    r = nssf_router(n);
    srv = g5c_server_start(&cfg, r, NULL, 0);
    TK_ASSERT(srv != NULL);
    snprintf(base, sizeof base, "http://127.0.0.1:%u", g5c_server_port(srv));

    /* registration, roaming registration, PDU session, UE configuration update, PDN connection */
    {
        static const struct {
            const char *name, *param, *json, *extra;
        } q[] = {
            {"nssf_AuthorizedNetworkSliceInfo", "slice-info-request-for-registration",
             "{\"requestedNssai\":[{\"sst\":1},{\"sst\":2},{\"sst\":7}],\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":1},\"defaultIndication\":true},"
             "{\"subscribedSnssai\":{\"sst\":2}}]}", NULL},
            {"nssf_AuthorizedNetworkSliceInfo_roaming", "slice-info-request-for-registration",
             "{\"requestedNssai\":[{\"sst\":1}],\"mappingOfNssai\":[{\"servingSnssai\":{\"sst\":1},\"homeSnssai\":{\"sst\":9}}],"
             "\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":9},\"defaultIndication\":true}]}", "&home-plmn-id=%7B%22mcc%22%3A%22310%22%2C%22mnc%22%3A%22260%22%7D"},
            {"nssf_AuthorizedNetworkSliceInfo_pdu", "slice-info-request-for-pdu-session", "{\"sNssai\":{\"sst\":1,\"sd\":\"000001\"},\"roamingIndication\":\"NON_ROAMING\"}", NULL},
            {"nssf_AuthorizedNetworkSliceInfo_cu", "slice-info-request-for-ue-cu",
             "{\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":1},\"defaultIndication\":true}],\"defaultConfiguredSnssaiInd\":true}", NULL},
            {"nssf_AuthorizedNetworkSliceInfo_pdn", "slice-info-request-for-pdn-connection", "[{\"sst\":9}]", "&home-plmn-id=%7B%22mcc%22%3A%22310%22%2C%22mnc%22%3A%22260%22%7D"},
        };
        for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
            char *pe = url_encode(q[i].json), *te = url_encode(tai);
            snprintf(sel, sizeof sel, "%s/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=amf-1&%s=%s&tai=%s%s", base, q[i].param, pe, te, q[i].extra ? q[i].extra : "");
            TK_ASSERT(rq("GET", sel, NULL, false, &v, NULL) == 200 && v != NULL);
            dump(q[i].name, v);
            g5c_json_free(v);
            free(pe);
            free(te);
        }
        {
            char *pe = url_encode("{\"sNssai\":{\"sst\":77},\"roamingIndication\":\"NON_ROAMING\"}");
            snprintf(sel, sizeof sel, "%s/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=amf-1&slice-info-request-for-pdu-session=%s", base, pe);
            free(pe);
            TK_ASSERT(rq("GET", sel, NULL, false, &v, NULL) == 403);
            dump("nssf_ProblemDetails_403", v);
            g5c_json_free(v);
            snprintf(sel, sizeof sel, "%s/nnssf-nsselection/v2/network-slice-information?nf-type=AMF", base);
            TK_ASSERT(rq("GET", sel, NULL, false, &v, NULL) == 400);
            dump("nssf_ProblemDetails_400", v);
            g5c_json_free(v);
        }
    }
    /* availability, a subscription, a change that is notified */
    e = g5c_xasprintf("%s/nnssf-nssaiavailability/v1/nssai-availability/subscriptions", base);
    b = g5c_xasprintf("{\"nfNssaiAvailabilityUri\":\"%s\",\"taiList\":[%s],\"event\":\"SNSSAI_STATUS_CHANGE_REPORT\",\"supportedFeatures\":\"7\"}", cb, tai);
    TK_ASSERT(rq("POST", e, b, false, &v, NULL) == 201);
    dump("nssf_NssfEventSubscriptionCreatedData", v);
    g5c_json_free(v);
    free(e);
    free(b);
    e = g5c_xasprintf("%s/nnssf-nssaiavailability/v1/nssai-availability/amf-1", base);
    b = g5c_xasprintf("{\"supportedNssaiAvailabilityData\":[{\"tai\":%s,\"supportedSnssaiList\":[{\"sst\":1},{\"sst\":1,\"sd\":\"000001\"},{\"sst\":2,\"wildcardSd\":true}]}],"
                      "\"amfSetId\":\"001-01-01-001\",\"supportedFeatures\":\"7\"}", tai);
    TK_ASSERT(rq("PUT", e, b, false, &v, NULL) == 200);
    dump("nssf_AuthorizedNssaiAvailabilityInfo", v);
    g5c_json_free(v);
    free(e);
    free(b);
    wait_dump("nssf_NssfEventNotification");
    g5c_server_stop(srv);
    g5c_router_free(r);
    nssf_destroy(n);
    g5c_server_stop(cbs);
    g5c_router_free(cbr);
}

/* ---- NEF: traffic influence, monitoring events, notifications ---- */

typedef struct {
    pthread_mutex_t mu;
    int n;
} nef_sink;

static void nef_cb(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    nef_sink *s = ctx;
    g5c_resp err;
    g5c_json *j = g5c_req_json(req, &err);
    if (j != NULL) {
        dump(g5c_json_get(j, "monitoringEventReports") != NULL ? "nef_MonitoringNotification" : "nef_TestNotification", j);
        pthread_mutex_lock(&s->mu);
        s->n++;
        pthread_mutex_unlock(&s->mu);
    }
    g5c_json_free(j);
    g5c_resp_status(resp, 204);
}

static void nef_udr_put(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_resp err;
    g5c_json *j = g5c_req_json(req, &err);
    (void)ctx;
    if (j != NULL)
        dump("nef_TrafficInfluData", j);
    g5c_json_free(j);
    g5c_resp_status(resp, 201);
}

static void nef_id_translation(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *o = g5c_json_new_obj();
    (void)ctx;
    (void)req;
    g5c_json_set_str(o, "supi", SUPI);
    g5c_resp_json(resp, 200, o);
    g5c_json_free(o);
}

static void nef_uecm(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *o = g5c_json_new_obj();
    (void)ctx;
    (void)req;
    g5c_json_set_str(o, "amfInstanceId", "3a29fd6c-cdee-41f1-a39b-af55908ebd32");
    g5c_resp_json(resp, 200, o);
    g5c_json_free(o);
}

static void nef_amf_create(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *o = g5c_json_new_obj();
    (void)ctx;
    (void)req;
    g5c_json_set_str(o, "subscriptionId", "1");
    g5c_resp_json(resp, 201, o);
    g5c_json_free(o);
}

static void nef_amf_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    g5c_resp_status(resp, 204);
}

static void bsf_payloads(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[200], base[96], url[300], *loc = NULL;
    g5c_json *root = g5c_yaml_parse("bsf: {}\n", 8, err, sizeof err), *v = NULL;
    bsf_cfg *c = bsf_cfg_parse(root, err, sizeof err);
    bsf *b;
    g5c_router *r;
    g5c_server *srv;
    static const char reg[] =
        "{\"supi\":\"imsi-001010000000001\",\"gpsi\":\"msisdn-491700000001\",\"ipv4Addr\":\"10.45.0.2\",\"ipv6Prefix\":\"2001:db8:1:2::/64\",\"dnn\":\"internet\","
        "\"snssai\":{\"sst\":1,\"sd\":\"000001\"},\"pcfFqdn\":\"pcf.example.org\",\"pcfIpEndPoints\":[{\"ipv4Address\":\"127.0.0.13\",\"transport\":\"TCP\",\"port\":7777}],"
        "\"pcfSmFqdn\":\"pcf-sm.example.org\",\"pcfId\":\"11111111-1111-4111-8111-111111111111\",\"recoveryTime\":\"2030-01-01T00:00:00Z\","
        "\"paraCom\":{\"supi\":\"imsi-001010000000001\",\"dnn\":\"internet\",\"snssai\":{\"sst\":1,\"sd\":\"000001\"}},\"bindLevel\":\"NF_INSTANCE\","
        "\"ipv4FrameRouteList\":[\"192.168.50.0/24\"],\"suppFeat\":\"1f\"}";
    TK_ASSERT(c != NULL);
    g5c_json_free(root);
    b = bsf_new(c, NULL);
    TK_ASSERT(b != NULL);
    r = bsf_router(b);
    srv = g5c_server_start(&cfg, r, NULL, 0);
    TK_ASSERT(srv != NULL);
    snprintf(base, sizeof base, "http://127.0.0.1:%u/nbsf-management/v1/pcfBindings", g5c_server_port(srv));
    /* register (201), discover (200), update (200), the existing binding for a combination (403), more than one match (400), a body that is wrong (400) */
    TK_ASSERT(rq("POST", base, reg, false, &v, &loc) == 201 && v != NULL && loc != NULL);
    dump("bsf_PcfBinding", v);
    g5c_json_free(v);
    snprintf(url, sizeof url, "%s?ipv4Addr=10.45.0.2&supp-feat=1f", base);
    TK_ASSERT(rq("GET", url, NULL, false, &v, NULL) == 200 && v != NULL);
    dump("bsf_PcfBinding_discovery", v);
    g5c_json_free(v);
    TK_ASSERT(rq("PATCH", loc, "{\"ipv4Addr\":\"10.45.0.3\",\"pcfFqdn\":\"pcf2.example.org\"}", false, &v, NULL) == 200 && v != NULL);
    dump("bsf_PcfBinding_updated", v);
    g5c_json_free(v);
    TK_ASSERT(rq("POST", base, "{\"supi\":\"imsi-001010000000009\",\"dnn\":\"internet\",\"snssai\":{\"sst\":1,\"sd\":\"000001\"},\"ipv4Addr\":\"10.45.0.9\",\"pcfFqdn\":\"pcf.example.org\","
                              "\"pcfSmFqdn\":\"other.example.org\",\"paraCom\":{\"supi\":\"imsi-001010000000001\",\"dnn\":\"internet\"},\"suppFeat\":\"4\"}", false, &v, NULL) == 403 && v != NULL);
    dump("bsf_ExtProblemDetails", v);
    g5c_json_free(v);
    TK_ASSERT(rq("POST", base, "{\"dnn\":\"internet\",\"snssai\":{\"sst\":2},\"ipv4Addr\":\"10.45.0.3\",\"pcfFqdn\":\"pcf.example.org\"}", false, &v, NULL) == 201);
    g5c_json_free(v);
    snprintf(url, sizeof url, "%s?ipv4Addr=10.45.0.3", base);
    TK_ASSERT(rq("GET", url, NULL, false, &v, NULL) == 400 && v != NULL);
    dump("bsf_ProblemDetails", v);
    g5c_json_free(v);
    TK_ASSERT(rq("POST", base, "{\"dnn\":\"internet\"}", false, &v, NULL) == 400 && v != NULL);
    dump("bsf_ProblemDetails_invalid", v);
    g5c_json_free(v);
    free(loc);
    g5c_server_stop(srv);
    g5c_router_free(r);
    bsf_destroy(b);
}

static void nef_payloads(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_router *peers = g5c_router_new(), *cbr = g5c_router_new(), *r;
    g5c_server *ps, *cbs, *srv;
    nef_sink sink;
    nef *n;
    nef_cfg *c;
    g5c_json *root, *v = NULL;
    char *y, err[200], base[96], peer[96], cb[96], *e, *b, *loc = NULL;
    memset(&sink, 0, sizeof sink);
    pthread_mutex_init(&sink.mu, NULL);
    g5c_router_route(peers, "PUT", "/nudr-dr/v1/application-data/influenceData/{id}", nef_udr_put, NULL);
    g5c_router_route(peers, "DELETE", "/nudr-dr/v1/application-data/influenceData/{id}", nef_amf_delete, NULL);
    g5c_router_route(peers, "GET", "/nudm-sdm/v2/{ueId}/id-translation-result", nef_id_translation, NULL);
    g5c_router_route(peers, "GET", "/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access", nef_uecm, NULL);
    g5c_router_route(peers, "POST", "/namf-evts/v1/subscriptions", nef_amf_create, NULL);
    g5c_router_route(peers, "DELETE", "/namf-evts/v1/subscriptions/{id}", nef_amf_delete, NULL);
    ps = g5c_server_start(&cfg, peers, NULL, 0);
    TK_ASSERT(ps != NULL);
    snprintf(peer, sizeof peer, "http://127.0.0.1:%u", g5c_server_port(ps));
    g5c_router_route(cbr, "POST", "/cb", nef_cb, &sink);
    cbs = g5c_server_start(&cfg, cbr, NULL, 0);
    TK_ASSERT(cbs != NULL);
    snprintf(cb, sizeof cb, "http://127.0.0.1:%u/cb", g5c_server_port(cbs));
    y = g5c_xasprintf("nef:\n  afs: [ { id: af1, no_auth: true, notify_hosts: ['127.0.0.1'] } ]\n  callback_uri: http://127.0.0.1:1\n  udr: { uri: '%s' }\n  udm: { uri: '%s' }\n  amf: { uri: '%s' }\n"
                      "  subscriptions: { notify_retries: 0 }\n", peer, peer, peer);
    root = g5c_yaml_parse(y, strlen(y), err, sizeof err);
    c = nef_cfg_parse(root, "001", "01", NULL, err, sizeof err);
    TK_ASSERT(c != NULL);
    g5c_json_free(root);
    free(y);
    n = nef_new(c, cl, NULL, NULL);
    TK_ASSERT(n != NULL && nef_start(n, err, sizeof err) == 0);
    r = nef_router(n);
    srv = g5c_server_start(&cfg, r, NULL, 0);
    TK_ASSERT(srv != NULL);
    snprintf(base, sizeof base, "http://127.0.0.1:%u", g5c_server_port(srv));

    /* traffic influence: a request for one UE with a test notification, one for any UE */
    e = g5c_xasprintf("%s/3gpp-traffic-influence/v1/af1/subscriptions", base);
    b = g5c_xasprintf("{\"afAppId\":\"app-1\",\"gpsi\":\"msisdn-491700000001\",\"dnn\":\"internet\",\"snssai\":{\"sst\":1,\"sd\":\"000001\"},"
                      "\"trafficRoutes\":[{\"dnai\":\"edge1\",\"routeProfId\":\"p1\"}],\"tfcCorrInd\":true,\"appReloInd\":true,\"suppFeat\":\"2\",\"requestTestNotification\":true,"
                      "\"subscribedEvents\":[\"UP_PATH_CHANGE\"],\"notificationDestination\":\"%s\",\"dnaiChgType\":\"EARLY\"}", cb);
    TK_ASSERT(rq("POST", e, b, false, &v, NULL) == 201);
    dump("nef_TrafficInfluSub", v);
    g5c_json_free(v);
    free(b);
    b = g5c_xasprintf("{\"trafficFilters\":[{\"flowId\":1,\"flowDescriptions\":[\"permit out ip from 10.0.0.1 to any\"]}],\"anyUeInd\":true}");
    TK_ASSERT(rq("POST", e, b, false, &v, NULL) == 201);
    g5c_json_free(v);
    free(b);
    TK_ASSERT(rq("POST", e, "{\"anyUeInd\":true}", false, &v, NULL) == 400);
    dump("nef_ProblemDetails_400", v);
    g5c_json_free(v);
    TK_ASSERT(rq("POST", e, "{\"afAppId\":\"a\",\"ipv4Addr\":\"10.0.0.7\"}", false, &v, NULL) == 501);
    dump("nef_ProblemDetails_501", v);
    g5c_json_free(v);
    free(e);

    /* monitoring: a subscription, then the AMF's report reaches the AF */
    e = g5c_xasprintf("%s/3gpp-monitoring-event/v1/af1/subscriptions", base);
    b = g5c_xasprintf("{\"externalId\":\"user1@example.com\",\"monitoringType\":\"LOSS_OF_CONNECTIVITY\",\"maximumNumberOfReports\":3,\"supportedFeatures\":\"601\","
                      "\"requestTestNotification\":true,\"notificationDestination\":\"%s\"}", cb);
    TK_ASSERT(rq("POST", e, b, false, &v, &loc) == 201 && loc != NULL);
    dump("nef_MonitoringEventSubscription", v);
    g5c_json_free(v);
    free(b);
    TK_ASSERT(rq("POST", e, "{\"externalId\":\"user1@example.com\",\"monitoringType\":\"ROAMING_STATUS\",\"maximumNumberOfReports\":1,\"supportedFeatures\":\"1f\",\"notificationDestination\":\"http://127.0.0.1:1/x\"}",
                 false, &v, NULL) == 500);
    dump("nef_ProblemDetails_500", v);
    g5c_json_free(v);
    free(e);
    {   /* the notification of the AMF */
        g5c_req req;
        g5c_resp resp;
        char *id = strrchr(loc, '/') + 1, path[160];
        snprintf(path, sizeof path, "/nnef-callback/v1/amf-events/%s", id);
        /* the correlation identifier is unknown to this peer: ask the NEF for it through its state is not possible, so notify with a wrong one and expect 403 */
        g5c_req_init(&req);
        req.method = g5c_xstrdup("POST");
        req.path = g5c_xstrdup(path);
        req.scheme = g5c_xstrdup("http");
        req.authority = g5c_xstrdup("nef.test:80");
        g5c_req_add_header(&req, "content-type", "application/json");
        g5c_req_set_body(&req, "{\"notifyCorrelationId\":\"x\",\"reportList\":[]}", strlen("{\"notifyCorrelationId\":\"x\",\"reportList\":[]}"));
        g5c_resp_init(&resp);
        g5c_router_dispatch(r, &req, &resp);
        TK_ASSERT(resp.status == 403);
        v = g5c_resp_parse_json(&resp);
        dump("nef_ProblemDetails_403", v);
        g5c_json_free(v);
        g5c_resp_free(&resp);
        g5c_req_free(&req);
    }
    free(loc);
    for (int i = 0; i < 400; i++) {
        pthread_mutex_lock(&sink.mu);
        int k = sink.n;
        pthread_mutex_unlock(&sink.mu);
        if (k >= 2)
            break;
        usleep(10000);
    }
    TK_ASSERT(sink.n >= 2); /* the two test notifications */
    g5c_server_stop(srv);
    g5c_router_free(r);
    nef_destroy(n);
    g5c_server_stop(cbs);
    g5c_server_stop(ps);
    g5c_router_free(cbr);
    g5c_router_free(peers);
}

int main(void)
{
    static const g5c_svc svcs[] = {{"nudm-ueau", "v1"}, {"nudm-sdm", "v2"}, {"nudm-uecm", "v1"}};
    g5c_json *prof;
    dir = getenv("G5C_PAYLOAD_DIR");
    if (dir == NULL || *dir == 0) {
        puts("dump_payloads: G5C_PAYLOAD_DIR not set, nothing to do");
        return 0;
    }
    g5c_log_init("error", false);
    cl = g5c_client_new(5000, NULL);
    identity_stack_payloads();
    udr_payloads();
    nssf_payloads();
    nef_payloads();
    bsf_payloads();
    pcf_payloads();
    nrf_payloads();
    prof = g5c_nrf_profile("c22f4910-cc36-43e1-a33e-e213b6aba908", "UDM", "127.1.0.1", 7773, "http", "001", "01", svcs, 3);
    dump("nrf_NFProfile", prof);
    g5c_json_free(prof);
    g5c_client_free(cl);
    puts("dump_payloads: done");
    return 0;
}
