/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The NSSF end to end, in process */
#define _DEFAULT_SOURCE
#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "g5c/nssf.h"
#include "g5c/testkit.h"

typedef struct {
    int status;
    g5c_json *json;
    char location[256], cause[64], accept_encoding[32];
} R;

static char *enc(const char *s)
{
    size_t n = strlen(s);
    char *o = g5c_xmalloc(n * 3 + 1), *p = o;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.')
            *p++ = (char)c;
        else
            p += sprintf(p, "%%%02X", c);
    }
    *p = '\0';
    return o;
}

static R rq_h(g5c_router *rt, const char *method, const char *target, const char *body, const char *ctype, const char *const *hdrs)
{
    g5c_req req;
    g5c_resp resp;
    const char *q = strchr(target, '?');
    R out;
    memset(&out, 0, sizeof out);
    g5c_req_init(&req);
    req.method = g5c_xstrdup(method);
    req.path = q ? g5c_xstrndup(target, (size_t)(q - target)) : g5c_xstrdup(target);
    req.query = q ? g5c_xstrdup(q + 1) : NULL;
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("nssf.test:80");
    if (body != NULL)
        g5c_req_add_header(&req, "content-type", ctype != NULL ? ctype : "application/json");
    for (size_t i = 0; hdrs != NULL && hdrs[i] != NULL; i += 2)
        g5c_req_add_header(&req, hdrs[i], hdrs[i + 1]);
    if (body != NULL)
        g5c_req_set_body(&req, body, strlen(body));
    g5c_resp_init(&resp);
    g5c_router_dispatch(rt, &req, &resp);
    out.status = resp.status;
    out.json = g5c_resp_parse_json(&resp);
    snprintf(out.location, sizeof out.location, "%s", g5c_resp_header_get(&resp, "location") ? g5c_resp_header_get(&resp, "location") : "");
    snprintf(out.accept_encoding, sizeof out.accept_encoding, "%s", g5c_resp_header_get(&resp, "accept-encoding") ? g5c_resp_header_get(&resp, "accept-encoding") : "");
    if (out.json != NULL && g5c_json_get_str(out.json, "cause") != NULL)
        snprintf(out.cause, sizeof out.cause, "%s", g5c_json_get_str(out.json, "cause"));
    g5c_resp_free(&resp);
    g5c_req_free(&req);
    return out;
}

static void done(R *r)
{
    g5c_json_free(r->json);
    r->json = NULL;
}

#define SEL "/nnssf-nsselection/v2/network-slice-information"
#define AV "/nnssf-nssaiavailability/v1/nssai-availability"
#define TAI1 "{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"tac\":\"000001\"}"
#define TAI2 "{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"tac\":\"000002\"}"

/* GET network-slice-information with the given JSON parameters (name, json pairs, NULL terminated) */
static R sel(g5c_router *rt, const char *nf_id, const char *const *params)
{
    char target[4096];
    size_t o = (size_t)snprintf(target, sizeof target, SEL "?nf-type=AMF&nf-id=%s", nf_id);
    for (size_t i = 0; params != NULL && params[i] != NULL; i += 2) {
        char *e = enc(params[i + 1]);
        o += (size_t)snprintf(target + o, sizeof target - o, "&%s=%s", params[i], e);
        free(e);
    }
    return rq_h(rt, "GET", target, NULL, NULL, NULL);
}

static const char CONFIG[] =
    "nssf:\n"
    "  slices:\n"
    "    - { snssai: { sst: 1 }, nrf: 'http://nrf-a:7777', nsi_id: 'nsi-1', tais: [ { mcc: '001', mnc: '01', tac: '000001' }, { mcc: '001', mnc: '01', tac: '000002' } ] }\n"
    "    - { snssai: { sst: 1, sd: '000001' }, nrf: 'http://nrf-b:7777', nrf_nfm: 'http://nrf-b:7777/nnrf-nfm/v1', restricted_for: [ '310-260' ], tais: [ { mcc: '001', mnc: '01', tac: '000001' } ] }\n"
    "    - { snssai: { sst: 2 }, nrf: 'http://nrf-c:7777', tac_ranges: [ { mcc: '001', mnc: '01', start: '000001', end: '00000f' } ] }\n"
    "    - { snssai: { sst: 3 } }\n"
    "  amf_sets:\n"
    "    - { id: '001-01-01-001', nrf: 'http://nrf:7777', amfs: [ amf-1, amf-2 ], snssais: [ { sst: 1 }, { sst: 2 } ], return_candidates: true }\n"
    "    - { id: '001-01-02-001', snssais: [ { sst: 1, sd: '000001' } ] }\n"
    "  mappings:\n"
    "    - { home_plmn: '310-260', serving: { sst: 1 }, home: { sst: 9 } }\n"
    "    - { home_plmn: '310-260', serving: { sst: 2 }, home: { sst: 8 } }\n";

static nssf *make(const char *yaml_extra, nssf_cfg **keep_unused)
{
    char *y = g5c_xasprintf("%s%s", CONFIG, yaml_extra != NULL ? yaml_extra : ""), err[200];
    g5c_json *root = g5c_yaml_parse(y, strlen(y), err, sizeof err);
    nssf_cfg *c;
    nssf *n;
    (void)keep_unused;
    if (root == NULL)
        TK_FAIL("yaml: %s", err);
    c = nssf_cfg_parse(root, "001", "01", "http://nrf:7777", err, sizeof err);
    if (c == NULL)
        TK_FAIL("config: %s", err);
    n = nssf_new(c, NULL, NULL);
    TK_ASSERT(n != NULL);
    g5c_json_free(root);
    free(y);
    return n;
}

static bool has_sn(const g5c_json *arr, int sst, const char *sd)
{
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const g5c_json *e = g5c_json_at(arr, i);
        int64_t s;
        const g5c_json *sn = g5c_json_get(e, "allowedSnssai") ? g5c_json_get(e, "allowedSnssai") : g5c_json_get(e, "configuredSnssai") ? g5c_json_get(e, "configuredSnssai") : e;
        const char *d = g5c_json_get_str(sn, "sd");
        if (g5c_json_get_int(sn, "sst", &s) && s == sst && ((sd == NULL && d == NULL) || (sd != NULL && d != NULL && strcasecmp(sd, d) == 0)))
            return true;
    }
    return false;
}

static const g5c_json *allowed(const g5c_json *out)
{
    return g5c_json_get(g5c_json_at(g5c_json_get(out, "allowedNssaiList"), 0), "allowedSnssaiList");
}

/* ---- slice selection ---- */

static void test_registration(void)
{
    nssf *n = make(NULL, NULL);
    g5c_router *r = nssf_router(n);
    R x;
    const char *p1[] = {"slice-info-request-for-registration",
                        "{\"requestedNssai\":[{\"sst\":1},{\"sst\":2}],\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":1},\"defaultIndication\":true},"
                        "{\"subscribedSnssai\":{\"sst\":2}},{\"subscribedSnssai\":{\"sst\":4}}]}",
                        "tai", TAI1, "supported-features", "0", NULL};
    const char *p2[] = {"slice-info-request-for-registration",
                        "{\"requestedNssai\":[{\"sst\":1},{\"sst\":5},{\"sst\":4}],\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":1},\"defaultIndication\":true},"
                        "{\"subscribedSnssai\":{\"sst\":4}}]}",
                        "tai", TAI1, NULL};
    const char *p3[] = {"slice-info-request-for-registration",
                        "{\"requestedNssai\":[{\"sst\":1,\"sd\":\"000001\"},{\"sst\":2}],\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":1,\"sd\":\"000001\"}},"
                        "{\"subscribedSnssai\":{\"sst\":2},\"defaultIndication\":true}]}",
                        "tai", TAI2, NULL};
    const char *p4[] = {"slice-info-request-for-registration",
                        "{\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":1},\"defaultIndication\":true},{\"subscribedSnssai\":{\"sst\":2}},"
                        "{\"subscribedSnssai\":{\"sst\":3},\"defaultIndication\":true}]}",
                        "tai", TAI1, NULL};
    const char *p5[] = {"slice-info-request-for-registration",
                        "{\"requestedNssai\":[{\"sst\":7}],\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":6},\"defaultIndication\":true}]}", "tai", TAI1, NULL};

    /* the requested slices the subscription permits and that exist here: allowed, each with the NRF of its network slice instance */
    x = sel(r, "amf-9", p1);
    TK_ASSERT(x.status == 200);
    TK_ASSERT(has_sn(allowed(x.json), 1, NULL) && has_sn(allowed(x.json), 2, NULL) && g5c_json_len(allowed(x.json)) == 2);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(g5c_json_at(allowed(x.json), 0), "nsiInformationList"), 0), "nrfId"), "http://nrf-a:7777/nnrf-disc/v1/nf-instances") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(g5c_json_at(allowed(x.json), 0), "nsiInformationList"), 0), "nsiId"), "nsi-1") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(x.json, "allowedNssaiList"), 0), "accessType"), "3GPP_ACCESS") == 0);
    TK_ASSERT(g5c_json_get(x.json, "rejectedNssaiInPlmn") == NULL && g5c_json_get(x.json, "configuredNssai") == NULL);
    /* an AMF that is not known: the configured set that supports the allowed S-NSSAIs, with its candidates and NRF */
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "targetAmfSet"), "001-01-01-001") == 0 && strcmp(g5c_json_get_str(x.json, "nrfAmfSet"), "http://nrf:7777/nnrf-disc/v1/nf-instances") == 0);
    TK_ASSERT(g5c_json_len(g5c_json_get(x.json, "candidateAmfList")) == 2);
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "supportedFeatures"), "0") == 0);
    done(&x);

    /* sst 5 is not subscribed and sst 4 does not exist here: both are rejected in the PLMN, and the Configured NSSAI is sent so that the UE can be fixed */
    x = sel(r, "amf-9", p2);
    TK_ASSERT(x.status == 200 && g5c_json_len(allowed(x.json)) == 1 && has_sn(allowed(x.json), 1, NULL));
    TK_ASSERT(has_sn(g5c_json_get(x.json, "rejectedNssaiInPlmn"), 5, NULL) && has_sn(g5c_json_get(x.json, "rejectedNssaiInPlmn"), 4, NULL));
    TK_ASSERT(g5c_json_len(g5c_json_get(x.json, "configuredNssai")) == 1 && has_sn(g5c_json_get(x.json, "configuredNssai"), 1, NULL));
    done(&x);

    /* a slice that exists, but not in this tracking area: rejected in the TA */
    x = sel(r, "amf-9", p3);
    TK_ASSERT(x.status == 200 && g5c_json_len(allowed(x.json)) == 1 && has_sn(allowed(x.json), 2, NULL));
    TK_ASSERT(has_sn(g5c_json_get(x.json, "rejectedNssaiInTa"), 1, "000001"));
    done(&x);

    /* no Requested NSSAI: the default subscribed S-NSSAIs (23.501 5.15.5.2.1), and the Configured NSSAI */
    x = sel(r, "amf-9", p4);
    TK_ASSERT(x.status == 200 && g5c_json_len(allowed(x.json)) == 2 && has_sn(allowed(x.json), 1, NULL) && has_sn(allowed(x.json), 3, NULL));
    TK_ASSERT(g5c_json_len(g5c_json_get(x.json, "configuredNssai")) == 3);
    TK_ASSERT(g5c_json_get(g5c_json_at(allowed(x.json), 1), "nsiInformationList") != NULL); /* sst 3 uses the NRF of the PLMN */
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(g5c_json_at(allowed(x.json), 1), "nsiInformationList"), 0), "nrfId"), "http://nrf:7777/nnrf-disc/v1/nf-instances") == 0);
    done(&x);

    /* nothing the PLMN can serve */
    x = sel(r, "amf-9", p5);
    TK_ASSERT(x.status == 403 && strcmp(x.cause, "SNSSAI_NOT_SUPPORTED") == 0);
    done(&x);
    g5c_router_free(r);
    nssf_destroy(n);
}

static void test_other_procedures(void)
{
    nssf *n = make(NULL, NULL);
    g5c_router *r = nssf_router(n);
    R x;
    const char *pdu[] = {"slice-info-request-for-pdu-session", "{\"sNssai\":{\"sst\":1,\"sd\":\"000001\"},\"roamingIndication\":\"NON_ROAMING\"}", "tai", TAI1, NULL};
    const char *pdu_ta[] = {"slice-info-request-for-pdu-session", "{\"sNssai\":{\"sst\":1,\"sd\":\"000001\"},\"roamingIndication\":\"NON_ROAMING\"}", "tai", TAI2, NULL};
    const char *pdu_no[] = {"slice-info-request-for-pdu-session", "{\"sNssai\":{\"sst\":77},\"roamingIndication\":\"LOCAL_BREAKOUT\"}", NULL};
    const char *pdu_ffffff[] = {"slice-info-request-for-pdu-session", "{\"sNssai\":{\"sst\":1,\"sd\":\"ffffff\"},\"roamingIndication\":\"NON_ROAMING\"}", NULL};
    const char *cu[] = {"slice-info-request-for-ue-cu",
                        "{\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":1},\"defaultIndication\":true},{\"subscribedSnssai\":{\"sst\":2}}],"
                        "\"defaultConfiguredSnssaiInd\":true}",
                        "tai", TAI1, NULL};
    const char *pdn[] = {"slice-info-request-for-pdn-connection", "[{\"sst\":9},{\"sst\":8},{\"sst\":7}]", "home-plmn-id", "{\"mcc\":\"310\",\"mnc\":\"260\"}", NULL};
    const char *pdn_no[] = {"slice-info-request-for-pdn-connection", "[{\"sst\":7}]", "home-plmn-id", "{\"mcc\":\"310\",\"mnc\":\"260\"}", NULL};

    /* PDU session establishment: the NRF (and NSI) of the network slice instance; the slice with sd FFFFFF is the slice without sd */
    x = sel(r, "amf-1", pdu);
    TK_ASSERT(x.status == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(x.json, "nsiInformation"), "nrfId"), "http://nrf-b:7777/nnrf-disc/v1/nf-instances") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(x.json, "nsiInformation"), "nrfNfMgtUri"), "http://nrf-b:7777/nnrf-nfm/v1") == 0);
    done(&x);
    x = sel(r, "amf-1", pdu_ffffff);
    TK_ASSERT(x.status == 200 && strcmp(g5c_json_get_str(g5c_json_get(x.json, "nsiInformation"), "nrfId"), "http://nrf-a:7777/nnrf-disc/v1/nf-instances") == 0);
    done(&x);
    x = sel(r, "amf-1", pdu_ta);
    TK_ASSERT(x.status == 403 && strcmp(x.cause, "SNSSAI_NOT_SUPPORTED") == 0);
    done(&x);
    x = sel(r, "amf-1", pdu_no);
    TK_ASSERT(x.status == 403 && strcmp(x.cause, "SNSSAI_NOT_SUPPORTED") == 0);
    done(&x);

    /* UE configuration update: the Allowed and the Configured NSSAI */
    x = sel(r, "amf-1", cu);
    TK_ASSERT(x.status == 200 && g5c_json_len(allowed(x.json)) == 1 && has_sn(allowed(x.json), 1, NULL));
    TK_ASSERT(g5c_json_len(g5c_json_get(x.json, "configuredNssai")) == 2);
    TK_ASSERT(g5c_json_get(x.json, "targetAmfSet") == NULL);
    done(&x);

    /* PDN connection establishment (RSIPCE): the serving S-NSSAI of the subscribed home ones */
    x = sel(r, "smf-1", pdn);
    TK_ASSERT(x.status == 200 && g5c_json_len(g5c_json_get(x.json, "mappingOfNssai")) == 2);
    done(&x);
    x = sel(r, "smf-1", pdn_no);
    TK_ASSERT(x.status == 403);
    done(&x);
    g5c_router_free(r);
    nssf_destroy(n);
}

static void test_roaming(void)
{
    nssf *n = make(NULL, NULL);
    g5c_router *r = nssf_router(n);
    R x;
    const char *reg[] = {"slice-info-request-for-registration",
                         "{\"requestedNssai\":[{\"sst\":1}],\"mappingOfNssai\":[{\"servingSnssai\":{\"sst\":1},\"homeSnssai\":{\"sst\":9}}],"
                         "\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":9},\"defaultIndication\":true},{\"subscribedSnssai\":{\"sst\":8}}]}",
                         "home-plmn-id", "{\"mcc\":\"310\",\"mnc\":\"260\"}", "tai", TAI1, NULL};
    const char *regbad[] = {"slice-info-request-for-registration",
                            "{\"requestedNssai\":[{\"sst\":1}],\"mappingOfNssai\":[{\"servingSnssai\":{\"sst\":1},\"homeSnssai\":{\"sst\":5}}],"
                            "\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":9},\"defaultIndication\":true}]}",
                            "home-plmn-id", "{\"mcc\":\"310\",\"mnc\":\"260\"}", "tai", TAI1, NULL};
    const char *map[] = {"slice-info-request-for-registration", "{\"sNssaiForMapping\":[{\"sst\":9},{\"sst\":77}],\"requestMapping\":true}", "home-plmn-id",
                         "{\"mcc\":\"310\",\"mnc\":\"260\"}", NULL};
    const char *mapno[] = {"slice-info-request-for-registration", "{\"sNssaiForMapping\":[{\"sst\":77}],\"requestMapping\":true}", "home-plmn-id",
                           "{\"mcc\":\"310\",\"mnc\":\"260\"}", NULL};
    x = sel(r, "amf-9", reg);
    TK_ASSERT(x.status == 200 && g5c_json_len(allowed(x.json)) == 1);
    TK_ASSERT(g5c_json_get(g5c_json_at(allowed(x.json), 0), "mappedHomeSnssai") != NULL);
    TK_ASSERT(has_sn(g5c_json_get(x.json, "mappingOfNssai"), 1, NULL) || g5c_json_len(g5c_json_get(x.json, "mappingOfNssai")) == 1);
    done(&x);
    x = sel(r, "amf-9", regbad); /* the mapped home S-NSSAI is not subscribed */
    TK_ASSERT(x.status == 200 && has_sn(allowed(x.json), 1, NULL) && has_sn(g5c_json_get(x.json, "rejectedNssaiInPlmn"), 1, NULL) == false);
    done(&x);
    x = sel(r, "amf-9", map);
    TK_ASSERT(x.status == 200 && g5c_json_len(allowed(x.json)) == 1 && g5c_json_len(g5c_json_get(x.json, "mappingOfNssai")) == 1);
    done(&x);
    x = sel(r, "amf-9", mapno);
    TK_ASSERT(x.status == 403);
    done(&x);
    g5c_router_free(r);
    nssf_destroy(n);
}

static void test_policy_and_errors(void)
{
    nssf *n = make("  policy: { include_subscribed: true, max_allowed: 2 }\n", NULL);
    g5c_router *r = nssf_router(n);
    R x;
    const char *p[] = {"slice-info-request-for-registration",
                       "{\"requestedNssai\":[{\"sst\":1}],\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":1},\"defaultIndication\":true},"
                       "{\"subscribedSnssai\":{\"sst\":2}},{\"subscribedSnssai\":{\"sst\":3}}]}",
                       "tai", TAI1, NULL};
    char target[256];
    /* the local policy adds the subscribed S-NSSAIs that were not requested, up to the limit */
    x = sel(r, "amf-9", p);
    TK_ASSERT(x.status == 200 && g5c_json_len(allowed(x.json)) == 2 && has_sn(allowed(x.json), 1, NULL));
    done(&x);
    /* malformed requests */
    x = rq_h(r, "GET", SEL, NULL, NULL, NULL);
    TK_ASSERT(x.status == 400 && strcmp(x.cause, "MANDATORY_QUERY_PARAM_MISSING") == 0);
    done(&x);
    x = rq_h(r, "GET", SEL "?nf-type=AMF&nf-id=a", NULL, NULL, NULL);
    TK_ASSERT(x.status == 400);
    done(&x);
    snprintf(target, sizeof target, SEL "?nf-type=amf%%3B&nf-id=a&slice-info-request-for-registration=%%7B%%7D");
    x = rq_h(r, "GET", target, NULL, NULL, NULL);
    TK_ASSERT(x.status == 400);
    done(&x);
    snprintf(target, sizeof target, SEL "?nf-type=AMF&nf-id=a&slice-info-request-for-registration=%%7Bnot");
    x = rq_h(r, "GET", target, NULL, NULL, NULL);
    TK_ASSERT(x.status == 400);
    done(&x);
    {
        const char *two[] = {"slice-info-request-for-registration", "{}", "slice-info-request-for-pdu-session", "{\"sNssai\":{\"sst\":1},\"roamingIndication\":\"NON_ROAMING\"}", NULL};
        const char *badsn[] = {"slice-info-request-for-pdu-session", "{\"sNssai\":{\"sst\":300},\"roamingIndication\":\"NON_ROAMING\"}", NULL};
        const char *nomember[] = {"slice-info-request-for-pdu-session", "{\"sNssai\":{\"sst\":1}}", NULL};
        const char *badtai[] = {"slice-info-request-for-registration", "{}", "tai", "{\"tac\":\"1\"}", NULL};
        x = sel(r, "amf-9", two);
        TK_ASSERT(x.status == 400);
        done(&x);
        x = sel(r, "amf-9", badsn);
        TK_ASSERT(x.status == 400);
        done(&x);
        x = sel(r, "amf-9", nomember);
        TK_ASSERT(x.status == 400);
        done(&x);
        x = sel(r, "amf-9", badtai);
        TK_ASSERT(x.status == 400);
        done(&x);
    }
    g5c_router_free(r);
    nssf_destroy(n);
}

/* ---- NSSAI availability ---- */

#define AVAIL_AMF1                                                                                                                            \
    "{\"supportedNssaiAvailabilityData\":[{\"tai\":" TAI1 ",\"supportedSnssaiList\":[{\"sst\":1},{\"sst\":1,\"sd\":\"000001\"},{\"sst\":5}]}],"       \
    "\"amfSetId\":\"001-01-01-001\",\"supportedFeatures\":\"7\"}"

static void test_availability(void)
{
    nssf *n = make(NULL, NULL);
    g5c_router *r = nssf_router(n);
    R x;
    const g5c_json *a;
    /* what the NSSF authorizes: the slices that exist in the tracking area (sst 5 does not exist), restricted for the roamers of the PLMNs the slice names */
    x = rq_h(r, "PUT", AV "/amf-1", AVAIL_AMF1, NULL, NULL);
    TK_ASSERT(x.status == 200);
    a = g5c_json_at(g5c_json_get(x.json, "authorizedNssaiAvailabilityData"), 0);
    TK_ASSERT(g5c_json_len(g5c_json_get(a, "supportedSnssaiList")) == 2 && has_sn(g5c_json_get(a, "supportedSnssaiList"), 1, NULL) &&
              has_sn(g5c_json_get(a, "supportedSnssaiList"), 1, "000001"));
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(g5c_json_at(g5c_json_get(a, "restrictedSnssaiList"), 0), "homePlmnId"), "mcc"), "310") == 0);
    TK_ASSERT(has_sn(g5c_json_get(g5c_json_at(g5c_json_get(a, "restrictedSnssaiList"), 0), "sNssaiList"), 1, "000001"));
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "supportedFeatures"), "7") == 0 && nssf_nf_count(n) == 1);
    done(&x);
    /* nothing authorized in the area: 204 */
    x = rq_h(r, "PUT", AV "/amf-2", "{\"supportedNssaiAvailabilityData\":[{\"tai\":" TAI1 ",\"supportedSnssaiList\":[{\"sst\":5}]}]}", NULL, NULL);
    TK_ASSERT(x.status == 204);
    done(&x);
    /* wildcard SD and SD ranges cover the configured slices */
    x = rq_h(r, "PUT", AV "/amf-3", "{\"supportedNssaiAvailabilityData\":[{\"tai\":" TAI1 ",\"supportedSnssaiList\":[{\"sst\":1,\"wildcardSd\":true}]}]}", NULL, NULL);
    TK_ASSERT(x.status == 200 && g5c_json_len(g5c_json_get(g5c_json_at(g5c_json_get(x.json, "authorizedNssaiAvailabilityData"), 0), "supportedSnssaiList")) == 2);
    done(&x);
    x = rq_h(r, "PUT", AV "/amf-3", "{\"supportedNssaiAvailabilityData\":[{\"tai\":" TAI1 ",\"supportedSnssaiList\":[{\"sst\":1,\"sdRanges\":[{\"start\":\"000000\",\"end\":\"0000ff\"}]}]}]}", NULL, NULL);
    TK_ASSERT(x.status == 200);
    a = g5c_json_get(g5c_json_at(g5c_json_get(x.json, "authorizedNssaiAvailabilityData"), 0), "supportedSnssaiList");
    TK_ASSERT(g5c_json_len(a) == 1 && has_sn(a, 1, "000001"));
    done(&x);
    /* a tracking area list and a TAC range: one entry for each area, one for the range */
    x = rq_h(r, "PUT", AV "/amf-4",
             "{\"supportedNssaiAvailabilityData\":[{\"tai\":" TAI1 ",\"taiList\":[" TAI2 "],\"taiRangeList\":[{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},"
             "\"tacRangeList\":[{\"start\":\"000003\",\"end\":\"000005\"}]}],\"supportedSnssaiList\":[{\"sst\":2}]}]}", NULL, NULL);
    TK_ASSERT(x.status == 200 && g5c_json_len(g5c_json_get(x.json, "authorizedNssaiAvailabilityData")) == 3);
    done(&x);

    /* the AMF that reported is now known to the selection: it stays when it supports what is allowed, its own set is the target */
    {
        const char *p[] = {"slice-info-request-for-registration", "{\"requestedNssai\":[{\"sst\":1}],\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":1}}]}", "tai", TAI1, NULL};
        x = sel(r, "amf-1", p);
        TK_ASSERT(x.status == 200 && strcmp(g5c_json_get_str(x.json, "targetAmfSet"), "001-01-01-001") == 0);
        done(&x);
        x = sel(r, "amf-2", p); /* amf-2 reported nothing it supports there: another set is the target */
        TK_ASSERT(x.status == 200 && g5c_json_get_str(x.json, "targetAmfSet") != NULL);
        done(&x);
    }

    /* patch */
    x = rq_h(r, "PATCH", AV "/amf-1", "[{\"op\":\"replace\",\"path\":\"/supportedNssaiAvailabilityData/0/supportedSnssaiList\",\"value\":[{\"sst\":1}]}]", "application/json-patch+json", NULL);
    TK_ASSERT(x.status == 200 && g5c_json_len(g5c_json_get(g5c_json_at(g5c_json_get(x.json, "authorizedNssaiAvailabilityData"), 0), "supportedSnssaiList")) == 1);
    done(&x);
    x = rq_h(r, "PATCH", AV "/amf-1", "[{\"op\":\"remove\",\"path\":\"/supportedNssaiAvailabilityData\"}]", "application/json-patch+json", NULL);
    TK_ASSERT(x.status == 400); /* the document would no longer be valid; nothing changed */
    done(&x);
    x = rq_h(r, "PATCH", AV "/amf-1", "[{\"op\":\"replace\",\"path\":\"/nope\",\"value\":1}]", "application/json-patch+json", NULL);
    TK_ASSERT(x.status == 400);
    done(&x);
    x = rq_h(r, "PATCH", AV "/nobody", "[{\"op\":\"remove\",\"path\":\"/amfSetId\"}]", "application/json-patch+json", NULL);
    TK_ASSERT(x.status == 404);
    done(&x);

    /* refusals */
    x = rq_h(r, "PUT", AV "/amf-5", "{\"supportedNssaiAvailabilityData\":[]}", NULL, NULL);
    TK_ASSERT(x.status == 400);
    done(&x);
    x = rq_h(r, "PUT", AV "/amf-5", "{\"supportedNssaiAvailabilityData\":[{\"tai\":" TAI1 ",\"supportedSnssaiList\":[{\"sst\":999}]}]}", NULL, NULL);
    TK_ASSERT(x.status == 400);
    done(&x);
    x = rq_h(r, "PUT", AV "/amf-5", "{not json", NULL, NULL);
    TK_ASSERT(x.status == 400);
    done(&x);
    {
        const char *h[] = {"content-encoding", "gzip", NULL};
        x = rq_h(r, "PUT", AV "/amf-5", AVAIL_AMF1, NULL, h);
        TK_ASSERT(x.status == 415);
        done(&x);
    }
    x = rq_h(r, "PUT", AV "/bad%20id", AVAIL_AMF1, NULL, NULL);
    TK_ASSERT(x.status == 400);
    done(&x);

    /* delete, options */
    x = rq_h(r, "DELETE", AV "/amf-3", NULL, NULL, NULL);
    TK_ASSERT(x.status == 204);
    done(&x);
    x = rq_h(r, "DELETE", AV "/amf-3", NULL, NULL, NULL);
    TK_ASSERT(x.status == 404);
    done(&x);
    x = rq_h(r, "OPTIONS", AV, NULL, NULL, NULL);
    TK_ASSERT(x.status == 200 && x.accept_encoding[0] != '\0');
    done(&x);
    g5c_router_free(r);
    nssf_destroy(n);
}

/* ---- subscriptions and notifications ---- */

typedef struct {
    pthread_mutex_t mu;
    g5c_json *items[32];
    size_t n;
    int answer;
    size_t calls;
} sink_t;

static void cb_handler(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    sink_t *s = ctx;
    g5c_json *j = g5c_req_json(req, resp);
    pthread_mutex_lock(&s->mu);
    s->calls++;
    if (j != NULL && s->n < 32)
        s->items[s->n++] = j;
    else
        g5c_json_free(j);
    pthread_mutex_unlock(&s->mu);
    g5c_resp_init(resp);
    g5c_resp_status(resp, s->answer);
}

static const g5c_json *wait_item(sink_t *s, size_t idx, int ms)
{
    for (int i = 0; i < ms / 5; i++) {
        pthread_mutex_lock(&s->mu);
        if (s->n > idx) {
            const g5c_json *j = s->items[idx];
            pthread_mutex_unlock(&s->mu);
            return j;
        }
        pthread_mutex_unlock(&s->mu);
        usleep(5000);
    }
    return NULL;
}

static size_t count(sink_t *s)
{
    size_t c;
    pthread_mutex_lock(&s->mu);
    c = s->n;
    pthread_mutex_unlock(&s->mu);
    return c;
}

static void test_subscriptions(void)
{
    sink_t sink;
    g5c_router *cbr = g5c_router_new();
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_server *srv;
    char cb[96], *body, sid[64], sid2[64], err[200];
    g5c_client *client = g5c_client_new(2000, NULL);
    nssf *n;
    g5c_router *r;
    g5c_json *root;
    nssf_cfg *c;
    R x;
    const g5c_json *m;
    memset(&sink, 0, sizeof sink);
    pthread_mutex_init(&sink.mu, NULL);
    sink.answer = 204;
    g5c_router_route(cbr, "POST", "/cb", cb_handler, &sink);
    srv = g5c_server_start(&cfg, cbr, NULL, 0);
    TK_ASSERT(srv != NULL);
    snprintf(cb, sizeof cb, "http://127.0.0.1:%u/cb", g5c_server_port(srv));
    {
        char *y = g5c_xasprintf("%s  subscriptions: { max: 3, notify_retries: 0 }\n", CONFIG);
        root = g5c_yaml_parse(y, strlen(y), err, sizeof err);
        free(y);
    }
    c = nssf_cfg_parse(root, "001", "01", "http://nrf:7777", err, sizeof err);
    TK_ASSERT(c != NULL);
    g5c_json_free(root);
    n = nssf_new(c, client, NULL);
    TK_ASSERT(nssf_start(n, err, sizeof err) == 0);
    r = nssf_router(n);

    /* one subscription for tracking area 1 without EANAN, one for the same area with EANAN */
    body = g5c_xasprintf("{\"nfNssaiAvailabilityUri\":\"%s\",\"taiList\":[" TAI1 "],\"event\":\"SNSSAI_STATUS_CHANGE_REPORT\",\"expiry\":\"2099-01-01T00:00:00Z\"}", cb);
    x = rq_h(r, "POST", AV "/subscriptions", body, NULL, NULL);
    free(body);
    TK_ASSERT(x.status == 201 && strstr(x.location, "/nssai-availability/subscriptions/") != NULL);
    snprintf(sid, sizeof sid, "%s", g5c_json_get_str(x.json, "subscriptionId"));
    TK_ASSERT(strcmp(g5c_json_get_str(x.json, "expiry"), "2099-01-01T00:00:00Z") != 0); /* the NSSF bounds it */
    TK_ASSERT(g5c_json_get(x.json, "authorizedNssaiAvailabilityData") == NULL); /* no AMF has reported anything yet */
    done(&x);
    body = g5c_xasprintf("{\"nfNssaiAvailabilityUri\":\"%s\",\"taiList\":[" TAI1 "],\"event\":\"SNSSAI_STATUS_CHANGE_REPORT\",\"supportedFeatures\":\"7\"}", cb);
    x = rq_h(r, "POST", AV "/subscriptions", body, NULL, NULL);
    free(body);
    TK_ASSERT(x.status == 201);
    snprintf(sid2, sizeof sid2, "%s", g5c_json_get_str(x.json, "subscriptionId"));
    done(&x);
    TK_ASSERT(nssf_subscription_count(n) == 2);

    /* an AMF reports: both are told what is authorized in their area */
    x = rq_h(r, "PUT", AV "/amf-1", AVAIL_AMF1, NULL, NULL);
    TK_ASSERT(x.status == 200);
    done(&x);
    TK_ASSERT(wait_item(&sink, 1, 3000) != NULL);
    m = wait_item(&sink, 0, 100);
    TK_ASSERT(g5c_json_len(g5c_json_get(m, "authorizedNssaiAvailabilityData")) == 1 && g5c_json_get_str(m, "subscriptionId") != NULL);
    /* the same report again changes nothing: no notification */
    x = rq_h(r, "PUT", AV "/amf-1", AVAIL_AMF1, NULL, NULL);
    done(&x);
    usleep(300000);
    TK_ASSERT(count(&sink) == 2);
    /* a second AMF adds a slice (sst 2) in the area: a notification with the whole new state */
    x = rq_h(r, "PUT", AV "/amf-2", "{\"supportedNssaiAvailabilityData\":[{\"tai\":" TAI1 ",\"supportedSnssaiList\":[{\"sst\":2}]}]}", NULL, NULL);
    done(&x);
    TK_ASSERT(wait_item(&sink, 3, 3000) != NULL);
    TK_ASSERT(g5c_json_len(g5c_json_get(g5c_json_at(g5c_json_get(wait_item(&sink, 2, 10), "authorizedNssaiAvailabilityData"), 0), "supportedSnssaiList")) == 3);
    /* both AMFs go: the subscription that asked for EANAN gets an empty array, the other is not told */
    x = rq_h(r, "DELETE", AV "/amf-1", NULL, NULL, NULL);
    done(&x);
    x = rq_h(r, "DELETE", AV "/amf-2", NULL, NULL, NULL);
    done(&x);
    TK_ASSERT(wait_item(&sink, 5, 3000) != NULL || wait_item(&sink, 4, 3000) != NULL);
    usleep(300000);
    {
        size_t empties = 0, n_items = count(&sink);
        for (size_t i = 4; i < n_items; i++)
            if (g5c_json_len(g5c_json_get(wait_item(&sink, i, 10), "authorizedNssaiAvailabilityData")) == 0)
                empties++;
        TK_ASSERT(empties >= 1);
    }

    /* modification (SUMOD), the event cannot change */
    {
        char path[256];
        snprintf(path, sizeof path, AV "/subscriptions/%s", sid);
        x = rq_h(r, "PATCH", path, "[{\"op\":\"replace\",\"path\":\"/taiList\",\"value\":[" TAI2 "]}]", "application/json-patch+json", NULL);
        TK_ASSERT(x.status == 200 && strcmp(g5c_json_get_str(x.json, "subscriptionId"), sid) == 0);
        done(&x);
        x = rq_h(r, "PATCH", path, "[{\"op\":\"replace\",\"path\":\"/event\",\"value\":\"OTHER\"}]", "application/json-patch+json", NULL);
        TK_ASSERT(x.status == 400);
        done(&x);
        x = rq_h(r, "PATCH", AV "/subscriptions/nope", "[{\"op\":\"remove\",\"path\":\"/expiry\"}]", "application/json-patch+json", NULL);
        TK_ASSERT(x.status == 404);
        done(&x);
        x = rq_h(r, "DELETE", path, NULL, NULL, NULL);
        TK_ASSERT(x.status == 204);
        done(&x);
        x = rq_h(r, "DELETE", path, NULL, NULL, NULL);
        TK_ASSERT(x.status == 404);
        done(&x);
    }
    /* refusals: no tracking area, a notification URI that is not a URI, the limit */
    body = g5c_xasprintf("{\"nfNssaiAvailabilityUri\":\"%s\",\"taiList\":[],\"event\":\"SNSSAI_STATUS_CHANGE_REPORT\"}", cb);
    x = rq_h(r, "POST", AV "/subscriptions", body, NULL, NULL);
    free(body);
    TK_ASSERT(x.status == 400);
    done(&x);
    x = rq_h(r, "POST", AV "/subscriptions", "{\"nfNssaiAvailabilityUri\":\"ftp://x\",\"taiList\":[" TAI1 "],\"event\":\"SNSSAI_STATUS_CHANGE_REPORT\"}", NULL, NULL);
    TK_ASSERT(x.status == 400);
    done(&x);
    for (int i = 0; i < 3; i++) {
        body = g5c_xasprintf("{\"nfNssaiAvailabilityUri\":\"%s\",\"taiList\":[" TAI1 "],\"event\":\"SNSSAI_STATUS_CHANGE_REPORT\"}", cb);
        x = rq_h(r, "POST", AV "/subscriptions", body, NULL, NULL);
        free(body);
        TK_ASSERT(x.status == (i < 2 ? 201 : 429)); /* one subscription is left of the three */
        done(&x);
    }
    (void)sid2;
    g5c_router_free(r);
    nssf_destroy(n);
    g5c_client_free(client);
    g5c_server_stop(srv);
    g5c_router_free(cbr);
    for (size_t i = 0; i < sink.n; i++)
        g5c_json_free(sink.items[i]);
}

/* ---- the state file ---- */

static void test_state(void)
{
    char path[] = "/tmp/g5c-nssf-XXXXXX", err[200], *extra;
    int fd = mkstemp(path);
    nssf *n;
    g5c_router *r;
    R x;
    TK_ASSERT(fd >= 0);
    close(fd);
    unlink(path);
    extra = g5c_xasprintf("  state_file: %s\n", path);
    n = make(extra, NULL);
    TK_ASSERT(nssf_start(n, err, sizeof err) == 0);
    r = nssf_router(n);
    x = rq_h(r, "PUT", AV "/amf-1", AVAIL_AMF1, NULL, NULL);
    TK_ASSERT(x.status == 200);
    done(&x);
    x = rq_h(r, "POST", AV "/subscriptions", "{\"nfNssaiAvailabilityUri\":\"http://127.0.0.1:9/cb\",\"taiList\":[" TAI1 "],\"event\":\"SNSSAI_STATUS_CHANGE_REPORT\"}", NULL, NULL);
    TK_ASSERT(x.status == 201);
    done(&x);
    g5c_router_free(r);
    nssf_destroy(n);

    n = make(extra, NULL); /* a new process reads what the last one wrote */
    TK_ASSERT(nssf_start(n, err, sizeof err) == 0);
    TK_ASSERT(nssf_nf_count(n) == 1 && nssf_subscription_count(n) == 1);
    r = nssf_router(n);
    {
        const char *p[] = {"slice-info-request-for-registration", "{\"requestedNssai\":[{\"sst\":1}],\"subscribedNssai\":[{\"subscribedSnssai\":{\"sst\":1}}]}", "tai", TAI1, NULL};
        x = sel(r, "amf-1", p);
        TK_ASSERT(x.status == 200 && strcmp(g5c_json_get_str(x.json, "targetAmfSet"), "001-01-01-001") == 0); /* amf-1 is remembered with its set */
        done(&x);
    }
    g5c_router_free(r);
    nssf_destroy(n);
    unlink(path);
    free(extra);
    /* an unwritable location is a start-up error */
    extra = g5c_xasprintf("  state_file: /nonexistent-dir/deeper/nssf.json\n");
    n = make(extra, NULL);
    TK_ASSERT(nssf_start(n, err, sizeof err) != 0 && err[0] != '\0');
    nssf_destroy(n);
    free(extra);
}

/* ---- configuration ---- */

static void test_config(void)
{
    static const struct {
        const char *yaml, *want;
    } bad[] = {
        {"nssf: {}\n", "nssf.slices"},
        {"x: 1\n", "nssf"},
        {"nssf:\n  slices: [ { snssai: { sst: 300 } } ]\n", "nssf.slices[0].snssai"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 }, nrf: 'ftp://x' } ]\n", "nssf.slices[0].nrf"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 }, surprise: 1 } ]\n", "nssf.slices[0]"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 } }, { snssai: { sst: 1 } } ]\n", "repeats"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 }, tais: [ { mcc: '1', mnc: '01', tac: '1' } ] } ]\n", "nssf.slices[0].tais[0]"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 }, tac_ranges: [ { mcc: '001', mnc: '01', start: '000009', end: '000001' } ] } ]\n", "tac_ranges[0]"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 }, restricted_for: [ 'x' ] } ]\n", "restricted_for[0]"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 } } ]\n  amf_sets: [ { id: 'nope' } ]\n", "amf_sets[0].id"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 } } ]\n  amf_sets: [ { id: '001-01-01-001' }, { id: '001-01-01-001' } ]\n", "repeats"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 } } ]\n  mappings: [ { home_plmn: '310-260', serving: { sst: 5 }, home: { sst: 1 } } ]\n", "not one of the slices"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 } } ]\n  policy: { max_allowed: 9 }\n", "max_allowed"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 } } ]\n  subscriptions: { max_lifetime_s: 5 }\n", "max_lifetime_s"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 } } ]\n  validate: maybe\n", "validate"},
        {"nssf:\n  slices: [ { snssai: { sst: 1 } } ]\n  surprise: 1\n", "nssf"},
    };
    char err[200];
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        g5c_json *root = g5c_yaml_parse(bad[i].yaml, strlen(bad[i].yaml), err, sizeof err);
        nssf_cfg *c;
        TK_ASSERT(root != NULL);
        c = nssf_cfg_parse(root, "001", "01", "http://nrf:7777", err, sizeof err);
        if (c != NULL || strstr(err, bad[i].want) == NULL)
            TK_FAIL("config case %zu: wanted an error naming %s, got: %s", i, bad[i].want, c ? "accepted" : err);
        g5c_json_free(root);
    }
    {   /* a slice needs an NRF: its own, or the one of the PLMN */
        static const char y1[] = "nssf:\n  slices: [ { snssai: { sst: 1 } } ]\n";
        g5c_json *root = g5c_yaml_parse(y1, sizeof y1 - 1, err, sizeof err);
        TK_ASSERT(nssf_cfg_parse(root, "001", "01", NULL, err, sizeof err) == NULL && strstr(err, "nrf") != NULL);
        g5c_json_free(root);
    }
}

int main(void)
{
    g5c_log_init("error", false);
    test_config();
    test_registration();
    test_other_procedures();
    test_roaming();
    test_policy_and_errors();
    test_availability();
    test_subscriptions();
    test_state();
    puts("nssf: ok");
    return 0;
}
