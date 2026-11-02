/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The UDR configuration: what a good file yields (store, options, udrInfo, group map) and the Nudr_GroupIDmap answers
 * built on it. The refusal of bad files is tested through the binary (check_bad_configs.sh). */
#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <string.h>

#include "g5c/testkit.h"
#include "g5c/udr.h"

static g5c_json *Y(const char *yaml)
{
    char err[200];
    g5c_json *j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    if (j == NULL)
        TK_FAIL("yaml: %s", err);
    return j;
}

static int call(g5c_router *r, const char *query, g5c_json **out)
{
    g5c_req req;
    g5c_resp resp;
    int st;
    g5c_req_init(&req);
    req.method = g5c_xstrdup("GET");
    req.path = g5c_xstrdup("/nudr-group-id-map/v1/nf-group-ids");
    req.query = g5c_xstrdup(query);
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("udr.test:80");
    g5c_resp_init(&resp);
    g5c_router_dispatch(r, &req, &resp);
    st = resp.status;
    *out = g5c_resp_parse_json(&resp);
    g5c_resp_free(&resp);
    g5c_req_free(&req);
    return st;
}

static void test_config_and_groupids(void)
{
    static const char yaml[] =
        "store: { type: memory }\n"
        "udr: { group_id: udr-grp-1, supi_ranges: [{ start: '001010000000000', end: '001019999999999' }], data_sets: [SUBSCRIPTION, POLICY] }\n"
        "subscriptions: { max_per_data_set: 7, max_lifetime_s: 600, notify_retries: 3 }\n"
        "cache: { max_age_s: 30 }\n"
        "validate: false\n"
        "group_ids:\n"
        "  - { nf_type: UDM, nf_group_id: udm-grp-1, supi_ranges: [{ start: '001010000000000', end: '001010999999999' }] }\n"
        "  - { nf_type: UDM, nf_group_id: udm-grp-2, supi_ranges: [{ start: '001011000000000', end: '001019999999999' }] }\n"
        "  - { nf_type: AUSF, nf_group_id: ausf-grp-1, supi_ranges: [{ start: '001010000000000', end: '001019999999999' }] }\n";
    g5c_json *cfg = Y(yaml), *v = NULL;
    udr_config uc;
    char err[200];
    g5c_udr *svc;
    g5c_router *r;
    unsetenv("G5C_UDR_PROVISIONING_TOKEN");
    TK_ASSERT(udr_config_parse(cfg, &uc, err, sizeof err) == 0);
    TK_ASSERT(uc.opts.no_validation && uc.opts.max_subscriptions == 7 && uc.opts.subscription_max_s == 600 && uc.opts.notify_retries == 3 &&
              uc.opts.cache_max_age_s == 30 && uc.opts.provisioning_token == NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(uc.nrf_info, "groupId"), "udr-grp-1") == 0);
    TK_ASSERT(g5c_json_len(g5c_json_get(uc.nrf_info, "supportedDataSets")) == 2);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(uc.nrf_info, "supiRanges"), 0), "end"), "001019999999999") == 0);

    uc.opts.ext_open = true; /* the identity data below is provisioned through the extension */
    svc = udr_new(uc.store, &uc.opts);
    TK_ASSERT(svc != NULL);
    r = udr_router(svc);

    TK_ASSERT(call(r, "nf-type=UDM&subscriberId=imsi-001010000000001", &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "UDM"), "udm-grp-1") == 0 && g5c_json_len(v) == 1);
    g5c_json_free(v);
    TK_ASSERT(call(r, "nf-type=UDM,AUSF&subscriberId=imsi-001011000000001", &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "UDM"), "udm-grp-2") == 0 && strcmp(g5c_json_get_str(v, "AUSF"), "ausf-grp-1") == 0);
    g5c_json_free(v);
    TK_ASSERT(call(r, "nf-type=PCF&subscriberId=imsi-001010000000001", &v) == 404); /* no PCF group configured */
    g5c_json_free(v);
    TK_ASSERT(call(r, "nf-type=UDM&subscriberId=imsi-999990000000001", &v) == 404); /* outside every range */
    g5c_json_free(v);
    TK_ASSERT(call(r, "nf-type=UDM&subscriberId=msisdn-12025550100", &v) == 404);   /* a GPSI that no identity data maps */
    g5c_json_free(v);
    TK_ASSERT(call(r, "nf-type=UDM", &v) == 400);
    g5c_json_free(v);
    TK_ASSERT(call(r, "subscriberId=imsi-1", &v) == 400);
    g5c_json_free(v);
    TK_ASSERT(call(r, "nf-type=udm%3B&subscriberId=imsi-001010000000001", &v) == 400);
    g5c_json_free(v);
    /* a GPSI that the identity data maps to a SUPI finds the group of that SUPI */
    {   /* the alias index is kept by the API, so go through it */
        g5c_req req;
        g5c_resp resp;
        const char *body = "{\"supiList\":[\"imsi-001010000000001\"],\"gpsiList\":[\"msisdn-12025550100\"]}";
        g5c_req_init(&req);
        req.method = g5c_xstrdup("PUT");
        req.path = g5c_xstrdup("/nudr-dr/v2/subscription-data/imsi-001010000000001/identity-data");
        req.scheme = g5c_xstrdup("http");
        req.authority = g5c_xstrdup("udr.test:80");
        g5c_req_add_header(&req, "content-type", "application/json");
        g5c_req_set_body(&req, body, strlen(body));
        g5c_resp_init(&resp);
        g5c_router_dispatch(r, &req, &resp);
        TK_ASSERT(resp.status < 300);
        g5c_resp_free(&resp);
        g5c_req_free(&req);
    }
    TK_ASSERT(call(r, "nf-type=UDM&subscriberId=msisdn-12025550100", &v) == 200 && strcmp(g5c_json_get_str(v, "UDM"), "udm-grp-1") == 0);
    g5c_json_free(v);

    g5c_router_free(r);
    udr_free(svc);
    udr_config_free(&uc);
    g5c_json_free(cfg);
}

static void test_defaults_and_refusals(void)
{
    g5c_json *cfg = Y("name: x\n"), *bad;
    udr_config uc;
    char err[200];
    unsetenv("G5C_UDR_PROVISIONING_TOKEN");
    TK_ASSERT(udr_config_parse(cfg, &uc, err, sizeof err) == 0);
    TK_ASSERT(!uc.opts.no_validation && uc.opts.max_subscriptions == 0 && g5c_json_len(g5c_json_get(uc.nrf_info, "supportedDataSets")) == 4);
    TK_ASSERT(g5c_json_get(uc.nrf_info, "supiRanges") == NULL && uc.opts.group_ids == NULL);
    udr_config_free(&uc);
    g5c_json_free(cfg);

    bad = Y("udr: { supi_ranges: [{ start: '2', end: '1' }] }\n");
    TK_ASSERT(udr_config_parse(bad, &uc, err, sizeof err) != 0 && strstr(err, "udr.supi_ranges[0]") != NULL);
    g5c_json_free(bad);
    bad = Y("store: { type: file }\n");
    TK_ASSERT(udr_config_parse(bad, &uc, err, sizeof err) != 0 && strstr(err, "store.path") != NULL);
    g5c_json_free(bad);
    bad = Y("store: { type: postgres, conninfo_file: /nonexistent/pg.conninfo }\n");
    TK_ASSERT(udr_config_parse(bad, &uc, err, sizeof err) != 0);
    g5c_json_free(bad);
    setenv("G5C_UDR_PG_CONNINFO", "host=/nonexistent port=1 user=x dbname=y", 1);
    bad = Y("store: { type: postgres }\n");
    TK_ASSERT(udr_config_parse(bad, &uc, err, sizeof err) != 0 && err[0] != '\0'); /* unreachable server, or no libpq in this build */
    g5c_json_free(bad);
    unsetenv("G5C_UDR_PG_CONNINFO");
}

int main(void)
{
    g5c_log_init("error", false);
    test_config_and_groupids();
    test_defaults_and_refusals();
    puts("udr config: ok");
    return 0;
}
