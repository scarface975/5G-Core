/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The SEPP in a roaming set-up, all in process: a visited network (PLMN 262 01) and a home network (PLMN 001 01), each with its SEPP, and a stand-in for the home UDM. A function of the
 * visited network asks the home UDM through both SEPPs (the roaming library of the test: the allowed request, a service the partner may not use, a resource it may not touch, a
 * subscriber of another network, a flood, an unknown network, a request from the wrong address, a target the home SEPP does not serve, and the topology hiding of a Location header). */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "g5c/sepp.h"
#include "g5c/testkit.h"

static _Atomic int udm_hits;
static char udm_last_via[128];

static void udm_get(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *o = g5c_json_new_obj();
    const char *v = g5c_req_header(req, "via");
    (void)ctx;
    atomic_fetch_add(&udm_hits, 1);
    snprintf(udm_last_via, sizeof udm_last_via, "%s", v != NULL ? v : "");
    g5c_json_set_str(o, "supi", g5c_req_param(req, "supi"));
    g5c_resp_json(resp, 200, o);
    g5c_json_free(o);
}

static void udm_post(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    char *loc = g5c_req_url(req, "/nudm-uecm/v1/imsi-001010000000001/registrations/amf-3gpp-access");
    (void)ctx;
    g5c_resp_status(resp, 201);
    g5c_resp_header(resp, "location", loc);
    free(loc);
}

typedef struct {
    g5c_nf *nf;
    sepp *s;
    g5c_router *rt;
    g5c_server *srv;
    char url[64];
} node_t;

static g5c_nf *make_nf(const char *name, const char *mcc, const char *mnc)
{
    char yaml[400], err[200];
    g5c_json *j;
    g5c_common c;
    g5c_nf *nf;
    snprintf(yaml, sizeof yaml, "name: %s\nplmn: { mcc: '%s', mnc: '%s' }\nsbi: { address: 127.0.0.1, port: 1 }\n", name, mcc, mnc);
    j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    TK_ASSERT(j != NULL && g5c_common_parse(j, &c, err, sizeof err) == 0);
    g5c_json_free(j);
    nf = g5c_nf_new(&c, err, sizeof err);
    TK_ASSERT(nf != NULL);
    return nf;
}

static void start_node(node_t *n, const char *name, const char *mcc, const char *mnc, const char *cfg_yaml)
{
    char err[200];
    g5c_json *root = g5c_yaml_parse(cfg_yaml, strlen(cfg_yaml), err, sizeof err);
    g5c_server_cfg sc = {"127.0.0.1", 0, NULL};
    TK_ASSERT(root != NULL);
    n->nf = make_nf(name, mcc, mnc);
    n->s = sepp_from_config(root, n->nf, err, sizeof err);
    if (n->s == NULL)
        TK_FAIL("config: %s", err);
    g5c_json_free(root);
    n->rt = sepp_router(n->s);
    n->srv = g5c_server_start(&sc, n->rt, err, sizeof err);
    TK_ASSERT(n->srv != NULL);
    snprintf(n->url, sizeof n->url, "http://127.0.0.1:%u", g5c_server_port(n->srv));
}

static int ask(g5c_client *cl, const char *sepp_url, const char *method, const char *target, const char *path, const char *extra_name, const char *extra_value, g5c_resp *out)
{
    char url[400], err[160];
    g5c_kv h[2] = {{"3gpp-sbi-target-apiroot", target}, {extra_name != NULL ? extra_name : "x-none", extra_value != NULL ? extra_value : "-"}};
    snprintf(url, sizeof url, "%s%s", sepp_url, path);
    if (g5c_client_request(cl, method, url, h, 2, "application/json", strcmp(method, "POST") == 0 ? "{}" : NULL, strcmp(method, "POST") == 0 ? 2 : 0, out, err, sizeof err) != 0)
        TK_FAIL("%s %s%s: %s", method, sepp_url, path, err);
    return out->status;
}

#define HOME_DOM "udm.5gc.mnc001.mcc001.3gppnetwork.org"
#define HOME_API "http://" HOME_DOM
#define SUPI_HOME "/nudm-sdm/v2/imsi-001010000000001/am-data"

int main(void)
{
    node_t home, home2, vis;
    g5c_server_cfg sc = {"127.0.0.1", 0, NULL};
    g5c_router *udm = g5c_router_new();
    g5c_server *udm_srv;
    char err[200], cfg[2400], udm_url[64];
    g5c_client *cl = g5c_client_new(3000, NULL);
    g5c_resp r;
    g5c_json *j;

    g5c_router_route(udm, "GET", "/nudm-sdm/v2/{supi}/am-data", udm_get, NULL);
    g5c_router_route(udm, "GET", "/nudm-sdm/v2/{supi}/location", udm_get, NULL);
    g5c_router_route(udm, "POST", "/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access", udm_post, NULL);
    g5c_router_route(udm, "GET", "/nausf-auth/v1/{x}", udm_get, NULL);
    udm_srv = g5c_server_start(&sc, udm, err, sizeof err);
    TK_ASSERT(udm_srv != NULL);
    snprintf(udm_url, sizeof udm_url, "http://127.0.0.1:%u", g5c_server_port(udm_srv));

    /* the home SEPP first (the visited one needs its address) */
    snprintf(cfg, sizeof cfg,
             "sepp:\n  public_apiroot: 'https://sepp.5gc.mnc001.mcc001.3gppnetwork.org'\n  local_targets: [ { apiroot: '%s', uri: '%s' } ]\n"
             "  partners:\n    - { name: visited, plmn: '26201', domain: '5gc.mnc001.mcc262.3gppnetwork.org', uri: 'http://127.0.0.1:1', sources: [ '127.0.0.1' ], "
             "allow_services: [ nudm-sdm, nudm-uecm ], deny_path_contains: [ /location ], rate_per_s: 3, burst: 6 }\n"
             "    - { name: other, plmn: '23401', domain: '5gc.mnc001.mcc234.3gppnetwork.org', uri: 'http://127.0.0.1:1', sources: [ '203.0.113.9' ], allow_services: [ '*' ] }\n",
             HOME_API, udm_url);
    start_node(&home, "sepp-home", "001", "01", cfg);
    snprintf(cfg, sizeof cfg, "sepp:\n  local_targets: [ { apiroot: '%s', uri: '%s' } ]\n  partners:\n    - { name: elsewhere, plmn: '26201', domain: '5gc.mnc001.mcc262.3gppnetwork.org', uri: 'http://127.0.0.1:1', sources: [ '203.0.113.9' ], allow_services: [ '*' ] }\n",
             HOME_API, udm_url);
    start_node(&home2, "sepp-home2", "001", "01", cfg);
    snprintf(cfg, sizeof cfg,
             "sepp:\n  partners:\n    - { name: home, plmn: '00101', domain: '5gc.mnc001.mcc001.3gppnetwork.org', uri: '%s', allow_services: [ nudm-sdm, nudm-uecm ] }\n", home.url);
    start_node(&vis, "sepp-visited", "262", "01", cfg);
    TK_ASSERT(sepp_partner_count(home.s) == 2 && sepp_partner_count(vis.s) == 1);

    /* 1. the allowed request: visited AMF -> visited SEPP -> home SEPP -> home UDM */
    ask(cl, vis.url, "GET", HOME_API, SUPI_HOME, NULL, NULL, &r);
    TK_ASSERT(r.status == 200 && atomic_load(&udm_hits) == 1);
    j = g5c_resp_parse_json(&r);
    TK_ASSERT(strcmp(g5c_json_get_str(j, "supi"), "imsi-001010000000001") == 0);
    g5c_json_free(j);
    g5c_resp_free(&r);
    TK_ASSERT(strstr(udm_last_via, "SEPP-sepp-home") != NULL && strstr(udm_last_via, "SEPP-sepp-visited") != NULL); /* both SEPPs are in the Via chain */

    /* 2. a service the home network does not open to the visited one */
    ask(cl, vis.url, "GET", HOME_API, "/nausf-auth/v1/ue-authentications", NULL, NULL, &r);
    TK_ASSERT(r.status == 403 && udm_hits == 1);
    g5c_resp_free(&r);

    /* 3. a resource the partner may not touch inside an allowed service */
    ask(cl, vis.url, "GET", HOME_API, "/nudm-sdm/v2/imsi-001010000000001/location", NULL, NULL, &r);
    j = g5c_resp_parse_json(&r);
    TK_ASSERT(r.status == 403 && j != NULL && strcmp(g5c_json_get_str(j, "cause"), "PATH_NOT_ALLOWED") == 0 && udm_hits == 1);
    g5c_json_free(j);
    g5c_resp_free(&r);

    /* 4. a subscriber of another network */
    ask(cl, vis.url, "GET", HOME_API, "/nudm-sdm/v2/imsi-310260000000001/am-data", NULL, NULL, &r);
    j = g5c_resp_parse_json(&r);
    TK_ASSERT(r.status == 403 && strcmp(g5c_json_get_str(j, "cause"), "IDENTITY_NOT_ALLOWED") == 0 && udm_hits == 1);
    g5c_json_free(j);
    g5c_resp_free(&r);

    /* 5. a request that comes from an address no partner has (a third SEPP, home2, whose only partner connects from another address), and a partner reached for a target it does not know */
    ask(cl, home2.url, "GET", HOME_API, SUPI_HOME, NULL, NULL, &r);
    j = g5c_resp_parse_json(&r);
    TK_ASSERT(r.status == 403 && strcmp(g5c_json_get_str(j, "cause"), "UNKNOWN_PARTNER") == 0);
    g5c_json_free(j);
    g5c_resp_free(&r);
    TK_ASSERT(udm_hits == 1);

    /* 6. a target the home SEPP does not deliver to */
    ask(cl, home.url, "GET", "http://smf.5gc.mnc001.mcc001.3gppnetwork.org", "/nsmf-pdusession/v1/sm-contexts", NULL, NULL, &r);
    TK_ASSERT(r.status == 403);
    g5c_resp_free(&r);

    /* 7. a visited-side request to a network with no relation: the visited SEPP has no partner for the domain, so it treats it as a request for itself and refuses it */
    ask(cl, vis.url, "GET", "http://udm.5gc.mnc001.mcc440.3gppnetwork.org", SUPI_HOME, NULL, NULL, &r);
    TK_ASSERT(r.status == 403);
    g5c_resp_free(&r);

    /* 8. topology hiding: the Location header of the home function does not reach the partner */
    ask(cl, vis.url, "POST", HOME_API, "/nudm-uecm/v1/imsi-001010000000001/registrations/amf-3gpp-access", NULL, NULL, &r);
    TK_ASSERT(r.status == 201);
    {
        const char *loc = g5c_resp_header_get(&r, "location");
        TK_ASSERT(loc != NULL && strncmp(loc, "https://sepp.5gc.mnc001.mcc001.3gppnetwork.org/nudm-uecm/", 56) == 0); /* the partner sees the SEPP, not the function's address */
    }
    g5c_resp_free(&r);

    /* 9. the rate: 3 a second with a burst of 6 for the visited network; a flood is answered with 429 and the home UDM sees at most the burst */
    {
        int ok = 0, limited = 0, before = atomic_load(&udm_hits);
        for (int i = 0; i < 20; i++) {
            g5c_client *fresh = g5c_client_new(3000, NULL); /* the SBI client backs off a server that asked for it: each request here comes from another consumer */
            ask(fresh, vis.url, "GET", HOME_API, SUPI_HOME, NULL, NULL, &r);
            g5c_client_free(fresh);
            ok += r.status == 200;
            limited += r.status == 429;
            if (r.status == 429)
                TK_ASSERT(g5c_resp_header_get(&r, "retry-after") != NULL);
            g5c_resp_free(&r);
        }
        TK_ASSERT(limited >= 10 && ok >= 1 && ok <= 9 && atomic_load(&udm_hits) - before == ok);
        sleep(2); /* tokens come back */
        ask(cl, vis.url, "GET", HOME_API, SUPI_HOME, NULL, NULL, &r);
        TK_ASSERT(r.status == 200);
        g5c_resp_free(&r);
    }

    /* 10. a request that has already passed this SEPP is a loop */
    ask(cl, vis.url, "GET", HOME_API, SUPI_HOME, "via", "SEPP-sepp-visited", &r);
    TK_ASSERT(r.status == 508);
    g5c_resp_free(&r);

    /* 11. N32-c (TS 29.573 6.1.4.2): a home SEPP that requires the negotiation, a visited SEPP that does it by itself, and one that does not */
    {
        node_t homeR, visR, visC;
        static const char *const cases[][2] = {
            {"{\"sender\":\"sepp.v\",\"supportedSecCapabilityList\":[\"PRINS\"],\"3GppSbiTargetApiRootSupported\":true}", "403"},            /* nothing in common */
            {"{\"sender\":\"sepp.v\",\"supportedSecCapabilityList\":[\"TLS\"]}", "403"},                                                    /* no 3gpp-Sbi-Target-apiRoot */
            {"{\"sender\":\"sepp.v\",\"supportedSecCapabilityList\":[\"TLS\"],\"3GppSbiTargetApiRootSupported\":true,\"plmnIdList\":[{\"mcc\":\"310\",\"mnc\":\"260\"}]}", "403"}, /* a PLMN that is not the partner's */
            {"{\"supportedSecCapabilityList\":[\"TLS\"],\"3GppSbiTargetApiRootSupported\":true}", "400"},                                     /* no sender */
            {"{\"sender\":\"sepp.v\",\"supportedSecCapabilityList\":[]}", "400"},
        };
        char url[160];
        snprintf(cfg, sizeof cfg,
                 "sepp:\n  public_apiroot: 'https://sepp.5gc.mnc001.mcc001.3gppnetwork.org'\n  handshake: { required: true }\n  local_targets: [ { apiroot: '%s', uri: '%s' } ]\n"
                 "  partners:\n    - { name: visited, plmn: '26201', domain: '5gc.mnc001.mcc262.3gppnetwork.org', uri: 'http://127.0.0.1:1', sources: [ '127.0.0.1' ], allow_services: [ nudm-sdm ] }\n",
                 HOME_API, udm_url);
        start_node(&homeR, "sepp-homeR", "001", "01", cfg);
        snprintf(cfg, sizeof cfg, "sepp:\n  handshake: { required: true, sender: 'sepp.5gc.mnc001.mcc262.3gppnetwork.org' }\n  partners:\n    - { name: home, plmn: '00101', domain: '5gc.mnc001.mcc001.3gppnetwork.org', uri: '%s', allow_services: [ nudm-sdm ] }\n", homeR.url);
        start_node(&visR, "sepp-visR", "262", "01", cfg);
        snprintf(cfg, sizeof cfg, "sepp:\n  partners:\n    - { name: home, plmn: '00101', domain: '5gc.mnc001.mcc001.3gppnetwork.org', uri: '%s', allow_services: [ nudm-sdm ] }\n", homeR.url);
        start_node(&visC, "sepp-visC", "262", "01", cfg);
        snprintf(url, sizeof url, "%s/n32c-handshake/v1/exchange-capability", homeR.url);
        for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
            TK_ASSERT(g5c_client_request(cl, "POST", url, NULL, 0, "application/json", cases[i][0], strlen(cases[i][0]), &r, err, sizeof err) == 0);
            TK_ASSERT(r.status == atoi(cases[i][1]));
            g5c_resp_free(&r);
        }
        TK_ASSERT(!sepp_partner_negotiated(homeR.s, "visited"));
        {   /* the PRINS-only operations are answered, not forwarded */
            static const char *const ops[] = {"exchange-params", "n32f-terminate", "n32f-error"};
            for (size_t i = 0; i < 3; i++) {
                char u2[200];
                snprintf(u2, sizeof u2, "%s/n32c-handshake/v1/%s", homeR.url, ops[i]);
                TK_ASSERT(g5c_client_request(cl, "POST", u2, NULL, 0, "application/json", "{}", 2, &r, err, sizeof err) == 0 && r.status == 501);
                g5c_resp_free(&r);
            }
        }
        /* a visited SEPP that does not negotiate: the home SEPP refuses what it sends */
        ask(cl, visC.url, "GET", HOME_API, SUPI_HOME, NULL, NULL, &r);
        j = g5c_resp_parse_json(&r);
        TK_ASSERT(r.status == 403 && j != NULL && strcmp(g5c_json_get_str(j, "cause"), "N32C_NOT_NEGOTIATED") == 0);
        g5c_json_free(j);
        g5c_resp_free(&r);
        /* one that does: the first request starts the negotiation, then it goes through */
        TK_ASSERT(!sepp_partner_negotiated(visR.s, "home"));
        {
            int before = atomic_load(&udm_hits);
            ask(cl, visR.url, "GET", HOME_API, SUPI_HOME, NULL, NULL, &r);
            TK_ASSERT(r.status == 200 && atomic_load(&udm_hits) == before + 1);
            g5c_resp_free(&r);
        }
        TK_ASSERT(sepp_partner_negotiated(visR.s, "home") && sepp_partner_negotiated(homeR.s, "visited"));
        /* a valid offer, answered with the selection */
        {
            const char *ok = "{\"sender\":\"sepp.v\",\"supportedSecCapabilityList\":[\"PRINS\",\"TLS\"],\"3GppSbiTargetApiRootSupported\":true,\"plmnIdList\":[{\"mcc\":\"262\",\"mnc\":\"01\"}]}";
            TK_ASSERT(g5c_client_request(cl, "POST", url, NULL, 0, "application/json", ok, strlen(ok), &r, err, sizeof err) == 0 && r.status == 200);
            j = g5c_resp_parse_json(&r);
            TK_ASSERT(strcmp(g5c_json_get_str(j, "selectedSecCapability"), "TLS") == 0 && strcmp(g5c_json_get_str(j, "sender"), "sepp.5gc.mnc001.mcc001.3gppnetwork.org") == 0);
            g5c_json_free(j);
            g5c_resp_free(&r);
        }
        g5c_server_stop(homeR.srv);
        g5c_server_stop(visR.srv);
        g5c_server_stop(visC.srv);
        g5c_router_free(homeR.rt);
        g5c_router_free(visR.rt);
        g5c_router_free(visC.rt);
        sepp_destroy(homeR.s);
        sepp_destroy(visR.s);
        sepp_destroy(visC.s);
        g5c_nf_free(homeR.nf);
        g5c_nf_free(visR.nf);
        g5c_nf_free(visC.nf);
    }

    /* configuration errors */
    {
        static const char *const bad[] = {"sepp:\n  partners: []\n", "sepp:\n  partners:\n    - { name: a, plmn: '1', domain: x, uri: 'http://h:1' }\n", "sepp:\n  bogus: 1\n  partners:\n    - { name: a, plmn: '26201', domain: x, uri: 'http://h:1' }\n",
                                          "sepp:\n  partners:\n    - { name: a, plmn: '26201', domain: x, uri: 'ftp://h' }\n", "other: 1\n"};
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
            g5c_json *root = g5c_yaml_parse(bad[i], strlen(bad[i]), err, sizeof err);
            err[0] = 0;
            TK_ASSERT(root != NULL && sepp_from_config(root, home.nf, err, sizeof err) == NULL && err[0] != 0);
            g5c_json_free(root);
        }
    }
    g5c_client_free(cl);
    g5c_server_stop(vis.srv);
    g5c_server_stop(home.srv);
    g5c_server_stop(home2.srv);
    g5c_server_stop(udm_srv);
    g5c_router_free(udm);
    g5c_router_free(vis.rt);
    g5c_router_free(home.rt);
    g5c_router_free(home2.rt);
    sepp_destroy(vis.s);
    sepp_destroy(home.s);
    sepp_destroy(home2.s);
    g5c_nf_free(vis.nf);
    g5c_nf_free(home.nf);
    g5c_nf_free(home2.nf);
    printf("sepp: OK\n");
    return 0;
}
