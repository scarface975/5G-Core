/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NRF end to end: a real HTTP/2 server and client, a callback server for the status notifications.
 * Covers Nnrf_NFManagement (register, replace, patch, heart-beat, deregister, retrieve, list, subscribe), Nnrf_NFDiscovery (filters and ordering),
 * the heart-beat monitor (SUSPENDED, purge), Nnrf_AccessToken (ES256 JWT, scopes, enforcement), persistence and configuration errors. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include "g5c/jwt.h"
#include "g5c/nrf.h"
#include "g5c/testkit.h"

/* ---- environment ------------------------------------------------------------------------------------------------------------------------------ */

typedef struct {
    g5c_registry *reg;
    g5c_nf *nf;
    nrf *n;
    g5c_router *r;
    g5c_server *srv;
    char base[64];
} env_t;

static g5c_client *cl;

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static const char *UDM1 = "11111111-1111-4111-8111-111111111111";
static const char *UDM2 = "22222222-2222-4222-8222-222222222222";
static const char *SMF1 = "33333333-3333-4333-8333-333333333333";
static const char *AMF1 = "44444444-4444-4444-8444-444444444444";
static const char *AUSF1 = "55555555-5555-4555-8555-555555555555";
static const char *PCF1 = "66666666-6666-4666-8666-666666666666";

static bool env_start(env_t *e, const char *registry_yaml, const char *state_file)
{
    char yaml[2000], err[300];
    g5c_json *j;
    g5c_common common;
    g5c_server_cfg sc = {"127.0.0.1", 0, NULL};
    memset(e, 0, sizeof *e);
    snprintf(yaml, sizeof yaml, "name: nrf-test\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\nregistry:\n%s%s%s%s", registry_yaml,
             state_file != NULL ? "  state_file: '" : "", state_file != NULL ? state_file : "", state_file != NULL ? "'\n" : "");
    j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    TK_ASSERT(j != NULL && g5c_common_parse(j, &common, err, sizeof err) == 0);
    common.port = 0;
    e->nf = g5c_nf_new(&common, err, sizeof err);
    TK_ASSERT(e->nf != NULL);
    e->n = nrf_from_config(j, e->nf, err, sizeof err);
    g5c_json_free(j);
    if (e->n == NULL) {
        fprintf(stderr, "config: %s\n", err);
        return false;
    }
    e->r = nrf_router(e->n);
    e->srv = g5c_server_start(&sc, e->r, err, sizeof err);
    TK_ASSERT(e->srv != NULL);
    snprintf(e->base, sizeof e->base, "http://127.0.0.1:%u", g5c_server_port(e->srv));
    nrf_set_self_uri(e->n, e->base);
    TK_ASSERT(nrf_start(e->n, err, sizeof err) == 0);
    return true;
}

static void env_stop(env_t *e)
{
    g5c_server_stop(e->srv);
    nrf_destroy(e->n);
    g5c_router_free(e->r);
    g5c_nf_free(e->nf);
}

/* ---- the notification receiver ------------------------------------------------------------------------------------------------------------------ */

static pthread_mutex_t cb_mu = PTHREAD_MUTEX_INITIALIZER;
static char cb_body[64][3000];
static int cb_n;

static void cb_recv(void *c, const g5c_req *q, g5c_resp *r)
{
    (void)c;
    pthread_mutex_lock(&cb_mu);
    if (cb_n < 64) {
        size_t n = q->body_len < sizeof cb_body[0] - 1 ? q->body_len : sizeof cb_body[0] - 1;
        memcpy(cb_body[cb_n], q->body, n);
        cb_body[cb_n][n] = 0;
        cb_n++;
    }
    pthread_mutex_unlock(&cb_mu);
    g5c_resp_status(r, 204);
}

static int cb_count(void)
{
    int n;
    pthread_mutex_lock(&cb_mu);
    n = cb_n;
    pthread_mutex_unlock(&cb_mu);
    return n;
}

static bool cb_wait(int want, double secs)
{
    double end = now_s() + secs;
    while (now_s() < end) {
        if (cb_count() >= want)
            return true;
        usleep(10000);
    }
    return cb_count() >= want;
}

/* the event of the i-th notification */
static void cb_event(int i, char *ev, size_t cap, char *uri, size_t ucap)
{
    char err[64];
    g5c_json *j;
    pthread_mutex_lock(&cb_mu);
    j = g5c_json_parse(cb_body[i], strlen(cb_body[i]), err, sizeof err);
    pthread_mutex_unlock(&cb_mu);
    TK_ASSERT(j != NULL);
    snprintf(ev, cap, "%s", g5c_json_get_str(j, "event") != NULL ? g5c_json_get_str(j, "event") : "");
    snprintf(uri, ucap, "%s", g5c_json_get_str(j, "nfInstanceUri") != NULL ? g5c_json_get_str(j, "nfInstanceUri") : "");
    g5c_json_free(j);
}

static void cb_reset(void)
{
    pthread_mutex_lock(&cb_mu);
    cb_n = 0;
    pthread_mutex_unlock(&cb_mu);
}

/* ---- HTTP helpers ---------------------------------------------------------------------------------------------------------------------------- */

static int call(const char *method, const char *url, const char *ctype, const char *body, const char *bearer, g5c_resp *out)
{
    char err[160], auth[1200];
    g5c_kv h[2];
    size_t nh = 0;
    if (bearer != NULL) {
        snprintf(auth, sizeof auth, "Bearer %s", bearer);
        h[nh++] = (g5c_kv){"authorization", auth};
    }
    TK_ASSERT(g5c_client_request(cl, method, url, h, nh, ctype, body, body != NULL ? strlen(body) : 0, out, err, sizeof err) == 0);
    return out->status;
}

static int put_profile(const env_t *e, const char *id, const char *body, g5c_resp *out)
{
    char url[200];
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/nf-instances/%s", e->base, id);
    return call("PUT", url, G5C_JSON_TYPE, body, NULL, out);
}

static int patch_profile(const env_t *e, const char *id, const char *body, const char *if_match, g5c_resp *out)
{
    char url[200], err[160];
    g5c_kv h[1];
    size_t nh = 0;
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/nf-instances/%s", e->base, id);
    if (if_match != NULL)
        h[nh++] = (g5c_kv){"if-match", if_match};
    TK_ASSERT(g5c_client_request(cl, "PATCH", url, h, nh, "application/json-patch+json", body, strlen(body), out, err, sizeof err) == 0);
    return out->status;
}

static int simple(const env_t *e, const char *method, const char *path)
{
    char url[400];
    g5c_resp r;
    int st;
    snprintf(url, sizeof url, "%s%s", e->base, path);
    st = call(method, url, NULL, NULL, NULL, &r);
    g5c_resp_free(&r);
    return st;
}

static char *profile_json(const char *id, const char *type, const char *extra)
{
    return g5c_xasprintf("{\"nfInstanceId\":\"%s\",\"nfType\":\"%s\",\"nfStatus\":\"REGISTERED\",\"ipv4Addresses\":[\"10.0.0.1\"]%s%s}", id, type,
                         extra != NULL ? "," : "", extra != NULL ? extra : "");
}

static void register_ok(const env_t *e, const char *id, const char *type, const char *extra)
{
    g5c_resp r;
    char *b = profile_json(id, type, extra);
    int st = put_profile(e, id, b, &r);
    TK_ASSERT(st == 201 || st == 200);
    g5c_resp_free(&r);
    free(b);
}

/* the discovery result: the number of instances and, in ids[], their nfInstanceId in order */
static size_t discover(const env_t *e, const char *query, char ids[8][37], int *status)
{
    char url[1200], err[64];
    g5c_resp r;
    g5c_json *j;
    size_t n = 0;
    snprintf(url, sizeof url, "%s/nnrf-disc/v1/nf-instances?%s", e->base, query);
    *status = call("GET", url, NULL, NULL, NULL, &r);
    if (*status == 200) {
        const g5c_json *a;
        j = g5c_json_parse((const char *)r.body, r.body_len, err, sizeof err);
        TK_ASSERT(j != NULL);
        TK_ASSERT(g5c_json_get(j, "validityPeriod") != NULL);
        a = g5c_json_get(j, "nfInstances");
        for (size_t i = 0; i < g5c_json_len(a) && n < 8; i++)
            snprintf(ids[n++], 37, "%s", g5c_json_get_str(g5c_json_at(a, i), "nfInstanceId"));
        g5c_json_free(j);
    }
    g5c_resp_free(&r);
    return n;
}

/* ---- cases ---------------------------------------------------------------------------------------------------------------------------------------- */

static void test_registration(const env_t *e)
{
    g5c_resp r;
    char url[300], *b;
    g5c_json *j;
    char perr[64];
    const char *etag1;
    char etag_copy[40];

    b = profile_json(UDM1, "UDM", "\"nfServices\":[{\"serviceInstanceId\":\"s1\",\"serviceName\":\"nudm-sdm\",\"versions\":[{\"apiVersionInUri\":\"v2\",\"apiFullVersion\":\"2.0.0\"}],"
                                  "\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\"}]");
    TK_ASSERT(put_profile(e, UDM1, b, &r) == 201);
    TK_ASSERT(g5c_resp_header_get(&r, "location") != NULL && strstr(g5c_resp_header_get(&r, "location"), UDM1) != NULL);
    etag1 = g5c_resp_header_get(&r, "etag");
    TK_ASSERT(etag1 != NULL);
    snprintf(etag_copy, sizeof etag_copy, "%s", etag1);
    j = g5c_resp_parse_json(&r);
    {
        int64_t hb = 0;
        TK_ASSERT(g5c_json_get_int(j, "heartBeatTimer", &hb) && hb == 1); /* the NRF chooses the interval (config: 1 s) */
        TK_ASSERT(strcmp(g5c_json_get_str(j, "nfStatus"), "REGISTERED") == 0);
    }
    g5c_json_free(j);
    g5c_resp_free(&r);
    TK_ASSERT(nrf_profile_count(e->n) == 1);

    /* the same document again is a replacement (200); an identical replacement keeps the entity tag changing monotonically, that is not asserted */
    TK_ASSERT(put_profile(e, UDM1, b, &r) == 200);
    g5c_resp_free(&r);
    free(b);

    /* refusals */
    TK_ASSERT(put_profile(e, "not-a-uuid", "{}", &r) == 400);
    g5c_resp_free(&r);
    b = profile_json(UDM2, "UDM", NULL);
    TK_ASSERT(put_profile(e, UDM1, b, &r) == 400); /* nfInstanceId differs from the URI */
    g5c_resp_free(&r);
    free(b);
    TK_ASSERT(put_profile(e, UDM2, "{\"nfInstanceId\":\"22222222-2222-4222-8222-222222222222\",\"nfStatus\":\"REGISTERED\"}", &r) == 400); /* no nfType */
    g5c_resp_free(&r);
    TK_ASSERT(put_profile(e, UDM2, "{\"nfType\":\"UDM\",\"nfStatus\":\"GONE\"}", &r) == 400);
    g5c_resp_free(&r);
    TK_ASSERT(put_profile(e, UDM2, "{\"nfType\":\"UDM\",\"ipv4Addresses\":\"10.0.0.1\"}", &r) == 400);
    g5c_resp_free(&r);
    TK_ASSERT(put_profile(e, UDM2, "{\"nfType\":\"UDM\",\"nfServices\":[{\"serviceName\":\"x\"}]}", &r) == 400); /* no serviceInstanceId */
    g5c_resp_free(&r);
    TK_ASSERT(put_profile(e, UDM2, "{\"nfType\":\"UDM\",\"heartBeatTimer\":0}", &r) == 400);
    g5c_resp_free(&r);
    TK_ASSERT(put_profile(e, UDM2, "[1,2]", &r) == 400);
    g5c_resp_free(&r);
    TK_ASSERT(put_profile(e, UDM2, "{broken", &r) == 400);
    g5c_resp_free(&r);
    TK_ASSERT(nrf_profile_count(e->n) == 1);

    /* a minimal profile is accepted: nfStatus defaults, the id comes from the URI */
    TK_ASSERT(put_profile(e, UDM2, "{\"nfType\":\"CUSTOM_XYZ\"}", &r) == 201);
    j = g5c_resp_parse_json(&r);
    TK_ASSERT(strcmp(g5c_json_get_str(j, "nfStatus"), "REGISTERED") == 0 && strcmp(g5c_json_get_str(j, "nfInstanceId"), UDM2) == 0);
    g5c_json_free(j);
    g5c_resp_free(&r);

    /* retrieval and list */
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/nf-instances/%s", e->base, UDM1);
    TK_ASSERT(call("GET", url, NULL, NULL, NULL, &r) == 200);
    TK_ASSERT(g5c_resp_header_get(&r, "etag") != NULL);
    g5c_resp_free(&r);
    TK_ASSERT(simple(e, "GET", "/nnrf-nfm/v1/nf-instances/99999999-9999-4999-8999-999999999999") == 404);
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/nf-instances?nf-type=UDM", e->base);
    TK_ASSERT(call("GET", url, NULL, NULL, NULL, &r) == 200);
    j = g5c_resp_parse_json(&r);
    TK_ASSERT(g5c_json_len(g5c_json_get(g5c_json_get(j, "_links"), "item")) == 1);
    TK_ASSERT(strstr(g5c_json_get_str(g5c_json_at(g5c_json_get(g5c_json_get(j, "_links"), "item"), 0), "href"), UDM1) != NULL);
    g5c_json_free(j);
    g5c_resp_free(&r);
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/nf-instances?limit=1", e->base);
    TK_ASSERT(call("GET", url, NULL, NULL, NULL, &r) == 200);
    j = g5c_resp_parse_json(&r);
    TK_ASSERT(g5c_json_len(g5c_json_get(g5c_json_get(j, "_links"), "item")) == 1);
    g5c_json_free(j);
    g5c_resp_free(&r);
    TK_ASSERT(simple(e, "GET", "/nnrf-nfm/v1/nf-instances?limit=0") == 400);
    TK_ASSERT(simple(e, "OPTIONS", "/nnrf-nfm/v1/nf-instances") == 204);

    /* deregistration */
    TK_ASSERT(simple(e, "DELETE", "/nnrf-nfm/v1/nf-instances/22222222-2222-4222-8222-222222222222") == 204);
    TK_ASSERT(simple(e, "DELETE", "/nnrf-nfm/v1/nf-instances/22222222-2222-4222-8222-222222222222") == 404);
    TK_ASSERT(nrf_profile_count(e->n) == 1);
    (void)perr;
    (void)etag_copy;
}

static void test_update(const env_t *e)
{
    g5c_resp r;
    char etag[40], status[16];
    g5c_json *j;
    /* heart-beat: replace /nfStatus - 204 and no new entity tag */
    TK_ASSERT(patch_profile(e, UDM1, "[{\"op\":\"replace\",\"path\":\"/nfStatus\",\"value\":\"REGISTERED\"}]", NULL, &r) == 204);
    TK_ASSERT(g5c_resp_header_get(&r, "etag") != NULL);
    snprintf(etag, sizeof etag, "%s", g5c_resp_header_get(&r, "etag"));
    g5c_resp_free(&r);
    TK_ASSERT(patch_profile(e, UDM1, "[{\"op\":\"replace\",\"path\":\"/nfStatus\",\"value\":\"REGISTERED\"}]", etag, &r) == 204);
    TK_ASSERT(strcmp(g5c_resp_header_get(&r, "etag"), etag) == 0);
    g5c_resp_free(&r);
    /* a load report with the heart-beat changes the profile (new tag) but is still a 204 */
    TK_ASSERT(patch_profile(e, UDM1, "[{\"op\":\"replace\",\"path\":\"/nfStatus\",\"value\":\"REGISTERED\"},{\"op\":\"add\",\"path\":\"/load\",\"value\":30}]", NULL, &r) == 204);
    TK_ASSERT(strcmp(g5c_resp_header_get(&r, "etag"), etag) != 0);
    snprintf(etag, sizeof etag, "%s", g5c_resp_header_get(&r, "etag"));
    g5c_resp_free(&r);
    /* a real change: 200 with the profile */
    TK_ASSERT(patch_profile(e, UDM1, "[{\"op\":\"add\",\"path\":\"/priority\",\"value\":5}]", etag, &r) == 200);
    j = g5c_resp_parse_json(&r);
    {
        int64_t p = 0;
        TK_ASSERT(g5c_json_get_int(j, "priority", &p) && p == 5);
    }
    g5c_json_free(j);
    TK_ASSERT(strcmp(g5c_resp_header_get(&r, "etag"), etag) != 0);
    g5c_resp_free(&r);
    /* precondition, conflict, malformed, immutable attributes, unknown instance */
    TK_ASSERT(patch_profile(e, UDM1, "[{\"op\":\"add\",\"path\":\"/priority\",\"value\":6}]", "\"1\"", &r) == 412);
    g5c_resp_free(&r);
    TK_ASSERT(patch_profile(e, UDM1, "[{\"op\":\"replace\",\"path\":\"/locality\",\"value\":\"x\"}]", NULL, &r) == 409); /* replace of a non-existing attribute */
    g5c_resp_free(&r);
    TK_ASSERT(patch_profile(e, UDM1, "[{\"op\":\"replace\",\"path\":\"/nfType\",\"value\":\"AMF\"}]", NULL, &r) == 400);
    g5c_resp_free(&r);
    TK_ASSERT(patch_profile(e, UDM1, "[{\"op\":\"replace\",\"path\":\"/nfStatus\",\"value\":\"DEAD\"}]", NULL, &r) == 400);
    g5c_resp_free(&r);
    TK_ASSERT(patch_profile(e, UDM1, "{\"op\":\"add\"}", NULL, &r) == 400);
    g5c_resp_free(&r);
    TK_ASSERT(patch_profile(e, UDM1, "[{\"op\":\"copy\",\"path\":\"/a\"}]", NULL, &r) == 400);
    g5c_resp_free(&r);
    TK_ASSERT(patch_profile(e, "99999999-9999-4999-8999-999999999999", "[{\"op\":\"replace\",\"path\":\"/nfStatus\",\"value\":\"REGISTERED\"}]", NULL, &r) == 404);
    g5c_resp_free(&r);
    TK_ASSERT(nrf_profile_status(e->n, UDM1, status, sizeof status) && strcmp(status, "REGISTERED") == 0);
    /* UNDISCOVERABLE through a heart-beat */
    TK_ASSERT(patch_profile(e, UDM1, "[{\"op\":\"replace\",\"path\":\"/nfStatus\",\"value\":\"UNDISCOVERABLE\"}]", NULL, &r) == 204);
    g5c_resp_free(&r);
    TK_ASSERT(nrf_profile_status(e->n, UDM1, status, sizeof status) && strcmp(status, "UNDISCOVERABLE") == 0);
    TK_ASSERT(patch_profile(e, UDM1, "[{\"op\":\"replace\",\"path\":\"/nfStatus\",\"value\":\"REGISTERED\"}]", NULL, &r) == 204);
    g5c_resp_free(&r);
}

static void test_discovery(const env_t *e)
{
    char ids[8][37];
    int st;
    size_t n;
    const char *smf_extra =
        "\"sNssais\":[{\"sst\":1},{\"sst\":1,\"sd\":\"000001\"}],\"locality\":\"dc-b\",\"priority\":2,"
        "\"smfInfo\":{\"sNssaiSmfInfoList\":[{\"sNssai\":{\"sst\":1},\"dnnSmfInfoList\":[{\"dnn\":\"internet\"},{\"dnn\":\"ims\"}]}],\"taiList\":[{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"tac\":\"000001\"}]},"
        "\"nfServices\":[{\"serviceInstanceId\":\"a\",\"serviceName\":\"nsmf-pdusession\",\"versions\":[{\"apiVersionInUri\":\"v1\",\"apiFullVersion\":\"1.0.0\"}],\"scheme\":\"http\","
        "\"nfServiceStatus\":\"REGISTERED\"},{\"serviceInstanceId\":\"b\",\"serviceName\":\"nsmf-event-exposure\",\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\"}]";
    register_ok(e, SMF1, "SMF", smf_extra);
    register_ok(e, UDM2, "UDM", "\"priority\":1,\"locality\":\"dc-a\",\"udmInfo\":{\"supiRanges\":[{\"start\":\"001010000000000\",\"end\":\"001010000009999\"}]},"
                                "\"nfServices\":[{\"serviceInstanceId\":\"c\",\"serviceName\":\"nudm-sdm\",\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\"},"
                                "{\"serviceInstanceId\":\"d\",\"serviceName\":\"nudm-uecm\",\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\"}]");
    register_ok(e, AMF1, "AMF", "\"amfInfo\":{\"amfSetId\":\"1\",\"amfRegionId\":\"2\",\"taiList\":[{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"tac\":\"000002\"}]}");
    register_ok(e, AUSF1, "AUSF", "\"allowedNfTypes\":[\"AMF\"],\"ausfInfo\":{\"supiRanges\":[{\"pattern\":\"^imsi-0010199.*$\"}]}");
    register_ok(e, PCF1, "PCF", "\"pcfInfo\":{\"dnnList\":[\"internet\"]}");

    TK_ASSERT(discover(e, "requester-nf-type=AMF", ids, &st) == 0 && st == 400);
    TK_ASSERT(discover(e, "target-nf-type=UDM", ids, &st) == 0 && st == 400);
    TK_ASSERT(discover(e, "target-nf-type=UDM&requester-nf-type=AMF&limit=0", ids, &st) == 0 && st == 400);
    TK_ASSERT(discover(e, "target-nf-type=UDM&requester-nf-type=AMF&complexQuery=x", ids, &st) == 0 && st == 400);
    TK_ASSERT(discover(e, "target-nf-type=UDM&requester-nf-type=AMF&snssais=notjson", ids, &st) == 0 && st == 400);

    /* by type: both UDMs, the one with the lower priority value first */
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AMF", ids, &st);
    TK_ASSERT(st == 200 && n == 2 && strcmp(ids[0], UDM2) == 0 && strcmp(ids[1], UDM1) == 0);
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AMF&limit=1", ids, &st);
    TK_ASSERT(n == 1 && strcmp(ids[0], UDM2) == 0);
    /* by service: only the instance that offers it, and only that service in the answer */
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AMF&service-names=nudm-uecm", ids, &st);
    TK_ASSERT(n == 1 && strcmp(ids[0], UDM2) == 0);
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AMF&service-names=nudm-sdm,nudm-uecm", ids, &st); /* style form, explode false */
    TK_ASSERT(n == 2);
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AMF&service-names=nudm-sdm&service-names=nudm-uecm", ids, &st); /* repeated: accepted too */
    TK_ASSERT(n == 2);
    /* a single S-NSSAI object is not an array: refused */
    n = discover(e, "target-nf-type=SMF&requester-nf-type=AMF&snssais=%7B%22sst%22%3A1%7D", ids, &st);
    TK_ASSERT(n == 0 && st == 400);
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AMF&service-names=nudm-nothing", ids, &st);
    TK_ASSERT(st == 200 && n == 0);
    {
        char url[400], err[64];
        g5c_resp r;
        g5c_json *j;
        snprintf(url, sizeof url, "%s/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF&service-names=nudm-uecm", e->base);
        TK_ASSERT(call("GET", url, NULL, NULL, NULL, &r) == 200);
        j = g5c_json_parse((const char *)r.body, r.body_len, err, sizeof err);
        TK_ASSERT(g5c_json_len(g5c_json_get(g5c_json_at(g5c_json_get(j, "nfInstances"), 0), "nfServices")) == 1); /* the intersection */
        g5c_json_free(j);
        g5c_resp_free(&r);
    }
    /* by slice, DNN, TAI */
    n = discover(e, "target-nf-type=SMF&requester-nf-type=AMF&snssais=%5B%7B%22sst%22%3A1%7D%5D", ids, &st);
    TK_ASSERT(n == 1 && strcmp(ids[0], SMF1) == 0);
    n = discover(e, "target-nf-type=SMF&requester-nf-type=AMF&snssais=%5B%7B%22sst%22%3A2%7D%5D", ids, &st);
    TK_ASSERT(st == 200 && n == 0);
    n = discover(e, "target-nf-type=SMF&requester-nf-type=AMF&snssais=%5B%7B%22sst%22%3A1%2C%22sd%22%3A%22000001%22%7D%5D", ids, &st);
    TK_ASSERT(n == 1);
    n = discover(e, "target-nf-type=SMF&requester-nf-type=AMF&dnn=ims", ids, &st);
    TK_ASSERT(n == 1);
    n = discover(e, "target-nf-type=SMF&requester-nf-type=AMF&dnn=other", ids, &st);
    TK_ASSERT(n == 0);
    n = discover(e, "target-nf-type=SMF&requester-nf-type=AMF&tai=%7B%22plmnId%22%3A%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D%2C%22tac%22%3A%22000001%22%7D", ids, &st);
    TK_ASSERT(n == 1);
    n = discover(e, "target-nf-type=SMF&requester-nf-type=AMF&tai=%7B%22plmnId%22%3A%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D%2C%22tac%22%3A%22000009%22%7D", ids, &st);
    TK_ASSERT(n == 0);
    n = discover(e, "target-nf-type=AMF&requester-nf-type=SMF&amf-set-id=1&amf-region-id=2", ids, &st);
    TK_ASSERT(n == 1);
    n = discover(e, "target-nf-type=AMF&requester-nf-type=SMF&amf-set-id=7", ids, &st);
    TK_ASSERT(n == 0);
    /* by SUPI: a range and a pattern */
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AUSF&supi=imsi-001010000000123", ids, &st);
    TK_ASSERT(n == 2); /* UDM1 has no range (serves any), UDM2's range holds it */
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AUSF&supi=imsi-001019999999999", ids, &st);
    TK_ASSERT(n == 1 && strcmp(ids[0], UDM1) == 0);
    n = discover(e, "target-nf-type=AUSF&requester-nf-type=AMF&supi=imsi-001019900000001", ids, &st);
    TK_ASSERT(n == 1 && strcmp(ids[0], AUSF1) == 0);
    n = discover(e, "target-nf-type=AUSF&requester-nf-type=AMF&supi=imsi-001010000000001", ids, &st);
    TK_ASSERT(n == 0);
    /* allowedNfTypes: the AUSF profile admits AMF only */
    n = discover(e, "target-nf-type=AUSF&requester-nf-type=SMF", ids, &st);
    TK_ASSERT(st == 200 && n == 0);
    n = discover(e, "target-nf-type=AUSF&requester-nf-type=AMF", ids, &st);
    TK_ASSERT(n == 1);
    /* by instance id, and the preferred locality changes the order */
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AMF&target-nf-instance-id=11111111-1111-4111-8111-111111111111", ids, &st);
    TK_ASSERT(n == 1 && strcmp(ids[0], UDM1) == 0);
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AMF&preferred-locality=dc-b", ids, &st);
    TK_ASSERT(n == 2);
    /* a PLMN the NRF does not serve */
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AMF&target-plmn-list=%5B%7B%22mcc%22%3A%22999%22%2C%22mnc%22%3A%2299%22%7D%5D", ids, &st);
    TK_ASSERT(st == 200 && n == 0);
    n = discover(e, "target-nf-type=UDM&requester-nf-type=AMF&target-plmn-list=%5B%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D%5D", ids, &st);
    TK_ASSERT(n == 2);
    /* Service-Map: a profile registered with the nfServiceList map is returned as the nfServices array unless the consumer supports the feature,
     * and the other way round (TS 29.510 6.1.9) */
    {
        char url[500], err[64];
        g5c_resp r;
        g5c_json *j;
        register_ok(e, "99999999-9999-4999-8999-999999999999", "CUSTOM_MAP",
                    "\"nfServiceList\":{\"x1\":{\"serviceInstanceId\":\"x1\",\"serviceName\":\"nmap-one\",\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\","
                    "\"ipEndPoints\":[{\"ipv4Address\":\"10.9.9.9\",\"port\":8080}]}}");
        snprintf(url, sizeof url, "%s/nnrf-disc/v1/nf-instances?target-nf-type=CUSTOM_MAP&requester-nf-type=AMF", e->base);
        TK_ASSERT(call("GET", url, NULL, NULL, NULL, &r) == 200);
        j = g5c_json_parse((const char *)r.body, r.body_len, err, sizeof err);
        g5c_resp_free(&r);
        TK_ASSERT(g5c_json_len(g5c_json_get(g5c_json_at(g5c_json_get(j, "nfInstances"), 0), "nfServices")) == 1);
        TK_ASSERT(g5c_json_get(g5c_json_at(g5c_json_get(j, "nfInstances"), 0), "nfServiceList") == NULL);
        g5c_json_free(j);
        snprintf(url, sizeof url, "%s/nnrf-disc/v1/nf-instances?target-nf-type=CUSTOM_MAP&requester-nf-type=AMF&supported-features=1", e->base);
        TK_ASSERT(call("GET", url, NULL, NULL, NULL, &r) == 200);
        j = g5c_json_parse((const char *)r.body, r.body_len, err, sizeof err);
        g5c_resp_free(&r);
        TK_ASSERT(g5c_json_get(g5c_json_get(g5c_json_at(g5c_json_get(j, "nfInstances"), 0), "nfServiceList"), "x1") != NULL);
        TK_ASSERT(g5c_json_get(g5c_json_at(g5c_json_get(j, "nfInstances"), 0), "nfServices") == NULL);
        g5c_json_free(j);
        n = discover(e, "target-nf-type=CUSTOM_MAP&requester-nf-type=AMF&service-names=nmap-other", ids, &st);
        TK_ASSERT(st == 200 && n == 0);
    }
    /* an unknown parameter is ignored */
    n = discover(e, "target-nf-type=PCF&requester-nf-type=SMF&dnn=internet&some-new-parameter=1", ids, &st);
    TK_ASSERT(st == 200 && n == 1);
}

static void test_subscriptions(const env_t *e, const char *cb_url)
{
    g5c_resp r;
    char url[300], sub1[40], *b, ev[40], uri[300];
    g5c_json *j;
    const char *loc;
    const char *CUS = "77777777-7777-4777-8777-777777777777";
    cb_reset();
    /* refusals */
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/subscriptions", e->base);
    TK_ASSERT(call("POST", url, G5C_JSON_TYPE, "{}", NULL, &r) == 400);
    g5c_resp_free(&r);
    TK_ASSERT(call("POST", url, G5C_JSON_TYPE, "{\"nfStatusNotificationUri\":\"ftp://x\"}", NULL, &r) == 400);
    g5c_resp_free(&r);
    b = g5c_xasprintf("{\"nfStatusNotificationUri\":\"%s\",\"subscrCond\":{\"guamiList\":[]}}", cb_url);
    TK_ASSERT(call("POST", url, G5C_JSON_TYPE, b, NULL, &r) == 400);
    g5c_resp_free(&r);
    free(b);
    b = g5c_xasprintf("{\"nfStatusNotificationUri\":\"%s\",\"reqNotifEvents\":[\"NF_EXPLODED\"]}", cb_url);
    TK_ASSERT(call("POST", url, G5C_JSON_TYPE, b, NULL, &r) == 400);
    g5c_resp_free(&r);
    free(b);

    /* all events of one NF type */
    b = g5c_xasprintf("{\"nfStatusNotificationUri\":\"%s\",\"subscrCond\":{\"nfType\":\"CUSTOM_CUS\"}}", cb_url);
    TK_ASSERT(call("POST", url, G5C_JSON_TYPE, b, NULL, &r) == 201);
    free(b);
    loc = g5c_resp_header_get(&r, "location");
    TK_ASSERT(loc != NULL);
    j = g5c_resp_parse_json(&r);
    snprintf(sub1, sizeof sub1, "%s", g5c_json_get_str(j, "subscriptionId"));
    TK_ASSERT(g5c_json_get_str(j, "validityTime") != NULL);
    g5c_json_free(j);
    g5c_resp_free(&r);
    TK_ASSERT(nrf_subscription_count(e->n) == 1);

    register_ok(e, CUS, "CUSTOM_CUS", "\"priority\":1");
    TK_ASSERT(cb_wait(1, 3));
    cb_event(0, ev, sizeof ev, uri, sizeof uri);
    TK_ASSERT(strcmp(ev, "NF_REGISTERED") == 0 && strstr(uri, CUS) != NULL && strstr(uri, e->base) == uri);
    register_ok(e, SMF1, "SMF", "\"priority\":9"); /* another type: no notification */
    {
        g5c_resp pr;
        TK_ASSERT(patch_profile(e, CUS, "[{\"op\":\"replace\",\"path\":\"/priority\",\"value\":3}]", NULL, &pr) == 200);
        g5c_resp_free(&pr);
        TK_ASSERT(cb_wait(2, 3));
        cb_event(1, ev, sizeof ev, uri, sizeof uri);
        TK_ASSERT(strcmp(ev, "NF_PROFILE_CHANGED") == 0);
        /* a load report alone does not notify */
        TK_ASSERT(patch_profile(e, CUS, "[{\"op\":\"replace\",\"path\":\"/nfStatus\",\"value\":\"REGISTERED\"},{\"op\":\"add\",\"path\":\"/load\",\"value\":7}]", NULL, &pr) == 204);
        g5c_resp_free(&pr);
    }
    usleep(300000);
    TK_ASSERT(cb_count() == 2);
    TK_ASSERT(simple(e, "DELETE", "/nnrf-nfm/v1/nf-instances/77777777-7777-4777-8777-777777777777") == 204);
    TK_ASSERT(cb_wait(3, 3));
    cb_event(2, ev, sizeof ev, uri, sizeof uri);
    TK_ASSERT(strcmp(ev, "NF_DEREGISTERED") == 0);

    /* extend, then remove */
    {
        char p[300], body[200];
        g5c_resp pr;
        snprintf(p, sizeof p, "%s/nnrf-nfm/v1/subscriptions/%s", e->base, sub1);
        snprintf(body, sizeof body, "[{\"op\":\"replace\",\"path\":\"/validityTime\",\"value\":\"2099-01-01T00:00:00Z\"}]");
        TK_ASSERT(call("PATCH", p, "application/json-patch+json", body, NULL, &pr) == 200);
        g5c_resp_free(&pr);
        TK_ASSERT(call("PATCH", p, "application/json-patch+json", "[{\"op\":\"replace\",\"path\":\"/validityTime\",\"value\":\"2001-01-01T00:00:00Z\"}]", NULL, &pr) == 400);
        g5c_resp_free(&pr);
        TK_ASSERT(call("PATCH", p, "application/json-patch+json", "[{\"op\":\"replace\",\"path\":\"/nfType\",\"value\":\"x\"}]", NULL, &pr) == 400);
        g5c_resp_free(&pr);
        TK_ASSERT(call("DELETE", p, NULL, NULL, NULL, &pr) == 204);
        g5c_resp_free(&pr);
        TK_ASSERT(call("DELETE", p, NULL, NULL, NULL, &pr) == 404);
        g5c_resp_free(&pr);
    }
    TK_ASSERT(nrf_subscription_count(e->n) == 0);

    /* a subscription to one instance and to selected events only */
    cb_reset();
    b = g5c_xasprintf("{\"nfStatusNotificationUri\":\"%s\",\"subscrCond\":{\"nfInstanceId\":\"%s\"},\"reqNotifEvents\":[\"NF_DEREGISTERED\"]}", cb_url, CUS);
    TK_ASSERT(call("POST", url, G5C_JSON_TYPE, b, NULL, &r) == 201);
    free(b);
    g5c_resp_free(&r);
    register_ok(e, CUS, "CUSTOM_CUS", NULL);
    usleep(300000);
    TK_ASSERT(cb_count() == 0);
    TK_ASSERT(simple(e, "DELETE", "/nnrf-nfm/v1/nf-instances/77777777-7777-4777-8777-777777777777") == 204);
    TK_ASSERT(cb_wait(1, 3));
    /* a subscription to a service and to monitored attributes only */
    cb_reset();
    b = g5c_xasprintf("{\"nfStatusNotificationUri\":\"%s\",\"subscrCond\":{\"nfType\":\"CUSTOM_CUS\"},\"reqNotifEvents\":[\"NF_PROFILE_CHANGED\"],"
                      "\"notifCondition\":{\"monitoredAttributes\":[\"/capacity\"]}}",
                      cb_url);
    TK_ASSERT(call("POST", url, G5C_JSON_TYPE, b, NULL, &r) == 201);
    free(b);
    g5c_resp_free(&r);
    register_ok(e, CUS, "CUSTOM_CUS", "\"capacity\":10");
    {
        g5c_resp pr;
        TK_ASSERT(patch_profile(e, CUS, "[{\"op\":\"add\",\"path\":\"/priority\",\"value\":4}]", NULL, &pr) == 200);
        g5c_resp_free(&pr);
        usleep(300000);
        TK_ASSERT(cb_count() == 0); /* not a monitored attribute */
        TK_ASSERT(patch_profile(e, CUS, "[{\"op\":\"replace\",\"path\":\"/capacity\",\"value\":20}]", NULL, &pr) == 200);
        g5c_resp_free(&pr);
    }
    TK_ASSERT(cb_wait(1, 3));
    TK_ASSERT(simple(e, "DELETE", "/nnrf-nfm/v1/nf-instances/77777777-7777-4777-8777-777777777777") == 204);
    /* leave no subscription behind for the next case */
    {
        char p[300];
        for (int i = 1; i < 10; i++) {
            snprintf(p, sizeof p, "/nnrf-nfm/v1/subscriptions/%d", i);
            (void)simple(e, "DELETE", p);
        }
    }
}

static void test_monitor(const env_t *e, const char *cb_url)
{
    char ids[8][37], status[16], url[300], *b, ev[40], uri[300];
    int st;
    g5c_resp r;
    const char *HB = "88888888-8888-4888-8888-888888888888";
    cb_reset();
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/subscriptions", e->base);
    b = g5c_xasprintf("{\"nfStatusNotificationUri\":\"%s\",\"subscrCond\":{\"nfInstanceId\":\"%s\"}}", cb_url, HB);
    TK_ASSERT(call("POST", url, G5C_JSON_TYPE, b, NULL, &r) == 201);
    g5c_resp_free(&r);
    free(b);
    register_ok(e, HB, "CUSTOM_HB", NULL);
    TK_ASSERT(cb_wait(1, 3));
    TK_ASSERT(discover(e, "target-nf-type=CUSTOM_HB&requester-nf-type=AMF", ids, &st) == 1);
    /* silent for more than suspend_after (2) x heartBeatTimer (1 s): SUSPENDED, not discoverable, subscribers told */
    {
        double end = now_s() + 6;
        bool susp = false;
        while (now_s() < end && !susp)
            susp = nrf_profile_status(e->n, HB, status, sizeof status) && strcmp(status, "SUSPENDED") == 0 ? true : (usleep(50000), false);
        TK_ASSERT(susp);
    }
    TK_ASSERT(cb_wait(2, 3));
    cb_event(1, ev, sizeof ev, uri, sizeof uri);
    TK_ASSERT(strcmp(ev, "NF_PROFILE_CHANGED") == 0);
    TK_ASSERT(discover(e, "target-nf-type=CUSTOM_HB&requester-nf-type=AMF", ids, &st) == 0 && st == 200);
    /* a heart-beat brings it back */
    {
        g5c_resp pr;
        TK_ASSERT(patch_profile(e, HB, "[{\"op\":\"replace\",\"path\":\"/nfStatus\",\"value\":\"REGISTERED\"}]", NULL, &pr) == 200); /* the status changed: the profile comes back */
        g5c_resp_free(&pr);
    }
    TK_ASSERT(nrf_profile_status(e->n, HB, status, sizeof status) && strcmp(status, "REGISTERED") == 0);
    TK_ASSERT(discover(e, "target-nf-type=CUSTOM_HB&requester-nf-type=AMF", ids, &st) == 1);
    /* silent again: SUSPENDED and, after purge_after (3 s), removed with a deregistration notice */
    {
        double end = now_s() + 12;
        while (now_s() < end && nrf_profile_status(e->n, HB, status, sizeof status))
            usleep(50000);
        TK_ASSERT(!nrf_profile_status(e->n, HB, status, sizeof status));
    }
    TK_ASSERT(cb_wait(5, 3)); /* registered, suspended, changed back, suspended, deregistered */
    cb_event(cb_count() - 1, ev, sizeof ev, uri, sizeof uri);
    TK_ASSERT(strcmp(ev, "NF_DEREGISTERED") == 0);
    {
        char p[300];
        for (int i = 1; i < 12; i++) {
            snprintf(p, sizeof p, "/nnrf-nfm/v1/subscriptions/%d", i);
            (void)simple(e, "DELETE", p);
        }
    }
}

static char *form(const char *grant, const char *id, const char *type, const char *scope, const char *ttype, const char *tid)
{
    char *b = g5c_xasprintf("grant_type=%s&nfInstanceId=%s&nfType=%s&scope=%s", grant, id, type, scope);
    if (ttype != NULL) {
        char *x = g5c_xasprintf("%s&targetNfType=%s", b, ttype);
        free(b);
        b = x;
    }
    if (tid != NULL) {
        char *x = g5c_xasprintf("%s&targetNfInstanceId=%s", b, tid);
        free(b);
        b = x;
    }
    return b;
}

static int token_req(const env_t *e, const char *body, g5c_json **rsp)
{
    char url[200];
    g5c_resp r;
    int st;
    snprintf(url, sizeof url, "%s/oauth2/token", e->base);
    st = call("POST", url, "application/x-www-form-urlencoded", body, NULL, &r);
    *rsp = g5c_resp_parse_json(&r);
    g5c_resp_free(&r);
    return st;
}

static void test_tokens(const env_t *e)
{
    g5c_json *rsp = NULL, *jwk, *claims, *keyset;
    char url[200], *b;
    g5c_resp r;
    g5c_jwt_key *pub;
    char err[100], tok[1100];
    int64_t exp = 0;
    const char *svc = "\"nfServices\":[{\"serviceInstanceId\":\"s\",\"serviceName\":\"nudm-sdm\",\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\"}]";
    /* the earlier cases left the heart-beat monitor to purge everything: register the producers and the consumers afresh */
    register_ok(e, UDM1, "UDM", svc);
    register_ok(e, UDM2, "UDM", svc);
    register_ok(e, AMF1, "AMF", NULL);
    register_ok(e, PCF1, "PCF", NULL);
    register_ok(e, AUSF1, "AUSF", "\"allowedNfTypes\":[\"AMF\"],\"nfServices\":[{\"serviceInstanceId\":\"t\",\"serviceName\":\"nausf-auth\",\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\"}]");
    /* the key set */
    snprintf(url, sizeof url, "%s/oauth2/jwks", e->base);
    TK_ASSERT(call("GET", url, NULL, NULL, NULL, &r) == 200);
    keyset = g5c_resp_parse_json(&r);
    g5c_resp_free(&r);
    jwk = g5c_json_dup(g5c_json_at(g5c_json_get(keyset, "keys"), 0));
    g5c_json_free(keyset);
    pub = g5c_jwt_key_from_jwk(jwk, err, sizeof err);
    TK_ASSERT(pub != NULL);
    g5c_json_free(jwk);
    /* a registered AMF asks for nudm-sdm of the UDMs */
    b = form("client_credentials", AMF1, "AMF", "nudm-sdm", "UDM", NULL);
    TK_ASSERT(token_req(e, b, &rsp) == 200);
    free(b);
    TK_ASSERT(strcmp(g5c_json_get_str(rsp, "token_type"), "Bearer") == 0);
    snprintf(tok, sizeof tok, "%s", g5c_json_get_str(rsp, "access_token"));
    TK_ASSERT(g5c_json_get(rsp, "expires_in") != NULL);
    g5c_json_free(rsp);
    claims = g5c_jwt_verify(pub, tok, err, sizeof err);
    TK_ASSERT(claims != NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(claims, "sub"), AMF1) == 0 && strcmp(g5c_json_get_str(claims, "scope"), "nudm-sdm") == 0 &&
              strcmp(g5c_json_get_str(claims, "aud"), "UDM") == 0 && g5c_json_get_str(claims, "iss") != NULL);
    TK_ASSERT(g5c_json_get_int(claims, "exp", &exp) && exp > (int64_t)time(NULL));
    g5c_json_free(claims);
    /* a damaged token does not verify, nor does one with another algorithm */
    {
        char bad[1100];
        snprintf(bad, sizeof bad, "%s", tok);
        bad[strlen(bad) - 3] = bad[strlen(bad) - 3] == 'A' ? 'B' : 'A';
        TK_ASSERT(g5c_jwt_verify(pub, bad, err, sizeof err) == NULL);
        TK_ASSERT(g5c_jwt_verify(pub, "eyJhbGciOiJub25lIn0.e30.", err, sizeof err) == NULL);
        TK_ASSERT(g5c_jwt_verify(pub, "a.b", err, sizeof err) == NULL);
    }
    /* refusals */
    b = form("password", AMF1, "AMF", "nudm-sdm", "UDM", NULL);
    TK_ASSERT(token_req(e, b, &rsp) == 400 && strcmp(g5c_json_get_str(rsp, "error"), "unsupported_grant_type") == 0);
    g5c_json_free(rsp);
    free(b);
    b = form("client_credentials", "99999999-9999-4999-8999-999999999999", "AMF", "nudm-sdm", "UDM", NULL);
    TK_ASSERT(token_req(e, b, &rsp) == 400 && strcmp(g5c_json_get_str(rsp, "error"), "invalid_client") == 0);
    g5c_json_free(rsp);
    free(b);
    b = form("client_credentials", AMF1, "SMF", "nudm-sdm", "UDM", NULL); /* registered as AMF, claims to be SMF */
    TK_ASSERT(token_req(e, b, &rsp) == 400 && strcmp(g5c_json_get_str(rsp, "error"), "invalid_client") == 0);
    g5c_json_free(rsp);
    free(b);
    b = form("client_credentials", AMF1, "AMF", "nudm-nothing", "UDM", NULL);
    TK_ASSERT(token_req(e, b, &rsp) == 400 && strcmp(g5c_json_get_str(rsp, "error"), "invalid_scope") == 0);
    g5c_json_free(rsp);
    free(b);
    b = form("client_credentials", AMF1, "AMF", "nudm-sdm", NULL, NULL);
    TK_ASSERT(token_req(e, b, &rsp) == 400 && strcmp(g5c_json_get_str(rsp, "error"), "invalid_request") == 0);
    g5c_json_free(rsp);
    free(b);
    /* the AUSF allows only AMF: a PCF cannot get a token for it */
    b = form("client_credentials", PCF1, "PCF", "nausf-auth", "AUSF", NULL);
    TK_ASSERT(token_req(e, b, &rsp) == 400);
    g5c_json_free(rsp);
    free(b);
    /* for one instance, and for the NRF itself */
    b = form("client_credentials", AMF1, "AMF", "nudm-sdm", NULL, UDM2);
    TK_ASSERT(token_req(e, b, &rsp) == 200);
    g5c_json_free(rsp);
    free(b);
    b = form("client_credentials", AMF1, "AMF", "nnrf-disc", "NRF", NULL);
    TK_ASSERT(token_req(e, b, &rsp) == 200);
    g5c_json_free(rsp);
    free(b);
    g5c_jwt_key_free(pub);
}

/* the discovery client the other functions use: endpoint of the first instance, cached for the validity period, forgotten on request */
static void test_discovery_client(const env_t *e)
{
    g5c_disc *d = g5c_disc_new(cl, e->base, "AMF", AMF1);
    g5c_disc_opts o;
    char *root;
    const char *ID = "abababab-abab-4bab-8bab-abababababab";
    char url[300];
    g5c_resp r;
    TK_ASSERT(g5c_disc_root(d, "CUSTOM_DISC", "ndisc-one", NULL) == NULL); /* nothing registered */
    register_ok(e, ID, "CUSTOM_DISC",
                "\"nfServices\":[{\"serviceInstanceId\":\"a\",\"serviceName\":\"ndisc-one\",\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\","
                "\"ipEndPoints\":[{\"ipv4Address\":\"10.7.7.7\",\"port\":9090}]}]");
    root = g5c_disc_root(d, "CUSTOM_DISC", "ndisc-one", NULL);
    TK_ASSERT(root != NULL && strcmp(root, "http://10.7.7.7:9090") == 0);
    free(root);
    /* cached: the answer survives the instance's deregistration until it is forgotten */
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/nf-instances/%s", e->base, ID);
    TK_ASSERT(call("DELETE", url, NULL, NULL, NULL, &r) == 204);
    g5c_resp_free(&r);
    root = g5c_disc_root(d, "CUSTOM_DISC", "ndisc-one", NULL);
    TK_ASSERT(root != NULL);
    free(root);
    g5c_disc_forget(d, "CUSTOM_DISC");
    TK_ASSERT(g5c_disc_root(d, "CUSTOM_DISC", "ndisc-one", NULL) == NULL);
    /* filters are passed on */
    memset(&o, 0, sizeof o);
    o.dnn = "internet";
    o.snssai_json = "[{\"sst\":1}]";
    register_ok(e, SMF1, "SMF",
                "\"smfInfo\":{\"sNssaiSmfInfoList\":[{\"sNssai\":{\"sst\":1},\"dnnSmfInfoList\":[{\"dnn\":\"internet\"}]}]},"
                "\"nfServices\":[{\"serviceInstanceId\":\"b\",\"serviceName\":\"nsmf-pdusession\",\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\","
                "\"ipEndPoints\":[{\"ipv4Address\":\"10.7.7.8\",\"port\":7777}]}]");
    root = g5c_disc_root(d, "SMF", "nsmf-pdusession", &o);
    TK_ASSERT(root != NULL && strcmp(root, "http://10.7.7.8:7777") == 0);
    free(root);
    o.dnn = "ims";
    TK_ASSERT(g5c_disc_root(d, "SMF", "nsmf-pdusession", &o) == NULL);
    g5c_disc_free(d);
}

static void test_enforcement(void)
{
    env_t e;
    g5c_json *rsp = NULL;
    char *b, tok[1100], ids[8][37];
    g5c_resp r;
    char url[300];
    int st;
    TK_ASSERT(env_start(&e, "  oauth2: { enabled: true, enforce: true, token_lifetime: 60 }\n", NULL));
    /* registering needs no token; discovery does */
    register_ok(&e, UDM1, "UDM", "\"nfServices\":[{\"serviceInstanceId\":\"s\",\"serviceName\":\"nudm-sdm\",\"scheme\":\"http\",\"nfServiceStatus\":\"REGISTERED\"}]");
    register_ok(&e, AMF1, "AMF", NULL);
    TK_ASSERT(discover(&e, "target-nf-type=UDM&requester-nf-type=AMF", ids, &st) == 0 && st == 401);
    TK_ASSERT(simple(&e, "GET", "/nnrf-nfm/v1/nf-instances") == 401);
    b = form("client_credentials", AMF1, "AMF", "nnrf-disc", "NRF", NULL);
    TK_ASSERT(token_req(&e, b, &rsp) == 200);
    free(b);
    snprintf(tok, sizeof tok, "%s", g5c_json_get_str(rsp, "access_token"));
    g5c_json_free(rsp);
    snprintf(url, sizeof url, "%s/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF", e.base);
    TK_ASSERT(call("GET", url, NULL, NULL, tok, &r) == 200);
    g5c_resp_free(&r);
    snprintf(url, sizeof url, "%s/nnrf-nfm/v1/nf-instances", e.base); /* the token covers nnrf-disc only */
    TK_ASSERT(call("GET", url, NULL, NULL, tok, &r) == 403);
    g5c_resp_free(&r);
    TK_ASSERT(call("GET", url, NULL, NULL, "garbage.token.value", &r) == 401);
    g5c_resp_free(&r);
    /* a token for another audience is no good here */
    b = form("client_credentials", AMF1, "AMF", "nudm-sdm", "UDM", NULL);
    TK_ASSERT(token_req(&e, b, &rsp) == 200);
    free(b);
    snprintf(tok, sizeof tok, "%s", g5c_json_get_str(rsp, "access_token"));
    g5c_json_free(rsp);
    snprintf(url, sizeof url, "%s/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF", e.base);
    TK_ASSERT(call("GET", url, NULL, NULL, tok, &r) == 403);
    g5c_resp_free(&r);
    /* health and metrics are not behind the guard (they are served by the runtime, not by this router) */
    env_stop(&e);
}

static void test_persistence(void)
{
    env_t e;
    char path[] = "/tmp/g5c-nrf-state-XXXXXX", status[16], ids[8][37];
    int fd = mkstemp(path), st;
    TK_ASSERT(fd >= 0);
    close(fd);
    unlink(path);
    TK_ASSERT(env_start(&e, "  heartbeat_timer: 30\n", path));
    register_ok(&e, UDM1, "UDM", "\"priority\":4");
    register_ok(&e, AMF1, "AMF", NULL);
    {
        g5c_resp r;
        char url[300], *b = g5c_xasprintf("{\"nfStatusNotificationUri\":\"http://127.0.0.1:9/x\",\"subscrCond\":{\"nfType\":\"AMF\"}}");
        snprintf(url, sizeof url, "%s/nnrf-nfm/v1/subscriptions", e.base);
        TK_ASSERT(call("POST", url, G5C_JSON_TYPE, b, NULL, &r) == 201);
        g5c_resp_free(&r);
        free(b);
    }
    env_stop(&e); /* writes the state file */
    TK_ASSERT(access(path, F_OK) == 0);
    TK_ASSERT(env_start(&e, "  heartbeat_timer: 30\n", path));
    TK_ASSERT(nrf_profile_count(e.n) == 2 && nrf_subscription_count(e.n) == 1);
    TK_ASSERT(nrf_profile_status(e.n, UDM1, status, sizeof status) && strcmp(status, "REGISTERED") == 0);
    TK_ASSERT(discover(&e, "target-nf-type=UDM&requester-nf-type=AMF", ids, &st) == 1 && strcmp(ids[0], UDM1) == 0);
    env_stop(&e);
    unlink(path);
}

static void test_config_errors(void)
{
    static const char *const bad[] = {
        "  heartbeat_timer: 0\n",
        "  heartbeat_timer: abc\n",
        "  suspend_after: 0\n",
        "  validity_period: 0\n",
        "  max_profiles: 0\n",
        "  unknown_key: 1\n",
        "  oauth2: { enabled: false, enforce: true }\n",
        "  oauth2: { token_lifetime: 0 }\n",
        "  oauth2: { surprise: 1 }\n",
        "  oauth2: 7\n",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        env_t e;
        char yaml[600], err[300];
        g5c_json *j;
        g5c_common common;
        g5c_nf *nf;
        nrf *n;
        snprintf(yaml, sizeof yaml, "name: nrf-test\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\nregistry:\n%s", bad[i]);
        j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
        TK_ASSERT(j != NULL && g5c_common_parse(j, &common, err, sizeof err) == 0);
        nf = g5c_nf_new(&common, err, sizeof err);
        TK_ASSERT(nf != NULL);
        n = nrf_from_config(j, nf, err, sizeof err);
        if (n != NULL)
            TK_FAIL("configuration %zu was accepted: %s", i, bad[i]);
        TK_ASSERT(err[0] != 0);
        g5c_json_free(j);
        g5c_nf_free(nf);
        (void)e;
    }
}

int main(void)
{
    env_t e;
    g5c_router *cbr = g5c_router_new();
    g5c_server_cfg sc = {"127.0.0.1", 0, NULL};
    g5c_server *cbs;
    char err[200], cb_url[100];
    cl = g5c_client_new(4000, NULL);
    g5c_router_route(cbr, "POST", "/cb", cb_recv, NULL);
    cbs = g5c_server_start(&sc, cbr, err, sizeof err);
    TK_ASSERT(cbs != NULL);
    snprintf(cb_url, sizeof cb_url, "http://127.0.0.1:%u/cb", g5c_server_port(cbs));

    TK_ASSERT(env_start(&e, "  heartbeat_timer: 1\n  suspend_after: 2\n  purge_after: 3\n  validity_period: 7\n", NULL));
    test_registration(&e);
    test_update(&e);
    test_discovery(&e);
    test_subscriptions(&e, cb_url);
    test_monitor(&e, cb_url);
    test_tokens(&e);
    test_discovery_client(&e);
    env_stop(&e);

    test_enforcement();
    test_persistence();
    test_config_errors();

    g5c_server_stop(cbs);
    g5c_router_free(cbr);
    g5c_client_free(cl);
    printf("nrf e2e: OK\n");
    return 0;
}
