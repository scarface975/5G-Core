/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* PCF: policy engine unit tests, and the services over real sockets: SM policy lifecycle, validation, layered policy, mid-session pushes to a mock SMF */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

#include "g5c/bsf.h"
#include "g5c/pcf.h"
#include "g5c/testkit.h"
#include "g5c/udr.h"

#define ADMIN "admin-token-0123456789"
#define SUPI "imsi-001010000000001"

static g5c_json *J(const char *s)
{
    g5c_json *j = g5c_json_parse(s, strlen(s), NULL, 0);
    TK_ASSERT(j != NULL);
    return j;
}

static g5c_json *Y(const char *s)
{
    char err[160];
    g5c_json *j = g5c_yaml_parse(s, strlen(s), err, sizeof err);
    if (j == NULL)
        TK_FAIL("yaml: %s", err);
    return j;
}

static void expect_json(const g5c_json *j, const char *want)
{
    g5c_json *w = J(want);
    if (!g5c_json_equal(j, w)) {
        char *a = g5c_json_to_string(j, NULL);
        TK_FAIL("json differs: got %s want %s", a, want);
    }
    g5c_json_free(w);
}

/* ---- policy engine ---- */

static pcf_policy parse_policy(const char *yaml, bool cfg)
{
    char err[200];
    pcf_policy p;
    g5c_json *j = Y(yaml);
    TK_ASSERT(pcf_policy_parse(j, cfg, &p, err, sizeof err) == 0);
    g5c_json_free(j);
    return p;
}

static pcf_session_info info_for(const char *dnn, const char *subs_ambr_json, const char *subs_qos_json)
{
    pcf_session_info s;
    memset(&s, 0, sizeof s);
    s.dnn = g5c_xstrdup(dnn);
    if (subs_ambr_json) {
        g5c_json *a = J(subs_ambr_json);
        char err[100];
        TK_ASSERT(pcf_ambr_parse(a, &s.subs_ambr, err, sizeof err) == 0);
        s.has_ambr = true;
        g5c_json_free(a);
    }
    if (subs_qos_json)
        s.subs_def_qos = J(subs_qos_json);
    return s;
}

static void test_bitrates(void)
{
    static const char *const ok[] = {"1 Gbps", "100 Mbps", "0.5 Kbps", "64 bps", "2 Tbps"};
    static const char *const bad[] = {"1Gbps", "Gbps", "1 gbps", "1..5 Mbps", ".5 Mbps", "5. Mbps", "1 Mb", "", "x Mbps"};
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++)
        TK_ASSERT(pcf_valid_bitrate(ok[i]));
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
        TK_ASSERT(!pcf_valid_bitrate(bad[i]));
    TK_ASSERT(pcf_is_gbr_5qi(1) && pcf_is_gbr_5qi(71) && !pcf_is_gbr_5qi(9) && !pcf_is_gbr_5qi(5));
}

static void test_resolution(void)
{
    pcf_policy none = parse_policy("{}", true), cfg;
    pcf_session_info s = info_for("internet", NULL, NULL), s2;
    pcf_resolved r = pcf_resolve(&s, &none, NULL);
    TK_ASSERT(strcmp(r.ambr.uplink, "1 Gbps") == 0 && r.qos.qi5 == 9 && r.nrules == 0); /* built-in defaults */
    pcf_resolved_free(&r);
    pcf_session_info_free(&s);

    /* subscribed values apply below operator policy */
    s = info_for("internet", "{\"uplink\":\"50 Mbps\",\"downlink\":\"100 Mbps\"}",
                 "{\"5qi\":8,\"arp\":{\"priorityLevel\":3,\"preemptCap\":\"MAY_PREEMPT\",\"preemptVuln\":\"NOT_PREEMPTABLE\"},\"priorityLevel\":90}");
    r = pcf_resolve(&s, &none, NULL);
    TK_ASSERT(strcmp(r.ambr.uplink, "50 Mbps") == 0 && strcmp(r.ambr.downlink, "100 Mbps") == 0);
    TK_ASSERT(r.qos.qi5 == 8 && r.qos.arp_priority == 3 && r.qos.preempt_cap && !r.qos.preempt_vuln &&
              r.qos.has_priority_level && r.qos.priority_level == 90);
    pcf_resolved_free(&r);
    cfg = parse_policy("default: { session_ambr: { uplink: '10 Mbps', downlink: '20 Mbps' } }\n", true);
    r = pcf_resolve(&s, &cfg, NULL);
    TK_ASSERT(strcmp(r.ambr.uplink, "10 Mbps") == 0 && r.qos.qi5 == 8); /* QoS still from the subscription */
    pcf_resolved_free(&r);
    pcf_session_info_free(&s);
    pcf_policy_free(&cfg);

    /* layers resolve each field independently */
    cfg = parse_policy("default: { session_ambr: { uplink: '1 Gbps', downlink: '1 Gbps' } }\ndnns:\n  ims:\n    default_qos: { qi5: 5 }\n", true);
    {
        pcf_policy sub = parse_policy("default: { session_ambr: { uplink: '5 Mbps', downlink: '5 Mbps' } }\ndnns:\n  ims:\n    session_ambr: { uplink: '2 Mbps', downlink: '2 Mbps' }\n", false);
        s = info_for("ims", NULL, NULL);
        s2 = info_for("internet", NULL, NULL);
        r = pcf_resolve(&s, &cfg, &sub);
        TK_ASSERT(strcmp(r.ambr.uplink, "2 Mbps") == 0); /* subscriber DNN profile wins */
        TK_ASSERT(r.qos.qi5 == 5);                       /* QoS from the configured DNN profile */
        pcf_resolved_free(&r);
        r = pcf_resolve(&s2, &cfg, &sub);
        TK_ASSERT(strcmp(r.ambr.uplink, "5 Mbps") == 0 && r.qos.qi5 == 9); /* subscriber default for other DNNs */
        pcf_resolved_free(&r);
        pcf_session_info_free(&s);
        pcf_session_info_free(&s2);
        pcf_policy_free(&sub);
    }
    pcf_policy_free(&cfg);
    pcf_policy_free(&none);
}

static void test_decision_shape(void)
{
    pcf_policy cfg = parse_policy("default:\n  pcc_rules:\n    - id: voice\n      flows: ['permit out 17 from any to assigned']\n      qi5: 1\n"
                                  "      gbr_ul: '128 Kbps'\n      gbr_dl: '128 Kbps'\n      mbr_ul: '256 Kbps'\n", true);
    pcf_session_info s = info_for("internet", NULL, NULL);
    pcf_resolved r = pcf_resolve(&s, &cfg, NULL);
    g5c_json *d = pcf_decision(&r);
    const g5c_json *qd;
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(g5c_json_get(g5c_json_get(d, "sessRules"), "SessRule-1"), "authSessAmbr"), "uplink"), "1 Gbps") == 0);
    TK_ASSERT(strcmp(g5c_json_str(g5c_json_at(g5c_json_get(g5c_json_get(g5c_json_get(d, "pccRules"), "PccRule-voice"), "refQosData"), 0)), "QosData-voice") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(g5c_json_get(g5c_json_get(d, "pccRules"), "PccRule-voice"), "flowInfos"), 0), "flowDescription"), "permit out 17 from any to assigned") == 0);
    qd = g5c_json_get(g5c_json_get(d, "qosDecs"), "QosData-voice");
    TK_ASSERT(strcmp(g5c_json_get_str(qd, "gbrDl"), "128 Kbps") == 0 && strcmp(g5c_json_get_str(qd, "maxbrUl"), "256 Kbps") == 0 && g5c_json_get(qd, "maxbrDl") == NULL);
    g5c_json_free(d);
    pcf_resolved_free(&r);
    pcf_session_info_free(&s);
    pcf_policy_free(&cfg);
    cfg = parse_policy("{}", true);
    s = info_for("internet", NULL, NULL);
    r = pcf_resolve(&s, &cfg, NULL);
    d = pcf_decision(&r);
    TK_ASSERT(g5c_json_get(d, "pccRules") == NULL && g5c_json_get(d, "qosDecs") == NULL); /* no empty arrays/objects */
    g5c_json_free(d);
    pcf_resolved_free(&r);
    pcf_session_info_free(&s);
    pcf_policy_free(&cfg);
}

static bool invalid(const char *yaml, const char *field_prefix)
{
    char err[200], field[200] = "", reason[200];
    pcf_policy p;
    g5c_json *j = Y(yaml);
    bool bad;
    if (pcf_policy_parse(j, false, &p, err, sizeof err) != 0) {
        g5c_json_free(j);
        return field_prefix == NULL;
    }
    g5c_json_free(j);
    bad = pcf_policy_validate(&p, false, field, sizeof field, reason, sizeof reason) != 0;
    pcf_policy_free(&p);
    if (bad && field_prefix != NULL)
        return strncmp(field, field_prefix, strlen(field_prefix)) == 0;
    return bad;
}

static void test_validation(void)
{
    const char *base = "default:\n  pcc_rules:\n    - id: r1\n      flows: ['permit out ip from any to any']\n      precedence: 10\n";
    char y[512];
#define RULE(qi5, extra) (snprintf(y, sizeof y, "%s      qi5: %d\n%s", base, (qi5), (extra)), y)
    TK_ASSERT(!invalid(RULE(1, "      gbr_ul: '64 Kbps'\n      gbr_dl: '64 Kbps'\n"), NULL));
    TK_ASSERT(!invalid(RULE(9, ""), NULL));
    TK_ASSERT(invalid(RULE(1, ""), NULL));                                         /* GBR 5QI without rates */
    TK_ASSERT(invalid(RULE(9, "      gbr_ul: '64 Kbps'\n      gbr_dl: '64 Kbps'\n"), NULL)); /* rates on a non-GBR 5QI */
    TK_ASSERT(invalid(RULE(9, "      gbr_ul: '64Kbps'\n      gbr_dl: '64Kbps'\n"), NULL));
    TK_ASSERT(invalid("default:\n  pcc_rules:\n    - id: r1\n      flows: ['permit out ip from any to any']\n      qi5: 9\n    - id: r1\n      flows: ['permit out ip from any to any']\n      qi5: 9\n", NULL)); /* duplicate ids */
    TK_ASSERT(invalid("default: { default_qos: { qi5: 1 } }\n", NULL));            /* GBR default flow */
    TK_ASSERT(invalid("default: { session_ambr: { uplink: fast, downlink: '1 Gbps' } }\n", NULL));
    TK_ASSERT(invalid("dnns:\n  ims:\n    pcc_rules:\n      - id: r1\n        flows: ['permit out ip from any to any']\n        qi5: 1\n", "dnns.ims.pccRules[0]"));
    TK_ASSERT(invalid("unknown_field: 1\n", NULL));
    TK_ASSERT(invalid("default: { default_qos: { qi5: 9, arp_priority: 16 } }\n", "default.defaultQos.arpPriority"));
    TK_ASSERT(invalid("default:\n  pcc_rules:\n    - id: 'a b'\n      flows: ['permit out ip from any to any']\n      qi5: 9\n", NULL));
    TK_ASSERT(invalid("default:\n  pcc_rules:\n    - id: a\n      flows: ['deny out ip from any to any']\n      qi5: 9\n", NULL));
#undef RULE
}

static void test_policy_roundtrip(void)
{
    pcf_policy p = parse_policy("default: { default_qos: { qi5: 5 } }\ndnns:\n  b: { session_ambr: { uplink: '1 Mbps', downlink: '1 Mbps' } }\n  a: {}\n", false);
    g5c_json *j = pcf_policy_to_json(&p), *back;
    pcf_policy q;
    char err[100];
    /* Option fields serialise as null, like the stored documents always did */
    TK_ASSERT(g5c_json_is(g5c_json_get(g5c_json_get(g5c_json_get(j, "default"), "default_qos"), "priority_level"), G5C_J_NULL));
    TK_ASSERT(strcmp(g5c_json_key_at(g5c_json_get(j, "dnns"), 0), "a") == 0); /* sorted */
    TK_ASSERT(pcf_policy_parse(j, false, &q, err, sizeof err) == 0);
    back = pcf_policy_to_json(&q);
    TK_ASSERT(g5c_json_equal(j, back));
    g5c_json_free(j);
    g5c_json_free(back);
    pcf_policy_free(&p);
    pcf_policy_free(&q);
}

/* ---- services over real sockets ---- */

static _Atomic int g_note_status = 204; /* what the mock SMF and the mock AF answer */

typedef struct {
    pthread_mutex_t mu;
    int n;
    char kind[64][16];
    g5c_json *body[64];
} notes_t;

static void note(notes_t *n, const char *kind, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *j = g5c_req_json(req, resp);
    if (j == NULL)
        return;
    pthread_mutex_lock(&n->mu);
    if (n->n < 64) {
        snprintf(n->kind[n->n], sizeof n->kind[0], "%s", kind);
        n->body[n->n++] = j;
    } else {
        g5c_json_free(j);
    }
    pthread_mutex_unlock(&n->mu);
    g5c_resp_status(resp, g_note_status);
}

static void smf_update(void *c, const g5c_req *req, g5c_resp *resp) { note(c, "update", req, resp); }
static void smf_terminate(void *c, const g5c_req *req, g5c_resp *resp) { note(c, "terminate", req, resp); }

typedef struct {
    g5c_udr_store *store;
    g5c_router *udr_r;
    g5c_server *udr_s;
    g5c_registry *metrics;
    g5c_client *client;
    pcf p;
    g5c_router *r;
    g5c_server *srv;
    char base[64], udr[64];
    /* mock SMF */
    notes_t notes;
    g5c_router *smf_r;
    g5c_server *smf_s;
    char smf[64];
} T;

static void setup(T *t, const char *policy_yaml)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[160];
    pcf_policy pol = parse_policy(policy_yaml, true);
    memset(t, 0, sizeof *t);
    t->client = g5c_client_new(5000, NULL);
    t->store = g5c_udr_store_memory();
    t->udr_r = g5c_udr_router(t->store);
    t->udr_s = g5c_server_start(&cfg, t->udr_r, err, sizeof err);
    TK_ASSERT(t->udr_s != NULL);
    snprintf(t->udr, sizeof t->udr, "http://127.0.0.1:%u", g5c_server_port(t->udr_s));
    t->metrics = g5c_registry_new();
    pcf_init(&t->p, &pol, t->client, t->udr, t->metrics);
    t->p.admin_token = g5c_xstrdup(ADMIN);
    t->r = pcf_router(&t->p);
    t->srv = g5c_server_start(&cfg, t->r, err, sizeof err);
    TK_ASSERT(t->srv != NULL);
    snprintf(t->base, sizeof t->base, "http://127.0.0.1:%u", g5c_server_port(t->srv));
    pthread_mutex_init(&t->notes.mu, NULL);
    t->smf_r = g5c_router_new();
    g5c_router_route(t->smf_r, "POST", "/nsmf-callback/v1/sm-policy-notify/{supi}/{id}/update", smf_update, &t->notes);
    g5c_router_route(t->smf_r, "POST", "/nsmf-callback/v1/sm-policy-notify/{supi}/{id}/terminate", smf_terminate, &t->notes);
    t->smf_s = g5c_server_start(&cfg, t->smf_r, err, sizeof err);
    TK_ASSERT(t->smf_s != NULL);
    snprintf(t->smf, sizeof t->smf, "http://127.0.0.1:%u", g5c_server_port(t->smf_s));
}

static void teardown(T *t)
{
    g5c_server_stop(t->srv);
    g5c_server_stop(t->smf_s);
    g5c_server_stop(t->udr_s);
    pcf_destroy(&t->p); /* waits for the notifications to AFs that are on their way: they use the client */
    g5c_client_free(t->client);
    g5c_router_free(t->r);
    g5c_router_free(t->smf_r);
    g5c_router_free(t->udr_r);
    g5c_udr_store_free(t->store);
    g5c_registry_free(t->metrics);
    for (int i = 0; i < t->notes.n; i++)
        g5c_json_free(t->notes.body[i]);
    pthread_mutex_destroy(&t->notes.mu);
}

static int call(T *t, const char *method, const char *path, const char *body, bool admin, g5c_json **out, char **loc)
{
    char *url = g5c_xasprintf("%s%s", t->base, path), auth[64], err[160];
    g5c_kv hdr = {"authorization", auth};
    g5c_resp r;
    int st;
    snprintf(auth, sizeof auth, "Bearer %s", ADMIN);
    TK_ASSERT(g5c_client_request(t->client, method, url, admin ? &hdr : NULL, admin ? 1 : 0, G5C_JSON_TYPE, body,
                                 body ? strlen(body) : 0, &r, err, sizeof err) == 0);
    free(url);
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

static char *ctx_body(const char *dnn, const char *notif)
{
    return g5c_xasprintf("{\"supi\":\"" SUPI "\",\"pduSessionId\":1,\"pduSessionType\":\"IPV4\",\"dnn\":\"%s\","
                         "\"notificationUri\":\"%s/nsmf-callback/v1/sm-policy-notify/" SUPI "/1\","
                         "\"sliceInfo\":{\"sst\":1},\"accessType\":\"3GPP_ACCESS\",\"ratType\":\"NR\","
                         "\"subsSessAmbr\":{\"uplink\":\"100 Mbps\",\"downlink\":\"200 Mbps\"},"
                         "\"subsDefQos\":{\"5qi\":9,\"arp\":{\"priorityLevel\":8,\"preemptCap\":\"NOT_PREEMPT\",\"preemptVuln\":\"NOT_PREEMPTABLE\"},\"priorityLevel\":80},"
                         "\"servingNetwork\":{\"mcc\":\"001\",\"mnc\":\"01\"}}",
                         dnn, notif);
}

#define SMP "/npcf-smpolicycontrol/v1/sm-policies"

static const char *WITH_IMS =
    "default: { session_ambr: { uplink: \"1 Gbps\", downlink: \"1 Gbps\" } }\n"
    "dnns:\n"
    "  ims:\n"
    "    default_qos: { qi5: 5, arp_priority: 2 }\n"
    "    pcc_rules:\n"
    "      - id: voice\n"
    "        flows: [\"permit out 17 from any to assigned\"]\n"
    "        qi5: 1\n"
    "        gbr_ul: \"128 Kbps\"\n"
    "        gbr_dl: \"128 Kbps\"\n"
    "rfsp: 7\n";

static const g5c_json *sess_rule(const g5c_json *d)
{
    return g5c_json_get(g5c_json_get(d, "sessRules"), "SessRule-1");
}

static void test_lifecycle(void)
{
    T t;
    g5c_json *d, *g, *u;
    char *loc = NULL, *body, expect[128];
    const char *path;
    setup(&t, "{}");
    body = ctx_body("internet", "http://127.0.0.1:1");
    TK_ASSERT(call(&t, "POST", SMP, body, false, &d, &loc) == 201);
    free(body);
    snprintf(expect, sizeof expect, "%s" SMP "/", t.base);
    TK_ASSERT(loc != NULL && strncmp(loc, expect, strlen(expect)) == 0); /* absolute Location */
    /* with nothing configured the subscribed values are authorised as they are */
    expect_json(g5c_json_get(sess_rule(d), "authSessAmbr"), "{\"uplink\":\"100 Mbps\",\"downlink\":\"200 Mbps\"}");
    {
        int64_t q = 0;
        TK_ASSERT(g5c_json_get_int(g5c_json_get(sess_rule(d), "authDefQos"), "5qi", &q) && q == 9);
        TK_ASSERT(g5c_json_get_int(g5c_json_get(sess_rule(d), "authDefQos"), "priorityLevel", &q) && q == 80);
    }
    path = loc + strlen(t.base);
    TK_ASSERT(call(&t, "GET", path, NULL, false, &g, NULL) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(g, "context"), "dnn"), "internet") == 0);
    TK_ASSERT(g5c_json_equal(g5c_json_get(g, "policy"), d));
    g5c_json_free(g);
    {
        char *p2 = g5c_xasprintf("%s/update", path);
        TK_ASSERT(call(&t, "POST", p2, "{\"repPolicyCtrlReqTriggers\":[\"PLMN_CH\"]}", false, &u, NULL) == 200);
        TK_ASSERT(g5c_json_equal(g5c_json_get(u, "sessRules"), g5c_json_get(d, "sessRules")));
        g5c_json_free(u);
        free(p2);
        p2 = g5c_xasprintf("%s/delete", path);
        TK_ASSERT(call(&t, "POST", p2, "{}", false, NULL, NULL) == 204);
        TK_ASSERT(call(&t, "GET", path, NULL, false, NULL, NULL) == 404);
        TK_ASSERT(call(&t, "POST", p2, "{}", false, NULL, NULL) == 404);
        free(p2);
        p2 = g5c_xasprintf("%s/update", path);
        TK_ASSERT(call(&t, "POST", p2, "{}", false, NULL, NULL) == 404);
        free(p2);
    }
    TK_ASSERT(pcf_session_count(&t.p) == 0);
    g5c_json_free(d);
    free(loc);
    teardown(&t);
}

static char *mutate(const char *dnn, const char *key, const char *raw_value /* NULL: remove */)
{
    char *b = ctx_body(dnn, "http://127.0.0.1:1");
    g5c_json *j = J(b);
    free(b);
    if (raw_value)
        g5c_json_set(j, key, J(raw_value));
    else
        g5c_json_remove(j, key);
    b = g5c_json_to_string(j, NULL);
    g5c_json_free(j);
    return b;
}

static void test_invalid_requests(void)
{
    T t;
    g5c_json *v;
    char *b;
    setup(&t, "{}");
    b = mutate("internet", "pduSessionType", NULL);
    TK_ASSERT(call(&t, "POST", SMP, b, false, NULL, NULL) == 400); /* pduSessionType is mandatory (TS 29.512) */
    free(b);
    b = mutate("internet", "sliceInfo", NULL);
    TK_ASSERT(call(&t, "POST", SMP, b, false, NULL, NULL) == 400);
    free(b);
    b = mutate("internet", "supi", "\"nope\"");
    TK_ASSERT(call(&t, "POST", SMP, b, false, &v, NULL) == 400);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(v, "invalidParams"), 0), "param"), "supi") == 0);
    g5c_json_free(v);
    free(b);
    b = mutate("internet", "pduSessionId", "0");
    TK_ASSERT(call(&t, "POST", SMP, b, false, NULL, NULL) == 400);
    free(b);
    b = mutate("internet", "notificationUri", "\"/relative/only\"");
    TK_ASSERT(call(&t, "POST", SMP, b, false, NULL, NULL) == 400);
    free(b);
    b = mutate("internet", "dnn", "\"\"");
    TK_ASSERT(call(&t, "POST", SMP, b, false, NULL, NULL) == 400);
    free(b);
    b = mutate("internet", "subsSessAmbr", "{\"uplink\":\"1 Mbps\",\"extra\":1}"); /* Ambr is strict */
    TK_ASSERT(call(&t, "POST", SMP, b, false, NULL, NULL) == 400);
    free(b);
    TK_ASSERT(call(&t, "POST", SMP, NULL, false, NULL, NULL) == 400); /* empty body */
    TK_ASSERT(pcf_session_count(&t.p) == 0);
    teardown(&t);
}

static void test_configured_profiles(void)
{
    T t;
    g5c_json *internet, *ims;
    char *b;
    setup(&t, WITH_IMS);
    b = ctx_body("internet", "http://127.0.0.1:1");
    TK_ASSERT(call(&t, "POST", SMP, b, false, &internet, NULL) == 201);
    free(b);
    /* the configured default beats the subscription */
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(sess_rule(internet), "authSessAmbr"), "uplink"), "1 Gbps") == 0);
    TK_ASSERT(g5c_json_get(internet, "pccRules") == NULL);
    g5c_json_free(internet);
    b = ctx_body("ims", "http://127.0.0.1:1");
    TK_ASSERT(call(&t, "POST", SMP, b, false, &ims, NULL) == 201);
    free(b);
    {
        int64_t v = 0;
        const g5c_json *dq = g5c_json_get(sess_rule(ims), "authDefQos");
        TK_ASSERT(g5c_json_get_int(dq, "5qi", &v) && v == 5);
        TK_ASSERT(g5c_json_get_int(g5c_json_get(dq, "arp"), "priorityLevel", &v) && v == 2);
        TK_ASSERT(g5c_json_get_int(g5c_json_get(g5c_json_get(ims, "qosDecs"), "QosData-voice"), "5qi", &v) && v == 1);
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(g5c_json_get(ims, "qosDecs"), "QosData-voice"), "gbrUl"), "128 Kbps") == 0);
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(g5c_json_get(g5c_json_get(ims, "pccRules"), "PccRule-voice"), "flowInfos"), 0), "flowDirection"), "BIDIRECTIONAL") == 0);
    }
    g5c_json_free(ims);
    teardown(&t);
}

static void test_push_mid_session(void)
{
    T t;
    char *loc = NULL, *b, path[160], *res;
    g5c_json *v;
    const char *over = "{\"default\":{\"session_ambr\":{\"uplink\":\"5 Mbps\",\"downlink\":\"10 Mbps\"}}}";
    setup(&t, "{}");
    b = ctx_body("internet", t.smf);
    TK_ASSERT(call(&t, "POST", SMP, b, false, NULL, &loc) == 201);
    res = g5c_xstrdup(loc);
    free(loc);

    /* an operator throttles the subscriber */
    TK_ASSERT(call(&t, "PUT", "/admin/v1/policies/" SUPI, over, true, &v, NULL) == 200);
    {
        int64_t n = 0;
        TK_ASSERT(g5c_json_get_int(v, "notifiedSessions", &n) && n == 1);
        g5c_json_free(v);
    }
    TK_ASSERT(t.notes.n == 1 && strcmp(t.notes.kind[0], "update") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(t.notes.body[0], "resourceUri"), res) == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(sess_rule(g5c_json_get(t.notes.body[0], "smPolicyDecision")), "authSessAmbr"), "uplink"), "5 Mbps") == 0);
    /* re-applying the same policy changes nothing, so no second notification */
    TK_ASSERT(call(&t, "PUT", "/admin/v1/policies/" SUPI, over, true, &v, NULL) == 200);
    {
        int64_t n = 99;
        TK_ASSERT(g5c_json_get_int(v, "notifiedSessions", &n) && n == 0);
        g5c_json_free(v);
    }
    TK_ASSERT(t.notes.n == 1);
    /* the stored decision reflects the push */
    snprintf(path, sizeof path, "%s", res + strlen(t.base));
    TK_ASSERT(call(&t, "GET", path, NULL, false, &v, NULL) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(sess_rule(g5c_json_get(v, "policy")), "authSessAmbr"), "uplink"), "5 Mbps") == 0);
    g5c_json_free(v);
    /* a NEW session of the same subscriber gets the override at creation */
    TK_ASSERT(call(&t, "POST", SMP, b, false, &v, NULL) == 201);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(sess_rule(v), "authSessAmbr"), "uplink"), "5 Mbps") == 0);
    g5c_json_free(v);
    /* removing the override restores the subscribed values and tells the SMF again (both sessions) */
    TK_ASSERT(call(&t, "DELETE", "/admin/v1/policies/" SUPI, NULL, true, NULL, NULL) == 204);
    TK_ASSERT(t.notes.n == 3);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(sess_rule(g5c_json_get(t.notes.body[2], "smPolicyDecision")), "authSessAmbr"), "uplink"), "100 Mbps") == 0);
    free(b);
    free(res);
    teardown(&t);
}

static void test_admin(void)
{
    T t;
    g5c_json *v;
    setup(&t, "{}");
    TK_ASSERT(call(&t, "GET", "/admin/v1/policies/" SUPI, NULL, false, NULL, NULL) == 401);
    TK_ASSERT(call(&t, "GET", "/admin/v1/policies/" SUPI, NULL, true, NULL, NULL) == 404);
    TK_ASSERT(call(&t, "PUT", "/admin/v1/policies/" SUPI,
                   "{\"dnns\":{\"ims\":{\"pcc_rules\":[{\"id\":\"v\",\"flows\":[\"permit out ip from any to any\"],\"qi5\":1}]}}}", true, &v, NULL) == 400);
    TK_ASSERT(strncmp(g5c_json_get_str(g5c_json_at(g5c_json_get(v, "invalidParams"), 0), "param"), "dnns.ims.pccRules[0]", 20) == 0);
    g5c_json_free(v);
    TK_ASSERT(call(&t, "PUT", "/admin/v1/policies/bogus", "{}", true, NULL, NULL) == 400);
    TK_ASSERT(call(&t, "PUT", "/admin/v1/policies/" SUPI, "{\"unknown_field\":1}", true, NULL, NULL) == 400);
    TK_ASSERT(call(&t, "PUT", "/admin/v1/policies/" SUPI, "{}", true, NULL, NULL) == 200);
    TK_ASSERT(call(&t, "GET", "/admin/v1/policies/" SUPI, NULL, true, NULL, NULL) == 200);
    /* with no token configured the admin API does not exist */
    free(t.p.admin_token);
    t.p.admin_token = NULL;
    TK_ASSERT(call(&t, "GET", "/admin/v1/sessions", NULL, true, NULL, NULL) == 404);
    teardown(&t);
}

static void test_termination_and_unreachable_smf(void)
{
    T t;
    char *loc = NULL, *b, *res, path[160];
    g5c_json *v, *list;
    setup(&t, "{}");
    b = ctx_body("internet", t.smf);
    TK_ASSERT(call(&t, "POST", SMP, b, false, NULL, &loc) == 201);
    free(b);
    res = g5c_xstrdup(loc);
    free(loc);
    TK_ASSERT(call(&t, "GET", "/admin/v1/sessions", NULL, true, &list, NULL) == 200 && g5c_json_len(list) == 1);
    snprintf(path, sizeof path, "/admin/v1/sessions/%s", g5c_json_get_str(g5c_json_at(list, 0), "smPolicyId"));
    g5c_json_free(list);
    TK_ASSERT(call(&t, "DELETE", path, NULL, true, NULL, NULL) == 204);
    TK_ASSERT(t.notes.n == 1 && strcmp(t.notes.kind[0], "terminate") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(t.notes.body[0], "resourceUri"), res) == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(t.notes.body[0], "cause"), "PDU_SESSION_TERMINATION") == 0);
    TK_ASSERT(call(&t, "DELETE", path, NULL, true, NULL, NULL) == 404);
    free(res);

    /* an SMF that went away must not break policy administration */
    b = ctx_body("internet", "http://127.0.0.1:1");
    TK_ASSERT(call(&t, "POST", SMP, b, false, NULL, NULL) == 201);
    free(b);
    TK_ASSERT(call(&t, "PUT", "/admin/v1/policies/" SUPI, "{\"default\":{\"session_ambr\":{\"uplink\":\"1 Mbps\",\"downlink\":\"1 Mbps\"}}}", true, &v, NULL) == 200);
    {
        int64_t n = 99;
        TK_ASSERT(g5c_json_get_int(v, "notifiedSessions", &n) && n == 0);
        g5c_json_free(v);
    }
    {
        char *m = g5c_registry_render(t.metrics);
        TK_ASSERT(strstr(m, "result=\"unreachable\"") != NULL);
        free(m);
    }
    teardown(&t);
}

static void test_am_policy(void)
{
    T t, plain;
    const char *base = "/npcf-am-policy-control/v1/policies";
    const char *req = "{\"notificationUri\":\"http://127.0.0.1:1/amf/cb\",\"supi\":\"" SUPI "\",\"accessType\":\"3GPP_ACCESS\",\"servingPlmn\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"suppFeat\":\"\"}";
    g5c_json *v;
    char *loc = NULL, *p2, expect[128];
    const char *path;
    setup(&t, WITH_IMS);
    TK_ASSERT(call(&t, "POST", base, req, false, &v, &loc) == 201);
    snprintf(expect, sizeof expect, "%s%s/", t.base, base);
    TK_ASSERT(loc && strncmp(loc, expect, strlen(expect)) == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(v, "request"), "supi"), SUPI) == 0);
    {
        int64_t r = 0;
        TK_ASSERT(g5c_json_get_int(v, "rfsp", &r) && r == 7);
    }
    g5c_json_free(v);
    path = loc + strlen(t.base);
    p2 = g5c_xasprintf("%s/update", path);
    TK_ASSERT(call(&t, "POST", p2, "{\"servingPlmn\":{\"mcc\":\"001\",\"mnc\":\"01\"}}", false, &v, NULL) == 200);
    {
        int64_t r = 0;
        TK_ASSERT(g5c_json_get_int(v, "rfsp", &r) && r == 7);
        /* PolicyUpdate must carry the association's resourceUri */
        TK_ASSERT(strcmp(g5c_json_get_str(v, "resourceUri"), loc) == 0);
    }
    g5c_json_free(v);
    TK_ASSERT(call(&t, "DELETE", path, NULL, false, NULL, NULL) == 204);
    TK_ASSERT(call(&t, "DELETE", path, NULL, false, NULL, NULL) == 404);
    TK_ASSERT(call(&t, "POST", p2, "{}", false, NULL, NULL) == 404);
    free(p2);
    free(loc);
    TK_ASSERT(call(&t, "POST", base, "{\"notificationUri\":\"http://x/y\",\"supi\":\"x\"}", false, NULL, NULL) == 400);
    teardown(&t);

    /* no rfsp configured -> attribute omitted; the empty `triggers` array is never sent */
    setup(&plain, "{}");
    TK_ASSERT(call(&plain, "POST", base, "{\"notificationUri\":\"http://x/y\",\"supi\":\"" SUPI "\",\"suppFeat\":\"3\"}", false, &v, NULL) == 201);
    TK_ASSERT(g5c_json_get(v, "rfsp") == NULL && g5c_json_get(v, "triggers") == NULL);
    /* suppFeat is mandatory in PolicyAssociation; no optional features are supported, so the negotiated set is empty */
    TK_ASSERT(strcmp(g5c_json_get_str(v, "suppFeat"), "") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(v, "request"), "suppFeat"), "3") == 0);
    g5c_json_free(v);
    teardown(&plain);
}

static void test_metrics_and_empty_arrays(void)
{
    T t;
    char *b, *m;
    g5c_json *d;
    setup(&t, "{}");
    b = ctx_body("internet", "http://127.0.0.1:1");
    TK_ASSERT(call(&t, "POST", SMP, b, false, &d, NULL) == 201);
    free(b);
    /* Open5GS rejects empty arrays for attributes the OpenAPI schema declares with minItems 1 */
    TK_ASSERT(g5c_json_get(d, "policyCtrlReqTriggers") == NULL);
    g5c_json_free(d);
    TK_ASSERT(call(&t, "POST", SMP, "{\"supi\":\"x\"}", false, NULL, NULL) == 400);
    m = g5c_registry_render(t.metrics);
    TK_ASSERT(strstr(m, "g5c_pcf_sm_policy_requests_total{result=\"created\"} 1") != NULL);
    TK_ASSERT(strstr(m, "g5c_pcf_sm_policy_requests_total{result=\"bad_request\"} 1") != NULL);
    TK_ASSERT(strstr(m, "g5c_pcf_sm_policies_active 1") != NULL);
    free(m);
    teardown(&t);
}

static void test_config_loading(void)
{
    char err[200];
    g5c_json *cfg, *root;
    g5c_common c;
    g5c_nf *nf;
    pcf *p;
    root = Y("name: pcf\nplmn: {mcc: '001', mnc: '01'}\nsbi: {address: 127.0.0.1, port: 1}\n");
    TK_ASSERT(g5c_common_parse(root, &c, err, sizeof err) == 0);
    nf = g5c_nf_new(&c, err, sizeof err);
    TK_ASSERT(nf != NULL);
    g5c_json_free(root);
    cfg = Y("udr: {uri: 'http://127.0.0.1:1'}\npolicy:\n  default:\n    session_ambr: {uplink: fast, downlink: '1 Gbps'}\n");
    TK_ASSERT(pcf_from_config(cfg, nf, err, sizeof err) == NULL && strstr(err, "policy.default.sessionAmbr.uplink") != NULL);
    g5c_json_free(cfg);
    cfg = Y("udr: {uri: 'http://127.0.0.1:1'}\npolicy:\n  default: {session_ambr: {uplink: '1 Gbps', downlink: '1 Gbps'}}\n  rfsp: 7\n");
    setenv("G5C_PCF_ADMIN_TOKEN", "short", 1);
    TK_ASSERT(pcf_from_config(cfg, nf, err, sizeof err) == NULL && strstr(err, "at least 16") != NULL);
    setenv("G5C_PCF_ADMIN_TOKEN", ADMIN, 1);
    p = pcf_from_config(cfg, nf, err, sizeof err);
    TK_ASSERT(p != NULL && p->cfg.has_rfsp && p->cfg.rfsp == 7 && strcmp(p->admin_token, ADMIN) == 0);
    unsetenv("G5C_PCF_ADMIN_TOKEN");
    pcf_destroy(p);
    free(p);
    g5c_json_free(cfg);
    g5c_nf_free(nf);
}

/* ---- negative, abuse and failure-injection tests (Phase 2 test plan: component layer) ---- */

/* Every structurally wrong policy document is refused with an explanation, never accepted partially. */
static void test_policy_parse_errors(void)
{
    static const char *const docs[] = {
        "- a\n- b\n",
        "7\n",
        "default: 5\n",
        "default: { bogus: 1 }\n",
        "default: { session_ambr: 5 }\n",
        "default: { session_ambr: { uplink: '1 Mbps' } }\n",
        "default: { session_ambr: { downlink: '1 Mbps' } }\n",
        "default: { session_ambr: { uplink: '1 Mbps', downlink: '1 Mbps', x: 1 } }\n",
        "default: { default_qos: 5 }\n",
        "default: { default_qos: { arp_priority: 3 } }\n",
        "default: { default_qos: { qi5: 300 } }\n",
        "default: { default_qos: { qi5: -1 } }\n",
        "default: { default_qos: { qi5: x } }\n",
        "default: { default_qos: { qi5: 9, arp_priority: 300 } }\n",
        "default: { default_qos: { qi5: 9, preempt_cap: 3 } }\n",
        "default: { default_qos: { qi5: 9, preempt_vuln: 'yes please' } }\n",
        "default: { default_qos: { qi5: 9, priority_level: 256 } }\n",
        "default: { default_qos: { qi5: 9, wat: 1 } }\n",
        "default: { pcc_rules: 5 }\n",
        "default: { pcc_rules: [ 5 ] }\n",
        "default: { pcc_rules: [ { id: a, flows: [] } ] }\n",
        "default: { pcc_rules: [ { flows: ['permit out ip from any to any'], qi5: 9 } ] }\n",
        "default: { pcc_rules: [ { id: a, qi5: 9 } ] }\n",
        "default: { pcc_rules: [ { id: a, flows: 'permit', qi5: 9 } ] }\n",
        "default: { pcc_rules: [ { id: a, flows: [ 5 ], qi5: 9 } ] }\n",
        "default: { pcc_rules: [ { id: a, flows: ['permit out ip from any to any'], qi5: 999 } ] }\n",
        "default: { pcc_rules: [ { id: a, flows: ['permit out ip from any to any'], qi5: 9, gbr_ul: 5 } ] }\n",
        "default: { pcc_rules: [ { id: a, flows: ['permit out ip from any to any'], qi5: 9, precedence: -3 } ] }\n",
        "default: { pcc_rules: [ { id: a, flows: ['permit out ip from any to any'], qi5: 9, zzz: 1 } ] }\n",
        "dnns: 5\n",
        "dnns: { internet: 5 }\n",
        "dnns: { internet: { default_qos: { qi5: 300 } } }\n",
        "rfsp: 70000\n",
        "rfsp: x\n",
    };
    char err[200];
    pcf_policy p;
    g5c_json *j;
    for (size_t i = 0; i < sizeof docs / sizeof *docs; i++) {
        int rc;
        err[0] = 0;
        j = Y(docs[i]);
        rc = pcf_policy_parse(j, true, &p, err, sizeof err);
        if (rc == 0) {
            char f[200], r[200];
            rc = pcf_policy_validate(&p, true, f, sizeof f, r, sizeof r); /* some mistakes show up only at the semantic check */
            pcf_policy_free(&p);
        }
        if (rc == 0)
            TK_FAIL("policy document %zu was accepted: %s", i, docs[i]);
        g5c_json_free(j);
    }
    j = Y("rfsp: 1\n"); /* the subscriber-scoped schema has no rfsp */
    TK_ASSERT(pcf_policy_parse(j, false, &p, err, sizeof err) != 0);
    g5c_json_free(j);
}

/* Garbage and misuse on every PCF endpoint: right status, no state change, the server keeps working. */
static void test_pcf_protocol_abuse(void)
{
    static const char *const garbage[] = {"{", "nope", "[1,", ""};
    static const struct {
        const char *method, *path;
    } eps[] = {
        {"POST", SMP},
        {"POST", SMP "/unknown/update"},
        {"POST", SMP "/unknown/delete"},
        {"POST", "/npcf-am-policy-control/v1/policies"},
        {"POST", "/npcf-am-policy-control/v1/policies/unknown/update"},
    };
    T t;
    char *big, *b, *loc = NULL;
    g5c_json *v;
    setup(&t, "{}");
    for (size_t i = 0; i < sizeof eps / sizeof *eps; i++)
        for (size_t g = 0; g < sizeof garbage / sizeof *garbage; g++) {
            int st = call(&t, eps[i].method, eps[i].path, garbage[g], false, NULL, NULL);
            if (st != 400 && st != 404)
                TK_FAIL("%s %s garbage %zu -> %d", eps[i].method, eps[i].path, g, st);
        }
    TK_ASSERT(call(&t, "GET", SMP "/unknown", NULL, false, NULL, NULL) == 404);
    TK_ASSERT(call(&t, "POST", SMP "/unknown/update", "{}", false, NULL, NULL) == 404);
    TK_ASSERT(call(&t, "POST", SMP "/unknown/delete", "{}", false, NULL, NULL) == 404);
    TK_ASSERT(call(&t, "GET", "/npcf-nothing/v1/x", NULL, false, NULL, NULL) == 404);
    {
        int st = call(&t, "DELETE", SMP, NULL, false, NULL, NULL);
        TK_ASSERT(st == 404 || st == 405);
    }
    /* admin API: every operation needs the token, unknown ids are 404, bad bodies 400 */
    TK_ASSERT(call(&t, "GET", "/admin/v1/sessions", NULL, false, NULL, NULL) == 401);
    TK_ASSERT(call(&t, "DELETE", "/admin/v1/sessions/x", NULL, false, NULL, NULL) == 401);
    TK_ASSERT(call(&t, "PUT", "/admin/v1/policies/" SUPI, "{}", false, NULL, NULL) == 401);
    TK_ASSERT(call(&t, "DELETE", "/admin/v1/policies/" SUPI, NULL, true, NULL, NULL) == 404);
    TK_ASSERT(call(&t, "DELETE", "/admin/v1/sessions/none", NULL, true, NULL, NULL) == 404);
    TK_ASSERT(call(&t, "PUT", "/admin/v1/policies/" SUPI, "{", true, NULL, NULL) == 400);
    /* body over the limit */
    big = malloc(G5C_SBI_MAX_BODY + 64);
    TK_ASSERT(big != NULL);
    memset(big, 'a', G5C_SBI_MAX_BODY + 63);
    big[G5C_SBI_MAX_BODY + 63] = 0;
    TK_ASSERT(call(&t, "POST", SMP, big, false, NULL, NULL) == 413);
    free(big);
    /* a valid session is untouched by all of the above */
    b = ctx_body("internet", "http://127.0.0.1:1");
    TK_ASSERT(call(&t, "POST", SMP, b, false, &v, &loc) == 201);
    free(b);
    g5c_json_free(v);
    TK_ASSERT(call(&t, "GET", loc + strlen(t.base), NULL, false, NULL, NULL) == 200);
    TK_ASSERT(pcf_session_count(&t.p) == 1);
    free(loc);
    teardown(&t);
}

/* The UDR goes away: new sessions fail cleanly with 503, established ones and the NF itself survive. */
static void test_pcf_udr_outage(void)
{
    T t;
    char *b, *loc = NULL, *path;
    g5c_json *v;
    int st;
    setup(&t, "{}");
    b = ctx_body("internet", "http://127.0.0.1:1");
    TK_ASSERT(call(&t, "POST", SMP, b, false, &v, &loc) == 201);
    g5c_json_free(v);
    path = g5c_xasprintf("%s", loc + strlen(t.base));
    free(loc);
    g5c_server_stop(t.udr_s);
    t.udr_s = NULL;
    st = call(&t, "POST", SMP, b, false, NULL, NULL);
    if (st != 503)
        TK_FAIL("create with the UDR down returned %d", st);
    TK_ASSERT(call(&t, "GET", path, NULL, false, NULL, NULL) == 200);
    TK_ASSERT(call(&t, "GET", "/admin/v1/sessions", NULL, true, NULL, NULL) == 200);
    st = call(&t, "GET", "/admin/v1/policies/" SUPI, NULL, true, NULL, NULL);
    if (st != 503)
        TK_FAIL("admin policy read with the UDR down returned %d", st);
    TK_ASSERT(pcf_session_count(&t.p) == 1);
    free(b);
    free(path);
    teardown(&t);
}

/* ---- Npcf_PolicyAuthorization (N5) ---- */

static void af_notify(void *c, const g5c_req *req, g5c_resp *resp) { note(c, "notify", req, resp); }
static void af_terminate(void *c, const g5c_req *req, g5c_resp *resp) { note(c, "af-terminate", req, resp); }

static bool wait_notes(notes_t *n, int want, int ms)
{
    for (int i = 0; i < ms / 5; i++) {
        pthread_mutex_lock(&n->mu);
        if (n->n >= want) {
            pthread_mutex_unlock(&n->mu);
            return true;
        }
        pthread_mutex_unlock(&n->mu);
        usleep(5000);
    }
    return false;
}

static const g5c_json *pcc_rule_of(const g5c_json *decision, const char *prefix)
{
    const g5c_json *rules = g5c_json_get(decision, "pccRules");
    for (size_t i = 0; i < g5c_json_len(rules); i++)
        if (strncmp(g5c_json_key_at(rules, i), prefix, strlen(prefix)) == 0)
            return g5c_json_val_at(rules, i);
    return NULL;
}

/* ---- the binding at the BSF (TS 29.521): registered when the SM policy association has a UE address, removed when it ends ---- */

static char *ctx_with_addr(const char *dnn, const char *notif, const char *v4, const char *v6, int pdu)
{
    char *b = ctx_body(dnn, notif);
    g5c_json *j = J(b), *l;
    char *out;
    free(b);
    if (v4 != NULL)
        g5c_json_set_str(j, "ipv4Address", v4);
    if (v6 != NULL)
        g5c_json_set_str(j, "ipv6AddressPrefix", v6);
    g5c_json_set_int(j, "pduSessionId", pdu);
    l = g5c_json_get_mut(j, "sliceInfo");
    g5c_json_set_str(l, "sd", "000001");
    out = g5c_json_to_string(j, NULL);
    g5c_json_free(j);
    return out;
}

static bool wait_bindings(bsf *b, size_t want)
{
    for (int i = 0; i < 300; i++) {
        if (bsf_binding_count(b) == want)
            return true;
        usleep(10000);
    }
    return false;
}

static int bsf_get(g5c_client *c, const char *base, const char *query, g5c_json **out)
{
    char *url = g5c_xasprintf("%s/nbsf-management/v1/pcfBindings?%s", base, query), err[160];
    g5c_resp r;
    int st = -1;
    if (g5c_client_get(c, url, &r, err, sizeof err) == 0) {
        st = r.status;
        *out = g5c_resp_parse_json(&r);
        g5c_resp_free(&r);
    }
    free(url);
    return st;
}

static void test_bsf_binding(void)
{
    T t;
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[200], bsf_base[64], *body, *loc = NULL, *cfgtext;
    g5c_json *root, *cfgj, *d = NULL, *bj = NULL;
    g5c_common c;
    g5c_nf *nf;
    bsf *b;
    g5c_router *br;
    g5c_server *bs;
    char *loc2 = NULL, *loc3 = NULL;
    setup(&t, "default: { session_ambr: { uplink: \"1 Gbps\", downlink: \"1 Gbps\" } }\n");
    root = Y("name: pcf\nplmn: {mcc: '001', mnc: '01'}\nsbi: {address: 127.0.0.7, port: 7779}\n");
    TK_ASSERT(g5c_common_parse(root, &c, err, sizeof err) == 0);
    nf = g5c_nf_new(&c, err, sizeof err);
    TK_ASSERT(nf != NULL);
    g5c_json_free(root);
    {
        g5c_json *r2 = Y("bsf: {}\n");
        bsf_cfg *bc = bsf_cfg_parse(r2, err, sizeof err);
        TK_ASSERT(bc != NULL);
        g5c_json_free(r2);
        b = bsf_new(bc, NULL);
    }
    br = bsf_router(b);
    bs = g5c_server_start(&cfg, br, err, sizeof err);
    TK_ASSERT(bs != NULL);
    snprintf(bsf_base, sizeof bsf_base, "http://127.0.0.1:%u", g5c_server_port(bs));
    /* configuration: wrong values are refused */
    cfgj = Y("bsf: { surprise: 1 }\n");
    TK_ASSERT(pcf_bsf_config(&t.p, cfgj, nf, err, sizeof err) != 0 && strstr(err, "bsf") != NULL);
    g5c_json_free(cfgj);
    cfgj = Y("bsf: { uri: 'ftp://x' }\n");
    TK_ASSERT(pcf_bsf_config(&t.p, cfgj, nf, err, sizeof err) != 0 && strstr(err, "bsf.uri") != NULL);
    g5c_json_free(cfgj);
    cfgj = Y("bsf: { enabled: false }\n");
    TK_ASSERT(pcf_bsf_config(&t.p, cfgj, nf, err, sizeof err) == 0 && t.p.bsf == NULL);
    g5c_json_free(cfgj);
    cfgj = Y("name: x\n");
    TK_ASSERT(pcf_bsf_config(&t.p, cfgj, nf, err, sizeof err) == 0 && t.p.bsf == NULL); /* no BSF named and no NRF to find one */
    g5c_json_free(cfgj);
    cfgtext = g5c_xasprintf("bsf: { uri: '%s/', fqdn: 'pcf.example.org' }\n", bsf_base);
    cfgj = Y(cfgtext);
    free(cfgtext);
    TK_ASSERT(pcf_bsf_config(&t.p, cfgj, nf, err, sizeof err) == 0 && t.p.bsf != NULL);
    g5c_json_free(cfgj);
    /* a session with an IPv4 address: the binding is at the BSF, with the DNN, the slice, the UE and where this PCF is */
    body = ctx_with_addr("internet", t.smf, "10.45.0.2", NULL, 1);
    TK_ASSERT(call(&t, "POST", SMP, body, false, &d, &loc) == 201);
    free(body);
    g5c_json_free(d);
    TK_ASSERT(wait_bindings(b, 1));
    TK_ASSERT(bsf_get(t.client, bsf_base, "ipv4Addr=10.45.0.2", &bj) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(bj, "supi"), SUPI) == 0 && strcmp(g5c_json_get_str(bj, "dnn"), "internet") == 0 &&
              strcmp(g5c_json_get_str(bj, "pcfId"), nf->instance_id) == 0 && strcmp(g5c_json_get_str(bj, "pcfFqdn"), "pcf.example.org") == 0 &&
              strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(bj, "pcfIpEndPoints"), 0), "ipv4Address"), "127.0.0.7") == 0 &&
              g5c_json_get_str(bj, "recoveryTime") != NULL);
    {
        int64_t port = 0;
        TK_ASSERT(g5c_json_get_int(g5c_json_at(g5c_json_get(bj, "pcfIpEndPoints"), 0), "port", &port) && port == 7779);
    }
    g5c_json_free(bj);
    /* a second session, IPv6 only, and one with no address at all (nothing to bind) */
    body = ctx_with_addr("internet", t.smf, NULL, "2001:db8:5::/64", 2);
    TK_ASSERT(call(&t, "POST", SMP, body, false, &d, &loc2) == 201);
    free(body);
    g5c_json_free(d);
    body = ctx_with_addr("ims", t.smf, NULL, NULL, 3);
    TK_ASSERT(call(&t, "POST", SMP, body, false, &d, &loc3) == 201);
    free(body);
    g5c_json_free(d);
    TK_ASSERT(wait_bindings(b, 2));
    TK_ASSERT(bsf_get(t.client, bsf_base, "ipv6Prefix=2001%3Adb8%3A5%3A%3A9%2F128", &bj) == 200);
    g5c_json_free(bj);
    /* the association ends: its binding goes, the others stay */
    {
        char *path = g5c_xasprintf("%s/delete", strstr(loc, SMP));
        TK_ASSERT(call(&t, "POST", path, "{}", false, NULL, NULL) == 204);
        free(path);
    }
    TK_ASSERT(wait_bindings(b, 1));
    TK_ASSERT(bsf_get(t.client, bsf_base, "ipv4Addr=10.45.0.2", &bj) == 204);
    g5c_json_free(bj);
    {
        char *id = g5c_xstrdup(strrchr(loc2, '/') + 1);
        TK_ASSERT(pcf_terminate(&t.p, id)); /* the PCF's own end of an association removes the binding as well */
        free(id);
    }
    TK_ASSERT(wait_bindings(b, 0));
    free(loc);
    free(loc2);
    free(loc3);
    /* a BSF that is gone costs the PDU session nothing */
    g5c_server_stop(bs);
    body = ctx_with_addr("internet", t.smf, "10.45.0.9", NULL, 4);
    {
        time_t t0 = time(NULL);
        TK_ASSERT(call(&t, "POST", SMP, body, false, &d, &loc) == 201);
        TK_ASSERT(time(NULL) - t0 < 2);
    }
    free(body);
    free(loc);
    g5c_json_free(d);
    g5c_router_free(br);
    bsf_destroy(b);
    teardown(&t);
    g5c_nf_free(nf);
}

static void test_policy_authorization(void)
{
    T t;
    notes_t af;
    g5c_router *afr = g5c_router_new();
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_server *afs;
    g5c_json *v, *cfgj;
    char *loc = NULL, *sm_body, afuri[96], err[640], *body, path[512];
    const char *id;
    const g5c_json *rule;
    int base_updates;
    static const char *const REFS =
        "policy_authorization:\n"
        "  qos_references:\n"
        "    voice: { qi5: 1, gbr_ul: '128 Kbps', gbr_dl: '128 Kbps', mbr_ul: '256 Kbps', mbr_dl: '256 Kbps' }\n"
        "    streaming: { qi5: 7 }\n"
        "  max_app_sessions: 3\n";
    setup(&t, "{}");
    cfgj = Y(REFS);
    TK_ASSERT(pcf_policyauth_config(&t.p, cfgj, err, sizeof err) == 0);
    g5c_json_free(cfgj);
    memset(&af, 0, sizeof af);
    pthread_mutex_init(&af.mu, NULL);
    g5c_router_route(afr, "POST", "/af/notify", af_notify, &af);
    g5c_router_route(afr, "POST", "/af/terminate", af_terminate, &af);
    afs = g5c_server_start(&cfg, afr, err, sizeof err);
    TK_ASSERT(afs != NULL);
    snprintf(afuri, sizeof afuri, "http://127.0.0.1:%u/af", g5c_server_port(afs));

    /* the PDU session of the UE: an SM policy with its IPv4 address */
    sm_body = g5c_xasprintf("{\"supi\":\"" SUPI "\",\"pduSessionId\":1,\"pduSessionType\":\"IPV4\",\"dnn\":\"internet\",\"ipv4Address\":\"10.46.0.2\","
                            "\"notificationUri\":\"%s/nsmf-callback/v1/sm-policy-notify/" SUPI "/1\",\"sliceInfo\":{\"sst\":1},\"accessType\":\"3GPP_ACCESS\",\"ratType\":\"NR\","
                            "\"subsSessAmbr\":{\"uplink\":\"100 Mbps\",\"downlink\":\"200 Mbps\"},"
                            "\"subsDefQos\":{\"5qi\":9,\"arp\":{\"priorityLevel\":8,\"preemptCap\":\"NOT_PREEMPT\",\"preemptVuln\":\"NOT_PREEMPTABLE\"},\"priorityLevel\":80},"
                            "\"servingNetwork\":{\"mcc\":\"001\",\"mnc\":\"01\"}}", t.smf);
    TK_ASSERT(call(&t, "POST", SMP, sm_body, false, &v, &loc) == 201);
    g5c_json_free(v);
    snprintf(path, sizeof path, "%s", loc + strlen(t.base));
    free(loc);
    loc = NULL;
    base_updates = t.notes.n;

    /* create: a media component with a QoS reference, its flows, the events of the resources */
    body = g5c_xasprintf("{\"ascReqData\":{\"suppFeat\":\"8010000\",\"ueIpv4\":\"10.46.0.2\",\"dnn\":\"internet\",\"sliceInfo\":{\"sst\":1},\"notifUri\":\"%s\","
                         "\"medComponents\":{\"1\":{\"medCompN\":1,\"qosReference\":\"voice\",\"fStatus\":\"ENABLED\","
                         "\"medSubComps\":{\"1\":{\"fNum\":1,\"fDescs\":[\"permit out 17 from 10.46.0.2 5004 to 192.0.2.10 5004\",\"permit out 17 from 192.0.2.10 5004 to 10.46.0.2 5004\"]}}}},"
                         "\"evSubsc\":{\"events\":[{\"event\":\"SUCCESSFUL_RESOURCES_ALLOCATION\"},{\"event\":\"FAILED_RESOURCES_ALLOCATION\"}],\"notifUri\":\"%s\"}}}", afuri, afuri);
    TK_ASSERT(call(&t, "POST", "/npcf-policyauthorization/v1/app-sessions", body, false, &v, &loc) == 201 && loc != NULL);
    id = strrchr(loc, '/') + 1;
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(v, "ascReqData"), "ueIpv4"), "10.46.0.2") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(v, "ascReqData"), "suppFeat"), "8010000") == 0);
    g5c_json_free(v);
    free(body);
    TK_ASSERT(wait_notes(&t.notes, base_updates + 1, 3000));
    {
        const g5c_json *dec = g5c_json_get(t.notes.body[base_updates], "smPolicyDecision");
        char prefix[64];
        snprintf(prefix, sizeof prefix, "PccRule-af-%s-1", id);
        rule = pcc_rule_of(dec, prefix);
        TK_ASSERT(rule != NULL && g5c_json_len(g5c_json_get(rule, "flowInfos")) == 2);
        {
            const g5c_json *qd = g5c_json_val_at(g5c_json_get(dec, "qosDecs"), 0);
            int64_t q = 0;
            TK_ASSERT(g5c_json_get_int(qd, "5qi", &q) && q == 1 && strcmp(g5c_json_get_str(qd, "gbrUl"), "128 Kbps") == 0 && strcmp(g5c_json_get_str(qd, "maxbrDl"), "256 Kbps") == 0);
        }
    }
    TK_ASSERT(wait_notes(&af, 1, 3000));
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(af.body[0], "evNotifs"), 0), "event"), "SUCCESSFUL_RESOURCES_ALLOCATION") == 0);
    TK_ASSERT(strstr(g5c_json_get_str(af.body[0], "evSubsUri"), id) != NULL);
    TK_ASSERT(pcf_app_session_count(&t.p) == 1);

    /* read */
    snprintf(path, sizeof path, "/npcf-policyauthorization/v1/app-sessions/%s", id);
    TK_ASSERT(call(&t, "GET", path, NULL, false, &v, NULL) == 200);
    TK_ASSERT(g5c_json_get(g5c_json_get(v, "ascReqData"), "medComponents") != NULL);
    g5c_json_free(v);
    TK_ASSERT(call(&t, "GET", "/npcf-policyauthorization/v1/app-sessions/nope", NULL, false, &v, NULL) == 404);
    g5c_json_free(v);

    /* modify: another QoS reference for the component; a second component; then remove the first */
    TK_ASSERT(call(&t, "PATCH", path, "{\"ascReqData\":{\"medComponents\":{\"1\":{\"medCompN\":1,\"qosReference\":\"streaming\"}}}}", false, &v, NULL) == 200);
    g5c_json_free(v);
    TK_ASSERT(wait_notes(&t.notes, base_updates + 2, 3000));
    {
        const g5c_json *dec = g5c_json_get(t.notes.body[base_updates + 1], "smPolicyDecision"), *qd = g5c_json_val_at(g5c_json_get(dec, "qosDecs"), 0);
        int64_t q = 0;
        TK_ASSERT(g5c_json_get_int(qd, "5qi", &q) && q == 7 && g5c_json_get(qd, "gbrUl") == NULL);
    }
    TK_ASSERT(call(&t, "PATCH", path,
                   "{\"ascReqData\":{\"medComponents\":{\"2\":{\"medCompN\":2,\"qosReference\":\"voice\",\"medSubComps\":{\"1\":{\"fNum\":1,\"fDescs\":[\"permit out 17 from 192.0.2.20 to 10.46.0.2\"]}}}}}}",
                   false, &v, NULL) == 200);
    g5c_json_free(v);
    TK_ASSERT(wait_notes(&t.notes, base_updates + 3, 3000));
    TK_ASSERT(g5c_json_len(g5c_json_get(g5c_json_get(t.notes.body[base_updates + 2], "smPolicyDecision"), "pccRules")) == 2);
    TK_ASSERT(call(&t, "PATCH", path, "{\"ascReqData\":{\"medComponents\":{\"1\":null}}}", false, &v, NULL) == 200);
    g5c_json_free(v);
    TK_ASSERT(wait_notes(&t.notes, base_updates + 4, 3000));
    TK_ASSERT(g5c_json_len(g5c_json_get(g5c_json_get(t.notes.body[base_updates + 3], "smPolicyDecision"), "pccRules")) == 1);
    /* a gate that is closed: no rule */
    TK_ASSERT(call(&t, "PATCH", path, "{\"ascReqData\":{\"medComponents\":{\"2\":{\"medCompN\":2,\"fStatus\":\"DISABLED\"}}}}", false, &v, NULL) == 200);
    g5c_json_free(v);
    TK_ASSERT(wait_notes(&t.notes, base_updates + 5, 3000));
    TK_ASSERT(g5c_json_get(g5c_json_get(t.notes.body[base_updates + 4], "smPolicyDecision"), "pccRules") == NULL);

    /* refusals */
    TK_ASSERT(call(&t, "PATCH", path, "{\"ascReqData\":{\"medComponents\":{\"3\":{\"medCompN\":3,\"qosReference\":\"unknown\",\"medSubComps\":{\"1\":{\"fNum\":1,\"fDescs\":[\"permit out ip from any to any\"]}}}}}}", false, &v, NULL) == 403);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "cause"), "REQUESTED_SERVICE_NOT_AUTHORIZED") == 0);
    g5c_json_free(v);
    TK_ASSERT(call(&t, "PATCH", path, "{\"ascReqData\":{\"medComponents\":{\"3\":{\"medCompN\":3,\"medType\":\"VIDEO\",\"marBwDl\":\"1 Mbps\",\"medSubComps\":{\"1\":{\"fNum\":1,\"fDescs\":[\"permit out ip from any to any\"]}}}}}}", false, &v, NULL) == 403);
    g5c_json_free(v);
    TK_ASSERT(call(&t, "PATCH", path, "{\"ascReqData\":{\"medComponents\":{\"3\":{\"medCompN\":3,\"qosReference\":\"voice\"}}}}", false, &v, NULL) == 400);
    g5c_json_free(v);
    TK_ASSERT(call(&t, "PATCH", path, "{\"ascReqData\":{\"medComponents\":{\"3\":{\"medCompN\":3,\"qosReference\":\"voice\",\"medSubComps\":{\"1\":{\"fNum\":1,\"fDescs\":[\"deny out ip from any to any\"]}}}}}}", false, &v, NULL) == 400);
    g5c_json_free(v);
    TK_ASSERT(call(&t, "PATCH", path, "{\"ascReqData\":{\"ueIpv4\":null}}", false, &v, NULL) == 400);
    g5c_json_free(v);
    TK_ASSERT(call(&t, "PATCH", "/npcf-policyauthorization/v1/app-sessions/nope", "{\"ascReqData\":{}}", false, &v, NULL) == 404);
    g5c_json_free(v);
    body = g5c_xasprintf("{\"ascReqData\":{\"suppFeat\":\"0\",\"ueIpv4\":\"10.46.9.9\",\"notifUri\":\"%s\"}}", afuri);
    TK_ASSERT(call(&t, "POST", "/npcf-policyauthorization/v1/app-sessions", body, false, &v, NULL) == 500);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "cause"), "PDU_SESSION_NOT_AVAILABLE") == 0);
    g5c_json_free(v);
    free(body);
    TK_ASSERT(call(&t, "POST", "/npcf-policyauthorization/v1/app-sessions", "{\"ascReqData\":{\"suppFeat\":\"0\",\"ueIpv4\":\"10.46.0.2\"}}", false, &v, NULL) == 400); /* no notifUri */
    g5c_json_free(v);
    body = g5c_xasprintf("{\"ascReqData\":{\"suppFeat\":\"0\",\"ueIpv6\":\"2001:db8::1\",\"notifUri\":\"%s\"}}", afuri);
    TK_ASSERT(call(&t, "POST", "/npcf-policyauthorization/v1/app-sessions", body, false, &v, NULL) == 500);
    g5c_json_free(v);
    free(body);
    body = g5c_xasprintf("{\"ascReqData\":{\"suppFeat\":\"0\",\"ueIpv4\":\"10.46.0.2\",\"dnn\":\"ims\",\"notifUri\":\"%s\"}}", afuri); /* the binding takes the DNN into account */
    TK_ASSERT(call(&t, "POST", "/npcf-policyauthorization/v1/app-sessions", body, false, &v, NULL) == 500);
    g5c_json_free(v);
    free(body);
    TK_ASSERT(call(&t, "POST", "/npcf-policyauthorization/v1/app-sessions", "not json", false, &v, NULL) == 400);
    g5c_json_free(v);

    /* events subscription as a resource of its own */
    snprintf(err, sizeof err, "%s/events-subscription", path);
    body = g5c_xasprintf("{\"events\":[{\"event\":\"FAILED_RESOURCES_ALLOCATION\"}],\"notifUri\":\"%s\"}", afuri);
    TK_ASSERT(call(&t, "PUT", err, body, false, &v, NULL) == 200);
    g5c_json_free(v);
    free(body);
    TK_ASSERT(call(&t, "DELETE", err, NULL, false, &v, NULL) == 204);
    TK_ASSERT(call(&t, "DELETE", err, NULL, false, &v, NULL) == 404);
    g5c_json_free(v);

    /* an SMF that refuses the update: the AF is told the resources failed */
    {
        int na = af.n;
        char p2[640];
        snprintf(p2, sizeof p2, "%s/events-subscription", path);
        body = g5c_xasprintf("{\"events\":[{\"event\":\"SUCCESSFUL_RESOURCES_ALLOCATION\"},{\"event\":\"FAILED_RESOURCES_ALLOCATION\"}],\"notifUri\":\"%s\"}", afuri);
        TK_ASSERT(call(&t, "PUT", p2, body, false, &v, NULL) == 201);
        g5c_json_free(v);
        free(body);
        g5c_json_free(NULL);
        g_note_status = 500;
        TK_ASSERT(call(&t, "PATCH", path, "{\"ascReqData\":{\"medComponents\":{\"2\":{\"medCompN\":2,\"fStatus\":\"ENABLED\"}}}}", false, &v, NULL) == 200);
        g5c_json_free(v);
        TK_ASSERT(wait_notes(&af, na + 1, 3000));
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(af.body[na], "evNotifs"), 0), "event"), "FAILED_RESOURCES_ALLOCATION") == 0);
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(af.body[na], "failedResourcAllocReports"), 0), "mcResourcStatus"), "INACTIVE") == 0);
        g_note_status = 204;
        /* the rule never reached the SMF (the stored decision is the last one it accepted): the next request installs it */
        {
            int nu = t.notes.n;
            TK_ASSERT(call(&t, "PATCH", path, "{\"ascReqData\":{\"medComponents\":{\"2\":{\"medCompN\":2,\"fStatus\":\"ENABLED\"}}}}", false, &v, NULL) == 200);
            g5c_json_free(v);
            TK_ASSERT(wait_notes(&t.notes, nu + 1, 3000));
            TK_ASSERT(g5c_json_len(g5c_json_get(g5c_json_get(t.notes.body[nu], "smPolicyDecision"), "pccRules")) == 1);
        }
    }

    /* delete: the rules go from the SMF */
    {
        int nu = t.notes.n;
        snprintf(err, sizeof err, "%s/delete", path);
        TK_ASSERT(call(&t, "POST", err, "{}", false, &v, NULL) == 204);
        TK_ASSERT(wait_notes(&t.notes, nu + 1, 3000));
        TK_ASSERT(g5c_json_get(g5c_json_get(t.notes.body[nu], "smPolicyDecision"), "pccRules") == NULL);
        TK_ASSERT(call(&t, "POST", err, "{}", false, &v, NULL) == 404);
        g5c_json_free(v);
        TK_ASSERT(pcf_app_session_count(&t.p) == 0);
    }
    free(loc);
    loc = NULL;

    /* the limit, and the end of the PDU session ends the application sessions (the AF is told) */
    for (int i = 0; i < 3; i++) {
        body = g5c_xasprintf("{\"ascReqData\":{\"suppFeat\":\"10000\",\"ueIpv4\":\"10.46.0.2\",\"notifUri\":\"%s\","
                             "\"medComponents\":{\"1\":{\"medCompN\":1,\"qosReference\":\"streaming\",\"medSubComps\":{\"1\":{\"fNum\":1,\"fDescs\":[\"permit out ip from any to any\"]}}}}}}", afuri);
        TK_ASSERT(call(&t, "POST", "/npcf-policyauthorization/v1/app-sessions", body, false, &v, i == 0 ? &loc : NULL) == 201);
        g5c_json_free(v);
        free(body);
    }
    body = g5c_xasprintf("{\"ascReqData\":{\"suppFeat\":\"0\",\"ueIpv4\":\"10.46.0.2\",\"notifUri\":\"%s\"}}", afuri);
    TK_ASSERT(call(&t, "POST", "/npcf-policyauthorization/v1/app-sessions", body, false, &v, NULL) == 429);
    g5c_json_free(v);
    free(body);
    {
        int nt = 0;
        pthread_mutex_lock(&af.mu);
        nt = af.n;
        pthread_mutex_unlock(&af.mu);
        {
            char smp[480];
            g5c_json *ids = NULL;
            TK_ASSERT(call(&t, "GET", "/admin/v1/sessions", NULL, true, &ids, NULL) == 200);
            TK_ASSERT(g5c_json_len(ids) == 1);
            snprintf(smp, sizeof smp, SMP "/%s", g5c_json_get_str(g5c_json_at(ids, 0), "smPolicyId"));
            g5c_json_free(ids);
            snprintf(err, sizeof err, "%s/delete", smp);
            TK_ASSERT(call(&t, "POST", err, "{}", false, &v, NULL) == 204);
            g5c_json_free(v);
        }
        for (int k = 0; k < 3; k++)
            TK_ASSERT(wait_notes(&af, nt + k + 1, 3000));
        TK_ASSERT(strcmp(g5c_json_get_str(af.body[nt], "termCause"), "PDU_SESSION_TERMINATION") == 0 && strstr(g5c_json_get_str(af.body[nt], "resUri"), "/app-sessions/") != NULL);
        TK_ASSERT(pcf_app_session_count(&t.p) == 0);
    }
    free(loc);
    free(sm_body);
    g5c_server_stop(afs);
    g5c_router_free(afr);
    for (int i = 0; i < af.n; i++)
        g5c_json_free(af.body[i]);
    pthread_mutex_destroy(&af.mu);
    teardown(&t);

    /* configuration */
    {
        static const struct {
            const char *yaml, *want;
        } bad[] = {
            {"policy_authorization: { surprise: 1 }\n", "policy_authorization"},
            {"policy_authorization:\n  qos_references: { x: { qi5: 0 } }\n", "qi5"},
            {"policy_authorization:\n  qos_references: { x: { qi5: 1 } }\n", "GBR"},
            {"policy_authorization:\n  qos_references: { x: { qi5: 7, gbr_ul: 'fast' } }\n", "gbr_ul"},
            {"policy_authorization:\n  qos_references: { x: { qi5: 7, extra: 1 } }\n", "extra"},
            {"policy_authorization:\n  max_app_sessions: 0\n", "max_app_sessions"},
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            pcf pp;
            pcf_policy pol = parse_policy("{}", true);
            g5c_json *c = Y(bad[i].yaml);
            pcf_init(&pp, &pol, NULL, "http://u", NULL);
            if (pcf_policyauth_config(&pp, c, err, sizeof err) == 0 || strstr(err, bad[i].want) == NULL)
                TK_FAIL("n5 config case %zu: wanted an error naming %s, got: %s", i, bad[i].want, err);
            pcf_destroy(&pp);
            g5c_json_free(c);
        }
    }
}

int main(void)
{
    g5c_log_init("error", false);
    test_bitrates();
    test_resolution();
    test_decision_shape();
    test_validation();
    test_policy_roundtrip();
    test_lifecycle();
    test_invalid_requests();
    test_configured_profiles();
    test_push_mid_session();
    test_admin();
    test_termination_and_unreachable_smf();
    test_am_policy();
    test_metrics_and_empty_arrays();
    test_config_loading();
    test_policy_parse_errors();
    test_pcf_protocol_abuse();
    test_pcf_udr_outage();
    test_policy_authorization();
    test_bsf_binding();
    puts("pcf: ok");
    return 0;
}
