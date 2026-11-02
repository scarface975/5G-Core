/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The SMF against the rest of the core in one process: udr + UDM + PCF + the UPF runtime (real PFCP and GTP-U sockets, a datagram
 * socketpair as the N6 interface) + this SMF, with a scripted AMF on the N11 side and a scripted gNB on N3.
 *
 * The AMF side follows TS 23.502 4.3.2.2.1 (establishment), 4.2.6 (AN release / service request), 4.3.4 (release) with the Nsmf_PDUSession
 * bodies of TS 29.502 (multipart/related with the N1 SM and N2 SM parts). */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "g5c/gtpu.h"
#include "g5c/nas.h"
#include "g5c/ngap.h"
#include "g5c/pcf.h"
#include "g5c/smf.h"
#include "g5c/testkit.h"
#include "g5c/udm.h"
#include "g5c/udr.h"
#include "g5c/upf_rt.h"

#define ADMIN "admin-token-0123456789"
#define K_HEX "465b5ce8b199b49faa5f0a2ee238a6bc"
#define OP_HEX "cdc202d5123e20f62b6d676ac72cb318"

/* ---- the scripted AMF ----------------------------------------------------------------------------------------------------------- */

typedef struct {
    char path[400];
    char ctype[200];
    uint8_t *body;
    size_t len;
} rec_t;

static pthread_mutex_t amf_mu = PTHREAD_MUTEX_INITIALIZER;
static rec_t N1N2[64];
static size_t n_n1n2;
static rec_t STATUS[16];
static size_t n_status;
static int amf_n1n2_status = 200; /* what the AMF answers to an N1N2MessageTransfer */

static void keep(rec_t *r, const g5c_req *q)
{
    const char *ct = g5c_req_header(q, "content-type");
    snprintf(r->path, sizeof r->path, "%s", q->path);
    snprintf(r->ctype, sizeof r->ctype, "%s", ct ? ct : "");
    r->body = g5c_xmalloc(q->body_len + 1);
    memcpy(r->body, q->body, q->body_len);
    r->len = q->body_len;
}

static void amf_n1n2(void *c, const g5c_req *q, g5c_resp *r)
{
    (void)c;
    pthread_mutex_lock(&amf_mu);
    if (n_n1n2 < 64)
        keep(&N1N2[n_n1n2++], q);
    if (amf_n1n2_status == 200) {
        g5c_json *j = g5c_json_new_obj();
        g5c_json_set_str(j, "cause", "N1_N2_TRANSFER_INITIATED");
        g5c_resp_json(r, 200, j);
        g5c_json_free(j);
    } else {
        g5c_resp_problem_simple(r, amf_n1n2_status, "UE_NOT_REACHABLE", "scripted failure");
    }
    pthread_mutex_unlock(&amf_mu);
}

static void amf_status(void *c, const g5c_req *q, g5c_resp *r)
{
    (void)c;
    pthread_mutex_lock(&amf_mu);
    if (n_status < 16)
        keep(&STATUS[n_status++], q);
    pthread_mutex_unlock(&amf_mu);
    g5c_resp_status(r, 204);
}

static atomic_int nrf_hits;
static atomic_int amf_port;

/* Nnrf_NFDiscovery: only the AMF with the id the tests send as servingNfId is known */
static void nrf_discover(void *c, const g5c_req *q, g5c_resp *r)
{
    char *id = g5c_req_query_decoded(q, "target-nf-instance-id");
    (void)c;
    atomic_fetch_add(&nrf_hits, 1);
    if (id == NULL || strcmp(id, "11111111-2222-4333-8444-555555555555") != 0) {
        g5c_resp_problem_simple(r, 404, "NF_INSTANCE_NOT_FOUND", "unknown AMF");
    } else {
        g5c_json *j = g5c_json_new_obj(), *p = g5c_json_push(g5c_json_set(j, "nfInstances", g5c_json_new_arr()), g5c_json_new_obj()), *sv, *ep;
        g5c_json_set_str(p, "nfInstanceId", id);
        g5c_json_set_str(p, "nfType", "AMF");
        sv = g5c_json_push(g5c_json_set(p, "nfServices", g5c_json_new_arr()), g5c_json_new_obj());
        g5c_json_set_str(sv, "serviceName", "namf-comm");
        g5c_json_set_str(sv, "scheme", "http");
        ep = g5c_json_push(g5c_json_set(sv, "ipEndPoints", g5c_json_new_arr()), g5c_json_new_obj());
        g5c_json_set_str(ep, "ipv4Address", "127.0.0.1");
        g5c_json_set_int(ep, "port", atomic_load(&amf_port));
        g5c_resp_json(r, 200, j);
        g5c_json_free(j);
    }
    free(id);
}

static void amf_reset(void)
{
    pthread_mutex_lock(&amf_mu);
    for (size_t i = 0; i < n_n1n2; i++)
        free(N1N2[i].body);
    for (size_t i = 0; i < n_status; i++)
        free(STATUS[i].body);
    n_n1n2 = n_status = 0;
    amf_n1n2_status = 200;
    pthread_mutex_unlock(&amf_mu);
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* wait until the AMF has seen `n` N1N2 transfers (or `n` status notifications) */
static bool wait_n1n2(size_t n)
{
    double end = now_s() + 4;
    while (now_s() < end) {
        size_t have;
        pthread_mutex_lock(&amf_mu);
        have = n_n1n2;
        pthread_mutex_unlock(&amf_mu);
        if (have >= n)
            return true;
        usleep(5000);
    }
    fprintf(stderr, "wait_n1n2(%zu): only %zu transfers arrived\n", n, n_n1n2);
    return false;
}

static bool wait_status(size_t n)
{
    double end = now_s() + 4;
    while (now_s() < end) {
        size_t have;
        pthread_mutex_lock(&amf_mu);
        have = n_status;
        pthread_mutex_unlock(&amf_mu);
        if (have >= n)
            return true;
        usleep(5000);
    }
    return false;
}

/* ---- the environment ----------------------------------------------------------------------------------------------------------------- */

static struct {
    g5c_registry *m;
    g5c_udr_store *store;
    g5c_router *udr_r, *udm_r, *pcf_r, *amf_r, *smf_r;
    g5c_server *udr_s, *udm_s, *pcf_s, *amf_s, *smf_s;
    g5c_client *cl;
    udm_keys keys;
    udm u;
    pcf p;
    upf_rt *rt;
    pthread_t upf_th;
    int dn, n6_peer; /* N6 socketpair: the UPF owns n6_peer's partner */
    int gnb;
    char gnb_ip[32];
    uint8_t gnb_ip4[4];
    smf *s;
    g5c_nf *nf;
    char smf_base[64], udm_base[64], pcf_base[64];
    uint16_t n3p, n4p;
    char smf_n4_ip[32];
    char state_path[200];
    char cdr_path[200];
} E;

static void *upf_runner(void *a)
{
    upf_rt_run(a);
    return NULL;
}

static int http(const char *method, const char *url, const char *ctype, const void *body, size_t blen, g5c_resp *out, bool admin)
{
    char err[160], auth[64];
    g5c_kv hdr = {"authorization", auth};
    snprintf(auth, sizeof auth, "Bearer %s", ADMIN);
    if (g5c_client_request(E.cl, method, url, admin ? &hdr : NULL, admin ? 1 : 0, ctype, body, blen, out, err, sizeof err) != 0) {
        fprintf(stderr, "http %s %s: %s\n", method, url, err);
        return -1;
    }
    return out->status;
}

static void provision(const char *json)
{
    g5c_resp r;
    char url[128];
    snprintf(url, sizeof url, "%s/admin/v1/subscribers", E.udm_base);
    TK_ASSERT(http("POST", url, G5C_JSON_TYPE, json, strlen(json), &r, true) == 201);
    g5c_resp_free(&r);
}

static void start_upf(uint16_t n4_port, uint16_t n3_port)
{
    upf_rt_config rc;
    char err[200];
    upf_rt_config_defaults(&rc);
    rc.n6_fd = E.n6_peer;
    rc.engine.n4_addr = (upf_addr){false, {127, 0, 0, 1}, n4_port};
    rc.engine.n3_addr = (upf_addr){false, {127, 0, 0, 1}, n3_port};
    rc.engine.heartbeat_interval = 0;
    E.rt = upf_rt_new(&rc, E.m, err, sizeof err);
    if (E.rt == NULL)
        TK_FAIL("UPF runtime: %s", err);
    E.n4p = upf_rt_pfcp_port(E.rt);
    E.n3p = upf_rt_gtpu_port(E.rt);
    TK_ASSERT(pthread_create(&E.upf_th, NULL, upf_runner, E.rt) == 0);
}

static void stop_upf(void)
{
    upf_rt_stop(E.rt);
    pthread_join(E.upf_th, NULL);
    upf_rt_free(E.rt);
    E.rt = NULL;
}

static void start_smf(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[300], yaml[3200];
    g5c_json *j;
    g5c_common common;
    snprintf(yaml, sizeof yaml,
             "name: smf-e2e\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\nnrf: { uri: 'http://127.0.0.1:%u' }\n"
             "smf:\n  udm: { uri: '%s' }\n  pcf: { uri: '%s' }\n  n1n2_delay_ms: 5\n  release_guard_ms: 400\n  state_file: '%s'\n  cdr: { file: '%s' }\n"
             "  n4: { address: %s, port: 8805, t1_ms: 150, n1: 2, heartbeat: { interval: 1, failures: 2 } }\n"
             "  upfs:\n    - { name: upf-1, address: 127.0.0.1, port: %u }\n"
             "  dnns:\n"
             "    - { name: internet, ipv4_pool: 10.45.0.0/29, ipv6_pool: '2001:db8:45::/48', dns: [8.8.8.8, '2001:4860:4860::8888'] }\n"
             "    - { name: ims, ipv4_pool: 10.46.0.0/24 }\n"
             "    - { name: v6only, ipv6_pool: '2001:db8:46::/48' }\n",
             g5c_server_port(E.amf_s), E.udm_base, E.pcf_base, E.state_path, E.cdr_path, E.smf_n4_ip, E.n4p);
    j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    TK_ASSERT(j != NULL && g5c_common_parse(j, &common, err, sizeof err) == 0);
    common.port = 0;
    E.nf = g5c_nf_new(&common, err, sizeof err);
    TK_ASSERT(E.nf != NULL);
    E.s = smf_from_config(j, E.nf, err, sizeof err);
    if (E.s == NULL)
        TK_FAIL("SMF config: %s", err);
    g5c_json_free(j);
    TK_ASSERT(smf_start(E.s, err, sizeof err) == 0);
    E.smf_r = smf_router(E.s);
    E.smf_s = g5c_server_start(&cfg, E.smf_r, err, sizeof err);
    TK_ASSERT(E.smf_s != NULL);
    snprintf(E.smf_base, sizeof E.smf_base, "http://127.0.0.1:%u", g5c_server_port(E.smf_s));
    TK_ASSERT(smf_n4_wait_up(E.s->n4, 4000));
}

static void stop_smf(void)
{
    smf_drain(E.s); /* the state file is written by a deferred job */
    g5c_server_stop(E.smf_s);
    smf_destroy(E.s);
    free(E.s);
    g5c_nf_free(E.nf);
    g5c_router_free(E.smf_r);
    E.s = NULL;
}

static void setup(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[300], udr_url[64], master[32];
    g5c_json *py;
    pcf_policy pol;
    int sv[2];
    unsigned pid = (unsigned)getpid() % 250;

    E.m = g5c_registry_new();
    E.store = g5c_udr_store_memory();
    E.udr_r = g5c_udr_router(E.store);
    E.udr_s = g5c_server_start(&cfg, E.udr_r, err, sizeof err);
    TK_ASSERT(E.udr_s != NULL);
    snprintf(udr_url, sizeof udr_url, "http://127.0.0.1:%u", g5c_server_port(E.udr_s));
    E.cl = g5c_client_new(4000, NULL);
    memset(master, 7, sizeof master);
    udm_keys_with_master(&E.keys, (const uint8_t *)master);
    udm_init(&E.u, E.cl, udr_url, &E.keys, NULL, 0, "00101", "udm-e2e", E.m);
    E.u.admin_token = g5c_xstrdup(ADMIN);
    E.udm_r = udm_router(&E.u);
    E.udm_s = g5c_server_start(&cfg, E.udm_r, err, sizeof err);
    TK_ASSERT(E.udm_s != NULL);
    snprintf(E.udm_base, sizeof E.udm_base, "http://127.0.0.1:%u", g5c_server_port(E.udm_s));

    {
        static const char y[] = "default:\n  session_ambr: { uplink: 100 Mbps, downlink: 200 Mbps }\n  pcc_rules:\n    - id: voice\n"
                                "      flows: ['permit out 17 from 198.51.100.0/24 5060 to assigned']\n      qi5: 1\n      gbr_ul: 128 Kbps\n"
                                "      gbr_dl: 128 Kbps\n      precedence: 10\n";
        py = g5c_yaml_parse(y, strlen(y), err, sizeof err);
    }
    TK_ASSERT(py != NULL && pcf_policy_parse(py, true, &pol, err, sizeof err) == 0);
    g5c_json_free(py);
    pcf_init(&E.p, &pol, E.cl, udr_url, E.m);
    E.p.admin_token = g5c_xstrdup(ADMIN);
    E.pcf_r = pcf_router(&E.p);
    E.pcf_s = g5c_server_start(&cfg, E.pcf_r, err, sizeof err);
    TK_ASSERT(E.pcf_s != NULL);
    snprintf(E.pcf_base, sizeof E.pcf_base, "http://127.0.0.1:%u", g5c_server_port(E.pcf_s));

    E.amf_r = g5c_router_new();
    g5c_router_route(E.amf_r, "POST", "/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages", amf_n1n2, NULL);
    g5c_router_route(E.amf_r, "GET", "/nnrf-disc/v1/nf-instances", nrf_discover, NULL);
    g5c_router_route(E.amf_r, "POST", "/namf-callback/v1/{supi}/sm-context-status/{psi}", amf_status, NULL);
    E.amf_s = g5c_server_start(&cfg, E.amf_r, err, sizeof err);
    TK_ASSERT(E.amf_s != NULL);
    atomic_store(&amf_port, g5c_server_port(E.amf_s));

    TK_ASSERT(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    E.n6_peer = sv[0];
    E.dn = sv[1];
    {
        struct timeval tv = {0, 300000};
        (void)setsockopt(E.dn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    start_upf(0, 0);

    snprintf(E.gnb_ip, sizeof E.gnb_ip, "127.88.%u.1", pid);
    E.gnb_ip4[0] = 127;
    E.gnb_ip4[1] = 88;
    E.gnb_ip4[2] = (uint8_t)pid;
    E.gnb_ip4[3] = 1;
    snprintf(E.smf_n4_ip, sizeof E.smf_n4_ip, "127.99.%u.4", pid);
    {
        struct sockaddr_in sa;
        struct timeval tv = {0, 300000};
        int one = 1;
        E.gnb = socket(AF_INET, SOCK_DGRAM, 0);
        (void)setsockopt(E.gnb, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        (void)setsockopt(E.gnb, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons(2152);
        inet_pton(AF_INET, E.gnb_ip, &sa.sin_addr);
        TK_ASSERT(bind(E.gnb, (struct sockaddr *)&sa, sizeof sa) == 0);
    }

    snprintf(E.state_path, sizeof E.state_path, "/tmp/g5c-smf-e2e-%u.json", (unsigned)getpid());
    (void)unlink(E.state_path);
    snprintf(E.cdr_path, sizeof E.cdr_path, "/tmp/g5c-smf-e2e-%u.cdr", (unsigned)getpid());
    (void)unlink(E.cdr_path);
    start_smf();
}

static void teardown(void)
{
    stop_smf();
    (void)unlink(E.state_path);
    (void)unlink(E.cdr_path);
    stop_upf();
    g5c_server_stop(E.amf_s);
    g5c_server_stop(E.pcf_s);
    g5c_server_stop(E.udm_s);
    g5c_server_stop(E.udr_s);
    g5c_client_free(E.cl);
    g5c_router_free(E.amf_r);
    g5c_router_free(E.pcf_r);
    g5c_router_free(E.udm_r);
    g5c_router_free(E.udr_r);
    pcf_destroy(&E.p);
    udm_destroy(&E.u);
    g5c_udr_store_free(E.store);
    g5c_registry_free(E.m);
    close(E.gnb);
    close(E.dn);
    amf_reset();
}

/* ---- AMF-side request builders ------------------------------------------------------------------------------------------------------- */

static void build_est_req(g5c_bytes *out, uint8_t psi, uint8_t pti, int pdu_type)
{
    nas_msg m;
    uint8_t irate[2] = {0xff, 0xff}, half;
    static const uint8_t ep[] = {0x80, 0x00, 0x0d, 0x00, 0x00, 0x03, 0x00, 0x00, 0x10, 0x00};
    TK_ASSERT(nas_msg_init(&m, "PDU session establishment request"));
    m.pdu_session_id = psi;
    m.pti = pti;
    nas_msg_set(&m, "Integrity protection maximum data rate", irate, 2);
    if (pdu_type >= 0) {
        half = (uint8_t)pdu_type;
        nas_msg_set(&m, "PDU session type", &half, 1);
        half = 1;
        nas_msg_set(&m, "SSC mode", &half, 1);
    }
    nas_msg_set(&m, "Extended protocol configuration options", ep, sizeof ep);
    TK_ASSERT(nas_msg_encode(&m, out) == NAS_OK);
    nas_msg_free(&m);
}

static char *create_json(const char *supi, int psi, const char *dnn, int sst, const char *extra)
{
    return g5c_xasprintf("{\"supi\":\"%s\",\"pei\":\"imeisv-4370816125816151\",\"pduSessionId\":%d,%s%s%s\"sNssai\":{\"sst\":%d},"
                         "\"servingNfId\":\"11111111-2222-4333-8444-555555555555\",\"guami\":{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"amfId\":\"020040\"},"
                         "\"servingNetwork\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"requestType\":\"INITIAL_REQUEST\",\"n1SmMsg\":{\"contentId\":\"n1SmMsg\"},"
                         "\"anType\":\"3GPP_ACCESS\",\"ratType\":\"NR\",\"smContextStatusUri\":\"http://127.0.0.1:%u/namf-callback/v1/%s/sm-context-status/%d\"%s}",
                         supi, psi, dnn ? "\"dnn\":\"" : "", dnn ? dnn : "", dnn ? "\"," : "", sst, g5c_server_port(E.amf_s), supi, psi,
                         extra ? extra : "");
}

/* POST a JSON part plus optional N1 / N2 parts; returns the HTTP status and fills *out. */
static int post_parts(const char *path, const char *json, const uint8_t *n1, size_t n1len, const uint8_t *n2, size_t n2len, g5c_resp *out)
{
    g5c_mp_part p[3];
    size_t np = 1;
    g5c_bytes body;
    char *ct, url[500];
    int st;
    p[0] = (g5c_mp_part){NULL, "application/json", (const uint8_t *)json, strlen(json)};
    if (n1)
        p[np++] = (g5c_mp_part){"n1SmMsg", "application/vnd.3gpp.5gnas", n1, n1len};
    if (n2)
        p[np++] = (g5c_mp_part){"n2SmInfo", "application/vnd.3gpp.ngap", n2, n2len};
    g5c_bytes_init(&body);
    TK_ASSERT(g5c_mp_build(p, np, &body, &ct) == 0);
    snprintf(url, sizeof url, "%s%s", E.smf_base, path);
    st = http("POST", url, ct, body.data, body.len, out, false);
    g5c_bytes_free(&body);
    free(ct);
    return st;
}

static int post_json(const char *path, const char *json, g5c_resp *out)
{
    char url[500];
    snprintf(url, sizeof url, "%s%s", E.smf_base, path);
    return http("POST", url, G5C_JSON_TYPE, json, strlen(json), out, false);
}

/* ref from a 201's Location */
static void ref_of(const g5c_resp *r, char ref[37])
{
    const char *l = g5c_resp_header_get(r, "location"), *p;
    TK_ASSERT(l != NULL && (p = strstr(l, "/nsmf-pdusession/v1/sm-contexts/")) != NULL);
    p += strlen("/nsmf-pdusession/v1/sm-contexts/");
    TK_ASSERT(strlen(p) == 36);
    memcpy(ref, p, 37);
}

/* establish a session and return its ref; the AMF's N1N2 record index is `idx` */
static int establish(const char *supi, int psi, const char *dnn, int sst, int pdu_type, char ref[37], g5c_resp *out)
{
    g5c_bytes n1;
    char *js = create_json(supi, psi, dnn, sst, NULL);
    int st;
    g5c_bytes_init(&n1);
    build_est_req(&n1, (uint8_t)psi, 7, pdu_type);
    st = post_parts("/nsmf-pdusession/v1/sm-contexts", js, n1.data, n1.len, NULL, 0, out);
    if (st != 201 && getenv("SMF_TEST_DEBUG"))
        fprintf(stderr, "establish(%s, %d, %s): %d %.*s\n", supi, psi, dnn, st, (int)out->body_len, (const char *)out->body);
    if (st == 201 && ref)
        ref_of(out, ref);
    g5c_bytes_free(&n1);
    free(js);
    return st;
}

typedef struct {
    nas_msg accept;
    bool have_accept;
    g5c_json *n2;     /* PDUSessionResourceSetupRequestTransfer decoded */
    uint8_t ul_ip[4];
    uint32_t ul_teid;
    g5c_json *meta;
    g5c_mp mp;
} setup_t;

static const g5c_json *n2_ie(const g5c_json *t, int id)
{
    const g5c_json *l = g5c_json_get(t, "protocolIEs");
    for (size_t i = 0; i < g5c_json_len(l); i++) {
        int64_t v;
        if (g5c_json_get_int(g5c_json_at(l, i), "id", &v) && v == id)
            return g5c_json_get(g5c_json_at(l, i), "value");
    }
    return NULL;
}

/* decode the i-th N1N2 transfer: JSON metadata, the accept, the N2 setup transfer */
static void read_transfer(size_t i, setup_t *s)
{
    char err[160];
    const g5c_mp_part *n1, *n2;
    memset(s, 0, sizeof *s);
    pthread_mutex_lock(&amf_mu);
    TK_ASSERT(i < n_n1n2);
    TK_ASSERT(g5c_mp_parse(N1N2[i].ctype, N1N2[i].body, N1N2[i].len, &s->mp) == 0);
    pthread_mutex_unlock(&amf_mu);
    s->meta = g5c_json_parse((const char *)s->mp.parts[0].data, s->mp.parts[0].len, err, sizeof err);
    TK_ASSERT(s->meta != NULL);
    n1 = g5c_mp_find(&s->mp, g5c_json_get_str(g5c_json_get(g5c_json_get(s->meta, "n1MessageContainer"), "n1MessageContent"), "contentId"));
    n2 = g5c_mp_find(&s->mp, g5c_json_get_str(g5c_json_get(g5c_json_get(g5c_json_get(g5c_json_get(s->meta, "n2InfoContainer"), "smInfo"), "n2InfoContent"), "ngapData"), "contentId"));
    TK_ASSERT(n1 != NULL && n2 != NULL);
    TK_ASSERT(nas_msg_decode(n1->data, n1->len, &s->accept) == NAS_OK);
    s->have_accept = true;
    s->n2 = ngap_decode_as("PDUSessionResourceSetupRequestTransfer", n2->data, n2->len, err, sizeof err);
    TK_ASSERT(s->n2 != NULL);
    {
        const g5c_json *gt = g5c_json_get(n2_ie(s->n2, NGAP_IE_UL_NGU_UP_TNLInformation), "gTPTunnel");
        uint8_t tb[4];
        TK_ASSERT(g5c_hex_decode(g5c_json_get_str(g5c_json_get(gt, "transportLayerAddress"), "hex"), s->ul_ip, 4) == 4);
        TK_ASSERT(g5c_hex_decode(g5c_json_str(g5c_json_get(gt, "gTP-TEID")), tb, 4) == 4);
        s->ul_teid = (uint32_t)tb[0] << 24 | (uint32_t)tb[1] << 16 | (uint32_t)tb[2] << 8 | tb[3];
    }
}

static void setup_free(setup_t *s)
{
    if (s->have_accept)
        nas_msg_free(&s->accept);
    g5c_json_free(s->n2);
    g5c_json_free(s->meta);
    g5c_mp_free(&s->mp);
}

/* the gNB's PDUSessionResourceSetupResponseTransfer */
static void gnb_response(g5c_bytes *out, uint32_t teid, const uint8_t ip[4], int nq, const int *qfis)
{
    g5c_bytes b;
    char *hex = g5c_hex_encode(ip, 4), err[160];
    g5c_json *j = g5c_json_new_obj(), *per, *gt, *fl;
    per = g5c_json_set(j, "dLQosFlowPerTNLInformation", g5c_json_new_obj());
    gt = g5c_json_set(g5c_json_set(per, "uPTransportLayerInformation", g5c_json_new_obj()), "gTPTunnel", g5c_json_new_obj());
    {
        g5c_json *a = g5c_json_set(gt, "transportLayerAddress", g5c_json_new_obj());
        g5c_json_set_int(a, "len", 32);
        g5c_json_set_str(a, "hex", hex);
        uint8_t tb[4] = {(uint8_t)(teid >> 24), (uint8_t)(teid >> 16), (uint8_t)(teid >> 8), (uint8_t)teid};
        char *th = g5c_hex_encode(tb, 4);
        g5c_json_set_str(gt, "gTP-TEID", th);
        free(th);
    }
    fl = g5c_json_set(per, "associatedQosFlowList", g5c_json_new_arr());
    for (int i = 0; i < nq; i++)
        g5c_json_set_int(g5c_json_push(fl, g5c_json_new_obj()), "qosFlowIdentifier", qfis[i]);
    g5c_bytes_init(&b);
    TK_ASSERT(ngap_encode_as("PDUSessionResourceSetupResponseTransfer", j, &b, err, sizeof err) == 0);
    g5c_bytes_append(out, b.data, b.len);
    g5c_bytes_free(&b);
    g5c_json_free(j);
    free(hex);
}

static int modify(const char *ref, const char *json, const uint8_t *n1, size_t n1len, const uint8_t *n2, size_t n2len, g5c_resp *out)
{
    char path[400];
    snprintf(path, sizeof path, "/nsmf-pdusession/v1/sm-contexts/%s/modify", ref);
    return post_parts(path, json, n1, n1len, n2, n2len, out);
}

static int activate(const char *ref, uint32_t gnb_teid)
{
    g5c_bytes n2;
    g5c_resp r;
    int qf[2] = {1, 2}, st;
    g5c_bytes_init(&n2);
    gnb_response(&n2, gnb_teid, E.gnb_ip4, 2, qf);
    st = modify(ref, "{\"n2SmInfo\":{\"contentId\":\"n2SmInfo\"},\"n2SmInfoType\":\"PDU_RES_SETUP_RSP\"}", NULL, 0, n2.data, n2.len, &r);
    if (st == 200) {
        g5c_json *j = g5c_resp_parse_json(&r);
        TK_ASSERT(j != NULL && strcmp(g5c_json_get_str(j, "upCnxState"), "ACTIVATED") == 0);
        g5c_json_free(j);
    }
    g5c_resp_free(&r);
    g5c_bytes_free(&n2);
    return st;
}

static int release(const char *ref)
{
    char path[400];
    g5c_resp r;
    int st;
    snprintf(path, sizeof path, "/nsmf-pdusession/v1/sm-contexts/%s/release", ref);
    st = post_json(path, "{\"cause\":\"REL_DUE_TO_DUPLICATE_SESSION_ID\"}", &r);
    g5c_resp_free(&r);
    return st;
}

/* ---- gNB / data network ------------------------------------------------------------------------------------------------------------------ */

static void ip4pkt(uint8_t *p, const uint8_t src[4], const uint8_t dst[4], uint8_t proto, uint16_t sport, uint16_t dport, size_t total)
{
    memset(p, 0, total);
    p[0] = 0x45;
    p[2] = (uint8_t)(total >> 8);
    p[3] = (uint8_t)total;
    p[8] = 64;
    p[9] = proto;
    memcpy(p + 12, src, 4);
    memcpy(p + 16, dst, 4);
    p[20] = (uint8_t)(sport >> 8);
    p[21] = (uint8_t)sport;
    p[22] = (uint8_t)(dport >> 8);
    p[23] = (uint8_t)dport;
}

static void gnb_send_ul(uint32_t teid, uint8_t qfi, const uint8_t *ip, size_t n)
{
    uint8_t cont[2], out[1600];
    gtpu_header h;
    size_t len;
    struct sockaddr_in sa;
    gtpu_header_init(&h, GTPU_G_PDU, teid);
    gtpu_pdu_session_container(cont, 1, qfi, false);
    h.ext[0].typ = GTPU_EXT_PDU_SESSION_CONTAINER;
    h.ext[0].data = cont;
    h.ext[0].len = 2;
    h.next = 1;
    TK_ASSERT(gtpu_encode(&h, ip, n, out, sizeof out, &len) == 0);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(E.n3p);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    TK_ASSERT(sendto(E.gnb, out, len, 0, (struct sockaddr *)&sa, sizeof sa) == (ssize_t)len);
}

/* one downlink datagram at the gNB: its TEID and QFI, or false after the timeout */
static bool gnb_recv(uint32_t *teid, uint8_t *qfi, size_t *plen)
{
    uint8_t buf[2000];
    ssize_t n = recv(E.gnb, buf, sizeof buf, 0);
    gtpu_header h;
    const uint8_t *pl;
    uint8_t t;
    bool rqi;
    if (n <= 0)
        return false;
    TK_ASSERT(gtpu_decode(buf, (size_t)n, &h, &pl, plen) == 0 && h.msg_type == GTPU_G_PDU);
    *teid = h.teid;
    *qfi = 0;
    if (h.next == 1)
        TK_ASSERT(gtpu_as_pdu_session_container(&h.ext[0], &t, qfi, &rqi));
    return true;
}

static void gnb_drain(void)
{
    uint32_t t;
    uint8_t q;
    size_t n;
    while (gnb_recv(&t, &q, &n))
        ;
}

static bool dn_recv(uint8_t *buf, size_t cap, size_t *n)
{
    ssize_t r = recv(E.dn, buf, cap, 0);
    if (r <= 0)
        return false;
    *n = (size_t)r;
    return true;
}

static void dn_send(const uint8_t *ip, size_t n)
{
    TK_ASSERT(write(E.dn, ip, n) == (ssize_t)n);
}

/* The engine belongs to the UPF thread; the runtime publishes a snapshot after each control-plane message and timer tick. */
static size_t upf_sessions(void)
{
    size_t n = 0;
    upf_rt_snapshot(E.rt, NULL, &n);
    return n;
}

static bool upf_has(size_t want)
{
    double end = now_s() + 2;
    while (now_s() < end) {
        if (upf_sessions() == want)
            return true;
        usleep(5000);
    }
    return upf_sessions() == want;
}

static bool wait_for(bool (*cond)(void), double secs)
{
    double end = now_s() + secs;
    while (now_s() < end) {
        if (cond())
            return true;
        usleep(10000);
    }
    return cond();
}

static bool all_clear(void)
{
    return smf_session_count(E.s) == 0 && upf_sessions() == 0 && pcf_session_count(&E.p) == 0;
}

/* ---- scenarios ---------------------------------------------------------------------------------------------------------------------------- */

static void check_accept_basics(setup_t *s, bool expect_voice)
{
    const uint8_t *v;
    size_t n;
    TK_ASSERT(s->accept.def->msg_type == 0xc2);
    v = nas_msg_get(&s->accept, "Session AMBR", &n);
    TK_ASSERT(v && n == 6 && v[0] == 2 && v[1] == 0xc3 && v[2] == 0x50 && v[4] == 0x61 && v[5] == 0xa8);
    v = nas_msg_get(&s->accept, "Authorized QoS rules", &n);
    TK_ASSERT(v && n > 9 && v[0] == 1 && v[3] == 0x31);
    if (expect_voice) {
        TK_ASSERT(v[9] == 2 && v[n - 1] == 2 && v[n - 2] == 10); /* QRI 2, precedence 10, QFI 2 */
        v = nas_msg_get(&s->accept, "Authorized QoS flow descriptions", &n);
        TK_ASSERT(v && n == 6 + 4 * 5 - 5 + 5 && v[0] == 2 && v[2] == 0x45); /* QFI 2 GBR with 5 parameters */
    }
}

static void test_happy_path(void)
{
    g5c_resp r;
    char ref[37];
    setup_t s;
    const char *supi = "imsi-001010000000001";
    uint8_t ue[4], dnip[4] = {93, 184, 216, 34}, buf[1700];
    size_t n;
    uint32_t teid;
    uint8_t qfi;
    size_t plen;

    provision("{\"supi\":\"imsi-001010000000001\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}");
    amf_reset();
    TK_ASSERT(establish(supi, 5, "internet", 1, 1, ref, &r) == 201);
    {   /* the 201 carries the context reference in Location and the user plane state */
        g5c_json *j = g5c_resp_parse_json(&r);
        TK_ASSERT(j != NULL && strcmp(g5c_json_get_str(j, "upCnxState"), "ACTIVATING") == 0);
        g5c_json_free(j);
    }
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    pthread_mutex_lock(&amf_mu);
    TK_ASSERT(strcmp(N1N2[0].path, "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages") == 0);
    pthread_mutex_unlock(&amf_mu);
    read_transfer(0, &s);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(s.meta, "n1MessageContainer"), "n1MessageClass"), "SM") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(s.meta, "n2InfoContainer"), "n2InformationClass"), "SM") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(g5c_json_get(g5c_json_get(s.meta, "n2InfoContainer"), "smInfo"), "n2InfoContent"), "ngapIeType"), "PDU_RES_SETUP_REQ") == 0);
    check_accept_basics(&s, true);
    {
        const uint8_t *v;
        size_t k;
        v = nas_msg_get(&s.accept, "PDU address", &k);
        TK_ASSERT(v && k == 5 && v[0] == 1 && v[1] == 10 && v[2] == 45 && v[3] == 0 && v[4] >= 2 && v[4] <= 6);
        memcpy(ue, v + 1, 4);
        v = nas_msg_get(&s.accept, "Extended protocol configuration options", &k);
        TK_ASSERT(v && k == 1 + 7 + 19 + 5 && v[0] == 0x80 && v[4] == 8 && v[k - 2] == 0x05 && v[k - 1] == 0x78); /* DNS 8.8.8.8, DNS 2001:4860:4860::8888, MTU 1400 */
        v = nas_msg_get(&s.accept, "5GSM cause", &k);
        TK_ASSERT(v == NULL);
    }
    TK_ASSERT(s.ul_ip[0] == 127 && s.ul_teid != 0);
    TK_ASSERT(smf_session_count(E.s) == 1 && upf_has(1) && pcf_session_count(&E.p) == 1);
    {   /* the UDM knows which SMF serves the session */
        g5c_json *reg = g5c_udr_map_get(E.store, supi, UDR_SMF_REGS, "5");
        TK_ASSERT(reg != NULL && strcmp(g5c_json_get_str(reg, "smfInstanceId"), E.nf->instance_id) == 0 && strcmp(g5c_json_get_str(reg, "dnn"), "internet") == 0);
        g5c_json_free(reg);
    }

    /* uplink works as soon as the tunnel exists, before the gNB has answered */
    ip4pkt(buf, ue, dnip, 6, 40000, 443, 60);
    gnb_send_ul(s.ul_teid, 1, buf, 60);
    {
        uint8_t got[200];
        TK_ASSERT(dn_recv(got, sizeof got, &n) && n == 60 && memcmp(got, buf, 60) == 0);
    }
    /* downlink is dropped until the gNB tunnel is known */
    ip4pkt(buf, dnip, ue, 6, 443, 40000, 60);
    dn_send(buf, 60);
    TK_ASSERT(!gnb_recv(&teid, &qfi, &plen));

    TK_ASSERT(activate(ref, 0x7001) == 200);
    dn_send(buf, 60);
    TK_ASSERT(gnb_recv(&teid, &qfi, &plen) && teid == 0x7001 && qfi == 1 && plen == 60);
    {   /* traffic matching the voice rule rides the GBR flow */
        const uint8_t sip[4] = {198, 51, 100, 9};
        ip4pkt(buf, sip, ue, 17, 5060, 5060, 80);
        dn_send(buf, 80);
        TK_ASSERT(gnb_recv(&teid, &qfi, &plen) && teid == 0x7001 && qfi == 2 && plen == 80);
    }

    /* AN release: the downlink is buffered, the SMF answers the UPF's report */
    {
        g5c_resp d;
        g5c_json *j;
        TK_ASSERT(modify(ref, "{\"upCnxState\":\"DEACTIVATED\",\"cause\":\"REL_DUE_TO_DUPLICATE_SESSION_ID\"}", NULL, 0, NULL, 0, &d) == 200);
        j = g5c_resp_parse_json(&d);
        TK_ASSERT(j != NULL && strcmp(g5c_json_get_str(j, "upCnxState"), "DEACTIVATED") == 0);
        g5c_json_free(j);
        g5c_resp_free(&d);
    }
    ip4pkt(buf, dnip, ue, 6, 443, 40000, 70);
    dn_send(buf, 70);
    TK_ASSERT(!gnb_recv(&teid, &qfi, &plen));
    {
        double end = now_s() + 3;
        upf_stats st;
        do {
            upf_rt_snapshot(E.rt, &st, NULL);
            if (st.reports_acked >= 1)
                break;
            usleep(10000);
        } while (now_s() < end);
        TK_ASSERT(st.reports_sent >= 1 && st.reports_acked >= 1); /* the SMF's Session Report Response */
    }
    /* the report made the SMF page the UE: an N1N2 transfer with the N2 setup request and no N1 message */
    TK_ASSERT(wait_n1n2(2));
    {
        g5c_mp pmp;
        g5c_json *pj;
        char perr[100];
        pthread_mutex_lock(&amf_mu);
        TK_ASSERT(g5c_mp_parse(N1N2[1].ctype, N1N2[1].body, N1N2[1].len, &pmp) == 0);
        pthread_mutex_unlock(&amf_mu);
        pj = g5c_json_parse((const char *)pmp.parts[0].data, pmp.parts[0].len, perr, sizeof perr);
        TK_ASSERT(pj != NULL && g5c_json_get(pj, "n1MessageContainer") == NULL);
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(g5c_json_get(g5c_json_get(pj, "n2InfoContainer"), "smInfo"), "n2InfoContent"), "ngapIeType"), "PDU_RES_SETUP_REQ") == 0);
        g5c_json_free(pj);
        g5c_mp_free(&pmp);
    }
    /* service request: the SMF returns the N2 setup request again; the gNB answers and the buffered packet is flushed */
    {
        g5c_resp d;
        const g5c_mp_part *n2p;
        g5c_mp mp;
        g5c_json *j;
        TK_ASSERT(modify(ref, "{\"upCnxState\":\"ACTIVATING\"}", NULL, 0, NULL, 0, &d) == 200);
        TK_ASSERT(g5c_mp_parse(g5c_resp_header_get(&d, "content-type"), d.body, d.body_len, &mp) == 0);
        j = g5c_json_parse((const char *)mp.parts[0].data, mp.parts[0].len, (char[100]){0}, 100);
        TK_ASSERT(j && strcmp(g5c_json_get_str(j, "n2SmInfoType"), "PDU_RES_SETUP_REQ") == 0 && strcmp(g5c_json_get_str(j, "upCnxState"), "ACTIVATING") == 0);
        n2p = g5c_mp_find(&mp, g5c_json_get_str(g5c_json_get(j, "n2SmInfo"), "contentId"));
        TK_ASSERT(n2p != NULL);
        {
            char err[100];
            g5c_json *t = ngap_decode_as("PDUSessionResourceSetupRequestTransfer", n2p->data, n2p->len, err, sizeof err);
            TK_ASSERT(t != NULL && n2_ie(t, NGAP_IE_UL_NGU_UP_TNLInformation) != NULL);
            g5c_json_free(t);
        }
        g5c_json_free(j);
        g5c_mp_free(&mp);
        g5c_resp_free(&d);
    }
    TK_ASSERT(activate(ref, 0x7002) == 200);
    TK_ASSERT(gnb_recv(&teid, &qfi, &plen) && teid == 0x7002 && plen == 70); /* the packet buffered while the UE was idle */

    /* UE-requested release: command out, complete in, everything is given back */
    {
        nas_msg m;
        g5c_bytes rel, cmpl;
        g5c_resp d;
        uint8_t cause = 36;
        const g5c_mp_part *p1, *p2;
        g5c_mp mp;
        g5c_json *j;
        char err[100];
        g5c_bytes_init(&rel);
        g5c_bytes_init(&cmpl);
        TK_ASSERT(nas_msg_init(&m, "PDU session release request"));
        m.pdu_session_id = 5;
        m.pti = 11;
        TK_ASSERT(nas_msg_encode(&m, &rel) == NAS_OK);
        nas_msg_free(&m);
        TK_ASSERT(modify(ref, "{\"n1SmMsg\":{\"contentId\":\"n1SmMsg\"}}", rel.data, rel.len, NULL, 0, &d) == 200);
        TK_ASSERT(g5c_mp_parse(g5c_resp_header_get(&d, "content-type"), d.body, d.body_len, &mp) == 0);
        j = g5c_json_parse((const char *)mp.parts[0].data, mp.parts[0].len, err, sizeof err);
        TK_ASSERT(j && strcmp(g5c_json_get_str(j, "n2SmInfoType"), "PDU_RES_REL_CMD") == 0);
        p1 = g5c_mp_find(&mp, "n1SmMsg");
        p2 = g5c_mp_find(&mp, "n2SmInfo");
        TK_ASSERT(p1 && p2 && nas_msg_decode(p1->data, p1->len, &m) == NAS_OK && m.def->msg_type == 0xd3 && m.pti == 11);
        nas_msg_free(&m);
        TK_ASSERT(smf_n2_parse_cause("PDUSessionResourceReleaseCommandTransfer", p2->data, p2->len, (char[64]){0}, 64) == 0);
        g5c_json_free(j);
        g5c_mp_free(&mp);
        g5c_resp_free(&d);
        TK_ASSERT(smf_session_count(E.s) == 1); /* still there until the UE has confirmed */
        TK_ASSERT(nas_msg_init(&m, "PDU session release complete"));
        m.pdu_session_id = 5;
        m.pti = 11;
        (void)cause;
        TK_ASSERT(nas_msg_encode(&m, &cmpl) == NAS_OK);
        nas_msg_free(&m);
        TK_ASSERT(modify(ref, "{\"n1SmMsg\":{\"contentId\":\"n1SmMsg\"}}", cmpl.data, cmpl.len, NULL, 0, &d) == 204);
        g5c_resp_free(&d);
        g5c_bytes_free(&rel);
        g5c_bytes_free(&cmpl);
    }
    TK_ASSERT(wait_for(all_clear, 3));
    TK_ASSERT(g5c_udr_map_get(E.store, supi, UDR_SMF_REGS, "5") == NULL);
    TK_ASSERT(smf_pool_used4(E.s->dnns[0].pool) == 0);
    {   /* the released context is gone */
        g5c_resp d;
        TK_ASSERT(modify(ref, "{}", NULL, 0, NULL, 0, &d) == 404);
        g5c_resp_free(&d);
    }
    /* and the tunnel is dead: an uplink packet draws an Error Indication */
    ip4pkt(buf, ue, dnip, 6, 40000, 443, 60);
    gnb_send_ul(s.ul_teid, 1, buf, 60);
    {
        uint8_t eb[64];
        ssize_t k = recv(E.gnb, eb, sizeof eb, 0);
        TK_ASSERT(k >= 8 && eb[1] == GTPU_ERROR_INDICATION);
    }
    {   /* the charging record of the session: who, how long, how much (the 60 octets of the uplink packet), why it ended */
        char *txt = g5c_read_file(E.cdr_path, 1U << 16, NULL), *line = NULL, *p;
        g5c_json *rec;
        char err[200];
        TK_ASSERT(txt != NULL);
        for (p = txt; *p;) {
            char *nl = strchr(p, '\n');
            if (nl == NULL)
                break;
            *nl = 0;
            if (strstr(p, "\"supi\":\"imsi-001010000000001\"") != NULL && strstr(p, "\"pduSessionId\":5") != NULL)
                line = p;
            p = nl + 1;
        }
        TK_ASSERT(line != NULL);
        rec = g5c_json_parse(line, strlen(line), err, sizeof err);
        TK_ASSERT(rec != NULL && strcmp(g5c_json_get_str(rec, "recordType"), "pduSession") == 0 && strcmp(g5c_json_get_str(rec, "dnn"), "internet") == 0);
        {
            int64_t ul = 0, dl = 0, seq = 0;
            bool rep = false;
            TK_ASSERT(g5c_json_get_bool(rec, "usageReported", &rep) && rep);
            TK_ASSERT(g5c_json_get_int(rec, "uplinkOctets", &ul) && ul >= 60 && g5c_json_get_int(rec, "downlinkOctets", &dl) && dl >= 0);
            TK_ASSERT(g5c_json_get_int(rec, "recordSequenceNumber", &seq) && seq >= 1);
        }
        TK_ASSERT(g5c_json_get_str(rec, "startTime") != NULL && g5c_json_get_str(rec, "endTime") != NULL && g5c_json_get_str(rec, "ueIpv4Address") != NULL);
        TK_ASSERT(g5c_json_get_str(rec, "closeCause") != NULL && g5c_json_get_str(rec, "closeCause")[0] != 0 && g5c_json_get_str(rec, "upf") != NULL);
        TK_ASSERT(g5c_json_get_int(g5c_json_get(rec, "snssai"), "sst", &(int64_t){0}));
        g5c_json_free(rec);
        free(txt);
    }
    setup_free(&s);
    gnb_drain();
}

static void test_release_and_replace(void)
{
    g5c_resp r;
    char ref1[37], ref2[37];
    const char *supi = "imsi-001010000000001";
    amf_reset();
    TK_ASSERT(establish(supi, 6, "internet", 1, 1, ref1, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    TK_ASSERT(release(ref1) == 204);
    TK_ASSERT(wait_for(all_clear, 3));
    TK_ASSERT(release(ref1) == 404);

    /* a second establishment of the same PDU session id replaces the first one */
    amf_reset();
    TK_ASSERT(establish(supi, 6, "internet", 1, 1, ref1, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    TK_ASSERT(establish(supi, 6, "internet", 1, 1, ref2, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(strcmp(ref1, ref2) != 0);
    TK_ASSERT(wait_n1n2(2));
    {
        g5c_resp d;
        TK_ASSERT(modify(ref1, "{}", NULL, 0, NULL, 0, &d) == 404);
        g5c_resp_free(&d);
    }
    TK_ASSERT(smf_session_count(E.s) == 1 && upf_has(1) && pcf_session_count(&E.p) == 1 && smf_pool_used4(E.s->dnns[0].pool) == 1);
    TK_ASSERT(release(ref2) == 204);
    TK_ASSERT(wait_for(all_clear, 3));
    TK_ASSERT(smf_pool_used4(E.s->dnns[0].pool) == 0);
}

/* a rejected establishment: HTTP status, ProblemDetails cause and the reject message for the UE */
static void expect_reject(g5c_resp *r, int status, const char *cause, int gsm_cause)
{
    g5c_mp mp;
    g5c_json *j;
    char err[100];
    TK_ASSERT(r->status == status);
    TK_ASSERT(g5c_mp_parse(g5c_resp_header_get(r, "content-type"), r->body, r->body_len, &mp) == 0);
    j = g5c_json_parse((const char *)mp.parts[0].data, mp.parts[0].len, err, sizeof err);
    TK_ASSERT(j != NULL);
    if (cause && strcmp(g5c_json_get_str(g5c_json_get(j, "error"), "cause"), cause) != 0)
        TK_FAIL("reject cause %s, wanted %s", g5c_json_get_str(g5c_json_get(j, "error"), "cause"), cause);
    if (gsm_cause) {
        const g5c_mp_part *p = g5c_mp_find(&mp, g5c_json_get_str(g5c_json_get(j, "n1SmMsg"), "contentId"));
        nas_msg m;
        const uint8_t *v;
        size_t n;
        TK_ASSERT(p != NULL && nas_msg_decode(p->data, p->len, &m) == NAS_OK && m.def->msg_type == 0xc3);
        v = nas_msg_get(&m, "5GSM cause", &n);
        if (!(v && n == 1 && v[0] == gsm_cause))
            TK_FAIL("5GSM cause %u, wanted %d", v ? v[0] : 0, gsm_cause);
        nas_msg_free(&m);
    }
    g5c_json_free(j);
    g5c_mp_free(&mp);
}

static void test_rejections(void)
{
    g5c_resp r;
    char ref[37];
    g5c_bytes n1;
    char *js;

    provision("{\"supi\":\"imsi-001010000000002\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{\"internet\":{\"session_types\":[\"IPV4\",\"IPV6\",\"IPV4V6\"]},"
              "\"v6only\":{\"session_types\":[\"IPV6\"]}}}");
    amf_reset();
    /* unknown DNN (not configured in the SMF) and unknown subscriber, unsubscribed slice, disallowed type */
    TK_ASSERT(establish("imsi-001010000000001", 5, "nonexistent", 1, 1, ref, &r) == 403);
    expect_reject(&r, 403, "DNN_DENIED", SMF_5GSM_MISSING_OR_UNKNOWN_DNN);
    g5c_resp_free(&r);
    TK_ASSERT(establish("imsi-001010000000099", 5, "internet", 1, 1, ref, &r) == 403);
    expect_reject(&r, 403, "DNN_DENIED", SMF_5GSM_MISSING_OR_UNKNOWN_DNN);
    g5c_resp_free(&r);
    TK_ASSERT(establish("imsi-001010000000001", 5, "internet", 9, 1, ref, &r) == 403);
    expect_reject(&r, 403, "DNN_DENIED", SMF_5GSM_MISSING_OR_UNKNOWN_DNN);
    g5c_resp_free(&r);
    TK_ASSERT(establish("imsi-001010000000001", 5, "internet", 1, 2, ref, &r) == 403); /* IPv6 on an IPv4-only subscription */
    expect_reject(&r, 403, "PDU_SESSION_TYPE_NOT_ALLOWED", SMF_5GSM_UNKNOWN_PDU_SESSION_TYPE);
    g5c_resp_free(&r);
    TK_ASSERT(establish("imsi-001010000000001", 5, "ims", 1, 1, ref, &r) == 403); /* the subscription has no `ims` */
    g5c_resp_free(&r);
    TK_ASSERT(smf_session_count(E.s) == 0 && upf_has(0) && pcf_session_count(&E.p) == 0 && n_n1n2 == 0);

    /* dual stack: both an IPv4 address and an IPv6 prefix, and the UE gets an interface identifier */
    {
        setup_t s;
        const uint8_t *v;
        size_t n;
        TK_ASSERT(establish("imsi-001010000000002", 3, "internet", 1, 3, ref, &r) == 201);
        g5c_resp_free(&r);
        TK_ASSERT(wait_n1n2(1));
        read_transfer(0, &s);
        v = nas_msg_get(&s.accept, "PDU address", &n);
        TK_ASSERT(v && n == 13 && v[0] == 3 && v[9] == 10 && v[10] == 45);
        TK_ASSERT(strcmp(g5c_json_str(n2_ie(s.n2, NGAP_IE_PDUSessionType)), "ipv4v6") == 0);
        TK_ASSERT(nas_msg_get(&s.accept, "5GSM cause", &n) == NULL);
        TK_ASSERT(smf_pool_used6(E.s->dnns[0].pool) == 1 && smf_pool_used4(E.s->dnns[0].pool) == 1);
        setup_free(&s);
        TK_ASSERT(release(ref) == 204);
        TK_ASSERT(wait_for(all_clear, 3));
        TK_ASSERT(smf_pool_used6(E.s->dnns[0].pool) == 0);
    }
    /* IPv4v6 requested on an IPv6-only DNN: the SMF gives IPv6 and says why (cause #51) */
    {
        setup_t s;
        const uint8_t *v;
        size_t n;
        amf_reset();
        TK_ASSERT(establish("imsi-001010000000002", 4, "v6only", 1, 3, ref, &r) == 201);
        g5c_resp_free(&r);
        TK_ASSERT(wait_n1n2(1));
        read_transfer(0, &s);
        v = nas_msg_get(&s.accept, "PDU address", &n);
        TK_ASSERT(v && n == 9 && v[0] == 2);
        v = nas_msg_get(&s.accept, "5GSM cause", &n);
        TK_ASSERT(v && n == 1 && v[0] == SMF_5GSM_PDU_TYPE_IPV6_ONLY);
        setup_free(&s);
        TK_ASSERT(release(ref) == 204);
        TK_ASSERT(wait_for(all_clear, 3));
    }

    /* malformed requests */
    g5c_bytes_init(&n1);
    build_est_req(&n1, 5, 7, 1);
    {
        const char *bad_json[] = {"{\"pduSessionId\":5,\"sNssai\":{\"sst\":1}}",                                                   /* no supi */
                                  "{\"supi\":\"x\",\"pduSessionId\":5,\"sNssai\":{\"sst\":1}}",                                     /* short supi */
                                  "{\"supi\":\"imsi-001010000000001\",\"pduSessionId\":0,\"sNssai\":{\"sst\":1}}",                  /* psi 0 */
                                  "{\"supi\":\"imsi-001010000000001\",\"pduSessionId\":16,\"sNssai\":{\"sst\":1}}",                 /* psi 16 */
                                  "{\"supi\":\"imsi-001010000000001\",\"pduSessionId\":5}",                                         /* no slice */
                                  "{\"supi\":\"imsi-001010000000001\",\"pduSessionId\":5,\"sNssai\":{\"sst\":300}}",
                                  "{\"supi\":\"imsi-001010000000001\",\"pduSessionId\":5,\"sNssai\":{\"sst\":1,\"sd\":\"zzzzzz\"}}",
                                  "{\"supi\":\"imsi-001010000000001\",\"pduSessionId\":5,\"sNssai\":{\"sst\":1}}",                  /* no n1SmMsg ref */
                                  "[1,2,3]"};
        for (size_t i = 0; i < sizeof bad_json / sizeof bad_json[0]; i++) {
            TK_ASSERT(post_parts("/nsmf-pdusession/v1/sm-contexts", bad_json[i], i == 7 ? NULL : n1.data, i == 7 ? 0 : n1.len, NULL, 0, &r) == 400);
            g5c_resp_free(&r);
        }
    }
    g5c_bytes_free(&n1);

    /* a NAS message whose PDU session id differs from the request's, a truncated NAS message, and a NAS message of another kind */
    {
        g5c_bytes n1b;
        nas_msg m;
        g5c_bytes_init(&n1b);
        build_est_req(&n1b, 9, 7, 1);
        js = create_json("imsi-001010000000001", 5, "internet", 1, NULL);
        TK_ASSERT(post_parts("/nsmf-pdusession/v1/sm-contexts", js, n1b.data, n1b.len, NULL, 0, &r) == 400);
        g5c_resp_free(&r);
        g5c_bytes_clear(&n1b);
        build_est_req(&n1b, 5, 7, 1);
        n1b.len = 5; /* cut inside the message */
        TK_ASSERT(post_parts("/nsmf-pdusession/v1/sm-contexts", js, n1b.data, n1b.len, NULL, 0, &r) == 400);
        expect_reject(&r, 400, "INVALID_MSG_FORMAT", SMF_5GSM_INVALID_MANDATORY_INFORMATION);
        g5c_resp_free(&r);
        g5c_bytes_clear(&n1b);
        TK_ASSERT(nas_msg_init(&m, "PDU session release request"));
        m.pdu_session_id = 5;
        m.pti = 3;
        TK_ASSERT(nas_msg_encode(&m, &n1b) == NAS_OK);
        nas_msg_free(&m);
        TK_ASSERT(post_parts("/nsmf-pdusession/v1/sm-contexts", js, n1b.data, n1b.len, NULL, 0, &r) == 400);
        expect_reject(&r, 400, "INVALID_MSG_FORMAT", SMF_5GSM_MESSAGE_TYPE_NOT_IMPLEMENTED);
        g5c_resp_free(&r);
        free(js);
        g5c_bytes_free(&n1b);
    }
    /* transport level: JSON without the multipart framing, a body that is not multipart although it says so, a wrong media type, a request type we do not serve */
    {
        char url[200];
        char *p;
        g5c_bytes b2;
        snprintf(url, sizeof url, "%s/nsmf-pdusession/v1/sm-contexts", E.smf_base);
        js = create_json("imsi-001010000000001", 5, "internet", 1, NULL);
        TK_ASSERT(post_json("/nsmf-pdusession/v1/sm-contexts", js, &r) == 400); /* the n1SmMsg reference has nothing to point at */
        g5c_resp_free(&r);
        TK_ASSERT(http("POST", url, "multipart/related; boundary=zz", "this is not multipart", 21, &r, false) == 400);
        g5c_resp_free(&r);
        TK_ASSERT(http("POST", url, "text/plain", js, strlen(js), &r, false) == 415);
        g5c_resp_free(&r);
        TK_ASSERT(http("POST", url, G5C_JSON_TYPE, "", 0, &r, false) == 400);
        g5c_resp_free(&r);
        g5c_bytes_init(&n1);
        build_est_req(&n1, 5, 7, 1);
        p = strstr(js, "\"INITIAL_REQUEST\"");
        TK_ASSERT(p != NULL);
        g5c_bytes_init(&b2);
        g5c_bytes_append(&b2, js, (size_t)(p - js));
        g5c_bytes_append_str(&b2, "\"EXISTING_PDU_SESSION\"");
        g5c_bytes_append_str(&b2, p + strlen("\"INITIAL_REQUEST\""));
        TK_ASSERT(post_parts("/nsmf-pdusession/v1/sm-contexts", (const char *)b2.data, n1.data, n1.len, NULL, 0, &r) == 501);
        g5c_resp_free(&r);
        g5c_bytes_free(&b2);
        g5c_bytes_free(&n1);
        free(js);
    }
    TK_ASSERT(smf_session_count(E.s) == 0 && upf_has(0) && pcf_session_count(&E.p) == 0);
}

static void test_failures(void)
{
    g5c_resp r;
    char ref[37], refs[8][37];
    const char *supi = "imsi-001010000000001";

    /* the AMF refuses the N1N2 transfer: the SMF gives everything back and tells the AMF the context is gone */
    amf_reset();
    pthread_mutex_lock(&amf_mu);
    amf_n1n2_status = 500;
    pthread_mutex_unlock(&amf_mu);
    TK_ASSERT(establish(supi, 7, "internet", 1, 1, ref, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1) && wait_status(1));
    TK_ASSERT(wait_for(all_clear, 3));
    TK_ASSERT(smf_pool_used4(E.s->dnns[0].pool) == 0 && g5c_udr_map_get(E.store, supi, UDR_SMF_REGS, "7") == NULL);
    {
        g5c_json *j;
        char err[100];
        pthread_mutex_lock(&amf_mu);
        TK_ASSERT(strcmp(STATUS[0].path, "/namf-callback/v1/imsi-001010000000001/sm-context-status/7") == 0);
        j = g5c_json_parse((const char *)STATUS[0].body, STATUS[0].len, err, sizeof err);
        pthread_mutex_unlock(&amf_mu);
        TK_ASSERT(j && strcmp(g5c_json_get_str(g5c_json_get(j, "statusInfo"), "resourceStatus"), "RELEASED") == 0);
        g5c_json_free(j);
    }
    amf_reset();

    /* the address pool of `internet` holds five UE addresses */
    for (int i = 0; i < 5; i++) {
        TK_ASSERT(establish(supi, 1 + i, "internet", 1, 1, refs[i], &r) == 201);
        g5c_resp_free(&r);
    }
    TK_ASSERT(establish(supi, 8, "internet", 1, 1, ref, &r) == 500);
    expect_reject(&r, 500, "INSUFFICIENT_RESOURCES", SMF_5GSM_INSUFFICIENT_RESOURCES);
    g5c_resp_free(&r);
    TK_ASSERT(smf_session_count(E.s) == 5 && smf_pool_used4(E.s->dnns[0].pool) == 5 && pcf_session_count(&E.p) == 5 && upf_has(5));
    TK_ASSERT(release(refs[2]) == 204);
    TK_ASSERT(establish(supi, 8, "internet", 1, 1, ref, &r) == 201);
    g5c_resp_free(&r);
    smf_drain(E.s); /* the transfer for the session that was released early finds nothing to send */
    TK_ASSERT(release(ref) == 204);
    for (int i = 0; i < 5; i++)
        if (i != 2)
            TK_ASSERT(release(refs[i]) == 204);
    TK_ASSERT(wait_for(all_clear, 3) && smf_pool_used4(E.s->dnns[0].pool) == 0);
    amf_reset();

    /* the gNB cannot set the resources up */
    TK_ASSERT(establish(supi, 2, "internet", 1, 1, ref, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    {
        g5c_bytes n2;
        char err[100];
        static const char cj[] = "{\"cause\":{\"radioNetwork\":\"radio-connection-with-ue-lost\"}}";
        g5c_json *d = g5c_json_parse(cj, strlen(cj), err, sizeof err);
        g5c_bytes_init(&n2);
        TK_ASSERT(d && ngap_encode_as("PDUSessionResourceSetupUnsuccessfulTransfer", d, &n2, err, sizeof err) == 0);
        g5c_json_free(d);
        TK_ASSERT(modify(ref, "{\"n2SmInfo\":{\"contentId\":\"n2SmInfo\"},\"n2SmInfoType\":\"PDU_RES_SETUP_FAIL\"}", NULL, 0, n2.data, n2.len, &r) == 204);
        g5c_resp_free(&r);
        g5c_bytes_free(&n2);
    }
    TK_ASSERT(wait_for(all_clear, 3));

    /* requests on a live context that the SMF cannot or must not honour */
    TK_ASSERT(establish(supi, 2, "internet", 1, 1, ref, &r) == 201);
    g5c_resp_free(&r);
    {
        nas_msg m;
        g5c_bytes b;
        g5c_resp d;
        int only_qfi2[1] = {2};
        g5c_bytes n2;
        g5c_bytes_init(&b);
        TK_ASSERT(nas_msg_init(&m, "PDU session modification request"));
        m.pdu_session_id = 2;
        m.pti = 4;
        TK_ASSERT(nas_msg_encode(&m, &b) == NAS_OK);
        nas_msg_free(&m);
        TK_ASSERT(modify(ref, "{\"n1SmMsg\":{\"contentId\":\"n1SmMsg\"}}", b.data, b.len, NULL, 0, &d) == 200);
        {
            g5c_mp mp;
            nas_msg rm;
            const g5c_mp_part *p;
            TK_ASSERT(g5c_mp_parse(g5c_resp_header_get(&d, "content-type"), d.body, d.body_len, &mp) == 0);
            p = g5c_mp_find(&mp, "n1SmMsg");
            TK_ASSERT(p && nas_msg_decode(p->data, p->len, &rm) == NAS_OK && rm.def->msg_type == 0xca && rm.pti == 4);
            nas_msg_free(&rm);
            g5c_mp_free(&mp);
        }
        g5c_resp_free(&d);
        /* a 5GMM message, a 5GSM message of an unexpected kind, and a PDU session id of another session */
        g5c_bytes_clear(&b);
        g5c_bytes_append(&b, "\x7e\x00\x41\x00", 4);
        TK_ASSERT(modify(ref, "{\"n1SmMsg\":{\"contentId\":\"n1SmMsg\"}}", b.data, b.len, NULL, 0, &d) == 400);
        g5c_resp_free(&d);
        g5c_bytes_clear(&b);
        g5c_bytes_append(&b, "\x2e\x02\x01\xc6", 4); /* PDU SESSION AUTHENTICATION COMPLETE for session 2 */
        TK_ASSERT(modify(ref, "{\"n1SmMsg\":{\"contentId\":\"n1SmMsg\"}}", b.data, b.len, NULL, 0, &d) == 501);
        g5c_resp_free(&d);
        g5c_bytes_clear(&b);
        g5c_bytes_append(&b, "\x2e\x09\x01\xd1", 4);
        TK_ASSERT(modify(ref, "{\"n1SmMsg\":{\"contentId\":\"n1SmMsg\"}}", b.data, b.len, NULL, 0, &d) == 400);
        g5c_resp_free(&d);
        g5c_bytes_free(&b);
        /* N2 information: unknown type, undecodable response, a response that does not accept the default flow */
        TK_ASSERT(modify(ref, "{\"n2SmInfo\":{\"contentId\":\"n2SmInfo\"},\"n2SmInfoType\":\"SECONDARY_RAT_USAGE\"}", NULL, 0, (const uint8_t *)"\x00", 1, &d) == 501);
        g5c_resp_free(&d);
        TK_ASSERT(modify(ref, "{\"n2SmInfo\":{\"contentId\":\"n2SmInfo\"},\"n2SmInfoType\":\"PDU_RES_SETUP_RSP\"}", NULL, 0, (const uint8_t *)"\xff\xff\xff", 3, &d) == 400);
        g5c_resp_free(&d);
        TK_ASSERT(modify(ref, "{\"n2SmInfoType\":\"PDU_RES_SETUP_RSP\"}", NULL, 0, NULL, 0, &d) == 400); /* no N2 part at all */
        g5c_resp_free(&d);
        g5c_bytes_init(&n2);
        gnb_response(&n2, 0x9000, E.gnb_ip4, 1, only_qfi2);
        TK_ASSERT(modify(ref, "{\"n2SmInfo\":{\"contentId\":\"n2SmInfo\"},\"n2SmInfoType\":\"PDU_RES_SETUP_RSP\"}", NULL, 0, n2.data, n2.len, &d) == 500);
        g5c_resp_free(&d);
        g5c_bytes_free(&n2);
        /* user-plane state values; an update that changes nothing the SMF cares about */
        TK_ASSERT(modify(ref, "{\"upCnxState\":\"SUSPENDED\"}", NULL, 0, NULL, 0, &d) == 400);
        g5c_resp_free(&d);
        TK_ASSERT(modify(ref, "{\"ueLocation\":{\"nrLocation\":{}}}", NULL, 0, NULL, 0, &d) == 200);
        g5c_resp_free(&d);
        TK_ASSERT(modify(ref, "not json", NULL, 0, NULL, 0, &d) == 400);
        g5c_resp_free(&d);
        TK_ASSERT(post_json("/nsmf-pdusession/v1/sm-contexts/00000000-0000-4000-8000-000000000000/modify", "{}", &d) == 404);
        g5c_resp_free(&d);
        TK_ASSERT(post_json("/nsmf-pdusession/v1/sm-contexts/00000000-0000-4000-8000-000000000000/release", "{}", &d) == 404);
        g5c_resp_free(&d);
        /* PCF notifications: malformed, for an unknown context */
        {
            char path[400];
            snprintf(path, sizeof path, "/nsmf-callback/v1/sm-policies/%s/update", ref);
            TK_ASSERT(post_json(path, "{}", &d) == 400);
            g5c_resp_free(&d);
            TK_ASSERT(post_json(path, "{\"smPolicyDecision\":{\"sessRules\":{\"s\":{\"authSessAmbr\":{\"uplink\":\"fast\",\"downlink\":\"1 Mbps\"}}}}}", &d) == 400);
            g5c_resp_free(&d);
            TK_ASSERT(post_json("/nsmf-callback/v1/sm-policies/00000000-0000-4000-8000-000000000000/update", "{\"smPolicyDecision\":{}}", &d) == 404);
            g5c_resp_free(&d);
            TK_ASSERT(post_json("/nsmf-callback/v1/sm-policies/00000000-0000-4000-8000-000000000000/terminate", "{}", &d) == 404);
            g5c_resp_free(&d);
        }
    }
    TK_ASSERT(release(ref) == 204);
    TK_ASSERT(wait_for(all_clear, 3));
    amf_reset();
}

/* UPF outage and restart */
static void test_upf_outage(void)
{
    g5c_resp r;
    char ref[37], stale[37];
    const char *supi = "imsi-001010000000001";
    uint16_t n4 = E.n4p, n3 = E.n3p;
    uint64_t restarts_before = g5c_counter_value(g5c_counter_get(E.nf->metrics, "g5c_smf_upf_restarts_total", "UPF restarts detected through the Recovery Time Stamp.", &(g5c_label){"upf", "upf-1"}, 1));

    amf_reset();
    TK_ASSERT(establish(supi, 3, "internet", 1, 1, ref, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    memcpy(stale, ref, 37);
    stop_upf();
    /* heartbeats (1 s, two misses at 150 ms x 2) notice; until then requests fail on the N4 timeout, afterwards there is no UPF to choose */
    {
        double end = now_s() + 10;
        while (now_s() < end && smf_upf_up(smf_n4_upf(E.s->n4, 0)))
            usleep(50000);
        TK_ASSERT(!smf_upf_up(smf_n4_upf(E.s->n4, 0)));
    }
    TK_ASSERT(establish(supi, 4, "internet", 1, 1, ref, &r) == 500);
    expect_reject(&r, 500, "INSUFFICIENT_RESOURCES", SMF_5GSM_INSUFFICIENT_RESOURCES);
    g5c_resp_free(&r);
    TK_ASSERT(smf_pool_used4(E.s->dnns[0].pool) == 1); /* only the session of the dead UPF holds an address (for now) */
    amf_reset();
    /* the UPF comes back on the same ports, with no state and a new Recovery Time Stamp */
    sleep(1); /* the NTP-based stamp has one-second resolution */
    start_upf(n4, n3);
    TK_ASSERT(smf_n4_wait_up(E.s->n4, 6000));
    TK_ASSERT(g5c_counter_value(g5c_counter_get(E.nf->metrics, "g5c_smf_upf_restarts_total", "UPF restarts detected through the Recovery Time Stamp.", &(g5c_label){"upf", "upf-1"}, 1)) ==
              restarts_before + 1);
    /* the SMF tells the AMF to release what the restarted UPF no longer has, and gives everything back */
    TK_ASSERT(wait_n1n2(1));
    {
        g5c_mp mp;
        g5c_json *j;
        char err[100];
        const g5c_mp_part *p1;
        nas_msg m;
        pthread_mutex_lock(&amf_mu);
        TK_ASSERT(g5c_mp_parse(N1N2[0].ctype, N1N2[0].body, N1N2[0].len, &mp) == 0);
        pthread_mutex_unlock(&amf_mu);
        j = g5c_json_parse((const char *)mp.parts[0].data, mp.parts[0].len, err, sizeof err);
        TK_ASSERT(j && strcmp(g5c_json_get_str(g5c_json_get(g5c_json_get(g5c_json_get(j, "n2InfoContainer"), "smInfo"), "n2InfoContent"), "ngapIeType"), "PDU_RES_REL_CMD") == 0);
        p1 = g5c_mp_find(&mp, g5c_json_get_str(g5c_json_get(g5c_json_get(j, "n1MessageContainer"), "n1MessageContent"), "contentId"));
        TK_ASSERT(p1 && nas_msg_decode(p1->data, p1->len, &m) == NAS_OK && m.def->msg_type == 0xd3 && m.pti == 0);
        nas_msg_free(&m);
        g5c_json_free(j);
        g5c_mp_free(&mp);
    }
    TK_ASSERT(wait_for(all_clear, 5) && smf_pool_used4(E.s->dnns[0].pool) == 0);
    TK_ASSERT(wait_status(1));
    {   /* new sessions work again */
        TK_ASSERT(establish(supi, 5, "internet", 1, 1, ref, &r) == 201);
        g5c_resp_free(&r);
        TK_ASSERT(release(ref) == 204);
        TK_ASSERT(wait_for(all_clear, 3));
    }
    (void)stale;
    amf_reset();
}

static const char *DEC_VOICE_256 =
    "{\"smPolicyDecision\":{\"sessRules\":{\"s\":{\"authSessAmbr\":{\"uplink\":\"50 Mbps\",\"downlink\":\"80 Mbps\"},"
    "\"authDefQos\":{\"5qi\":9,\"arp\":{\"priorityLevel\":8}}}},"
    "\"pccRules\":{\"PccRule-voice\":{\"pccRuleId\":\"PccRule-voice\",\"precedence\":10,\"flowInfos\":[{\"flowDescription\":"
    "\"permit out 17 from 198.51.100.0/24 5060 to assigned\",\"flowDirection\":\"BIDIRECTIONAL\"}],\"refQosData\":[\"QosData-voice\"]}},"
    "\"qosDecs\":{\"QosData-voice\":{\"qosId\":\"QosData-voice\",\"5qi\":1,\"gbrUl\":\"256 Kbps\",\"gbrDl\":\"256 Kbps\"}}}}";
static const char *DEC_VIDEO =
    "{\"smPolicyDecision\":{\"sessRules\":{\"s\":{\"authSessAmbr\":{\"uplink\":\"50 Mbps\",\"downlink\":\"80 Mbps\"},"
    "\"authDefQos\":{\"5qi\":9,\"arp\":{\"priorityLevel\":8}}}},"
    "\"pccRules\":{\"PccRule-video\":{\"pccRuleId\":\"PccRule-video\",\"precedence\":20,\"flowInfos\":[{\"flowDescription\":"
    "\"permit out 17 from 203.0.113.0/24 to assigned\",\"flowDirection\":\"DOWNLINK\"}],\"refQosData\":[\"QosData-video\"]}},"
    "\"qosDecs\":{\"QosData-video\":{\"qosId\":\"QosData-video\",\"5qi\":2,\"gbrUl\":\"1 Mbps\",\"gbrDl\":\"2 Mbps\"}}}}";

/* the i-th N1N2 record as JSON metadata, NAS message and N2 transfer bytes (NULL when absent) */
static void read_record(size_t i, g5c_json **meta, nas_msg *nas, bool *have_nas, g5c_json **n2, const char *n2type, g5c_mp *mp)
{
    char err[160];
    const g5c_mp_part *p1, *p2;
    pthread_mutex_lock(&amf_mu);
    TK_ASSERT(i < n_n1n2 && g5c_mp_parse(N1N2[i].ctype, N1N2[i].body, N1N2[i].len, mp) == 0);
    pthread_mutex_unlock(&amf_mu);
    *meta = g5c_json_parse((const char *)mp->parts[0].data, mp->parts[0].len, err, sizeof err);
    TK_ASSERT(*meta != NULL);
    p1 = g5c_mp_find(mp, g5c_json_get_str(g5c_json_get(g5c_json_get(*meta, "n1MessageContainer"), "n1MessageContent"), "contentId"));
    *have_nas = p1 != NULL && nas_msg_decode(p1->data, p1->len, nas) == NAS_OK;
    p2 = g5c_mp_find(mp, g5c_json_get_str(g5c_json_get(g5c_json_get(g5c_json_get(g5c_json_get(*meta, "n2InfoContainer"), "smInfo"), "n2InfoContent"), "ngapData"), "contentId"));
    *n2 = p2 != NULL ? ngap_decode_as(n2type, p2->data, p2->len, err, sizeof err) : NULL;
}

static void test_policy_update(void)
{
    g5c_resp r, d;
    char ref[37], path[400];
    const char *supi = "imsi-001010000000001";
    uint8_t ue[4], dnip[4] = {93, 184, 216, 34}, buf[200];
    setup_t st;
    uint32_t teid;
    uint8_t qfi;
    size_t plen;
    g5c_json *meta, *n2;
    g5c_mp mp;
    nas_msg nas;
    bool have;
    const uint8_t *v;
    size_t n;

    amf_reset();
    TK_ASSERT(establish(supi, 6, "internet", 1, 1, ref, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    read_transfer(0, &st);
    v = nas_msg_get(&st.accept, "PDU address", &n);
    TK_ASSERT(v && n == 5);
    memcpy(ue, v + 1, 4);
    TK_ASSERT(activate(ref, 0x7101) == 200);
    snprintf(path, sizeof path, "/nsmf-callback/v1/sm-policies/%s/update", ref);

    /* 1: same rule, new guaranteed rate and a new session AMBR: Update QER on the UPF, modification command + modify request to the UE and the gNB */
    TK_ASSERT(post_json(path, DEC_VOICE_256, &d) == 204);
    g5c_resp_free(&d);
    TK_ASSERT(wait_n1n2(2));
    read_record(1, &meta, &nas, &have, &n2, "PDUSessionResourceModifyRequestTransfer", &mp);
    TK_ASSERT(have && nas.def->msg_type == 0xcb && nas.pdu_session_id == 6 && nas.pti == 0);
    v = nas_msg_get(&nas, "Session AMBR", &n);
    TK_ASSERT(v && n == 6 && v[0] == 2 && ((v[1] << 8) | v[2]) == 20000 && v[3] == 1 && ((v[4] << 8) | v[5]) == 50000); /* 80 Mbps as 20000 x 4 kbit/s, 50 Mbps as 50000 x 1 kbit/s */
    TK_ASSERT(nas_msg_get(&nas, "Authorized QoS rules", &n) == NULL);   /* the rule itself did not change */
    v = nas_msg_get(&nas, "Authorized QoS flow descriptions", &n);
    TK_ASSERT(v && v[0] == 2 && v[1] == 0x60); /* QFI 2, operation 011: modify */
    TK_ASSERT(n2 != NULL && n2_ie(n2, NGAP_IE_PDUSessionAggregateMaximumBitRate) != NULL && n2_ie(n2, NGAP_IE_QosFlowAddOrModifyRequestList) != NULL &&
              n2_ie(n2, NGAP_IE_QosFlowToReleaseList) == NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(meta, "n2InfoContainer"), "n2InformationClass"), "SM") == 0 &&
              strcmp(g5c_json_get_str(g5c_json_get(g5c_json_get(g5c_json_get(meta, "n2InfoContainer"), "smInfo"), "n2InfoContent"), "ngapIeType"), "PDU_RES_MOD_REQ") == 0);
    nas_msg_free(&nas);
    g5c_json_free(n2);
    g5c_json_free(meta);
    g5c_mp_free(&mp);
    {   /* the UE and the gNB answer; both are acknowledged */
        nas_msg m;
        g5c_bytes c;
        g5c_bytes_init(&c);
        TK_ASSERT(nas_msg_init(&m, "PDU session modification complete"));
        m.pdu_session_id = 6;
        m.pti = 0;
        TK_ASSERT(nas_msg_encode(&m, &c) == NAS_OK);
        nas_msg_free(&m);
        TK_ASSERT(modify(ref, "{\"n2SmInfoType\":\"PDU_RES_MOD_RSP\"}", NULL, 0, NULL, 0, &d) == 204);
        g5c_resp_free(&d);
        TK_ASSERT(modify(ref, "{\"n1SmMsg\":{\"contentId\":\"n1SmMsg\"}}", c.data, c.len, NULL, 0, &d) == 204);
        g5c_resp_free(&d);
        g5c_bytes_free(&c);
    }
    {   /* the voice rule still rides QFI 2 */
        const uint8_t sip[4] = {198, 51, 100, 9};
        ip4pkt(buf, sip, ue, 17, 5060, 5060, 80);
        dn_send(buf, 80);
        TK_ASSERT(gnb_recv(&teid, &qfi, &plen) && teid == 0x7101 && qfi == 2);
    }

    /* 2: the voice rule goes, a downlink-only video rule with its own QoS data comes */
    TK_ASSERT(post_json(path, DEC_VIDEO, &d) == 204);
    g5c_resp_free(&d);
    TK_ASSERT(wait_n1n2(3));
    read_record(2, &meta, &nas, &have, &n2, "PDUSessionResourceModifyRequestTransfer", &mp);
    TK_ASSERT(have && nas.def->msg_type == 0xcb);
    v = nas_msg_get(&nas, "Authorized QoS rules", &n);
    TK_ASSERT(v != NULL && v[0] == 2 && v[1] == 0 && v[2] == 1 && v[3] == 0x40); /* delete QRI 2, then create the video rule */
    TK_ASSERT(n > 4 && v[4] == 3 && v[7] == 0x21); /* QRI 3: create new QoS rule with one packet filter */
    v = nas_msg_get(&nas, "Authorized QoS flow descriptions", &n);
    TK_ASSERT(v && v[0] == 2 && v[1] == 0x40 && v[2] == 0x00); /* delete QFI 2 (E bit 0, no parameters) ... */
    TK_ASSERT(n > 3 && v[3] == 3 && v[4] == 0x20); /* ... create QFI 3 */
    TK_ASSERT(n2_ie(n2, NGAP_IE_QosFlowToReleaseList) != NULL && n2_ie(n2, NGAP_IE_QosFlowAddOrModifyRequestList) != NULL &&
              n2_ie(n2, NGAP_IE_PDUSessionAggregateMaximumBitRate) == NULL);
    nas_msg_free(&nas);
    g5c_json_free(n2);
    g5c_json_free(meta);
    g5c_mp_free(&mp);
    {
        const uint8_t sip[4] = {198, 51, 100, 9}, vip[4] = {203, 0, 113, 5};
        ip4pkt(buf, sip, ue, 17, 5060, 5060, 80); /* the old voice traffic is plain default-flow traffic now */
        dn_send(buf, 80);
        TK_ASSERT(gnb_recv(&teid, &qfi, &plen) && qfi == 1);
        ip4pkt(buf, vip, ue, 17, 4000, 4000, 80);
        dn_send(buf, 80);
        TK_ASSERT(gnb_recv(&teid, &qfi, &plen) && qfi == 3);
    }
    /* the uplink of the default flow is untouched */
    ip4pkt(buf, ue, dnip, 6, 40000, 443, 60);
    gnb_send_ul(st.ul_teid, 1, buf, 60);
    {
        uint8_t got[200];
        size_t k;
        TK_ASSERT(dn_recv(got, sizeof got, &k) && k == 60);
    }
    /* an update that changes nothing is acknowledged and sends nothing */
    {
        size_t before;
        pthread_mutex_lock(&amf_mu);
        before = n_n1n2;
        pthread_mutex_unlock(&amf_mu);
        TK_ASSERT(post_json(path, DEC_VIDEO, &d) == 204);
        g5c_resp_free(&d);
        usleep(100000);
        pthread_mutex_lock(&amf_mu);
        TK_ASSERT(n_n1n2 == before);
        pthread_mutex_unlock(&amf_mu);
    }

    /* 3: termination by the PCF releases the session through the UE; a complete finishes it */
    snprintf(path, sizeof path, "/nsmf-callback/v1/sm-policies/%s/terminate", ref);
    TK_ASSERT(post_json(path, "{\"resourceUri\":\"x\",\"cause\":\"PDU_SESSION_TERMINATION\"}", &d) == 204);
    g5c_resp_free(&d);
    TK_ASSERT(wait_n1n2(4));
    read_record(3, &meta, &nas, &have, &n2, "PDUSessionResourceReleaseCommandTransfer", &mp);
    TK_ASSERT(have && nas.def->msg_type == 0xd3 && n2 != NULL);
    nas_msg_free(&nas);
    g5c_json_free(n2);
    g5c_json_free(meta);
    g5c_mp_free(&mp);
    {
        nas_msg m;
        g5c_bytes c;
        g5c_bytes_init(&c);
        TK_ASSERT(nas_msg_init(&m, "PDU session release complete"));
        m.pdu_session_id = 6;
        m.pti = 0;
        TK_ASSERT(nas_msg_encode(&m, &c) == NAS_OK);
        nas_msg_free(&m);
        TK_ASSERT(modify(ref, "{\"n1SmMsg\":{\"contentId\":\"n1SmMsg\"}}", c.data, c.len, NULL, 0, &d) == 204);
        g5c_resp_free(&d);
        g5c_bytes_free(&c);
    }
    TK_ASSERT(wait_for(all_clear, 3));
    setup_free(&st);

    /* ... and when the UE never confirms, the guard timer removes the session */
    amf_reset();
    TK_ASSERT(establish(supi, 7, "internet", 1, 1, ref, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    snprintf(path, sizeof path, "/nsmf-callback/v1/sm-policies/%s/terminate", ref);
    TK_ASSERT(post_json(path, "{}", &d) == 204);
    g5c_resp_free(&d);
    TK_ASSERT(smf_session_count(E.s) == 1);
    TK_ASSERT(wait_for(all_clear, 4));
    amf_reset();
}

/* A-03: the PCF sets a volume threshold, the UPF reports when it is passed, the SMF tells the PCF, the PCF throttles the session and the SMF applies it (UPF, UE and gNB are told) */
static void test_usage_monitoring(void)
{
    g5c_resp r;
    char ref[37];
    const char *supi = "imsi-001010000000001";
    uint8_t ue[4], dnip[4] = {93, 184, 216, 34}, pkt[1200];
    setup_t st;
    const uint8_t *v;
    size_t n;
    char *m;
    g5c_json *meta, *n2;
    g5c_mp mp;
    nas_msg nas;
    bool have;

    amf_reset();
    E.p.cfg.um_volume = 6000;
    E.p.cfg.um_throttle.uplink = g5c_xstrdup("256 Kbps");
    E.p.cfg.um_throttle.downlink = g5c_xstrdup("256 Kbps");
    TK_ASSERT(establish(supi, 8, "internet", 1, 1, ref, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    read_transfer(0, &st);
    v = nas_msg_get(&st.accept, "PDU address", &n);
    TK_ASSERT(v && n == 5);
    memcpy(ue, v + 1, 4);
    TK_ASSERT(activate(ref, 0x7301) == 200);

    /* below the threshold (3 x 1200 octets): nothing happens */
    for (int i = 0; i < 3; i++) {
        uint8_t got[1500];
        size_t k;
        ip4pkt(pkt, ue, dnip, 17, 5000, 53, sizeof pkt);
        gnb_send_ul(st.ul_teid, 1, pkt, sizeof pkt);
        TK_ASSERT(dn_recv(got, sizeof got, &k) && k == sizeof pkt);
    }
    usleep(300000);
    {
        size_t seen;
        pthread_mutex_lock(&amf_mu);
        seen = n_n1n2;
        pthread_mutex_unlock(&amf_mu);
        TK_ASSERT(seen == 1);
    }
    /* past it (6 x 1200): the UPF reports, the PCF throttles, the UE and the gNB get the new session AMBR */
    for (int i = 0; i < 3; i++) {
        uint8_t got[1500];
        size_t k;
        ip4pkt(pkt, ue, dnip, 17, 5000, 53, sizeof pkt);
        gnb_send_ul(st.ul_teid, 1, pkt, sizeof pkt);
        TK_ASSERT(dn_recv(got, sizeof got, &k) && k == sizeof pkt);
    }
    TK_ASSERT(wait_n1n2(2));
    read_record(1, &meta, &nas, &have, &n2, "PDUSessionResourceModifyRequestTransfer", &mp);
    TK_ASSERT(have && nas.def->msg_type == 0xcb && nas.pdu_session_id == 8);
    v = nas_msg_get(&nas, "Session AMBR", &n);
    TK_ASSERT(v && n == 6 && v[0] == 1 && ((v[1] << 8) | v[2]) == 256 && v[3] == 1 && ((v[4] << 8) | v[5]) == 256); /* 256 kbit/s each way */
    TK_ASSERT(n2 != NULL && n2_ie(n2, NGAP_IE_PDUSessionAggregateMaximumBitRate) != NULL);
    nas_msg_free(&nas);
    g5c_json_free(n2);
    g5c_json_free(meta);
    g5c_mp_free(&mp);
    m = g5c_registry_render(E.m); /* the PCF's registry */
    TK_ASSERT(strstr(m, "g5c_pcf_usage_throttled_total 1") != NULL && strstr(m, "g5c_pcf_usage_reports_total 1") != NULL);
    free(m);
    m = g5c_registry_render(E.nf->metrics); /* the SMF's */
    TK_ASSERT(strstr(m, "g5c_smf_usage_reports_total{result=\"received\"} 1") != NULL && strstr(m, "g5c_smf_usage_reports_total{result=\"applied\"} 1") != NULL);
    free(m);
    setup_free(&st);
    TK_ASSERT(release(ref) == 204);
    TK_ASSERT(wait_for(all_clear, 3));
    free(E.p.cfg.um_throttle.uplink);
    free(E.p.cfg.um_throttle.downlink);
    E.p.cfg.um_throttle.uplink = E.p.cfg.um_throttle.downlink = NULL;
    E.p.cfg.um_volume = 0;
    amf_reset();
}

/* sessions survive an SMF restart; if their UPF restarted in the meantime they are released instead */
static void test_persistence(void)
{
    g5c_resp r, d;
    char ref[37];
    const char *supi = "imsi-001010000000001";
    uint16_t n4 = E.n4p, n3 = E.n3p;

    amf_reset();
    TK_ASSERT(establish(supi, 8, "internet", 1, 1, ref, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    TK_ASSERT(activate(ref, 0x7201) == 200);
    stop_smf();
    start_smf();
    TK_ASSERT(smf_session_count(E.s) == 1 && smf_pool_used4(E.s->dnns[0].pool) == 1 && upf_has(1));
    {   /* the restored context is fully usable: deactivate, release, everything is returned */
        TK_ASSERT(modify(ref, "{\"upCnxState\":\"DEACTIVATED\"}", NULL, 0, NULL, 0, &d) == 200);
        g5c_resp_free(&d);
        TK_ASSERT(release(ref) == 204);
        TK_ASSERT(wait_for(all_clear, 3) && smf_pool_used4(E.s->dnns[0].pool) == 0);
        TK_ASSERT(g5c_udr_map_get(E.store, supi, UDR_SMF_REGS, "8") == NULL);
    }

    /* a session, then the SMF stops and the UPF restarts while it is away */
    amf_reset();
    TK_ASSERT(establish(supi, 9, "internet", 1, 1, ref, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    stop_smf();
    stop_upf();
    sleep(1);
    start_upf(n4, n3);
    amf_reset();
    start_smf();
    TK_ASSERT(wait_n1n2(1));
    TK_ASSERT(wait_for(all_clear, 5) && smf_pool_used4(E.s->dnns[0].pool) == 0);
    amf_reset();
}

/* the AMF is found through the NRF; an AMF the NRF does not know is reached at the host of its status URI */
static void test_discovery(void)
{
    g5c_resp r;
    char ref[37];
    char *js;
    g5c_bytes n1;
    const char *supi = "imsi-001010000000001";
    int hits;

    amf_reset();
    hits = atomic_load(&nrf_hits);
    TK_ASSERT(establish(supi, 10, "internet", 1, 1, ref, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    TK_ASSERT(atomic_load(&nrf_hits) > hits || hits > 0); /* the answer is cached for a minute */
    TK_ASSERT(release(ref) == 204);
    TK_ASSERT(wait_for(all_clear, 3));

    amf_reset();
    hits = atomic_load(&nrf_hits);
    js = create_json(supi, 11, "internet", 1, ",\"servingNfId\":\"00000000-0000-4000-8000-0000000000aa\"");
    g5c_bytes_init(&n1);
    build_est_req(&n1, 11, 7, 1);
    TK_ASSERT(post_parts("/nsmf-pdusession/v1/sm-contexts", js, n1.data, n1.len, NULL, 0, &r) == 201);
    ref_of(&r, ref);
    g5c_resp_free(&r);
    TK_ASSERT(atomic_load(&nrf_hits) > hits);
    TK_ASSERT(wait_n1n2(1)); /* the fallback to the status URI delivered it */
    g5c_bytes_free(&n1);
    free(js);
    TK_ASSERT(release(ref) == 204);
    TK_ASSERT(wait_for(all_clear, 3));
    amf_reset();
}

/* an IPv6 session: the UE's router solicitation is forwarded by the UPF to the SMF, which answers with the session's /64 through the UPF */
static void test_router_solicitation(void)
{
    g5c_resp r;
    char ref[37];
    setup_t st;
    const uint8_t *v;
    size_t n;
    uint8_t pkt[48];
    static const uint8_t ll[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7};
    static const uint8_t all_routers[16] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    uint32_t sum = 0, teid;
    uint8_t qfi;
    size_t plen;
    amf_reset();
    TK_ASSERT(establish("imsi-001010000000002", 12, "internet", 1, 3, ref, &r) == 201);
    g5c_resp_free(&r);
    TK_ASSERT(wait_n1n2(1));
    read_transfer(0, &st);
    v = nas_msg_get(&st.accept, "PDU address", &n);
    TK_ASSERT(v && n == 13 && v[0] == 3);
    memset(pkt, 0, sizeof pkt);
    pkt[0] = 0x60;
    pkt[5] = 8;
    pkt[6] = 58;
    pkt[7] = 255;
    memcpy(pkt + 8, ll, 16);
    memcpy(pkt + 24, all_routers, 16);
    pkt[40] = 133;
    for (size_t i = 0; i < 16; i += 2)
        sum += (uint32_t)(ll[i] << 8 | ll[i + 1]) + (uint32_t)(all_routers[i] << 8 | all_routers[i + 1]);
    sum += 8 + 58 + 133u * 256u;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    pkt[42] = (uint8_t)(~sum >> 8);
    pkt[43] = (uint8_t)~sum;
    TK_ASSERT(activate(ref, 0x7301) == 200);
    gnb_send_ul(st.ul_teid, 1, pkt, sizeof pkt);
    {   /* the advertisement reaches the gNB tunnel: IPv6, ICMPv6 type 134, the session's prefix (the pool's first /64) */
        uint8_t buf[300];
        ssize_t k = recv(E.gnb, buf, sizeof buf, 0);
        gtpu_header gh;
        const uint8_t *pl;
        size_t pln;
        TK_ASSERT(k > 0 && gtpu_decode(buf, (size_t)k, &gh, &pl, &pln) == 0 && gh.teid == 0x7301);
        TK_ASSERT(pln >= 88 && (pl[0] >> 4) == 6 && pl[6] == 58 && pl[40] == 134);
        TK_ASSERT(pl[56] == 3 && pl[58] == 64 && pl[72] == 0x20 && pl[73] == 0x01 && pl[74] == 0x0d && pl[75] == 0xb8 && pl[76] == 0x00 && pl[77] == 0x45);
        TK_ASSERT(memcmp(pl + 24, ll, 16) == 0);
    }
    (void)teid;
    (void)qfi;
    (void)plen;
    setup_free(&st);
    TK_ASSERT(release(ref) == 204);
    TK_ASSERT(wait_for(all_clear, 3));
    amf_reset();
}

static atomic_int conc_fail;

static void *conc_worker(void *arg)
{
    int t = (int)(intptr_t)arg;
    for (int cycle = 0; cycle < 4; cycle++) {
        g5c_resp r;
        char ref[37];
        g5c_resp d;
        int psi = 1 + t;
        g5c_bytes n2;
        int qf[1] = {1};
        if (establish("imsi-001010000000003", psi, "ims", 1, 1, ref, &r) != 201) {
            atomic_fetch_add(&conc_fail, 1);
            g5c_resp_free(&r);
            continue;
        }
        g5c_resp_free(&r);
        g5c_bytes_init(&n2);
        gnb_response(&n2, 0x100u + (uint32_t)t, E.gnb_ip4, 1, qf);
        if (modify(ref, "{\"n2SmInfo\":{\"contentId\":\"n2SmInfo\"},\"n2SmInfoType\":\"PDU_RES_SETUP_RSP\"}", NULL, 0, n2.data, n2.len, &d) != 200)
            atomic_fetch_add(&conc_fail, 1);
        g5c_resp_free(&d);
        g5c_bytes_free(&n2);
        if (modify(ref, "{\"upCnxState\":\"DEACTIVATED\"}", NULL, 0, NULL, 0, &d) != 200)
            atomic_fetch_add(&conc_fail, 1);
        g5c_resp_free(&d);
        if (release(ref) != 204)
            atomic_fetch_add(&conc_fail, 1);
    }
    return NULL;
}

static void test_concurrency(void)
{
    pthread_t th[8];
    provision("{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{\"ims\":{\"session_types\":[\"IPV4\"]}}}");
    for (intptr_t i = 0; i < 8; i++)
        TK_ASSERT(pthread_create(&th[i], NULL, conc_worker, (void *)i) == 0);
    for (int i = 0; i < 8; i++)
        pthread_join(th[i], NULL);
    TK_ASSERT(atomic_load(&conc_fail) == 0);
    smf_drain(E.s);
    TK_ASSERT(wait_for(all_clear, 5));
    TK_ASSERT(smf_pool_used4(E.s->dnns[1].pool) == 0);
    TK_ASSERT(E.s->created >= 32 && E.s->released >= 32);
    amf_reset();
}

static void test_metrics(void)
{
    char *txt = g5c_registry_render(E.nf->metrics);
    TK_ASSERT(strstr(txt, "g5c_smf_sm_context_requests_total{op=\"create\",result=\"ok\"}") != NULL);
    TK_ASSERT(strstr(txt, "g5c_smf_create_sm_context_seconds_count") != NULL);
    TK_ASSERT(strstr(txt, "g5c_smf_pdu_sessions_active 0") != NULL);
    TK_ASSERT(strstr(txt, "g5c_smf_ue_addresses_in_use{dnn=\"internet\"} 0") != NULL);
    free(txt);
}

int main(void)
{
    g5c_log_init("error", false);
    setup();
    test_happy_path();
    test_release_and_replace();
    test_rejections();
    test_failures();
    test_policy_update();
    test_usage_monitoring();
    test_discovery();
    test_router_solicitation();
    test_concurrency();
    test_upf_outage();
    test_metrics();
    test_persistence();
    teardown();
    printf("smf e2e: OK\n");
    return 0;
}
