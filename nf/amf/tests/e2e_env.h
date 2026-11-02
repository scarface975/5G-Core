/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The AMF against the rest of the core in one process */
#ifndef G5C_AMF_E2E_ENV_H
#define G5C_AMF_E2E_ENV_H
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include "../src/sctp_abi.h"
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "g5c/amf.h"
#include "g5c/ausf.h"
#include "g5c/eapaka.h"
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

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ---- environment ---- */

static struct {
    g5c_registry *m;
    g5c_udr_store *store;
    g5c_router *udr_r, *udm_r, *pcf_r, *ausf_r, *smf_r, *amf_r, *cb_r;
    g5c_server *udr_s, *udm_s, *pcf_s, *ausf_s, *smf_s, *amf_s, *cb_s;
    g5c_client *cl;
    udm_keys keys;
    udm u;
    pcf p;
    ausf *au;
    upf_rt *rt;
    pthread_t upf_th;
    int dn, n6_peer;
    int gnb_udp[2];
    char gnb_ip[2][32];
    uint8_t gnb_ip4[2][4];
    smf *s;
    g5c_nf *smf_nf, *amf_nf;
    amf *a;
    char smf_base[64], udm_base[64], pcf_base[64], ausf_base[64], amf_base[64], cb_base[64];
    uint16_t n3p, n4p;
    char smf_n4_ip[32];
    char smf_state[200], amf_state[200];
    char snn[64];
} E;

static void *upf_runner(void *a)
{
    upf_rt_run(a);
    return NULL;
}

/* events delivered to the scripted subscriber (Namf_EventExposure notifications) */
static pthread_mutex_t cb_mu = PTHREAD_MUTEX_INITIALIZER;
static char cb_last[8][1500];
static size_t cb_n;
static atomic_int cb_failure_notifs;

static void cb_event(void *c, const g5c_req *q, g5c_resp *r)
{
    (void)c;
    pthread_mutex_lock(&cb_mu);
    if (cb_n < 8) {
        size_t n = q->body_len < sizeof cb_last[0] - 1 ? q->body_len : sizeof cb_last[0] - 1;
        memcpy(cb_last[cb_n], q->body, n);
        cb_last[cb_n][n] = 0;
        cb_n++;
    }
    pthread_mutex_unlock(&cb_mu);
    g5c_resp_status(r, 204);
}

static void cb_n1n2_failure(void *c, const g5c_req *q, g5c_resp *r)
{
    (void)c;
    (void)q;
    atomic_fetch_add(&cb_failure_notifs, 1);
    g5c_resp_status(r, 204);
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

static void start_upf(void)
{
    upf_rt_config rc;
    char err[200];
    upf_rt_config_defaults(&rc);
    rc.n6_fd = E.n6_peer;
    rc.engine.n4_addr = (upf_addr){false, {127, 0, 0, 1}, 0};
    rc.engine.n3_addr = (upf_addr){false, {127, 0, 0, 1}, 0};
    rc.engine.heartbeat_interval = 0;
    E.rt = upf_rt_new(&rc, E.m, err, sizeof err);
    if (E.rt == NULL)
        TK_FAIL("UPF runtime: %s", err);
    E.n4p = upf_rt_pfcp_port(E.rt);
    E.n3p = upf_rt_gtpu_port(E.rt);
    TK_ASSERT(pthread_create(&E.upf_th, NULL, upf_runner, E.rt) == 0);
}

/* knobs the load driver changes before setup(): the size of the "internet" address pool and whether the SMF and AMF persist their state */
static const char *g_inet_pool = "10.45.0.0/28";
static bool g_persist = true;
static const char *g_amf_extra = NULL; /* extra lines for the amf: block (two-space indent) */

static void start_smf(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[300], yaml[3200];
    g5c_json *j;
    g5c_common common;
    char sf[256] = "";
    if (g_persist)
        snprintf(sf, sizeof sf, "  state_file: '%s'\n", E.smf_state);
    snprintf(yaml, sizeof yaml,
             "name: smf-e2e\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\n"
             "smf:\n  udm: { uri: '%s' }\n  pcf: { uri: '%s' }\n  n1n2_delay_ms: 5\n  release_guard_ms: 500\n%s"
             "  n4: { address: %s, port: 8805, t1_ms: 150, n1: 2, heartbeat: { interval: 1, failures: 2 } }\n"
             "  upfs:\n    - { name: upf-1, address: 127.0.0.1, port: %u }\n"
             "  dnns:\n    - { name: internet, ipv4_pool: %s, dns: [8.8.8.8] }\n    - { name: ims, ipv4_pool: 10.46.0.0/24 }\n",
             E.udm_base, E.pcf_base, sf, E.smf_n4_ip, E.n4p, g_inet_pool);
    j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    TK_ASSERT(j != NULL && g5c_common_parse(j, &common, err, sizeof err) == 0);
    common.port = 0;
    E.smf_nf = g5c_nf_new(&common, err, sizeof err);
    TK_ASSERT(E.smf_nf != NULL);
    E.s = smf_from_config(j, E.smf_nf, err, sizeof err);
    if (E.s == NULL)
        TK_FAIL("SMF config: %s", err);
    g5c_json_free(j);
    TK_ASSERT(smf_start(E.s, err, sizeof err) == 0);
    E.smf_r = smf_router(E.s);
    E.smf_s = g5c_server_start(&cfg, E.smf_r, err, sizeof err);
    TK_ASSERT(E.smf_s != NULL);
    snprintf(E.smf_base, sizeof E.smf_base, "http://127.0.0.1:%u", g5c_server_port(E.smf_s));
    smf_set_self_uri(E.s, E.smf_base);
    TK_ASSERT(smf_n4_wait_up(E.s->n4, 4000));
}

static unsigned g_t3512 = 3600;

static void start_amf(const char *extra)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[300], yaml[3600];
    g5c_json *j;
    g5c_common common;
    char af[256] = "";
    if (g_persist)
        snprintf(af, sizeof af, "  state_file: '%s'\n", E.amf_state);
    snprintf(yaml, sizeof yaml,
             "name: amf-e2e\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\n"
             "amf:\n  guami: { region: 2, set: 1, pointer: 0 }\n  ngap: { address: 127.0.0.1, port: 0 }\n  tais: [ { tac: 1 }, { tac: 2 } ]\n"
             "  slices: [ { sst: 1 }, { sst: 2, sd: '000002' } ]\n  ausf: { uri: '%s' }\n  udm: { uri: '%s' }\n  pcf: { uri: '%s' }\n  smf: { uri: '%s' }\n"
             "%s  workers: 6\n  paging_tries: 2\n  reachable_grace: 1\n"
             "  timers: { t3512: %u, t3513: 1, t3550: 1, t3555: 1, t3560: 1, t3570: 1, t3522: 1 }\n%s",
             E.ausf_base, E.udm_base, E.pcf_base, E.smf_base, af, g_t3512, extra != NULL ? extra : "");
    j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    TK_ASSERT(j != NULL && g5c_common_parse(j, &common, err, sizeof err) == 0);
    common.port = 0;
    E.amf_nf = g5c_nf_new(&common, err, sizeof err);
    TK_ASSERT(E.amf_nf != NULL);
    E.a = amf_from_config(j, E.amf_nf, err, sizeof err);
    if (E.a == NULL)
        TK_FAIL("AMF config: %s", err);
    g5c_json_free(j);
    E.amf_r = amf_router(E.a);
    E.amf_s = g5c_server_start(&cfg, E.amf_r, err, sizeof err);
    TK_ASSERT(E.amf_s != NULL);
    snprintf(E.amf_base, sizeof E.amf_base, "http://127.0.0.1:%u", g5c_server_port(E.amf_s));
    amf_set_self_uri(E.a, E.amf_base);
    if (amf_start(E.a, err, sizeof err) != 0)
        TK_FAIL("AMF start: %s", err);
}

static void stop_amf(void)
{
    g5c_server_stop(E.amf_s);
    amf_destroy(E.a);
    g5c_nf_free(E.amf_nf);
    g5c_router_free(E.amf_r);
    E.a = NULL;
}

static void bind_gnb_udp(int i, const char *ip)
{
    struct sockaddr_in sa;
    struct timeval tv = {0, 300000};
    int one = 1;
    E.gnb_udp[i] = socket(AF_INET, SOCK_DGRAM, 0);
    (void)setsockopt(E.gnb_udp[i], SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    (void)setsockopt(E.gnb_udp[i], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(2152);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    TK_ASSERT(bind(E.gnb_udp[i], (struct sockaddr *)&sa, sizeof sa) == 0);
    snprintf(E.gnb_ip[i], sizeof E.gnb_ip[i], "%s", ip);
    inet_pton(AF_INET, ip, E.gnb_ip4[i]);
}

static void setup(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[300], udr_url[64], master[32];
    g5c_json *py;
    pcf_policy pol;
    int sv[2];
    unsigned pid = (unsigned)getpid() % 250;
    char ip[32];

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
        static const char y[] = "default:\n  session_ambr: { uplink: 100 Mbps, downlink: 200 Mbps }\n";
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

    E.au = ausf_new(E.cl, E.udm_base, NULL, "", "ausf-e2e", E.m, NULL);
    E.ausf_r = ausf_router(E.au);
    E.ausf_s = g5c_server_start(&cfg, E.ausf_r, err, sizeof err);
    TK_ASSERT(E.ausf_s != NULL);
    snprintf(E.ausf_base, sizeof E.ausf_base, "http://127.0.0.1:%u", g5c_server_port(E.ausf_s));

    E.cb_r = g5c_router_new();
    g5c_router_route(E.cb_r, "POST", "/events", cb_event, NULL);
    g5c_router_route(E.cb_r, "POST", "/n1n2-failure", cb_n1n2_failure, NULL);
    E.cb_s = g5c_server_start(&cfg, E.cb_r, err, sizeof err);
    TK_ASSERT(E.cb_s != NULL);
    snprintf(E.cb_base, sizeof E.cb_base, "http://127.0.0.1:%u", g5c_server_port(E.cb_s));

    TK_ASSERT(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    E.n6_peer = sv[0];
    E.dn = sv[1];
    {
        struct timeval tv = {0, 300000};
        (void)setsockopt(E.dn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    start_upf();
    snprintf(E.smf_n4_ip, sizeof E.smf_n4_ip, "127.99.%u.4", pid);
    snprintf(ip, sizeof ip, "127.88.%u.1", pid);
    bind_gnb_udp(0, ip);
    snprintf(ip, sizeof ip, "127.89.%u.1", pid);
    bind_gnb_udp(1, ip);
    snprintf(E.smf_state, sizeof E.smf_state, "/tmp/g5c-amf-e2e-smf-%u.json", (unsigned)getpid());
    snprintf(E.amf_state, sizeof E.amf_state, "/tmp/g5c-amf-e2e-amf-%u.json", (unsigned)getpid());
    (void)unlink(E.smf_state);
    (void)unlink(E.amf_state);
    start_smf();
    start_amf(g_amf_extra);
    TK_ASSERT(g5c_serving_network_name("001", "01", E.snn, sizeof E.snn) > 0);
}

static void teardown(void)
{
    stop_amf();
    smf_drain(E.s);
    g5c_server_stop(E.smf_s);
    smf_destroy(E.s);
    free(E.s);
    g5c_nf_free(E.smf_nf);
    g5c_router_free(E.smf_r);
    (void)unlink(E.smf_state);
    (void)unlink(E.amf_state);
    upf_rt_stop(E.rt);
    pthread_join(E.upf_th, NULL);
    upf_rt_free(E.rt);
    g5c_server_stop(E.cb_s);
    g5c_server_stop(E.ausf_s);
    g5c_server_stop(E.pcf_s);
    g5c_server_stop(E.udm_s);
    g5c_server_stop(E.udr_s);
    g5c_client_free(E.cl);
    g5c_router_free(E.cb_r);
    g5c_router_free(E.ausf_r);
    g5c_router_free(E.pcf_r);
    g5c_router_free(E.udm_r);
    g5c_router_free(E.udr_r);
    ausf_free(E.au);
    pcf_destroy(&E.p);
    udm_destroy(&E.u);
    g5c_udr_store_free(E.store);
    g5c_registry_free(E.m);
    close(E.gnb_udp[0]);
    close(E.gnb_udp[1]);
    close(E.dn);
}

/* ---- the scripted gNB (N2 over SCTP) ---- */

typedef struct {
    int fd;
    int idx; /* which UDP / N3 identity */
} gnb_t;

/* the load driver in remote mode points the scripted gNBs at an AMF in another process */
static uint16_t g_ngap_port_override;
static const char *g_ngap_ip = "127.0.0.1";

static void gnb_open(gnb_t *g, int idx)
{
    struct sockaddr_in sa;
    int one = 1;
    memset(g, 0, sizeof *g);
    g->idx = idx;
    g->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    TK_ASSERT(g->fd >= 0);
    (void)setsockopt(g->fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &one, sizeof one);
    (void)setsockopt(g->fd, IPPROTO_SCTP, SCTP_NODELAY, &one, sizeof one); /* as a gNB does: no Nagle wait for a delayed SACK */
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(g_ngap_port_override != 0 ? g_ngap_port_override : amf_ngap_port(E.a));
    inet_pton(AF_INET, g_ngap_ip, &sa.sin_addr);
    if (connect(g->fd, (struct sockaddr *)&sa, sizeof sa) != 0)
        TK_FAIL("a gNB cannot connect to the AMF (%s)", strerror(errno));
}

static void gnb_close(gnb_t *g)
{
    if (g->fd >= 0)
        close(g->fd);
    g->fd = -1;
}

static void gnb_tx_raw(gnb_t *g, const uint8_t *b, size_t n, uint16_t stream)
{
    struct msghdr mh;
    struct iovec iov = {(void *)(uintptr_t)b, n};
    char cbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo))];
    struct cmsghdr *cm;
    struct sctp_sndinfo si;
    memset(&mh, 0, sizeof mh);
    memset(cbuf, 0, sizeof cbuf);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cbuf;
    mh.msg_controllen = sizeof cbuf;
    cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = IPPROTO_SCTP;
    cm->cmsg_type = SCTP_SNDINFO;
    cm->cmsg_len = CMSG_LEN(sizeof si);
    memset(&si, 0, sizeof si);
    si.snd_sid = stream;
    si.snd_ppid = htonl(60);
    memcpy(CMSG_DATA(cm), &si, sizeof si);
    TK_ASSERT(sendmsg(g->fd, &mh, MSG_NOSIGNAL) == (ssize_t)n);
}

static void gnb_tx(gnb_t *g, g5c_json *pdu, uint16_t stream)
{
    g5c_bytes b;
    char err[160];
    g5c_bytes_init(&b);
    if (ngap_encode(pdu, &b, err, sizeof err) != 0)
        TK_FAIL("encoding an NGAP PDU: %s", err);
    gnb_tx_raw(g, b.data, b.len, stream);
    g5c_bytes_free(&b);
    g5c_json_free(pdu);
}

/* one PDU from the AMF or NULL after the timeout / on close */
static g5c_json *gnb_rx(gnb_t *g, int timeout_ms)
{
    struct pollfd p = {g->fd, POLLIN, 0};
    uint8_t buf[65536];
    char err[160];
    ssize_t n;
    g5c_json *j;
    if (poll(&p, 1, timeout_ms) <= 0)
        return NULL;
    n = recv(g->fd, buf, sizeof buf, 0);
    if (n <= 0)
        return NULL;
    j = ngap_decode(buf, (size_t)n, err, sizeof err);
    if (j == NULL)
        TK_FAIL("the AMF sent an undecodable NGAP PDU: %s", err);
    return j;
}

static g5c_json *new_pdu(const char *kind, int proc, const char *crit)
{
    g5c_json *root = g5c_json_new_obj(), *m = g5c_json_set(root, kind, g5c_json_new_obj()), *v;
    g5c_json_set_int(m, "procedureCode", proc);
    g5c_json_set_str(m, "criticality", crit);
    v = g5c_json_set(m, "value", g5c_json_new_obj());
    g5c_json_set(v, "protocolIEs", g5c_json_new_arr());
    return root;
}

static g5c_json *add_ie(g5c_json *pdu, int id, const char *crit, g5c_json *value)
{
    g5c_json *m = g5c_json_get_mut(pdu, g5c_json_key_at(pdu, 0)), *v = g5c_json_get_mut(m, "value"), *ies = g5c_json_get_mut(v, "protocolIEs");
    g5c_json *e = g5c_json_push(ies, g5c_json_new_obj());
    g5c_json_set_int(e, "id", id);
    g5c_json_set_str(e, "criticality", crit);
    g5c_json_set(e, "value", value);
    return e;
}

static const g5c_json *ie_of(const g5c_json *pdu, int id)
{
    return ngap_find_ie(ngap_pdu_message(pdu), id);
}

static int64_t proc_of(const g5c_json *pdu)
{
    int64_t c = -1;
    (void)ngap_procedure_code(pdu, &c);
    return c;
}

static bool is_kind(const g5c_json *pdu, const char *k)
{
    const char *kk = ngap_pdu_kind(pdu);
    return kk != NULL && strcmp(kk, k) == 0;
}

static g5c_json *bits_json(const uint8_t *p, size_t nbits)
{
    g5c_json *o = g5c_json_new_obj();
    char *h = g5c_hex_encode(p, (nbits + 7) / 8);
    g5c_json_set_int(o, "len", (int64_t)nbits);
    g5c_json_set_str(o, "hex", h);
    free(h);
    return o;
}

static g5c_json *ng_cause_json(const char *group, const char *value)
{
    g5c_json *c = g5c_json_new_obj();
    g5c_json_set_str(c, group, value);
    return c;
}

static g5c_json *hex_str(const uint8_t *p, size_t n)
{
    char *h = g5c_hex_encode(p, n);
    g5c_json *j = g5c_json_new_str(h);
    free(h);
    return j;
}

/* NG Setup: returns the AMF's answer (caller frees). tac / plmn selectable. */
static g5c_json *gnb_ng_setup(gnb_t *g, uint32_t gnb_id, uint32_t tac, const char *plmn_hex, const char *name)
{
    g5c_json *p = new_pdu("initiatingMessage", NGAP_PROC_NGSetup, "reject"), *ta, *gn, *b, *pl;
    uint8_t id[4] = {(uint8_t)(gnb_id >> 24), (uint8_t)(gnb_id >> 16), (uint8_t)(gnb_id >> 8), (uint8_t)gnb_id}, t[3] = {(uint8_t)(tac >> 16), (uint8_t)(tac >> 8), (uint8_t)tac};
    gn = g5c_json_new_obj();
    b = g5c_json_set(g5c_json_set(gn, "globalGNB-ID", g5c_json_new_obj()), "gNB-ID", g5c_json_new_obj());
    g5c_json_set_str(g5c_json_get_mut(gn, "globalGNB-ID"), "pLMNIdentity", plmn_hex);
    g5c_json_set(b, "gNB-ID", bits_json(id, 32));
    add_ie(p, NGAP_IE_GlobalRANNodeID, "reject", gn);
    add_ie(p, NGAP_IE_RANNodeName, "ignore", g5c_json_new_str(name));
    ta = g5c_json_new_arr();
    {
        g5c_json *it = g5c_json_push(ta, g5c_json_new_obj()), *bl = g5c_json_set(it, "broadcastPLMNList", g5c_json_new_arr());
        char *h = g5c_hex_encode(t, 3);
        g5c_json_set_str(it, "tAC", h);
        free(h);
        pl = g5c_json_push(bl, g5c_json_new_obj());
        g5c_json_set_str(pl, "pLMNIdentity", plmn_hex);
        g5c_json_set_str(g5c_json_set(g5c_json_push(g5c_json_set(pl, "tAISliceSupportList", g5c_json_new_arr()), g5c_json_new_obj()), "s-NSSAI", g5c_json_new_obj()), "sST",
                         "01");
    }
    add_ie(p, NGAP_IE_SupportedTAList, "reject", ta);
    add_ie(p, NGAP_IE_DefaultPagingDRX, "ignore", g5c_json_new_str("v128"));
    gnb_tx(g, p, 0);
    return gnb_rx(g, 3000);
}

static void gnb_setup_ok(gnb_t *g, int idx, uint32_t gnb_id, uint32_t tac)
{
    g5c_json *r;
    gnb_open(g, idx);
    r = gnb_ng_setup(g, gnb_id, tac, "00f110", "gnb-test");
    TK_ASSERT(r != NULL && is_kind(r, "successfulOutcome") && proc_of(r) == NGAP_PROC_NGSetup);
    g5c_json_free(r);
}

/* ---- the scripted UE ---- */

typedef struct {
    char supi[24];  /* "imsi-..." */
    char msin[16];
    uint8_t k[16], op[16], opc[16];
    uint8_t cap[4]; /* UE security capability value: EA, IA, EEA, EIA */
    bool have_ctx;
    uint8_t ngksi;
    uint8_t kamf[32];
    uint8_t abba[2];
    nas_sec_ctx sec;
    uint8_t int_alg, enc_alg;
    uint32_t ul_count, dl_count; /* next uplink count to use / next downlink count expected */
    uint32_t tmsi;
    bool have_guti;
    uint32_t last_ul; /* the count of the last uplink message (for KgNB) */
    uint32_t smc_ul;  /* the count of the security mode complete */
    uint64_t amf_id;
    uint32_t ran_id;
    uint8_t kgnb[32];
    uint8_t reg_req[512];
    size_t reg_len;
    uint16_t psi_status;
    bool flip_res; /* answer the authentication with a wrong RES* */
    bool report_mac_failure;
    bool report_sync_failure;
} ue_t;

static void ue_init(ue_t *u, const char *imsi, uint32_t ran_id)
{
    memset(u, 0, sizeof *u);
    snprintf(u->supi, sizeof u->supi, "imsi-%s", imsi);
    snprintf(u->msin, sizeof u->msin, "%s", imsi + 5); /* MCC 001 MNC 01 */
    TK_ASSERT(tk_unhex(K_HEX, u->k, 16) == 16 && tk_unhex(OP_HEX, u->op, 16) == 16);
    TK_ASSERT(g5c_milenage_derive_opc(u->k, u->op, u->opc) == 0);
    u->cap[0] = 0xf0;
    u->cap[1] = 0xf0;
    u->cap[2] = 0xf0;
    u->cap[3] = 0xf0;
    u->ran_id = ran_id;
    u->ngksi = 7;
}

static void ue_provision(const ue_t *u, const char *extra)
{
    char *js = g5c_xasprintf("{\"supi\":\"%s\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"%s}", u->supi, extra != NULL ? extra : "");
    provision(js);
    free(js);
}

/* protect an uplink NAS message with the UE's current context (SHT 2) or the new one (SHT 4) */
static void ue_protect(ue_t *u, uint8_t sht, const uint8_t *plain, size_t n, g5c_bytes *out)
{
    TK_ASSERT(nas_protect(&u->sec, sht, G5C_DIR_UL, u->ul_count, plain, n, out) == NAS_OK);
    u->last_ul = u->ul_count;
    u->ul_count++;
}

/* verify and open a downlink protected message; false when the MAC does not verify */
static bool ue_open(ue_t *u, const uint8_t *nas, size_t len, g5c_bytes *plain, nas_any *any_out)
{
    nas_any a;
    uint32_t est;
    TK_ASSERT(nas_any_decode(nas, len, &a) == NAS_OK);
    if (!a.is_protected) {
        g5c_bytes_append(plain, nas, len);
        if (any_out != NULL)
            *any_out = a;
        else
            nas_any_free(&a);
        return true;
    }
    est = (u->dl_count & ~0xffu) | a.prot.seq;
    if (a.prot.seq < (uint8_t)(u->dl_count & 0xff))
        est += 0x100;
    if (!nas_protected_verify(&a.prot, &u->sec, G5C_DIR_DL, est)) {
        nas_any_free(&a);
        return false;
    }
    TK_ASSERT(nas_protected_open(&a.prot, &u->sec, G5C_DIR_DL, est, plain) == NAS_OK);
    u->dl_count = est + 1;
    nas_any_free(&a);
    return true;
}

static void put_msin_identity(const ue_t *u, g5c_bytes *out)
{
    nas_mobile_identity id;
    uint8_t bcd[16];
    size_t n = 0;
    memset(&id, 0, sizeof id);
    id.kind = NAS_ID_SUCI;
    snprintf(id.mcc, sizeof id.mcc, "001");
    snprintf(id.mnc, sizeof id.mnc, "01");
    snprintf(id.routing_indicator, sizeof id.routing_indicator, "0000");
    TK_ASSERT(g5c_msin_to_bcd(u->msin, bcd, sizeof bcd, &n) == 0);
    memcpy(id.output, bcd, n);
    id.output_len = n;
    TK_ASSERT(nas_mobile_identity_encode(&id, out) == NAS_OK);
}

static void put_guti_identity(const ue_t *u, g5c_bytes *out)
{
    nas_mobile_identity id;
    memset(&id, 0, sizeof id);
    id.kind = NAS_ID_GUTI;
    snprintf(id.mcc, sizeof id.mcc, "001");
    snprintf(id.mnc, sizeof id.mnc, "01");
    id.amf_region = 2;
    id.amf_set = 1;
    id.amf_pointer = 0;
    id.tmsi = u->tmsi;
    TK_ASSERT(nas_mobile_identity_encode(&id, out) == NAS_OK);
}

/* REGISTRATION REQUEST (plain encoding); with_guti: use the 5G-GUTI as the identity */
static void build_reg_request(ue_t *u, uint8_t type, bool with_guti, g5c_bytes *out)
{
    nas_msg m;
    g5c_bytes id;
    uint8_t half;
    static const uint8_t req_nssai[] = {0x02, 0x01, 0x01};
    TK_ASSERT(nas_msg_init(&m, "Registration request"));
    half = type;
    nas_msg_set(&m, "5GS registration type", &half, 1);
    half = u->have_ctx ? (u->ngksi & 7) : 7;
    nas_msg_set(&m, "ngKSI", &half, 1);
    g5c_bytes_init(&id);
    if (with_guti)
        put_guti_identity(u, &id);
    else
        put_msin_identity(u, &id);
    nas_msg_set(&m, "5GS mobile identity", id.data, id.len);
    g5c_bytes_free(&id);
    nas_msg_set(&m, "UE security capability", u->cap, 4);
    nas_msg_set(&m, "Requested NSSAI", req_nssai, sizeof req_nssai);
    TK_ASSERT(nas_msg_encode(&m, out) == NAS_OK);
    nas_msg_free(&m);
}

/* ---- gNB-side message helpers ---- */

static g5c_json *tai_json(uint32_t tac)
{
    g5c_json *t = g5c_json_new_obj();
    uint8_t b[3] = {(uint8_t)(tac >> 16), (uint8_t)(tac >> 8), (uint8_t)tac}, plmn[3] = {0x00, 0xf1, 0x10};
    char *h = g5c_hex_encode(b, 3);
    g5c_json_set(t, "pLMNIdentity", hex_str(plmn, 3));
    g5c_json_set_str(t, "tAC", h);
    free(h);
    return t;
}

static g5c_json *uli_json(uint32_t tac, uint64_t cell)
{
    g5c_json *u = g5c_json_new_obj(), *nr = g5c_json_set(u, "userLocationInformationNR", g5c_json_new_obj()), *cg = g5c_json_set(nr, "nR-CGI", g5c_json_new_obj());
    uint8_t plmn[3] = {0x00, 0xf1, 0x10}, c[5];
    uint64_t v = cell << 4;
    for (int i = 4; i >= 0; i--) {
        c[i] = (uint8_t)v;
        v >>= 8;
    }
    g5c_json_set(cg, "pLMNIdentity", hex_str(plmn, 3));
    g5c_json_set(cg, "nRCellIdentity", bits_json(c, 36));
    g5c_json_set(nr, "tAI", tai_json(tac));
    g5c_json_set_str(nr, "timeStamp", "ee68b8cc");
    return u;
}

static void gnb_initial_ue(gnb_t *g, ue_t *u, const uint8_t *nas, size_t n, uint32_t tac, bool with_stmsi)
{
    g5c_json *p = new_pdu("initiatingMessage", NGAP_PROC_InitialUEMessage, "ignore");
    add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "reject", g5c_json_new_int(u->ran_id));
    add_ie(p, NGAP_IE_NAS_PDU, "reject", hex_str(nas, n));
    add_ie(p, NGAP_IE_UserLocationInformation, "reject", uli_json(tac, 0x100 + (uint64_t)g->idx));
    add_ie(p, NGAP_IE_RRCEstablishmentCause, "ignore", g5c_json_new_str("mo-Signalling"));
    if (with_stmsi) {
        g5c_json *st = g5c_json_new_obj();
        uint8_t set[2] = {0x00, 0x40}, ptr = 0, tm[4] = {(uint8_t)(u->tmsi >> 24), (uint8_t)(u->tmsi >> 16), (uint8_t)(u->tmsi >> 8), (uint8_t)u->tmsi};
        g5c_json_set(st, "aMFSetID", bits_json(set, 10));
        g5c_json_set(st, "aMFPointer", bits_json(&ptr, 6));
        g5c_json_set(st, "fiveG-TMSI", hex_str(tm, 4));
        add_ie(p, NGAP_IE_FiveG_S_TMSI, "reject", st);
    }
    add_ie(p, NGAP_IE_UEContextRequest, "ignore", g5c_json_new_str("requested"));
    gnb_tx(g, p, (uint16_t)(1 + u->ran_id % 7));
}

static void gnb_uplink_nas(gnb_t *g, ue_t *u, const uint8_t *nas, size_t n, uint32_t tac)
{
    g5c_json *p = new_pdu("initiatingMessage", NGAP_PROC_UplinkNASTransport, "ignore");
    add_ie(p, NGAP_IE_AMF_UE_NGAP_ID, "reject", g5c_json_new_int((int64_t)u->amf_id));
    add_ie(p, NGAP_IE_RAN_UE_NGAP_ID, "reject", g5c_json_new_int(u->ran_id));
    add_ie(p, NGAP_IE_NAS_PDU, "reject", hex_str(nas, n));
    add_ie(p, NGAP_IE_UserLocationInformation, "ignore", uli_json(tac, 0x100 + (uint64_t)g->idx));
    gnb_tx(g, p, (uint16_t)(1 + u->ran_id % 7));
}

/* the NAS PDU of a DownlinkNASTransport / ICS / PDU session message, or false */
static bool nas_of(const g5c_json *pdu, uint8_t **out, size_t *n)
{
    const char *h = g5c_json_str(ie_of(pdu, NGAP_IE_NAS_PDU));
    size_t l;
    if (h == NULL)
        return false;
    l = strlen(h) / 2;
    *out = g5c_xmalloc(l + 1);
    TK_ASSERT(g5c_hex_decode(h, *out, l) == (long)l);
    *n = l;
    return true;
}

static void learn_ids(ue_t *u, const g5c_json *pdu)
{
    int64_t v;
    if (g5c_json_int(ie_of(pdu, NGAP_IE_AMF_UE_NGAP_ID), &v))
        u->amf_id = (uint64_t)v;
}

/* receive the next NGAP PDU, asserting its procedure and kind */
static g5c_json *rx_expect(gnb_t *g, int64_t proc, const char *kind, int timeout_ms)
{
    g5c_json *p = gnb_rx(g, timeout_ms);
    if (p == NULL)
        TK_FAIL("no NGAP message (wanted procedure %lld %s)", (long long)proc, kind);
    if (proc_of(p) != proc || !is_kind(p, kind)) {
        char *s = g5c_json_to_string(p, NULL);
        TK_FAIL("wanted procedure %lld %s, got %.300s", (long long)proc, kind, s);
    }
    return p;
}

/* receive a DL NAS TRANSPORT and open it */
static g5c_bytes dl_nas(gnb_t *g, ue_t *u)
{
    g5c_json *p = rx_expect(g, NGAP_PROC_DownlinkNASTransport, "initiatingMessage", 3000);
    uint8_t *nas;
    size_t n;
    g5c_bytes plain;
    g5c_bytes_init(&plain);
    learn_ids(u, p);
    TK_ASSERT(nas_of(p, &nas, &n));
    TK_ASSERT(ue_open(u, nas, n, &plain, NULL));
    free(nas);
    g5c_json_free(p);
    return plain;
}

#endif
