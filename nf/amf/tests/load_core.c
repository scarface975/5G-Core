/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Load driver for the whole control plane (strategy phase 6: multi-UE, multi-session scale tests, 100 -> 1,000 -> 10,000 simulated UEs).
 *
 * The environment of e2e_env.h (udr, UDM, AUSF, PCF, UPF runtime, SMF and AMF, every one with its real HTTP/2, PFCP, GTP-U and SCTP sockets) runs in
 * this process; G5C_LOAD_GNBS scripted gNBs, each on its own SCTP association and thread, drive G5C_LOAD_UES scripted UEs through
 *     5G-AKA registration -> PDU session establishment -> hold -> UE-originated de-registration (PDU sessions are released with the context).
 * Every UE derives the keys itself (Milenage, KAUSF/KSEAF/KAMF, NAS keys, KgNB) and checks what the network answers, so a wrong MAC or a wrong key fails
 * the run. Latencies are measured per procedure. The run passes when every UE completed, the AMF, SMF and UPF are empty at the end and the process did
 * not leak descriptors.
 *
 *   G5C_LOAD_UES       number of UEs (default 200)
 *   G5C_LOAD_GNBS      number of gNBs / concurrent UE procedures (default 16)
 *   G5C_LOAD_WAVES     how many times the whole population registers and de-registers (default 1; RSS is compared across waves)
 *   G5C_LOAD_SECONDS   soak: keep running waves until this many seconds have passed (overrides G5C_LOAD_WAVES)
 *   G5C_LOAD_HOLD_MS   how long the registered population is held before it de-registers (default 0)
 *   G5C_LOAD_JSON      path of a JSON report to write (optional)
 *   G5C_LOAD_BASE      offset added to the IMSI number (to keep a run apart from earlier ones)
 *   G5C_LOAD_CHAOS_SECONDS  chaos mode: loop register / session / de-register cycles for this long, counting failures instead of stopping (used while
 *                      deploy/run/g5c-cluster.sh kills and restarts network functions)
 *   G5C_LOAD_STORM_SECONDS  storm mode: every gNB sends Registration Requests back to back for this long (no waiting for the core to keep up) and counts what comes back: challenged
 *                      (admitted), refused with cause #22 congestion (amf.overload), or anything else. The challenged UEs are left to the AMF's timers. The run fails when a reply is neither
 *   G5C_LOAD_ADMIN_TOKEN / G5C_LOAD_NO_PROVISION  the bearer token of the UDM admin API (default: the cluster's test token); set NO_PROVISION when the subscribers exist already (tools/cli/g5c-tester)
 *   G5C_LOAD_FANOUT    1: this process is one of several against the same core (tools/cli/g5c-fanout): the population counts of the core are not judged, the caller does that
 *   G5C_LOAD_MOBILITY  mobility mode (backlog B-09): every UE registers on one gNB, establishes its session and then moves between two gNBs (tracking areas 1 and 2) by this many Xn path switches, each checked
 *                      (next hop, chaining count, switched sessions); then it de-registers
 *   G5C_LOAD_CHECK_MEM 0: do not assert that RSS stops growing between waves (sanitizer builds)
 *   G5C_LOAD_TRAFFIC_MBPS  user plane (backlog B-02): once every UE has its session, each UE sends uplink GTP-U at this rate (Mbit/s, may be fractional) for G5C_LOAD_TRAFFIC_MS
 *   G5C_LOAD_ECHO      an echo server behind the UPF (tools/cli/g5c-dn --echo 7 on the data network gateway): the uplink packets are addressed to it and come back as downlink through
 *                      the UPF to the gNB's N3 socket, which gives loss, round-trip time and jitter and the downlink rate (at most 2 gNBs: each owns an N3 address).
 *                      G5C_LOAD_EXPECT_DL_MBPS: the per-UE downlink rate the session AMBR allows (judged like G5C_LOAD_EXPECT_MBPS); G5C_LOAD_ECHO_MAX_LOSS_PCT: fail above this loss
 *                      (default traffic: each UE sends at G5C_LOAD_TRAFFIC_MBPS)  G5C_LOAD_TRAFFIC_SIZE octets (default 1000). Remote mode only: the UPF's counters say what was forwarded and what its rate limiter
 *                      dropped. G5C_LOAD_EXPECT_MBPS: the per-UE rate the session AMBR allows; the run fails when the delivered rate is not between 0.5x and 1.3x of it (0: judge nothing)
 *
 * Remote mode (G5C_LOAD_REMOTE=1) does not start the network functions: the gNBs connect to real daemons (deploy/run/g5c-cluster.sh starts them) and the
 * counts come from their /metrics endpoints.
 *   G5C_LOAD_AMF_NGAP  ip:port of the AMF's N2 endpoint        (default 127.2.0.5:38412)
 *   G5C_LOAD_UDM       base URL of the UDM (admin API)           (default http://127.2.0.1:7773)
 *   G5C_LOAD_AMF_SBI / G5C_LOAD_SMF_SBI / G5C_LOAD_UPF_SBI  base URLs for the gauges
 *   G5C_LOAD_WAVE_HOOK shell command run after every wave (the cluster script samples RSS with it) */
#define _GNU_SOURCE
#pragma GCC diagnostic ignored "-Wunused-function"
#include <dirent.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/common_interface_defs.h>
#endif

#include <arpa/inet.h>
#include <setjmp.h>
#include <sys/socket.h>
#include "g5c/gtpu.h"
#include "g5c/testkit.h"

/* a failed check ends the run, except inside a tolerant section (chaos mode), where it unwinds to the section's setjmp and is counted */
static __thread jmp_buf *tl_jb;
static __thread char tl_msg[512];
#undef TK_FAIL
#define TK_FAIL(...)                                                                                                                                         \
    do {                                                                                                                                                      \
        if (tl_jb != NULL) {                                                                                                                                  \
            snprintf(tl_msg, sizeof tl_msg, __VA_ARGS__);                                                                                                     \
            longjmp(*tl_jb, 1);                                                                                                                               \
        }                                                                                                                                                     \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);                                                                                                           \
        printf(__VA_ARGS__);                                                                                                                                  \
        printf("\n");                                                                                                                                         \
        exit(1);                                                                                                                                              \
    } while (0)

#include "e2e_procs.h"

static unsigned env_uint(const char *name, unsigned dflt)
{
    const char *v = getenv(name);
    return v != NULL && *v != 0 ? (unsigned)strtoul(v, NULL, 10) : dflt;
}

static long open_fds(void)
{
    DIR *d = opendir("/proc/self/fd");
    long n = 0;
    if (d == NULL)
        return -1;
    while (readdir(d) != NULL)
        n++;
    closedir(d);
    return n;
}

static long rss_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[128];
    long v = -1;
    if (f == NULL)
        return -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "VmRSS: %ld kB", &v) == 1)
            break;
    fclose(f);
    return v;
}

static size_t upf_sessions(void)
{
    size_t n = 0;
    upf_rt_snapshot(E.rt, NULL, &n);
    return n;
}

static bool remote, fanout; /* fanout: other load processes share the core, so the population counts are not this process's alone */
static char amf_sbi[96], smf_sbi[96], upf_sbi[96];

/* one value of a Prometheus text exposition */
static long scrape(const char *base, const char *name)
{
    char url[160], err[160];
    g5c_resp r;
    long v = 0; /* a gauge that was never set is not exported yet: zero */
    snprintf(url, sizeof url, "%s/metrics", base);
    if (g5c_client_request(E.cl, "GET", url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) != 0)
        return -1;
    if (r.status == 200 && r.body != NULL) {
        size_t nl = strlen(name);
        const char *l = (const char *)r.body;
        while (*l != 0) {
            const char *eol = strchr(l, '\n');
            size_t len = eol != NULL ? (size_t)(eol - l) : strlen(l);
            if (len > nl && strncmp(l, name, nl) == 0 && (l[nl] == ' ' || l[nl] == '{')) {
                const char *sp = l + len;
                while (sp > l && sp[-1] != ' ')
                    sp--;
                v = strtol(sp, NULL, 10);
                break;
            }
            if (eol == NULL)
                break;
            l = eol + 1;
        }
    }
    g5c_resp_free(&r);
    return v;
}

static size_t n_amf_ues(void)
{
    return remote ? (size_t)scrape(amf_sbi, "g5c_amf_ue_contexts") : amf_ue_count(E.a);
}

static size_t n_smf_sessions(void)
{
    return remote ? (size_t)scrape(smf_sbi, "g5c_smf_pdu_sessions_active") : smf_session_count(E.s);
}

static size_t n_upf_sessions(void)
{
    return remote ? (size_t)scrape(upf_sbi, "g5c_upf_sessions") : upf_sessions();
}

/* the count a wave must reach: base + want */
static bool count_is(size_t cur, size_t base, size_t want)
{
    if (fanout)
        return true;
    return remote ? cur >= want && cur <= base + want : cur == base + want;
}

/* after de-registration: back to the base (remote: at most the base, leftovers may have gone) */
static bool count_back(size_t cur, size_t base)
{
    if (fanout)
        return true;
    return remote ? cur <= base : cur == base;
}

/* wait until the three counts have not changed for a while (leftovers of an earlier run - a chaos run - are still being released) */
static void settle_counts(void)
{
    size_t a = n_amf_ues(), m = n_smf_sessions(), u = n_upf_sessions();
    double stable_since = now_s(), end = now_s() + 20;
    while (now_s() < end && now_s() - stable_since < 2.0) {
        size_t a2, m2, u2;
        usleep(100000);
        a2 = n_amf_ues();
        m2 = n_smf_sessions();
        u2 = n_upf_sessions();
        if (a2 != a || m2 != m || u2 != u) {
            a = a2;
            m = m2;
            u = u2;
            stable_since = now_s();
        }
    }
}

static pthread_barrier_t bar_registered, bar_release, bar_tgo, bar_tdone;
static bool traf_on;
static double traf_mbps, traf_ms;
static unsigned traf_size;

/* With G5C_LOAD_ECHO the packets go to an echo server behind the UPF and return as downlink */
static const char *echo_ip;
static pthread_mutex_t echo_mu = PTHREAD_MUTEX_INITIALIZER;
static unsigned long echo_sent, echo_recv, echo_bytes;
static double echo_rtt[400000];
static size_t echo_nrtt;

static void ip_header_checksum(uint8_t *ip)
{
    uint32_t sum = 0;
    ip[10] = ip[11] = 0;
    for (int i = 0; i < 20; i += 2)
        sum += (uint32_t)(ip[i] << 8 | ip[i + 1]);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    ip[10] = (uint8_t)(~sum >> 8);
    ip[11] = (uint8_t)~sum;
}

/* downlink datagrams waiting at the gNB's N3 socket: GTP-U with the echoed packet, whose payload carries the sequence number and the time it left */
static void echo_collect(int fd)
{
    uint8_t buf[2000];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof buf, MSG_DONTWAIT)) > 0) {
        gtpu_header gh;
        const uint8_t *pl;
        size_t plen;
        double t0;
        if (gtpu_decode(buf, (size_t)n, &gh, &pl, &plen) != 0 || gh.msg_type != GTPU_G_PDU || plen < 40 || (pl[0] >> 4) != 4 || pl[9] != 17)
            continue;
        memcpy(&t0, pl + 32, sizeof t0);
        pthread_mutex_lock(&echo_mu);
        echo_recv++;
        echo_bytes += plen;
        if (echo_nrtt < sizeof echo_rtt / sizeof echo_rtt[0])
            echo_rtt[echo_nrtt++] = now_s() - t0;
        pthread_mutex_unlock(&echo_mu);
    }
}

/* One UE's uplink traffic (B-02) */
static void traffic_phase(const sess_t *ss, int gnb)
{
    bool echo = echo_ip != NULL;
    int fd = echo ? E.gnb_udp[gnb] : socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to;
    uint8_t ip[1500], out[1600], cont[2];
    gtpu_header h;
    size_t len, size = traf_size < 60 ? 60 : traf_size > 1400 ? 1400 : traf_size;
    double start, interval = (double)size * 8.0 / (traf_mbps * 1e6), sent = 0;
    uint32_t seq = 0;
    TK_ASSERT(fd >= 0);
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(remote ? 2152 : E.n3p);
    memcpy(&to.sin_addr, ss->upf_ip, 4);
    memset(ip, 0, sizeof ip);
    ip[0] = 0x45;
    ip[2] = (uint8_t)(size >> 8);
    ip[3] = (uint8_t)size;
    ip[8] = 64;
    ip[9] = 17;
    memcpy(ip + 12, ss->ue_ip, 4);
    if (echo) {
        TK_ASSERT(inet_pton(AF_INET, echo_ip, ip + 16) == 1);
    } else {
        ip[16] = 198, ip[17] = 51, ip[18] = 100, ip[19] = 1;
    }
    ip_header_checksum(ip); /* the kernel behind the TUN device drops a packet whose header checksum is wrong */
    ip[20] = 0x13, ip[21] = 0x88, ip[22] = 0, ip[23] = echo ? 7 : 9; /* UDP 5000 -> 7 (echo) or 9 (discard) */
    ip[24] = (uint8_t)((size - 20) >> 8);
    ip[25] = (uint8_t)(size - 20);
    gtpu_header_init(&h, GTPU_G_PDU, ss->upf_teid);
    gtpu_pdu_session_container(cont, 1, 1, false);
    h.ext[0].typ = GTPU_EXT_PDU_SESSION_CONTAINER;
    h.ext[0].data = cont;
    h.ext[0].len = 2;
    h.next = 1;
    start = now_s();
    while (now_s() - start < traf_ms / 1000.0) {
        double due = (now_s() - start) / interval; /* packets that should have gone by now */
        while (sent < due) {
            double t = now_s();
            memcpy(ip + 28, &seq, sizeof seq);
            memcpy(ip + 32, &t, sizeof t);
            seq++;
            TK_ASSERT(gtpu_encode(&h, ip, size, out, sizeof out, &len) == 0);
            (void)sendto(fd, out, len, 0, (struct sockaddr *)&to, sizeof to);
            sent += 1;
        }
        if (echo)
            echo_collect(fd);
        usleep(500);
    }
    if (echo) {
        pthread_mutex_lock(&echo_mu);
        echo_sent += (unsigned long)sent;
        pthread_mutex_unlock(&echo_mu);
        for (int i = 0; i < 12; i++) { /* stragglers: the last packets are still on their way back */
            usleep(50000);
            echo_collect(fd);
        }
    } else {
        close(fd);
    }
}

typedef struct {
    unsigned idx;
    unsigned first, count;
    double *t_reg, *t_pdu, *t_dereg; /* per UE of this gNB, seconds */
} worker_t;

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static unsigned imsi_base;

static void imsi_of(char *out, size_t cap, unsigned n)
{
    snprintf(out, cap, "00101%010u", imsi_base + n + 1);
}

static void *gnb_thread(void *arg)
{
    worker_t *w = arg;
    gnb_t g;
    ue_t *ues = g5c_xmalloc(sizeof *ues * w->count);
    sess_t *sessions = g5c_xcalloc(w->count ? w->count : 1, sizeof *sessions);
    char imsi[16];
    g5c_json *r;
    int idx = (int)(w->idx % 2);
    gnb_open(&g, idx);
    r = gnb_ng_setup(&g, 1000 + w->idx, 1, "00f110", "gnb-load");
    TK_ASSERT(r != NULL && is_kind(r, "successfulOutcome") && proc_of(r) == NGAP_PROC_NGSetup);
    g5c_json_free(r);
    for (unsigned i = 0; i < w->count; i++) {
        double t0;
        accept_info ai;
        sess_t s;
        imsi_of(imsi, sizeof imsi, w->first + i);
        ue_init(&ues[i], imsi, 1 + i);
        t0 = now_s();
        ai = ue_register_ex(&g, &ues[i], 1, false, false, NULL);
        accept_free(&ai);
        w->t_reg[i] = now_s() - t0;
        t0 = now_s();
        s = ue_establish(&g, &ues[i], 1, 0x10000 + w->first + i, 1);
        TK_ASSERT(s.has_ue_ip);
        sessions[i] = s;
        w->t_pdu[i] = now_s() - t0;
    }
    pthread_barrier_wait(&bar_registered);
    if (traf_on) {
        pthread_barrier_wait(&bar_tgo); /* every UE has its session; the main thread has read the UPF counters */
        for (unsigned i = 0; i < w->count; i++)
            traffic_phase(&sessions[i], (int)(w->idx % 2));
        pthread_barrier_wait(&bar_tdone);
    }
    pthread_barrier_wait(&bar_release);
    for (unsigned i = 0; i < w->count; i++) {
        double t0 = now_s();
        nas_msg m;
        g5c_bytes b, id;
        uint8_t dt = 0x09, ng = ues[i].ngksi;
        g5c_bytes_init(&b);
        g5c_bytes_init(&id);
        put_guti_identity(&ues[i], &id);
        TK_ASSERT(nas_msg_init(&m, "De-registration request (UE originating de-registration)"));
        nas_msg_set(&m, "De-registration type", &dt, 1);
        nas_msg_set(&m, "ngKSI", &ng, 1);
        nas_msg_set(&m, "5GS mobile identity", id.data, id.len);
        TK_ASSERT(nas_msg_encode(&m, &b) == NAS_OK);
        nas_msg_free(&m);
        ue_send_protected(&g, &ues[i], 2, b.data, b.len, 1);
        g5c_bytes_free(&b);
        g5c_bytes_free(&id);
        gnb_confirm_release(&g, &ues[i]);
        w->t_dereg[i] = now_s() - t0;
    }
    gnb_close(&g);
    free(sessions);
    free(ues);
    return NULL;
}

/* ---- chaos mode: a tolerant load that keeps going while network functions are killed and restarted ---- */

static atomic_long c_ok, c_fail_reg, c_fail_est, c_fail_dereg, c_reconnects;
static atomic_bool chaos_stop;
static double chaos_deadline;

/* one attempt: connect and NG Setup; failures unwind here */
static bool connect_once(gnb_t *g, unsigned who)
{
    jmp_buf jb;
    g5c_json *volatile r = NULL;
    tl_jb = &jb;
    if (setjmp(jb) == 0) {
        gnb_open(g, (int)(who % 2));
        r = gnb_ng_setup(g, 1000 + who, 1, "00f110", "gnb-chaos");
        tl_jb = NULL;
        if (r != NULL && is_kind(r, "successfulOutcome")) {
            g5c_json_free(r);
            return true;
        }
        g5c_json_free(r);
        return false;
    }
    tl_jb = NULL;
    return false;
}

/* NG Setup on a fresh association; false when the AMF cannot be reached within the tries */
static bool gnb_connect(gnb_t *g, unsigned who, int tries)
{
    for (int t = 0; t < tries && !atomic_load(&chaos_stop); t++) {
        if (connect_once(g, who))
            return true;
        gnb_close(g);
        usleep(300000);
    }
    return false;
}

/* register, establish a session, de-register; returns how far it got: 0 nothing, 1 registered, 2 session up, 3 all done */
static int one_cycle(gnb_t *g, unsigned imsi_n, uint32_t ran_id)
{
    jmp_buf jb;
    volatile int stage = 0;
    ue_t u;
    char imsi[16];
    tl_jb = &jb;
    if (setjmp(jb) != 0) {
        tl_jb = NULL;
        return stage;
    }
    imsi_of(imsi, sizeof imsi, imsi_n);
    ue_init(&u, imsi, ran_id);
    {
        accept_info ai = ue_register_ex(g, &u, 1, false, false, NULL);
        accept_free(&ai);
    }
    stage = 1;
    {
        sess_t s = ue_establish(g, &u, 1, 0x20000 + ran_id, 1);
        TK_ASSERT(s.has_ue_ip);
    }
    stage = 2;
    {
        nas_msg m;
        g5c_bytes b, id;
        uint8_t dt = 0x09, ng = u.ngksi;
        g5c_bytes_init(&b);
        g5c_bytes_init(&id);
        put_guti_identity(&u, &id);
        TK_ASSERT(nas_msg_init(&m, "De-registration request (UE originating de-registration)"));
        nas_msg_set(&m, "De-registration type", &dt, 1);
        nas_msg_set(&m, "ngKSI", &ng, 1);
        nas_msg_set(&m, "5GS mobile identity", id.data, id.len);
        TK_ASSERT(nas_msg_encode(&m, &b) == NAS_OK);
        nas_msg_free(&m);
        ue_send_protected(g, &u, 2, b.data, b.len, 1);
        g5c_bytes_free(&b);
        g5c_bytes_free(&id);
        gnb_confirm_release(g, &u);
    }
    stage = 3;
    tl_jb = NULL;
    return stage;
}

/* storm mode: one Registration Request; 1 the AMF challenged the UE (admitted), 2 refused it with cause #22, 3 anything else */
static atomic_long s_tried, s_admitted, s_congested, s_other;

static int one_attempt(gnb_t *g, unsigned imsi_n, uint32_t ran_id)
{
    jmp_buf jb;
    volatile int rc = 3;
    ue_t u;
    char imsi[16];
    g5c_bytes req, plain;
    tl_jb = &jb;
    if (setjmp(jb) != 0) {
        tl_jb = NULL;
        return 3;
    }
    imsi_of(imsi, sizeof imsi, imsi_n);
    ue_init(&u, imsi, ran_id);
    g5c_bytes_init(&req);
    build_reg_request(&u, 1, false, &req);
    gnb_initial_ue(g, &u, req.data, req.len, 1, false);
    g5c_bytes_free(&req);
    plain = dl_nas(g, &u);
    if (plain.len >= 4 && plain.data[2] == 0x44 && plain.data[3] == 22)
        rc = 2;
    else if (plain.len >= 3 && plain.data[2] == 0x56)
        rc = 1;
    g5c_bytes_free(&plain);
    if (rc == 2)
        gnb_confirm_release(g, &u);
    tl_jb = NULL;
    return rc;
}

static void *storm_thread(void *arg)
{
    worker_t *w = arg;
    gnb_t g;
    uint32_t seq = 1;
    unsigned i = 0;
    memset(&g, 0, sizeof g);
    g.fd = -1;
    if (!gnb_connect(&g, w->idx, 50))
        return NULL;
    while (now_s() < chaos_deadline) {
        int r = one_attempt(&g, w->first + i % w->count, seq++);
        i++;
        atomic_fetch_add(&s_tried, 1);
        if (r == 1) {
            atomic_fetch_add(&s_admitted, 1);
        } else if (r == 2) {
            atomic_fetch_add(&s_congested, 1);
        } else {
            atomic_fetch_add(&s_other, 1);
            gnb_close(&g); /* unknown state: a new association */
            if (!gnb_connect(&g, w->idx, 100))
                break;
        }
    }
    gnb_close(&g);
    return NULL;
}

static int storm_main(unsigned n_ues, unsigned n_gnbs, unsigned seconds)
{
    pthread_t *th = g5c_xmalloc(sizeof *th * n_gnbs);
    worker_t *w = g5c_xmalloc(sizeof *w * n_gnbs);
    unsigned per = n_ues / n_gnbs, rem = n_ues % n_gnbs, next = 0;
    double t0;
    long tried;
    printf("storm: %u gNBs send Registration Requests back to back for %u s\n", n_gnbs, seconds);
    fflush(stdout);
    for (unsigned i = 0; i < n_ues; i++) {
        char imsi[16], js[200];
        imsi_of(imsi, sizeof imsi, i);
        snprintf(js, sizeof js, "{\"supi\":\"imsi-%s\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}", imsi);
        if (getenv("G5C_LOAD_NO_PROVISION") == NULL)
            provision(js);
    }
    t0 = now_s();
    chaos_deadline = t0 + seconds;
    for (unsigned i = 0; i < n_gnbs; i++) {
        w[i].idx = i;
        w[i].first = next;
        w[i].count = per + (i < rem ? 1 : 0);
        next += w[i].count;
        TK_ASSERT(pthread_create(&th[i], NULL, storm_thread, &w[i]) == 0);
    }
    for (unsigned i = 0; i < n_gnbs; i++)
        pthread_join(th[i], NULL);
    tried = atomic_load(&s_tried);
    printf("storm: %ld registrations in %.1f s (%.0f/s): %ld admitted, %ld refused with congestion (#22), %ld other\n", tried, now_s() - t0, (double)tried / (now_s() - t0),
           atomic_load(&s_admitted), atomic_load(&s_congested), atomic_load(&s_other));
    free(th);
    free(w);
    return tried > 0 && atomic_load(&s_other) == 0 ? 0 : 1;
}

static void *chaos_thread(void *arg)
{
    worker_t *w = arg;
    gnb_t g;
    uint32_t seq = 1;
    unsigned i = 0;
    memset(&g, 0, sizeof g);
    g.fd = -1;
    if (!gnb_connect(&g, w->idx, 50))
        return NULL;
    while (now_s() < chaos_deadline && !atomic_load(&chaos_stop)) {
        int st = one_cycle(&g, w->first + i % w->count, seq++);
        i++;
        if (st == 3) {
            atomic_fetch_add(&c_ok, 1);
            continue;
        }
        if (st == 0)
            atomic_fetch_add(&c_fail_reg, 1);
        else if (st == 1)
            atomic_fetch_add(&c_fail_est, 1);
        else
            atomic_fetch_add(&c_fail_dereg, 1);
        /* the association is in an unknown state: start over on a new one */
        gnb_close(&g);
        atomic_fetch_add(&c_reconnects, 1);
        if (!gnb_connect(&g, w->idx, 100))
            break;
    }
    gnb_close(&g);
    return NULL;
}

static int chaos_main(unsigned n_ues, unsigned n_gnbs, unsigned seconds)
{
    pthread_t *th = g5c_xmalloc(sizeof *th * n_gnbs);
    worker_t *w = g5c_xmalloc(sizeof *w * n_gnbs);
    unsigned per = n_ues / n_gnbs, rem = n_ues % n_gnbs, next = 0;
    double t0;
    long total;
    printf("chaos: %u UEs over %u gNBs for %u s (failures are counted, not fatal)\n", n_ues, n_gnbs, seconds);
    fflush(stdout);
    for (unsigned i = 0; i < n_ues; i++) {
        char imsi[16], js[200];
        imsi_of(imsi, sizeof imsi, i);
        snprintf(js, sizeof js, "{\"supi\":\"imsi-%s\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}", imsi);
        if (getenv("G5C_LOAD_NO_PROVISION") == NULL)
            provision(js);
    }
    t0 = now_s();
    chaos_deadline = t0 + seconds;
    for (unsigned i = 0; i < n_gnbs; i++) {
        w[i].idx = i;
        w[i].first = next;
        w[i].count = per + (i < rem ? 1 : 0);
        next += w[i].count;
        TK_ASSERT(pthread_create(&th[i], NULL, chaos_thread, &w[i]) == 0);
    }
    for (unsigned i = 0; i < n_gnbs; i++)
        pthread_join(th[i], NULL);
    total = atomic_load(&c_ok) + atomic_load(&c_fail_reg) + atomic_load(&c_fail_est) + atomic_load(&c_fail_dereg);
    printf("chaos: %ld UE cycles in %.0f s: %ld completed, %ld failed in registration, %ld in session setup, %ld in de-registration; %ld reconnects\n", total,
           now_s() - t0, atomic_load(&c_ok), atomic_load(&c_fail_reg), atomic_load(&c_fail_est), atomic_load(&c_fail_dereg), atomic_load(&c_reconnects));
    free(th);
    free(w);
    return atomic_load(&c_ok) > 0 ? 0 : 1;
}

/* ---- mobility mode (backlog B-09): Xn path switches against real daemons ----
 * Each worker owns two gNBs (two associations, tracking areas 1 and 2). A UE registers and establishes its session on gNB A, then moves A -> B -> A ... for G5C_LOAD_MOBILITY
 * path switches; every answer is checked (the UE and RAN identifiers, the next hop and its chaining count against the UE's own derivation, the switched session list), and the UE
 * de-registers from wherever it ended. The run passes when every UE did all its moves and the core is empty at the end. */
static atomic_long m_done, m_moves, m_fail;
static unsigned mob_hops;

static void drain(gnb_t *g)
{
    g5c_json *p;
    while ((p = gnb_rx(g, 40)) != NULL)
        g5c_json_free(p);
}

static bool mob_connect(gnb_t *g, int idx, unsigned id, uint32_t tac)
{
    g5c_json *r;
    gnb_open(g, idx);
    r = gnb_ng_setup(g, id, tac, "00f110", "gnb-mobility");
    if (r != NULL && is_kind(r, "successfulOutcome")) {
        g5c_json_free(r);
        return true;
    }
    g5c_json_free(r);
    gnb_close(g);
    return false;
}

static void *mobility_thread(void *arg)
{
    worker_t *w = arg;
    gnb_t g[2];
    if (!mob_connect(&g[0], 0, 3000 + 2 * w->idx, 1) || !mob_connect(&g[1], 1, 3001 + 2 * w->idx, 2)) {
        atomic_fetch_add(&m_fail, (long)w->count);
        return NULL;
    }
    for (unsigned i = 0; i < w->count; i++) {
        jmp_buf jb;
        volatile unsigned hop = 0;
        ue_t u;
        char imsi[16];
        volatile int at = 0;
        tl_jb = &jb;
        if (setjmp(jb) != 0) {
            tl_jb = NULL;
            atomic_fetch_add(&m_fail, 1);
            fprintf(stderr, "mobility: UE %u failed after %u moves: %s\n", w->first + i, hop, tl_msg);
            gnb_close(&g[0]);
            gnb_close(&g[1]);
            if (!mob_connect(&g[0], 0, 3000 + 2 * w->idx, 1) || !mob_connect(&g[1], 1, 3001 + 2 * w->idx, 2))
                return NULL;
            continue;
        }
        imsi_of(imsi, sizeof imsi, w->first + i);
        ue_init(&u, imsi, 1 + i);
        {
            accept_info ai = ue_register_ex(&g[0], &u, 1, false, false, NULL);
            accept_free(&ai);
        }
        {
            sess_t s = ue_establish(&g[0], &u, 1, 0x10000 + w->first + i, 1);
            TK_ASSERT(s.has_ue_ip);
        }
        for (hop = 0; hop < mob_hops; hop++) {
            int to = 1 - at;
            drain(&g[to]);
            gnb_path_switch(&g[to], to, &u, 100000 + (w->first + i) * 64 + hop, to == 0 ? 1 : 2, 0x200 + hop, 0x40000 + (w->first + i) * 64 + hop, (int)hop + 2);
            at = to;
            atomic_fetch_add(&m_moves, 1);
        }
        drain(&g[at]);
        {
            nas_msg m;
            g5c_bytes b, id;
            uint8_t dt = 0x09, ng = u.ngksi;
            g5c_bytes_init(&b);
            g5c_bytes_init(&id);
            put_guti_identity(&u, &id);
            TK_ASSERT(nas_msg_init(&m, "De-registration request (UE originating de-registration)"));
            nas_msg_set(&m, "De-registration type", &dt, 1);
            nas_msg_set(&m, "ngKSI", &ng, 1);
            nas_msg_set(&m, "5GS mobile identity", id.data, id.len);
            TK_ASSERT(nas_msg_encode(&m, &b) == NAS_OK);
            nas_msg_free(&m);
            ue_send_protected(&g[at], &u, 2, b.data, b.len, 1);
            g5c_bytes_free(&b);
            g5c_bytes_free(&id);
            gnb_confirm_release(&g[at], &u);
        }
        tl_jb = NULL;
        atomic_fetch_add(&m_done, 1);
    }
    gnb_close(&g[0]);
    gnb_close(&g[1]);
    return NULL;
}

static int mobility_main(unsigned n_ues, unsigned n_gnbs, unsigned hops)
{
    pthread_t *th = g5c_xmalloc(sizeof *th * n_gnbs);
    worker_t *w = g5c_xmalloc(sizeof *w * n_gnbs);
    unsigned per = n_ues / n_gnbs, rem = n_ues % n_gnbs, next = 0;
    double t0;
    mob_hops = hops;
    printf("mobility: %u UEs over %u workers, %u Xn path switches each\n", n_ues, n_gnbs, hops);
    fflush(stdout);
    for (unsigned i = 0; i < n_ues; i++) {
        char imsi[16], js[200];
        imsi_of(imsi, sizeof imsi, i);
        snprintf(js, sizeof js, "{\"supi\":\"imsi-%s\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}", imsi);
        if (getenv("G5C_LOAD_NO_PROVISION") == NULL)
            provision(js);
    }
    t0 = now_s();
    for (unsigned i = 0; i < n_gnbs; i++) {
        w[i].idx = i;
        w[i].first = next;
        w[i].count = per + (i < rem ? 1 : 0);
        next += w[i].count;
        TK_ASSERT(pthread_create(&th[i], NULL, mobility_thread, &w[i]) == 0);
    }
    for (unsigned i = 0; i < n_gnbs; i++)
        pthread_join(th[i], NULL);
    printf("mobility: %ld of %u UEs completed, %ld path switches in %.1f s (%.0f/s), %ld failed\n", atomic_load(&m_done), n_ues, atomic_load(&m_moves), now_s() - t0,
           (double)atomic_load(&m_moves) / (now_s() - t0), atomic_load(&m_fail));
    free(th);
    free(w);
    return atomic_load(&m_done) == (long)n_ues && atomic_load(&m_fail) == 0 ? 0 : 1;
}

static double pct(const double *sorted, size_t n, double p)
{
    return n == 0 ? 0 : sorted[(size_t)((double)(n - 1) * p)];
}

static void report(const char *name, double *v, size_t n, FILE *js, bool last)
{
    qsort(v, n, sizeof *v, cmp_d);
    printf("  %-14s n=%-6zu p50 %7.1f ms  p95 %7.1f ms  p99 %7.1f ms  max %7.1f ms\n", name, n, pct(v, n, 0.50) * 1e3, pct(v, n, 0.95) * 1e3, pct(v, n, 0.99) * 1e3,
           pct(v, n, 1.0) * 1e3);
    if (js != NULL)
        fprintf(js, "    \"%s\": {\"n\": %zu, \"p50_ms\": %.2f, \"p95_ms\": %.2f, \"p99_ms\": %.2f, \"max_ms\": %.2f}%s\n", name, n, pct(v, n, 0.50) * 1e3,
                pct(v, n, 0.95) * 1e3, pct(v, n, 0.99) * 1e3, pct(v, n, 1.0) * 1e3, last ? "" : ",");
}

int main(void)
{
    double traf_expect = 0;
    unsigned hold_ms = env_uint("G5C_LOAD_HOLD_MS", 0), n_ues = env_uint("G5C_LOAD_UES", 200), n_gnbs = env_uint("G5C_LOAD_GNBS", 16);
    const char *json_path = getenv("G5C_LOAD_JSON");
    size_t b_amf = 0, b_smf = 0, b_upf = 0;
    pthread_t *th;
    worker_t *w;
    double *t_reg, *t_pdu, *t_dereg, t_start = 0, t_registered = 0, t_end = 0, end;
    long fds0, fds1, rss0, rss1, rss_peak = 0;
    char extra[200], pool[64];
    unsigned per, rem, next = 0, waves = env_uint("G5C_LOAD_WAVES", 1);
    long rss_first = 0, rss_last = 0;
    unsigned waves_done = 0;
    double soak_end = env_uint("G5C_LOAD_SECONDS", 0) != 0 ? g5c_now_seconds() + env_uint("G5C_LOAD_SECONDS", 0) : 0;
    size_t want = 0;

    if (n_gnbs > n_ues)
        n_gnbs = n_ues;
    TK_ASSERT(n_ues >= 1 && n_gnbs >= 1);
    /* the pool must hold every UE */
    snprintf(pool, sizeof pool, "10.%d.0.0/%d", 45, n_ues > 60000 ? 15 : 16);
    g_inet_pool = pool;
    g_persist = false;
    snprintf(extra, sizeof extra, "  max_unauthenticated: %u\n", n_gnbs * 4 + 64);
    g_amf_extra = extra;
    remote = env_uint("G5C_LOAD_REMOTE", 0) != 0;
    fanout = env_uint("G5C_LOAD_FANOUT", 0) != 0;
    if (remote) {
        const char *ep = getenv("G5C_LOAD_AMF_NGAP") != NULL ? getenv("G5C_LOAD_AMF_NGAP") : "127.2.0.5:38412", *colon = strrchr(ep, ':');
        static char ip[64];
        const char *u = getenv("G5C_LOAD_UDM") != NULL ? getenv("G5C_LOAD_UDM") : "http://127.2.0.1:7773";
        TK_ASSERT(colon != NULL && (size_t)(colon - ep) < sizeof ip);
        memcpy(ip, ep, (size_t)(colon - ep));
        g_ngap_ip = ip;
        g_ngap_port_override = (uint16_t)strtoul(colon + 1, NULL, 10);
        snprintf(E.udm_base, sizeof E.udm_base, "%s", u);
        snprintf(amf_sbi, sizeof amf_sbi, "%s", getenv("G5C_LOAD_AMF_SBI") != NULL ? getenv("G5C_LOAD_AMF_SBI") : "http://127.2.0.5:7777");
        snprintf(smf_sbi, sizeof smf_sbi, "%s", getenv("G5C_LOAD_SMF_SBI") != NULL ? getenv("G5C_LOAD_SMF_SBI") : "http://127.2.0.4:7776");
        snprintf(upf_sbi, sizeof upf_sbi, "%s", getenv("G5C_LOAD_UPF_SBI") != NULL ? getenv("G5C_LOAD_UPF_SBI") : "http://127.2.0.7:9091");
        {
            char tlserr[200] = "";
            E.cl = g5c_client_new_env(4000, tlserr, sizeof tlserr);
            if (E.cl == NULL)
                fprintf(stderr, "load: %s\n", tlserr);
        }
        TK_ASSERT(E.cl != NULL);
        TK_ASSERT(g5c_serving_network_name("001", "01", E.snn, sizeof E.snn) > 0);
        inet_pton(AF_INET, "127.0.0.1", E.gnb_ip4[0]);
        inet_pton(AF_INET, "127.0.0.2", E.gnb_ip4[1]);
        if (getenv("G5C_LOAD_ECHO") != NULL && getenv("G5C_LOAD_ECHO")[0] != 0) { /* downlink arrives at the gNBs' N3 addresses: one socket each */
            bind_gnb_udp(0, "127.0.0.1");
            bind_gnb_udp(1, "127.0.0.2");
        }
    } else {
        setup();
    }
    imsi_base = env_uint("G5C_LOAD_BASE", 0);
    if (getenv("G5C_LOAD_TRAFFIC_MBPS") != NULL && atof(getenv("G5C_LOAD_TRAFFIC_MBPS")) > 0) {
        TK_ASSERT(remote); /* the counters of the UPF's metrics are the measurement */
        traf_on = true;
        traf_mbps = atof(getenv("G5C_LOAD_TRAFFIC_MBPS"));
        traf_ms = (double)env_uint("G5C_LOAD_TRAFFIC_MS", 1000);
        traf_size = env_uint("G5C_LOAD_TRAFFIC_SIZE", 1000);
        traf_expect = getenv("G5C_LOAD_EXPECT_MBPS") != NULL ? atof(getenv("G5C_LOAD_EXPECT_MBPS")) : 0;
        if (getenv("G5C_LOAD_ECHO") != NULL && getenv("G5C_LOAD_ECHO")[0] != 0) {
            echo_ip = getenv("G5C_LOAD_ECHO");
            TK_ASSERT(n_gnbs <= 2); /* each gNB thread owns an N3 address */
        }
    }
    if (env_uint("G5C_LOAD_STORM_SECONDS", 0) != 0)
        return storm_main(n_ues, n_gnbs, env_uint("G5C_LOAD_STORM_SECONDS", 0));
    if (env_uint("G5C_LOAD_MOBILITY", 0) != 0)
        return mobility_main(n_ues, n_gnbs, env_uint("G5C_LOAD_MOBILITY", 0));
    if (env_uint("G5C_LOAD_CHAOS_SECONDS", 0) != 0)
        return chaos_main(n_ues, n_gnbs, env_uint("G5C_LOAD_CHAOS_SECONDS", 0));
    fds0 = open_fds();
    rss0 = rss_kb();

    printf("load: %u UEs over %u gNBs (provisioning...)\n", n_ues, n_gnbs);
    fflush(stdout);
    t_start = now_s();
    for (unsigned i = 0; i < n_ues; i++) {
        char imsi[16], js[200];
        imsi_of(imsi, sizeof imsi, i);
        snprintf(js, sizeof js, "{\"supi\":\"imsi-%s\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}", imsi);
        if (getenv("G5C_LOAD_NO_PROVISION") == NULL)
            provision(js);
    }
    printf("load: provisioned %u subscribers in %.1f s\n", n_ues, now_s() - t_start);
    fflush(stdout);

    th = g5c_xmalloc(sizeof *th * n_gnbs);
    w = g5c_xmalloc(sizeof *w * n_gnbs);
    t_reg = g5c_xmalloc(sizeof *t_reg * n_ues);
    t_pdu = g5c_xmalloc(sizeof *t_pdu * n_ues);
    t_dereg = g5c_xmalloc(sizeof *t_dereg * n_ues);
    per = n_ues / n_gnbs;
    rem = n_ues % n_gnbs;
    if (soak_end != 0)
        waves = 0xffffffffu;
    for (unsigned wave = 0; wave < waves; wave++) {
        next = 0;
        if (remote)
            settle_counts();
        b_amf = n_amf_ues(); /* the population already there (a run after a chaos run starts with leftovers) */
        b_smf = n_smf_sessions();
        b_upf = n_upf_sessions();
        want = n_ues;
        TK_ASSERT(pthread_barrier_init(&bar_registered, NULL, n_gnbs + 1) == 0);
        TK_ASSERT(pthread_barrier_init(&bar_release, NULL, n_gnbs + 1) == 0);
        TK_ASSERT(pthread_barrier_init(&bar_tgo, NULL, n_gnbs + 1) == 0);
        TK_ASSERT(pthread_barrier_init(&bar_tdone, NULL, n_gnbs + 1) == 0);
        t_start = now_s();
        for (unsigned i = 0; i < n_gnbs; i++) {
            w[i].idx = i;
            w[i].first = next;
            w[i].count = per + (i < rem ? 1 : 0);
            w[i].t_reg = t_reg + next;
            w[i].t_pdu = t_pdu + next;
            w[i].t_dereg = t_dereg + next;
            next += w[i].count;
            TK_ASSERT(pthread_create(&th[i], NULL, gnb_thread, &w[i]) == 0);
        }
        pthread_barrier_wait(&bar_registered);
        t_registered = now_s();
        if (rss_kb() > rss_peak)
            rss_peak = rss_kb();
        printf("load: wave %u: %u UEs registered with a PDU session each in %.1f s (%.0f UE/s); AMF holds %zu UE contexts, SMF %zu sessions, UPF %zu sessions\n",
               wave + 1, n_ues, t_registered - t_start, (double)n_ues / (t_registered - t_start), n_amf_ues(), n_smf_sessions(), n_upf_sessions());
        end = now_s() + 10;
        while (now_s() < end && (!count_is(n_amf_ues(), b_amf, want) || !count_is(n_smf_sessions(), b_smf, want) || !count_is(n_upf_sessions(), b_upf, want)))
            usleep(20000);
        TK_ASSERT(count_is(n_amf_ues(), b_amf, want));
        TK_ASSERT(count_is(n_smf_sessions(), b_smf, want));
        TK_ASSERT(count_is(n_upf_sessions(), b_upf, want));
        if (hold_ms > 0)
            usleep(hold_ms * 1000);
        if (traf_on) {
            const char *ul = "g5c_upf_bytes_total{direction=\"uplink\"}", *pk = "g5c_upf_packets_total{direction=\"uplink\"}", *dr = "g5c_upf_dropped_packets_total{reason=\"rate_limit\"}";
            long b0, b1, p0, p1, d0, d1;
            double secs, per_ue, offered_pkts;
            usleep(1500000); /* the UPF exports its counters once a second */
            b0 = scrape(upf_sbi, ul);
            p0 = scrape(upf_sbi, pk);
            d0 = scrape(upf_sbi, dr);
            pthread_barrier_wait(&bar_tgo);
            t_start = now_s();
            pthread_barrier_wait(&bar_tdone);
            secs = now_s() - t_start;
            usleep(1800000);
            b1 = scrape(upf_sbi, ul);
            p1 = scrape(upf_sbi, pk);
            d1 = scrape(upf_sbi, dr);
            per_ue = (double)(b1 - b0) * 8.0 / 1e6 / ((double)n_ues * traf_ms / 1000.0);
            offered_pkts = (double)n_ues * traf_mbps * 1e6 / 8.0 / (double)(traf_size < 60 ? 60 : traf_size > 1400 ? 1400 : traf_size) * traf_ms / 1000.0;
            printf("traffic: %u UEs x %.0f ms at %.2f Mbit/s offered each (%u octet packets, %.1f s wall): the UPF forwarded %ld octets in %ld packets = %.2f Mbit/s per UE, "
                   "its rate limiter dropped %ld packets (about %.0f offered)\n",
                   n_ues, traf_ms, traf_mbps, traf_size, secs, b1 - b0, p1 - p0, per_ue, d1 - d0, offered_pkts);
            if (echo_ip != NULL) {
                double loss = echo_sent > 0 ? 100.0 * (1.0 - (double)echo_recv / (double)echo_sent) : 100.0, avg = 0, jit = 0, p95 = 0, dl;
                double max_loss = getenv("G5C_LOAD_ECHO_MAX_LOSS_PCT") != NULL ? atof(getenv("G5C_LOAD_ECHO_MAX_LOSS_PCT")) : 101.0;
                double exp_dl = getenv("G5C_LOAD_EXPECT_DL_MBPS") != NULL ? atof(getenv("G5C_LOAD_EXPECT_DL_MBPS")) : 0;
                for (size_t i = 0; i < echo_nrtt; i++) {
                    avg += echo_rtt[i];
                    if (i > 0)
                        jit += echo_rtt[i] > echo_rtt[i - 1] ? echo_rtt[i] - echo_rtt[i - 1] : echo_rtt[i - 1] - echo_rtt[i];
                }
                if (echo_nrtt > 0) {
                    avg /= (double)echo_nrtt;
                    jit /= (double)(echo_nrtt > 1 ? echo_nrtt - 1 : 1);
                    qsort(echo_rtt, echo_nrtt, sizeof echo_rtt[0], cmp_d);
                    p95 = echo_rtt[(size_t)((double)(echo_nrtt - 1) * 0.95)];
                }
                dl = (double)echo_bytes * 8.0 / 1e6 / ((double)n_ues * traf_ms / 1000.0);
                printf("traffic: echo through the UPF: %lu sent, %lu came back as downlink (%.1f %% lost); round trip avg %.2f ms, p95 %.2f ms, jitter %.2f ms; downlink %.2f Mbit/s per UE\n", echo_sent,
                       echo_recv, loss, avg * 1e3, p95 * 1e3, jit * 1e3, dl);
                TK_ASSERT(loss <= max_loss);
                if (exp_dl > 0) {
                    bool dok = dl >= 0.5 * exp_dl && dl <= 1.3 * exp_dl;
                    printf("traffic: the downlink AMBR allows %.2f Mbit/s per UE: delivered %.2f Mbit/s (%.0f %%): %s\n", exp_dl, dl, 100.0 * dl / exp_dl, dok ? "ENFORCED" : "NOT ENFORCED");
                    TK_ASSERT(dok);
                }
            }
            if (traf_expect > 0) {
                bool ok = per_ue >= 0.5 * traf_expect && per_ue <= 1.3 * traf_expect;
                printf("traffic: the session AMBR allows %.2f Mbit/s per UE: delivered %.2f Mbit/s (%.0f %%): %s\n", traf_expect, per_ue, 100.0 * per_ue / traf_expect, ok ? "ENFORCED" : "NOT ENFORCED");
                TK_ASSERT(ok);
            }
        }
        pthread_barrier_wait(&bar_release);
        for (unsigned i = 0; i < n_gnbs; i++)
            pthread_join(th[i], NULL);
        t_end = now_s();
        end = now_s() + 20;
        while (now_s() < end && (!count_back(n_amf_ues(), b_amf) || !count_back(n_smf_sessions(), b_smf) || !count_back(n_upf_sessions(), b_upf)))
            usleep(20000);
        TK_ASSERT(count_back(n_amf_ues(), b_amf));
        TK_ASSERT(count_back(n_smf_sessions(), b_smf));
        TK_ASSERT(count_back(n_upf_sessions(), b_upf));
        pthread_barrier_destroy(&bar_registered);
        pthread_barrier_destroy(&bar_release);
        pthread_barrier_destroy(&bar_tgo);
        pthread_barrier_destroy(&bar_tdone);
        (void)malloc_trim(0); /* tell allocator retention (RSS stays high after a free) from a leak */
        rss_last = rss_kb();
        if (wave == 0)
            rss_first = rss_last;
        waves_done = wave + 1;
        printf("load: wave %u: de-registered %u UEs in %.1f s; AMF, SMF and UPF are empty; RSS after trim %ld kB\n", wave + 1, n_ues, t_end - t_registered,
               rss_last);
        fflush(stdout);
        if (getenv("G5C_LOAD_WAVE_HOOK") != NULL)
            (void)!system(getenv("G5C_LOAD_WAVE_HOOK"));
        if (soak_end != 0 && g5c_now_seconds() >= soak_end)
            break;
    }
    /* growth between the first and the last wave: allocator retention shows up in wave one only, a leak in every wave */
    if (waves_done >= 2) {
        long first = rss_first, last = rss_last;
        printf("load: RSS after wave 1 %ld kB, after wave %u %ld kB\n", first, waves_done, last);
        if (env_uint("G5C_LOAD_CHECK_MEM", 1) != 0)
            TK_ASSERT(last <= first + first / 10 + 16384);
    }

    {
        FILE *js = json_path != NULL ? fopen(json_path, "w") : NULL;
        printf("load: de-registered %u UEs in %.1f s; AMF, SMF and UPF are empty\n", n_ues, t_end - t_registered);
        if (js != NULL)
            fprintf(js, "{\n  \"ues\": %u, \"gnbs\": %u, \"register_seconds\": %.2f, \"ue_per_second\": %.1f, \"deregister_seconds\": %.2f,\n  \"latency\": {\n", n_ues,
                    n_gnbs, t_registered - t_start, (double)n_ues / (t_registered - t_start), t_end - t_registered);
        report("registration", t_reg, n_ues, js, false);
        report("pdu-session", t_pdu, n_ues, js, false);
        report("deregistration", t_dereg, n_ues, js, true);
        rss1 = rss_kb();
        fds1 = open_fds();
        printf("  RSS %ld kB -> peak %ld kB -> %ld kB after de-registration; open fds %ld -> %ld\n", rss0, rss_peak, rss1, fds0, fds1);
        if (js != NULL) {
            fprintf(js, "  },\n  \"rss_kb\": {\"start\": %ld, \"peak\": %ld, \"end\": %ld}, \"fds\": {\"start\": %ld, \"end\": %ld}\n}\n", rss0, rss_peak, rss1, fds0, fds1);
            fclose(js);
        }
    }
    /* the SBI clients keep a pool of connections per concurrent caller; the pool is bounded by the concurrency, not by the number of UEs */
    printf("  open fds after / before: %ld / %ld\n", fds1, fds0);
    TK_ASSERT(fds1 <= fds0 + 160 + 4L * n_gnbs);
    if (!remote)
        teardown();
    printf("load: PASS\n");
    free(th);
    free(w);
    free(t_reg);
    free(t_pdu);
    free(t_dereg);
    return 0;
}
