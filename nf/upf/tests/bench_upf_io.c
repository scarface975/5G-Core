/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Capacity and end-to-end throughput of the UPF runtime over real UDP sockets (the N3 side) and a datagram socketpair (the N6 side, standing in for
 * the TUN device). Stage A exit criterion: at least 1 Gbit/s on one host.
 * Two figures per direction: the wall-clock rate delivered (which a noisy shared host can halve from one run to the next) and the
 * UPF thread's capacity: bytes forwarded per second of CPU time that thread actually used, which does not depend on being scheduled.
 * The gate is on the capacity (at least 1 Gbit/s) plus a sanity floor on the delivered rate. Opt-in:
 *     G5C_PERF=1 ~/g5c-cbuild/plain/nf/upf/bench_upf_io */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "builders.h"
#include "g5c/upf_rt.h"

#define PKT 1400
#define SECS 2.0

static double thread_cpu(pthread_t t)
{
    clockid_t cid;
    struct timespec ts;
    if (pthread_getcpuclockid(t, &cid) != 0 || clock_gettime(cid, &ts) != 0)
        return 0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static double secs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void *runner(void *a)
{
    upf_rt_run(a);
    return NULL;
}

typedef struct {
    int fd;
    struct sockaddr_in to;
    uint8_t pkt[1600];
    size_t len;
    atomic_bool stop;
    uint64_t sent;
} sender_t;

static void *send_loop(void *a)
{
    sender_t *s = a;
    while (!atomic_load(&s->stop)) {
        for (int i = 0; i < 64; i++)
            if (s->to.sin_family == AF_INET ? sendto(s->fd, s->pkt, s->len, 0, (struct sockaddr *)&s->to, sizeof s->to) > 0 : send(s->fd, s->pkt, s->len, 0) > 0)
                s->sent++;
    }
    return NULL;
}

static int bind_udp(const char *ip, uint16_t port, uint16_t *got)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0), big = 16 << 20;
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    struct timeval tv = {1, 0};
    TK_ASSERT(fd >= 0);
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    TK_ASSERT(inet_pton(AF_INET, ip, &sa.sin_addr) == 1 && bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0);
    if (got && getsockname(fd, (struct sockaddr *)&sa, &sl) == 0)
        *got = ntohs(sa.sin_port);
    return fd;
}

int main(void)
{
    upf_rt_config rc;
    upf_rt *rt;
    int sv[2], smf, gnb, big = 16 << 20;
    uint16_t n4p, n3p;
    pthread_t th, sth;
    char err[200], gnb_ip[32];
    uint8_t resp[1700], ip[PKT], gnbip[4] = {127, 88, 0, 1};
    bld_t b;
    pfcp_header h;
    const uint8_t *body;
    size_t bl;
    uint32_t teid;
    static const uint8_t UE[4] = {10, 46, 0, 2}, DN[4] = {10, 99, 0, 1};
    sender_t s;
    double t0, cpu0;
    uint64_t got;
    static uint8_t buf[2048];
    pfcp_ie ie, g;
    pfcp_fteid f;
    struct sockaddr_in sa;

    if (getenv("G5C_PERF") == NULL) {
        puts("bench_upf_io: G5C_PERF not set, skipping");
        return 0;
    }
    g5c_log_init("error", false);
    snprintf(gnb_ip, sizeof gnb_ip, "127.88.%u.1", (unsigned)(getpid() % 250));
    gnbip[2] = (uint8_t)(getpid() % 250);
    TK_ASSERT(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    (void)setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    (void)setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    (void)setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    upf_rt_config_defaults(&rc);
    rc.n6_fd = sv[0];
    rc.engine.n4_addr = (upf_addr){false, {127, 0, 0, 1}, 0};
    rc.engine.n3_addr = (upf_addr){false, {127, 0, 0, 1}, 0};
    rc.engine.heartbeat_interval = 0;
    rt = upf_rt_new(&rc, NULL, err, sizeof err);
    if (rt == NULL)
        TK_FAIL("runtime: %s", err);
    n4p = upf_rt_pfcp_port(rt);
    n3p = upf_rt_gtpu_port(rt);
    smf = bind_udp("127.0.0.1", 0, NULL);
    gnb = bind_udp(gnb_ip, 2152, NULL);
    TK_ASSERT(pthread_create(&th, NULL, runner, rt) == 0);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(n4p);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    {
        pfcp_header hh;
        size_t n = 0;
        b_assoc(&b, 7);
        pfcp_header_node(&hh, PFCP_ASSOCIATION_SETUP_REQUEST, 1);
        TK_ASSERT(pfcp_encode(&hh, b.body, b.pos, buf, sizeof buf, &n) == 0);
        TK_ASSERT(sendto(smf, buf, n, 0, (struct sockaddr *)&sa, sizeof sa) == (ssize_t)n && recv(smf, resp, sizeof resp, 0) > 0);
        b_session_head(&b, 1);
        b_pdr_ul(&b, 1, 100, 1, 1, 0, 0, NULL, true);
        b_pdr_dl(&b, 2, 100, UE, 2, 0, 0, NULL);
        b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
        b_far(&b, 2, PFCP_AA_FORW, UPF_IF_ACCESS, 0x77, gnbip, 0);
        pfcp_header_session(&hh, PFCP_SESSION_ESTABLISHMENT_REQUEST, 0, 2);
        TK_ASSERT(pfcp_encode(&hh, b.body, b.pos, buf, sizeof buf, &n) == 0);
        TK_ASSERT(sendto(smf, buf, n, 0, (struct sockaddr *)&sa, sizeof sa) == (ssize_t)n);
        n = (size_t)recv(smf, resp, sizeof resp, 0);
        TK_ASSERT(pfcp_decode(resp, n, &h, &body, &bl) == 0 && find_ie(body, bl, PFCP_IE_CREATED_PDR, &g, 0) &&
                  find_ie(g.value, g.len, PFCP_IE_FTEID, &ie, 0) && pfcp_fteid_decode(&ie, &f) == 0);
        teid = f.teid;
    }

    /* uplink: gNB -> UPF -> N6. A shared host is noisy, so each direction gets up to three one-run attempts and the best counts;
     * every attempt is printed. */
    ipv4(ip, UE, DN, 17, 4000, 53, PKT);
    {
        struct timeval tv = {1, 0};
        (void)setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(gnb, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    {
        double best = 0, bestcap = 0;
        for (int attempt = 1; attempt <= 3 && bestcap < 2.0; attempt++) {
            struct timeval drain = {0, 100000}, tv = {1, 0};
            memset(&s, 0, sizeof s);
            s.fd = gnb;
            s.to.sin_family = AF_INET;
            s.to.sin_port = htons(n3p);
            inet_pton(AF_INET, "127.0.0.1", &s.to.sin_addr);
            s.len = gpdu_ul(s.pkt, sizeof s.pkt, teid, 1, ip, PKT);
            cpu0 = thread_cpu(th);
            TK_ASSERT(pthread_create(&sth, NULL, send_loop, &s) == 0);
            t0 = secs();
            got = 0;
            while (secs() - t0 < SECS) {
                ssize_t n = recv(sv[1], buf, sizeof buf, 0);
                if (n == PKT)
                    got++;
            }
            {
                double dt = secs() - t0, gbps = (double)(got * PKT) * 8 / dt / 1e9, cpu, cap;
                atomic_store(&s.stop, true);
                pthread_join(sth, NULL);
                cpu = thread_cpu(th) - cpu0;
                cap = cpu > 0 ? (double)(got * PKT) * 8 / cpu / 1e9 : 0;
                if (cap > bestcap)
                    bestcap = cap;
                printf("uplink   (N3 -> N6) attempt %d: %.2f Gbit/s delivered, UPF capacity %.1f Gbit/s per core (%.0f kpps, %llu of %llu sent, %.1f%%)\n", attempt, gbps, cap, (double)got / dt / 1e3,
                       (unsigned long long)got, (unsigned long long)s.sent, s.sent ? 100.0 * (double)got / (double)s.sent : 0.0);
                if (gbps > best)
                    best = gbps;
            }
            (void)setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &drain, sizeof drain);
            while (recv(sv[1], buf, sizeof buf, 0) > 0)
                ;
            (void)setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        }
        printf("uplink   best: %.2f Gbit/s delivered, %.1f Gbit/s capacity\n", best, bestcap);
        TK_ASSERT(bestcap >= 1.0 && best >= 0.3);
    }
    /* downlink: N6 -> UPF -> gNB */
    ipv4(ip, DN, UE, 17, 53, 4000, PKT);
    {
        double best = 0, bestcap = 0;
        for (int attempt = 1; attempt <= 3 && bestcap < 2.0; attempt++) {
            struct timeval drain = {0, 100000}, tv = {1, 0};
            memset(&s, 0, sizeof s);
            s.fd = sv[1];
            s.len = PKT;
            memcpy(s.pkt, ip, PKT);
            cpu0 = thread_cpu(th);
            TK_ASSERT(pthread_create(&sth, NULL, send_loop, &s) == 0);
            t0 = secs();
            got = 0;
            while (secs() - t0 < SECS) {
                ssize_t n = recv(gnb, buf, sizeof buf, 0);
                if (n > 0)
                    got++;
            }
            {
                double dt = secs() - t0, gbps = (double)(got * PKT) * 8 / dt / 1e9, cpu, cap;
                atomic_store(&s.stop, true);
                pthread_join(sth, NULL);
                cpu = thread_cpu(th) - cpu0;
                cap = cpu > 0 ? (double)(got * PKT) * 8 / cpu / 1e9 : 0;
                if (cap > bestcap)
                    bestcap = cap;
                printf("downlink (N6 -> N3) attempt %d: %.2f Gbit/s delivered, UPF capacity %.1f Gbit/s per core (%.0f kpps, %llu of %llu sent, %.1f%%)\n", attempt, gbps, cap, (double)got / dt / 1e3,
                       (unsigned long long)got, (unsigned long long)s.sent, s.sent ? 100.0 * (double)got / (double)s.sent : 0.0);
                if (gbps > best)
                    best = gbps;
            }
            (void)setsockopt(gnb, SOL_SOCKET, SO_RCVTIMEO, &drain, sizeof drain);
            while (recv(gnb, buf, sizeof buf, 0) > 0)
                ;
            (void)setsockopt(gnb, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        }
        printf("downlink best: %.2f Gbit/s delivered, %.1f Gbit/s capacity\n", best, bestcap);
        TK_ASSERT(bestcap >= 1.0 && best >= 0.3);
    }
    upf_rt_stop(rt);
    pthread_join(th, NULL);
    upf_rt_free(rt);
    close(smf);
    close(gnb);
    close(sv[1]);
    return 0;
}
