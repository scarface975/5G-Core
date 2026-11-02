/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "g5c/upf_rt.h"
#include "priv.h"

#define BATCH 32
#define PKT_BUF 2304
#define TUN_BUF 9300

struct upf_rt {
    upf *engine;
    upf_rt_config cfg;
    int ep, fd_n4, fd_n3, fd_n6, fd_timer, fd_stop;
    bool tun_owned;
    uint16_t port_n4, port_n3;
    g5c_registry *metrics;
    upf_stats last;
    double last_sync;
    uint64_t tx_drops;
    /* a copy of the engine's counters for other threads: refreshed after control-plane messages and on every timer tick */
    pthread_mutex_t pubmu;
    upf_stats pub;
    size_t pub_sessions;
    /* outgoing GTP-U packets are collected while a batch of input is processed and sent with one sendmmsg */
    struct mmsghdr txm[BATCH];
    struct iovec txv[BATCH];
    struct sockaddr_in txa[BATCH];
    uint8_t txb[BATCH][PKT_BUF];
    unsigned ntx;
};

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void upf_rt_config_defaults(upf_rt_config *c)
{
    memset(c, 0, sizeof *c);
    upf_config_defaults(&c->engine);
    snprintf(c->tun_dev, sizeof c->tun_dev, "ogstun");
    c->n6_fd = -1;
}

/* ---- I/O callbacks ----------------------------------------------------------------------------------------------------------------- */

static void sa_of(const upf_addr *a, struct sockaddr_in *sa)
{
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    memcpy(&sa->sin_addr, a->b, 4);
    sa->sin_port = htons(a->port);
}

static void flush_tx(upf_rt *rt)
{
    unsigned done = 0;
    while (done < rt->ntx) {
        int r = sendmmsg(rt->fd_n3, rt->txm + done, rt->ntx - done, MSG_DONTWAIT);
        if (r <= 0) { /* socket buffer full or an error: what is left is dropped, like any congested link would */
            rt->tx_drops += rt->ntx - done;
            break;
        }
        done += (unsigned)r;
    }
    rt->ntx = 0;
}

static void rt_tx_gtpu(void *ctx, const upf_addr *to, const uint8_t *p, size_t n)
{
    upf_rt *rt = ctx;
    unsigned i = rt->ntx;
    if (n > PKT_BUF) {
        rt->tx_drops++;
        return;
    }
    memcpy(rt->txb[i], p, n);
    sa_of(to, &rt->txa[i]);
    rt->txv[i].iov_base = rt->txb[i];
    rt->txv[i].iov_len = n;
    memset(&rt->txm[i], 0, sizeof rt->txm[i]);
    rt->txm[i].msg_hdr.msg_iov = &rt->txv[i];
    rt->txm[i].msg_hdr.msg_iovlen = 1;
    rt->txm[i].msg_hdr.msg_name = &rt->txa[i];
    rt->txm[i].msg_hdr.msg_namelen = sizeof rt->txa[i];
    rt->ntx = i + 1;
    if (rt->ntx == BATCH)
        flush_tx(rt);
}

static void rt_tx_n4(void *ctx, const upf_addr *to, const uint8_t *p, size_t n)
{
    upf_rt *rt = ctx;
    struct sockaddr_in sa;
    sa_of(to, &sa);
    if (sendto(rt->fd_n4, p, n, MSG_DONTWAIT, (struct sockaddr *)&sa, sizeof sa) < 0)
        rt->tx_drops++;
}

static void rt_tx_n6(void *ctx, const uint8_t *p, size_t n)
{
    upf_rt *rt = ctx;
    if (write(rt->fd_n6, p, n) < 0)
        rt->tx_drops++;
}

/* ---- setup ---------------------------------------------------------------------------------------------------------------------------- */

static int bind_udp(const upf_addr *a, uint16_t *port_out, char *err, size_t errcap, const char *what)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0), one = 1, big = 8 << 20;
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    if (fd < 0) {
        snprintf(err, errcap, "%s: socket: %s", what, strerror(errno));
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    sa_of(a, &sa);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        snprintf(err, errcap, "%s: cannot bind %u.%u.%u.%u:%u: %s", what, a->b[0], a->b[1], a->b[2], a->b[3], a->port, strerror(errno));
        close(fd);
        return -1;
    }
    if (getsockname(fd, (struct sockaddr *)&sa, &sl) == 0)
        *port_out = ntohs(sa.sin_port);
    return fd;
}

static int open_tun(const char *dev, char *err, size_t errcap)
{
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, errcap, "N6: cannot open /dev/net/tun: %s", strerror(errno));
        return -1;
    }
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        snprintf(err, errcap, "N6: cannot attach to TUN device %s: %s", dev, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int ep_add(int ep, int fd)
{
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = fd};
    return epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
}

upf_rt *upf_rt_new(const upf_rt_config *cfg, g5c_registry *metrics, char *err, size_t errcap)
{
    upf_rt *rt = g5c_xcalloc(1, sizeof *rt);
    pthread_mutex_init(&rt->pubmu, NULL);
    upf_io io = {rt, rt_tx_gtpu, rt_tx_n6, rt_tx_n4};
    struct itimerspec its = {{0, 20 * 1000 * 1000}, {0, 20 * 1000 * 1000}};
    upf_rt_config c = *cfg;
    rt->cfg = c;
    rt->metrics = metrics;
    rt->fd_n4 = rt->fd_n3 = rt->fd_n6 = rt->fd_timer = rt->fd_stop = rt->ep = -1;
    rt->fd_n4 = bind_udp(&c.engine.n4_addr, &rt->port_n4, err, errcap, "N4");
    if (rt->fd_n4 < 0)
        goto bad;
    rt->fd_n3 = bind_udp(&c.engine.n3_addr, &rt->port_n3, err, errcap, "N3");
    if (rt->fd_n3 < 0)
        goto bad;
    /* the addresses we advertise carry the port we really got (tests bind port 0) */
    c.engine.n4_addr.port = rt->port_n4;
    c.engine.n3_addr.port = rt->port_n3;
    if (c.n6_fd >= 0) {
        rt->fd_n6 = c.n6_fd;
        (void)fcntl(rt->fd_n6, F_SETFL, fcntl(rt->fd_n6, F_GETFL) | O_NONBLOCK);
    } else {
        rt->fd_n6 = open_tun(c.tun_dev, err, errcap);
        if (rt->fd_n6 < 0)
            goto bad;
        rt->tun_owned = true;
    }
    rt->fd_timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    rt->fd_stop = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    rt->ep = epoll_create1(EPOLL_CLOEXEC);
    if (rt->fd_timer < 0 || rt->fd_stop < 0 || rt->ep < 0 || timerfd_settime(rt->fd_timer, 0, &its, NULL) != 0 || ep_add(rt->ep, rt->fd_n4) != 0 ||
        ep_add(rt->ep, rt->fd_n3) != 0 || ep_add(rt->ep, rt->fd_n6) != 0 || ep_add(rt->ep, rt->fd_timer) != 0 || ep_add(rt->ep, rt->fd_stop) != 0) {
        snprintf(err, errcap, "event loop: %s", strerror(errno));
        goto bad;
    }
    rt->engine = upf_new(&c.engine, &io, metrics);
    return rt;
bad:
    upf_rt_free(rt);
    return NULL;
}

void upf_rt_free(upf_rt *rt)
{
    if (rt == NULL)
        return;
    upf_free(rt->engine);
    if (rt->fd_n4 >= 0)
        close(rt->fd_n4);
    if (rt->fd_n3 >= 0)
        close(rt->fd_n3);
    if (rt->fd_n6 >= 0 && rt->tun_owned)
        close(rt->fd_n6);
    if (rt->fd_timer >= 0)
        close(rt->fd_timer);
    if (rt->fd_stop >= 0)
        close(rt->fd_stop);
    if (rt->ep >= 0)
        close(rt->ep);
    pthread_mutex_destroy(&rt->pubmu);
    free(rt);
}

static void publish(upf_rt *rt)
{
    pthread_mutex_lock(&rt->pubmu);
    rt->pub = rt->engine->st;
    rt->pub_sessions = upf_session_count(rt->engine);
    pthread_mutex_unlock(&rt->pubmu);
}

void upf_rt_snapshot(upf_rt *rt, upf_stats *st, size_t *sessions)
{
    pthread_mutex_lock(&rt->pubmu);
    if (st != NULL)
        *st = rt->pub;
    if (sessions != NULL)
        *sessions = rt->pub_sessions;
    pthread_mutex_unlock(&rt->pubmu);
}

upf *upf_rt_engine(upf_rt *rt)
{
    return rt->engine;
}

uint16_t upf_rt_pfcp_port(const upf_rt *rt)
{
    return rt->port_n4;
}

uint16_t upf_rt_gtpu_port(const upf_rt *rt)
{
    return rt->port_n3;
}

void upf_rt_stop(upf_rt *rt)
{
    uint64_t one = 1;
    if (write(rt->fd_stop, &one, sizeof one) < 0) {
        /* nothing to do: the loop also notices the closed descriptor */
    }
}

/* ---- metrics ------------------------------------------------------------------------------------------------------------------------------ */

static void sync_metrics(upf_rt *rt)
{
    const upf_stats *s = &rt->engine->st;
    upf_stats *l = &rt->last;
    g5c_registry *m = rt->metrics;
    if (m == NULL)
        return;
#define PKTS(dir, field, bfield) \
    do { \
        g5c_label lab = {"direction", dir}; \
        g5c_counter_add(g5c_counter_get(m, "g5c_upf_packets_total", "User-plane packets forwarded.", &lab, 1), s->field - l->field); \
        g5c_counter_add(g5c_counter_get(m, "g5c_upf_bytes_total", "User-plane bytes forwarded.", &lab, 1), s->bfield - l->bfield); \
    } while (0)
    PKTS("uplink", ul_pkts, ul_bytes);
    PKTS("downlink", dl_pkts, dl_bytes);
#define DROP(reason, field) \
    do { \
        g5c_label lab = {"reason", reason}; \
        g5c_counter_add(g5c_counter_get(m, "g5c_upf_dropped_packets_total", "Packets dropped, by reason.", &lab, 1), s->field - l->field); \
    } while (0)
    DROP("no_session", drop_no_session);
    DROP("no_pdr", drop_no_pdr);
    DROP("far", drop_far);
    DROP("gate", drop_gate);
    DROP("rate_limit", drop_rate);
    DROP("spoofed_source", drop_spoof);
    DROP("malformed", drop_bad_packet);
    DROP("buffer_full_or_expired", drop_buffer);
    DROP("no_route", drop_no_route);
#define N4(type, field) \
    do { \
        g5c_label lab = {"direction", type}; \
        g5c_counter_add(g5c_counter_get(m, "g5c_upf_n4_messages_total", "PFCP messages.", &lab, 1), s->field - l->field); \
    } while (0)
    N4("rx", n4_rx);
    N4("tx", n4_tx);
    g5c_counter_add(g5c_counter_get(m, "g5c_upf_sessions_created_total", "PFCP sessions established.", NULL, 0), s->sessions_created - l->sessions_created);
    g5c_counter_add(g5c_counter_get(m, "g5c_upf_gtpu_error_indications_total", "GTP-U Error Indications sent.", NULL, 0), s->error_ind - l->error_ind);
    g5c_counter_add(g5c_counter_get(m, "g5c_upf_session_reports_total", "PFCP Session Report Requests sent.", NULL, 0), s->reports_sent - l->reports_sent);
    g5c_counter_add(g5c_counter_get(m, "g5c_upf_tx_failures_total", "Packets the kernel refused to send.", NULL, 0), rt->tx_drops);
    rt->tx_drops = 0;
    g5c_gauge_set(g5c_gauge_get(m, "g5c_upf_sessions", "PFCP sessions currently installed.", NULL, 0), (int64_t)upf_session_count(rt->engine));
    *l = *s;
}

/* ---- the loop ---------------------------------------------------------------------------------------------------------------------------- */

static void drain_gtpu(upf_rt *rt)
{
    static uint8_t bufs[BATCH][PKT_BUF];
    struct mmsghdr msgs[BATCH];
    struct iovec iov[BATCH];
    struct sockaddr_in names[BATCH];
    for (int round = 0; round < 8; round++) { /* bounded, so N4 and the TUN get their turn */
        int n;
        double now;
        memset(msgs, 0, sizeof msgs);
        for (int i = 0; i < BATCH; i++) {
            iov[i].iov_base = bufs[i];
            iov[i].iov_len = PKT_BUF;
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = &names[i];
            msgs[i].msg_hdr.msg_namelen = sizeof names[i];
        }
        n = recvmmsg(rt->fd_n3, msgs, BATCH, MSG_DONTWAIT, NULL);
        if (n <= 0)
            return;
        now = now_s();
        for (int i = 0; i < n; i++) {
            upf_addr from;
            memset(&from, 0, sizeof from);
            if (names[i].sin_family != AF_INET)
                continue;
            memcpy(from.b, &names[i].sin_addr, 4);
            from.port = ntohs(names[i].sin_port);
            upf_gtpu_packet(rt->engine, &from, bufs[i], msgs[i].msg_len, now);
        }
        flush_tx(rt);
        if (n < BATCH)
            return;
    }
}

static void drain_n4(upf_rt *rt)
{
    uint8_t buf[2048];
    for (int i = 0; i < 64; i++) {
        struct sockaddr_in sa;
        socklen_t sl = sizeof sa;
        upf_addr from;
        ssize_t n = recvfrom(rt->fd_n4, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&sa, &sl);
        if (n < 0)
            return;
        memset(&from, 0, sizeof from);
        memcpy(from.b, &sa.sin_addr, 4);
        from.port = ntohs(sa.sin_port);
        upf_n4_message(rt->engine, &from, buf, (size_t)n, now_s());
    }
    flush_tx(rt); /* buffered downlink packets released by a modification */
    publish(rt);
}

static void drain_n6(upf_rt *rt)
{
    static uint8_t buf[TUN_BUF];
    for (int i = 0; i < 256; i++) {
        ssize_t n = read(rt->fd_n6, buf, sizeof buf);
        if (n <= 0)
            return;
        upf_n6_packet(rt->engine, buf, (size_t)n, now_s());
    }
    flush_tx(rt);
}

int upf_rt_run(upf_rt *rt)
{
    struct epoll_event evs[16];
    bool stop = false;
    rt->last_sync = now_s();
    while (!stop) {
        int n = epoll_wait(rt->ep, evs, 16, 1000);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (fd == rt->fd_n3)
                drain_gtpu(rt);
            else if (fd == rt->fd_n6)
                drain_n6(rt);
            else if (fd == rt->fd_n4)
                drain_n4(rt);
            else if (fd == rt->fd_timer) {
                uint64_t exp;
                double now = now_s();
                if (read(rt->fd_timer, &exp, sizeof exp) < 0) {
                    /* spurious wake-up */
                }
                upf_tick(rt->engine, now);
                flush_tx(rt);
                publish(rt);
                if (now - rt->last_sync >= 1.0) {
                    sync_metrics(rt);
                    rt->last_sync = now;
                }
            } else if (fd == rt->fd_stop) {
                stop = true;
            }
        }
    }
    sync_metrics(rt);
    return 0;
}
