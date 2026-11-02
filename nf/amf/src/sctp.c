/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The N2 transport: a kernel SCTP endpoint (one-to-one style sockets, PPID 60, RFC 6458 ancillary data) with one reader thread. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include "sctp_abi.h"
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include "priv.h"

#define RX_MAX 65536
#define ID_LISTEN UINT64_MAX
#define ID_WAKE (UINT64_MAX - 1)

static uint64_t ev_id(uint32_t idx, uint32_t gen)
{
    return (uint64_t)gen << 32 | idx;
}

static void set_opt_int(int fd, int level, int name, int v)
{
    (void)setsockopt(fd, level, name, &v, sizeof v);
}

/* N2 is a low-rate signalling association: acknowledge every packet at once */
static void set_sack(int fd)
{
    struct sctp_sack_info si = {0, 1, 1};
    (void)setsockopt(fd, IPPROTO_SCTP, SCTP_DELAYED_SACK, &si, sizeof si);
}

static bool addr_parse(const char *s, uint16_t port, struct sockaddr_storage *ss, socklen_t *len)
{
    struct sockaddr_in *a4 = (struct sockaddr_in *)ss;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)ss;
    memset(ss, 0, sizeof *ss);
    if (inet_pton(AF_INET, s, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port = htons(port);
        *len = sizeof *a4;
        return true;
    }
    if (inet_pton(AF_INET6, s, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port);
        *len = sizeof *a6;
        return true;
    }
    return false;
}

static void peer_name(const struct sockaddr_storage *ss, char *out, size_t cap)
{
    char host[INET6_ADDRSTRLEN] = "?";
    uint16_t port = 0;
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)ss;
        inet_ntop(AF_INET, &a->sin_addr, host, sizeof host);
        port = ntohs(a->sin_port);
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)ss;
        inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof host);
        port = ntohs(a->sin6_port);
    }
    snprintf(out, cap, "%s:%u", host, port);
}

int amf_gnb_send(amf *a, uint32_t gnb, uint32_t gen, uint16_t stream, const uint8_t *buf, size_t len)
{
    amf_gnb *g;
    struct msghdr mh;
    struct iovec iov;
    char cbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo))];
    struct cmsghdr *cm;
    struct sctp_sndinfo si;
    int rc = -1;
    if (gnb >= AMF_MAX_GNB)
        return -1;
    g = &a->gnbs[gnb];
    pthread_mutex_lock(&g->smu);
    if (g->used && g->gen == gen && g->fd >= 0) {
        memset(&mh, 0, sizeof mh);
        memset(cbuf, 0, sizeof cbuf);
        iov.iov_base = (void *)(uintptr_t)buf;
        iov.iov_len = len;
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
        si.snd_ppid = htonl(AMF_PPID_NGAP);
        memcpy(CMSG_DATA(cm), &si, sizeof si);
        for (int tries = 0; tries < 50; tries++) {
            ssize_t n = sendmsg(g->fd, &mh, MSG_NOSIGNAL);
            if (n == (ssize_t)len) {
                rc = 0;
                break;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                struct pollfd p = {g->fd, POLLOUT, 0};
                (void)poll(&p, 1, 100);
                continue;
            }
            break;
        }
    }
    pthread_mutex_unlock(&g->smu);
    return rc;
}

int amf_send_pdu(amf *a, uint32_t gnb, uint32_t gen, uint16_t stream, const g5c_json *pdu)
{
    g5c_bytes b;
    char err[160];
    int rc;
    g5c_bytes_init(&b);
    if (ngap_encode(pdu, &b, err, sizeof err) != 0) {
        G5C_LOGE(AMF_LOG, "cannot encode an NGAP PDU: %s", err);
        g5c_bytes_free(&b);
        return -1;
    }
    rc = amf_gnb_send(a, gnb, gen, stream, b.data, b.len);
    g5c_bytes_free(&b);
    return rc;
}

/* Called from the reader thread only. */
static void gnb_close(amf *a, uint32_t idx)
{
    amf_gnb *g = &a->gnbs[idx];
    pthread_mutex_lock(&g->smu);
    if (g->used) {
        (void)epoll_ctl(a->epfd, EPOLL_CTL_DEL, g->fd, NULL);
        close(g->fd);
        g->fd = -1;
        pthread_mutex_lock(&a->tmu);
        g->used = false;
        g->gen++;
        pthread_mutex_unlock(&a->tmu);
    }
    pthread_mutex_unlock(&g->smu);
    pthread_mutex_lock(&a->tmu);
    g->setup = false;
    g->ntas = 0;
    free(g->rxbuf);
    g->rxbuf = NULL;
    g->rxlen = 0;
    pthread_mutex_unlock(&a->tmu);
}

void amf_gnb_drop(amf *a, uint32_t gnb)
{
    /* shut the association down; the reader notices the close and cleans up */
    amf_gnb *g = &a->gnbs[gnb];
    pthread_mutex_lock(&g->smu);
    if (g->used && g->fd >= 0)
        shutdown(g->fd, SHUT_RDWR);
    pthread_mutex_unlock(&g->smu);
}

static void accept_one(amf *a)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int fd = accept4(a->lfd, (struct sockaddr *)&ss, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
    uint32_t idx = AMF_MAX_GNB;
    struct epoll_event ev;
    if (fd < 0)
        return;
    pthread_mutex_lock(&a->tmu);
    for (uint32_t i = 0; i < AMF_MAX_GNB; i++)
        if (!a->gnbs[i].used) {
            idx = i;
            break;
        }
    pthread_mutex_unlock(&a->tmu);
    if (idx == AMF_MAX_GNB) {
        G5C_LOGW(AMF_LOG, "no free gNB slot: association refused");
        close(fd);
        return;
    }
    set_opt_int(fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, 1);
    set_opt_int(fd, IPPROTO_SCTP, SCTP_NODELAY, 1);
    set_sack(fd);
    {
        amf_gnb *g = &a->gnbs[idx];
        pthread_mutex_lock(&g->smu);
        g->fd = fd;
        pthread_mutex_lock(&a->tmu);
        g->used = true;
        pthread_mutex_unlock(&a->tmu);
        peer_name(&ss, g->peer, sizeof g->peer);
        pthread_mutex_unlock(&g->smu);
        pthread_mutex_lock(&a->tmu);
        g->setup = false;
        g->ntas = 0;
        g->nconns = 0;
        g->name[0] = 0;
        pthread_mutex_unlock(&a->tmu);
        G5C_LOGI(AMF_LOG, "N2 association from %s accepted (slot %u)", g->peer, idx);
        memset(&ev, 0, sizeof ev);
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.u64 = ev_id(idx, g->gen);
        if (epoll_ctl(a->epfd, EPOLL_CTL_ADD, fd, &ev) != 0)
            gnb_close(a, idx);
    }
}

static void read_gnb(amf *a, uint32_t idx, uint32_t gen)
{
    amf_gnb *g = &a->gnbs[idx];
    static __thread uint8_t buf[RX_MAX];
    if (!g->used || g->gen != gen)
        return;
    for (;;) {
        struct msghdr mh;
        struct iovec iov = {buf, sizeof buf};
        char cbuf[CMSG_SPACE(sizeof(struct sctp_rcvinfo)) + 64];
        ssize_t n;
        uint16_t stream = 0;
        memset(&mh, 0, sizeof mh);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = cbuf;
        mh.msg_controllen = sizeof cbuf;
        n = recvmsg(g->fd, &mh, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            if (errno == EINTR)
                continue;
            G5C_LOGI(AMF_LOG, "N2 association %s: read error %s", g->peer, strerror(errno));
            gnb_close(a, idx);
            ngap_gnb_lost(a, idx);
            return;
        }
        if (n == 0) {
            G5C_LOGI(AMF_LOG, "N2 association %s closed", g->peer);
            gnb_close(a, idx);
            ngap_gnb_lost(a, idx);
            return;
        }
        if (mh.msg_flags & MSG_NOTIFICATION)
            continue;
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm != NULL; cm = CMSG_NXTHDR(&mh, cm))
            if (cm->cmsg_level == IPPROTO_SCTP && cm->cmsg_type == SCTP_RCVINFO) {
                struct sctp_rcvinfo ri;
                memcpy(&ri, CMSG_DATA(cm), sizeof ri);
                stream = ri.rcv_sid;
            }
        if (!(mh.msg_flags & MSG_EOR)) { /* a message larger than our buffer */
            G5C_LOGW(AMF_LOG, "N2 association %s sent an oversized message: closing", g->peer);
            gnb_close(a, idx);
            ngap_gnb_lost(a, idx);
            return;
        }
        ngap_reader_dispatch(a, idx, gen, stream, buf, (size_t)n);
        if (!g->used || g->gen != gen)
            return;
    }
}

static void *reader_main(void *arg)
{
    amf *a = arg;
    struct epoll_event evs[32];
    while (!a->stop) {
        int n = epoll_wait(a->epfd, evs, 32, 500);
        for (int i = 0; i < n; i++) {
            uint64_t id = evs[i].data.u64;
            if (id == ID_LISTEN) {
                accept_one(a);
            } else if (id == ID_WAKE) {
                uint64_t v;
                (void)!read(a->wakefd, &v, sizeof v);
            } else {
                uint32_t idx = (uint32_t)(id & 0xffffffffu), gen = (uint32_t)(id >> 32);
                if (idx < AMF_MAX_GNB)
                    read_gnb(a, idx, gen);
            }
        }
    }
    return NULL;
}

int amf_sctp_start(amf *a, char *err, size_t cap)
{
    struct sockaddr_storage ss;
    socklen_t sl;
    struct epoll_event ev;
    int fd;
    if (!addr_parse(a->cfg.ngap_addr, a->cfg.ngap_port, &ss, &sl)) {
        snprintf(err, cap, "invalid NGAP address `%s`", a->cfg.ngap_addr);
        return -1;
    }
    fd = socket(ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_SCTP);
    if (fd < 0) {
        snprintf(err, cap, "cannot create an SCTP socket: %s (is the kernel's SCTP support loaded?)", strerror(errno));
        return -1;
    }
    set_opt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1);
    set_opt_int(fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, 1);
    set_opt_int(fd, IPPROTO_SCTP, SCTP_NODELAY, 1);
    set_sack(fd);
    if (bind(fd, (struct sockaddr *)&ss, sl) != 0 || listen(fd, 64) != 0) {
        snprintf(err, cap, "cannot listen on %s:%u (SCTP): %s", a->cfg.ngap_addr, a->cfg.ngap_port, strerror(errno));
        close(fd);
        return -1;
    }
    {
        struct sockaddr_storage bs;
        socklen_t bl = sizeof bs;
        if (getsockname(fd, (struct sockaddr *)&bs, &bl) == 0)
            a->bound_port = ntohs(bs.ss_family == AF_INET ? ((struct sockaddr_in *)&bs)->sin_port : ((struct sockaddr_in6 *)&bs)->sin6_port);
    }
    a->lfd = fd;
    a->epfd = epoll_create1(EPOLL_CLOEXEC);
    a->wakefd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (a->epfd < 0 || a->wakefd < 0) {
        snprintf(err, cap, "epoll: %s", strerror(errno));
        close(fd);
        return -1;
    }
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    ev.data.u64 = ID_LISTEN;
    (void)epoll_ctl(a->epfd, EPOLL_CTL_ADD, fd, &ev);
    ev.data.u64 = ID_WAKE;
    (void)epoll_ctl(a->epfd, EPOLL_CTL_ADD, a->wakefd, &ev);
    if (pthread_create(&a->reader, NULL, reader_main, a) != 0) {
        snprintf(err, cap, "cannot start the N2 reader thread");
        return -1;
    }
    a->reader_on = true;
    G5C_LOGI(AMF_LOG, "N2 (SCTP) listening on %s:%u", a->cfg.ngap_addr, a->bound_port);
    return 0;
}

void amf_sctp_stop(amf *a)
{
    if (a->reader_on) {
        uint64_t one = 1;
        a->stop = true;
        (void)!write(a->wakefd, &one, sizeof one);
        pthread_join(a->reader, NULL);
        a->reader_on = false;
    }
    for (uint32_t i = 0; i < AMF_MAX_GNB; i++) {
        amf_gnb *g = &a->gnbs[i];
        if (g->used) {
            close(g->fd);
            g->used = false;
            g->fd = -1;
        }
        free(g->rxbuf);
        g->rxbuf = NULL;
    }
    if (a->lfd > 0)
        close(a->lfd);
    if (a->epfd > 0)
        close(a->epfd);
    if (a->wakefd > 0)
        close(a->wakefd);
    a->lfd = a->epfd = a->wakefd = -1;
}
