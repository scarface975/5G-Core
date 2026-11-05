/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* PFCP client side of N4 (TS 29.244) */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "g5c/gtpu.h"
#include "g5c/smf.h"

#define MAX_PENDING 128

struct smf_upf {
    smf_upf_cfg cfg;
    struct sockaddr_in addr;
    atomic_bool up;
    atomic_bool have_recovery;
    atomic_uint_fast32_t peer_recovery;
    unsigned hb_fail;
    double next_hb, next_assoc, down_since;
    bool lost_fired;
};

typedef struct {
    bool used, done;
    uint32_t seq;
    struct sockaddr_in peer;
    smf_n4_msg resp;
    pthread_cond_t cv;
} pending;

struct smf_n4 {
    int fd, gfd;
    uint16_t port;
    uint8_t local_ip4[4];
    smf_n4_cfg cfg;
    unsigned inject_seed;
    smf_upf *upfs;
    size_t n;
    pthread_mutex_t mu;
    pending pend[MAX_PENDING];
    atomic_uint_fast32_t seq;
    atomic_uint_fast64_t seid;
    uint32_t recovery_ts;
    pthread_t rx, hb;
    atomic_bool stop;
    smf_n4_hooks hooks;
    g5c_registry *metrics;
    size_t rr;
    bool started;
};

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static bool is_request(uint8_t t)
{
    switch (t) {
    case 1: case 3: case 5: case 7: case 9: case 12: case 14: case 50: case 52: case 54: case 56:
        return true;
    default:
        return false;
    }
}

static void count(smf_n4 *n, const char *name, const char *help, const char *k, const char *v)
{
    g5c_label l = {k, v};
    if (n->metrics != NULL)
        g5c_counter_inc(g5c_counter_get(n->metrics, name, help, k != NULL ? &l : NULL, k != NULL ? 1 : 0));
}

static smf_upf *upf_by_addr(smf_n4 *n, const struct sockaddr_in *a)
{
    for (size_t i = 0; i < n->n; i++)
        if (n->upfs[i].addr.sin_addr.s_addr == a->sin_addr.s_addr)
            return &n->upfs[i];
    return NULL;
}

static void send_raw(smf_n4 *n, const struct sockaddr_in *to, const uint8_t *p, size_t len)
{
    (void)sendto(n->fd, p, len, 0, (const struct sockaddr *)to, sizeof *to);
}

static void respond(smf_n4 *n, const struct sockaddr_in *to, uint8_t type, bool session, uint64_t seid, uint32_t seq, const uint8_t *body,
                    size_t blen)
{
    uint8_t out[256];
    size_t len;
    pfcp_header h;
    if (session)
        pfcp_header_session(&h, type, seid, seq);
    else
        pfcp_header_node(&h, type, seq);
    if (pfcp_encode(&h, body, blen, out, sizeof out, &len) == 0)
        send_raw(n, to, out, len);
}

static void node_id_body(smf_n4 *n, uint8_t *b, size_t cap, size_t *pos)
{
    pfcp_node_id id;
    memset(&id, 0, sizeof id);
    memcpy(id.ip4, n->local_ip4, 4);
    pfcp_node_id_put(b, cap, pos, &id);
}

/* association state transitions */
static void upf_mark_up(smf_n4 *n, smf_upf *u, uint32_t recovery, bool have_recovery)
{
    bool restarted = false, was_up;
    pthread_mutex_lock(&n->mu);
    was_up = u->up;
    if (have_recovery && atomic_load(&u->have_recovery) && atomic_load(&u->peer_recovery) != recovery)
        restarted = true;
    if (have_recovery) {
        atomic_store(&u->have_recovery, true);
        atomic_store(&u->peer_recovery, recovery);
    }
    u->up = true;
    u->down_since = 0;
    u->lost_fired = false;
    u->hb_fail = 0;
    u->next_hb = g5c_now_seconds() + n->cfg.hb_interval_s;
    pthread_mutex_unlock(&n->mu);
    if (!was_up)
        G5C_LOGI("g5c_smf", "N4 association with UPF %s established", u->cfg.name);
    if (restarted) {
        G5C_LOGW("g5c_smf", "UPF %s restarted (Recovery Time Stamp changed)", u->cfg.name);
        count(n, "g5c_smf_upf_restarts_total", "UPF restarts detected through the Recovery Time Stamp.", "upf", u->cfg.name);
        if (n->hooks.on_upf_event != NULL)
            n->hooks.on_upf_event(n->hooks.user, u, SMF_UPF_RESTART);
    }
}

static void upf_mark_down(smf_n4 *n, smf_upf *u, const char *why)
{
    bool was_up;
    pthread_mutex_lock(&n->mu);
    was_up = u->up;
    u->up = false;
    u->next_assoc = g5c_now_seconds() + 1;
    if (was_up) {
        u->down_since = g5c_now_seconds();
        u->lost_fired = false;
    }
    pthread_mutex_unlock(&n->mu);
    if (was_up) {
        G5C_LOGW("g5c_smf", "UPF %s is down: %s", u->cfg.name, why);
        count(n, "g5c_smf_upf_down_total", "UPF associations lost.", "upf", u->cfg.name);
        if (n->hooks.on_upf_event != NULL)
            n->hooks.on_upf_event(n->hooks.user, u, SMF_UPF_DOWN);
    }
}

/* requests from the UPF */
static void handle_request(smf_n4 *n, const struct sockaddr_in *from, const pfcp_header *h, const uint8_t *body, size_t blen)
{
    smf_upf *u = upf_by_addr(n, from);
    uint8_t b[128];
    size_t pos = 0;
    switch (h->msg_type) {
    case PFCP_HEARTBEAT_REQUEST:
        pfcp_put_u32(b, sizeof b, &pos, PFCP_IE_RECOVERY_TIME_STAMP, n->recovery_ts);
        respond(n, from, PFCP_HEARTBEAT_RESPONSE, false, 0, h->seq, b, pos);
        break;
    case PFCP_ASSOCIATION_SETUP_REQUEST: {
        uint32_t rec = 0;
        bool have = false;
        size_t p = 0;
        pfcp_ie ie;
        while (pfcp_ie_next(body, blen, &p, &ie) == 1)
            if (ie.typ == PFCP_IE_RECOVERY_TIME_STAMP && pfcp_get_u32(&ie, &rec) == 0)
                have = true;
        if (u == NULL || !have) { /* only configured UPFs may associate */
            pfcp_put_u8(b, sizeof b, &pos, PFCP_IE_CAUSE, PFCP_CAUSE_REJECTED);
        } else {
            pfcp_put_u8(b, sizeof b, &pos, PFCP_IE_CAUSE, PFCP_CAUSE_ACCEPTED);
            node_id_body(n, b, sizeof b, &pos);
            pfcp_put_u32(b, sizeof b, &pos, PFCP_IE_RECOVERY_TIME_STAMP, n->recovery_ts);
            upf_mark_up(n, u, rec, true);
        }
        respond(n, from, PFCP_ASSOCIATION_SETUP_RESPONSE, false, 0, h->seq, b, pos);
        break;
    }
    case PFCP_ASSOCIATION_RELEASE_REQUEST:
        pfcp_put_u8(b, sizeof b, &pos, PFCP_IE_CAUSE, PFCP_CAUSE_ACCEPTED);
        node_id_body(n, b, sizeof b, &pos);
        respond(n, from, PFCP_ASSOCIATION_RELEASE_RESPONSE, false, 0, h->seq, b, pos);
        if (u != NULL)
            upf_mark_down(n, u, "association released by the UPF");
        break;
    case PFCP_SESSION_REPORT_REQUEST: {
        uint8_t cause = PFCP_CAUSE_SESSION_NOT_FOUND;
        uint64_t up_seid = 0;
        if (u != NULL && h->has_seid && n->hooks.on_session_report != NULL)
            cause = n->hooks.on_session_report(n->hooks.user, u, h->seid, body, blen, &up_seid);
        pfcp_put_u8(b, sizeof b, &pos, PFCP_IE_CAUSE, cause);
        respond(n, from, PFCP_SESSION_REPORT_RESPONSE, true, up_seid, h->seq, b, pos);
        break;
    }
    default:
        break; /* PFD management, node report etc */
    }
}

static void handle_response(smf_n4 *n, const struct sockaddr_in *from, const pfcp_header *h, const uint8_t *body, size_t blen)
{
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < MAX_PENDING; i++) {
        pending *p = &n->pend[i];
        if (p->used && !p->done && p->seq == h->seq && p->peer.sin_addr.s_addr == from->sin_addr.s_addr && p->peer.sin_port == from->sin_port) {
            if (blen <= sizeof p->resp.body) {
                p->resp.h = *h;
                memcpy(p->resp.body, body, blen);
                p->resp.blen = blen;
                p->done = true;
                pthread_cond_broadcast(&p->cv);
            }
            break;
        }
    }
    pthread_mutex_unlock(&n->mu);
}

static void *rx_main(void *a)
{
    smf_n4 *n = a;
    uint8_t buf[4096];
    while (!atomic_load(&n->stop)) {
        struct pollfd pf[2] = {{n->fd, POLLIN, 0}, {n->gfd, POLLIN, 0}};
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t r;
        pfcp_header h;
        const uint8_t *body;
        size_t blen;
        if (poll(pf, n->gfd >= 0 ? 2 : 1, 100) <= 0)
            continue;
        if (n->gfd >= 0 && (pf[1].revents & POLLIN)) { /* a G-PDU forwarded by a UPF */
            gtpu_header gh;
            const uint8_t *pl;
            size_t plen;
            r = recvfrom(n->gfd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
            if (r > 0 && gtpu_decode(buf, (size_t)r, &gh, &pl, &plen) == 0 && gh.msg_type == GTPU_G_PDU && n->hooks.on_gtpu != NULL) {
                smf_peer peer;
                memcpy(peer.ip4, &from.sin_addr, 4);
                peer.port = ntohs(from.sin_port);
                n->hooks.on_gtpu(n->hooks.user, gh.teid, pl, plen, &peer);
            }
            continue;
        }
        if (!(pf[0].revents & POLLIN))
            continue;
        r = recvfrom(n->fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (r <= 0 || pfcp_decode(buf, (size_t)r, &h, &body, &blen) != 0) {
            if (r > 0)
                count(n, "g5c_smf_n4_malformed_total", "Malformed PFCP datagrams received.", NULL, NULL);
            continue;
        }
        if (is_request(h.msg_type)) {
            handle_request(n, &from, &h, body, blen);
        } else if (n->cfg.inject_drop_pct != 0 && (unsigned)(rand_r(&n->inject_seed) % 100) < n->cfg.inject_drop_pct) {
            count(n, "g5c_smf_injected_total", "Failures injected on purpose (smf.inject), by kind.", "kind", "n4_response_dropped"); /* the caller sees a timeout and retransmits */
        } else {
            handle_response(n, &from, &h, body, blen);
        }
    }
    return NULL;
}

/* ---- requests ---- */

static int call_ex(smf_n4 *n, smf_upf *u, uint8_t type, bool session, uint64_t seid, const uint8_t *body, size_t blen, smf_n4_msg *resp,
                   unsigned tries)
{
    uint8_t out[2400];
    size_t len, slot = MAX_PENDING;
    pfcp_header h;
    uint32_t seq = (uint32_t)(atomic_fetch_add(&n->seq, 1) & 0x7fffff) + 1;
    int rc = -1;
    memset(resp, 0, offsetof(smf_n4_msg, body)); /* a call that fails (UPF gone, timeout) leaves an empty response */
    resp->blen = 0;
    if (session)
        pfcp_header_session(&h, type, seid, seq);
    else
        pfcp_header_node(&h, type, seq);
    if (pfcp_encode(&h, body, blen, out, sizeof out, &len) != 0)
        return -1;
    pthread_mutex_lock(&n->mu);
    for (size_t i = 0; i < MAX_PENDING; i++)
        if (!n->pend[i].used) {
            slot = i;
            break;
        }
    if (slot == MAX_PENDING) {
        pthread_mutex_unlock(&n->mu);
        return -1;
    }
    n->pend[slot].used = true;
    n->pend[slot].done = false;
    n->pend[slot].seq = seq;
    n->pend[slot].peer = u->addr;
    pthread_mutex_unlock(&n->mu);

    for (unsigned t = 0; t < tries && rc != 0; t++) {
        struct timespec dl;
        send_raw(n, &u->addr, out, len);
        pthread_mutex_lock(&n->mu);
        clock_gettime(CLOCK_MONOTONIC, &dl);
        double t1 = g5c_real_wait(n->cfg.t1_ms / 1000.0); /* T1 is on the warped clock (backlog B-12): the real time to wait for a response */
        unsigned long t1_ns = (unsigned long)(t1 * 1e9);
        dl.tv_sec += (time_t)(t1_ns / 1000000000UL);
        dl.tv_nsec += (long)(t1_ns % 1000000000UL);
        if (dl.tv_nsec >= 1000000000L) {
            dl.tv_sec++;
            dl.tv_nsec -= 1000000000L;
        }
        while (!n->pend[slot].done) {
            if (pthread_cond_timedwait(&n->pend[slot].cv, &n->mu, &dl) == ETIMEDOUT)
                break;
        }
        if (n->pend[slot].done) {
            *resp = n->pend[slot].resp;
            rc = 0;
        }
        pthread_mutex_unlock(&n->mu);
        if (rc != 0 && t + 1 < tries)
            count(n, "g5c_smf_n4_retransmissions_total", "PFCP request retransmissions.", NULL, NULL);
    }
    pthread_mutex_lock(&n->mu);
    n->pend[slot].used = false;
    pthread_mutex_unlock(&n->mu);
    if (rc != 0)
        count(n, "g5c_smf_n4_timeouts_total", "PFCP requests that were never answered.", NULL, NULL);
    return rc;
}

int smf_n4_call(smf_n4 *n, smf_upf *u, uint8_t type, bool session, uint64_t seid, const uint8_t *body, size_t blen, smf_n4_msg *resp)
{
    return call_ex(n, u, type, session, seid, body, blen, resp, n->cfg.n1);
}

static bool assoc_setup(smf_n4 *n, smf_upf *u)
{
    uint8_t b[128];
    size_t pos = 0;
    smf_n4_msg r;
    size_t p = 0;
    pfcp_ie ie;
    uint32_t rec = 0;
    bool have = false, ok = false;
    node_id_body(n, b, sizeof b, &pos);
    pfcp_put_u32(b, sizeof b, &pos, PFCP_IE_RECOVERY_TIME_STAMP, n->recovery_ts);
    if (call_ex(n, u, PFCP_ASSOCIATION_SETUP_REQUEST, false, 0, b, pos, &r, 1) != 0)
        return false;
    while (pfcp_ie_next(r.body, r.blen, &p, &ie) == 1) {
        uint8_t c;
        if (ie.typ == PFCP_IE_CAUSE && pfcp_get_u8(&ie, &c) == 0)
            ok = c == PFCP_CAUSE_ACCEPTED;
        else if (ie.typ == PFCP_IE_RECOVERY_TIME_STAMP && pfcp_get_u32(&ie, &rec) == 0)
            have = true;
    }
    if (ok)
        upf_mark_up(n, u, rec, have);
    else
        G5C_LOGW("g5c_smf", "UPF %s refused the association", u->cfg.name);
    return ok;
}

static void *hb_main(void *a)
{
    smf_n4 *n = a;
    while (!atomic_load(&n->stop)) {
        double now = g5c_now_seconds(); /* virtual time: the heartbeat, association retry and lost-after timers follow the warp (backlog B-12) */
        for (size_t i = 0; i < n->n && !atomic_load(&n->stop); i++) {
            smf_upf *u = &n->upfs[i];
            bool up, due_assoc, due_hb, gone = false;
            pthread_mutex_lock(&n->mu);
            up = u->up;
            if (!up && !u->lost_fired && u->down_since > 0 && n->cfg.lost_after_s > 0 && now - u->down_since >= n->cfg.lost_after_s) {
                u->lost_fired = true;
                gone = true;
            }
            due_assoc = !up && now >= u->next_assoc;
            due_hb = up && n->cfg.hb_interval_s > 0 && now >= u->next_hb;
            if (due_assoc)
                u->next_assoc = now + 1;
            if (due_hb)
                u->next_hb = now + n->cfg.hb_interval_s;
            pthread_mutex_unlock(&n->mu);
            if (gone) {
                G5C_LOGW("g5c_smf", "UPF %s has been unreachable for %us: declared lost", u->cfg.name, n->cfg.lost_after_s);
                count(n, "g5c_smf_upf_lost_total", "UPFs declared lost after staying unreachable.", "upf", u->cfg.name);
                if (n->hooks.on_upf_event != NULL)
                    n->hooks.on_upf_event(n->hooks.user, u, SMF_UPF_LOST);
            }
            if (due_assoc) {
                assoc_setup(n, u);
            } else if (due_hb) {
                uint8_t b[16];
                size_t pos = 0;
                smf_n4_msg r;
                pfcp_put_u32(b, sizeof b, &pos, PFCP_IE_RECOVERY_TIME_STAMP, n->recovery_ts);
                if (call_ex(n, u, PFCP_HEARTBEAT_REQUEST, false, 0, b, pos, &r, 1) == 0) {
                    size_t p = 0;
                    pfcp_ie ie;
                    uint32_t rec = 0;
                    bool have = false;
                    while (pfcp_ie_next(r.body, r.blen, &p, &ie) == 1)
                        if (ie.typ == PFCP_IE_RECOVERY_TIME_STAMP && pfcp_get_u32(&ie, &rec) == 0)
                            have = true;
                    bool changed = have && atomic_load(&u->have_recovery) && atomic_load(&u->peer_recovery) != rec;
                    upf_mark_up(n, u, rec, have);
                    if (changed) { /* a restarted UPF has no association with us */
                        pthread_mutex_lock(&n->mu);
                        u->up = false;
                        u->next_assoc = 0;
                        pthread_mutex_unlock(&n->mu);
                    }
                } else {
                    bool lost;
                    pthread_mutex_lock(&n->mu);
                    lost = ++u->hb_fail >= (n->cfg.hb_failures == 0 ? 3 : n->cfg.hb_failures);
                    pthread_mutex_unlock(&n->mu);
                    if (lost)
                        upf_mark_down(n, u, "heartbeat lost");
                }
            }
        }
        {
            struct timespec ts = {0, 100000000L};
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

/* ---- lifecycle ---- */

smf_n4 *smf_n4_new(const smf_n4_cfg *cfg, const smf_n4_hooks *hooks, g5c_registry *metrics, char *err, size_t cap)
{
    smf_n4 *n = g5c_xcalloc(1, sizeof *n);
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    pthread_condattr_t ca;
    int one = 1;
    n->cfg = *cfg;
    if (n->cfg.t1_ms == 0)
        n->cfg.t1_ms = 1000;
    if (n->cfg.n1 == 0)
        n->cfg.n1 = 3;
    n->metrics = metrics;
    if (hooks != NULL)
        n->hooks = *hooks;
    pthread_mutex_init(&n->mu, NULL);
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    for (size_t i = 0; i < MAX_PENDING; i++)
        pthread_cond_init(&n->pend[i].cv, &ca);
    pthread_condattr_destroy(&ca);
    n->recovery_ts = pfcp_ntp_now();
    {
        uint64_t r = 0;
        g5c_random(&r, sizeof r);
        atomic_store(&n->seid, (r & 0x0000ffffffffffffULL) | 1);
        atomic_store(&n->seq, (uint32_t)(r >> 48));
    }
    n->gfd = -1;
    n->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (n->fd < 0) {
        snprintf(err, cap, "N4 socket: %s", strerror(errno));
        goto fail;
    }
    (void)setsockopt(n->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(cfg->port);
    if (inet_pton(AF_INET, cfg->address, &sa.sin_addr) != 1) {
        snprintf(err, cap, "N4 address `%s` is not an IPv4 address", cfg->address);
        goto fail;
    }
    memcpy(n->local_ip4, &sa.sin_addr, 4);
    if (bind(n->fd, (struct sockaddr *)&sa, sizeof sa) != 0 || getsockname(n->fd, (struct sockaddr *)&sa, &sl) != 0) {
        snprintf(err, cap, "N4 bind %s:%u: %s", cfg->address, cfg->port, strerror(errno));
        goto fail;
    }
    n->port = ntohs(sa.sin_port);
    if (cfg->gtpu_port != 0) { /* optional: only IPv6 sessions need it; a failure disables router advertisements */
        struct sockaddr_in ga = sa;
        n->gfd = socket(AF_INET, SOCK_DGRAM, 0);
        ga.sin_port = htons(cfg->gtpu_port);
        if (n->gfd >= 0 && (setsockopt(n->gfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 || bind(n->gfd, (struct sockaddr *)&ga, sizeof ga) != 0)) {
            G5C_LOGW("g5c_smf", "cannot bind GTP-U %s:%u (%s): IPv6 router advertisements are disabled", cfg->address, cfg->gtpu_port, strerror(errno));
            close(n->gfd);
            n->gfd = -1;
        }
    }
    n->n = cfg->nupfs;
    n->upfs = g5c_xcalloc(n->n == 0 ? 1 : n->n, sizeof *n->upfs);
    for (size_t i = 0; i < n->n; i++) {
        smf_upf *u = &n->upfs[i];
        u->cfg = cfg->upfs[i];
        u->cfg.dnns = NULL;
        u->cfg.ndnns = 0;
        for (size_t k = 0; k < cfg->upfs[i].ndnns; k++) {
            u->cfg.dnns = g5c_xrealloc(u->cfg.dnns, (u->cfg.ndnns + 1) * sizeof *u->cfg.dnns);
            u->cfg.dnns[u->cfg.ndnns++] = g5c_xstrdup(cfg->upfs[i].dnns[k]);
        }
        if (u->cfg.has_known_recovery) {
            atomic_store(&u->have_recovery, true);
            atomic_store(&u->peer_recovery, u->cfg.known_recovery);
        }
        u->addr.sin_family = AF_INET;
        u->addr.sin_port = htons(u->cfg.port == 0 ? 8805 : u->cfg.port);
        if (inet_pton(AF_INET, u->cfg.address, &u->addr.sin_addr) != 1) {
            snprintf(err, cap, "UPF `%s`: address `%s` is not an IPv4 address", u->cfg.name, u->cfg.address);
            goto fail;
        }
    }
    n->cfg.upfs = NULL; /* the copies above are authoritative */
    return n;
fail:
    if (n->fd >= 0)
        close(n->fd);
    for (size_t i = 0; i < n->n; i++) {
        for (size_t k = 0; k < n->upfs[i].cfg.ndnns; k++)
            free(n->upfs[i].cfg.dnns[k]);
        free(n->upfs[i].cfg.dnns);
    }
    free(n->upfs);
    free(n);
    return NULL;
}

int smf_n4_start(smf_n4 *n, char *err, size_t cap)
{
    if (n->started)
        return 0;
    if (pthread_create(&n->rx, NULL, rx_main, n) != 0) {
        snprintf(err, cap, "cannot start the N4 receive thread");
        return -1;
    }
    if (pthread_create(&n->hb, NULL, hb_main, n) != 0) {
        atomic_store(&n->stop, true);
        pthread_join(n->rx, NULL);
        snprintf(err, cap, "cannot start the N4 heartbeat thread");
        return -1;
    }
    n->started = true;
    return 0;
}

void smf_n4_free(smf_n4 *n)
{
    if (n == NULL)
        return;
    atomic_store(&n->stop, true);
    if (n->started) {
        pthread_join(n->hb, NULL);
        pthread_join(n->rx, NULL);
    }
    close(n->fd);
    if (n->gfd >= 0)
        close(n->gfd);
    for (size_t i = 0; i < n->n; i++) {
        for (size_t k = 0; k < n->upfs[i].cfg.ndnns; k++)
            free(n->upfs[i].cfg.dnns[k]);
        free(n->upfs[i].cfg.dnns);
    }
    for (size_t i = 0; i < MAX_PENDING; i++)
        pthread_cond_destroy(&n->pend[i].cv);
    pthread_mutex_destroy(&n->mu);
    free(n->upfs);
    free(n);
}

uint16_t smf_n4_port(const smf_n4 *n)
{
    return n->port;
}

size_t smf_n4_nupfs(const smf_n4 *n)
{
    return n->n;
}

smf_upf *smf_n4_upf(smf_n4 *n, size_t i)
{
    return i < n->n ? &n->upfs[i] : NULL;
}

const char *smf_upf_name(const smf_upf *u)
{
    return u->cfg.name;
}

bool smf_upf_up(const smf_upf *u)
{
    return u->up; /* advisory read; the transitions are serialised under the lock elsewhere */
}

int smf_n4_send_gtpu(smf_n4 *n, const smf_peer *to, uint32_t teid, const uint8_t *payload, size_t len)
{
    uint8_t out[1600];
    size_t ol = 0;
    gtpu_header h;
    struct sockaddr_in sa;
    if (n->gfd < 0)
        return -1;
    gtpu_header_init(&h, GTPU_G_PDU, teid);
    if (gtpu_encode(&h, payload, len, out, sizeof out, &ol) != 0)
        return -1;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    memcpy(&sa.sin_addr, to->ip4, 4);
    sa.sin_port = htons(to->port);
    return sendto(n->gfd, out, ol, 0, (struct sockaddr *)&sa, sizeof sa) == (ssize_t)ol ? 0 : -1;
}

void smf_n4_local_addr(const smf_n4 *n, uint8_t ip4[4])
{
    memcpy(ip4, n->local_ip4, 4);
}

uint64_t smf_n4_new_seid(smf_n4 *n)
{
    uint64_t v = atomic_fetch_add(&n->seid, 1);
    return v == 0 ? atomic_fetch_add(&n->seid, 1) : v;
}

uint32_t smf_n4_recovery(const smf_n4 *n)
{
    return n->recovery_ts;
}

void smf_n4_set_recovery(smf_n4 *n, uint32_t ts)
{
    if (!n->started)
        n->recovery_ts = ts;
}

void smf_n4_seed_seid(smf_n4 *n, uint64_t floor)
{
    uint64_t cur = atomic_load(&n->seid);
    while (cur < floor && !atomic_compare_exchange_weak(&n->seid, &cur, floor))
        ;
}

void smf_upf_set_known_recovery(smf_upf *u, uint32_t ts)
{
    atomic_store(&u->have_recovery, true);
    atomic_store(&u->peer_recovery, ts);
}

bool smf_upf_recovery(const smf_upf *u, uint32_t *ts)
{
    if (!atomic_load(&u->have_recovery))
        return false;
    *ts = (uint32_t)atomic_load(&u->peer_recovery);
    return true;
}

static bool serves(const smf_upf *u, const char *dnn, uint8_t sst, bool has_sd, uint32_t sd)
{
    bool ok = u->cfg.ndnns == 0;
    for (size_t i = 0; i < u->cfg.ndnns && !ok; i++)
        ok = strcmp(u->cfg.dnns[i], dnn) == 0;
    if (!ok)
        return false;
    if (u->cfg.nsnssai == 0)
        return true;
    for (size_t i = 0; i < u->cfg.nsnssai; i++)
        if (u->cfg.snssai[i].sst == sst && (!u->cfg.snssai[i].has_sd || (has_sd && u->cfg.snssai[i].sd == sd)))
            return true;
    return false;
}

smf_upf *smf_n4_select(smf_n4 *n, const char *dnn, uint8_t sst, bool has_sd, uint32_t sd)
{
    smf_upf *pick = NULL;
    pthread_mutex_lock(&n->mu);
    for (size_t k = 0; k < n->n && pick == NULL; k++) {
        smf_upf *u = &n->upfs[(n->rr + k) % n->n];
        if (u->up && serves(u, dnn, sst, has_sd, sd)) {
            pick = u;
            n->rr = (size_t)(u - n->upfs) + 1;
        }
    }
    pthread_mutex_unlock(&n->mu);
    return pick;
}

bool smf_n4_wait_up(smf_n4 *n, unsigned timeout_ms)
{
    double end = mono() + timeout_ms / 1000.0;
    for (;;) {
        bool all = true;
        pthread_mutex_lock(&n->mu);
        for (size_t i = 0; i < n->n; i++)
            all = all && n->upfs[i].up;
        pthread_mutex_unlock(&n->mu);
        if (all)
            return true;
        if (mono() >= end)
            return false;
        {
            struct timespec ts = {0, 20000000L};
            nanosleep(&ts, NULL);
        }
    }
}
