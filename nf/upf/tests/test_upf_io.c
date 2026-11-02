/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The UPF runtime over real sockets: an SMF, a gNB and a data network talk to it through UDP and a datagram socketpair (standing in
 * for the TUN device, so no privileges are needed). */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "builders.h"
#include "g5c/upf_rt.h"

static int udp_socket(const char *ip, uint16_t port, uint16_t *got)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0), one = 1;
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    struct timeval tv = {2, 0};
    TK_ASSERT(fd >= 0);
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    TK_ASSERT(inet_pton(AF_INET, ip, &sa.sin_addr) == 1);
    TK_ASSERT(bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0);
    if (got) {
        TK_ASSERT(getsockname(fd, (struct sockaddr *)&sa, &sl) == 0);
        *got = ntohs(sa.sin_port);
    }
    return fd;
}

static void send_to(int fd, const char *ip, uint16_t port, const uint8_t *p, size_t n)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    TK_ASSERT(inet_pton(AF_INET, ip, &sa.sin_addr) == 1);
    TK_ASSERT(sendto(fd, p, n, 0, (struct sockaddr *)&sa, sizeof sa) == (ssize_t)n);
}

static void *runner(void *a)
{
    upf_rt_run(a);
    return NULL;
}

/* one PFCP request/response round trip */
static size_t n4_call(int fd, uint16_t port, uint8_t type, bool session, uint64_t seid, const bld_t *b, uint8_t *resp, size_t cap)
{
    uint8_t out[1700];
    size_t n = 0;
    ssize_t r;
    pfcp_header h;
    static uint32_t seq = 1;
    if (session)
        pfcp_header_session(&h, type, seid, seq++);
    else
        pfcp_header_node(&h, type, seq++);
    TK_ASSERT(pfcp_encode(&h, b->body, b->pos, out, sizeof out, &n) == 0);
    send_to(fd, "127.0.0.1", port, out, n);
    r = recv(fd, resp, cap, 0);
    TK_ASSERT(r > 0);
    return (size_t)r;
}

int main(void)
{
    upf_rt_config rc;
    upf_rt *rt;
    g5c_registry *m = g5c_registry_new();
    int sv[2], smf, gnb, dn;
    uint16_t smf_port, gnb_port = 2152, n4p, n3p;
    pthread_t th;
    char err[200], gnb_ip[32];
    uint8_t resp[1700], pkt[1500], ip[200];
    size_t rn;
    bld_t b;
    pfcp_header h;
    const uint8_t *body;
    size_t bl;
    uint32_t teid = 0;
    uint64_t useid = 0;
    static const uint8_t UE[4] = {10, 46, 0, 2}, DNIP[4] = {10, 99, 0, 1};
    uint8_t gnbip[4] = {127, 88, 0, 1};

    snprintf(gnb_ip, sizeof gnb_ip, "127.88.%u.1", (unsigned)(getpid() % 250));
    gnbip[2] = (uint8_t)(getpid() % 250);
    TK_ASSERT(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    upf_rt_config_defaults(&rc);
    rc.n6_fd = sv[0];
    rc.engine.n4_addr = (upf_addr){false, {127, 0, 0, 1}, 0};
    rc.engine.n3_addr = (upf_addr){false, {127, 0, 0, 1}, 0};
    rc.engine.heartbeat_interval = 0;
    rt = upf_rt_new(&rc, m, err, sizeof err);
    if (rt == NULL)
        TK_FAIL("runtime: %s", err);
    n4p = upf_rt_pfcp_port(rt);
    n3p = upf_rt_gtpu_port(rt);
    TK_ASSERT(n4p != 0 && n3p != 0 && n4p != n3p);
    smf = udp_socket("127.0.0.1", 0, &smf_port);
    gnb = udp_socket(gnb_ip, gnb_port, NULL);
    dn = sv[1];
    {
        struct timeval tv = {2, 0};
        (void)setsockopt(dn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    TK_ASSERT(pthread_create(&th, NULL, runner, rt) == 0);

    /* N4: association */
    b_assoc(&b, 0xe6000001u);
    rn = n4_call(smf, n4p, PFCP_ASSOCIATION_SETUP_REQUEST, false, 0, &b, resp, sizeof resp);
    TK_ASSERT(pfcp_decode(resp, rn, &h, &body, &bl) == 0 && h.msg_type == PFCP_ASSOCIATION_SETUP_RESPONSE);
    {
        pfcp_ie ie;
        uint8_t c;
        TK_ASSERT(find_ie(body, bl, PFCP_IE_CAUSE, &ie, 0) && pfcp_get_u8(&ie, &c) == 0 && c == PFCP_CAUSE_ACCEPTED);
    }
    /* N4: session with the gNB tunnel already known */
    b_session_head(&b, 0x1234);
    b_pdr_ul(&b, 1, 100, 1, 1, 0, 1, NULL, true);
    b_pdr_dl(&b, 2, 100, UE, 2, 0, 1, NULL);
    b_far(&b, 1, PFCP_AA_FORW, UPF_IF_CORE, 0, NULL, 0);
    b_far(&b, 2, PFCP_AA_FORW, UPF_IF_ACCESS, 0xabcd, gnbip, 0);
    b_urr(&b, 1, 0);
    rn = n4_call(smf, n4p, PFCP_SESSION_ESTABLISHMENT_REQUEST, true, 0, &b, resp, sizeof resp);
    TK_ASSERT(pfcp_decode(resp, rn, &h, &body, &bl) == 0 && h.msg_type == PFCP_SESSION_ESTABLISHMENT_RESPONSE && h.seid == 0x1234);
    {
        pfcp_ie ie, g;
        pfcp_fteid f;
        pfcp_fseid fs;
        TK_ASSERT(find_ie(body, bl, PFCP_IE_FSEID, &ie, 0) && pfcp_fseid_decode(&ie, &fs) == 0);
        useid = fs.seid;
        TK_ASSERT(find_ie(body, bl, PFCP_IE_CREATED_PDR, &g, 0) && find_ie(g.value, g.len, PFCP_IE_FTEID, &ie, 0) && pfcp_fteid_decode(&ie, &f) == 0);
        teid = f.teid;
        TK_ASSERT(f.v4 && f.ip4[0] == 127 && teid != 0);
    }

    /* N3 -> N6: an uplink packet comes out of the data-network descriptor */
    ipv4(ip, UE, DNIP, 17, 4000, 53, 120);
    rn = gpdu_ul(pkt, sizeof pkt, teid, 1, ip, 120);
    send_to(gnb, "127.0.0.1", n3p, pkt, rn);
    {
        uint8_t got[300];
        ssize_t n = recv(dn, got, sizeof got, 0);
        TK_ASSERT(n == 120 && memcmp(got, ip, 120) == 0);
    }
    /* N6 -> N3: a downlink packet reaches the gNB, encapsulated for the tunnel the SMF configured */
    ipv4(ip, DNIP, UE, 17, 53, 4000, 150);
    TK_ASSERT(write(dn, ip, 150) == 150);
    {
        uint8_t got[400];
        gtpu_header gh;
        const uint8_t *pl;
        size_t plen;
        ssize_t n = recv(gnb, got, sizeof got, 0);
        TK_ASSERT(n > 0 && gtpu_decode(got, (size_t)n, &gh, &pl, &plen) == 0 && gh.teid == 0xabcd && plen == 150 && memcmp(pl, ip, 150) == 0);
    }
    /* many packets in a burst: nothing is lost (the loop drains in batches) */
    for (int i = 0; i < 200; i++) {
        ipv4(ip, UE, DNIP, 17, 4000, 53, 100 + (size_t)(i % 50));
        rn = gpdu_ul(pkt, sizeof pkt, teid, 1, ip, 100 + (size_t)(i % 50));
        send_to(gnb, "127.0.0.1", n3p, pkt, rn);
    }
    for (int i = 0; i < 200; i++) {
        uint8_t got[300];
        ssize_t n = recv(dn, got, sizeof got, 0);
        TK_ASSERT(n == 100 + (ssize_t)(i % 50));
    }
    /* echo over the real socket */
    {
        uint8_t echo[12] = {0x32, GTPU_ECHO_REQUEST, 0, 4, 0, 0, 0, 0, 0, 7, 0, 0}, got[64];
        ssize_t n;
        send_to(gnb, "127.0.0.1", n3p, echo, sizeof echo);
        n = recv(gnb, got, sizeof got, 0);
        TK_ASSERT(n >= 8 && got[1] == GTPU_ECHO_RESPONSE);
    }
    /* delete: the usage report counts what was forwarded (1 + 200 uplink packets, 1 downlink) */
    b.pos = 0;
    rn = n4_call(smf, n4p, PFCP_SESSION_DELETION_REQUEST, true, useid, &b, resp, sizeof resp);
    TK_ASSERT(pfcp_decode(resp, rn, &h, &body, &bl) == 0 && h.msg_type == PFCP_SESSION_DELETION_RESPONSE);
    {
        pfcp_ie g, ie;
        TK_ASSERT(find_ie(body, bl, PFCP_IE_USAGE_REPORT_SDR, &g, 0) && find_ie(g.value, g.len, PFCP_IE_VOLUME_MEASUREMENT, &ie, 0));
        TK_ASSERT(ie.value[32] == 202 /* packets: 1 + 200 + 1 */);
    }
    /* after deletion the TEID is dead: an Error Indication comes back */
    ipv4(ip, UE, DNIP, 17, 4000, 53, 100);
    rn = gpdu_ul(pkt, sizeof pkt, teid, 1, ip, 100);
    send_to(gnb, "127.0.0.1", n3p, pkt, rn);
    {
        uint8_t got[64];
        ssize_t n = recv(gnb, got, sizeof got, 0);
        TK_ASSERT(n == 24 && got[1] == GTPU_ERROR_INDICATION);
    }

    upf_rt_stop(rt);
    pthread_join(th, NULL);
    {   /* the metrics endpoint's data */
        char *text = g5c_registry_render(m);
        TK_ASSERT(strstr(text, "g5c_upf_packets_total{direction=\"uplink\"}") != NULL && strstr(text, "g5c_upf_sessions") != NULL);
        free(text);
    }
    upf_rt_free(rt);
    g5c_registry_free(m);
    close(smf);
    close(gnb);
    close(sv[1]);
    puts("upf runtime: ok");
    return 0;
}
