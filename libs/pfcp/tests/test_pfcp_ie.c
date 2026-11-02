/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Typed PFCP IEs against real Open5GS messages (pfcp_vectors.h), plus robustness properties. */
#include <string.h>

#include "g5c/pfcp_ie.h"
#include "g5c/testkit.h"
#include "pfcp_vectors.h"

static size_t load(const char *hex, uint8_t *buf, size_t cap)
{
    long n = tk_unhex(hex, buf, cap);
    TK_ASSERT(n > 0);
    return (size_t)n;
}

/* Visit every IE, recursing into grouped ones. */
typedef void (*visit_fn)(const pfcp_ie *ie, int depth, void *ctx);
static const uint16_t GROUPED[] = {1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 78, 79, 80, 83, 85, 86, 87};

static bool is_grouped(uint16_t t)
{
    for (size_t i = 0; i < sizeof GROUPED / sizeof *GROUPED; i++)
        if (GROUPED[i] == t)
            return true;
    return false;
}

static void walk(const uint8_t *b, size_t n, int depth, visit_fn f, void *ctx)
{
    size_t pos = 0;
    pfcp_ie ie;
    int rc;
    while ((rc = pfcp_ie_next(b, n, &pos, &ie)) == 1) {
        f(&ie, depth, ctx);
        if (is_grouped(ie.typ))
            walk(ie.value, ie.len, depth + 1, f, ctx);
    }
    TK_ASSERT(rc == 0);
}

static const uint8_t *body_of(const uint8_t *msg, size_t n, size_t *blen, pfcp_header *h)
{
    const uint8_t *b;
    TK_ASSERT(pfcp_decode(msg, n, h, &b, blen) == 0);
    return b;
}

/* decode then re-encode every typed IE: the bytes must come back identical */
static void identity(const pfcp_ie *ie, int depth, void *ctx)
{
    uint8_t out[512];
    size_t pos = 0;
    int *count = ctx;
    (void)depth;
    switch (ie->typ) {
    case PFCP_IE_NODE_ID: {
        pfcp_node_id v;
        TK_ASSERT(pfcp_node_id_decode(ie, &v) == 0 && pfcp_node_id_put(out, sizeof out, &pos, &v) == 0);
        break;
    }
    case PFCP_IE_FSEID: {
        pfcp_fseid v;
        TK_ASSERT(pfcp_fseid_decode(ie, &v) == 0 && pfcp_fseid_put(out, sizeof out, &pos, &v) == 0);
        break;
    }
    case PFCP_IE_FTEID: {
        pfcp_fteid v;
        TK_ASSERT(pfcp_fteid_decode(ie, &v) == 0 && pfcp_fteid_put(out, sizeof out, &pos, &v) == 0);
        break;
    }
    case PFCP_IE_UE_IP_ADDRESS: {
        pfcp_ue_ip v;
        TK_ASSERT(pfcp_ue_ip_decode(ie, &v) == 0 && pfcp_ue_ip_put(out, sizeof out, &pos, &v) == 0);
        break;
    }
    case PFCP_IE_OUTER_HEADER_CREATION: {
        pfcp_ohc v;
        TK_ASSERT(pfcp_ohc_decode(ie, &v) == 0 && pfcp_ohc_put(out, sizeof out, &pos, &v) == 0);
        break;
    }
    case PFCP_IE_MBR:
    case PFCP_IE_GBR: {
        pfcp_bitrate v;
        TK_ASSERT(pfcp_bitrate_decode(ie, &v) == 0 && pfcp_bitrate_put(out, sizeof out, &pos, ie->typ, &v) == 0);
        break;
    }
    case PFCP_IE_NETWORK_INSTANCE: {
        char name[64];
        TK_ASSERT(pfcp_network_instance_decode(ie, name, sizeof name) == 0 && pfcp_network_instance_put(out, sizeof out, &pos, name) == 0);
        break;
    }
    case PFCP_IE_REPORTING_TRIGGERS:
    case PFCP_IE_USAGE_REPORT_TRIGGER: {
        uint32_t m;
        TK_ASSERT(pfcp_trigger_decode(ie, &m) == 0 && pfcp_trigger_put(out, sizeof out, &pos, ie->typ, m) == 0);
        break;
    }
    default:
        return;
    }
    /* out holds a complete IE: 4-byte header then the value */
    TK_ASSERT(pos == 4u + ie->len && memcmp(out + 4, ie->value, ie->len) == 0 && ((out[0] << 8) | out[1]) == ie->typ);
    (*count)++;
}

typedef struct {
    int n[200];
} counts_t;

static void count_types(const pfcp_ie *ie, int depth, void *ctx)
{
    counts_t *c = ctx;
    (void)depth;
    if (ie->typ < 200)
        c->n[ie->typ]++;
}

static void test_real_messages(void)
{
    static const char *const all[] = {PFCPV_ASSOC_SETUP_REQ, PFCPV_ASSOC_SETUP_RSP, PFCPV_SESS_EST_REQ, PFCPV_SESS_EST_RSP,
                                      PFCPV_SESS_MOD_REQ, PFCPV_SESS_MOD_RSP, PFCPV_SESS_DEL_REQ, PFCPV_SESS_DEL_RSP};
    uint8_t buf[1024];
    int typed = 0;
    for (size_t i = 0; i < sizeof all / sizeof *all; i++) {
        pfcp_header h;
        size_t n = load(all[i], buf, sizeof buf), bl;
        const uint8_t *b = body_of(buf, n, &bl, &h);
        walk(b, bl, 0, identity, &typed);
    }
    TK_ASSERT(typed >= 18); /* identity checked on every typed IE of the eight real messages */

    {   /* structure of the session establishment request */
        pfcp_header h;
        size_t n = load(PFCPV_SESS_EST_REQ, buf, sizeof buf), bl;
        const uint8_t *b = body_of(buf, n, &bl, &h);
        counts_t c;
        memset(&c, 0, sizeof c);
        walk(b, bl, 0, count_types, &c);
        TK_ASSERT(h.msg_type == PFCP_SESSION_ESTABLISHMENT_REQUEST && h.has_seid && h.seid == 0);
        TK_ASSERT(c.n[PFCP_IE_CREATE_PDR] == 4 && c.n[PFCP_IE_CREATE_FAR] == 3 && c.n[PFCP_IE_CREATE_QER] == 1 &&
                  c.n[PFCP_IE_CREATE_URR] == 1 && c.n[PFCP_IE_CREATE_BAR] == 1 && c.n[PFCP_IE_PDI] == 4);
    }
}

static void find_first(const pfcp_ie *ie, int depth, void *ctx)
{
    struct { uint16_t typ; pfcp_ie got; bool have; int skip; } *f = ctx;
    (void)depth;
    if (ie->typ == f->typ && !f->have) {
        if (f->skip-- > 0)
            return;
        f->got = *ie;
        f->have = true;
    }
}

static pfcp_ie nth_ie(const uint8_t *b, size_t bl, uint16_t typ, int skip)
{
    struct { uint16_t typ; pfcp_ie got; bool have; int skip; } f = {typ, {0, NULL, 0}, false, skip};
    walk(b, bl, 0, find_first, &f);
    TK_ASSERT(f.have);
    return f.got;
}

static void test_field_values(void)
{
    uint8_t buf[1024];
    pfcp_header h;
    size_t n = load(PFCPV_SESS_EST_REQ, buf, sizeof buf), bl;
    const uint8_t *b = body_of(buf, n, &bl, &h);
    pfcp_ie ie;
    {   /* the UPF is asked to choose TEIDs: CH + CHID 5 on the access-side PDRs, plain CH on the CP-function one */
        pfcp_fteid f;
        ie = nth_ie(b, bl, PFCP_IE_FTEID, 0);
        TK_ASSERT(pfcp_fteid_decode(&ie, &f) == 0 && f.ch && f.chid && f.choose_id == 5 && f.v4 && f.v6);
        ie = nth_ie(b, bl, PFCP_IE_FTEID, 1);
        TK_ASSERT(pfcp_fteid_decode(&ie, &f) == 0 && f.ch && !f.chid);
    }
    {
        pfcp_ue_ip u;
        ie = nth_ie(b, bl, PFCP_IE_UE_IP_ADDRESS, 0);
        TK_ASSERT(pfcp_ue_ip_decode(&ie, &u) == 0 && u.v4 && u.sd && !u.v6 && u.ip4[0] == 10 && u.ip4[1] == 46 && u.ip4[3] == 2);
    }
    {
        pfcp_ohc o;
        ie = nth_ie(b, bl, PFCP_IE_OUTER_HEADER_CREATION, 0);
        TK_ASSERT(pfcp_ohc_decode(&ie, &o) == 0 && o.desc == PFCP_OHC_GTPU_IPV4 && o.teid == 1 && o.ip4[0] == 127 && o.ip4[3] == 4);
    }
    {
        uint16_t aa;
        ie = nth_ie(b, bl, PFCP_IE_APPLY_ACTION, 0);
        TK_ASSERT(pfcp_apply_action_decode(&ie, &aa) == 0 && aa == (PFCP_AA_BUFF | PFCP_AA_NOCP));
        ie = nth_ie(b, bl, PFCP_IE_APPLY_ACTION, 1);
        TK_ASSERT(pfcp_apply_action_decode(&ie, &aa) == 0 && aa == PFCP_AA_FORW);
    }
    {
        pfcp_bitrate m;
        pfcp_gate g;
        pfcp_volume v;
        pfcp_sdf_filter s;
        char ni[64];
        ie = nth_ie(b, bl, PFCP_IE_MBR, 0);
        TK_ASSERT(pfcp_bitrate_decode(&ie, &m) == 0 && m.ul == 1000000 && m.dl == 1000000); /* kbit/s: 1 Gbit/s */
        ie = nth_ie(b, bl, PFCP_IE_GATE_STATUS, 0);
        TK_ASSERT(pfcp_gate_decode(&ie, &g) == 0 && !g.ul_closed && !g.dl_closed);
        ie = nth_ie(b, bl, PFCP_IE_VOLUME_THRESHOLD, 0);
        TK_ASSERT(pfcp_volume_decode(&ie, &v) == 0 && v.has_total && !v.has_ul && v.total == 104857600u); /* 100 MiB */
        ie = nth_ie(b, bl, PFCP_IE_SDF_FILTER, 0);
        TK_ASSERT(pfcp_sdf_filter_decode(&ie, &s) == 0 && s.has_fd && strncmp(s.flow, "permit out 58 from ff02::2/128", 30) == 0);
        ie = nth_ie(b, bl, PFCP_IE_NETWORK_INSTANCE, 0);
        TK_ASSERT(pfcp_network_instance_decode(&ie, ni, sizeof ni) == 0 && strcmp(ni, "internet") == 0);
    }
    {   /* the UPF's usage report in the deletion response: build the same Volume Measurement and compare bytes */
        uint8_t out[128], want[128];
        size_t pos = 0, wn;
        pfcp_volume_meas vm = {true, true, true, true, true, true, 252, 0, 252, 3, 0, 3};
        size_t dn = load(PFCPV_SESS_DEL_RSP, buf, sizeof buf), dbl;
        const uint8_t *db = body_of(buf, dn, &dbl, &h);
        ie = nth_ie(db, dbl, PFCP_IE_VOLUME_MEASUREMENT, 0);
        TK_ASSERT(pfcp_volume_meas_put(out, sizeof out, &pos, &vm) == 0);
        wn = ie.len;
        memcpy(want, ie.value, wn);
        TK_ASSERT(pos == 4 + wn && memcmp(out + 4, want, wn) == 0);
        {
            uint32_t t;
            ie = nth_ie(db, dbl, PFCP_IE_USAGE_REPORT_TRIGGER, 0);
            TK_ASSERT(pfcp_trigger_decode(&ie, &t) == 0 && t == PFCP_URT_TERMR);
        }
    }
}

static void test_builders(void)
{
    uint8_t out[256];
    size_t pos = 0, mark;
    pfcp_ie ie;
    size_t p2 = 0;
    pfcp_fteid f = {.v4 = true, .teid = 0x0005ff35, .ip4 = {127, 1, 0, 7}};
    pfcp_group_begin(out, sizeof out, &pos, PFCP_IE_CREATED_PDR, &mark);
    pfcp_put_u16(out, sizeof out, &pos, PFCP_IE_PDR_ID, 2);
    pfcp_fteid_put(out, sizeof out, &pos, &f);
    pfcp_group_end(out, &pos, mark);
    /* identical to the group Open5GS's UPF sent for PDR 2 */
    {
        uint8_t want[64], buf[256];
        pfcp_header h;
        size_t n = load(PFCPV_SESS_EST_RSP, buf, sizeof buf), bl;
        const uint8_t *b = body_of(buf, n, &bl, &h);
        ie = nth_ie(b, bl, PFCP_IE_CREATED_PDR, 0);
        (void)want;
        TK_ASSERT(pos == 4 + ie.len && memcmp(out + 4, ie.value, ie.len) == 0);
    }
    TK_ASSERT(pfcp_ie_next(out, pos, &p2, &ie) == 1 && ie.typ == PFCP_IE_CREATED_PDR);
    {   /* network instance with several labels, and a verbatim value */
        char name[64];
        uint8_t o2[64];
        size_t q = 0;
        TK_ASSERT(pfcp_network_instance_put(o2, sizeof o2, &q, "internet.mnc001.mcc001") == 0);
        p2 = 0;
        TK_ASSERT(pfcp_ie_next(o2, q, &p2, &ie) == 1 && pfcp_network_instance_decode(&ie, name, sizeof name) == 0 &&
                  strcmp(name, "internet.mnc001.mcc001") == 0);
        {
            pfcp_ie plain = {PFCP_IE_NETWORK_INSTANCE, (const uint8_t *)"ims", 3};
            TK_ASSERT(pfcp_network_instance_decode(&plain, name, sizeof name) == 0 && strcmp(name, "ims") == 0);
        }
        TK_ASSERT(pfcp_network_instance_put(o2, sizeof o2, &q, "a..b") != 0); /* empty label */
    }
    TK_ASSERT(pfcp_put_u32(out, 5, &(size_t){0}, 1, 1) == PFCP_E_NOSPACE);
}

/* every decoder must survive every truncation and random garbage (run under ASan) */
static void test_robustness(void)
{
    tk_rng rng = {0x5eed1234ULL};
    uint8_t buf[600];
    for (int iter = 0; iter < 20000; iter++) {
        size_t n = (size_t)(tk_rng_next(&rng) % 48);
        pfcp_ie ie;
        union {
            pfcp_node_id a; pfcp_fseid b; pfcp_fteid c; pfcp_ue_ip d; pfcp_ohc e; pfcp_bitrate f; pfcp_gate g; pfcp_sdf_filter h;
            pfcp_volume i;
        } u;
        char name[32];
        uint16_t aa;
        uint32_t m;
        uint8_t b8;
        tk_rng_bytes(&rng, buf, n);
        ie.typ = 0;
        ie.value = buf;
        ie.len = n;
        (void)pfcp_node_id_decode(&ie, &u.a);
        (void)pfcp_fseid_decode(&ie, &u.b);
        (void)pfcp_fteid_decode(&ie, &u.c);
        (void)pfcp_ue_ip_decode(&ie, &u.d);
        (void)pfcp_ohc_decode(&ie, &u.e);
        (void)pfcp_bitrate_decode(&ie, &u.f);
        (void)pfcp_gate_decode(&ie, &u.g);
        (void)pfcp_sdf_filter_decode(&ie, &u.h);
        (void)pfcp_volume_decode(&ie, &u.i);
        (void)pfcp_network_instance_decode(&ie, name, sizeof name);
        (void)pfcp_apply_action_decode(&ie, &aa);
        (void)pfcp_trigger_decode(&ie, &m);
        (void)pfcp_get_u8(&ie, &b8);
    }
    {   /* every prefix of a real session establishment parses without overrunning */
        pfcp_header h;
        size_t n = load(PFCPV_SESS_EST_REQ, buf, sizeof buf);
        for (size_t cut = 0; cut < n; cut++) {
            const uint8_t *b;
            size_t bl, pos = 0;
            pfcp_ie ie;
            if (pfcp_decode(buf, cut, &h, &b, &bl) == 0)
                while (pfcp_ie_next(b, bl, &pos, &ie) == 1)
                    ;
        }
    }
}

int main(void)
{
    test_real_messages();
    test_field_values();
    test_builders();
    test_robustness();
    puts("pfcp typed IEs: ok");
    return 0;
}
