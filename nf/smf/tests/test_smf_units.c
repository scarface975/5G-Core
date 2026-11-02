/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* SMF building blocks without any network */
#include <string.h>

#include "g5c/gtpu.h"
#include "g5c/nas.h"
#include "g5c/ngap.h"
#include "g5c/smf.h"
#include "g5c/testkit.h"
#include "rig.h"

/* ---- bit rates ---- */

static void test_bitrates(void)
{
    static const struct {
        const char *s;
        bool ok;
        uint64_t kbps;
    } t[] = {{"100 Mbps", true, 100000}, {"1 Gbps", true, 1000000}, {"2 Tbps", true, 2000000000ull}, {"64 Kbps", true, 64},
             {"1.5 Mbps", true, 1500}, {"999 bps", true, 1}, {"1001 bps", true, 2}, {"0 Kbps", true, 0}, {"0.0004 Kbps", true, 1},
             {"1 gbps", false, 0}, {"Mbps", false, 0}, {"10Mbps", false, 0}, {"-1 Kbps", false, 0}, {"1. Mbps", false, 0},
             {"1 Mbps ", false, 0}, {"", false, 0}, {"5000000 Tbps", false, 0}, {"1 Pbps", false, 0}, {" 1 Mbps", false, 0}};
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        uint64_t v = 12345;
        bool ok = smf_parse_bitrate(t[i].s, &v);
        if (ok != t[i].ok || (ok && v != t[i].kbps))
            TK_FAIL("bitrate `%s`: ok=%d value=%llu", t[i].s, ok, (unsigned long long)v);
    }
    {
        static const struct {
            uint64_t k;
            const char *s;
        } f[] = {{1000000, "1 Gbps"}, {1500, "1500 Kbps"}, {2000, "2 Mbps"}, {0, "0 Kbps"}, {1, "1 Kbps"}, {3000000000ull, "3 Tbps"}};
        for (size_t i = 0; i < sizeof f / sizeof f[0]; i++) {
            char *s = smf_format_bitrate(f[i].k);
            TK_ASSERT(strcmp(s, f[i].s) == 0);
            free(s);
        }
    }
}

/* ---- pools ---- */

static void test_pools(void)
{
    char err[160];
    smf_pool *p = smf_pool_new("10.45.0.0/28", "2001:db8:1::/62", err, sizeof err);
    uint8_t seen[16][4];
    uint8_t ip[4], pre[8];
    TK_ASSERT(p != NULL && smf_pool_has4(p) && smf_pool_has6(p));
    /* a /28 has 16 addresses: network, gateway (.1) and broadcast are not handed out */
    for (int i = 0; i < 13; i++) {
        TK_ASSERT(smf_pool_alloc4(p, seen[i]) == 0);
        TK_ASSERT(seen[i][0] == 10 && seen[i][1] == 45 && seen[i][2] == 0 && seen[i][3] >= 2 && seen[i][3] <= 14);
        for (int k = 0; k < i; k++)
            TK_ASSERT(memcmp(seen[i], seen[k], 4) != 0);
    }
    TK_ASSERT(smf_pool_used4(p) == 13 && smf_pool_alloc4(p, ip) == -1);
    smf_pool_release4(p, seen[5]);
    smf_pool_release4(p, seen[5]); /* a double release must not corrupt the count */
    TK_ASSERT(smf_pool_used4(p) == 12 && smf_pool_alloc4(p, ip) == 0 && memcmp(ip, seen[5], 4) == 0);
    {   /* releasing something outside the pool, or the gateway, is ignored */
        const uint8_t out[4] = {10, 46, 0, 5}, gw[4] = {10, 45, 0, 1};
        smf_pool_release4(p, out);
        smf_pool_release4(p, gw);
        TK_ASSERT(smf_pool_used4(p) == 13);
    }
    /* a /62 split into /64s: four prefixes */
    for (int i = 0; i < 4; i++) {
        TK_ASSERT(smf_pool_alloc6(p, pre) == 0 && pre[0] == 0x20 && pre[1] == 0x01 && pre[2] == 0x0d && pre[3] == 0xb8 && pre[7] == (uint8_t)i);
    }
    TK_ASSERT(smf_pool_alloc6(p, pre) == -1 && smf_pool_used6(p) == 4);
    smf_pool_free(p);

    /* a freed address is not reused straight away */
    p = smf_pool_new("192.168.0.0/24", NULL, err, sizeof err);
    TK_ASSERT(p != NULL && !smf_pool_has6(p));
    {
        uint8_t a[4], b[4];
        TK_ASSERT(smf_pool_alloc4(p, a) == 0);
        smf_pool_release4(p, a);
        TK_ASSERT(smf_pool_alloc4(p, b) == 0 && memcmp(a, b, 4) != 0);
        TK_ASSERT(smf_pool_alloc6(p, pre) == -1);
    }
    smf_pool_free(p);

    TK_ASSERT(smf_pool_new(NULL, NULL, err, sizeof err) == NULL);
    TK_ASSERT(smf_pool_new("10.0.0.0/31", NULL, err, sizeof err) == NULL);
    TK_ASSERT(smf_pool_new("10.0.0.0/7", NULL, err, sizeof err) == NULL);
    TK_ASSERT(smf_pool_new("10.0.0.0", NULL, err, sizeof err) == NULL);
    TK_ASSERT(smf_pool_new("300.0.0.0/24", NULL, err, sizeof err) == NULL);
    TK_ASSERT(smf_pool_new("10.0.0.0/24x", NULL, err, sizeof err) == NULL);
    TK_ASSERT(smf_pool_new(NULL, "2001:db8::/64", err, sizeof err) == NULL);
    TK_ASSERT(smf_pool_new(NULL, "2001:db8::/47", err, sizeof err) == NULL);
    TK_ASSERT(smf_pool_new(NULL, "zz::/48", err, sizeof err) == NULL);
    /* the address is masked down to the network */
    p = smf_pool_new("10.45.7.9/24", NULL, err, sizeof err);
    {
        uint8_t a[4];
        TK_ASSERT(p != NULL && smf_pool_alloc4(p, a) == 0 && a[2] == 7 && a[3] == 2);
    }
    smf_pool_free(p);
    /* a /8 is the largest allowed */
    p = smf_pool_new("10.0.0.0/8", NULL, err, sizeof err);
    TK_ASSERT(p != NULL);
    smf_pool_free(p);
}

/* ---- IPFilterRule ---- */

static void test_ipfilter(void)
{
    smf_ipfilter f;
    TK_ASSERT(smf_ipfilter_parse("permit out ip from any to assigned", &f) == 0 && f.any_proto && f.src_any && f.dst_any && !f.has_sport && !f.has_dport);
    TK_ASSERT(smf_ipfilter_parse("permit out 17 from 192.0.2.0/24 53 to assigned", &f) == 0 && f.proto == 17 && !f.src_any && f.src_plen == 24 &&
              f.src[2] == 2 && f.has_sport && f.sport_lo == 53 && f.sport_hi == 53);
    TK_ASSERT(smf_ipfilter_parse("permit out tcp from 10.1.1.1 to 10.9.9.9/32 8000-8100", &f) == 0 && f.proto == 6 && f.src_plen == 32 &&
              f.dst_plen == 32 && f.has_dport && f.dport_lo == 8000 && f.dport_hi == 8100);
    TK_ASSERT(smf_ipfilter_parse("permit out udp from any 1000 to any 2000", &f) == 0 && f.has_sport && f.has_dport);
    TK_ASSERT(smf_ipfilter_parse("permit out ip from 2001:db8::1 to assigned", &f) == 0 && f.src_v6); /* parsed, but flagged for the callers */
    {
        static const char *const bad[] = {"", "deny out ip from any to any", "permit in ip from any to any", "permit out ip from any", "permit out ip from any to",
                                         "permit out ip from any 80 to any", /* ports need a protocol */
                                         "permit out 300 from any to any", "permit out ip from any to any frag", "permit out tcp from any 99999 to any",
                                         "permit out tcp from any 90-80 to any", "permit out tcp from 10.0.0.0/99 to any", "permit out tcp from nonsense to any",
                                         "permit out icmp from any to any", "permit out tcp from any 80,443 to any", "permit out ip to any from any"};
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
            if (smf_ipfilter_parse(bad[i], &f) == 0)
                TK_FAIL("`%s` should not parse", bad[i]);
    }
}

/* ---- policy ---- */

static g5c_json *J(const char *s)
{
    char err[160];
    g5c_json *j = g5c_json_parse(s, strlen(s), err, sizeof err);
    if (j == NULL)
        TK_FAIL("test JSON: %s", err);
    return j;
}

#define DECISION_DEFAULT                                                                                                                     \
    "\"sessRules\":{\"SessRule-1\":{\"sessRuleId\":\"SessRule-1\",\"authSessAmbr\":{\"uplink\":\"100 Mbps\",\"downlink\":\"200 Mbps\"},"          \
    "\"authDefQos\":{\"5qi\":9,\"arp\":{\"priorityLevel\":8,\"preemptCap\":\"NOT_PREEMPT\",\"preemptVuln\":\"NOT_PREEMPTABLE\"},\"priorityLevel\":80}}}"

static void test_policy(void)
{
    smf_policy p;
    char err[200];
    g5c_json *d;

    d = J("{" DECISION_DEFAULT "}");
    TK_ASSERT(smf_policy_from_decision(d, &p, err, sizeof err) == 0);
    TK_ASSERT(p.ambr_ul == 100000 && p.ambr_dl == 200000 && p.nflows == 1 && p.nrules == 0);
    TK_ASSERT(p.flows[0].qfi == 1 && p.flows[0].qi5 == 9 && p.flows[0].arp_prio == 8 && !p.flows[0].pre_cap && !p.flows[0].pre_vuln &&
              p.flows[0].has_prio_level && p.flows[0].prio_level == 80 && !p.flows[0].gbr);
    smf_policy_free(&p);
    g5c_json_free(d);

    /* two rules sharing one QoS data, one GBR rule on its own flow, one rule on the default flow */
    d = J("{" DECISION_DEFAULT ",\"pccRules\":{"
          "\"A\":{\"pccRuleId\":\"A\",\"precedence\":10,\"flowInfos\":[{\"flowDescription\":\"permit out 17 from 10.1.1.0/24 5060 to assigned\",\"flowDirection\":\"BIDIRECTIONAL\"}],\"refQosData\":[\"Q1\"]},"
          "\"B\":{\"pccRuleId\":\"B\",\"precedence\":20,\"flowInfos\":[{\"flowDescription\":\"permit out ip from 10.2.2.2 to assigned\",\"flowDirection\":\"DOWNLINK\"}],\"refQosData\":[\"Q1\"]},"
          "\"C\":{\"pccRuleId\":\"C\",\"precedence\":30,\"flowInfos\":[{\"flowDescription\":\"permit out ip from any to assigned\"}],\"refQosData\":[\"Q2\"]},"
          "\"D\":{\"pccRuleId\":\"D\",\"precedence\":40,\"flowInfos\":[{\"flowDescription\":\"permit out 6 from 10.3.3.3 to assigned\",\"flowDirection\":\"UPLINK\"}]}},"
          "\"qosDecs\":{\"Q1\":{\"qosId\":\"Q1\",\"5qi\":7,\"arp\":{\"priorityLevel\":5,\"preemptCap\":\"MAY_PREEMPT\",\"preemptVuln\":\"PREEMPTABLE\"}},"
          "\"Q2\":{\"qosId\":\"Q2\",\"5qi\":1,\"gbrUl\":\"1 Mbps\",\"gbrDl\":\"2 Mbps\",\"maxbrUl\":\"3 Mbps\",\"maxbrDl\":\"4 Mbps\"}}}");
    TK_ASSERT(smf_policy_from_decision(d, &p, err, sizeof err) == 0);
    TK_ASSERT(p.nflows == 3 && p.nrules == 4);
    TK_ASSERT(p.flows[1].qfi == 2 && p.flows[1].qi5 == 7 && p.flows[1].pre_cap && p.flows[1].pre_vuln && !p.flows[1].gbr && strcmp(p.flows[1].qos_id, "Q1") == 0);
    TK_ASSERT(p.flows[2].qfi == 3 && p.flows[2].qi5 == 1 && p.flows[2].gbr && p.flows[2].gbr_ul == 1000 && p.flows[2].gbr_dl == 2000 &&
              p.flows[2].mbr_ul == 3000 && p.flows[2].mbr_dl == 4000);
    TK_ASSERT(p.rules[0].qfi == 2 && p.rules[1].qfi == 2 && p.rules[2].qfi == 3 && p.rules[3].qfi == SMF_DEFAULT_QFI);
    TK_ASSERT(p.rules[0].dirs[0] == 0 && p.rules[1].dirs[0] == 1 && p.rules[2].dirs[0] == 0 && p.rules[3].dirs[0] == 2);
    TK_ASSERT(p.rules[0].precedence == 10 && strcmp(p.rules[0].filters[0], "permit out 17 from 10.1.1.0/24 5060 to assigned") == 0);
    smf_policy_free(&p);
    g5c_json_free(d);

    /* a GBR flow without maximum rates: they default to the guaranteed ones (what the PCF sends when only gbr_* is configured) */
    d = J("{\"pccRules\":{\"A\":{\"pccRuleId\":\"A\",\"precedence\":1,\"flowInfos\":[{\"flowDescription\":\"permit out ip from any to assigned\"}],\"refQosData\":[\"Q\"]}},"
          "\"qosDecs\":{\"Q\":{\"5qi\":1,\"gbrUl\":\"128 Kbps\",\"gbrDl\":\"256 Kbps\",\"maxbrUl\":\"512 Kbps\"}}}");
    TK_ASSERT(smf_policy_from_decision(d, &p, err, sizeof err) == 0 && p.flows[1].gbr && p.flows[1].mbr_ul == 512 && p.flows[1].mbr_dl == 256 && p.flows[1].gbr_ul == 128);
    smf_policy_free(&p);
    g5c_json_free(d);

    /* a decision without session rules still yields the default flow (built-in values) */
    d = J("{}");
    TK_ASSERT(smf_policy_from_decision(d, &p, err, sizeof err) == 0 && p.nflows == 1 && p.flows[0].qi5 == 9 && p.ambr_ul == 0);
    smf_policy_free(&p);
    g5c_json_free(d);

    {
        static const char *const bad[] = {
            "[]",
            "{\"sessRules\":{\"s\":{\"authSessAmbr\":{\"uplink\":\"fast\",\"downlink\":\"1 Mbps\"}}}}",
            "{\"sessRules\":{\"s\":{\"authSessAmbr\":{\"uplink\":\"1 Mbps\"}}}}",
            "{\"sessRules\":{\"s\":{\"authDefQos\":{\"arp\":{}}}}}",
            "{\"pccRules\":[]}",
            /* a rule without flows, with a malformed or v6 flow description, without precedence, or pointing at unknown QoS data */
            "{\"pccRules\":{\"A\":{\"pccRuleId\":\"A\",\"precedence\":1,\"flowInfos\":[]}}}",
            "{\"pccRules\":{\"A\":{\"pccRuleId\":\"A\",\"precedence\":1,\"flowInfos\":[{\"flowDescription\":\"permit out garbage\"}]}}}",
            "{\"pccRules\":{\"A\":{\"pccRuleId\":\"A\",\"precedence\":1,\"flowInfos\":[{\"flowDescription\":\"permit out ip from 2001:db8::1 to assigned\"}]}}}",
            "{\"pccRules\":{\"A\":{\"pccRuleId\":\"A\",\"flowInfos\":[{\"flowDescription\":\"permit out ip from any to assigned\"}]}}}",
            "{\"pccRules\":{\"A\":{\"pccRuleId\":\"A\",\"precedence\":255,\"flowInfos\":[{\"flowDescription\":\"permit out ip from any to assigned\"}]}}}",
            "{\"pccRules\":{\"A\":{\"pccRuleId\":\"A\",\"precedence\":1,\"flowInfos\":[{\"flowDescription\":\"permit out ip from any to assigned\"}],\"refQosData\":[\"nope\"]}}}",
            "{\"pccRules\":{\"A\":{\"precedence\":1,\"flowInfos\":[{\"flowDescription\":\"permit out ip from any to assigned\"}]}}}",
            /* a GBR flow needs all four rates; 5QI is mandatory */
            "{\"pccRules\":{\"A\":{\"pccRuleId\":\"A\",\"precedence\":1,\"flowInfos\":[{\"flowDescription\":\"permit out ip from any to assigned\"}],\"refQosData\":[\"Q\"]}},\"qosDecs\":{\"Q\":{\"5qi\":1,\"gbrUl\":\"1 Mbps\"}}}",
            "{\"pccRules\":{\"A\":{\"pccRuleId\":\"A\",\"precedence\":1,\"flowInfos\":[{\"flowDescription\":\"permit out ip from any to assigned\"}],\"refQosData\":[\"Q\"]}},\"qosDecs\":{\"Q\":{\"arp\":{}}}}"};
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            d = J(bad[i]);
            if (smf_policy_from_decision(d, &p, err, sizeof err) == 0)
                TK_FAIL("decision %zu should be refused", i);
            g5c_json_free(d);
        }
    }
    {   /* more rules or flows than the model holds */
        g5c_bytes b;
        g5c_bytes_init(&b);
        g5c_bytes_append_str(&b, "{\"pccRules\":{");
        for (int i = 0; i < SMF_MAX_RULES + 1; i++)
            g5c_bytes_printf(&b, "%s\"R%d\":{\"pccRuleId\":\"R%d\",\"precedence\":%d,\"flowInfos\":[{\"flowDescription\":\"permit out ip from any to assigned\"}]}",
                             i ? "," : "", i, i, i + 1);
        g5c_bytes_append_str(&b, "}}");
        d = J((const char *)b.data);
        TK_ASSERT(smf_policy_from_decision(d, &p, err, sizeof err) != 0);
        g5c_json_free(d);
        g5c_bytes_free(&b);
    }
}

/* ---- 5GSM ---- */

static void build_est_req(g5c_bytes *out, uint8_t psi, uint8_t pti, int pdu_type, bool epco)
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
    if (epco)
        nas_msg_set(&m, "Extended protocol configuration options", ep, sizeof ep);
    TK_ASSERT(nas_msg_encode(&m, out) == NAS_OK);
    nas_msg_free(&m);
}

static void test_gsm(void)
{
    g5c_bytes b;
    smf_est_req er;
    nas_msg m;
    const uint8_t *v;
    size_t n;
    g5c_bytes_init(&b);
    build_est_req(&b, 5, 3, 3, true);
    TK_ASSERT(smf_gsm_parse_est_req(b.data, b.len, &er) == 0);
    TK_ASSERT(er.psi == 5 && er.pti == 3 && er.pdu_type == 3 && er.ssc_mode == 1 && er.pco_dns4 && er.pco_dns6 && er.pco_mtu);
    {   /* the same message cut short or corrupted never reads out of bounds */
        for (size_t i = 0; i < b.len; i++)
            (void)smf_gsm_parse_est_req(b.data, i, &er);
        TK_ASSERT(smf_gsm_parse_est_req(b.data, 3, &er) != 0);
        {
            uint8_t c[64];
            memcpy(c, b.data, b.len);
            c[0] = 0x7e; /* 5GMM */
            TK_ASSERT(smf_gsm_parse_est_req(c, b.len, &er) != 0);
            memcpy(c, b.data, b.len);
            c[3] = 0xd1; /* a different 5GSM message type */
            TK_ASSERT(smf_gsm_parse_est_req(c, b.len, &er) == SMF_5GSM_MESSAGE_TYPE_NOT_IMPLEMENTED);
            memcpy(c, b.data, b.len);
            c[2] = 0; /* PTI 0 is "no procedure transaction identity" */
            TK_ASSERT(smf_gsm_parse_est_req(c, b.len, &er) == SMF_5GSM_INVALID_PTI);
        }
    }
    g5c_bytes_clear(&b);
    build_est_req(&b, 1, 7, -1, false);
    TK_ASSERT(smf_gsm_parse_est_req(b.data, b.len, &er) == 0 && er.pdu_type == 0 && er.ssc_mode == 0 && !er.pco_dns4);
    g5c_bytes_free(&b);

    /* Session-AMBR: unit codes are 4^(u-1) kbit/s; the value rounds up and never exceeds 16 bits */
    {
        uint8_t a[6];
        smf_gsm_session_ambr(100000, 200000, a);
        TK_ASSERT(a[0] == 2 && a[1] == 0xc3 && a[2] == 0x50 && a[3] == 2 && a[4] == 0x61 && a[5] == 0xa8); /* DL 200 Mbps = 50000 x 4 kbps, UL 25000 x 4 kbps */
        smf_gsm_session_ambr(1, 65535, a);
        TK_ASSERT(a[0] == 1 && a[1] == 0xff && a[2] == 0xff && a[3] == 1 && a[4] == 0 && a[5] == 1);
        smf_gsm_session_ambr(65536, 1000000, a);
        TK_ASSERT(a[0] == 3 && ((a[1] << 8) | a[2]) == 62500 && a[3] == 2 && ((a[4] << 8) | a[5]) == 16384);
        smf_gsm_session_ambr(0, 0, a); /* unlimited: the largest value the field can carry */
        TK_ASSERT(a[0] == a[3] && (a[1] << 8 | a[2]) > 0);
    }

    /* the default QoS rule, byte for byte */
    {
        g5c_bytes r;
        static const uint8_t want[] = {0x01, 0x00, 0x06, 0x31, 0x31, 0x01, 0x01, 0xff, 0x01};
        g5c_bytes_init(&r);
        TK_ASSERT(smf_gsm_put_qos_rule(&r, 1, true, 255, 1, NULL, NULL, 0) == 0);
        TK_ASSERT(r.len == sizeof want && memcmp(r.data, want, sizeof want) == 0);
        g5c_bytes_free(&r);
    }
    /* a rule with filters: bidirectional UDP from a /24 and source port, and a downlink-only match-everything filter that must not use "match-all" */
    {
        g5c_bytes r;
        const char *fl[2] = {"permit out 17 from 10.1.1.0/24 5060 to assigned", "permit out ip from any to assigned"};
        uint8_t dirs[2] = {0, 1};
        static const uint8_t want[] = {0x02, 0x00, 0x1e, 0x22, /* QRI 2, length 30, create rule + 2 filters */
                                       0x31, 0x0e, 0x10, 0x0a, 0x01, 0x01, 0x00, 0xff, 0xff, 0xff, 0x00, 0x30, 0x11, 0x50, 0x13, 0xc4, /* filter 1: both ways, 14 octets */
                                       0x12, 0x09, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* filter 2: DL only, id 2, any remote IPv4 address */
                                       0x1e, 0x02};                                                    /* precedence 30, QFI 2 */
        g5c_bytes_init(&r);
        TK_ASSERT(smf_gsm_put_qos_rule(&r, 2, false, 30, 2, fl, dirs, 2) == 0);
        if (r.len != sizeof want || memcmp(r.data, want, sizeof want) != 0) {
            for (size_t i = 0; i < r.len; i++)
                fprintf(stderr, "%02x ", r.data[i]);
            fprintf(stderr, "\n");
            TK_FAIL("QoS rule encoding differs (len %zu, want %zu)", r.len, sizeof want);
        }
        g5c_bytes_free(&r);
    }
    {   /* refused: a QFI or QRI of 0, an IPv6 filter, an unparsable filter, no filters */
        g5c_bytes r;
        const char *bad = "permit out ip from 2001:db8::1 to assigned", *junk = "junk";
        uint8_t d = 0;
        g5c_bytes_init(&r);
        TK_ASSERT(smf_gsm_put_qos_rule(&r, 0, false, 1, 1, NULL, NULL, 0) != 0);
        TK_ASSERT(smf_gsm_put_qos_rule(&r, 1, false, 1, 0, NULL, NULL, 0) != 0);
        TK_ASSERT(smf_gsm_put_qos_rule(&r, 1, false, 1, 64, NULL, NULL, 0) != 0);
        TK_ASSERT(smf_gsm_put_qos_rule(&r, 1, false, 1, 2, &bad, &d, 1) != 0);
        TK_ASSERT(smf_gsm_put_qos_rule(&r, 1, false, 1, 2, &junk, &d, 1) != 0);
        {
            const char *none[1] = {NULL};
            TK_ASSERT(smf_gsm_put_qos_rule(&r, 1, false, 1, 2, none, &d, 0) != 0);
        }
        g5c_bytes_free(&r);
    }
    /* QoS flow description of a GBR flow: QFI 3, create, E bit, 5 parameters (5QI, GFBR UL/DL, MFBR UL/DL) */
    {
        smf_flow f;
        g5c_bytes r;
        memset(&f, 0, sizeof f);
        f.qfi = 3;
        f.qi5 = 1;
        f.gbr = true;
        f.gbr_ul = 1000;
        f.gbr_dl = 2000;
        f.mbr_ul = 3000;
        f.mbr_dl = 4000;
        g5c_bytes_init(&r);
        TK_ASSERT(smf_gsm_put_qos_flow_desc(&r, &f) == 0);
        /* header: QFI, op code 001<<5, E=1 + 5 parameters */
        TK_ASSERT(r.len == 3 + 3 + 4 * 5 && r.data[0] == 3 && r.data[1] == 0x20 && r.data[2] == 0x45);
        TK_ASSERT(r.data[3] == 1 && r.data[4] == 1 && r.data[5] == 1);              /* 5QI */
        /* each rate parameter: identifier, length 3, unit (1 = 1 kbit/s), 16-bit value */
        TK_ASSERT(r.data[6] == 2 && r.data[7] == 3 && r.data[8] == 1 && ((r.data[9] << 8) | r.data[10]) == 1000);   /* GFBR UL */
        TK_ASSERT(r.data[11] == 3 && r.data[12] == 3 && r.data[13] == 1 && ((r.data[14] << 8) | r.data[15]) == 2000); /* GFBR DL */
        TK_ASSERT(r.data[16] == 4 && r.data[17] == 3 && r.data[18] == 1 && ((r.data[19] << 8) | r.data[20]) == 3000); /* MFBR UL */
        TK_ASSERT(r.data[21] == 5 && r.data[22] == 3 && r.data[23] == 1 && ((r.data[24] << 8) | r.data[25]) == 4000); /* MFBR DL */
        g5c_bytes_clear(&r);
        f.gbr = false;
        TK_ASSERT(smf_gsm_put_qos_flow_desc(&r, &f) == 0 && r.len == 6 && r.data[2] == 0x41);
        f.qfi = 0;
        TK_ASSERT(smf_gsm_put_qos_flow_desc(&r, &f) != 0);
        g5c_bytes_free(&r);
    }

    /* the accept as a whole, decoded again by the NAS library */
    {
        smf_policy pol;
        smf_est_acc acc;
        g5c_bytes out;
        g5c_json *d = J("{" DECISION_DEFAULT ",\"pccRules\":{\"A\":{\"pccRuleId\":\"A\",\"precedence\":80,\"flowInfos\":[{\"flowDescription\":\"permit out ip from any to assigned\"}],"
                        "\"refQosData\":[\"Q\"]}},\"qosDecs\":{\"Q\":{\"5qi\":5,\"arp\":{\"priorityLevel\":3}}}}");
        char err[160];
        nas_snssai sn;
        TK_ASSERT(smf_policy_from_decision(d, &pol, err, sizeof err) == 0);
        g5c_json_free(d);
        memset(&acc, 0, sizeof acc);
        acc.psi = 5;
        acc.pti = 3;
        acc.pdu_type = 3;
        acc.ssc_mode = 1;
        acc.ip4[0] = 10;
        acc.ip4[1] = 45;
        acc.ip4[3] = 2;
        for (int i = 0; i < 8; i++)
            acc.ifid[i] = (uint8_t)(0xa0 + i);
        acc.ambr_ul = pol.ambr_ul;
        acc.ambr_dl = pol.ambr_dl;
        acc.pol = &pol;
        acc.has_snssai = true;
        acc.sst = 1;
        acc.has_sd = true;
        acc.sd = 0x010203;
        acc.dnn = "internet";
        acc.req.pco_dns4 = true;
        acc.req.pco_mtu = true;
        acc.ndns4 = 2;
        acc.dns4[0][0] = 8;
        acc.dns4[0][1] = acc.dns4[0][2] = acc.dns4[0][3] = 8;
        acc.dns4[1][0] = 1;
        acc.dns4[1][1] = acc.dns4[1][2] = acc.dns4[1][3] = 1;
        acc.mtu = 1400;
        acc.cause = SMF_5GSM_PDU_TYPE_IPV4_ONLY;
        g5c_bytes_init(&out);
        TK_ASSERT(smf_gsm_build_est_accept(&acc, &out) == 0);
        TK_ASSERT(nas_msg_decode(out.data, out.len, &m) == NAS_OK && m.pdu_session_id == 5 && m.pti == 3 && m.def->msg_type == 0xc2);
        v = nas_msg_get(&m, "Selected PDU session type", &n);
        TK_ASSERT(v && n == 1 && v[0] == 3);
        v = nas_msg_get(&m, "Selected SSC mode", &n);
        TK_ASSERT(v && n == 1 && v[0] == 1);
        v = nas_msg_get(&m, "Session AMBR", &n);
        TK_ASSERT(v && n == 6 && v[0] == 2 && v[1] == 0xc3);
        v = nas_msg_get(&m, "PDU address", &n);
        TK_ASSERT(v && n == 13 && v[0] == 3 && v[1] == 0xa0 && v[8] == 0xa7 && v[9] == 10 && v[10] == 45 && v[12] == 2);
        v = nas_msg_get(&m, "5GSM cause", &n);
        TK_ASSERT(v && n == 1 && v[0] == SMF_5GSM_PDU_TYPE_IPV4_ONLY);
        v = nas_msg_get(&m, "S-NSSAI", &n);
        TK_ASSERT(v && nas_snssai_decode(v, n, &sn) == 0 && sn.sst == 1 && sn.has_sd && sn.sd == 0x010203);
        v = nas_msg_get(&m, "Authorized QoS rules", &n);
        TK_ASSERT(v && n > 9 && v[0] == 1 && v[2] == 6 && v[9] == 2); /* default rule, then QRI 2 */
        TK_ASSERT(v[n - 2] == 81 && v[n - 1] == 2);                    /* precedence 80 is reserved: sent as 81, bound to QFI 2 */
        v = nas_msg_get(&m, "Authorized QoS flow descriptions", &n);
        TK_ASSERT(v && n == 6 && v[0] == 2 && v[1] == 0x20 && v[2] == 0x41 && v[5] == 5);
        v = nas_msg_get(&m, "Extended protocol configuration options", &n);
        /* 0x80, DNS 8.8.8.8, DNS 1.1.1.1, MTU 1400 */
        TK_ASSERT(v && n == 1 + 7 + 7 + 5 && v[0] == 0x80 && v[1] == 0 && v[2] == 0x0d && v[3] == 4 && v[4] == 8 && v[8] == 0 && v[9] == 0x0d && v[n - 5] == 0 &&
                  v[n - 4] == 0x10 && v[n - 3] == 2 && ((v[n - 2] << 8) | v[n - 1]) == 1400);
        v = nas_msg_get(&m, "DNN", &n);
        {
            char dn[64];
            TK_ASSERT(v && nas_dnn_decode(v, n, dn, sizeof dn) == 0 && strcmp(dn, "internet") == 0);
        }
        nas_msg_free(&m);
        /* IPv4 only: the PDU address is the type octet plus 4 octets */
        acc.pdu_type = 1;
        g5c_bytes_clear(&out);
        TK_ASSERT(smf_gsm_build_est_accept(&acc, &out) == 0 && nas_msg_decode(out.data, out.len, &m) == NAS_OK);
        v = nas_msg_get(&m, "PDU address", &n);
        TK_ASSERT(v && n == 5 && v[0] == 1 && v[1] == 10 && v[4] == 2);
        nas_msg_free(&m);
        g5c_bytes_free(&out);
        smf_policy_free(&pol);
    }

    /* reject and release command */
    {
        g5c_bytes out;
        g5c_bytes_init(&out);
        TK_ASSERT(smf_gsm_build_est_reject(5, 3, SMF_5GSM_MISSING_OR_UNKNOWN_DNN, &out) == 0);
        TK_ASSERT(nas_msg_decode(out.data, out.len, &m) == NAS_OK && m.def->msg_type == 0xc3 && m.pdu_session_id == 5 && m.pti == 3);
        v = nas_msg_get(&m, "5GSM cause", &n);
        TK_ASSERT(v && n == 1 && v[0] == 27);
        nas_msg_free(&m);
        g5c_bytes_clear(&out);
        TK_ASSERT(smf_gsm_build_release_cmd(5, 9, SMF_5GSM_REGULAR_DEACTIVATION, &out) == 0);
        TK_ASSERT(nas_msg_decode(out.data, out.len, &m) == NAS_OK && m.def->msg_type == 0xd3 && m.pti == 9);
        nas_msg_free(&m);
        {
            uint8_t mt, psi, pti;
            TK_ASSERT(smf_gsm_peek(out.data, out.len, &mt, &psi, &pti) == 0 && mt == 0xd3 && psi == 5 && pti == 9);
            TK_ASSERT(smf_gsm_peek(out.data, 3, &mt, &psi, &pti) != 0);
        }
        g5c_bytes_free(&out);
    }
}

/* ---- N2 ---- */

static void test_n2(void)
{
    smf_policy pol;
    smf_n2_setup in;
    g5c_bytes out;
    char err[200];
    g5c_json *d = J("{" DECISION_DEFAULT ",\"pccRules\":{\"A\":{\"pccRuleId\":\"A\",\"precedence\":10,\"flowInfos\":[{\"flowDescription\":\"permit out ip from any to assigned\"}],"
                    "\"refQosData\":[\"Q\"]}},\"qosDecs\":{\"Q\":{\"5qi\":1,\"gbrUl\":\"1 Mbps\",\"gbrDl\":\"2 Mbps\",\"maxbrUl\":\"3 Mbps\",\"maxbrDl\":\"4 Mbps\"}}}"), *t;
    const g5c_json *ies;
    TK_ASSERT(smf_policy_from_decision(d, &pol, err, sizeof err) == 0);
    g5c_json_free(d);
    memset(&in, 0, sizeof in);
    in.pdu_type = 1;
    in.ambr_ul = pol.ambr_ul;
    in.ambr_dl = pol.ambr_dl;
    in.upf_ip4[0] = 10;
    in.upf_ip4[1] = 100;
    in.upf_ip4[3] = 7;
    in.ul_teid = 0x01020304;
    in.pol = &pol;
    g5c_bytes_init(&out);
    TK_ASSERT(smf_n2_build_setup_req(&in, &out) == 0 && out.len > 20);
    t = ngap_decode_as("PDUSessionResourceSetupRequestTransfer", out.data, out.len, err, sizeof err);
    TK_ASSERT(t != NULL);
    ies = g5c_json_get(t, "protocolIEs");
    TK_ASSERT(g5c_json_len(ies) == 4);
    {
        const g5c_json *ambr = NULL, *tnl = NULL, *pt = NULL, *flows = NULL;
        for (size_t i = 0; i < 4; i++) {
            int64_t id;
            const g5c_json *e = g5c_json_at(ies, i);
            TK_ASSERT(g5c_json_get_int(e, "id", &id));
            if (id == NGAP_IE_PDUSessionAggregateMaximumBitRate)
                ambr = g5c_json_get(e, "value");
            else if (id == NGAP_IE_UL_NGU_UP_TNLInformation)
                tnl = g5c_json_get(e, "value");
            else if (id == NGAP_IE_PDUSessionType)
                pt = g5c_json_get(e, "value");
            else if (id == NGAP_IE_QosFlowSetupRequestList)
                flows = g5c_json_get(e, "value");
        }
        int64_t v;
        TK_ASSERT(ambr && tnl && pt && flows);
        TK_ASSERT(g5c_json_get_int(ambr, "pDUSessionAggregateMaximumBitRateUL", &v) && v == 100000000);
        TK_ASSERT(g5c_json_get_int(ambr, "pDUSessionAggregateMaximumBitRateDL", &v) && v == 200000000);
        TK_ASSERT(strcmp(g5c_json_str(pt), "ipv4") == 0);
        {
            const g5c_json *gt = g5c_json_get(tnl, "gTPTunnel");
            TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(gt, "transportLayerAddress"), "hex"), "0a640007") == 0);
            TK_ASSERT(strcmp(g5c_json_str(g5c_json_get(gt, "gTP-TEID")), "01020304") == 0);
        }
        TK_ASSERT(g5c_json_len(flows) == 2);
        TK_ASSERT(g5c_json_get_int(g5c_json_at(flows, 0), "qosFlowIdentifier", &v) && v == 1);
        {
            const g5c_json *q = g5c_json_get(g5c_json_at(flows, 0), "qosFlowLevelQosParameters");
            TK_ASSERT(g5c_json_get_int(g5c_json_get(g5c_json_get(q, "qosCharacteristics"), "nonDynamic5QI"), "fiveQI", &v) && v == 9);
            TK_ASSERT(g5c_json_get_int(g5c_json_get(q, "allocationAndRetentionPriority"), "priorityLevelARP", &v) && v == 8);
            TK_ASSERT(g5c_json_get(q, "gBR-QosInformation") == NULL);
            q = g5c_json_get(g5c_json_at(flows, 1), "qosFlowLevelQosParameters");
            TK_ASSERT(g5c_json_get_int(g5c_json_get(q, "gBR-QosInformation"), "guaranteedFlowBitRateDL", &v) && v == 2000000);
            TK_ASSERT(g5c_json_get_int(g5c_json_get(q, "gBR-QosInformation"), "maximumFlowBitRateUL", &v) && v == 3000000);
        }
    }
    g5c_json_free(t);
    /* unlimited session AMBR: the optional IE is left out; IPv4v6 type */
    in.ambr_ul = in.ambr_dl = 0;
    in.pdu_type = 3;
    g5c_bytes_clear(&out);
    TK_ASSERT(smf_n2_build_setup_req(&in, &out) == 0);
    t = ngap_decode_as("PDUSessionResourceSetupRequestTransfer", out.data, out.len, err, sizeof err);
    TK_ASSERT(t != NULL && g5c_json_len(g5c_json_get(t, "protocolIEs")) == 3);
    g5c_json_free(t);
    in.pdu_type = 0;
    TK_ASSERT(smf_n2_build_setup_req(&in, &out) != 0);
    smf_policy_free(&pol);

    /* the gNB's answer */
    {
        smf_an_tunnel tun;
        static const char *const good =
            "{\"dLQosFlowPerTNLInformation\":{\"uPTransportLayerInformation\":{\"gTPTunnel\":{\"transportLayerAddress\":{\"len\":32,\"hex\":\"c0a80164\"},"
            "\"gTP-TEID\":\"0000abcd\"}},\"associatedQosFlowList\":[{\"qosFlowIdentifier\":1},{\"qosFlowIdentifier\":3}]}}";
        g5c_bytes_clear(&out);
        d = J(good);
        TK_ASSERT(ngap_encode_as("PDUSessionResourceSetupResponseTransfer", d, &out, err, sizeof err) == 0);
        g5c_json_free(d);
        TK_ASSERT(smf_n2_parse_setup_rsp(out.data, out.len, &tun, err, sizeof err) == 0);
        TK_ASSERT(tun.v4 && !tun.v6 && tun.ip4[0] == 192 && tun.ip4[3] == 100 && tun.teid == 0xabcd && tun.naccepted == 2 && tun.accepted[0] == 1 && tun.accepted[1] == 3);
        /* dual-stack transport address: IPv4 first, then IPv6 */
        g5c_bytes_clear(&out);
        d = J("{\"dLQosFlowPerTNLInformation\":{\"uPTransportLayerInformation\":{\"gTPTunnel\":{\"transportLayerAddress\":{\"len\":160,"
              "\"hex\":\"c0a801642001000000000000000000000000000a\"},\"gTP-TEID\":\"00000001\"}},\"associatedQosFlowList\":[{\"qosFlowIdentifier\":1}]}}");
        TK_ASSERT(ngap_encode_as("PDUSessionResourceSetupResponseTransfer", d, &out, err, sizeof err) == 0);
        g5c_json_free(d);
        TK_ASSERT(smf_n2_parse_setup_rsp(out.data, out.len, &tun, err, sizeof err) == 0 && tun.v4 && tun.v6 && tun.ip6[0] == 0x20 && tun.ip6[15] == 0x0a);
        /* an address that is not 32, 128 or 160 bits long is refused */
        g5c_bytes_clear(&out);
        d = J("{\"dLQosFlowPerTNLInformation\":{\"uPTransportLayerInformation\":{\"gTPTunnel\":{\"transportLayerAddress\":{\"len\":24,"
              "\"hex\":\"c0a801\"},\"gTP-TEID\":\"00000001\"}},\"associatedQosFlowList\":[{\"qosFlowIdentifier\":1}]}}");
        TK_ASSERT(ngap_encode_as("PDUSessionResourceSetupResponseTransfer", d, &out, err, sizeof err) == 0);
        g5c_json_free(d);
        TK_ASSERT(smf_n2_parse_setup_rsp(out.data, out.len, &tun, err, sizeof err) != 0);
        /* garbage and truncations */
        TK_ASSERT(smf_n2_parse_setup_rsp((const uint8_t *)"\xff\xff", 2, &tun, err, sizeof err) != 0);
        TK_ASSERT(smf_n2_parse_setup_rsp(out.data, 0, &tun, err, sizeof err) != 0);
        for (size_t i = 0; i < out.len; i++)
            (void)smf_n2_parse_setup_rsp(out.data, i, &tun, err, sizeof err);
    }
    /* handover transfers: the target gNB's downlink tunnel, and the SMF's own answers */
    {
        smf_an_tunnel tun;
        static const char *const ps =
            "{\"dL-NGU-UP-TNLInformation\":{\"gTPTunnel\":{\"transportLayerAddress\":{\"len\":32,\"hex\":\"0a000002\"},\"gTP-TEID\":\"00001234\"}},"
            "\"qosFlowAcceptedList\":[{\"qosFlowIdentifier\":1},{\"qosFlowIdentifier\":5}]}";
        static const char *const ack =
            "{\"dL-NGU-UP-TNLInformation\":{\"gTPTunnel\":{\"transportLayerAddress\":{\"len\":32,\"hex\":\"0a000003\"},\"gTP-TEID\":\"00005678\"}},"
            "\"qosFlowSetupResponseList\":[{\"qosFlowIdentifier\":1}]}";
        g5c_bytes_clear(&out);
        d = J(ps);
        TK_ASSERT(ngap_encode_as("PathSwitchRequestTransfer", d, &out, err, sizeof err) == 0);
        g5c_json_free(d);
        TK_ASSERT(smf_n2_parse_path_switch(out.data, out.len, &tun, err, sizeof err) == 0);
        TK_ASSERT(tun.v4 && tun.ip4[3] == 2 && tun.teid == 0x1234 && tun.naccepted == 2 && tun.accepted[1] == 5);
        TK_ASSERT(smf_n2_parse_path_switch(out.data, out.len / 2, &tun, err, sizeof err) != 0);
        g5c_bytes_clear(&out);
        d = J(ack);
        TK_ASSERT(ngap_encode_as("HandoverRequestAcknowledgeTransfer", d, &out, err, sizeof err) == 0);
        g5c_json_free(d);
        TK_ASSERT(smf_n2_parse_ho_ack(out.data, out.len, &tun, err, sizeof err) == 0);
        TK_ASSERT(tun.v4 && tun.ip4[3] == 3 && tun.teid == 0x5678 && tun.naccepted == 1);
        g5c_bytes_clear(&out);
        {
            static const uint8_t up_ip4[4] = {10, 0, 0, 7};
            TK_ASSERT(smf_n2_build_path_switch_ack(up_ip4, 0xabcdef01, &out) == 0);
            t = ngap_decode_as("PathSwitchRequestAcknowledgeTransfer", out.data, out.len, err, sizeof err);
            TK_ASSERT(t != NULL);
            TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(g5c_json_get(g5c_json_get(t, "uL-NGU-UP-TNLInformation"), "gTPTunnel"), "transportLayerAddress"), "hex"),
                             "0a000007") == 0);
            TK_ASSERT(strcmp(g5c_json_str(g5c_json_get(g5c_json_get(g5c_json_get(t, "uL-NGU-UP-TNLInformation"), "gTPTunnel"), "gTP-TEID")), "abcdef01") == 0);
            g5c_json_free(t);
        }
        g5c_bytes_clear(&out);
        TK_ASSERT(smf_n2_build_ho_command(&out) == 0 && out.len > 0);
        {
            t = ngap_decode_as("HandoverCommandTransfer", out.data, out.len, err, sizeof err);
            TK_ASSERT(t != NULL && g5c_json_len(t) == 0);
            g5c_json_free(t);
        }
    }
    /* causes */
    {
        char c[96];
        g5c_bytes_clear(&out);
        d = J("{\"cause\":{\"radioNetwork\":\"radio-connection-with-ue-lost\"}}");
        TK_ASSERT(ngap_encode_as("PDUSessionResourceSetupUnsuccessfulTransfer", d, &out, err, sizeof err) == 0);
        g5c_json_free(d);
        TK_ASSERT(smf_n2_parse_cause("PDUSessionResourceSetupUnsuccessfulTransfer", out.data, out.len, c, sizeof c) == 0);
        TK_ASSERT(strcmp(c, "radioNetwork:radio-connection-with-ue-lost") == 0);
        TK_ASSERT(smf_n2_parse_cause("PDUSessionResourceSetupUnsuccessfulTransfer", out.data, 1, c, sizeof c) != 0);
        g5c_bytes_clear(&out);
        TK_ASSERT(smf_n2_build_release_cmd(&out) == 0);
        TK_ASSERT(smf_n2_parse_cause("PDUSessionResourceReleaseCommandTransfer", out.data, out.len, c, sizeof c) == 0 && strcmp(c, "nas:normal-release") == 0);
    }
    g5c_bytes_free(&out);
}

/* ---- PCC rules -> PFCP, checked against the UPF engine ---- */

static const uint8_t UEIP[4] = {10, 45, 0, 7};
static const uint8_t GNB4[4] = {127, 1, 0, 100};

static smf_policy mapping_policy(void)
{
    smf_policy p;
    char err[200];
    g5c_json *d = J("{" DECISION_DEFAULT ",\"pccRules\":{"
                    "\"V\":{\"pccRuleId\":\"V\",\"precedence\":10,\"flowInfos\":[{\"flowDescription\":\"permit out 17 from 198.51.100.0/24 5060 to assigned\",\"flowDirection\":\"BIDIRECTIONAL\"}],\"refQosData\":[\"Qv\"]},"
                    "\"D\":{\"pccRuleId\":\"D\",\"precedence\":20,\"flowInfos\":[{\"flowDescription\":\"permit out ip from 203.0.113.9 to assigned\",\"flowDirection\":\"DOWNLINK\"}],\"refQosData\":[\"Qd\"]},"
                    "\"U\":{\"pccRuleId\":\"U\",\"precedence\":30,\"flowInfos\":[{\"flowDescription\":\"permit out 6 from 192.0.2.77 to assigned\",\"flowDirection\":\"UPLINK\"}]}},"
                    "\"qosDecs\":{\"Qv\":{\"qosId\":\"Qv\",\"5qi\":1,\"gbrUl\":\"1 Mbps\",\"gbrDl\":\"1 Mbps\",\"maxbrUl\":\"2 Mbps\",\"maxbrDl\":\"2 Mbps\"},"
                    "\"Qd\":{\"qosId\":\"Qd\",\"5qi\":7}}}");
    TK_ASSERT(smf_policy_from_decision(d, &p, err, sizeof err) == 0);
    g5c_json_free(d);
    return p;
}

static void test_rule_mapping(void)
{
    smf_policy pol = mapping_policy();
    smf_n4_est est;
    uint8_t body[2048];
    size_t blen = 0;
    smf_n4_msg rsp;
    smf_n4_est_rsp er;
    pfcp_header h;
    size_t bl, pos = 0;
    const uint8_t *b;
    pfcp_ie ie;
    int npdr = 0, nfar = 0, nqer = 0, nbar = 0;
    uint32_t qer_gbr = 0;

    memset(&est, 0, sizeof est);
    est.cp_seid = 0x1122334455ULL;
    est.smf_ip4[0] = 127;
    est.smf_ip4[1] = 1;
    est.smf_ip4[3] = 4;
    est.dnn = "internet";
    est.pdu_type = 1;
    est.has4 = true;
    memcpy(est.ue4, UEIP, 4);
    est.has_snssai = true;
    est.sst = 1;
    est.has_sd = true;
    est.sd = 0xabcdef;
    est.pol = &pol;
    TK_ASSERT(smf_n4_build_est(&est, body, sizeof body, &blen) == 0);

    /* structure: 2 default PDRs + V (UL, DL) + D (DL only) + U (UL only) = 6; 2 FARs; QERs: session + 3 flows; 1 BAR */
    while (pfcp_ie_next(body, blen, &pos, &ie) == 1) {
        if (ie.typ == PFCP_IE_CREATE_PDR)
            npdr++;
        else if (ie.typ == PFCP_IE_CREATE_FAR)
            nfar++;
        else if (ie.typ == PFCP_IE_CREATE_QER)
            nqer++;
        else if (ie.typ == PFCP_IE_CREATE_BAR)
            nbar++;
    }
    TK_ASSERT(npdr == 6 && nfar == 2 && nqer == 4 && nbar == 1);
    (void)qer_gbr;

    /* the UPF engine accepts it */
    rig_new(NULL);
    {
        bld_t a;
        b_assoc(&a, 0xe5000001u);
        send_n4(PFCP_ASSOCIATION_SETUP_REQUEST, false, 0, a.body, a.pos);
    }
    rig_reset_captures();
    send_n4(PFCP_SESSION_ESTABLISHMENT_REQUEST, true, 0, body, blen);
    b = rig_n4(PFCP_SESSION_ESTABLISHMENT_RESPONSE, &h, &bl);
    TK_ASSERT(b != NULL);
    memcpy(rsp.body, b, bl);
    rsp.blen = bl;
    rsp.h = h;
    TK_ASSERT(smf_n4_parse_est_rsp(&rsp, &er) == 0);
    if (!er.ok)
        TK_FAIL("the UPF refused the SMF's establishment (cause %u, offending IE %u)", er.cause, er.offending_ie);
    TK_ASSERT(er.ul_ip4[3] == 7 && er.ul_teid != 0 && h.seid == est.cp_seid);

    /* uplink through the tunnel reaches the data network */
    {
        uint8_t ip[40], g[200];
        const uint8_t dst[4] = {8, 8, 8, 8};
        size_t n;
        ipv4(ip, UEIP, dst, 6, 1234, 80, 40);
        n = gpdu_ul(g, sizeof g, er.ul_teid, 1, ip, 40);
        upf_gtpu_packet(U, &GNB, g, n, NOW);
        TK_ASSERT(RIG.nn6 == 1);
        /* a source that is not the UE's address is dropped (the engine checks it) */
        {
            const uint8_t other[4] = {10, 45, 0, 99};
            ipv4(ip, other, dst, 6, 1234, 80, 40);
            n = gpdu_ul(g, sizeof g, er.ul_teid, 1, ip, 40);
            upf_gtpu_packet(U, &GNB, g, n, NOW);
            TK_ASSERT(RIG.nn6 == 1 && U->st.drop_spoof == 1);
        }
    }
    /* downlink before the gNB tunnel is known: dropped */
    {
        uint8_t ip[40];
        const uint8_t src[4] = {198, 51, 100, 5};
        ipv4(ip, src, UEIP, 17, 5060, 5060, 40);
        upf_n6_packet(U, ip, 40, NOW);
        TK_ASSERT(RIG.ngtpu == 0);
    }
    /* activate: the gNB tunnel */
    {
        smf_an_tunnel t;
        uint8_t mb[256];
        size_t ml = 0;
        pfcp_header mh;
        size_t mbl;
        const uint8_t *mbody;
        memset(&t, 0, sizeof t);
        t.v4 = true;
        memcpy(t.ip4, GNB4, 4);
        t.teid = 0x7001;
        TK_ASSERT(smf_n4_build_mod_activate(&t, "internet", mb, sizeof mb, &ml) == 0);
        rig_reset_captures();
        send_n4(PFCP_SESSION_MODIFICATION_REQUEST, true, er.up_seid, mb, ml);
        mbody = rig_n4(PFCP_SESSION_MODIFICATION_RESPONSE, &mh, &mbl);
        TK_ASSERT(mbody && cause_of(mbody, mbl) == PFCP_CAUSE_ACCEPTED);
        t.v4 = false;
        TK_ASSERT(smf_n4_build_mod_activate(&t, "internet", mb, sizeof mb, &ml) != 0); /* IPv6-only gNB: not supported */
    }
    /* downlink now reaches the gNB with the QFI of the matching flow: default flow 1, voice rule 2, the downlink-only rule 3 */
    {
        static const struct {
            uint8_t src[4];
            uint8_t proto;
            uint16_t sport;
            uint8_t qfi;
        } dl[] = {{{8, 8, 8, 8}, 6, 80, 1}, {{198, 51, 100, 5}, 17, 5060, 2}, {{198, 51, 100, 5}, 17, 5061, 1}, {{203, 0, 113, 9}, 6, 443, 3}};
        for (size_t i = 0; i < sizeof dl / sizeof dl[0]; i++) {
            uint8_t ip[60];
            gtpu_header gh;
            const uint8_t *pl;
            size_t pln, before = RIG.ngtpu;
            uint8_t t, q;
            bool rqi;
            ipv4(ip, dl[i].src, UEIP, dl[i].proto, dl[i].sport, 5060, 40);
            upf_n6_packet(U, ip, 40, NOW);
            if (RIG.ngtpu != before + 1)
                TK_FAIL("downlink packet %zu was not forwarded", i);
            TK_ASSERT(gtpu_decode(RIG.gtpu[RIG.ngtpu - 1].d, RIG.gtpu[RIG.ngtpu - 1].n, &gh, &pl, &pln) == 0 && gh.teid == 0x7001);
            TK_ASSERT(gh.next == 1 && gtpu_as_pdu_session_container(&gh.ext[0], &t, &q, &rqi) && t == 0);
            if (q != dl[i].qfi)
                TK_FAIL("downlink packet %zu: QFI %u, wanted %u", i, q, dl[i].qfi);
        }
    }
    /* deactivate: the downlink is buffered and the SMF is told (Downlink Data Report) */
    {
        uint8_t mb[128], ip[40];
        size_t ml = 0;
        pfcp_header mh;
        size_t mbl;
        const uint8_t *mbody;
        const uint8_t src[4] = {8, 8, 8, 8};
        TK_ASSERT(smf_n4_build_mod_deactivate(mb, sizeof mb, &ml) == 0);
        rig_reset_captures();
        send_n4(PFCP_SESSION_MODIFICATION_REQUEST, true, er.up_seid, mb, ml);
        mbody = rig_n4(PFCP_SESSION_MODIFICATION_RESPONSE, &mh, &mbl);
        TK_ASSERT(mbody && cause_of(mbody, mbl) == PFCP_CAUSE_ACCEPTED);
        ipv4(ip, src, UEIP, 6, 80, 1234, 40);
        upf_n6_packet(U, ip, 40, NOW);
        TK_ASSERT(RIG.ngtpu == 0 && U->st.buffered == 1);
        TK_ASSERT(rig_n4(PFCP_SESSION_REPORT_REQUEST, &mh, &mbl) != NULL);
    }
    /* deletion needs no body */
    rig_reset_captures();
    send_n4(PFCP_SESSION_DELETION_REQUEST, true, er.up_seid, NULL, 0);
    TK_ASSERT(rig_n4(PFCP_SESSION_DELETION_RESPONSE, &h, &bl) != NULL && upf_session_count(U) == 0);
    upf_free(U);

    /* limits and refusals */
    est.pol = NULL;
    TK_ASSERT(smf_n4_build_est(&est, body, sizeof body, &blen) != 0);
    est.pol = &pol;
    est.has4 = false;
    TK_ASSERT(smf_n4_build_est(&est, body, sizeof body, &blen) != 0); /* no UE address at all */
    est.has4 = true;
    TK_ASSERT(smf_n4_build_est(&est, body, 100, &blen) != 0); /* too small a buffer */
    est.dnn = "a..b";
    TK_ASSERT(smf_n4_build_est(&est, body, sizeof body, &blen) != 0); /* empty DNN label */
    smf_policy_free(&pol);

    /* response parsing on hostile input */
    {
        smf_n4_msg m;
        smf_n4_est_rsp o;
        memset(&m, 0, sizeof m);
        m.h.msg_type = PFCP_SESSION_ESTABLISHMENT_RESPONSE;
        TK_ASSERT(smf_n4_parse_est_rsp(&m, &o) == 0 && !o.ok); /* empty */
        m.body[0] = 0x00;
        m.body[1] = PFCP_IE_CAUSE;
        m.body[2] = 0;
        m.body[3] = 1;
        m.body[4] = PFCP_CAUSE_REJECTED;
        m.blen = 5;
        TK_ASSERT(smf_n4_parse_est_rsp(&m, &o) == 0 && !o.ok && o.cause == PFCP_CAUSE_REJECTED && smf_n4_cause_of(&m) == PFCP_CAUSE_REJECTED);
        m.body[4] = 0;
        m.blen = 4; /* IE longer than the body */
        TK_ASSERT(smf_n4_parse_est_rsp(&m, &o) != 0 || !o.ok);
        m.h.msg_type = PFCP_SESSION_MODIFICATION_RESPONSE;
        TK_ASSERT(smf_n4_parse_est_rsp(&m, &o) != 0);
    }
}

/* ---- policy updates ---- */

static smf_policy policy_from(const char *json)
{
    smf_policy p;
    char err[200];
    g5c_json *d = J(json);
    TK_ASSERT(smf_policy_from_decision(d, &p, err, sizeof err) == 0);
    g5c_json_free(d);
    return p;
}

static void test_policy_update(void)
{
    smf_policy a = mapping_policy(), b;
    smf_n4_est est;
    uint8_t body[2048], ub[2048];
    size_t blen = 0, ulen = 0;
    smf_n4_msg rsp;
    smf_n4_est_rsp er;
    pfcp_header h;
    size_t bl;
    const uint8_t *bp;
    bool changed;
    g5c_bytes n1, n2;

    /* ids of the initial decision: flows 1..3 -> QFI 1..3 and QER 2..4, rules V (UL+DL), D (DL only), U (UL only) */
    smf_policy_assign_ids(&a, NULL);
    TK_ASSERT(a.flows[1].qfi == 2 && a.flows[1].qer_id == 3 && a.flows[2].qfi == 3 && a.flows[2].qer_id == 4);
    TK_ASSERT(a.rules[0].pdr_ul == 100 && a.rules[0].pdr_dl == 101 && a.rules[1].pdr_ul == 0 && a.rules[1].pdr_dl == 103 && a.rules[2].pdr_ul == 104 && a.rules[2].pdr_dl == 0);
    TK_ASSERT(a.rules[0].qri == 2 && a.rules[1].qri == 3 && a.rules[2].qri == 4);

    /* the new decision: V unchanged but with a lower guaranteed rate, D gone, U unchanged, a new rule W with new QoS data, session AMBR halved */
    b = policy_from("{\"sessRules\":{\"s\":{\"authSessAmbr\":{\"uplink\":\"50 Mbps\",\"downlink\":\"100 Mbps\"},\"authDefQos\":{\"5qi\":9,\"arp\":{\"priorityLevel\":8}}}},"
                    "\"pccRules\":{"
                    "\"V\":{\"pccRuleId\":\"V\",\"precedence\":10,\"flowInfos\":[{\"flowDescription\":\"permit out 17 from 198.51.100.0/24 5060 to assigned\",\"flowDirection\":\"BIDIRECTIONAL\"}],\"refQosData\":[\"Qv\"]},"
                    "\"U\":{\"pccRuleId\":\"U\",\"precedence\":30,\"flowInfos\":[{\"flowDescription\":\"permit out 6 from 192.0.2.77 to assigned\",\"flowDirection\":\"UPLINK\"}]},"
                    "\"W\":{\"pccRuleId\":\"W\",\"precedence\":40,\"flowInfos\":[{\"flowDescription\":\"permit out 17 from 192.0.2.0/24 to assigned\",\"flowDirection\":\"DOWNLINK\"}],\"refQosData\":[\"Qw\"]}},"
                    "\"qosDecs\":{\"Qv\":{\"qosId\":\"Qv\",\"5qi\":1,\"gbrUl\":\"512 Kbps\",\"gbrDl\":\"512 Kbps\",\"maxbrUl\":\"1 Mbps\",\"maxbrDl\":\"1 Mbps\"},"
                    "\"Qw\":{\"qosId\":\"Qw\",\"5qi\":4,\"gbrUl\":\"1 Mbps\",\"gbrDl\":\"1 Mbps\"}}}");
    smf_policy_assign_ids(&b, &a);
    TK_ASSERT(b.nflows == 3 && b.flows[1].qfi == 2 && b.flows[1].qer_id == 3);     /* Qv keeps its identity */
    TK_ASSERT(b.flows[2].qfi == 4 && b.flows[2].qer_id == 5);                       /* Qw: QFI 3 is not reused in the same step (Qd is being deleted); new QER id */
    TK_ASSERT(b.rules[0].pdr_ul == 100 && b.rules[0].pdr_dl == 101 && b.rules[0].qri == 2); /* V unchanged */
    TK_ASSERT(b.rules[1].pdr_ul == 104 && b.rules[1].qri == 4);                              /* U unchanged */
    TK_ASSERT(b.rules[2].pdr_ul == 0 && b.rules[2].pdr_dl == 105 && b.rules[2].qri == 5);   /* W: fresh PDR id; QRI 3 is D's, being deleted in the same step */

    /* the engine accepts the update, and traffic follows the new rules */
    memset(&est, 0, sizeof est);
    est.cp_seid = 0x77;
    est.smf_ip4[0] = 127;
    est.smf_ip4[1] = 1;
    est.smf_ip4[3] = 4;
    est.dnn = "internet";
    est.pdu_type = 1;
    est.has4 = true;
    memcpy(est.ue4, UEIP, 4);
    est.pol = &a;
    TK_ASSERT(smf_n4_build_est(&est, body, sizeof body, &blen) == 0);
    rig_new(NULL);
    {
        bld_t as;
        b_assoc(&as, 0xe5000002u);
        send_n4(PFCP_ASSOCIATION_SETUP_REQUEST, false, 0, as.body, as.pos);
    }
    rig_reset_captures();
    send_n4(PFCP_SESSION_ESTABLISHMENT_REQUEST, true, 0, body, blen);
    bp = rig_n4(PFCP_SESSION_ESTABLISHMENT_RESPONSE, &h, &bl);
    TK_ASSERT(bp != NULL);
    memcpy(rsp.body, bp, bl);
    rsp.blen = bl;
    rsp.h = h;
    TK_ASSERT(smf_n4_parse_est_rsp(&rsp, &er) == 0 && er.ok);
    {   /* activate */
        smf_an_tunnel t;
        uint8_t mb[256];
        size_t ml = 0;
        memset(&t, 0, sizeof t);
        t.v4 = true;
        memcpy(t.ip4, GNB4, 4);
        t.teid = 0x7001;
        TK_ASSERT(smf_n4_build_mod_activate(&t, "internet", mb, sizeof mb, &ml) == 0);
        send_n4(PFCP_SESSION_MODIFICATION_REQUEST, true, er.up_seid, mb, ml);
    }
    est.pol = &b;
    TK_ASSERT(smf_n4_build_policy_update(&est, &a, &b, ub, sizeof ub, &ulen, &changed) == 0 && changed && ulen > 0);
    rig_reset_captures();
    send_n4(PFCP_SESSION_MODIFICATION_REQUEST, true, er.up_seid, ub, ulen);
    bp = rig_n4(PFCP_SESSION_MODIFICATION_RESPONSE, &h, &bl);
    TK_ASSERT(bp != NULL && cause_of(bp, bl) == PFCP_CAUSE_ACCEPTED);
    {
        static const struct {
            uint8_t src[4];
            uint8_t proto;
            uint16_t sport;
            uint8_t qfi;
        } dl[] = {{{198, 51, 100, 5}, 17, 5060, 2},  /* V: still its own flow */
                  {{203, 0, 113, 9}, 6, 443, 1},      /* D was removed: default flow */
                  {{192, 0, 2, 5}, 17, 4000, 4}};     /* W: the new flow */
        for (size_t i = 0; i < sizeof dl / sizeof dl[0]; i++) {
            uint8_t ip[60];
            gtpu_header gh;
            const uint8_t *pl;
            size_t pln, before = RIG.ngtpu;
            uint8_t t, q;
            bool rqi;
            ipv4(ip, dl[i].src, UEIP, dl[i].proto, dl[i].sport, 5060, 40);
            upf_n6_packet(U, ip, 40, NOW);
            TK_ASSERT(RIG.ngtpu == before + 1);
            TK_ASSERT(gtpu_decode(RIG.gtpu[RIG.ngtpu - 1].d, RIG.gtpu[RIG.ngtpu - 1].n, &gh, &pl, &pln) == 0 && gh.next == 1 &&
                      gtpu_as_pdu_session_container(&gh.ext[0], &t, &q, &rqi));
            if (q != dl[i].qfi)
                TK_FAIL("after the update, downlink packet %zu has QFI %u, wanted %u", i, q, dl[i].qfi);
        }
    }
    upf_free(U);

    /* nothing changed: no N4 message, no NAS command, no N2 transfer */
    smf_policy_assign_ids(&b, &b);
    TK_ASSERT(smf_n4_build_policy_update(&est, &b, &b, ub, sizeof ub, &ulen, &changed) == 0 && !changed && ulen == 0);
    g5c_bytes_init(&n1);
    g5c_bytes_init(&n2);
    TK_ASSERT(smf_gsm_build_mod_cmd(5, &b, &b, &n1) == 1 && smf_n2_build_mod_req(&b, &b, &n2) == 1);

    /* the commands for a -> b */
    g5c_bytes_clear(&n1);
    TK_ASSERT(smf_gsm_build_mod_cmd(5, &a, &b, &n1) == 0);
    {
        nas_msg m;
        const uint8_t *v;
        size_t n;
        TK_ASSERT(nas_msg_decode(n1.data, n1.len, &m) == NAS_OK && m.def->msg_type == 0xcb && m.pdu_session_id == 5 && m.pti == 0);
        v = nas_msg_get(&m, "Session AMBR", &n);
        TK_ASSERT(v && n == 6);
        v = nas_msg_get(&m, "Authorized QoS rules", &n);
        /* delete D (QRI 3, operation 010), then create W (QRI 5) */
        TK_ASSERT(v && n > 8 && v[0] == 3 && v[1] == 0 && v[2] == 1 && v[3] == 0x40);
        TK_ASSERT(v[4] == 5 && (v[7] & 0xe0) == 0x20); /* create QRI 5 */
        v = nas_msg_get(&m, "Authorized QoS flow descriptions", &n);
        TK_ASSERT(v != NULL);
        {   /* Qd (QFI 3) deleted, Qw (QFI 4) created, Qv (QFI 2) modified */
            size_t off = 0, deletes = 0, creates = 0, modifies = 0;
            while (off + 3 <= n) {
                unsigned op = v[off + 1] >> 5, np = v[off + 2] & 0x3f;
                size_t plen2 = 0, po = off + 3;
                for (unsigned k = 0; k < np && po + 2 <= n; k++) {
                    plen2 = v[po + 1];
                    po += 2 + plen2;
                }
                deletes += op == 2;
                creates += op == 1;
                modifies += op == 3;
                off = po;
            }
            TK_ASSERT(deletes == 1 && creates == 1 && modifies == 1);
        }
        nas_msg_free(&m);
    }
    TK_ASSERT(smf_n2_build_mod_req(&a, &b, &n2) == 0 && n2.len > 5);
    {
        char err[160];
        g5c_json *t = ngap_decode_as("PDUSessionResourceModifyRequestTransfer", n2.data, n2.len, err, sizeof err);
        const g5c_json *ies;
        TK_ASSERT(t != NULL);
        ies = g5c_json_get(t, "protocolIEs");
        TK_ASSERT(g5c_json_len(ies) >= 2); /* AMBR and the QoS flow list (Qv modified, Qw added); Qd was replaced under the same QFI */
        g5c_json_free(t);
    }
    g5c_bytes_free(&n1);
    g5c_bytes_free(&n2);
    smf_policy_free(&a);
    smf_policy_free(&b);
}

/* ---- IPv6 router advertisement ---- */

static uint16_t icmp6_sum(const uint8_t src[16], const uint8_t dst[16], const uint8_t *m, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < 16; i += 2)
        sum += (uint32_t)(src[i] << 8 | src[i + 1]) + (uint32_t)(dst[i] << 8 | dst[i + 1]);
    sum += (uint32_t)len + 58u;
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)(m[i] << 8 | m[i + 1]);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static size_t build_rs(uint8_t *p, bool good_sum, uint8_t hop, bool unspecified_src)
{
    static const uint8_t ll[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55};
    static const uint8_t un[16] = {0};
    static const uint8_t all_routers[16] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const uint8_t *src = unspecified_src ? un : ll;
    uint16_t c;
    memset(p, 0, 48);
    p[0] = 0x60;
    p[5] = 8;
    p[6] = 58;
    p[7] = hop;
    memcpy(p + 8, src, 16);
    memcpy(p + 24, all_routers, 16);
    p[40] = 133;
    c = icmp6_sum(src, all_routers, p + 40, 8);
    if (!good_sum)
        c ^= 0x1234;
    p[42] = (uint8_t)(c >> 8);
    p[43] = (uint8_t)c;
    return 48;
}

static void test_router_advertisement(void)
{
    uint8_t rs[64], ra[256];
    size_t n = 0, rl;
    static const uint8_t prefix[8] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x45, 0x00, 0x07};
    rl = build_rs(rs, true, 255, false);
    TK_ASSERT(smf_ra_build(prefix, 1400, rs, rl, ra, sizeof ra, &n) == 0 && n == 40 + 48 + 8);
    TK_ASSERT((ra[0] >> 4) == 6 && ra[6] == 58 && ra[7] == 255 && ra[40] == 134 && ra[41] == 0);
    TK_ASSERT(memcmp(ra + 24, rs + 8, 16) == 0);                             /* answered to the soliciting address */
    TK_ASSERT(ra[44] == 64 && ra[45] == 0 && ra[46] == 0x07 && ra[47] == 0x08); /* hop limit, no M/O, router lifetime 1800 s */
    TK_ASSERT(ra[56] == 3 && ra[57] == 4 && ra[58] == 64 && ra[59] == 0xc0);    /* prefix information: /64, on-link + autonomous */
    TK_ASSERT(memcmp(ra + 72, prefix, 8) == 0 && ra[88] == 5 && ra[89] == 1 && ra[94] == 0x05 && ra[95] == 0x78); /* the prefix and the MTU option */
    {   /* the checksum the receiver recomputes */
        uint8_t tmp[64];
        memcpy(tmp, ra + 40, n - 40);
        tmp[2] = tmp[3] = 0;
        TK_ASSERT(icmp6_sum(ra + 8, ra + 24, tmp, n - 40) == (uint16_t)(ra[42] << 8 | ra[43]));
    }
    /* without an MTU the option is left out; a solicitation from :: is answered to all nodes */
    rl = build_rs(rs, true, 255, true);
    TK_ASSERT(smf_ra_build(prefix, 0, rs, rl, ra, sizeof ra, &n) == 0 && n == 40 + 48 && ra[24] == 0xff && ra[25] == 0x02 && ra[39] == 1);
    /* not solicitations RFC 4861 accepts */
    TK_ASSERT(smf_ra_build(prefix, 0, rs, 20, ra, sizeof ra, &n) != 0);
    rl = build_rs(rs, false, 255, false);
    TK_ASSERT(smf_ra_build(prefix, 0, rs, rl, ra, sizeof ra, &n) != 0); /* bad checksum */
    rl = build_rs(rs, true, 64, false);
    TK_ASSERT(smf_ra_build(prefix, 0, rs, rl, ra, sizeof ra, &n) != 0); /* hop limit must be 255 */
    rl = build_rs(rs, true, 255, false);
    rs[40] = 134;
    TK_ASSERT(smf_ra_build(prefix, 0, rs, rl, ra, sizeof ra, &n) != 0); /* not type 133 */
    rs[40] = 133;
    rs[0] = 0x45;
    TK_ASSERT(smf_ra_build(prefix, 0, rs, rl, ra, sizeof ra, &n) != 0); /* not IPv6 */
    TK_ASSERT(smf_ra_build(prefix, 0, rs, rl, ra, 50, &n) != 0);       /* no room */
}

int main(void)
{
    g5c_log_init("error", false);
    test_bitrates();
    test_pools();
    test_ipfilter();
    test_policy();
    test_gsm();
    test_n2();
    test_rule_mapping();
    test_policy_update();
    test_router_advertisement();
    printf("smf units: OK\n");
    return 0;
}
