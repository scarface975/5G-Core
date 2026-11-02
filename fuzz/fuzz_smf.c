/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: everything the SMF parses that a peer controls. Byte 0 selects the entry point, the rest is the input:
 *   0 multipart/related body (an AMF's Create / Update SM Context request)
 *   1 PDU Session Establishment Request NAS message (from the UE through the AMF)
 *   2 PDUSessionResourceSetupResponseTransfer (from the gNB through the AMF)
 *   3 IPFilterRule text (from the PCF)
 *   4 SmPolicyDecision JSON (from the PCF)
 *   5 BitRate text (from the PCF / UDM)
 *   6 PFCP Session Establishment Response body (from the UPF)
 *   7 PDU Session Establishment Request NAS message, then the accept built from what was parsed
 *   8 {"old": SmPolicyDecision, "new": SmPolicyDecision}: identifiers assigned, then the N4 / NAS / N2 modification built between them
 *   9 IPv6 packet: router solicitation parsing and the advertisement
 * Whatever is accepted is pushed through the matching encoder, so the builders see hostile values too. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/base.h"
#include "g5c/smf.h"

static void policy_roundtrip(const g5c_json *d)
{
    smf_policy p;
    char err[200];
    if (smf_policy_from_decision(d, &p, err, sizeof err) != 0)
        return;
    {
        smf_n4_est est;
        uint8_t body[2048];
        size_t blen;
        memset(&est, 0, sizeof est);
        est.dnn = "internet";
        est.pdu_type = 1;
        est.has4 = true;
        est.ue4[0] = 10;
        est.pol = &p;
        (void)smf_n4_build_est(&est, body, sizeof body, &blen);
    }
    {
        smf_est_acc acc;
        g5c_bytes out;
        memset(&acc, 0, sizeof acc);
        acc.psi = 1;
        acc.pti = 1;
        acc.pdu_type = 1;
        acc.ssc_mode = 1;
        acc.ambr_ul = p.ambr_ul;
        acc.ambr_dl = p.ambr_dl;
        acc.pol = &p;
        g5c_bytes_init(&out);
        (void)smf_gsm_build_est_accept(&acc, &out);
        g5c_bytes_free(&out);
    }
    {
        smf_n2_setup n2;
        g5c_bytes out;
        memset(&n2, 0, sizeof n2);
        n2.pdu_type = 1;
        n2.ambr_ul = p.ambr_ul;
        n2.ambr_dl = p.ambr_dl;
        n2.pol = &p;
        g5c_bytes_init(&out);
        (void)smf_n2_build_setup_req(&n2, &out);
        g5c_bytes_free(&out);
    }
    smf_policy_free(&p);
}

static void update_roundtrip(const g5c_json *doc)
{
    smf_policy a, b;
    char err[200];
    smf_n4_est est;
    uint8_t body[4096];
    size_t blen;
    bool changed;
    g5c_bytes n1, n2;
    if (smf_policy_from_decision(g5c_json_get(doc, "old"), &a, err, sizeof err) != 0)
        return;
    if (smf_policy_from_decision(g5c_json_get(doc, "new"), &b, err, sizeof err) != 0) {
        smf_policy_free(&a);
        return;
    }
    smf_policy_assign_ids(&a, NULL);
    smf_policy_assign_ids(&b, &a);
    memset(&est, 0, sizeof est);
    est.dnn = "internet";
    est.pdu_type = 1;
    est.has4 = true;
    est.pol = &b;
    (void)smf_n4_build_policy_update(&est, &a, &b, body, sizeof body, &blen, &changed);
    g5c_bytes_init(&n1);
    g5c_bytes_init(&n2);
    (void)smf_gsm_build_mod_cmd(5, &a, &b, &n1);
    (void)smf_n2_build_mod_req(&a, &b, &n2);
    g5c_bytes_free(&n1);
    g5c_bytes_free(&n2);
    smf_policy_free(&a);
    smf_policy_free(&b);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t sel;
    const uint8_t *in;
    size_t n;
    char err[200];
    if (size == 0)
        return 0;
    sel = data[0] % 10;
    in = data + 1;
    n = size - 1;
    switch (sel) {
    case 0: {
        g5c_mp mp;
        if (g5c_mp_parse("multipart/related; boundary=fuzz", in, n, &mp) == 0) {
            for (size_t i = 0; i < mp.n; i++)
                (void)g5c_mp_find(&mp, mp.parts[i].content_id);
            g5c_mp_free(&mp);
        }
        break;
    }
    case 1:
    case 7: {
        smf_est_req er;
        if (smf_gsm_parse_est_req(in, n, &er) == 0 && sel == 7) {
            smf_est_acc acc;
            g5c_bytes out;
            memset(&acc, 0, sizeof acc);
            acc.psi = er.psi;
            acc.pti = er.pti;
            acc.pdu_type = er.pdu_type >= 1 && er.pdu_type <= 3 ? er.pdu_type : 1;
            acc.ssc_mode = 1;
            acc.req = er;
            acc.ndns4 = 1;
            acc.mtu = 1400;
            g5c_bytes_init(&out);
            (void)smf_gsm_build_est_accept(&acc, &out);
            g5c_bytes_free(&out);
        }
        {
            uint8_t mt, psi, pti;
            (void)smf_gsm_peek(in, n, &mt, &psi, &pti);
        }
        break;
    }
    case 2: {
        smf_an_tunnel t;
        char cause[96];
        (void)smf_n2_parse_setup_rsp(in, n, &t, err, sizeof err);
        (void)smf_n2_parse_cause("PDUSessionResourceSetupUnsuccessfulTransfer", in, n, cause, sizeof cause);
        break;
    }
    case 3: {
        char *s = g5c_xstrndup((const char *)in, n);
        smf_ipfilter f;
        (void)smf_ipfilter_parse(s, &f);
        {
            g5c_bytes b;
            const char *fl[1] = {s};
            uint8_t dir = 0;
            g5c_bytes_init(&b);
            (void)smf_gsm_put_qos_rule(&b, 2, false, 10, 2, fl, &dir, 1);
            g5c_bytes_free(&b);
        }
        free(s);
        break;
    }
    case 4: {
        g5c_json *d = g5c_json_parse((const char *)in, n, err, sizeof err);
        if (d != NULL) {
            policy_roundtrip(d);
            g5c_json_free(d);
        }
        break;
    }
    case 5: {
        char *s = g5c_xstrndup((const char *)in, n);
        uint64_t k;
        if (smf_parse_bitrate(s, &k)) {
            char *f = smf_format_bitrate(k);
            uint64_t back;
            if (!smf_parse_bitrate(f, &back) || back != k)
                abort(); /* what we print must parse back to the same value */
            free(f);
        }
        free(s);
        break;
    }
    case 6: {
        smf_n4_msg m;
        smf_n4_est_rsp r;
        memset(&m, 0, sizeof m);
        m.h.msg_type = PFCP_SESSION_ESTABLISHMENT_RESPONSE;
        m.blen = n > sizeof m.body ? sizeof m.body : n;
        memcpy(m.body, in, m.blen);
        (void)smf_n4_parse_est_rsp(&m, &r);
        (void)smf_n4_cause_of(&m);
        break;
    }
    case 8: {
        g5c_json *d = g5c_json_parse((const char *)in, n, err, sizeof err);
        if (d != NULL) {
            update_roundtrip(d);
            g5c_json_free(d);
        }
        break;
    }
    case 9: {
        static const uint8_t prefix[8] = {0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2};
        uint8_t ra[256];
        size_t ralen;
        (void)smf_ra_build(prefix, 1400, in, n, ra, sizeof ra, &ralen);
        break;
    }
    default:
        break;
    }
    return 0;
}
