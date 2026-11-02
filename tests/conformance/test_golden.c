/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Conformance against the golden traces (Open5GS v2.8.0 oracle driven by UERANSIM):
 *  - every NAS message carried in the traces decodes and re-encodes byte-exact;
 *  - the real NAS integrity MACs verify with keys re-derived by our own crypto (K, OPc, RAND from the trace);
 *  - the 5G-AKA vectors our UDM generates are bit-exact against Open5GS's AUTN and the UE's RES*;
 *  - 5GSM messages nested in UL/DL NAS transport round-trip. */
#define _DEFAULT_SOURCE
#include <stdio.h>

#include "g5c/config.h"
#include "g5c/nas.h"
#include "g5c/ngap.h"
#include "g5c/testkit.h"
#include "g5c/udm.h"

#ifndef G5C_FIXTURES
#error "G5C_FIXTURES must point at tests/fixtures/golden"
#endif

#define K_HEX "465B5CE8B199B49FAA5F0A2EE238A6BC"
#define OPC_HEX "E8ED289DEBA952E4283B54E88E6183CA"
#define SNN "5G:mnc001.mcc001.3gppnetwork.org"

static const char *const S[] = {"s1_ngap_pdus.hex", "s2_ngap_pdus.hex", "s3_ngap_pdus.hex"};
static const char *const EXTRA[] = {"ngap_handover_master_pdus.hex", "ngap_handover_final_pdus.hex",
                                     "ngap_release_scenario_pdus.hex"};

typedef struct {
    bool ul;
    uint8_t *nas;
    size_t len;
} nas_item;

typedef struct {
    nas_item *v;
    size_t n, cap;
} nas_list;

static void list_free(nas_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i].nas);
    free(l->v);
    memset(l, 0, sizeof *l);
}

/* NAS PDUs of a trace with their direction (true = uplink, from the UE) */
static void load_nas(const char *file, nas_list *out)
{
    char path[512], *text, *line, *save = NULL;
    size_t len = 0;
    snprintf(path, sizeof path, "%s/%s", G5C_FIXTURES, file);
    text = g5c_read_file(path, 1U << 24, &len);
    TK_ASSERT(text != NULL);
    for (line = strtok_r(text, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        char *sp = strchr(line, ' ');
        uint8_t b[4096], nas[4096];
        long n, nl;
        g5c_json *pdu;
        const g5c_json *ie;
        const char *name, *hex;
        bool ul;
        if (sp == NULL)
            continue;
        n = tk_unhex(sp + 1, b, sizeof b);
        if (n < 0) {
            char *cr = strchr(sp + 1, '\r');
            if (cr) {
                *cr = 0;
                n = tk_unhex(sp + 1, b, sizeof b);
            }
        }
        TK_ASSERT(n > 0);
        pdu = ngap_decode(b, (size_t)n, NULL, 0);
        TK_ASSERT(pdu != NULL);
        name = ngap_procedure_name(pdu);
        ul = strcmp(name, "InitialUEMessage") == 0 || strcmp(name, "UplinkNASTransport") == 0;
        if (ul || strcmp(name, "DownlinkNASTransport") == 0 || strcmp(name, "InitialContextSetupRequest") == 0) {
            ie = ngap_find_ie(ngap_pdu_message(pdu), NGAP_IE_NAS_PDU);
            hex = g5c_json_str(ie);
            if (hex != NULL) {
                nl = tk_unhex(hex, nas, sizeof nas);
                TK_ASSERT(nl > 0);
                if (out->n == out->cap) {
                    out->cap = out->cap ? out->cap * 2 : 32;
                    out->v = g5c_xrealloc(out->v, out->cap * sizeof *out->v);
                }
                out->v[out->n].ul = ul;
                out->v[out->n].len = (size_t)nl;
                out->v[out->n].nas = g5c_xmalloc((size_t)nl);
                memcpy(out->v[out->n].nas, nas, (size_t)nl);
                out->n++;
            }
        }
        g5c_json_free(pdu);
    }
    free(text);
}

static void note(char seen[][96], size_t *n, const char *name)
{
    for (size_t i = 0; i < *n; i++)
        if (strcmp(seen[i], name) == 0)
            return;
    if (*n < 64)
        snprintf(seen[(*n)++], 96, "%s", name);
}

static bool was_seen(char seen[][96], size_t n, const char *name)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(seen[i], name) == 0)
            return true;
    return false;
}

static void test_all_nas_roundtrip(void)
{
    char seen[64][96];
    size_t nseen = 0;
    static const char *const must[] = {"Registration request", "Authentication request", "Authentication response", "Security mode command"};
    for (int t = 0; t < 6; t++) {
        nas_list l = {0};
        load_nas(t < 3 ? S[t] : EXTRA[t - 3], &l);
        for (size_t i = 0; i < l.n; i++) {
            nas_any a;
            nas_msg inner;
            bool have = false;
            TK_ASSERT(nas_any_decode(l.v[i].nas, l.v[i].len, &a) == 0);
            if (!a.is_protected) {
                g5c_bytes re;
                g5c_bytes_init(&re);
                TK_ASSERT(nas_msg_encode(&a.plain, &re) == 0);
                TK_ASSERT(re.len == l.v[i].len && memcmp(re.data, l.v[i].nas, re.len) == 0);
                g5c_bytes_free(&re);
                note(seen, &nseen, nas_msg_name(&a.plain));
            } else if (nas_msg_decode(a.prot.payload, a.prot.payload_len, &inner) == 0) {
                /* inner message is decodable directly when not ciphered (NEA0 in these traces) */
                have = true;
                note(seen, &nseen, nas_msg_name(&inner));
            } /* else: ciphered with a key we do not hold (other captures) */
            if (have)
                nas_msg_free(&inner);
            nas_any_free(&a);
        }
        list_free(&l);
    }
    for (size_t i = 0; i < sizeof must / sizeof *must; i++)
        if (!was_seen(seen, nseen, must[i]))
            TK_FAIL("%s not seen in the traces", must[i]);
    printf("  %zu distinct NAS message types seen\n", nseen);
}

static void test_integrity_macs(void)
{
    uint8_t k[16], opc[16];
    TK_ASSERT(tk_unhex(K_HEX, k, 16) == 16 && tk_unhex(OPC_HEX, opc, 16) == 16);
    for (int t = 0; t < 3; t++) {
        nas_list l = {0};
        g5c_milenage m;
        nas_sec_ctx ctxs[8];
        size_t nctx = 0, checked = 0;
        /* One security context per Authentication request seen (a trace may hold several procedures). The oracle
         * selected NIA2 / NEA0 (see the UE log). */
        g5c_milenage_init(&m, k, opc);
        load_nas(S[t], &l);
        for (size_t i = 0; i < l.n; i++) {
            nas_any a;
            TK_ASSERT(nas_any_decode(l.v[i].nas, l.v[i].len, &a) == 0);
            if (!a.is_protected && strcmp(nas_msg_name(&a.plain), "Authentication request") == 0) {
                size_t rl = 0, al = 0;
                const uint8_t *rand = nas_msg_get(&a.plain, "Authentication parameter RAND (5G authentication challenge)", &rl),
                              *autn = nas_msg_get(&a.plain, "Authentication parameter AUTN (5G authentication challenge)", &al);
                g5c_milenage_vector v;
                uint8_t kausf[32], kseaf[32], kamf[32];
                TK_ASSERT(rand && rl == 16 && autn && al == 16 && nctx < 8);
                TK_ASSERT(g5c_milenage_f2345(&m, rand, &v) == 0);
                TK_ASSERT(g5c_kausf(v.ck, v.ik, SNN, autn, kausf) == 0 && g5c_kseaf(kausf, SNN, kseaf) == 0);
                /* K_AMF takes the digits-only IMSI as SUPI input */
                TK_ASSERT(g5c_kamf(kseaf, "001010000000001", (const uint8_t[]){0, 0}, kamf) == 0);
                TK_ASSERT(g5c_algo_key(kamf, G5C_ALG_NAS_INT, 2, ctxs[nctx].knas_int) == 0);
                TK_ASSERT(g5c_algo_key(kamf, G5C_ALG_NAS_ENC, 0, ctxs[nctx].knas_enc) == 0);
                ctxs[nctx].int_alg = NAS_IA2;
                ctxs[nctx].enc_alg = NAS_EA0;
                nctx++;
            } else if (a.is_protected) {
                g5c_dir dir = l.v[i].ul ? G5C_DIR_UL : G5C_DIR_DL;
                uint32_t count = a.prot.seq;
                const nas_sec_ctx *ctx = NULL;
                g5c_bytes inner, again;
                nas_msg im;
                nas_any q;
                for (size_t c = nctx; c > 0; c--)
                    if (nas_protected_verify(&a.prot, &ctxs[c - 1], dir, count)) {
                        ctx = &ctxs[c - 1];
                        break;
                    }
                if (ctx == NULL)
                    TK_FAIL("MAC of a protected message (sht %u, seq %u, %s) verifies under none of %zu contexts", a.prot.sht,
                            a.prot.seq, l.v[i].ul ? "UL" : "DL", nctx);
                g5c_bytes_init(&inner);
                g5c_bytes_init(&again);
                TK_ASSERT(nas_protected_open(&a.prot, ctx, dir, count, &inner) == 0);
                TK_ASSERT(nas_msg_decode(inner.data, inner.len, &im) == 0);
                {   /* the inner message round-trips, and re-protecting reproduces the wire bytes exactly */
                    g5c_bytes re;
                    g5c_bytes_init(&re);
                    TK_ASSERT(nas_msg_encode(&im, &re) == 0 && re.len == inner.len && memcmp(re.data, inner.data, re.len) == 0);
                    g5c_bytes_free(&re);
                }
                nas_msg_free(&im);
                TK_ASSERT(nas_protect(ctx, a.prot.sht, dir, count, inner.data, inner.len, &again) == 0);
                TK_ASSERT(again.len == l.v[i].len && memcmp(again.data, l.v[i].nas, again.len) == 0);
                TK_ASSERT(nas_any_decode(again.data, again.len, &q) == 0 && q.is_protected && q.prot.seq == a.prot.seq &&
                          memcmp(q.prot.mac, a.prot.mac, 4) == 0);
                nas_any_free(&q);
                g5c_bytes_free(&inner);
                g5c_bytes_free(&again);
                checked++;
            }
            nas_any_free(&a);
        }
        TK_ASSERT(checked > 0);
        printf("  %s: %zu protected messages verified under %zu contexts\n", S[t], checked, nctx);
        list_free(&l);
    }
}

/* Phase 1 exit criterion: our vector generation is bit-exact against Open5GS. In the traces Open5GS (UDM+AUSF)
 * produced RAND and AUTN for the subscriber's K/OPc and UERANSIM answered with RES*. For every authentication request
 * we recover the SQN and AMF from AUTN, regenerate the vector with the UDM's own code and require the same AUTN
 * (MAC-A included), and require our XRES* to equal the RES* the independent UE implementation computed. */
static void test_udm_vs_open5gs(void)
{
    uint8_t k[16], opc[16];
    int checked = 0;
    TK_ASSERT(tk_unhex(K_HEX, k, 16) == 16 && tk_unhex(OPC_HEX, opc, 16) == 16);
    for (int t = 0; t < 3; t++) {
        nas_list l = {0};
        g5c_milenage m;
        uint8_t pending_xres[16];
        bool have_pending = false;
        g5c_milenage_init(&m, k, opc);
        load_nas(S[t], &l);
        for (size_t i = 0; i < l.n; i++) {
            nas_any a;
            const char *name;
            TK_ASSERT(nas_any_decode(l.v[i].nas, l.v[i].len, &a) == 0);
            name = a.is_protected ? "" : nas_msg_name(&a.plain);
            if (strcmp(name, "Authentication request") == 0) {
                size_t rl = 0, al = 0;
                const uint8_t *rand = nas_msg_get(&a.plain, "Authentication parameter RAND (5G authentication challenge)", &rl),
                              *autn = nas_msg_get(&a.plain, "Authentication parameter AUTN (5G authentication challenge)", &al);
                g5c_milenage_vector v;
                uint64_t sqn = 0;
                udm_heav av;
                TK_ASSERT(rand && rl == 16 && autn && al == 16);
                TK_ASSERT(g5c_milenage_f2345(&m, rand, &v) == 0);
                for (int b = 0; b < 6; b++) /* recover SQN the way a UE does */
                    sqn = (sqn << 8) | (uint64_t)(autn[b] ^ v.ak[b]);
                TK_ASSERT(udm_generate_av(k, opc, sqn, autn + 6 /* AMF */, rand, SNN, &av) == 0);
                if (memcmp(av.autn, autn, 16) != 0) {
                    char *a1 = g5c_hex_encode(autn, 16), *a2 = g5c_hex_encode(av.autn, 16);
                    TK_FAIL("AUTN differs from Open5GS for SQN %llx: %s vs ours %s", (unsigned long long)sqn, a1, a2);
                }
                memcpy(pending_xres, av.xres_star, 16);
                have_pending = true;
                checked++;
            } else if (strcmp(name, "Authentication response") == 0) {
                size_t rl = 0;
                const uint8_t *res = nas_msg_get(&a.plain, "Authentication response parameter", &rl);
                TK_ASSERT(have_pending && res && rl == 16);
                if (memcmp(res, pending_xres, 16) != 0)
                    TK_FAIL("RES* computed by UERANSIM differs from our XRES*");
                have_pending = false;
                checked++;
            }
            nas_any_free(&a);
        }
        list_free(&l);
    }
    printf("  %d AUTN/RES* checks against the real traces passed\n", checked);
    TK_ASSERT(checked >= 6);
}

static void test_nested_5gsm(void)
{
    int n = 0;
    for (int t = 0; t < 6; t++) {
        nas_list l = {0};
        load_nas(t < 3 ? S[t] : EXTRA[t - 3], &l);
        for (size_t i = 0; i < l.n; i++) {
            nas_any a;
            nas_msg inner;
            const nas_msg *m = NULL;
            bool own = false;
            const uint8_t *pc;
            size_t pl = 0;
            TK_ASSERT(nas_any_decode(l.v[i].nas, l.v[i].len, &a) == 0);
            if (!a.is_protected) {
                m = &a.plain;
            } else if (nas_msg_decode(a.prot.payload, a.prot.payload_len, &inner) == 0) {
                m = &inner;
                own = true;
            }
            if (m != NULL && (strcmp(nas_msg_name(m), "UL NAS transport") == 0 || strcmp(nas_msg_name(m), "DL NAS transport") == 0) &&
                (pc = nas_msg_get(m, "Payload container", &pl)) != NULL) {
                nas_msg sm;
                g5c_bytes re;
                TK_ASSERT(nas_msg_decode(pc, pl, &sm) == 0 && sm.def->proto == NAS_PROTO_SM);
                g5c_bytes_init(&re);
                TK_ASSERT(nas_msg_encode(&sm, &re) == 0 && re.len == pl && memcmp(re.data, pc, pl) == 0);
                g5c_bytes_free(&re);
                nas_msg_free(&sm);
                n++;
            }
            if (own)
                nas_msg_free(&inner);
            nas_any_free(&a);
        }
        list_free(&l);
    }
    TK_ASSERT(n >= 1);
    printf("  %d nested 5GSM payloads round-tripped\n", n);
}

static void test_garbage_and_truncation(void)
{
    tk_rng rng = {2024};
    nas_list l = {0};
    for (int i = 0; i < 100000; i++) {
        uint8_t b[60];
        nas_any a;
        nas_msg m;
        tk_rng_bytes(&rng, b, sizeof b);
        b[0] = (b[0] & 1) ? 0x2e : 0x7e;
        if (nas_any_decode(b, sizeof b, &a) == 0)
            nas_any_free(&a);
        if (nas_msg_decode(b, sizeof b, &m) == 0)
            nas_msg_free(&m);
    }
    load_nas(S[0], &l);
    for (size_t i = 0; i < l.n; i++)
        for (size_t cut = 0; cut < l.v[i].len; cut++) {
            nas_any a;
            if (nas_any_decode(l.v[i].nas, cut, &a) == 0)
                nas_any_free(&a);
        }
    list_free(&l);
}

/* G5C_EXPORT_NAS=1: print every NAS PDU of the traces as "<n> <hex>" lines (seed corpus for fuzz/fuzz_nas.c). */
static void export_nas_seeds(void)
{
    unsigned n = 0;
    for (int t = 0; t < 6; t++) {
        nas_list l = {0};
        load_nas(t < 3 ? S[t] : EXTRA[t - 3], &l);
        for (size_t i = 0; i < l.n; i++) {
            char *hx = g5c_hex_encode(l.v[i].nas, l.v[i].len);
            printf("%u %s\n", n++, hx);
            free(hx);
        }
        list_free(&l);
    }
}

int main(void)
{
    if (getenv("G5C_EXPORT_NAS") != NULL) {
        export_nas_seeds();
        return 0;
    }
    test_all_nas_roundtrip();
    test_integrity_macs();
    test_udm_vs_open5gs();
    test_nested_5gsm();
    test_garbage_and_truncation();
    puts("golden conformance: ok");
    return 0;
}
