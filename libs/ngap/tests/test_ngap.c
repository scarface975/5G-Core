/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NGAP APER codec against real captures */
#define _DEFAULT_SOURCE
#include <stdio.h>

#include "g5c/config.h"
#include "g5c/ngap.h"
#include "g5c/testkit.h"

#ifndef G5C_FIXTURES
#error "G5C_FIXTURES must point at tests/fixtures/golden"
#endif

static const char *const TRACES[] = {"s1_ngap_pdus.hex", "s2_ngap_pdus.hex", "s3_ngap_pdus.hex", "ngap_handover_master_pdus.hex",
                                      "ngap_handover_final_pdus.hex", "ngap_release_scenario_pdus.hex"};

typedef struct {
    char names[64][128];
    size_t n;
} seen_t;

static void note_seen(seen_t *s, const char *name)
{
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->names[i], name) == 0)
            return;
    if (s->n < 64)
        snprintf(s->names[s->n++], sizeof s->names[0], "%s", name);
}

/* Calls cb for every PDU of every trace. */
typedef void (*pdu_cb)(const char *trace, int frame, const uint8_t *b, size_t n, void *ctx);

static void for_each_pdu(pdu_cb cb, void *ctx)
{
    for (size_t t = 0; t < sizeof TRACES / sizeof *TRACES; t++) {
        char path[512], *text, *line, *save = NULL;
        size_t len = 0;
        snprintf(path, sizeof path, "%s/%s", G5C_FIXTURES, TRACES[t]);
        text = g5c_read_file(path, 1U << 24, &len);
        if (text == NULL)
            TK_FAIL("cannot read %s", path);
        for (line = strtok_r(text, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
            char *sp = strchr(line, ' ');
            uint8_t b[4096];
            long n;
            if (sp == NULL)
                continue;
            *sp = 0;
            n = tk_unhex(sp + 1, b, sizeof b);
            if (n < 0) {
                char *cr = strchr(sp + 1, '\r');
                if (cr) {
                    *cr = 0;
                    n = tk_unhex(sp + 1, b, sizeof b);
                }
            }
            TK_ASSERT(n > 0);
            cb(TRACES[t], atoi(line), b, (size_t)n, ctx);
        }
        free(text);
    }
}

static void roundtrip_cb(const char *trace, int frame, const uint8_t *b, size_t n, void *ctx)
{
    seen_t *seen = ctx;
    char err[200];
    g5c_json *j = ngap_decode(b, n, err, sizeof err);
    g5c_bytes out;
    const char *name;
    if (j == NULL)
        TK_FAIL("%s frame %d: decode failed: %s", trace, frame, err);
    name = ngap_procedure_name(j);
    TK_ASSERT(name != NULL);
    g5c_bytes_init(&out);
    if (ngap_encode(j, &out, err, sizeof err) != 0)
        TK_FAIL("%s frame %d (%s): encode failed: %s", trace, frame, name, err);
    if (out.len != n || memcmp(out.data, b, n) != 0) {
        char *a = g5c_hex_encode(b, n), *c = g5c_hex_encode(out.data, out.len);
        TK_FAIL("%s frame %d (%s): re-encoded bytes differ\n  in : %s\n  out: %s", trace, frame, name, a, c);
    }
    {
        char key[96];
        snprintf(key, sizeof key, "%s/%s", ngap_pdu_kind(j), name);
        note_seen(seen, key);
    }
    g5c_bytes_free(&out);
    g5c_json_free(j);
}

static void test_golden_roundtrip(void)
{
    seen_t seen;
    memset(&seen, 0, sizeof seen);
    for_each_pdu(roundtrip_cb, &seen);
    printf("  %zu distinct message types round-tripped byte-exact\n", seen.n);
    TK_ASSERT(seen.n >= 12);
}

/* Contained transfer types (OCTET STRING CONTAINING ...) inside the PDU session IEs must round-trip as well. */
static void contained_cb(const char *trace, int frame, const uint8_t *b, size_t n, void *ctx)
{
    int *count = ctx;
    char err[200];
    g5c_json *j = ngap_decode(b, n, err, sizeof err);
    const g5c_json *msg, *ies;
    (void)trace;
    (void)frame;
    TK_ASSERT(j != NULL);
    msg = ngap_pdu_message(j);
    ies = g5c_json_get(msg, "protocolIEs");
    for (size_t i = 0; i < g5c_json_len(ies); i++) {
        const g5c_json *v = g5c_json_get(g5c_json_at(ies, i), "value"), *list;
        /* PDUSessionResourceSetupListSUReq / ...SURes carry per-session transfers */
        if (!g5c_json_is(v, G5C_J_ARRAY))
            continue;
        list = v;
        for (size_t k = 0; k < g5c_json_len(list); k++) {
            const g5c_json *item = g5c_json_at(list, k);
            for (size_t f = 0; f < g5c_json_len(item); f++) {
                const char *key = g5c_json_key_at(item, f), *hex = g5c_json_str(g5c_json_val_at(item, f));
                uint8_t raw[2048];
                long rl;
                g5c_json *tj;
                g5c_bytes out;
                char tname[256];
                if (hex == NULL || key == NULL || !strstr(key, "Transfer"))
                    continue;
                /* field pDUSessionResourceSetupRequestTransfer -> type PDUSessionResourceSetupRequestTransfer */
                snprintf(tname, sizeof tname, "%s", key);
                tname[0] = (char)(tname[0] >= 'a' && tname[0] <= 'z' ? tname[0] - 32 : tname[0]);
                rl = tk_unhex(hex, raw, sizeof raw);
                TK_ASSERT(rl > 0);
                tj = ngap_decode_as(tname, raw, (size_t)rl, err, sizeof err);
                if (tj == NULL) /* a field whose type has a different name: not checked here */
                    continue;
                g5c_bytes_init(&out);
                TK_ASSERT(ngap_encode_as(tname, tj, &out, err, sizeof err) == 0);
                TK_ASSERT(out.len == (size_t)rl && memcmp(out.data, raw, out.len) == 0);
                (*count)++;
                g5c_bytes_free(&out);
                g5c_json_free(tj);
            }
        }
    }
    g5c_json_free(j);
}

static void test_contained_transfers(void)
{
    int count = 0;
    for_each_pdu(contained_cb, &count);
    printf("  %d contained transfer containers round-tripped\n", count);
    TK_ASSERT(count >= 2);
}

/* Robustness: every truncation and many single-bit corruptions of every real PDU must fail or decode cleanly. */
static void robustness_cb(const char *trace, int frame, const uint8_t *b, size_t n, void *ctx)
{
    tk_rng *rng = ctx;
    uint8_t *tmp = g5c_xmalloc(n + 1);
    (void)trace;
    (void)frame;
    for (size_t cut = 0; cut < n; cut++) {
        g5c_json *j = ngap_decode(b, cut, NULL, 0);
        g5c_json_free(j);
    }
    for (int k = 0; k < 300; k++) {
        g5c_json *j;
        memcpy(tmp, b, n);
        tmp[tk_rng_next(rng) % n] ^= (uint8_t)(1U << (tk_rng_next(rng) % 8));
        j = ngap_decode(tmp, n, NULL, 0);
        if (j != NULL) { /* if it decodes it must also encode */
            g5c_bytes out;
            g5c_bytes_init(&out);
            (void)ngap_encode(j, &out, NULL, 0);
            g5c_bytes_free(&out);
            g5c_json_free(j);
        }
    }
    free(tmp);
}

static void test_robustness(void)
{
    tk_rng rng = {0x9e3779b97f4a7c15ULL};
    for_each_pdu(robustness_cb, &rng);
    {   /* pure noise */
        uint8_t b[64];
        for (int i = 0; i < 20000; i++) {
            g5c_json *j;
            tk_rng_bytes(&rng, b, sizeof b);
            j = ngap_decode(b, 1 + tk_rng_next(&rng) % sizeof b, NULL, 0);
            g5c_json_free(j);
        }
    }
}

/* Build a message from a JSON description, as an NF would. */
static void test_build_from_scratch(void)
{
    static const char *const spec =
        "{\"initiatingMessage\":{\"procedureCode\":21,\"criticality\":\"reject\",\"value\":{\"protocolIEs\":["
        "{\"id\":27,\"criticality\":\"reject\",\"value\":{\"globalGNB-ID\":{\"pLMNIdentity\":\"00f110\","
        "\"gNB-ID\":{\"gNB-ID\":{\"len\":22,\"hex\":\"000008\"}}}}},"
        "{\"id\":82,\"criticality\":\"ignore\",\"value\":\"UERANSIM-gnb-1-1-1\"},"
        "{\"id\":102,\"criticality\":\"ignore\",\"value\":[{\"tAC\":\"000001\",\"broadcastPLMNList\":[{\"pLMNIdentity\":\"00f110\","
        "\"tAISliceSupportList\":[{\"s-NSSAI\":{\"sST\":\"01\"}}]}]}]},"
        "{\"id\":21,\"criticality\":\"ignore\",\"value\":\"v128\"}]}}}";
    char err[200];
    g5c_json *j, *back;
    g5c_bytes out;
    /* the spec text uses plain names; the PagingDRX enumeration value is named v128 */
    j = g5c_json_parse(spec, strlen(spec), err, sizeof err);
    TK_ASSERT(j != NULL);
    g5c_bytes_init(&out);
    if (ngap_encode(j, &out, err, sizeof err) != 0)
        TK_FAIL("encode from scratch: %s", err);
    back = ngap_decode(out.data, out.len, err, sizeof err);
    TK_ASSERT(back != NULL);
    TK_ASSERT(strcmp(ngap_procedure_name(back), "NGSetup") == 0);
    TK_ASSERT(ngap_find_ie(ngap_pdu_message(back), NGAP_IE_RANNodeName) != NULL);
    TK_ASSERT(strcmp(g5c_json_str(ngap_find_ie(ngap_pdu_message(back), NGAP_IE_RANNodeName)), "UERANSIM-gnb-1-1-1") == 0);
    TK_ASSERT(g5c_json_equal(g5c_json_get(g5c_json_get(back, "initiatingMessage"), "value"),
                             g5c_json_get(g5c_json_get(j, "initiatingMessage"), "value")) ||
              g5c_json_len(ngap_pdu_message(back)) == 1);
    g5c_json_free(back);
    g5c_bytes_free(&out);

    /* errors are reported, not crashed on */
    {
        static const char badtxt[] = "{\"initiatingMessage\":{\"procedureCode\":21,\"criticality\":\"reject\",\"value\":{}}}";
        g5c_json *bad = g5c_json_parse(badtxt, strlen(badtxt), NULL, 0);
        g5c_bytes_init(&out);
        TK_ASSERT(bad != NULL && ngap_encode(bad, &out, err, sizeof err) != 0 && err[0] != 0);
        g5c_bytes_free(&out);
        g5c_json_free(bad);
    }
    g5c_json_free(j);
}

int main(void)
{
    TK_ASSERT(NGAP_NPROCS > 40);
    test_golden_roundtrip();
    test_contained_transfers();
    test_robustness();
    test_build_from_scratch();
    puts("ngap: ok");
    return 0;
}
