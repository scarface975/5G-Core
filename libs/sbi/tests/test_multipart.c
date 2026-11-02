/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include <string.h>

#include "g5c/multipart.h"
#include "g5c/testkit.h"

static void test_roundtrip(void)
{
    static const uint8_t bin1[] = {0x2e, 0x01, 0x01, 0xc1, 0x0d, 0x0a, 0x2d, 0x2d, 0x00, 0xff}; /* contains CRLF and dashes */
    static const uint8_t bin2[] = {0x00};
    const char *json = "{\"pduSessionId\":5}";
    g5c_mp_part in[3] = {{NULL, "application/json", (const uint8_t *)json, strlen(json)},
                         {"n1smmsg", "application/vnd.3gpp.5gnas", bin1, sizeof bin1},
                         {"n2smmsg", "application/vnd.3gpp.ngap", bin2, 0}};
    g5c_bytes b;
    char *ct;
    g5c_mp m;
    g5c_bytes_init(&b);
    TK_ASSERT(g5c_mp_build(in, 3, &b, &ct) == 0);
    TK_ASSERT(g5c_mp_is_multipart(ct));
    TK_ASSERT(g5c_mp_parse(ct, b.data, b.len, &m) == 0 && m.n == 3);
    TK_ASSERT(m.parts[0].content_id == NULL && strcmp(m.parts[0].content_type, "application/json") == 0);
    TK_ASSERT(m.parts[0].len == strlen(json) && memcmp(m.parts[0].data, json, m.parts[0].len) == 0);
    TK_ASSERT(g5c_mp_find(&m, "n1smmsg") != NULL && g5c_mp_find(&m, "n1smmsg")->len == sizeof bin1);
    TK_ASSERT(memcmp(g5c_mp_find(&m, "n1smmsg")->data, bin1, sizeof bin1) == 0);
    TK_ASSERT(g5c_mp_find(&m, "n2smmsg")->len == 0 && g5c_mp_find(&m, "nope") == NULL);
    g5c_mp_free(&m);
    g5c_bytes_free(&b);
    free(ct);
}

static void test_parse_variants(void)
{
    g5c_mp m;
    /* quoted boundary, angle-bracket content ids, preamble, transport padding, LF-only header lines are rejected nowhere else */
    const char *body = "preamble\r\n--AaB03x  \r\nContent-Type: application/json\r\n\r\n{}\r\n--AaB03x\r\nContent-ID: <abc>\r\n"
                       "content-type: application/vnd.3gpp.5gnas\r\n\r\nXYZ\r\n--AaB03x--\r\nepilogue";
    TK_ASSERT(g5c_mp_parse("multipart/related; type=\"application/json\"; boundary=\"AaB03x\"", (const uint8_t *)body, strlen(body), &m) == 0);
    TK_ASSERT(m.n == 2 && m.parts[0].len == 2 && g5c_mp_find(&m, "abc") != NULL && g5c_mp_find(&m, "abc")->len == 3);
    g5c_mp_free(&m);
    /* the delimiter at the very start of the body */
    body = "--b1\r\nContent-Type: application/json\r\n\r\n[]\r\n--b1--";
    TK_ASSERT(g5c_mp_parse("Multipart/Related;boundary=b1", (const uint8_t *)body, strlen(body), &m) == 0 && m.n == 1);
    g5c_mp_free(&m);
}

static void test_rejects(void)
{
    g5c_mp m;
    const char *ok = "--b\r\nContent-Type: a/b\r\n\r\nx\r\n--b--";
    TK_ASSERT(g5c_mp_parse("application/json", (const uint8_t *)ok, strlen(ok), &m) != 0);
    TK_ASSERT(g5c_mp_parse("multipart/related", (const uint8_t *)ok, strlen(ok), &m) != 0); /* no boundary */
    TK_ASSERT(g5c_mp_parse("multipart/related; boundary=\"b", (const uint8_t *)ok, strlen(ok), &m) != 0);
    TK_ASSERT(g5c_mp_parse(NULL, (const uint8_t *)ok, strlen(ok), &m) != 0);
    {
        const char *noclose = "--b\r\nContent-Type: a/b\r\n\r\nx";
        TK_ASSERT(g5c_mp_parse("multipart/related; boundary=b", (const uint8_t *)noclose, strlen(noclose), &m) != 0);
    }
    {
        const char *nohdrend = "--b\r\nContent-Type: a/b";
        TK_ASSERT(g5c_mp_parse("multipart/related; boundary=b", (const uint8_t *)nohdrend, strlen(nohdrend), &m) != 0);
    }
    {
        const char *badhdr = "--b\r\nnocolon\r\n\r\nx\r\n--b--";
        TK_ASSERT(g5c_mp_parse("multipart/related; boundary=b", (const uint8_t *)badhdr, strlen(badhdr), &m) != 0);
    }
    {
        const char *empty = "--b--";
        TK_ASSERT(g5c_mp_parse("multipart/related; boundary=b", (const uint8_t *)empty, strlen(empty), &m) != 0);
    }
    {
        /* more parts than we accept */
        g5c_bytes b;
        char *ct;
        g5c_mp_part p[G5C_MP_MAX_PARTS + 1];
        for (size_t i = 0; i < G5C_MP_MAX_PARTS + 1; i++) {
            p[i].content_id = NULL;
            p[i].content_type = "a/b";
            p[i].data = (const uint8_t *)"x";
            p[i].len = 1;
        }
        g5c_bytes_init(&b);
        TK_ASSERT(g5c_mp_build(p, G5C_MP_MAX_PARTS + 1, &b, &ct) == 0);
        TK_ASSERT(g5c_mp_parse(ct, b.data, b.len, &m) != 0);
        g5c_bytes_free(&b);
        free(ct);
    }
}

/* every truncation of a valid body and every single-byte corruption must be handled without a crash (ASan covers the rest) */
static void test_mutations(void)
{
    const char *ok = "--b\r\nContent-Type: a/b\r\nContent-Id: n1\r\n\r\nxyz\r\n--b\r\nContent-Type: c/d\r\n\r\n12345\r\n--b--\r\n";
    size_t n = strlen(ok);
    for (size_t i = 0; i <= n; i++) {
        g5c_mp m;
        if (g5c_mp_parse("multipart/related; boundary=b", (const uint8_t *)ok, i, &m) == 0)
            g5c_mp_free(&m);
    }
    for (size_t i = 0; i < n; i++)
        for (unsigned v = 0; v < 256; v += 51) {
            char c[128];
            g5c_mp m;
            memcpy(c, ok, n);
            c[i] = (char)v;
            if (g5c_mp_parse("multipart/related; boundary=b", (const uint8_t *)c, n, &m) == 0)
                g5c_mp_free(&m);
        }
}

int main(void)
{
    test_roundtrip();
    test_parse_variants();
    test_rejects();
    test_mutations();
    printf("multipart: OK\n");
    return 0;
}
