/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include "g5c/base.h"
#include "g5c/config.h"
#include "g5c/json.h"
#include "g5c/metrics.h"
#include "g5c/testkit.h"

static g5c_json *P(const char *s)
{
    char err[128];
    g5c_json *j = g5c_json_parse(s, strlen(s), err, sizeof err);
    if (j == NULL)
        TK_FAIL("parse failed: %s (%s)", s, err);
    return j;
}

static void expect_bad(const char *s)
{
    g5c_json *j = g5c_json_parse(s, strlen(s), NULL, 0);
    if (j != NULL)
        TK_FAIL("accepted invalid JSON: %s", s);
}

static void test_base64(void)
{
    /* RFC 4648 clause 10 */
    static const char *const enc[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
    static const char *const raw[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    uint8_t buf[16];
    for (size_t i = 0; i < 7; i++) {
        char *e = g5c_base64_encode((const uint8_t *)raw[i], strlen(raw[i]));
        TK_ASSERT(strcmp(e, enc[i]) == 0);
        free(e);
        TK_ASSERT(g5c_base64_decode(enc[i], buf, sizeof buf) == (long)strlen(raw[i]) && memcmp(buf, raw[i], strlen(raw[i])) == 0);
    }
    TK_ASSERT(g5c_base64_decode("Zg=", buf, 16) < 0 && g5c_base64_decode("Zg==Zg==", buf, 16) < 0 && g5c_base64_decode("Z===", buf, 16) < 0);
    TK_ASSERT(g5c_base64_decode("Zh==", buf, 16) < 0 && g5c_base64_decode("Zm9=", buf, 16) < 0); /* non-canonical padding bits */
    TK_ASSERT(g5c_base64_decode("Zm9v!A==", buf, 16) < 0 && g5c_base64_decode("Zm9vYmFy", buf, 5) < 0);
    {
        uint8_t all[256], back[256];
        char *e;
        for (int i = 0; i < 256; i++)
            all[i] = (uint8_t)i;
        e = g5c_base64_encode(all, sizeof all);
        TK_ASSERT(g5c_base64_decode(e, back, sizeof back) == 256 && memcmp(all, back, 256) == 0);
        free(e);
    }
}

static void test_json(void)
{
    g5c_json *j = P("{\"a\":1,\"b\":[true,null,\"x\\u00e9\\n\"],\"c\":{\"d\":-2.5e1},\"a\":7}");
    int64_t i = 0;
    char *s;
    TK_ASSERT(g5c_json_get_int(j, "a", &i) && i == 7); /* last duplicate wins */
    TK_ASSERT(g5c_json_len(g5c_json_get(j, "b")) == 3);
    TK_ASSERT(strcmp(g5c_json_str(g5c_json_at(g5c_json_get(j, "b"), 2)), "x\xc3\xa9\n") == 0);
    {
        double d = 0;
        TK_ASSERT(g5c_json_num(g5c_json_get(g5c_json_get(j, "c"), "d"), &d) && d == -25.0);
    }
    {
        g5c_json *pd = P("{\"status\":404,\"detail\":\"no such SUPI\",\"cause\":\"USER_NOT_FOUND\"}");
        s = g5c_json_to_string(pd, NULL);
        g5c_json_free(pd);
    }
    TK_ASSERT(strcmp(s, "{\"status\":404,\"detail\":\"no such SUPI\",\"cause\":\"USER_NOT_FOUND\"}") == 0);
    free(s);
    g5c_json_free(j);

    expect_bad("{");
    expect_bad("[1,]");
    expect_bad("{\"a\":}");
    expect_bad("01");
    expect_bad("\"\\ud800\"");
    expect_bad("\"a\x01\"");
    expect_bad("[1] x");
    expect_bad("\"\xff\"");
    expect_bad("\"\\u0000\"");
    {   /* depth limit */
        char deep[201];
        memset(deep, '[', 100);
        memset(deep + 100, ']', 100);
        deep[200] = 0;
        expect_bad(deep);
    }
    {   /* builders, set/replace/remove, dup, equal */
        g5c_json *o = g5c_json_new_obj(), *c;
        g5c_json_set_str(o, "k", "v");
        g5c_json_set_int(o, "n", 3);
        g5c_json_set_str(o, "k", "w"); /* replace keeps one key */
        TK_ASSERT(g5c_json_len(o) == 2 && strcmp(g5c_json_get_str(o, "k"), "w") == 0);
        c = g5c_json_dup(o);
        TK_ASSERT(g5c_json_equal(o, c));
        TK_ASSERT(g5c_json_remove(c, "n") && !g5c_json_equal(o, c));
        g5c_json_free(c);
        g5c_json_free(o);
    }
    {   /* round trip of control chars and quotes */
        g5c_json *o = g5c_json_new_obj();
        g5c_json *back;
        char *t;
        g5c_json_set_str(o, "s", "a\"b\\c\n\t\x01");
        t = g5c_json_to_string(o, NULL);
        back = P(t);
        TK_ASSERT(g5c_json_equal(o, back));
        free(t);
        g5c_json_free(back);
        g5c_json_free(o);
    }
}

static g5c_json *Y(const char *s)
{
    char err[128];
    g5c_json *j = g5c_yaml_parse(s, strlen(s), err, sizeof err);
    if (j == NULL)
        TK_FAIL("yaml failed: %s", err);
    return j;
}

static void test_yaml_and_config(void)
{
    g5c_common c;
    char err[160];
    g5c_json *j = Y("\n"
                    "name: udm-1   # comment\n"
                    "plmn: { mcc: '001', mnc: '01' }\n"
                    "sbi: { address: 127.0.0.12, port: 7777 }\n"
                    "list:\n"
                    "  - a: 1\n"
                    "    b: two\n"
                    "  - [1, 2, 3]\n"
                    "  - plain\n"
                    "nested:\n"
                    "  x:\n"
                    "    y: true\n"
                    "same:\n"
                    "- p\n"
                    "- q\n");
    TK_ASSERT(strcmp(g5c_json_get_str(j, "name"), "udm-1") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(j, "plmn"), "mcc"), "001") == 0);
    TK_ASSERT(g5c_json_len(g5c_json_get(j, "list")) == 3);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(j, "list"), 0), "b"), "two") == 0);
    TK_ASSERT(g5c_json_len(g5c_json_at(g5c_json_get(j, "list"), 1)) == 3);
    {
        bool b = false;
        TK_ASSERT(g5c_json_get_bool(g5c_json_get(g5c_json_get(j, "nested"), "x"), "y", &b) && b);
    }
    TK_ASSERT(g5c_json_len(g5c_json_get(j, "same")) == 2);

    TK_ASSERT(g5c_common_parse(j, &c, err, sizeof err) == 0);
    TK_ASSERT(strcmp(c.log_level, "info") == 0 && !c.has_tls && c.port == 7777);
    TK_ASSERT(g5c_common_validate(&c, err, sizeof err) == 0);
    free(c.mcc);
    c.mcc = g5c_xstrdup("1");
    TK_ASSERT(g5c_common_validate(&c, err, sizeof err) != 0 && strstr(err, "plmn.mcc") != NULL);
    free(c.mcc);
    c.mcc = g5c_xstrdup("001");
    free(c.mnc);
    c.mnc = g5c_xstrdup("1234");
    TK_ASSERT(g5c_common_validate(&c, err, sizeof err) != 0 && strstr(err, "plmn.mnc") != NULL);
    free(c.mnc);
    c.mnc = g5c_xstrdup("01");
    c.port = 0;
    TK_ASSERT(g5c_common_validate(&c, err, sizeof err) != 0);
    g5c_common_free(&c);
    g5c_json_free(j);

    /* unknown keys rejected */
    j = Y("name: x\nplmn: {mcc: '001', mnc: '01'}\nsbi: {address: 127.0.0.1, port: 1, typo: 1}\n");
    TK_ASSERT(g5c_common_parse(j, &c, err, sizeof err) != 0 && strstr(err, "typo") != NULL);
    g5c_json_free(j);

    /* bad yaml */
    TK_ASSERT(g5c_yaml_parse("a: &x 1", 7, err, sizeof err) == NULL);
    TK_ASSERT(g5c_yaml_parse("a:\n\tb: 1", 8, err, sizeof err) == NULL);
    /* leading zeros stay strings; plain ints are ints */
    j = Y("a: 001\nb: 12\nc: -3\nd: 1.5\ne: ~\n");
    TK_ASSERT(g5c_json_is(g5c_json_get(j, "a"), G5C_J_STRING) && g5c_json_is(g5c_json_get(j, "b"), G5C_J_INT));
    TK_ASSERT(g5c_json_is(g5c_json_get(j, "d"), G5C_J_DOUBLE) && g5c_json_is(g5c_json_get(j, "e"), G5C_J_NULL));
    g5c_json_free(j);
}

static void test_metrics(void)
{
    g5c_registry *r = g5c_registry_new();
    const g5c_label l1[] = {{"method", "GET"}, {"code", "200"}}, l2[] = {{"code", "200"}, {"method", "GET"}},
                    l3[] = {{"method", "POST"}, {"code", "500"}}, esc[] = {{"v", "a\"b\\c"}},
                    rt[] = {{"route", "/x"}};
    char *t;
    g5c_counter *c = g5c_counter_get(r, "g5c_requests_total", "Requests.", l1, 2);
    g5c_histogram *h;
    g5c_counter_inc(c);
    g5c_counter_add(c, 2);
    g5c_counter_inc(g5c_counter_get(r, "g5c_requests_total", "Requests.", l2, 2));
    g5c_counter_inc(g5c_counter_get(r, "g5c_requests_total", "Requests.", l3, 2));
    {
        g5c_gauge *g = g5c_gauge_get(r, "g5c_ues", "Registered UEs.", NULL, 0);
        g5c_gauge_set(g, 5);
        g5c_gauge_add(g, -2);
    }
    h = g5c_histogram_get(r, "g5c_latency_seconds", "Latency.", rt, 1);
    g5c_histogram_observe(h, 0.0004);
    g5c_histogram_observe(h, 0.003);
    g5c_histogram_observe(h, 5.0);
    g5c_counter_inc(g5c_counter_get(r, "m", "h", esc, 1));
    g5c_gauge_set(g5c_gauge_get(r, "m", "h", esc, 1), 9); /* kind clash: detached, no crash */
    t = g5c_registry_render(r);
    TK_ASSERT(strstr(t, "# TYPE g5c_requests_total counter") != NULL);
    TK_ASSERT(strstr(t, "g5c_requests_total{code=\"200\",method=\"GET\"} 4") != NULL);
    TK_ASSERT(strstr(t, "g5c_requests_total{code=\"500\",method=\"POST\"} 1") != NULL);
    TK_ASSERT(strstr(t, "g5c_ues 3") != NULL);
    TK_ASSERT(strstr(t, "g5c_latency_seconds_bucket{route=\"/x\",le=\"0.0005\"} 1") != NULL);
    TK_ASSERT(strstr(t, "g5c_latency_seconds_bucket{route=\"/x\",le=\"0.005\"} 2") != NULL);
    TK_ASSERT(strstr(t, "g5c_latency_seconds_bucket{route=\"/x\",le=\"+Inf\"} 3") != NULL);
    TK_ASSERT(strstr(t, "g5c_latency_seconds_count{route=\"/x\"} 3") != NULL);
    TK_ASSERT(strstr(t, "m{v=\"a\\\"b\\\\c\"} 1") != NULL);
    free(t);
    g5c_registry_free(r);
}

static void test_base(void)
{
    char u[37], *p;
    uint8_t b[4];
    g5c_bytes bb;
    TK_ASSERT(g5c_uuid_v4(u) == 0 && strlen(u) == 36 && u[14] == '4' && u[8] == '-');
    p = g5c_percent_decode("imsi-0010100000%2d01%zz%4");
    TK_ASSERT(strcmp(p, "imsi-0010100000-01%zz%4") == 0);
    free(p);
    TK_ASSERT(g5c_hex_decode("deadBEEF", b, 4) == 4 && b[0] == 0xde && b[3] == 0xef);
    TK_ASSERT(g5c_hex_decode("abc", b, 4) < 0 && g5c_hex_decode("zz", b, 4) < 0 && g5c_hex_decode("0011223344", b, 4) < 0);
    p = g5c_hex_encode(b, 4);
    TK_ASSERT(strcmp(p, "deadbeef") == 0);
    free(p);
    g5c_bytes_init(&bb);
    for (int i = 0; i < 1000; i++)
        TK_ASSERT(g5c_bytes_printf(&bb, "%d,", i) == 0);
    TK_ASSERT(bb.data[bb.len] == 0 && bb.len > 3000);
    g5c_bytes_free(&bb);
    TK_ASSERT(g5c_is_digits("0123") && !g5c_is_digits("") && !g5c_is_digits("12a"));
}

/* ---- property-based tests for the JSON layer (strategy 4.1: unit layer, property-based) --------------------------- */

static void rand_string(tk_rng *r, char *out, size_t cap)
{
    static const char *const pieces[] = {"a", "Z", "0", " ", "\"", "\\", "/", "\n", "\t", "\x01", "\x1f", "é", "€", "\xf0\x9f\x98\x80", "{", "}", "[", "]", ":", ","};
    size_t n = tk_rng_next(r) % 12, len = 0;
    out[0] = 0;
    for (size_t i = 0; i < n; i++) {
        const char *p = pieces[tk_rng_next(r) % (sizeof pieces / sizeof *pieces)];
        if (len + strlen(p) + 1 >= cap)
            break;
        strcpy(out + len, p);
        len += strlen(p);
    }
}

static g5c_json *rand_json(tk_rng *r, int depth)
{
    char s[128];
    unsigned k = (unsigned)(tk_rng_next(r) % (depth > 0 ? 8 : 5));
    switch (k) {
    case 0:
        return g5c_json_new_null();
    case 1:
        return g5c_json_new_bool((tk_rng_next(r) & 1) != 0);
    case 2: {
        static const int64_t edge[] = {0, -1, 1, 255, 65535, 2147483647LL, -2147483648LL, 9007199254740993LL, INT64_MAX, INT64_MIN};
        return g5c_json_new_int((tk_rng_next(r) & 1) ? edge[tk_rng_next(r) % (sizeof edge / sizeof *edge)] : (int64_t)tk_rng_next(r));
    }
    case 3: {
        static const double d[] = {0.5, -0.25, 1e-7, 3.14159265358979, 1e300, -1e-300, 123456.789, 0.1};
        return g5c_json_new_double(d[tk_rng_next(r) % (sizeof d / sizeof *d)]);
    }
    case 4:
        rand_string(r, s, sizeof s);
        return g5c_json_new_str(s);
    case 5:
    case 6: {
        g5c_json *a = g5c_json_new_arr();
        size_t n = tk_rng_next(r) % 5;
        for (size_t i = 0; i < n; i++)
            g5c_json_push(a, rand_json(r, depth - 1));
        return a;
    }
    default: {
        g5c_json *o = g5c_json_new_obj();
        size_t n = tk_rng_next(r) % 5;
        for (size_t i = 0; i < n; i++) {
            rand_string(r, s, sizeof s);
            g5c_json_set(o, s, rand_json(r, depth - 1)); /* duplicate keys overwrite: the tree stays well formed */
        }
        return o;
    }
    }
}

static void test_json_properties(void)
{
    tk_rng r = {0x9e3779b97f4a7c15ULL};
    for (int iter = 0; iter < 3000; iter++) {
        g5c_json *a = rand_json(&r, 5), *b;
        size_t n1 = 0, n2 = 0;
        char *s1 = g5c_json_to_string(a, &n1), *s2;
        char err[128];
        TK_ASSERT(s1 != NULL);
        b = g5c_json_parse(s1, n1, err, sizeof err);
        if (b == NULL)
            TK_FAIL("iteration %d: our own output does not parse (%s): %s", iter, err, s1);
        if (!g5c_json_equal(a, b))
            TK_FAIL("iteration %d: round trip changed the value: %s", iter, s1);
        s2 = g5c_json_to_string(b, &n2);
        if (n1 != n2 || memcmp(s1, s2, n1) != 0)
            TK_FAIL("iteration %d: serialisation is not stable: %s vs %s", iter, s1, s2);
        /* every strict prefix of an object or array document is incomplete and must be rejected */
        if (g5c_json_is(a, G5C_J_OBJECT) || g5c_json_is(a, G5C_J_ARRAY))
            for (size_t cut = 0; cut < n1; cut += 1 + n1 / 40) {
                g5c_json *t = g5c_json_parse(s1, cut, NULL, 0);
                if (t != NULL)
                    TK_FAIL("iteration %d: accepted a %zu-byte prefix of %zu bytes: %.*s", iter, cut, n1, (int)cut, s1);
            }
        /* corrupting bytes never crashes the parser; whatever it accepts is stable under re-serialisation */
        for (int m = 0; m < 6 && n1 > 0; m++) {
            char *c = g5c_xmalloc(n1 + 1);
            g5c_json *p;
            memcpy(c, s1, n1);
            c[tk_rng_next(&r) % n1] = (char)tk_rng_next(&r);
            p = g5c_json_parse(c, n1, NULL, 0);
            if (p != NULL) {
                size_t n3 = 0;
                char *s3 = g5c_json_to_string(p, &n3);
                g5c_json *q = g5c_json_parse(s3, n3, NULL, 0);
                if (q == NULL || !g5c_json_equal(p, q))
                    TK_FAIL("mutated input %.*s re-serialised as %s", (int)n1, c, s3);
                g5c_json_free(q);
                free(s3);
                g5c_json_free(p);
            }
            free(c);
        }
        g5c_json_free(a);
        g5c_json_free(b);
        free(s1);
        free(s2);
    }
}

/* RFC 8259 conformance table: documents that must parse, and documents that must be refused. */
static void test_json_conformance(void)
{
    static const char *const accept[] = {
        "0", "-0", "1", "-1", "1.5", "-1.5e10", "1E+2", "0.0", "1e-2", "123456789012345678", "true", "false", "null", "\"\"",
        "\"a\"", "\"\\u0041\"", "\"\\ud83d\\ude00\"", "\"\\/\\b\\f\\n\\r\\t\\\"\\\\\"", " \t\r\n[ ]\n", "[]", "{}", "[[]]", "{\"a\":{}}",
        "[1,2,3]", "{\"a\":1,\"b\":[true,null]}", "\"\xe2\x82\xac\"", "\"\xf0\x9f\x98\x80\"",
    };
    static const char *const reject[] = {
        "", " ", "01", "00", "1e999", "-1e999", "[1e400]", "1.", ".5", "+1", "-", "--1", "1e", "1e+", "0x10", "NaN", "Infinity", "-Infinity", "nul", "True", "TRUE",
        "[1,]", "[,1]", "[1 2]", "{\"a\":1,}", "{,}", "{\"a\"}", "{\"a\":}", "{a:1}", "{'a':1}", "'a'", "[", "]", "{", "}", "[}", "{]",
        "\"abc", "abc\"", "\"\\x41\"", "\"\\u12\"", "\"\\u12G4\"", "\"\\ud83d\"", "\"\\ude00\"", "\"\\ud83d\\u0041\"",
        "\"a\nb\"", "\"a\tb\"", "\"\x01\"", "\"\x7f\"x", "[1] x", "[1][2]", "1 2", "\xef\xbb\xbf[]", "\"\xc0\xaf\"", "\"\xe0\x80\xaf\"",
        "\"\xed\xa0\x80\"", "\"\xf4\x90\x80\x80\"", "\"\xff\"", "\"\x80\"", "\"\xc3\"", "[\"\xe2\x82\"]", "// c\n1", "/* c */ 1", "[1,2",
        "{\"a\":1 \"b\":2}", "{\"a\" 1}", "[\"a\" \"b\"]", "\\u0041", "\"\\\"",
    };
    for (size_t i = 0; i < sizeof accept / sizeof *accept; i++) {
        g5c_json *j = g5c_json_parse(accept[i], strlen(accept[i]), NULL, 0);
        if (j == NULL)
            TK_FAIL("valid JSON refused: %s", accept[i]);
        g5c_json_free(j);
    }
    for (size_t i = 0; i < sizeof reject / sizeof *reject; i++) {
        g5c_json *j = g5c_json_parse(reject[i], strlen(reject[i]), NULL, 0);
        if (j != NULL)
            TK_FAIL("invalid JSON accepted: [%s]", reject[i]);
    }
    {   /* an embedded NUL is not valid inside a string or between tokens */
        static const char nul_in_string[] = {'"', 'a', 0, 'b', '"'};
        static const char nul_after[] = {'1', 0};
        TK_ASSERT(g5c_json_parse(nul_in_string, sizeof nul_in_string, NULL, 0) == NULL);
        TK_ASSERT(g5c_json_parse(nul_after, sizeof nul_after, NULL, 0) == NULL);
    }
    {   /* nesting limit: 64 levels are fine, deeper is refused instead of overflowing the stack */
        char deep[400];
        g5c_json *j;
        memset(deep, '[', 64);
        memset(deep + 64, ']', 64);
        j = g5c_json_parse(deep, 128, NULL, 0);
        TK_ASSERT(j != NULL);
        g5c_json_free(j);
        memset(deep, '[', 70);
        memset(deep + 70, ']', 70);
        TK_ASSERT(g5c_json_parse(deep, 140, NULL, 0) == NULL);
    }
    {   /* duplicate keys: lookups see the last one (documented; the parser does not de-duplicate, that would be quadratic) */
        g5c_json *j = g5c_json_parse("{\"a\":1,\"a\":2}", 13, NULL, 0);
        int64_t v = 0;
        TK_ASSERT(j != NULL && g5c_json_get_int(j, "a", &v) && v == 2);
        g5c_json_free(j);
    }
}

/* The object index (used above 16 members) must behave exactly like a linear scan: model-based test. */
static void test_json_object_index(void)
{
    enum { SPACE = 300 };
    tk_rng r = {0x1234567ULL};
    int64_t model[SPACE];
    bool present[SPACE];
    g5c_json *o = g5c_json_new_obj();
    char key[24];
    memset(present, 0, sizeof present);
    for (int op = 0; op < 60000; op++) {
        unsigned k = (unsigned)(tk_rng_next(&r) % SPACE), what = (unsigned)(tk_rng_next(&r) % 10);
        int64_t v;
        snprintf(key, sizeof key, "key-%u", k);
        if (what < 5) {
            v = (int64_t)(tk_rng_next(&r) & 0xffff);
            g5c_json_set_int(o, key, v);
            model[k] = v;
            present[k] = true;
        } else if (what < 7) {
            bool removed = g5c_json_remove(o, key);
            TK_ASSERT(removed == present[k]);
            present[k] = false;
        } else {
            bool got = g5c_json_get_int(o, key, &v);
            TK_ASSERT(got == present[k]);
            if (got)
                TK_ASSERT(v == model[k]);
        }
        if (op % 5000 == 0) { /* full cross-check, plus a copy must agree */
            size_t live = 0;
            g5c_json *d = g5c_json_dup(o);
            for (unsigned i = 0; i < SPACE; i++) {
                int64_t a = 0, b = 0;
                snprintf(key, sizeof key, "key-%u", i);
                TK_ASSERT(g5c_json_get_int(o, key, &a) == present[i]);
                TK_ASSERT(g5c_json_get_int(d, key, &b) == present[i] && (!present[i] || (a == model[i] && b == a)));
                live += present[i];
            }
            TK_ASSERT(g5c_json_len(o) == live && g5c_json_equal(o, d));
            g5c_json_free(d);
        }
    }
    g5c_json_free(o);

    /* duplicates in parsed text, with enough members to use the index: the last one wins and survives a copy */
    {
        g5c_bytes b;
        g5c_json *j, *c;
        int64_t v = 0;
        g5c_bytes_init(&b);
        g5c_bytes_append_str(&b, "{");
        for (int i = 0; i < 100; i++) {
            char e[40];
            snprintf(e, sizeof e, "%s\"k%d\":%d", i ? "," : "", i % 40, i);
            g5c_bytes_append_str(&b, e);
        }
        g5c_bytes_append_str(&b, "}");
        j = g5c_json_parse((const char *)b.data, b.len, NULL, 0);
        TK_ASSERT(j != NULL);
        c = g5c_json_dup(j);
        for (int i = 0; i < 40; i++) {
            char k2[16];
            snprintf(k2, sizeof k2, "k%d", i);
            TK_ASSERT(g5c_json_get_int(j, k2, &v) && v == (i + 80 < 100 ? i + 80 : i + 40));
            TK_ASSERT(g5c_json_get_int(c, k2, &v) && v == (i + 80 < 100 ? i + 80 : i + 40));
        }
        g5c_json_free(c);
        g5c_json_free(j);
        g5c_bytes_free(&b);
    }
    /* a large object builds and answers in linear time */
    {
        g5c_json *big = g5c_json_new_obj();
        for (int i = 0; i < 200000; i++) {
            snprintf(key, sizeof key, "n%d", i);
            g5c_json_set_int(big, key, i);
        }
        for (int i = 0; i < 200000; i += 997) {
            int64_t v = 0;
            snprintf(key, sizeof key, "n%d", i);
            TK_ASSERT(g5c_json_get_int(big, key, &v) && v == i);
        }
        g5c_json_free(big);
    }
}

int main(void)
{
    test_base();
    test_base64();
    test_json();
    test_json_conformance();
    test_json_properties();
    test_json_object_index();
    test_yaml_and_config();
    test_metrics();
    puts("base: ok");
    return 0;
}
