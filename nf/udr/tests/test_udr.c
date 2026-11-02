/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "g5c/testkit.h"
#include "g5c/udr.h"

static g5c_json *J(const char *s)
{
    g5c_json *j = g5c_json_parse(s, strlen(s), NULL, 0);
    TK_ASSERT(j != NULL);
    return j;
}

static char *dump(const g5c_json *j)
{
    return g5c_json_to_string(j, NULL);
}

static void expect_json(const g5c_json *j, const char *want)
{
    g5c_json *w = J(want);
    if (!g5c_json_equal(j, w)) {
        char *a = dump(j);
        TK_FAIL("json differs: got %s want %s", a, want);
    }
    g5c_json_free(w);
}

static void test_patch(void)
{
    char err[160];
    g5c_json *d = J("{\"sequenceNumber\":{\"sqn\":\"000000000020\",\"x\":1},\"list\":[1,2]}");
    g5c_json *p = J("[{\"op\":\"replace\",\"path\":\"/sequenceNumber/sqn\",\"value\":\"000000000040\"},"
                    "{\"op\":\"add\",\"path\":\"/sequenceNumber/y\",\"value\":true},"
                    "{\"op\":\"remove\",\"path\":\"/sequenceNumber/x\"},"
                    "{\"op\":\"add\",\"path\":\"/list/-\",\"value\":3},"
                    "{\"op\":\"remove\",\"path\":\"/list/0\"}]");
    TK_ASSERT(g5c_json_patch(&d, p, err, sizeof err) == 0);
    expect_json(d, "{\"sequenceNumber\":{\"sqn\":\"000000000040\",\"y\":true},\"list\":[2,3]}");
    g5c_json_free(p);
    g5c_json_free(d);

    d = J("{\"a\":1}");
    p = J("[{\"op\":\"replace\",\"path\":\"/b\",\"value\":1}]");
    TK_ASSERT(g5c_json_patch(&d, p, err, sizeof err) == G5C_PATCH_PATH);
    g5c_json_free(p);
    p = J("[{\"op\":\"move\",\"path\":\"/a\",\"from\":\"/b\"}]");
    TK_ASSERT(g5c_json_patch(&d, p, err, sizeof err) == G5C_PATCH_ITEM);
    g5c_json_free(p);
    p = J("[{\"op\":\"replace\",\"path\":\"/x/y/z\",\"value\":1}]");
    TK_ASSERT(g5c_json_patch(&d, p, err, sizeof err) == G5C_PATCH_PATH);
    g5c_json_free(p);
    p = J("[{\"op\":\"replace\",\"path\":\"a\",\"value\":1}]");
    TK_ASSERT(g5c_json_patch(&d, p, err, sizeof err) == G5C_PATCH_ITEM);
    g5c_json_free(p);
    g5c_json_free(d);

    d = J("{\"a/b\":{\"c~d\":1}}");
    p = J("[{\"op\":\"replace\",\"path\":\"/a~1b/c~0d\",\"value\":2}]");
    TK_ASSERT(g5c_json_patch(&d, p, err, sizeof err) == 0);
    expect_json(d, "{\"a/b\":{\"c~d\":2}}");
    g5c_json_free(p);
    g5c_json_free(d);
}

static size_t fsize(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (size_t)st.st_size : 0;
}

static void wait_journal_grows(const char *jp, size_t above)
{
    for (int i = 0; i < 300 && fsize(jp) <= above; i++)
        usleep(10000);
    TK_ASSERT(fsize(jp) > above);
}

/* A crash leaves the snapshot and the journal as they were on disk */
static void test_journal_recovery(void)
{
    char dir[] = "/tmp/g5c-udrj-XXXXXX", a[64], aj[80], b[64], bj[80], cmd[600], err[160];
    g5c_udr_store *s, *s2;
    g5c_json *v;
    size_t n;
    TK_ASSERT(mkdtemp(dir) != NULL);
    snprintf(a, sizeof a, "%s/a.json", dir);
    snprintf(aj, sizeof aj, "%s.journal", a);
    snprintf(b, sizeof b, "%s/b.json", dir);
    snprintf(bj, sizeof bj, "%s.journal", b);
    s = g5c_udr_store_open(a, err, sizeof err);
    TK_ASSERT(s != NULL);
    TK_ASSERT(g5c_udr_put(s, "imsi-7", UDR_AM, J("{\"nssai\":7}")));
    TK_ASSERT(g5c_udr_put(s, "imsi-8", UDR_AM, J("{\"nssai\":8}")));
    wait_journal_grows(aj, 0);
    n = fsize(aj);
    TK_ASSERT(g5c_udr_remove(s, "imsi-8"));
    TK_ASSERT(g5c_udr_map_put(s, "imsi-7", UDR_SMF_REGS, "1", J("{\"id\":1}")));
    wait_journal_grows(aj, n);

    /* the image a crash would leave (the store above is still running) */
    snprintf(cmd, sizeof cmd, "cp -p '%s' '%s' && cp -p '%s' '%s'", a, b, aj, bj);
    TK_ASSERT(system(cmd) == 0);
    s2 = g5c_udr_store_open(b, err, sizeof err);
    TK_ASSERT(s2 != NULL);
    v = g5c_udr_get(s2, "imsi-7", UDR_AM);
    expect_json(v, "{\"nssai\":7}");
    g5c_json_free(v);
    v = g5c_udr_map_get(s2, "imsi-7", UDR_SMF_REGS, "1");
    expect_json(v, "{\"id\":1}");
    g5c_json_free(v);
    v = g5c_udr_get(s2, "imsi-8", UDR_AM);
    TK_ASSERT(v == NULL); /* removed after it was first journaled */
    g5c_udr_store_free(s2);
    g5c_udr_store_free(s);

    /* a journal older than its snapshot is ignored: age the journal, touch the snapshot */
    snprintf(cmd, sizeof cmd, "touch -d '2001-01-01' '%s' && touch '%s'", bj, b);
    TK_ASSERT(system(cmd) == 0);
    {
        char *jj = g5c_xasprintf("printf '{\"u\":\"imsi-9\",\"d\":{\"am\":1}}\\n' >> '%s' && touch -d '2001-01-01' '%s'", bj, bj);
        TK_ASSERT(system(jj) == 0);
        free(jj);
        snprintf(cmd, sizeof cmd, "touch '%s'", b);
        TK_ASSERT(system(cmd) == 0);
    }
    s2 = g5c_udr_store_open(b, err, sizeof err);
    TK_ASSERT(s2 != NULL);
    v = g5c_udr_get(s2, "imsi-9", "am");
    TK_ASSERT(v == NULL);
    g5c_udr_store_free(s2);
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    TK_ASSERT(system(cmd) == 0);
}

static void test_store_persistence(void)
{
    char path[] = "/tmp/g5c-udr-XXXXXX", err[160];
    int fd = mkstemp(path);
    g5c_udr_store *s;
    g5c_json *v, *ids;
    TK_ASSERT(fd >= 0);
    close(fd);
    unlink(path);
    s = g5c_udr_store_open(path, err, sizeof err);
    TK_ASSERT(s != NULL);
    TK_ASSERT(g5c_udr_put(s, "imsi-2", UDR_AM, J("{\"nssai\":1}")));
    TK_ASSERT(!g5c_udr_put(s, "imsi-2", UDR_AM, J("{\"nssai\":2}")));
    TK_ASSERT(g5c_udr_put(s, "imsi-1", UDR_AUTH, J("{\"k\":\"x\"}")));
    TK_ASSERT(g5c_udr_map_put(s, "imsi-1", UDR_SMF_REGS, "5", J("{\"id\":5}")));
    g5c_udr_store_free(s);

    s = g5c_udr_store_open(path, err, sizeof err);
    TK_ASSERT(s != NULL);
    v = g5c_udr_get(s, "imsi-2", UDR_AM);
    expect_json(v, "{\"nssai\":2}");
    g5c_json_free(v);
    ids = g5c_udr_ids(s);
    expect_json(ids, "[\"imsi-1\",\"imsi-2\"]"); /* sorted */
    g5c_json_free(ids);
    v = g5c_udr_map_get(s, "imsi-1", UDR_SMF_REGS, "5");
    expect_json(v, "{\"id\":5}");
    g5c_json_free(v);
    TK_ASSERT(g5c_udr_remove(s, "imsi-1") && !g5c_udr_remove(s, "imsi-1"));
    g5c_udr_store_free(s);
    unlink(path);

    {   /* a corrupt file is refused, not silently replaced */
        FILE *f = fopen(path, "wb");
        TK_ASSERT(f != NULL);
        fputs("{not json", f);
        fclose(f);
        TK_ASSERT(g5c_udr_store_open(path, err, sizeof err) == NULL);
        unlink(path);
    }
}

static int call(g5c_client *c, const char *base, const char *method, const char *path, const char *body, g5c_json **out)
{
    char *u = g5c_xasprintf("%s%s", base, path), err[160];
    g5c_resp r;
    int rc = g5c_client_request(c, method, u, NULL, 0, G5C_JSON_TYPE, body, body ? strlen(body) : 0, &r, err, sizeof err), st;
    free(u);
    TK_ASSERT(rc == 0);
    st = r.status;
    if (out)
        *out = g5c_resp_parse_json(&r);
    g5c_resp_free(&r);
    return st;
}

/* A few operations over a real HTTP/2 socket (the in-process API tests are in test_udr_api.c). */
static void test_routes(void)
{
    g5c_udr_store *st = g5c_udr_store_memory();
    g5c_router *r = g5c_udr_router(st);
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_server *srv = g5c_server_start(&cfg, r, NULL, 0);
    g5c_client *c = g5c_client_new(3000, NULL);
    char base[64];
    g5c_json *v;
    const char *A = "/nudr-dr/v1/subscription-data/imsi-1/authentication-data/authentication-subscription";
    TK_ASSERT(srv != NULL);
    snprintf(base, sizeof base, "http://127.0.0.1:%u", g5c_server_port(srv));

    TK_ASSERT(call(c, base, "GET", A, NULL, &v) == 404);
    {
        const char *cause = g5c_json_get_str(v, "cause");
        TK_ASSERT(cause != NULL && strcmp(cause, "USER_NOT_FOUND") == 0);
        g5c_json_free(v);
    }
    TK_ASSERT(call(c, base, "PUT", A, "{\"authenticationMethod\":\"5G_AKA\",\"sequenceNumber\":{\"sqn\":\"000000000020\"}}", NULL) == 201);
    TK_ASSERT(call(c, base, "PATCH", A, "[{\"op\":\"replace\",\"path\":\"/sequenceNumber/sqn\",\"value\":\"000000000040\"}]", NULL) == 204);
    TK_ASSERT(call(c, base, "GET", A, NULL, &v) == 200);
    expect_json(v, "{\"authenticationMethod\":\"5G_AKA\",\"sequenceNumber\":{\"sqn\":\"000000000040\"}}");
    g5c_json_free(v);
    TK_ASSERT(call(c, base, "GET", "/nudr-dr/v2/subscription-data/imsi-1/authentication-data/authentication-subscription", NULL, NULL) == 200);
    TK_ASSERT(call(c, base, "GET", "/nudr-dr/v1/subscription-data", NULL, &v) == 200);
    expect_json(v, "[\"imsi-1\"]");
    g5c_json_free(v);
    TK_ASSERT(call(c, base, "DELETE", "/nudr-dr/v1/subscription-data/imsi-1", NULL, NULL) == 204);
    TK_ASSERT(call(c, base, "DELETE", "/nudr-dr/v1/subscription-data/imsi-1", NULL, NULL) == 404);

    g5c_client_free(c);
    g5c_server_stop(srv);
    g5c_router_free(r);
    g5c_udr_store_free(st);
}

/* JSON Patch (RFC 6902) cases: the add/replace/remove examples of the RFC's appendix A, then the error classes */
static void test_patch_rfc6902(void)
{
    static const struct {
        const char *doc, *patch, *want;
        int rc;
    } cases[] = {
        /* A.1 adding an object member */
        {"{\"foo\":\"bar\"}", "[{\"op\":\"add\",\"path\":\"/baz\",\"value\":\"qux\"}]", "{\"foo\":\"bar\",\"baz\":\"qux\"}", 0},
        /* A.2 adding an array element */
        {"{\"foo\":[\"bar\",\"baz\"]}", "[{\"op\":\"add\",\"path\":\"/foo/1\",\"value\":\"qux\"}]", "{\"foo\":[\"bar\",\"qux\",\"baz\"]}", 0},
        /* A.3 removing an object member */
        {"{\"baz\":\"qux\",\"foo\":\"bar\"}", "[{\"op\":\"remove\",\"path\":\"/baz\"}]", "{\"foo\":\"bar\"}", 0},
        /* A.4 removing an array element */
        {"{\"foo\":[\"bar\",\"qux\",\"baz\"]}", "[{\"op\":\"remove\",\"path\":\"/foo/1\"}]", "{\"foo\":[\"bar\",\"baz\"]}", 0},
        /* A.5 replacing a value */
        {"{\"baz\":\"qux\",\"foo\":\"bar\"}", "[{\"op\":\"replace\",\"path\":\"/baz\",\"value\":\"boo\"}]", "{\"baz\":\"boo\",\"foo\":\"bar\"}", 0},
        /* A.10 adding a nested member object */
        {"{\"foo\":\"bar\"}", "[{\"op\":\"add\",\"path\":\"/child\",\"value\":{\"grandchild\":{}}}]", "{\"foo\":\"bar\",\"child\":{\"grandchild\":{}}}", 0},
        /* A.11 ignoring unrecognised elements */
        {"{\"foo\":\"bar\"}", "[{\"op\":\"add\",\"path\":\"/baz\",\"value\":\"qux\",\"xyz\":123}]", "{\"foo\":\"bar\",\"baz\":\"qux\"}", 0},
        /* A.12 adding to a nonexistent target */
        {"{\"foo\":\"bar\"}", "[{\"op\":\"add\",\"path\":\"/baz/bat\",\"value\":\"qux\"}]", "{\"foo\":\"bar\"}", G5C_PATCH_PATH},
        /* A.16 adding an array value */
        {"{\"foo\":[\"bar\"]}", "[{\"op\":\"add\",\"path\":\"/foo/-\",\"value\":[\"abc\",\"def\"]}]", "{\"foo\":[\"bar\",[\"abc\",\"def\"]]}", 0},
        /* escapes */
        {"{\"a/b\":1,\"m~n\":2}", "[{\"op\":\"replace\",\"path\":\"/a~1b\",\"value\":9},{\"op\":\"replace\",\"path\":\"/m~0n\",\"value\":8}]", "{\"a/b\":9,\"m~n\":8}", 0},
        /* replacing the whole document */
        {"{\"a\":1}", "[{\"op\":\"replace\",\"path\":\"\",\"value\":[1,2]}]", "[1,2]", 0},
        /* an empty patch is a no-op */
        {"{\"a\":1}", "[]", "{\"a\":1}", 0},
        /* sequential ops see each other's effects */
        {"{\"a\":[]}", "[{\"op\":\"add\",\"path\":\"/a/-\",\"value\":1},{\"op\":\"add\",\"path\":\"/a/0\",\"value\":0},{\"op\":\"replace\",\"path\":\"/a/1\",\"value\":5}]", "{\"a\":[0,5]}", 0},
        /* errors */
        {"{\"a\":[1]}", "[{\"op\":\"add\",\"path\":\"/a/5\",\"value\":0}]", "{\"a\":[1]}", G5C_PATCH_PATH},        /* beyond the end */
        {"{\"a\":[1]}", "[{\"op\":\"remove\",\"path\":\"/a/1\"}]", "{\"a\":[1]}", G5C_PATCH_PATH},
        {"{\"a\":[1]}", "[{\"op\":\"replace\",\"path\":\"/a/1\",\"value\":0}]", "{\"a\":[1]}", G5C_PATCH_PATH},
        {"{\"a\":[1]}", "[{\"op\":\"replace\",\"path\":\"/a/x\",\"value\":0}]", "{\"a\":[1]}", G5C_PATCH_PATH},      /* not an index */
        {"{\"a\":[1]}", "[{\"op\":\"replace\",\"path\":\"/a/-1\",\"value\":0}]", "{\"a\":[1]}", G5C_PATCH_PATH},
        {"{\"a\":1}", "[{\"op\":\"remove\",\"path\":\"/b\"}]", "{\"a\":1}", G5C_PATCH_PATH},
        {"{\"a\":1}", "[{\"op\":\"add\",\"path\":\"/a/b\",\"value\":1}]", "{\"a\":1}", G5C_PATCH_PATH},              /* parent is a scalar */
        {"{\"a\":1}", "[{\"op\":\"add\",\"path\":\"/b\"}]", "{\"a\":1}", G5C_PATCH_ITEM},                            /* value missing */
        {"{\"a\":1}", "[{\"op\":\"replace\",\"path\":\"/a\"}]", "{\"a\":1}", G5C_PATCH_ITEM},
        {"{\"a\":[1]}", "[{\"op\":\"add\",\"path\":\"/a/0\"}]", "{\"a\":[1]}", G5C_PATCH_ITEM},
        {"{\"a\":1}", "[{\"op\":\"copy\",\"path\":\"/b\",\"from\":\"/a\"}]", "{\"a\":1}", G5C_PATCH_ITEM},          /* unsupported ops */
        {"{\"a\":1}", "[{\"op\":\"test\",\"path\":\"/a\",\"value\":1}]", "{\"a\":1}", G5C_PATCH_ITEM},
        {"{\"a\":[1]}", "[{\"op\":\"move\",\"path\":\"/a/0\",\"from\":\"/a/0\"}]", "{\"a\":[1]}", G5C_PATCH_ITEM},
        {"{\"a\":1}", "[{\"path\":\"/a\",\"value\":1}]", "{\"a\":1}", G5C_PATCH_ITEM},                              /* no op */
        {"{\"a\":1}", "[{\"op\":\"remove\"}]", "{\"a\":1}", G5C_PATCH_ITEM},                                         /* no path */
        {"{\"a\":1}", "[{\"op\":\"remove\",\"path\":\"a\"}]", "{\"a\":1}", G5C_PATCH_ITEM},                          /* bad pointer */
        {"{\"a\":1}", "{\"op\":\"remove\",\"path\":\"/a\"}", "{\"a\":1}", G5C_PATCH_ITEM},                           /* not an array */
        {"{\"a\":1}", "[{\"op\":\"remove\",\"path\":\"\"}]", "{\"a\":1}", G5C_PATCH_ITEM},                           /* cannot remove the root */
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        char err[160] = {0};
        g5c_json *d = J(cases[i].doc), *p = J(cases[i].patch);
        int rc = g5c_json_patch(&d, p, err, sizeof err);
        if (rc != cases[i].rc)
            TK_FAIL("patch case %zu: rc %d, wanted %d (%s)", i, rc, cases[i].rc, cases[i].patch);
        if (cases[i].rc != 0 && err[0] == 0)
            TK_FAIL("patch case %zu: refused without a message", i);
        if (cases[i].rc == 0)
            expect_json(d, cases[i].want);
        g5c_json_free(d);
        g5c_json_free(p);
    }
}

/* Store start-up failures: unreadable, corrupt and unwritable locations are refused up front. */
static void test_store_startup(void)
{
    char dir[] = "/tmp/g5c-udr-XXXXXX", path[128], err[200];
    g5c_udr_store *s;
    FILE *f;
    TK_ASSERT(mkdtemp(dir) != NULL);
    snprintf(path, sizeof path, "%s/missing-dir/udr.json", dir);
    TK_ASSERT(g5c_udr_store_open(path, err, sizeof err) == NULL && err[0] != 0); /* cannot create */
    snprintf(path, sizeof path, "%s/arr.json", dir);
    f = fopen(path, "wb");
    TK_ASSERT(f != NULL);
    fputs("[1,2,3]", f);
    fclose(f);
    TK_ASSERT(g5c_udr_store_open(path, err, sizeof err) == NULL); /* valid JSON, wrong shape */
    f = fopen(path, "wb");
    TK_ASSERT(f != NULL);
    fputs("{\"imsi-1\":{\"x\":1}", f); /* truncated */
    fclose(f);
    TK_ASSERT(g5c_udr_store_open(path, err, sizeof err) == NULL);
    f = fopen(path, "wb");
    TK_ASSERT(f != NULL);
    fclose(f); /* empty file */
    TK_ASSERT(g5c_udr_store_open(path, err, sizeof err) == NULL);
    snprintf(path, sizeof path, "%s/fresh.json", dir);
    s = g5c_udr_store_open(path, err, sizeof err); /* first run creates the file immediately */
    TK_ASSERT(s != NULL && access(path, F_OK) == 0);
    g5c_udr_store_free(s);
    (void)remove(path);
    snprintf(path, sizeof path, "%s/arr.json", dir);
    (void)remove(path);
    (void)rmdir(dir);
}

int main(void)
{
    g5c_log_init("error", false);
    test_patch();
    test_patch_rfc6902();
    test_store_startup();
    test_store_persistence();
    test_journal_recovery();
    test_routes();
    puts("udr: ok");
    return 0;
}
