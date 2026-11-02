/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The storage interface, run against every backend: the same expectations for memory, the journalled file and PostgreSQL (when G5C_UDR_TEST_PG is set) */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "g5c/base.h"
#include "g5c/testkit.h"

static g5c_json *J(const char *s)
{
    g5c_json *j = g5c_json_parse(s, strlen(s), NULL, 0);
    TK_ASSERT(j != NULL);
    return j;
}

static bool jeq(const g5c_json *a, const char *want)
{
    g5c_json *w = J(want);
    bool r = g5c_json_equal(a, w);
    g5c_json_free(w);
    return r;
}

static void wipe(udr_db *d)
{
    g5c_json *all = g5c_json_new_arr();
    TK_ASSERT(d->ops->parts(d->self, all) == 0);
    for (size_t i = 0; i < g5c_json_len(all); i++)
        d->ops->del_part(d->self, g5c_json_str(g5c_json_at(all, i)));
    g5c_json_free(all);
}

static int put(udr_db *d, const char *part, const char *key, const char *doc, const udr_cond *c, bool *created, udr_rec *out)
{
    return d->ops->put(d->self, part, key, J(doc), c, created, out, NULL);
}

static void test_basic(udr_db *d)
{
    udr_rec r, r2, old;
    bool created = false;
    udr_list l;
    g5c_json *parts;
    wipe(d);
    TK_ASSERT(d->ops->get(d->self, "u1", "a", &r) == 0);
    TK_ASSERT(d->ops->part_exists(d->self, "u1") == 0);

    TK_ASSERT(put(d, "u1", "a", "{\"n\":1,\"s\":\"x\"}", NULL, &created, &r) == UDR_DB_OK && created && r.rev > 0 && r.mtime > 1700000000);
    r2 = r;
    TK_ASSERT(d->ops->part_exists(d->self, "u1") == 1);
    TK_ASSERT(d->ops->get(d->self, "u1", "a", &r) == 1 && jeq(r.doc, "{\"n\":1,\"s\":\"x\"}") && r.rev == r2.rev);
    g5c_json_free(r.doc);
    /* a replacement has a new revision and hands back what it replaced */
    TK_ASSERT(d->ops->put(d->self, "u1", "a", J("{\"n\":2}"), NULL, &created, &r, &old) == UDR_DB_OK && !created);
    TK_ASSERT(r.rev > r2.rev && old.doc != NULL && jeq(old.doc, "{\"n\":1,\"s\":\"x\"}") && old.rev == r2.rev);
    g5c_json_free(old.doc);
    TK_ASSERT(d->ops->put(d->self, "u1", "new", J("{}"), NULL, &created, &r, &old) == UDR_DB_OK && created && old.doc == NULL);

    /* keys: unicode, long, and with characters a LIKE pattern would treat specially */
    TK_ASSERT(put(d, "u1", "p%_/x\\y", "{\"k\":1}", NULL, NULL, NULL) == UDR_DB_OK);
    TK_ASSERT(d->ops->get(d->self, "u1", "p%_/x\\y", &r) == 1);
    g5c_json_free(r.doc);
    TK_ASSERT(put(d, "u1", "caf\xc3\xa9/\xe2\x82\xac", "{\"k\":\"\xc3\xa9\"}", NULL, NULL, NULL) == UDR_DB_OK);
    TK_ASSERT(d->ops->get(d->self, "u1", "caf\xc3\xa9/\xe2\x82\xac", &r) == 1 && strcmp(g5c_json_get_str(r.doc, "k"), "\xc3\xa9") == 0);
    g5c_json_free(r.doc);

    /* a listing is the keys below "<prefix>/", in key order, and not a sibling that merely starts the same */
    TK_ASSERT(put(d, "u2", "ctx/smf/1", "{\"i\":1}", NULL, NULL, NULL) == UDR_DB_OK);
    TK_ASSERT(put(d, "u2", "ctx/smf/10", "{\"i\":10}", NULL, NULL, NULL) == UDR_DB_OK);
    TK_ASSERT(put(d, "u2", "ctx/smf/2", "{\"i\":2}", NULL, NULL, NULL) == UDR_DB_OK);
    TK_ASSERT(put(d, "u2", "ctx/smf/2/deep", "{\"i\":22}", NULL, NULL, NULL) == UDR_DB_OK);
    TK_ASSERT(put(d, "u2", "ctx/smfx", "{\"i\":0}", NULL, NULL, NULL) == UDR_DB_OK);
    TK_ASSERT(put(d, "u3", "ctx/smf/9", "{\"i\":9}", NULL, NULL, NULL) == UDR_DB_OK);
    TK_ASSERT(d->ops->list(d->self, "u2", "ctx/smf", &l) == 0 && l.n == 4);
    TK_ASSERT(strcmp(l.keys[0], "ctx/smf/1") == 0 && strcmp(l.keys[1], "ctx/smf/10") == 0 && strcmp(l.keys[2], "ctx/smf/2") == 0 &&
              strcmp(l.keys[3], "ctx/smf/2/deep") == 0);
    TK_ASSERT(jeq(l.recs[1].doc, "{\"i\":10}") && l.recs[1].rev > 0);
    udr_list_free(&l);
    TK_ASSERT(d->ops->list(d->self, "u2", "nothing", &l) == 0 && l.n == 0);
    udr_list_free(&l);

    parts = g5c_json_new_arr();
    TK_ASSERT(d->ops->parts(d->self, parts) == 0 && jeq(parts, "[\"u1\",\"u2\",\"u3\"]"));
    g5c_json_free(parts);

    /* removal: the record comes back, the partition goes with its last record */
    TK_ASSERT(d->ops->del(d->self, "u3", "ctx/smf/9", NULL, &old) == UDR_DB_OK && jeq(old.doc, "{\"i\":9}"));
    g5c_json_free(old.doc);
    TK_ASSERT(d->ops->del(d->self, "u3", "ctx/smf/9", NULL, NULL) == UDR_DB_ABSENT);
    TK_ASSERT(d->ops->part_exists(d->self, "u3") == 0);
    TK_ASSERT(d->ops->del_part(d->self, "u2") == 1 && d->ops->del_part(d->self, "u2") == 0);
    TK_ASSERT(d->ops->get(d->self, "u2", "ctx/smf/1", &r) == 0);
    TK_ASSERT(d->ops->count(d->self) == 4); /* what is left of u1: a, new, p%_/x\y and the unicode key */
}

static void test_conditions(udr_db *d)
{
    udr_rec a, b, o;
    bool created;
    udr_cond c;
    wipe(d);
    TK_ASSERT(put(d, "u", "k", "{\"v\":1}", NULL, &created, &a) == UDR_DB_OK);
    c.kind = UDR_COND_NOT_EXISTS;
    TK_ASSERT(put(d, "u", "k", "{\"v\":2}", &c, NULL, NULL) == UDR_DB_PRECONDITION);
    TK_ASSERT(put(d, "u", "other", "{\"v\":2}", &c, &created, NULL) == UDR_DB_OK && created);
    c.kind = UDR_COND_EXISTS;
    TK_ASSERT(put(d, "u", "absent", "{}", &c, NULL, NULL) == UDR_DB_PRECONDITION);
    c.kind = UDR_COND_MATCH;
    c.rev = a.rev + 1000;
    TK_ASSERT(put(d, "u", "k", "{\"v\":3}", &c, NULL, NULL) == UDR_DB_PRECONDITION);
    c.rev = a.rev;
    TK_ASSERT(put(d, "u", "k", "{\"v\":4}", &c, NULL, &b) == UDR_DB_OK && b.rev > a.rev);
    TK_ASSERT(put(d, "u", "k", "{\"v\":5}", &c, NULL, NULL) == UDR_DB_PRECONDITION); /* the old tag is stale now */
    TK_ASSERT(d->ops->get(d->self, "u", "k", &o) == 1 && jeq(o.doc, "{\"v\":4}"));
    g5c_json_free(o.doc);
    c.rev = b.rev;
    TK_ASSERT(d->ops->del(d->self, "u", "k", &c, NULL) == UDR_DB_OK);
    c.kind = UDR_COND_MATCH;
    c.rev = 1;
    TK_ASSERT(d->ops->del(d->self, "u", "other", &c, NULL) == UDR_DB_PRECONDITION);
    TK_ASSERT(d->ops->get(d->self, "u", "other", &o) == 1);
    g5c_json_free(o.doc);
}

static int add_one(g5c_json **doc, void *arg, char *err, size_t errcap)
{
    int64_t v = 0;
    (void)arg;
    (void)err;
    (void)errcap;
    g5c_json_get_int(*doc, "n", &v);
    g5c_json_set_int(*doc, "n", v + 1);
    return 0;
}

static int refuse(g5c_json **doc, void *arg, char *err, size_t errcap)
{
    (void)doc;
    (void)arg;
    snprintf(err, errcap, "refused on purpose");
    return -1;
}

static void test_mutate(udr_db *d)
{
    udr_rec o, old;
    char err[80] = "";
    udr_cond c = {UDR_COND_MATCH, 0};
    wipe(d);
    TK_ASSERT(d->ops->mutate(d->self, "u", "ctr", add_one, NULL, NULL, NULL, NULL, err, sizeof err) == UDR_DB_ABSENT);
    TK_ASSERT(put(d, "u", "ctr", "{\"n\":0}", NULL, NULL, NULL) == UDR_DB_OK);
    TK_ASSERT(d->ops->mutate(d->self, "u", "ctr", add_one, NULL, NULL, &o, &old, err, sizeof err) == UDR_DB_OK);
    TK_ASSERT(jeq(o.doc, "{\"n\":1}") && jeq(old.doc, "{\"n\":0}") && o.rev > old.rev);
    g5c_json_free(o.doc);
    g5c_json_free(old.doc);
    TK_ASSERT(d->ops->mutate(d->self, "u", "ctr", refuse, NULL, NULL, NULL, NULL, err, sizeof err) == UDR_DB_REJECTED);
    TK_ASSERT(strcmp(err, "refused on purpose") == 0);
    c.rev = 1;
    TK_ASSERT(d->ops->mutate(d->self, "u", "ctr", add_one, NULL, &c, NULL, NULL, err, sizeof err) == UDR_DB_PRECONDITION);
    TK_ASSERT(d->ops->get(d->self, "u", "ctr", &o) == 1 && jeq(o.doc, "{\"n\":1}")); /* neither the refusal nor the stale tag changed it */
    g5c_json_free(o.doc);
}

typedef struct {
    udr_db *d;
    int iters;
    int created_ok;
} Worker;

static void *incr_thread(void *arg)
{
    Worker *w = arg;
    char err[64];
    for (int i = 0; i < w->iters; i++)
        TK_ASSERT(w->d->ops->mutate(w->d->self, "u", "ctr", add_one, NULL, NULL, NULL, NULL, err, sizeof err) == UDR_DB_OK);
    return NULL;
}

static void *create_thread(void *arg)
{
    Worker *w = arg;
    udr_cond c = {UDR_COND_NOT_EXISTS, 0};
    int rc = put(w->d, "u", "single", "{\"by\":1}", &c, NULL, NULL);
    TK_ASSERT(rc == UDR_DB_OK || rc == UDR_DB_PRECONDITION);
    w->created_ok = rc == UDR_DB_OK;
    return NULL;
}

/* many threads read-modify-write one document: no increment is lost; many create the same key: one wins */
static void test_contention(udr_db *d)
{
    enum { T = 8, N = 40 };
    pthread_t th[T];
    Worker w[T];
    udr_rec o;
    int winners = 0;
    wipe(d);
    TK_ASSERT(put(d, "u", "ctr", "{\"n\":0}", NULL, NULL, NULL) == UDR_DB_OK);
    for (int i = 0; i < T; i++) {
        w[i] = (Worker){d, N, 0};
        pthread_create(&th[i], NULL, incr_thread, &w[i]);
    }
    for (int i = 0; i < T; i++)
        pthread_join(th[i], NULL);
    TK_ASSERT(d->ops->get(d->self, "u", "ctr", &o) == 1);
    TK_ASSERT(jeq(o.doc, "{\"n\":320}"));
    g5c_json_free(o.doc);
    for (int i = 0; i < T; i++) {
        w[i] = (Worker){d, 0, 0};
        pthread_create(&th[i], NULL, create_thread, &w[i]);
    }
    for (int i = 0; i < T; i++) {
        pthread_join(th[i], NULL);
        winners += w[i].created_ok;
    }
    TK_ASSERT(winners == 1);
}

static void run_all(udr_db *d, const char *name)
{
    (void)name;
    test_basic(d);
    test_conditions(d);
    test_mutate(d);
    test_contention(d);
}

int main(void)
{
    char err[256], dir[] = "/tmp/g5c-udrdb-XXXXXX", path[128];
    udr_db *d;
    const char *pg = getenv("G5C_UDR_TEST_PG");
    g5c_log_init("error", false);

    d = udr_db_memory();
    run_all(d, "memory");
    udr_db_free(d);

    TK_ASSERT(mkdtemp(dir) != NULL);
    snprintf(path, sizeof path, "%s/db.json", dir);
    d = udr_db_file(path, err, sizeof err);
    TK_ASSERT(d != NULL);
    run_all(d, "file");
    udr_db_free(d);
    {
        char cmd[400];
        snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
        TK_ASSERT(system(cmd) == 0);
    }

    if (pg != NULL && pg[0] != '\0') {
        udr_rec o;
        udr_db *d2;
        d = udr_db_postgres(pg, 4, err, sizeof err);
        if (d == NULL)
            TK_FAIL("postgres: %s", err);
        run_all(d, "postgresql");
        /* what one process wrote is there for the next (and for another replica) */
        TK_ASSERT(put(d, "persist", "k", "{\"v\":\"kept\"}", NULL, NULL, NULL) == UDR_DB_OK);
        d2 = udr_db_postgres(pg, 2, err, sizeof err);
        TK_ASSERT(d2 != NULL);
        TK_ASSERT(d2->ops->get(d2->self, "persist", "k", &o) == 1 && jeq(o.doc, "{\"v\":\"kept\"}"));
        g5c_json_free(o.doc);
        /* a second replica's change is seen by the first, and revisions do not collide */
        {
            udr_rec a, b;
            TK_ASSERT(put(d, "persist", "r", "{\"w\":1}", NULL, NULL, &a) == UDR_DB_OK);
            TK_ASSERT(d2->ops->put(d2->self, "persist", "r", J("{\"w\":2}"), NULL, NULL, &b, NULL) == UDR_DB_OK);
            TK_ASSERT(b.rev > a.rev);
            TK_ASSERT(d->ops->get(d->self, "persist", "r", &o) == 1 && jeq(o.doc, "{\"w\":2}") && o.rev == b.rev);
            g5c_json_free(o.doc);
        }
        udr_db_free(d2);
        wipe(d);
        udr_db_free(d);
        /* an unreachable server is a start-up error with a message */
        TK_ASSERT(udr_db_postgres("host=/nonexistent port=1 user=x dbname=y", 1, err, sizeof err) == NULL && err[0] != '\0');
        puts("udr db: ok (memory, file, postgresql)");
    } else {
        puts("udr db: ok (memory, file)");
    }
    return 0;
}
