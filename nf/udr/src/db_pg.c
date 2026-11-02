/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* PostgreSQL storage backend (libpq).
 *
 * One table holds every document: (part, key) -> jsonb, revision, modification time. Keys are compared bytewise
 * (COLLATE "C") so that "all keys below <prefix>/" is an index range scan. Revisions come from a sequence, so they stay
 * unique and increasing across replicas of the UDR sharing one database. Every mutation is a short transaction that
 * locks the row it changes (SELECT ... FOR UPDATE), checks the precondition, and writes; two UDR replicas therefore see
 * the same atomic read-modify-write behaviour as the in-memory backend. A pool of connections serves the request
 * threads; a lost connection is reset once before the operation is reported as failed. */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "g5c/base.h"
#include "g5c/udr.h"

#ifndef G5C_HAVE_LIBPQ

bool g5c_udr_have_postgres(void)
{
    return false;
}

udr_db *udr_db_postgres(const char *conninfo, int pool, char *err, size_t errcap)
{
    (void)conninfo;
    (void)pool;
    snprintf(err, errcap, "this build has no PostgreSQL support (libpq was not found at configure time)");
    return NULL;
}

#else

#include <libpq-fe.h>

#define SCHEMA_VERSION 1

typedef struct {
    PGconn *c;
    bool busy;
} slot_t;

typedef struct {
    char *conninfo;
    slot_t *slots;
    int nslots;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    _Atomic long count; /* records: counted at start, then kept by this process's own inserts and deletes */
} pgdb;

static void log_pg(const char *what, PGconn *c)
{
    char *m = g5c_xstrdup(PQerrorMessage(c));
    size_t n = strlen(m);
    while (n > 0 && (m[n - 1] == '\n' || m[n - 1] == '\r'))
        m[--n] = '\0';
    G5C_LOGE("g5c_udr", "postgresql: %s: %s", what, m);
    free(m);
}

static slot_t *acquire(pgdb *d)
{
    slot_t *s = NULL;
    pthread_mutex_lock(&d->mu);
    for (;;) {
        for (int i = 0; i < d->nslots && s == NULL; i++)
            if (!d->slots[i].busy)
                s = &d->slots[i];
        if (s != NULL)
            break;
        pthread_cond_wait(&d->cv, &d->mu);
    }
    s->busy = true;
    pthread_mutex_unlock(&d->mu);
    if (PQstatus(s->c) != CONNECTION_OK) {
        PQreset(s->c);
        if (PQstatus(s->c) != CONNECTION_OK)
            log_pg("connection lost and not recovered", s->c);
    }
    return s;
}

static void release(pgdb *d, slot_t *s)
{
    pthread_mutex_lock(&d->mu);
    s->busy = false;
    pthread_cond_signal(&d->cv);
    pthread_mutex_unlock(&d->mu);
}

/* run one statement; NULL (and the error logged) on failure, otherwise a result the caller clears */
static PGresult *q(PGconn *c, const char *sql, int np, const char *const *params, ExecStatusType want)
{
    PGresult *r = PQexecParams(c, sql, np, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(r) != want) {
        const char *st = PQresultErrorField(r, PG_DIAG_SQLSTATE);
        if (st == NULL || strcmp(st, "23505") != 0) /* a duplicate key is an answer, not a fault */
            log_pg(sql, c);
        PQclear(r);
        return NULL;
    }
    return r;
}

static bool exec_simple(PGconn *c, const char *sql)
{
    PGresult *r = PQexec(c, sql);
    bool ok = PQresultStatus(r) == PGRES_COMMAND_OK;
    if (!ok)
        log_pg(sql, c);
    PQclear(r);
    return ok;
}

static void rollback(PGconn *c)
{
    PGresult *r = PQexec(c, "ROLLBACK");
    PQclear(r);
}

static uint64_t u64(const char *s)
{
    return (uint64_t)strtoull(s, NULL, 10);
}

static void rec_from_row(PGresult *r, int row, int col, udr_rec *out, bool with_doc)
{
    if (out == NULL)
        return;
    out->doc = NULL;
    if (with_doc) {
        const char *t = PQgetvalue(r, row, col);
        out->doc = g5c_json_parse(t, strlen(t), NULL, 0);
    }
    out->rev = u64(PQgetvalue(r, row, col + 1));
    out->mtime = (int64_t)strtoll(PQgetvalue(r, row, col + 2), NULL, 10);
}

/* ---- operations ------------------------------------------------------------------------------------------------- */

static int p_get(void *self, const char *part, const char *key, udr_rec *out)
{
    pgdb *d = self;
    slot_t *s = acquire(d);
    const char *params[2] = {part, key};
    PGresult *r = q(s->c, "SELECT doc::text, rev, mtime FROM udr_doc WHERE part = $1 AND key = $2", 2, params, PGRES_TUPLES_OK);
    int rc = -1;
    if (r != NULL) {
        rc = PQntuples(r) == 1;
        if (rc)
            rec_from_row(r, 0, 0, out, true);
        PQclear(r);
    }
    release(d, s);
    return rc;
}

/* lock the row of (part, key) and read it inside the open transaction: 1 present, 0 absent, -1 error */
static int lock_row(PGconn *c, const char *part, const char *key, udr_rec *cur)
{
    const char *params[2] = {part, key};
    PGresult *r = q(c, "SELECT doc::text, rev, mtime FROM udr_doc WHERE part = $1 AND key = $2 FOR UPDATE", 2, params, PGRES_TUPLES_OK);
    int rc = -1;
    if (r != NULL) {
        rc = PQntuples(r) == 1;
        if (rc)
            rec_from_row(r, 0, 0, cur, true);
        PQclear(r);
    }
    return rc;
}

static int p_put(void *self, const char *part, const char *key, g5c_json *doc, const udr_cond *c, bool *created,
                 udr_rec *out, udr_rec *old_out)
{
    pgdb *d = self;
    slot_t *s = acquire(d);
    char *text = g5c_json_to_string(doc, NULL);
    int result = UDR_DB_ERROR;
    g5c_json_free(doc);
    for (int attempt = 0; attempt < 3; attempt++) {
        udr_rec cur;
        PGresult *r;
        const char *params[3] = {part, key, text};
        int have;
        memset(&cur, 0, sizeof cur);
        if (!exec_simple(s->c, "BEGIN"))
            break;
        have = lock_row(s->c, part, key, &cur);
        if (have < 0) {
            rollback(s->c);
            break;
        }
        if (!udr_cond_ok(c, have == 1, have == 1 ? cur.rev : 0)) {
            rollback(s->c);
            g5c_json_free(cur.doc);
            result = UDR_DB_PRECONDITION;
            break;
        }
        if (have == 1)
            r = q(s->c, "UPDATE udr_doc SET doc = $3::jsonb, rev = nextval('udr_rev_seq'), mtime = floor(extract(epoch from now()))::bigint "
                        "WHERE part = $1 AND key = $2 RETURNING rev, mtime", 3, params, PGRES_TUPLES_OK);
        else
            r = q(s->c, "INSERT INTO udr_doc (part, key, doc, rev, mtime) VALUES ($1, $2, $3::jsonb, nextval('udr_rev_seq'), "
                        "floor(extract(epoch from now()))::bigint) RETURNING rev, mtime", 3, params, PGRES_TUPLES_OK);
        if (r == NULL) {
            rollback(s->c);
            g5c_json_free(cur.doc);
            if (have == 0 && c != NULL && c->kind == UDR_COND_NOT_EXISTS) { /* somebody created it between our read and write */
                result = UDR_DB_PRECONDITION;
                break;
            }
            continue; /* a concurrent insert of the same key: read it again and update */
        }
        if (!exec_simple(s->c, "COMMIT")) {
            PQclear(r);
            g5c_json_free(cur.doc);
            break;
        }
        if (created != NULL)
            *created = have == 0;
        if (out != NULL) {
            out->doc = NULL;
            out->rev = u64(PQgetvalue(r, 0, 0));
            out->mtime = (int64_t)strtoll(PQgetvalue(r, 0, 1), NULL, 10);
        }
        if (old_out != NULL) {
            memset(old_out, 0, sizeof *old_out);
            if (have == 1) {
                *old_out = cur;
                cur.doc = NULL;
            }
        }
        if (have == 0)
            atomic_fetch_add(&d->count, 1);
        PQclear(r);
        g5c_json_free(cur.doc);
        result = UDR_DB_OK;
        break;
    }
    free(text);
    release(d, s);
    return result;
}

static int p_del(void *self, const char *part, const char *key, const udr_cond *c, udr_rec *old)
{
    pgdb *d = self;
    slot_t *s = acquire(d);
    int result = UDR_DB_ERROR;
    udr_rec cur;
    int have;
    memset(&cur, 0, sizeof cur);
    if (!exec_simple(s->c, "BEGIN")) {
        release(d, s);
        return result;
    }
    have = lock_row(s->c, part, key, &cur);
    if (have < 0) {
        rollback(s->c);
    } else if (have == 0) {
        rollback(s->c);
        result = UDR_DB_ABSENT;
    } else if (!udr_cond_ok(c, true, cur.rev)) {
        rollback(s->c);
        g5c_json_free(cur.doc);
        result = UDR_DB_PRECONDITION;
    } else {
        const char *params[2] = {part, key};
        PGresult *r = q(s->c, "DELETE FROM udr_doc WHERE part = $1 AND key = $2", 2, params, PGRES_COMMAND_OK);
        if (r == NULL) {
            rollback(s->c);
            g5c_json_free(cur.doc);
        } else {
            PQclear(r);
            if (exec_simple(s->c, "COMMIT")) {
                atomic_fetch_sub(&d->count, 1);
                if (old != NULL) {
                    *old = cur;
                    cur.doc = NULL;
                }
                result = UDR_DB_OK;
            }
            g5c_json_free(cur.doc);
        }
    }
    release(d, s);
    return result;
}

static int p_mutate(void *self, const char *part, const char *key, udr_mutator fn, void *arg, const udr_cond *c,
                    udr_rec *out, udr_rec *old_out, char *err, size_t errcap)
{
    pgdb *d = self;
    slot_t *s = acquire(d);
    int result = UDR_DB_ERROR;
    udr_rec cur;
    int have;
    memset(&cur, 0, sizeof cur);
    if (!exec_simple(s->c, "BEGIN")) {
        release(d, s);
        return result;
    }
    have = lock_row(s->c, part, key, &cur);
    if (have < 0) {
        rollback(s->c);
    } else if (have == 0) {
        rollback(s->c);
        result = UDR_DB_ABSENT;
    } else if (!udr_cond_ok(c, true, cur.rev)) {
        rollback(s->c);
        g5c_json_free(cur.doc);
        result = UDR_DB_PRECONDITION;
    } else {
        g5c_json *copy = g5c_json_dup(cur.doc);
        if (fn(&copy, arg, err, errcap) != 0) {
            rollback(s->c);
            g5c_json_free(copy);
            g5c_json_free(cur.doc);
            result = UDR_DB_REJECTED;
        } else {
            char *text = g5c_json_to_string(copy, NULL);
            const char *params[3] = {part, key, text};
            PGresult *r = q(s->c, "UPDATE udr_doc SET doc = $3::jsonb, rev = nextval('udr_rev_seq'), mtime = floor(extract(epoch from now()))::bigint "
                                  "WHERE part = $1 AND key = $2 RETURNING rev, mtime", 3, params, PGRES_TUPLES_OK);
            free(text);
            if (r == NULL) {
                rollback(s->c);
                g5c_json_free(copy);
                g5c_json_free(cur.doc);
            } else if (!exec_simple(s->c, "COMMIT")) {
                PQclear(r);
                g5c_json_free(copy);
                g5c_json_free(cur.doc);
            } else {
                if (out != NULL) {
                    out->doc = copy;
                    copy = NULL;
                    out->rev = u64(PQgetvalue(r, 0, 0));
                    out->mtime = (int64_t)strtoll(PQgetvalue(r, 0, 1), NULL, 10);
                }
                if (old_out != NULL) {
                    *old_out = cur;
                    cur.doc = NULL;
                }
                PQclear(r);
                g5c_json_free(copy);
                g5c_json_free(cur.doc);
                result = UDR_DB_OK;
            }
        }
    }
    release(d, s);
    return result;
}

static int p_list(void *self, const char *part, const char *prefix, udr_list *out)
{
    pgdb *d = self;
    slot_t *s = acquire(d);
    char *lo = g5c_xasprintf("%s/", prefix), *hi = g5c_xasprintf("%s0", prefix); /* '0' is the character after '/' */
    const char *params[3] = {part, lo, hi};
    PGresult *r = q(s->c, "SELECT doc::text, rev, mtime, key FROM udr_doc WHERE part = $1 AND key >= $2 AND key < $3 ORDER BY key",
                    3, params, PGRES_TUPLES_OK);
    int rc = -1;
    memset(out, 0, sizeof *out);
    if (r != NULL) {
        int n = PQntuples(r);
        out->keys = g5c_xcalloc((size_t)n + 1, sizeof *out->keys);
        out->recs = g5c_xcalloc((size_t)n + 1, sizeof *out->recs);
        for (int i = 0; i < n; i++) {
            out->keys[i] = g5c_xstrdup(PQgetvalue(r, i, 3));
            rec_from_row(r, i, 0, &out->recs[i], true);
        }
        out->n = (size_t)n;
        PQclear(r);
        rc = 0;
    }
    free(lo);
    free(hi);
    release(d, s);
    return rc;
}

static int p_part_exists(void *self, const char *part)
{
    pgdb *d = self;
    slot_t *s = acquire(d);
    const char *params[1] = {part};
    PGresult *r = q(s->c, "SELECT 1 FROM udr_doc WHERE part = $1 LIMIT 1", 1, params, PGRES_TUPLES_OK);
    int rc = -1;
    if (r != NULL) {
        rc = PQntuples(r) == 1;
        PQclear(r);
    }
    release(d, s);
    return rc;
}

static int p_parts(void *self, g5c_json *out)
{
    pgdb *d = self;
    slot_t *s = acquire(d);
    PGresult *r = q(s->c, "SELECT DISTINCT part FROM udr_doc ORDER BY part", 0, NULL, PGRES_TUPLES_OK);
    int rc = -1;
    if (r != NULL) {
        for (int i = 0; i < PQntuples(r); i++)
            g5c_json_push_str(out, PQgetvalue(r, i, 0));
        PQclear(r);
        rc = 0;
    }
    release(d, s);
    return rc;
}

static int p_del_part(void *self, const char *part)
{
    pgdb *d = self;
    slot_t *s = acquire(d);
    const char *params[1] = {part};
    PGresult *r = q(s->c, "DELETE FROM udr_doc WHERE part = $1", 1, params, PGRES_COMMAND_OK);
    int rc = -1;
    if (r != NULL) {
        long n = strtol(PQcmdTuples(r), NULL, 10);
        atomic_fetch_sub(&d->count, n);
        rc = n > 0;
        PQclear(r);
    }
    release(d, s);
    return rc;
}

static size_t p_count(void *self)
{
    pgdb *d = self;
    long n = atomic_load(&d->count);
    return n > 0 ? (size_t)n : 0;
}

static void p_close(void *self)
{
    pgdb *d = self;
    for (int i = 0; i < d->nslots; i++)
        if (d->slots[i].c != NULL)
            PQfinish(d->slots[i].c);
    free(d->slots);
    free(d->conninfo);
    pthread_mutex_destroy(&d->mu);
    pthread_cond_destroy(&d->cv);
    free(d);
}

static const udr_db_ops pg_ops = {"postgresql", p_get,    p_put,         p_del,     p_mutate, p_list,
                                  p_part_exists, p_parts, p_del_part, p_count, p_close};

bool g5c_udr_have_postgres(void)
{
    return true;
}

/* create or check the schema over the first connection */
static bool init_schema(PGconn *c, char *err, size_t errcap)
{
    PGresult *r;
    const char *ver;
    if (!exec_simple(c, "CREATE TABLE IF NOT EXISTS udr_schema (version integer NOT NULL)")) {
        snprintf(err, errcap, "postgresql: cannot create the schema: %s", PQerrorMessage(c));
        return false;
    }
    /* serialise concurrent first starts of several replicas */
    if (!exec_simple(c, "BEGIN") || !exec_simple(c, "LOCK TABLE udr_schema IN EXCLUSIVE MODE")) {
        snprintf(err, errcap, "postgresql: cannot lock the schema: %s", PQerrorMessage(c));
        rollback(c);
        return false;
    }
    r = PQexec(c, "SELECT version FROM udr_schema");
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        snprintf(err, errcap, "postgresql: %s", PQerrorMessage(c));
        PQclear(r);
        rollback(c);
        return false;
    }
    if (PQntuples(r) == 0) {
        PQclear(r);
        if (!exec_simple(c, "CREATE TABLE IF NOT EXISTS udr_doc (part text COLLATE \"C\" NOT NULL, key text COLLATE \"C\" NOT NULL, "
                            "doc jsonb NOT NULL, rev bigint NOT NULL, mtime bigint NOT NULL, PRIMARY KEY (part, key))") ||
            !exec_simple(c, "CREATE SEQUENCE IF NOT EXISTS udr_rev_seq") ||
            !exec_simple(c, "INSERT INTO udr_schema (version) VALUES (" "1" ")")) {
            snprintf(err, errcap, "postgresql: cannot create the tables: %s", PQerrorMessage(c));
            rollback(c);
            return false;
        }
    } else {
        ver = PQgetvalue(r, 0, 0);
        if (atoi(ver) != SCHEMA_VERSION) {
            snprintf(err, errcap, "postgresql: the schema is version %s, this UDR supports version %d", ver, SCHEMA_VERSION);
            PQclear(r);
            rollback(c);
            return false;
        }
        PQclear(r);
    }
    if (!exec_simple(c, "COMMIT")) {
        snprintf(err, errcap, "postgresql: %s", PQerrorMessage(c));
        return false;
    }
    return true;
}

udr_db *udr_db_postgres(const char *conninfo, int pool, char *err, size_t errcap)
{
    pgdb *d = g5c_xcalloc(1, sizeof *d);
    udr_db *db;
    PGresult *r;
    if (pool < 1)
        pool = 1;
    d->conninfo = g5c_xasprintf("%s application_name=g5c-udr connect_timeout=5", conninfo);
    d->nslots = pool;
    d->slots = g5c_xcalloc((size_t)pool, sizeof *d->slots);
    pthread_mutex_init(&d->mu, NULL);
    pthread_cond_init(&d->cv, NULL);
    for (int i = 0; i < pool; i++) {
        d->slots[i].c = PQconnectdb(d->conninfo);
        if (PQstatus(d->slots[i].c) != CONNECTION_OK) {
            snprintf(err, errcap, "postgresql: %s", PQerrorMessage(d->slots[i].c));
            p_close(d);
            return NULL;
        }
    }
    if (!init_schema(d->slots[0].c, err, errcap)) {
        p_close(d);
        return NULL;
    }
    r = PQexec(d->slots[0].c, "SELECT count(*) FROM udr_doc");
    if (PQresultStatus(r) == PGRES_TUPLES_OK)
        atomic_store(&d->count, strtol(PQgetvalue(r, 0, 0), NULL, 10));
    PQclear(r);
    db = g5c_xcalloc(1, sizeof *db);
    db->ops = &pg_ops;
    db->self = d;
    return db;
}

#endif
