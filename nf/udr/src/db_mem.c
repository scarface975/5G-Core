/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* In-memory storage backend with optional write-behind persistence (snapshot + journal).
 *
 * Layout: root object part -> object key -> record {"v": document, "r": revision, "t": modification time}.
 * Persistence: a mutation records the partition it touched; a flusher thread appends the current content of every
 * touched partition to a journal (path.journal, one JSON line each, one fsync per batch) at most once per FLUSH_GAP_MS.
 * The snapshot (the file itself) is rewritten only when the journal has outgrown it. A snapshot newer than the journal
 * means the journal was folded into it (a crash between the snapshot and the journal truncation): that journal is
 * ignored. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "api.h"
#include "g5c/base.h"
#include "g5c/config.h"

#define FLUSH_GAP_MS 50
#define JOURNAL_MIN_BYTES (4u << 20)

typedef struct {
    char *path; /* NULL: volatile */
    pthread_rwlock_t lock;
    g5c_json *db;
    uint64_t rev;
    size_t count;
    pthread_t flusher;
    pthread_mutex_t fmu;
    pthread_cond_t fcv;
    bool flusher_on, stopping;
    g5c_json *dirty; /* object: partitions changed since the last flush (guarded by fmu) */
    char *jpath;
    int jfd;
    size_t jbytes, snapbytes;
} memdb;

static bool persist(memdb *s, const char *part);
static void flusher_start(memdb *s);
static void replay_journal(memdb *s);

static memdb *mem_new(void)
{
    memdb *s = g5c_xcalloc(1, sizeof *s);
    s->jfd = -1;
    pthread_rwlock_init(&s->lock, NULL);
    s->db = g5c_json_new_obj();
    return s;
}

static void recount(memdb *s)
{
    s->count = 0;
    s->rev = 0;
    for (size_t i = 0; i < g5c_json_len(s->db); i++) {
        const g5c_json *p = g5c_json_val_at(s->db, i);
        for (size_t k = 0; k < g5c_json_len(p); k++) {
            int64_t r = 0;
            (void)g5c_json_get_int(g5c_json_val_at(p, k), "r", &r);
            if ((uint64_t)r > s->rev)
                s->rev = (uint64_t)r;
            s->count++;
        }
    }
}

/* ---- persistence ------------------------------------------------------------------------------------------------ */

/* serialise (under the read lock) and replace the file atomically; the journal is folded in and truncated */
static bool write_file(memdb *s)
{
    char *tmp, *text;
    size_t n = 0;
    FILE *f;
    bool ok = false;
    pthread_rwlock_rdlock(&s->lock);
    text = g5c_json_to_string(s->db, &n);
    pthread_rwlock_unlock(&s->lock);
    tmp = g5c_xasprintf("%s.tmp", s->path);
    f = text != NULL ? fopen(tmp, "wb") : NULL;
    if (f != NULL) {
        ok = fwrite(text, 1, n, f) == n && fflush(f) == 0 && fsync(fileno(f)) == 0;
        if (fclose(f) != 0)
            ok = false;
        ok = ok && rename(tmp, s->path) == 0;
        if (!ok)
            (void)unlink(tmp);
    }
    if (!ok)
        G5C_LOGE("g5c_udr", "failed to persist the subscriber store to %s: %s", s->path, strerror(errno));
    if (ok) {
        s->snapbytes = n;
        if (s->jfd >= 0 && ftruncate(s->jfd, 0) == 0)
            s->jbytes = 0;
    }
    free(tmp);
    free(text);
    return ok;
}

/* append the current content of each listed partition to the journal: {"u":part,"d":content-or-null} per line */
static bool append_journal(memdb *s, const g5c_json *parts)
{
    size_t cap = 4096, len = 0;
    char *buf = g5c_xmalloc(cap);
    bool ok = true;
    pthread_rwlock_rdlock(&s->lock);
    for (size_t i = 0; i < g5c_json_len(parts); i++) {
        const char *id = g5c_json_key_at(parts, i);
        const g5c_json *doc = g5c_json_get(s->db, id);
        g5c_json *idj = g5c_json_new_str(id);
        char *ids_txt = g5c_json_to_string(idj, NULL);
        char *doc_txt = doc != NULL ? g5c_json_to_string(doc, NULL) : g5c_xstrdup("null");
        size_t need = strlen(ids_txt) + strlen(doc_txt) + 16;
        g5c_json_free(idj);
        if (len + need > cap) {
            cap = (len + need) * 2;
            buf = g5c_xrealloc(buf, cap);
        }
        len += (size_t)snprintf(buf + len, cap - len, "{\"u\":%s,\"d\":%s}\n", ids_txt, doc_txt);
        free(ids_txt);
        free(doc_txt);
    }
    pthread_rwlock_unlock(&s->lock);
    for (size_t off = 0; ok && off < len;) {
        ssize_t w = write(s->jfd, buf + off, len - off);
        if (w <= 0)
            ok = false;
        else
            off += (size_t)w;
    }
    ok = ok && fsync(s->jfd) == 0;
    if (ok)
        s->jbytes += len;
    else
        G5C_LOGE("g5c_udr", "failed to append to the journal %s: %s", s->jpath, strerror(errno));
    free(buf);
    return ok;
}

static void *flusher_main(void *arg)
{
    memdb *s = arg;
    for (;;) {
        struct timespec gap = {0, FLUSH_GAP_MS * 1000000L};
        g5c_json *take;
        bool full, stopping;
        pthread_mutex_lock(&s->fmu);
        while (g5c_json_len(s->dirty) == 0 && !s->stopping)
            pthread_cond_wait(&s->fcv, &s->fmu);
        stopping = s->stopping;
        if (g5c_json_len(s->dirty) == 0 && stopping) {
            pthread_mutex_unlock(&s->fmu);
            return NULL;
        }
        pthread_mutex_unlock(&s->fmu);
        if (!stopping)
            nanosleep(&gap, NULL); /* let a burst of mutations coalesce into one batch */
        pthread_mutex_lock(&s->fmu);
        take = s->dirty;
        s->dirty = g5c_json_new_obj();
        pthread_mutex_unlock(&s->fmu);
        full = s->jfd < 0 || !append_journal(s, take);
        g5c_json_free(take);
        if (full || s->jbytes > (s->snapbytes * 2 > JOURNAL_MIN_BYTES ? s->snapbytes * 2 : JOURNAL_MIN_BYTES))
            (void)write_file(s);
    }
}

/* A mutation of partition `part` happened (the caller holds the write lock). Before the flusher exists (the first-run
 * creation check) the file is written at once and the result returned. */
static bool persist(memdb *s, const char *part)
{
    if (s->path == NULL)
        return true;
    if (!s->flusher_on)
        return write_file(s);
    pthread_mutex_lock(&s->fmu);
    if (g5c_json_get(s->dirty, part) == NULL)
        g5c_json_set(s->dirty, part, g5c_json_new_null());
    pthread_cond_signal(&s->fcv);
    pthread_mutex_unlock(&s->fmu);
    return true;
}

static void replay_journal(memdb *s)
{
    size_t len = 0;
    struct stat sn, js;
    char *text;
    if (stat(s->jpath, &js) != 0)
        return;
    if (stat(s->path, &sn) == 0 &&
        (sn.st_mtim.tv_sec > js.st_mtim.tv_sec ||
         (sn.st_mtim.tv_sec == js.st_mtim.tv_sec && sn.st_mtim.tv_nsec > js.st_mtim.tv_nsec))) {
        if (truncate(s->jpath, 0) != 0) /* folded into the snapshot already */
            G5C_LOGW("g5c_udr", "cannot truncate the stale journal %s", s->jpath);
        return;
    }
    text = g5c_read_file(s->jpath, 1024U << 20, &len);
    if (text == NULL)
        return;
    for (size_t pos = 0; pos < len;) {
        char *nl = memchr(text + pos, '\n', len - pos), perr[96];
        size_t ll = nl != NULL ? (size_t)(nl - (text + pos)) : len - pos;
        g5c_json *j;
        if (nl == NULL)
            break; /* a torn last line: the write did not complete */
        j = g5c_json_parse(text + pos, ll, perr, sizeof perr);
        pos += ll + 1;
        if (j == NULL)
            continue;
        {
            const char *u = g5c_json_get_str(j, "u");
            const g5c_json *d = g5c_json_get(j, "d");
            if (u != NULL && d != NULL) {
                if (g5c_json_is(d, G5C_J_OBJECT))
                    g5c_json_set(s->db, u, g5c_json_dup(d));
                else
                    (void)g5c_json_remove(s->db, u);
            }
        }
        g5c_json_free(j);
    }
    s->jbytes = len;
    free(text);
}

static void flusher_start(memdb *s)
{
    s->jpath = g5c_xasprintf("%s.journal", s->path);
    s->jfd = open(s->jpath, O_WRONLY | O_CREAT | O_APPEND, 0600);
    s->dirty = g5c_json_new_obj();
    pthread_mutex_init(&s->fmu, NULL);
    pthread_cond_init(&s->fcv, NULL);
    if (pthread_create(&s->flusher, NULL, flusher_main, s) == 0)
        s->flusher_on = true;
}

/* ---- operations ------------------------------------------------------------------------------------------------- */

static int64_t now_epoch(void)
{
    return (int64_t)time(NULL);
}

static g5c_json *rec_new(g5c_json *doc, uint64_t rev)
{
    g5c_json *r = g5c_json_new_obj();
    g5c_json_set(r, "v", doc);
    g5c_json_set_int(r, "r", (int64_t)rev);
    g5c_json_set_int(r, "t", now_epoch());
    return r;
}

static void rec_out(const g5c_json *r, udr_rec *out, bool with_doc)
{
    int64_t v = 0;
    if (out == NULL)
        return;
    out->doc = with_doc ? g5c_json_dup(g5c_json_get(r, "v")) : NULL;
    out->rev = g5c_json_get_int(r, "r", &v) ? (uint64_t)v : 0;
    out->mtime = g5c_json_get_int(r, "t", &v) ? v : 0;
}

static uint64_t rec_rev(const g5c_json *r)
{
    int64_t v = 0;
    return r != NULL && g5c_json_get_int(r, "r", &v) ? (uint64_t)v : 0;
}

static int m_get(void *self, const char *part, const char *key, udr_rec *out)
{
    memdb *s = self;
    const g5c_json *r;
    pthread_rwlock_rdlock(&s->lock);
    r = g5c_json_get(g5c_json_get(s->db, part), key);
    if (r != NULL)
        rec_out(r, out, true);
    pthread_rwlock_unlock(&s->lock);
    return r != NULL;
}

static int m_put(void *self, const char *part, const char *key, g5c_json *doc, const udr_cond *c, bool *created,
                 udr_rec *out, udr_rec *old_out)
{
    memdb *s = self;
    int rc = UDR_DB_OK;
    pthread_rwlock_wrlock(&s->lock);
    {
        g5c_json *p = g5c_json_get_mut(s->db, part);
        const g5c_json *old = g5c_json_get(p, key);
        if (!udr_cond_ok(c, old != NULL, rec_rev(old))) {
            g5c_json_free(doc);
            rc = UDR_DB_PRECONDITION;
        } else {
            g5c_json *rec = rec_new(doc, ++s->rev);
            if (p == NULL)
                p = g5c_json_set(s->db, part, g5c_json_new_obj());
            if (created != NULL)
                *created = old == NULL;
            if (old_out != NULL) {
                memset(old_out, 0, sizeof *old_out);
                if (old != NULL)
                    rec_out(old, old_out, true);
            }
            if (old == NULL)
                s->count++;
            rec_out(rec, out, false);
            g5c_json_set(p, key, rec);
            persist(s, part);
        }
    }
    pthread_rwlock_unlock(&s->lock);
    return rc;
}

static int m_del(void *self, const char *part, const char *key, const udr_cond *c, udr_rec *old)
{
    memdb *s = self;
    int rc = UDR_DB_OK;
    pthread_rwlock_wrlock(&s->lock);
    {
        g5c_json *p = g5c_json_get_mut(s->db, part);
        const g5c_json *cur = g5c_json_get(p, key);
        if (cur == NULL) {
            rc = UDR_DB_ABSENT;
        } else if (!udr_cond_ok(c, true, rec_rev(cur))) {
            rc = UDR_DB_PRECONDITION;
        } else {
            rec_out(cur, old, true);
            (void)g5c_json_remove(p, key);
            s->count--;
            if (g5c_json_len(p) == 0)
                (void)g5c_json_remove(s->db, part);
            persist(s, part);
        }
    }
    pthread_rwlock_unlock(&s->lock);
    return rc;
}

static int m_mutate(void *self, const char *part, const char *key, udr_mutator fn, void *arg, const udr_cond *c,
                    udr_rec *out, udr_rec *old, char *err, size_t errcap)
{
    memdb *s = self;
    int rc = UDR_DB_OK;
    pthread_rwlock_wrlock(&s->lock);
    {
        g5c_json *p = g5c_json_get_mut(s->db, part);
        const g5c_json *cur = g5c_json_get(p, key);
        if (cur == NULL) {
            rc = UDR_DB_ABSENT;
        } else if (!udr_cond_ok(c, true, rec_rev(cur))) {
            rc = UDR_DB_PRECONDITION;
        } else {
            g5c_json *copy = g5c_json_dup(g5c_json_get(cur, "v"));
            if (fn(&copy, arg, err, errcap) != 0) {
                g5c_json_free(copy);
                rc = UDR_DB_REJECTED;
            } else {
                g5c_json *rec = rec_new(copy, ++s->rev);
                rec_out(cur, old, true);
                rec_out(rec, out, true);
                g5c_json_set(p, key, rec);
                persist(s, part);
            }
        }
    }
    pthread_rwlock_unlock(&s->lock);
    return rc;
}

static int cmp_idx(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int m_list(void *self, const char *part, const char *prefix, udr_list *out)
{
    memdb *s = self;
    size_t pl = strlen(prefix);
    const char **keys = NULL;
    size_t n = 0;
    memset(out, 0, sizeof *out);
    pthread_rwlock_rdlock(&s->lock);
    {
        const g5c_json *p = g5c_json_get(s->db, part);
        keys = g5c_xcalloc(g5c_json_len(p) + 1, sizeof *keys);
        for (size_t i = 0; i < g5c_json_len(p); i++) {
            const char *k = g5c_json_key_at(p, i);
            if (strncmp(k, prefix, pl) == 0 && k[pl] == '/')
                keys[n++] = k;
        }
        qsort(keys, n, sizeof *keys, cmp_idx);
        out->keys = g5c_xcalloc(n + 1, sizeof *out->keys);
        out->recs = g5c_xcalloc(n + 1, sizeof *out->recs);
        for (size_t i = 0; i < n; i++) {
            out->keys[i] = g5c_xstrdup(keys[i]);
            rec_out(g5c_json_get(p, keys[i]), &out->recs[i], true);
        }
        out->n = n;
    }
    pthread_rwlock_unlock(&s->lock);
    free(keys);
    return 0;
}

static int m_part_exists(void *self, const char *part)
{
    memdb *s = self;
    int r;
    pthread_rwlock_rdlock(&s->lock);
    r = g5c_json_get(s->db, part) != NULL;
    pthread_rwlock_unlock(&s->lock);
    return r;
}

static int m_parts(void *self, g5c_json *out)
{
    memdb *s = self;
    const char **ids;
    size_t n;
    pthread_rwlock_rdlock(&s->lock);
    n = g5c_json_len(s->db);
    ids = g5c_xcalloc(n ? n : 1, sizeof *ids);
    for (size_t i = 0; i < n; i++)
        ids[i] = g5c_json_key_at(s->db, i);
    qsort(ids, n, sizeof *ids, cmp_idx);
    for (size_t i = 0; i < n; i++)
        g5c_json_push_str(out, ids[i]);
    free(ids);
    pthread_rwlock_unlock(&s->lock);
    return 0;
}

static int m_del_part(void *self, const char *part)
{
    memdb *s = self;
    int had = 0;
    pthread_rwlock_wrlock(&s->lock);
    {
        const g5c_json *p = g5c_json_get(s->db, part);
        if (p != NULL) {
            s->count -= g5c_json_len(p);
            had = g5c_json_remove(s->db, part);
            persist(s, part);
        }
    }
    pthread_rwlock_unlock(&s->lock);
    return had;
}

static size_t m_count(void *self)
{
    memdb *s = self;
    size_t n;
    pthread_rwlock_rdlock(&s->lock);
    n = s->count;
    pthread_rwlock_unlock(&s->lock);
    return n;
}

static void m_close(void *self)
{
    memdb *s = self;
    if (s->flusher_on) { /* writes what is pending, then the thread ends */
        pthread_mutex_lock(&s->fmu);
        s->stopping = true;
        pthread_cond_signal(&s->fcv);
        pthread_mutex_unlock(&s->fmu);
        pthread_join(s->flusher, NULL);
        pthread_cond_destroy(&s->fcv);
        pthread_mutex_destroy(&s->fmu);
    }
    if (s->jfd >= 0)
        close(s->jfd);
    free(s->jpath);
    g5c_json_free(s->dirty);
    g5c_json_free(s->db);
    free(s->path);
    pthread_rwlock_destroy(&s->lock);
    free(s);
}

static const udr_db_ops mem_ops = {"memory", m_get,    m_put,         m_del,     m_mutate, m_list,
                                   m_part_exists, m_parts, m_del_part, m_count, m_close};

static udr_db *wrap(memdb *s)
{
    udr_db *d = g5c_xcalloc(1, sizeof *d);
    d->ops = &mem_ops;
    d->self = s;
    return d;
}

udr_db *udr_db_memory(void)
{
    return wrap(mem_new());
}

udr_db *udr_db_file(const char *path, char *err, size_t errcap)
{
    memdb *s = mem_new();
    size_t len = 0;
    char *text = g5c_read_file(path, 256U << 20, &len);
    s->path = g5c_xstrdup(path);
    if (text == NULL) {
        if (access(path, F_OK) == 0) { /* exists but unreadable */
            snprintf(err, errcap, "cannot read %s", path);
            m_close(s);
            return NULL;
        }
        /* first run: create the file now, so an unwritable location is a start-up error, not a surprise at the first write */
        if (!persist(s, NULL)) {
            snprintf(err, errcap, "cannot create %s: %s", path, strerror(errno));
            m_close(s);
            return NULL;
        }
        flusher_start(s);
        return wrap(s);
    }
    g5c_json_free(s->db);
    s->db = g5c_json_parse(text, len, err, errcap);
    free(text);
    if (s->db == NULL || !g5c_json_is(s->db, G5C_J_OBJECT)) {
        if (s->db != NULL)
            snprintf(err, errcap, "%s: not a JSON object", path);
        g5c_json_free(s->db);
        s->db = g5c_json_new_obj();
        m_close(s);
        return NULL;
    }
    s->snapbytes = len;
    s->jpath = g5c_xasprintf("%s.journal", path);
    replay_journal(s);
    free(s->jpath);
    s->jpath = NULL;
    recount(s);
    flusher_start(s);
    return wrap(s);
}
