/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Validator for a schema pool generated from the pinned 3GPP OpenAPI files (tools/oa_pool.py) */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/oaschema.h"
#include "g5c/base.h"

#define MAX_DEPTH 48

typedef struct {
    char *pattern;
    regex_t re;
    bool ok; /* false: the pattern is outside the POSIX subset; it accepts everything */
} pat_t;

struct oa_schemas {
    g5c_json *pool; /* array of simplified schemas */
    pthread_mutex_t mu;
    pat_t **pats; /* individually allocated: a compiled regex is not moved */
    size_t npats;
};

oa_schemas *oa_schemas_load(const char *const *chunks, size_t nchunks, size_t count, char *err, size_t errcap)
{
    oa_schemas *s = g5c_xcalloc(1, sizeof *s);
    size_t total = 0, off = 0;
    char *text;
    for (size_t i = 0; i < nchunks; i++)
        total += strlen(chunks[i]);
    text = g5c_xmalloc(total + 1);
    for (size_t i = 0; i < nchunks; i++) {
        size_t n = strlen(chunks[i]);
        memcpy(text + off, chunks[i], n);
        off += n;
    }
    text[total] = '\0';
    s->pool = g5c_json_parse(text, total, err, errcap);
    free(text);
    if (s->pool == NULL || !g5c_json_is(s->pool, G5C_J_ARRAY) || g5c_json_len(s->pool) != count) {
        if (s->pool != NULL)
            snprintf(err, errcap, "schema pool has %zu entries, expected %zu", g5c_json_len(s->pool), count);
        g5c_json_free(s->pool);
        free(s);
        return NULL;
    }
    pthread_mutex_init(&s->mu, NULL);
    return s;
}

void oa_schemas_free(oa_schemas *s)
{
    if (s == NULL)
        return;
    for (size_t i = 0; i < s->npats; i++) {
        if (s->pats[i]->ok)
            regfree(&s->pats[i]->re);
        free(s->pats[i]->pattern);
        free(s->pats[i]);
    }
    free(s->pats);
    pthread_mutex_destroy(&s->mu);
    g5c_json_free(s->pool);
    free(s);
}

const g5c_json *oa_schema_node(const oa_schemas *s, int id)
{
    return id >= 0 ? g5c_json_at(s->pool, (size_t)id) : NULL;
}

/* ECMA-262 patterns of the OpenAPI files, reduced to POSIX ERE where that is lossless. */
static char *to_ere(const char *p)
{
    size_t n = strlen(p), o = 0;
    char *out = g5c_xmalloc(n * 8 + 1);
    for (size_t i = 0; i < n; i++) {
        if (p[i] == '\\' && i + 1 < n) {
            const char *rep = NULL;
            switch (p[i + 1]) {
            case 'd': rep = "[0-9]"; break;
            case 'D': rep = "[^0-9]"; break;
            case 'w': rep = "[A-Za-z0-9_]"; break;
            case 's': rep = "[ \t\r\n]"; break;
            default: break;
            }
            if (rep != NULL) {
                o += (size_t)snprintf(out + o, 16, "%s", rep);
                i++;
                continue;
            }
            out[o++] = p[i];
            out[o++] = p[++i];
            continue;
        }
        if (p[i] == '(' && i + 2 < n && p[i + 1] == '?' && p[i + 2] == ':') {
            out[o++] = '(';
            i += 2;
            continue;
        }
        out[o++] = p[i];
    }
    out[o] = '\0';
    return out;
}

static bool pattern_match(oa_schemas *s, const char *pattern, const char *text)
{
    pat_t *p = NULL;
    bool r = true;
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->npats; i++)
        if (strcmp(s->pats[i]->pattern, pattern) == 0) {
            p = s->pats[i];
            break;
        }
    if (p == NULL) {
        char *ere = to_ere(pattern);
        s->pats = g5c_xrealloc(s->pats, (s->npats + 1) * sizeof *s->pats);
        p = g5c_xcalloc(1, sizeof *p);
        s->pats[s->npats++] = p;
        p->pattern = g5c_xstrdup(pattern);
        p->ok = regcomp(&p->re, ere, REG_EXTENDED | REG_NOSUB) == 0;
        free(ere);
    }
    if (p->ok)
        r = regexec(&p->re, text, 0, NULL, 0) == 0;
    pthread_mutex_unlock(&s->mu);
    return r;
}

typedef struct {
    oa_schemas *s;
    char *err;
    size_t cap;
    char path[256];
} vctx;

static void fail(vctx *v, const char *fmt, ...) G5C_PRINTF(2, 3);
static void fail(vctx *v, const char *fmt, ...)
{
    va_list ap;
    int n;
    if (v->err == NULL || v->err[0] != '\0')
        return; /* keep the innermost first reason */
    n = snprintf(v->err, v->cap, "%s: ", v->path[0] ? v->path : "/");
    if (n < 0 || (size_t)n >= v->cap)
        return;
    va_start(ap, fmt);
    vsnprintf(v->err + n, v->cap - (size_t)n, fmt, ap);
    va_end(ap);
}

static bool check(vctx *v, const g5c_json *sch, const g5c_json *doc, int depth);

static bool check_ref(vctx *v, int64_t ix, const g5c_json *doc, int depth)
{
    if (ix < 0 || (size_t)ix >= g5c_json_len(v->s->pool))
        return true;
    return check(v, g5c_json_at(v->s->pool, (size_t)ix), doc, depth + 1);
}

/* a combinator alternative is tried quietly: its reason must not become the message of the enclosing failure */
static bool quiet(vctx *v, const g5c_json *sch, const g5c_json *doc, int depth)
{
    char saved[256];
    vctx q = *v;
    q.err = saved;
    q.cap = sizeof saved;
    saved[0] = '\0';
    return check(&q, sch, doc, depth);
}

static bool type_ok(const char *t, const g5c_json *d)
{
    if (strcmp(t, "object") == 0)
        return g5c_json_is(d, G5C_J_OBJECT);
    if (strcmp(t, "array") == 0)
        return g5c_json_is(d, G5C_J_ARRAY);
    if (strcmp(t, "string") == 0)
        return g5c_json_is(d, G5C_J_STRING);
    if (strcmp(t, "boolean") == 0)
        return g5c_json_is(d, G5C_J_BOOL);
    if (strcmp(t, "integer") == 0)
        return g5c_json_is(d, G5C_J_INT);
    if (strcmp(t, "number") == 0)
        return g5c_json_is(d, G5C_J_INT) || g5c_json_is(d, G5C_J_DOUBLE);
    return true;
}

static size_t utf8_len(const char *s)
{
    size_t n = 0;
    for (; *s; s++)
        if (((unsigned char)*s & 0xC0) != 0x80)
            n++;
    return n;
}

static bool check(vctx *v, const g5c_json *sch, const g5c_json *doc, int depth)
{
    const g5c_json *x;
    if (depth > MAX_DEPTH) {
        fail(v, "nesting too deep");
        return false;
    }
    if (sch == NULL || !g5c_json_is(sch, G5C_J_OBJECT))
        return true;
    if ((x = g5c_json_get(sch, "$")) != NULL) {
        int64_t ix;
        return g5c_json_int(x, &ix) ? check_ref(v, ix, doc, depth) : true;
    }
    if (g5c_json_is(doc, G5C_J_NULL)) {
        bool nb = false;
        if (g5c_json_get_bool(sch, "nullable", &nb) && nb)
            return true;
        if (g5c_json_get(sch, "type") == NULL && g5c_json_get(sch, "anyOf") == NULL &&
            g5c_json_get(sch, "oneOf") == NULL && g5c_json_get(sch, "properties") == NULL &&
            g5c_json_get(sch, "enum") == NULL)
            return true;
    }
    if ((x = g5c_json_get(sch, "type")) != NULL && g5c_json_is(x, G5C_J_STRING) && !type_ok(g5c_json_str(x), doc)) {
        if (!g5c_json_is(doc, G5C_J_NULL) || !(g5c_json_get(sch, "nullable") != NULL)) {
            fail(v, "expected %s", g5c_json_str(x));
            return false;
        }
    }
    if ((x = g5c_json_get(sch, "enum")) != NULL && g5c_json_is(x, G5C_J_ARRAY)) {
        bool hit = false;
        for (size_t i = 0; i < g5c_json_len(x) && !hit; i++)
            hit = g5c_json_equal(g5c_json_at(x, i), doc);
        if (!hit) {
            fail(v, "not one of the permitted values");
            return false;
        }
    }
    if (g5c_json_is(doc, G5C_J_STRING)) {
        const char *str = g5c_json_str(doc);
        int64_t lim;
        const char *pat = g5c_json_get_str(sch, "pattern");
        if (g5c_json_get_int(sch, "minLength", &lim) && (int64_t)utf8_len(str) < lim) {
            fail(v, "shorter than %lld", (long long)lim);
            return false;
        }
        if (g5c_json_get_int(sch, "maxLength", &lim) && (int64_t)utf8_len(str) > lim) {
            fail(v, "longer than %lld", (long long)lim);
            return false;
        }
        if (pat != NULL && !pattern_match(v->s, pat, str)) {
            fail(v, "does not match the pattern %s", pat);
            return false;
        }
    }
    if (g5c_json_is(doc, G5C_J_INT) || g5c_json_is(doc, G5C_J_DOUBLE)) {
        double val = 0, lim;
        (void)g5c_json_num(doc, &val);
        if (g5c_json_get(sch, "minimum") != NULL && g5c_json_num(g5c_json_get(sch, "minimum"), &lim) && val < lim) {
            fail(v, "below the minimum %g", lim);
            return false;
        }
        if (g5c_json_get(sch, "maximum") != NULL && g5c_json_num(g5c_json_get(sch, "maximum"), &lim) && val > lim) {
            fail(v, "above the maximum %g", lim);
            return false;
        }
    }
    if (g5c_json_is(doc, G5C_J_ARRAY)) {
        int64_t lim;
        const g5c_json *items = g5c_json_get(sch, "items");
        if (g5c_json_get_int(sch, "minItems", &lim) && (int64_t)g5c_json_len(doc) < lim) {
            fail(v, "fewer than %lld items", (long long)lim);
            return false;
        }
        if (g5c_json_get_int(sch, "maxItems", &lim) && (int64_t)g5c_json_len(doc) > lim) {
            fail(v, "more than %lld items", (long long)lim);
            return false;
        }
        if (items != NULL)
            for (size_t i = 0; i < g5c_json_len(doc); i++) {
                size_t keep = strlen(v->path);
                snprintf(v->path + keep, sizeof v->path - keep, "/%zu", i);
                if (!check(v, items, g5c_json_at(doc, i), depth + 1))
                    return false;
                v->path[keep] = '\0';
            }
    }
    if (g5c_json_is(doc, G5C_J_OBJECT)) {
        const g5c_json *req = g5c_json_get(sch, "required"), *props = g5c_json_get(sch, "properties");
        const g5c_json *ap = g5c_json_get(sch, "additionalProperties");
        int64_t lim;
        if (g5c_json_get_int(sch, "minProperties", &lim) && (int64_t)g5c_json_len(doc) < lim) {
            fail(v, "fewer than %lld properties", (long long)lim);
            return false;
        }
        if (g5c_json_get_int(sch, "maxProperties", &lim) && (int64_t)g5c_json_len(doc) > lim) {
            fail(v, "more than %lld properties", (long long)lim);
            return false;
        }
        for (size_t i = 0; req != NULL && i < g5c_json_len(req); i++) {
            const char *k = g5c_json_str(g5c_json_at(req, i));
            if (k != NULL && g5c_json_get(doc, k) == NULL) {
                fail(v, "missing the required member '%s'", k);
                return false;
            }
        }
        for (size_t i = 0; i < g5c_json_len(doc); i++) {
            const char *k = g5c_json_key_at(doc, i);
            const g5c_json *psch = props != NULL ? g5c_json_get(props, k) : NULL;
            size_t keep = strlen(v->path);
            if (psch == NULL) {
                if (ap == NULL || g5c_json_is(ap, G5C_J_BOOL)) {
                    bool allowed = true;
                    if (ap != NULL)
                        (void)g5c_json_bool(ap, &allowed);
                    if (!allowed) {
                        fail(v, "member '%s' is not allowed", k);
                        return false;
                    }
                    continue;
                }
                psch = ap;
            }
            snprintf(v->path + keep, sizeof v->path - keep, "/%s", k);
            if (!check(v, psch, g5c_json_val_at(doc, i), depth + 1))
                return false;
            v->path[keep] = '\0';
        }
    }
    if ((x = g5c_json_get(sch, "allOf")) != NULL && g5c_json_is(x, G5C_J_ARRAY))
        for (size_t i = 0; i < g5c_json_len(x); i++)
            if (!check(v, g5c_json_at(x, i), doc, depth + 1))
                return false;
    for (int k = 0; k < 2; k++) {
        x = g5c_json_get(sch, k == 0 ? "anyOf" : "oneOf");
        if (x != NULL && g5c_json_is(x, G5C_J_ARRAY) && g5c_json_len(x) > 0) {
            bool hit = false;
            for (size_t i = 0; i < g5c_json_len(x) && !hit; i++)
                hit = quiet(v, g5c_json_at(x, i), doc, depth + 1);
            if (!hit) {
                fail(v, "matches none of the permitted forms");
                return false;
            }
        }
    }
    return true;
}

int oa_validate(const oa_schemas *s, int id, const g5c_json *doc, char *err, size_t errcap)
{
    vctx v;
    if (err != NULL && errcap > 0)
        err[0] = '\0';
    if (id < 0 || s == NULL)
        return 0;
    v.s = (oa_schemas *)(uintptr_t)s;
    v.err = err;
    v.cap = errcap;
    v.path[0] = '\0';
    if (err == NULL) {
        char tmp[8] = "";
        v.err = tmp;
        v.cap = sizeof tmp;
        return check(&v, g5c_json_at(s->pool, (size_t)id), doc, 0) ? 0 : -1;
    }
    return check(&v, g5c_json_at(s->pool, (size_t)id), doc, 0) ? 0 : -1;
}
