/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include "g5c/json.h"

#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct g5c_json {
    g5c_jtype type;
    union {
        bool b;
        int64_t i;
        double d;
        char *s;
        struct {
            g5c_json **v;
            size_t n, cap;
        } arr;
        struct {
            char **k;
            g5c_json **v;
            size_t n, cap;
            /* open-addressing index (key -> latest member + 1) for objects with many members, so lookups and inserts stay
             * O(1) and a hostile body with tens of thousands of keys cannot make the NF quadratic. Maintained eagerly on
             * every change, never built lazily: readers of a shared DOM must not mutate it. */
            uint32_t *ht;
            size_t htcap; /* power of two, 0: no index */
        } obj;
    } u;
};

static g5c_json *node(g5c_jtype t)
{
    g5c_json *j = g5c_xcalloc(1, sizeof *j);
    j->type = t;
    return j;
}

void g5c_json_free(g5c_json *j)
{
    if (j == NULL)
        return;
    switch (j->type) {
    case G5C_J_STRING:
        free(j->u.s);
        break;
    case G5C_J_ARRAY:
        for (size_t i = 0; i < j->u.arr.n; i++)
            g5c_json_free(j->u.arr.v[i]);
        free(j->u.arr.v);
        break;
    case G5C_J_OBJECT:
        for (size_t i = 0; i < j->u.obj.n; i++) {
            free(j->u.obj.k[i]);
            g5c_json_free(j->u.obj.v[i]);
        }
        free(j->u.obj.k);
        free(j->u.obj.v);
        free(j->u.obj.ht);
        break;
    default:
        break;
    }
    free(j);
}

/* ---- accessors ------------------------------------------------------------ */

g5c_jtype g5c_json_type(const g5c_json *j)
{
    return j ? j->type : G5C_J_NULL;
}

bool g5c_json_is(const g5c_json *j, g5c_jtype t)
{
    return j != NULL && j->type == t;
}

#define HT_MIN_MEMBERS 16

static size_t key_hash(const char *k)
{
    uint64_t h = 1469598103934665603ULL; /* FNV-1a */
    for (; *k; k++)
        h = (h ^ (uint8_t)*k) * 1099511628211ULL;
    return (size_t)(h ^ (h >> 32));
}

/* index of the latest member called `key`, or SIZE_MAX (last duplicate wins) */
static size_t obj_find(const g5c_json *o, const char *key)
{
    if (o->u.obj.ht != NULL) {
        size_t mask = o->u.obj.htcap - 1, h = key_hash(key) & mask;
        while (o->u.obj.ht[h] != 0) {
            size_t idx = o->u.obj.ht[h] - 1;
            if (strcmp(o->u.obj.k[idx], key) == 0)
                return idx;
            h = (h + 1) & mask;
        }
        return SIZE_MAX;
    }
    for (size_t i = o->u.obj.n; i > 0; i--)
        if (strcmp(o->u.obj.k[i - 1], key) == 0)
            return i - 1;
    return SIZE_MAX;
}

static void ht_put(g5c_json *o, size_t idx)
{
    size_t mask = o->u.obj.htcap - 1, h = key_hash(o->u.obj.k[idx]) & mask;
    while (o->u.obj.ht[h] != 0) {
        if (strcmp(o->u.obj.k[o->u.obj.ht[h] - 1], o->u.obj.k[idx]) == 0) { /* duplicate key: the newer member wins */
            o->u.obj.ht[h] = (uint32_t)(idx + 1);
            return;
        }
        h = (h + 1) & mask;
    }
    o->u.obj.ht[h] = (uint32_t)(idx + 1);
}

static void ht_rebuild(g5c_json *o)
{
    size_t want = 0;
    free(o->u.obj.ht);
    o->u.obj.ht = NULL;
    o->u.obj.htcap = 0;
    if (o->u.obj.n < HT_MIN_MEMBERS || o->u.obj.n >= UINT32_MAX / 4)
        return;
    want = 64;
    while (want < o->u.obj.n * 2 + 2)
        want <<= 1;
    o->u.obj.ht = g5c_xcalloc(want, sizeof *o->u.obj.ht);
    o->u.obj.htcap = want;
    for (size_t i = 0; i < o->u.obj.n; i++)
        ht_put(o, i);
}

const g5c_json *g5c_json_get(const g5c_json *obj, const char *key)
{
    size_t i;
    if (!g5c_json_is(obj, G5C_J_OBJECT))
        return NULL;
    i = obj_find(obj, key);
    return i == SIZE_MAX ? NULL : obj->u.obj.v[i];
}

g5c_json *g5c_json_get_mut(g5c_json *obj, const char *key)
{
    return (g5c_json *)(uintptr_t)g5c_json_get(obj, key);
}

size_t g5c_json_len(const g5c_json *j)
{
    if (g5c_json_is(j, G5C_J_ARRAY))
        return j->u.arr.n;
    if (g5c_json_is(j, G5C_J_OBJECT))
        return j->u.obj.n;
    return 0;
}

const g5c_json *g5c_json_at(const g5c_json *arr, size_t i)
{
    return (g5c_json_is(arr, G5C_J_ARRAY) && i < arr->u.arr.n) ? arr->u.arr.v[i] : NULL;
}

const char *g5c_json_key_at(const g5c_json *obj, size_t i)
{
    return (g5c_json_is(obj, G5C_J_OBJECT) && i < obj->u.obj.n) ? obj->u.obj.k[i] : NULL;
}

const g5c_json *g5c_json_val_at(const g5c_json *obj, size_t i)
{
    return (g5c_json_is(obj, G5C_J_OBJECT) && i < obj->u.obj.n) ? obj->u.obj.v[i] : NULL;
}

const char *g5c_json_str(const g5c_json *j)
{
    return g5c_json_is(j, G5C_J_STRING) ? j->u.s : NULL;
}

bool g5c_json_int(const g5c_json *j, int64_t *out)
{
    if (!g5c_json_is(j, G5C_J_INT))
        return false;
    *out = j->u.i;
    return true;
}

bool g5c_json_bool(const g5c_json *j, bool *out)
{
    if (!g5c_json_is(j, G5C_J_BOOL))
        return false;
    *out = j->u.b;
    return true;
}

bool g5c_json_num(const g5c_json *j, double *out)
{
    if (g5c_json_is(j, G5C_J_INT))
        *out = (double)j->u.i;
    else if (g5c_json_is(j, G5C_J_DOUBLE))
        *out = j->u.d;
    else
        return false;
    return true;
}

const char *g5c_json_get_str(const g5c_json *obj, const char *key)
{
    return g5c_json_str(g5c_json_get(obj, key));
}

bool g5c_json_get_int(const g5c_json *obj, const char *key, int64_t *out)
{
    return g5c_json_int(g5c_json_get(obj, key), out);
}

bool g5c_json_get_bool(const g5c_json *obj, const char *key, bool *out)
{
    return g5c_json_bool(g5c_json_get(obj, key), out);
}

/* ---- construction ---------------------------------------------------------- */

g5c_json *g5c_json_new_null(void)
{
    return node(G5C_J_NULL);
}

g5c_json *g5c_json_new_bool(bool b)
{
    g5c_json *j = node(G5C_J_BOOL);
    j->u.b = b;
    return j;
}

g5c_json *g5c_json_new_int(int64_t i)
{
    g5c_json *j = node(G5C_J_INT);
    j->u.i = i;
    return j;
}

g5c_json *g5c_json_new_double(double d)
{
    g5c_json *j = node(G5C_J_DOUBLE);
    j->u.d = d;
    return j;
}

g5c_json *g5c_json_new_strn(const char *s, size_t n)
{
    g5c_json *j = node(G5C_J_STRING);
    j->u.s = g5c_xstrndup(s, n);
    return j;
}

g5c_json *g5c_json_new_str(const char *s)
{
    return g5c_json_new_strn(s, strlen(s));
}

g5c_json *g5c_json_new_arr(void)
{
    return node(G5C_J_ARRAY);
}

g5c_json *g5c_json_new_obj(void)
{
    return node(G5C_J_OBJECT);
}

g5c_json *g5c_json_push(g5c_json *arr, g5c_json *val)
{
    if (!g5c_json_is(arr, G5C_J_ARRAY)) {
        g5c_json_free(val);
        return NULL;
    }
    if (arr->u.arr.n == arr->u.arr.cap) {
        arr->u.arr.cap = arr->u.arr.cap ? arr->u.arr.cap * 2 : 4;
        arr->u.arr.v = g5c_xrealloc(arr->u.arr.v, arr->u.arr.cap * sizeof *arr->u.arr.v);
    }
    arr->u.arr.v[arr->u.arr.n++] = val;
    return val;
}

g5c_json *g5c_json_push_str(g5c_json *arr, const char *s)
{
    return g5c_json_push(arr, g5c_json_new_str(s));
}

static g5c_json *obj_append(g5c_json *obj, char *key /* owned */, g5c_json *val)
{
    if (obj->u.obj.n == obj->u.obj.cap) {
        obj->u.obj.cap = obj->u.obj.cap ? obj->u.obj.cap * 2 : 4;
        obj->u.obj.k = g5c_xrealloc(obj->u.obj.k, obj->u.obj.cap * sizeof *obj->u.obj.k);
        obj->u.obj.v = g5c_xrealloc(obj->u.obj.v, obj->u.obj.cap * sizeof *obj->u.obj.v);
    }
    obj->u.obj.k[obj->u.obj.n] = key;
    obj->u.obj.v[obj->u.obj.n++] = val;
    if (obj->u.obj.ht != NULL && obj->u.obj.n * 2 + 2 <= obj->u.obj.htcap)
        ht_put(obj, obj->u.obj.n - 1);
    else if (obj->u.obj.n >= HT_MIN_MEMBERS)
        ht_rebuild(obj); /* first index, or the table is getting full */
    return val;
}

g5c_json *g5c_json_set(g5c_json *obj, const char *key, g5c_json *val)
{
    if (!g5c_json_is(obj, G5C_J_OBJECT)) {
        g5c_json_free(val);
        return NULL;
    }
    {
        size_t i = obj_find(obj, key);
        if (i != SIZE_MAX) {
            g5c_json_free(obj->u.obj.v[i]);
            obj->u.obj.v[i] = val;
            return val;
        }
    }
    return obj_append(obj, g5c_xstrdup(key), val);
}

g5c_json *g5c_json_set_str(g5c_json *obj, const char *key, const char *s)
{
    return g5c_json_set(obj, key, g5c_json_new_str(s));
}

g5c_json *g5c_json_set_int(g5c_json *obj, const char *key, int64_t i)
{
    return g5c_json_set(obj, key, g5c_json_new_int(i));
}

g5c_json *g5c_json_set_bool(g5c_json *obj, const char *key, bool b)
{
    return g5c_json_set(obj, key, g5c_json_new_bool(b));
}

g5c_json *g5c_json_detach(g5c_json *obj, const char *key)
{
    if (!g5c_json_is(obj, G5C_J_OBJECT))
        return NULL;
    {
        size_t at = obj_find(obj, key);
        if (at != SIZE_MAX) {
            g5c_json *v = obj->u.obj.v[at];
            free(obj->u.obj.k[at]);
            memmove(&obj->u.obj.k[at], &obj->u.obj.k[at + 1], (obj->u.obj.n - at - 1) * sizeof *obj->u.obj.k);
            memmove(&obj->u.obj.v[at], &obj->u.obj.v[at + 1], (obj->u.obj.n - at - 1) * sizeof *obj->u.obj.v);
            obj->u.obj.n--;
            if (obj->u.obj.ht != NULL)
                ht_rebuild(obj);
            return v;
        }
    }
    return NULL;
}

bool g5c_json_remove(g5c_json *obj, const char *key)
{
    g5c_json *v = g5c_json_detach(obj, key);
    g5c_json_free(v);
    return v != NULL;
}

g5c_json *g5c_json_at_mut(g5c_json *arr, size_t i)
{
    return (g5c_json_is(arr, G5C_J_ARRAY) && i < arr->u.arr.n) ? arr->u.arr.v[i] : NULL;
}

bool g5c_json_arr_insert(g5c_json *arr, size_t i, g5c_json *val)
{
    if (!g5c_json_is(arr, G5C_J_ARRAY) || i > arr->u.arr.n) {
        g5c_json_free(val);
        return false;
    }
    g5c_json_push(arr, val); /* grows the array; then rotate into place */
    memmove(&arr->u.arr.v[i + 1], &arr->u.arr.v[i], (arr->u.arr.n - 1 - i) * sizeof *arr->u.arr.v);
    arr->u.arr.v[i] = val;
    return true;
}

bool g5c_json_arr_remove(g5c_json *arr, size_t i)
{
    if (!g5c_json_is(arr, G5C_J_ARRAY) || i >= arr->u.arr.n)
        return false;
    g5c_json_free(arr->u.arr.v[i]);
    memmove(&arr->u.arr.v[i], &arr->u.arr.v[i + 1], (arr->u.arr.n - i - 1) * sizeof *arr->u.arr.v);
    arr->u.arr.n--;
    return true;
}

bool g5c_json_arr_replace(g5c_json *arr, size_t i, g5c_json *val)
{
    if (!g5c_json_is(arr, G5C_J_ARRAY) || i >= arr->u.arr.n) {
        g5c_json_free(val);
        return false;
    }
    g5c_json_free(arr->u.arr.v[i]);
    arr->u.arr.v[i] = val;
    return true;
}

g5c_json *g5c_json_dup(const g5c_json *j)
{
    g5c_json *o;
    if (j == NULL)
        return NULL;
    switch (j->type) {
    case G5C_J_STRING:
        return g5c_json_new_str(j->u.s);
    case G5C_J_ARRAY:
        o = g5c_json_new_arr();
        for (size_t i = 0; i < j->u.arr.n; i++)
            g5c_json_push(o, g5c_json_dup(j->u.arr.v[i]));
        return o;
    case G5C_J_OBJECT:
        o = g5c_json_new_obj();
        for (size_t i = 0; i < j->u.obj.n; i++)
            obj_append(o, g5c_xstrdup(j->u.obj.k[i]), g5c_json_dup(j->u.obj.v[i]));
        return o;
    default:
        o = node(j->type);
        o->u = j->u;
        return o;
    }
}

bool g5c_json_equal(const g5c_json *a, const g5c_json *b)
{
    if (a == b)
        return true;
    if (a == NULL || b == NULL)
        return false;
    if (a->type != b->type) {
        double x, y;
        return g5c_json_num(a, &x) && g5c_json_num(b, &y) && x == y;
    }
    switch (a->type) {
    case G5C_J_NULL:
        return true;
    case G5C_J_BOOL:
        return a->u.b == b->u.b;
    case G5C_J_INT:
        return a->u.i == b->u.i;
    case G5C_J_DOUBLE:
        return a->u.d == b->u.d;
    case G5C_J_STRING:
        return strcmp(a->u.s, b->u.s) == 0;
    case G5C_J_ARRAY:
        if (a->u.arr.n != b->u.arr.n)
            return false;
        for (size_t i = 0; i < a->u.arr.n; i++)
            if (!g5c_json_equal(a->u.arr.v[i], b->u.arr.v[i]))
                return false;
        return true;
    case G5C_J_OBJECT: {
        /* order-insensitive, by effective (last) value of each key */
        size_t na = 0, nb = 0;
        for (size_t i = 0; i < a->u.obj.n; i++)
            if (g5c_json_get(a, a->u.obj.k[i]) == a->u.obj.v[i])
                na++;
        for (size_t i = 0; i < b->u.obj.n; i++)
            if (g5c_json_get(b, b->u.obj.k[i]) == b->u.obj.v[i])
                nb++;
        if (na != nb)
            return false;
        for (size_t i = 0; i < a->u.obj.n; i++) {
            if (g5c_json_get(a, a->u.obj.k[i]) != a->u.obj.v[i])
                continue;
            if (!g5c_json_equal(a->u.obj.v[i], g5c_json_get(b, a->u.obj.k[i])))
                return false;
        }
        return true;
    }
    }
    return false;
}

/* ---- serialisation --------------------------------------------------------- */

static int write_str(g5c_bytes *o, const char *s)
{
    if (g5c_bytes_putc(o, '"') != 0)
        return -1;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        int rc;
        switch (c) {
        case '"':
            rc = g5c_bytes_append_str(o, "\\\"");
            break;
        case '\\':
            rc = g5c_bytes_append_str(o, "\\\\");
            break;
        case '\n':
            rc = g5c_bytes_append_str(o, "\\n");
            break;
        case '\r':
            rc = g5c_bytes_append_str(o, "\\r");
            break;
        case '\t':
            rc = g5c_bytes_append_str(o, "\\t");
            break;
        default:
            rc = c < 0x20 ? g5c_bytes_printf(o, "\\u%04x", c) : g5c_bytes_putc(o, (char)c);
        }
        if (rc != 0)
            return -1;
    }
    return g5c_bytes_putc(o, '"');
}

static int write_val(const g5c_json *j, g5c_bytes *o)
{
    switch (j->type) {
    case G5C_J_NULL:
        return g5c_bytes_append_str(o, "null");
    case G5C_J_BOOL:
        return g5c_bytes_append_str(o, j->u.b ? "true" : "false");
    case G5C_J_INT:
        return g5c_bytes_printf(o, "%lld", (long long)j->u.i);
    case G5C_J_DOUBLE:
        if (!isfinite(j->u.d))
            return g5c_bytes_append_str(o, "null");
        return g5c_bytes_printf(o, "%.17g", j->u.d);
    case G5C_J_STRING:
        return write_str(o, j->u.s);
    case G5C_J_ARRAY:
        if (g5c_bytes_putc(o, '[') != 0)
            return -1;
        for (size_t i = 0; i < j->u.arr.n; i++)
            if ((i && g5c_bytes_putc(o, ',') != 0) || write_val(j->u.arr.v[i], o) != 0)
                return -1;
        return g5c_bytes_putc(o, ']');
    case G5C_J_OBJECT:
        if (g5c_bytes_putc(o, '{') != 0)
            return -1;
        for (size_t i = 0; i < j->u.obj.n; i++) {
            if ((i && g5c_bytes_putc(o, ',') != 0) || write_str(o, j->u.obj.k[i]) != 0 ||
                g5c_bytes_putc(o, ':') != 0 || write_val(j->u.obj.v[i], o) != 0)
                return -1;
        }
        return g5c_bytes_putc(o, '}');
    }
    return -1;
}

int g5c_json_write(const g5c_json *j, g5c_bytes *out)
{
    return j ? write_val(j, out) : g5c_bytes_append_str(out, "null");
}

char *g5c_json_to_string(const g5c_json *j, size_t *len)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    if (g5c_json_write(j, &b) != 0) {
        g5c_bytes_free(&b);
        return NULL;
    }
    return g5c_bytes_take(&b, len);
}

/* ---- parser ---------------------------------------------------------------- */

typedef struct {
    const char *start, *p, *end;
    char *err;
    size_t errcap;
    bool failed;
} ps;

static void fail(ps *s, const char *msg)
{
    if (!s->failed && s->err != NULL && s->errcap > 0)
        snprintf(s->err, s->errcap, "%s at offset %zu", msg, (size_t)(s->p - s->start));
    s->failed = true;
}

static void skip_ws(ps *s)
{
    while (s->p < s->end && (*s->p == ' ' || *s->p == '\t' || *s->p == '\n' || *s->p == '\r'))
        s->p++;
}

static int hex4(const char *p)
{
    int v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        int d;
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
        else
            return -1;
        v = v * 16 + d;
    }
    return v;
}

static void put_utf8(g5c_bytes *b, uint32_t c)
{
    char o[4];
    size_t n;
    if (c < 0x80) {
        o[0] = (char)c;
        n = 1;
    } else if (c < 0x800) {
        o[0] = (char)(0xC0 | (c >> 6));
        o[1] = (char)(0x80 | (c & 0x3F));
        n = 2;
    } else if (c < 0x10000) {
        o[0] = (char)(0xE0 | (c >> 12));
        o[1] = (char)(0x80 | ((c >> 6) & 0x3F));
        o[2] = (char)(0x80 | (c & 0x3F));
        n = 3;
    } else {
        o[0] = (char)(0xF0 | (c >> 18));
        o[1] = (char)(0x80 | ((c >> 12) & 0x3F));
        o[2] = (char)(0x80 | ((c >> 6) & 0x3F));
        o[3] = (char)(0x80 | (c & 0x3F));
        n = 4;
    }
    g5c_bytes_append(b, o, n);
}

/* Length of a valid UTF-8 sequence at p (bounded by end), or 0 if invalid. */
static size_t utf8_len(const unsigned char *p, const unsigned char *end)
{
    size_t need;
    uint32_t c = p[0], min;
    if (c < 0x80)
        return 1;
    if (c >= 0xC2 && c <= 0xDF) {
        need = 1;
        c &= 0x1F;
        min = 0x80;
    } else if (c >= 0xE0 && c <= 0xEF) {
        need = 2;
        c &= 0x0F;
        min = 0x800;
    } else if (c >= 0xF0 && c <= 0xF4) {
        need = 3;
        c &= 0x07;
        min = 0x10000;
    } else {
        return 0;
    }
    if ((size_t)(end - p) < need + 1)
        return 0;
    for (size_t i = 1; i <= need; i++) {
        if ((p[i] & 0xC0) != 0x80)
            return 0;
        c = (c << 6) | (p[i] & 0x3F);
    }
    if (c < min || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF))
        return 0;
    return need + 1;
}

static char *parse_string(ps *s)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    s->p++; /* opening quote */
    for (;;) {
        unsigned char c;
        if (s->p >= s->end) {
            fail(s, "unterminated string");
            goto bad;
        }
        c = (unsigned char)*s->p;
        if (c == '"') {
            s->p++;
            break;
        }
        if (c < 0x20) {
            fail(s, "control character in string");
            goto bad;
        }
        if (c == '\\') {
            char e;
            if (s->end - s->p < 2) {
                fail(s, "bad escape");
                goto bad;
            }
            e = s->p[1];
            s->p += 2;
            switch (e) {
            case '"': g5c_bytes_putc(&b, '"'); break;
            case '\\': g5c_bytes_putc(&b, '\\'); break;
            case '/': g5c_bytes_putc(&b, '/'); break;
            case 'b': g5c_bytes_putc(&b, '\b'); break;
            case 'f': g5c_bytes_putc(&b, '\f'); break;
            case 'n': g5c_bytes_putc(&b, '\n'); break;
            case 'r': g5c_bytes_putc(&b, '\r'); break;
            case 't': g5c_bytes_putc(&b, '\t'); break;
            case 'u': {
                int u, lo;
                uint32_t cp;
                if (s->end - s->p < 4 || (u = hex4(s->p)) < 0) {
                    fail(s, "bad \\u escape");
                    goto bad;
                }
                s->p += 4;
                cp = (uint32_t)u;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (s->end - s->p < 6 || s->p[0] != '\\' || s->p[1] != 'u' || (lo = hex4(s->p + 2)) < 0 ||
                        lo < 0xDC00 || lo > 0xDFFF) {
                        fail(s, "lone surrogate");
                        goto bad;
                    }
                    s->p += 6;
                    cp = 0x10000U + (((uint32_t)u - 0xD800U) << 10) + ((uint32_t)lo - 0xDC00U);
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    fail(s, "lone surrogate");
                    goto bad;
                }
                if (cp == 0) { /* NUL cannot live in a C string */
                    fail(s, "NUL in string");
                    goto bad;
                }
                put_utf8(&b, cp);
                break;
            }
            default:
                fail(s, "bad escape");
                goto bad;
            }
            continue;
        }
        {
            size_t l = utf8_len((const unsigned char *)s->p, (const unsigned char *)s->end);
            if (l == 0) {
                fail(s, "invalid UTF-8");
                goto bad;
            }
            g5c_bytes_append(&b, s->p, l);
            s->p += l;
        }
    }
    return g5c_bytes_take(&b, NULL);
bad:
    g5c_bytes_free(&b);
    return NULL;
}

static g5c_json *parse_number(ps *s)
{
    const char *start = s->p, *p = s->p;
    bool is_float = false;
    char buf[64];
    size_t n;
    if (p < s->end && *p == '-')
        p++;
    if (p >= s->end) {
        fail(s, "bad number");
        return NULL;
    }
    if (*p == '0') {
        p++;
    } else if (*p >= '1' && *p <= '9') {
        while (p < s->end && *p >= '0' && *p <= '9')
            p++;
    } else {
        fail(s, "bad number");
        return NULL;
    }
    if (p < s->end && *p == '.') {
        is_float = true;
        p++;
        if (p >= s->end || *p < '0' || *p > '9') {
            fail(s, "bad number");
            return NULL;
        }
        while (p < s->end && *p >= '0' && *p <= '9')
            p++;
    }
    if (p < s->end && (*p == 'e' || *p == 'E')) {
        is_float = true;
        p++;
        if (p < s->end && (*p == '+' || *p == '-'))
            p++;
        if (p >= s->end || *p < '0' || *p > '9') {
            fail(s, "bad number");
            return NULL;
        }
        while (p < s->end && *p >= '0' && *p <= '9')
            p++;
    }
    n = (size_t)(p - start);
    if (n >= sizeof buf) {
        fail(s, "number too long");
        return NULL;
    }
    memcpy(buf, start, n);
    buf[n] = '\0';
    s->p = p;
    if (!is_float) {
        char *e;
        long long v;
        errno = 0;
        v = strtoll(buf, &e, 10);
        if (errno == 0 && *e == '\0')
            return g5c_json_new_int((int64_t)v);
        /* does not fit in int64: fall back to double */
    }
    {
        double d = strtod(buf, NULL);
        if (!isfinite(d)) { /* 1e999 would become infinity and later serialise as null: refuse it instead */
            fail(s, "number out of range");
            return NULL;
        }
        return g5c_json_new_double(d);
    }
}

static g5c_json *parse_value(ps *s, int depth)
{
    g5c_json *j = NULL;
    skip_ws(s);
    if (s->p >= s->end) {
        fail(s, "unexpected end");
        return NULL;
    }
    if (depth > G5C_JSON_MAX_DEPTH) {
        fail(s, "nesting too deep");
        return NULL;
    }
    switch (*s->p) {
    case '{': {
        j = g5c_json_new_obj();
        s->p++;
        skip_ws(s);
        if (s->p < s->end && *s->p == '}') {
            s->p++;
            return j;
        }
        for (;;) {
            char *k;
            g5c_json *v;
            skip_ws(s);
            if (s->p >= s->end || *s->p != '"') {
                fail(s, "expected object key");
                goto bad;
            }
            k = parse_string(s);
            if (k == NULL)
                goto bad;
            skip_ws(s);
            if (s->p >= s->end || *s->p != ':') {
                free(k);
                fail(s, "expected ':'");
                goto bad;
            }
            s->p++;
            v = parse_value(s, depth + 1);
            if (v == NULL) {
                free(k);
                goto bad;
            }
            obj_append(j, k, v);
            skip_ws(s);
            if (s->p < s->end && *s->p == ',') {
                s->p++;
                continue;
            }
            if (s->p < s->end && *s->p == '}') {
                s->p++;
                return j;
            }
            fail(s, "expected ',' or '}'");
            goto bad;
        }
    }
    case '[': {
        j = g5c_json_new_arr();
        s->p++;
        skip_ws(s);
        if (s->p < s->end && *s->p == ']') {
            s->p++;
            return j;
        }
        for (;;) {
            g5c_json *v = parse_value(s, depth + 1);
            if (v == NULL)
                goto bad;
            g5c_json_push(j, v);
            skip_ws(s);
            if (s->p < s->end && *s->p == ',') {
                s->p++;
                continue;
            }
            if (s->p < s->end && *s->p == ']') {
                s->p++;
                return j;
            }
            fail(s, "expected ',' or ']'");
            goto bad;
        }
    }
    case '"': {
        char *str = parse_string(s);
        if (str == NULL)
            return NULL;
        j = node(G5C_J_STRING);
        j->u.s = str;
        return j;
    }
    case 't':
        if (s->end - s->p >= 4 && memcmp(s->p, "true", 4) == 0) {
            s->p += 4;
            return g5c_json_new_bool(true);
        }
        break;
    case 'f':
        if (s->end - s->p >= 5 && memcmp(s->p, "false", 5) == 0) {
            s->p += 5;
            return g5c_json_new_bool(false);
        }
        break;
    case 'n':
        if (s->end - s->p >= 4 && memcmp(s->p, "null", 4) == 0) {
            s->p += 4;
            return g5c_json_new_null();
        }
        break;
    default:
        if (*s->p == '-' || (*s->p >= '0' && *s->p <= '9'))
            return parse_number(s);
    }
    fail(s, "unexpected character");
    return NULL;
bad:
    g5c_json_free(j);
    return NULL;
}

g5c_json *g5c_json_parse(const char *str, size_t len, char *err, size_t errcap)
{
    ps s = {str, str, str + len, err, errcap, false};
    g5c_json *j;
    if (err != NULL && errcap > 0)
        err[0] = '\0';
    j = parse_value(&s, 0);
    if (j == NULL)
        return NULL;
    skip_ws(&s);
    if (s.p != s.end) {
        fail(&s, "trailing characters");
        g5c_json_free(j);
        return NULL;
    }
    return j;
}
