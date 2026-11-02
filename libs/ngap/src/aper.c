/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Generic ASN.1 APER (X.691 aligned variant) codec driven by the generated NGAP schema. See ngap.h for the JSON
 * representation. Unsupported on purpose: length fragmentation (values of 16 KiB or more in one length-prefixed field),
 * REAL, and the IE-pair containers (not used by any NGAP message). */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/ngap.h"

#define MAX_IES_COUNT 65535U

/* ---- bit reader ---------------------------------------------------------------------------------------------------- */

typedef struct {
    const uint8_t *buf;
    size_t nbits, pos;
} br_t;

static int br_get(br_t *r, unsigned n, uint64_t *out)
{
    uint64_t v = 0;
    if (n > 64 || n > r->nbits - r->pos)
        return -1;
    for (unsigned i = 0; i < n; i++) {
        size_t p = r->pos + i;
        v = (v << 1) | (((unsigned)r->buf[p >> 3] >> (7 - (p & 7))) & 1U);
    }
    r->pos += n;
    *out = v;
    return 0;
}

static int br_align(br_t *r)
{
    size_t np = (r->pos + 7) & ~(size_t)7;
    if (np > r->nbits)
        return -1;
    r->pos = np;
    return 0;
}

/* aligned octets */
static const uint8_t *br_octets(br_t *r, size_t n)
{
    const uint8_t *p;
    if (br_align(r) != 0 || n > (r->nbits - r->pos) / 8)
        return NULL;
    p = r->buf + (r->pos >> 3);
    r->pos += n * 8;
    return p;
}

/* ---- bit writer ---------------------------------------------------------------------------------------------------- */

typedef struct {
    uint8_t *buf;
    size_t cap, nbits;
    bool oom;
} bw_t;

static void bw_ensure(bw_t *w, size_t bits_more)
{
    size_t need = (w->nbits + bits_more + 7) / 8;
    if (need > w->cap) {
        uint8_t *p;
        size_t nc = w->cap ? w->cap * 2 : 64;
        while (nc < need)
            nc *= 2;
        p = realloc(w->buf, nc);
        if (p == NULL) {
            w->oom = true;
            return;
        }
        memset(p + w->cap, 0, nc - w->cap);
        w->buf = p;
        w->cap = nc;
    }
}

static void bw_put(bw_t *w, uint64_t v, unsigned n)
{
    bw_ensure(w, n);
    if (w->oom)
        return;
    for (unsigned i = 0; i < n; i++) {
        size_t p = w->nbits + i;
        unsigned bit = (unsigned)((v >> (n - 1 - i)) & 1U);
        if (bit)
            w->buf[p >> 3] = (uint8_t)(w->buf[p >> 3] | (0x80U >> (p & 7)));
    }
    w->nbits += n;
}

static void bw_align(bw_t *w)
{
    size_t np = (w->nbits + 7) & ~(size_t)7;
    bw_ensure(w, np - w->nbits);
    w->nbits = np; /* padding bits are already zero */
}

static void bw_octets(bw_t *w, const uint8_t *p, size_t n)
{
    bw_align(w);
    bw_ensure(w, n * 8);
    if (w->oom)
        return;
    if (n)
        memcpy(w->buf + (w->nbits >> 3), p, n);
    w->nbits += n * 8;
}

static void bw_free(bw_t *w)
{
    free(w->buf);
    memset(w, 0, sizeof *w);
}

/* ---- contexts ------------------------------------------------------------------------------------------------------ */

typedef struct {
    char *err;
    size_t errcap;
    bool failed;
    size_t nodes;
} ctx_t;

static void fail(ctx_t *c, const char *fmt, ...) G5C_PRINTF(2, 3);
static void fail(ctx_t *c, const char *fmt, ...)
{
    va_list ap;
    if (c->failed)
        return;
    c->failed = true;
    if (c->err != NULL && c->errcap > 0) {
        va_start(ap, fmt);
        vsnprintf(c->err, c->errcap, fmt, ap);
        va_end(ap);
    }
}

static const ngap_type *resolve(const ngap_type *t)
{
    while (t->kind == NG_ALIAS)
        t = t->alias;
    return t;
}

static unsigned ceil_log2(uint64_t range)
{
    unsigned b = 0;
    uint64_t x = 1;
    while (x < range && b < 64) {
        x <<= 1;
        b++;
    }
    return b;
}

static unsigned span_octets(uint64_t span)
{
    unsigned n = 1;
    while (n < 8 && (span >> (8 * n)) != 0)
        n++;
    return n;
}

static const char *const CRIT[] = {"reject", "ignore", "notify"};

/* ---- constrained numbers and length determinants ------------------------------------------------------------------ */

/* Constrained whole number with the given span (ub - lb): encoded offset in *off. */
static int dec_constrained(br_t *r, uint64_t span, uint64_t *off)
{
    if (span == 0) {
        *off = 0;
        return 0;
    }
    if (span <= 254) { /* range <= 255: bit-field, no alignment */
        return br_get(r, ceil_log2(span + 1), off);
    }
    if (span == 255) {
        return br_align(r) == 0 ? br_get(r, 8, off) : -1;
    }
    if (span <= 65535) {
        return br_align(r) == 0 ? br_get(r, 16, off) : -1;
    }
    {   /* range > 64K: length of the octets in a small bit-field, then the octets */
        unsigned maxo = span_octets(span);
        uint64_t l, v = 0;
        const uint8_t *p;
        if (br_get(r, ceil_log2(maxo), &l) != 0)
            return -1;
        l += 1;
        if (l > maxo)
            return -1;
        p = br_octets(r, (size_t)l);
        if (p == NULL)
            return -1;
        for (size_t i = 0; i < l; i++)
            v = (v << 8) | p[i];
        *off = v;
        return 0;
    }
}

static void enc_constrained(bw_t *w, uint64_t span, uint64_t off)
{
    if (span == 0)
        return;
    if (span <= 254) {
        bw_put(w, off, ceil_log2(span + 1));
    } else if (span == 255) {
        bw_align(w);
        bw_put(w, off, 8);
    } else if (span <= 65535) {
        bw_align(w);
        bw_put(w, off, 16);
    } else {
        unsigned maxo = span_octets(span), n = 1;
        uint8_t b[8];
        while (n < 8 && (off >> (8 * n)) != 0)
            n++;
        bw_put(w, n - 1, ceil_log2(maxo));
        for (unsigned i = 0; i < n; i++)
            b[i] = (uint8_t)(off >> (8 * (n - 1 - i)));
        bw_octets(w, b, n);
    }
}

/* unconstrained length determinant (no fragmentation) */
static int dec_len_unc(br_t *r, size_t *n)
{
    uint64_t b0, b1;
    if (br_align(r) != 0 || br_get(r, 8, &b0) != 0)
        return -1;
    if ((b0 & 0x80U) == 0) {
        *n = (size_t)b0;
        return 0;
    }
    if ((b0 & 0xC0U) == 0x80U) {
        if (br_get(r, 8, &b1) != 0)
            return -1;
        *n = (size_t)(((b0 & 0x3FU) << 8) | b1);
        return 0;
    }
    return -1; /* fragmentation */
}

static int enc_len_unc(bw_t *w, size_t n)
{
    bw_align(w);
    if (n < 128) {
        bw_put(w, n, 8);
    } else if (n < 16384) {
        bw_put(w, 0x8000U | n, 16);
    } else {
        return -1;
    }
    return 0;
}

/* length determinant for a constrained/unconstrained size */
static int dec_len(br_t *r, int64_t lb, uint8_t has_ub, int64_t ub, size_t *n)
{
    if (has_ub && ub < 65536) {
        uint64_t off;
        if (ub < lb)
            return -1;
        if (dec_constrained(r, (uint64_t)(ub - lb), &off) != 0)
            return -1;
        *n = (size_t)((uint64_t)lb + off);
        return 0;
    }
    return dec_len_unc(r, n);
}

static int enc_len(bw_t *w, int64_t lb, uint8_t has_ub, int64_t ub, size_t n)
{
    if (has_ub && ub < 65536) {
        if ((int64_t)n < lb || (int64_t)n > ub)
            return -1;
        enc_constrained(w, (uint64_t)(ub - lb), (uint64_t)((int64_t)n - lb));
        return 0;
    }
    return enc_len_unc(w, n);
}

/* normally small non-negative whole number (X.691 11.6) */
static int dec_small(br_t *r, uint64_t *v)
{
    uint64_t b;
    if (br_get(r, 1, &b) != 0)
        return -1;
    if (b == 0)
        return br_get(r, 6, v);
    {
        size_t n;
        const uint8_t *p;
        uint64_t x = 0;
        if (dec_len_unc(r, &n) != 0 || n == 0 || n > 8)
            return -1;
        p = br_octets(r, n);
        if (p == NULL)
            return -1;
        for (size_t i = 0; i < n; i++)
            x = (x << 8) | p[i];
        *v = x;
        return 0;
    }
}

static int enc_small(bw_t *w, uint64_t v)
{
    if (v < 64) {
        bw_put(w, 0, 1);
        bw_put(w, v, 6);
        return 0;
    }
    {
        uint8_t b[8];
        unsigned n = 1;
        bw_put(w, 1, 1);
        while (n < 8 && (v >> (8 * n)) != 0)
            n++;
        for (unsigned i = 0; i < n; i++)
            b[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
        if (enc_len_unc(w, n) != 0)
            return -1;
        bw_octets(w, b, n);
        return 0;
    }
}

/* normally small length (X.691 11.9.3.4): n >= 1 */
static int dec_small_len(br_t *r, size_t *n)
{
    uint64_t b, v;
    if (br_get(r, 1, &b) != 0)
        return -1;
    if (b == 0) {
        if (br_get(r, 6, &v) != 0)
            return -1;
        *n = (size_t)v + 1;
        return 0;
    }
    return dec_len_unc(r, n);
}

static int enc_small_len(bw_t *w, size_t n)
{
    if (n <= 64) {
        bw_put(w, 0, 1);
        bw_put(w, n - 1, 6);
        return 0;
    }
    bw_put(w, 1, 1);
    return enc_len_unc(w, n);
}

/* ---- decoding ------------------------------------------------------------------------------------------------------- */

static g5c_json *dec(ctx_t *c, br_t *r, const ngap_type *t, int depth);

static g5c_json *dec_raw_hex(ctx_t *c, const uint8_t *p, size_t n)
{
    char *hx = g5c_hex_encode(p, n);
    g5c_json *j = g5c_json_new_str(hx);
    (void)c;
    free(hx);
    return j;
}

static g5c_json *node_budget(ctx_t *c, g5c_json *j)
{
    if (++c->nodes > NGAP_MAX_NODES) {
        g5c_json_free(j);
        fail(c, "message too complex");
        return NULL;
    }
    return j;
}

/* Decode an open type: length + contents, the contents decoded as `t` in a fresh bit stream. */
static g5c_json *dec_open(ctx_t *c, br_t *r, const ngap_type *t, int depth, bool *raw_out)
{
    size_t n;
    const uint8_t *p;
    br_t sub;
    g5c_json *v;
    if (dec_len_unc(r, &n) != 0) {
        fail(c, "bad open type length");
        return NULL;
    }
    p = br_octets(r, n);
    if (p == NULL) {
        fail(c, "open type overruns the message");
        return NULL;
    }
    if (t == NULL) {
        g5c_json *o = g5c_json_new_obj();
        char *hx = g5c_hex_encode(p, n);
        g5c_json_set_str(o, "_raw", hx);
        free(hx);
        if (raw_out)
            *raw_out = true;
        return o;
    }
    sub.buf = p;
    sub.nbits = n * 8;
    sub.pos = 0;
    v = dec(c, &sub, t, depth + 1);
    return v;
}

static const ngap_ie_def *find_def(const ngap_ie_set *s, uint16_t id)
{
    for (size_t i = 0; i < s->n; i++)
        if (s->defs[i].id == id)
            return &s->defs[i];
    return NULL;
}

/* One protocol IE / extension / private IE field. */
static g5c_json *dec_ie_field(ctx_t *c, br_t *r, const ngap_type *t, int depth)
{
    uint64_t id, cr;
    g5c_json *o = g5c_json_new_obj(), *val;
    const ngap_ie_def *d = NULL;
    if (t->kind == NG_PRIVATE_CONTAINER) {
        uint64_t idx;
        if (br_get(r, 1, &idx) != 0) {
            fail(c, "truncated private IE id");
            goto bad;
        }
        if (idx == 0) {
            if (dec_constrained(r, 65535, &id) != 0) {
                fail(c, "truncated private IE id");
                goto bad;
            }
            g5c_json_set_int(g5c_json_set(o, "id", g5c_json_new_obj()), "local", (int64_t)id);
        } else {
            size_t n;
            const uint8_t *p;
            if (dec_len_unc(r, &n) != 0 || (p = br_octets(r, n)) == NULL) {
                fail(c, "bad private IE oid");
                goto bad;
            }
            g5c_json_set(g5c_json_set(o, "id", g5c_json_new_obj()), "global", dec_raw_hex(c, p, n));
            id = 0x10000;
        }
    } else {
        if (dec_constrained(r, 65535, &id) != 0) {
            fail(c, "truncated IE id");
            goto bad;
        }
        g5c_json_set_int(o, "id", (int64_t)id);
    }
    if (br_get(r, 2, &cr) != 0 || cr > 2) {
        fail(c, "bad criticality");
        goto bad;
    }
    g5c_json_set_str(o, "criticality", CRIT[cr]);
    if (t->set != NULL && id < 0x10000)
        d = find_def(t->set, (uint16_t)id);
    if (d != NULL)
        g5c_json_set_str(o, "name", d->name);
    val = dec_open(c, r, d ? d->type : NULL, depth, NULL);
    if (val == NULL)
        goto bad;
    g5c_json_set(o, "value", val);
    return o;
bad:
    g5c_json_free(o);
    return NULL;
}

static const ngap_proc *find_proc(int64_t code)
{
    for (size_t i = 0; i < NGAP_NPROCS; i++)
        if (NGAP_PROCS[i].code == code)
            return &NGAP_PROCS[i];
    return NULL;
}

static g5c_json *dec_seq(ctx_t *c, br_t *r, const ngap_type *t, int depth)
{
    uint64_t ext = 0;
    g5c_json *o = g5c_json_new_obj();
    uint8_t present[128];
    size_t nopt = 0;
    if (t->ext && br_get(r, 1, &ext) != 0)
        goto trunc;
    for (size_t i = 0; i < t->nroot; i++)
        if (t->fields[i].optional) {
            uint64_t b;
            if (nopt >= sizeof present || br_get(r, 1, &b) != 0)
                goto trunc;
            present[nopt++] = (uint8_t)b;
        }
    nopt = 0;
    for (size_t i = 0; i < t->nroot; i++) {
        const ngap_field *f = &t->fields[i];
        g5c_json *v;
        if (f->optional && !present[nopt++])
            continue;
        v = dec(c, r, f->type, depth + 1);
        if (v == NULL)
            goto bad;
        g5c_json_set(o, f->name, v);
    }
    if (ext) {
        size_t n, nadd = t->nfields - t->nroot;
        uint8_t bits[256];
        g5c_json *extra = NULL;
        if (dec_small_len(r, &n) != 0 || n > sizeof bits)
            goto trunc;
        for (size_t i = 0; i < n; i++) {
            uint64_t b;
            if (br_get(r, 1, &b) != 0)
                goto trunc;
            bits[i] = (uint8_t)b;
        }
        for (size_t i = 0; i < n; i++) {
            g5c_json *v;
            if (!bits[i])
                continue;
            if (i < nadd) {
                v = dec_open(c, r, t->fields[t->nroot + i].type, depth, NULL);
                if (v == NULL)
                    goto bad;
                g5c_json_set(o, t->fields[t->nroot + i].name, v);
            } else {
                size_t ln;
                const uint8_t *p;
                char key[24];
                if (dec_len_unc(r, &ln) != 0 || (p = br_octets(r, ln)) == NULL)
                    goto trunc;
                if (extra == NULL)
                    extra = g5c_json_set(o, "_ext", g5c_json_new_obj());
                snprintf(key, sizeof key, "%zu", i);
                g5c_json_set(extra, key, dec_raw_hex(c, p, ln));
            }
        }
    }
    return node_budget(c, o);
trunc:
    fail(c, "truncated %s", t->name[0] ? t->name : "SEQUENCE");
bad:
    g5c_json_free(o);
    return NULL;
}

static g5c_json *dec_choice(ctx_t *c, br_t *r, const ngap_type *t, int depth)
{
    uint64_t ext = 0, idx;
    g5c_json *o = g5c_json_new_obj(), *v;
    if (t->ext && br_get(r, 1, &ext) != 0)
        goto trunc;
    if (!ext) {
        if (dec_constrained(r, t->nroot ? t->nroot - 1 : 0, &idx) != 0)
            goto trunc;
        if (idx >= t->nroot) {
            fail(c, "CHOICE index out of range");
            goto bad;
        }
        v = dec(c, r, t->fields[idx].type, depth + 1);
        if (v == NULL)
            goto bad;
        g5c_json_set(o, t->fields[idx].name, v);
    } else {
        size_t n;
        const uint8_t *p;
        if (dec_small(r, &idx) != 0 || dec_len_unc(r, &n) != 0 || (p = br_octets(r, n)) == NULL)
            goto trunc;
        idx += t->nroot;
        if (idx < t->nfields) {
            br_t sub = {p, n * 8, 0};
            v = dec(c, &sub, t->fields[idx].type, depth + 1);
            if (v == NULL)
                goto bad;
            g5c_json_set(o, t->fields[idx].name, v);
        } else {
            g5c_json_set_int(o, "_ext_choice", (int64_t)idx);
            g5c_json_set(o, "raw", dec_raw_hex(c, p, n));
        }
    }
    return node_budget(c, o);
trunc:
    fail(c, "truncated CHOICE");
bad:
    g5c_json_free(o);
    return NULL;
}

static g5c_json *dec_int(ctx_t *c, br_t *r, const ngap_type *t)
{
    uint64_t ext = 0, off;
    if (t->ext && br_get(r, 1, &ext) != 0)
        goto trunc;
    if (!ext && t->has_lb && t->has_ub) {
        if (dec_constrained(r, t->span, &off) != 0)
            goto trunc;
        if (off > t->span) {
            fail(c, "INTEGER value out of range");
            return NULL;
        }
        if (t->lb >= 0 && (uint64_t)t->lb + off > (uint64_t)INT64_MAX) {
            fail(c, "INTEGER does not fit 63 bits");
            return NULL;
        }
        return node_budget(c, g5c_json_new_int((int64_t)((uint64_t)t->lb + off)));
    }
    {   /* semi-constrained (lb only) or unconstrained / extension: length + octets */
        size_t n;
        const uint8_t *p;
        if (dec_len_unc(r, &n) != 0 || n == 0 || n > 8 || (p = br_octets(r, n)) == NULL) {
            fail(c, "bad INTEGER encoding");
            return NULL;
        }
        if (!ext && t->has_lb) {
            uint64_t v = 0;
            for (size_t i = 0; i < n; i++)
                v = (v << 8) | p[i];
            if (v > (uint64_t)INT64_MAX - (t->lb > 0 ? (uint64_t)t->lb : 0)) {
                fail(c, "INTEGER does not fit 63 bits");
                return NULL;
            }
            return node_budget(c, g5c_json_new_int(t->lb + (int64_t)v));
        }
        {   /* two's complement */
            int64_t v = (p[0] & 0x80U) ? -1 : 0;
            for (size_t i = 0; i < n; i++)
                v = (int64_t)(((uint64_t)v << 8) | p[i]);
            return node_budget(c, g5c_json_new_int(v));
        }
    }
trunc:
    fail(c, "truncated INTEGER");
    return NULL;
}

static g5c_json *dec_enum(ctx_t *c, br_t *r, const ngap_type *t)
{
    uint64_t ext = 0, idx;
    if (t->ext && br_get(r, 1, &ext) != 0)
        goto trunc;
    if (!ext) {
        if (dec_constrained(r, t->nroot ? t->nroot - 1 : 0, &idx) != 0)
            goto trunc;
    } else {
        if (dec_small(r, &idx) != 0)
            goto trunc;
        idx += t->nroot;
    }
    if (idx < t->nnames)
        return node_budget(c, g5c_json_new_str(t->names[idx]));
    if (!ext) {
        fail(c, "ENUMERATED index out of range");
        return NULL;
    }
    return node_budget(c, g5c_json_new_int((int64_t)idx));
trunc:
    fail(c, "truncated ENUMERATED");
    return NULL;
}

/* size determination shared by OCTET STRING / BIT STRING / character strings: returns false on error. `unit_bits` is
 * the width of one element (8 for octets/chars, 1 for bits). */
static bool dec_size(ctx_t *c, br_t *r, const ngap_type *t, unsigned unit_bits, size_t *n, bool *aligned, bool *has_len)
{
    uint64_t ext = 0;
    *has_len = false;
    if (t->ext && br_get(r, 1, &ext) != 0) {
        fail(c, "truncated size");
        return false;
    }
    if (!ext && t->has_lb && t->has_ub && t->lb == t->ub) {
        uint64_t bits = (uint64_t)t->lb * unit_bits;
        *n = (size_t)t->lb;
        *aligned = bits > 16;
        if (bits >= 65536) { /* too long for a fixed-size field: a length determinant is used */
            *has_len = true;
            if (dec_len_unc(r, n) != 0) {
                fail(c, "bad length");
                return false;
            }
        }
        return true;
    }
    *has_len = true;
    *aligned = true;
    if (ext) {
        if (dec_len_unc(r, n) != 0) {
            fail(c, "bad length");
            return false;
        }
    } else if (dec_len(r, t->has_lb ? t->lb : 0, t->has_ub, t->ub, n) != 0) {
        fail(c, "bad length");
        return false;
    }
    return true;
}

static bool printable_ok(uint8_t ch)
{
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == ' ' || ch == '\'' ||
           ch == '(' || ch == ')' || ch == '+' || ch == ',' || ch == '-' || ch == '.' || ch == '/' || ch == ':' ||
           ch == '=' || ch == '?';
}

static g5c_json *dec(ctx_t *c, br_t *r, const ngap_type *t, int depth)
{
    t = resolve(t);
    if (depth > NGAP_MAX_DEPTH) {
        fail(c, "nesting too deep");
        return NULL;
    }
    switch (t->kind) {
    case NG_BOOL: {
        uint64_t b;
        if (br_get(r, 1, &b) != 0) {
            fail(c, "truncated BOOLEAN");
            return NULL;
        }
        return node_budget(c, g5c_json_new_bool(b != 0));
    }
    case NG_NULL:
        return node_budget(c, g5c_json_new_null());
    case NG_INT:
        return dec_int(c, r, t);
    case NG_ENUM:
        return dec_enum(c, r, t);
    case NG_SEQ:
        return dec_seq(c, r, t, depth);
    case NG_CHOICE:
        return dec_choice(c, r, t, depth);
    case NG_OCTETS: {
        size_t n;
        bool aligned, hl;
        const uint8_t *p;
        uint8_t small[2];
        if (!dec_size(c, r, t, 8, &n, &aligned, &hl))
            return NULL;
        if (n == 0)
            return node_budget(c, g5c_json_new_str(""));
        if (!aligned) { /* fixed size of at most two octets: a bit-field, not aligned */
            for (size_t i = 0; i < n; i++) {
                uint64_t b;
                if (br_get(r, 8, &b) != 0) {
                    fail(c, "truncated OCTET STRING");
                    return NULL;
                }
                small[i] = (uint8_t)b;
            }
            return node_budget(c, dec_raw_hex(c, small, n));
        }
        p = br_octets(r, n);
        if (p == NULL) {
            fail(c, "truncated OCTET STRING");
            return NULL;
        }
        return node_budget(c, dec_raw_hex(c, p, n));
    }
    case NG_BITS: {
        size_t n, nbytes;
        bool aligned, hl;
        g5c_json *o;
        uint8_t *buf;
        if (!dec_size(c, r, t, 1, &n, &aligned, &hl))
            return NULL;
        nbytes = (n + 7) / 8;
        buf = g5c_xcalloc(nbytes ? nbytes : 1, 1);
        if (n > 0) {
            if (aligned && br_align(r) != 0) {
                free(buf);
                fail(c, "truncated BIT STRING");
                return NULL;
            }
            for (size_t i = 0; i < n; i++) {
                uint64_t b;
                if (br_get(r, 1, &b) != 0) {
                    free(buf);
                    fail(c, "truncated BIT STRING");
                    return NULL;
                }
                if (b)
                    buf[i >> 3] = (uint8_t)(buf[i >> 3] | (0x80U >> (i & 7)));
            }
        }
        o = g5c_json_new_obj();
        g5c_json_set_int(o, "len", (int64_t)n);
        g5c_json_set(o, "hex", dec_raw_hex(c, buf, nbytes));
        free(buf);
        return node_budget(c, o);
    }
    case NG_STR: {
        size_t n;
        bool aligned, hl;
        const uint8_t *p;
        uint8_t tmp[2];
        g5c_json *j;
        if (t->strkind == 2) { /* UTF8String: not a known-multiplier type, length is in octets */
            uint64_t ext = 0;
            if (t->ext && br_get(r, 1, &ext) != 0) {
                fail(c, "truncated string");
                return NULL;
            }
            if (dec_len_unc(r, &n) != 0 || (p = br_octets(r, n)) == NULL) {
                fail(c, "truncated string");
                return NULL;
            }
        } else {
            if (!dec_size(c, r, t, 8, &n, &aligned, &hl))
                return NULL;
            if (n == 0)
                return node_budget(c, g5c_json_new_str(""));
            if (aligned) {
                p = br_octets(r, n);
            } else { /* at most two characters, unaligned */
                for (size_t i = 0; i < n; i++) {
                    uint64_t b;
                    if (br_get(r, 8, &b) != 0) {
                        fail(c, "truncated string");
                        return NULL;
                    }
                    tmp[i] = (uint8_t)b;
                }
                p = tmp;
            }
            if (p == NULL) {
                fail(c, "truncated string");
                return NULL;
            }
        }
        for (size_t i = 0; i < n; i++) {
            uint8_t ch = p[i];
            bool ok = t->strkind == 0 ? printable_ok(ch) : t->strkind == 1 ? (ch >= 0x20 && ch <= 0x7e) : t->strkind == 3 ? ch < 0x80 : ch != 0;
            if (!ok) {
                fail(c, "illegal character in string");
                return NULL;
            }
        }
        j = g5c_json_new_strn((const char *)p, n);
        if (g5c_json_str(j) == NULL || strlen(g5c_json_str(j)) != n) {
            g5c_json_free(j);
            fail(c, "illegal NUL in string");
            return NULL;
        }
        return node_budget(c, j);
    }
    case NG_OID: {
        size_t n;
        const uint8_t *p;
        if (dec_len_unc(r, &n) != 0 || (p = br_octets(r, n)) == NULL) {
            fail(c, "truncated OBJECT IDENTIFIER");
            return NULL;
        }
        return node_budget(c, dec_raw_hex(c, p, n));
    }
    case NG_SEQOF: {
        uint64_t ext = 0;
        size_t n;
        g5c_json *arr;
        if (t->ext && br_get(r, 1, &ext) != 0)
            goto trunc;
        if (!ext && t->has_lb && t->has_ub && t->lb == t->ub)
            n = (size_t)t->lb;
        else if (ext) {
            if (dec_len_unc(r, &n) != 0)
                goto trunc;
        } else if (dec_len(r, t->has_lb ? t->lb : 0, t->has_ub, t->ub, &n) != 0)
            goto trunc;
        arr = g5c_json_new_arr();
        for (size_t i = 0; i < n; i++) {
            g5c_json *v = dec(c, r, t->elem, depth + 1);
            if (v == NULL) {
                g5c_json_free(arr);
                return NULL;
            }
            g5c_json_push(arr, v);
        }
        return node_budget(c, arr);
    trunc:
        fail(c, "truncated SEQUENCE OF");
        return NULL;
    }
    case NG_IE_CONTAINER:
    case NG_EXT_CONTAINER:
    case NG_PRIVATE_CONTAINER:
    case NG_IE_LIST: {
        size_t n;
        g5c_json *arr;
        int64_t lb = t->kind == NG_IE_CONTAINER ? 0 : 1, ub = 65535;
        if (t->kind == NG_IE_LIST) {
            lb = t->lb;
            ub = t->ub;
        }
        if (dec_len(r, lb, 1, ub, &n) != 0) {
            fail(c, "truncated IE container");
            return NULL;
        }
        arr = g5c_json_new_arr();
        for (size_t i = 0; i < n; i++) {
            g5c_json *e;
            if (t->kind == NG_IE_LIST) {
                /* each element is a single container: id, criticality and the open type value */
                ngap_type single = *t;
                single.kind = NG_IE_SINGLE;
                e = dec_ie_field(c, r, &single, depth);
            } else {
                e = dec_ie_field(c, r, t, depth);
            }
            if (e == NULL) {
                g5c_json_free(arr);
                return NULL;
            }
            g5c_json_push(arr, e);
        }
        return node_budget(c, arr);
    }
    case NG_IE_SINGLE:
        return dec_ie_field(c, r, t, depth);
    case NG_PROCMSG: {
        uint64_t code, cr;
        g5c_json *o, *v;
        const ngap_proc *pr;
        const ngap_type *mt = NULL;
        if (br_align(r) != 0 || br_get(r, 8, &code) != 0 || br_get(r, 2, &cr) != 0 || cr > 2) {
            fail(c, "truncated PDU header");
            return NULL;
        }
        pr = find_proc((int64_t)code);
        if (pr != NULL)
            mt = t->strkind == 0 ? pr->init : t->strkind == 1 ? pr->succ : pr->unsucc;
        o = g5c_json_new_obj();
        g5c_json_set_int(o, "procedureCode", (int64_t)code);
        g5c_json_set_str(o, "criticality", CRIT[cr]);
        v = dec_open(c, r, mt, depth, NULL);
        if (v == NULL) {
            g5c_json_free(o);
            return NULL;
        }
        g5c_json_set(o, "value", v);
        return node_budget(c, o);
    }
    default:
        fail(c, "unsupported ASN.1 construct (%s)", t->name);
        return NULL;
    }
}

/* ---- encoding -------------------------------------------------------------------------------------------------------- */

static int enc(ctx_t *c, bw_t *w, const ngap_type *t, const g5c_json *v, int depth);

static int jfail(ctx_t *c, const char *what, const ngap_type *t)
{
    fail(c, "cannot encode %s as %s", what, t->name[0] ? t->name : "value");
    return -1;
}

/* open type: encode `v` as t into a scratch stream and emit length + octets */
static int enc_open(ctx_t *c, bw_t *w, const ngap_type *t, const g5c_json *v, int depth)
{
    bw_t sub;
    int rc;
    const char *raw;
    memset(&sub, 0, sizeof sub);
    raw = g5c_json_get_str(v, "_raw");
    if (raw != NULL) {
        size_t n = strlen(raw) / 2;
        uint8_t *b = g5c_xmalloc(n + 1);
        if (g5c_hex_decode(raw, b, n) != (long)n) {
            free(b);
            fail(c, "bad _raw hex");
            return -1;
        }
        rc = enc_len_unc(w, n);
        if (rc != 0)
            fail(c, "open type too large");
        else
            bw_octets(w, b, n);
        free(b);
        return rc;
    }
    if (t == NULL) {
        fail(c, "no schema for this value (give \"_raw\")");
        return -1;
    }
    rc = enc(c, &sub, t, v, depth + 1);
    if (rc != 0) {
        bw_free(&sub);
        return -1;
    }
    bw_align(&sub);
    if (sub.nbits == 0) { /* an empty encoding is sent as a single zero octet (X.691 10.2.1) */
        bw_put(&sub, 0, 8);
    }
    if (sub.oom || enc_len_unc(w, sub.nbits / 8) != 0) {
        bw_free(&sub);
        fail(c, "open type too large");
        return -1;
    }
    bw_octets(w, sub.buf, sub.nbits / 8);
    bw_free(&sub);
    return 0;
}

static int crit_index(const g5c_json *j)
{
    const char *s = g5c_json_str(j);
    int64_t n;
    if (s != NULL) {
        for (int i = 0; i < 3; i++)
            if (strcmp(s, CRIT[i]) == 0)
                return i;
        return -1;
    }
    if (g5c_json_int(j, &n) && n >= 0 && n <= 2)
        return (int)n;
    return -1;
}

static int enc_ie_field(ctx_t *c, bw_t *w, const ngap_type *t, const g5c_json *e, int depth)
{
    const g5c_json *id = g5c_json_get(e, "id"), *val = g5c_json_get(e, "value");
    int cr = crit_index(g5c_json_get(e, "criticality"));
    int64_t idn = 0;
    const ngap_ie_def *d = NULL;
    if (!g5c_json_is(e, G5C_J_OBJECT) || id == NULL || val == NULL || cr < 0)
        return jfail(c, "IE entry (id, criticality, value required)", t);
    if (t->kind == NG_PRIVATE_CONTAINER) {
        int64_t loc;
        if (g5c_json_get_int(id, "local", &loc) && loc >= 0 && loc <= 65535) {
            bw_put(w, 0, 1);
            enc_constrained(w, 65535, (uint64_t)loc);
        } else if (g5c_json_get_str(id, "global") != NULL) {
            const char *h = g5c_json_get_str(id, "global");
            size_t n = strlen(h) / 2;
            uint8_t *b = g5c_xmalloc(n + 1);
            if (g5c_hex_decode(h, b, n) != (long)n || enc_len_unc((bw_put(w, 1, 1), w), n) != 0) {
                free(b);
                fail(c, "bad private IE id");
                return -1;
            }
            bw_octets(w, b, n);
            free(b);
        } else {
            return jfail(c, "private IE id", t);
        }
    } else {
        if (!g5c_json_int(id, &idn) || idn < 0 || idn > 65535)
            return jfail(c, "IE id", t);
        enc_constrained(w, 65535, (uint64_t)idn);
        if (t->set != NULL)
            d = find_def(t->set, (uint16_t)idn);
    }
    bw_put(w, (uint64_t)cr, 2);
    return enc_open(c, w, d ? d->type : NULL, val, depth);
}

static const ngap_field *find_field(const ngap_type *t, const char *name, size_t *idx)
{
    for (size_t i = 0; i < t->nfields; i++)
        if (strcmp(t->fields[i].name, name) == 0) {
            *idx = i;
            return &t->fields[i];
        }
    return NULL;
}

static int enc_seq(ctx_t *c, bw_t *w, const ngap_type *t, const g5c_json *v, int depth)
{
    bool ext = false;
    const g5c_json *extra = g5c_json_get(v, "_ext");
    size_t nadd = t->nfields - t->nroot, last_add = 0;
    bool add_present[256] = {false};
    if (!g5c_json_is(v, G5C_J_OBJECT))
        return jfail(c, "non-object", t);
    for (size_t i = 0; i < g5c_json_len(v); i++) {
        const char *k = g5c_json_key_at(v, i);
        size_t idx;
        if (strcmp(k, "_ext") == 0)
            continue;
        if (find_field(t, k, &idx) == NULL) {
            fail(c, "%s: unknown field \"%s\"", t->name[0] ? t->name : "SEQUENCE", k);
            return -1;
        }
    }
    if (nadd > 256)
        return jfail(c, "too many extension additions", t);
    for (size_t i = 0; i < nadd; i++)
        if (g5c_json_get(v, t->fields[t->nroot + i].name) != NULL) {
            add_present[i] = true;
            ext = true;
            last_add = i + 1;
        }
    for (size_t i = 0; i < g5c_json_len(extra); i++) {
        char *end;
        unsigned long idx = strtoul(g5c_json_key_at(extra, i), &end, 10);
        if (*end != 0 || idx >= 256)
            return jfail(c, "bad _ext key", t);
        ext = true;
        if (idx + 1 > last_add)
            last_add = idx + 1;
    }
    if (t->ext)
        bw_put(w, ext ? 1 : 0, 1);
    else if (ext)
        return jfail(c, "extension additions on a non-extensible type", t);
    for (size_t i = 0; i < t->nroot; i++)
        if (t->fields[i].optional)
            bw_put(w, g5c_json_get(v, t->fields[i].name) != NULL ? 1 : 0, 1);
    for (size_t i = 0; i < t->nroot; i++) {
        const ngap_field *f = &t->fields[i];
        const g5c_json *fv = g5c_json_get(v, f->name);
        if (fv == NULL) {
            if (!f->optional) {
                fail(c, "%s: mandatory field \"%s\" missing", t->name[0] ? t->name : "SEQUENCE", f->name);
                return -1;
            }
            continue;
        }
        if (enc(c, w, f->type, fv, depth + 1) != 0)
            return -1;
    }
    if (ext) {
        if (enc_small_len(w, last_add) != 0)
            return -1;
        for (size_t i = 0; i < last_add; i++) {
            char key[24];
            snprintf(key, sizeof key, "%zu", i);
            bw_put(w, (add_present[i] || g5c_json_get(extra, key) != NULL) ? 1 : 0, 1);
        }
        for (size_t i = 0; i < last_add; i++) {
            char key[24];
            const g5c_json *fv;
            snprintf(key, sizeof key, "%zu", i);
            if (i < nadd && add_present[i]) {
                if (enc_open(c, w, t->fields[t->nroot + i].type, g5c_json_get(v, t->fields[t->nroot + i].name), depth) != 0)
                    return -1;
            } else if ((fv = g5c_json_get(extra, key)) != NULL) {
                const char *h = g5c_json_str(fv);
                size_t n = h ? strlen(h) / 2 : 0;
                uint8_t *b = g5c_xmalloc(n + 1);
                if (h == NULL || g5c_hex_decode(h, b, n) != (long)n || enc_len_unc(w, n) != 0) {
                    free(b);
                    return jfail(c, "bad _ext entry", t);
                }
                bw_octets(w, b, n);
                free(b);
            }
        }
    }
    return 0;
}

static int enc_choice(ctx_t *c, bw_t *w, const ngap_type *t, const g5c_json *v, int depth)
{
    size_t idx = 0;
    const ngap_field *f = NULL;
    const char *key;
    if (!g5c_json_is(v, G5C_J_OBJECT) || g5c_json_len(v) != 1)
        return jfail(c, "CHOICE value (needs exactly one key)", t);
    key = g5c_json_key_at(v, 0);
    if (strcmp(key, "_ext_choice") == 0 || strcmp(key, "raw") == 0)
        return jfail(c, "raw extension alternative (give _ext_choice together with raw)", t);
    f = find_field(t, key, &idx);
    if (f == NULL) {
        fail(c, "CHOICE has no alternative \"%s\"", key);
        return -1;
    }
    if (t->ext)
        bw_put(w, idx >= t->nroot ? 1 : 0, 1);
    if (idx < t->nroot) {
        enc_constrained(w, t->nroot ? t->nroot - 1 : 0, idx);
        return enc(c, w, f->type, g5c_json_val_at(v, 0), depth + 1);
    }
    if (enc_small(w, idx - t->nroot) != 0)
        return -1;
    return enc_open(c, w, f->type, g5c_json_val_at(v, 0), depth);
}

static int enc_int(ctx_t *c, bw_t *w, const ngap_type *t, const g5c_json *v)
{
    int64_t x;
    bool inroot;
    if (!g5c_json_int(v, &x))
        return jfail(c, "non-integer", t);
    inroot = true;
    if (t->has_lb && x < t->lb)
        inroot = false;
    if (t->has_lb && t->has_ub && (uint64_t)x - (uint64_t)t->lb > t->span)
        inroot = false;
    if (t->ext)
        bw_put(w, inroot ? 0 : 1, 1);
    if (!inroot && !t->ext) {
        fail(c, "INTEGER %lld out of range", (long long)x);
        return -1;
    }
    if (inroot && t->has_lb && t->has_ub) {
        enc_constrained(w, t->span, (uint64_t)x - (uint64_t)t->lb);
        return 0;
    }
    {
        uint8_t b[9] = {0};
        unsigned n;
        if (inroot && t->has_lb) { /* semi-constrained: offset from the lower bound as unsigned octets */
            uint64_t off = (uint64_t)x - (uint64_t)t->lb;
            n = 1;
            while (n < 8 && (off >> (8 * n)) != 0)
                n++;
            for (unsigned i = 0; i < n; i++)
                b[i] = (uint8_t)(off >> (8 * (n - 1 - i)));
        } else { /* unconstrained / extension: minimal two's complement */
            n = 8;
            for (unsigned i = 0; i < 8; i++)
                b[i] = (uint8_t)((uint64_t)x >> (8 * (7 - i)));
            while (n > 1 && ((b[8 - n] == 0x00 && (b[9 - n] & 0x80U) == 0) || (b[8 - n] == 0xff && (b[9 - n] & 0x80U) != 0)))
                n--;
            memmove(b, b + (8 - n), n);
        }
        if (enc_len_unc(w, n) != 0)
            return -1;
        bw_octets(w, b, n);
    }
    return 0;
}

static int enc_enum(ctx_t *c, bw_t *w, const ngap_type *t, const g5c_json *v)
{
    int64_t idx = -1;
    const char *s = g5c_json_str(v);
    if (s != NULL) {
        for (size_t i = 0; i < t->nnames; i++)
            if (strcmp(t->names[i], s) == 0)
                idx = (int64_t)i;
        if (idx < 0) {
            fail(c, "unknown enumeration value \"%s\"", s);
            return -1;
        }
    } else if (!g5c_json_int(v, &idx) || idx < 0) {
        return jfail(c, "enumeration", t);
    }
    if (t->ext)
        bw_put(w, (uint64_t)idx >= t->nroot ? 1 : 0, 1);
    if ((uint64_t)idx < t->nroot) {
        enc_constrained(w, t->nroot ? t->nroot - 1 : 0, (uint64_t)idx);
        return 0;
    }
    if (!t->ext) {
        fail(c, "enumeration index out of range");
        return -1;
    }
    return enc_small(w, (uint64_t)idx - t->nroot);
}

/* size handling for strings: returns the ext bit / fixed / length-prefixed layout decision */
static int enc_size(ctx_t *c, bw_t *w, const ngap_type *t, size_t n, unsigned unit_bits, bool *aligned)
{
    bool inroot = true;
    if (t->has_lb && (int64_t)n < t->lb)
        inroot = false;
    if (t->has_ub && (int64_t)n > t->ub)
        inroot = false;
    if (t->ext)
        bw_put(w, inroot ? 0 : 1, 1);
    else if (!inroot) {
        fail(c, "size %zu violates the constraint of %s", n, t->name[0] ? t->name : "value");
        return -1;
    }
    if (inroot && t->has_lb && t->has_ub && t->lb == t->ub) {
        uint64_t bits = (uint64_t)t->lb * unit_bits;
        *aligned = bits > 16;
        if (bits >= 65536 && enc_len_unc(w, n) != 0)
            return -1;
        return 0;
    }
    *aligned = true;
    if (!inroot)
        return enc_len_unc(w, n);
    return enc_len(w, t->has_lb ? t->lb : 0, t->has_ub, t->ub, n);
}

static int enc(ctx_t *c, bw_t *w, const ngap_type *t, const g5c_json *v, int depth)
{
    t = resolve(t);
    if (depth > NGAP_MAX_DEPTH) {
        fail(c, "nesting too deep");
        return -1;
    }
    switch (t->kind) {
    case NG_BOOL: {
        bool b;
        if (!g5c_json_bool(v, &b))
            return jfail(c, "non-boolean", t);
        bw_put(w, b ? 1 : 0, 1);
        return 0;
    }
    case NG_NULL:
        return 0;
    case NG_INT:
        return enc_int(c, w, t, v);
    case NG_ENUM:
        return enc_enum(c, w, t, v);
    case NG_SEQ:
        return enc_seq(c, w, t, v, depth);
    case NG_CHOICE:
        return enc_choice(c, w, t, v, depth);
    case NG_OCTETS:
    case NG_OID: {
        const char *h = g5c_json_str(v);
        size_t n = h ? strlen(h) / 2 : 0;
        uint8_t *b;
        bool aligned = true;
        int rc = 0;
        if (h == NULL || strlen(h) % 2 != 0)
            return jfail(c, "non-hex string", t);
        b = g5c_xmalloc(n + 1);
        if (g5c_hex_decode(h, b, n) != (long)n) {
            free(b);
            return jfail(c, "non-hex string", t);
        }
        if (t->kind == NG_OID)
            rc = enc_len_unc(w, n);
        else
            rc = enc_size(c, w, t, n, 8, &aligned);
        if (rc == 0 && n > 0) {
            if (aligned) {
                bw_octets(w, b, n);
            } else {
                for (size_t i = 0; i < n; i++)
                    bw_put(w, b[i], 8);
            }
        }
        free(b);
        return rc;
    }
    case NG_BITS: {
        int64_t n;
        const char *h = g5c_json_get_str(v, "hex");
        size_t nb;
        uint8_t *b;
        bool aligned = true;
        if (!g5c_json_get_int(v, "len", &n) || n < 0 || h == NULL)
            return jfail(c, "BIT STRING (needs len and hex)", t);
        nb = ((size_t)n + 7) / 8;
        if (strlen(h) != 2 * nb)
            return jfail(c, "BIT STRING hex of the wrong length", t);
        b = g5c_xmalloc(nb + 1);
        if (g5c_hex_decode(h, b, nb) != (long)nb) {
            free(b);
            return jfail(c, "BIT STRING hex", t);
        }
        if (enc_size(c, w, t, (size_t)n, 1, &aligned) != 0) {
            free(b);
            return -1;
        }
        if (n > 0) {
            if (aligned)
                bw_align(w);
            for (size_t i = 0; i < (size_t)n; i++)
                bw_put(w, ((unsigned)b[i >> 3] >> (7 - (i & 7))) & 1U, 1);
        }
        free(b);
        return 0;
    }
    case NG_STR: {
        const char *s = g5c_json_str(v);
        size_t n = s ? strlen(s) : 0;
        bool aligned = true;
        if (s == NULL)
            return jfail(c, "non-string", t);
        for (size_t i = 0; i < n; i++) {
            uint8_t ch = (uint8_t)s[i];
            bool ok = t->strkind == 0 ? printable_ok(ch) : t->strkind == 1 ? (ch >= 0x20 && ch <= 0x7e) : t->strkind == 3 ? ch < 0x80 : true;
            if (!ok) {
                fail(c, "illegal character in string");
                return -1;
            }
        }
        if (t->strkind == 2) {
            if (t->ext)
                bw_put(w, 0, 1);
            if (enc_len_unc(w, n) != 0)
                return -1;
            bw_octets(w, (const uint8_t *)s, n);
            return 0;
        }
        if (enc_size(c, w, t, n, 8, &aligned) != 0)
            return -1;
        if (n > 0) {
            if (aligned) {
                bw_octets(w, (const uint8_t *)s, n);
            } else {
                for (size_t i = 0; i < n; i++)
                    bw_put(w, (uint8_t)s[i], 8);
            }
        }
        return 0;
    }
    case NG_SEQOF: {
        size_t n = g5c_json_len(v);
        bool inroot = true;
        if (!g5c_json_is(v, G5C_J_ARRAY))
            return jfail(c, "non-array", t);
        if (t->has_lb && (int64_t)n < t->lb)
            inroot = false;
        if (t->has_ub && (int64_t)n > t->ub)
            inroot = false;
        if (t->ext)
            bw_put(w, inroot ? 0 : 1, 1);
        else if (!inroot) {
            fail(c, "SEQUENCE OF size %zu violates its constraint", n);
            return -1;
        }
        if (inroot && t->has_lb && t->has_ub && t->lb == t->ub) {
            /* fixed size: no length */
        } else if (!inroot) {
            if (enc_len_unc(w, n) != 0)
                return -1;
        } else if (enc_len(w, t->has_lb ? t->lb : 0, t->has_ub, t->ub, n) != 0) {
            return -1;
        }
        for (size_t i = 0; i < n; i++)
            if (enc(c, w, t->elem, g5c_json_at(v, i), depth + 1) != 0)
                return -1;
        return 0;
    }
    case NG_IE_CONTAINER:
    case NG_EXT_CONTAINER:
    case NG_PRIVATE_CONTAINER:
    case NG_IE_LIST: {
        size_t n = g5c_json_len(v);
        int64_t lb = t->kind == NG_IE_CONTAINER ? 0 : 1, ub = 65535;
        if (!g5c_json_is(v, G5C_J_ARRAY))
            return jfail(c, "non-array", t);
        if (t->kind == NG_IE_LIST) {
            lb = t->lb;
            ub = t->ub;
        }
        if (n > MAX_IES_COUNT || enc_len(w, lb, 1, ub, n) != 0) {
            fail(c, "IE count %zu violates the container constraint", n);
            return -1;
        }
        for (size_t i = 0; i < n; i++) {
            ngap_type single = *t;
            if (t->kind == NG_IE_LIST)
                single.kind = NG_IE_SINGLE;
            if (enc_ie_field(c, w, t->kind == NG_IE_LIST ? &single : t, g5c_json_at(v, i), depth) != 0)
                return -1;
        }
        return 0;
    }
    case NG_IE_SINGLE:
        return enc_ie_field(c, w, t, v, depth);
    case NG_PROCMSG: {
        int64_t code;
        int cr = crit_index(g5c_json_get(v, "criticality"));
        const ngap_proc *pr;
        const ngap_type *mt = NULL;
        const g5c_json *val = g5c_json_get(v, "value");
        if (!g5c_json_get_int(v, "procedureCode", &code) || code < 0 || code > 255 || cr < 0 || val == NULL)
            return jfail(c, "PDU (procedureCode, criticality, value required)", t);
        pr = find_proc(code);
        if (pr != NULL)
            mt = t->strkind == 0 ? pr->init : t->strkind == 1 ? pr->succ : pr->unsucc;
        bw_align(w);
        bw_put(w, (uint64_t)code, 8);
        bw_put(w, (uint64_t)cr, 2);
        return enc_open(c, w, mt, val, depth);
    }
    default:
        fail(c, "unsupported ASN.1 construct (%s)", t->name);
        return -1;
    }
}

/* ---- public API ------------------------------------------------------------------------------------------------------ */

static g5c_json *decode_type(const ngap_type *t, const uint8_t *buf, size_t len, char *err, size_t errcap)
{
    ctx_t c = {err, errcap, false, 0};
    br_t r = {buf, len * 8, 0};
    g5c_json *j;
    if (err != NULL && errcap > 0)
        err[0] = 0;
    if (len == 0) {
        fail(&c, "empty message");
        return NULL;
    }
    j = dec(&c, &r, t, 0);
    if (j == NULL && !c.failed)
        fail(&c, "decode failed");
    return j;
}

static int encode_type(const ngap_type *t, const g5c_json *v, g5c_bytes *out, char *err, size_t errcap)
{
    ctx_t c = {err, errcap, false, 0};
    bw_t w;
    int rc;
    memset(&w, 0, sizeof w);
    if (err != NULL && errcap > 0)
        err[0] = 0;
    rc = enc(&c, &w, t, v, 0);
    if (rc == 0 && w.oom) {
        fail(&c, "out of memory");
        rc = -1;
    }
    if (rc == 0) {
        bw_align(&w);
        if (w.nbits == 0)
            bw_put(&w, 0, 8); /* the complete encoding of an empty value is one zero octet */
        if (g5c_bytes_append(out, w.buf, w.nbits / 8) != 0) {
            fail(&c, "out of memory");
            rc = -1;
        }
    }
    bw_free(&w);
    return rc == 0 ? 0 : -1;
}

g5c_json *ngap_decode(const uint8_t *buf, size_t len, char *err, size_t errcap)
{
    return decode_type(NGAP_PDU_TYPE, buf, len, err, errcap);
}

int ngap_encode(const g5c_json *pdu, g5c_bytes *out, char *err, size_t errcap)
{
    return encode_type(NGAP_PDU_TYPE, pdu, out, err, errcap);
}

static const ngap_type *named(const char *name)
{
    for (size_t i = 0; i < NGAP_NNAMED; i++)
        if (strcmp(NGAP_NAMED[i].name, name) == 0)
            return NGAP_NAMED[i].type;
    return NULL;
}

g5c_json *ngap_decode_as(const char *type_name, const uint8_t *buf, size_t len, char *err, size_t errcap)
{
    const ngap_type *t = named(type_name);
    if (t == NULL) {
        if (err && errcap)
            snprintf(err, errcap, "unknown ASN.1 type %s", type_name);
        return NULL;
    }
    return decode_type(t, buf, len, err, errcap);
}

int ngap_encode_as(const char *type_name, const g5c_json *v, g5c_bytes *out, char *err, size_t errcap)
{
    const ngap_type *t = named(type_name);
    if (t == NULL) {
        if (err && errcap)
            snprintf(err, errcap, "unknown ASN.1 type %s", type_name);
        return -1;
    }
    return encode_type(t, v, out, err, errcap);
}

const char *ngap_pdu_kind(const g5c_json *pdu)
{
    if (g5c_json_len(pdu) != 1)
        return NULL;
    return g5c_json_key_at(pdu, 0);
}

const g5c_json *ngap_pdu_message(const g5c_json *pdu)
{
    return g5c_json_get(g5c_json_val_at(pdu, 0), "value");
}

bool ngap_procedure_code(const g5c_json *pdu, int64_t *out)
{
    return g5c_json_get_int(g5c_json_val_at(pdu, 0), "procedureCode", out);
}

const char *ngap_procedure_name(const g5c_json *pdu)
{
    int64_t code;
    if (!ngap_procedure_code(pdu, &code))
        return NULL;
    for (size_t i = 0; i < NGAP_NPROCS; i++)
        if (NGAP_PROCS[i].code == code)
            return NGAP_PROCS[i].name;
    return NULL;
}

const g5c_json *ngap_find_ie(const g5c_json *message, int64_t id)
{
    const g5c_json *ies = g5c_json_get(message, "protocolIEs");
    for (size_t i = 0; i < g5c_json_len(ies); i++) {
        int64_t x;
        const g5c_json *e = g5c_json_at(ies, i);
        if (g5c_json_get_int(e, "id", &x) && x == id)
            return g5c_json_get(e, "value");
    }
    return NULL;
}
