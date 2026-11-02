/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* YAML subset for configuration files, producing the same DOM as JSON (see json.h for the supported subset). */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/json.h"

#define MAX_LINES 20000
#define MAX_DEPTH 32

typedef struct {
    char *text; /* content without indentation or trailing comment/whitespace */
    int indent;
    int lineno;
} line_t;

typedef struct {
    line_t *l;
    size_t n, pos;
    char *err;
    size_t errcap;
    bool failed;
} y_t;

static void yfail(y_t *y, int lineno, const char *msg)
{
    if (!y->failed && y->err != NULL && y->errcap > 0)
        snprintf(y->err, y->errcap, "yaml line %d: %s", lineno, msg);
    y->failed = true;
}

/* Strip a trailing comment (a '#' at start or after whitespace, outside quotes) and trailing spaces. */
static void strip_comment(char *s)
{
    char q = 0;
    size_t n = strlen(s);
    for (size_t i = 0; i < n; i++) {
        if (q) {
            if (s[i] == '\\' && q == '"' && i + 1 < n)
                i++;
            else if (s[i] == q) {
                if (q == '\'' && i + 1 < n && s[i + 1] == '\'')
                    i++;
                else
                    q = 0;
            }
        } else if (s[i] == '"' || s[i] == '\'') {
            if (i == 0 || s[i - 1] == ' ' || s[i - 1] == '{' || s[i - 1] == '[' || s[i - 1] == ',' ||
                s[i - 1] == ':')
                q = s[i];
        } else if (s[i] == '#' && (i == 0 || s[i - 1] == ' ')) {
            s[i] = '\0';
            break;
        }
    }
    n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

/* ---- scalars / flow ---- */

static g5c_json *resolve_plain(const char *s)
{
    char *e;
    if (*s == '\0' || strcmp(s, "~") == 0 || strcmp(s, "null") == 0 || strcmp(s, "Null") == 0)
        return g5c_json_new_null();
    if (strcmp(s, "true") == 0 || strcmp(s, "True") == 0)
        return g5c_json_new_bool(true);
    if (strcmp(s, "false") == 0 || strcmp(s, "False") == 0)
        return g5c_json_new_bool(false);
    {
        const char *p = s;
        size_t digits = 0;
        if (*p == '-')
            p++;
        while (*p >= '0' && *p <= '9') {
            p++;
            digits++;
        }
        if (*p == '\0' && digits > 0) {
            const char *d = (*s == '-') ? s + 1 : s;
            if (digits == 1 || *d != '0') { /* no leading zeros: 001 stays a string */
                long long v;
                errno = 0;
                v = strtoll(s, &e, 10);
                if (errno == 0 && *e == '\0')
                    return g5c_json_new_int((int64_t)v);
            }
        } else if (*p == '.' && digits > 0 && p[1] >= '0' && p[1] <= '9') {
            const char *q = p + 1;
            while (*q >= '0' && *q <= '9')
                q++;
            if (*q == '\0')
                return g5c_json_new_double(strtod(s, NULL));
        }
    }
    return g5c_json_new_str(s);
}

typedef struct {
    const char *p;
    y_t *y;
    int lineno;
} fl_t;

static void fskip(fl_t *f)
{
    while (*f->p == ' ')
        f->p++;
}

/* Parse a quoted scalar at f->p; returns heap string or NULL. */
static char *parse_quoted(fl_t *f)
{
    char q = *f->p++;
    g5c_bytes b;
    g5c_bytes_init(&b);
    for (;;) {
        char c = *f->p;
        if (c == '\0') {
            yfail(f->y, f->lineno, "unterminated quoted string");
            g5c_bytes_free(&b);
            return NULL;
        }
        f->p++;
        if (q == '\'') {
            if (c == '\'') {
                if (*f->p == '\'') {
                    g5c_bytes_putc(&b, '\'');
                    f->p++;
                    continue;
                }
                break;
            }
            g5c_bytes_putc(&b, c);
        } else {
            if (c == '"')
                break;
            if (c == '\\') {
                char e = *f->p++;
                switch (e) {
                case 'n': g5c_bytes_putc(&b, '\n'); break;
                case 't': g5c_bytes_putc(&b, '\t'); break;
                case 'r': g5c_bytes_putc(&b, '\r'); break;
                case '0': g5c_bytes_putc(&b, '\0'); break;
                case '"': g5c_bytes_putc(&b, '"'); break;
                case '\\': g5c_bytes_putc(&b, '\\'); break;
                case '/': g5c_bytes_putc(&b, '/'); break;
                default:
                    yfail(f->y, f->lineno, "unsupported escape");
                    g5c_bytes_free(&b);
                    return NULL;
                }
                continue;
            }
            g5c_bytes_putc(&b, c);
        }
    }
    return g5c_bytes_take(&b, NULL);
}

static g5c_json *parse_flow(fl_t *f, int depth, bool in_flow);

static char *trim_dup(const char *a, const char *b)
{
    while (a < b && *a == ' ')
        a++;
    while (b > a && b[-1] == ' ')
        b--;
    return g5c_xstrndup(a, (size_t)(b - a));
}

static g5c_json *parse_flow(fl_t *f, int depth, bool in_flow)
{
    fskip(f);
    if (depth > MAX_DEPTH) {
        yfail(f->y, f->lineno, "nesting too deep");
        return NULL;
    }
    if (*f->p == '{') {
        g5c_json *o = g5c_json_new_obj();
        f->p++;
        fskip(f);
        if (*f->p == '}') {
            f->p++;
            return o;
        }
        for (;;) {
            char *k;
            g5c_json *v;
            fskip(f);
            if (*f->p == '"' || *f->p == '\'') {
                k = parse_quoted(f);
            } else {
                const char *s = f->p;
                while (*f->p && *f->p != ':' && *f->p != ',' && *f->p != '}')
                    f->p++;
                k = trim_dup(s, f->p);
            }
            if (k == NULL)
                goto bad_obj;
            fskip(f);
            if (*f->p != ':') {
                free(k);
                yfail(f->y, f->lineno, "expected ':' in flow mapping");
                goto bad_obj;
            }
            f->p++;
            v = parse_flow(f, depth + 1, true);
            if (v == NULL) {
                free(k);
                goto bad_obj;
            }
            g5c_json_set(o, k, v);
            free(k);
            fskip(f);
            if (*f->p == ',') {
                f->p++;
                continue;
            }
            if (*f->p == '}') {
                f->p++;
                return o;
            }
            yfail(f->y, f->lineno, "expected ',' or '}'");
            goto bad_obj;
        }
    bad_obj:
        g5c_json_free(o);
        return NULL;
    }
    if (*f->p == '[') {
        g5c_json *a = g5c_json_new_arr();
        f->p++;
        fskip(f);
        if (*f->p == ']') {
            f->p++;
            return a;
        }
        for (;;) {
            g5c_json *v = parse_flow(f, depth + 1, true);
            if (v == NULL)
                goto bad_arr;
            g5c_json_push(a, v);
            fskip(f);
            if (*f->p == ',') {
                f->p++;
                continue;
            }
            if (*f->p == ']') {
                f->p++;
                return a;
            }
            yfail(f->y, f->lineno, "expected ',' or ']'");
            goto bad_arr;
        }
    bad_arr:
        g5c_json_free(a);
        return NULL;
    }
    if (*f->p == '"' || *f->p == '\'') {
        char *s = parse_quoted(f);
        g5c_json *j;
        if (s == NULL)
            return NULL;
        j = g5c_json_new_str(s);
        free(s);
        return j;
    }
    if (*f->p == '&' || *f->p == '*' || *f->p == '!' || *f->p == '|' || *f->p == '>') {
        yfail(f->y, f->lineno, "anchors, tags and block scalars are not supported");
        return NULL;
    }
    {
        const char *s = f->p;
        char *t;
        g5c_json *j;
        if (in_flow) {
            while (*f->p && *f->p != ',' && *f->p != '}' && *f->p != ']')
                f->p++;
        } else {
            f->p += strlen(f->p);
        }
        t = trim_dup(s, f->p);
        j = resolve_plain(t);
        free(t);
        return j;
    }
}

/* Parse the value text of an inline entry (after "key:" or "- "). */
static g5c_json *parse_inline(y_t *y, const char *text, int lineno)
{
    fl_t f = {text, y, lineno};
    g5c_json *j = parse_flow(&f, 0, false);
    if (j != NULL) {
        fskip(&f);
        if (*f.p != '\0') {
            yfail(y, lineno, "unexpected trailing text");
            g5c_json_free(j);
            return NULL;
        }
    }
    return j;
}

/* ---- block structure ---- */

static g5c_json *parse_block(y_t *y, int indent, int depth);

/* Locate the key/value separator of a block mapping line. Returns pointer to ':' or NULL. */
static const char *find_colon(const char *s)
{
    if (*s == '"' || *s == '\'') {
        char q = *s++;
        for (; *s; s++) {
            if (q == '"' && *s == '\\' && s[1])
                s++;
            else if (*s == q) {
                if (q == '\'' && s[1] == '\'')
                    s++;
                else {
                    s++;
                    break;
                }
            }
        }
        return (*s == ':' && (s[1] == ' ' || s[1] == '\0')) ? s : NULL;
    }
    if (*s == '{' || *s == '[')
        return NULL;
    for (; *s; s++)
        if (*s == ':' && (s[1] == ' ' || s[1] == '\0'))
            return s;
    return NULL;
}

static bool is_seq_item(const char *t)
{
    return t[0] == '-' && (t[1] == ' ' || t[1] == '\0');
}

static g5c_json *parse_block(y_t *y, int indent, int depth)
{
    line_t *ln = &y->l[y->pos];
    if (depth > MAX_DEPTH) {
        yfail(y, ln->lineno, "nesting too deep");
        return NULL;
    }
    if (is_seq_item(ln->text)) {
        g5c_json *arr = g5c_json_new_arr();
        while (y->pos < y->n && y->l[y->pos].indent == indent && is_seq_item(y->l[y->pos].text)) {
            line_t *it = &y->l[y->pos];
            const char *rest = it->text + 1;
            g5c_json *v;
            int skip = 0;
            while (*rest == ' ') {
                rest++;
                skip++;
            }
            if (*rest == '\0') {
                y->pos++;
                if (y->pos < y->n && y->l[y->pos].indent > indent)
                    v = parse_block(y, y->l[y->pos].indent, depth + 1);
                else
                    v = g5c_json_new_null();
            } else if (find_colon(rest) != NULL || is_seq_item(rest)) {
                /* "- key: value": the item is a mapping whose first line sits after the dash */
                char *nt = g5c_xstrdup(rest);
                free(it->text);
                it->text = nt;
                it->indent = indent + 1 + skip;
                v = parse_block(y, it->indent, depth + 1);
            } else {
                v = parse_inline(y, rest, it->lineno);
                y->pos++;
            }
            if (v == NULL) {
                g5c_json_free(arr);
                return NULL;
            }
            g5c_json_push(arr, v);
        }
        return arr;
    }
    if (find_colon(ln->text) != NULL) {
        g5c_json *obj = g5c_json_new_obj();
        while (y->pos < y->n && y->l[y->pos].indent == indent && !is_seq_item(y->l[y->pos].text)) {
            line_t *e = &y->l[y->pos];
            const char *colon = find_colon(e->text);
            char *key;
            const char *rest;
            g5c_json *v;
            if (colon == NULL) {
                yfail(y, e->lineno, "expected 'key: value'");
                goto bad;
            }
            if (e->text[0] == '"' || e->text[0] == '\'') {
                fl_t f = {e->text, y, e->lineno};
                key = parse_quoted(&f);
                if (key == NULL)
                    goto bad;
            } else {
                key = trim_dup(e->text, colon);
            }
            rest = colon + 1;
            while (*rest == ' ')
                rest++;
            y->pos++;
            if (*rest == '\0') {
                if (y->pos < y->n && y->l[y->pos].indent > indent)
                    v = parse_block(y, y->l[y->pos].indent, depth + 1);
                else if (y->pos < y->n && y->l[y->pos].indent == indent && is_seq_item(y->l[y->pos].text))
                    v = parse_block(y, indent, depth + 1); /* "key:" followed by a same-indent sequence */
                else
                    v = g5c_json_new_null();
            } else {
                v = parse_inline(y, rest, e->lineno);
            }
            if (v == NULL) {
                free(key);
                goto bad;
            }
            g5c_json_set(obj, key, v);
            free(key);
        }
        if (y->pos < y->n && y->l[y->pos].indent > indent) {
            yfail(y, y->l[y->pos].lineno, "unexpected indentation");
            goto bad;
        }
        return obj;
    bad:
        g5c_json_free(obj);
        return NULL;
    }
    {
        g5c_json *v = parse_inline(y, ln->text, ln->lineno);
        y->pos++;
        return v;
    }
}

g5c_json *g5c_yaml_parse(const char *s, size_t len, char *err, size_t errcap)
{
    y_t y = {NULL, 0, 0, err, errcap, false};
    size_t cap = 0, i = 0;
    int lineno = 0;
    g5c_json *result = NULL;
    if (err != NULL && errcap > 0)
        err[0] = '\0';
    while (i <= len && !y.failed) {
        size_t j = i;
        char *t;
        int ind = 0;
        size_t k;
        while (j < len && s[j] != '\n')
            j++;
        lineno++;
        t = g5c_xstrndup(s + i, j - i);
        if (memchr(t, '\0', j - i) != NULL) {
            free(t);
            yfail(&y, lineno, "NUL byte");
            break;
        }
        i = j + 1;
        strip_comment(t);
        for (k = 0; t[k] == ' '; k++)
            ind++;
        if (t[k] == '\t') {
            free(t);
            yfail(&y, lineno, "tabs are not allowed for indentation");
            break;
        }
        if (t[k] == '\0' || strcmp(t, "---") == 0 || strcmp(t + k, "---") == 0) {
            if (t[k] != '\0' && lineno > 1 && y.n > 0)
                yfail(&y, lineno, "multiple documents are not supported");
            free(t);
            continue;
        }
        if (y.n == MAX_LINES) {
            free(t);
            yfail(&y, lineno, "too many lines");
            break;
        }
        if (y.n == cap) {
            cap = cap ? cap * 2 : 64;
            y.l = g5c_xrealloc(y.l, cap * sizeof *y.l);
        }
        memmove(t, t + k, strlen(t + k) + 1);
        y.l[y.n].text = t;
        y.l[y.n].indent = ind;
        y.l[y.n].lineno = lineno;
        y.n++;
    }
    if (!y.failed) {
        if (y.n == 0) {
            result = g5c_json_new_null();
        } else {
            result = parse_block(&y, y.l[0].indent, 0);
            if (result != NULL && y.pos < y.n) {
                yfail(&y, y.l[y.pos].lineno, "unexpected content");
                g5c_json_free(result);
                result = NULL;
            }
        }
    }
    for (size_t n = 0; n < y.n; n++)
        free(y.l[n].text);
    free(y.l);
    return y.failed ? NULL : result;
}
