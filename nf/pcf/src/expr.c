/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _POSIX_C_SOURCE 200809L
/* A small expression language for policy conditions (backlog G-02). It has no loops, no functions of its own, no variables you can set and no access to anything but the fields of
 * the session it is given, and it is bounded: an expression is at most 400 characters and 64 nodes deep or wide, so evaluating one takes a bounded number of steps.
 *
 *   expr    := or
 *   or      := and ( "or" and )*
 *   and     := not ( "and" not )*
 *   not     := "not" not | cmp
 *   cmp     := term [ ( "==" | "!=" | "<" | "<=" | ">" | ">=" | "startswith" | "endswith" | "contains" ) term | "in" "[" term ( "," term )* "]" ]
 *   term    := field | 'string' | number | "(" expr ")"
 *
 * Fields: supi, dnn, sst, sd, plmn (mcc+mnc of the SUPI), qi5 (the subscribed default 5QI, 0 when none). Numbers and strings compare with their own kind only: a string against a number
 * is false, not an error, and an unknown field is a parse error. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "expr.h"

enum { N_OR, N_AND, N_NOT, N_CMP, N_IN, N_FIELD, N_STR, N_NUM };
enum { C_EQ, C_NE, C_LT, C_LE, C_GT, C_GE, C_STARTS, C_ENDS, C_CONTAINS };

typedef struct node {
    int kind, op;
    struct node *a, *b;
    struct node **list;
    size_t nlist;
    char *s;
    double n;
} node;

struct pcf_expr {
    node *root;
    size_t nodes;
};

typedef struct {
    const char *p;
    char *err;
    size_t cap;
    size_t nodes, depth;
    bool bad;
} ps;

static void fail(ps *x, const char *msg)
{
    if (!x->bad)
        snprintf(x->err, x->cap, "%s (at \"%.20s\")", msg, x->p);
    x->bad = true;
}

static void skip(ps *x)
{
    while (isspace((unsigned char)*x->p))
        x->p++;
}

static bool word(ps *x, const char *w)
{
    size_t n = strlen(w);
    skip(x);
    if (strncmp(x->p, w, n) == 0 && !isalnum((unsigned char)x->p[n]) && x->p[n] != '_') {
        x->p += n;
        return true;
    }
    return false;
}

static node *mk(ps *x, int kind)
{
    node *n;
    if (++x->nodes > 64) {
        fail(x, "the expression is too large (64 nodes at most)");
        return NULL;
    }
    n = calloc(1, sizeof *n);
    n->kind = kind;
    return n;
}

static void nfree(node *n)
{
    if (n == NULL)
        return;
    nfree(n->a);
    nfree(n->b);
    for (size_t i = 0; i < n->nlist; i++)
        nfree(n->list[i]);
    free(n->list);
    free(n->s);
    free(n);
}

static node *p_or(ps *x);

static node *p_term(ps *x)
{
    node *n;
    skip(x);
    if (x->bad)
        return NULL;
    if (*x->p == '(') {
        x->p++;
        if (++x->depth > 16) {
            fail(x, "parentheses nested too deep (16 at most)");
            return NULL;
        }
        n = p_or(x);
        x->depth--;
        skip(x);
        if (n != NULL && *x->p != ')') {
            fail(x, "missing )");
            nfree(n);
            return NULL;
        }
        if (n != NULL)
            x->p++;
        return n;
    }
    if (*x->p == '\'') {
        const char *e = strchr(x->p + 1, '\'');
        if (e == NULL) {
            fail(x, "unterminated string");
            return NULL;
        }
        n = mk(x, N_STR);
        if (n == NULL)
            return NULL;
        n->s = strndup(x->p + 1, (size_t)(e - x->p - 1));
        x->p = e + 1;
        return n;
    }
    if (isdigit((unsigned char)*x->p)) {
        char *end;
        n = mk(x, N_NUM);
        if (n == NULL)
            return NULL;
        n->n = strtod(x->p, &end);
        x->p = end;
        return n;
    }
    if (isalpha((unsigned char)*x->p)) {
        static const char *const fields[] = {"supi", "dnn", "sst", "sd", "plmn", "qi5", NULL};
        size_t l = 0;
        while (isalnum((unsigned char)x->p[l]) || x->p[l] == '_')
            l++;
        for (size_t i = 0; fields[i] != NULL; i++)
            if (strlen(fields[i]) == l && strncmp(x->p, fields[i], l) == 0) {
                n = mk(x, N_FIELD);
                if (n == NULL)
                    return NULL;
                n->s = strdup(fields[i]);
                x->p += l;
                return n;
            }
        fail(x, "unknown field (supi, dnn, sst, sd, plmn, qi5)");
        return NULL;
    }
    fail(x, "a field, a 'string', a number or ( was expected");
    return NULL;
}

static node *p_cmp(ps *x)
{
    node *l = p_term(x), *c;
    static const struct {
        const char *t;
        int op;
    } ops[] = {{"==", C_EQ}, {"!=", C_NE}, {"<=", C_LE}, {">=", C_GE}, {"<", C_LT}, {">", C_GT}};
    if (l == NULL)
        return NULL;
    skip(x);
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++)
        if (strncmp(x->p, ops[i].t, strlen(ops[i].t)) == 0) {
            x->p += strlen(ops[i].t);
            c = mk(x, N_CMP);
            if (c == NULL) {
                nfree(l);
                return NULL;
            }
            c->op = ops[i].op;
            c->a = l;
            c->b = p_term(x);
            if (c->b == NULL) {
                nfree(c);
                return NULL;
            }
            return c;
        }
    {
        int op = word(x, "startswith") ? C_STARTS : word(x, "endswith") ? C_ENDS : word(x, "contains") ? C_CONTAINS : -1;
        if (op >= 0) {
            c = mk(x, N_CMP);
            if (c == NULL) {
                nfree(l);
                return NULL;
            }
            c->op = op;
            c->a = l;
            c->b = p_term(x);
            if (c->b == NULL) {
                nfree(c);
                return NULL;
            }
            return c;
        }
    }
    if (word(x, "in")) {
        c = mk(x, N_IN);
        if (c == NULL) {
            nfree(l);
            return NULL;
        }
        c->a = l;
        skip(x);
        if (*x->p != '[') {
            fail(x, "[ was expected after in");
            nfree(c);
            return NULL;
        }
        x->p++;
        for (;;) {
            node *t = p_term(x);
            if (t == NULL) {
                nfree(c);
                return NULL;
            }
            c->list = realloc(c->list, (c->nlist + 1) * sizeof *c->list);
            c->list[c->nlist++] = t;
            skip(x);
            if (*x->p == ',') {
                x->p++;
                continue;
            }
            if (*x->p == ']') {
                x->p++;
                break;
            }
            fail(x, "] or , was expected");
            nfree(c);
            return NULL;
        }
        return c;
    }
    return l;
}

static node *p_not(ps *x)
{
    if (word(x, "not")) {
        node *n = mk(x, N_NOT), *a;
        if (n == NULL)
            return NULL;
        if (++x->depth > 16) {
            fail(x, "too deep");
            nfree(n);
            return NULL;
        }
        a = p_not(x);
        x->depth--;
        if (a == NULL) {
            nfree(n);
            return NULL;
        }
        n->a = a;
        return n;
    }
    return p_cmp(x);
}

static node *p_and(ps *x)
{
    node *l = p_not(x);
    while (l != NULL && word(x, "and")) {
        node *n = mk(x, N_AND), *r;
        if (n == NULL) {
            nfree(l);
            return NULL;
        }
        r = p_not(x);
        if (r == NULL) {
            nfree(n);
            nfree(l);
            return NULL;
        }
        n->a = l;
        n->b = r;
        l = n;
    }
    return l;
}

static node *p_or(ps *x)
{
    node *l = p_and(x);
    while (l != NULL && word(x, "or")) {
        node *n = mk(x, N_OR), *r;
        if (n == NULL) {
            nfree(l);
            return NULL;
        }
        r = p_and(x);
        if (r == NULL) {
            nfree(n);
            nfree(l);
            return NULL;
        }
        n->a = l;
        n->b = r;
        l = n;
    }
    return l;
}

pcf_expr *pcf_expr_parse(const char *src, char *err, size_t cap)
{
    ps x = {src, err, cap, 0, 0, false};
    node *r;
    pcf_expr *e;
    err[0] = 0;
    if (src == NULL || strlen(src) > 400) {
        snprintf(err, cap, "the expression is empty or longer than 400 characters");
        return NULL;
    }
    r = p_or(&x);
    skip(&x);
    if (r != NULL && *x.p != 0) {
        fail(&x, "unexpected text after the expression");
        nfree(r);
        return NULL;
    }
    if (r == NULL) {
        if (err[0] == 0)
            snprintf(err, cap, "empty expression");
        return NULL;
    }
    e = calloc(1, sizeof *e);
    e->root = r;
    e->nodes = x.nodes;
    return e;
}

void pcf_expr_free(pcf_expr *e)
{
    if (e != NULL) {
        nfree(e->root);
        free(e);
    }
}

/* a value: a string or a number */
typedef struct {
    bool is_num;
    double n;
    const char *s;
    char buf[64];
} val;

static val value_of(const node *n, const pcf_expr_ctx *c)
{
    val v;
    memset(&v, 0, sizeof v);
    if (n->kind == N_NUM) {
        v.is_num = true;
        v.n = n->n;
    } else if (n->kind == N_STR) {
        v.s = n->s;
    } else if (n->kind == N_FIELD) {
        if (strcmp(n->s, "supi") == 0) {
            v.s = c->supi != NULL ? c->supi : "";
        } else if (strcmp(n->s, "dnn") == 0) {
            v.s = c->dnn != NULL ? c->dnn : "";
        } else if (strcmp(n->s, "sd") == 0) {
            v.s = c->sd != NULL ? c->sd : "";
        } else if (strcmp(n->s, "plmn") == 0) { /* "imsi-<mcc><mnc>..." : the first five digits: MCC and a two digit MNC (the SUPI alone does not tell a three digit MNC) */
            const char *d = c->supi != NULL && strncmp(c->supi, "imsi-", 5) == 0 ? c->supi + 5 : "";
            static __thread char plmn_buf[8]; /* a value is returned by copy: its string must outlive it */
            snprintf(plmn_buf, sizeof plmn_buf, "%.5s", d);
            v.s = plmn_buf;
        } else if (strcmp(n->s, "sst") == 0) {
            v.is_num = true;
            v.n = c->sst;
        } else {
            v.is_num = true;
            v.n = c->qi5;
        }
    }
    return v;
}

static bool compare(int op, const val *a, const val *b)
{
    if (a->is_num != b->is_num)
        return op == C_NE;
    if (a->is_num) {
        switch (op) {
        case C_EQ: return a->n == b->n;
        case C_NE: return a->n != b->n;
        case C_LT: return a->n < b->n;
        case C_LE: return a->n <= b->n;
        case C_GT: return a->n > b->n;
        case C_GE: return a->n >= b->n;
        default: return false;
        }
    }
    switch (op) {
    case C_EQ: return strcmp(a->s, b->s) == 0;
    case C_NE: return strcmp(a->s, b->s) != 0;
    case C_LT: return strcmp(a->s, b->s) < 0;
    case C_LE: return strcmp(a->s, b->s) <= 0;
    case C_GT: return strcmp(a->s, b->s) > 0;
    case C_GE: return strcmp(a->s, b->s) >= 0;
    case C_STARTS: return strncmp(a->s, b->s, strlen(b->s)) == 0;
    case C_ENDS: return strlen(a->s) >= strlen(b->s) && strcmp(a->s + strlen(a->s) - strlen(b->s), b->s) == 0;
    case C_CONTAINS: return strstr(a->s, b->s) != NULL;
    default: return false;
    }
}

static bool eval(const node *n, const pcf_expr_ctx *c)
{
    switch (n->kind) {
    case N_OR: return eval(n->a, c) || eval(n->b, c);
    case N_AND: return eval(n->a, c) && eval(n->b, c);
    case N_NOT: return !eval(n->a, c);
    case N_CMP: {
        val a = value_of(n->a, c), b = value_of(n->b, c);
        if (n->a->kind == N_CMP || n->b->kind == N_CMP)
            return false;
        return compare(n->op, &a, &b);
    }
    case N_IN: {
        val a = value_of(n->a, c);
        for (size_t i = 0; i < n->nlist; i++) {
            val b = value_of(n->list[i], c);
            if (compare(C_EQ, &a, &b))
                return true;
        }
        return false;
    }
    default: {
        val v = value_of(n, c); /* a bare value is true when it is a non-empty string or a non-zero number */
        return v.is_num ? v.n != 0 : v.s != NULL && v.s[0] != 0;
    }
    }
}

bool pcf_expr_eval(const pcf_expr *e, const pcf_expr_ctx *c)
{
    return eval(e->root, c);
}
