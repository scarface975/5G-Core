/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* JSON Patch (RFC 6902): add, replace, remove. Used by the NRF (NFUpdate) and the UDR (PATCH of stored documents). */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/base.h"
#include "g5c/json.h"

/* ---- JSON Patch ------------------------------------------------------------------------------------------- */

static void perr(char *err, size_t cap, const char *prefix, const char *a)
{
    if (err != NULL && cap > 0)
        snprintf(err, cap, "%s%s", prefix, a);
}

/* Split an RFC 6901 pointer into unescaped tokens. Returns count or -1. */
static long tokens(const char *path, char ***out)
{
    char **v = NULL;
    size_t n = 0;
    const char *p;
    *out = NULL;
    if (path[0] == '\0')
        return 0;
    if (path[0] != '/')
        return -1;
    p = path + 1;
    for (;;) {
        const char *e = strchr(p, '/');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        char *t = g5c_xmalloc(len + 1), *w = t;
        for (size_t i = 0; i < len; i++) {
            if (p[i] == '~' && i + 1 < len && p[i + 1] == '1') {
                *w++ = '/';
                i++;
            } else if (p[i] == '~' && i + 1 < len && p[i + 1] == '0') {
                *w++ = '~';
                i++;
            } else {
                *w++ = p[i];
            }
        }
        *w = 0;
        v = g5c_xrealloc(v, (n + 1) * sizeof *v);
        v[n++] = t;
        if (e == NULL)
            break;
        p = e + 1;
    }
    *out = v;
    return (long)n;
}

static void tokens_free(char **v, long n)
{
    if (v == NULL)
        return;
    for (long i = 0; i < n; i++)
        free(v[i]);
    free(v);
}

static bool parse_index(const char *s, size_t *out)
{
    char *e;
    unsigned long long v;
    if (*s < '0' || *s > '9')
        return false;
    errno = 0;
    v = strtoull(s, &e, 10);
    if (errno != 0 || *e != 0)
        return false;
    *out = (size_t)v;
    return true;
}

int g5c_json_patch(g5c_json **doc, const g5c_json *items, char *err, size_t errcap)
{
    if (!g5c_json_is(items, G5C_J_ARRAY)) {
        perr(err, errcap, "unsupported or malformed patch item: ", "patch must be an array");
        return G5C_PATCH_ITEM;
    }
    for (size_t k = 0; k < g5c_json_len(items); k++) {
        const g5c_json *item = g5c_json_at(items, k), *value = g5c_json_get(item, "value");
        const char *op = g5c_json_get_str(item, "op"), *path = g5c_json_get_str(item, "path");
        char **tok;
        long nt;
        g5c_json *parent;
        const char *last;
        int rc = G5C_PATCH_OK;

        if (op == NULL || path == NULL) {
            perr(err, errcap, "unsupported or malformed patch item: ", "missing op or path");
            return G5C_PATCH_ITEM;
        }
        nt = tokens(path, &tok);
        if (nt < 0) {
            perr(err, errcap, "unsupported or malformed patch item: bad pointer ", path);
            return G5C_PATCH_ITEM;
        }
        if (nt == 0 || tok == NULL) { /* the whole document */
            if ((strcmp(op, "add") == 0 || strcmp(op, "replace") == 0) && value != NULL) {
                g5c_json_free(*doc);
                *doc = g5c_json_dup(value);
                continue;
            }
            perr(err, errcap, "unsupported or malformed patch item: ", op);
            return G5C_PATCH_ITEM;
        }
        parent = *doc;
        for (long i = 0; i + 1 < nt && parent != NULL; i++) {
            if (g5c_json_is(parent, G5C_J_OBJECT)) {
                parent = g5c_json_get_mut(parent, tok[i]);
            } else if (g5c_json_is(parent, G5C_J_ARRAY)) {
                size_t idx;
                parent = parse_index(tok[i], &idx) ? g5c_json_at_mut(parent, idx) : NULL;
            } else {
                parent = NULL;
            }
        }
        last = tok[nt - 1];
        if (parent == NULL) {
            perr(err, errcap, "path not found: ", path);
            rc = G5C_PATCH_PATH;
        } else if (g5c_json_is(parent, G5C_J_OBJECT)) {
            if ((strcmp(op, "add") == 0 || strcmp(op, "replace") == 0) && value == NULL) {
                perr(err, errcap, "unsupported or malformed patch item: ", "value missing");
                rc = G5C_PATCH_ITEM;
            } else if (strcmp(op, "add") == 0) {
                g5c_json_set(parent, last, g5c_json_dup(value));
            } else if (strcmp(op, "replace") == 0) {
                if (g5c_json_get(parent, last) == NULL) {
                    perr(err, errcap, "path not found: ", path);
                    rc = G5C_PATCH_PATH;
                } else {
                    g5c_json_set(parent, last, g5c_json_dup(value));
                }
            } else if (strcmp(op, "remove") == 0) {
                if (!g5c_json_remove(parent, last)) {
                    perr(err, errcap, "path not found: ", path);
                    rc = G5C_PATCH_PATH;
                }
            } else {
                perr(err, errcap, "unsupported or malformed patch item: ", op);
                rc = G5C_PATCH_ITEM;
            }
        } else if (g5c_json_is(parent, G5C_J_ARRAY)) {
            size_t i = 0;
            bool is_add = strcmp(op, "add") == 0, is_rep = strcmp(op, "replace") == 0, is_rm = strcmp(op, "remove") == 0;
            if (!(is_add || is_rep || is_rm)) {
                perr(err, errcap, "unsupported or malformed patch item: ", op);
                rc = G5C_PATCH_ITEM;
            } else if ((is_add || is_rep) && value == NULL) {
                perr(err, errcap, "unsupported or malformed patch item: ", "value missing");
                rc = G5C_PATCH_ITEM;
            } else if (is_add && strcmp(last, "-") == 0) {
                g5c_json_push(parent, g5c_json_dup(value));
            } else if (!parse_index(last, &i)) {
                perr(err, errcap, "path not found: ", path);
                rc = G5C_PATCH_PATH;
            } else if (is_add && i <= g5c_json_len(parent)) {
                g5c_json_arr_insert(parent, i, g5c_json_dup(value));
            } else if (is_rep && i < g5c_json_len(parent)) {
                g5c_json_arr_replace(parent, i, g5c_json_dup(value));
            } else if (is_rm && i < g5c_json_len(parent)) {
                g5c_json_arr_remove(parent, i);
            } else {
                perr(err, errcap, "path not found: ", path);
                rc = G5C_PATCH_PATH;
            }
        } else { /* the parent exists but is a scalar: the target cannot exist */
            perr(err, errcap, "path not found: ", path);
            rc = G5C_PATCH_PATH;
        }
        tokens_free(tok, nt);
        if (rc != G5C_PATCH_OK)
            return rc;
    }
    return G5C_PATCH_OK;
}

