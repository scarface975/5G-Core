/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Helpers shared by the storage backends: preconditions, entity tags, merge patch. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "g5c/base.h"

void udr_list_free(udr_list *l)
{
    for (size_t i = 0; i < l->n; i++) {
        free(l->keys[i]);
        g5c_json_free(l->recs[i].doc);
    }
    free(l->keys);
    free(l->recs);
    memset(l, 0, sizeof *l);
}

void udr_db_free(udr_db *d)
{
    if (d == NULL)
        return;
    d->ops->close(d->self);
    free(d);
}

bool udr_cond_ok(const udr_cond *c, bool exists, uint64_t rev)
{
    if (c == NULL)
        return true;
    switch (c->kind) {
    case UDR_COND_NONE: return true;
    case UDR_COND_MATCH: return exists && rev == c->rev;
    case UDR_COND_NOT_EXISTS: return !exists;
    case UDR_COND_EXISTS: return exists;
    }
    return true;
}

char *udr_etag_str(uint64_t rev)
{
    return g5c_xasprintf("\"%llx\"", (unsigned long long)rev);
}

uint64_t udr_etag_rev(const char *etag)
{
    char *end;
    unsigned long long v;
    if (etag == NULL)
        return 0;
    if (strncmp(etag, "W/", 2) == 0)
        etag += 2;
    if (*etag != '"')
        return 0;
    v = strtoull(etag + 1, &end, 16);
    if (end == etag + 1 || *end != '"')
        return 0;
    return v;
}

void udr_merge_patch(g5c_json **doc, const g5c_json *patch)
{
    if (!g5c_json_is(patch, G5C_J_OBJECT)) {
        g5c_json_free(*doc);
        *doc = g5c_json_dup(patch);
        return;
    }
    if (!g5c_json_is(*doc, G5C_J_OBJECT)) {
        g5c_json_free(*doc);
        *doc = g5c_json_new_obj();
    }
    for (size_t i = 0; i < g5c_json_len(patch); i++) {
        const char *k = g5c_json_key_at(patch, i);
        const g5c_json *pv = g5c_json_val_at(patch, i);
        if (g5c_json_is(pv, G5C_J_NULL)) {
            (void)g5c_json_remove(*doc, k);
        } else if (g5c_json_is(pv, G5C_J_OBJECT)) {
            g5c_json *cur = g5c_json_detach(*doc, k);
            if (cur == NULL)
                cur = g5c_json_new_obj();
            udr_merge_patch(&cur, pv);
            g5c_json_set(*doc, k, cur);
        } else {
            g5c_json_set(*doc, k, g5c_json_dup(pv));
        }
    }
}
