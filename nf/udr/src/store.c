/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The store handle: a storage backend plus the direct-access helpers used by tests and tools. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "g5c/base.h"
#include "g5c/udr.h"
#include "priv.h"

static g5c_udr_store *wrap(udr_db *db)
{
    g5c_udr_store *s;
    if (db == NULL)
        return NULL;
    s = g5c_xcalloc(1, sizeof *s);
    s->db = db;
    return s;
}

g5c_udr_store *g5c_udr_store_memory(void)
{
    return wrap(udr_db_memory());
}

g5c_udr_store *g5c_udr_store_open(const char *path, char *err, size_t errcap)
{
    return wrap(udr_db_file(path, err, errcap));
}

g5c_udr_store *g5c_udr_store_postgres(const char *conninfo, int pool, char *err, size_t errcap)
{
    return wrap(udr_db_postgres(conninfo, pool, err, errcap));
}

void g5c_udr_store_track(g5c_udr_store *s, void *owned)
{
    s->owned = g5c_xrealloc(s->owned, (s->nowned + 1) * sizeof *s->owned);
    s->owned[s->nowned++] = owned;
}

void g5c_udr_store_free(g5c_udr_store *s)
{
    if (s == NULL)
        return;
    udr_free(s->svc);
    for (size_t i = 0; i < s->nowned; i++)
        free(s->owned[i]);
    free(s->owned);
    udr_db_free(s->db);
    free(s);
}

size_t udr_record_count(g5c_udr_store *s)
{
    return s->db->ops->count(s->db->self);
}

g5c_json *g5c_udr_get(g5c_udr_store *s, const char *ue, const char *key)
{
    udr_rec r;
    return s->db->ops->get(s->db->self, ue, key, &r) == 1 ? r.doc : NULL;
}

bool g5c_udr_exists(g5c_udr_store *s, const char *ue)
{
    return s->db->ops->part_exists(s->db->self, ue) == 1;
}

bool g5c_udr_put(g5c_udr_store *s, const char *ue, const char *key, g5c_json *val)
{
    bool created = false;
    (void)s->db->ops->put(s->db->self, ue, key, val, NULL, &created, NULL, NULL);
    return created;
}

bool g5c_udr_take(g5c_udr_store *s, const char *ue, const char *key)
{
    udr_rec old;
    if (s->db->ops->del(s->db->self, ue, key, NULL, &old) != UDR_DB_OK)
        return false;
    g5c_json_free(old.doc);
    return true;
}

typedef struct {
    const g5c_json *items;
} patch_arg;

static int apply_patch(g5c_json **doc, void *arg, char *err, size_t errcap)
{
    return g5c_json_patch(doc, ((patch_arg *)arg)->items, err, errcap);
}

int g5c_udr_patch(g5c_udr_store *s, const char *ue, const char *key, const g5c_json *items, char *err, size_t errcap)
{
    patch_arg a = {items};
    int rc = s->db->ops->mutate(s->db->self, ue, key, apply_patch, &a, NULL, NULL, NULL, err, errcap);
    return rc == UDR_DB_OK ? 1 : rc == UDR_DB_ABSENT ? 0 : -1;
}

static char *child_key(const char *key, const char *child)
{
    return g5c_xasprintf("%s/%s", key, child);
}

bool g5c_udr_map_put(g5c_udr_store *s, const char *ue, const char *key, const char *child, g5c_json *val)
{
    char *k = child_key(key, child);
    bool created = g5c_udr_put(s, ue, k, val);
    free(k);
    return created;
}

g5c_json *g5c_udr_map_get(g5c_udr_store *s, const char *ue, const char *key, const char *child)
{
    char *k = child_key(key, child);
    g5c_json *r = g5c_udr_get(s, ue, k);
    free(k);
    return r;
}

bool g5c_udr_map_remove(g5c_udr_store *s, const char *ue, const char *key, const char *child)
{
    char *k = child_key(key, child);
    bool r = g5c_udr_take(s, ue, k);
    free(k);
    return r;
}

g5c_json *g5c_udr_map_values(g5c_udr_store *s, const char *ue, const char *key)
{
    udr_list l;
    g5c_json *out;
    if (!g5c_udr_exists(s, ue))
        return NULL;
    out = g5c_json_new_arr();
    if (s->db->ops->list(s->db->self, ue, key, &l) == 0) {
        size_t pl = strlen(key) + 1;
        for (size_t i = 0; i < l.n; i++)
            if (strchr(l.keys[i] + pl, '/') == NULL) {
                g5c_json_push(out, l.recs[i].doc);
                l.recs[i].doc = NULL;
            }
        udr_list_free(&l);
    }
    return out;
}

g5c_json *g5c_udr_ids(g5c_udr_store *s)
{
    g5c_json *all = g5c_json_new_arr(), *out = g5c_json_new_arr();
    (void)s->db->ops->parts(s->db->self, all);
    for (size_t i = 0; i < g5c_json_len(all); i++) {
        const char *p = g5c_json_str(g5c_json_at(all, i));
        if (strcmp(p, UDR_GLOBAL_PART) != 0 && strncmp(p, UDR_GROUP_PREFIX, strlen(UDR_GROUP_PREFIX)) != 0)
            g5c_json_push_str(out, p);
    }
    g5c_json_free(all);
    return out;
}

bool g5c_udr_remove(g5c_udr_store *s, const char *ue)
{
    return s->db->ops->del_part(s->db->self, ue) == 1;
}
