/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include <stdlib.h>
#include <string.h>

#include "priv.h"

struct upf_ptrmap {
    uint64_t *keys;
    void **vals;
    uint8_t *used;
    size_t cap, n;
};

static size_t hash64(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return (size_t)x;
}

upf_ptrmap *ptrmap_new(void)
{
    upf_ptrmap *m = g5c_xcalloc(1, sizeof *m);
    m->cap = 64;
    m->keys = g5c_xcalloc(m->cap, sizeof *m->keys);
    m->vals = g5c_xcalloc(m->cap, sizeof *m->vals);
    m->used = g5c_xcalloc(m->cap, 1);
    return m;
}

void ptrmap_free(upf_ptrmap *m)
{
    if (m == NULL)
        return;
    free(m->keys);
    free(m->vals);
    free(m->used);
    free(m);
}

size_t ptrmap_len(const upf_ptrmap *m)
{
    return m->n;
}

void *ptrmap_get(const upf_ptrmap *m, uint64_t key)
{
    size_t i = hash64(key) & (m->cap - 1);
    while (m->used[i]) {
        if (m->keys[i] == key)
            return m->vals[i];
        i = (i + 1) & (m->cap - 1);
    }
    return NULL;
}

static void put_raw(upf_ptrmap *m, uint64_t key, void *val)
{
    size_t i = hash64(key) & (m->cap - 1);
    while (m->used[i]) {
        if (m->keys[i] == key) {
            m->vals[i] = val;
            return;
        }
        i = (i + 1) & (m->cap - 1);
    }
    m->used[i] = 1;
    m->keys[i] = key;
    m->vals[i] = val;
    m->n++;
}

void ptrmap_put(upf_ptrmap *m, uint64_t key, void *val)
{
    if ((m->n + 1) * 2 > m->cap) {
        upf_ptrmap old = *m;
        m->cap *= 2;
        m->keys = g5c_xcalloc(m->cap, sizeof *m->keys);
        m->vals = g5c_xcalloc(m->cap, sizeof *m->vals);
        m->used = g5c_xcalloc(m->cap, 1);
        m->n = 0;
        for (size_t i = 0; i < old.cap; i++)
            if (old.used[i])
                put_raw(m, old.keys[i], old.vals[i]);
        free(old.keys);
        free(old.vals);
        free(old.used);
    }
    put_raw(m, key, val);
}

void ptrmap_del(upf_ptrmap *m, uint64_t key)
{
    size_t i = hash64(key) & (m->cap - 1), j;
    while (m->used[i] && m->keys[i] != key)
        i = (i + 1) & (m->cap - 1);
    if (!m->used[i])
        return;
    m->used[i] = 0;
    m->n--;
    /* backward-shift: re-insert the cluster that follows */
    j = (i + 1) & (m->cap - 1);
    while (m->used[j]) {
        uint64_t k = m->keys[j];
        void *v = m->vals[j];
        m->used[j] = 0;
        m->n--;
        put_raw(m, k, v);
        j = (j + 1) & (m->cap - 1);
    }
}
