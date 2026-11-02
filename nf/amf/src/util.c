/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Small helpers: hash maps, identifiers, S-NSSAI and TAI conversions. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

/* ---- maps ------------------------------------------------------------------------------------------------------------------------------- */

typedef struct mnode {
    struct mnode *next;
    uint64_t key;
    char *skey;
    void *val;
} mnode;

struct amf_map {
    mnode **b;
    size_t nb, n;
};

struct amf_smap {
    amf_map m;
};

static size_t mix(uint64_t k)
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    return (size_t)k;
}

static uint64_t fnv(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    for (; *s != 0; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    }
    return h;
}

static void m_init(amf_map *m)
{
    m->nb = 64;
    m->n = 0;
    m->b = g5c_xcalloc(m->nb, sizeof *m->b);
}

static void m_grow(amf_map *m)
{
    size_t nb = m->nb * 2;
    mnode **b = g5c_xcalloc(nb, sizeof *b);
    for (size_t i = 0; i < m->nb; i++)
        for (mnode *n = m->b[i], *nx; n != NULL; n = nx) {
            size_t j = mix(n->skey != NULL ? fnv(n->skey) : n->key) % nb;
            nx = n->next;
            n->next = b[j];
            b[j] = n;
        }
    free(m->b);
    m->b = b;
    m->nb = nb;
}

static void m_clear(amf_map *m)
{
    for (size_t i = 0; i < m->nb; i++)
        for (mnode *n = m->b[i], *nx; n != NULL; n = nx) {
            nx = n->next;
            free(n->skey);
            free(n);
        }
    free(m->b);
    m->b = NULL;
}

amf_map *amap_new(void)
{
    amf_map *m = g5c_xcalloc(1, sizeof *m);
    m_init(m);
    return m;
}

void amap_free(amf_map *m)
{
    if (m == NULL)
        return;
    m_clear(m);
    free(m);
}

void *amap_get(const amf_map *m, uint64_t key)
{
    for (mnode *n = m->b[mix(key) % m->nb]; n != NULL; n = n->next)
        if (n->skey == NULL && n->key == key)
            return n->val;
    return NULL;
}

void amap_put(amf_map *m, uint64_t key, void *val)
{
    size_t i = mix(key) % m->nb;
    for (mnode *n = m->b[i]; n != NULL; n = n->next)
        if (n->skey == NULL && n->key == key) {
            n->val = val;
            return;
        }
    if (m->n * 2 > m->nb) {
        m_grow(m);
        i = mix(key) % m->nb;
    }
    {
        mnode *n = g5c_xcalloc(1, sizeof *n);
        n->key = key;
        n->val = val;
        n->next = m->b[i];
        m->b[i] = n;
        m->n++;
    }
}

void amap_del(amf_map *m, uint64_t key)
{
    for (mnode **pp = &m->b[mix(key) % m->nb]; *pp != NULL; pp = &(*pp)->next)
        if ((*pp)->skey == NULL && (*pp)->key == key) {
            mnode *n = *pp;
            *pp = n->next;
            free(n);
            m->n--;
            return;
        }
}

size_t amap_count(const amf_map *m)
{
    return m->n;
}

amf_smap *smap_new(void)
{
    amf_smap *m = g5c_xcalloc(1, sizeof *m);
    m_init(&m->m);
    return m;
}

void smap_free(amf_smap *m)
{
    if (m == NULL)
        return;
    m_clear(&m->m);
    free(m);
}

void *smap_get(const amf_smap *m, const char *key)
{
    for (mnode *n = m->m.b[mix(fnv(key)) % m->m.nb]; n != NULL; n = n->next)
        if (n->skey != NULL && strcmp(n->skey, key) == 0)
            return n->val;
    return NULL;
}

void smap_put(amf_smap *m, const char *key, void *val)
{
    size_t i = mix(fnv(key)) % m->m.nb;
    for (mnode *n = m->m.b[i]; n != NULL; n = n->next)
        if (n->skey != NULL && strcmp(n->skey, key) == 0) {
            n->val = val;
            return;
        }
    if (m->m.n * 2 > m->m.nb) {
        m_grow(&m->m);
        i = mix(fnv(key)) % m->m.nb;
    }
    {
        mnode *n = g5c_xcalloc(1, sizeof *n);
        n->skey = g5c_xstrdup(key);
        n->val = val;
        n->next = m->m.b[i];
        m->m.b[i] = n;
        m->m.n++;
    }
}

void smap_del(amf_smap *m, const char *key)
{
    for (mnode **pp = &m->m.b[mix(fnv(key)) % m->m.nb]; *pp != NULL; pp = &(*pp)->next)
        if ((*pp)->skey != NULL && strcmp((*pp)->skey, key) == 0) {
            mnode *n = *pp;
            *pp = n->next;
            free(n->skey);
            free(n);
            m->m.n--;
            return;
        }
}

/* ---- helpers ---------------------------------------------------------------------------------------------------------------------------- */

void amf_count(amf *a, const char *name, const char *help, const char *lk, const char *lv)
{
    if (lk != NULL) {
        g5c_label l = {lk, lv};
        g5c_counter_inc(g5c_counter_get(a->metrics, name, help, &l, 1));
    } else {
        g5c_counter_inc(g5c_counter_get(a->metrics, name, help, NULL, 0));
    }
}

char *amf_hex(const uint8_t *p, size_t n)
{
    return g5c_hex_encode(p, n);
}

int amf_tai_eq(const amf_tai *a, const amf_tai *b)
{
    return memcmp(a->plmn, b->plmn, 3) == 0 && a->tac == b->tac;
}

uint32_t amf_get_be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

void amf_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* {"plmnId":{"mcc":..,"mnc":..},"tac":"000001"} */
void amf_tai_to_json(const amf_tai *t, g5c_json *parent, const char *key)
{
    g5c_json *o = g5c_json_set(parent, key, g5c_json_new_obj()), *p = g5c_json_set(o, "plmnId", g5c_json_new_obj());
    char mcc[4], mnc[4], tac[7];
    if (nas_plmn_decode(t->plmn, 3, mcc, mnc) != 0) {
        snprintf(mcc, sizeof mcc, "000");
        snprintf(mnc, sizeof mnc, "00");
    }
    g5c_json_set_str(p, "mcc", mcc);
    g5c_json_set_str(p, "mnc", mnc);
    snprintf(tac, sizeof tac, "%06X", t->tac & 0xffffffu);
    g5c_json_set_str(o, "tac", tac);
}

void amf_snssai_json(const nas_snssai *s, g5c_json *parent, const char *key)
{
    g5c_json *o = g5c_json_set(parent, key, g5c_json_new_obj());
    g5c_json_set_int(o, "sst", s->sst);
    if (s->has_sd) {
        char sd[7];
        snprintf(sd, sizeof sd, "%06X", s->sd & 0xffffffu);
        g5c_json_set_str(o, "sd", sd);
    }
}

bool amf_snssai_from_json(const g5c_json *j, nas_snssai *out)
{
    int64_t sst;
    const char *sd;
    memset(out, 0, sizeof *out);
    if (!g5c_json_get_int(j, "sst", &sst) || sst < 0 || sst > 255)
        return false;
    out->sst = (uint8_t)sst;
    sd = g5c_json_get_str(j, "sd");
    if (sd != NULL) {
        char *end;
        unsigned long v;
        if (strlen(sd) != 6)
            return false;
        v = strtoul(sd, &end, 16);
        if (*end != 0)
            return false;
        out->has_sd = true;
        out->sd = (uint32_t)v;
    }
    return true;
}

bool amf_snssai_eq(const nas_snssai *a, const nas_snssai *b)
{
    return a->sst == b->sst && a->has_sd == b->has_sd && (!a->has_sd || a->sd == b->sd);
}

bool amf_snssai_in(const nas_snssai *list, size_t n, const nas_snssai *s)
{
    for (size_t i = 0; i < n; i++)
        if (amf_snssai_eq(&list[i], s))
            return true;
    return false;
}

/* "imsi-001010000000001" -> "001010000000001" */
void amf_supi_digits(const char *supi, char *out, size_t cap)
{
    const char *p = strchr(supi, '-');
    snprintf(out, cap, "%s", p != NULL ? p + 1 : supi);
}
