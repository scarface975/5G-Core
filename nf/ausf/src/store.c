/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The tables of the AUSF: authentication contexts (by id, and by UE and serving network while pending) and security contexts (by SUPI). Every function that
 * says so expects ausf.mu to be held; the others take it. */
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "priv.h"

/* ---- hmap ---------------------------------------------------------------------------------------------------------------------------------------- */

static size_t hash_str(const char *s)
{
    size_t h = 1469598103934665603ULL; /* FNV-1a */
    for (; *s; s++)
        h = (h ^ (unsigned char)*s) * 1099511628211ULL;
    return h;
}

void hmap_init(hmap *h)
{
    h->nb = 64;
    h->n = 0;
    h->b = g5c_xcalloc(h->nb, sizeof *h->b);
}

void hmap_clear(hmap *h)
{
    for (size_t i = 0; i < h->nb; i++)
        for (hnode *n = h->b[i], *nx; n != NULL; n = nx) {
            nx = n->next;
            free(n->key);
            free(n);
        }
    free(h->b);
    h->b = NULL;
    h->nb = h->n = 0;
}

void *hmap_get(const hmap *h, const char *key)
{
    for (hnode *n = h->b[hash_str(key) & (h->nb - 1)]; n != NULL; n = n->next)
        if (strcmp(n->key, key) == 0)
            return n->val;
    return NULL;
}

static void grow(hmap *h)
{
    size_t nb = h->nb * 2;
    hnode **b = g5c_xcalloc(nb, sizeof *b);
    for (size_t i = 0; i < h->nb; i++)
        for (hnode *n = h->b[i], *nx; n != NULL; n = nx) {
            size_t k = hash_str(n->key) & (nb - 1);
            nx = n->next;
            n->next = b[k];
            b[k] = n;
        }
    free(h->b);
    h->b = b;
    h->nb = nb;
}

void hmap_put(hmap *h, const char *key, void *val)
{
    size_t k = hash_str(key) & (h->nb - 1);
    hnode *n;
    for (n = h->b[k]; n != NULL; n = n->next)
        if (strcmp(n->key, key) == 0) {
            n->val = val;
            return;
        }
    n = g5c_xmalloc(sizeof *n);
    n->key = g5c_xstrdup(key);
    n->val = val;
    n->next = h->b[k];
    h->b[k] = n;
    if (++h->n > h->nb)
        grow(h);
}

void *hmap_del(hmap *h, const char *key)
{
    hnode **pp = &h->b[hash_str(key) & (h->nb - 1)];
    for (; *pp != NULL; pp = &(*pp)->next)
        if (strcmp((*pp)->key, key) == 0) {
            hnode *n = *pp;
            void *v = n->val;
            *pp = n->next;
            free(n->key);
            free(n);
            h->n--;
            return v;
        }
    return NULL;
}

void hmap_each(const hmap *h, void (*fn)(const char *key, void *val, void *arg), void *arg)
{
    for (size_t i = 0; i < h->nb; i++)
        for (hnode *n = h->b[i]; n != NULL; n = n->next)
            fn(n->key, n->val, arg);
}

/* ---- lists ----------------------------------------------------------------------------------------------------------------------------------------- */

static void list_push(clist *l, ausf_ctx *c)
{
    c->lnext = NULL;
    c->lprev = l->tail;
    if (l->tail != NULL)
        l->tail->lnext = c;
    else
        l->head = c;
    l->tail = c;
    l->n++;
}

static void list_unlink(clist *l, ausf_ctx *c)
{
    if (c->lprev != NULL)
        c->lprev->lnext = c->lnext;
    else
        l->head = c->lnext;
    if (c->lnext != NULL)
        c->lnext->lprev = c->lprev;
    else
        l->tail = c->lprev;
    c->lprev = c->lnext = NULL;
    l->n--;
}

/* ---- contexts ----------------------------------------------------------------------------------------------------------------------------------- */

ausf_ctx *ctx_new(const char *id_in, const char *snn)
{
    ausf_ctx *c = g5c_xcalloc(1, sizeof *c);
    if (g5c_uuid_v4(c->id) != 0) {
        free(c);
        return NULL;
    }
    c->id_in = g5c_xstrdup(id_in);
    c->snn = g5c_xstrdup(snn);
    c->key = g5c_xasprintf("%s|%s", id_in, snn);
    c->created = g5c_now_seconds();
    return c;
}

void ctx_free(ausf_ctx *c)
{
    if (c == NULL)
        return;
    OPENSSL_cleanse(c->xres_star, sizeof c->xres_star);
    OPENSSL_cleanse(c->kausf, sizeof c->kausf);
    OPENSSL_cleanse(c->xres, sizeof c->xres);
    OPENSSL_cleanse(&c->keys, sizeof c->keys);
    free(c->id_in);
    free(c->supi);
    free(c->snn);
    free(c->key);
    free(c->auth_event_id);
    free(c);
}

/* removes c from every table; the caller owns it afterwards */
static void detach(ausf *a, ausf_ctx *c)
{
    hmap_del(&a->by_id, c->id);
    if (c->st != ST_DONE) {
        if (hmap_get(&a->by_key, c->key) == c)
            hmap_del(&a->by_key, c->key);
        list_unlink(&a->pending, c);
    } else {
        list_unlink(&a->done, c);
    }
}

void store_reap(ausf *a, double now)
{
    while (a->pending.head != NULL && a->pending.head->expires <= now) {
        ausf_ctx *c = a->pending.head;
        detach(a, c);
        ctx_free(c);
        ausf_count(a, "g5c_ausf_contexts_expired_total", "Authentication contexts that timed out.", NULL, NULL);
    }
    while (a->done.head != NULL && a->done.head->expires <= now) {
        ausf_ctx *c = a->done.head;
        detach(a, c);
        ctx_free(c);
    }
}

bool store_insert(ausf *a, ausf_ctx *c)
{
    double now = g5c_now_seconds();
    ausf_ctx *old;
    pthread_mutex_lock(&a->mu);
    store_reap(a, now);
    c->st = c->method == M_5GAKA ? ST_AKA_WAIT : ST_EAP_CHALLENGE;
    c->expires = now + a->o.ctx_lifetime_s;
    /* TS 29.509 5.2.2.2.2: one confirmation per UE and serving network, a new start replaces the old one */
    old = hmap_get(&a->by_key, c->key);
    if (old != NULL) {
        detach(a, old);
        ctx_free(old);
    }
    if (a->pending.n + a->done.n >= a->o.max_contexts) {
        if (a->done.head != NULL) {
            ausf_ctx *e = a->done.head;
            detach(a, e);
            ctx_free(e);
        } else {
            pthread_mutex_unlock(&a->mu);
            return false;
        }
    }
    hmap_put(&a->by_id, c->id, c);
    hmap_put(&a->by_key, c->key, c);
    list_push(&a->pending, c);
    store_gauges(a);
    pthread_mutex_unlock(&a->mu);
    return true;
}

bool store_reinsert(ausf *a, ausf_ctx *c)
{
    pthread_mutex_lock(&a->mu);
    /* the context keeps its original expiry: a session cannot be kept open by answering slowly */
    if (c->expires <= g5c_now_seconds()) {
        pthread_mutex_unlock(&a->mu);
        return false;
    }
    {
        ausf_ctx *old = hmap_get(&a->by_key, c->key);
        if (old != NULL && old != c) {
            /* a newer start for the same UE and serving network came in while this one was handled: that one wins */
            pthread_mutex_unlock(&a->mu);
            return false;
        }
    }
    hmap_put(&a->by_id, c->id, c);
    hmap_put(&a->by_key, c->key, c);
    /* keep the list ordered by expiry: walk back from the tail */
    {
        ausf_ctx *p = a->pending.tail;
        while (p != NULL && p->expires > c->expires)
            p = p->lprev;
        if (p == NULL) {
            c->lprev = NULL;
            c->lnext = a->pending.head;
            if (a->pending.head != NULL)
                a->pending.head->lprev = c;
            else
                a->pending.tail = c;
            a->pending.head = c;
        } else {
            c->lprev = p;
            c->lnext = p->lnext;
            if (p->lnext != NULL)
                p->lnext->lprev = c;
            else
                a->pending.tail = c;
            p->lnext = c;
        }
        a->pending.n++;
    }
    store_gauges(a);
    pthread_mutex_unlock(&a->mu);
    return true;
}

ausf_ctx *store_take(ausf *a, const char *id)
{
    ausf_ctx *c;
    pthread_mutex_lock(&a->mu);
    store_reap(a, g5c_now_seconds());
    c = hmap_get(&a->by_id, id);
    if (c != NULL)
        detach(a, c);
    store_gauges(a);
    pthread_mutex_unlock(&a->mu);
    return c;
}

void store_finish(ausf *a, ausf_ctx *c)
{
    double now = g5c_now_seconds();
    OPENSSL_cleanse(c->xres_star, sizeof c->xres_star);
    OPENSSL_cleanse(c->kausf, sizeof c->kausf);
    OPENSSL_cleanse(c->xres, sizeof c->xres);
    OPENSSL_cleanse(&c->keys, sizeof c->keys);
    c->st = ST_DONE;
    c->expires = now + a->o.result_retention_s;
    pthread_mutex_lock(&a->mu);
    store_reap(a, now);
    if (a->pending.n + a->done.n >= a->o.max_contexts && a->done.head != NULL) {
        ausf_ctx *e = a->done.head;
        detach(a, e);
        ctx_free(e);
    }
    hmap_put(&a->by_id, c->id, c);
    list_push(&a->done, c);
    store_gauges(a);
    pthread_mutex_unlock(&a->mu);
}

/* ---- security contexts ------------------------------------------------------------------------------------------------------------------------- */

static void ue_free(ausf_ue *u)
{
    if (u == NULL)
        return;
    OPENSSL_cleanse(u->kausf, sizeof u->kausf);
    free(u->supi);
    free(u->snn);
    free(u->last_auth_id);
    free(u);
}

void ue_mark_dirty(ausf *a)
{
    pthread_mutex_lock(&a->mu);
    a->dirty = true;
    pthread_cond_signal(&a->cv);
    pthread_mutex_unlock(&a->mu);
}

void ue_store(ausf *a, const char *supi, const char *snn, ausf_method m, const uint8_t kausf[32], const char *auth_id)
{
    ausf_ue *u;
    pthread_mutex_lock(&a->mu);
    u = hmap_get(&a->ues, supi);
    if (u == NULL) {
        if (a->ues.n >= a->o.max_ue_contexts) {
            /* the table is full: the SoR / UPU protection of this UE is not available, its authentication still succeeded */
            pthread_mutex_unlock(&a->mu);
            G5C_LOGW(AUSF_LOG, "security context table full (%zu): %s not stored", a->o.max_ue_contexts, supi);
            ausf_count(a, "g5c_ausf_ue_context_overflow_total", "Security contexts that could not be stored.", NULL, NULL);
            return;
        }
        u = g5c_xcalloc(1, sizeof *u);
        u->supi = g5c_xstrdup(supi);
        hmap_put(&a->ues, supi, u);
    }
    free(u->snn);
    free(u->last_auth_id);
    u->snn = g5c_xstrdup(snn);
    u->last_auth_id = auth_id != NULL ? g5c_xstrdup(auth_id) : NULL;
    memcpy(u->kausf, kausf, 32);
    u->method = m;
    u->counter_sor = 1; /* TS 33.501 6.14.2.3 and 6.15.2.2: back to 0x0001 when a new KAUSF is stored */
    u->counter_upu = 1;
    u->t_ms = g5c_unix_millis();
    u->gen++;
    a->dirty = true;
    store_gauges(a);
    pthread_cond_signal(&a->cv);
    pthread_mutex_unlock(&a->mu);
}

bool ue_is_current(ausf *a, const char *supi, const char *auth_id)
{
    ausf_ue *u;
    bool r;
    pthread_mutex_lock(&a->mu);
    u = hmap_get(&a->ues, supi);
    r = u != NULL && u->last_auth_id != NULL && strcmp(u->last_auth_id, auth_id) == 0;
    pthread_mutex_unlock(&a->mu);
    return r;
}

bool ue_drop(ausf *a, const char *supi)
{
    ausf_ue *u;
    pthread_mutex_lock(&a->mu);
    u = hmap_del(&a->ues, supi);
    if (u != NULL) {
        a->dirty = true;
        store_gauges(a);
        pthread_cond_signal(&a->cv);
    }
    pthread_mutex_unlock(&a->mu);
    ue_free(u);
    return u != NULL;
}

/* used by the writer and by the destructor */
void ausf_ue_free_all(ausf *a);
void ausf_ue_free_all(ausf *a)
{
    for (size_t i = 0; i < a->ues.nb; i++)
        for (hnode *n = a->ues.b[i]; n != NULL; n = n->next)
            ue_free(n->val);
}

bool ausf_ue_kausf(ausf *a, const char *supi, uint8_t kausf[32], uint16_t *counter_sor, uint16_t *counter_upu)
{
    ausf_ue *u;
    bool r = false;
    pthread_mutex_lock(&a->mu);
    u = hmap_get(&a->ues, supi);
    if (u != NULL) {
        memcpy(kausf, u->kausf, 32);
        if (counter_sor != NULL)
            *counter_sor = u->counter_sor;
        if (counter_upu != NULL)
            *counter_upu = u->counter_upu;
        r = true;
    }
    pthread_mutex_unlock(&a->mu);
    return r;
}

bool ausf_ue_set_counters(ausf *a, const char *supi, uint16_t counter_sor, uint16_t counter_upu)
{
    ausf_ue *u;
    bool r = false;
    pthread_mutex_lock(&a->mu);
    u = hmap_get(&a->ues, supi);
    if (u != NULL) {
        u->counter_sor = counter_sor;
        u->counter_upu = counter_upu;
        a->dirty = true;
        pthread_cond_signal(&a->cv);
        r = true;
    }
    pthread_mutex_unlock(&a->mu);
    return r;
}

size_t ausf_context_count(ausf *a)
{
    size_t n;
    pthread_mutex_lock(&a->mu);
    n = a->pending.n + a->done.n;
    pthread_mutex_unlock(&a->mu);
    return n;
}

size_t ausf_ue_count(ausf *a)
{
    size_t n;
    pthread_mutex_lock(&a->mu);
    n = a->ues.n;
    pthread_mutex_unlock(&a->mu);
    return n;
}
