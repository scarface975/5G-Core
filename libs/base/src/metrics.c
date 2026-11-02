/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include "g5c/metrics.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/base.h"

static const double BOUNDS[] = {0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0};
#define NB (sizeof BOUNDS / sizeof BOUNDS[0])

struct g5c_counter {
    _Atomic uint64_t v;
};
struct g5c_gauge {
    _Atomic int64_t v;
};
struct g5c_histogram {
    _Atomic uint64_t buckets[NB + 1];
    _Atomic uint64_t sum_micros;
    _Atomic uint64_t count;
};

typedef enum { K_COUNTER, K_GAUGE, K_HIST } kind_t;
static const char *const KIND_NAME[] = {"counter", "gauge", "histogram"};

typedef struct {
    char *labels; /* rendered, e.g. {code="200",method="GET"} or "" */
    void *metric;
} series_t;

typedef struct {
    char *name, *help;
    kind_t kind;
    series_t *s;
    size_t n, cap;
} family_t;

struct g5c_registry {
    pthread_mutex_t mu;
    family_t *f;
    size_t n, cap;
    void **detached;
    size_t ndet, capdet;
};

g5c_registry *g5c_registry_new(void)
{
    g5c_registry *r = g5c_xcalloc(1, sizeof *r);
    pthread_mutex_init(&r->mu, NULL);
    return r;
}

static void free_metric(kind_t k, void *m)
{
    (void)k;
    free(m);
}

void g5c_registry_free(g5c_registry *r)
{
    if (r == NULL)
        return;
    for (size_t i = 0; i < r->n; i++) {
        for (size_t j = 0; j < r->f[i].n; j++) {
            free(r->f[i].s[j].labels);
            free_metric(r->f[i].kind, r->f[i].s[j].metric);
        }
        free(r->f[i].s);
        free(r->f[i].name);
        free(r->f[i].help);
    }
    for (size_t i = 0; i < r->ndet; i++)
        free(r->detached[i]);
    free(r->detached);
    free(r->f);
    pthread_mutex_destroy(&r->mu);
    free(r);
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static char *label_set(const g5c_label *l, size_t n)
{
    g5c_bytes b;
    char **parts;
    if (n == 0)
        return g5c_xstrdup("");
    parts = g5c_xcalloc(n, sizeof *parts);
    for (size_t i = 0; i < n; i++) {
        g5c_bytes v;
        g5c_bytes_init(&v);
        g5c_bytes_printf(&v, "%s=\"", l[i].k);
        for (const char *p = l[i].v; *p; p++) {
            if (*p == '\\')
                g5c_bytes_append_str(&v, "\\\\");
            else if (*p == '"')
                g5c_bytes_append_str(&v, "\\\"");
            else if (*p == '\n')
                g5c_bytes_append_str(&v, "\\n");
            else
                g5c_bytes_putc(&v, *p);
        }
        g5c_bytes_putc(&v, '"');
        parts[i] = g5c_bytes_take(&v, NULL);
    }
    qsort(parts, n, sizeof *parts, cmp_str);
    g5c_bytes_init(&b);
    g5c_bytes_putc(&b, '{');
    for (size_t i = 0; i < n; i++) {
        if (i)
            g5c_bytes_putc(&b, ',');
        g5c_bytes_append_str(&b, parts[i]);
        free(parts[i]);
    }
    g5c_bytes_putc(&b, '}');
    free(parts);
    return g5c_bytes_take(&b, NULL);
}

static size_t metric_size(kind_t k)
{
    return k == K_COUNTER ? sizeof(g5c_counter) : k == K_GAUGE ? sizeof(g5c_gauge) : sizeof(g5c_histogram);
}

static void *series(g5c_registry *r, const char *name, const char *help, kind_t kind, const g5c_label *l,
                    size_t n)
{
    char *key = label_set(l, n);
    family_t *fam = NULL;
    void *m = NULL;
    pthread_mutex_lock(&r->mu);
    for (size_t i = 0; i < r->n; i++)
        if (strcmp(r->f[i].name, name) == 0) {
            fam = &r->f[i];
            break;
        }
    if (fam == NULL) {
        if (r->n == r->cap) {
            r->cap = r->cap ? r->cap * 2 : 16;
            r->f = g5c_xrealloc(r->f, r->cap * sizeof *r->f);
        }
        fam = &r->f[r->n++];
        memset(fam, 0, sizeof *fam);
        fam->name = g5c_xstrdup(name);
        fam->help = g5c_xstrdup(help);
        fam->kind = kind;
    }
    if (fam->kind != kind) { /* programming error: hand back a detached metric rather than crash */
        m = g5c_xcalloc(1, metric_size(kind));
        if (r->ndet == r->capdet) {
            r->capdet = r->capdet ? r->capdet * 2 : 8;
            r->detached = g5c_xrealloc(r->detached, r->capdet * sizeof *r->detached);
        }
        r->detached[r->ndet++] = m;
        free(key);
        pthread_mutex_unlock(&r->mu);
        return m;
    }
    for (size_t i = 0; i < fam->n; i++)
        if (strcmp(fam->s[i].labels, key) == 0) {
            m = fam->s[i].metric;
            break;
        }
    if (m == NULL) {
        if (fam->n == fam->cap) {
            fam->cap = fam->cap ? fam->cap * 2 : 4;
            fam->s = g5c_xrealloc(fam->s, fam->cap * sizeof *fam->s);
        }
        m = g5c_xcalloc(1, metric_size(kind));
        fam->s[fam->n].labels = key;
        fam->s[fam->n].metric = m;
        fam->n++;
        key = NULL;
    }
    pthread_mutex_unlock(&r->mu);
    free(key);
    return m;
}

g5c_counter *g5c_counter_get(g5c_registry *r, const char *name, const char *help, const g5c_label *l, size_t n)
{
    return series(r, name, help, K_COUNTER, l, n);
}

g5c_gauge *g5c_gauge_get(g5c_registry *r, const char *name, const char *help, const g5c_label *l, size_t n)
{
    return series(r, name, help, K_GAUGE, l, n);
}

g5c_histogram *g5c_histogram_get(g5c_registry *r, const char *name, const char *help, const g5c_label *l,
                                 size_t n)
{
    return series(r, name, help, K_HIST, l, n);
}

void g5c_counter_inc(g5c_counter *c)
{
    atomic_fetch_add_explicit(&c->v, 1, memory_order_relaxed);
}

void g5c_counter_add(g5c_counter *c, uint64_t n)
{
    atomic_fetch_add_explicit(&c->v, n, memory_order_relaxed);
}

uint64_t g5c_counter_value(const g5c_counter *c)
{
    return atomic_load_explicit(&((g5c_counter *)(uintptr_t)c)->v, memory_order_relaxed);
}

void g5c_gauge_set(g5c_gauge *g, int64_t v)
{
    atomic_store_explicit(&g->v, v, memory_order_relaxed);
}

void g5c_gauge_add(g5c_gauge *g, int64_t d)
{
    atomic_fetch_add_explicit(&g->v, d, memory_order_relaxed);
}

int64_t g5c_gauge_value(const g5c_gauge *g)
{
    return atomic_load_explicit(&((g5c_gauge *)(uintptr_t)g)->v, memory_order_relaxed);
}

void g5c_histogram_observe(g5c_histogram *h, double secs)
{
    size_t i = 0;
    while (i < NB && !(secs <= BOUNDS[i]))
        i++;
    atomic_fetch_add_explicit(&h->buckets[i], 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&h->sum_micros, secs > 0 ? (uint64_t)(secs * 1e6) : 0, memory_order_relaxed);
    atomic_fetch_add_explicit(&h->count, 1, memory_order_relaxed);
}

uint64_t g5c_histogram_count(const g5c_histogram *h)
{
    return atomic_load_explicit(&((g5c_histogram *)(uintptr_t)h)->count, memory_order_relaxed);
}

typedef struct {
    const char *labels;
    void *metric;
} sref;

static int cmp_series(const void *a, const void *b)
{
    return strcmp(((const sref *)a)->labels, ((const sref *)b)->labels);
}

static int cmp_fam(const void *a, const void *b)
{
    return strcmp((*(family_t *const *)a)->name, (*(family_t *const *)b)->name);
}

static void le_labels(g5c_bytes *o, const char *labels, const char *le)
{
    if (labels[0] == '\0') {
        g5c_bytes_printf(o, "{le=\"%s\"}", le);
    } else {
        size_t n = strlen(labels);
        g5c_bytes_append(o, labels, n - 1); /* drop the closing brace */
        g5c_bytes_printf(o, ",le=\"%s\"}", le);
    }
}

char *g5c_registry_render(g5c_registry *r)
{
    g5c_bytes o;
    family_t **order;
    g5c_bytes_init(&o);
    pthread_mutex_lock(&r->mu);
    order = g5c_xcalloc(r->n ? r->n : 1, sizeof *order);
    for (size_t i = 0; i < r->n; i++)
        order[i] = &r->f[i];
    qsort(order, r->n, sizeof *order, cmp_fam);
    for (size_t i = 0; i < r->n; i++) {
        family_t *f = order[i];
        sref *ss = g5c_xcalloc(f->n ? f->n : 1, sizeof *ss);
        for (size_t j = 0; j < f->n; j++) {
            ss[j].labels = f->s[j].labels;
            ss[j].metric = f->s[j].metric;
        }
        qsort(ss, f->n, sizeof *ss, cmp_series);
        g5c_bytes_printf(&o, "# HELP %s %s\n# TYPE %s %s\n", f->name, f->help, f->name, KIND_NAME[f->kind]);
        for (size_t j = 0; j < f->n; j++) {
            if (f->kind == K_COUNTER) {
                g5c_bytes_printf(&o, "%s%s %llu\n", f->name, ss[j].labels,
                                 (unsigned long long)g5c_counter_value(ss[j].metric));
            } else if (f->kind == K_GAUGE) {
                g5c_bytes_printf(&o, "%s%s %lld\n", f->name, ss[j].labels,
                                 (long long)g5c_gauge_value(ss[j].metric));
            } else {
                g5c_histogram *h = ss[j].metric;
                uint64_t cum = 0;
                for (size_t k = 0; k < NB; k++) {
                    char le[32];
                    cum += atomic_load_explicit(&h->buckets[k], memory_order_relaxed);
                    snprintf(le, sizeof le, "%g", BOUNDS[k]);
                    g5c_bytes_printf(&o, "%s_bucket", f->name);
                    le_labels(&o, ss[j].labels, le);
                    g5c_bytes_printf(&o, " %llu\n", (unsigned long long)cum);
                }
                cum += atomic_load_explicit(&h->buckets[NB], memory_order_relaxed);
                g5c_bytes_printf(&o, "%s_bucket", f->name);
                le_labels(&o, ss[j].labels, "+Inf");
                g5c_bytes_printf(&o, " %llu\n", (unsigned long long)cum);
                g5c_bytes_printf(&o, "%s_sum%s %g\n", f->name, ss[j].labels,
                                 (double)atomic_load_explicit(&h->sum_micros, memory_order_relaxed) / 1e6);
                g5c_bytes_printf(&o, "%s_count%s %llu\n", f->name, ss[j].labels,
                                 (unsigned long long)g5c_histogram_count(h));
            }
        }
        free(ss);
    }
    free(order);
    pthread_mutex_unlock(&r->mu);
    return g5c_bytes_take(&o, NULL);
}
