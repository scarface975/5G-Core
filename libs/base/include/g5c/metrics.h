/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Prometheus-style metrics registry (text exposition format 0.0.4): counters, gauges, histograms with labels.
 * Thread-safe. Metric handles are owned by the registry and stay valid until g5c_registry_free(). */
#ifndef G5C_METRICS_H
#define G5C_METRICS_H

#include <stddef.h>
#include <stdint.h>

typedef struct g5c_registry g5c_registry;
typedef struct g5c_counter g5c_counter;
typedef struct g5c_gauge g5c_gauge;
typedef struct g5c_histogram g5c_histogram;
typedef struct {
    const char *k, *v;
} g5c_label;

g5c_registry *g5c_registry_new(void);
void g5c_registry_free(g5c_registry *r);

/* Get or create a series. A name reused with another metric kind yields a detached metric (never NULL). */
g5c_counter *g5c_counter_get(g5c_registry *r, const char *name, const char *help, const g5c_label *labels,
                             size_t nlabels);
g5c_gauge *g5c_gauge_get(g5c_registry *r, const char *name, const char *help, const g5c_label *labels,
                         size_t nlabels);
/* Default latency buckets (seconds): 0.0005 .. 1.0 */
g5c_histogram *g5c_histogram_get(g5c_registry *r, const char *name, const char *help, const g5c_label *labels,
                                 size_t nlabels);

void g5c_counter_inc(g5c_counter *c);
void g5c_counter_add(g5c_counter *c, uint64_t n);
uint64_t g5c_counter_value(const g5c_counter *c);
void g5c_gauge_set(g5c_gauge *g, int64_t v);
void g5c_gauge_add(g5c_gauge *g, int64_t d);
int64_t g5c_gauge_value(const g5c_gauge *g);
void g5c_histogram_observe(g5c_histogram *h, double secs);
uint64_t g5c_histogram_count(const g5c_histogram *h);

/* Heap string in the Prometheus text format (caller frees). */
char *g5c_registry_render(g5c_registry *r);

/* Convenience: increment a counter with no labels / with labels in one call. */
#define G5C_COUNT(reg, name, help) g5c_counter_inc(g5c_counter_get((reg), (name), (help), NULL, 0))

#endif
