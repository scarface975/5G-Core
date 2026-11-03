/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Overload and rate control of a producer (TS 29.500 5.2.7.2, 6.3 load control, 6.4 overload control): a token bucket per client address in front of every route;
 * a request above the rate gets 429 with Retry-After and a 3gpp-Sbi-Oci header; with `capacity_rps` every response carries 3gpp-Sbi-Lci. Health and metrics are never limited */
#ifndef G5C_OVERLOAD_H
#define G5C_OVERLOAD_H

#include "g5c/config.h"
#include "g5c/metrics.h"
#include "g5c/sbi.h"

typedef struct g5c_overload g5c_overload;

g5c_overload *g5c_overload_new(const g5c_overload_cfg *cfg, const char *instance_id, g5c_registry *metrics);
/* Becomes the outermost guard of the router: the older one runs for the requests that pass. */
void g5c_overload_attach(g5c_overload *o, g5c_router *router);
void g5c_overload_free(g5c_overload *o);
/* New limits for the requests that follow (a configuration reload); the buckets of the clients are kept. A disabled configuration lets everything through. */
void g5c_overload_reconfigure(g5c_overload *o, const g5c_overload_cfg *cfg);

#endif
