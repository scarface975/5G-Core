/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* SCP: the Service Communication Proxy (3GPP TS 23.501 6.2.19, Annex E; TS 29.500 6.10).
 * Indirect communication for the other functions: a consumer (or a producer sending a notification) sends its request to the SCP, which forwards it to the
 * producer and returns the answer.
 *   Model C  the request names the producer in 3gpp-Sbi-Target-apiRoot (the consumer did the discovery at the NRF); the SCP forwards it there and, when that
 *            producer cannot be reached, reselects an alternative (3gpp-Sbi-Discovery-* / 3gpp-Sbi-Routing-Binding) or answers 504 TARGET_NF_NOT_REACHABLE
 *   Model D  delegated discovery: the request carries the discovery factors in 3gpp-Sbi-Discovery-* headers; the SCP discovers at the NRF, selects (priority,
 *            capacity, load, health) and forwards, and tells the consumer the producer's instance in 3gpp-Sbi-Producer-Id
 * Notifications and callbacks travel the same way (the consumer's apiRoot is the target). Errors the SCP itself makes are the ProblemDetails of TS 29.500
 * 5.2.7.4 with a Server header naming the SCP; an error it relays gets a Via header. A next-hop SCP can be configured. */
#ifndef G5C_SCP_H
#define G5C_SCP_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/nfcore.h"
#include "g5c/sbi.h"

typedef struct scp scp;
typedef struct scp_cfg scp_cfg;

/* The `scp:` block of the configuration. `name` is the FQDN-like name of this SCP (the common `name`: Server and Via headers), `nrf_uri` the NRF of the common
 * sections (may be NULL: then only Model C and the NRF named by the requests work). NULL with err on an invalid configuration. */
scp_cfg *scp_cfg_parse(const g5c_json *root, const char *name, const char *nrf_uri, char *err, size_t errcap);
void scp_cfg_free(scp_cfg *c);
unsigned scp_cfg_workers(const scp_cfg *c);

/* `cfg` is consumed. `client` carries the forwarded requests (and the discovery); `metrics` may be NULL. */
scp *scp_new(scp_cfg *cfg, g5c_client *client, g5c_registry *metrics);
scp *scp_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap);
g5c_router *scp_router(scp *s);
unsigned scp_workers(const scp *s); /* threads that forward: set G5C_SBI_WORKERS to it before the server starts */
void scp_destroy(scp *s);

/* ---- introspection (tests, tools) ------------------------------------------------------------------------------------------------------ */
size_t scp_quarantined(scp *s);
size_t scp_cached_discoveries(scp *s);

#endif
