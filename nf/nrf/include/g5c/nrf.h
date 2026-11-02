/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NRF: the NF repository of the service-based architecture (3GPP TS 23.501 6.2.6, TS 29.510).
 *   Nnrf_NFManagement  /nnrf-nfm/v1   register, update (replace, patch, heart-beat), deregister, retrieve, list, subscribe / notify
 *   Nnrf_NFDiscovery   /nnrf-disc/v1  search over the registered profiles
 *   Nnrf_AccessToken   /oauth2/token  OAuth2 client-credentials tokens (ES256 JWT, TS 33.501 13.4.1)
 * Profiles and subscriptions are held in memory and written to a state file (write-behind) so that a restart keeps the registry. */
#ifndef G5C_NRF_H
#define G5C_NRF_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/jwt.h"
#include "g5c/nfcore.h"
#include "g5c/sbi.h"

typedef struct nrf nrf;

/* `cfg` is the whole configuration document (the nrf: block is read from it); `nf` supplies the metrics registry, the outgoing client and the
 * instance id. NULL with err on an invalid configuration. */
nrf *nrf_from_config(const g5c_json *cfg, g5c_nf *nf, char *err, size_t errcap);
/* Starts the monitor and notification threads and restores the state file. */
int nrf_start(nrf *n, char *err, size_t errcap);
g5c_router *nrf_router(nrf *n);
/* Only the routes (n may be NULL: the route table does not depend on state; used to document the interfaces). */
void nrf_routes(g5c_router *r, nrf *n);
/* scheme://authority under which this NRF is reached (used in notifications); set it once the listener port is known. */
void nrf_set_self_uri(nrf *n, const char *uri);
/* the same, only when no self_uri was configured */
void nrf_set_self_uri_default(nrf *n, const char *uri);
/* Stops the threads, writes the state file, frees. */
void nrf_destroy(nrf *n);

/* ---- introspection (tests, tools) ------------------------------------------------------------------------------------------------------ */

size_t nrf_profile_count(nrf *n);
size_t nrf_subscription_count(nrf *n);
/* nfStatus of a registered instance into out (>= 16 bytes); false when not registered. */
bool nrf_profile_status(nrf *n, const char *nf_instance_id, char *out, size_t cap);
/* The token-signing public key as a JWK (caller frees); NULL when OAuth2 is disabled. */
g5c_json *nrf_jwk(nrf *n);

/* The service names of the NRF itself, for the registration of an NRF with another NRF (TS 29.510 5.2.2.2.3). */
#define NRF_SVC_NFM "nnrf-nfm"
#define NRF_SVC_DISC "nnrf-disc"
#define NRF_SVC_OAUTH2 "nnrf-oauth2"

#endif
