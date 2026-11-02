/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* OAuth 2.0 access tokens of the NRF between network functions (TS 33.501 13.4.1, TS 29.510 5.4 and 6.3.5.2.4).
 *
 *   Producer (the OAuth2 resource server): g5c_oauth_rs. A guard on the NF's router: a request for one of the NF's own services needs a bearer token that the NRF signed
 *   (checked against the NRF's key set, /oauth2/jwks, fetched on first use and again when the key id is unknown or the set is old), that has not expired, whose audience is
 *   this NF's type or instance id, and whose scope holds the service the request is for. Requests that are not for a service of the NF (health, metrics, callbacks, the
 *   admin and northbound APIs) and routes that authenticate their callers themselves (G5C_ROUTE_OWN_AUTH) are left to their own handling.
 *
 *   Consumer (the OAuth2 client): g5c_oauth_client. A token provider for the SBI client: for a request to a service of another NF it asks the NRF for a token (client credentials,
 *   scope = the service, target = the NF type that offers it), keeps it until shortly before it expires and sends it. A request that has an Authorization header already is left alone. */
#ifndef G5C_OAUTH_H
#define G5C_OAUTH_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/metrics.h"
#include "g5c/sbi.h"

typedef struct g5c_oauth_rs g5c_oauth_rs;
typedef struct g5c_oauth_client g5c_oauth_client;

/* ---- producer ---------------------------------------------------------------------------------------------------------------------------------------------- */

/* `client` fetches the key set at `nrf_uri`; `services` are the NF's service names (the first segment of their paths); `metrics` may be NULL. */
g5c_oauth_rs *g5c_oauth_rs_new(g5c_client *client, const char *nrf_uri, const char *own_type, const char *own_instance_id, const char *const *services, size_t nservices,
                               unsigned leeway_s, unsigned jwks_refresh_s, g5c_registry *metrics);
void g5c_oauth_rs_free(g5c_oauth_rs *rs);
/* Puts the check in front of the router's own guard (which still runs for what passes). The router must outlive `rs` use; `rs` is freed by the caller after the router. */
void g5c_oauth_rs_attach(g5c_oauth_rs *rs, g5c_router *router);
/* The guard itself (for tests): 0 to go on, non-zero after filling `resp`. */
int g5c_oauth_rs_guard(void *rs, const g5c_req *req, g5c_resp *resp);

/* ---- consumer ---------------------------------------------------------------------------------------------------------------------------------------------- */

g5c_oauth_client *g5c_oauth_client_new(g5c_client *client, const char *nrf_uri, const char *own_type, const char *own_instance_id, g5c_registry *metrics);
void g5c_oauth_client_free(g5c_oauth_client *c);
/* A g5c_token_fn: the token for a request to `url`, or NULL when the request needs none (not a service of another NF) or the NRF refused. */
char *g5c_oauth_client_token(void *client, const char *method, const char *url);
/* A g5c_token_reject_fn: the producer answered 401 to the token for this URL: drop it and let the next call ask the NRF again (the NRF's key changed, the token was revoked). */
void g5c_oauth_client_reject(void *client, const char *method, const char *url);

/* The NF type that offers a service (nudm-sdm: UDM); NULL for names that are not services of the 5GC. */
const char *g5c_oauth_service_nf_type(const char *service);

#endif
