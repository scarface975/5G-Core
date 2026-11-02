/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NEF: the Network Exposure Function (3GPP TS 23.501 6.2.5, TS 23.502 4.15; northbound APIs of TS 29.522 and TS 29.122).
 *   3gpp-traffic-influence  /3gpp-traffic-influence/v1/{afId}/subscriptions   an AF's traffic influence requirements, stored as application (influence)
 *                                                                              data in the UDR for the SMF / PCF to apply (TS 29.522 4.4.7.3)
 *   3gpp-monitoring-event   /3gpp-monitoring-event/v1/{scsAsId}/subscriptions  loss of connectivity, UE reachability and location reporting of a UE,
 *                                                                              from the AMF's Namf_EventExposure (TS 29.122 4.4.2, TS 29.522 4.4.2)
 *   3gpp-as-session-with-qos /3gpp-as-session-with-qos/v1/{afId}/subscriptions  a QoS for flows of a UE, authorized at the PCF (Npcf_PolicyAuthorization, TS 29.514)
 * An AF is an entry of the configuration (its identifier, its bearer token, the APIs it may use, the hosts its notifications may go to); the subscriptions
 * are state, kept in a file when one is configured. The functions behind the NEF (UDR, UDM, AMF) are found through the NRF unless the configuration names them. */
#ifndef G5C_NEF_H
#define G5C_NEF_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/nfcore.h"
#include "g5c/sbi.h"

typedef struct nef nef;
typedef struct nef_cfg nef_cfg;

#define NEF_API_TRAFFIC_INFLUENCE "3gpp-traffic-influence"
#define NEF_API_MONITORING_EVENT "3gpp-monitoring-event"
#define NEF_API_AS_SESSION_WITH_QOS "3gpp-as-session-with-qos"

/* The `nef:` block of the configuration. `callback_uri` (may be NULL) is the root at which the NEF's own callback endpoints are reachable by the AMF
 * (the default is the address of the SBI listener). NULL with err on an invalid configuration. */
nef_cfg *nef_cfg_parse(const g5c_json *root, const char *serving_mcc, const char *serving_mnc, const char *default_callback_uri, char *err, size_t errcap);
void nef_cfg_free(nef_cfg *c);

/* `cfg` is consumed. `client` calls the other functions and delivers the notifications; `disc` finds them (may be NULL: then only configured
 * addresses work); `metrics` may be NULL. */
nef *nef_new(nef_cfg *cfg, g5c_client *client, g5c_disc *disc, g5c_registry *metrics);
/* the whole configuration document and the NF context */
nef *nef_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap);
/* Restores the state file and starts the worker thread. */
int nef_start(nef *n, char *err, size_t errcap);
g5c_router *nef_router(nef *n);
/* Stops the worker, writes the state file, frees. */
void nef_destroy(nef *n);

/* ---- introspection (tests, tools) ------------------------------------------------------------------------------------------------------ */
size_t nef_subscription_count(nef *n, const char *api);

#endif
