/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NSSF: the Network Slice Selection Function (3GPP TS 23.501 6.2.14, 5.15; TS 29.531).
 *   Nnssf_NSSelection        /nnssf-nsselection/v2        the Allowed and Configured NSSAI, the rejected S-NSSAIs, the target AMF set, the NSI
 *                                                        (registration, PDU session establishment, UE configuration update, PDN connection)
 *   Nnssf_NSSAIAvailability  /nnssf-nssaiavailability/v1  the S-NSSAIs each AMF supports per tracking area (update, delete), subscriptions to
 *                                                        changes of their availability and the notifications
 * The slices of the PLMN (which S-NSSAI, which NRF serves its network functions, in which tracking areas it exists), the AMF sets and the roaming
 * mappings are configuration; the NSSAI availability reported by the AMFs and the subscriptions are state, kept in a file when one is configured. */
#ifndef G5C_NSSF_H
#define G5C_NSSF_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/nfcore.h"
#include "g5c/sbi.h"

typedef struct nssf nssf;
typedef struct nssf_cfg nssf_cfg;

#define NSSF_SVC_NSSELECTION "nnssf-nsselection"
#define NSSF_SVC_NSSAIAVAILABILITY "nnssf-nssaiavailability"

/* The `nssf:` block of the configuration, validated against `serving_mcc` / `serving_mnc` (the PLMN of the common sections) and `nrf_uri` */
nssf_cfg *nssf_cfg_parse(const g5c_json *root, const char *serving_mcc, const char *serving_mnc, const char *nrf_uri, char *err, size_t errcap);
void nssf_cfg_free(nssf_cfg *c);

/* `cfg` is consumed. `client` sends the notifications (NULL: subscriptions are kept, nothing is sent); `metrics` may be NULL. */
nssf *nssf_new(nssf_cfg *cfg, g5c_client *client, g5c_registry *metrics);
/* the whole configuration document and the NF context */
nssf *nssf_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap);
/* Restores the state file and starts the worker thread. */
int nssf_start(nssf *n, char *err, size_t errcap);
g5c_router *nssf_router(nssf *n);
/* Stops the worker, writes the state file, frees. */
void nssf_destroy(nssf *n);

/* ---- introspection (tests, tools) ---- */
size_t nssf_nf_count(nssf *n);           /* NFs that hold NSSAI availability */
size_t nssf_subscription_count(nssf *n);

#endif
