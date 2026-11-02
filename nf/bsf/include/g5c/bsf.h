/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* BSF: the Binding Support Function (3GPP TS 23.501 6.2.? / 7.2.15, TS 23.503; TS 29.521).
 *   Nbsf_Management   /nbsf-management/v1   register (POST /pcfBindings), update (PATCH), deregister (DELETE) and discover (GET) the PCF that holds the SM policy
 *                                           association of a PDU session, by the UE's IPv4 address, IPv6 prefix or MAC address
 * A binding is what a PCF registers when a PDU session gets its address; an NEF or AF that wants to talk to "the PCF of this UE" asks the BSF for it. The bindings
 * are state, kept in a file when one is configured. */
#ifndef G5C_BSF_H
#define G5C_BSF_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/nfcore.h"
#include "g5c/sbi.h"

typedef struct bsf bsf;
typedef struct bsf_cfg bsf_cfg;

#define BSF_SVC_MANAGEMENT "nbsf-management"

/* The `bsf:` block of the configuration (optional; the defaults apply when it is absent). NULL with err on an invalid configuration. */
bsf_cfg *bsf_cfg_parse(const g5c_json *root, char *err, size_t errcap);
void bsf_cfg_free(bsf_cfg *c);

/* `cfg` is consumed; `metrics` may be NULL. */
bsf *bsf_new(bsf_cfg *cfg, g5c_registry *metrics);
bsf *bsf_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap);
/* Restores the state file and starts the thread that writes it. */
int bsf_start(bsf *b, char *err, size_t errcap);
g5c_router *bsf_router(bsf *b);
/* Stops the thread, writes the state file, frees. */
void bsf_destroy(bsf *b);

/* The bsfInfo of the NF profile (TS 29.510 6.1.6.2.? BsfInfo): the DNNs, IP domains and address ranges the BSF serves; NULL when none is configured. Owned by `b`. */
const g5c_json *bsf_nrf_info(const bsf *b);

/* ---- introspection (tests, tools) ------------------------------------------------------------------------------------------------------ */
size_t bsf_binding_count(bsf *b);

#endif
