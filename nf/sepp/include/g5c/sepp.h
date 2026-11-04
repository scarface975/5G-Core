/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* SEPP: the Security Edge Protection Proxy (3GPP TS 23.501 6.2.17, TS 29.573, TS 33.501 13.2), in the TLS-protected mode of N32-f.
 *
 * A request for another network arrives from a local function with the apiRoot of its target in 3gpp-Sbi-Target-apiRoot. When that apiRoot is in the domain of a partner, the SEPP screens it
 * and sends it to the partner's SEPP (over TLS when the partner's `uri` is https), naming the originating network in 3gpp-Sbi-Originating-Network-Id. A request that arrives from a partner
 * SEPP is screened against that partner's policy and delivered to the local target it names. Screening is per partner: the services it may use, paths it may not touch, a request rate,
 * and the identities it may ask about. Locations that the partner's policy does not allow, and anything addressed to a target the SEPP does not serve, are refused with ProblemDetails.
 *
 * Not in this version: PRINS (application layer protection of N32-f), the N32-c capability exchange and security negotiation (the partner relation is configured), and the IPX
 * provider's modification policy. */
#ifndef G5C_SEPP_H
#define G5C_SEPP_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/nfcore.h"
#include "g5c/sbi.h"

typedef struct sepp sepp;

/* `root` is the whole configuration; `nf` supplies the client, the metrics and the local PLMN. NULL with err on an invalid configuration. */
sepp *sepp_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap);
g5c_router *sepp_router(sepp *s);
void sepp_destroy(sepp *s);

/* ---- introspection (tests, tools) ---- */
size_t sepp_partner_count(const sepp *s);

#endif
