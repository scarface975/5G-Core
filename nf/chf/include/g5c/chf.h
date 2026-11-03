/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* CHF: the Charging Function (3GPP TS 32.240, TS 32.290; Nchf_ConvergedCharging of TS 32.291) with volume quota grants and per-subscriber balances */
#ifndef G5C_CHF_H
#define G5C_CHF_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/nfcore.h"
#include "g5c/sbi.h"

typedef struct chf chf;

#define CHF_SVC_CHARGING "nchf-convergedcharging"

/* NULL with err on an invalid configuration. `root` is the whole configuration; the `chf:` block is optional. `nf` may be NULL (tests). */
chf *chf_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap);
g5c_router *chf_router(chf *c);
void chf_destroy(chf *c);

/* ---- introspection (tests, tools) ---- */
size_t chf_session_count(chf *c);
/* remaining volume of a subscriber in bytes; UINT64_MAX when unlimited */
unsigned long long chf_balance(chf *c, const char *supi);

#endif
