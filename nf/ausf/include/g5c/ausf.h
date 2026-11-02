/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* AUSF: the authentication server function of the service-based architecture (3GPP TS 23.501 6.2.5, TS 33.501 6.1, TS 29.509).
 *   Nausf_UEAuthentication  /nausf-auth/v1          5G AKA and EAP-AKA' (RFC 5448, TS 33.501 Annex F), the confirmation and EAP session resources, the removal of an
 *                                                   authentication result, the clean-up of a security context (deregister) and the FN-RG authentication of Release 16
 *   Nausf_SoRProtection     /nausf-sorprotection/v1 SoR-MAC-IAUSF, CounterSoR, SoR-XMAC-IUE (TS 33.501 6.14, A.17, A.18)
 *   Nausf_UPUProtection     /nausf-upuprotection/v1 UPU-MAC-IAUSF, CounterUPU, UPU-XMAC-IUE (TS 33.501 6.15, A.19, A.20)
 * The authentication vectors come from the UDM (Nudm_UEAuthentication), found through the NRF or by configuration. The latest KAUSF of every SUPI that was
 * authenticated is kept (TS 33.501 6.1.1.2: it is needed by the SoR and UPU protection), optionally in an encrypted state file that survives a restart. */
#ifndef G5C_AUSF_H
#define G5C_AUSF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "g5c/crypto.h"
#include "g5c/metrics.h"
#include "g5c/nfcore.h"
#include "g5c/sbi.h"

#define AUSF_SVC_AUTH "nausf-auth"
#define AUSF_SVC_SOR "nausf-sorprotection"
#define AUSF_SVC_UPU "nausf-upuprotection"

typedef struct ausf ausf;

typedef struct {
    double ctx_lifetime_s;      /* how long a started authentication waits for the UE's answer (30) */
    double result_retention_s;  /* how long a finished authentication stays addressable for its removal (86400) */
    size_t max_contexts;        /* started plus finished authentications held at once (1,000,000) */
    size_t max_ue_contexts;     /* security contexts (KAUSF per SUPI) held at once (2,000,000) */
    char **snn_allow;           /* serving network names that may be used; NULL: every well-formed name (TS 33.501 6.1.2) */
    size_t n_snn_allow;
    bool eap_result_ind;        /* ask the peer for protected success indications (AT_RESULT_IND, RFC 4187 6.2) in EAP-AKA' */
    uint8_t eap_first_id;       /* the identifier of the first EAP request of a session; 0 */
    char *state_file;           /* the security-context store; NULL: memory only */
    uint8_t master_key[32];     /* wraps the KAUSF values in the state file */
    bool has_master_key;
    int udm_timeout_ms;         /* informational: the client of the NF carries the real timeout */
    g5c_json *nrf_info;         /* the ausfInfo registered with the NRF (supiRanges, routingIndicators, groupId); NULL: none */
} ausf_opts;

void ausf_opts_default(ausf_opts *o);
void ausf_opts_free(ausf_opts *o);

/* `udm` is the UDM's apiRoot, or NULL when `disc` (owned, may be NULL) finds it through the NRF */
ausf *ausf_new(g5c_client *client, const char *udm, g5c_disc *disc, const char *self_uri, const char *instance_id, g5c_registry *metrics, const ausf_opts *o);
/* Restores the state file and starts the thread that writes it. 0, or -1 with err filled. */
int ausf_start(ausf *a, char *err, size_t errcap);
/* Stops the thread, writes the state file, frees everything (secrets are wiped). */
void ausf_free(ausf *a);
g5c_router *ausf_router(ausf *a);
/* Only the routes (a may be NULL: the route table does not depend on state; used to document the interfaces). */
void ausf_routes(g5c_router *r, ausf *a);
/* The externally reachable base URI used in links and Location headers; takes effect for requests handled afterwards. */
void ausf_set_self_uri(ausf *a, const char *uri);

/* The daemon: `cfg` is the whole configuration document (the udm: and ausf: blocks are read from it). NULL with err on an invalid configuration */
ausf *ausf_from_config(const g5c_json *cfg, g5c_nf *nf, char *err, size_t errcap);
/* ausfInfo of the NRF profile built from the configuration, NULL when none was configured. Borrowed from `a`. */
const g5c_json *ausf_nrf_info(const ausf *a);

/* ---- introspection (tests, tools) ---- */

size_t ausf_context_count(ausf *a); /* started plus finished authentications */
size_t ausf_ue_count(ausf *a);
/* The latest KAUSF stored for `supi`, with its counters; false when there is none. */
bool ausf_ue_kausf(ausf *a, const char *supi, uint8_t kausf[32], uint16_t *counter_sor, uint16_t *counter_upu);
/* Set the next counter values of a stored security context (tests of the wrap-around behaviour). false when there is none. */
bool ausf_ue_set_counters(ausf *a, const char *supi, uint16_t counter_sor, uint16_t counter_upu);
/* Write the state file now (a no-op without one). */
int ausf_flush(ausf *a);

#endif
