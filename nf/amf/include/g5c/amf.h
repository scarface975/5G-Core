/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5G core Access and Mobility Management Function (AMF), Phase 5 (ADR-0016).
 *
 *  - N2 (TS 38.413): an SCTP endpoint for gNBs: NG Setup, RAN Configuration Update, NG Reset, Initial UE Message, UL/DL NAS Transport, Initial Context
 *    Setup, UE Context Release (both directions), PDU Session Resource Setup / Modify / Release, Paging, Error Indication, Xn path switch, N2 handover.
 *  - N1 (TS 24.501): 5GMM registration (initial, mobility, periodic), identification, 5G-AKA through the AUSF, NAS security mode with integrity and
 *    ciphering, 5G-GUTI allocation, configuration update, service request, UE- and network-initiated de-registration, 5GSM transport.
 *  - SBI: clients for AUSF, UDM (UECM, SDM), PCF (AM policy), SMF (Nsmf_PDUSession) and the NRF (discovery); servers for Namf_Communication
 *    (N1N2MessageTransfer and the callbacks of the SMF, UDM and PCF) and Namf_EventExposure.
 *
 * Threading: one reader thread owns the SCTP sockets and decodes NGAP. The messages of one UE association are queued on its connection object and run
 * in order by a pool worker; whoever touches a UE context (NAS handling, SBI handler, timer) holds that context's mutex, so SBI calls that block only
 * delay that UE. */
#ifndef G5C_AMF_H
#define G5C_AMF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "g5c/base.h"
#include "g5c/json.h"
#include "g5c/nfcore.h"

typedef struct amf amf;

/* Parse the `amf:` section (the PLMN comes from the common section); NULL with err on failure. */
amf *amf_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap);
/* Restores persisted contexts, binds the NGAP socket and starts the threads. 0 / -1 with err. */
int amf_start(amf *a, char *err, size_t errcap);
/* Stops the threads, closes the associations and frees everything (the pointer is freed too). */
void amf_destroy(amf *a);
/* The Namf routes for the SBI server (call once; ownership passes to the caller). */
g5c_router *amf_router(amf *a);
/* Register the Namf routes of `a` on `r` (a may be NULL when only the route table is wanted, e.g. for the documentation tools). */
void amf_routes(g5c_router *r, amf *a);
/* Where the other NFs reach our SBI (callback URIs are built from this). Call after the listener is up when the port is dynamic. */
void amf_set_self_uri(amf *a, const char *uri);
/* The AmfInfo the NRF profile carries (caller frees). */
g5c_json *amf_nrf_info(const amf *a);

/* ---- introspection (tests, g5c-ctl) ------------------------------------------------------------------------------------------------------ */

uint16_t amf_ngap_port(const amf *a);
size_t amf_gnb_count(amf *a);
size_t amf_ue_count(amf *a);

typedef struct {
    bool known;
    bool registered;   /* 5GMM-REGISTERED */
    bool connected;    /* CM-CONNECTED */
    uint32_t tmsi;
    unsigned npdu;     /* PDU sessions the AMF holds a reference for */
    unsigned nallowed; /* S-NSSAIs in the allowed NSSAI */
    uint8_t int_alg, enc_alg;
    uint32_t ul_count, dl_count;
} amf_ue_info;
bool amf_ue_lookup(amf *a, const char *supi, amf_ue_info *out);

/* Counters of completed procedures, for the tests' synchronisation. */
typedef struct {
    uint64_t registrations, auth_ok, auth_fail, deregistrations, service_requests, pagings, handovers, path_switches, releases;
} amf_stats;
void amf_get_stats(amf *a, amf_stats *out);

/* Network-initiated procedures an operator (or a test) can trigger. 0 on success, a negative value if the UE is unknown / unreachable. */
int amf_ue_deregister(amf *a, const char *supi, bool reregister);
int amf_ue_config_update(amf *a, const char *supi, bool new_guti);

/* ---- hooks for the fuzz harness and unit tests (no sockets involved) ------------------------------------------------------------------------ */

/* Start the workers and the timer thread only (no SCTP listener, no state file). */
int amf_test_start(amf *a);
/* Mark gNB slot `slot` as set up (serving `tac` of the configured PLMN) without a transport; what the AMF sends to it is dropped. */
void amf_test_gnb(amf *a, unsigned slot, uint32_t tac);
/* Run an NGAP PDU through the receive path as if it came from gNB slot `slot` on stream 1. */
void amf_test_inject(amf *a, unsigned slot, const uint8_t *pdu, size_t len);
/* Install a registered, idle UE with a native security context (NEA2 / NIA2) so that protected NAS messages are verified against `kamf`. */
void amf_test_add_ue(amf *a, const char *supi, uint32_t tmsi, const uint8_t kamf[32]);
/* Dispatch an SBI request through the router (as the server would). */
void amf_test_sbi(amf *a, g5c_router *r, const char *method, const char *path, const char *ctype, const uint8_t *body, size_t len);
/* Wait until no queued task is running (timers that are not yet due do not count). */
void amf_test_drain(amf *a);

#endif
