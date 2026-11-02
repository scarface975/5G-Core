/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* EAP-AKA' (RFC 5448, RFC 9048) in the 3GPP 5G profile (TS 33.501 clause 6.1.3.1 and Annex F) */
#ifndef G5C_EAPAKA_H
#define G5C_EAPAKA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- numbers (RFC 3748 4, RFC 4187 clause 11, RFC 5448 clause 6, RFC 9048 clause 6) ---- */

#define G5C_EAP_REQUEST 1
#define G5C_EAP_RESPONSE 2
#define G5C_EAP_SUCCESS 3
#define G5C_EAP_FAILURE 4
#define G5C_EAP_TYPE_AKA_PRIME 50

#define G5C_EAPAKA_CHALLENGE 1
#define G5C_EAPAKA_AUTH_REJECT 2
#define G5C_EAPAKA_SYNC_FAILURE 4
#define G5C_EAPAKA_NOTIFICATION 12
#define G5C_EAPAKA_CLIENT_ERROR 14

#define G5C_AT_RAND 1
#define G5C_AT_AUTN 2
#define G5C_AT_RES 3
#define G5C_AT_AUTS 4
#define G5C_AT_MAC 11
#define G5C_AT_NOTIFICATION 12
#define G5C_AT_CLIENT_ERROR_CODE 22
#define G5C_AT_KDF_INPUT 23
#define G5C_AT_KDF 24
#define G5C_AT_CHECKCODE 134
#define G5C_AT_RESULT_IND 135

#define G5C_EAPAKA_NOTIF_SUCCESS 32768
#define G5C_EAPAKA_NOTIF_GENERAL_FAILURE 16384
#define G5C_EAPAKA_NOTIF_FAILURE_AFTER_AUTH 0

/* ---- key derivation ---- */

/* CK' and IK' (TS 33.501 Annex A.3 = TS 33.402 Annex A.2 with the serving network name as access network identity) */
int g5c_ck_ik_prime(const uint8_t ck[16], const uint8_t ik[16], const char *snn, const uint8_t sqn_xor_ak[6], uint8_t ck_p[16], uint8_t ik_p[16]);

/* PRF' of RFC 5448 clause 3.4.1: T1 | T2 | ... with HMAC-SHA-256 keyed by the 256-bit `key`; fills `out_len` octets. */
int g5c_prf_prime(const uint8_t key[32], const uint8_t *s, size_t s_len, uint8_t *out, size_t out_len);

typedef struct {
    uint8_t k_encr[16], k_aut[32], k_re[32], msk[64], emsk[64];
} g5c_eapaka_keys;

/* RFC 5448 clause 3.3 with AT_KDF = 1: MK = PRF'(IK'|CK', "EAP-AKA'"|Identity). `identity` for the 5G profile is the IMSI digits (TS 33.501 Annex F.3). */
int g5c_eapaka_prime_keys(const uint8_t ck_p[16], const uint8_t ik_p[16], const char *identity, g5c_eapaka_keys *out);

/* KAUSF is the most significant 256 bits of the EMSK (TS 33.501 6.1.3.1 step 10). */
void g5c_eapaka_kausf(const g5c_eapaka_keys *k, uint8_t kausf[32]);

/* ---- packets ---- */

#define G5C_EAP_MAX_ATTRS 12
#define G5C_EAP_MAX_PKT 1020 /* the EAP MTU every lower layer must provide (RFC 3748 clause 3) */

typedef struct {
    uint8_t type;
    const uint8_t *val; /* the attribute value (after the type and length octets) */
    size_t vlen;        /* (Length * 4) - 2, so a value of 2 mod 4 octets overall is always a multiple of 2 */
} g5c_eap_attr;

typedef struct {
    uint8_t code, id;
    uint8_t method;  /* EAP type, 0 for Success and Failure */
    uint8_t subtype; /* EAP-AKA subtype, 0 for Success and Failure */
    g5c_eap_attr attrs[G5C_EAP_MAX_ATTRS];
    size_t nattrs;
} g5c_eap_pkt;

/* Frames: Success / Failure (4 octets), Request / Response of an EAP-AKA type */
bool g5c_eap_parse(const uint8_t *b, size_t n, g5c_eap_pkt *p);
const g5c_eap_attr *g5c_eap_find(const g5c_eap_pkt *p, uint8_t type);

/* Builds a Request or Response of the EAP-AKA' method; attribute values are copied (their vlen + 2 must be a multiple of 4: the caller pads) */
int g5c_eap_build(uint8_t code, uint8_t id, uint8_t subtype, const g5c_eap_attr *attrs, size_t nattrs, uint8_t *out, size_t cap, size_t *len);
/* Success / Failure */
void g5c_eap_build_result(uint8_t code, uint8_t id, uint8_t out[4]);

/* AT_MAC (RFC 4187 10.15 with the HMAC-SHA-256-128 of RFC 5448 3.4.2) */
int g5c_eap_mac_set(uint8_t *pkt, size_t len, const uint8_t k_aut[32], const uint8_t *extra, size_t extra_len);
/* true when the AT_MAC of the packet verifies (constant time). */
bool g5c_eap_mac_ok(const uint8_t *pkt, size_t len, const uint8_t k_aut[32], const uint8_t *extra, size_t extra_len);

#endif
