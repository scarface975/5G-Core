/* SPDX-License-Identifier: LicenseRef-Proprietary */
#ifndef G5C_CRYPTO_H
#define G5C_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* ---- MILENAGE (TS 35.206) ---- */

typedef struct {
    uint8_t res[8];     /* f2 */
    uint8_t ck[16];     /* f3 */
    uint8_t ik[16];     /* f4 */
    uint8_t ak[6];      /* f5 */
    uint8_t ak_star[6]; /* f5* */
} g5c_milenage_vector;

typedef struct {
    uint8_t k[16];
    uint8_t opc[16];
} g5c_milenage;

/* OPc = E_K(OP) xor OP. Returns 0 on success, -1 on crypto failure. */
int g5c_milenage_derive_opc(const uint8_t k[16], const uint8_t op[16], uint8_t opc[16]);

void g5c_milenage_init(g5c_milenage *m, const uint8_t k[16], const uint8_t opc[16]);

/* f1 / f1*: MAC-A and MAC-S. Returns 0 on success. */
int g5c_milenage_f1(const g5c_milenage *m, const uint8_t rand[16], const uint8_t sqn[6],
                    const uint8_t amf[2], uint8_t mac_a[8], uint8_t mac_s[8]);

/* f2, f3, f4, f5, f5*. Returns 0 on success. */
int g5c_milenage_f2345(const g5c_milenage *m, const uint8_t rand[16], g5c_milenage_vector *out);

/* ---- Generic 3GPP KDF (TS 33.220 Annex B.2) ---- */

#define G5C_KDF_MAX_PARAMS 8

/* HMAC-SHA-256 over FC || P0 || L0 || P1 || L1 . with 2-octet lengths */
int g5c_kdf(const uint8_t *key, size_t key_len, uint8_t fc, const uint8_t *const *params,
            const size_t *param_lens, size_t nparams, uint8_t out[32]);

/* ---- 5G-AKA key hierarchy (TS 33.501 Annex A) ---- */

/* "5G:mnc<MNC padded to 3>.mcc<MCC>.3gppnetwork.org". Returns length, or -1 if cap too small / bad input. */
int g5c_serving_network_name(const char *mcc, const char *mnc, char *out, size_t cap);

void g5c_autn(const uint8_t sqn[6], const uint8_t ak[6], const uint8_t amf[2],
              const uint8_t mac_a[8], uint8_t autn[16]);
int g5c_res_star(const uint8_t ck[16], const uint8_t ik[16], const char *snn, const uint8_t rand[16],
                 const uint8_t *res, size_t res_len, uint8_t out[16]);
int g5c_hres_star(const uint8_t rand[16], const uint8_t res_star[16], uint8_t out[16]);
int g5c_kausf(const uint8_t ck[16], const uint8_t ik[16], const char *snn,
              const uint8_t sqn_xor_ak[6], uint8_t out[32]);
int g5c_kseaf(const uint8_t kausf[32], const char *snn, uint8_t out[32]);
/* supi: IMSI digits only (no "imsi-" prefix). */
int g5c_kamf(const uint8_t kseaf[32], const char *supi, const uint8_t abba[2], uint8_t out[32]);

typedef enum {
    G5C_ALG_NAS_ENC = 1,
    G5C_ALG_NAS_INT = 2,
    G5C_ALG_RRC_ENC = 3,
    G5C_ALG_RRC_INT = 4,
    G5C_ALG_UP_ENC = 5,
    G5C_ALG_UP_INT = 6
} g5c_alg_type;

int g5c_algo_key(const uint8_t kamf[32], g5c_alg_type t, uint8_t algo_id, uint8_t out[16]);
/* access: 0x01 = 3GPP, 0x02 = non-3GPP */
int g5c_kgnb(const uint8_t kamf[32], uint32_t ul_nas_count, uint8_t access, uint8_t out[32]);

/* ---- NAS security algorithms (TS 33.501 Annex D) ---- */

typedef enum { G5C_DIR_UL = 0, G5C_DIR_DL = 1 } g5c_dir;

/* 128-NEA2 (AES-CTR). In place; encryption == decryption. Returns 0 / -1. */
int g5c_nea2(const uint8_t key[16], uint32_t count, uint8_t bearer, g5c_dir dir, uint8_t *data,
             size_t len);
/* 128-NIA2 (AES-CMAC, 32 MSBs). Returns 0 / -1. */
int g5c_nia2(const uint8_t key[16], uint32_t count, uint8_t bearer, g5c_dir dir,
             const uint8_t *msg, size_t len, uint8_t mac[4]);

/* ---- SUCI ECIES (TS 33.501 Annex C.3) ---- */

typedef enum { G5C_PROFILE_A = 0, G5C_PROFILE_B = 1 } g5c_profile;

typedef enum {
    G5C_SUCI_OK = 0,
    G5C_SUCI_TOO_SHORT = -1,
    G5C_SUCI_INVALID_KEY = -2,
    G5C_SUCI_DEGENERATE = -3,
    G5C_SUCI_MAC_MISMATCH = -4,
    G5C_SUCI_MSIN = -5,
    G5C_SUCI_NOSPACE = -6,
    G5C_SUCI_INTERNAL = -7
} g5c_suci_err;

#define G5C_SUCI_TAG_LEN 8
size_t g5c_suci_pubkey_len(g5c_profile p); /* 32 for A, 33 for B */
/* Wire-format public key for a private key. Output buffer must hold 33 octets. */
int g5c_suci_public_key(g5c_profile p, const uint8_t secret[32], uint8_t *out, size_t cap,
                        size_t *out_len);
/* out = eph_pub || ct || tag; needs pubkey_len + msin_len + 8 octets. */
int g5c_suci_conceal(g5c_profile p, const uint8_t *hn_pub, size_t hn_pub_len,
                     const uint8_t eph_secret[32], const uint8_t *msin_bcd, size_t msin_len,
                     uint8_t *out, size_t cap, size_t *out_len);
/* Writes the BCD MSIN octets; needs len(output) - pubkey_len - 8 octets. */
int g5c_suci_deconceal(g5c_profile p, const uint8_t hn_secret[32], const uint8_t *output,
                       size_t output_len, uint8_t *msin_bcd, size_t cap, size_t *msin_len);
/* digits "0123456789" -> BCD (first digit low nibble, odd length padded with 0xF). */
int g5c_msin_to_bcd(const char *msin, uint8_t *out, size_t cap, size_t *out_len);
int g5c_bcd_to_msin(const uint8_t *bcd, size_t len, char *out, size_t cap);

#endif
