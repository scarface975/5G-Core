/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5GS NAS (3GPP TS 24.501, Rel-16) codec.
 *
 *  - Table-driven framing for all 5GMM and 5GSM messages: NAS_MESSAGES is generated from the spec's message-content
 *    tables (tools/gen_nas_defs.py), so IEIs, formats (V/LV/LV-E/T/TV/TLV/TLV-E), presence and order come straight
 *    from TS 24.501 clause 8.
 *  - typed accessors for the IEs the core needs (clause 9.11).
 *  - the security-protected envelope, integrity and ciphering (TS 24.501 4.4, TS 33.501 6.4).
 *
 * Messages decode to a list of raw IE values keyed by the spec's IE name; unknown optional IEs are kept verbatim so a
 * decode/encode cycle preserves the wire bytes. */
#ifndef G5C_NAS_H
#define G5C_NAS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "g5c/base.h"
#include "g5c/crypto.h"

#define NAS_EPD_5GMM 0x7e
#define NAS_EPD_5GSM 0x2e
#define NAS_MAX_IES 256 /* IEs accepted per message */

typedef enum { NAS_PROTO_MM, NAS_PROTO_SM } nas_proto;
typedef enum { NAS_PRES_M, NAS_PRES_O, NAS_PRES_C } nas_presence;
typedef enum { NAS_FMT_V, NAS_FMT_LV, NAS_FMT_LVE, NAS_FMT_T, NAS_FMT_TV, NAS_FMT_TLV, NAS_FMT_TLVE } nas_format;

typedef struct {
    int16_t iei;     /* -1 when the IE is untagged */
    bool half_iei;   /* IEI occupies only the upper nibble (type 1 IE) */
    const char *name;
    const char *clause;
    uint8_t presence, format;
    uint32_t min, max; /* as listed (TV: total including the IEI); max 0 = unbounded */
    bool half;         /* value is half an octet (V 1/2) */
} nas_iedef;

typedef struct {
    const char *name;
    uint8_t proto, msg_type;
    const nas_iedef *ies;
    size_t nies;
} nas_msgdef;

extern const nas_msgdef NAS_MESSAGES[];
extern const size_t NAS_NMESSAGES;

typedef enum {
    NAS_OK = 0,
    NAS_E_TRUNCATED = -1,
    NAS_E_EPD = -2,
    NAS_E_MSGTYPE = -3,
    NAS_E_MISSING = -4, /* a mandatory IE is absent; nas_msg.err_name names it */
    NAS_E_PROTECTED = -5,
    NAS_E_INVALID = -6,
    NAS_E_SECURITY = -7,
    NAS_E_TOO_MANY_IES = -8
} nas_err;

const char *nas_strerror(int err);
const nas_msgdef *nas_lookup(nas_proto proto, uint8_t msg_type);
const nas_msgdef *nas_lookup_name(const char *name);

/* One IE value. `value` excludes the IEI and length octets; for half-octet IEs it is one octet holding the nibble in
 * its low 4 bits. */
typedef struct {
    const char *name; /* spec name, or "unknown" */
    int16_t iei;      /* -1 for untagged IEs */
    uint8_t format;   /* kept so unknown IEs can be re-encoded */
    uint8_t *value;
    size_t len;
} nas_ie;

typedef struct {
    const nas_msgdef *def;
    uint8_t pdu_session_id, pti; /* 5GSM only */
    nas_ie *ies;
    size_t nies, cap;
    const char *err_name; /* set with NAS_E_MISSING */
} nas_msg;

bool nas_msg_init(nas_msg *m, const char *name); /* false if the message name is unknown */
void nas_msg_free(nas_msg *m);
const char *nas_msg_name(const nas_msg *m);
const uint8_t *nas_msg_get(const nas_msg *m, const char *name, size_t *len); /* NULL if absent */
/* Set or replace an IE by spec name; false if the message does not define it. */
bool nas_msg_set(nas_msg *m, const char *name, const uint8_t *value, size_t len);
bool nas_msg_equal(const nas_msg *a, const nas_msg *b);
/* Decode a plain NAS message. */
int nas_msg_decode(const uint8_t *buf, size_t len, nas_msg *out);
/* Append the plain wire encoding to out. */
int nas_msg_encode(const nas_msg *m, g5c_bytes *out);

/* ---- typed information elements (clause 9.11) ----------------------------------------------------------------------- */

/* 3-octet PLMN (TS 24.008 10.5.1.13) <-> digit strings (mcc[4], mnc[4]). */
int nas_plmn_decode(const uint8_t *b, size_t len, char mcc[4], char mnc[4]);
int nas_plmn_encode(const char *mcc, const char *mnc, uint8_t out[3]);

typedef enum {
    NAS_ID_NONE = 0,
    NAS_ID_SUCI = 1,
    NAS_ID_GUTI = 2,
    NAS_ID_IMEI = 3,
    NAS_ID_STMSI = 4,
    NAS_ID_IMEISV = 5,
    NAS_ID_OTHER = 7
} nas_id_kind;

#define NAS_ID_MAX_OUTPUT 128

typedef struct {
    nas_id_kind kind;
    /* SUCI */
    uint8_t supi_format; /* 0 IMSI, 1 network-specific */
    char mcc[4], mnc[4];
    char routing_indicator[5];
    uint8_t scheme, hn_key_id; /* scheme: 0 null, 1 Profile A, 2 Profile B */
    uint8_t output[NAS_ID_MAX_OUTPUT];
    size_t output_len;
    /* GUTI / S-TMSI */
    uint8_t amf_region;
    uint16_t amf_set;
    uint8_t amf_pointer;
    uint32_t tmsi;
    /* IMEI / IMEISV digits */
    char digits[20];
    /* OTHER */
    uint8_t other_type;
} nas_mobile_identity;

/* 5GS mobile identity value octets (without the length field). */
int nas_mobile_identity_decode(const uint8_t *v, size_t len, nas_mobile_identity *out);
/* IMEI/IMEISV are not encoded: they only arrive from UEs. */
int nas_mobile_identity_encode(const nas_mobile_identity *id, g5c_bytes *out);
/* MSIN digits when the null protection scheme is used. false otherwise. */
bool nas_suci_null_scheme_msin(const nas_mobile_identity *id, char *out, size_t cap);
/* Canonical SUCI string (TS 23.003 2.2B): suci-0-001-01-0000-0-0-0000000001 (scheme output as hex when protected). */
char *nas_suci_to_string(const nas_mobile_identity *id); /* caller frees */

typedef struct {
    bool mapped;
    uint8_t ksi; /* 7 = no key available */
} nas_ngksi;
nas_ngksi nas_ngksi_from_nibble(uint8_t n);
uint8_t nas_ngksi_to_nibble(nas_ngksi k);

typedef struct {
    bool follow_on;
    uint8_t kind; /* 1 initial, 2 mobility updating, 3 periodic updating, 4 emergency, 5 SNPN onboarding */
} nas_reg_type;
nas_reg_type nas_reg_type_from_nibble(uint8_t n);
uint8_t nas_reg_type_to_nibble(nas_reg_type r);

typedef struct {
    uint8_t ea, ia; /* 5G-EA0..7 / 5G-IA0..7 bitmaps (EA0 = bit 8) */
    bool has_eps;
    uint8_t eea, eia;
} nas_ue_sec_cap;
int nas_ue_sec_cap_decode(const uint8_t *v, size_t len, nas_ue_sec_cap *out);
size_t nas_ue_sec_cap_encode(const nas_ue_sec_cap *c, uint8_t out[4]);
bool nas_supports_ea(const nas_ue_sec_cap *c, unsigned n);
bool nas_supports_ia(const nas_ue_sec_cap *c, unsigned n);
/* Selected NAS security algorithms octet (clause 9.11.3.34): ciphering high nibble, integrity low. */
uint8_t nas_selected_algorithms(uint8_t ciphering, uint8_t integrity);

typedef struct {
    uint8_t sst;
    bool has_sd;
    uint32_t sd;
} nas_snssai;
int nas_snssai_decode(const uint8_t *v, size_t len, nas_snssai *out);
size_t nas_snssai_encode(const nas_snssai *s, uint8_t out[4]);
/* NSSAI IE value: list of length-prefixed S-NSSAIs. Returns the count, or a negative error. */
int nas_nssai_decode(const uint8_t *v, size_t len, nas_snssai *out, size_t cap);
int nas_nssai_encode(const nas_snssai *list, size_t n, g5c_bytes *out);
/* DNN (clause 9.11.2.1A): length-prefixed labels <-> dot-separated string. */
int nas_dnn_decode(const uint8_t *v, size_t len, char *out, size_t cap);
int nas_dnn_encode(const char *dnn, g5c_bytes *out);

/* ---- security (TS 24.501 4.4 and 9.3, TS 33.501 6.4 and Annex D) ------------------------------------------------------- */

#define NAS_BEARER_3GPP 1 /* bearer identity for NAS over 3GPP access (TS 33.501 D.1.1) */

typedef enum { NAS_IA0 = 0, NAS_IA2 = 2 } nas_int_alg;
typedef enum { NAS_EA0 = 0, NAS_EA2 = 2 } nas_enc_alg;

/* From the 4-bit algorithm id; SNOW 3G (1) and ZUC (3) are not implemented yet. 0 / NAS_E_SECURITY. */
int nas_int_alg_from_id(uint8_t id, nas_int_alg *out);
int nas_enc_alg_from_id(uint8_t id, nas_enc_alg *out);

typedef struct {
    uint8_t knas_int[16], knas_enc[16];
    nas_int_alg int_alg;
    nas_enc_alg enc_alg;
} nas_sec_ctx;

/* A security-protected 5GMM message (TS 24.501 8.2.28); payload points into the decoded buffer. */
typedef struct {
    uint8_t sht; /* security header type 1..=4 */
    uint8_t mac[4];
    uint8_t seq;
    const uint8_t *payload;
    size_t payload_len;
} nas_protected;

typedef struct {
    bool is_protected;
    nas_msg plain;
    nas_protected prot;
} nas_any;

/* Decode the outer layer. Free with nas_any_free. */
int nas_any_decode(const uint8_t *buf, size_t len, nas_any *out);
void nas_any_free(nas_any *a);
/* Verify the MAC for the NAS COUNT (overflow << 8 | seq) and direction. */
bool nas_protected_verify(const nas_protected *p, const nas_sec_ctx *ctx, g5c_dir dir, uint32_t count);
/* Recover the inner plain message bytes (deciphering when the header type says so). */
int nas_protected_open(const nas_protected *p, const nas_sec_ctx *ctx, g5c_dir dir, uint32_t count, g5c_bytes *out);
/* Protect a plain NAS message: optional ciphering (SHT 2 and 4), then the MAC over seq || payload. The low octet of
 * the 32-bit NAS COUNT becomes the sequence number on the wire. */
int nas_protect(const nas_sec_ctx *ctx, uint8_t sht, g5c_dir dir, uint32_t count, const uint8_t *plain, size_t plen,
                g5c_bytes *out);

#endif
