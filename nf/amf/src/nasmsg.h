/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5GMM message builders (nasmsg.c). */
#ifndef G5C_AMF_NASMSG_H
#define G5C_AMF_NASMSG_H

#include "priv.h"

typedef struct {
    uint8_t plmn[3];
    amf_guami_id id;
    uint32_t tmsi;
    amf_tai tai[AMF_MAX_TAI];
    size_t ntai;
    nas_snssai allowed[AMF_MAX_SLICE];
    size_t nallowed;
    nas_snssai rejected[AMF_MAX_SLICE];
    size_t nrejected;
    bool has_psi_status;
    uint16_t psi_status;
    bool has_react;
    uint16_t react;
    unsigned t3512, t3502;
} nm_regacc;

typedef struct {
    uint8_t plmn[3];
    amf_guami_id id;
    uint32_t tmsi; /* 0: no new 5G-GUTI */
    amf_tai tai[AMF_MAX_TAI];
    size_t ntai;
    bool has_allowed;
    nas_snssai allowed[AMF_MAX_SLICE];
    size_t nallowed;
    bool ack;
    const char *full_name, *short_name;
    bool with_time; /* local time zone, universal time and daylight saving time (UTC, no offset) */
} nm_cfgupd;

uint8_t nm_gprs_timer3(unsigned secs);
uint8_t nm_gprs_timer2(unsigned secs);
int nm_identity_request(g5c_bytes *out);
int nm_auth_request(uint8_t ngksi, const uint8_t abba[2], const uint8_t rand[16], const uint8_t autn[16], g5c_bytes *out);
int nm_auth_reject(g5c_bytes *out);
/* EAP based authentication (TS 24.501 5.4.1.2): the EAP message in the Authentication Request, the Authentication Reject and the Security Mode Command */
int nm_auth_request_eap(uint8_t ngksi, const uint8_t abba[2], const uint8_t *eap, size_t eap_len, g5c_bytes *out);
int nm_auth_reject_eap(const uint8_t *eap, size_t eap_len, g5c_bytes *out);
int nm_smc_eap(uint8_t int_alg, uint8_t enc_alg, uint8_t ngksi, const uint8_t *ue_cap, size_t cap_len, bool imeisv_req, bool rinmr, const uint8_t *eap, size_t eap_len,
               const uint8_t abba[2], g5c_bytes *out);
int nm_smc(uint8_t int_alg, uint8_t enc_alg, uint8_t ngksi, const uint8_t *ue_cap, size_t cap_len, bool imeisv_req, bool rinmr, g5c_bytes *out);
int nm_reg_reject(uint8_t cause, g5c_bytes *out);
int nm_reg_accept(const nm_regacc *p, g5c_bytes *out);
int nm_service_accept(bool has_status, uint16_t status, bool has_react, uint16_t react, g5c_bytes *out);
int nm_service_reject(uint8_t cause, bool has_status, uint16_t status, g5c_bytes *out);
int nm_dl_nas_transport(uint8_t ptype, const uint8_t *payload, size_t len, uint8_t psi, uint8_t cause, g5c_bytes *out);
int nm_dereg_request_ue_term(bool reregister, uint8_t cause, g5c_bytes *out);
int nm_dereg_accept_ue_orig(g5c_bytes *out);
int nm_config_update(const nm_cfgupd *p, g5c_bytes *out);

#endif
