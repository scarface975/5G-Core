#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* 5GMM message builders of the AMF (TS 24.501 clause 8.2) on top of the table-driven codec of libs/nas. IE names are the spec's. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "nasmsg.h"

static void setb(nas_msg *m, const char *ie, const void *v, size_t n)
{
    (void)nas_msg_set(m, ie, v, n);
}

static void set1(nas_msg *m, const char *ie, uint8_t v)
{
    (void)nas_msg_set(m, ie, &v, 1);
}

static int finish(nas_msg *m, g5c_bytes *out)
{
    int rc = nas_msg_encode(m, out);
    nas_msg_free(m);
    return rc;
}

/* GPRS timer 3 (TS 24.008 10.5.7.4a): the largest unit that represents the value exactly, else the smallest unit that can hold it. */
uint8_t nm_gprs_timer3(unsigned secs)
{
    static const struct {
        unsigned secs;
        uint8_t unit;
    } units[] = {{1152000, 6}, {36000, 2}, {3600, 1}, {600, 0}, {60, 5}, {30, 4}, {2, 3}};
    for (size_t i = 0; i < sizeof units / sizeof units[0]; i++)
        if (secs % units[i].secs == 0 && secs / units[i].secs <= 31)
            return (uint8_t)(units[i].unit << 5 | (secs / units[i].secs));
    for (size_t i = sizeof units / sizeof units[0]; i-- > 0;)
        if (secs / units[i].secs + (secs % units[i].secs != 0) <= 31)
            return (uint8_t)(units[i].unit << 5 | (secs / units[i].secs + (secs % units[i].secs != 0)));
    return (uint8_t)(6 << 5 | 31);
}

/* GPRS timer 2 (TS 24.008 10.5.7.4) */
uint8_t nm_gprs_timer2(unsigned secs)
{
    if (secs <= 62 && secs % 2 == 0 && secs / 2 <= 31)
        return (uint8_t)(0 << 5 | secs / 2);
    if (secs % 60 == 0 && secs / 60 <= 31)
        return (uint8_t)(1 << 5 | secs / 60);
    {
        unsigned v = (secs + 359) / 360;
        return (uint8_t)(2 << 5 | (v > 31 ? 31 : v));
    }
}

int nm_identity_request(g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "Identity request"))
        return -1;
    set1(&m, "Identity type", 1); /* SUCI */
    set1(&m, "Spare half octet", 0);
    return finish(&m, out);
}

int nm_auth_request(uint8_t ngksi, const uint8_t abba[2], const uint8_t rand[16], const uint8_t autn[16], g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "Authentication request"))
        return -1;
    set1(&m, "ngKSI", ngksi & 0x7);
    set1(&m, "Spare half octet", 0);
    setb(&m, "ABBA", abba, 2);
    setb(&m, "Authentication parameter RAND (5G authentication challenge)", rand, 16);
    setb(&m, "Authentication parameter AUTN (5G authentication challenge)", autn, 16);
    return finish(&m, out);
}

int nm_auth_request_eap(uint8_t ngksi, const uint8_t abba[2], const uint8_t *eap, size_t eap_len, g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "Authentication request"))
        return -1;
    set1(&m, "ngKSI", ngksi & 0x7);
    set1(&m, "Spare half octet", 0);
    setb(&m, "ABBA", abba, 2);
    setb(&m, "EAP message", eap, eap_len);
    return finish(&m, out);
}

int nm_auth_reject_eap(const uint8_t *eap, size_t eap_len, g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "Authentication reject"))
        return -1;
    setb(&m, "EAP message", eap, eap_len);
    return finish(&m, out);
}

int nm_auth_reject(g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "Authentication reject"))
        return -1;
    return finish(&m, out);
}

int nm_smc(uint8_t int_alg, uint8_t enc_alg, uint8_t ngksi, const uint8_t *ue_cap, size_t cap_len, bool imeisv_req, bool rinmr, g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "Security mode command"))
        return -1;
    set1(&m, "Selected NAS security algorithms", nas_selected_algorithms(enc_alg, int_alg));
    set1(&m, "ngKSI", ngksi & 0x7);
    set1(&m, "Spare half octet", 0);
    setb(&m, "Replayed UE security capabilities", ue_cap, cap_len);
    if (imeisv_req)
        set1(&m, "IMEISV request", 1);
    if (rinmr)
        set1(&m, "Additional 5G security information", 0x02);
    return finish(&m, out);
}

int nm_smc_eap(uint8_t int_alg, uint8_t enc_alg, uint8_t ngksi, const uint8_t *ue_cap, size_t cap_len, bool imeisv_req, bool rinmr, const uint8_t *eap, size_t eap_len,
               const uint8_t abba[2], g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "Security mode command"))
        return -1;
    set1(&m, "Selected NAS security algorithms", nas_selected_algorithms(enc_alg, int_alg));
    set1(&m, "ngKSI", ngksi & 0x7);
    set1(&m, "Spare half octet", 0);
    setb(&m, "Replayed UE security capabilities", ue_cap, cap_len);
    if (imeisv_req)
        set1(&m, "IMEISV request", 1);
    if (rinmr)
        set1(&m, "Additional 5G security information", 0x02);
    /* TS 24.501 5.4.1.2.1: the EAP-success message and the ngKSI go to the UE in the Security Mode Command; the ABBA goes with the EAP-success (5.4.1.2.2.2) */
    setb(&m, "EAP message", eap, eap_len);
    setb(&m, "ABBA", abba, 2);
    return finish(&m, out);
}

int nm_reg_reject(uint8_t cause, g5c_bytes *out)
{
    return nm_reg_reject_t3346(cause, 0, out);
}

int nm_reg_reject_t3346(uint8_t cause, unsigned t3346_s, g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "Registration reject"))
        return -1;
    set1(&m, "5GMM cause", cause);
    if (t3346_s > 0)
        set1(&m, "T3346 value", nm_gprs_timer2(t3346_s));
    return finish(&m, out);
}

/* TAI list (TS 24.501 9.11.3.9): one partial list of type 00 per PLMN present */
static void put_tai_list(g5c_bytes *b, const amf_tai *t, size_t n)
{
    size_t done = 0;
    bool used[AMF_MAX_TAI] = {false};
    while (done < n) {
        size_t first = n, count = 0;
        uint8_t hdr;
        for (size_t i = 0; i < n; i++)
            if (!used[i]) {
                first = i;
                break;
            }
        for (size_t i = first; i < n; i++)
            if (!used[i] && memcmp(t[i].plmn, t[first].plmn, 3) == 0)
                count++;
        hdr = (uint8_t)((count - 1) & 0x1f); /* type 00: list of TACs belonging to one PLMN, non-consecutive */
        (void)g5c_bytes_append(b, &hdr, 1);
        (void)g5c_bytes_append(b, t[first].plmn, 3);
        for (size_t i = first; i < n; i++)
            if (!used[i] && memcmp(t[i].plmn, t[first].plmn, 3) == 0) {
                uint8_t tac[3] = {(uint8_t)(t[i].tac >> 16), (uint8_t)(t[i].tac >> 8), (uint8_t)t[i].tac};
                (void)g5c_bytes_append(b, tac, 3);
                used[i] = true;
                done++;
            }
    }
}

static int put_guti(const nm_regacc *p, g5c_bytes *out)
{
    nas_mobile_identity id;
    memset(&id, 0, sizeof id);
    id.kind = NAS_ID_GUTI;
    if (nas_plmn_decode(p->plmn, 3, id.mcc, id.mnc) != 0)
        return -1;
    id.amf_region = p->id.region;
    id.amf_set = p->id.set;
    id.amf_pointer = p->id.pointer;
    id.tmsi = p->tmsi;
    return nas_mobile_identity_encode(&id, out);
}

int nm_reg_accept(const nm_regacc *p, g5c_bytes *out)
{
    nas_msg m;
    g5c_bytes t;
    uint8_t v;
    if (!nas_msg_init(&m, "Registration accept"))
        return -1;
    set1(&m, "5GS registration result", 0x01); /* 3GPP access */
    g5c_bytes_init(&t);
    if (p->tmsi != 0 && put_guti(p, &t) == 0)
        setb(&m, "5G-GUTI", t.data, t.len);
    g5c_bytes_clear(&t);
    if (p->ntai > 0) {
        put_tai_list(&t, p->tai, p->ntai);
        setb(&m, "TAI list", t.data, t.len);
        g5c_bytes_clear(&t);
    }
    if (p->nallowed > 0 && nas_nssai_encode(p->allowed, p->nallowed, &t) >= 0) {
        setb(&m, "Allowed NSSAI", t.data, t.len);
        g5c_bytes_clear(&t);
    }
    if (p->nrejected > 0) {
        for (size_t i = 0; i < p->nrejected; i++) {
            uint8_t sn[4];
            size_t l = nas_snssai_encode(&p->rejected[i], sn);
            uint8_t hdr = (uint8_t)(l << 4 | 0); /* cause 0: not available in the current PLMN */
            (void)g5c_bytes_append(&t, &hdr, 1);
            (void)g5c_bytes_append(&t, sn, l);
        }
        setb(&m, "Rejected NSSAI", t.data, t.len);
        g5c_bytes_clear(&t);
    }
    {
        uint8_t nfs[2] = {0, 0};
        setb(&m, "5GS network feature support", nfs, 2);
    }
    if (p->has_psi_status) {
        uint8_t s[2] = {(uint8_t)(p->psi_status & 0xff), (uint8_t)(p->psi_status >> 8)};
        setb(&m, "PDU session status", s, 2);
    }
    if (p->has_react) {
        uint8_t s[2] = {(uint8_t)(p->react & 0xff), (uint8_t)(p->react >> 8)};
        setb(&m, "PDU session reactivation result", s, 2);
    }
    if (p->t3512 != 0) {
        v = nm_gprs_timer3(p->t3512);
        setb(&m, "T3512 value", &v, 1);
    }
    if (p->t3502 != 0) {
        v = nm_gprs_timer2(p->t3502);
        setb(&m, "T3502 value", &v, 1);
    }
    g5c_bytes_free(&t);
    return finish(&m, out);
}

int nm_service_accept(bool has_status, uint16_t status, bool has_react, uint16_t react, g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "Service accept"))
        return -1;
    if (has_status) {
        uint8_t s[2] = {(uint8_t)(status & 0xff), (uint8_t)(status >> 8)};
        setb(&m, "PDU session status", s, 2);
    }
    if (has_react) {
        uint8_t s[2] = {(uint8_t)(react & 0xff), (uint8_t)(react >> 8)};
        setb(&m, "PDU session reactivation result", s, 2);
    }
    return finish(&m, out);
}

int nm_service_reject(uint8_t cause, bool has_status, uint16_t status, g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "Service reject"))
        return -1;
    set1(&m, "5GMM cause", cause);
    if (has_status) {
        uint8_t s[2] = {(uint8_t)(status & 0xff), (uint8_t)(status >> 8)};
        setb(&m, "PDU session status", s, 2);
    }
    return finish(&m, out);
}

/* payload container (TS 24.501 9.11.3.39): type 1 = N1 SM information */
int nm_dl_nas_transport(uint8_t ptype, const uint8_t *payload, size_t len, uint8_t psi, uint8_t cause, g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "DL NAS transport"))
        return -1;
    set1(&m, "Payload container type", ptype);
    set1(&m, "Spare half octet", 0);
    setb(&m, "Payload container", payload, len);
    if (psi != 0)
        set1(&m, "PDU session ID", psi);
    if (cause != 0)
        set1(&m, "5GMM cause", cause);
    return finish(&m, out);
}

int nm_dereg_request_ue_term(bool reregister, uint8_t cause, g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "De-registration request (UE terminated de-registration)"))
        return -1;
    set1(&m, "De-registration type", (uint8_t)((reregister ? 0x04 : 0x00) | 0x01)); /* 3GPP access; bit 3 re-registration required */
    set1(&m, "Spare half octet", 0);
    if (cause != 0)
        set1(&m, "5GMM cause", cause);
    return finish(&m, out);
}

int nm_dereg_accept_ue_orig(g5c_bytes *out)
{
    nas_msg m;
    if (!nas_msg_init(&m, "De-registration accept (UE originating de-registration)"))
        return -1;
    return finish(&m, out);
}

static uint8_t bcd_swapped(unsigned v)
{
    return (uint8_t)(((v % 10) << 4) | (v / 10 % 10));
}

/* network name IE value (TS 24.008 10.5.3.5a): UCS2 with the extension bit, as the oracle's AMF does */
static void put_name(g5c_bytes *b, const char *s)
{
    uint8_t hdr = 0x90;
    (void)g5c_bytes_append(b, &hdr, 1);
    for (const char *p = s; *p != 0; p++) {
        uint8_t u[2] = {0, (uint8_t)*p};
        (void)g5c_bytes_append(b, u, 2);
    }
}

int nm_config_update(const nm_cfgupd *p, g5c_bytes *out)
{
    nas_msg m;
    g5c_bytes t;
    if (!nas_msg_init(&m, "Configuration update command"))
        return -1;
    g5c_bytes_init(&t);
    if (p->ack)
        set1(&m, "Configuration update indication", 0x01);
    if (p->tmsi != 0) {
        nm_regacc ra;
        memset(&ra, 0, sizeof ra);
        memcpy(ra.plmn, p->plmn, 3);
        ra.id = p->id;
        ra.tmsi = p->tmsi;
        if (put_guti(&ra, &t) == 0)
            setb(&m, "5G-GUTI", t.data, t.len);
        g5c_bytes_clear(&t);
    }
    if (p->ntai > 0) {
        put_tai_list(&t, p->tai, p->ntai);
        setb(&m, "TAI list", t.data, t.len);
        g5c_bytes_clear(&t);
    }
    if (p->has_allowed && nas_nssai_encode(p->allowed, p->nallowed, &t) >= 0) {
        setb(&m, "Allowed NSSAI", t.data, t.len);
        g5c_bytes_clear(&t);
    }
    if (p->full_name != NULL) {
        put_name(&t, p->full_name);
        setb(&m, "Full name for network", t.data, t.len);
        g5c_bytes_clear(&t);
    }
    if (p->short_name != NULL) {
        put_name(&t, p->short_name);
        setb(&m, "Short name for network", t.data, t.len);
        g5c_bytes_clear(&t);
    }
    if (p->with_time) {
        time_t now = time(NULL);
        struct tm tmv;
        uint8_t tz = 0, ut[7];
        gmtime_r(&now, &tmv);
        setb(&m, "Local time zone", &tz, 1);
        ut[0] = bcd_swapped((unsigned)(tmv.tm_year % 100));
        ut[1] = bcd_swapped((unsigned)tmv.tm_mon + 1);
        ut[2] = bcd_swapped((unsigned)tmv.tm_mday);
        ut[3] = bcd_swapped((unsigned)tmv.tm_hour);
        ut[4] = bcd_swapped((unsigned)tmv.tm_min);
        ut[5] = bcd_swapped((unsigned)tmv.tm_sec);
        ut[6] = 0;
        setb(&m, "Universal time and local time zone", ut, 7);
        set1(&m, "Network daylight saving time", 0);
    }
    g5c_bytes_free(&t);
    return finish(&m, out);
}
