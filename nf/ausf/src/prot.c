/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nausf_SoRProtection (TS 29.509 5.3, 6.2) and Nausf_UPUProtection (TS 29.509 5.4, 6.3) */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "priv.h"

#define SOR_BASE "/nausf-sorprotection/v1/{supi}/ue-sor/generate-sor-data"
#define UPU_BASE "/nausf-upuprotection/v1/{supi}/ue-upu/generate-upu-data"
#define MAX_SOR_ENTRIES 16 /* TS 24.501 9.11.3.51: octets 23 to 102 hold at most 16 entries of 5 octets */
#define MAX_SECURED_PACKET 1000
#define MAX_UPU_LIST 1000

/* ---- encodings ---- */

/* PLMN identity, 3 octets (TS 24.008 10.5.1.13): MCC2|MCC1, MNC3|MCC3, MNC2|MNC1; a two digit MNC has 1111 as its third digit */
static bool plmn_octets(const g5c_json *plmn, uint8_t out[3])
{
    const char *mcc = g5c_json_get_str(plmn, "mcc"), *mnc = g5c_json_get_str(plmn, "mnc");
    size_t ml;
    if (mcc == NULL || mnc == NULL || strlen(mcc) != 3 || !g5c_is_digits(mcc) || !g5c_is_digits(mnc))
        return false;
    ml = strlen(mnc);
    if (ml != 2 && ml != 3)
        return false;
    out[0] = (uint8_t)(((mcc[1] - '0') << 4) | (mcc[0] - '0'));
    out[1] = (uint8_t)(((ml == 3 ? mnc[2] - '0' : 0xF) << 4) | (mcc[2] - '0'));
    out[2] = (uint8_t)(((mnc[1] - '0') << 4) | (mnc[0] - '0'));
    return true;
}

/* one access technology of TS 29.571 / TS 29.509 6.2.6.3.3 into the two octets of EFPLMNwAcT (TS 31.102 4.2.5) */
static bool act_bits(const char *name, uint8_t *o1, uint8_t *o2)
{
    static const struct {
        const char *name;
        uint8_t o1, o2;
    } T[] = {{"NR", 0x08, 0},
             {"SATELLITE_NG_RAN", 0x04, 0},
             {"EUTRAN_IN_WBS1_MODE_AND_NBS1_MODE", 0x40, 0}, /* b7 b6 b5 = 1 0 0 */
             {"EUTRAN_IN_NBS1_MODE_ONLY", 0x50, 0},          /* 1 0 1 */
             {"EUTRAN_IN_WBS1_MODE_ONLY", 0x60, 0},          /* 1 1 0 */
             {"UTRAN", 0x80, 0},
             {"GSM_AND_ECGSM_IoT", 0, 0x80},     /* b8 b4 b3 = 1 0 0 */
             {"GSM_WITHOUT_ECGSM_IoT", 0, 0x84}, /* 1 0 1 */
             {"ECGSM_IoT_ONLY", 0, 0x88},        /* 1 1 0 */
             {"CDMA_1xRTT", 0, 0x10},
             {"CDMA_HRPD", 0, 0x20},
             {"GSM_COMPACT", 0, 0x40}};
    for (size_t i = 0; i < sizeof T / sizeof *T; i++)
        if (strcmp(name, T[i].name) == 0) {
            *o1 |= T[i].o1;
            *o2 |= T[i].o2;
            return true;
        }
    return false;
}

/* the PLMN ID and access technology list (TS 24.501 Figure 9.11.3.51.3) of a steering container array; false on an invalid entry */
static bool encode_steering(const g5c_json *arr, uint8_t *out, size_t *len)
{
    size_t n = g5c_json_len(arr);
    if (n > MAX_SOR_ENTRIES)
        return false;
    for (size_t i = 0; i < n; i++) {
        const g5c_json *e = g5c_json_at(arr, i), *al;
        uint8_t o1 = 0, o2 = 0;
        if (!g5c_json_is(e, G5C_J_OBJECT) || !plmn_octets(g5c_json_get(e, "plmnId"), out + 5 * i))
            return false;
        al = g5c_json_get(e, "accessTechList");
        if (al == NULL || g5c_json_is(al, G5C_J_NULL) || g5c_json_len(al) == 0) {
            /* TS 29.509 6.2.6.2.4: absent means every access technology is equally preferred */
            o1 = 0xCC; /* UTRAN, E-UTRAN (WB-S1 and NB-S1), NG-RAN, satellite NG-RAN */
            o2 = 0xF0; /* GSM, GSM COMPACT, cdma2000 HRPD, cdma2000 1xRTT */
        } else {
            if (!g5c_json_is(al, G5C_J_ARRAY))
                return false;
            for (size_t k = 0; k < g5c_json_len(al); k++) {
                const char *t = g5c_json_str(g5c_json_at(al, k));
                if (t == NULL || !act_bits(t, &o1, &o2))
                    return false;
            }
        }
        out[5 * i + 3] = o1;
        out[5 * i + 4] = o2;
    }
    *len = 5 * n;
    return true;
}

/* ---- the counters ---- */

typedef struct {
    uint8_t kausf[32];
    uint16_t counter;
} grant_t;

/* the counter to use for the next MAC of `supi` and the KAUSF; 0 granted, 1 no such UE, 2 the counter is about to wrap (TS 33.501 6.14.2.3) */
static int grant(ausf *a, const char *supi, bool sor, grant_t *g)
{
    ausf_ue *u;
    pthread_mutex_lock(&a->mu);
    u = hmap_get(&a->ues, supi);
    if (u == NULL) {
        pthread_mutex_unlock(&a->mu);
        return 1;
    }
    {
        uint16_t *ctr = sor ? &u->counter_sor : &u->counter_upu;
        if (*ctr == 0xFFFF) {
            pthread_mutex_unlock(&a->mu);
            return 2; /* the service is suspended until a fresh KAUSF is stored */
        }
        g->counter = *ctr;
        (*ctr)++; /* "monotonically increment it for each additional calculated MAC" */
    }
    memcpy(g->kausf, u->kausf, 32);
    a->dirty = true;
    pthread_cond_signal(&a->cv);
    pthread_mutex_unlock(&a->mu);
    return 0;
}

static int mac128(const uint8_t kausf[32], uint8_t fc, const uint8_t *const *p, const size_t *l, size_t n, uint8_t out[16])
{
    uint8_t full[32];
    if (g5c_kdf(kausf, 32, fc, p, l, n, full) != 0)
        return -1;
    memcpy(out, full + 16, 16); /* the 128 least significant bits (TS 33.501 A.17 to A.20) */
    OPENSSL_cleanse(full, sizeof full);
    return 0;
}

static int check_supi(const g5c_req *req, g5c_resp *resp, const char **supi)
{
    *supi = g5c_req_param(req, "supi");
    if (*supi == NULL || !ausf_valid_supi(*supi)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "supi", "not a SUPI");
        return -1;
    }
    return 0;
}

static void grant_failure(int rc, const char *what, g5c_resp *resp)
{
    if (rc == 1)
        g5c_resp_problem_simple(resp, 404, "CONTEXT_NOT_FOUND", "no security context for this UE");
    else
        g5c_resp_problem_simple(resp, 503, "COUNTER_WRAP", what);
}

/* ---- Nausf_SoRProtection ---- */

static void sor_generate(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    ausf *a = ctx;
    g5c_json *j;
    const char *supi;
    const g5c_json *sc;
    bool ack = false;
    uint8_t list[5 * MAX_SOR_ENTRIES], pkt[MAX_SECURED_PACKET], hdr, ctr[2], mac[16], xmac[16];
    size_t ll = 0;
    bool has_list = false, plmn_list = false;
    const uint8_t *p[3];
    size_t l[3], np;
    grant_t g;
    int rc;
    g5c_json *out;
    char *h;

    memset(&g, 0, sizeof g);
    if (check_supi(req, resp, &supi) != 0)
        return;
    j = g5c_req_json(req, resp);
    if (j == NULL)
        return;
    if (!g5c_json_get_bool(j, "ackInd", &ack)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "ackInd", "mandatory boolean");
        goto done;
    }
    sc = g5c_json_get(j, "steeringContainer");
    if (sc != NULL && !g5c_json_is(sc, G5C_J_NULL)) {
        if (g5c_json_is(sc, G5C_J_ARRAY)) {
            if (g5c_json_len(sc) > 0) {
                if (!encode_steering(sc, list, &ll)) {
                    g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "steeringContainer", "at most 16 PLMN identities with known access technologies");
                    goto done;
                }
                has_list = plmn_list = true;
            } /* an empty list: the HPLMN indication that no change is needed (TS 29.509 5.3.1) */
        } else if (g5c_json_str(sc) != NULL) {
            long n = g5c_base64_decode(g5c_json_str(sc), pkt, sizeof pkt);
            if (n <= 0) {
                g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "steeringContainer", "not a base64 secured packet");
                goto done;
            }
            ll = (size_t)n;
            has_list = true;
        } else {
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "steeringContainer", "an array of SteeringInfo or a secured packet");
            goto done;
        }
    }
    /* TS 24.501 9.11.3.51 Figure 9.11.3.51.5: bit 1 SOR data type 0, bit 2 list indication, bit 3 list type, bit 4 ACK */
    hdr = (uint8_t)((ack ? 8 : 0) | (plmn_list ? 4 : 0) | (has_list ? 2 : 0));
    rc = grant(a, supi, true, &g);
    if (rc != 0) {
        ausf_count(a, "g5c_ausf_sor_total", "SoR protection requests by result.", "result", rc == 1 ? "no_context" : "counter_wrap");
        grant_failure(rc, "CounterSoR is about to wrap around: the SoR protection is suspended until the UE authenticates again", resp);
        goto done;
    }
    ctr[0] = (uint8_t)(g.counter >> 8);
    ctr[1] = (uint8_t)g.counter;
    p[0] = &hdr;
    l[0] = 1;
    p[1] = ctr;
    l[1] = 2;
    np = 2;
    if (has_list) {
        p[2] = plmn_list ? list : pkt;
        l[2] = ll;
        np = 3;
    }
    if (mac128(g.kausf, 0x77, p, l, np, mac) != 0) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "crypto failure");
        goto done;
    }
    out = g5c_json_new_obj();
    h = g5c_hex_encode(mac, 16);
    g5c_json_set_str(out, "sorMacIausf", h);
    free(h);
    h = g5c_xasprintf("%04x", g.counter);
    g5c_json_set_str(out, "counterSor", h);
    free(h);
    if (ack) {
        static const uint8_t one = 1;
        const uint8_t *xp[2] = {&one, ctr};
        const size_t xl[2] = {1, 2};
        if (mac128(g.kausf, 0x78, xp, xl, 2, xmac) != 0) {
            g5c_json_free(out);
            g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "crypto failure");
            goto done;
        }
        h = g5c_hex_encode(xmac, 16);
        g5c_json_set_str(out, "sorXmacIue", h);
        free(h);
    }
    g5c_resp_json(resp, 200, out);
    ausf_no_store(resp);
    g5c_json_free(out);
    ausf_count(a, "g5c_ausf_sor_total", "SoR protection requests by result.", "result", "ok");
done:
    OPENSSL_cleanse(&g, sizeof g);
    g5c_json_free(j);
}

/* ---- Nausf_UPUProtection ---- */

/* one S-NSSAI value of the NSSAI IE: length octet, SST, SD when given (TS 24.501 9.11.2.8) */
static bool encode_snssai(const g5c_json *s, uint8_t *out, size_t *n)
{
    int64_t sst;
    const char *sd = g5c_json_get_str(s, "sd");
    if (!g5c_json_get_int(s, "sst", &sst) || sst < 0 || sst > 255)
        return false;
    out[1] = (uint8_t)sst;
    if (sd == NULL) {
        out[0] = 1;
        *n = 2;
        return true;
    }
    if (strlen(sd) != 6 || g5c_hex_decode(sd, out + 2, 3) != 3)
        return false;
    out[0] = 4;
    *n = 5;
    return true;
}

/* append "type | length(2) | data" of one UE parameters update data set (TS 24.501 Figure 9.11.3.53A.2) */
static bool put_set(uint8_t *buf, size_t *off, uint8_t type, const uint8_t *data, size_t dl)
{
    if (*off + 3 + dl > MAX_UPU_LIST)
        return false;
    buf[(*off)++] = type;
    buf[(*off)++] = (uint8_t)(dl >> 8);
    buf[(*off)++] = (uint8_t)dl;
    memcpy(buf + *off, data, dl);
    *off += dl;
    return true;
}

static bool encode_upu(const g5c_json *arr, uint8_t *buf, size_t *len)
{
    size_t off = 0;
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const g5c_json *d = g5c_json_at(arr, i), *nssai = g5c_json_get(d, "defaultConfNssai");
        const char *sec = g5c_json_get_str(d, "secPacket"), *rid = g5c_json_get_str(d, "routingId");
        if (!g5c_json_is(d, G5C_J_OBJECT))
            return false;
        if (g5c_json_get(d, "secPacket") != NULL && sec == NULL)
            return false;
        if (sec != NULL) {
            uint8_t pkt[MAX_SECURED_PACKET];
            long n = g5c_base64_decode(sec, pkt, sizeof pkt);
            if (n <= 0 || !put_set(buf, &off, 0x01, pkt, (size_t)n)) /* routing indicator update data: a secured packet */
                return false;
        }
        if (nssai != NULL && !g5c_json_is(nssai, G5C_J_NULL)) {
            uint8_t v[16 * 5];
            size_t vl = 0;
            if (!g5c_json_is(nssai, G5C_J_ARRAY) || g5c_json_len(nssai) == 0 || g5c_json_len(nssai) > 16) /* TS 24.501 9.11.3.37 NOTE 3 */
                return false;
            for (size_t k = 0; k < g5c_json_len(nssai); k++) {
                size_t n = 0;
                if (!encode_snssai(g5c_json_at(nssai, k), v + vl, &n))
                    return false;
                vl += n;
            }
            if (!put_set(buf, &off, 0x02, v, vl)) /* default configured NSSAI update data */
                return false;
        }
        if (rid != NULL) {
            uint8_t v[2] = {0xFF, 0xFF};
            size_t n = strlen(rid);
            if (n < 1 || n > 4 || !g5c_is_digits(rid))
                return false;
            /* TS 24.501 9.11.3.4: digit 1 and 3 in bits 1 to 4, digit 2 and 4 in bits 5 to 8, unused digits 1111 */
            for (size_t k = 0; k < n; k++) {
                uint8_t dg = (uint8_t)(rid[k] - '0');
                v[k / 2] = (uint8_t)((v[k / 2] & (k % 2 == 0 ? 0xF0 : 0x0F)) | (k % 2 == 0 ? dg : dg << 4));
            }
            if (!put_set(buf, &off, 0x04, v, 2)) /* ME routing indicator update data */
                return false;
        }
        if (sec == NULL && (nssai == NULL || g5c_json_is(nssai, G5C_J_NULL)) && rid == NULL)
            return false; /* an UpuData without content */
    }
    *len = off;
    return off > 0;
}

static void upu_generate(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    ausf *a = ctx;
    g5c_json *j;
    const g5c_json *list;
    const char *supi, *hdr_s;
    bool ack = false;
    uint8_t data[MAX_UPU_LIST], hdr, ctr[2], mac[16], xmac[16];
    size_t dl = 0;
    grant_t g;
    int rc;
    g5c_json *out;
    char *h;
    const uint8_t *p[2];
    size_t l[2];

    memset(&g, 0, sizeof g);
    if (check_supi(req, resp, &supi) != 0)
        return;
    j = g5c_req_json(req, resp);
    if (j == NULL)
        return;
    list = g5c_json_get(j, "upuDataList");
    hdr_s = g5c_json_get_str(j, "upuHeader");
    if (!g5c_json_is(list, G5C_J_ARRAY) || g5c_json_len(list) == 0) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "upuDataList", "a non-empty array of UpuData");
        goto done;
    }
    if (hdr_s == NULL || strlen(hdr_s) != 2 || g5c_hex_decode(hdr_s, &hdr, 1) != 1 || (hdr & 1) != 0) {
        /* TS 29.509 6.3.6.3.2: two hexadecimal characters; bit 1 is the UPU data type, 0 for update data */
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "upuHeader", "two hexadecimal characters, UPU data type 0");
        goto done;
    }
    if (!g5c_json_get_bool(j, "upuAckInd", &ack)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "upuAckInd", "mandatory boolean");
        goto done;
    }
    if (!encode_upu(list, data, &dl)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "upuDataList", "invalid UE parameters update data");
        goto done;
    }
    rc = grant(a, supi, false, &g);
    if (rc != 0) {
        ausf_count(a, "g5c_ausf_upu_total", "UPU protection requests by result.", "result", rc == 1 ? "no_context" : "counter_wrap");
        grant_failure(rc, "CounterUPU is about to wrap around: the UPU protection is suspended until the UE authenticates again", resp);
        goto done;
    }
    ctr[0] = (uint8_t)(g.counter >> 8);
    ctr[1] = (uint8_t)g.counter;
    p[0] = data; /* TS 33.501 A.19: the UE parameters update list, then CounterUPU */
    l[0] = dl;
    p[1] = ctr;
    l[1] = 2;
    if (mac128(g.kausf, 0x7B, p, l, 2, mac) != 0) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "crypto failure");
        goto done;
    }
    out = g5c_json_new_obj();
    h = g5c_hex_encode(mac, 16);
    g5c_json_set_str(out, "upuMacIausf", h);
    free(h);
    h = g5c_xasprintf("%04x", g.counter);
    g5c_json_set_str(out, "counterUpu", h);
    free(h);
    if (ack) {
        static const uint8_t one = 1;
        const uint8_t *xp[2] = {&one, ctr};
        const size_t xl[2] = {1, 2};
        if (mac128(g.kausf, 0x7C, xp, xl, 2, xmac) != 0) {
            g5c_json_free(out);
            g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "crypto failure");
            goto done;
        }
        h = g5c_hex_encode(xmac, 16);
        g5c_json_set_str(out, "upuXmacIue", h);
        free(h);
    }
    g5c_resp_json(resp, 200, out);
    ausf_no_store(resp);
    g5c_json_free(out);
    ausf_count(a, "g5c_ausf_upu_total", "UPU protection requests by result.", "result", "ok");
done:
    OPENSSL_cleanse(&g, sizeof g);
    g5c_json_free(j);
}

void ausf_prot_routes(g5c_router *r, ausf *a)
{
    g5c_router_route(r, "POST", SOR_BASE, sor_generate, a);
    g5c_router_route(r, "POST", UPU_BASE, upu_generate, a);
}
