/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Typed views of the information elements the core needs first (TS 24.501 clause 9.11). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/nas.h"

static int bad(void)
{
    return NAS_E_INVALID;
}

/* ---- PLMN ---- */

int nas_plmn_decode(const uint8_t *b, size_t len, char mcc[4], char mnc[4])
{
    uint8_t d[6];
    if (len < 3)
        return NAS_E_TRUNCATED;
    d[0] = b[0] & 0xf;
    d[1] = (uint8_t)(b[0] >> 4);
    d[2] = b[1] & 0xf;
    d[3] = b[2] & 0xf;
    d[4] = (uint8_t)(b[2] >> 4);
    d[5] = (uint8_t)(b[1] >> 4);
    for (int i = 0; i < 5; i++)
        if (d[i] > 9)
            return bad();
    mcc[0] = (char)('0' + d[0]);
    mcc[1] = (char)('0' + d[1]);
    mcc[2] = (char)('0' + d[2]);
    mcc[3] = 0;
    mnc[0] = (char)('0' + d[3]);
    mnc[1] = (char)('0' + d[4]);
    if (d[5] != 0xf) {
        if (d[5] > 9)
            return bad();
        mnc[2] = (char)('0' + d[5]);
        mnc[3] = 0;
    } else {
        mnc[2] = 0;
    }
    return NAS_OK;
}

int nas_plmn_encode(const char *mcc, const char *mnc, uint8_t out[3])
{
    size_t nl = strlen(mnc);
    uint8_t m[3], n[3];
    if (strlen(mcc) != 3 || nl < 2 || nl > 3 || !g5c_is_digits(mcc) || !g5c_is_digits(mnc))
        return bad();
    for (int i = 0; i < 3; i++)
        m[i] = (uint8_t)(mcc[i] - '0');
    n[0] = (uint8_t)(mnc[0] - '0');
    n[1] = (uint8_t)(mnc[1] - '0');
    n[2] = nl == 3 ? (uint8_t)(mnc[2] - '0') : 0xf;
    out[0] = (uint8_t)((m[1] << 4) | m[0]);
    out[1] = (uint8_t)((n[2] << 4) | m[2]);
    out[2] = (uint8_t)((n[1] << 4) | n[0]);
    return NAS_OK;
}

/* ---- BCD ---- */

/* Digits of b (low nibble first), stopping at a non-digit nibble; at most max digits. */
static size_t bcd_digits(const uint8_t *b, size_t n, char *out, size_t max)
{
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t nib[2] = {(uint8_t)(b[i] & 0xf), (uint8_t)(b[i] >> 4)};
        for (int j = 0; j < 2; j++)
            if (nib[j] <= 9 && k < max)
                out[k++] = (char)('0' + nib[j]);
    }
    out[k] = 0;
    return k;
}

static int bcd_pack(const char *digits, size_t octets, uint8_t *out)
{
    size_t n = strlen(digits);
    if (n > octets * 2 || (n && !g5c_is_digits(digits)))
        return bad();
    for (size_t i = 0; i < octets; i++) {
        uint8_t lo = 2 * i < n ? (uint8_t)(digits[2 * i] - '0') : 0xf;
        uint8_t hi = 2 * i + 1 < n ? (uint8_t)(digits[2 * i + 1] - '0') : 0xf;
        out[i] = (uint8_t)(lo | (hi << 4));
    }
    return NAS_OK;
}

/* ---- 5GS mobile identity ---- */

int nas_mobile_identity_decode(const uint8_t *v, size_t len, nas_mobile_identity *out)
{
    uint8_t t;
    memset(out, 0, sizeof *out);
    if (len == 0)
        return NAS_E_TRUNCATED;
    t = v[0];
    switch (t & 0x07) {
    case 0:
        out->kind = NAS_ID_NONE;
        return NAS_OK;
    case 1: {
        int rc;
        if (len < 8)
            return NAS_E_TRUNCATED;
        if (len - 8 > NAS_ID_MAX_OUTPUT)
            return bad();
        out->kind = NAS_ID_SUCI;
        out->supi_format = (uint8_t)((t >> 4) & 0x07);
        rc = nas_plmn_decode(v + 1, 3, out->mcc, out->mnc);
        if (rc != NAS_OK)
            return rc;
        bcd_digits(v + 4, 2, out->routing_indicator, 4);
        out->scheme = v[6] & 0x0f;
        out->hn_key_id = v[7];
        out->output_len = len - 8;
        memcpy(out->output, v + 8, out->output_len);
        return NAS_OK;
    }
    case 2: {
        int rc;
        if (len < 11)
            return NAS_E_TRUNCATED;
        out->kind = NAS_ID_GUTI;
        rc = nas_plmn_decode(v + 1, 3, out->mcc, out->mnc);
        if (rc != NAS_OK)
            return rc;
        out->amf_region = v[4];
        out->amf_set = (uint16_t)(((unsigned)v[5] << 2) | (v[6] >> 6));
        out->amf_pointer = v[6] & 0x3f;
        out->tmsi = ((uint32_t)v[7] << 24) | ((uint32_t)v[8] << 16) | ((uint32_t)v[9] << 8) | v[10];
        return NAS_OK;
    }
    case 4:
        if (len < 7)
            return NAS_E_TRUNCATED;
        out->kind = NAS_ID_STMSI;
        out->amf_set = (uint16_t)(((unsigned)v[1] << 2) | (v[2] >> 6));
        out->amf_pointer = v[2] & 0x3f;
        out->tmsi = ((uint32_t)v[3] << 24) | ((uint32_t)v[4] << 16) | ((uint32_t)v[5] << 8) | v[6];
        return NAS_OK;
    case 3:
    case 5: {
        /* first digit in the high nibble of octet 1; odd/even indicator in bit 4 */
        bool odd = (t & 0x08) != 0;
        size_t k = 0;
        uint8_t d0 = (uint8_t)(t >> 4);
        out->kind = (t & 0x07) == 3 ? NAS_ID_IMEI : NAS_ID_IMEISV;
        if (len > 10) /* at most 15/16 digits */
            return bad();
        out->digits[k++] = (char)('0' + (d0 > 9 ? 9 : d0));
        for (size_t i = 1; i < len; i++) {
            uint8_t lo = v[i] & 0xf, hi = (uint8_t)(v[i] >> 4);
            out->digits[k++] = (char)('0' + (lo > 9 ? 9 : lo));
            if (odd || i + 1 < len)
                out->digits[k++] = (char)('0' + (hi > 9 ? 9 : hi));
        }
        out->digits[k] = 0;
        return NAS_OK;
    }
    default:
        if (len - 1 > NAS_ID_MAX_OUTPUT)
            return bad();
        out->kind = NAS_ID_OTHER;
        out->other_type = t & 0x07;
        out->output_len = len - 1;
        memcpy(out->output, v + 1, out->output_len);
        return NAS_OK;
    }
}

int nas_mobile_identity_encode(const nas_mobile_identity *id, g5c_bytes *out)
{
    uint8_t b[16];
    int rc;
    switch (id->kind) {
    case NAS_ID_NONE:
        return g5c_bytes_putc(out, 0) == 0 ? NAS_OK : bad();
    case NAS_ID_SUCI: {
        uint8_t ri[2];
        char t = (char)(0x01 | ((id->supi_format & 0x07) << 4));
        rc = nas_plmn_encode(id->mcc, id->mnc, b);
        if (rc != NAS_OK)
            return rc;
        rc = bcd_pack(id->routing_indicator, 2, ri);
        if (rc != NAS_OK)
            return rc;
        if (g5c_bytes_putc(out, t) != 0 || g5c_bytes_append(out, b, 3) != 0 || g5c_bytes_append(out, ri, 2) != 0 ||
            g5c_bytes_putc(out, (char)(id->scheme & 0x0f)) != 0 || g5c_bytes_putc(out, (char)id->hn_key_id) != 0 ||
            g5c_bytes_append(out, id->output, id->output_len) != 0)
            return bad();
        return NAS_OK;
    }
    case NAS_ID_GUTI:
        rc = nas_plmn_encode(id->mcc, id->mnc, b);
        if (rc != NAS_OK)
            return rc;
        b[3] = id->amf_region;
        b[4] = (uint8_t)(id->amf_set >> 2);
        b[5] = (uint8_t)(((id->amf_set & 0x3) << 6) | (id->amf_pointer & 0x3f));
        b[6] = (uint8_t)(id->tmsi >> 24);
        b[7] = (uint8_t)(id->tmsi >> 16);
        b[8] = (uint8_t)(id->tmsi >> 8);
        b[9] = (uint8_t)id->tmsi;
        if (g5c_bytes_putc(out, (char)0xf2) != 0 || g5c_bytes_append(out, b, 10) != 0)
            return bad();
        return NAS_OK;
    case NAS_ID_STMSI:
        b[0] = 0xf4;
        b[1] = (uint8_t)(id->amf_set >> 2);
        b[2] = (uint8_t)(((id->amf_set & 0x3) << 6) | (id->amf_pointer & 0x3f));
        b[3] = (uint8_t)(id->tmsi >> 24);
        b[4] = (uint8_t)(id->tmsi >> 16);
        b[5] = (uint8_t)(id->tmsi >> 8);
        b[6] = (uint8_t)id->tmsi;
        return g5c_bytes_append(out, b, 7) == 0 ? NAS_OK : bad();
    case NAS_ID_OTHER:
        if (g5c_bytes_putc(out, (char)(id->other_type & 0x07)) != 0 ||
            g5c_bytes_append(out, id->output, id->output_len) != 0)
            return bad();
        return NAS_OK;
    default:
        return bad(); /* IMEI encoding not supported */
    }
}

bool nas_suci_null_scheme_msin(const nas_mobile_identity *id, char *out, size_t cap)
{
    if (id->kind != NAS_ID_SUCI || id->scheme != 0 || cap < 16)
        return false;
    bcd_digits(id->output, id->output_len, out, 15);
    return true;
}

char *nas_suci_to_string(const nas_mobile_identity *id)
{
    char msin[16];
    char *out, *hex = NULL;
    const char *tail;
    if (nas_suci_null_scheme_msin(id, msin, sizeof msin)) {
        tail = msin;
    } else {
        hex = g5c_hex_encode(id->output, id->output_len);
        tail = hex;
    }
    out = g5c_xasprintf("suci-%u-%s-%s-%s-%u-%u-%s", id->supi_format, id->mcc, id->mnc, id->routing_indicator, id->scheme,
                        id->hn_key_id, tail);
    free(hex);
    return out;
}

/* ---- small nibble IEs ---- */

nas_ngksi nas_ngksi_from_nibble(uint8_t n)
{
    nas_ngksi k = {(n & 0x08) != 0, (uint8_t)(n & 0x07)};
    return k;
}

uint8_t nas_ngksi_to_nibble(nas_ngksi k)
{
    return (uint8_t)(((unsigned)k.mapped << 3) | (k.ksi & 0x07));
}

nas_reg_type nas_reg_type_from_nibble(uint8_t n)
{
    nas_reg_type r = {(n & 0x08) != 0, (uint8_t)(n & 0x07)};
    return r;
}

uint8_t nas_reg_type_to_nibble(nas_reg_type r)
{
    return (uint8_t)(((unsigned)r.follow_on << 3) | (r.kind & 0x07));
}

int nas_ue_sec_cap_decode(const uint8_t *v, size_t len, nas_ue_sec_cap *out)
{
    memset(out, 0, sizeof *out);
    if (len < 2)
        return NAS_E_TRUNCATED;
    out->ea = v[0];
    out->ia = v[1];
    if (len >= 4) {
        out->has_eps = true;
        out->eea = v[2];
        out->eia = v[3];
    }
    return NAS_OK;
}

size_t nas_ue_sec_cap_encode(const nas_ue_sec_cap *c, uint8_t out[4])
{
    out[0] = c->ea;
    out[1] = c->ia;
    if (c->has_eps) {
        out[2] = c->eea;
        out[3] = c->eia;
        return 4;
    }
    return 2;
}

bool nas_supports_ea(const nas_ue_sec_cap *c, unsigned n)
{
    return n < 8 && (c->ea & (0x80U >> n)) != 0;
}

bool nas_supports_ia(const nas_ue_sec_cap *c, unsigned n)
{
    return n < 8 && (c->ia & (0x80U >> n)) != 0;
}

uint8_t nas_selected_algorithms(uint8_t ciphering, uint8_t integrity)
{
    return (uint8_t)(((ciphering & 0x0f) << 4) | (integrity & 0x0f));
}

/* ---- S-NSSAI / NSSAI / DNN ---- */

int nas_snssai_decode(const uint8_t *v, size_t len, nas_snssai *out)
{
    memset(out, 0, sizeof *out);
    if (len == 1) {
        out->sst = v[0];
        return NAS_OK;
    }
    if (len >= 4) {
        out->sst = v[0];
        out->has_sd = true;
        out->sd = ((uint32_t)v[1] << 16) | ((uint32_t)v[2] << 8) | v[3];
        return NAS_OK;
    }
    return bad();
}

size_t nas_snssai_encode(const nas_snssai *s, uint8_t out[4])
{
    out[0] = s->sst;
    if (s->has_sd) {
        out[1] = (uint8_t)(s->sd >> 16);
        out[2] = (uint8_t)(s->sd >> 8);
        out[3] = (uint8_t)s->sd;
        return 4;
    }
    return 1;
}

int nas_nssai_decode(const uint8_t *v, size_t len, nas_snssai *out, size_t cap)
{
    size_t n = 0;
    while (len > 0) {
        size_t l = v[0];
        if (l > len - 1)
            return NAS_E_TRUNCATED;
        if (n == cap)
            return bad();
        if (nas_snssai_decode(v + 1, l, &out[n]) != NAS_OK)
            return bad();
        n++;
        v += 1 + l;
        len -= 1 + l;
    }
    return (int)n;
}

int nas_nssai_encode(const nas_snssai *list, size_t n, g5c_bytes *out)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t e[4];
        size_t l = nas_snssai_encode(&list[i], e);
        if (g5c_bytes_putc(out, (char)l) != 0 || g5c_bytes_append(out, e, l) != 0)
            return bad();
    }
    return NAS_OK;
}

int nas_dnn_decode(const uint8_t *v, size_t len, char *out, size_t cap)
{
    size_t i = 0, o = 0;
    while (i < len) {
        size_t n = v[i];
        if (n > len - i - 1)
            return NAS_E_TRUNCATED;
        if (o + n + 2 > cap)
            return bad();
        if (o > 0)
            out[o++] = '.';
        for (size_t k = 0; k < n; k++) {
            unsigned char c = v[i + 1 + k];
            if (c < 0x20 || c > 0x7e) /* labels are printable ASCII (the previous decoder demanded UTF-8) */
                return bad();
            out[o++] = (char)c;
        }
        i += 1 + n;
    }
    out[o] = 0;
    return NAS_OK;
}

int nas_dnn_encode(const char *dnn, g5c_bytes *out)
{
    const char *p = dnn;
    for (;;) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 62)
            return bad();
        if (g5c_bytes_putc(out, (char)l) != 0 || g5c_bytes_append(out, p, l) != 0)
            return bad();
        if (!dot)
            break;
        p = dot + 1;
    }
    return NAS_OK;
}
