/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* AKA/SQN, credential protection, SUPI/SUCI resolution and small utilities for the UDM. */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "g5c/eapaka.h"
#include "g5c/udm.h"

#define SQN_MASK ((1ULL << 48) - 1)

/* ---- AKA ------------------------------------------------------------------------------------------------------ */

uint64_t udm_next_sqn(uint64_t stored)
{
    return (stored + UDM_SQN_STEP) & SQN_MASK;
}

void udm_sqn_to_hex(uint64_t sqn, char out[13])
{
    snprintf(out, 13, "%012llx", (unsigned long long)(sqn & SQN_MASK));
}

bool udm_sqn_from_hex(const char *s, uint64_t *out)
{
    uint64_t v = 0;
    if (strlen(s) != 12)
        return false;
    for (size_t i = 0; i < 12; i++) {
        int d;
        if (s[i] >= '0' && s[i] <= '9')
            d = s[i] - '0';
        else if (s[i] >= 'a' && s[i] <= 'f')
            d = s[i] - 'a' + 10;
        else if (s[i] >= 'A' && s[i] <= 'F')
            d = s[i] - 'A' + 10;
        else
            return false;
        v = (v << 4) | (uint64_t)d;
    }
    *out = v;
    return true;
}

static void sqn_bytes(uint64_t sqn, uint8_t b[6])
{
    for (int i = 0; i < 6; i++)
        b[i] = (uint8_t)(sqn >> (8 * (5 - i)));
}

int udm_generate_av(const uint8_t k[16], const uint8_t opc[16], uint64_t sqn, const uint8_t amf[2],
                    const uint8_t rand[16], const char *snn, udm_heav *out)
{
    g5c_milenage m;
    g5c_milenage_vector v;
    uint8_t sqn6[6], mac_a[8], mac_s[8];
    g5c_milenage_init(&m, k, opc);
    sqn_bytes(sqn, sqn6);
    if (g5c_milenage_f1(&m, rand, sqn6, amf, mac_a, mac_s) != 0 || g5c_milenage_f2345(&m, rand, &v) != 0)
        return -1;
    memcpy(out->rand, rand, 16);
    g5c_autn(sqn6, v.ak, amf, mac_a, out->autn);
    if (g5c_res_star(v.ck, v.ik, snn, rand, v.res, 8, out->xres_star) != 0 ||
        g5c_kausf(v.ck, v.ik, snn, out->autn /* first 6 octets: SQN xor AK */, out->kausf) != 0)
        return -1;
    OPENSSL_cleanse(&v, sizeof v);
    return 0;
}

int udm_generate_av_prime(const uint8_t k[16], const uint8_t opc[16], uint64_t sqn, const uint8_t amf[2], const uint8_t rand[16], const char *snn, udm_hep *out)
{
    g5c_milenage m;
    g5c_milenage_vector v;
    uint8_t sqn6[6], mac_a[8], mac_s[8];
    int rc;
    if ((amf[0] & 0x80) == 0)
        return -1; /* RFC 5448 3.3: the AMF separation bit is set in an EAP-AKA' vector */
    g5c_milenage_init(&m, k, opc);
    sqn_bytes(sqn, sqn6);
    if (g5c_milenage_f1(&m, rand, sqn6, amf, mac_a, mac_s) != 0 || g5c_milenage_f2345(&m, rand, &v) != 0)
        return -1;
    memcpy(out->rand, rand, 16);
    g5c_autn(sqn6, v.ak, amf, mac_a, out->autn);
    memcpy(out->xres, v.res, 8);
    rc = g5c_ck_ik_prime(v.ck, v.ik, snn, out->autn /* SQN xor AK */, out->ck_prime, out->ik_prime);
    OPENSSL_cleanse(&v, sizeof v);
    return rc;
}

int udm_resync(const uint8_t k[16], const uint8_t opc[16], const uint8_t rand[16], const uint8_t auts[14],
               uint64_t *sqn_ms)
{
    g5c_milenage m;
    g5c_milenage_vector v;
    uint8_t sqn[6], mac_a[8], mac_s[8], zero_amf[2] = {0, 0};
    uint64_t s = 0;
    g5c_milenage_init(&m, k, opc);
    if (g5c_milenage_f2345(&m, rand, &v) != 0)
        return -1;
    for (int i = 0; i < 6; i++)
        sqn[i] = (uint8_t)(auts[i] ^ v.ak_star[i]);
    if (g5c_milenage_f1(&m, rand, sqn, zero_amf, mac_a, mac_s) != 0)
        return -1;
    if (CRYPTO_memcmp(mac_s, auts + 6, 8) != 0)
        return 1;
    for (int i = 0; i < 6; i++)
        s = (s << 8) | sqn[i];
    *sqn_ms = s;
    return 0;
}

/* ---- credential protection -------------------------------------------------------------------------------------- */

void udm_keys_none(udm_keys *k)
{
    memset(k, 0, sizeof *k);
}

void udm_keys_with_master(udm_keys *k, const uint8_t master[32])
{
    k->has_master = true;
    memcpy(k->master, master, 32);
}

int udm_keys_from_hex(udm_keys *k, const char *hex64)
{
    char buf[80];
    size_t n;
    uint8_t m[32];
    while (*hex64 == ' ' || *hex64 == '\t' || *hex64 == '\n' || *hex64 == '\r')
        hex64++;
    n = strlen(hex64);
    while (n > 0 && (hex64[n - 1] == ' ' || hex64[n - 1] == '\t' || hex64[n - 1] == '\n' || hex64[n - 1] == '\r'))
        n--;
    if (n != 64)
        return UDM_KEY_BAD_MASTER;
    memcpy(buf, hex64, n);
    buf[n] = 0;
    if (g5c_hex_decode(buf, m, 32) != 32)
        return UDM_KEY_BAD_MASTER;
    udm_keys_with_master(k, m);
    OPENSSL_cleanse(m, sizeof m);
    return 0;
}

int udm_protect(const udm_keys *k, const uint8_t *plain, size_t n, const char *supi, char **stored, const char **scheme)
{
    uint8_t *buf;
    int outl = 0, fin = 0;
    EVP_CIPHER_CTX *c;
    size_t total;
    if (!k->has_master) {
        *stored = g5c_hex_encode(plain, n);
        *scheme = UDM_PROT_NONE;
        return 0;
    }
    if (n > 4096)
        return UDM_KEY_MALFORMED;
    total = 12 + n + 16;
    buf = g5c_xmalloc(total);
    if (g5c_random(buf, 12) != 0) {
        free(buf);
        return UDM_KEY_RANDOM;
    }
    c = EVP_CIPHER_CTX_new();
    if (c == NULL ||
        EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, k->master, buf) != 1 ||
        EVP_EncryptUpdate(c, NULL, &outl, (const uint8_t *)supi, (int)strlen(supi)) != 1 ||
        (n > 0 && EVP_EncryptUpdate(c, buf + 12, &outl, plain, (int)n) != 1) ||
        EVP_EncryptFinal_ex(c, buf + 12 + n, &fin) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, buf + 12 + n) != 1) {
        EVP_CIPHER_CTX_free(c);
        free(buf);
        return UDM_KEY_DECRYPT;
    }
    EVP_CIPHER_CTX_free(c);
    *stored = g5c_hex_encode(buf, total);
    *scheme = UDM_PROT_AES256GCM;
    free(buf);
    return 0;
}

static int unprotect_m(const uint8_t *master, bool has_master, const char *stored, const char *scheme, const char *supi, uint8_t *out, size_t cap, size_t *len)
{
    size_t hl = strlen(stored), rl;
    uint8_t *raw;
    int rc = UDM_KEY_MALFORMED;
    if (hl % 2 != 0 || hl > 8192)
        return UDM_KEY_MALFORMED;
    rl = hl / 2;
    raw = g5c_xmalloc(rl ? rl : 1);
    if (g5c_hex_decode(stored, raw, rl) != (long)rl)
        goto done;
    if (scheme == NULL || strcmp(scheme, UDM_PROT_NONE) == 0) {
        if (rl > cap)
            goto done;
        memcpy(out, raw, rl);
        *len = rl;
        rc = 0;
    } else if (strcmp(scheme, UDM_PROT_AES256GCM) == 0) {
        EVP_CIPHER_CTX *c;
        size_t ctl;
        int outl = 0, fin = 0;
        if (!has_master) {
            rc = UDM_KEY_NO_MASTER;
            goto done;
        }
        if (rl < 12 + 16)
            goto done;
        ctl = rl - 12 - 16;
        if (ctl > cap)
            goto done;
        rc = UDM_KEY_DECRYPT;
        c = EVP_CIPHER_CTX_new();
        if (c != NULL && EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, master, raw) == 1 &&
            EVP_DecryptUpdate(c, NULL, &outl, (const uint8_t *)supi, (int)strlen(supi)) == 1 &&
            (ctl == 0 || EVP_DecryptUpdate(c, out, &outl, raw + 12, (int)ctl) == 1) &&
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, raw + 12 + ctl) == 1 &&
            EVP_DecryptFinal_ex(c, out + ctl, &fin) == 1) {
            *len = ctl;
            rc = 0;
        }
        EVP_CIPHER_CTX_free(c);
    } else {
        rc = UDM_KEY_SCHEME;
    }
done:
    OPENSSL_cleanse(raw, rl);
    free(raw);
    return rc;
}

int udm_unprotect_ex(const udm_keys *k, const char *stored, const char *scheme, const char *supi, uint8_t *out, size_t cap, size_t *len, bool *used_previous)
{
    int rc = unprotect_m(k->master, k->has_master, stored, scheme, supi, out, cap, len);
    if (used_previous != NULL)
        *used_previous = false;
    if (rc == UDM_KEY_DECRYPT && k->has_previous) {
        rc = unprotect_m(k->previous, true, stored, scheme, supi, out, cap, len);
        if (rc == 0 && used_previous != NULL)
            *used_previous = true;
    }
    return rc;
}

int udm_unprotect(const udm_keys *k, const char *stored, const char *scheme, const char *supi, uint8_t *out, size_t cap, size_t *len)
{
    return udm_unprotect_ex(k, stored, scheme, supi, out, cap, len, NULL);
}

int udm_keys_set_previous_hex(udm_keys *k, const char *hex64)
{
    udm_keys t;
    memset(&t, 0, sizeof t);
    if (udm_keys_from_hex(&t, hex64) != 0)
        return UDM_KEY_BAD_MASTER;
    k->has_previous = true;
    memcpy(k->previous, t.master, 32);
    OPENSSL_cleanse(&t, sizeof t);
    return 0;
}

/* ---- identity ------------------------------------------------------------------------------------------------------ */

static bool all_digits(const char *s, size_t n)
{
    if (n == 0)
        return false;
    for (size_t i = 0; i < n; i++)
        if (s[i] < '0' || s[i] > '9')
            return false;
    return true;
}

int udm_resolve(const char *id, const udm_hnkey *keys, size_t nkeys, char *out, size_t cap)
{
    const char *p[7];
    size_t pl[7];
    const char *rest;
    int n = 0;
    long scheme, key_id;
    char *e;
    char msin[32];

    if (strncmp(id, "imsi-", 5) == 0) {
        size_t dl = strlen(id + 5);
        if (dl < 6 || dl > 15 || !all_digits(id + 5, dl))
            return UDM_ID_MALFORMED;
        if (strlen(id) + 1 > cap)
            return UDM_ID_MALFORMED;
        memcpy(out, id, strlen(id) + 1); /* length checked against cap above */
        return 0;
    }
    if (strncmp(id, "suci-", 5) != 0)
        return UDM_ID_MALFORMED;
    rest = id + 5;
    /* <supi type>-<mcc>-<mnc>-<routing indicator>-<scheme id>-<hn key id>-<scheme output> (7 fields, last unsplit) */
    while (n < 6) {
        const char *d = strchr(rest, '-');
        if (d == NULL)
            return UDM_ID_MALFORMED;
        p[n] = rest;
        pl[n] = (size_t)(d - rest);
        n++;
        rest = d + 1;
    }
    p[6] = rest;
    pl[6] = strlen(rest);
    if (pl[0] != 1 || p[0][0] != '0')
        return UDM_ID_UNSUPPORTED;
    if (pl[1] != 3 || pl[2] < 2 || pl[2] > 3 || !all_digits(p[1], pl[1]) || !all_digits(p[2], pl[2]))
        return UDM_ID_MALFORMED;
    {
        char tmp[16];
        if (pl[4] == 0 || pl[4] > 8 || pl[5] == 0 || pl[5] > 8)
            return UDM_ID_MALFORMED;
        memcpy(tmp, p[4], pl[4]);
        tmp[pl[4]] = 0;
        scheme = strtol(tmp, &e, 10);
        if (*e != 0 || scheme < 0 || scheme > 255)
            return UDM_ID_MALFORMED;
        memcpy(tmp, p[5], pl[5]);
        tmp[pl[5]] = 0;
        key_id = strtol(tmp, &e, 10);
        if (*e != 0 || key_id < 0 || key_id > 255)
            return UDM_ID_MALFORMED;
    }
    if (scheme == 0) {
        if (pl[6] == 0 || pl[6] > 20 || !all_digits(p[6], pl[6]))
            return UDM_ID_MALFORMED;
        memcpy(msin, p[6], pl[6]);
        msin[pl[6]] = 0;
    } else if (scheme == 1 || scheme == 2) {
        g5c_profile prof = scheme == 1 ? G5C_PROFILE_A : G5C_PROFILE_B;
        const udm_hnkey *key = NULL;
        uint8_t output[256], bcd[64];
        long ol;
        size_t bl = 0;
        for (size_t i = 0; i < nkeys; i++)
            if (keys[i].id == key_id && keys[i].profile == prof) {
                key = &keys[i];
                break;
            }
        if (key == NULL)
            return UDM_ID_UNKNOWN_KEY;
        {
            char *hex = g5c_xstrndup(p[6], pl[6]);
            ol = g5c_hex_decode(hex, output, sizeof output);
            free(hex);
        }
        if (ol < 0)
            return UDM_ID_MALFORMED;
        if (g5c_suci_deconceal(prof, key->secret, output, (size_t)ol, bcd, sizeof bcd, &bl) != 0 ||
            g5c_bcd_to_msin(bcd, bl, msin, sizeof msin) != 0)
            return UDM_ID_DECONCEAL;
    } else {
        return UDM_ID_UNSUPPORTED;
    }
    if ((size_t)snprintf(out, cap, "imsi-%.*s%.*s%s", (int)pl[1], p[1], (int)pl[2], p[2], msin) >= cap)
        return UDM_ID_MALFORMED;
    return 0;
}

/* ---- util ----------------------------------------------------------------------------------------------------------- */

void udm_iso8601_utc(uint64_t secs, char out[21])
{
    int64_t days = (int64_t)(secs / 86400), rem = (int64_t)(secs % 86400);
    int64_t z = days + 719468, era = (z >= 0 ? z : z - 146096) / 146097, doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365, y = yoe + era * 400;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100), mp = (5 * doy + 2) / 153;
    int64_t d = doy - (153 * mp + 2) / 5 + 1, m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2)
        y++;
    {
        char tmp[96];
        snprintf(tmp, sizeof tmp, "%04lld-%02lld-%02lldT%02lld:%02lld:%02lldZ", (long long)y, (long long)m, (long long)d,
                 (long long)(rem / 3600), (long long)(rem % 3600 / 60), (long long)(rem % 60));
        memcpy(out, tmp, 20);
        out[20] = 0;
    }
}

void udm_now_iso8601(char out[21])
{
    time_t t = time(NULL);
    udm_iso8601_utc(t > 0 ? (uint64_t)t : 0, out);
}

bool udm_plmn_from_query(const char *q, char *out, size_t cap)
{
    g5c_json *j;
    const char *mcc, *mnc;
    bool ok = false;
    if (q == NULL)
        return false;
    j = g5c_json_parse(q, strlen(q), NULL, 0);
    mcc = g5c_json_get_str(j, "mcc");
    mnc = g5c_json_get_str(j, "mnc");
    if (mcc != NULL && mnc != NULL && strlen(mcc) + strlen(mnc) + 1 <= cap) {
        snprintf(out, cap, "%s%s", mcc, mnc);
        ok = true;
    }
    g5c_json_free(j);
    return ok;
}

bool udm_valid_snn(const char *s)
{
    /* "5G:mnc" 3 digits ".mcc" 3 digits ".3gppnetwork.org" */
    static const char tail[] = ".3gppnetwork.org";
    if (strncmp(s, "5G:mnc", 6) != 0 || !all_digits(s + 6, 3) || strncmp(s + 9, ".mcc", 4) != 0 ||
        !all_digits(s + 13, 3))
        return false;
    if (strncmp(s + 16, tail, sizeof tail - 1) != 0)
        return false;
    s += 16 + sizeof tail - 1;
    if (*s == 0)
        return true;
    /* optional SNPN network identifier (Release 16): ":" and 11 upper-case hex digits, pattern of TS 29.503 ServingNetworkName */
    if (*s != ':' || strlen(s + 1) != 11)
        return false;
    for (const char *c = s + 1; *c; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'A' && *c <= 'F')))
            return false;
    return true;
}
