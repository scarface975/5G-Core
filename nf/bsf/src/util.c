#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Addresses, features, times and the merge patch. */
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "priv.h"

bool bsf_parse_ipv4(const char *s, uint32_t *out)
{
    struct in_addr a;
    if (s == NULL || inet_pton(AF_INET, s, &a) != 1)
        return false;
    *out = ntohl(a.s_addr);
    return true;
}

static bool split_len(const char *s, char *addr, size_t acap, unsigned max, unsigned *len)
{
    const char *slash = s != NULL ? strchr(s, '/') : NULL;
    char *end;
    unsigned long v;
    if (slash == NULL || (size_t)(slash - s) >= acap || slash == s)
        return false;
    memcpy(addr, s, (size_t)(slash - s));
    addr[slash - s] = '\0';
    if (!g5c_is_digits(slash + 1) || strlen(slash + 1) > 3)
        return false;
    v = strtoul(slash + 1, &end, 10);
    if (*end != '\0' || v > max)
        return false;
    *len = (unsigned)v;
    return true;
}

bool bsf_parse_pfx4(const char *s, pfx4_t *out)
{
    char addr[40];
    unsigned len;
    uint32_t a;
    if (!split_len(s, addr, sizeof addr, 32, &len) || !bsf_parse_ipv4(addr, &a))
        return false;
    out->len = (uint8_t)len;
    out->addr = len == 0 ? 0 : a & (0xFFFFFFFFu << (32 - len));
    return true;
}

static void mask6(uint8_t a[16], unsigned len)
{
    for (unsigned i = 0; i < 16; i++) {
        if (len >= (i + 1) * 8)
            continue;
        if (len <= i * 8)
            a[i] = 0;
        else
            a[i] &= (uint8_t)(0xFFu << (8 - (len - i * 8)));
    }
}

bool bsf_parse_pfx6(const char *s, pfx6_t *out)
{
    char addr[64];
    unsigned len;
    struct in6_addr a;
    if (!split_len(s, addr, sizeof addr, 128, &len) || inet_pton(AF_INET6, addr, &a) != 1)
        return false;
    memcpy(out->a, a.s6_addr, 16);
    out->len = (uint8_t)len;
    mask6(out->a, len);
    return true;
}

bool bsf_parse_mac(const char *s, mac_t *out)
{
    unsigned v[6];
    char c;
    if (s == NULL || strlen(s) != 17 || sscanf(s, "%2x-%2x-%2x-%2x-%2x-%2x%c", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &c) != 6)
        return false;
    for (int i = 0; i < 6; i++)
        out->m[i] = (uint8_t)v[i];
    return true;
}

bool bsf_pfx6_covers(const pfx6_t *p, const pfx6_t *addr)
{
    pfx6_t t;
    if (addr->len < p->len)
        return false;
    t = *addr;
    mask6(t.a, p->len);
    return memcmp(t.a, p->a, 16) == 0;
}

bool bsf_pfx4_covers(const pfx4_t *p, uint32_t addr)
{
    return p->len == 0 || (addr & (0xFFFFFFFFu << (32 - p->len))) == p->addr;
}

unsigned bsf_features_parse(const char *s)
{
    unsigned v = 0;
    if (s == NULL)
        return 0;
    for (size_t i = 0; s[i] != '\0' && i < 8; i++) {
        if (!isxdigit((unsigned char)s[i]))
            return 0;
        v = v * 16 + (unsigned)(isdigit((unsigned char)s[i]) ? s[i] - '0' : tolower((unsigned char)s[i]) - 'a' + 10);
    }
    return v;
}

char *bsf_features_str(unsigned f)
{
    return g5c_xasprintf("%x", f);
}

void bsf_merge_patch(g5c_json **doc, const g5c_json *patch)
{
    if (!g5c_json_is(patch, G5C_J_OBJECT)) {
        g5c_json_free(*doc);
        *doc = g5c_json_dup(patch);
        return;
    }
    if (!g5c_json_is(*doc, G5C_J_OBJECT)) {
        g5c_json_free(*doc);
        *doc = g5c_json_new_obj();
    }
    for (size_t i = 0; i < g5c_json_len(patch); i++) {
        const char *k = g5c_json_key_at(patch, i);
        const g5c_json *v = g5c_json_val_at(patch, i);
        if (g5c_json_is(v, G5C_J_NULL)) {
            g5c_json_remove(*doc, k);
        } else if (g5c_json_is(v, G5C_J_OBJECT)) {
            g5c_json *cur = g5c_json_detach(*doc, k);
            bsf_merge_patch(&cur, v);
            g5c_json_set(*doc, k, cur);
        } else {
            g5c_json_set(*doc, k, g5c_json_dup(v));
        }
    }
}

/* RFC 3339 date-time (the DateTime of TS 29.571 5.2.2) as milliseconds since the epoch, or -1 */
int64_t bsf_parse_rfc3339(const char *s)
{
    int y, mo, d, h, mi, sec, n = 0, oh = 0, om = 0;
    struct tm tmv;
    int64_t ms = 0;
    const char *p;
    if (s == NULL || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &mo, &d, &h, &mi, &sec, &n) != 6 || n != 19)
        return -1;
    p = s + 19;
    if (*p == '.') {
        int digits = 0;
        int64_t frac = 0;
        for (p++; isdigit((unsigned char)*p); p++, digits++)
            if (digits < 3)
                frac = frac * 10 + (*p - '0');
        if (digits == 0)
            return -1;
        for (int i = digits; i < 3; i++)
            frac *= 10;
        ms = frac;
    }
    if (*p == 'Z' || *p == 'z') {
        if (p[1] != 0)
            return -1;
    } else if ((*p == '+' || *p == '-') && sscanf(p + 1, "%2d:%2d%n", &oh, &om, &n) == 2 && n == 5 && p[6] == 0) {
        int off = (oh * 60 + om) * 60;
        if (oh > 23 || om > 59)
            return -1;
        if (*p == '+')
            off = -off;
        sec += off;
    } else {
        return -1;
    }
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || sec < -86400 || sec > 86400 + 61)
        return -1;
    memset(&tmv, 0, sizeof tmv);
    tmv.tm_year = y - 1900;
    tmv.tm_mon = mo - 1;
    tmv.tm_mday = d;
    tmv.tm_hour = h;
    tmv.tm_min = mi;
    tmv.tm_sec = sec;
    return (int64_t)timegm(&tmv) * 1000 + ms;
}
