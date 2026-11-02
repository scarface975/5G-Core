/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Base64 of RFC 4648 clause 4 (standard alphabet, '=' padding), as used by the 3GPP "format: base64" strings (EapPayload, SecuredPacket). */
#include <string.h>

#include "g5c/base.h"

static const char ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *g5c_base64_encode(const uint8_t *p, size_t n)
{
    char *out = g5c_xmalloc(4 * ((n + 2) / 3) + 1), *w = out;
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8) | p[i + 2];
        *w++ = ALPHA[v >> 18];
        *w++ = ALPHA[(v >> 12) & 63];
        *w++ = ALPHA[(v >> 6) & 63];
        *w++ = ALPHA[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)p[i] << 16;
        *w++ = ALPHA[v >> 18];
        *w++ = ALPHA[(v >> 12) & 63];
        *w++ = '=';
        *w++ = '=';
    } else if (n - i == 2) {
        uint32_t v = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8);
        *w++ = ALPHA[v >> 18];
        *w++ = ALPHA[(v >> 12) & 63];
        *w++ = ALPHA[(v >> 6) & 63];
        *w++ = '=';
    }
    *w = 0;
    return out;
}

static int val(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

long g5c_base64_decode(const char *s, uint8_t *out, size_t cap)
{
    size_t n = strlen(s), w = 0;
    if (n % 4 != 0)
        return -1;
    for (size_t i = 0; i < n; i += 4) {
        int a = val(s[i]), b = val(s[i + 1]), c, d;
        bool last = i + 4 == n;
        uint32_t v;
        if (a < 0 || b < 0)
            return -1;
        if (s[i + 2] == '=') {
            /* "xx==": only as the final quartet, and the unused bits must be zero (canonical form) */
            if (!last || s[i + 3] != '=' || (b & 15) != 0)
                return -1;
            if (w + 1 > cap)
                return -1;
            out[w++] = (uint8_t)((a << 2) | (b >> 4));
            break;
        }
        c = val(s[i + 2]);
        if (c < 0)
            return -1;
        if (s[i + 3] == '=') {
            if (!last || (c & 3) != 0 || w + 2 > cap)
                return -1;
            out[w++] = (uint8_t)((a << 2) | (b >> 4));
            out[w++] = (uint8_t)((b << 4) | (c >> 2));
            break;
        }
        d = val(s[i + 3]);
        if (d < 0 || w + 3 > cap)
            return -1;
        v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        out[w++] = (uint8_t)(v >> 16);
        out[w++] = (uint8_t)(v >> 8);
        out[w++] = (uint8_t)v;
    }
    return (long)w;
}
