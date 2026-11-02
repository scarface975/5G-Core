#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Small helpers of the NEF: problem details, URIs, JSON merge patch (RFC 7386), RFC 3339 times, supported features. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "priv.h"

void nef_problem(g5c_resp *resp, int status, const char *cause, const char *detail)
{
    g5c_resp_problem_simple(resp, status, cause, detail);
}

void nef_invalid(g5c_resp *resp, int status, const char *cause, const char *pointer, const char *reason)
{
    g5c_resp_problem_invalid(resp, status, cause, pointer, reason);
}

/* ---- URIs ----------------------------------------------------------------------------------------------------------- */

/* [start, end) of the host in the authority of an http(s) URI; false when the URI is not acceptable */
static bool authority(const char *u, const char **hs, const char **he)
{
    const char *p, *a, *end;
    if (u == NULL)
        return false;
    if (strncasecmp(u, "http://", 7) == 0)
        a = u + 7;
    else if (strncasecmp(u, "https://", 8) == 0)
        a = u + 8;
    else
        return false;
    end = a + strcspn(a, "/?#");
    if (end == a || memchr(a, '@', (size_t)(end - a)) != NULL || strchr(u, '#') != NULL)
        return false;
    for (p = u; *p != 0; p++)
        if ((unsigned char)*p <= 0x20 || (unsigned char)*p == 0x7f)
            return false;
    if (*a == '[') {
        const char *rb = memchr(a, ']', (size_t)(end - a));
        if (rb == NULL || rb == a + 1)
            return false;
        *hs = a + 1;
        *he = rb;
        return rb + 1 == end || (rb[1] == ':' && rb + 2 < end);
    }
    *hs = a;
    *he = memchr(a, ':', (size_t)(end - a));
    if (*he == NULL)
        *he = end;
    else if (*he + 1 == end)
        return false;
    return *he > *hs;
}

bool uri_ok(const char *u)
{
    const char *hs, *he;
    return authority(u, &hs, &he);
}

char *uri_host(const char *u)
{
    const char *hs, *he;
    if (!authority(u, &hs, &he))
        return NULL;
    return g5c_xstrndup(hs, (size_t)(he - hs));
}

bool notify_host_allowed(const nef_af *af, const char *uri)
{
    char *h;
    bool ok = false;
    if (!uri_ok(uri))
        return false;
    if (af->any_host)
        return true;
    h = uri_host(uri);
    for (size_t i = 0; h != NULL && i < af->nhosts; i++)
        if (strcasecmp(af->hosts[i], h) == 0)
            ok = true;
    free(h);
    return ok;
}

/* ---- JSON merge patch ----------------------------------------------------------------------------------------------- */

void merge_patch(g5c_json **doc, const g5c_json *patch)
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
        const g5c_json *pv = g5c_json_val_at(patch, i);
        if (g5c_json_is(pv, G5C_J_NULL)) {
            g5c_json_remove(*doc, k);
        } else if (g5c_json_is(pv, G5C_J_OBJECT)) {
            g5c_json *cur = g5c_json_detach(*doc, k);
            merge_patch(&cur, pv);
            g5c_json_set(*doc, k, cur);
        } else {
            g5c_json_set(*doc, k, g5c_json_dup(pv));
        }
    }
}

/* ---- times ---------------------------------------------------------------------------------------------------------- */

int64_t parse_rfc3339(const char *s)
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

void format_rfc3339(int64_t ms, char out[32])
{
    time_t t = (time_t)(ms / 1000);
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

/* ---- supported features (TS 29.571 5.2.2) ----------------------------------------------------------------------------- */

unsigned feat_parse(const char *s)
{
    unsigned v = 0;
    size_t n;
    if (s == NULL)
        return 0;
    n = strlen(s);
    if (n == 0 || n > 8)
        return n == 0 ? 0 : 0xFFFFFFFFu; /* longer than we know about: every feature up to bit 31 is "offered"; the caller masks */
    for (size_t i = 0; i < n; i++) {
        if (!isxdigit((unsigned char)s[i]))
            return 0;
        v = v * 16 + (unsigned)(isdigit((unsigned char)s[i]) ? s[i] - '0' : tolower((unsigned char)s[i]) - 'a' + 10);
    }
    return v;
}

char *feat_str(unsigned f)
{
    return f == 0 ? NULL : g5c_xasprintf("%x", f);
}

bool is_hex_id(const char *s)
{
    size_t n = s == NULL ? 0 : strlen(s);
    if (n == 0 || n > 64)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && s[i] != '-' && s[i] != '_' && s[i] != '.')
            return false;
    return true;
}

char *pct_encode(const char *s)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    for (; *s != 0; s++) {
        unsigned char ch = (unsigned char)*s;
        if (isalnum(ch) || ch == 0x2d || ch == 0x2e || ch == 0x5f || ch == 0x7e)
            g5c_bytes_putc(&b, (char)ch);
        else
            g5c_bytes_printf(&b, "%%%02X", ch);
    }
    return g5c_bytes_take(&b, NULL);
}

/* The status the AF gets when another function refused the request: what is the AF's doing stays as it is, the rest is a failure of the system. */
int peer_status(int upstream)
{
    return upstream == 400 || upstream == 403 || upstream == 404 || upstream == 409 || upstream == 429 ? upstream : 500;
}
