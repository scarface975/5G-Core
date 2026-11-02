/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Date and time formats of the Nudr API: HTTP dates (If-Modified-Since, Last-Modified) and RFC 3339 (expiry). */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "priv.h"

static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    {
        const int64_t era = (y >= 0 ? y : y - 399) / 400;
        const unsigned yoe = (unsigned)(y - era * 400);
        const unsigned doy = (153 * (m + (m > 2 ? (unsigned)-3 : 9)) + 2) / 5 + d - 1;
        const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + (int64_t)doe - 719468;
    }
}

int64_t udr_parse_http_date(const char *s)
{
    static const char *const mon[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int d, y, hh, mm, ss;
    char m3[4];
    unsigned mi = 0;
    if (s == NULL || sscanf(s, "%*3s, %d %3s %d %d:%d:%d GMT", &d, m3, &y, &hh, &mm, &ss) != 6)
        return -1;
    for (unsigned i = 0; i < 12; i++)
        if (strncasecmp(m3, mon[i], 3) == 0)
            mi = i + 1;
    if (mi == 0 || d < 1 || d > 31)
        return -1;
    return days_from_civil(y, mi, (unsigned)d) * 86400 + hh * 3600 + mm * 60 + ss;
}

void udr_http_date(int64_t t, char *out, size_t cap)
{
    time_t tt = (time_t)t;
    struct tm tm;
    out[0] = '\0';
    if (gmtime_r(&tt, &tm) != NULL)
        (void)strftime(out, cap, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

int64_t udr_parse_rfc3339(const char *s)
{
    int y, mo, d, hh, mm, ss, n = 0;
    int64_t t;
    const char *p;
    if (s == NULL || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &mo, &d, &hh, &mm, &ss, &n) != 6 || n == 0)
        return -1;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || hh > 23 || mm > 59 || ss > 60)
        return -1;
    t = days_from_civil(y, (unsigned)mo, (unsigned)d) * 86400 + hh * 3600 + mm * 60 + ss;
    p = s + n;
    if (*p == '.') { /* fraction of a second: ignored */
        p++;
        while (*p >= '0' && *p <= '9')
            p++;
    }
    if (*p == 'Z' || *p == 'z' || *p == '\0')
        return t;
    if (*p == '+' || *p == '-') {
        int oh, om;
        if (sscanf(p + 1, "%2d:%2d", &oh, &om) != 2)
            return -1;
        return *p == '+' ? t - (oh * 3600 + om * 60) : t + (oh * 3600 + om * 60);
    }
    return -1;
}

void udr_rfc3339(int64_t t, char *out, size_t cap)
{
    time_t tt = (time_t)t;
    struct tm tm;
    out[0] = '\0';
    if (gmtime_r(&tt, &tm) != NULL)
        (void)strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}
