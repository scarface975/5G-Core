/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Identifiers of the NSSF's API: S-NSSAI, TAI, PLMN, SupportedFeatures. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "priv.h"

static bool hex_n(const char *s, size_t n, uint32_t *out)
{
    uint32_t v = 0;
    if (s == NULL || strlen(s) != n)
        return false;
    for (size_t i = 0; i < n; i++) {
        if (!isxdigit((unsigned char)s[i]))
            return false;
        v = v * 16 + (uint32_t)(isdigit((unsigned char)s[i]) ? s[i] - '0' : tolower((unsigned char)s[i]) - 'a' + 10);
    }
    *out = v;
    return true;
}

bool sn_from_json(const g5c_json *j, sn_t *out)
{
    int64_t sst;
    const char *sd;
    uint32_t v;
    if (!g5c_json_is(j, G5C_J_OBJECT) || !g5c_json_get_int(j, "sst", &sst) || sst < 0 || sst > 255)
        return false;
    out->sst = (int)sst;
    out->sd = -1;
    sd = g5c_json_get_str(j, "sd");
    if (sd != NULL) {
        if (!hex_n(sd, 6, &v))
            return false;
        out->sd = v == 0xFFFFFFu ? -1 : (int)v;
    }
    return true;
}

g5c_json *sn_json(const sn_t *s)
{
    g5c_json *o = g5c_json_new_obj();
    g5c_json_set_int(o, "sst", s->sst);
    if (s->sd >= 0) {
        char sd[16];
        snprintf(sd, sizeof sd, "%06x", (unsigned)s->sd);
        g5c_json_set_str(o, "sd", sd);
    }
    return o;
}

bool sn_equal(const sn_t *a, const sn_t *b)
{
    return a->sst == b->sst && a->sd == b->sd;
}

bool sn_in(const sn_t *list, size_t n, const sn_t *s)
{
    for (size_t i = 0; i < n; i++)
        if (sn_equal(&list[i], s))
            return true;
    return false;
}

bool parse_tac(const char *s, uint32_t *out)
{
    return hex_n(s, 4, out) || hex_n(s, 6, out);
}

void format_tac(uint32_t tac, char out[7])
{
    snprintf(out, 7, "%06x", (unsigned)(tac & 0xFFFFFFu));
}

static bool digits(const char *s, size_t lo, size_t hi)
{
    size_t n = s != NULL ? strlen(s) : 0;
    if (n < lo || n > hi)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isdigit((unsigned char)s[i]))
            return false;
    return true;
}

bool plmn_from_json(const g5c_json *j, char mcc[4], char mnc[4])
{
    const char *a = g5c_json_get_str(j, "mcc"), *b = g5c_json_get_str(j, "mnc");
    if (!digits(a, 3, 3) || !digits(b, 2, 3))
        return false;
    memset(mcc, 0, 4);
    memcpy(mcc, a, 3);
    memset(mnc, 0, 4);
    memcpy(mnc, b, strlen(b));
    return true;
}

bool plmn_from_str(const char *s, char mcc[4], char mnc[4])
{
    const char *dash = s != NULL ? strchr(s, '-') : NULL;
    char a[8], b[8];
    if (dash == NULL || dash - s != 3)
        return false;
    snprintf(a, sizeof a, "%.3s", s);
    snprintf(b, sizeof b, "%s", dash + 1);
    if (!digits(a, 3, 3) || !digits(b, 2, 3))
        return false;
    memset(mcc, 0, 4);
    memcpy(mcc, a, 3);
    memset(mnc, 0, 4);
    memcpy(mnc, b, strlen(b));
    return true;
}

g5c_json *plmn_json(const char mcc[4], const char mnc[4])
{
    g5c_json *o = g5c_json_new_obj();
    g5c_json_set_str(o, "mcc", mcc);
    g5c_json_set_str(o, "mnc", mnc);
    return o;
}

bool tai_from_json(const g5c_json *j, tai_t *out)
{
    if (!g5c_json_is(j, G5C_J_OBJECT) || !plmn_from_json(g5c_json_get(j, "plmnId"), out->mcc, out->mnc))
        return false;
    return parse_tac(g5c_json_get_str(j, "tac"), &out->tac);
}

g5c_json *tai_json(const tai_t *t)
{
    g5c_json *o = g5c_json_new_obj();
    char tac[7];
    format_tac(t->tac, tac);
    g5c_json_set(o, "plmnId", plmn_json(t->mcc, t->mnc));
    g5c_json_set_str(o, "tac", tac);
    return o;
}

bool tai_equal(const tai_t *a, const tai_t *b)
{
    return a->tac == b->tac && strcmp(a->mcc, b->mcc) == 0 && strcmp(a->mnc, b->mnc) == 0;
}

unsigned features_parse(const char *s)
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

char *features_str(unsigned f)
{
    return g5c_xasprintf("%x", f);
}

bool ext_sn_from_json(const g5c_json *j, sn_ext_t *out)
{
    const g5c_json *rl = g5c_json_get(j, "sdRanges");
    bool wc = false;
    memset(out, 0, sizeof *out);
    if (!sn_from_json(j, &out->sn))
        return false;
    if (g5c_json_get(j, "wildcardSd") != NULL && g5c_json_get_bool(j, "wildcardSd", &wc))
        out->wildcard = wc;
    if (rl != NULL && g5c_json_is(rl, G5C_J_ARRAY)) {
        out->ranges = g5c_xcalloc(g5c_json_len(rl) + 1, sizeof *out->ranges);
        for (size_t i = 0; i < g5c_json_len(rl); i++) {
            uint32_t lo, hi;
            if (hex_n(g5c_json_get_str(g5c_json_at(rl, i), "start"), 6, &lo) && hex_n(g5c_json_get_str(g5c_json_at(rl, i), "end"), 6, &hi)) {
                out->ranges[out->nranges].lo = (int)lo;
                out->ranges[out->nranges].hi = (int)hi;
                out->nranges++;
            }
        }
    }
    return true;
}

void ext_sn_free(sn_ext_t *e)
{
    free(e->ranges);
    memset(e, 0, sizeof *e);
}

bool ext_sn_matches(const sn_ext_t *e, const sn_t *s)
{
    if (e->sn.sst != s->sst)
        return false;
    if (e->wildcard)
        return true;
    if (e->nranges > 0) {
        for (size_t i = 0; i < e->nranges; i++)
            if (s->sd >= 0 && s->sd >= e->ranges[i].lo && s->sd <= e->ranges[i].hi)
                return true;
    }
    if (e->nranges > 0)
        return false; /* the S-NSSAI is the SD ranges, not the bare SST */
    return e->sn.sd == s->sd;
}
