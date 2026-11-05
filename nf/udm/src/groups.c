/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Device groups known to the UDM (backlog H-04). A group has an external identifier (TS 29.503 ExtGroupId, `extgroupid-<local>@<domain>`), an internal one (TS 29.571 GroupId: eight hex digits,
 * the PLMN as MCC and MNC, and one to ten octets in hex) and its members: SUPIs listed one by one and/or ranges of IMSI digits. Nudm_SDM answers GetGroupIdentifiers from them and puts the
 * internal identifiers of a member's groups in the `internalGroupIds` of its access and mobility subscription data. Configuration (reloadable):
 *
 *   groups:
 *     - { ext_group_id: 'extgroupid-meters@example.com', int_group_id: '0000000a-001-01-0a',
 *         members: [ imsi-001010000000001 ], supi_ranges: [ { start: '001010000000100', end: '001010000000199' } ] } */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/base.h"
#include "g5c/config.h"
#include "g5c/udm.h"

#define MAX_GROUPS 256
#define MAX_MEMBERS 100000
#define MAX_RANGES 16

typedef struct {
    char *start, *end;
} range_t;

typedef struct {
    char *ext, *intid;
    char **members; /* sorted */
    size_t nmembers;
    range_t ranges[MAX_RANGES];
    size_t nranges;
} group_t;

struct udm_groups {
    group_t *g;
    size_t n;
};

static bool ext_ok(const char *s)
{
    const char *at;
    if (s == NULL || strncmp(s, "extgroupid-", 11) != 0)
        return false;
    at = strchr(s + 11, '@');
    return at != NULL && at > s + 11 && at[1] != '\0' && strchr(at + 1, '@') == NULL && strlen(s) <= 128;
}

/* ^[A-Fa-f0-9]{8}-[0-9]{3}-[0-9]{2,3}-([A-Fa-f0-9][A-Fa-f0-9]){1,10}$ */
static bool intid_ok(const char *s)
{
    size_t i = 0, n;
    if (s == NULL)
        return false;
    for (; i < 8; i++)
        if (!isxdigit((unsigned char)s[i]))
            return false;
    if (s[i++] != '-')
        return false;
    for (size_t k = 0; k < 3; k++, i++)
        if (!isdigit((unsigned char)s[i]))
            return false;
    if (s[i++] != '-')
        return false;
    n = 0;
    while (isdigit((unsigned char)s[i]) && n < 3) {
        i++;
        n++;
    }
    if (n < 2 || s[i++] != '-')
        return false;
    n = 0;
    while (isxdigit((unsigned char)s[i])) {
        i++;
        n++;
    }
    return s[i] == '\0' && n >= 2 && n <= 20 && n % 2 == 0;
}

static bool supi_ok(const char *s)
{
    return s != NULL && strncmp(s, "imsi-", 5) == 0 && strlen(s) >= 10 && strlen(s) <= 24 && strspn(s + 5, "0123456789") == strlen(s + 5);
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void udm_groups_free(udm_groups *gs)
{
    if (gs == NULL)
        return;
    for (size_t i = 0; i < gs->n; i++) {
        group_t *g = &gs->g[i];
        free(g->ext);
        free(g->intid);
        for (size_t k = 0; k < g->nmembers; k++)
            free(g->members[k]);
        free(g->members);
        for (size_t k = 0; k < g->nranges; k++) {
            free(g->ranges[k].start);
            free(g->ranges[k].end);
        }
    }
    free(gs->g);
    free(gs);
}

udm_groups *udm_groups_parse(const g5c_json *arr, char *err, size_t cap)
{
    static const char *const keys[] = {"ext_group_id", "int_group_id", "members", "supi_ranges", NULL};
    udm_groups *gs = g5c_xcalloc(1, sizeof *gs);
    size_t total = 0;
    if (arr == NULL)
        return gs;
    if (!g5c_json_is(arr, G5C_J_ARRAY) || g5c_json_len(arr) > MAX_GROUPS) {
        snprintf(err, cap, "invalid config: `groups` must be a list of at most %d groups", MAX_GROUPS);
        goto bad;
    }
    gs->g = g5c_xcalloc(g5c_json_len(arr) ? g5c_json_len(arr) : 1, sizeof *gs->g);
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const g5c_json *e = g5c_json_at(arr, i), *ml = NULL, *rl = NULL;
        group_t *g = &gs->g[i];
        char where[32];
        snprintf(where, sizeof where, "groups[%zu]", i);
        gs->n = i + 1;
        if (!g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, keys, where, err, cap) != 0) {
            if (err[0] == 0)
                snprintf(err, cap, "invalid config: `%s` must be a mapping", where);
            goto bad;
        }
        if (!ext_ok(g5c_json_get_str(e, "ext_group_id")) || !intid_ok(g5c_json_get_str(e, "int_group_id"))) {
            snprintf(err, cap, "invalid config: `%s` needs `ext_group_id` (extgroupid-<name>@<domain>) and `int_group_id` (TS 29.571 GroupId, e.g. 0000000a-001-01-0a)", where);
            goto bad;
        }
        g->ext = g5c_xstrdup(g5c_json_get_str(e, "ext_group_id"));
        g->intid = g5c_xstrdup(g5c_json_get_str(e, "int_group_id"));
        for (size_t k = 0; k < i; k++)
            if (strcmp(gs->g[k].ext, g->ext) == 0 || strcmp(gs->g[k].intid, g->intid) == 0) {
                snprintf(err, cap, "invalid config: `%s` repeats an identifier of an earlier group", where);
                goto bad;
            }
        ml = g5c_json_get(e, "members");
        rl = g5c_json_get(e, "supi_ranges");
        if ((ml != NULL && !g5c_json_is(ml, G5C_J_ARRAY)) || (rl != NULL && (!g5c_json_is(rl, G5C_J_ARRAY) || g5c_json_len(rl) > MAX_RANGES))) {
            snprintf(err, cap, "invalid config: `%s.members` and `%s.supi_ranges` must be lists (at most %d ranges)", where, where, MAX_RANGES);
            goto bad;
        }
        total += g5c_json_len(ml);
        if (total > MAX_MEMBERS) {
            snprintf(err, cap, "invalid config: more than %d listed group members", MAX_MEMBERS);
            goto bad;
        }
        g->members = g5c_xcalloc(g5c_json_len(ml) ? g5c_json_len(ml) : 1, sizeof *g->members);
        for (size_t k = 0; k < g5c_json_len(ml); k++) {
            const char *m = g5c_json_str(g5c_json_at(ml, k));
            if (!supi_ok(m)) {
                snprintf(err, cap, "invalid config: `%s.members[%zu]` must be a SUPI (imsi-<digits>)", where, k);
                goto bad;
            }
            g->members[k] = g5c_xstrdup(m);
            g->nmembers = k + 1;
        }
        qsort(g->members, g->nmembers, sizeof *g->members, cmp_str);
        for (size_t k = 0; rl != NULL && k < g5c_json_len(rl); k++) {
            const g5c_json *r = g5c_json_at(rl, k);
            const char *lo = g5c_json_get_str(r, "start"), *hi = g5c_json_get_str(r, "end");
            if (lo == NULL || hi == NULL || strlen(lo) < 6 || strlen(lo) > 15 || strlen(lo) != strlen(hi) || strspn(lo, "0123456789") != strlen(lo) || strspn(hi, "0123456789") != strlen(hi) || strcmp(lo, hi) > 0) {
                snprintf(err, cap, "invalid config: `%s.supi_ranges[%zu]` needs `start` and `end`, digit strings of the same length (6..15), start <= end", where, k);
                goto bad;
            }
            g->ranges[k].start = g5c_xstrdup(lo);
            g->ranges[k].end = g5c_xstrdup(hi);
            g->nranges = k + 1;
        }
    }
    return gs;
bad:
    udm_groups_free(gs);
    return NULL;
}

static bool is_member(const group_t *g, const char *supi)
{
    const char *digits = strncmp(supi, "imsi-", 5) == 0 ? supi + 5 : NULL;
    if (g->nmembers > 0 && bsearch(&supi, g->members, g->nmembers, sizeof *g->members, cmp_str) != NULL)
        return true;
    for (size_t k = 0; digits != NULL && k < g->nranges; k++) {
        size_t n = strlen(g->ranges[k].start);
        if (strlen(digits) == n && strcmp(digits, g->ranges[k].start) >= 0 && strcmp(digits, g->ranges[k].end) <= 0)
            return true;
    }
    return false;
}

size_t udm_groups_count(const udm_groups *gs)
{
    return gs != NULL ? gs->n : 0;
}

void udm_set_groups(udm *u, udm_groups *gs)
{
    udm_groups *old;
    pthread_mutex_lock(&u->groups_mu);
    old = u->groups;
    u->groups = gs;
    pthread_mutex_unlock(&u->groups_mu);
    udm_groups_free(old);
}

void udm_groups_annotate(udm *u, const char *supi, g5c_json *am_data)
{
    g5c_json *ids = NULL;
    pthread_mutex_lock(&u->groups_mu);
    for (size_t i = 0; u->groups != NULL && i < u->groups->n; i++) {
        const group_t *g = &u->groups->g[i];
        bool have = false;
        if (!is_member(g, supi))
            continue;
        if (ids == NULL) {
            ids = g5c_json_get_mut(am_data, "internalGroupIds");
            if (ids == NULL || !g5c_json_is(ids, G5C_J_ARRAY))
                ids = g5c_json_set(am_data, "internalGroupIds", g5c_json_new_arr());
        }
        for (size_t k = 0; k < g5c_json_len(ids); k++)
            have = have || g5c_streq(g5c_json_str(g5c_json_at(ids, k)), g->intid);
        if (!have)
            g5c_json_push_str(ids, g->intid);
    }
    pthread_mutex_unlock(&u->groups_mu);
}

/* GetGroupIdentifiers (TS 29.503 5.2.2.9): ?ext-group-id=...|int-group-id=...[&ue-id-ind=true] */
static void group_identifiers(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    char *ext = g5c_req_query_decoded(req, "ext-group-id"), *intid = g5c_req_query_decoded(req, "int-group-id"), *ind = g5c_req_query_decoded(req, "ue-id-ind");
    g5c_json *out = NULL;
    bool want_ids = ind != NULL && strcmp(ind, "true") == 0;
    if ((ext == NULL) == (intid == NULL)) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_MISSING", "ext-group-id", "exactly one of ext-group-id and int-group-id is required");
        goto done;
    }
    if ((ext != NULL && !ext_ok(ext)) || (intid != NULL && !intid_ok(intid)) || (ind != NULL && strcmp(ind, "true") != 0 && strcmp(ind, "false") != 0)) {
        g5c_resp_problem_invalid(resp, 400, "INVALID_QUERY_PARAM", ext != NULL ? "ext-group-id" : "int-group-id", "does not have the format of the specification");
        goto done;
    }
    pthread_mutex_lock(&u->groups_mu);
    for (size_t i = 0; u->groups != NULL && i < u->groups->n && out == NULL; i++) {
        const group_t *g = &u->groups->g[i];
        if (!(ext != NULL ? strcmp(g->ext, ext) == 0 : strcmp(g->intid, intid) == 0))
            continue;
        out = g5c_json_new_obj();
        g5c_json_set_str(out, "extGroupId", g->ext);
        g5c_json_set_str(out, "intGroupId", g->intid);
        if (want_ids && g->nmembers > 0) { /* the members listed one by one; a range is not enumerated */
            g5c_json *l = g5c_json_set(out, "ueIdList", g5c_json_new_arr());
            for (size_t k = 0; k < g->nmembers; k++)
                g5c_json_set_str(g5c_json_push(l, g5c_json_new_obj()), "supi", g->members[k]);
        }
    }
    pthread_mutex_unlock(&u->groups_mu);
    if (out == NULL) {
        g5c_resp_problem_simple(resp, 404, "DATA_NOT_FOUND", "no such group");
    } else {
        g5c_resp_json(resp, 200, out);
        g5c_json_free(out);
    }
done:
    free(ext);
    free(intid);
    free(ind);
}

void udm_groups_routes(g5c_router *r, udm *u)
{
    static const char *const versions[] = {"v2", "v1"};
    for (size_t i = 0; i < 2; i++) {
        char *p = g5c_xasprintf("/nudm-sdm/%s/group-data/group-identifiers", versions[i]);
        g5c_router_route(r, "GET", p, group_identifiers, u);
        free(p);
    }
}

/* configuration reload of `groups` */
int udm_reload_groups(void *ctx, const g5c_json *from, const g5c_json *to, char *err, size_t errcap)
{
    udm *u = ctx;
    udm_groups *gs;
    (void)from;
    err[0] = '\0';
    gs = udm_groups_parse(to, err, errcap);
    if (gs == NULL)
        return -1;
    udm_set_groups(u, gs);
    return 0;
}
