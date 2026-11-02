/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nudr_GroupIDmap (TS 29.504 5.3, API TS29504_Nudr_GroupIDmap.yaml): the NF group a subscriber belongs to, per NF type.
 * The mapping is configured (group_ids: nf_type, nf_group_id, supi_ranges); the NRF and the NFs that need the UDM or AUSF
 * group of a subscriber (TS 23.502 4.2.2.2.1) query it. */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/base.h"
#include "priv.h"

#define GROUPID_ROOT "/nudr-group-id-map/v1"

typedef struct {
    g5c_udr *u;
} gctx;

static bool in_range(const g5c_json *ranges, const char *digits)
{
    for (size_t i = 0; i < g5c_json_len(ranges); i++) {
        const g5c_json *r = g5c_json_at(ranges, i);
        const char *lo = g5c_json_get_str(r, "start"), *hi = g5c_json_get_str(r, "end");
        size_t n = strlen(digits);
        if (lo != NULL && hi != NULL && strlen(lo) == n && strlen(hi) == n && strcmp(digits, lo) >= 0 && strcmp(digits, hi) <= 0)
            return true;
    }
    return false;
}

static bool nftype_ok(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 32)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!(isupper((unsigned char)s[i]) || isdigit((unsigned char)s[i]) || s[i] == '_'))
            return false;
    return true;
}

static void h_group_ids(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_udr *u = ((gctx *)ctx)->u;
    char *types = g5c_req_query_decoded(req, "nf-type"), *sub = g5c_req_query_decoded(req, "subscriberId"), *part = NULL;
    const g5c_json *map = udr_opts_get(u)->group_ids;
    g5c_json *out = NULL;
    const char *digits = NULL;
    if (types == NULL || types[0] == '\0' || sub == NULL || sub[0] == '\0') {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_QUERY_PARAM_MISSING", types == NULL || types[0] == '\0' ? "nf-type" : "subscriberId",
                                 "the query parameter is required");
        goto done;
    }
    part = udr_part_for_id(u, UDR_PART_UE, sub);
    if (strncmp(part, "imsi-", 5) == 0)
        digits = part + 5;
    out = g5c_json_new_obj();
    for (char *save = NULL, *t = strtok_r(types, ",", &save); t != NULL; t = strtok_r(NULL, ",", &save)) {
        while (*t == ' ')
            t++;
        if (!nftype_ok(t)) {
            g5c_resp_problem_invalid(resp, 400, "INVALID_QUERY_PARAM", "nf-type", "not an NF type");
            goto done;
        }
        for (size_t i = 0; digits != NULL && i < g5c_json_len(map); i++) {
            const g5c_json *e = g5c_json_at(map, i);
            const char *nt = g5c_json_get_str(e, "nf_type"), *gid = g5c_json_get_str(e, "nf_group_id");
            if (nt != NULL && gid != NULL && strcmp(nt, t) == 0 && in_range(g5c_json_get(e, "supi_ranges"), digits) &&
                g5c_json_get(out, t) == NULL)
                g5c_json_set_str(out, t, gid);
        }
    }
    if (g5c_json_len(out) == 0)
        g5c_resp_problem_simple(resp, 404, "DATA_NOT_FOUND", "no NF group is configured for this subscriber and NF type");
    else
        g5c_resp_json(resp, 200, out);
done:
    g5c_json_free(out);
    free(types);
    free(sub);
    free(part);
}

void udr_register_groupid_routes(g5c_udr *u, g5c_router *r)
{
    gctx *c = g5c_xcalloc(1, sizeof *c);
    c->u = u;
    udr_track_alloc(u, c);
    g5c_router_route(r, "GET", GROUPID_ROOT "/nf-group-ids", h_group_ids, c);
}
