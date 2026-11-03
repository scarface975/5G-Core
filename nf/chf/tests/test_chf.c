/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The CHF in process: a charging session reserves a quota against the balance, updates debit and re-grant, the last grant carries a final unit indication, an exhausted balance is
 * denied, a release writes the record and frees the reservation, a bad configuration is refused. */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "g5c/chf.h"
#include "g5c/testkit.h"

typedef struct {
    int status;
    g5c_json *json;
    char location[256];
} R;

static R rq(g5c_router *rt, const char *target, const char *body)
{
    g5c_req req;
    g5c_resp resp;
    R out;
    memset(&out, 0, sizeof out);
    g5c_req_init(&req);
    req.method = g5c_xstrdup("POST");
    req.path = g5c_xstrdup(target);
    req.scheme = g5c_xstrdup("http");
    req.authority = g5c_xstrdup("chf.test:80");
    g5c_req_add_header(&req, "content-type", "application/json");
    g5c_req_set_body(&req, body, strlen(body));
    g5c_resp_init(&resp);
    g5c_router_dispatch(rt, &req, &resp);
    out.status = resp.status;
    out.json = g5c_resp_parse_json(&resp);
    snprintf(out.location, sizeof out.location, "%s", g5c_resp_header_get(&resp, "location") ? g5c_resp_header_get(&resp, "location") : "");
    g5c_resp_free(&resp);
    g5c_req_free(&req);
    return out;
}

static chf *make(const char *yaml, g5c_router **rt)
{
    char err[200];
    g5c_json *root = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    chf *c;
    if (root == NULL)
        TK_FAIL("yaml: %s", err);
    c = chf_from_config(root, NULL, err, sizeof err);
    if (c == NULL)
        TK_FAIL("config: %s", err);
    g5c_json_free(root);
    *rt = chf_router(c);
    return c;
}

static const g5c_json *mi(const R *r)
{
    return g5c_json_at(g5c_json_get(r->json, "multipleUnitInformation"), 0);
}

static int64_t granted(const R *r)
{
    int64_t v = -1;
    (void)g5c_json_get_int(g5c_json_get(mi(r), "grantedUnit"), "totalVolume", &v);
    return v;
}

#define CREATE(supi, q)                                                                                                                             \
    "{\"subscriberIdentifier\":\"" supi "\",\"multipleUnitUsage\":[{\"ratingGroup\":7,\"requestedUnit\":{\"totalVolume\":" q "}}],"                \
    "\"pduSessionChargingInformation\":{\"pduSessionInformation\":{\"pduSessionID\":5,\"dnn\":\"internet\"}}}"

#define USED(used, ask)                                                                                                                             \
    "{\"multipleUnitUsage\":[{\"ratingGroup\":7,\"usedUnitContainer\":[{\"totalVolume\":" used "}],\"requestedUnit\":{\"totalVolume\":" ask "}}]}"

static void path_of(char *out, size_t cap, const R *r, const char *op)
{
    const char *p = strrchr(r->location, '/');
    snprintf(out, cap, "/nchf-convergedcharging/v3/chargingdata/%s/%s", p != NULL ? p + 1 : "", op);
}

int main(void)
{
    g5c_router *rt;
    chf *c;
    R a, b, d;
    char path[300], pb[300];
    char cdr[] = "/tmp/g5c-chf-cdr-XXXXXX";
    char yaml[600];
    int fd = mkstemp(cdr);
    FILE *f;
    char line[600], perr[100];
    close(fd);
    snprintf(yaml, sizeof yaml, "chf:\n  default_balance_bytes: 1000\n  max_grant_bytes: 400\n  accounts: [ { supi: 'imsi-00101999', balance_bytes: 0 } ]\n  cdr_file: '%s'\n", cdr);
    c = make(yaml, &rt);

    /* a quota within the ceiling is granted as asked */
    a = rq(rt, "/nchf-convergedcharging/v3/chargingdata", CREATE("imsi-001010000000001", "300"));
    TK_ASSERT(a.status == 201 && strstr(a.location, "/nchf-convergedcharging/v3/chargingdata/") != NULL);
    TK_ASSERT(strcmp(g5c_json_get_str(mi(&a), "resultCode"), "SUCCESS") == 0 && granted(&a) == 300 && g5c_json_get(mi(&a), "finalUnitIndication") == NULL);
    TK_ASSERT(chf_session_count(c) == 1);

    /* above the ceiling: cut to it */
    b = rq(rt, "/nchf-convergedcharging/v3/chargingdata", CREATE("imsi-001010000000002", "5000"));
    TK_ASSERT(b.status == 201 && granted(&b) == 400);
    path_of(pb, sizeof pb, &b, "release");
    d = rq(rt, pb, "{\"multipleUnitUsage\":[{\"ratingGroup\":7}]}");
    TK_ASSERT(d.status == 204);
    g5c_json_free(b.json);

    /* the balance is 1000: 300 used and a new quota of 400, then 400 more used and the 300 that is left is the last grant, with the final unit indication */
    path_of(path, sizeof path, &a, "update");
    d = rq(rt, path, "{\"multipleUnitUsage\":[{\"ratingGroup\":7,\"usedUnitContainer\":[{\"totalVolume\":300,\"uplinkVolume\":100,\"downlinkVolume\":200,\"time\":12}],"
                     "\"requestedUnit\":{\"totalVolume\":400}}]}");
    TK_ASSERT(d.status == 200 && granted(&d) == 400 && chf_balance(c, "imsi-001010000000001") == 700);
    g5c_json_free(d.json);
    d = rq(rt, path, USED("400", "400"));
    TK_ASSERT(d.status == 200 && granted(&d) == 300 && chf_balance(c, "imsi-001010000000001") == 300);
    TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_get(mi(&d), "finalUnitIndication"), "finalUnitAction"), "TERMINATE") == 0);
    g5c_json_free(d.json);
    d = rq(rt, path, USED("300", "400"));
    TK_ASSERT(d.status == 200 && granted(&d) == -1 && strcmp(g5c_json_get_str(mi(&d), "resultCode"), "END_USER_SERVICE_DENIED") == 0 && chf_balance(c, "imsi-001010000000001") == 0);
    g5c_json_free(d.json);

    /* a subscriber with nothing is denied at once */
    b = rq(rt, "/nchf-convergedcharging/v3/chargingdata", CREATE("imsi-001019990000001", "100"));
    TK_ASSERT(b.status == 201 && strcmp(g5c_json_get_str(mi(&b), "resultCode"), "END_USER_SERVICE_DENIED") == 0);
    g5c_json_free(b.json);

    /* the release of the first closes it; a second release finds nothing */
    path_of(path, sizeof path, &a, "release");
    d = rq(rt, path, "{\"multipleUnitUsage\":[{\"ratingGroup\":7}]}");
    TK_ASSERT(d.status == 204);
    d = rq(rt, path, "{\"multipleUnitUsage\":[{\"ratingGroup\":7}]}");
    TK_ASSERT(d.status == 404);
    g5c_json_free(d.json);
    g5c_json_free(a.json);
    f = fopen(cdr, "r");
    TK_ASSERT(f != NULL);
    {
        int n = 0, found = 0;
        while (fgets(line, sizeof line, f) != NULL) {
            g5c_json *j = g5c_json_parse(line, strlen(line), perr, sizeof perr);
            int64_t tot = 0, ul = 0, t = 0;
            n++;
            if (j != NULL && strcmp(g5c_json_get_str(j, "supi"), "imsi-001010000000001") == 0 && g5c_json_get_int(j, "totalVolume", &tot) && tot == 1000) {
                (void)g5c_json_get_int(j, "uplinkVolume", &ul);
                (void)g5c_json_get_int(j, "time", &t);
                found = ul == 100 && t == 12 && strcmp(g5c_json_get_str(j, "dnn"), "internet") == 0;
            }
            g5c_json_free(j);
        }
        fclose(f);
        TK_ASSERT(n == 2 && found); /* the second subscriber's session and the first */
    }

    /* mistakes */
    d = rq(rt, "/nchf-convergedcharging/v3/chargingdata", "{\"multipleUnitUsage\":[]}");
    TK_ASSERT(d.status == 400);
    g5c_json_free(d.json);
    d = rq(rt, "/nchf-convergedcharging/v3/chargingdata/nope/update", "{}");
    TK_ASSERT(d.status == 404);
    g5c_json_free(d.json);
    g5c_router_free(rt);
    chf_destroy(c);
    unlink(cdr);

    {
        char err[200];
        const char *bad1 = "chf:\n  max_grant_bytes: 0\n", *bad2 = "chf:\n  bogus: 1\n";
        g5c_json *root = g5c_yaml_parse(bad1, strlen(bad1), err, sizeof err);
        TK_ASSERT(root != NULL && chf_from_config(root, NULL, err, sizeof err) == NULL && strstr(err, "max_grant_bytes") != NULL);
        g5c_json_free(root);
        root = g5c_yaml_parse(bad2, strlen(bad2), err, sizeof err);
        TK_ASSERT(root != NULL && chf_from_config(root, NULL, err, sizeof err) == NULL);
        g5c_json_free(root);
    }
    printf("chf: OK\n");
    return 0;
}
