/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Roles and tenants for the admin APIs: the token file (valid and every way of being invalid), the principal behind a token, the role a request needs, the SUPI ranges of a tenant, the single admin
 * token as a principal, and the file read again when it changes (a revoked token stops working; a broken rewrite changes nothing). */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "g5c/authz.h"
#include "g5c/testkit.h"

static char path[96];

static void write_file(const char *text)
{
    FILE *f = fopen(path, "w");
    TK_ASSERT(f != NULL);
    fputs(text, f);
    fclose(f);
}

static char *entry(const char *name, const char *token, const char *roles, const char *tenant)
{
    char h[65];
    g5c_authz_hash(token, h);
    return g5c_xasprintf("{\"name\":\"%s\",\"sha256\":\"%s\",\"roles\":[%s]%s%s%s}", name, h, roles, tenant != NULL ? ",\"tenant\":\"" : "", tenant != NULL ? tenant : "", tenant != NULL ? "\"" : "");
}

static int ask(g5c_authz *a, const char *token, g5c_principal *who)
{
    g5c_req req;
    char hv[200];
    int rc;
    g5c_req_init(&req);
    req.method = g5c_xstrdup("GET");
    req.path = g5c_xstrdup("/admin/v1/subscribers");
    if (token != NULL) {
        snprintf(hv, sizeof hv, "Bearer %s", token);
        g5c_req_add_header(&req, "authorization", hv);
    }
    rc = g5c_authz_identify(a, &req, who);
    g5c_req_free(&req);
    return rc;
}

static unsigned need(const char *method, const char *p)
{
    if (strncmp(p, "/admin/", 7) != 0)
        return 0;
    if (strcmp(p, "/admin/v1/keys/rewrap") == 0)
        return G5C_ROLE_KEY_ADMIN;
    return strcmp(method, "GET") == 0 ? G5C_ROLE_READ : G5C_ROLE_PROVISION;
}

static int check(g5c_authz *a, const char *token, const char *method, const char *p, g5c_principal *who, int *status)
{
    g5c_req req;
    g5c_resp resp;
    char hv[200];
    int rc;
    g5c_req_init(&req);
    req.method = g5c_xstrdup(method);
    req.path = g5c_xstrdup(p);
    if (token != NULL) {
        snprintf(hv, sizeof hv, "Bearer %s", token);
        g5c_req_add_header(&req, "authorization", hv);
    }
    g5c_resp_init(&resp);
    rc = g5c_authz_check(a, &req, need, who, &resp);
    *status = resp.status;
    g5c_resp_free(&resp);
    g5c_req_free(&req);
    return rc;
}

int main(void)
{
    char err[300], tmpl[] = "/tmp/g5c-authz-XXXXXX";
    char *noc, *prov, *root, *keys, text[4096];
    g5c_authz *a;
    g5c_principal who;
    int st;
    TK_ASSERT(mkdtemp(tmpl) != NULL);
    snprintf(path, sizeof path, "%s/tokens.json", tmpl);

    noc = entry("noc", "noc-token-0123456789", "\"read\"", NULL);
    prov = entry("acme-prov", "acme-token-0123456789", "\"read\",\"provision\"", "acme");
    keys = entry("keys", "keys-token-0123456789", "\"key-admin\"", NULL);
    root = entry("root", "root-token-0123456789", "\"read\",\"provision\",\"policy\",\"key-admin\"", NULL);
    snprintf(text, sizeof text, "{\"tokens\":[%s,%s,%s,%s],\"tenants\":{\"acme\":{\"supi_prefixes\":[\"imsi-0010199\",\"imsi-0010198\"]},\"beta\":{\"supi_prefixes\":[\"imsi-0010288\"]}}}", noc, prov, keys, root);
    write_file(text);
    a = g5c_authz_new(path, NULL, err, sizeof err);
    TK_ASSERT(a != NULL && g5c_authz_enabled(a));

    /* who is who */
    TK_ASSERT(ask(a, "noc-token-0123456789", &who) == 0 && strcmp(who.name, "noc") == 0 && who.roles == G5C_ROLE_READ && who.tenant[0] == '\0');
    TK_ASSERT(ask(a, "acme-token-0123456789", &who) == 0 && strcmp(who.name, "acme-prov") == 0 && who.roles == (G5C_ROLE_READ | G5C_ROLE_PROVISION) && strcmp(who.tenant, "acme") == 0);
    TK_ASSERT(ask(a, "root-token-0123456789", &who) == 0 && who.roles == G5C_ROLE_ALL);
    TK_ASSERT(ask(a, "noc-token-012345678", &who) != 0 && ask(a, "", &who) != 0 && ask(a, NULL, &who) != 0 && ask(a, "NOC-TOKEN-0123456789", &who) != 0);

    /* the role a request needs: 401 without a known token, 403 with too little, nothing for what is not an admin path */
    TK_ASSERT(check(a, "noc-token-0123456789", "GET", "/admin/v1/subscribers", &who, &st) == 0);
    TK_ASSERT(check(a, "noc-token-0123456789", "POST", "/admin/v1/subscribers", &who, &st) != 0 && st == 403);
    TK_ASSERT(check(a, "noc-token-0123456789", "DELETE", "/admin/v1/subscribers/imsi-001019900000001", &who, &st) != 0 && st == 403);
    TK_ASSERT(check(a, "acme-token-0123456789", "POST", "/admin/v1/subscribers", &who, &st) == 0);
    TK_ASSERT(check(a, "acme-token-0123456789", "POST", "/admin/v1/keys/rewrap", &who, &st) != 0 && st == 403);
    TK_ASSERT(check(a, "keys-token-0123456789", "POST", "/admin/v1/keys/rewrap", &who, &st) == 0);
    TK_ASSERT(check(a, "keys-token-0123456789", "GET", "/admin/v1/subscribers", &who, &st) != 0 && st == 403);
    TK_ASSERT(check(a, "nonsense", "GET", "/admin/v1/subscribers", &who, &st) != 0 && st == 401);
    TK_ASSERT(check(a, NULL, "GET", "/admin/v1/subscribers", &who, &st) != 0 && st == 401);
    TK_ASSERT(check(a, NULL, "GET", "/nudm-sdm/v2/x", &who, &st) == 0); /* not an admin path */

    /* tenants */
    ask(a, "acme-token-0123456789", &who);
    TK_ASSERT(g5c_authz_supi_allowed(a, &who, "imsi-001019900000001") && g5c_authz_supi_allowed(a, &who, "imsi-001019800000077"));
    TK_ASSERT(!g5c_authz_supi_allowed(a, &who, "imsi-001028800000001") && !g5c_authz_supi_allowed(a, &who, "imsi-001010000000001") && !g5c_authz_supi_allowed(a, &who, NULL));
    TK_ASSERT(!g5c_authz_supi_allowed(a, &who, "imsi-001019")); /* a SUPI shorter than the prefix does not match */
    ask(a, "root-token-0123456789", &who);
    TK_ASSERT(g5c_authz_supi_allowed(a, &who, "imsi-999990000000001")); /* no tenant: everything */
    g5c_authz_free(a);

    /* the single admin token is a principal with every role and no tenant, next to the file or alone */
    a = g5c_authz_new(path, "the-single-admin-token-1", err, sizeof err);
    TK_ASSERT(a != NULL && ask(a, "the-single-admin-token-1", &who) == 0 && strcmp(who.name, "admin") == 0 && who.roles == G5C_ROLE_ALL && ask(a, "noc-token-0123456789", &who) == 0);
    g5c_authz_free(a);
    a = g5c_authz_new(NULL, "the-single-admin-token-1", err, sizeof err);
    TK_ASSERT(a != NULL && g5c_authz_enabled(a) && ask(a, "the-single-admin-token-1", &who) == 0 && ask(a, "noc-token-0123456789", &who) != 0);
    g5c_authz_free(a);
    a = g5c_authz_new(NULL, NULL, err, sizeof err);
    TK_ASSERT(a != NULL && !g5c_authz_enabled(a));
    g5c_authz_free(a);

    /* every way of being invalid names its cause and gives no authz */
    {
        char h[65], good[512];
        static const struct {
            const char *body, *want;
        } bad[] = {
            {"{\"tokens\":[],\"surprise\":1}", "surprise"},
            {"{\"tokens\":5}", "`tokens` must be a list"},
            {"{\"tokens\":[{\"name\":\"a b\",\"sha256\":\"H\",\"roles\":[\"read\"]}]}", "`name`"},
            {"{\"tokens\":[{\"name\":\"a\",\"sha256\":\"zz\",\"roles\":[\"read\"]}]}", "`sha256`"},
            {"{\"tokens\":[{\"name\":\"a\",\"sha256\":\"H\",\"roles\":[]}]}", "`roles` must list"},
            {"{\"tokens\":[{\"name\":\"a\",\"sha256\":\"H\",\"roles\":[\"root\"]}]}", "unknown role `root`"},
            {"{\"tokens\":[{\"name\":\"a\",\"sha256\":\"H\",\"roles\":[\"read\"],\"tenant\":\"nope\"}]}", "tenant `nope` is not defined"},
            {"{\"tokens\":[{\"name\":\"a\",\"sha256\":\"H\",\"roles\":[\"read\"],\"extra\":1}]}", "extra"},
            {"{\"tokens\":[{\"name\":\"a\",\"sha256\":\"H\",\"roles\":[\"read\"]},{\"name\":\"a\",\"sha256\":\"H2\",\"roles\":[\"read\"]}]}", "used twice"},
            {"{\"tokens\":[{\"name\":\"a\",\"sha256\":\"H\",\"roles\":[\"read\"]},{\"name\":\"b\",\"sha256\":\"H\",\"roles\":[\"read\"]}]}", "used twice"},
            {"{\"tokens\":[{\"name\":\"a\",\"sha256\":\"H\",\"roles\":[\"key-admin\"],\"tenant\":\"t\"}],\"tenants\":{\"t\":{\"supi_prefixes\":[\"imsi-0010199\"]}}}", "cannot belong to a tenant"},
            {"{\"tokens\":[],\"tenants\":{\"t\":{\"supi_prefixes\":[]}}}", "`supi_prefixes` must list"},
            {"{\"tokens\":[],\"tenants\":{\"t\":{\"supi_prefixes\":[\"001019\"]}}}", "SUPI prefix"},
            {"{\"tokens\":[],\"tenants\":{\"t\":{\"supi_prefixes\":[\"imsi-12\"]}}}", "SUPI prefix"},
            {"{\"tokens\":[],\"tenants\":5}", "`tenants` must be a mapping"},
            {"not json at all {", ""},
        };
        g5c_authz_hash("one", h);
        snprintf(good, sizeof good, "%s", h);
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
            char h2[65];
            char *s, *p;
            g5c_authz_hash("two", h2);
            s = g5c_xstrdup(bad[i].body);
            while ((p = strstr(s, "\"H2\"")) != NULL) {
                char *n = g5c_xasprintf("%.*s\"%s\"%s", (int)(p - s), s, h2, p + 4);
                free(s);
                s = n;
            }
            while ((p = strstr(s, "\"H\"")) != NULL) {
                char *n = g5c_xasprintf("%.*s\"%s\"%s", (int)(p - s), s, good, p + 3);
                free(s);
                s = n;
            }
            write_file(s);
            err[0] = 0;
            a = g5c_authz_new(path, NULL, err, sizeof err);
            if (a != NULL || strstr(err, bad[i].want) == NULL)
                TK_FAIL("token file case %zu: wanted [%s] in [%s]", i, bad[i].want, err);
            free(s);
        }
    }
    TK_ASSERT(g5c_authz_new("/nonexistent/tokens.json", NULL, err, sizeof err) == NULL);

    /* the file is read again when it changes */
    write_file(text);
    a = g5c_authz_new(path, NULL, err, sizeof err);
    TK_ASSERT(a != NULL && ask(a, "noc-token-0123456789", &who) == 0 && ask(a, "acme-token-0123456789", &who) == 0);
    sleep(1);
    {   /* two tokens are revoked, a new one appears */
        char *extra = entry("new-one", "new-token-0123456789", "\"policy\"", NULL);
        snprintf(text, sizeof text, "{\"tokens\":[%s]}", extra);
        free(extra);
        write_file(text);
    }
    sleep(1);
    TK_ASSERT(ask(a, "noc-token-0123456789", &who) != 0 && ask(a, "acme-token-0123456789", &who) != 0); /* revoked */
    TK_ASSERT(ask(a, "new-token-0123456789", &who) == 0 && who.roles == G5C_ROLE_POLICY);
    sleep(1);
    write_file("{ this is not valid");
    sleep(1);
    TK_ASSERT(ask(a, "new-token-0123456789", &who) == 0); /* a broken rewrite changes nothing */
    g5c_authz_free(a);

    free(noc);
    free(prov);
    free(keys);
    free(root);
    unlink(path);
    rmdir(tmpl);
    printf("authz: PASS\n");
    return 0;
}
