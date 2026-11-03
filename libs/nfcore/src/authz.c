/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _GNU_SOURCE
#include "g5c/authz.h"

#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "g5c/base.h"
#include "g5c/config.h"

#define MAX_TOKENS 256
#define MAX_PREFIXES 32

typedef struct {
    g5c_principal who;
    char hash[65];
} entry_t;

typedef struct {
    char name[48];
    char **prefixes;
    size_t n;
} tenant_t;

struct g5c_authz {
    char *path;
    char *legacy_hash; /* SHA-256 of the single admin token, NULL when there is none */
    pthread_mutex_t mu;
    entry_t *entries;
    size_t nentries;
    tenant_t *tenants;
    size_t ntenants;
    struct timespec mtime;
    time_t checked;
};

void g5c_authz_hash(const char *token, char out[65])
{
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)token, strlen(token), d);
    for (size_t i = 0; i < sizeof d; i++)
        snprintf(out + 2 * i, 3, "%02x", d[i]);
}

const char *g5c_role_name(unsigned role)
{
    switch (role) {
    case G5C_ROLE_READ:
        return "read";
    case G5C_ROLE_PROVISION:
        return "provision";
    case G5C_ROLE_POLICY:
        return "policy";
    case G5C_ROLE_KEY_ADMIN:
        return "key-admin";
    default:
        return "?";
    }
}

static unsigned role_of(const char *s)
{
    for (unsigned r = 1; r <= G5C_ROLE_KEY_ADMIN; r <<= 1)
        if (strcmp(g5c_role_name(r), s) == 0)
            return r;
    return 0;
}

static void free_tables(entry_t *e, tenant_t *t, size_t nt)
{
    free(e);
    for (size_t i = 0; i < nt; i++) {
        for (size_t j = 0; j < t[i].n; j++)
            free(t[i].prefixes[j]);
        free(t[i].prefixes);
    }
    free(t);
}

static bool is_hex64(const char *s)
{
    if (s == NULL || strlen(s) != 64)
        return false;
    for (; *s; s++)
        if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f')))
            return false;
    return true;
}

static bool is_name(const char *s)
{
    size_t n = s != NULL ? strlen(s) : 0;
    if (n == 0 || n >= 48)
        return false;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '-' || *s == '_' || *s == '.'))
            return false;
    return true;
}

static int load_file(const char *path, entry_t **out_e, size_t *out_n, tenant_t **out_t, size_t *out_nt, char *err, size_t errcap)
{
    static const char *const k_top[] = {"tokens", "tenants", NULL}, *const k_tok[] = {"name", "sha256", "roles", "tenant", NULL}, *const k_ten[] = {"supi_prefixes", NULL};
    g5c_json *root = g5c_config_load(path, err, errcap);
    const g5c_json *tokens, *tenants;
    entry_t *e = NULL;
    tenant_t *t = NULL;
    size_t n = 0, nt = 0;
    if (root == NULL)
        return -1;
    if (g5c_json_check_keys(root, k_top, "admin tokens file", err, errcap) != 0)
        goto bad;
    tenants = g5c_json_get(root, "tenants");
    if (tenants != NULL && !g5c_json_is(tenants, G5C_J_OBJECT)) {
        snprintf(err, errcap, "`tenants` must be a mapping");
        goto bad;
    }
    t = g5c_xcalloc(tenants != NULL && g5c_json_len(tenants) > 0 ? g5c_json_len(tenants) : 1, sizeof *t);
    for (size_t i = 0; tenants != NULL && i < g5c_json_len(tenants); i++) {
        const char *name = g5c_json_key_at(tenants, i);
        const g5c_json *ten = g5c_json_val_at(tenants, i), *pl;
        if (!is_name(name) || !g5c_json_is(ten, G5C_J_OBJECT) || g5c_json_check_keys(ten, k_ten, "tenant", err, errcap) != 0) {
            if (err[0] == 0)
                snprintf(err, errcap, "a tenant needs a short name and a mapping");
            goto bad;
        }
        pl = g5c_json_get(ten, "supi_prefixes");
        if (!g5c_json_is(pl, G5C_J_ARRAY) || g5c_json_len(pl) == 0 || g5c_json_len(pl) > MAX_PREFIXES) {
            snprintf(err, errcap, "tenant %s: `supi_prefixes` must list 1 to %d prefixes", name, MAX_PREFIXES);
            goto bad;
        }
        snprintf(t[nt].name, sizeof t[nt].name, "%s", name);
        t[nt].prefixes = g5c_xcalloc(g5c_json_len(pl), sizeof *t[nt].prefixes);
        for (size_t k = 0; k < g5c_json_len(pl); k++) {
            const char *p = g5c_json_str(g5c_json_at(pl, k));
            if (p == NULL || strncmp(p, "imsi-", 5) != 0 || strlen(p) < 9 || strlen(p) > 20 || !g5c_is_digits(p + 5)) {
                snprintf(err, errcap, "tenant %s: a SUPI prefix is `imsi-` and at least 4 digits", name);
                nt++;
                goto bad;
            }
            t[nt].prefixes[t[nt].n++] = g5c_xstrdup(p);
        }
        nt++;
    }
    tokens = g5c_json_get(root, "tokens");
    if (!g5c_json_is(tokens, G5C_J_ARRAY) || g5c_json_len(tokens) > MAX_TOKENS) {
        snprintf(err, errcap, "`tokens` must be a list of at most %d entries", MAX_TOKENS);
        goto bad;
    }
    e = g5c_xcalloc(g5c_json_len(tokens) + 1, sizeof *e);
    for (size_t i = 0; i < g5c_json_len(tokens); i++) {
        const g5c_json *tk = g5c_json_at(tokens, i), *rl;
        const char *name = g5c_json_get_str(tk, "name"), *hash = g5c_json_get_str(tk, "sha256"), *tenant = g5c_json_get_str(tk, "tenant");
        unsigned roles = 0;
        if (!g5c_json_is(tk, G5C_J_OBJECT) || g5c_json_check_keys(tk, k_tok, "token entry", err, errcap) != 0) {
            if (err[0] == 0)
                snprintf(err, errcap, "a token entry must be a mapping");
            goto bad;
        }
        if (!is_name(name) || !is_hex64(hash)) {
            snprintf(err, errcap, "token entry %zu: `name` (letters, digits, - _ .) and `sha256` (64 lower-case hex characters) are required", i + 1);
            goto bad;
        }
        for (size_t k = 0; k < n; k++)
            if (strcmp(e[k].who.name, name) == 0 || strcmp(e[k].hash, hash) == 0) {
                snprintf(err, errcap, "token entry %s: the name or the hash is used twice", name);
                goto bad;
            }
        rl = g5c_json_get(tk, "roles");
        if (!g5c_json_is(rl, G5C_J_ARRAY) || g5c_json_len(rl) == 0) {
            snprintf(err, errcap, "token %s: `roles` must list at least one of read, provision, policy, key-admin", name);
            goto bad;
        }
        for (size_t k = 0; k < g5c_json_len(rl); k++) {
            unsigned r = role_of(g5c_json_str(g5c_json_at(rl, k)) != NULL ? g5c_json_str(g5c_json_at(rl, k)) : "");
            if (r == 0) {
                snprintf(err, errcap, "token %s: unknown role `%s`", name, g5c_json_str(g5c_json_at(rl, k)) != NULL ? g5c_json_str(g5c_json_at(rl, k)) : "?");
                goto bad;
            }
            roles |= r;
        }
        if (tenant != NULL) {
            bool known = false;
            for (size_t k = 0; k < nt; k++)
                known = known || strcmp(t[k].name, tenant) == 0;
            if (!known || strlen(tenant) >= sizeof e[0].who.tenant) {
                snprintf(err, errcap, "token %s: the tenant `%s` is not defined", name, tenant);
                goto bad;
            }
            if (roles & G5C_ROLE_KEY_ADMIN) {
                snprintf(err, errcap, "token %s: key-admin affects every subscriber and cannot belong to a tenant", name);
                goto bad;
            }
            snprintf(e[n].who.tenant, sizeof e[n].who.tenant, "%s", tenant);
        }
        snprintf(e[n].who.name, sizeof e[n].who.name, "%s", name);
        snprintf(e[n].hash, sizeof e[n].hash, "%s", hash);
        e[n].who.roles = roles;
        n++;
    }
    g5c_json_free(root);
    *out_e = e;
    *out_n = n;
    *out_t = t;
    *out_nt = nt;
    return 0;
bad:
    free_tables(e, t, nt);
    g5c_json_free(root);
    return -1;
}

static void stamp(const char *path, struct timespec *mt)
{
    struct stat st;
    if (stat(path, &st) == 0)
        *mt = st.st_mtim;
}

g5c_authz *g5c_authz_new(const char *path, const char *legacy_token, char *err, size_t errcap)
{
    g5c_authz *a = g5c_xcalloc(1, sizeof *a);
    pthread_mutex_init(&a->mu, NULL);
    if (legacy_token != NULL) {
        a->legacy_hash = g5c_xmalloc(65);
        g5c_authz_hash(legacy_token, a->legacy_hash);
    }
    if (path != NULL) {
        a->path = g5c_xstrdup(path);
        if (load_file(path, &a->entries, &a->nentries, &a->tenants, &a->ntenants, err, errcap) != 0) {
            g5c_authz_free(a);
            return NULL;
        }
        stamp(path, &a->mtime);
    }
    return a;
}

void g5c_authz_free(g5c_authz *a)
{
    if (a == NULL)
        return;
    free_tables(a->entries, a->tenants, a->ntenants);
    free(a->path);
    free(a->legacy_hash);
    pthread_mutex_destroy(&a->mu);
    free(a);
}

bool g5c_authz_enabled(const g5c_authz *a)
{
    return a != NULL && (a->path != NULL || a->legacy_hash != NULL);
}

/* the file again, when it changed (looked at most once a second); a file that no longer parses keeps the tables in force */
static void refresh(g5c_authz *a)
{
    time_t now = time(NULL);
    struct stat st;
    entry_t *e = NULL;
    tenant_t *t = NULL;
    size_t n = 0, nt = 0;
    char err[200] = "";
    if (a->path == NULL || now == a->checked)
        return;
    a->checked = now;
    if (stat(a->path, &st) != 0 || (st.st_mtim.tv_sec == a->mtime.tv_sec && st.st_mtim.tv_nsec == a->mtime.tv_nsec))
        return;
    a->mtime = st.st_mtim;
    if (load_file(a->path, &e, &n, &t, &nt, err, sizeof err) != 0) {
        G5C_LOGE("g5c_audit", "admin tokens file %s changed but is not valid, the old tokens stay in force: %s", a->path, err);
        return;
    }
    free_tables(a->entries, a->tenants, a->ntenants);
    a->entries = e;
    a->nentries = n;
    a->tenants = t;
    a->ntenants = nt;
    G5C_LOGI("g5c_audit", "admin tokens file read again: %zu tokens, %zu tenants", n, nt);
}

int g5c_authz_identify(g5c_authz *a, const g5c_req *req, g5c_principal *out)
{
    const char *tok = g5c_bearer_token(req);
    char h[65];
    int rc = -1;
    if (a == NULL || tok == NULL || *tok == '\0')
        return -1;
    g5c_authz_hash(tok, h);
    pthread_mutex_lock(&a->mu);
    refresh(a);
    if (a->legacy_hash != NULL && CRYPTO_memcmp(h, a->legacy_hash, 64) == 0) { /* the whole table is walked: the time does not tell which entry matched */
        memset(out, 0, sizeof *out);
        snprintf(out->name, sizeof out->name, "admin");
        out->roles = G5C_ROLE_ALL;
        rc = 0;
    }
    for (size_t i = 0; i < a->nentries; i++)
        if (CRYPTO_memcmp(h, a->entries[i].hash, 64) == 0 && rc != 0) {
            *out = a->entries[i].who;
            rc = 0;
        }
    pthread_mutex_unlock(&a->mu);
    OPENSSL_cleanse(h, sizeof h);
    return rc;
}

void g5c_authz_who(g5c_authz *a, const g5c_req *req, g5c_principal *who)
{
    memset(who, 0, sizeof *who);
    if (a == NULL || g5c_authz_identify(a, req, who) != 0) {
        memset(who, 0, sizeof *who);
        snprintf(who->name, sizeof who->name, "admin");
        who->roles = G5C_ROLE_ALL;
    }
}

int g5c_authz_check(g5c_authz *a, const g5c_req *req, g5c_role_fn need, g5c_principal *who, g5c_resp *resp)
{
    unsigned role = need(req->method, req->path);
    if (role == 0)
        return 0;
    if (g5c_authz_identify(a, req, who) != 0) {
        g5c_resp_problem_simple(resp, 401, "UNAUTHORIZED", NULL);
        g5c_resp_header(resp, "www-authenticate", "Bearer");
        return 1;
    }
    if ((who->roles & role) != role) {
        char d[96];
        snprintf(d, sizeof d, "the role %s is needed", role == G5C_ROLE_ALL ? "admin (every role)" : g5c_role_name(role));
        G5C_LOGW("g5c_audit", "admin API: %s %s refused for %s: %s", req->method, req->path, who->name, d);
        g5c_resp_problem_simple(resp, 403, "FORBIDDEN", d);
        return 1;
    }
    return 0;
}

bool g5c_authz_supi_allowed(const g5c_authz *a, const g5c_principal *p, const char *supi)
{
    bool ok = false;
    if (p->tenant[0] == '\0')
        return true;
    if (supi == NULL)
        return false;
    pthread_mutex_lock((pthread_mutex_t *)(uintptr_t)&a->mu);
    for (size_t i = 0; i < a->ntenants; i++)
        if (strcmp(a->tenants[i].name, p->tenant) == 0)
            for (size_t k = 0; k < a->tenants[i].n; k++)
                if (strncmp(supi, a->tenants[i].prefixes[k], strlen(a->tenants[i].prefixes[k])) == 0)
                    ok = true;
    pthread_mutex_unlock((pthread_mutex_t *)(uintptr_t)&a->mu);
    return ok;
}
