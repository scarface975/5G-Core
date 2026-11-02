/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nudr_DataRepository: one generic engine over the generated operation table (TS 29.505 / TS 29.519).
 *
 * A resource is addressed by its URI. The storage key is the path without the subscriber and the serving PLMN, the
 * partition is the subscriber, the group or the global one. GET, PUT, PATCH, DELETE and POST behave the same on every
 * resource; what differs (which schema, which status codes, collections, composite parents) comes from the table. */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "api.h"
#include "g5c/base.h"
#include "g5c/udr.h"
#include "priv.h"

static const char *const ROOTS[] = {"/nudr-dr/v1", "/nudr-dr/v2"};

typedef struct {
    g5c_udr *u;
    udr_op_def op; /* by value: extension operations are derived copies */
    int doc_schema;
    bool ext;
} rctx;

struct g5c_udr {
    g5c_udr_store *store;
    udr_db *db;
    udr_opts o;
    char *token;
    udr_schemas *sch;
    rctx **ctxs;
    size_t nctx;
    udr_notifier *nt;
    g5c_counter *c_conflict, *c_invalid, *c_notfound;
    g5c_gauge *g_records;
    g5c_registry *reg;
    bool own_reg;
    g5c_json *groups;
    void **allocs;
    size_t nallocs;
};


/* ---- small helpers ---------------------------------------------------------------------------------------------- */

static void problem(g5c_resp *resp, int status, const char *cause, const char *detail)
{
    g5c_resp_problem_simple(resp, status, cause, detail);
}

static void db_error(g5c_resp *resp)
{
    problem(resp, 500, "SYSTEM_FAILURE", "the data repository is unavailable");
}

static int hexval(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

/* percent-decode a path parameter; NULL when it is malformed or would add a path separator */
static char *pdecode(const char *s)
{
    size_t n = strlen(s), o = 0;
    char *out = g5c_xmalloc(n + 1);
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '%') {
            int hi = i + 2 < n ? hexval(s[i + 1]) : -1, lo = i + 2 < n ? hexval(s[i + 2]) : -1;
            if (hi < 0 || lo < 0)
                goto bad;
            out[o++] = (char)(hi * 16 + lo);
            i += 2;
        } else {
            out[o++] = s[i];
        }
        if (out[o - 1] == '/' || (unsigned char)out[o - 1] < 0x20)
            goto bad;
    }
    out[o] = '\0';
    return out;
bad:
    free(out);
    return NULL;
}

/* the storage key of the request: the template with each {name} replaced by the decoded path parameter */
static char *expand_key(const g5c_req *req, const char *tmpl)
{
    char *out = g5c_xstrdup("");
    for (const char *p = tmpl; *p;) {
        if (*p == '{') {
            const char *e = strchr(p, '}');
            char *name, *dec, *next;
            const char *val;
            if (e == NULL)
                break;
            name = g5c_xstrndup(p + 1, (size_t)(e - p - 1));
            val = g5c_req_param(req, name);
            free(name);
            dec = val != NULL ? pdecode(val) : NULL;
            if (dec == NULL) {
                free(out);
                return NULL;
            }
            next = g5c_xasprintf("%s%s", out, dec);
            free(dec);
            free(out);
            out = next;
            p = e + 1;
        } else {
            size_t n = strcspn(p, "{");
            char *next = g5c_xasprintf("%s%.*s", out, (int)n, p);
            free(out);
            out = next;
            p += n;
        }
    }
    return out;
}

static bool is_ue_part(const udr_op_def *op)
{
    return op->part == UDR_PART_UE;
}

/* The partition of a subscriber, a group or the global one. A subscriber may be addressed by a GPSI: the alias index
 * (maintained from the identity data) maps it to the SUPI. */
char *udr_part_for_id(g5c_udr *u, udr_part_kind kind, const char *id)
{
    char *part;
    if (kind == UDR_PART_GLOBAL)
        return g5c_xstrdup(UDR_GLOBAL_PART);
    if (kind == UDR_PART_GROUP)
        return g5c_xasprintf("%s%s", UDR_GROUP_PREFIX, id);
    part = g5c_xstrdup(id);
    if (u->db->ops->part_exists(u->db->self, id) != 1) {
        char *ak = g5c_xasprintf("%s/%s", UDR_ALIAS_KEY, id);
        udr_rec r;
        if (u->db->ops->get(u->db->self, UDR_GLOBAL_PART, ak, &r) == 1) {
            const char *supi = g5c_json_get_str(r.doc, "supi");
            if (supi != NULL) {
                free(part);
                part = g5c_xstrdup(supi);
            }
            g5c_json_free(r.doc);
        }
        free(ak);
    }
    return part;
}

static char *partition_of(g5c_udr *u, const udr_op_def *op, const g5c_req *req)
{
    const char *raw;
    char *id, *part;
    if (op->part == UDR_PART_GLOBAL)
        return g5c_xstrdup(UDR_GLOBAL_PART);
    raw = g5c_req_param(req, op->part == UDR_PART_UE ? "ueId" : "ueGroupId");
    id = raw != NULL ? pdecode(raw) : NULL;
    if (id == NULL || id[0] == '\0') {
        free(id);
        return NULL;
    }
    part = udr_part_for_id(u, op->part, id);
    free(id);
    return part;
}

/* The storage address a resource URI of this API names: the first GET operation whose template fits the path. */
bool udr_resolve_uri(g5c_udr *u, const char *uri, char **part, char **key)
{
    const char *p = uri, *q;
    char *path, *segs[16];
    size_t ns = 0;
    bool found = false;
    if ((q = strstr(p, "://")) != NULL) {
        p = strchr(q + 3, '/');
        if (p == NULL)
            return false;
    }
    if (strncmp(p, "/nudr-dr/v", 10) != 0)
        return false;
    p += 10;
    while (*p >= '0' && *p <= '9')
        p++;
    if (*p != '/')
        return false;
    path = g5c_xstrndup(p, strcspn(p, "?#"));
    {
        char *save = NULL;
        for (char *t = strtok_r(path, "/", &save); t != NULL && ns < 16; t = strtok_r(NULL, "/", &save))
            segs[ns++] = t;
    }
    for (size_t i = 0; i < udr_ops_count && !found; i++) {
        const udr_op_def *op = &udr_ops[i];
        const char *names[8], *vals[8];
        size_t nn = 0, k = 0;
        char *tp, *tsegs[16];
        size_t nt = 0;
        bool ok = true;
        if (strcmp(op->method, "GET") != 0)
            continue;
        tp = g5c_xstrdup(op->path);
        {
            char *save = NULL;
            for (char *t = strtok_r(tp, "/", &save); t != NULL && nt < 16; t = strtok_r(NULL, "/", &save))
                tsegs[nt++] = t;
        }
        if (nt == ns) {
            for (k = 0; k < nt && ok; k++) {
                size_t l = strlen(tsegs[k]);
                if (tsegs[k][0] == '{' && tsegs[k][l - 1] == '}') {
                    if (nn < 8) {
                        tsegs[k][l - 1] = '\0';
                        names[nn] = tsegs[k] + 1;
                        vals[nn++] = segs[k];
                    }
                } else if (strcmp(tsegs[k], segs[k]) != 0) {
                    ok = false;
                }
            }
        } else {
            ok = false;
        }
        if (ok) { /* expand the key and find the subscriber */
            char *out = g5c_xstrdup(""), *id = NULL;
            bool good = true;
            for (const char *t = op->key; *t && good;) {
                if (*t == '{') {
                    const char *e = strchr(t, '}');
                    char *nm = g5c_xstrndup(t + 1, (size_t)(e - t - 1)), *dec = NULL, *next;
                    for (size_t z = 0; z < nn; z++)
                        if (strcmp(names[z], nm) == 0)
                            dec = pdecode(vals[z]);
                    free(nm);
                    if (dec == NULL) {
                        good = false;
                        break;
                    }
                    next = g5c_xasprintf("%s%s", out, dec);
                    free(dec);
                    free(out);
                    out = next;
                    t = e + 1;
                } else {
                    size_t n = strcspn(t, "{");
                    char *next = g5c_xasprintf("%s%.*s", out, (int)n, t);
                    free(out);
                    out = next;
                    t += n;
                }
            }
            for (size_t z = 0; z < nn && good; z++)
                if ((op->part == UDR_PART_UE && strcmp(names[z], "ueId") == 0) ||
                    (op->part == UDR_PART_GROUP && strcmp(names[z], "ueGroupId") == 0)) {
                    id = pdecode(vals[z]);
                    good = id != NULL;
                }
            if (good && (op->part == UDR_PART_GLOBAL || id != NULL)) {
                *part = udr_part_for_id(u, op->part, id != NULL ? id : "");
                *key = out;
                found = true;
            } else {
                free(out);
            }
            free(id);
        }
        free(tp);
    }
    free(path);
    return found;
}

static void set_validators(const g5c_udr *u, g5c_resp *resp, uint64_t rev, int64_t mtime)
{
    char *et = udr_etag_str(rev), date[48], cc[40];
    g5c_resp_header(resp, "etag", et);
    free(et);
    udr_http_date(mtime, date, sizeof date);
    if (date[0] != '\0')
        g5c_resp_header(resp, "last-modified", date);
    snprintf(cc, sizeof cc, "max-age=%u", u->o.cache_max_age_s);
    g5c_resp_header(resp, "cache-control", cc);
}

/* does an If-Match / If-None-Match list contain the entity tag of `rev` (or "*")? */
static bool etag_list_has(const char *list, uint64_t rev)
{
    const char *p = list;
    while (p != NULL && *p) {
        size_t n;
        char *tok;
        while (*p == ' ' || *p == ',')
            p++;
        n = strcspn(p, ",");
        if (n == 0)
            break;
        tok = g5c_xstrndup(p, n);
        while (n > 0 && tok[n - 1] == ' ')
            tok[--n] = '\0';
        if (strcmp(tok, "*") == 0 || udr_etag_rev(tok) == rev) {
            free(tok);
            return true;
        }
        free(tok);
        p += strcspn(p, ",");
    }
    return false;
}

/* The write preconditions of the request. 0 ok; -1 when If-Match is present but malformed. */
static int parse_write_cond(const g5c_req *req, udr_cond *c)
{
    const char *im = g5c_req_header(req, "if-match"), *inm = g5c_req_header(req, "if-none-match");
    memset(c, 0, sizeof *c);
    if (im != NULL) {
        if (strcmp(im, "*") == 0) {
            c->kind = UDR_COND_EXISTS;
        } else {
            uint64_t rev = udr_etag_rev(im);
            if (rev == 0)
                return -1;
            c->kind = UDR_COND_MATCH;
            c->rev = rev;
        }
    } else if (inm != NULL && strcmp(inm, "*") == 0) {
        c->kind = UDR_COND_NOT_EXISTS;
    }
    return 0;
}

static void not_found(g5c_udr *u, const udr_op_def *op, const char *part, g5c_resp *resp, const char *what)
{
    const char *cause = "DATA_NOT_FOUND";
    char *d;
    if (is_ue_part(op) && u->db->ops->part_exists(u->db->self, part) != 1)
        cause = "USER_NOT_FOUND";
    d = g5c_xasprintf("no %s for %s", what, part);
    problem(resp, 404, cause, d);
    free(d);
    g5c_counter_inc(u->c_notfound);
}

/* ---- the `fields` query parameter ------------------------------------------------------------------------------- */

static void copy_path(const g5c_json *src, char **segs, size_t n, g5c_json **dst)
{
    if (n == 0) {
        g5c_json_free(*dst);
        *dst = g5c_json_dup(src);
        return;
    }
    if (g5c_json_is(src, G5C_J_OBJECT)) {
        const g5c_json *child = g5c_json_get(src, segs[0]);
        g5c_json *sub;
        if (child == NULL)
            return;
        if (*dst == NULL)
            *dst = g5c_json_new_obj();
        sub = g5c_json_detach(*dst, segs[0]);
        copy_path(child, segs + 1, n - 1, &sub);
        if (sub != NULL)
            g5c_json_set(*dst, segs[0], sub);
    } else if (g5c_json_is(src, G5C_J_ARRAY)) { /* an array is transparent: the rest of the pointer applies to every element */
        if (*dst == NULL) {
            *dst = g5c_json_new_arr();
            for (size_t i = 0; i < g5c_json_len(src); i++)
                g5c_json_push(*dst, g5c_json_new_obj());
        }
        for (size_t i = 0; i < g5c_json_len(src) && i < g5c_json_len(*dst); i++) {
            g5c_json *e = g5c_json_dup(g5c_json_at(*dst, i));
            copy_path(g5c_json_at(src, i), segs, n, &e);
            g5c_json_arr_replace(*dst, i, e);
        }
    }
}

static g5c_json *select_fields(const g5c_json *doc, const char *fields)
{
    g5c_json *out = NULL;
    const char *p = fields;
    while (*p) {
        size_t n;
        char *ptr, **segs = NULL;
        while (*p == ' ')
            p++;
        n = strcspn(p, ",");
        ptr = *p == '/' ? g5c_xstrndup(p, n) : g5c_xasprintf("/%.*s", (int)n, p); /* a bare member name is taken as /name */
        size_t ns = 0;
        for (char *s = ptr; *s == '/'; ) {
            char *e = strchr(s + 1, '/'), *seg;
            seg = e != NULL ? g5c_xstrndup(s + 1, (size_t)(e - s - 1)) : g5c_xstrdup(s + 1);
            for (char *r = seg, *w = seg;; r++) { /* ~1 -> /, ~0 -> ~ */
                if (r[0] == '~' && r[1] == '1') {
                    *w++ = '/';
                    r++;
                } else if (r[0] == '~' && r[1] == '0') {
                    *w++ = '~';
                    r++;
                } else {
                    *w++ = *r;
                    if (*r == '\0')
                        break;
                }
            }
            segs = g5c_xrealloc(segs, (ns + 1) * sizeof *segs);
            segs[ns++] = seg;
            s = e != NULL ? e : s + strlen(s);
        }
        if (ns > 0)
            copy_path(doc, segs, ns, &out);
        for (size_t i = 0; i < ns; i++)
            free(segs[i]);
        free(segs);
        free(ptr);
        p += n;
        if (*p == ',')
            p++;
    }
    return out != NULL ? out : g5c_json_new_obj();
}

/* ---- views ------------------------------------------------------------------------------------------------------ */

/* S-NSSAI equality (TS 23.003 28.4.2): the slice differentiator FFFFFF means that none is associated, like an absent `sd` */
bool udr_snssai_equal(const g5c_json *a, const g5c_json *b)
{
    const char *sa, *sb;
    if (a == NULL || b == NULL)
        return false;
    if (!g5c_json_equal(g5c_json_get(a, "sst"), g5c_json_get(b, "sst")))
        return false;
    sa = g5c_json_get_str(a, "sd");
    sb = g5c_json_get_str(b, "sd");
    if (sa != NULL && strcasecmp(sa, "ffffff") == 0)
        sa = NULL;
    if (sb != NULL && strcasecmp(sb, "ffffff") == 0)
        sb = NULL;
    if (sa == NULL || sb == NULL)
        return sa == sb;
    return strcasecmp(sa, sb) == 0;
}

#define snssai_eq udr_snssai_equal

/* session-management subscription data filtered by ?single-nssai= and ?dnn= (TS 29.505) */
static g5c_json *sm_view(const g5c_req *req, const g5c_json *list)
{
    g5c_json *out = g5c_json_new_arr(), *want = NULL;
    char *q = g5c_req_query_decoded(req, "single-nssai"), *want_dnn = g5c_req_query_decoded(req, "dnn");
    if (q != NULL)
        want = g5c_json_parse(q, strlen(q), NULL, 0);
    free(q);
    for (size_t i = 0; i < g5c_json_len(list); i++) {
        g5c_json *d = g5c_json_dup(g5c_json_at(list, i)), *cfg;
        if (want != NULL && !snssai_eq(g5c_json_get(d, "singleNssai"), want)) {
            g5c_json_free(d);
            continue;
        }
        cfg = g5c_json_get_mut(d, "dnnConfigurations");
        if (want_dnn != NULL && g5c_json_is(cfg, G5C_J_OBJECT))
            for (size_t k = g5c_json_len(cfg); k > 0; k--)
                if (strcmp(g5c_json_key_at(cfg, k - 1), want_dnn) != 0) {
                    char *key = g5c_xstrdup(g5c_json_key_at(cfg, k - 1));
                    g5c_json_remove(cfg, key);
                    free(key);
                }
        g5c_json_push(out, d);
    }
    g5c_json_free(want);
    free(want_dnn);
    return out;
}

/* SM policy data (TS 29.519) narrowed by ?snssai= and ?dnn=: only the slices and DNNs asked for; NULL when no slice matches */
static g5c_json *smpolicy_view(const g5c_req *req, const g5c_json *doc)
{
    char *q = g5c_req_query_decoded(req, "snssai"), *want_dnn = g5c_req_query_decoded(req, "dnn");
    g5c_json *want = q != NULL ? g5c_json_parse(q, strlen(q), NULL, 0) : NULL, *out = g5c_json_dup(doc), *slices, *kept;
    free(q);
    if (want == NULL && want_dnn == NULL) {
        free(want_dnn);
        return out;
    }
    slices = g5c_json_get_mut(out, "smPolicySnssaiData");
    kept = g5c_json_new_obj();
    for (size_t i = 0; slices != NULL && i < g5c_json_len(slices); i++) {
        g5c_json *e = g5c_json_dup(g5c_json_val_at(slices, i)), *dnns;
        if (want != NULL && !snssai_eq(g5c_json_get(e, "snssai"), want)) {
            g5c_json_free(e);
            continue;
        }
        dnns = g5c_json_get_mut(e, "smPolicyDnnData");
        if (want_dnn != NULL && g5c_json_is(dnns, G5C_J_OBJECT)) {
            for (size_t k = g5c_json_len(dnns); k > 0; k--)
                if (strcmp(g5c_json_key_at(dnns, k - 1), want_dnn) != 0) {
                    char *key = g5c_xstrdup(g5c_json_key_at(dnns, k - 1));
                    g5c_json_remove(dnns, key);
                    free(key);
                }
            if (g5c_json_len(dnns) == 0)
                g5c_json_remove(e, "smPolicyDnnData");
        }
        g5c_json_set(kept, g5c_json_key_at(slices, i), e);
    }
    free(want_dnn);
    g5c_json_free(want);
    if (g5c_json_len(kept) == 0) {
        g5c_json_free(kept);
        g5c_json_free(out);
        return NULL;
    }
    g5c_json_set(out, "smPolicySnssaiData", kept);
    return out;
}

static bool key_has_suffix(const char *key, const char *suffix)
{
    size_t kl = strlen(key), sl = strlen(suffix);
    return kl >= sl && strcmp(key + kl - sl, suffix) == 0;
}

/* the direct children (one more path segment) of a collection key */
static g5c_json *collection_docs(g5c_udr *u, const char *part, const char *key, size_t *n_out)
{
    udr_list l;
    g5c_json *arr = g5c_json_new_arr();
    size_t pl = strlen(key) + 1;
    if (u->db->ops->list(u->db->self, part, key, &l) != 0) {
        g5c_json_free(arr);
        return NULL;
    }
    for (size_t i = 0; i < l.n; i++)
        if (strchr(l.keys[i] + pl, '/') == NULL) {
            g5c_json_push(arr, l.recs[i].doc);
            l.recs[i].doc = NULL;
        }
    udr_list_free(&l);
    *n_out = g5c_json_len(arr);
    return arr;
}

/* the composite parents (ProvisionedDataSets, ContextDataSets): the members present for the subscriber */
static g5c_json *assemble(g5c_udr *u, const char *part, const char *key, bool *is_composite)
{
    g5c_json *out = NULL;
    for (size_t i = 0; i < udr_composites_count; i++) {
        const udr_composite *c = &udr_composites[i];
        if (strcmp(c->parent, key) != 0)
            continue;
        *is_composite = true;
        if (out == NULL)
            out = g5c_json_new_obj();
        if (c->list) {
            size_t n = 0;
            g5c_json *arr = collection_docs(u, part, c->child, &n);
            if (arr != NULL && n > 0)
                g5c_json_set(out, c->prop, arr);
            else
                g5c_json_free(arr);
        } else {
            udr_rec r;
            if (u->db->ops->get(u->db->self, part, c->child, &r) == 1)
                g5c_json_set(out, c->prop, r.doc);
        }
    }
    return out;
}

/* ---- GET -------------------------------------------------------------------------------------------------------- */

static void send_doc(const g5c_udr *u, const g5c_req *req, g5c_resp *resp, g5c_json *doc, const udr_rec *rec)
{
    char *q = g5c_req_query_decoded(req, "fields");
    if (q != NULL && q[0] != '\0') {
        g5c_json *sel = select_fields(doc, q);
        g5c_json_free(doc);
        doc = sel;
    }
    free(q);
    if (rec != NULL)
        set_validators(u, resp, rec->rev, rec->mtime);
    g5c_resp_json(resp, 200, doc);
    g5c_json_free(doc);
}

static void h_get(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const rctx *c = ctx;
    g5c_udr *u = c->u;
    char *part = partition_of(u, &c->op, req), *key = expand_key(req, c->op.key);
    udr_rec rec;
    int rc;
    if (part == NULL || key == NULL) {
        problem(resp, 400, "MANDATORY_IE_INCORRECT", "malformed path parameter");
        goto out;
    }
    rc = u->db->ops->get(u->db->self, part, key, &rec);
    if (rc < 0) {
        db_error(resp);
        goto out;
    }
    if (rc == 1) {
        const char *inm = g5c_req_header(req, "if-none-match"), *ims = g5c_req_header(req, "if-modified-since");
        g5c_json *doc = rec.doc;
        if (inm != NULL ? etag_list_has(inm, rec.rev) : (ims != NULL && udr_parse_http_date(ims) >= rec.mtime)) {
            set_validators(u, resp, rec.rev, rec.mtime);
            g5c_resp_status(resp, 304);
            g5c_json_free(doc);
            goto out;
        }
        if (key_has_suffix(key, "provisioned-data/sm-data") && g5c_json_is(doc, G5C_J_ARRAY)) {
            g5c_json *view = sm_view(req, doc);
            g5c_json_free(doc);
            doc = view;
            if (g5c_json_len(doc) == 0) {
                g5c_json_free(doc);
                not_found(u, &c->op, part, resp, "session management data");
                goto out;
            }
        }
        if (strcmp(key, "policy-data/ues/sm-data") == 0 && g5c_json_is(doc, G5C_J_OBJECT)) {
            g5c_json *view = smpolicy_view(req, doc);
            g5c_json_free(doc);
            if (view == NULL) {
                not_found(u, &c->op, part, resp, "SM policy data for the slice");
                goto out;
            }
            doc = view;
        }
        send_doc(u, req, resp, doc, &rec);
        goto out;
    }
    {
        bool composite = false;
        g5c_json *asm_doc = assemble(u, part, key, &composite);
        if (composite) {
            if (asm_doc == NULL || g5c_json_len(asm_doc) == 0) {
                g5c_json_free(asm_doc);
                not_found(u, &c->op, part, resp, "data");
                goto out;
            }
            send_doc(u, req, resp, asm_doc, NULL);
            goto out;
        }
    }
    if (c->op.coll) {
        size_t n = 0;
        g5c_json *arr = collection_docs(u, part, key, &n);
        if (arr == NULL) {
            db_error(resp);
        } else if (n == 0) {
            g5c_json_free(arr);
            not_found(u, &c->op, part, resp, "data");
        } else {
            send_doc(u, req, resp, arr, NULL);
        }
        goto out;
    }
    not_found(u, &c->op, part, resp, "data");
out:
    free(part);
    free(key);
}

/* ---- PUT / POST ------------------------------------------------------------------------------------------------- */

static bool ext_allowed(const rctx *c, const g5c_req *req, g5c_resp *resp);

static bool body_ok(const rctx *c, g5c_json *body, int schema, g5c_resp *resp)
{
    char err[200];
    if (c->u->o.no_validation || schema < 0)
        return true;
    if (udr_schema_validate(c->u->sch, schema, body, err, sizeof err) == 0)
        return true;
    g5c_counter_inc(c->u->c_invalid);
    problem(resp, 400, "MANDATORY_IE_INCORRECT", err);
    return false;
}

static void note_write(g5c_udr *u)
{
    if (u->g_records != NULL)
        g5c_gauge_set(u->g_records, (int64_t)u->db->ops->count(u->db->self));
}

/* the alias index (GPSI -> SUPI) follows the identity data of the subscriber */
static void sync_aliases(g5c_udr *u, const char *part, const g5c_json *before, const g5c_json *after)
{
    const g5c_json *old_l = g5c_json_get(before, "gpsiList"), *new_l = g5c_json_get(after, "gpsiList");
    for (size_t i = 0; i < g5c_json_len(old_l); i++) {
        const char *g = g5c_json_str(g5c_json_at(old_l, i));
        bool keep = false;
        for (size_t k = 0; g != NULL && k < g5c_json_len(new_l); k++)
            keep = keep || strcmp(g, g5c_json_str(g5c_json_at(new_l, k)) ? g5c_json_str(g5c_json_at(new_l, k)) : "") == 0;
        if (g != NULL && !keep) {
            char *ak = g5c_xasprintf("%s/%s", UDR_ALIAS_KEY, g);
            u->db->ops->del(u->db->self, UDR_GLOBAL_PART, ak, NULL, NULL);
            free(ak);
        }
    }
    for (size_t i = 0; i < g5c_json_len(new_l); i++) {
        const char *g = g5c_json_str(g5c_json_at(new_l, i));
        if (g != NULL) {
            char *ak = g5c_xasprintf("%s/%s", UDR_ALIAS_KEY, g);
            g5c_json *d = g5c_json_new_obj();
            g5c_json_set_str(d, "supi", part);
            u->db->ops->put(u->db->self, UDR_GLOBAL_PART, ak, d, NULL, NULL, NULL, NULL);
            free(ak);
        }
    }
}

static void created_reply(const g5c_req *req, g5c_resp *resp, const char *id_suffix, g5c_json *doc, int status)
{
    char *loc = g5c_req_url(req, req->path);
    if (id_suffix != NULL) {
        char *l2 = g5c_xasprintf("%s/%s", loc, id_suffix);
        free(loc);
        loc = l2;
    }
    g5c_resp_header(resp, "location", loc);
    free(loc);
    g5c_resp_json(resp, status, doc);
}

/* The UDR decides how long a subscription lives (TS 29.504 5.2.2.6.2): the consumer's expiry is a hint, never more than
 * the configured maximum, and spread a little so that subscriptions made together do not all expire together. */
static bool prepare_subscription(g5c_udr *u, const char *key, g5c_json *body, bool is_new, g5c_resp *resp)
{
    int64_t now = (int64_t)time(NULL), max = u->o.subscription_max_s ? u->o.subscription_max_s : 86400, want = now + max;
    const char *exp;
    char stamp[32];
    uint32_t r = 0;
    if (!udr_is_subscription_key(key) || !g5c_json_is(body, G5C_J_OBJECT))
        return true;
    if (is_new) {
        size_t limit = u->o.max_subscriptions ? u->o.max_subscriptions : 10000;
        if (udr_subscription_count(u, key) >= limit) {
            problem(resp, 429, "TOO_MANY_SUBSCRIPTIONS", "the repository holds the maximum number of subscriptions for this data set");
            return false;
        }
    }
    exp = g5c_json_get_str(body, "expiry");
    if (exp != NULL) {
        int64_t t = udr_parse_rfc3339(exp);
        if (t > now && t < want)
            want = t;
    }
    (void)g5c_random(&r, sizeof r);
    want -= (int64_t)((double)(want - now) * 0.05 * ((double)r / 4294967295.0));
    udr_rfc3339(want, stamp, sizeof stamp);
    g5c_json_set_str(body, "expiry", stamp);
    return true;
}

static void h_put(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const rctx *c = ctx;
    g5c_udr *u = c->u;
    char *part = NULL, *key = NULL;
    g5c_json *body, *before = NULL;
    udr_cond cond;
    udr_rec out;
    bool created = false;
    int rc;
    if (c->ext && !ext_allowed(c, req, resp))
        return;
    body = g5c_req_json(req, resp);
    if (body == NULL)
        return;
    part = partition_of(u, &c->op, req);
    key = expand_key(req, c->op.key);
    if (part == NULL || key == NULL) {
        problem(resp, 400, "MANDATORY_IE_INCORRECT", "malformed path parameter");
        goto done;
    }
    if (!body_ok(c, body, c->op.req_schema >= 0 ? c->op.req_schema : c->doc_schema, resp))
        goto done;
    if (parse_write_cond(req, &cond) != 0) {
        problem(resp, 412, "PRECONDITION_FAILED", "malformed If-Match");
        goto done;
    }
    if (!prepare_subscription(u, key, body, false, resp))
        goto done;
    /* A PUT creates the subscriber's partition when it is the first data written for it (registrations and policy data
     * can precede the subscription data). */
    {
        udr_rec old;
        rc = u->db->ops->put(u->db->self, part, key, g5c_json_dup(body), &cond, &created, &out, &old);
        if (rc == UDR_DB_OK)
            before = old.doc;
    }
    if (rc == UDR_DB_PRECONDITION) {
        g5c_counter_inc(u->c_conflict);
        problem(resp, 412, "PRECONDITION_FAILED", "the resource changed");
        goto done;
    }
    if (rc != UDR_DB_OK) {
        db_error(resp);
        goto done;
    }
    note_write(u);
    if (strcmp(key, "subscription-data/identity-data") == 0)
        sync_aliases(u, part, before, body);
    udr_notify(u, part, key, before, body, g5c_req_header(req, "3gpp-sbi-notification-correlation"));
    set_validators(u, resp, out.rev, out.mtime);
    if (u->o.put_no_content) {
        if (created) { /* the Location of what was created is still given */
            char *loc = g5c_req_url(req, req->path);
            g5c_resp_header(resp, "location", loc);
            free(loc);
        }
        g5c_resp_status(resp, 204);
    } else if (created) {
        if (c->op.ok_mask & UDR_OK_201)
            created_reply(req, resp, NULL, body, 201);
        else
            g5c_resp_status(resp, 204);
    } else if (c->op.ok_mask & UDR_OK_200) {
        g5c_resp_json(resp, 200, body);
    } else {
        g5c_resp_status(resp, 204);
    }
done:
    g5c_json_free(before);
    g5c_json_free(body);
    free(part);
    free(key);
}

static void h_post(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const rctx *c = ctx;
    g5c_udr *u = c->u;
    char *part = NULL, *key = NULL, *id = NULL, *child = NULL;
    g5c_json *body;
    char uuid[37];
    int rc;
    udr_rec out;
    body = g5c_req_json(req, resp);
    if (body == NULL)
        return;
    part = partition_of(u, &c->op, req);
    key = expand_key(req, c->op.key);
    if (part == NULL || key == NULL) {
        problem(resp, 400, "MANDATORY_IE_INCORRECT", "malformed path parameter");
        goto done;
    }
    if (!body_ok(c, body, c->op.req_schema, resp))
        goto done;
    if (is_ue_part(&c->op) && u->db->ops->part_exists(u->db->self, part) != 1) {
        not_found(u, &c->op, part, resp, "subscriber");
        goto done;
    }
    g5c_uuid_v4(uuid);
    id = g5c_xstrdup(uuid);
    child = g5c_xasprintf("%s/%s", key, id);
    if (!prepare_subscription(u, key, body, true, resp))
        goto done;
    if (key_has_suffix(key, "subs-to-notify") && g5c_json_is(body, G5C_J_OBJECT) && strncmp(key, "subscription-data/", 18) == 0)
        g5c_json_set_str(body, "subscriptionId", id);
    rc = u->db->ops->put(u->db->self, part, child, g5c_json_dup(body), NULL, NULL, &out, NULL);
    if (rc != UDR_DB_OK) {
        db_error(resp);
        goto done;
    }
    note_write(u);
    udr_notify(u, part, child, NULL, body, g5c_req_header(req, "3gpp-sbi-notification-correlation"));
    set_validators(u, resp, out.rev, out.mtime);
    created_reply(req, resp, id, body, 201);
done:
    g5c_json_free(body);
    free(part);
    free(key);
    free(id);
    free(child);
}

/* ---- PATCH ------------------------------------------------------------------------------------------------------ */

typedef struct {
    const rctx *c;
    const g5c_json *patch;
    bool merge;
} patch_arg;

static int apply_patch(g5c_json **doc, void *arg, char *err, size_t errcap)
{
    patch_arg *a = arg;
    if (a->merge)
        udr_merge_patch(doc, a->patch);
    else if (g5c_json_patch(doc, a->patch, err, errcap) != 0)
        return -1;
    if (!a->c->u->o.no_validation && a->c->doc_schema >= 0 &&
        udr_schema_validate(a->c->u->sch, a->c->doc_schema, *doc, err, errcap) != 0)
        return -1;
    return 0;
}

static void h_patch(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const rctx *c = ctx;
    g5c_udr *u = c->u;
    char *part = NULL, *key = NULL;
    g5c_json *body;
    const char *ct = g5c_req_header(req, "content-type");
    patch_arg a;
    udr_cond cond;
    udr_rec out, old;
    char err[200] = "";
    int rc;
    if (c->ext && !ext_allowed(c, req, resp))
        return;
    a.c = c;
    a.merge = ct != NULL && strncasecmp(ct, "application/merge-patch+json", 28) == 0;
    /* JSON Patch is application/json-patch+json; plain application/json is taken as JSON Patch too (the UDM's clients) */
    if (!a.merge && ct != NULL && strncasecmp(ct, "application/json", 16) != 0) {
        problem(resp, 415, "UNSUPPORTED_MEDIA_TYPE", "expected application/json-patch+json or application/merge-patch+json");
        return;
    }
    body = g5c_req_json(req, resp);
    if (body == NULL)
        return;
    a.patch = body;
    if (!a.merge && !g5c_json_is(body, G5C_J_ARRAY)) {
        problem(resp, 400, "MANDATORY_IE_INCORRECT", "a JSON Patch document is an array");
        g5c_json_free(body);
        return;
    }
    part = partition_of(u, &c->op, req);
    key = expand_key(req, c->op.key);
    if (part == NULL || key == NULL) {
        problem(resp, 400, "MANDATORY_IE_INCORRECT", "malformed path parameter");
        goto done;
    }
    if (parse_write_cond(req, &cond) != 0) {
        problem(resp, 412, "PRECONDITION_FAILED", "malformed If-Match");
        goto done;
    }
    rc = u->db->ops->mutate(u->db->self, part, key, apply_patch, &a, &cond, &out, &old, err, sizeof err);
    if (rc == UDR_DB_ABSENT) {
        not_found(u, &c->op, part, resp, "data");
    } else if (rc == UDR_DB_PRECONDITION) {
        g5c_counter_inc(u->c_conflict);
        problem(resp, 412, "PRECONDITION_FAILED", "the resource changed");
    } else if (rc == UDR_DB_REJECTED) {
        problem(resp, 400, "MODIFICATION_NOT_ALLOWED", err);
    } else if (rc != UDR_DB_OK) {
        db_error(resp);
    } else {
        note_write(u);
        udr_notify(u, part, key, old.doc, out.doc, g5c_req_header(req, "3gpp-sbi-notification-correlation"));
        set_validators(u, resp, out.rev, out.mtime);
        if (c->op.ok_mask & UDR_OK_204) {
            g5c_resp_status(resp, 204);
        } else {
            g5c_resp_json(resp, 200, out.doc);
        }
        g5c_json_free(out.doc);
        g5c_json_free(old.doc);
    }
done:
    g5c_json_free(body);
    free(part);
    free(key);
}

/* ---- DELETE ----------------------------------------------------------------------------------------------------- */

static void h_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const rctx *c = ctx;
    g5c_udr *u = c->u;
    char *part, *key;
    udr_cond cond;
    udr_rec old;
    int rc;
    if (c->ext && !ext_allowed(c, req, resp))
        return;
    part = partition_of(u, &c->op, req);
    key = expand_key(req, c->op.key);
    if (part == NULL || key == NULL) {
        problem(resp, 400, "MANDATORY_IE_INCORRECT", "malformed path parameter");
        goto done;
    }
    if (parse_write_cond(req, &cond) != 0) {
        problem(resp, 412, "PRECONDITION_FAILED", "malformed If-Match");
        goto done;
    }
    rc = u->db->ops->del(u->db->self, part, key, &cond, &old);
    if (rc == UDR_DB_ABSENT) {
        not_found(u, &c->op, part, resp, "data");
    } else if (rc == UDR_DB_PRECONDITION) {
        g5c_counter_inc(u->c_conflict);
        problem(resp, 412, "PRECONDITION_FAILED", "the resource changed");
    } else if (rc != UDR_DB_OK) {
        db_error(resp);
    } else {
        note_write(u);
        if (strcmp(key, "subscription-data/identity-data") == 0)
            sync_aliases(u, part, old.doc, NULL);
        udr_notify(u, part, key, old.doc, NULL, g5c_req_header(req, "3gpp-sbi-notification-correlation"));
        g5c_json_free(old.doc);
        g5c_resp_status(resp, 204);
    }
done:
    free(part);
    free(key);
}

/* ---- provisioning extensions ------------------------------------------------------------------------------------ */

static bool ct_equal(const char *a, const char *b)
{
    unsigned char d = 0;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb)
        return false;
    for (size_t i = 0; i < la; i++)
        d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

static bool ext_allowed(const rctx *c, const g5c_req *req, g5c_resp *resp)
{
    const g5c_udr *u = c->u;
    /* the provisioning token travels in its own header, so that Authorization stays free for the access token of the NRF; the bearer form is still accepted */
    const char *t = g5c_req_header(req, "x-g5c-provisioning-token") != NULL ? g5c_req_header(req, "x-g5c-provisioning-token") : g5c_bearer_token(req);
    if (u->token != NULL) {
        if (t == NULL) {
            problem(resp, 401, "MISSING_TOKEN", "provisioning requires a bearer token");
            g5c_resp_header(resp, "www-authenticate", "Bearer");
            return false;
        }
        if (!ct_equal(t, u->token)) {
            problem(resp, 403, "INVALID_TOKEN", "the token does not authorise provisioning");
            return false;
        }
        return true;
    }
    if (u->o.ext_open)
        return true;
    problem(resp, 403, "PROVISIONING_DISABLED", "this repository has no provisioning token configured");
    return false;
}

static void h_ids(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const rctx *c = ctx;
    g5c_json *ids;
    if (!ext_allowed(c, req, resp))
        return;
    ids = g5c_udr_ids(c->u->store);
    g5c_resp_json(resp, 200, ids);
    g5c_json_free(ids);
}

static void h_remove_sub(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const rctx *c = ctx;
    g5c_udr *u = c->u;
    const char *raw;
    char *id;
    udr_rec ident;
    if (!ext_allowed(c, req, resp))
        return;
    raw = g5c_req_param(req, "ueId");
    id = raw != NULL ? pdecode(raw) : NULL;
    if (id == NULL) {
        problem(resp, 400, "MANDATORY_IE_INCORRECT", "malformed ueId");
        return;
    }
    if (u->db->ops->get(u->db->self, id, "subscription-data/identity-data", &ident) == 1) {
        sync_aliases(u, id, ident.doc, NULL);
        g5c_json_free(ident.doc);
    }
    if (u->db->ops->del_part(u->db->self, id) == 1) {
        note_write(u);
        udr_notify(u, id, NULL, NULL, NULL, NULL);
        g5c_resp_status(resp, 204);
    } else {
        problem(resp, 404, "USER_NOT_FOUND", id);
    }
    free(id);
}

/* ---- router ------------------------------------------------------------------------------------------------------ */

static rctx *mk_ctx(g5c_udr *u, const udr_op_def *op, int doc_schema, bool ext)
{
    rctx *c = g5c_xcalloc(1, sizeof *c);
    c->u = u;
    c->op = *op;
    c->doc_schema = doc_schema;
    c->ext = ext;
    u->ctxs = g5c_xrealloc(u->ctxs, (u->nctx + 1) * sizeof *u->ctxs);
    u->ctxs[u->nctx++] = c;
    return c;
}

static bool template_has(const char *path, const char *method)
{
    for (size_t i = 0; i < udr_ops_count; i++)
        if (strcmp(udr_ops[i].path, path) == 0 && strcmp(udr_ops[i].method, method) == 0)
            return true;
    return false;
}

static bool is_composite_parent(const char *key)
{
    for (size_t i = 0; i < udr_composites_count; i++)
        if (strcmp(udr_composites[i].parent, key) == 0)
            return true;
    return false;
}

static int doc_schema_of(const char *path)
{
    int s = -1;
    for (size_t i = 0; i < udr_ops_count; i++) {
        if (strcmp(udr_ops[i].path, path) != 0)
            continue;
        if (strcmp(udr_ops[i].method, "GET") == 0 && udr_ops[i].resp_schema >= 0)
            return udr_ops[i].resp_schema;
        if ((strcmp(udr_ops[i].method, "PUT") == 0 || strcmp(udr_ops[i].method, "POST") == 0) &&
            udr_ops[i].req_schema >= 0 && s < 0)
            s = udr_ops[i].req_schema;
    }
    return s;
}

static g5c_handler handler_for(const char *method, bool post_create)
{
    if (strcmp(method, "GET") == 0)
        return h_get;
    if (strcmp(method, "PUT") == 0)
        return h_put;
    if (strcmp(method, "PATCH") == 0)
        return h_patch;
    if (strcmp(method, "DELETE") == 0)
        return h_delete;
    (void)post_create;
    return h_post;
}

static void register_ops(g5c_udr *u, g5c_router *r)
{
    for (size_t v = 0; v < sizeof ROOTS / sizeof *ROOTS; v++) {
        for (size_t i = 0; i < udr_ops_count; i++) {
            const udr_op_def *op = &udr_ops[i];
            char *tmpl = g5c_xasprintf("%s%s", ROOTS[v], op->path);
            rctx *c = mk_ctx(u, op, doc_schema_of(op->path), false);
            g5c_router_route(r, op->method, tmpl, handler_for(op->method, op->post_create), c);
            free(tmpl);
        }
        /* The resources that have a GET but no write operation are provisioned through the same URI by an extension; these routes check the provisioning token themselves
         * (G5C_ROUTE_OWN_AUTH: the access token of the NRF is not asked for). */
        for (size_t i = 0; i < udr_ops_count; i++) {
            const udr_op_def *op = &udr_ops[i];
            int ds;
            if (strcmp(op->method, "GET") != 0 || op->coll || is_composite_parent(op->key) || op->resp_schema < 0)
                continue;
            ds = doc_schema_of(op->path);
            if (!template_has(op->path, "PUT")) {
                udr_op_def x = *op;
                char *tmpl = g5c_xasprintf("%s%s", ROOTS[v], op->path);
                x.method = "PUT";
                x.req_schema = ds;
                x.ok_mask = UDR_OK_201 | UDR_OK_204;
                g5c_router_route_flags(r, "PUT", tmpl, h_put, mk_ctx(u, &x, ds, true), G5C_ROUTE_OWN_AUTH);
                free(tmpl);
            }
            if (!template_has(op->path, "DELETE")) {
                udr_op_def x = *op;
                char *tmpl = g5c_xasprintf("%s%s", ROOTS[v], op->path);
                x.method = "DELETE";
                g5c_router_route_flags(r, "DELETE", tmpl, h_delete, mk_ctx(u, &x, ds, true), G5C_ROUTE_OWN_AUTH);
                free(tmpl);
            }
        }
        {
            char *base = g5c_xasprintf("%s/subscription-data", ROOTS[v]);
            char *one = g5c_xasprintf("%s/subscription-data/{ueId}", ROOTS[v]);
            udr_op_def x;
            memset(&x, 0, sizeof x);
            x.req_schema = x.resp_schema = x.resp201_schema = -1;
            x.part = UDR_PART_UE;
            g5c_router_route_flags(r, "GET", base, h_ids, mk_ctx(u, &x, -1, true), G5C_ROUTE_OWN_AUTH);
            g5c_router_route_flags(r, "DELETE", one, h_remove_sub, mk_ctx(u, &x, -1, true), G5C_ROUTE_OWN_AUTH);
            free(base);
            free(one);
        }
    }
}

g5c_udr *udr_new(g5c_udr_store *store, const udr_opts *o)
{
    g5c_udr *u = g5c_xcalloc(1, sizeof *u);
    char err[160];
    u->store = store;
    u->db = store->db;
    if (o != NULL)
        u->o = *o;
    if (u->o.group_ids != NULL) {
        u->groups = g5c_json_dup(u->o.group_ids);
        u->o.group_ids = u->groups;
    }
    if (u->o.provisioning_token != NULL && u->o.provisioning_token[0] != '\0')
        u->token = g5c_xstrdup(u->o.provisioning_token);
    u->sch = udr_schemas_load(err, sizeof err);
    if (u->sch == NULL) {
        G5C_LOGE("g5c_udr", "the generated schema pool is unusable: %s", err);
        free(u->token);
        free(u);
        return NULL;
    }
    if (u->o.metrics == NULL) {
        u->reg = g5c_registry_new();
        u->own_reg = true;
        u->o.metrics = u->reg;
    } else {
        u->reg = u->o.metrics;
    }
    u->c_conflict = g5c_counter_get(u->reg, "g5c_udr_precondition_failures_total", "writes refused by If-Match / If-None-Match", NULL, 0);
    u->c_invalid = g5c_counter_get(u->reg, "g5c_udr_invalid_bodies_total", "bodies rejected by the 3GPP schemas", NULL, 0);
    u->c_notfound = g5c_counter_get(u->reg, "g5c_udr_not_found_total", "reads and writes of absent data", NULL, 0);
    u->g_records = g5c_gauge_get(u->reg, "g5c_udr_records", "stored documents", NULL, 0);
    u->nt = udr_notifier_new(u);
    return u;
}

void udr_free(g5c_udr *u)
{
    if (u == NULL)
        return;
    udr_notifier_free(u->nt);
    for (size_t i = 0; i < u->nallocs; i++)
        free(u->allocs[i]);
    free(u->allocs);
    g5c_json_free(u->groups);
    for (size_t i = 0; i < u->nctx; i++)
        free(u->ctxs[i]);
    free(u->ctxs);
    udr_schemas_free(u->sch);
    if (u->own_reg)
        g5c_registry_free(u->reg);
    free(u->token);
    free(u);
}

g5c_router *udr_router(g5c_udr *u)
{
    g5c_router *r = g5c_router_new();
    register_ops(u, r);
    udr_register_groupid_routes(u, r);
    return r;
}

g5c_router *g5c_udr_router_opts(g5c_udr_store *store, const udr_opts *o)
{
    if (store->svc == NULL)
        store->svc = udr_new(store, o);
    return store->svc != NULL ? udr_router(store->svc) : NULL;
}

g5c_router *g5c_udr_router(g5c_udr_store *store)
{
    udr_opts o;
    memset(&o, 0, sizeof o);
    o.ext_open = true;
    return g5c_udr_router_opts(store, &o);
}

udr_db *udr_db_get(g5c_udr *u)
{
    return u->db;
}

const udr_opts *udr_opts_get(const g5c_udr *u)
{
    return &u->o;
}

udr_notifier *udr_notifier_of(g5c_udr *u)
{
    return u->nt;
}

void udr_track_alloc(g5c_udr *u, void *p)
{
    u->allocs = g5c_xrealloc(u->allocs, (u->nallocs + 1) * sizeof *u->allocs);
    u->allocs[u->nallocs++] = p;
}
