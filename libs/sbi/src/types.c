/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Request/response types, ProblemDetails, path-template router, bearer guard. */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "g5c/sbi.h"

/* ---- helpers ---- */

static char *lower_dup(const char *s)
{
    char *d = g5c_xstrdup(s);
    for (char *p = d; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    return d;
}

static void headers_free(g5c_header *h, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free(h[i].name);
        free(h[i].value);
    }
    free(h);
}

static const char *headers_get(const g5c_header *h, size_t n, const char *name)
{
    for (size_t i = 0; i < n; i++)
        if (strcasecmp(h[i].name, name) == 0)
            return h[i].value;
    return NULL;
}

static void set_body(uint8_t **dst, size_t *len, const void *p, size_t n)
{
    free(*dst);
    *dst = g5c_xmalloc(n + 1);
    if (n)
        memcpy(*dst, p, n);
    (*dst)[n] = 0;
    *len = n;
}

/* ---- request ---- */

/* "Timestamp: ...; Load-Metric: 35%; ..." -> the number after the named parameter */
static bool param_num(const char *v, const char *name, unsigned *out)
{
    const char *p = strstr(v, name);
    char *e;
    unsigned long n;
    if (p == NULL)
        return false;
    p += strlen(name);
    while (*p == ' ' || *p == ':')
        p++;
    n = strtoul(p, &e, 10);
    if (e == p || n > 100000)
        return false;
    *out = (unsigned)n;
    return true;
}

bool g5c_sbi_parse_lci(const char *value, unsigned *load_pct)
{
    return value != NULL && param_num(value, "Load-Metric", load_pct) && *load_pct <= 100;
}

bool g5c_sbi_parse_oci(const char *value, unsigned *validity_s, unsigned *reduction_pct)
{
    return value != NULL && param_num(value, "Period-of-Validity", validity_s) && param_num(value, "Overload-Reduction-Metric", reduction_pct) && *reduction_pct <= 100;
}

void g5c_req_init(g5c_req *r)
{
    memset(r, 0, sizeof *r);
}

void g5c_req_free(g5c_req *r)
{
    free(r->method);
    free(r->path);
    free(r->query);
    free(r->scheme);
    free(r->authority);
    headers_free(r->headers, r->nheaders);
    for (size_t i = 0; i < r->nparams; i++) {
        free(r->params[i].name);
        free(r->params[i].value);
    }
    free(r->params);
    free(r->body);
    memset(r, 0, sizeof *r);
}

void g5c_req_add_header(g5c_req *r, const char *name, const char *value)
{
    r->headers = g5c_xrealloc(r->headers, (r->nheaders + 1) * sizeof *r->headers);
    r->headers[r->nheaders].name = lower_dup(name);
    r->headers[r->nheaders].value = g5c_xstrdup(value);
    r->nheaders++;
}

void g5c_req_set_body(g5c_req *r, const void *p, size_t n)
{
    set_body(&r->body, &r->body_len, p, n);
}

const char *g5c_req_header(const g5c_req *r, const char *name)
{
    return headers_get(r->headers, r->nheaders, name);
}

const char *g5c_req_param(const g5c_req *r, const char *name)
{
    for (size_t i = 0; i < r->nparams; i++)
        if (strcmp(r->params[i].name, name) == 0)
            return r->params[i].value;
    return NULL;
}

char *g5c_req_query(const g5c_req *r, const char *name)
{
    const char *q = r->query, *end;
    size_t nl = strlen(name);
    if (q == NULL)
        return NULL;
    while (*q) {
        end = strchr(q, '&');
        if (end == NULL)
            end = q + strlen(q);
        if ((size_t)(end - q) >= nl && strncmp(q, name, nl) == 0 && (q[nl] == '=' || q + nl == end))
            return q[nl] == '=' && q + nl < end ? g5c_xstrndup(q + nl + 1, (size_t)(end - q) - nl - 1)
                                                : g5c_xstrdup("");
        q = *end ? end + 1 : end;
    }
    return NULL;
}

char *g5c_req_query_decoded(const g5c_req *r, const char *name)
{
    char *raw = g5c_req_query(r, name), *dec;
    if (raw == NULL)
        return NULL;
    dec = g5c_percent_decode(raw);
    free(raw);
    return dec;
}

char *g5c_req_url(const g5c_req *r, const char *path)
{
    return g5c_xasprintf("%s://%s%s", r->scheme ? r->scheme : "http", r->authority ? r->authority : "", path);
}

g5c_json *g5c_req_json(const g5c_req *r, g5c_resp *err)
{
    char e[160];
    g5c_json *j = g5c_json_parse((const char *)r->body, r->body_len, e, sizeof e);
    if (j == NULL)
        g5c_resp_problem_simple(err, 400, "MANDATORY_IE_INCORRECT", e);
    return j;
}

/* ---- response ---- */

void g5c_resp_init(g5c_resp *r)
{
    memset(r, 0, sizeof *r);
    r->status = 200;
}

void g5c_resp_free(g5c_resp *r)
{
    headers_free(r->headers, r->nheaders);
    free(r->body);
    memset(r, 0, sizeof *r);
}

void g5c_resp_status(g5c_resp *r, int code)
{
    r->status = (code >= 100 && code <= 599) ? code : 500;
}

void g5c_resp_header(g5c_resp *r, const char *name, const char *value)
{
    char *ln = lower_dup(name);
    for (size_t i = 0; i < r->nheaders; i++) {
        if (strcmp(r->headers[i].name, ln) == 0) {
            free(r->headers[i].value);
            r->headers[i].value = g5c_xstrdup(value);
            free(ln);
            return;
        }
    }
    r->headers = g5c_xrealloc(r->headers, (r->nheaders + 1) * sizeof *r->headers);
    r->headers[r->nheaders].name = ln;
    r->headers[r->nheaders].value = g5c_xstrdup(value);
    r->nheaders++;
}

const char *g5c_resp_header_get(const g5c_resp *r, const char *name)
{
    return headers_get(r->headers, r->nheaders, name);
}

void g5c_resp_content(g5c_resp *r, int code, const char *ctype, const void *body, size_t n)
{
    g5c_resp_status(r, code);
    g5c_resp_header(r, "content-type", ctype);
    set_body(&r->body, &r->body_len, body, n);
}

void g5c_resp_json(g5c_resp *r, int code, const g5c_json *j)
{
    size_t n = 0;
    char *s = g5c_json_to_string(j, &n);
    if (s == NULL) {
        g5c_resp_problem_simple(r, 500, "SYSTEM_FAILURE", "cannot serialise response");
        return;
    }
    g5c_resp_content(r, code, G5C_JSON_TYPE, s, n);
    free(s);
}

g5c_json *g5c_resp_parse_json(const g5c_resp *r)
{
    return g5c_json_parse((const char *)r->body, r->body_len, NULL, 0);
}

/* ---- ProblemDetails ---- */

static const char *reason_phrase(int status)
{
    switch (status) {
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 412: return "Precondition Failed";
    case 413: return "Content Too Large";
    case 415: return "Unsupported Media Type";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default: return NULL;
    }
}

void g5c_resp_problem(g5c_resp *r, const g5c_problem *p)
{
    g5c_json *o = g5c_json_new_obj();
    int status = p->status ? p->status : 500;
    size_t n = 0;
    char *s;
    const char *title = p->title != NULL ? p->title : reason_phrase(status);
    if (p->type)
        g5c_json_set_str(o, "type", p->type);
    if (title)
        g5c_json_set_str(o, "title", title);
    g5c_json_set_int(o, "status", status);
    if (p->detail)
        g5c_json_set_str(o, "detail", p->detail);
    if (p->instance)
        g5c_json_set_str(o, "instance", p->instance);
    if (p->cause)
        g5c_json_set_str(o, "cause", p->cause);
    if (p->invalid_param) {
        g5c_json *arr = g5c_json_set(o, "invalidParams", g5c_json_new_arr());
        g5c_json *e = g5c_json_push(arr, g5c_json_new_obj());
        g5c_json_set_str(e, "param", p->invalid_param);
        if (p->invalid_reason)
            g5c_json_set_str(e, "reason", p->invalid_reason);
    }
    s = g5c_json_to_string(o, &n);
    g5c_json_free(o);
    g5c_resp_content(r, status, G5C_PROBLEM_TYPE, s ? s : "{}", s ? n : 2);
    free(s);
}

void g5c_resp_problem_simple(g5c_resp *r, int status, const char *cause, const char *detail)
{
    g5c_problem p = {0};
    p.status = status;
    p.cause = cause;
    p.detail = detail;
    g5c_resp_problem(r, &p);
}

void g5c_resp_problem_invalid(g5c_resp *r, int status, const char *cause, const char *param, const char *reason)
{
    g5c_problem p = {0};
    p.status = status;
    p.cause = cause;
    p.invalid_param = param;
    p.invalid_reason = reason;
    g5c_resp_problem(r, &p);
}

char *g5c_resp_problem_cause(const g5c_resp *r)
{
    g5c_json *j = g5c_resp_parse_json(r);
    const char *c = g5c_json_get_str(j, "cause");
    char *out = c ? g5c_xstrdup(c) : NULL;
    g5c_json_free(j);
    return out;
}

/* ---- router ---- */

typedef struct {
    char *name; /* NULL for a literal */
    char *lit;
} seg_t;

typedef struct {
    char *method, *tmpl;
    seg_t *segs;
    size_t nsegs;
    g5c_handler h;
    void *ctx;
    unsigned flags;
} route_t;

struct g5c_router {
    route_t *routes;
    size_t n, cap;
    g5c_guard_fn guard;
    void *guard_ctx;
    g5c_observer_fn obs;
    void *obs_ctx;
    g5c_handler fallback;
    void *fallback_ctx;
};

size_t g5c_router_count(const g5c_router *r)
{
    return r->n;
}

bool g5c_router_route_at(const g5c_router *r, size_t i, const char **method, const char **tmpl)
{
    if (i >= r->n)
        return false;
    *method = r->routes[i].method;
    *tmpl = r->routes[i].tmpl;
    return true;
}

g5c_router *g5c_router_new(void)
{
    return g5c_xcalloc(1, sizeof(g5c_router));
}

static void route_free(route_t *r)
{
    for (size_t i = 0; i < r->nsegs; i++) {
        free(r->segs[i].name);
        free(r->segs[i].lit);
    }
    free(r->segs);
    free(r->method);
    free(r->tmpl);
}

void g5c_router_free(g5c_router *r)
{
    if (r == NULL)
        return;
    for (size_t i = 0; i < r->n; i++)
        route_free(&r->routes[i]);
    free(r->routes);
    free(r);
}

/* Split a path into non-empty segments; returns count. Segments point into a heap copy returned in *buf. */
static size_t split_path(const char *path, char **buf, char ***parts)
{
    char *copy = g5c_xstrdup(path), *p = copy;
    size_t n = 0, cap = 8;
    char **v = g5c_xcalloc(cap, sizeof *v);
    while (*p) {
        char *e;
        while (*p == '/')
            p++;
        if (!*p)
            break;
        e = strchr(p, '/');
        if (n == cap) {
            cap *= 2;
            v = g5c_xrealloc(v, cap * sizeof *v);
        }
        v[n++] = p;
        if (e == NULL)
            break;
        *e = '\0';
        p = e + 1;
    }
    *buf = copy;
    *parts = v;
    return n;
}

void g5c_router_route_flags(g5c_router *r, const char *method, const char *tmpl, g5c_handler h, void *ctx, unsigned flags)
{
    char *buf, **parts;
    size_t n = split_path(tmpl, &buf, &parts);
    route_t *rt;
    if (r->n == r->cap) {
        r->cap = r->cap ? r->cap * 2 : 16;
        r->routes = g5c_xrealloc(r->routes, r->cap * sizeof *r->routes);
    }
    rt = &r->routes[r->n++];
    memset(rt, 0, sizeof *rt);
    rt->method = g5c_xstrdup(method);
    rt->tmpl = g5c_xstrdup(tmpl);
    rt->segs = g5c_xcalloc(n ? n : 1, sizeof *rt->segs);
    rt->nsegs = n;
    rt->h = h;
    rt->ctx = ctx;
    rt->flags = flags;
    for (size_t i = 0; i < n; i++) {
        size_t l = strlen(parts[i]);
        if (l >= 2 && parts[i][0] == '{' && parts[i][l - 1] == '}')
            rt->segs[i].name = g5c_xstrndup(parts[i] + 1, l - 2);
        else
            rt->segs[i].lit = g5c_xstrdup(parts[i]);
    }
    free(parts);
    free(buf);
}

void g5c_router_route(g5c_router *r, const char *method, const char *tmpl, g5c_handler h, void *ctx)
{
    g5c_router_route_flags(r, method, tmpl, h, ctx, 0);
}

unsigned g5c_router_flags_of(const g5c_router *r, const char *method, const char *path)
{
    char *buf, **parts;
    size_t np = split_path(path, &buf, &parts);
    unsigned flags = 0;
    for (size_t i = 0; i < r->n; i++) {
        const route_t *rt = &r->routes[i];
        bool match = rt->nsegs == np && strcmp(rt->method, method) == 0;
        for (size_t s = 0; match && s < np; s++)
            if (rt->segs[s].lit != NULL && strcmp(rt->segs[s].lit, parts[s]) != 0)
                match = false;
        if (match) {
            flags = rt->flags;
            break;
        }
    }
    free(parts);
    free(buf);
    return flags;
}

void g5c_router_merge(g5c_router *r, g5c_router *other)
{
    for (size_t i = 0; i < other->n; i++) {
        if (r->n == r->cap) {
            r->cap = r->cap ? r->cap * 2 : 16;
            r->routes = g5c_xrealloc(r->routes, r->cap * sizeof *r->routes);
        }
        r->routes[r->n++] = other->routes[i]; /* ownership moves */
    }
    if (r->fallback == NULL && other->fallback != NULL) {
        r->fallback = other->fallback;
        r->fallback_ctx = other->fallback_ctx;
    }
    free(other->routes);
    free(other);
}

void g5c_router_set_fallback(g5c_router *r, g5c_handler h, void *ctx)
{
    r->fallback = h;
    r->fallback_ctx = ctx;
}

void g5c_router_set_guard(g5c_router *r, g5c_guard_fn g, void *ctx)
{
    r->guard = g;
    r->guard_ctx = ctx;
}

void g5c_router_get_guard(const g5c_router *r, g5c_guard_fn *g, void **ctx)
{
    *g = r->guard;
    *ctx = r->guard_ctx;
}

void g5c_router_set_observer(g5c_router *r, g5c_observer_fn o, void *ctx)
{
    r->obs = o;
    r->obs_ctx = ctx;
}

static void params_clear(g5c_req *req)
{
    for (size_t i = 0; i < req->nparams; i++) {
        free(req->params[i].name);
        free(req->params[i].value);
    }
    free(req->params);
    req->params = NULL;
    req->nparams = 0;
}

void g5c_router_dispatch(const g5c_router *r, g5c_req *req, g5c_resp *resp)
{
    double t0 = g5c_now_seconds();
    const char *tmpl = "unmatched";
    char *buf, **parts;
    size_t np;
    char allow[256] = "";
    bool handled = false;

    if (r->guard != NULL && r->guard(r->guard_ctx, req, resp) != 0)
        goto done;
    np = split_path(req->path, &buf, &parts);
    for (size_t i = 0; i < r->n && !handled; i++) {
        const route_t *rt = &r->routes[i];
        bool match = rt->nsegs == np;
        for (size_t s = 0; match && s < np; s++)
            if (rt->segs[s].lit != NULL && strcmp(rt->segs[s].lit, parts[s]) != 0)
                match = false;
        if (!match)
            continue;
        if (strcmp(rt->method, req->method) == 0) {
            params_clear(req);
            for (size_t s = 0; s < np; s++) {
                if (rt->segs[s].name == NULL)
                    continue;
                req->params = g5c_xrealloc(req->params, (req->nparams + 1) * sizeof *req->params);
                req->params[req->nparams].name = g5c_xstrdup(rt->segs[s].name);
                req->params[req->nparams].value = g5c_xstrdup(parts[s]);
                req->nparams++;
            }
            tmpl = rt->tmpl;
            rt->h(rt->ctx, req, resp);
            handled = true;
        } else {
            size_t l = strlen(allow);
            if (strstr(allow, rt->method) == NULL && l + strlen(rt->method) + 3 < sizeof allow)
                snprintf(allow + l, sizeof allow - l, "%s%s", l ? ", " : "", rt->method);
        }
    }
    free(parts);
    free(buf);
    if (!handled && r->fallback != NULL) {
        params_clear(req);
        tmpl = "fallback";
        r->fallback(r->fallback_ctx, req, resp);
        handled = true;
    }
    if (!handled) {
        if (allow[0] == '\0') {
            char *d = g5c_xasprintf("no route for %s", req->path);
            g5c_resp_problem_simple(resp, 404, "RESOURCE_NOT_FOUND", d);
            free(d);
        } else {
            char *d = g5c_xasprintf("%s not allowed", req->method);
            g5c_resp_problem_simple(resp, 405, "METHOD_NOT_ALLOWED", d);
            g5c_resp_header(resp, "allow", allow);
            free(d);
        }
        G5C_LOGW("g5c_sbi", "%s %s matched no route -> %d", req->method, req->path, resp->status);
    }
done:
    G5C_LOGD("g5c_sbi", "%s %s%s%s -> %d", req->method, req->path, req->query != NULL ? "?" : "", req->query != NULL ? req->query : "", resp->status);
    if (r->obs != NULL)
        r->obs(r->obs_ctx, req->method, tmpl, resp->status, g5c_now_seconds() - t0);
}

/* ---- bearer guard ---- */

const char *g5c_bearer_token(const g5c_req *r)
{
    const char *v = g5c_req_header(r, "authorization");
    if (v == NULL || strncmp(v, "Bearer ", 7) != 0)
        return NULL;
    v += 7;
    while (*v == ' ')
        v++;
    return *v ? v : NULL;
}

int g5c_bearer_guard(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const g5c_bearer_cfg *cfg = ctx;
    const char *t = g5c_bearer_token(req);
    if (t != NULL && cfg->verify(cfg->user, t))
        return 0;
    g5c_resp_problem_simple(resp, 401, t ? "INVALID_TOKEN" : "MISSING_TOKEN", NULL);
    g5c_resp_header(resp, "www-authenticate", "Bearer");
    return 1;
}
