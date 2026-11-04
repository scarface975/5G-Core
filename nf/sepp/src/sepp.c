/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _POSIX_C_SOURCE 200809L
/* The SEPP (see include/g5c/sepp.h).
 *
 *   sepp:
 *     public_apiroot: https://sepp.5gc.mnc001.mcc001.3gppnetwork.org   the apiRoot partners see: Location headers of answers to a partner name it (topology hiding)
 *     local_targets: [ { apiroot: "https://udm.5gc.mnc001.mcc001.3gppnetwork.org", uri: "http://127.2.0.1:7773" } ]   what a partner's target apiRoot stands for here: the function to deliver to
 *     max_body: 1048576        timeout_ms: 5000
 *     partners:
 *       - name: visited-a
 *         plmn: '26201'                        MCC and MNC of the partner network (informational: the domain and the sources decide)
 *         domain: 5gc.mnc001.mcc262.3gppnetwork.org   targets under this domain are sent to this partner
 *         uri: https://sepp.partner.example:7792      its SEPP
 *         sources: [ 192.0.2.10 ]              addresses its SEPP connects from: this is how a request from it is recognised (use sbi.tls.allowed_peers to pin its certificate too)
 *         allow_services: [ nudm-sdm, nausf-auth ]   the services it may use here ('*' for all); the first path segment of the request
 *         deny_path_contains: [ /location ]    paths it may not touch even within an allowed service
 *         rate_per_s: 100   burst: 200         token bucket for the requests it sends here
 *         supi_must_be_local: true             a SUPI in a request path must belong to the local network (a partner may ask about our subscribers, not about others)
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "g5c/sepp.h"

#define H_TARGET "3gpp-sbi-target-apiroot"
#define MAX_PARTNERS 32
#define MAX_LIST 16

typedef struct {
    char *name, *plmn, *domain, *uri;
    char *sources[MAX_LIST];
    size_t nsources;
    char *allow[MAX_LIST];
    size_t nallow;
    char *deny[MAX_LIST];
    size_t ndeny;
    double rate, burst;
    bool supi_local;
    double tokens, last; /* the bucket */
    pthread_mutex_t mu;
} partner_t;

struct sepp {
    char *name, *public_root, *local_plmn;
    struct {
        char *apiroot, *uri;
    } local[MAX_LIST];
    size_t nlocal;
    partner_t part[MAX_PARTNERS];
    size_t npart;
    size_t max_body;
    g5c_client *client;
    g5c_registry *metrics;
};

static void count(sepp *s, const char *partner, const char *dir, const char *result)
{
    g5c_label l[] = {{"partner", partner}, {"direction", dir}, {"result", result}};
    g5c_counter_inc(g5c_counter_get(s->metrics, "g5c_sepp_requests_total", "Requests handled by the SEPP, by partner, direction and result.", l, 3));
}

static void refuse(sepp *s, g5c_resp *resp, int status, const char *cause, const char *detail, const char *partner, const char *dir, const char *result)
{
    g5c_resp_problem_simple(resp, status, cause, detail);
    g5c_resp_header(resp, "server", s->name);
    count(s, partner, dir, result);
}

/* ---- configuration ---- */

static int str_list(const g5c_json *o, const char *key, char **dst, size_t *n, const char *where, char *err, size_t cap)
{
    const g5c_json *l = g5c_json_get(o, key);
    *n = 0;
    if (l == NULL)
        return 0;
    if (!g5c_json_is(l, G5C_J_ARRAY) || g5c_json_len(l) > MAX_LIST) {
        snprintf(err, cap, "invalid config: `%s.%s` must be a list of at most %d strings", where, key, MAX_LIST);
        return -1;
    }
    for (size_t i = 0; i < g5c_json_len(l); i++) {
        const char *v = g5c_json_str(g5c_json_at(l, i));
        if (v == NULL || v[0] == 0) {
            snprintf(err, cap, "invalid config: `%s.%s[%zu]` must be a non-empty string", where, key, i);
            return -1;
        }
        dst[(*n)++] = g5c_xstrdup(v);
    }
    return 0;
}

static bool uri_ok(const char *u)
{
    return u != NULL && (strncmp(u, "http://", 7) == 0 || strncmp(u, "https://", 8) == 0) && strlen(u) > 9;
}

sepp *sepp_from_config(const g5c_json *root, g5c_nf *nf, char *err, size_t errcap)
{
    static const char *const top[] = {"public_apiroot", "local_targets", "max_body", "timeout_ms", "partners", NULL};
    static const char *const pk[] = {"name", "plmn", "domain", "uri", "sources", "allow_services", "deny_path_contains", "rate_per_s", "burst", "supi_must_be_local", NULL};
    const g5c_json *blk = g5c_json_get(root, "sepp"), *pl;
    sepp *s = g5c_xcalloc(1, sizeof *s);
    int64_t v;
    s->name = g5c_xasprintf("SEPP-%s", nf->common.name);
    s->local_plmn = g5c_xasprintf("%s%s", nf->common.mcc, nf->common.mnc);
    s->max_body = 1048576;
    s->client = nf->client;
    s->metrics = nf->metrics;
    if (blk == NULL || !g5c_json_is(blk, G5C_J_OBJECT) || g5c_json_check_keys(blk, top, "sepp", err, errcap) != 0) {
        if (err[0] == 0)
            snprintf(err, errcap, "invalid config: `sepp` is required and must be a mapping");
        goto bad;
    }
    if (g5c_json_get_str(blk, "public_apiroot") != NULL) {
        if (!uri_ok(g5c_json_get_str(blk, "public_apiroot"))) {
            snprintf(err, errcap, "invalid config: `sepp.public_apiroot` must be an http(s) URI");
            goto bad;
        }
        s->public_root = g5c_xstrdup(g5c_json_get_str(blk, "public_apiroot"));
    }
    {
        const g5c_json *lt = g5c_json_get(blk, "local_targets");
        static const char *const lk[] = {"apiroot", "uri", NULL};
        if (lt != NULL && (!g5c_json_is(lt, G5C_J_ARRAY) || g5c_json_len(lt) > MAX_LIST)) {
            snprintf(err, errcap, "invalid config: `sepp.local_targets` must be a list of at most %d entries", MAX_LIST);
            goto bad;
        }
        for (size_t i = 0; lt != NULL && i < g5c_json_len(lt); i++) {
            const g5c_json *e = g5c_json_at(lt, i);
            const char *ar = g5c_json_get_str(e, "apiroot"), *u = g5c_json_get_str(e, "uri");
            if (!g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, lk, "sepp.local_targets", err, errcap) != 0 || !uri_ok(ar) || !uri_ok(u)) {
                if (err[0] == 0)
                    snprintf(err, errcap, "invalid config: `sepp.local_targets[%zu]` needs `apiroot` and `uri`, both http(s)", i);
                goto bad;
            }
            s->local[i].apiroot = g5c_xstrdup(ar);
            s->local[i].uri = g5c_xstrdup(u);
            s->nlocal = i + 1;
        }
    }
    if (g5c_json_get(blk, "max_body") != NULL) {
        if (!g5c_json_get_int(blk, "max_body", &v) || v < 1 || v > 67108864) {
            snprintf(err, errcap, "invalid config: `sepp.max_body` must be 1..=67108864");
            goto bad;
        }
        s->max_body = (size_t)v;
    }
    if (g5c_json_get(blk, "timeout_ms") != NULL) {
        if (!g5c_json_get_int(blk, "timeout_ms", &v) || v < 100 || v > 120000) {
            snprintf(err, errcap, "invalid config: `sepp.timeout_ms` must be 100..=120000");
            goto bad;
        }
        g5c_client_set_timeout(nf->client, (int)v);
    }
    pl = g5c_json_get(blk, "partners");
    if (!g5c_json_is(pl, G5C_J_ARRAY) || g5c_json_len(pl) < 1 || g5c_json_len(pl) > MAX_PARTNERS) {
        snprintf(err, errcap, "invalid config: `sepp.partners` must list 1 to %d partners", MAX_PARTNERS);
        goto bad;
    }
    for (size_t i = 0; i < g5c_json_len(pl); i++) {
        const g5c_json *e = g5c_json_at(pl, i);
        partner_t *p = &s->part[i];
        const char *nm = g5c_json_get_str(e, "name"), *plmn = g5c_json_get_str(e, "plmn"), *dom = g5c_json_get_str(e, "domain"), *uri = g5c_json_get_str(e, "uri");
        char where[48];
        snprintf(where, sizeof where, "sepp.partners[%zu]", i);
        s->npart = i + 1;
        pthread_mutex_init(&p->mu, NULL);
        if (!g5c_json_is(e, G5C_J_OBJECT) || g5c_json_check_keys(e, pk, where, err, errcap) != 0 || nm == NULL || plmn == NULL || dom == NULL || !uri_ok(uri)) {
            if (err[0] == 0)
                snprintf(err, errcap, "invalid config: `%s` needs `name`, `plmn`, `domain` and an http(s) `uri`", where);
            goto bad;
        }
        if (strlen(plmn) < 5 || strlen(plmn) > 6 || strspn(plmn, "0123456789") != strlen(plmn)) {
            snprintf(err, errcap, "invalid config: `%s.plmn` must be MCC and MNC, 5 or 6 digits", where);
            goto bad;
        }
        p->name = g5c_xstrdup(nm);
        p->plmn = g5c_xstrdup(plmn);
        p->domain = g5c_xstrdup(dom);
        p->uri = g5c_xstrdup(uri);
        if (str_list(e, "sources", p->sources, &p->nsources, where, err, errcap) != 0 || str_list(e, "allow_services", p->allow, &p->nallow, where, err, errcap) != 0 ||
            str_list(e, "deny_path_contains", p->deny, &p->ndeny, where, err, errcap) != 0)
            goto bad;
        p->rate = 100;
        p->burst = 200;
        if (g5c_json_get(e, "rate_per_s") != NULL && (!g5c_json_get_int(e, "rate_per_s", &v) || v < 1 || v > 1000000)) {
            snprintf(err, errcap, "invalid config: `%s.rate_per_s` must be 1..=1000000", where);
            goto bad;
        } else if (g5c_json_get(e, "rate_per_s") != NULL) {
            p->rate = (double)v;
            p->burst = p->rate * 2;
        }
        if (g5c_json_get(e, "burst") != NULL) {
            if (!g5c_json_get_int(e, "burst", &v) || v < 1 || v > 10000000) {
                snprintf(err, errcap, "invalid config: `%s.burst` must be 1..=10000000", where);
                goto bad;
            }
            p->burst = (double)v;
        }
        p->supi_local = true;
        (void)g5c_json_get_bool(e, "supi_must_be_local", &p->supi_local);
        p->tokens = p->burst;
    }
    for (size_t i = 0; i < s->npart; i++)
        for (size_t k = 0; k < s->part[i].nsources; k++)
            for (size_t j = 0; j < i; j++)
                for (size_t m = 0; m < s->part[j].nsources; m++)
                    if (strcmp(s->part[i].sources[k], s->part[j].sources[m]) == 0) {
                        snprintf(err, errcap, "invalid config: partners `%s` and `%s` both list the source address %s: a request could not be told apart", s->part[j].name, s->part[i].name, s->part[i].sources[k]);
                        goto bad;
                    }
    return s;
bad:
    sepp_destroy(s);
    return NULL;
}

void sepp_destroy(sepp *s)
{
    if (s == NULL)
        return;
    for (size_t i = 0; i < s->nlocal; i++) {
        free(s->local[i].apiroot);
        free(s->local[i].uri);
    }
    for (size_t i = 0; i < s->npart; i++) {
        partner_t *p = &s->part[i];
        free(p->name);
        free(p->plmn);
        free(p->domain);
        free(p->uri);
        for (size_t k = 0; k < p->nsources; k++)
            free(p->sources[k]);
        for (size_t k = 0; k < p->nallow; k++)
            free(p->allow[k]);
        for (size_t k = 0; k < p->ndeny; k++)
            free(p->deny[k]);
        pthread_mutex_destroy(&p->mu);
    }
    free(s->name);
    free(s->public_root);
    free(s->local_plmn);
    free(s);
}

size_t sepp_partner_count(const sepp *s)
{
    return s->npart;
}

/* ---- the request ---- */

/* host (without port) of an apiRoot: "https://udm.5gc.mnc001.mcc262.3gppnetwork.org:8443/prefix" */
static size_t host_of(const char *root, const char **start)
{
    const char *p = strstr(root, "://");
    size_t n = 0;
    p = p != NULL ? p + 3 : root;
    *start = p;
    while (p[n] != 0 && p[n] != ':' && p[n] != '/')
        n++;
    return n;
}

static bool domain_match(const char *host, size_t hl, const char *domain)
{
    size_t dl = strlen(domain);
    if (hl < dl)
        return false;
    if (strncasecmp(host + hl - dl, domain, dl) != 0)
        return false;
    return hl == dl || host[hl - dl - 1] == '.';
}

static bool bucket_take(partner_t *p)
{
    struct timespec ts;
    double now;
    bool ok;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    now = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
    pthread_mutex_lock(&p->mu);
    if (p->last != 0) {
        p->tokens += (now - p->last) * p->rate;
        if (p->tokens > p->burst)
            p->tokens = p->burst;
    }
    p->last = now;
    ok = p->tokens >= 1.0;
    if (ok)
        p->tokens -= 1.0;
    pthread_mutex_unlock(&p->mu);
    return ok;
}

static bool hop_by_hop(const char *n)
{
    static const char *const l[] = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
                                    "content-type", H_TARGET, "via", NULL};
    for (size_t i = 0; l[i] != NULL; i++)
        if (strcmp(n, l[i]) == 0)
            return true;
    return n[0] == ':';
}

/* the service of a path: its first segment ("/nudm-sdm/v2/..." -> "nudm-sdm") */
static void service_of(const char *path, char *out, size_t cap)
{
    const char *p = path[0] == '/' ? path + 1 : path;
    size_t n = strcspn(p, "/");
    snprintf(out, cap, "%.*s", (int)(n < cap - 1 ? n : cap - 1), p);
}

/* A SUPI (imsi-<digits>) in the path: does it belong to the PLMN `plmn` (5 or 6 digits)? false when there is one that does not. */
static bool supi_plmn_ok(const char *path, const char *plmn)
{
    const char *p = path;
    size_t pl = strlen(plmn);
    while ((p = strstr(p, "imsi-")) != NULL) {
        p += 5;
        if (strncmp(p, plmn, pl) != 0)
            return false;
    }
    return true;
}

static void relay(sepp *s, g5c_resp *resp, const g5c_resp *r, bool hide, const char *local_root)
{
    const char *ctype = g5c_resp_header_get(r, "content-type");
    if (r->body_len > 0)
        g5c_resp_content(resp, r->status, ctype != NULL ? ctype : G5C_JSON_TYPE, r->body, r->body_len);
    else
        g5c_resp_status(resp, r->status);
    for (size_t i = 0; i < r->nheaders; i++) {
        const char *n = r->headers[i].name, *val = r->headers[i].value;
        if (hop_by_hop(n) || strcmp(n, "date") == 0)
            continue;
        if (hide && strcmp(n, "location") == 0 && local_root != NULL && strncmp(val, local_root, strlen(local_root)) == 0 && s->public_root != NULL) {
            char *loc = g5c_xasprintf("%s%s", s->public_root, val + strlen(local_root)); /* topology hiding: the partner sees this SEPP, not the function */
            g5c_resp_header(resp, n, loc);
            free(loc);
            continue;
        }
        g5c_resp_header(resp, n, val);
    }
    g5c_resp_header(resp, "via", s->name);
}

static void sepp_proxy(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    sepp *s = ctx;
    const char *target = g5c_req_header(req, H_TARGET), *hs;
    partner_t *out = NULL, *in = NULL;
    char service[64], *url = NULL, *q = NULL;
    const char *via_in;
    const char *dir, *pname;
    size_t hl;
    g5c_kv *hv = NULL;
    size_t nh = 0, cap;
    const char *ctype = g5c_req_header(req, "content-type");
    char *base = NULL, *via_out = NULL;
    g5c_resp r;
    char err[160];
    int rc;
    if (target == NULL || !uri_ok(target)) {
        refuse(s, resp, 400, "MANDATORY_IE_INCORRECT", "3gpp-Sbi-Target-apiRoot is required and must be an apiRoot", "-", "-", "bad_request");
        return;
    }
    if (req->body_len > s->max_body) {
        refuse(s, resp, 413, "INVALID_MSG_FORMAT", "the payload is larger than the SEPP forwards", "-", "-", "too_large");
        return;
    }
    via_in = g5c_req_header(req, "via");
    if (via_in != NULL && strstr(via_in, s->name) != NULL) {
        refuse(s, resp, 508, "LOOP_DETECTED", "the request has already passed this SEPP", "-", "-", "loop");
        return;
    }
    hl = host_of(target, &hs);
    for (size_t i = 0; i < s->npart && out == NULL; i++)
        if (domain_match(hs, hl, s->part[i].domain))
            out = &s->part[i];
    service_of(req->path, service, sizeof service);
    if (out != NULL) { /* a local function asks a partner network */
        dir = "outbound";
        pname = out->name;
        if (out->nallow > 0) { /* the services this SEPP lets through to the partner, by the same list that screens the partner's requests here */
            bool ok = false;
            for (size_t i = 0; i < out->nallow && !ok; i++)
                ok = strcmp(out->allow[i], "*") == 0 || strcmp(out->allow[i], service) == 0;
            if (!ok) {
                refuse(s, resp, 403, "SERVICE_NOT_ALLOWED", "that service is not offered to this partner network", pname, dir, "denied_service");
                return;
            }
        }
        base = g5c_xstrdup(out->uri);
    } else { /* a partner SEPP asks a local function */
        bool local_ok = false;
        dir = "inbound";
        /* TS 29.573 5.3.3: with TLS between the SEPPs the peer is known by the connection it comes on (the certificate, pinned with sbi.tls.allowed_peers, and the address); there is no header
         * that names the originating network. The partner is the one whose `sources` hold the address the request came from. */
        for (size_t i = 0; i < s->npart && in == NULL; i++)
            for (size_t k = 0; k < s->part[i].nsources && in == NULL; k++)
                if (strcmp(s->part[i].sources[k], req->peer) == 0)
                    in = &s->part[i];
        if (in == NULL) {
            refuse(s, resp, 403, "UNKNOWN_PARTNER", "no roaming relation with the address the request comes from", "-", dir, "unknown_partner");
            return;
        }
        pname = in->name;
        for (size_t i = 0; i < s->nlocal && !local_ok; i++) {
            size_t l = strlen(s->local[i].apiroot);
            local_ok = strncasecmp(target, s->local[i].apiroot, l) == 0 && (target[l] == 0 || target[l] == '/');
            if (local_ok)
                base = g5c_xstrdup(s->local[i].uri);
        }
        if (!local_ok) {
            refuse(s, resp, 403, "TARGET_NOT_ALLOWED", "this SEPP does not deliver to that target", pname, dir, "denied_target");
            return;
        }
        {
            bool ok = false;
            for (size_t i = 0; i < in->nallow && !ok; i++)
                ok = strcmp(in->allow[i], "*") == 0 || strcmp(in->allow[i], service) == 0;
            if (!ok) {
                refuse(s, resp, 403, "SERVICE_NOT_ALLOWED", "that service is not open to the partner network", pname, dir, "denied_service");
                free(base);
                return;
            }
        }
        for (size_t i = 0; i < in->ndeny; i++)
            if (strstr(req->path, in->deny[i]) != NULL) {
                refuse(s, resp, 403, "PATH_NOT_ALLOWED", "the partner may not use that resource", pname, dir, "denied_path");
                free(base);
                return;
            }
        if (in->supi_local && !supi_plmn_ok(req->path, s->local_plmn)) {
            refuse(s, resp, 403, "IDENTITY_NOT_ALLOWED", "the request names a subscriber of another network", pname, dir, "denied_identity");
            free(base);
            return;
        }
        if (!bucket_take(in)) {
            refuse(s, resp, 429, "TOO_MANY_REQUESTS", "the partner network sends more requests than its policy allows", pname, dir, "rate_limited");
            g5c_resp_header(resp, "retry-after", "1");
            free(base);
            return;
        }
    }
    if (out != NULL && !bucket_take(out)) {
        refuse(s, resp, 429, "TOO_MANY_REQUESTS", "the requests to this partner network exceed the policy", pname, dir, "rate_limited");
        g5c_resp_header(resp, "retry-after", "1");
        free(base);
        return;
    }
    /* forward */
    {
        size_t bl = strlen(base);
        while (bl > 0 && base[bl - 1] == '/')
            bl--;
        q = req->query != NULL && req->query[0] != 0 ? g5c_xasprintf("?%s", req->query) : g5c_xstrdup("");
        url = g5c_xasprintf("%.*s%s%s", (int)bl, base, req->path, q);
    }
    cap = req->nheaders + 3;
    hv = g5c_xcalloc(cap, sizeof *hv);
    for (size_t i = 0; i < req->nheaders; i++)
        if (!hop_by_hop(req->headers[i].name))
            hv[nh++] = (g5c_kv){req->headers[i].name, req->headers[i].value};
    if (out != NULL) { /* to a partner SEPP: the target apiRoot goes in the header (TS 29.573 C.2.1.3), the request URI is the partner SEPP's */
        hv[nh++] = (g5c_kv){H_TARGET, target};
    }
    via_out = via_in != NULL ? g5c_xasprintf("%s, %s", via_in, s->name) : g5c_xstrdup(s->name); /* every SEPP the request passed */
    hv[nh++] = (g5c_kv){"via", via_out};
    memset(&r, 0, sizeof r);
    rc = g5c_client_request(s->client, req->method, url, hv, nh, ctype, req->body_len > 0 ? req->body : NULL, req->body_len, &r, err, sizeof err);
    if (rc == G5C_SBI_E_OVERLOAD) { /* the next SEPP or the function asked its consumers to back off (TS 29.500 6.4): the consumer is told the same */
        refuse(s, resp, 429, "TOO_MANY_REQUESTS", "the target asked its consumers to back off", pname, dir, "backed_off");
        g5c_resp_header(resp, "retry-after", "1");
    } else if (rc != 0) {
        refuse(s, resp, 504, "TARGET_NF_NOT_REACHABLE", out != NULL ? "the partner network's SEPP did not answer" : "the local target did not answer", pname, dir, "unreachable");
    } else {
        relay(s, resp, &r, in != NULL, base);
        count(s, pname, dir, "forwarded");
        g5c_resp_free(&r);
    }
    free(hv);
    free(via_out);
    free(url);
    free(q);
    free(base);
}

g5c_router *sepp_router(sepp *s)
{
    g5c_router *r = g5c_router_new();
    g5c_router_set_fallback(r, sepp_proxy, s);
    return r;
}
