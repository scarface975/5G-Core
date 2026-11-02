#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The forwarding of the SCP (TS 29.500 6.10): classify the request (Model C, Model D, notification), choose the producers to try, forward with the headers the
 * specification says, retry and reselect, and shape the answer (Producer-Id, Target-apiRoot, Via, Server). */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "priv.h"

#define H_TARGET "3gpp-sbi-target-apiroot"
#define H_NRF "3gpp-sbi-nrf-uri"
#define H_CALLBACK "3gpp-sbi-callback"
#define H_BINDING "3gpp-sbi-routing-binding"
#define H_PRODUCER "3gpp-sbi-producer-id"
#define H_DISC "3gpp-sbi-discovery-"

/* ---- errors made by the SCP -------------------------------------------------------------------------------------------------- */

void scp_problem(scp *s, g5c_resp *resp, int status, const char *cause, const char *detail, const char *invalid_param)
{
    char *srv = g5c_xasprintf("SCP-%s", s->cfg->name);
    if (invalid_param != NULL)
        g5c_resp_problem_invalid(resp, status, cause, invalid_param, detail != NULL ? detail : "");
    else
        g5c_resp_problem_simple(resp, status, cause, detail);
    g5c_resp_header(resp, "server", srv);
    free(srv);
    g5c_counter_inc(s->c_result[R_SCP_ERR]);
}

/* ---- headers --------------------------------------------------------------------------------------------------------------------- */

static bool hop_by_hop(const char *n)
{
    static const char *const l[] = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length", NULL};
    for (size_t i = 0; l[i] != NULL; i++)
        if (strcmp(n, l[i]) == 0)
            return true;
    return false;
}

static bool scp_only(const char *n)
{
    return strcmp(n, H_TARGET) == 0 || strcmp(n, H_NRF) == 0 || strncmp(n, H_DISC, strlen(H_DISC)) == 0;
}

typedef struct {
    g5c_kv *v;
    size_t n;
    char **owned;
    size_t nowned;
} hv_t;

static void hv_add(hv_t *h, const char *name, const char *value)
{
    h->v = g5c_xrealloc(h->v, (h->n + 1) * sizeof *h->v);
    h->v[h->n].name = name;
    h->v[h->n].value = value;
    h->n++;
}

static void hv_add_owned(hv_t *h, const char *name, char *value)
{
    h->owned = g5c_xrealloc(h->owned, (h->nowned + 1) * sizeof *h->owned);
    h->owned[h->nowned++] = value;
    hv_add(h, name, value);
}

static void hv_free(hv_t *h)
{
    for (size_t i = 0; i < h->nowned; i++)
        free(h->owned[i]);
    free(h->owned);
    free(h->v);
}

/* the query without the cache key parameter (TS 29.500 6.10.2.6) */
static char *query_without_ck(const char *q)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    for (const char *p = q; p != NULL && *p != 0;) {
        size_t n = strcspn(p, "&");
        if (!(n >= 3 && strncmp(p, "ck=", 3) == 0) && !(n == 2 && strncmp(p, "ck", 2) == 0)) {
            if (b.len > 0)
                g5c_bytes_putc(&b, '&');
            g5c_bytes_append(&b, p, n);
        }
        p += n;
        if (*p == '&')
            p++;
    }
    return g5c_bytes_take(&b, NULL);
}

/* ---- late requests (TS 29.500 6.11.2) ---------------------------------------------------------------------------------------- */

static bool request_late(const g5c_req *req)
{
    const char *ts = g5c_req_header(req, "3gpp-sbi-sender-timestamp"), *mx = g5c_req_header(req, "3gpp-sbi-max-rsp-time");
    struct tm tmv;
    const char *rest;
    double sent;
    long ms = 0;
    if (ts == NULL || mx == NULL || !g5c_is_digits(mx))
        return false;
    memset(&tmv, 0, sizeof tmv);
    rest = strptime(ts, "%a, %d %b %Y %H:%M:%S", &tmv);
    if (rest == NULL)
        return false;
    if (*rest == '.')
        ms = strtol(rest + 1, NULL, 10);
    sent = (double)timegm(&tmv) * 1000.0 + (double)ms;
    return (double)g5c_unix_millis() > sent + (double)strtol(mx, NULL, 10);
}

/* ---- one forward ------------------------------------------------------------------------------------------------------------------ */

typedef struct {
    int rc; /* 0, or a g5c_sbi_err */
    g5c_resp r;
    char err[160];
} fwd_t;

static const char *pass_headers_skip_self(const g5c_req *req, hv_t *h, const char *via_value, bool keep_discovery)
{
    const char *ctype = NULL;
    for (size_t i = 0; i < req->nheaders; i++) {
        const char *n = req->headers[i].name, *v = req->headers[i].value;
        if (hop_by_hop(n) || strcmp(n, "via") == 0)
            continue;
        if (strcmp(n, "content-type") == 0) {
            ctype = v;
            continue;
        }
        if (scp_only(n) && !(keep_discovery && strcmp(n, H_TARGET) != 0))
            continue;
        hv_add(h, n, v);
    }
    {
        const char *old = g5c_req_header(req, "via");
        char *joined = old != NULL ? g5c_xasprintf("%s, %s", old, via_value) : g5c_xstrdup(via_value);
        hv_add_owned(h, "via", joined);
    }
    return ctype;
}

static void forward(scp *s, const g5c_req *req, const char *target_root, const char *selected_root, const char *stripped, const char *query, bool to_next, fwd_t *f)
{
    hv_t h;
    char *via = g5c_xasprintf("2.0 SCP-%s", s->cfg->name), *url, *q = query != NULL ? query_without_ck(query) : NULL;
    const char *ctype;
    size_t l;
    memset(&h, 0, sizeof h);
    memset(f, 0, sizeof *f);
    ctype = pass_headers_skip_self(req, &h, via, to_next && s->cfg->next_delegates);
    if (to_next) {
        l = strlen(s->cfg->next_uri);
        while (l > 0 && s->cfg->next_uri[l - 1] == '/')
            l--;
        url = g5c_xasprintf("%.*s%s%s%s", (int)l, s->cfg->next_uri, stripped, q != NULL && q[0] != '\0' ? "?" : "", q != NULL ? q : "");
        if (selected_root != NULL)
            hv_add(&h, H_TARGET, selected_root);
    } else {
        l = strlen(target_root);
        while (l > 0 && target_root[l - 1] == '/')
            l--;
        url = g5c_xasprintf("%.*s%s%s%s", (int)l, target_root, stripped, q != NULL && q[0] != '\0' ? "?" : "", q != NULL ? q : "");
    }
    f->rc = g5c_client_request(s->client, req->method, url, h.v, h.n, ctype, req->body_len > 0 ? req->body : NULL, req->body_len, &f->r, f->err, sizeof f->err);
    free(url);
    free(q);
    free(via);
    hv_free(&h);
}

static bool idempotent(const char *m)
{
    return strcmp(m, "GET") == 0 || strcmp(m, "PUT") == 0 || strcmp(m, "DELETE") == 0 || strcmp(m, "HEAD") == 0 || strcmp(m, "OPTIONS") == 0;
}

/* ---- the answer ---------------------------------------------------------------------------------------------------------------- */

static void relay(scp *s, g5c_resp *resp, fwd_t *f, const cand_t *cand, bool by_scp, const char *requested_root)
{
    const char *ctype = g5c_resp_header_get(&f->r, "content-type");
    bool has_loc = g5c_resp_header_get(&f->r, "location") != NULL;
    char *srv;
    if (f->r.body_len > 0)
        g5c_resp_content(resp, f->r.status, ctype != NULL ? ctype : G5C_JSON_TYPE, f->r.body, f->r.body_len);
    else
        g5c_resp_status(resp, f->r.status);
    for (size_t i = 0; i < f->r.nheaders; i++) {
        const char *n = f->r.headers[i].name;
        if (hop_by_hop(n) || strcmp(n, "content-type") == 0 || strcmp(n, "date") == 0 || n[0] == ':')
            continue;
        g5c_resp_header(resp, n, f->r.headers[i].value);
    }
    if (by_scp && cand != NULL && cand->nf_id != NULL && g5c_resp_header_get(&f->r, H_PRODUCER) == NULL) {
        char *v = g5c_xasprintf("nfinst=%s", cand->nf_id);
        g5c_resp_header(resp, H_PRODUCER, v);
        free(v);
    }
    if (cand != NULL && requested_root != NULL && strcmp(cand->apiroot, requested_root) != 0 && !has_loc) {
        g5c_resp_header(resp, H_TARGET, cand->apiroot); /* TS 29.500 6.10.4: another producer than the one the request named */
    }
    if (f->r.status >= 400) {
        srv = g5c_xasprintf("SCP-%s", s->cfg->name);
        g5c_resp_header(resp, "via", srv); /* 6.10.8.3: the SCP relays this error, it did not make it */
        free(srv);
    }
    g5c_counter_inc(s->c_result[f->r.status < 300 ? R_2XX : f->r.status < 400 ? R_3XX : f->r.status < 500 ? R_4XX : R_5XX]);
}

/* ---- the request ---------------------------------------------------------------------------------------------------------------- */

static bool has_discovery_headers(const g5c_req *req)
{
    for (size_t i = 0; i < req->nheaders; i++)
        if (strncmp(req->headers[i].name, H_DISC, strlen(H_DISC)) == 0)
            return true;
    return false;
}

/* from a Routing Binding Indication: the discovery query that finds the instance or the set it names (TS 29.500 5.2.3.2.5) */
static char *binding_query(const char *rb)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    for (const char *p = rb; p != NULL && *p != 0;) {
        size_t n = strcspn(p, ";");
        const char *eq;
        while (*p == ' ')
            p++, n = n > 0 ? n - 1 : 0;
        eq = memchr(p, '=', n);
        if (eq != NULL) {
            size_t kl = (size_t)(eq - p), vl = n - kl - 1;
            if ((kl == 6 && strncmp(p, "nfinst", 6) == 0 && vl > 0 && vl < 64) || (kl == 5 && strncmp(p, "nfset", 5) == 0 && vl > 0 && vl < 128)) {
                if (b.len > 0)
                    g5c_bytes_putc(&b, '&');
                g5c_bytes_printf(&b, "%s=%.*s", kl == 6 ? "target-nf-instance-id" : "target-nf-set-id", (int)vl, eq + 1);
            }
        }
        p += n;
        if (*p == ';')
            p++;
    }
    return g5c_bytes_take(&b, NULL);
}

void scp_proxy(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    scp *s = ctx;
    const scp_cfg *cfg = s->cfg;
    double t0 = g5c_now_seconds();
    const char *target = g5c_req_header(req, H_TARGET), *ua = g5c_req_header(req, "user-agent"), *nrf_hdr = g5c_req_header(req, H_NRF), *rb = g5c_req_header(req, H_BINDING),
               *via_in = g5c_req_header(req, "via");
    bool has_disc = has_discovery_headers(req), callback = g5c_req_header(req, H_CALLBACK) != NULL, by_scp = false, reselected = false;
    cands_t list;
    char *cache_key = NULL, *requested = NULL, *stripped = NULL, detail[240], via_me[160];
    const char *cause = "UNSPECIFIED_NF_FAILURE";
    size_t path_off = 0, tried = 0;
    int model = target != NULL ? (callback ? M_CB : M_C) : (callback ? M_CB : M_D), st;
    fwd_t f;
    bool done = false;
    memset(&list, 0, sizeof list);
    if (atomic_fetch_add(&s->inflight, 1) >= cfg->max_inflight) {
        scp_problem(s, resp, 503, "NF_CONGESTION", "the SCP is handling the most requests it may", NULL);
        g5c_resp_header(resp, "retry-after", "1");
        goto out;
    }
    g5c_gauge_set(s->g_inflight, (int64_t)atomic_load(&s->inflight));
    g5c_counter_inc(s->c_model[model]);
    G5C_LOGD(SCP_LOG, "%s %s model %s%s%s discovery=%s ua=%s", req->method, req->path, model == M_C ? "C" : model == M_D ? "D" : "notification", target != NULL ? " target=" : "", target != NULL ? target : "",
             has_disc ? "yes" : "no", ua != NULL ? ua : "-");
    snprintf(via_me, sizeof via_me, "SCP-%s", cfg->name);
    if (via_in != NULL) {
        /* the Via of a request names every SCP it passed: this one twice is a loop */
        char *needle = g5c_xasprintf("2.0 %s", via_me);
        bool loop = strstr(via_in, needle) != NULL;
        free(needle);
        if (loop) {
            scp_problem(s, resp, 508, "LOOP_DETECTED", "the request has already passed this SCP", NULL);
            goto out;
        }
    }
    if (req->body_len > cfg->max_body) {
        scp_problem(s, resp, 413, "INVALID_MSG_FORMAT", "the payload is larger than the SCP processes", NULL);
        goto out;
    }
    if (request_late(req)) {
        scp_problem(s, resp, 504, "TIMED_OUT_REQUEST", "the request has timed out at its originator", NULL);
        goto out;
    }
    /* the SCP's own deployment-specific string comes off the path */
    if (cfg->prefix[0] != '\0') {
        size_t pl = strlen(cfg->prefix);
        if (strncmp(req->path, cfg->prefix, pl) != 0 || (req->path[pl] != '/' && req->path[pl] != '\0')) {
            scp_problem(s, resp, 404, "RESOURCE_NOT_FOUND", "the path does not start with the SCP's prefix", NULL);
            goto out;
        }
        path_off = pl;
    }
    stripped = g5c_xstrdup(req->path[path_off] != '\0' ? req->path + path_off : "/");
    if (strncmp(stripped, "/scp-default-sub-notify-uri", 27) == 0) {
        scp_problem(s, resp, 404, "RESOURCE_NOT_FOUND", "default notification subscriptions are not supported", NULL);
        goto out;
    }
    /* who to send it to */
    if (target != NULL) {
        if (!apiroot_ok(target)) {
            scp_problem(s, resp, 400, "MANDATORY_IE_INCORRECT", "not an apiRoot (scheme://authority[prefix])", "3gpp-Sbi-Target-apiRoot");
            goto out;
        }
        if (!target_allowed(cfg, target)) {
            scp_problem(s, resp, 403, "TARGET_NOT_ALLOWED", "the SCP does not forward to that target", "3gpp-Sbi-Target-apiRoot");
            goto out;
        }
        requested = g5c_xstrdup(target);
        cands_add(&list, target, NULL, 0, 100, 0);
    } else if (has_disc && cfg->next_uri != NULL && cfg->next_delegates) {
        /* the next hop selects: the discovery headers go with the request */
    } else if (has_disc) {
        if (!cfg->delegated) {
            scp_problem(s, resp, 400, "INVALID_DISCOVERY_PARAM", "delegated discovery is not offered by this SCP", "3gpp-Sbi-Discovery-target-nf-type");
            goto out;
        }
        by_scp = true;
        st = scp_discover(s, req, ua, nrf_hdr, NULL, &list, &cache_key, &cause, detail, sizeof detail);
        if (st != 0) {
            scp_problem(s, resp, st, cause, detail, st == 400 && strcmp(cause, "MANDATORY_IE_MISSING") == 0 ? "3gpp-Sbi-Discovery-target-nf-type" : NULL);
            goto out;
        }
        for (size_t i = 0; i < list.n; i++)
            if (!target_allowed(cfg, list.v[i].apiroot)) {
                free(list.v[i].apiroot);
                free(list.v[i].nf_id);
                memmove(&list.v[i], &list.v[i + 1], (list.n - i - 1) * sizeof *list.v);
                list.n--;
                i--;
            }
        if (list.n == 0) {
            scp_problem(s, resp, 400, "NF_DISCOVERY_FAILURE", "no producer the SCP may forward to matches the discovery factors", NULL);
            goto out;
        }
    } else {
        scp_problem(s, resp, 400, "MANDATORY_IE_MISSING", "neither the apiRoot of the target nor the discovery factors are given", "3gpp-Sbi-Target-apiRoot");
        goto out;
    }
    if (list.n == 0 && cfg->next_uri != NULL) {
        /* the next hop does the selection: one forward, with the discovery headers */
        forward(s, req, NULL, NULL, stripped, req->query, true, &f);
        if (f.rc == 0) {
            relay(s, resp, &f, NULL, false, NULL);
            g5c_resp_free(&f.r);
        } else {
            scp_report(s, "next-hop", false);
            scp_problem(s, resp, 504, "TARGET_NF_NOT_REACHABLE", "the next-hop SCP is not reachable", NULL);
        }
        goto out;
    }
    /* the candidates in turn */
    for (size_t i = 0;; i++) {
        const cand_t *cand;
        bool to_next = cfg->next_uri != NULL;
        char *auth;
        if (i >= list.n) {
            /* a producer that cannot be reached is replaced when the request says how: discovery factors or a Routing Binding Indication */
            if (!reselected && target != NULL && (has_disc || rb != NULL) && cfg->delegated) {
                char *bq = rb != NULL ? binding_query(rb) : NULL;
                cands_t more;
                reselected = true;
                if (has_disc || (bq != NULL && bq[0] != '\0')) {
                    if (scp_discover(s, req, ua, nrf_hdr, bq, &more, &cache_key, &cause, detail, sizeof detail) == 0) {
                        for (size_t k = 0; k < more.n; k++) {
                            bool seen = false;
                            for (size_t j = 0; j < list.n; j++)
                                if (strcmp(list.v[j].apiroot, more.v[k].apiroot) == 0)
                                    seen = true;
                            if (!seen && target_allowed(cfg, more.v[k].apiroot))
                                cands_add(&list, more.v[k].apiroot, more.v[k].nf_id, more.v[k].priority, more.v[k].capacity, more.v[k].load);
                        }
                        by_scp = true;
                        cands_free(&more);
                    }
                }
                free(bq);
                if (i < list.n) {
                    i--; /* the loop counts it up again: the first candidate that was added is next */
                    continue;
                }
            }
            break;
        }
        if (tried >= cfg->attempts)
            break;
        cand = &list.v[i];
        auth = authority_of(cand->apiroot);
        tried++;
        forward(s, req, cand->apiroot, cand->apiroot, stripped, req->query, to_next, &f);
        if (f.rc == 0 && !(cfg->retry_503 && f.r.status == 503 && i + 1 < list.n)) {
            scp_report(s, to_next ? "next-hop" : auth, f.r.status != 503 && f.r.status != 504);
            g5c_counter_inc(s->c_attempt[A_OK]);
            relay(s, resp, &f, cand, by_scp, requested);
            g5c_resp_free(&f.r);
            free(auth);
            done = true;
            break;
        }
        if (f.rc == 0) {
            /* 503: the producer refuses for now; the next candidate is tried, the answer is kept if there is none */
            scp_report(s, auth, false);
            g5c_counter_inc(s->c_attempt[A_RETRIED]);
            if (i + 1 >= list.n || tried >= cfg->attempts) {
                relay(s, resp, &f, cand, by_scp, requested);
                g5c_resp_free(&f.r);
                free(auth);
                done = true;
                break;
            }
            g5c_resp_free(&f.r);
            free(auth);
            continue;
        }
        /* no answer */
        scp_report(s, to_next ? "next-hop" : auth, false);
        if (cache_key != NULL)
            scp_cache_forget(s, cache_key);
        G5C_LOGW(SCP_LOG, "%s %s: %s did not answer: %s", req->method, stripped, cand->apiroot, f.err);
        free(auth);
        if (f.rc == G5C_SBI_E_TIMEOUT && !idempotent(req->method)) {
            /* the request may have been processed: it is not sent twice */
            g5c_counter_inc(s->c_attempt[A_FAILED]);
            scp_problem(s, resp, 504, "TARGET_NF_NOT_REACHABLE", "the target NF did not answer in time; the request is not repeated", NULL);
            done = true;
            break;
        }
        g5c_counter_inc(s->c_attempt[A_RETRIED]);
        if (to_next)
            break;
    }
    if (!done) {
        g5c_counter_inc(s->c_attempt[A_FAILED]);
        scp_problem(s, resp, 504, "TARGET_NF_NOT_REACHABLE", "neither the target NF nor an alternative is reachable", NULL);
    }
out:
    g5c_histogram_observe(s->h_latency, g5c_now_seconds() - t0);
    atomic_fetch_sub(&s->inflight, 1);
    cands_free(&list);
    free(cache_key);
    free(requested);
    free(stripped);
}
