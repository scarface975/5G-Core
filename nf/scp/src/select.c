#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The SCP's choice of the producer: discovery at the NRF on behalf of the consumer (TS 29.500 6.10.3), the cache of the answers, the order in which the
 * candidates are tried (priority, then weighted by capacity and load), and the health of the producers (a producer that fails is left alone for a while). */
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "priv.h"

/* ---- candidates ------------------------------------------------------------------------------------------------------------- */

void cands_free(cands_t *c)
{
    for (size_t i = 0; i < c->n; i++) {
        free(c->v[i].apiroot);
        free(c->v[i].nf_id);
    }
    free(c->v);
    memset(c, 0, sizeof *c);
}

void cands_add(cands_t *c, const char *apiroot, const char *nf_id, int priority, unsigned capacity, unsigned load)
{
    cand_t *e;
    if (c->n == c->cap) {
        c->cap = c->cap == 0 ? 8 : c->cap * 2;
        c->v = g5c_xrealloc(c->v, c->cap * sizeof *c->v);
    }
    e = &c->v[c->n++];
    e->apiroot = g5c_xstrdup(apiroot);
    e->nf_id = nf_id != NULL ? g5c_xstrdup(nf_id) : NULL;
    e->priority = priority;
    e->capacity = capacity;
    e->load = load;
}

static cands_t cands_copy(const cands_t *c)
{
    cands_t o;
    memset(&o, 0, sizeof o);
    for (size_t i = 0; i < c->n; i++)
        cands_add(&o, c->v[i].apiroot, c->v[i].nf_id, c->v[i].priority, c->v[i].capacity, c->v[i].load);
    return o;
}

/* ---- URIs ---------------------------------------------------------------------------------------------------------------------- */

bool apiroot_ok(const char *s)
{
    const char *a, *end;
    if (s == NULL)
        return false;
    if (strncasecmp(s, "http://", 7) == 0)
        a = s + 7;
    else if (strncasecmp(s, "https://", 8) == 0)
        a = s + 8;
    else
        return false;
    end = a + strcspn(a, "/?#");
    if (end == a || memchr(a, '@', (size_t)(end - a)) != NULL || strlen(s) > 512)
        return false;
    for (const char *p = s; *p != 0; p++)
        if ((unsigned char)*p <= 0x20 || (unsigned char)*p == 0x7f || *p == '?' || *p == '#')
            return false;
    return true;
}

char *authority_of(const char *apiroot)
{
    const char *a = strstr(apiroot, "://");
    size_t n;
    if (a == NULL)
        return g5c_xstrdup("");
    a += 3;
    n = strcspn(a, "/?#");
    return g5c_xstrndup(a, n);
}

static char *host_of_authority(const char *auth)
{
    if (auth[0] == '[') {
        const char *rb = strchr(auth, ']');
        return rb != NULL ? g5c_xstrndup(auth + 1, (size_t)(rb - auth - 1)) : g5c_xstrdup(auth);
    } else {
        const char *c = strrchr(auth, ':');
        return c != NULL ? g5c_xstrndup(auth, (size_t)(c - auth)) : g5c_xstrdup(auth);
    }
}

static bool cidr_match(const char *entry, const char *host)
{
    char buf[64], *slash;
    struct in_addr a, b;
    int bits;
    snprintf(buf, sizeof buf, "%s", entry);
    slash = strchr(buf, '/');
    if (slash == NULL)
        return false;
    *slash = '\0';
    bits = atoi(slash + 1);
    if (bits < 0 || bits > 32 || inet_pton(AF_INET, buf, &a) != 1 || inet_pton(AF_INET, host, &b) != 1)
        return false;
    if (bits == 0)
        return true;
    return ((ntohl(a.s_addr) ^ ntohl(b.s_addr)) >> (32 - bits)) == 0;
}

bool target_allowed(const scp_cfg *c, const char *apiroot)
{
    char *auth, *host;
    bool ok = false;
    if (c->nallow == 0)
        return true;
    auth = authority_of(apiroot);
    host = host_of_authority(auth);
    for (size_t i = 0; i < c->nallow && !ok; i++) {
        const char *e = c->allow[i];
        if (strchr(e, '/') != NULL)
            ok = cidr_match(e, host);
        else if (e[0] == '*' && e[1] == '.')
            ok = strlen(host) > strlen(e + 1) && strcasecmp(host + strlen(host) - strlen(e + 1), e + 1) == 0;
        else
            ok = strcasecmp(e, host) == 0 || strcasecmp(e, auth) == 0;
    }
    free(auth);
    free(host);
    return ok;
}

/* ---- health ------------------------------------------------------------------------------------------------------------------- */

static health_t *health_find(scp *s, const char *authority, bool create)
{
    for (size_t i = 0; i < s->nhealth; i++)
        if (strcmp(s->health[i].authority, authority) == 0)
            return &s->health[i];
    if (!create || s->nhealth >= 4096)
        return NULL;
    s->health = g5c_xrealloc(s->health, (s->nhealth + 1) * sizeof *s->health);
    memset(&s->health[s->nhealth], 0, sizeof *s->health);
    s->health[s->nhealth].authority = g5c_xstrdup(authority);
    return &s->health[s->nhealth++];
}

bool scp_healthy(scp *s, const char *authority)
{
    health_t *h;
    bool ok = true;
    pthread_mutex_lock(&s->mu);
    h = health_find(s, authority, false);
    if (h != NULL && h->until > g5c_now_seconds())
        ok = false;
    pthread_mutex_unlock(&s->mu);
    return ok;
}

static void quarantined_gauge(scp *s)
{
    int64_t n = 0;
    double now = g5c_now_seconds();
    for (size_t i = 0; i < s->nhealth; i++)
        if (s->health[i].until > now)
            n++;
    g5c_gauge_set(s->g_quarantined, n);
}

void scp_report(scp *s, const char *authority, bool ok)
{
    health_t *h;
    pthread_mutex_lock(&s->mu);
    h = health_find(s, authority, !ok);
    if (h != NULL) {
        if (ok) {
            h->fails = 0;
            h->until = 0;
        } else if (++h->fails >= s->cfg->quarantine_failures) {
            h->until = g5c_now_seconds() + (double)s->cfg->quarantine_s;
            h->fails = 0;
            G5C_LOGW(SCP_LOG, "%s is left alone for %us after repeated failures", authority, s->cfg->quarantine_s);
        }
        quarantined_gauge(s);
    }
    pthread_mutex_unlock(&s->mu);
}

size_t scp_quarantined(scp *s)
{
    size_t n = 0;
    double now = g5c_now_seconds();
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->nhealth; i++)
        if (s->health[i].until > now)
            n++;
    pthread_mutex_unlock(&s->mu);
    return n;
}

/* ---- ordering ------------------------------------------------------------------------------------------------------------------ */

static uint32_t rnd32(void)
{
    uint32_t v = 0;
    g5c_random(&v, sizeof v);
    return v;
}

static double weight(const cand_t *c)
{
    double cap = c->capacity > 0 ? (double)c->capacity : 1.0, free_part = c->load >= 100 ? 1.0 : (double)(100 - c->load);
    return cap * free_part;
}

/* priority first (lower is better), inside a priority a weighted random order; producers that are being left alone go last */
static void order(scp *s, cands_t *c)
{
    cands_t out;
    bool *used = g5c_xcalloc(c->n ? c->n : 1, sizeof *used);
    memset(&out, 0, sizeof out);
    for (int pass = 0; pass < 2; pass++) {
        for (;;) {
            int best = INT32_MAX;
            double total = 0;
            for (size_t i = 0; i < c->n; i++) {
                char *a;
                bool h;
                if (used[i])
                    continue;
                a = authority_of(c->v[i].apiroot);
                h = scp_healthy(s, a);
                free(a);
                if ((pass == 0) != h)
                    continue;
                if (c->v[i].priority < best)
                    best = c->v[i].priority;
            }
            if (best == INT32_MAX)
                break;
            for (size_t i = 0; i < c->n; i++) {
                char *a;
                bool h;
                if (used[i] || c->v[i].priority != best)
                    continue;
                a = authority_of(c->v[i].apiroot);
                h = scp_healthy(s, a);
                free(a);
                if ((pass == 0) == h)
                    total += weight(&c->v[i]);
            }
            {
                double pick = ((double)rnd32() / 4294967296.0) * total, acc = 0;
                size_t chosen = c->n;
                for (size_t i = 0; i < c->n; i++) {
                    char *a;
                    bool h;
                    if (used[i] || c->v[i].priority != best)
                        continue;
                    a = authority_of(c->v[i].apiroot);
                    h = scp_healthy(s, a);
                    free(a);
                    if ((pass == 0) != h)
                        continue;
                    acc += weight(&c->v[i]);
                    chosen = i;
                    if (acc > pick)
                        break;
                }
                if (chosen == c->n)
                    break;
                used[chosen] = true;
                cands_add(&out, c->v[chosen].apiroot, c->v[chosen].nf_id, c->v[chosen].priority, c->v[chosen].capacity, c->v[chosen].load);
            }
        }
    }
    free(used);
    cands_free(c);
    *c = out;
}

/* ---- the profiles of the NRF ------------------------------------------------------------------------------------------------------ */

static unsigned uint_of(const g5c_json *j, const char *k, unsigned dflt)
{
    int64_t v;
    return g5c_json_get_int(j, k, &v) && v >= 0 && v < 1000000 ? (unsigned)v : dflt;
}

/* the apiRoot of one NF service of a profile */
static char *service_root(const g5c_json *prof, const g5c_json *svc)
{
    const char *scheme = g5c_json_get_str(svc, "scheme"), *fqdn = g5c_json_get_str(svc, "fqdn"), *prefix = g5c_json_get_str(svc, "apiPrefix"), *ip = NULL;
    const g5c_json *ep = g5c_json_at(g5c_json_get(svc, "ipEndPoints"), 0);
    int64_t port = 0;
    char host[128];
    if (scheme == NULL)
        scheme = "http";
    if (ep != NULL) {
        ip = g5c_json_get_str(ep, "ipv4Address");
        if (ip == NULL && g5c_json_get_str(ep, "ipv6Address") != NULL) {
            snprintf(host, sizeof host, "[%s]", g5c_json_get_str(ep, "ipv6Address"));
            ip = host;
        }
        (void)g5c_json_get_int(ep, "port", &port);
    }
    if (ip == NULL && fqdn == NULL)
        fqdn = g5c_json_get_str(prof, "fqdn");
    if (ip == NULL && fqdn == NULL) {
        const g5c_json *a = g5c_json_at(g5c_json_get(prof, "ipv4Addresses"), 0);
        ip = g5c_json_str(a);
    }
    if (ip == NULL && fqdn == NULL)
        return NULL;
    if (prefix != NULL && prefix[0] != '/')
        prefix = NULL;
    if (port > 0)
        return g5c_xasprintf("%s://%s:%lld%s", scheme, ip != NULL ? ip : fqdn, (long long)port, prefix != NULL ? prefix : "");
    return g5c_xasprintf("%s://%s%s", scheme, ip != NULL ? ip : fqdn, prefix != NULL ? prefix : "");
}

static void add_profile(cands_t *c, const g5c_json *prof, const char *service)
{
    const char *st = g5c_json_get_str(prof, "nfStatus"), *id = g5c_json_get_str(prof, "nfInstanceId");
    const g5c_json *svcs = g5c_json_get(prof, "nfServices");
    unsigned prio = uint_of(prof, "priority", 100), cap = uint_of(prof, "capacity", 100), load = uint_of(prof, "load", 0);
    if (st != NULL && strcmp(st, "REGISTERED") != 0)
        return;
    if (!g5c_json_is(svcs, G5C_J_ARRAY) && g5c_json_is(g5c_json_get(prof, "nfServiceList"), G5C_J_OBJECT)) {
        svcs = NULL; /* the map form: its values are the services */
    }
    if (svcs == NULL) {
        const g5c_json *m = g5c_json_get(prof, "nfServiceList");
        for (size_t i = 0; i < g5c_json_len(m); i++) {
            const g5c_json *sv = g5c_json_val_at(m, i);
            const char *name = g5c_json_get_str(sv, "serviceName");
            char *root;
            if (service != NULL && (name == NULL || strcmp(name, service) != 0))
                continue;
            root = service_root(prof, sv);
            if (root != NULL) {
                cands_add(c, root, id, (int)uint_of(sv, "priority", prio), uint_of(sv, "capacity", cap), uint_of(sv, "load", load));
                free(root);
                return;
            }
        }
        return;
    }
    for (size_t i = 0; i < g5c_json_len(svcs); i++) {
        const g5c_json *sv = g5c_json_at(svcs, i);
        const char *name = g5c_json_get_str(sv, "serviceName"), *sst = g5c_json_get_str(sv, "nfServiceStatus");
        char *root;
        if (service != NULL && (name == NULL || strcmp(name, service) != 0))
            continue;
        if (sst != NULL && strcmp(sst, "REGISTERED") != 0)
            continue;
        root = service_root(prof, sv);
        if (root != NULL) {
            cands_add(c, root, id, (int)uint_of(sv, "priority", prio), uint_of(sv, "capacity", cap), uint_of(sv, "load", load));
            free(root);
            return; /* one service instance of a producer */
        }
    }
}

/* ---- cache --------------------------------------------------------------------------------------------------------------------- */

static void cache_drop(scp *s, size_t i)
{
    free(s->cache[i].key);
    cands_free(&s->cache[i].c);
    s->cache[i] = s->cache[--s->ncache];
}

static bool cache_get(scp *s, const char *key, cands_t *out)
{
    bool hit = false;
    double now = g5c_now_seconds();
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->ncache;) {
        if (s->cache[i].expiry <= now) {
            cache_drop(s, i);
            continue;
        }
        if (!hit && strcmp(s->cache[i].key, key) == 0) {
            *out = cands_copy(&s->cache[i].c);
            hit = true;
        }
        i++;
    }
    pthread_mutex_unlock(&s->mu);
    return hit;
}

static void cache_put(scp *s, const char *key, const cands_t *c, unsigned ttl)
{
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->ncache; i++)
        if (strcmp(s->cache[i].key, key) == 0) {
            cache_drop(s, i);
            break;
        }
    if (s->ncache >= s->cfg->disc_max)
        cache_drop(s, 0);
    s->cache = g5c_xrealloc(s->cache, (s->ncache + 1) * sizeof *s->cache);
    s->cache[s->ncache].key = g5c_xstrdup(key);
    s->cache[s->ncache].c = cands_copy(c);
    s->cache[s->ncache].expiry = g5c_now_seconds() + (double)ttl;
    s->ncache++;
    pthread_mutex_unlock(&s->mu);
}

void scp_cache_forget(scp *s, const char *key)
{
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->ncache; i++)
        if (strcmp(s->cache[i].key, key) == 0) {
            cache_drop(s, i);
            break;
        }
    pthread_mutex_unlock(&s->mu);
}

size_t scp_cached_discoveries(scp *s)
{
    size_t n;
    pthread_mutex_lock(&s->mu);
    n = s->ncache;
    pthread_mutex_unlock(&s->mu);
    return n;
}

/* ---- discovery ------------------------------------------------------------------------------------------------------------------ */

#define DISC_PREFIX "3gpp-sbi-discovery-"

static void pct_into(g5c_bytes *b, const char *v)
{
    for (; *v != 0; v++) {
        unsigned char c = (unsigned char)*v;
        if (isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~' || c == ',')
            g5c_bytes_putc(b, (char)c);
        else
            g5c_bytes_printf(b, "%%%02X", c);
    }
}

/* the URI of the NRF's discovery service from a 3gpp-Sbi-Nrf-Uri header ("nnrf-disc: \"https://nrf/nnrf-disc/v1/\"; ..."); NULL when it names none */
static char *nrf_disc_from_header(const char *h)
{
    const char *p = h != NULL ? strstr(h, "nnrf-disc") : NULL, *q1, *q2;
    if (p == NULL)
        return NULL;
    q1 = strchr(p, '"');
    q2 = q1 != NULL ? strchr(q1 + 1, '"') : NULL;
    if (q1 == NULL || q2 == NULL || q2 == q1 + 1)
        return NULL;
    {
        char *u = g5c_xstrndup(q1 + 1, (size_t)(q2 - q1 - 1));
        size_t n = strlen(u);
        while (n > 0 && u[n - 1] == '/')
            u[--n] = '\0';
        if (!apiroot_ok(u)) {
            free(u);
            return NULL;
        }
        return u;
    }
}

int scp_discover(scp *s, const g5c_req *req, const char *ua, const char *nrf_hdr, const char *extra_query, cands_t *out, char **cache_key, const char **cause, char *detail, size_t dcap)
{
    g5c_bytes q;
    char *query, *key, *base = NULL, *url, err[160], requester[32] = "";
    const char *target_type = NULL, *services = NULL;
    bool have_requester = false;
    g5c_resp r;
    unsigned ttl = s->cfg->disc_ttl_s;
    int rc = 0;
    *cause = "NF_DISCOVERY_FAILURE";
    memset(out, 0, sizeof *out);
    free(*cache_key);
    *cache_key = NULL;
    g5c_bytes_init(&q);
    for (size_t i = 0; i < req->nheaders; i++) {
        const char *name = req->headers[i].name, *val = req->headers[i].value;
        const char *pn;
        if (strncmp(name, DISC_PREFIX, strlen(DISC_PREFIX)) != 0)
            continue;
        pn = name + strlen(DISC_PREFIX);
        if (*pn == '\0' || strlen(pn) > 48)
            continue;
        for (const char *c = pn; *c != 0; c++)
            if (!(isalnum((unsigned char)*c) || *c == '-')) {
                g5c_bytes_free(&q);
                *cause = "INVALID_DISCOVERY_PARAM";
                snprintf(detail, dcap, "the header %s is not a discovery parameter", name);
                return 400;
            }
        if (strcmp(pn, "target-nf-type") == 0)
            target_type = val;
        else if (strcmp(pn, "service-names") == 0)
            services = val;
        else if (strcmp(pn, "requester-nf-type") == 0)
            have_requester = true;
        if (q.len > 0)
            g5c_bytes_putc(&q, '&');
        g5c_bytes_printf(&q, "%s=", pn);
        pct_into(&q, val);
    }
    if (target_type == NULL || target_type[0] == '\0') {
        g5c_bytes_free(&q);
        *cause = "MANDATORY_IE_MISSING";
        snprintf(detail, dcap, "3gpp-Sbi-Discovery-target-nf-type is required for delegated discovery");
        return 400;
    }
    if (!have_requester) {
        /* the type of the consumer: the User-Agent starts with it (TS 29.500 5.2.2.2) */
        size_t n = ua != NULL ? strcspn(ua, "-/ ") : 0;
        if (n == 0 || n >= sizeof requester) {
            g5c_bytes_free(&q);
            *cause = "MANDATORY_IE_MISSING";
            snprintf(detail, dcap, "the NF type of the requester is in neither 3gpp-Sbi-Discovery-requester-nf-type nor the User-Agent");
            return 400;
        }
        for (size_t i = 0; i < n; i++)
            requester[i] = (char)toupper((unsigned char)ua[i]);
        requester[n] = '\0';
        if (q.len > 0)
            g5c_bytes_putc(&q, '&');
        g5c_bytes_printf(&q, "requester-nf-type=%s", requester);
    }
    if (extra_query != NULL && extra_query[0] != '\0') {
        if (q.len > 0)
            g5c_bytes_putc(&q, '&');
        g5c_bytes_append_str(&q, extra_query);
    }
    query = g5c_bytes_take(&q, NULL);
    if (strcmp(target_type, "NRF") == 0) {
        /* a request for the NRF itself (a function that delegates its registration): the NRF of the SCP, or the one the request names */
        char *h = nrf_disc_from_header(nrf_hdr);
        const char *root = s->cfg->nrf_uri;
        if (h != NULL) {
            char *cut = strstr(h, "/nnrf-");
            if (cut != NULL)
                *cut = '\0';
            root = h;
        }
        if (root == NULL) {
            *cause = "NF_DISCOVERY_FAILURE";
            snprintf(detail, dcap, "the SCP has no NRF");
            rc = 400;
        } else {
            cands_add(out, root, NULL, 0, 100, 0);
        }
        free(h);
        free(query);
        return rc;
    }
    base = nrf_disc_from_header(nrf_hdr);
    if (base == NULL) {
        if (s->cfg->nrf_uri == NULL) {
            free(query);
            *cause = "NF_DISCOVERY_FAILURE";
            snprintf(detail, dcap, "the SCP has no NRF to discover at");
            return 400;
        }
        base = g5c_xasprintf("%s/nnrf-disc/v1", s->cfg->nrf_uri);
    }
    key = g5c_xasprintf("%s?%s", base, query);
    *cache_key = g5c_xstrdup(key);
    if (cache_get(s, key, out)) {
        g5c_counter_inc(s->c_disc[D_HIT]);
        order(s, out);
        free(key);
        free(base);
        free(query);
        return 0;
    }
    url = g5c_xasprintf("%s/nf-instances?%s", base, query);
    if (g5c_client_request(s->client, "GET", url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) != 0) {
        g5c_counter_inc(s->c_disc[D_FAIL]);
        *cause = "TARGET_NF_NOT_REACHABLE";
        snprintf(detail, dcap, "the NRF cannot be reached: %s", err);
        rc = 504;
    } else {
        if (r.status == 200) {
            g5c_json *res = g5c_resp_parse_json(&r);
            const g5c_json *list = g5c_json_get(res, "nfInstances");
            int64_t v;
            const char *first = services;
            char svc[64] = "";
            if (first != NULL) {
                size_t n = strcspn(first, ",");
                if (n < sizeof svc) {
                    memcpy(svc, first, n);
                    svc[n] = '\0';
                }
            }
            for (size_t i = 0; i < g5c_json_len(list); i++)
                add_profile(out, g5c_json_at(list, i), svc[0] != '\0' ? svc : NULL);
            if (g5c_json_get_int(res, "validityPeriod", &v) && v > 0 && (unsigned)v < ttl)
                ttl = (unsigned)v;
            g5c_json_free(res);
            if (out->n == 0) {
                g5c_counter_inc(s->c_disc[D_NONE]);
                snprintf(detail, dcap, "no NF instance matches the discovery factors");
                rc = 400;
            } else {
                g5c_counter_inc(s->c_disc[D_MISS]);
                if (ttl > 0)
                    cache_put(s, key, out, ttl);
                order(s, out);
            }
        } else {
            g5c_counter_inc(s->c_disc[D_FAIL]);
            snprintf(detail, dcap, "the NRF answered %d to the discovery", r.status);
            rc = r.status >= 400 && r.status < 500 ? 400 : 504; /* the NRF refuses the discovery factors, or it is failing */
            if (rc == 504)
                *cause = "TARGET_NF_NOT_REACHABLE";
        }
        g5c_resp_free(&r);
    }
    if (rc != 0)
        cands_free(out);
    free(url);
    free(key);
    free(base);
    free(query);
    return rc;
}
