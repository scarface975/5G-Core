/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* NF discovery client (Nnrf_NFDiscovery, TS 29.510 clause 5.3): the endpoint of an instance of a given NF type and service, from the NRF, cached for
 * the validity period the NRF states. Every NF that does not have a peer's address in its configuration resolves it here. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/nfcore.h"

#define DISC_SLOTS 32

typedef struct {
    char key[160];
    char root[200]; /* empty: free slot */
    double expires; /* monotonic seconds */
} slot_t;

struct g5c_disc {
    g5c_client *client;
    char *nrf;
    char *requester_type;
    char *requester_id;
    pthread_mutex_t mu;
    slot_t slots[DISC_SLOTS];
    unsigned next_victim;
};

static char *pct(const char *s)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t n = strlen(s);
    char *o = g5c_xmalloc(n * 3 + 1), *p = o;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            *p++ = (char)c;
        } else {
            *p++ = '%';
            *p++ = hex[c >> 4];
            *p++ = hex[c & 15];
        }
    }
    *p = 0;
    return o;
}

g5c_disc *g5c_disc_new(g5c_client *c, const char *nrf_uri, const char *requester_type, const char *requester_id)
{
    g5c_disc *d = g5c_xcalloc(1, sizeof *d);
    size_t n = strlen(nrf_uri);
    while (n > 0 && nrf_uri[n - 1] == '/')
        n--;
    d->client = c;
    d->nrf = g5c_xstrndup(nrf_uri, n);
    d->requester_type = g5c_xstrdup(requester_type);
    d->requester_id = requester_id != NULL ? g5c_xstrdup(requester_id) : NULL;
    pthread_mutex_init(&d->mu, NULL);
    return d;
}

void g5c_disc_free(g5c_disc *d)
{
    if (d == NULL)
        return;
    pthread_mutex_destroy(&d->mu);
    free(d->nrf);
    free(d->requester_type);
    free(d->requester_id);
    free(d);
}

/* scheme://host:port of the service in a profile: the first IP end point, else the service's or the profile's FQDN, else the profile's address */
static char *root_of_profile(const g5c_json *p, const char *service)
{
    const g5c_json *arr = g5c_json_get(p, "nfServices"), *map = g5c_json_get(p, "nfServiceList");
    size_t na = g5c_json_len(arr), nm = g5c_json_len(map);
    for (size_t i = 0; i < na + nm; i++) {
        const g5c_json *sv = i < na ? g5c_json_at(arr, i) : g5c_json_val_at(map, i - na), *eps;
        const char *name = g5c_json_get_str(sv, "serviceName"), *scheme = g5c_json_get_str(sv, "scheme");
        if (service != NULL && (name == NULL || strcmp(name, service) != 0))
            continue;
        eps = g5c_json_get(sv, "ipEndPoints");
        for (size_t k = 0; k < g5c_json_len(eps); k++) {
            const g5c_json *ep = g5c_json_at(eps, k);
            const char *ip = g5c_json_get_str(ep, "ipv4Address"), *ip6 = g5c_json_get_str(ep, "ipv6Address");
            int64_t port = 0;
            bool has_port = g5c_json_get_int(ep, "port", &port) && port > 0 && port < 65536;
            const char *sch = scheme != NULL ? scheme : "http";
            if (ip != NULL)
                return has_port ? g5c_xasprintf("%s://%s:%lld", sch, ip, (long long)port) : g5c_xasprintf("%s://%s", sch, ip);
            if (ip6 != NULL)
                return has_port ? g5c_xasprintf("%s://[%s]:%lld", sch, ip6, (long long)port) : g5c_xasprintf("%s://[%s]", sch, ip6);
        }
        if (g5c_json_get_str(sv, "fqdn") != NULL)
            return g5c_xasprintf("%s://%s", scheme != NULL ? scheme : "http", g5c_json_get_str(sv, "fqdn"));
        if (g5c_json_get_str(sv, "apiPrefix") != NULL && g5c_json_get_str(sv, "fqdn") == NULL)
            continue;
    }
    if (g5c_json_get_str(p, "fqdn") != NULL)
        return g5c_xasprintf("http://%s", g5c_json_get_str(p, "fqdn"));
    {
        const g5c_json *ips = g5c_json_get(p, "ipv4Addresses");
        if (g5c_json_len(ips) > 0 && g5c_json_str(g5c_json_at(ips, 0)) != NULL)
            return g5c_xasprintf("http://%s:7777", g5c_json_str(g5c_json_at(ips, 0)));
    }
    return NULL;
}

char *g5c_disc_root(g5c_disc *d, const char *target_type, const char *service, const g5c_disc_opts *o)
{
    char key[160], *url, err[160], *root = NULL;
    double now = g5c_now_seconds(), validity = 60;
    g5c_resp r;
    g5c_bytes q;
    snprintf(key, sizeof key, "%s|%s|%s|%s|%s|%s", target_type, service != NULL ? service : "", o != NULL && o->snssai_json != NULL ? o->snssai_json : "",
             o != NULL && o->dnn != NULL ? o->dnn : "", o != NULL && o->tai_json != NULL ? o->tai_json : "", o != NULL && o->supi != NULL ? o->supi : "");
    pthread_mutex_lock(&d->mu);
    for (int i = 0; i < DISC_SLOTS; i++)
        if (d->slots[i].root[0] != 0 && d->slots[i].expires > now && strcmp(d->slots[i].key, key) == 0) {
            root = g5c_xstrdup(d->slots[i].root);
            break;
        }
    pthread_mutex_unlock(&d->mu);
    if (root != NULL)
        return root;

    g5c_bytes_init(&q);
    {
        char *t = pct(target_type), *rq = pct(d->requester_type);
        g5c_bytes_printf(&q, "%s/nnrf-disc/v1/nf-instances?target-nf-type=%s&requester-nf-type=%s", d->nrf, t, rq);
        free(t);
        free(rq);
    }
    if (d->requester_id != NULL) {
        char *e = pct(d->requester_id);
        g5c_bytes_printf(&q, "&requester-nf-instance-id=%s", e);
        free(e);
    }
    if (service != NULL) {
        char *e = pct(service);
        g5c_bytes_printf(&q, "&service-names=%s", e);
        free(e);
    }
    if (o != NULL) {
        if (o->dnn != NULL) {
            char *e = pct(o->dnn);
            g5c_bytes_printf(&q, "&dnn=%s", e);
            free(e);
        }
        if (o->snssai_json != NULL) {
            char *e = pct(o->snssai_json);
            g5c_bytes_printf(&q, "&snssais=%s", e);
            free(e);
        }
        if (o->tai_json != NULL) {
            char *e = pct(o->tai_json);
            g5c_bytes_printf(&q, "&tai=%s", e);
            free(e);
        }
        if (o->supi != NULL) {
            char *e = pct(o->supi);
            g5c_bytes_printf(&q, "&supi=%s", e);
            free(e);
        }
    }
    url = g5c_bytes_take(&q, NULL);
    if (g5c_client_get(d->client, url, &r, err, sizeof err) != 0) {
        G5C_LOGW("g5c_disc", "NRF discovery of %s: %s", target_type, err);
        free(url);
        return NULL;
    }
    free(url);
    if (r.status == 200) {
        g5c_json *j = g5c_resp_parse_json(&r);
        const g5c_json *list = g5c_json_get(j, "nfInstances");
        int64_t v;
        if (g5c_json_get_int(j, "validityPeriod", &v) && v >= 1 && v <= 3600)
            validity = (double)v;
        for (size_t i = 0; i < g5c_json_len(list) && root == NULL; i++) /* the NRF sorted them: priority, then load */
            root = root_of_profile(g5c_json_at(list, i), service);
        g5c_json_free(j);
    } else {
        G5C_LOGW("g5c_disc", "NRF discovery of %s answered %d", target_type, r.status);
    }
    g5c_resp_free(&r);
    if (root != NULL) {
        int slot = -1;
        pthread_mutex_lock(&d->mu);
        for (int i = 0; i < DISC_SLOTS && slot < 0; i++)
            if (d->slots[i].root[0] == 0 || d->slots[i].expires <= now || strcmp(d->slots[i].key, key) == 0)
                slot = i;
        if (slot < 0)
            slot = (int)(d->next_victim++ % DISC_SLOTS);
        snprintf(d->slots[slot].key, sizeof d->slots[slot].key, "%s", key);
        snprintf(d->slots[slot].root, sizeof d->slots[slot].root, "%s", root);
        d->slots[slot].expires = now + validity;
        pthread_mutex_unlock(&d->mu);
    }
    return root;
}

void g5c_disc_forget(g5c_disc *d, const char *target_type)
{
    size_t n = strlen(target_type);
    pthread_mutex_lock(&d->mu);
    for (int i = 0; i < DISC_SLOTS; i++)
        if (strncmp(d->slots[i].key, target_type, n) == 0 && d->slots[i].key[n] == '|')
            d->slots[i].root[0] = 0;
    pthread_mutex_unlock(&d->mu);
}
