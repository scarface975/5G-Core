/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nbsf_Management (TS 29.521): the bindings, their indexes, and the four operations.
 *
 * A binding is found by the UE address it was registered with: the IPv4 address (hash), an IPv6 prefix of /64 or longer (hash of its first 64 bits; the prefixes shorter than
 * /64 are a short list), a MAC address (hash), and a framed route (a list: they are rare). The SamePcf check (TS 29.521 4.2.2.2) finds a binding by SUPI, DNN and S-NSSAI
 * (hash) or, when the combination is not complete, in the list of the bindings that hold SM policy addressing information. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include "priv.h"

/* ---- the hash table ------------------------------------------------------------------------------------------------------------- */

static uint64_t hash_str(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    for (; *s != '\0'; s++)
        h = (h ^ (unsigned char)*s) * 1099511628211ULL;
    return h;
}

static void ht_init(ht_t *t)
{
    t->nbuckets = 1024;
    t->count = 0;
    t->buckets = g5c_xcalloc(t->nbuckets, sizeof *t->buckets);
}

static void ht_free(ht_t *t)
{
    for (size_t i = 0; i < t->nbuckets; i++)
        for (hnode_t *n = t->buckets[i], *nx; n != NULL; n = nx) {
            nx = n->next;
            free(n->key);
            free(n);
        }
    free(t->buckets);
    memset(t, 0, sizeof *t);
}

static void ht_grow(ht_t *t)
{
    size_t nb = t->nbuckets * 2;
    hnode_t **nbk = g5c_xcalloc(nb, sizeof *nbk);
    for (size_t i = 0; i < t->nbuckets; i++)
        for (hnode_t *n = t->buckets[i], *nx; n != NULL; n = nx) {
            size_t k = (size_t)(hash_str(n->key) & (nb - 1));
            nx = n->next;
            n->next = nbk[k];
            nbk[k] = n;
        }
    free(t->buckets);
    t->buckets = nbk;
    t->nbuckets = nb;
}

static void ht_add(ht_t *t, const char *key, bind_t *b)
{
    hnode_t *n = g5c_xmalloc(sizeof *n);
    size_t k;
    if (t->count >= t->nbuckets * 3 / 4)
        ht_grow(t);
    k = (size_t)(hash_str(key) & (t->nbuckets - 1));
    n->key = g5c_xstrdup(key);
    n->b = b;
    n->next = t->buckets[k];
    t->buckets[k] = n;
    t->count++;
}

static void ht_del(ht_t *t, const char *key, bind_t *b)
{
    size_t k = (size_t)(hash_str(key) & (t->nbuckets - 1));
    for (hnode_t **pp = &t->buckets[k]; *pp != NULL; pp = &(*pp)->next)
        if ((*pp)->b == b && strcmp((*pp)->key, key) == 0) {
            hnode_t *n = *pp;
            *pp = n->next;
            free(n->key);
            free(n);
            t->count--;
            return;
        }
}

static hnode_t *ht_head(const ht_t *t, const char *key)
{
    return t->buckets[(size_t)(hash_str(key) & (t->nbuckets - 1))];
}

/* ---- keys ----------------------------------------------------------------------------------------------------------------------- */

static void key_v4(char out[16], uint32_t a)
{
    snprintf(out, 16, "4:%08x", a);
}

static void key_v6(char out[24], const uint8_t a[16])
{
    snprintf(out, 24, "6:%02x%02x%02x%02x%02x%02x%02x%02x", a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
}

static void key_mac(char out[16], const mac_t *m)
{
    snprintf(out, 16, "m:%02x%02x%02x%02x%02x%02x", m->m[0], m->m[1], m->m[2], m->m[3], m->m[4], m->m[5]);
}

static char *key_combo(const char *supi, const char *dnn, int sst, int sd)
{
    return g5c_xasprintf("s:%s|%s|%d-%d", supi, dnn, sst, sd);
}

/* ---- a binding ------------------------------------------------------------------------------------------------------------------ */

static void bind_clear(bind_t *b)
{
    free(b->supi);
    free(b->gpsi);
    free(b->dnn);
    free(b->domain);
    free(b->pcf_id);
    free(b->v6);
    free(b->mac);
    free(b->fr4);
    free(b->fr6);
    g5c_json_free(b->doc);
    b->supi = b->gpsi = b->dnn = b->domain = b->pcf_id = NULL;
    b->v6 = NULL;
    b->mac = NULL;
    b->fr4 = NULL;
    b->fr6 = NULL;
    b->doc = NULL;
    b->nv6 = b->nmac = b->nfr4 = b->nfr6 = 0;
    b->has_v4 = b->has_sm = false;
}

static void bind_free(bind_t *b)
{
    if (b == NULL)
        return;
    bind_clear(b);
    free(b->id);
    free(b);
}

/* an S-NSSAI as (sst, sd): an absent sd and FFFFFF are the same (TS 23.003 28.4.2) */
static bool snssai_of(const g5c_json *j, int *sst, int *sd)
{
    int64_t v;
    const char *s;
    if (!g5c_json_is(j, G5C_J_OBJECT) || !g5c_json_get_int(j, "sst", &v) || v < 0 || v > 255)
        return false;
    *sst = (int)v;
    *sd = -1;
    s = g5c_json_get_str(j, "sd");
    if (g5c_json_get(j, "sd") != NULL) {
        char *end;
        long x;
        if (s == NULL || strlen(s) != 6)
            return false;
        x = strtol(s, &end, 16);
        if (*end != '\0')
            return false;
        *sd = x == 0xFFFFFF ? -1 : (int)x;
    }
    return true;
}

static void str_of(const g5c_json *doc, const char *key, char **out)
{
    const char *s = g5c_json_get_str(doc, key);
    *out = s != NULL ? g5c_xstrdup(s) : NULL;
}

/* Fills `b` from the PcfBinding. false with the name of the member that is wrong in *param. */
static bool bind_parse(bind_t *b, const g5c_json *doc, const char **param)
{
    const g5c_json *l;
    memset(b, 0, sizeof *b);
    *param = NULL;
    b->doc = g5c_json_dup(doc);
    str_of(doc, "supi", &b->supi);
    str_of(doc, "gpsi", &b->gpsi);
    str_of(doc, "dnn", &b->dnn);
    str_of(doc, "ipDomain", &b->domain);
    str_of(doc, "pcfId", &b->pcf_id);
    if (b->dnn == NULL || !snssai_of(g5c_json_get(doc, "snssai"), &b->sst, &b->sd)) {
        *param = b->dnn == NULL ? "dnn" : "snssai";
        return false;
    }
    if (g5c_json_get(doc, "ipv4Addr") != NULL) {
        if (!bsf_parse_ipv4(g5c_json_get_str(doc, "ipv4Addr"), &b->v4)) {
            *param = "ipv4Addr";
            return false;
        }
        b->has_v4 = true;
    }
    if (g5c_json_get(doc, "ipv6Prefix") != NULL || g5c_json_get(doc, "addIpv6Prefixes") != NULL) {
        size_t n = (g5c_json_get(doc, "ipv6Prefix") != NULL ? 1 : 0) + g5c_json_len(g5c_json_get(doc, "addIpv6Prefixes"));
        if (n > BSF_MAX_ADDRS) {
            *param = "addIpv6Prefixes";
            return false;
        }
        b->v6 = g5c_xcalloc(n, sizeof *b->v6);
        if (g5c_json_get(doc, "ipv6Prefix") != NULL) {
            if (!bsf_parse_pfx6(g5c_json_get_str(doc, "ipv6Prefix"), &b->v6[b->nv6++])) {
                *param = "ipv6Prefix";
                return false;
            }
        }
        l = g5c_json_get(doc, "addIpv6Prefixes");
        for (size_t i = 0; i < g5c_json_len(l); i++)
            if (!bsf_parse_pfx6(g5c_json_str(g5c_json_at(l, i)), &b->v6[b->nv6++])) {
                *param = "addIpv6Prefixes";
                return false;
            }
    }
    if (g5c_json_get(doc, "macAddr48") != NULL || g5c_json_get(doc, "addMacAddrs") != NULL) {
        size_t n = (g5c_json_get(doc, "macAddr48") != NULL ? 1 : 0) + g5c_json_len(g5c_json_get(doc, "addMacAddrs"));
        if (n > BSF_MAX_ADDRS) {
            *param = "addMacAddrs";
            return false;
        }
        b->mac = g5c_xcalloc(n, sizeof *b->mac);
        if (g5c_json_get(doc, "macAddr48") != NULL && !bsf_parse_mac(g5c_json_get_str(doc, "macAddr48"), &b->mac[b->nmac++])) {
            *param = "macAddr48";
            return false;
        }
        l = g5c_json_get(doc, "addMacAddrs");
        for (size_t i = 0; i < g5c_json_len(l); i++)
            if (!bsf_parse_mac(g5c_json_str(g5c_json_at(l, i)), &b->mac[b->nmac++])) {
                *param = "addMacAddrs";
                return false;
            }
    }
    l = g5c_json_get(doc, "ipv4FrameRouteList");
    if (l != NULL) {
        if (g5c_json_len(l) > BSF_MAX_ADDRS) {
            *param = "ipv4FrameRouteList";
            return false;
        }
        b->fr4 = g5c_xcalloc(g5c_json_len(l) + 1, sizeof *b->fr4);
        for (size_t i = 0; i < g5c_json_len(l); i++)
            if (!bsf_parse_pfx4(g5c_json_str(g5c_json_at(l, i)), &b->fr4[b->nfr4++])) {
                *param = "ipv4FrameRouteList";
                return false;
            }
    }
    l = g5c_json_get(doc, "ipv6FrameRouteList");
    if (l != NULL) {
        if (g5c_json_len(l) > BSF_MAX_ADDRS) {
            *param = "ipv6FrameRouteList";
            return false;
        }
        b->fr6 = g5c_xcalloc(g5c_json_len(l) + 1, sizeof *b->fr6);
        for (size_t i = 0; i < g5c_json_len(l); i++)
            if (!bsf_parse_pfx6(g5c_json_str(g5c_json_at(l, i)), &b->fr6[b->nfr6++])) {
                *param = "ipv6FrameRouteList";
                return false;
            }
    }
    b->has_sm = g5c_json_get(doc, "pcfSmFqdn") != NULL || g5c_json_get(doc, "pcfSmIpEndPoints") != NULL;
    b->features = bsf_features_parse(g5c_json_get_str(doc, "suppFeat"));
    if (g5c_json_get(doc, "recoveryTime") != NULL) {
        int64_t ms = bsf_parse_rfc3339(g5c_json_get_str(doc, "recoveryTime"));
        if (ms < 0) {
            *param = "recoveryTime";
            return false;
        }
        b->recovery_s = ms / 1000;
    }
    return true;
}

/* ---- the indexes ---------------------------------------------------------------------------------------------------------------- */

static void list_push(bind_t ***v, size_t *n, size_t *cap, bind_t *b, size_t *ix)
{
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 1024;
        *v = g5c_xrealloc(*v, *cap * sizeof **v);
    }
    *ix = *n;
    (*v)[(*n)++] = b;
}

static void route_push(route_t **v, size_t *n, size_t *cap, const route_t *r)
{
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 64;
        *v = g5c_xrealloc(*v, *cap * sizeof **v);
    }
    (*v)[(*n)++] = *r;
}

static void route_drop(route_t *v, size_t *n, bind_t *b)
{
    for (size_t i = 0; i < *n;)
        if (v[i].b == b)
            v[i] = v[--*n];
        else
            i++;
}

static void index_add(bsf *s, bind_t *b)
{
    char key[40];
    ht_add(&s->by_id, (snprintf(key, sizeof key, "i:%.36s", b->id), key), b);
    if (b->has_v4) {
        key_v4(key, b->v4);
        ht_add(&s->by_v4, key, b);
    }
    for (size_t i = 0; i < b->nv6; i++) {
        if (b->v6[i].len >= 64) {
            key_v6(key, b->v6[i].a);
            ht_add(&s->by_v6, key, b);
        } else {
            route_t r = {b, true, {0, 0}, b->v6[i]};
            route_push(&s->short6, &s->nshort6, &s->capshort6, &r);
        }
    }
    for (size_t i = 0; i < b->nmac; i++) {
        key_mac(key, &b->mac[i]);
        ht_add(&s->by_mac, key, b);
    }
    for (size_t i = 0; i < b->nfr4; i++) {
        route_t r = {b, false, b->fr4[i], {{0}, 0}};
        route_push(&s->routes, &s->nroutes, &s->caproutes, &r);
    }
    for (size_t i = 0; i < b->nfr6; i++) {
        route_t r = {b, true, {0, 0}, b->fr6[i]};
        route_push(&s->routes, &s->nroutes, &s->caproutes, &r);
    }
    if (b->has_sm) {
        list_push(&s->sm, &s->nsm, &s->capsm, b, &b->sm_ix);
        if (b->supi != NULL) {
            char *k = key_combo(b->supi, b->dnn, b->sst, b->sd);
            ht_add(&s->by_combo, k, b);
            free(k);
        }
    }
    list_push(&s->all, &s->nall, &s->capall, b, &b->all_ix);
    if (b->pcf_id != NULL && b->recovery_s > 0) {
        size_t i;
        for (i = 0; i < s->npcf_rec; i++)
            if (strcmp(s->pcf_rec[i].pcf_id, b->pcf_id) == 0)
                break;
        if (i == s->npcf_rec) {
            s->pcf_rec = g5c_xrealloc(s->pcf_rec, (s->npcf_rec + 1) * sizeof *s->pcf_rec);
            s->pcf_rec[i].pcf_id = g5c_xstrdup(b->pcf_id);
            s->pcf_rec[i].rec = 0;
            s->npcf_rec++;
        }
        if (b->recovery_s > s->pcf_rec[i].rec)
            s->pcf_rec[i].rec = b->recovery_s;
    }
}

static void index_del(bsf *s, bind_t *b)
{
    char key[40];
    ht_del(&s->by_id, (snprintf(key, sizeof key, "i:%.36s", b->id), key), b);
    if (b->has_v4) {
        key_v4(key, b->v4);
        ht_del(&s->by_v4, key, b);
    }
    for (size_t i = 0; i < b->nv6; i++)
        if (b->v6[i].len >= 64) {
            key_v6(key, b->v6[i].a);
            ht_del(&s->by_v6, key, b);
        }
    route_drop(s->short6, &s->nshort6, b);
    for (size_t i = 0; i < b->nmac; i++) {
        key_mac(key, &b->mac[i]);
        ht_del(&s->by_mac, key, b);
    }
    route_drop(s->routes, &s->nroutes, b);
    if (b->has_sm) {
        if (b->supi != NULL) {
            char *k = key_combo(b->supi, b->dnn, b->sst, b->sd);
            ht_del(&s->by_combo, k, b);
            free(k);
        }
        s->sm[b->sm_ix] = s->sm[--s->nsm];
        s->sm[b->sm_ix]->sm_ix = b->sm_ix;
    }
    s->all[b->all_ix] = s->all[--s->nall];
    s->all[b->all_ix]->all_ix = b->all_ix;
}

static bind_t *find_id(bsf *s, const char *id)
{
    char key[48];
    if (id == NULL || strlen(id) > 36)
        return NULL;
    snprintf(key, sizeof key, "i:%s", id);
    for (hnode_t *n = ht_head(&s->by_id, key); n != NULL; n = n->next)
        if (strcmp(n->key, key) == 0)
            return n->b;
    return NULL;
}

static void gauge(bsf *s)
{
    g5c_gauge_set(s->g_bindings, (int64_t)s->nall);
}

/* remove a binding the BSF holds (caller holds the lock) */
static void remove_binding(bsf *s, bind_t *b)
{
    index_del(s, b);
    bind_free(b);
}

void bsf_bindings_free(bsf *s)
{
    for (size_t i = 0; i < s->nall; i++)
        bind_free(s->all[i]);
    free(s->all);
    free(s->sm);
    free(s->short6);
    free(s->routes);
    for (size_t i = 0; i < s->npcf_rec; i++)
        free(s->pcf_rec[i].pcf_id);
    free(s->pcf_rec);
    ht_free(&s->by_id);
    ht_free(&s->by_v4);
    ht_free(&s->by_v6);
    ht_free(&s->by_mac);
    ht_free(&s->by_combo);
    s->all = NULL;
    s->nall = 0;
}

/* ---- validation of a binding (TS 29.521 4.2.2.2, 5.6.2.2) ------------------------------------------------------------------------ */

static bool semantic_check(const bind_t *nb, const g5c_json *doc, unsigned neg, const char **param, const char **why)
{
    bool addr = nb->has_v4 || nb->nv6 > 0 || nb->nmac > 0;
    bool pcf_addr = g5c_json_get(doc, "pcfFqdn") != NULL || g5c_json_get(doc, "pcfIpEndPoints") != NULL ||
                    (g5c_json_get(doc, "pcfDiamHost") != NULL && g5c_json_get(doc, "pcfDiamRealm") != NULL);
    static const char *const multi[] = {"addIpv6Prefixes", "addMacAddrs", NULL};
    static const char *const same[] = {"pcfSmFqdn", "pcfSmIpEndPoints", "paraCom", NULL};
    for (int i = 0; multi[i] != NULL; i++)
        if (!(neg & BSF_F_MULTI_UE_ADDR) && g5c_json_get(doc, multi[i]) != NULL) {
            *param = multi[i];
            *why = "the feature MultiUeAddr is not negotiated";
            return false;
        }
    for (int i = 0; same[i] != NULL; i++)
        if (!(neg & BSF_F_SAME_PCF) && g5c_json_get(doc, same[i]) != NULL) {
            *param = same[i];
            *why = "the feature SamePcf is not negotiated";
            return false;
        }
    if (nb->domain != NULL && !nb->has_v4) {
        *param = "ipDomain";
        *why = "the IPv4 address domain applies to an IPv4 address only";
        return false;
    }
    if (g5c_json_get(doc, "paraCom") != NULL && g5c_json_len(g5c_json_get(doc, "paraCom")) == 0) {
        *param = "paraCom";
        *why = "at least one of supi, dnn and snssai is required";
        return false;
    }
    if (!(neg & BSF_F_EXT_SAME_PCF)) {
        if (!addr) {
            *param = "ipv4Addr";
            *why = "the address of the UE (ipv4Addr, ipv6Prefix, addIpv6Prefixes, macAddr48 or addMacAddrs) is required";
            return false;
        }
        if (!pcf_addr) {
            *param = "pcfFqdn";
            *why = "the address of the PCF (pcfFqdn, pcfIpEndPoints, or pcfDiamHost with pcfDiamRealm) is required";
            return false;
        }
    }
    return true;
}

static void invalid(bsf *s, g5c_resp *resp, const char *cause, const char *param, const char *why)
{
    (void)s;
    g5c_resp_problem_invalid(resp, 400, cause, param, why);
}

/* a "<json pointer>: <reason>" of the schema validator as an invalidParams entry */
static void invalid_schema(bsf *s, g5c_resp *resp, const char *e)
{
    char param[96] = "", why[160];
    const char *colon = strstr(e, ": ");
    if (colon != NULL && (size_t)(colon - e) < sizeof param) {
        size_t n = (size_t)(colon - e);
        memcpy(param, e, n);
        param[n] = '\0';
        snprintf(why, sizeof why, "%s", colon + 2);
    } else {
        snprintf(why, sizeof why, "%s", e);
    }
    invalid(s, resp, "MANDATORY_IE_INCORRECT", param[0] ? param : "body", why);
}

/* ---- the SamePcf check -------------------------------------------------------------------------------------------------------------- */

static bool combo_matches(const bind_t *e, const char *supi, const char *dnn, bool has_snssai, int sst, int sd)
{
    return (supi == NULL || (e->supi != NULL && strcmp(e->supi, supi) == 0)) && (dnn == NULL || strcmp(e->dnn, dnn) == 0) &&
           (!has_snssai || (e->sst == sst && e->sd == sd));
}

static bind_t *same_pcf_binding(bsf *s, const g5c_json *para)
{
    const char *supi = g5c_json_get_str(para, "supi"), *dnn = g5c_json_get_str(para, "dnn");
    int sst = 0, sd = -1;
    bool has_snssai = g5c_json_get(para, "snssai") != NULL && snssai_of(g5c_json_get(para, "snssai"), &sst, &sd);
    if (supi != NULL && dnn != NULL && has_snssai) {
        char *k = key_combo(supi, dnn, sst, sd);
        for (hnode_t *n = ht_head(&s->by_combo, k); n != NULL; n = n->next)
            if (strcmp(n->key, k) == 0) {
                free(k);
                return n->b;
            }
        free(k);
        return NULL;
    }
    for (size_t i = 0; i < s->nsm; i++)
        if (combo_matches(s->sm[i], supi, dnn, has_snssai, sst, sd))
            return s->sm[i];
    return NULL;
}

/* ---- Nbsf_Management_Register --------------------------------------------------------------------------------------------------- */

static void count(bsf *s, int op, int result)
{
    g5c_counter_inc(s->c_ops[op][result]);
}

static void reply_existing(g5c_resp *resp, const bind_t *e)
{
    g5c_json *p, *body;
    char *text;
    size_t len = 0;
    const g5c_json *v;
    g5c_resp_problem_simple(resp, 403, "EXISTING_BINDING_INFO_FOUND", "a PCF binding for this combination of SUPI, DNN and S-NSSAI exists");
    p = g5c_resp_parse_json(resp);
    if (p == NULL)
        return;
    body = p;
    if ((v = g5c_json_get(e->doc, "pcfSmFqdn")) != NULL)
        g5c_json_set(body, "pcfSmFqdn", g5c_json_dup(v));
    if ((v = g5c_json_get(e->doc, "pcfSmIpEndPoints")) != NULL)
        g5c_json_set(body, "pcfSmIpEndPoints", g5c_json_dup(v));
    text = g5c_json_to_string(body, &len);
    if (text != NULL)
        g5c_resp_content(resp, 403, "application/problem+json", text, len);
    free(text);
    g5c_json_free(body);
}

static bool same_address(const bind_t *a, const bind_t *b)
{
    if (a->has_v4 != b->has_v4 || (a->has_v4 && a->v4 != b->v4) || a->nv6 != b->nv6 || a->nmac != b->nmac)
        return false;
    for (size_t i = 0; i < a->nv6; i++)
        if (a->v6[i].len != b->v6[i].len || memcmp(a->v6[i].a, b->v6[i].a, 16) != 0)
            return false;
    for (size_t i = 0; i < a->nmac; i++)
        if (memcmp(a->mac[i].m, b->mac[i].m, 6) != 0)
            return false;
    return true;
}

static bool str_eq(const char *a, const char *b)
{
    return (a == NULL && b == NULL) || (a != NULL && b != NULL && strcmp(a, b) == 0);
}

/* The earlier bindings for the same UE address, DNN, S-NSSAI and IP domain (caller holds the lock), whichever PCF registered them: an address is unique within its DNN,
 * S-NSSAI and IP domain, so such a binding is stale (a PCF that restarted, a session that moved to another PCF, an address that was handed to another UE) and the new
 * one replaces it. */
static size_t collect_replaced(bsf *s, const bind_t *nb, bind_t **out, size_t cap)
{
    size_t n = 0;
    char key[40];
    const ht_t *t = NULL;
    if (nb->has_v4) {
        key_v4(key, nb->v4);
        t = &s->by_v4;
    } else if (nb->nv6 > 0 && nb->v6[0].len >= 64) {
        key_v6(key, nb->v6[0].a);
        t = &s->by_v6;
    } else if (nb->nmac > 0) {
        key_mac(key, &nb->mac[0]);
        t = &s->by_mac;
    }
    if (t == NULL)
        return 0;
    for (hnode_t *h = ht_head(t, key); h != NULL && n < cap; h = h->next) {
        const bind_t *e = h->b;
        bool dup = false;
        if (strcmp(h->key, key) != 0 || strcmp(e->dnn, nb->dnn) != 0 || e->sst != nb->sst || e->sd != nb->sd ||
            !str_eq(e->domain, nb->domain) || !same_address(e, nb))
            continue;
        for (size_t i = 0; i < n; i++)
            dup = dup || out[i] == e;
        if (!dup)
            out[n++] = h->b;
    }
    return n;
}

/* the bindings of this PCF that predate its newest recovery time (caller holds the lock) */
static size_t purge_older(bsf *s, const bind_t *nb)
{
    size_t victims = 0, i;
    int64_t known = 0;
    bind_t **list;
    if (!s->cfg->purge_on_recovery || nb->pcf_id == NULL || nb->recovery_s <= 0)
        return 0;
    for (i = 0; i < s->npcf_rec; i++)
        if (strcmp(s->pcf_rec[i].pcf_id, nb->pcf_id) == 0)
            known = s->pcf_rec[i].rec;
    if (nb->recovery_s <= known)
        return 0;
    list = g5c_xmalloc((s->nall + 1) * sizeof *list);
    for (i = 0; i < s->nall; i++)
        if (str_eq(s->all[i]->pcf_id, nb->pcf_id) && s->all[i]->recovery_s > 0 && s->all[i]->recovery_s < nb->recovery_s)
            list[victims++] = s->all[i];
    for (i = 0; i < victims; i++)
        remove_binding(s, list[i]);
    free(list);
    return victims;
}

static void h_register(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    bsf *s = ctx;
    g5c_json *body = g5c_req_json(req, resp), *stored = NULL;
    bind_t *nb = NULL, *same;
    const char *param = NULL, *why = NULL;
    char err[200], *f, *loc, *full;
    unsigned neg;
    bind_t *victims[8];
    size_t nv, purged;
    if (body == NULL) {
        count(s, 0, 2);
        return;
    }
    if (s->cfg->validate && oa_validate(s->sch, BSF_SCH_PCF_BINDING, body, err, sizeof err) != 0) {
        invalid_schema(s, resp, err);
        goto rejected;
    }
    neg = bsf_features_parse(g5c_json_get_str(body, "suppFeat")) & s->cfg->features;
    if ((neg & BSF_F_EXT_SAME_PCF) && !(neg & BSF_F_SAME_PCF))
        neg &= ~BSF_F_EXT_SAME_PCF;
    stored = g5c_json_dup(body);
    f = bsf_features_str(neg);
    g5c_json_set_str(stored, "suppFeat", f);
    free(f);
    nb = g5c_xmalloc(sizeof *nb);
    if (!bind_parse(nb, stored, &param)) {
        invalid(s, resp, "MANDATORY_IE_INCORRECT", param != NULL ? param : "body", "the value is not valid");
        goto rejected;
    }
    if (!semantic_check(nb, stored, neg, &param, &why)) {
        invalid(s, resp, strcmp(param, "ipv4Addr") == 0 || strcmp(param, "pcfFqdn") == 0 ? "MANDATORY_IE_MISSING" : "OPTIONAL_IE_INCORRECT", param, why);
        goto rejected;
    }
    nb->features = neg;
    nb->id = g5c_xmalloc(37);
    g5c_uuid_v4(nb->id);
    pthread_mutex_lock(&s->mu);
    if ((neg & BSF_F_SAME_PCF) && g5c_json_get(stored, "paraCom") != NULL && (same = same_pcf_binding(s, g5c_json_get(stored, "paraCom"))) != NULL) {
        reply_existing(resp, same);
        pthread_mutex_unlock(&s->mu);
        goto rejected;
    }
    purged = purge_older(s, nb);
    if (s->cfg->replace_stale) {
        nv = collect_replaced(s, nb, victims, sizeof victims / sizeof *victims);
        for (size_t i = 0; i < nv; i++)
            remove_binding(s, victims[i]);
        for (size_t i = 0; i < nv; i++)
            g5c_counter_inc(s->c_replaced);
    }
    for (size_t i = 0; i < purged; i++)
        g5c_counter_inc(s->c_purged);
    if (s->nall >= s->cfg->max_bindings) {
        pthread_mutex_unlock(&s->mu);
        bsf_problem(resp, 503, "NF_CONGESTION", "the BSF holds as many bindings as it is configured to");
        goto rejected;
    }
    index_add(s, nb);
    gauge(s);
    pthread_mutex_unlock(&s->mu);
    bsf_kick(s);
    loc = g5c_req_url(req, req->path);
    full = g5c_xasprintf("%s/%s", loc, nb->id);
    g5c_resp_header(resp, "location", full);
    free(full);
    free(loc);
    g5c_resp_json(resp, 201, stored);
    g5c_json_free(stored);
    g5c_json_free(body);
    count(s, 0, 0);
    return;
rejected:
    if (nb != NULL)
        bind_free(nb);
    g5c_json_free(stored);
    g5c_json_free(body);
    count(s, 0, 2);
}

/* ---- Nbsf_Management_Deregister -------------------------------------------------------------------------------------------------- */

static void h_deregister(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    bsf *s = ctx;
    bind_t *b;
    pthread_mutex_lock(&s->mu);
    b = find_id(s, g5c_req_param(req, "bindingId"));
    if (b == NULL) {
        pthread_mutex_unlock(&s->mu);
        bsf_problem(resp, 404, "BINDING_NOT_FOUND", "no PCF session binding with this identifier");
        count(s, 1, 1);
        return;
    }
    remove_binding(s, b);
    gauge(s);
    pthread_mutex_unlock(&s->mu);
    bsf_kick(s);
    g5c_resp_status(resp, 204);
    count(s, 1, 0);
}

/* ---- Nbsf_Management_Update ------------------------------------------------------------------------------------------------------ */

static void h_update(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    bsf *s = ctx;
    const char *id = g5c_req_param(req, "bindingId"), *ct = g5c_req_header(req, "content-type"), *param = NULL, *why = NULL;
    g5c_json *patch, *doc = NULL;
    bind_t *b, nb;
    char err[200];
    bool parsed = false;
    if (ct != NULL && strncasecmp(ct, "application/merge-patch+json", 28) != 0 && strncasecmp(ct, "application/json", 16) != 0) {
        g5c_resp_header(resp, "accept-patch", "application/merge-patch+json");
        bsf_problem(resp, 415, "UNSUPPORTED_MEDIA_TYPE", "the patch document must be application/merge-patch+json");
        count(s, 3, 2);
        return;
    }
    patch = g5c_req_json(req, resp);
    if (patch == NULL) {
        count(s, 3, 2);
        return;
    }
    if (g5c_json_is(patch, G5C_J_OBJECT)) {
        static const char *const allowed[] = {"ipv4Addr", "ipDomain", "ipv6Prefix", "addIpv6Prefixes", "macAddr48", "addMacAddrs", "pcfId", "pcfFqdn",
                                              "pcfIpEndPoints", "pcfDiamHost", "pcfDiamRealm", NULL};
        for (size_t i = 0; i < g5c_json_len(patch); i++) {
            bool ok = false;
            for (int k = 0; allowed[k] != NULL; k++)
                ok = ok || strcmp(g5c_json_key_at(patch, i), allowed[k]) == 0;
            if (!ok) {
                bsf_problem(resp, 403, "MODIFICATION_NOT_ALLOWED", "only the members of PcfBindingPatch can be modified");
                goto rejected;
            }
        }
    }
    if (!g5c_json_is(patch, G5C_J_OBJECT) || (s->cfg->validate && oa_validate(s->sch, BSF_SCH_PCF_BINDING_PATCH, patch, err, sizeof err) != 0)) {
        invalid_schema(s, resp, g5c_json_is(patch, G5C_J_OBJECT) ? err : "body: the patch document must be a JSON object");
        goto rejected;
    }
    pthread_mutex_lock(&s->mu);
    b = find_id(s, id);
    if (b == NULL) {
        pthread_mutex_unlock(&s->mu);
        bsf_problem(resp, 404, "BINDING_NOT_FOUND", "no PCF session binding with this identifier");
        g5c_json_free(patch);
        count(s, 3, 1);
        return;
    }
    if (!(b->features & BSF_F_BINDING_UPDATE)) {
        pthread_mutex_unlock(&s->mu);
        bsf_problem(resp, 501, NULL, "the feature BindingUpdate was not negotiated for this binding");
        goto rejected;
    }
    doc = g5c_json_dup(b->doc);
    bsf_merge_patch(&doc, patch);
    if (s->cfg->validate && oa_validate(s->sch, BSF_SCH_PCF_BINDING, doc, err, sizeof err) != 0) {
        pthread_mutex_unlock(&s->mu);
        invalid_schema(s, resp, err);
        goto rejected;
    }
    parsed = bind_parse(&nb, doc, &param);
    if (!parsed || !semantic_check(&nb, doc, b->features, &param, &why)) {
        pthread_mutex_unlock(&s->mu);
        invalid(s, resp, why == NULL ? "MANDATORY_IE_INCORRECT" : "MANDATORY_IE_MISSING", param != NULL ? param : "body", why != NULL ? why : "the value is not valid");
        if (parsed || nb.doc != NULL)
            bind_clear(&nb);
        goto rejected;
    }
    /* keep the identity of the resource: take the new contents into the same structure */
    index_del(s, b);
    nb.id = b->id;
    nb.features = b->features;
    nb.all_ix = b->all_ix;
    nb.sm_ix = b->sm_ix;
    bind_clear(b);
    *b = nb;
    index_add(s, b);
    g5c_resp_json(resp, 200, b->doc);
    pthread_mutex_unlock(&s->mu);
    bsf_kick(s);
    g5c_json_free(doc);
    g5c_json_free(patch);
    count(s, 3, 0);
    return;
rejected:
    g5c_json_free(doc);
    g5c_json_free(patch);
    count(s, 3, 2);
}

/* ---- Nbsf_Management_Discovery --------------------------------------------------------------------------------------------------- */

typedef struct {
    bind_t *b;
    int plen;
} hit_t;

static void hit_add(hit_t **hits, size_t *n, size_t *cap, bind_t *b, int plen)
{
    for (size_t i = 0; i < *n; i++)
        if ((*hits)[i].b == b) {
            if (plen > (*hits)[i].plen)
                (*hits)[i].plen = plen;
            return;
        }
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 8;
        *hits = g5c_xrealloc(*hits, *cap * sizeof **hits);
    }
    (*hits)[*n].b = b;
    (*hits)[(*n)++].plen = plen;
}

static const char *const QUERY_NAMES[] = {"ipv4Addr", "ipv6Prefix", "macAddr48", "dnn", "supi", "gpsi", "snssai", "ipDomain", "supp-feat", NULL};

/* the first query parameter that is not defined by TS 29.521 5.3.2.3.2, copied into out */
static bool unknown_query_param(const g5c_req *req, char *out, size_t cap)
{
    const char *p = req->query;
    while (p != NULL && *p != '\0') {
        size_t n = strcspn(p, "&="), k;
        bool known = false;
        for (k = 0; QUERY_NAMES[k] != NULL; k++)
            known = known || (strlen(QUERY_NAMES[k]) == n && strncmp(QUERY_NAMES[k], p, n) == 0);
        if (n > 0 && !known) {
            snprintf(out, cap, "%.*s", (int)(n < cap - 1 ? n : cap - 1), p);
            return true;
        }
        p += n;
        p += strcspn(p, "&");
        if (*p == '&')
            p++;
    }
    return false;
}

static void h_discover(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    bsf *s = ctx;
    char *v4q = g5c_req_query_decoded(req, "ipv4Addr"), *v6q = g5c_req_query_decoded(req, "ipv6Prefix"), *macq = g5c_req_query_decoded(req, "macAddr48"),
         *dnn = g5c_req_query_decoded(req, "dnn"), *supi = g5c_req_query_decoded(req, "supi"), *gpsi = g5c_req_query_decoded(req, "gpsi"),
         *snq = g5c_req_query_decoded(req, "snssai"), *dom = g5c_req_query_decoded(req, "ipDomain"), *sf = g5c_req_query_decoded(req, "supp-feat");
    char unk[64];
    uint32_t a4 = 0;
    pfx6_t a6 = {{0}, 128};
    mac_t am;
    int sst = 0, sd = -1, naddr = (v4q != NULL) + (v6q != NULL) + (macq != NULL), plen_max = -1;
    bool has_sn = false;
    hit_t *hits = NULL;
    size_t nh = 0, caph = 0, nbest = 0;
    bind_t *best = NULL;
    unsigned qfeat = 0;
    if (unknown_query_param(req, unk, sizeof unk)) {
        invalid(s, resp, "INVALID_QUERY_PARAM", unk, "this query parameter is not defined for the service");
        goto rejected;
    }
    if (naddr == 0) {
        invalid(s, resp, "MANDATORY_QUERY_PARAM_MISSING", "ipv4Addr", "one of ipv4Addr, ipv6Prefix and macAddr48 is required");
        goto rejected;
    }
    if (naddr > 1) {
        invalid(s, resp, "MANDATORY_QUERY_PARAM_INCORRECT", v4q != NULL ? "ipv4Addr" : "ipv6Prefix", "only one of ipv4Addr, ipv6Prefix and macAddr48 may be given");
        goto rejected;
    }
    if (v4q != NULL && !bsf_parse_ipv4(v4q, &a4)) {
        invalid(s, resp, "MANDATORY_QUERY_PARAM_INCORRECT", "ipv4Addr", "not an IPv4 address");
        goto rejected;
    }
    if (v6q != NULL) {
        char *withlen = strchr(v6q, '/') != NULL ? g5c_xstrdup(v6q) : g5c_xasprintf("%s/128", v6q);
        bool ok = bsf_parse_pfx6(withlen, &a6);
        free(withlen);
        if (!ok) {
            invalid(s, resp, "MANDATORY_QUERY_PARAM_INCORRECT", "ipv6Prefix", "not an IPv6 prefix");
            goto rejected;
        }
    }
    if (macq != NULL && !bsf_parse_mac(macq, &am)) {
        invalid(s, resp, "MANDATORY_QUERY_PARAM_INCORRECT", "macAddr48", "not a MAC address");
        goto rejected;
    }
    if (snq != NULL) {
        g5c_json *j = g5c_json_parse(snq, strlen(snq), NULL, 0);
        has_sn = j != NULL && snssai_of(j, &sst, &sd);
        g5c_json_free(j);
        if (!has_sn) {
            invalid(s, resp, "OPTIONAL_QUERY_PARAM_INCORRECT", "snssai", "not a JSON encoded S-NSSAI");
            goto rejected;
        }
    }
    if (sf != NULL) {
        for (const char *c = sf; *c != '\0'; c++)
            if (!isxdigit((unsigned char)*c)) {
                invalid(s, resp, "OPTIONAL_QUERY_PARAM_INCORRECT", "supp-feat", "not a hexadecimal string");
                goto rejected;
            }
        qfeat = bsf_features_parse(sf);
    }
    pthread_mutex_lock(&s->mu);
    if (v4q != NULL) {
        char key[16];
        key_v4(key, a4);
        for (hnode_t *n = ht_head(&s->by_v4, key); n != NULL; n = n->next)
            if (strcmp(n->key, key) == 0)
                hit_add(&hits, &nh, &caph, n->b, 32);
        for (size_t i = 0; i < s->nroutes; i++)
            if (!s->routes[i].v6 && bsf_pfx4_covers(&s->routes[i].p4, a4))
                hit_add(&hits, &nh, &caph, s->routes[i].b, s->routes[i].p4.len);
    } else if (v6q != NULL) {
        char key[24];
        key_v6(key, a6.a);
        for (hnode_t *n = ht_head(&s->by_v6, key); n != NULL; n = n->next) {
            if (strcmp(n->key, key) != 0)
                continue;
            for (size_t i = 0; i < n->b->nv6; i++)
                if (n->b->v6[i].len >= 64 && bsf_pfx6_covers(&n->b->v6[i], &a6))
                    hit_add(&hits, &nh, &caph, n->b, n->b->v6[i].len);
        }
        for (size_t i = 0; i < s->nshort6; i++)
            if (bsf_pfx6_covers(&s->short6[i].p6, &a6))
                hit_add(&hits, &nh, &caph, s->short6[i].b, s->short6[i].p6.len);
        for (size_t i = 0; i < s->nroutes; i++)
            if (s->routes[i].v6 && bsf_pfx6_covers(&s->routes[i].p6, &a6))
                hit_add(&hits, &nh, &caph, s->routes[i].b, s->routes[i].p6.len);
    } else {
        char key[16];
        key_mac(key, &am);
        for (hnode_t *n = ht_head(&s->by_mac, key); n != NULL; n = n->next)
            if (strcmp(n->key, key) == 0)
                hit_add(&hits, &nh, &caph, n->b, 48);
    }
    /* the other query parameters narrow the matches; the longest prefix of what is left wins */
    for (size_t i = 0; i < nh; i++) {
        const bind_t *e = hits[i].b;
        if ((dnn != NULL && strcmp(e->dnn, dnn) != 0) || (supi != NULL && !str_eq(e->supi, supi)) || (gpsi != NULL && !str_eq(e->gpsi, gpsi)) ||
            (has_sn && (e->sst != sst || e->sd != sd)) || (dom != NULL && !str_eq(e->domain, dom)))
            hits[i].plen = -1;
        if (hits[i].plen > plen_max)
            plen_max = hits[i].plen;
    }
    for (size_t i = 0; i < nh; i++)
        if (hits[i].plen >= 0 && hits[i].plen == plen_max) {
            nbest++;
            best = hits[i].b;
        }
    if (nbest == 0) {
        pthread_mutex_unlock(&s->mu);
        g5c_resp_status(resp, 204);
        count(s, 2, 1);
    } else if (nbest > 1) {
        pthread_mutex_unlock(&s->mu);
        bsf_problem(resp, 400, "MULTIPLE_BINDING_INFO_FOUND", "more than one PCF session binding matches the query parameters");
        count(s, 2, 2);
    } else {
        g5c_json *out = g5c_json_dup(best->doc);
        unsigned f = best->features & qfeat;
        pthread_mutex_unlock(&s->mu);
        g5c_json_remove(out, "suppFeat");
        if (sf != NULL) {
            char *fs = bsf_features_str(f);
            g5c_json_set_str(out, "suppFeat", fs);
            free(fs);
        }
        g5c_resp_json(resp, 200, out);
        g5c_json_free(out);
        count(s, 2, 0);
    }
    goto done;
rejected:
    count(s, 2, 2);
done:
    free(hits);
    free(v4q);
    free(v6q);
    free(macq);
    free(dnn);
    free(supi);
    free(gpsi);
    free(snq);
    free(dom);
    free(sf);
}

/* ---- the state file's way in ----------------------------------------------------------------------------------------------------- */

bool bsf_insert_doc(bsf *s, const char *id, const g5c_json *doc, char *err, size_t errcap)
{
    bind_t *nb;
    const char *param = NULL;
    if (id == NULL || strlen(id) != 36 || doc == NULL) {
        snprintf(err, errcap, "no identifier");
        return false;
    }
    nb = g5c_xmalloc(sizeof *nb);
    if (!bind_parse(nb, doc, &param)) {
        snprintf(err, errcap, "%s is not valid", param != NULL ? param : "the binding");
        bind_clear(nb);
        free(nb);
        return false;
    }
    nb->id = g5c_xstrdup(id);
    pthread_mutex_lock(&s->mu);
    if (find_id(s, id) != NULL || s->nall >= s->cfg->max_bindings) {
        pthread_mutex_unlock(&s->mu);
        snprintf(err, errcap, "duplicate or over the limit");
        bind_free(nb);
        return false;
    }
    index_add(s, nb);
    gauge(s);
    pthread_mutex_unlock(&s->mu);
    return true;
}

size_t bsf_binding_count(bsf *s)
{
    size_t n;
    pthread_mutex_lock(&s->mu);
    n = s->nall;
    pthread_mutex_unlock(&s->mu);
    return n;
}

void bsf_bindings_init(bsf *s)
{
    ht_init(&s->by_id);
    ht_init(&s->by_v4);
    ht_init(&s->by_v6);
    ht_init(&s->by_mac);
    ht_init(&s->by_combo);
}

void bsf_routes(g5c_router *r, bsf *s)
{
    g5c_router_route(r, "POST", "/nbsf-management/v1/pcfBindings", h_register, s);
    g5c_router_route(r, "GET", "/nbsf-management/v1/pcfBindings", h_discover, s);
    g5c_router_route(r, "DELETE", "/nbsf-management/v1/pcfBindings/{bindingId}", h_deregister, s);
    g5c_router_route(r, "PATCH", "/nbsf-management/v1/pcfBindings/{bindingId}", h_update, s);
}
