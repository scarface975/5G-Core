/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Shared UDM state, per-subscriber locks and the full router. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "g5c/udm.h"

struct supi_lock {
    char *supi;
    int refs;
    pthread_mutex_t mu;
};

static int os_rand(void *ctx, uint8_t out[16])
{
    (void)ctx;
    return g5c_random(out, 16);
}

void udm_init(udm *u, g5c_client *client, const char *udr_base, const udm_keys *keys, const udm_hnkey *hn_keys,
              size_t nhn_keys, const char *plmn, const char *instance_id, g5c_registry *metrics)
{
    memset(u, 0, sizeof *u);
    udm_udr_init(&u->udr, client, udr_base);
    u->keys = *keys;
    if (nhn_keys > 0) {
        u->hn_keys = g5c_xmalloc(nhn_keys * sizeof *u->hn_keys);
        memcpy(u->hn_keys, hn_keys, nhn_keys * sizeof *u->hn_keys);
        u->nhn_keys = nhn_keys;
    }
    snprintf(u->plmn, sizeof u->plmn, "%s", plmn);
    snprintf(u->instance_id, sizeof u->instance_id, "%s", instance_id);
    u->metrics = metrics;
    u->client = client;
    u->rand_fn = os_rand;
    pthread_mutex_init(&u->mu, NULL);
    u->sdm_subs = g5c_json_new_obj();
    u->next_sub = 1;
    u->ee_subs = g5c_json_new_obj();
    u->next_ee = 1;
}

void udm_track(udm *u, void *owned)
{
    u->owned = g5c_xrealloc(u->owned, (u->nowned + 1) * sizeof *u->owned);
    u->owned[u->nowned++] = owned;
}

void udm_destroy(udm *u)
{
    for (size_t i = 0; i < u->nowned; i++)
        free(u->owned[i]);
    free(u->owned);
    for (size_t i = 0; i < u->nlocks; i++) { /* only non-empty if a lock was leaked */
        pthread_mutex_destroy(&u->locks[i]->mu);
        free(u->locks[i]->supi);
        free(u->locks[i]);
    }
    free(u->locks);
    udm_udr_free(&u->udr);
    if (u->hn_keys)
        OPENSSL_cleanse(u->hn_keys, u->nhn_keys * sizeof *u->hn_keys);
    free(u->hn_keys);
    OPENSSL_cleanse(&u->keys, sizeof u->keys);
    if (u->admin_token) {
        OPENSSL_cleanse(u->admin_token, strlen(u->admin_token));
        free(u->admin_token);
    }
    g5c_json_free(u->sdm_subs);
    g5c_json_free(u->ee_subs);
    free(u->ee_amf_uri);
    free(u->ee_self_uri);
    pthread_mutex_destroy(&u->mu);
}

/* A table of per-SUPI mutexes; an entry lives only while someone holds or waits for it. */
udm_supi_lock *udm_lock_supi(udm *u, const char *supi)
{
    struct supi_lock *l = NULL;
    pthread_mutex_lock(&u->mu);
    for (size_t i = 0; i < u->nlocks; i++)
        if (strcmp(u->locks[i]->supi, supi) == 0) {
            l = u->locks[i];
            break;
        }
    if (l == NULL) {
        l = g5c_xcalloc(1, sizeof *l);
        l->supi = g5c_xstrdup(supi);
        pthread_mutex_init(&l->mu, NULL);
        u->locks = g5c_xrealloc(u->locks, (u->nlocks + 1) * sizeof *u->locks);
        u->locks[u->nlocks++] = l;
    }
    l->refs++;
    pthread_mutex_unlock(&u->mu);
    pthread_mutex_lock(&l->mu);
    return l;
}

void udm_unlock_supi(udm *u, udm_supi_lock *l)
{
    pthread_mutex_unlock(&l->mu);
    pthread_mutex_lock(&u->mu);
    if (--l->refs == 0) {
        for (size_t i = 0; i < u->nlocks; i++)
            if (u->locks[i] == l) {
                u->locks[i] = u->locks[--u->nlocks];
                break;
            }
        pthread_mutex_destroy(&l->mu);
        free(l->supi);
        free(l);
    }
    pthread_mutex_unlock(&u->mu);
}

g5c_router *udm_router(udm *u)
{
    g5c_router *r = g5c_router_new();
    udm_ueau_routes(r, u);
    udm_sdm_routes(r, u);
    udm_uecm_routes(r, u);
    udm_ee_routes(r, u);
    udm_admin_routes(r, u);
    g5c_router_set_guard(r, udm_admin_guard, u);
    return r;
}
