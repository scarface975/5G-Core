/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "priv.h"

void ausf_ue_free_all(ausf *a);

void ausf_opts_default(ausf_opts *o)
{
    memset(o, 0, sizeof *o);
    o->ctx_lifetime_s = 30.0;
    o->result_retention_s = 86400.0;
    o->max_contexts = 1000000;
    o->max_ue_contexts = 2000000;
    o->eap_result_ind = false;
    o->udm_timeout_ms = 0;
}

void ausf_opts_free(ausf_opts *o)
{
    for (size_t i = 0; i < o->n_snn_allow; i++)
        free(o->snn_allow[i]);
    free(o->snn_allow);
    free(o->state_file);
    g5c_json_free(o->nrf_info);
    OPENSSL_cleanse(o->master_key, sizeof o->master_key);
    memset(o, 0, sizeof *o);
}

static void trim_slash(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && s[n - 1] == '/')
        s[--n] = 0;
}

ausf *ausf_new(g5c_client *client, const char *udm, g5c_disc *disc, const char *self_uri, const char *instance_id, g5c_registry *metrics, const ausf_opts *o)
{
    ausf *a = g5c_xcalloc(1, sizeof *a);
    a->client = client;
    if (udm != NULL) {
        a->udm = g5c_xstrdup(udm);
        trim_slash(a->udm);
    }
    a->disc = disc;
    a->self_uri = g5c_xstrdup(self_uri != NULL ? self_uri : ""); /* empty: links use the address the consumer used */
    trim_slash(a->self_uri);
    snprintf(a->instance_id, sizeof a->instance_id, "%s", instance_id);
    a->metrics = metrics;
    if (o != NULL) {
        a->o = *o;
        a->o.snn_allow = NULL;
        a->o.n_snn_allow = 0;
        a->o.state_file = o->state_file != NULL ? g5c_xstrdup(o->state_file) : NULL;
        a->o.nrf_info = NULL;
        if (o->n_snn_allow > 0) {
            a->o.snn_allow = g5c_xcalloc(o->n_snn_allow, sizeof *a->o.snn_allow);
            for (size_t i = 0; i < o->n_snn_allow; i++)
                a->o.snn_allow[i] = g5c_xstrdup(o->snn_allow[i]);
            a->o.n_snn_allow = o->n_snn_allow;
        }
        if (o->nrf_info != NULL)
            a->nrf_info = g5c_json_dup(o->nrf_info);
    } else {
        ausf_opts_default(&a->o);
    }
    if (a->o.ctx_lifetime_s <= 0)
        a->o.ctx_lifetime_s = 30.0;
    if (a->o.result_retention_s <= 0)
        a->o.result_retention_s = 86400.0;
    if (a->o.max_contexts == 0)
        a->o.max_contexts = 1000000;
    if (a->o.max_ue_contexts == 0)
        a->o.max_ue_contexts = 2000000;
    a->g_pending = g5c_gauge_get(metrics, "g5c_ausf_contexts", "Authentication contexts held, by state.", &(g5c_label){"state", "pending"}, 1);
    a->g_done = g5c_gauge_get(metrics, "g5c_ausf_contexts", "Authentication contexts held, by state.", &(g5c_label){"state", "finished"}, 1);
    a->g_ues = g5c_gauge_get(metrics, "g5c_ausf_security_contexts", "Security contexts held (the latest KAUSF per SUPI).", NULL, 0);
    pthread_mutex_init(&a->mu, NULL);
    pthread_cond_init(&a->cv, NULL);
    hmap_init(&a->by_id);
    hmap_init(&a->by_key);
    hmap_init(&a->ues);
    a->gap_ms = 100;
    return a;
}

int ausf_start(ausf *a, char *err, size_t errcap)
{
    if (a->o.state_file == NULL)
        return 0;
    if (!a->o.has_master_key) {
        snprintf(err, errcap, "a state file needs a master key (the KAUSF values in it are encrypted)");
        return -1;
    }
    if (state_load(a, err, errcap) != 0)
        return -1;
    state_start_writer(a);
    return 0;
}

void ausf_free(ausf *a)
{
    if (a == NULL)
        return;
    state_stop_writer(a);
    for (ausf_ctx *c = a->pending.head, *n; c != NULL; c = n) {
        n = c->lnext;
        ctx_free(c);
    }
    for (ausf_ctx *c = a->done.head, *n; c != NULL; c = n) {
        n = c->lnext;
        ctx_free(c);
    }
    ausf_ue_free_all(a);
    hmap_clear(&a->by_id);
    hmap_clear(&a->by_key);
    hmap_clear(&a->ues);
    g5c_disc_free(a->disc);
    free(a->udm);
    free(a->self_uri);
    g5c_json_free(a->nrf_info);
    ausf_opts_free(&a->o);
    OPENSSL_cleanse(a->o.master_key, sizeof a->o.master_key);
    pthread_mutex_destroy(&a->mu);
    pthread_cond_destroy(&a->cv);
    free(a);
}

void ausf_set_self_uri(ausf *a, const char *uri)
{
    char *n = g5c_xstrdup(uri);
    trim_slash(n);
    pthread_mutex_lock(&a->mu);
    free(a->self_uri);
    a->self_uri = n;
    pthread_mutex_unlock(&a->mu);
}

const g5c_json *ausf_nrf_info(const ausf *a)
{
    return a->nrf_info;
}

char *ausf_url(ausf *a, const char *path)
{
    char *u;
    pthread_mutex_lock(&a->mu);
    u = g5c_xasprintf("%s%s", a->self_uri, path);
    pthread_mutex_unlock(&a->mu);
    return u;
}

void ausf_no_store(g5c_resp *resp)
{
    g5c_resp_header(resp, "cache-control", "no-store");
}

void ausf_hal(g5c_resp *resp)
{
    g5c_resp_header(resp, "content-type", "application/3gppHal+json");
}

void store_gauges(ausf *a)
{
    g5c_gauge_set(a->g_pending, (int64_t)a->pending.n);
    g5c_gauge_set(a->g_done, (int64_t)a->done.n);
    g5c_gauge_set(a->g_ues, (int64_t)a->ues.n);
}

void ausf_count(ausf *a, const char *name, const char *help, const char *lk, const char *lv)
{
    g5c_label l = {lk, lv};
    g5c_counter_inc(g5c_counter_get(a->metrics, name, help, lk != NULL ? &l : NULL, lk != NULL ? 1 : 0));
}

void ausf_count2(ausf *a, const char *name, const char *help, const char *k1, const char *v1, const char *k2, const char *v2)
{
    g5c_label l[2] = {{k1, v1}, {k2, v2}};
    g5c_counter_inc(g5c_counter_get(a->metrics, name, help, l, 2));
}

/* ---- identifiers ---- */

static bool id_chars(const char *s)
{
    /* what a SUPI or SUCI is made of; nothing that could change the path of the request to the UDM */
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && strchr("-_.:@+~", *s) == NULL)
            return false;
    return true;
}

bool ausf_valid_supi(const char *s)
{
    size_t n;
    if (s == NULL || strlen(s) > 128 || !id_chars(s))
        return false;
    if (g5c_starts_with(s, "imsi-")) {
        n = strlen(s + 5);
        if (n < 5 || n > 15)
            return false;
        for (const char *p = s + 5; *p; p++)
            if (!isdigit((unsigned char)*p))
                return false;
        return true;
    }
    /* network specific identifiers: nai-<user>@<realm>, gci-..., gli-... (TS 29.571 5.3.2) */
    return (g5c_starts_with(s, "nai-") || g5c_starts_with(s, "gci-") || g5c_starts_with(s, "gli-")) && strlen(s) > 4;
}

bool ausf_valid_supi_or_suci(const char *s)
{
    if (s == NULL || strlen(s) > 512 || !id_chars(s))
        return false;
    if (g5c_starts_with(s, "suci-"))
        return strlen(s) > 5;
    return ausf_valid_supi(s);
}

const char *ausf_imsi_digits(const char *supi)
{
    return g5c_starts_with(supi, "imsi-") ? supi + 5 : NULL;
}

/* ---- routes ---- */

void ausf_routes(g5c_router *r, ausf *a)
{
    ausf_ueau_routes(r, a);
    ausf_prot_routes(r, a);
}

g5c_router *ausf_router(ausf *a)
{
    g5c_router *r = g5c_router_new();
    ausf_routes(r, a);
    return r;
}
