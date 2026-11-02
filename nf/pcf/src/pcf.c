#define _DEFAULT_SOURCE
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* PCF state, policy store (UDR), router and configuration. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include <unistd.h>

#include "g5c/config.h"
#include "g5c/pcf.h"

void pcf_init(pcf *p, pcf_policy *cfg, g5c_client *client, const char *udr_uri, g5c_registry *metrics)
{
    size_t n = strlen(udr_uri);
    memset(p, 0, sizeof *p);
    p->app_max = 10000;
    p->cfg = *cfg;
    memset(cfg, 0, sizeof *cfg);
    p->client = client;
    while (n > 0 && udr_uri[n - 1] == '/')
        n--;
    p->udr = g5c_xstrndup(udr_uri, n);
    p->metrics = metrics;
    pthread_mutex_init(&p->mu, NULL);
}

static void session_free(pcf_sm_session *s)
{
    free(s->id);
    free(s->supi);
    free(s->dnn);
    free(s->notification_uri);
    free(s->resource_uri);
    pcf_session_info_free(&s->info);
    g5c_json_free(s->context);
    g5c_json_free(s->decision);
}

void pcf_track(pcf *p, void *owned)
{
    p->owned = g5c_xrealloc(p->owned, (p->nowned + 1) * sizeof *p->owned);
    p->owned[p->nowned++] = owned;
}

void pcf_destroy(pcf *p)
{
    for (int i = 0; i < 100 && atomic_load(&p->notes_inflight) > 0; i++)
        usleep(50000); /* notifications to AFs still on their way */
    pcf_bsf_free(p);
    pcf_apps_free(p);
    for (size_t i = 0; i < p->nsessions; i++)
        session_free(&p->sessions[i]);
    free(p->sessions);
    for (size_t i = 0; i < p->nassocs; i++) {
        free(p->assocs[i].id);
        free(p->assocs[i].supi);
        g5c_json_free(p->assocs[i].request);
    }
    free(p->assocs);
    for (size_t i = 0; i < p->nowned; i++)
        free(p->owned[i]);
    free(p->owned);
    pcf_policy_free(&p->cfg);
    free(p->udr);
    g5c_disc_free(p->udr_disc);
    if (p->admin_token) {
        OPENSSL_cleanse(p->admin_token, strlen(p->admin_token));
        free(p->admin_token);
    }
    pthread_mutex_destroy(&p->mu);
}

size_t pcf_session_count(pcf *p)
{
    size_t n;
    pthread_mutex_lock(&p->mu);
    n = p->nsessions;
    pthread_mutex_unlock(&p->mu);
    return n;
}

/* ---- policy store ---- */

/* The PCF's own per-subscriber policy document is held in the UDR as operator-specific policy data */
#define PCF_OSD_KEY "g5c-policy"

static char *store_url(pcf *p, const char *supi)
{
    char *r, *root = NULL;
    if (p->udr_disc != NULL) {
        root = g5c_disc_root(p->udr_disc, "UDR", "nudr-dr", NULL);
        if (root == NULL) /* no UDR registered at the NRF */
            root = g5c_xstrdup("http://127.0.0.1:1");
    }
    r = g5c_xasprintf("%s/nudr-dr/v1/policy-data/ues/%s/operator-specific-data", root != NULL ? root : p->udr, supi);
    free(root);
    return r;
}

pcf_store_rc pcf_store_get(pcf *p, const char *supi, pcf_policy *out)
{
    char *u = store_url(p, supi), err[200];
    g5c_resp r;
    int rc = g5c_client_get(p->client, u, &r, err, sizeof err);
    pcf_store_rc res = PCF_STORE_ERROR;
    free(u);
    if (rc != 0)
        return PCF_STORE_ERROR;
    if (r.status == 200) {
        g5c_json *map = g5c_resp_parse_json(&r);
        const g5c_json *doc = g5c_json_get(g5c_json_get(map, PCF_OSD_KEY), "value");
        if (doc == NULL)
            res = PCF_STORE_NONE; /* the subscriber has operator-specific data, but none of this PCF's */
        else if (pcf_policy_parse(doc, false, out, err, sizeof err) == 0)
            res = PCF_STORE_OK;
        else
            G5C_LOGE("g5c_pcf", "stored policy for %s is malformed: %s", supi, err);
        g5c_json_free(map);
    } else if (r.status == 404) {
        res = PCF_STORE_NONE;
    }
    g5c_resp_free(&r);
    return res;
}

bool pcf_store_put(pcf *p, const char *supi, const pcf_policy *pol)
{
    char *u = store_url(p, supi);
    g5c_json *j = g5c_json_new_obj(), *box = g5c_json_set(j, PCF_OSD_KEY, g5c_json_new_obj());
    g5c_resp r;
    int rc;
    bool ok = false;
    g5c_json_set_str(box, "dataType", "object");
    g5c_json_set_str(box, "dataTypeDefinition", "g5c.pcf.policy.v1");
    g5c_json_set(box, "value", pcf_policy_to_json(pol));
    rc = g5c_client_send_json(p->client, "PUT", u, j, &r, NULL, 0);
    free(u);
    g5c_json_free(j);
    if (rc == 0) {
        ok = r.status == 200 || r.status == 201 || r.status == 204;
        g5c_resp_free(&r);
    }
    return ok;
}

int pcf_store_delete(pcf *p, const char *supi)
{
    char *u = store_url(p, supi);
    g5c_resp r;
    int rc = g5c_client_request(p->client, "DELETE", u, NULL, 0, NULL, NULL, 0, &r, NULL, 0), res = -1;
    free(u);
    if (rc != 0)
        return -1;
    if (r.status == 204)
        res = 1;
    else if (r.status == 404)
        res = 0;
    g5c_resp_free(&r);
    return res;
}

/* ---- router ---- */

g5c_router *pcf_router(pcf *p)
{
    g5c_router *r = g5c_router_new();
    pcf_smpolicy_routes(r, p);
    pcf_ampolicy_routes(r, p);
    pcf_admin_routes(r, p);
    pcf_policyauth_routes(r, p);
    g5c_router_set_guard(r, pcf_admin_guard, p);
    return r;
}

/* ---- configuration ---- */

pcf *pcf_from_config(const g5c_json *cfg, g5c_nf *nf, char *err, size_t errcap)
{
    static const char *const k_udr[] = {"uri", NULL};
    const g5c_json *udr = g5c_json_get(cfg, "udr");
    bool discover_udr = udr == NULL && nf->common.nrf_uri != NULL; /* no `udr:` block: the UDR is found through the NRF */
    pcf_policy pol;
    char field[200], reason[200], ferr[200];
    pcf *p;
    if (!discover_udr && (!g5c_json_is(udr, G5C_J_OBJECT) || g5c_json_get_str(udr, "uri") == NULL)) {
        snprintf(err, errcap, "invalid config: `udr.uri` is required (or `nrf.uri`, to find the UDR through the NRF)");
        return NULL;
    }
    if (!discover_udr && g5c_json_check_keys(udr, k_udr, "udr", err, errcap) != 0)
        return NULL;
    if (pcf_policy_parse(g5c_json_get(cfg, "policy"), true, &pol, err, errcap) != 0)
        return NULL;
    if (pcf_policy_validate(&pol, true, field, sizeof field, reason, sizeof reason) != 0) {
        snprintf(err, errcap, "%s: %s", field, reason);
        pcf_policy_free(&pol);
        return NULL;
    }
    p = g5c_xcalloc(1, sizeof *p);
    pcf_init(p, &pol, nf->client, discover_udr ? "http://unused" : g5c_json_get_str(udr, "uri"), nf->metrics);
    if (discover_udr) {
        free(p->udr);
        p->udr = NULL;
        p->udr_disc = g5c_disc_new(nf->client, nf->common.nrf_uri, "PCF", nf->instance_id);
    }
    if (pcf_policyauth_config(p, cfg, err, errcap) != 0) {
        pcf_destroy(p);
        free(p);
        return NULL;
    }
    if (pcf_bsf_config(p, cfg, nf, err, errcap) != 0) {
        pcf_destroy(p);
        free(p);
        return NULL;
    }
    p->admin_token = g5c_secret_from_env_or_file("G5C_PCF_ADMIN_TOKEN", g5c_json_get_str(cfg, "admin_token_file"), ferr, sizeof ferr);
    if (p->admin_token == NULL && ferr[0]) {
        snprintf(err, errcap, "%s", ferr);
        pcf_destroy(p);
        free(p);
        return NULL;
    }
    if (p->admin_token != NULL && strlen(p->admin_token) < 16) {
        snprintf(err, errcap, "admin token must be at least 16 characters");
        pcf_destroy(p);
        free(p);
        return NULL;
    }
    return p;
}
