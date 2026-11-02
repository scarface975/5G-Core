/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The SMF's SBI clients: Nudm_SDM / Nudm_UECM, Npcf_SMPolicyControl, Namf_Communication. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/multipart.h"
#include "priv.h"

/* The apiRoot of the UDM or PCF: the configured address, or the one the NRF gives (cached for its validity period). The answer of a discovery is copied
 * into a per-thread buffer, valid until the next call on the same thread; with no UDM / PCF known it is an address that refuses the connection, so the
 * caller reports the usual peer failure. */
static const char *peer_root(smf *s, const char *type, const char *service)
{
    static __thread char buf[256];
    const char *conf = strcmp(type, "UDM") == 0 ? s->udm : s->pcf;
    char *r;
    if (conf != NULL)
        return conf;
    r = s->disc != NULL ? g5c_disc_root(s->disc, type, service, NULL) : NULL;
    snprintf(buf, sizeof buf, "%s", r != NULL ? r : "http://127.0.0.1:1");
    free(r);
    return buf;
}

static char *pct_encode(const char *s)
{
    g5c_bytes b;
    g5c_bytes_init(&b);
    for (; *s != 0; s++) {
        unsigned char c = (unsigned char)*s;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~')
            g5c_bytes_putc(&b, (char)c);
        else
            g5c_bytes_printf(&b, "%%%02X", c);
    }
    return g5c_bytes_take(&b, NULL);
}

static g5c_json *snssai_json(uint8_t sst, bool has_sd, uint32_t sd)
{
    g5c_json *j = g5c_json_new_obj();
    g5c_json_set_int(j, "sst", sst);
    if (has_sd) {
        char hex[7];
        snprintf(hex, sizeof hex, "%06X", sd);
        g5c_json_set_str(j, "sd", hex);
    }
    return j;
}

/* ---- UDM ----------------------------------------------------------------------------------------------------------------------------------- */

int smf_udm_sm_data(smf *s, const char *supi, const g5c_json *plmn, uint8_t sst, bool has_sd, uint32_t sd, const char *dnn, g5c_json **out)
{
    g5c_json *sn = snssai_json(sst, has_sd, sd), *body = NULL;
    char *snj = g5c_json_to_string(sn, NULL), *sne = pct_encode(snj), *dnne = pct_encode(dnn), *plmnq = NULL, *url, err[160];
    g5c_resp r;
    int rc = SMF_PEER_FAIL;
    g5c_json_free(sn);
    free(snj);
    if (g5c_json_is(plmn, G5C_J_OBJECT)) {
        char *pj = g5c_json_to_string(plmn, NULL), *pe = pct_encode(pj);
        plmnq = g5c_xasprintf("&plmn-id=%s", pe);
        free(pj);
        free(pe);
    }
    url = g5c_xasprintf("%s/nudm-sdm/v2/%s/sm-data?single-nssai=%s&dnn=%s%s", peer_root(s, "UDM", "nudm-sdm"), supi, sne, dnne, plmnq != NULL ? plmnq : "");
    free(sne);
    free(dnne);
    free(plmnq);
    if (g5c_client_get(s->client, url, &r, err, sizeof err) != 0) {
        G5C_LOGE("g5c_smf", "UDM sm-data: %s", err);
        free(url);
        return SMF_PEER_FAIL;
    }
    free(url);
    if (r.status == 200 && (body = g5c_resp_parse_json(&r)) != NULL && g5c_json_is(body, G5C_J_ARRAY)) {
        for (size_t i = 0; i < g5c_json_len(body) && rc != SMF_PEER_OK; i++) {
            const g5c_json *cfg = g5c_json_get(g5c_json_get(g5c_json_at(body, i), "dnnConfigurations"), dnn);
            if (cfg != NULL) {
                *out = g5c_json_dup(cfg);
                rc = SMF_PEER_OK;
            }
        }
        if (rc != SMF_PEER_OK)
            rc = 404;
    } else if (r.status == 404) {
        rc = 404;
    } else {
        G5C_LOGE("g5c_smf", "UDM sm-data answered %d", r.status);
    }
    g5c_json_free(body);
    g5c_resp_free(&r);
    return rc;
}

int smf_udm_register(smf *s, const smf_sess *ss, const g5c_json *plmn)
{
    g5c_json *b = g5c_json_new_obj();
    char *url = g5c_xasprintf("%s/nudm-uecm/v1/%s/registrations/smf-registrations/%u", peer_root(s, "UDM", "nudm-uecm"), ss->supi, ss->psi), err[160];
    g5c_resp r;
    int rc = SMF_PEER_FAIL;
    g5c_json_set_str(b, "smfInstanceId", s->instance_id);
    g5c_json_set_int(b, "pduSessionId", ss->psi);
    g5c_json_set(b, "singleNssai", snssai_json(ss->sst, ss->has_sd, ss->sd));
    g5c_json_set_str(b, "dnn", ss->dnn);
    if (g5c_json_is(plmn, G5C_J_OBJECT))
        g5c_json_set(b, "plmnId", g5c_json_dup(plmn));
    if (g5c_client_send_json(s->client, "PUT", url, b, &r, err, sizeof err) == 0) {
        rc = (r.status == 200 || r.status == 201) ? SMF_PEER_OK : SMF_PEER_FAIL;
        if (rc != SMF_PEER_OK)
            G5C_LOGE("g5c_smf", "UDM SMF registration answered %d", r.status);
        g5c_resp_free(&r);
    } else {
        G5C_LOGE("g5c_smf", "UDM SMF registration: %s", err);
    }
    g5c_json_free(b);
    free(url);
    return rc;
}

int smf_udm_deregister(smf *s, const char *supi, uint8_t psi)
{
    char *url = g5c_xasprintf("%s/nudm-uecm/v1/%s/registrations/smf-registrations/%u", peer_root(s, "UDM", "nudm-uecm"), supi, psi), err[160];
    g5c_resp r;
    int rc = SMF_PEER_FAIL;
    if (g5c_client_request(s->client, "DELETE", url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) == 0) {
        rc = (r.status == 204 || r.status == 404) ? SMF_PEER_OK : SMF_PEER_FAIL;
        g5c_resp_free(&r);
    }
    free(url);
    return rc;
}

/* ---- PCF ----------------------------------------------------------------------------------------------------------------------------------- */

int smf_pcf_create(smf *s, const smf_sess *ss, const g5c_json *cfg, const char *notif, const g5c_json *plmn, g5c_json **decision, char **resource)
{
    g5c_json *b = g5c_json_new_obj();
    char *url = g5c_xasprintf("%s/npcf-smpolicycontrol/v1/sm-policies", peer_root(s, "PCF", "npcf-smpolicycontrol")), err[160];
    g5c_resp r;
    int rc = SMF_PEER_FAIL;
    const g5c_json *amb = g5c_json_get(cfg, "sessionAmbr"), *q = g5c_json_get(cfg, "5gQosProfile");
    g5c_json_set_str(b, "supi", ss->supi);
    g5c_json_set_int(b, "pduSessionId", ss->psi);
    g5c_json_set_str(b, "pduSessionType", ss->pdu_type == 1 ? "IPV4" : ss->pdu_type == 2 ? "IPV6" : "IPV4V6");
    g5c_json_set_str(b, "dnn", ss->dnn);
    g5c_json_set_str(b, "notificationUri", notif);
    g5c_json_set(b, "sliceInfo", snssai_json(ss->sst, ss->has_sd, ss->sd));
    if (g5c_json_is(amb, G5C_J_OBJECT))
        g5c_json_set(b, "subsSessAmbr", g5c_json_dup(amb));
    if (g5c_json_is(q, G5C_J_OBJECT))
        g5c_json_set(b, "subsDefQos", g5c_json_dup(q));
    if (ss->has4) {
        char ip[16];
        snprintf(ip, sizeof ip, "%u.%u.%u.%u", ss->ue4[0], ss->ue4[1], ss->ue4[2], ss->ue4[3]);
        g5c_json_set_str(b, "ipv4Address", ip);
    }
    if (g5c_json_is(plmn, G5C_J_OBJECT))
        g5c_json_set(b, "servingNetwork", g5c_json_dup(plmn));
    if (g5c_client_send_json(s->client, "POST", url, b, &r, err, sizeof err) == 0) {
        if (r.status == 201) {
            const char *loc = g5c_resp_header_get(&r, "location");
            *decision = g5c_resp_parse_json(&r);
            if (*decision != NULL && loc != NULL) {
                *resource = g5c_xstrdup(loc);
                rc = 0;
            } else {
                g5c_json_free(*decision);
                *decision = NULL;
                G5C_LOGE("g5c_smf", "PCF answered 201 without a decision or a Location");
            }
        } else {
            G5C_LOGE("g5c_smf", "PCF SM policy create answered %d", r.status);
            rc = r.status;
        }
        g5c_resp_free(&r);
    } else {
        G5C_LOGE("g5c_smf", "PCF SM policy create: %s", err);
    }
    g5c_json_free(b);
    free(url);
    return rc;
}

void smf_pcf_delete(smf *s, const char *resource)
{
    char *url = g5c_xasprintf("%s/delete", resource), err[160];
    g5c_json *b = g5c_json_new_obj();
    g5c_resp r;
    if (g5c_client_send_json(s->client, "POST", url, b, &r, err, sizeof err) == 0) {
        if (r.status != 204 && r.status != 404)
            G5C_LOGW("g5c_smf", "PCF SM policy delete answered %d", r.status);
        g5c_resp_free(&r);
    } else {
        G5C_LOGW("g5c_smf", "PCF SM policy delete: %s", err);
    }
    g5c_json_free(b);
    free(url);
}

/* ---- AMF ----------------------------------------------------------------------------------------------------------------------------------- */

int smf_amf_n1n2(smf *s, const smf_sess *ss, const uint8_t *n1, size_t n1len, const char *n2_type, const uint8_t *n2, size_t n2len)
{
    g5c_json *j = g5c_json_new_obj();
    g5c_mp_part parts[3];
    size_t np = 1;
    g5c_bytes body;
    char *ct = NULL, *jtxt, err[160];
    g5c_resp r;
    int rc = SMF_PEER_FAIL;
    g5c_kv hdr = {"accept", "application/json"};
    g5c_json_set_int(j, "pduSessionId", ss->psi);
    if (n1len > 0) {
        g5c_json *c = g5c_json_set(j, "n1MessageContainer", g5c_json_new_obj());
        g5c_json_set_str(c, "n1MessageClass", "SM");
        g5c_json_set_str(g5c_json_set(c, "n1MessageContent", g5c_json_new_obj()), "contentId", "n1SmMsg");
    }
    if (n2len > 0) {
        g5c_json *c = g5c_json_set(j, "n2InfoContainer", g5c_json_new_obj()), *sm, *ic;
        g5c_json_set_str(c, "n2InformationClass", "SM");
        sm = g5c_json_set(c, "smInfo", g5c_json_new_obj());
        g5c_json_set_int(sm, "pduSessionId", ss->psi);
        ic = g5c_json_set(sm, "n2InfoContent", g5c_json_new_obj());
        g5c_json_set_str(ic, "ngapIeType", n2_type);
        g5c_json_set_str(g5c_json_set(ic, "ngapData", g5c_json_new_obj()), "contentId", "n2SmInfo");
        {
            g5c_json *sn = g5c_json_set(sm, "sNssai", g5c_json_new_obj());
            g5c_json_set_int(sn, "sst", ss->sst);
            if (ss->has_sd) {
                char hex[7];
                snprintf(hex, sizeof hex, "%06X", ss->sd);
                g5c_json_set_str(sn, "sd", hex);
            }
        }
    }
    jtxt = g5c_json_to_string(j, NULL);
    g5c_json_free(j);
    parts[0] = (g5c_mp_part){NULL, "application/json", (const uint8_t *)jtxt, strlen(jtxt)};
    if (n1len > 0)
        parts[np++] = (g5c_mp_part){"n1SmMsg", "application/vnd.3gpp.5gnas", n1, n1len};
    if (n2len > 0)
        parts[np++] = (g5c_mp_part){"n2SmInfo", "application/vnd.3gpp.ngap", n2, n2len};
    g5c_bytes_init(&body);
    if (g5c_mp_build(parts, np, &body, &ct) == 0) {
        char *url = g5c_xstrdup(ss->amf_n1n2_url);
        if (g5c_client_request(s->client, "POST", url, &hdr, 1, ct, body.data, body.len, &r, err, sizeof err) == 0) {
            rc = (r.status == 200 || r.status == 202) ? 0 : r.status;
            if (rc != 0) {
                G5C_LOGE("g5c_smf", "AMF N1N2MessageTransfer answered %d", r.status);
            }
            g5c_resp_free(&r);
        } else {
            G5C_LOGE("g5c_smf", "AMF N1N2MessageTransfer: %s", err);
        }
        free(url);
    }
    g5c_bytes_free(&body);
    free(ct);
    free(jtxt);
    return rc;
}

void smf_amf_status_notify(smf *s, const char *uri, const char *status, const char *cause)
{
    g5c_json *b = g5c_json_new_obj(), *si = g5c_json_set(b, "statusInfo", g5c_json_new_obj());
    char err[160];
    g5c_resp r;
    if (uri == NULL) {
        g5c_json_free(b);
        return;
    }
    g5c_json_set_str(si, "resourceStatus", status);
    if (cause != NULL)
        g5c_json_set_str(si, "cause", cause);
    if (g5c_client_send_json(s->client, "POST", uri, b, &r, err, sizeof err) == 0)
        g5c_resp_free(&r);
    else
        G5C_LOGW("g5c_smf", "AMF status notification: %s", err);
    g5c_json_free(b);
}

/* ---- NRF discovery ------------------------------------------------------------------------------------------------------------------------- */

static char *root_of_profile(const g5c_json *p)
{
    const g5c_json *svcs = g5c_json_get(p, "nfServices");
    for (size_t i = 0; i < g5c_json_len(svcs); i++) {
        const g5c_json *sv = g5c_json_at(svcs, i), *eps;
        const char *name = g5c_json_get_str(sv, "serviceName"), *scheme = g5c_json_get_str(sv, "scheme");
        if (name == NULL || strcmp(name, "namf-comm") != 0)
            continue;
        eps = g5c_json_get(sv, "ipEndPoints");
        for (size_t k = 0; k < g5c_json_len(eps); k++) {
            const g5c_json *ep = g5c_json_at(eps, k);
            const char *ip = g5c_json_get_str(ep, "ipv4Address");
            int64_t port = 0;
            if (ip != NULL && g5c_json_get_int(ep, "port", &port) && port > 0 && port < 65536)
                return g5c_xasprintf("%s://%s:%lld", scheme != NULL ? scheme : "http", ip, (long long)port);
        }
        {   /* no endpoint listed: the service's fqdn / apiPrefix, or the profile's address */
            const char *fq = g5c_json_get_str(sv, "fqdn");
            if (fq != NULL)
                return g5c_xasprintf("%s://%s", scheme != NULL ? scheme : "http", fq);
        }
    }
    return NULL;
}

char *smf_nrf_amf_root(smf *s, const char *id)
{
    char *url, *root = NULL, err[160];
    g5c_resp r;
    double now = g5c_now_seconds();
    int slot = -1;
    if (s->nrf == NULL || id == NULL || strlen(id) >= 40)
        return NULL;
    pthread_mutex_lock(&s->cmu);
    for (int i = 0; i < 4; i++)
        if (s->amf_cache[i].root != NULL && strcmp(s->amf_cache[i].id, id) == 0 && s->amf_cache[i].expires > now) {
            root = g5c_xstrdup(s->amf_cache[i].root);
            break;
        }
    pthread_mutex_unlock(&s->cmu);
    if (root != NULL)
        return root;
    {
        char *ide = pct_encode(id);
        url = g5c_xasprintf("%s/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF&target-nf-instance-id=%s", s->nrf, ide);
        free(ide);
    }
    if (g5c_client_get(s->client, url, &r, err, sizeof err) != 0) {
        G5C_LOGW("g5c_smf", "NRF discovery of AMF %s: %s", id, err);
        free(url);
        return NULL;
    }
    free(url);
    if (r.status == 200) {
        g5c_json *j = g5c_resp_parse_json(&r);
        const g5c_json *list = g5c_json_get(j, "nfInstances");
        for (size_t i = 0; i < g5c_json_len(list) && root == NULL; i++) {
            const g5c_json *p = g5c_json_at(list, i);
            const char *pid = g5c_json_get_str(p, "nfInstanceId");
            if (pid == NULL || strcmp(pid, id) == 0)
                root = root_of_profile(p);
        }
        g5c_json_free(j);
    } else {
        G5C_LOGW("g5c_smf", "NRF discovery of AMF %s answered %d", id, r.status);
    }
    g5c_resp_free(&r);
    if (root != NULL) {
        pthread_mutex_lock(&s->cmu);
        for (int i = 0; i < 4 && slot < 0; i++)
            if (s->amf_cache[i].root == NULL || strcmp(s->amf_cache[i].id, id) == 0 || s->amf_cache[i].expires <= now)
                slot = i;
        if (slot < 0)
            slot = (int)(((uint64_t)now) % 4);
        free(s->amf_cache[slot].root);
        snprintf(s->amf_cache[slot].id, sizeof s->amf_cache[slot].id, "%s", id);
        s->amf_cache[slot].root = g5c_xstrdup(root);
        s->amf_cache[slot].expires = now + 60;
        pthread_mutex_unlock(&s->cmu);
    }
    return root;
}
