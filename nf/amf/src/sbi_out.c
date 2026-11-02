/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The AMF as an SBI consumer: Nnrf_NFDiscovery, Nausf_UEAuthentication, Nudm_UEContextManagement, Nudm_SubscriberDataManagement and Npcf_AMPolicyControl */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "priv.h"

static char *pct(const char *s)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t n = strlen(s);
    char *o = g5c_xmalloc(n * 3 + 1), *p = o;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '.' || c == '_' || c == '~') {
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

/* ---- discovery ---- */

/* The apiRoot of a peer: its configured address, or the one the NRF gives (the shared discovery client caches it for the validity period). */
char *amf_nf_root(amf *a, const char *nf_type, const char *service, const nas_snssai *s, const char *dnn)
{
    const char *conf = NULL;
    g5c_disc_opts o;
    char *root, snj[64];
    if (strcmp(nf_type, "AUSF") == 0)
        conf = a->cfg.ausf;
    else if (strcmp(nf_type, "UDM") == 0)
        conf = a->cfg.udm;
    else if (strcmp(nf_type, "PCF") == 0)
        conf = a->cfg.pcf;
    else if (strcmp(nf_type, "SMF") == 0)
        conf = a->cfg.smf;
    else if (strcmp(nf_type, "NSSF") == 0)
        conf = a->cfg.nssf;
    if (conf != NULL)
        return g5c_xstrdup(conf);
    if (a->nrf_disc == NULL)
        return NULL;
    memset(&o, 0, sizeof o);
    o.dnn = dnn;
    if (s != NULL) {
        if (s->has_sd)
            snprintf(snj, sizeof snj, "[{\"sst\":%u,\"sd\":\"%06X\"}]", (unsigned)s->sst, (unsigned)(s->sd & 0xffffffu));
        else
            snprintf(snj, sizeof snj, "[{\"sst\":%u}]", (unsigned)s->sst);
        o.snssai_json = snj;
    }
    root = g5c_disc_root(a->nrf_disc, nf_type, service, &o);
    if (root == NULL)
        G5C_LOGW(AMF_LOG, "NRF discovery of %s%s%s found nothing", nf_type, service != NULL ? " / " : "", service != NULL ? service : "");
    return root;
}

/* ---- NSSF ---- */

static g5c_json *sn_obj(const nas_snssai *s)
{
    g5c_json *o = g5c_json_new_obj();
    g5c_json_set_int(o, "sst", s->sst);
    if (s->has_sd) {
        char *sd = g5c_xasprintf("%06X", (unsigned)(s->sd & 0xffffffu));
        g5c_json_set_str(o, "sd", sd);
        free(sd);
    }
    return o;
}

static size_t sn_list_from(const g5c_json *arr, const char *wrapper, nas_snssai *out, size_t cap)
{
    size_t n = 0;
    for (size_t i = 0; i < g5c_json_len(arr) && n < cap; i++) {
        const g5c_json *e = g5c_json_at(arr, i);
        nas_snssai s;
        if (wrapper != NULL)
            e = g5c_json_get(e, wrapper);
        if (e != NULL && amf_snssai_from_json(e, &s) && !amf_snssai_in(out, n, &s))
            out[n++] = s;
    }
    return n;
}

/* Nnssf_NSSelection for a registration (TS 29.531 5.2.2.2.2) */
int amf_nssf_registration(amf *a, const amf_ue *u, const amf_tai *tai, const nas_snssai *req, size_t nreq, nas_snssai *allowed, size_t *nallowed, nas_snssai *rejected, size_t *nrej)
{
    char *root = amf_nf_root(a, "NSSF", "nnssf-nsselection", NULL, NULL), *url, *info_txt, *info_enc, *tai_txt, *tai_enc, err[160];
    g5c_json *info = g5c_json_new_obj(), *sub, *rq, *tj = g5c_json_new_obj();
    g5c_resp r;
    int rc = -1;
    *nallowed = *nrej = 0;
    if (root == NULL) {
        g5c_json_free(info);
        g5c_json_free(tj);
        return -1;
    }
    sub = g5c_json_set(info, "subscribedNssai", g5c_json_new_arr());
    for (size_t i = 0; i < u->nsubscribed; i++) {
        g5c_json *e = g5c_json_push(sub, g5c_json_new_obj());
        g5c_json_set(e, "subscribedSnssai", sn_obj(&u->subscribed[i]));
        g5c_json_set_bool(e, "defaultIndication", i < u->ndefault);
    }
    if (nreq > 0) {
        rq = g5c_json_set(info, "requestedNssai", g5c_json_new_arr());
        for (size_t i = 0; i < nreq; i++)
            g5c_json_push(rq, sn_obj(&req[i]));
    }
    amf_tai_to_json(tai, tj, "t");
    info_txt = g5c_json_to_string(info, NULL);
    tai_txt = g5c_json_to_string(g5c_json_get(tj, "t"), NULL);
    info_enc = pct(info_txt);
    tai_enc = pct(tai_txt);
    url = g5c_xasprintf("%s/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=%s&slice-info-request-for-registration=%s&tai=%s", root, a->nf->instance_id, info_enc, tai_enc);
    if (g5c_client_get(a->client, url, &r, err, sizeof err) == 0) {
        if (r.status == 200) {
            g5c_json *j = g5c_resp_parse_json(&r);
            const g5c_json *list = g5c_json_get(j, "allowedNssaiList"), *l0 = g5c_json_at(list, 0);
            nas_snssai tmp[AMF_MAX_SLICE];
            size_t nt = sn_list_from(g5c_json_get(l0, "allowedSnssaiList"), "allowedSnssai", tmp, AMF_MAX_SLICE);
            for (size_t i = 0; i < nt; i++)
                if (amf_snssai_in(a->cfg.slices, a->cfg.nslices, &tmp[i]))
                    allowed[(*nallowed)++] = tmp[i];
            *nrej = sn_list_from(g5c_json_get(j, "rejectedNssaiInPlmn"), NULL, rejected, AMF_MAX_SLICE);
            if (*nrej < AMF_MAX_SLICE) {
                nas_snssai ta[AMF_MAX_SLICE];
                size_t nta = sn_list_from(g5c_json_get(j, "rejectedNssaiInTa"), NULL, ta, AMF_MAX_SLICE);
                for (size_t i = 0; i < nta && *nrej < AMF_MAX_SLICE; i++)
                    if (!amf_snssai_in(rejected, *nrej, &ta[i]))
                        rejected[(*nrej)++] = ta[i];
            }
            rc = *nallowed > 0 ? 0 : 1;
            g5c_json_free(j);
        } else if (r.status == 403) {
            rc = 1; /* SNSSAI_NOT_SUPPORTED: none of the requested or subscribed slices is available here */
        } else {
            G5C_LOGW(AMF_LOG, "NSSF slice selection for %s: status %d", u->supi, r.status);
        }
        g5c_resp_free(&r);
    } else {
        G5C_LOGW(AMF_LOG, "NSSF slice selection: %s", err);
    }
    amf_count(a, "g5c_amf_nssf_selections_total", "Slice selections by the NSSF, by outcome.", "result", rc == 0 ? "ok" : rc == 1 ? "refused" : "unavailable");
    free(url);
    free(info_enc);
    free(tai_enc);
    free(info_txt);
    free(tai_txt);
    g5c_json_free(info);
    g5c_json_free(tj);
    free(root);
    return rc;
}

/* Nnssf_NSSelection for a PDU session establishment (TS 29.531 5.2.2.2.3): is the S-NSSAI served in this tracking area, and which NSI */
int amf_nssf_pdu_session(amf *a, const nas_snssai *sn, const amf_tai *tai)
{
    char *root = amf_nf_root(a, "NSSF", "nnssf-nsselection", NULL, NULL), *url, *info_txt, *info_enc, *tai_txt, *tai_enc, err[160];
    g5c_json *info = g5c_json_new_obj(), *tj = g5c_json_new_obj();
    g5c_resp r;
    int rc = -1;
    if (root == NULL) {
        g5c_json_free(info);
        g5c_json_free(tj);
        return -1;
    }
    g5c_json_set(info, "sNssai", sn_obj(sn));
    g5c_json_set_str(info, "roamingIndication", "NON_ROAMING");
    amf_tai_to_json(tai, tj, "t");
    info_txt = g5c_json_to_string(info, NULL);
    tai_txt = g5c_json_to_string(g5c_json_get(tj, "t"), NULL);
    info_enc = pct(info_txt);
    tai_enc = pct(tai_txt);
    url = g5c_xasprintf("%s/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=%s&slice-info-request-for-pdu-session=%s&tai=%s", root, a->nf->instance_id, info_enc, tai_enc);
    if (g5c_client_get(a->client, url, &r, err, sizeof err) == 0) {
        if (r.status == 200)
            rc = 0;
        else if (r.status == 403)
            rc = 1;
        else
            G5C_LOGW(AMF_LOG, "NSSF slice selection for a PDU session: status %d", r.status);
        g5c_resp_free(&r);
    } else {
        G5C_LOGW(AMF_LOG, "NSSF slice selection for a PDU session: %s", err);
    }
    amf_count(a, "g5c_amf_nssf_pdu_session_checks_total", "Slice checks by the NSSF for PDU session establishments, by outcome.", "result", rc == 0 ? "ok" : rc == 1 ? "refused" : "unavailable");
    free(url);
    free(info_enc);
    free(tai_enc);
    free(info_txt);
    free(tai_txt);
    g5c_json_free(info);
    g5c_json_free(tj);
    free(root);
    return rc;
}

/* ---- AUSF ---- */

int amf_ausf_start(amf *a, const char *id, const uint8_t *resync_rand, const uint8_t *auts, amf_authv *out, int *http)
{
    char *root = amf_nf_root(a, "AUSF", "nausf-auth", NULL, NULL), *url, err[160];
    g5c_json *b = g5c_json_new_obj();
    g5c_resp r;
    int rc = -1;
    *http = 0;
    if (root == NULL) {
        g5c_json_free(b);
        return -1;
    }
    g5c_json_set_str(b, "supiOrSuci", id);
    g5c_json_set_str(b, "servingNetworkName", a->snn);
    if (resync_rand != NULL && auts != NULL) {
        char *rh = g5c_hex_encode(resync_rand, 16), *ah = g5c_hex_encode(auts, 14);
        g5c_json *ri = g5c_json_set(b, "resynchronizationInfo", g5c_json_new_obj());
        g5c_json_set_str(ri, "rand", rh);
        g5c_json_set_str(ri, "auts", ah);
        free(rh);
        free(ah);
    }
    url = g5c_xasprintf("%s/nausf-auth/v1/ue-authentications", root);
    if (g5c_client_send_json(a->client, "POST", url, b, &r, err, sizeof err) == 0) {
        *http = r.status;
        if (r.status == 201) {
            g5c_json *j = g5c_resp_parse_json(&r);
            const g5c_json *d = g5c_json_get(j, "5gAuthData");
            const char *href = g5c_json_get_str(g5c_json_get(g5c_json_get(j, "_links"), "5g-aka"), "href"), *loc = g5c_resp_header_get(&r, "location");
            const char *rd = g5c_json_get_str(d, "rand"), *au = g5c_json_get_str(d, "autn"), *hx = g5c_json_get_str(d, "hxresStar");
            const char *at = g5c_json_get_str(j, "authType"), *eap_b64 = g5c_json_str(d), *eap_href = g5c_json_get_str(g5c_json_get(g5c_json_get(j, "_links"), "eap-session"), "href");
            out->eap = false;
            if (at != NULL && strcmp(at, "EAP_AKA_PRIME") == 0) {
                /* EAP-AKA' (TS 29.509 5.2.2.2.3): 5gAuthData is the EAP-Request/AKA'-Challenge in base64, the link is the eap-session resource */
                long n = eap_b64 != NULL ? g5c_base64_decode(eap_b64, out->eap_pkt, sizeof out->eap_pkt) : -1;
                if (n > 8 && (eap_href != NULL || loc != NULL)) {
                    out->eap = true;
                    out->eap_len = (size_t)n;
                    if (eap_href != NULL)
                        snprintf(out->ctx_url, sizeof out->ctx_url, "%s", eap_href);
                    else
                        snprintf(out->ctx_url, sizeof out->ctx_url, "%s/eap-session", loc);
                    rc = 0;
                } else {
                    G5C_LOGE(AMF_LOG, "AUSF answered 201 without a usable EAP-AKA' challenge");
                }
            } else if (rd != NULL && au != NULL && hx != NULL && g5c_hex_decode(rd, out->rand, 16) == 16 && g5c_hex_decode(au, out->autn, 16) == 16 &&
                g5c_hex_decode(hx, out->hxres, 16) == 16 && (href != NULL || loc != NULL)) {
                if (href != NULL) {
                    snprintf(out->ctx_url, sizeof out->ctx_url, "%s", href);
                } else {
                    snprintf(out->ctx_url, sizeof out->ctx_url, "%s/5g-aka-confirmation", loc);
                }
                rc = 0;
            } else {
                G5C_LOGE(AMF_LOG, "AUSF answered 201 without a usable 5G-AKA vector");
            }
            g5c_json_free(j);
        }
        g5c_resp_free(&r);
    } else {
        G5C_LOGE(AMF_LOG, "AUSF: %s", err);
    }
    free(url);
    free(root);
    g5c_json_free(b);
    return rc;
}

int amf_ausf_eap(amf *a, const char *url, const uint8_t *pkt, size_t n, amf_eapr *out, int *http)
{
    g5c_json *b = g5c_json_new_obj();
    g5c_resp r;
    char err[160];
    int rc = -1;
    *http = 0;
    memset(out, 0, sizeof *out);
    if (pkt != NULL && n > 0) {
        char *b64 = g5c_base64_encode(pkt, n);
        g5c_json_set_str(b, "eapPayload", b64);
        free(b64);
    } else {
        g5c_json_set(b, "eapPayload", g5c_json_new_null()); /* nothing came from the UE */
    }
    if (g5c_client_send_json(a->client, "POST", url, b, &r, err, sizeof err) == 0) {
        *http = r.status;
        if (r.status == 200) {
            g5c_json *j = g5c_resp_parse_json(&r);
            const char *pl = g5c_json_get_str(j, "eapPayload"), *res = g5c_json_get_str(j, "authResult"), *s = g5c_json_get_str(j, "supi"), *k = g5c_json_get_str(j, "kSeaf");
            const char *href = g5c_json_get_str(g5c_json_get(g5c_json_get(j, "_links"), "eap-session"), "href");
            long len = pl != NULL ? g5c_base64_decode(pl, out->pkt, sizeof out->pkt) : -1;
            if (len >= 4 && res != NULL) {
                out->len = (size_t)len;
                if (href != NULL)
                    snprintf(out->next_url, sizeof out->next_url, "%s", href);
                if (strcmp(res, "AUTHENTICATION_SUCCESS") == 0) {
                    if (s != NULL && k != NULL && g5c_hex_decode(k, out->kseaf, 32) == 32) {
                        snprintf(out->supi, sizeof out->supi, "%s", s);
                        out->result = 1;
                        rc = 0;
                    }
                } else if (strcmp(res, "AUTHENTICATION_FAILURE") == 0) {
                    out->result = -1;
                    rc = 0;
                } else if (strcmp(res, "AUTHENTICATION_ONGOING") == 0) {
                    out->result = 0;
                    rc = 0;
                }
            }
            g5c_json_free(j);
        }
        g5c_resp_free(&r);
    } else {
        G5C_LOGE(AMF_LOG, "AUSF EAP session: %s", err);
    }
    g5c_json_free(b);
    return rc;
}

void amf_ausf_remove(amf *a, const char *url)
{
    char err[160];
    g5c_resp r;
    if (url == NULL || url[0] == 0)
        return;
    if (g5c_client_request(a->client, "DELETE", url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) == 0) {
        if (r.status != 204 && r.status != 404 && r.status != 405)
            G5C_LOGW(AMF_LOG, "AUSF answered %d to the removal of an authentication result", r.status);
        g5c_resp_free(&r);
    } else {
        G5C_LOGW(AMF_LOG, "removal of an authentication result at the AUSF: %s", err);
    }
}

int amf_ausf_confirm(amf *a, const char *ctx_url, const uint8_t res_star[16], char *supi, size_t supi_cap, uint8_t kseaf[32], bool *success, int *http)
{
    g5c_json *b = g5c_json_new_obj();
    g5c_resp r;
    char err[160], *rh = g5c_hex_encode(res_star, 16);
    int rc = -1;
    *success = false;
    *http = 0;
    g5c_json_set_str(b, "resStar", rh);
    free(rh);
    if (g5c_client_send_json(a->client, "PUT", ctx_url, b, &r, err, sizeof err) == 0) {
        *http = r.status;
        if (r.status == 200) {
            g5c_json *j = g5c_resp_parse_json(&r);
            const char *res = g5c_json_get_str(j, "authResult"), *s = g5c_json_get_str(j, "supi"), *k = g5c_json_get_str(j, "kseaf");
            if (res != NULL && strcmp(res, "AUTHENTICATION_SUCCESS") == 0 && s != NULL && k != NULL && g5c_hex_decode(k, kseaf, 32) == 32) {
                snprintf(supi, supi_cap, "%s", s);
                *success = true;
                rc = 0;
            } else if (res != NULL && strcmp(res, "AUTHENTICATION_FAILURE") == 0) {
                rc = 0;
            }
            g5c_json_free(j);
        }
        g5c_resp_free(&r);
    } else {
        G5C_LOGE(AMF_LOG, "AUSF confirmation: %s", err);
    }
    g5c_json_free(b);
    return rc;
}

/* ---- UDM ---- */

static void amf_id_hex(const amf *a, char out[7])
{
    uint32_t v = (uint32_t)a->cfg.id.region << 16 | (uint32_t)a->cfg.id.set << 6 | a->cfg.id.pointer;
    snprintf(out, 7, "%06X", v);
}

static void plmn_json(const amf *a, g5c_json *parent, const char *key)
{
    g5c_json *p = g5c_json_set(parent, key, g5c_json_new_obj());
    g5c_json_set_str(p, "mcc", a->cfg.mcc);
    g5c_json_set_str(p, "mnc", a->cfg.mnc);
}

int amf_udm_register(amf *a, amf_ue *u)
{
    char *root = amf_nf_root(a, "UDM", "nudm-uecm", NULL, NULL), *url, err[160], idh[7], *cb;
    g5c_json *b = g5c_json_new_obj(), *g;
    g5c_resp r;
    int rc = -1;
    if (root == NULL) {
        g5c_json_free(b);
        return -1;
    }
    amf_id_hex(a, idh);
    cb = amf_cb_uri(a, "/namf-callback/v1/dereg-notify");
    g5c_json_set_str(b, "amfInstanceId", a->instance_id);
    {
        char *full = g5c_xasprintf("%s/%s", cb, u->supi);
        g5c_json_set_str(b, "deregCallbackUri", full);
        free(full);
    }
    g = g5c_json_set(b, "guami", g5c_json_new_obj());
    plmn_json(a, g, "plmnId");
    g5c_json_set_str(g, "amfId", idh);
    g5c_json_set_str(b, "ratType", "NR");
    g5c_json_set_bool(b, "initialRegistrationInd", true);
    if (u->pei[0] != 0)
        g5c_json_set_str(b, "pei", u->pei);
    url = g5c_xasprintf("%s/nudm-uecm/v1/%s/registrations/amf-3gpp-access", root, u->supi);
    if (g5c_client_send_json(a->client, "PUT", url, b, &r, err, sizeof err) == 0) {
        if (r.status == 200 || r.status == 201)
            rc = 0;
        else
            G5C_LOGW(AMF_LOG, "UDM refused the AMF registration of %s (%d)", u->supi, r.status);
        rc = rc == 0 ? 0 : r.status;
        g5c_resp_free(&r);
    } else {
        G5C_LOGE(AMF_LOG, "UDM registration: %s", err);
    }
    free(cb);
    free(url);
    free(root);
    g5c_json_free(b);
    return rc;
}

void amf_udm_deregister(amf *a, amf_ue *u)
{
    char *root = amf_nf_root(a, "UDM", "nudm-uecm", NULL, NULL), *url, err[160];
    g5c_resp r;
    if (root == NULL)
        return;
    url = g5c_xasprintf("%s/nudm-uecm/v1/%s/registrations/amf-3gpp-access", root, u->supi);
    if (g5c_client_request(a->client, "DELETE", url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) == 0) {
        if (r.status != 204 && r.status != 404 && r.status != 403 && r.status != 405)
            G5C_LOGW(AMF_LOG, "UDM de-registration of %s answered %d", u->supi, r.status);
        g5c_resp_free(&r);
    } else {
        G5C_LOGW(AMF_LOG, "UDM de-registration: %s", err);
    }
    free(url);
    free(root);
    u->uecm = false;
}

/* "1 Gbps" style bit rates (TS 29.571 5.5.2) */
bool amf_parse_bitrate(const char *s, uint64_t *out)
{
    char *end;
    double v;
    uint64_t mult = 1;
    if (s == NULL)
        return false;
    v = strtod(s, &end);
    while (*end == ' ')
        end++;
    if (strcmp(end, "bps") == 0)
        mult = 1;
    else if (strcmp(end, "Kbps") == 0)
        mult = 1000ULL;
    else if (strcmp(end, "Mbps") == 0)
        mult = 1000000ULL;
    else if (strcmp(end, "Gbps") == 0)
        mult = 1000000000ULL;
    else if (strcmp(end, "Tbps") == 0)
        mult = 1000000000000ULL;
    else
        return false;
    if (v < 0 || v > 1e15)
        return false;
    *out = (uint64_t)(v * (double)mult);
    return true;
}

/* Access and mobility subscription data: UE-AMBR and the subscribed NSSAI (TS 29.503 5.2.2.2). */
int amf_udm_am_data(amf *a, amf_ue *u)
{
    char *root = amf_nf_root(a, "UDM", "nudm-sdm", NULL, NULL), *url, err[160], *plmn_txt, *plmn_enc;
    g5c_json *p = g5c_json_new_obj();
    g5c_resp r;
    int rc = -1;
    if (root == NULL) {
        g5c_json_free(p);
        return -1;
    }
    g5c_json_set_str(p, "mcc", a->cfg.mcc);
    g5c_json_set_str(p, "mnc", a->cfg.mnc);
    plmn_txt = g5c_json_to_string(p, NULL);
    plmn_enc = pct(plmn_txt);
    url = g5c_xasprintf("%s/nudm-sdm/v2/%s/am-data?plmn-id=%s", root, u->supi, plmn_enc);
    if (g5c_client_get(a->client, url, &r, err, sizeof err) == 0) {
        if (r.status == 200) {
            g5c_json *j = g5c_resp_parse_json(&r);
            const g5c_json *amb = g5c_json_get(j, "subscribedUeAmbr"), *ns = g5c_json_get(j, "nssai"), *def = g5c_json_get(ns, "defaultSingleNssais"),
                           *sing = g5c_json_get(ns, "singleNssais");
            uint64_t v;
            u->ambr_ul = u->ambr_dl = 0;
            if (amf_parse_bitrate(g5c_json_get_str(amb, "uplink"), &v))
                u->ambr_ul = v;
            if (amf_parse_bitrate(g5c_json_get_str(amb, "downlink"), &v))
                u->ambr_dl = v;
            u->nsubscribed = 0;
            for (size_t i = 0; i < g5c_json_len(def) && u->nsubscribed < AMF_MAX_SLICE; i++) {
                nas_snssai s;
                if (amf_snssai_from_json(g5c_json_at(def, i), &s))
                    u->subscribed[u->nsubscribed++] = s;
            }
            u->ndefault = u->nsubscribed;
            /* default S-NSSAIs come first; the rest of the subscribed ones follow */
            for (size_t i = 0; i < g5c_json_len(sing) && u->nsubscribed < AMF_MAX_SLICE; i++) {
                nas_snssai s;
                if (amf_snssai_from_json(g5c_json_at(sing, i), &s) && !amf_snssai_in(u->subscribed, u->nsubscribed, &s))
                    u->subscribed[u->nsubscribed++] = s;
            }
            rc = 0;
            g5c_json_free(j);
        } else {
            G5C_LOGW(AMF_LOG, "UDM subscription data of %s: status %d", u->supi, r.status);
            rc = r.status;
        }
        g5c_resp_free(&r);
    } else {
        G5C_LOGE(AMF_LOG, "UDM subscription data: %s", err);
    }
    free(plmn_enc);
    free(plmn_txt);
    g5c_json_free(p);
    free(url);
    free(root);
    return rc;
}

void amf_udm_sdm_subscribe(amf *a, amf_ue *u)
{
    char *root = amf_nf_root(a, "UDM", "nudm-sdm", NULL, NULL), *url, err[160], *cb;
    g5c_json *b = g5c_json_new_obj();
    g5c_resp r;
    if (root == NULL) {
        g5c_json_free(b);
        return;
    }
    cb = amf_cb_uri(a, "/namf-callback/v1/sdm-notify");
    {
        char *full = g5c_xasprintf("%s/%s", cb, u->supi);
        g5c_json_set_str(b, "callbackReference", full);
        free(full);
    }
    g5c_json_set_str(b, "nfInstanceId", a->instance_id);
    {
        g5c_json *m = g5c_json_set(b, "monitoredResourceUris", g5c_json_new_arr());
        char *res = g5c_xasprintf("/%s/am-data", u->supi);
        g5c_json_push_str(m, res);
        free(res);
    }
    url = g5c_xasprintf("%s/nudm-sdm/v2/%s/sdm-subscriptions", root, u->supi);
    if (g5c_client_send_json(a->client, "POST", url, b, &r, err, sizeof err) == 0) {
        u->sdm_subscribed = r.status == 201;
        if (u->sdm_subscribed && r.body != NULL) {
            char perr[64];
            g5c_json *rb = g5c_json_parse((const char *)r.body, r.body_len, perr, sizeof perr);
            const char *id = g5c_json_get_str(rb, "subscriptionId");
            if (id != NULL && strlen(id) < sizeof u->sdm_sub_id)
                snprintf(u->sdm_sub_id, sizeof u->sdm_sub_id, "%s", id);
            g5c_json_free(rb);
        }
        g5c_resp_free(&r);
    }
    free(cb);
    free(url);
    free(root);
    g5c_json_free(b);
}

void amf_udm_sdm_unsubscribe(amf *a, amf_ue *u)
{
    char *root, *url, err[160];
    g5c_resp r;
    if (u->sdm_sub_id[0] == 0)
        return;
    root = amf_nf_root(a, "UDM", "nudm-sdm", NULL, NULL);
    if (root != NULL) {
        url = g5c_xasprintf("%s/nudm-sdm/v2/%s/sdm-subscriptions/%s", root, u->supi, u->sdm_sub_id);
        if (g5c_client_request(a->client, "DELETE", url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) == 0) {
            if (r.status != 204 && r.status != 404)
                G5C_LOGW(AMF_LOG, "UDM unsubscribe of %s answered %d", u->supi, r.status);
            g5c_resp_free(&r);
        }
        free(url);
        free(root);
    }
    u->sdm_sub_id[0] = 0;
    u->sdm_subscribed = false;
}

/* ---- PCF ---- */

int amf_pcf_create(amf *a, amf_ue *u)
{
    char *root = amf_nf_root(a, "PCF", "npcf-am-policy-control", NULL, NULL), *url, err[160], *cb;
    g5c_json *b = g5c_json_new_obj();
    g5c_resp r;
    int rc = -1;
    if (root == NULL) {
        g5c_json_free(b);
        return 0; /* no PCF in the deployment: no AM policy */
    }
    cb = amf_cb_uri(a, "/namf-callback/v1/am-policy");
    {
        char *full = g5c_xasprintf("%s/%s/update", cb, u->supi);
        g5c_json_set_str(b, "notificationUri", full);
        free(full);
    }
    g5c_json_set_str(b, "supi", u->supi);
    g5c_json_set_str(b, "suppFeat", "0");
    g5c_json_set_str(b, "accessType", "3GPP_ACCESS");
    g5c_json_set_str(b, "ratType", "NR");
    plmn_json(a, b, "servingPlmn");
    if (u->pei[0] != 0)
        g5c_json_set_str(b, "pei", u->pei);
    if (u->has_loc) {
        g5c_json *tmp = g5c_json_new_obj(), *v;
        amf_location_json(u->conn, u, tmp);
        v = g5c_json_detach(tmp, "ueLocation");
        if (v != NULL)
            g5c_json_set(b, "userLoc", v);
        g5c_json_free(tmp);
    }
    url = g5c_xasprintf("%s/npcf-am-policy-control/v1/policies", root);
    if (g5c_client_send_json(a->client, "POST", url, b, &r, err, sizeof err) == 0) {
        if (r.status == 201) {
            const char *loc = g5c_resp_header_get(&r, "location");
            if (loc != NULL)
                snprintf(u->pcf_url, sizeof u->pcf_url, "%s", loc);
            rc = 0;
        } else {
            G5C_LOGW(AMF_LOG, "PCF AM policy for %s: status %d", u->supi, r.status);
            rc = r.status;
        }
        g5c_resp_free(&r);
    } else {
        G5C_LOGE(AMF_LOG, "PCF AM policy: %s", err);
    }
    free(cb);
    free(url);
    free(root);
    g5c_json_free(b);
    return rc;
}

void amf_pcf_delete(amf *a, amf_ue *u)
{
    char err[160];
    g5c_resp r;
    if (u->pcf_url[0] == 0)
        return;
    if (g5c_client_request(a->client, "DELETE", u->pcf_url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) == 0)
        g5c_resp_free(&r);
    else
        G5C_LOGW(AMF_LOG, "PCF AM policy delete: %s", err);
    u->pcf_url[0] = 0;
}
