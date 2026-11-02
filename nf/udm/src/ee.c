#define _DEFAULT_SOURCE
#define _XOPEN_SOURCE 700
/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Nudm_EventExposure (TS 29.503 clause 5.5): an NF or AF subscribes at the UDM to events of a UE (or of any UE); the UDM subscribes at the AMF that serves the UE (Namf_EventExposure) and
 * turns the AMF's reports into MonitoringReports for the subscriber's callbackReference.
 *
 * Events: LOSS_OF_CONNECTIVITY, UE_CONNECTION_MANAGEMENT_STATE, LOCATION_REPORTING, UE_REACHABILITY_FOR_DATA (the ones the AMF can report); any other type is answered 501.
 * Identities: a SUPI, a GPSI (msisdn-... / extid-..., resolved through the UDR) or anyUE (the AMF from `ee.amf_uri` or found through the NRF).
 * Honoured options: immediateFlag (the current state in the answer), reportingOptions.maxNumOfReports and .expiry.
 * Not covered: group identities, subscriptions for a UE that is not registered yet (404 CONTEXT_NOT_FOUND), persistence (subscriptions live in this process, like the AMF's own). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "g5c/config.h"
#include "g5c/udm.h"

#define EE_BASE "/nudm-ee/v1"
#define LOG "g5c_udm"

typedef struct {
    const char *ee, *amf;
} evmap_t;

static const evmap_t EVMAP[] = {
    {"LOSS_OF_CONNECTIVITY", "LOSS_OF_CONNECTIVITY"},
    {"UE_CONNECTION_MANAGEMENT_STATE", "CONNECTIVITY_STATE_REPORT"},
    {"LOCATION_REPORTING", "LOCATION_REPORT"},
    {"UE_REACHABILITY_FOR_DATA", "REACHABILITY_REPORT"},
};
#define NEV (sizeof EVMAP / sizeof EVMAP[0])

static const char *amf_type_of(const char *ee)
{
    for (size_t i = 0; ee != NULL && i < NEV; i++)
        if (strcmp(EVMAP[i].ee, ee) == 0)
            return EVMAP[i].amf;
    return NULL;
}

static const char *ee_type_of(const char *amf)
{
    for (size_t i = 0; amf != NULL && i < NEV; i++)
        if (strcmp(EVMAP[i].amf, amf) == 0)
            return EVMAP[i].ee;
    return NULL;
}

/* ---- persistence: the subscriptions survive a restart of the UDM (the AMF keeps its half) ---------------------------------------------------------------------- */

static void ee_save(udm *u)
{
    char *tmp, *txt;
    FILE *f;
    g5c_json *doc;
    if (u->ee_state_file == NULL)
        return;
    pthread_mutex_lock(&u->mu);
    doc = g5c_json_new_obj();
    g5c_json_set_int(doc, "next", (int64_t)u->next_ee);
    g5c_json_set(doc, "subscriptions", g5c_json_dup(u->ee_subs));
    pthread_mutex_unlock(&u->mu);
    txt = g5c_json_to_string(doc, NULL);
    g5c_json_free(doc);
    tmp = g5c_xasprintf("%s.tmp", u->ee_state_file);
    f = fopen(tmp, "wb");
    if (f != NULL) {
        bool ok = fputs(txt, f) >= 0;
        ok = (fclose(f) == 0) && ok;
        (void)!chmod(tmp, 0600);
        if (!ok || rename(tmp, u->ee_state_file) != 0)
            G5C_LOGW(LOG, "cannot write the event exposure state file %s", u->ee_state_file);
    } else {
        G5C_LOGW(LOG, "cannot write the event exposure state file %s", tmp);
    }
    free(tmp);
    free(txt);
}

void udm_ee_load(udm *u)
{
    size_t n = 0;
    char *txt = g5c_read_file(u->ee_state_file, 1u << 24, &n);
    g5c_json *doc;
    int64_t next = 0;
    if (txt == NULL)
        return; /* no file yet: a first start */
    doc = g5c_json_parse(txt, n, NULL, 0);
    free(txt);
    if (g5c_json_is(g5c_json_get(doc, "subscriptions"), G5C_J_OBJECT)) {
        pthread_mutex_lock(&u->mu);
        g5c_json_free(u->ee_subs);
        u->ee_subs = g5c_json_dup(g5c_json_get(doc, "subscriptions"));
        if (g5c_json_get_int(doc, "next", &next) && next > 0)
            u->next_ee = (uint64_t)next;
        pthread_mutex_unlock(&u->mu);
        G5C_LOGI(LOG, "%zu event exposure subscriptions read from %s", g5c_json_len(u->ee_subs), u->ee_state_file);
    }
    g5c_json_free(doc);
}

static void count(udm *u, const char *name, const char *help, const char *result)
{
    if (result != NULL) {
        g5c_label l = {"result", result};
        g5c_counter_inc(g5c_counter_get(u->metrics, name, help, &l, 1));
    } else {
        g5c_counter_inc(g5c_counter_get(u->metrics, name, help, NULL, 0));
    }
}

/* scheme://host:port of an absolute URI, heap string; NULL when it is not one */
static char *authority_of(const char *uri)
{
    const char *p, *e;
    if (uri == NULL || (p = strstr(uri, "://")) == NULL)
        return NULL;
    e = strchr(p + 3, '/');
    return e != NULL ? g5c_xasprintf("%.*s", (int)(e - uri), uri) : g5c_xstrdup(uri);
}

static bool is_http(const char *s)
{
    return s != NULL && (strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0);
}

/* The root of the AMF to subscribe at: the one that holds the UE's registration (its callback URI names it), else the configured one, else any AMF the NRF knows. */
static char *amf_root_for(udm *u, const char *supi, udr_result *why)
{
    char *root = NULL;
    g5c_json *reg = NULL;
    if (supi != NULL) {
        udr_result r = udm_udr_amf_registration(&u->udr, supi, &reg);
        if (r.kind == UDR_OK)
            root = authority_of(g5c_json_get_str(reg, "deregCallbackUri"));
        else if (why != NULL)
            *why = r;
        g5c_json_free(reg);
        if (root == NULL && u->ee_amf_uri == NULL)
            return NULL;
    }
    if (root == NULL && u->ee_amf_uri != NULL)
        root = g5c_xstrdup(u->ee_amf_uri);
    if (root == NULL && u->udr.disc != NULL)
        root = g5c_disc_root(u->udr.disc, "AMF", "namf-evts", NULL);
    return root;
}

/* ---- translation of the AMF's reports (TS 29.518 ReportList) into MonitoringReports (TS 29.503 6.4.6.2.? MonitoringReport) -------------------------------------------------------- */

static void reports_from_amf(const g5c_json *mc, const g5c_json *rep, g5c_json *out)
{
    const char *amf = g5c_json_get_str(rep, "type"), *ee = ee_type_of(amf), *ts = g5c_json_get_str(rep, "timeStamp");
    char now[21];
    if (ee == NULL || (strcmp(amf, "REACHABILITY_REPORT") == 0 && !(g5c_json_get_str(rep, "reachability") != NULL && strcmp(g5c_json_get_str(rep, "reachability"), "REACHABLE") == 0)))
        return; /* UE_REACHABILITY_FOR_DATA: the UE can be reached now */
    if (ts == NULL) {
        udm_now_iso8601(now);
        ts = now;
    }
    for (size_t i = 0; i < g5c_json_len(mc); i++) {
        const g5c_json *cfg = g5c_json_val_at(mc, i);
        const char *key = g5c_json_key_at(mc, i), *et = g5c_json_get_str(cfg, "eventType");
        char *end = NULL;
        long long ref = strtoll(key, &end, 10);
        g5c_json *m;
        if (et == NULL || strcmp(et, ee) != 0 || end == key || *end != 0)
            continue;
        m = g5c_json_push(out, g5c_json_new_obj());
        g5c_json_set_int(m, "referenceId", ref);
        g5c_json_set_str(m, "eventType", ee);
        if (strcmp(amf, "LOSS_OF_CONNECTIVITY") == 0 && g5c_json_get_str(rep, "lossOfConnectReason") != NULL) {
            g5c_json_set_str(g5c_json_set(m, "report", g5c_json_new_obj()), "lossOfConnectReason", g5c_json_get_str(rep, "lossOfConnectReason"));
        } else if (strcmp(amf, "CONNECTIVITY_STATE_REPORT") == 0 && g5c_json_len(g5c_json_get(rep, "cmInfoList")) > 0) {
            g5c_json_set(g5c_json_set(m, "report", g5c_json_new_obj()), "newCmInfoList", g5c_json_dup(g5c_json_get(rep, "cmInfoList")));
        } else if (strcmp(amf, "LOCATION_REPORT") == 0 && g5c_json_get(rep, "location") != NULL) {
            g5c_json_set(g5c_json_set(m, "report", g5c_json_new_obj()), "location", g5c_json_dup(g5c_json_get(rep, "location")));
        }
        g5c_json_set_str(m, "timeStamp", ts);
    }
}

/* ---- the service ------------------------------------------------------------------------------------------------------------------------------------------------------------- */

static void forget_at_amf(udm *u, const g5c_json *rec)
{
    const char *root = g5c_json_get_str(rec, "amfRoot"), *id = g5c_json_get_str(rec, "amfSub");
    if (root != NULL && id != NULL) {
        char *url = g5c_xasprintf("%s/namf-evts/v1/subscriptions/%s", root, id), err[160];
        g5c_resp r;
        if (g5c_client_request(u->client, "DELETE", url, NULL, 0, G5C_JSON_TYPE, NULL, 0, &r, err, sizeof err) == 0)
            g5c_resp_free(&r);
        free(url);
    }
}

static void create(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    const char *ue = g5c_req_param(req, "ueIdentity"), *cb, *supi = NULL;
    g5c_json *in = g5c_req_json(req, resp), *body, *sub, *evl, *rec, *out, *ar = NULL, *reports;
    const g5c_json *mc, *ro;
    char *root = NULL, *url, err[160], id[24], *notify, supi_buf[48] = "";
    bool imm = false, any = false;
    g5c_resp r;
    udr_result why = {0};
    if (in == NULL)
        return;
    cb = g5c_json_get_str(in, "callbackReference");
    mc = g5c_json_get(in, "monitoringConfigurations");
    ro = g5c_json_get(in, "reportingOptions");
    if (!is_http(cb) || !g5c_json_is(mc, G5C_J_OBJECT) || g5c_json_len(mc) == 0) {
        g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_MISSING", "callbackReference", "callbackReference (an http URI) and monitoringConfigurations are required");
        goto done;
    }
    if (u->ee_self_uri == NULL) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "ee.notify_uri is not configured and the listen address is a wildcard");
        goto done;
    }
    evl = g5c_json_new_arr();
    for (size_t i = 0; i < g5c_json_len(mc); i++) {
        const g5c_json *cfg = g5c_json_val_at(mc, i);
        const char *key = g5c_json_key_at(mc, i), *et = g5c_json_get_str(cfg, "eventType"), *at = amf_type_of(et);
        char *end = NULL;
        bool dup = false, f = false;
        (void)strtoll(key, &end, 10);
        if (et == NULL || end == key || *end != 0) {
            g5c_resp_problem_invalid(resp, 400, "MANDATORY_IE_INCORRECT", "monitoringConfigurations", "keys are reference ids (integers) and each entry needs an eventType");
            g5c_json_free(evl);
            goto done;
        }
        if (at == NULL) {
            g5c_resp_problem_invalid(resp, 501, "UNSUPPORTED_MONITORING_EVENT_TYPE", "eventType",
                                     "supported: LOSS_OF_CONNECTIVITY, UE_CONNECTION_MANAGEMENT_STATE, LOCATION_REPORTING, UE_REACHABILITY_FOR_DATA");
            g5c_json_free(evl);
            goto done;
        }
        for (size_t k = 0; k < g5c_json_len(evl); k++)
            if (strcmp(g5c_json_get_str(g5c_json_at(evl, k), "type"), at) == 0)
                dup = true;
        if (!dup)
            g5c_json_set_str(g5c_json_push(evl, g5c_json_new_obj()), "type", at);
        if (g5c_json_get_bool(cfg, "immediateFlag", &f) && f)
            imm = true;
    }
    /* the UE */
    if (ue != NULL && strcmp(ue, "anyUE") == 0) {
        any = true;
    } else if (ue != NULL && strncmp(ue, "imsi-", 5) == 0) {
        snprintf(supi_buf, sizeof supi_buf, "%s", ue);
    } else if (ue != NULL && (strncmp(ue, "msisdn-", 7) == 0 || strncmp(ue, "extid-", 6) == 0)) {
        g5c_json *idd = NULL;
        udr_result ir = udm_udr_identity(&u->udr, ue, &idd);
        const char *s = ir.kind == UDR_OK ? g5c_json_str(g5c_json_at(g5c_json_get(idd, "supiList"), 0)) : NULL;
        if (s == NULL) {
            if (ir.kind == UDR_OK || ir.kind == UDR_NOT_FOUND)
                g5c_resp_problem_simple(resp, 404, "USER_NOT_FOUND", "no SUPI is known for the identity");
            else
                udm_udr_fail(&ir, "USER_NOT_FOUND", resp);
            g5c_json_free(idd);
            g5c_json_free(evl);
            goto done;
        }
        snprintf(supi_buf, sizeof supi_buf, "%s", s);
        g5c_json_free(idd);
    } else {
        g5c_resp_problem_simple(resp, 501, "UNSUPPORTED_RESOURCE_URI", "ueIdentity: a SUPI, a GPSI (msisdn-/extid-) or anyUE");
        g5c_json_free(evl);
        goto done;
    }
    if (supi_buf[0] != 0)
        supi = supi_buf;
    root = amf_root_for(u, supi, &why);
    if (root == NULL) {
        if (supi != NULL) {
            if (why.kind == UDR_OK)
                why.kind = UDR_NOT_FOUND;
            udm_udr_fail(&why, "CONTEXT_NOT_FOUND", resp); /* no AMF registration: nobody to subscribe at */
        } else
            g5c_resp_problem_simple(resp, 503, "SERVICE_UNAVAILABLE", "no AMF to subscribe at (set ee.amf_uri or register an AMF at the NRF)");
        g5c_json_free(evl);
        goto done;
    }
    pthread_mutex_lock(&u->mu);
    snprintf(id, sizeof id, "%llu", (unsigned long long)u->next_ee++);
    pthread_mutex_unlock(&u->mu);
    notify = g5c_xasprintf("%s" EE_BASE "/amf-notify/%s", u->ee_self_uri, id);
    body = g5c_json_new_obj();
    sub = g5c_json_set(body, "subscription", g5c_json_new_obj());
    g5c_json_set(sub, "eventList", evl);
    g5c_json_set_str(sub, "eventNotifyUri", notify);
    g5c_json_set_str(sub, "notifyCorrelationId", id);
    if (any)
        g5c_json_set_bool(sub, "anyUE", true);
    else
        g5c_json_set_str(sub, "supi", supi);
    if (imm && !any)
        g5c_json_set_bool(sub, "immediateFlag", true);
    url = g5c_xasprintf("%s/namf-evts/v1/subscriptions", root);
    if (g5c_client_send_json(u->client, "POST", url, body, &r, err, sizeof err) != 0) {
        g5c_resp_problem_simple(resp, 503, "SERVICE_UNAVAILABLE", "the AMF is unreachable");
        G5C_LOGW(LOG, "EE subscription: AMF %s unreachable: %s", root, err);
        count(u, "g5c_udm_ee_subscriptions_total", "Nudm_EventExposure subscriptions.", "amf_unreachable");
        goto amf_done;
    }
    if (r.status != 201) {
        g5c_resp_problem_simple(resp, r.status == 501 ? 501 : 500, r.status == 501 ? "UNSUPPORTED_MONITORING_EVENT_TYPE" : "SYSTEM_FAILURE", "the AMF refused the subscription");
        g5c_resp_free(&r);
        count(u, "g5c_udm_ee_subscriptions_total", "Nudm_EventExposure subscriptions.", "amf_refused");
        goto amf_done;
    }
    ar = g5c_resp_parse_json(&r);
    g5c_resp_free(&r);
    if (g5c_json_get_str(ar, "subscriptionId") == NULL) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "the AMF answered without a subscriptionId");
        goto amf_done;
    }
    rec = g5c_json_new_obj();
    g5c_json_set_str(rec, "ue", ue);
    g5c_json_set_str(rec, "cb", cb);
    g5c_json_set_str(rec, "amfRoot", root);
    g5c_json_set_str(rec, "amfSub", g5c_json_get_str(ar, "subscriptionId"));
    g5c_json_set(rec, "mc", g5c_json_dup(mc));
    if (ro != NULL)
        g5c_json_set(rec, "ro", g5c_json_dup(ro));
    g5c_json_set_int(rec, "sent", 0);
    pthread_mutex_lock(&u->mu);
    g5c_json_set(u->ee_subs, id, rec);
    pthread_mutex_unlock(&u->mu);
    ee_save(u);
    out = g5c_json_new_obj();
    {
        g5c_json *es = g5c_json_dup(in);
        g5c_json_set_str(es, "subscriptionId", id);
        g5c_json_set(out, "eeSubscription", es);
    }
    reports = g5c_json_new_arr();
    for (size_t i = 0; i < g5c_json_len(g5c_json_get(ar, "reportList")); i++)
        reports_from_amf(mc, g5c_json_at(g5c_json_get(ar, "reportList"), i), reports);
    if (g5c_json_len(reports) > 0)
        g5c_json_set(out, "eventReports", reports);
    else
        g5c_json_free(reports);
    {
        char *path = g5c_xasprintf(EE_BASE "/%s/ee-subscriptions/%s", ue, id), *loc = g5c_req_url(req, path);
        g5c_resp_json(resp, 201, out);
        g5c_resp_header(resp, "location", loc);
        free(path);
        free(loc);
    }
    g5c_json_free(out);
    count(u, "g5c_udm_ee_subscriptions_total", "Nudm_EventExposure subscriptions.", "created");
    G5C_LOGI(LOG, "EE subscription %s created for %s at %s", id, ue, root);
amf_done:
    g5c_json_free(ar);
    g5c_json_free(body);
    free(url);
    free(notify);
done:
    free(root);
    g5c_json_free(in);
}

static void remove_sub(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    const char *id = g5c_req_param(req, "subscriptionId");
    g5c_json *rec;
    pthread_mutex_lock(&u->mu);
    rec = id != NULL ? g5c_json_detach(u->ee_subs, id) : NULL;
    pthread_mutex_unlock(&u->mu);
    if (rec == NULL) {
        g5c_resp_problem_simple(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such subscription");
        return;
    }
    forget_at_amf(u, rec);
    g5c_json_free(rec);
    ee_save(u);
    g5c_resp_status(resp, 204);
}

static void patch_sub(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    const char *id = g5c_req_param(req, "subscriptionId");
    g5c_json *ops = g5c_req_json(req, resp), *rec;
    int status = 204;
    if (ops == NULL)
        return;
    pthread_mutex_lock(&u->mu);
    rec = id != NULL ? g5c_json_get_mut(u->ee_subs, id) : NULL;
    if (rec == NULL) {
        status = 404;
    } else {
        for (size_t i = 0; i < g5c_json_len(ops); i++) {
            const g5c_json *op = g5c_json_at(ops, i), *v = g5c_json_get(op, "value");
            const char *path = g5c_json_get_str(op, "path"), *opn = g5c_json_get_str(op, "op");
            int64_t n;
            if (path == NULL || opn == NULL || (strcmp(opn, "replace") != 0 && strcmp(opn, "add") != 0)) {
                status = 403;
            } else if (strcmp(path, "/callbackReference") == 0 && is_http(g5c_json_str(v))) {
                g5c_json_set_str(rec, "cb", g5c_json_str(v));
            } else if (strcmp(path, "/reportingOptions/maxNumOfReports") == 0 && g5c_json_int(v, &n) && n > 0) {
                g5c_json *ro = g5c_json_get_mut(rec, "ro");
                if (ro == NULL)
                    ro = g5c_json_set(rec, "ro", g5c_json_new_obj());
                g5c_json_set_int(ro, "maxNumOfReports", n);
            } else if (strcmp(path, "/reportingOptions/expiry") == 0 && g5c_json_str(v) != NULL) {
                g5c_json *ro = g5c_json_get_mut(rec, "ro");
                if (ro == NULL)
                    ro = g5c_json_set(rec, "ro", g5c_json_new_obj());
                g5c_json_set_str(ro, "expiry", g5c_json_str(v));
            } else {
                status = 403; /* the other fields of an EeSubscription are not modifiable here */
            }
        }
    }
    pthread_mutex_unlock(&u->mu);
    if (status == 204) {
        ee_save(u);
        g5c_resp_status(resp, 204);
    } else if (status == 404)
        g5c_resp_problem_simple(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such subscription");
    else
        g5c_resp_problem_simple(resp, 403, "MODIFICATION_NOT_ALLOWED", "only callbackReference and reportingOptions (maxNumOfReports, expiry) can be replaced");
    g5c_json_free(ops);
}

static bool expired(const char *iso)
{
    struct tm t;
    memset(&t, 0, sizeof t);
    if (iso == NULL || strptime(iso, "%Y-%m-%dT%H:%M:%S", &t) == NULL)
        return false;
    return timegm(&t) < time(NULL);
}

/* From the AMF: Namf_EventExposure notification for one of our subscriptions. */
static void amf_notify(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    const char *id = g5c_req_param(req, "subId");
    g5c_json *in = g5c_req_json(req, resp), *rec, *mc = NULL, *arr, *dead = NULL;
    char *cb = NULL;
    int64_t max = 0;
    int64_t sent = 0;
    bool drop = false;
    if (in == NULL)
        return;
    pthread_mutex_lock(&u->mu);
    rec = id != NULL ? g5c_json_get_mut(u->ee_subs, id) : NULL;
    if (rec != NULL) {
        const g5c_json *ro = g5c_json_get(rec, "ro");
        cb = g5c_xstrdup(g5c_json_get_str(rec, "cb"));
        mc = g5c_json_dup(g5c_json_get(rec, "mc"));
        (void)g5c_json_get_int(ro, "maxNumOfReports", &max);
        (void)g5c_json_get_int(rec, "sent", &sent);
        if (expired(g5c_json_get_str(ro, "expiry")))
            drop = true;
    }
    pthread_mutex_unlock(&u->mu);
    if (rec == NULL) {
        g5c_resp_problem_simple(resp, 404, "SUBSCRIPTION_NOT_FOUND", "no such subscription");
        g5c_json_free(in);
        return;
    }
    arr = g5c_json_new_arr();
    if (!drop)
        for (size_t i = 0; i < g5c_json_len(g5c_json_get(in, "reportList")); i++)
            reports_from_amf(mc, g5c_json_at(g5c_json_get(in, "reportList"), i), arr);
    if (g5c_json_len(arr) > 0) {
        g5c_resp r;
        char err[160];
        const char *result = "ok";
        if (g5c_client_send_json(u->client, "POST", cb, arr, &r, err, sizeof err) == 0) {
            if (r.status < 200 || r.status > 299) {
                result = "rejected";
                G5C_LOGW(LOG, "EE subscriber %s rejected a report (%d)", cb, r.status);
            }
            g5c_resp_free(&r);
        } else {
            result = "unreachable";
            G5C_LOGW(LOG, "EE subscriber %s unreachable: %s", cb, err);
        }
        count(u, "g5c_udm_ee_notifications_total", "Nudm_EventExposure reports sent to subscribers.", result);
        sent += (int64_t)g5c_json_len(arr);
        pthread_mutex_lock(&u->mu);
        rec = g5c_json_get_mut(u->ee_subs, id);
        if (rec != NULL)
            g5c_json_set_int(rec, "sent", sent);
        pthread_mutex_unlock(&u->mu);
        ee_save(u);
        if (max > 0 && sent >= max)
            drop = true;
    }
    if (drop) {
        pthread_mutex_lock(&u->mu);
        dead = g5c_json_detach(u->ee_subs, id);
        pthread_mutex_unlock(&u->mu);
        if (dead != NULL) {
            ee_save(u);
            forget_at_amf(u, dead);
            G5C_LOGI(LOG, "EE subscription %s ended (%s)", id, max > 0 && sent >= max ? "maxNumOfReports reached" : "expired");
            g5c_json_free(dead);
        }
    }
    g5c_resp_status(resp, 204);
    g5c_json_free(arr);
    g5c_json_free(mc);
    free(cb);
    g5c_json_free(in);
}

void udm_ee_routes(g5c_router *r, udm *u)
{
    g5c_router_route(r, "POST", EE_BASE "/{ueIdentity}/ee-subscriptions", create, u);
    g5c_router_route(r, "DELETE", EE_BASE "/{ueIdentity}/ee-subscriptions/{subscriptionId}", remove_sub, u);
    g5c_router_route(r, "PATCH", EE_BASE "/{ueIdentity}/ee-subscriptions/{subscriptionId}", patch_sub, u);
    g5c_router_route(r, "POST", EE_BASE "/amf-notify/{subId}", amf_notify, u);
}
