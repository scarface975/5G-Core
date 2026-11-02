/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The AUSF as a consumer of Nudm_UEAuthentication (TS 29.503 clause 5.4): authentication vectors, the recording of the result and its removal. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "priv.h"

void udm_answer_free(udm_answer *r)
{
    g5c_json_free(r->body);
    memset(r, 0, sizeof *r);
}

/* the UDM's apiRoot; NULL when none is configured or registered */
static char *udm_root(ausf *a, const char *supi)
{
    if (a->disc != NULL) {
        g5c_disc_opts o = {0};
        o.supi = supi;
        return g5c_disc_root(a->disc, "UDM", "nudm-ueau", supi != NULL ? &o : NULL);
    }
    return a->udm != NULL ? g5c_xstrdup(a->udm) : NULL;
}

static void forget(ausf *a)
{
    if (a->disc != NULL)
        g5c_disc_forget(a->disc, "UDM"); /* ask the NRF again next time: the instance may be gone */
}

/* one request to the UDM; answer filled in, 0 when a response came back at all */
static int call(ausf *a, const char *supi_hint, const char *method, const char *id, const char *tail, const g5c_json *body, udm_answer *out, g5c_resp *keep)
{
    char *root = udm_root(a, supi_hint), *url, err[160];
    g5c_resp r;
    int rc;
    memset(out, 0, sizeof *out);
    if (root == NULL) {
        out->no_udm = true;
        return -1;
    }
    url = g5c_xasprintf("%s/nudm-ueau/v1/%s%s", root, id, tail);
    free(root);
    rc = g5c_client_send_json(a->client, method, url, body, &r, err, sizeof err);
    free(url);
    if (rc != 0) {
        G5C_LOGW(AUSF_LOG, "UDM unreachable: %s", err);
        forget(a);
        return -1;
    }
    out->status = r.status;
    out->body = g5c_resp_parse_json(&r);
    {
        char *c = g5c_resp_problem_cause(&r);
        if (c != NULL) {
            snprintf(out->cause, sizeof out->cause, "%s", c);
            free(c);
        }
    }
    if (keep != NULL)
        *keep = r;
    else
        g5c_resp_free(&r);
    return 0;
}

void udm_generate(ausf *a, const char *id_in, const char *snn, const g5c_json *resync, udm_answer *out)
{
    g5c_json *body = g5c_json_new_obj();
    g5c_json_set_str(body, "servingNetworkName", snn);
    g5c_json_set_str(body, "ausfInstanceId", a->instance_id);
    if (resync != NULL)
        g5c_json_set(body, "resynchronizationInfo", g5c_json_dup(resync));
    call(a, g5c_starts_with(id_in, "imsi-") ? id_in : NULL, "POST", id_in, "/security-information/generate-auth-data", body, out, NULL);
    g5c_json_free(body);
}

static g5c_json *event_body(ausf *a, const char *snn, const char *auth_type, bool success, bool removal)
{
    char stamp[32];
    time_t t = time(NULL);
    struct tm tm;
    g5c_json *ev = g5c_json_new_obj();
    gmtime_r(&t, &tm);
    strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%SZ", &tm);
    g5c_json_set_str(ev, "nfInstanceId", a->instance_id);
    g5c_json_set_bool(ev, "success", success);
    g5c_json_set_str(ev, "timeStamp", stamp);
    g5c_json_set_str(ev, "authType", auth_type);
    g5c_json_set_str(ev, "servingNetworkName", snn);
    if (removal)
        g5c_json_set_bool(ev, "authRemovalInd", true);
    return ev;
}

int udm_auth_event(ausf *a, const char *supi, const char *snn, const char *auth_type, bool success, char **event_id)
{
    g5c_json *ev = event_body(a, snn, auth_type, success, false);
    udm_answer u;
    g5c_resp r;
    int rc = -1;
    if (event_id != NULL)
        *event_id = NULL;
    if (call(a, supi, "POST", supi, "/auth-events", ev, &u, &r) == 0) {
        if (u.status >= 200 && u.status <= 299) {
            const char *loc = g5c_resp_header_get(&r, "location");
            rc = 0;
            if (loc != NULL && event_id != NULL) {
                const char *slash = strrchr(loc, '/');
                if (slash != NULL && slash[1] != 0)
                    *event_id = g5c_xstrdup(slash + 1);
            }
        } else {
            G5C_LOGW(AUSF_LOG, "UDM refused the authentication event of %s (%d %s)", supi, u.status, u.cause);
        }
        g5c_resp_free(&r);
    }
    udm_answer_free(&u);
    g5c_json_free(ev);
    ausf_count(a, "g5c_ausf_udm_events_total", "Authentication results reported to the UDM.", "result", rc == 0 ? "recorded" : "failed");
    return rc;
}

/* one PUT of the removal; the HTTP status, 0 when the UDM did not answer */
static int put_removal(ausf *a, const char *url, const char *snn, const char *auth_type, bool success)
{
    g5c_json *ev = event_body(a, snn, auth_type, success, true);
    char err[160];
    g5c_resp r;
    int st = 0;
    if (g5c_client_send_json(a->client, "PUT", url, ev, &r, err, sizeof err) == 0) {
        st = r.status;
        g5c_resp_free(&r);
    } else {
        G5C_LOGW(AUSF_LOG, "could not remove an authentication result at the UDM: %s", err);
        forget(a);
    }
    g5c_json_free(ev);
    return st;
}

int udm_auth_removal(ausf *a, const char *supi, const char *snn, const char *auth_type, const char *event_id)
{
    char *root = udm_root(a, supi), *url;
    int st;
    const char *how = "removed";
    if (root == NULL)
        return -1;
    url = g5c_xasprintf("%s/nudm-ueau/v1/%s/auth-events/%s", root, supi, event_id != NULL ? event_id : "unknown");
    free(root);
    /* TS 29.503 6.3.6.2.6: success is false when the result is removed. Open5GS's UDM insists on true next to authRemovalInd (its own AUSF sends that): a UDM that
     * answers 400 gets the second form. */
    st = put_removal(a, url, snn, auth_type, false);
    if (st == 400) {
        st = put_removal(a, url, snn, auth_type, true);
        how = "removed_compat";
    }
    free(url);
    if (st < 200 || st > 299) {
        G5C_LOGW(AUSF_LOG, "UDM refused the removal of the authentication result of %s (%d)", supi, st);
        how = "failed";
    }
    ausf_count(a, "g5c_ausf_udm_removals_total", "Authentication result removals sent to the UDM.", "result", how);
    return st >= 200 && st <= 299 ? 0 : -1;
}

void udm_rg_auth_ctx(ausf *a, const char *suci, bool authenticated, udm_answer *out)
{
    /* TS 29.503 6.3.3.3: GET .../{supiOrSuci}/security-information-rg?authenticated-ind=... */
    call(a, NULL, "GET", suci, authenticated ? "/security-information-rg?authenticated-ind=true" : "/security-information-rg?authenticated-ind=false", NULL, out, NULL);
}
