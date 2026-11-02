/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Subscriber provisioning (/admin/v1, not part of the 3GPP API). Disabled unless an admin token is set.
 * This is the only place plaintext K/OP/OPc is accepted; it is protected before it reaches the UDR. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "g5c/config.h"
#include "g5c/udm.h"
#include "console_html.h"

/* Guard for everything under /admin/: 404 when disabled, 401 without the right bearer token. Other paths pass. */
int udm_admin_guard(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const udm *u = ctx;
    const char *presented;
    if (strncmp(req->path, "/admin/", 7) != 0)
        return 0;
    if (u->admin_token == NULL) {
        g5c_resp_problem_simple(resp, 404, "RESOURCE_NOT_FOUND", NULL);
        return 1;
    }
    presented = g5c_bearer_token(req);
    if (presented != NULL && strlen(presented) == strlen(u->admin_token) &&
        CRYPTO_memcmp(presented, u->admin_token, strlen(presented)) == 0)
        return 0;
    g5c_resp_problem_simple(resp, 401, "UNAUTHORIZED", NULL);
    g5c_resp_header(resp, "www-authenticate", "Bearer");
    return 1;
}

static void bad(g5c_resp *resp, const char *detail)
{
    g5c_resp_problem_simple(resp, 400, "MANDATORY_IE_INCORRECT", detail);
}

static bool hex_n(const char *h, uint8_t *out, size_t n)
{
    return h != NULL && strlen(h) == 2 * n && g5c_hex_decode(h, out, n) == (long)n;
}

static char *lower(const char *s)
{
    char *d = g5c_xstrdup(s);
    for (char *p = d; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    return d;
}

/* ---- request validation (the AdminSubscriber document) ----------------------------------------------------------- */

static int check_obj_keys(const g5c_json *o, const char *const *allowed, const char *where, g5c_resp *resp)
{
    char err[160];
    if (g5c_json_check_keys(o, allowed, where, err, sizeof err) != 0) {
        bad(resp, err);
        return -1;
    }
    return 0;
}

typedef struct {
    int64_t sst;
    const char *sd; /* optional */
} slice_t;

static g5c_json *snssai_json(const slice_t *s)
{
    g5c_json *o = g5c_json_new_obj();
    g5c_json_set_int(o, "sst", s->sst);
    if (s->sd) {
        char *l = lower(s->sd);
        g5c_json_set_str(o, "sd", l);
        free(l);
    }
    return o;
}

static char *snssai_key(const slice_t *s)
{
    if (s->sd) {
        char *l = lower(s->sd), *k = g5c_xasprintf("%lld-%s", (long long)s->sst, l);
        free(l);
        return k;
    }
    return g5c_xasprintf("%lld", (long long)s->sst);
}

static bool str_in(const char *s, const char *const *set)
{
    for (; *set; set++)
        if (strcmp(s, *set) == 0)
            return true;
    return false;
}

#define UDM_MAX_SLICES 64
#define UDM_MAX_DNNS 256

static int cmp_names(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Validate and store a subscriber in the UDR. Fills resp (and returns false) on any failure; true when stored. */
static bool provision(udm *u, const g5c_json *s, const char **supi_out, g5c_resp *resp)
{
    static const char *const k_top[] = {"supi", "k", "opc", "op", "amf", "sqn", "auth_method", "slices", "dnns", "ue_ambr_ul", "ue_ambr_dl", "gpsi", "msisdn", NULL};
    static const char *const k_slice[] = {"sst", "sd", NULL};
    static const char *const k_dnn[] = {"qi5", "ambr_ul", "ambr_dl", "session_types", NULL};
    static const char *const types[] = {"IPV4", "IPV6", "IPV4V6", NULL};
    const char *supi = g5c_json_get_str(s, "supi"), *ks = g5c_json_get_str(s, "k"), *opcs = g5c_json_get_str(s, "opc"),
               *ops = g5c_json_get_str(s, "op"), *amfs = g5c_json_get_str(s, "amf"), *sqns = g5c_json_get_str(s, "sqn"),
               *ambr_ul = g5c_json_get_str(s, "ue_ambr_ul"), *ambr_dl = g5c_json_get_str(s, "ue_ambr_dl"),
               *auth_method = g5c_json_get_str(s, "auth_method");
    const g5c_json *slices = g5c_json_get(s, "slices"), *dnns = g5c_json_get(s, "dnns");
    uint8_t k[16], opc[16], op[16], amf[2];
    uint64_t sqn_v;
    size_t ns = 0, nd = 0;
    slice_t *sl = NULL;
    g5c_json *auth = NULL, *nssai, *am, *dnn_cfgs, *sm, *smf_sel, *sni;
    char *enc_k = NULL, *enc_opc = NULL, *l;
    const char *scheme = NULL, *scheme2 = NULL;
    udr_result r;
    bool ok = false;
    size_t dl;

    *supi_out = supi;
    if (!g5c_json_is(s, G5C_J_OBJECT)) {
        bad(resp, "expected an object");
        return false;
    }
    if (check_obj_keys(s, k_top, "subscriber", resp) != 0)
        return false;
    if (g5c_json_get(s, "auth_method") != NULL && (auth_method == NULL || (strcmp(auth_method, "5G_AKA") != 0 && strcmp(auth_method, "EAP_AKA_PRIME") != 0))) {
        bad(resp, "auth_method must be 5G_AKA or EAP_AKA_PRIME");
        return false;
    }
    if (supi == NULL || ks == NULL) {
        bad(resp, supi == NULL ? "missing field `supi`" : "missing field `k`");
        return false;
    }
    if (g5c_json_get(s, "msisdn") != NULL && (g5c_json_get_str(s, "msisdn") == NULL || strlen(g5c_json_get_str(s, "msisdn")) < 5 || strlen(g5c_json_get_str(s, "msisdn")) > 15 ||
                                              !g5c_is_digits(g5c_json_get_str(s, "msisdn")))) {
        bad(resp, "msisdn must be 5 to 15 digits");
        return false;
    }
    if (g5c_json_get(s, "gpsi") != NULL && (g5c_json_get_str(s, "gpsi") == NULL || (strncmp(g5c_json_get_str(s, "gpsi"), "msisdn-", 7) != 0 && strncmp(g5c_json_get_str(s, "gpsi"), "extid-", 6) != 0) ||
                                            strlen(g5c_json_get_str(s, "gpsi")) > 128)) {
        bad(resp, "gpsi must be msisdn-<digits> or extid-<identifier>@<domain>");
        return false;
    }
    if (strncmp(supi, "imsi-", 5) != 0 || (dl = strlen(supi + 5)) < 6 || dl > 15 || !g5c_is_digits(supi + 5)) {
        bad(resp, "supi must be imsi-<6..15 digits>");
        return false;
    }
    if (!hex_n(ks, k, 16)) {
        bad(resp, "k must be 32 hex characters");
        return false;
    }
    if (opcs != NULL && ops == NULL) {
        if (!hex_n(opcs, opc, 16)) {
            bad(resp, "opc must be 32 hex characters");
            return false;
        }
    } else if (opcs == NULL && ops != NULL) {
        if (!hex_n(ops, op, 16)) {
            bad(resp, "op must be 32 hex characters");
            return false;
        }
        if (g5c_milenage_derive_opc(k, op, opc) != 0) {
            g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", NULL);
            return false;
        }
    } else {
        bad(resp, "give exactly one of opc and op");
        return false;
    }
    if (amfs == NULL)
        amfs = "8000";
    if (sqns == NULL)
        sqns = "000000000000";
    if (ambr_ul == NULL)
        ambr_ul = "1 Gbps";
    if (ambr_dl == NULL)
        ambr_dl = "1 Gbps";
    if (!hex_n(amfs, amf, 2)) {
        bad(resp, "amf must be 4 hex characters");
        return false;
    }
    if (!udm_sqn_from_hex(sqns, &sqn_v)) {
        bad(resp, "sqn must be 12 hex characters");
        return false;
    }

    /* slices (default: sst 1), dnns (default: internet with defaults) */
    if (slices != NULL && !g5c_json_is(slices, G5C_J_ARRAY)) {
        bad(resp, "slices must be an array");
        return false;
    }
    ns = slices ? g5c_json_len(slices) : 1;
    sl = g5c_xcalloc(ns ? ns : 1, sizeof *sl);
    if (slices == NULL) {
        sl[0].sst = 1;
    } else {
        for (size_t i = 0; i < ns; i++) {
            const g5c_json *e = g5c_json_at(slices, i);
            if (!g5c_json_is(e, G5C_J_OBJECT) || check_obj_keys(e, k_slice, "slice", resp) != 0) {
                if (resp->body == NULL)
                    bad(resp, "invalid slice");
                goto out;
            }
            if (!g5c_json_get_int(e, "sst", &sl[i].sst) || sl[i].sst < 0 || sl[i].sst > 255) {
                bad(resp, "slice sst must be 0..=255");
                goto out;
            }
            sl[i].sd = g5c_json_get_str(e, "sd");
            if (g5c_json_get(e, "sd") != NULL && !g5c_json_is(g5c_json_get(e, "sd"), G5C_J_NULL) && sl[i].sd == NULL) {
                bad(resp, "sd must be a string");
                goto out;
            }
        }
    }
    if (dnns != NULL && !g5c_json_is(dnns, G5C_J_OBJECT)) {
        bad(resp, "dnns must be an object");
        goto out;
    }
    nd = dnns ? g5c_json_len(dnns) : 1;
    if (ns == 0 || nd == 0) {
        bad(resp, "at least one slice and one dnn are required");
        goto out;
    }
    if (ns > UDM_MAX_SLICES || nd > UDM_MAX_DNNS) { /* implementation limits, so one subscriber cannot outgrow a UDR request */
        bad(resp, "too many slices or dnns (limits: 64 slices, 256 dnns)");
        goto out;
    }
    for (size_t i = 0; i < ns; i++)
        if (sl[i].sd != NULL && (strlen(sl[i].sd) != 6 || g5c_hex_decode(sl[i].sd, (uint8_t[3]){0}, 3) != 3)) {
            bad(resp, "sd must be 6 hex characters");
            goto out;
        }

    /* build the per-DNN session configuration while validating it */
    dnn_cfgs = g5c_json_new_obj();
    {
        size_t cnt = dnns ? nd : 1;
        /* sorted by DNN name, like the previous BTreeMap */
        const char **names = g5c_xcalloc(cnt, sizeof *names);
        for (size_t i = 0; i < cnt; i++)
            names[i] = dnns ? g5c_json_key_at(dnns, i) : "internet";
        qsort(names, cnt, sizeof *names, cmp_names);
        sni = g5c_json_new_obj();
        for (size_t i = 0; i < cnt; i++) {
            const g5c_json *c = dnns ? g5c_json_get(dnns, names[i]) : NULL, *st = g5c_json_get(c, "session_types");
            int64_t qi5 = 9;
            const char *aul = "1 Gbps", *adl = "1 Gbps";
            g5c_json *e, *pst, *ssc, *qos, *arp, *allowed;
            const char *first;
            if (dnns && (!g5c_json_is(c, G5C_J_OBJECT) || check_obj_keys(c, k_dnn, "dnn", resp) != 0)) {
                if (resp->body == NULL)
                    bad(resp, "invalid dnn configuration");
                free(names);
                g5c_json_free(dnn_cfgs);
                g5c_json_free(sni);
                goto out;
            }
            if (c != NULL) {
                if (g5c_json_get(c, "qi5") != NULL && (!g5c_json_get_int(c, "qi5", &qi5) || qi5 < 0 || qi5 > 255)) {
                    bad(resp, "qi5 must be 0..=255");
                    free(names);
                    g5c_json_free(dnn_cfgs);
                    g5c_json_free(sni);
                    goto out;
                }
                if (g5c_json_get_str(c, "ambr_ul"))
                    aul = g5c_json_get_str(c, "ambr_ul");
                if (g5c_json_get_str(c, "ambr_dl"))
                    adl = g5c_json_get_str(c, "ambr_dl");
            }
            if (names[i][0] == 0 || (st != NULL && (!g5c_json_is(st, G5C_J_ARRAY) || g5c_json_len(st) == 0))) {
                bad(resp, "dnn needs a name and session types from IPV4, IPV6, IPV4V6");
                free(names);
                g5c_json_free(dnn_cfgs);
                g5c_json_free(sni);
                goto out;
            }
            allowed = g5c_json_new_arr();
            if (st == NULL) {
                g5c_json_push_str(allowed, "IPV4");
            } else {
                for (size_t t = 0; t < g5c_json_len(st); t++) {
                    const char *ts = g5c_json_str(g5c_json_at(st, t));
                    if (ts == NULL || !str_in(ts, types)) {
                        bad(resp, "dnn needs a name and session types from IPV4, IPV6, IPV4V6");
                        g5c_json_free(allowed);
                        free(names);
                        g5c_json_free(dnn_cfgs);
                        g5c_json_free(sni);
                        goto out;
                    }
                    g5c_json_push_str(allowed, ts);
                }
            }
            first = g5c_json_str(g5c_json_at(allowed, 0));
            e = g5c_json_set(dnn_cfgs, names[i], g5c_json_new_obj());
            pst = g5c_json_set(e, "pduSessionTypes", g5c_json_new_obj());
            g5c_json_set_str(pst, "defaultSessionType", first);
            g5c_json_set(pst, "allowedSessionTypes", allowed);
            ssc = g5c_json_set(e, "sscModes", g5c_json_new_obj());
            g5c_json_set_str(ssc, "defaultSscMode", "SSC_MODE_1");
            g5c_json_push_str(g5c_json_set(ssc, "allowedSscModes", g5c_json_new_arr()), "SSC_MODE_1");
            qos = g5c_json_set(e, "5gQosProfile", g5c_json_new_obj());
            g5c_json_set_int(qos, "5qi", qi5);
            arp = g5c_json_set(qos, "arp", g5c_json_new_obj());
            g5c_json_set_int(arp, "priorityLevel", 8);
            g5c_json_set_str(arp, "preemptCap", "NOT_PREEMPT");
            g5c_json_set_str(arp, "preemptVuln", "NOT_PREEMPTABLE");
            g5c_json_set_int(qos, "priorityLevel", 80);
            {
                g5c_json *amb = g5c_json_set(e, "sessionAmbr", g5c_json_new_obj());
                g5c_json_set_str(amb, "uplink", aul);
                g5c_json_set_str(amb, "downlink", adl);
            }
        }
        /* SMF selection info: one entry per slice, listing the DNNs */
        for (size_t i = 0; i < ns; i++) {
            char *key = snssai_key(&sl[i]);
            g5c_json *info = g5c_json_set(sni, key, g5c_json_new_obj()),
                     *arr = g5c_json_set(info, "dnnInfos", g5c_json_new_arr());
            for (size_t d = 0; d < cnt; d++)
                g5c_json_set_str(g5c_json_push(arr, g5c_json_new_obj()), "dnn", names[d]);
            free(key);
        }
        free(names);
    }

    /* protect the credentials before they reach the UDR */
    if (udm_protect(&u->keys, k, 16, supi, &enc_k, &scheme) != 0 || udm_protect(&u->keys, opc, 16, supi, &enc_opc, &scheme2) != 0) {
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", NULL);
        g5c_json_free(dnn_cfgs);
        g5c_json_free(sni);
        goto out;
    }
    auth = g5c_json_new_obj();
    g5c_json_set_str(auth, "authenticationMethod", auth_method != NULL ? auth_method : "5G_AKA");
    g5c_json_set_str(auth, "encPermanentKey", enc_k);
    g5c_json_set_str(auth, "protectionParameterId", scheme);
    {
        g5c_json *sq = g5c_json_set(auth, "sequenceNumber", g5c_json_new_obj());
        g5c_json_set_str(sq, "sqnScheme", "NON_TIME_BASED");
        l = lower(sqns);
        g5c_json_set_str(sq, "sqn", l);
        free(l);
        g5c_json_set_int(g5c_json_set(sq, "lastIndexes", g5c_json_new_obj()), "ausf", 0);
    }
    l = lower(amfs);
    g5c_json_set_str(auth, "authenticationManagementField", l);
    free(l);
    g5c_json_set_str(auth, "algorithmId", "milenage");
    g5c_json_set_str(auth, "encOpcKey", enc_opc);
    g5c_json_set_str(auth, "supi", supi);

    am = g5c_json_new_obj();
    {
        g5c_json *ue = g5c_json_set(am, "subscribedUeAmbr", g5c_json_new_obj());
        g5c_json_set_str(ue, "uplink", ambr_ul);
        g5c_json_set_str(ue, "downlink", ambr_dl);
        nssai = g5c_json_set(am, "nssai", g5c_json_new_obj());
        g5c_json_push(g5c_json_set(nssai, "defaultSingleNssais", g5c_json_new_arr()), snssai_json(&sl[0]));
        {
            g5c_json *all = g5c_json_set(nssai, "singleNssais", g5c_json_new_arr());
            for (size_t i = 0; i < ns; i++)
                g5c_json_push(all, snssai_json(&sl[i]));
        }
    }
    sm = g5c_json_new_arr();
    for (size_t i = 0; i < ns; i++) {
        g5c_json *e = g5c_json_push(sm, g5c_json_new_obj());
        g5c_json_set(e, "singleNssai", snssai_json(&sl[i]));
        g5c_json_set(e, "dnnConfigurations", g5c_json_dup(dnn_cfgs));
    }
    smf_sel = g5c_json_new_obj();
    g5c_json_set(smf_sel, "subscribedSnssaiInfos", sni); /* takes ownership */
    g5c_json_free(dnn_cfgs);

    r = udm_udr_put_auth_subscription(&u->udr, supi, auth);
    if (r.kind == UDR_OK)
        r = udm_udr_put_am_data(&u->udr, supi, u->plmn, am);
    if (r.kind == UDR_OK)
        r = udm_udr_put_sm_data(&u->udr, supi, u->plmn, sm);
    if (r.kind == UDR_OK)
        r = udm_udr_put_smf_selection(&u->udr, supi, u->plmn, smf_sel);
    if (r.kind == UDR_OK && (g5c_json_get(s, "gpsi") != NULL || g5c_json_get(s, "msisdn") != NULL)) {
        /* the GPSIs of the subscriber: the NEF finds the SUPI behind an external identity with them */
        g5c_json *idd = g5c_json_new_obj(), *sl2 = g5c_json_set(idd, "supiList", g5c_json_new_arr()), *gl = g5c_json_set(idd, "gpsiList", g5c_json_new_arr());
        g5c_json_push_str(sl2, supi);
        if (g5c_json_get_str(s, "msisdn") != NULL) {
            char *g = g5c_xasprintf("msisdn-%s", g5c_json_get_str(s, "msisdn"));
            g5c_json_push_str(gl, g);
            free(g);
        }
        if (g5c_json_get_str(s, "gpsi") != NULL)
            g5c_json_push_str(gl, g5c_json_get_str(s, "gpsi"));
        r = udm_udr_put_identity(&u->udr, supi, idd);
        g5c_json_free(idd);
    }
    if (r.kind != UDR_OK)
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", NULL);
    else
        ok = true;
    g5c_json_free(am);
    g5c_json_free(sm);
    g5c_json_free(smf_sel);
out:
    if (enc_k)
        OPENSSL_cleanse(enc_k, strlen(enc_k));
    free(enc_k);
    free(enc_opc);
    g5c_json_free(auth);
    OPENSSL_cleanse(k, sizeof k);
    OPENSSL_cleanse(opc, sizeof opc);
    OPENSSL_cleanse(op, sizeof op);
    free(sl);
    return ok;
}

/* ---- routes ------------------------------------------------------------------------------------------------------- */

static void post_subscriber(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    g5c_json *s = g5c_req_json(req, resp), *o;
    const char *supi = NULL;
    if (s == NULL)
        return;
    if (provision(u, s, &supi, resp)) {
        char *path = g5c_xasprintf("/admin/v1/subscribers/%s", supi), *loc = g5c_req_url(req, path);
        G5C_LOGI("g5c_udm", "subscriber %s provisioned", supi);
        G5C_LOGI("g5c_audit", "udm admin: subscriber.provision supi=%s", supi);
        udm_sdm_notify_change(u, supi); /* consumers holding an sdm-subscription for this SUPI learn about the change */
        o = g5c_json_new_obj();
        g5c_json_set_str(o, "supi", supi);
        g5c_resp_json(resp, 201, o);
        g5c_resp_header(resp, "location", loc);
        g5c_json_free(o);
        free(path);
        free(loc);
    }
    g5c_json_free(s);
}

/* POST /admin/v1/subscribers-bulk: an array of up to 1000 subscribers (the /admin/v1/subscribers body each), or {"subscribers": [...]}. Each is checked and stored on its own: one bad record does not stop the
 * others. The answer is 200 with the totals and, in order, {supi, status} per record (201 stored, else the status and detail the single-record call would have given). */
#define UDM_BULK_MAX 1000

static void post_bulk(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    g5c_json *in = g5c_req_json(req, resp), *out, *results;
    const g5c_json *list;
    size_t created = 0, failed = 0, n;
    if (in == NULL)
        return;
    list = g5c_json_is(in, G5C_J_ARRAY) ? in : g5c_json_get(in, "subscribers");
    n = g5c_json_len(list);
    if (!g5c_json_is(list, G5C_J_ARRAY) || n == 0 || n > UDM_BULK_MAX) {
        bad(resp, "an array of 1 to 1000 subscribers is expected");
        g5c_json_free(in);
        return;
    }
    out = g5c_json_new_obj();
    results = g5c_json_set(out, "results", g5c_json_new_arr());
    for (size_t i = 0; i < n; i++) {
        const g5c_json *s = g5c_json_at(list, i);
        g5c_json *r = g5c_json_push(results, g5c_json_new_obj());
        g5c_resp one;
        const char *supi = NULL;
        g5c_resp_init(&one);
        if (provision(u, s, &supi, &one)) {
            G5C_LOGI("g5c_audit", "udm admin: subscriber.provision supi=%s (bulk)", supi);
            udm_sdm_notify_change(u, supi);
            g5c_json_set_str(r, "supi", supi);
            g5c_json_set_int(r, "status", 201);
            created++;
        } else {
            g5c_json *pb = g5c_resp_parse_json(&one);
            const char *detail = g5c_json_get_str(pb, "detail"), *given = g5c_json_get_str(s, "supi");
            g5c_json_set_str(r, "supi", given != NULL ? given : "");
            g5c_json_set_int(r, "status", one.status != 0 ? one.status : 400);
            g5c_json_set_str(r, "detail", detail != NULL ? detail : "refused");
            g5c_json_free(pb);
            failed++;
        }
        g5c_resp_free(&one);
    }
    g5c_json_set_int(out, "total", (int64_t)n);
    g5c_json_set_int(out, "created", (int64_t)created);
    g5c_json_set_int(out, "failed", (int64_t)failed);
    G5C_LOGI("g5c_audit", "udm admin: subscriber.bulk total=%zu created=%zu failed=%zu", n, created, failed);
    g5c_resp_json(resp, 200, out);
    g5c_json_free(out);
    g5c_json_free(in);
}

static void list_subscribers(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    g5c_json *l = NULL;
    udr_result r = udm_udr_list_subscribers(&u->udr, &l);
    (void)req;
    if (r.kind == UDR_OK) {
        g5c_resp_json(resp, 200, l);
        g5c_json_free(l);
    } else {
        udm_udr_fail(&r, "DATA_NOT_FOUND", resp);
    }
}

static void get_subscriber(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    const char *supi = g5c_req_param(req, "supi");
    g5c_json *a = NULL, *am = NULL, *sm = NULL, *o;
    const g5c_json *x;
    udr_result r;
    supi = supi ? supi : "";
    r = udm_udr_auth_subscription(&u->udr, supi, &a); /* credentials are never returned */
    if (r.kind != UDR_OK) {
        udm_udr_fail(&r, "USER_NOT_FOUND", resp);
        return;
    }
    if (udm_udr_am_data(&u->udr, supi, u->plmn, &am).kind != UDR_OK) {
        g5c_json_free(am);
        am = NULL;
    }
    if (udm_udr_sm_data(&u->udr, supi, u->plmn, NULL, NULL, &sm).kind != UDR_OK) {
        g5c_json_free(sm);
        sm = NULL;
    }
    o = g5c_json_new_obj();
    g5c_json_set_str(o, "supi", supi);
    x = g5c_json_get(a, "authenticationMethod");
    g5c_json_set(o, "authenticationMethod", x ? g5c_json_dup(x) : g5c_json_new_null());
    x = g5c_json_get(a, "protectionParameterId");
    g5c_json_set(o, "protectionParameterId", x ? g5c_json_dup(x) : g5c_json_new_null());
    x = g5c_json_get(g5c_json_get(a, "sequenceNumber"), "sqn");
    g5c_json_set(o, "sqn", x ? g5c_json_dup(x) : g5c_json_new_null());
    x = g5c_json_get(a, "authenticationManagementField");
    g5c_json_set(o, "amf", x ? g5c_json_dup(x) : g5c_json_new_null());
    g5c_json_set(o, "amData", am ? am : g5c_json_new_null());
    g5c_json_set(o, "smData", sm ? sm : g5c_json_new_null());
    g5c_resp_json(resp, 200, o);
    g5c_json_free(o);
    g5c_json_free(a);
}

static void delete_subscriber(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    const char *supi = g5c_req_param(req, "supi");
    udr_result r = udm_udr_delete_subscriber(&u->udr, supi ? supi : "");
    if (r.kind == UDR_OK) {
        G5C_LOGI("g5c_audit", "udm admin: subscriber.delete supi=%s", supi ? supi : "");
        g5c_resp_status(resp, 204);
    } else {
        udm_udr_fail(&r, "USER_NOT_FOUND", resp);
    }
}

/* POST /admin/v1/keys/rewrap: every stored K and OPc that only the previous master key opens is protected again with the current one (rotation of the master key).
 * The SQN and everything else of the record stay as they are: only the three protection fields are replaced, through a patch. */
static void rewrap(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    udm *u = ctx;
    g5c_json *list = NULL, *out;
    udr_result r;
    size_t done = 0, current = 0, failed = 0;
    (void)req;
    if (!u->keys.has_master) {
        bad(resp, "no master key is configured");
        return;
    }
    r = udm_udr_list_subscribers(&u->udr, &list);
    if (r.kind != UDR_OK) {
        udm_udr_fail(&r, "DATA_NOT_FOUND", resp);
        return;
    }
    for (size_t i = 0; i < g5c_json_len(list); i++) {
        const g5c_json *e = g5c_json_at(list, i);
        const char *supi = g5c_json_str(e) != NULL ? g5c_json_str(e) : g5c_json_get_str(e, "supi");
        g5c_json *sub = NULL, *patch;
        const char *scheme, *ek, *eo;
        uint8_t k[16], opc[16];
        size_t kl = 0, ol = 0;
        bool pk = false, po = false;
        char *nk = NULL, *no = NULL;
        const char *s1 = NULL, *s2 = NULL;
        udr_result ur;
        if (supi == NULL)
            continue;
        ur = udm_udr_auth_subscription(&u->udr, supi, &sub);
        if (ur.kind != UDR_OK) {
            failed++;
            continue;
        }
        scheme = g5c_json_get_str(sub, "protectionParameterId");
        ek = g5c_json_get_str(sub, "encPermanentKey");
        eo = g5c_json_get_str(sub, "encOpcKey");
        if (ek == NULL || eo == NULL || udm_unprotect_ex(&u->keys, ek, scheme, supi, k, sizeof k, &kl, &pk) != 0 || kl != 16 ||
            udm_unprotect_ex(&u->keys, eo, scheme, supi, opc, sizeof opc, &ol, &po) != 0 || ol != 16) {
            G5C_LOGE("g5c_udm", "%s: stored credentials do not open with the current or the previous master key", supi);
            failed++;
            g5c_json_free(sub);
            continue;
        }
        if (!pk && !po && scheme != NULL && strcmp(scheme, UDM_PROT_AES256GCM) == 0) {
            current++;
            g5c_json_free(sub);
            OPENSSL_cleanse(k, sizeof k);
            OPENSSL_cleanse(opc, sizeof opc);
            continue;
        }
        if (udm_protect(&u->keys, k, 16, supi, &nk, &s1) != 0 || udm_protect(&u->keys, opc, 16, supi, &no, &s2) != 0) {
            failed++;
        } else {
            const char *paths[3] = {"/encPermanentKey", "/encOpcKey", "/protectionParameterId"};
            const char *vals[3] = {nk, no, s1};
            patch = g5c_json_new_arr();
            for (int j = 0; j < 3; j++) {
                g5c_json *op = g5c_json_push(patch, g5c_json_new_obj());
                g5c_json_set_str(op, "op", "replace");
                g5c_json_set_str(op, "path", paths[j]);
                g5c_json_set_str(op, "value", vals[j]);
            }
            ur = udm_udr_patch_auth_subscription(&u->udr, supi, patch);
            g5c_json_free(patch);
            if (ur.kind == UDR_OK) {
                done++;
                G5C_LOGI("g5c_audit", "udm admin: keys.rewrap supi=%s", supi);
            } else {
                failed++;
            }
        }
        if (nk != NULL)
            OPENSSL_cleanse(nk, strlen(nk));
        free(nk);
        free(no);
        OPENSSL_cleanse(k, sizeof k);
        OPENSSL_cleanse(opc, sizeof opc);
        g5c_json_free(sub);
    }
    g5c_json_free(list);
    out = g5c_json_new_obj();
    g5c_json_set_int(out, "rewrapped", (int64_t)done);
    g5c_json_set_int(out, "alreadyCurrent", (int64_t)current);
    g5c_json_set_int(out, "failed", (int64_t)failed);
    g5c_resp_json(resp, failed == 0 ? 200 : 207, out);
    g5c_json_free(out);
}

/* GET /console: the operator console (deploy/console/index.html), a single page that uses the admin API of this function. It is served only when the admin API is enabled; the page itself holds nothing
 * secret, and its content security policy lets it run only its own script and talk only to this server. A browser needs TLS to speak to the function: import the operator certificate. */
static void console_page(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    const udm *u = ctx;
    (void)req;
    if (u->admin_token == NULL) {
        g5c_resp_problem_simple(resp, 404, "RESOURCE_NOT_FOUND", NULL);
        return;
    }
    g5c_resp_content(resp, 200, "text/html; charset=utf-8", (const char *)UDM_CONSOLE_HTML, UDM_CONSOLE_HTML_LEN);
    g5c_resp_header(resp, "content-security-policy", UDM_CONSOLE_CSP);
    g5c_resp_header(resp, "x-frame-options", "DENY");
    g5c_resp_header(resp, "x-content-type-options", "nosniff");
    g5c_resp_header(resp, "referrer-policy", "no-referrer");
    g5c_resp_header(resp, "cache-control", "no-store");
}

void udm_admin_routes(g5c_router *r, udm *u)
{
    g5c_router_route(r, "GET", "/console", console_page, u);
    g5c_router_route(r, "POST", "/admin/v1/subscribers", post_subscriber, u);
    g5c_router_route(r, "POST", "/admin/v1/subscribers-bulk", post_bulk, u);
    g5c_router_route(r, "GET", "/admin/v1/subscribers", list_subscribers, u);
    g5c_router_route(r, "GET", "/admin/v1/subscribers/{supi}", get_subscriber, u);
    g5c_router_route(r, "DELETE", "/admin/v1/subscribers/{supi}", delete_subscriber, u);
    g5c_router_route(r, "POST", "/admin/v1/keys/rewrap", rewrap, u);
}
