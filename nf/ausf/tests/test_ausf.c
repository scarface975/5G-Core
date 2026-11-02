/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* AUSF end to end: udr + UDM + AUSF on real sockets, driven by a simulated UE that performs the real USIM-side checks (AUTN MAC, SQN freshness, AUTS
 * generation) with our own Milenage implementation, for 5G AKA and EAP-AKA'; plus SoR and UPU protection, the state file, the configuration and faults of the UDM. */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

#include "g5c/ausf.h"
#include "g5c/eapaka.h"
#include "g5c/testkit.h"
#include "g5c/udm.h"
#include "g5c/udr.h"

#define SNN "5G:mnc001.mcc001.3gppnetwork.org"
#define ADMIN "admin-token-0123456789"
#define K "465b5ce8b199b49faa5f0a2ee238a6bc"
#define OP "cdc202d5123e20f62b6d676ac72cb318"
#define SUPI "imsi-001010000000001"

typedef struct {
    g5c_udr_store *store;
    g5c_router *udr_r, *udm_r, *ausf_r;
    g5c_server *udr_s, *udm_s, *ausf_s;
    g5c_registry *metrics_udm, *metrics_ausf;
    g5c_client *client;
    udm u;
    ausf *a;
    char udr[64], udm[64], ausf[64];
} S;

static double g_lifetime; /* when set, the context lifetime of the next stack */
static bool g_eap_ind;    /* ask for protected success indications */

static void h(const char *hex, uint8_t *out, size_t n)
{
    TK_ASSERT(tk_unhex(hex, out, n) == (long)n);
}

static void stack(S *s, bool encrypt, const udm_hnkey *hn)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[160];
    udm_keys keys;
    memset(s, 0, sizeof *s);
    s->client = g5c_client_new(5000, NULL);
    s->store = g5c_udr_store_memory();
    s->udr_r = g5c_udr_router(s->store);
    s->udr_s = g5c_server_start(&cfg, s->udr_r, err, sizeof err);
    TK_ASSERT(s->udr_s != NULL);
    snprintf(s->udr, sizeof s->udr, "http://127.0.0.1:%u", g5c_server_port(s->udr_s));
    if (encrypt) {
        uint8_t m[32];
        memset(m, 0x5a, 32);
        udm_keys_with_master(&keys, m);
    } else {
        udm_keys_none(&keys);
    }
    s->metrics_udm = g5c_registry_new();
    s->metrics_ausf = g5c_registry_new();
    udm_init(&s->u, s->client, s->udr, &keys, hn, hn ? 1 : 0, "00101", "udm-test", s->metrics_udm);
    s->u.admin_token = g5c_xstrdup(ADMIN);
    s->udm_r = udm_router(&s->u);
    s->udm_s = g5c_server_start(&cfg, s->udm_r, err, sizeof err);
    TK_ASSERT(s->udm_s != NULL);
    snprintf(s->udm, sizeof s->udm, "http://127.0.0.1:%u", g5c_server_port(s->udm_s));
    {
        ausf_opts o;
        ausf_opts_default(&o);
        if (g_lifetime > 0)
            o.ctx_lifetime_s = g_lifetime;
        o.eap_result_ind = g_eap_ind;
        s->a = ausf_new(s->client, s->udm, NULL, "", "ausf-test", s->metrics_ausf, &o);
    }
    s->ausf_r = ausf_router(s->a);
    s->ausf_s = g5c_server_start(&cfg, s->ausf_r, err, sizeof err);
    TK_ASSERT(s->ausf_s != NULL);
    snprintf(s->ausf, sizeof s->ausf, "http://127.0.0.1:%u", g5c_server_port(s->ausf_s));
}

static void unstack(S *s)
{
    g5c_server_stop(s->ausf_s);
    g5c_server_stop(s->udm_s);
    g5c_server_stop(s->udr_s);
    g5c_client_free(s->client);
    g5c_router_free(s->ausf_r);
    g5c_router_free(s->udm_r);
    g5c_router_free(s->udr_r);
    ausf_free(s->a);
    udm_destroy(&s->u);
    g5c_udr_store_free(s->store);
    g5c_registry_free(s->metrics_udm);
    g5c_registry_free(s->metrics_ausf);
}

/* returns status; *out gets the parsed body */
static int call(S *s, const char *method, const char *url, const char *body, bool admin, g5c_json **out)
{
    char auth[64], err[160];
    g5c_kv hdr = {"authorization", auth};
    g5c_resp r;
    int st;
    snprintf(auth, sizeof auth, "Bearer %s", ADMIN);
    TK_ASSERT(g5c_client_request(s->client, method, url, admin ? &hdr : NULL, admin ? 1 : 0, G5C_JSON_TYPE, body,
                                 body ? strlen(body) : 0, &r, err, sizeof err) == 0);
    st = r.status;
    if (out)
        *out = g5c_resp_parse_json(&r);
    g5c_resp_free(&r);
    return st;
}

static int admin(S *s, const char *method, const char *path, const char *body, g5c_json **out)
{
    char *u = g5c_xasprintf("%s%s", s->udm, path);
    int st = call(s, method, u, body, true, out);
    free(u);
    return st;
}

static void provision(S *s, const char *supi, const char *sqn)
{
    char body[256];
    snprintf(body, sizeof body, "{\"supi\":\"%s\",\"k\":\"%s\",\"op\":\"%s\",\"sqn\":\"%s\"}", supi, K, OP, sqn);
    TK_ASSERT(admin(s, "POST", "/admin/v1/subscribers", body, NULL) == 201);
}

/* AUSF start: returns status; *out is the body */
static int start_auth(S *s, const char *id, const char *rand_hex, const char *auts_hex, g5c_json **out)
{
    char body[512], *u = g5c_xasprintf("%s/nausf-auth/v1/ue-authentications", s->ausf);
    int st;
    if (rand_hex)
        snprintf(body, sizeof body, "{\"supiOrSuci\":\"%s\",\"servingNetworkName\":\"%s\",\"resynchronizationInfo\":{\"rand\":\"%s\",\"auts\":\"%s\"}}", id, SNN, rand_hex, auts_hex);
    else
        snprintf(body, sizeof body, "{\"supiOrSuci\":\"%s\",\"servingNetworkName\":\"%s\"}", id, SNN);
    st = call(s, "POST", u, body, false, out);
    free(u);
    return st;
}

static int confirm(S *s, const char *href, const uint8_t *res_star, size_t n, g5c_json **out)
{
    char *hx = g5c_hex_encode(res_star, n), body[128];
    int st;
    snprintf(body, sizeof body, "{\"resStar\":\"%s\"}", hx);
    st = call(s, "PUT", href, body, false, out);
    free(hx);
    return st;
}

/* ---- the UE side ---------------------------------------------------------------------------------------- */

typedef struct {
    uint8_t k[16], opc[16];
    uint64_t sqn_ms;
} ue_t;

typedef enum { UE_OK, UE_SYNC, UE_MAC } ue_kind;
typedef struct {
    ue_kind kind;
    uint8_t res_star[16], kseaf[32], auts[14];
} ue_out;

static void ue_init(ue_t *u, uint64_t sqn_ms)
{
    uint8_t op[16];
    h(K, u->k, 16);
    h(OP, op, 16);
    TK_ASSERT(g5c_milenage_derive_opc(u->k, op, u->opc) == 0);
    u->sqn_ms = sqn_ms;
}

static ue_out ue_challenge(ue_t *u, const uint8_t rand[16], const uint8_t autn[16])
{
    g5c_milenage m;
    g5c_milenage_vector v;
    uint8_t sqn[6], mac_a[8], mac_s[8], ka[32];
    uint64_t sqn_n = 0;
    ue_out o;
    memset(&o, 0, sizeof o);
    g5c_milenage_init(&m, u->k, u->opc);
    TK_ASSERT(g5c_milenage_f2345(&m, rand, &v) == 0);
    for (int i = 0; i < 6; i++)
        sqn[i] = (uint8_t)(autn[i] ^ v.ak[i]);
    TK_ASSERT(g5c_milenage_f1(&m, rand, sqn, autn + 6, mac_a, mac_s) == 0);
    if (memcmp(mac_a, autn + 8, 8) != 0) {
        o.kind = UE_MAC;
        return o;
    }
    for (int i = 0; i < 6; i++)
        sqn_n = (sqn_n << 8) | sqn[i];
    if (sqn_n <= u->sqn_ms) { /* synchronisation failure: AUTS = (SQNms xor AK*) || MAC-S */
        uint8_t ms6[6];
        for (int i = 0; i < 6; i++)
            ms6[i] = (uint8_t)(u->sqn_ms >> (8 * (5 - i)));
        TK_ASSERT(g5c_milenage_f1(&m, rand, ms6, (const uint8_t[]){0, 0}, mac_a, mac_s) == 0);
        for (int i = 0; i < 6; i++)
            o.auts[i] = (uint8_t)(ms6[i] ^ v.ak_star[i]);
        memcpy(o.auts + 6, mac_s, 8);
        o.kind = UE_SYNC;
        return o;
    }
    u->sqn_ms = sqn_n;
    TK_ASSERT(g5c_res_star(v.ck, v.ik, SNN, rand, v.res, 8, o.res_star) == 0);
    TK_ASSERT(g5c_kausf(v.ck, v.ik, SNN, autn, ka) == 0);
    TK_ASSERT(g5c_kseaf(ka, SNN, o.kseaf) == 0);
    o.kind = UE_OK;
    return o;
}

typedef struct {
    uint8_t rand[16], autn[16], hxres[16];
    char href[256];
} chal;

static chal auth_data(int status, g5c_json *v)
{
    chal c;
    const g5c_json *d = g5c_json_get(v, "5gAuthData");
    if (status != 201) {
        char *t = v != NULL ? g5c_json_to_string(v, NULL) : NULL;
        TK_FAIL("authentication start answered %d: %s", status, t != NULL ? t : "(no body)");
    }
    h(g5c_json_get_str(d, "rand"), c.rand, 16);
    h(g5c_json_get_str(d, "autn"), c.autn, 16);
    h(g5c_json_get_str(d, "hxresStar"), c.hxres, 16);
    snprintf(c.href, sizeof c.href, "%s", g5c_json_get_str(g5c_json_get(g5c_json_get(v, "_links"), "5g-aka"), "href"));
    g5c_json_free(v);
    return c;
}

static chal start_ok(S *s, const char *id)
{
    g5c_json *v = NULL;
    int st = start_auth(s, id, NULL, NULL, &v);
    return auth_data(st, v);
}

static char *kseaf_hex(const uint8_t k[32])
{
    return g5c_hex_encode(k, 32);
}

static void auth_status(S *s, g5c_json **out)
{
    char *u = g5c_xasprintf("%s/nudr-dr/v1/subscription-data/" SUPI "/authentication-data/authentication-status", s->udr);
    TK_ASSERT(call(s, "GET", u, NULL, false, out) == 200);
    free(u);
}

/* ---- tests ----------------------------------------------------------------------------------------------- */

static void test_full_aka(void)
{
    S s;
    ue_t ue;
    chal c;
    ue_out o;
    g5c_json *v;
    uint8_t hres[16];
    char *kx;
    bool b = false;
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    ue_init(&ue, 0);
    c = start_ok(&s, SUPI);
    o = ue_challenge(&ue, c.rand, c.autn);
    TK_ASSERT(o.kind == UE_OK);
    TK_ASSERT(g5c_hres_star(c.rand, o.res_star, hres) == 0 && memcmp(hres, c.hxres, 16) == 0); /* the AMF-side check */
    TK_ASSERT(confirm(&s, c.href, o.res_star, 16, &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_SUCCESS") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "supi"), SUPI) == 0);
    kx = kseaf_hex(o.kseaf); /* both sides derived the same K_SEAF independently */
    TK_ASSERT(strcmp(g5c_json_get_str(v, "kseaf"), kx) == 0);
    free(kx);
    g5c_json_free(v);
    auth_status(&s, &v); /* the UDM recorded the outcome in the UDR */
    TK_ASSERT(g5c_json_get_bool(v, "success", &b) && b);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "servingNetworkName"), SNN) == 0);
    g5c_json_free(v);
    TK_ASSERT(confirm(&s, c.href, o.res_star, 16, NULL) == 404); /* contexts are single use */
    unstack(&s);
}

static void test_wrong_res_star(void)
{
    S s;
    chal c;
    uint8_t zero[16] = {0};
    g5c_json *v;
    bool b = true;
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    c = start_ok(&s, SUPI);
    TK_ASSERT(confirm(&s, c.href, zero, 16, &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_FAILURE") == 0);
    TK_ASSERT(g5c_json_get(v, "kseaf") == NULL); /* no key material on failure */
    g5c_json_free(v);
    auth_status(&s, &v);
    TK_ASSERT(g5c_json_get_bool(v, "success", &b) && !b);
    g5c_json_free(v);
    unstack(&s);
}

static void test_sqn_advances(void)
{
    S s;
    ue_t ue;
    g5c_json *v;
    uint8_t seen[5][16];
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    ue_init(&ue, 0);
    for (int i = 1; i <= 5; i++) {
        chal c = start_ok(&s, SUPI);
        ue_out o = ue_challenge(&ue, c.rand, c.autn);
        for (int j = 0; j < i - 1; j++)
            TK_ASSERT(memcmp(seen[j], c.rand, 16) != 0); /* RAND never repeats */
        memcpy(seen[i - 1], c.rand, 16);
        TK_ASSERT(o.kind == UE_OK);
        TK_ASSERT(confirm(&s, c.href, o.res_star, 16, NULL) == 200);
        {
            uint64_t want_sqn = 32;
            want_sqn *= (uint64_t)i;
            TK_ASSERT(ue.sqn_ms == want_sqn); /* SQN steps by 32 per vector */
        }
    }
    TK_ASSERT(admin(&s, "GET", "/admin/v1/subscribers/" SUPI, NULL, &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "sqn"), "0000000000a0") == 0);
    {
        char *dump = g5c_json_to_string(v, NULL);
        TK_ASSERT(strstr(dump, K) == NULL); /* admin read must never expose K */
        free(dump);
    }
    g5c_json_free(v);
    unstack(&s);
}

static void test_resync(void)
{
    S s;
    ue_t ue;
    chal c, c2;
    ue_out o;
    g5c_json *v = NULL;
    char *rh, *ah, *kx;
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    ue_init(&ue, 0x10000); /* the USIM is far ahead of the network */
    c = start_ok(&s, SUPI);
    o = ue_challenge(&ue, c.rand, c.autn);
    TK_ASSERT(o.kind == UE_SYNC);
    rh = g5c_hex_encode(c.rand, 16);
    ah = g5c_hex_encode(o.auts, 14);
    {
        int st = start_auth(&s, SUPI, rh, ah, &v);
        c2 = auth_data(st, v);
    }
    free(rh);
    free(ah);
    TK_ASSERT(memcmp(c.rand, c2.rand, 16) != 0);
    o = ue_challenge(&ue, c2.rand, c2.autn);
    TK_ASSERT(o.kind == UE_OK);
    TK_ASSERT(ue.sqn_ms == 0x10000 + 32); /* the network continues from the UE's SQN */
    TK_ASSERT(confirm(&s, c2.href, o.res_star, 16, &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_SUCCESS") == 0);
    kx = kseaf_hex(o.kseaf);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "kseaf"), kx) == 0);
    free(kx);
    g5c_json_free(v);
    unstack(&s);
}

static void test_forged_auts(void)
{
    S s;
    ue_t ue;
    chal c;
    ue_out o;
    g5c_json *v = NULL;
    char *rh, *ah, *cause;
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    ue_init(&ue, 0x10000);
    c = start_ok(&s, SUPI);
    o = ue_challenge(&ue, c.rand, c.autn);
    TK_ASSERT(o.kind == UE_SYNC);
    o.auts[13] ^= 1;
    rh = g5c_hex_encode(c.rand, 16);
    ah = g5c_hex_encode(o.auts, 14);
    TK_ASSERT(start_auth(&s, SUPI, rh, ah, &v) == 403);
    cause = g5c_xstrdup(g5c_json_get_str(v, "cause"));
    TK_ASSERT(strcmp(cause, "AUTHENTICATION_REJECTED") == 0);
    free(cause);
    g5c_json_free(v);
    free(rh);
    free(ah);
    TK_ASSERT(admin(&s, "GET", "/admin/v1/subscribers/" SUPI, NULL, &v) == 200);
    /* a rejected resync must not move the SQN beyond the one vector already issued */
    TK_ASSERT(strcmp(g5c_json_get_str(v, "sqn"), "000000000020") == 0);
    g5c_json_free(v);
    unstack(&s);
}

static void test_suci(void)
{
    S s;
    ue_t ue;
    udm_hnkey hn;
    uint8_t hn_pub[33], msin[8], out[64], eph[32];
    size_t pl = 0, ml = 0, ol = 0;
    char *ids[2], *hx;
    g5c_json *v = NULL;
    memset(&hn, 0, sizeof hn);
    hn.id = 1;
    hn.profile = G5C_PROFILE_A;
    h("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d", hn.secret, 32);
    stack(&s, false, &hn);
    provision(&s, SUPI, "000000000000");
    ue_init(&ue, 0);
    memset(eph, 0x31, 32);
    TK_ASSERT(g5c_suci_public_key(G5C_PROFILE_A, hn.secret, hn_pub, sizeof hn_pub, &pl) == 0);
    TK_ASSERT(g5c_msin_to_bcd("0000000001", msin, sizeof msin, &ml) == 0);
    TK_ASSERT(g5c_suci_conceal(G5C_PROFILE_A, hn_pub, pl, eph, msin, ml, out, sizeof out, &ol) == 0);
    hx = g5c_hex_encode(out, ol);
    ids[0] = g5c_xasprintf("suci-0-001-01-0000-1-1-%s", hx);
    ids[1] = g5c_xstrdup("suci-0-001-01-0000-0-0-0000000001");
    free(hx);
    for (int i = 0; i < 2; i++) {
        chal c = start_ok(&s, ids[i]);
        ue_out o = ue_challenge(&ue, c.rand, c.autn);
        TK_ASSERT(o.kind == UE_OK);
        TK_ASSERT(confirm(&s, c.href, o.res_star, 16, &v) == 200);
        TK_ASSERT(strcmp(g5c_json_get_str(v, "supi"), SUPI) == 0);
        g5c_json_free(v);
        free(ids[i]);
    }
    TK_ASSERT(start_auth(&s, "suci-0-001-01-0000-1-1-00", NULL, NULL, NULL) == 403);
    TK_ASSERT(start_auth(&s, "not-an-id", NULL, NULL, NULL) == 400);
    unstack(&s);
}

static void test_error_cases(void)
{
    S s;
    g5c_json *v = NULL;
    char *u, *cause;
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    TK_ASSERT(start_auth(&s, "imsi-001010000000099", NULL, NULL, &v) == 404);
    cause = g5c_xstrdup(g5c_json_get_str(v, "cause"));
    TK_ASSERT(strcmp(cause, "USER_NOT_FOUND") == 0);
    free(cause);
    g5c_json_free(v);
    u = g5c_xasprintf("%s/nudm-ueau/v1/" SUPI "/security-information/generate-auth-data", s.udm);
    TK_ASSERT(call(&s, "POST", u, "{\"servingNetworkName\":\"evil.example.org\"}", false, &v) == 403);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "cause"), "SERVING_NETWORK_NOT_AUTHORIZED") == 0);
    g5c_json_free(v);
    free(u);
    u = g5c_xasprintf("%s/nausf-auth/v1/ue-authentications/nope/5g-aka-confirmation", s.ausf);
    TK_ASSERT(confirm(&s, u, (const uint8_t[16]){0}, 16, NULL) == 404);
    free(u);
    u = g5c_xasprintf("%s/nausf-auth/v1/ue-authentications/nope", s.ausf);
    TK_ASSERT(call(&s, "DELETE", u, NULL, false, NULL) == 404);
    free(u);
    unstack(&s);
}

static void test_context_expiry(void)
{
    S s;
    chal c;
    uint8_t zero[16] = {0};
    g_lifetime = 0.2;
    stack(&s, false, NULL);
    g_lifetime = 0;
    provision(&s, SUPI, "000000000000");
    c = start_ok(&s, SUPI);
    usleep(400 * 1000);
    TK_ASSERT(confirm(&s, c.href, zero, 16, NULL) == 404); /* expired */
    unstack(&s);
}

static void test_encrypted_at_rest(void)
{
    S s;
    ue_t ue;
    chal c;
    ue_out o;
    g5c_json *stored, *copy;
    uint8_t k[16], op[16], opc[16];
    char *dump, *opc_hex;
    stack(&s, true, NULL);
    provision(&s, SUPI, "000000000000");
    stored = g5c_udr_get(s.store, SUPI, UDR_AUTH);
    TK_ASSERT(stored != NULL && strcmp(g5c_json_get_str(stored, "protectionParameterId"), "aes-256-gcm-v1") == 0);
    h(K, k, 16);
    h(OP, op, 16);
    TK_ASSERT(g5c_milenage_derive_opc(k, op, opc) == 0);
    opc_hex = g5c_hex_encode(opc, 16);
    dump = g5c_json_to_string(stored, NULL);
    TK_ASSERT(strstr(dump, K) == NULL && strstr(dump, opc_hex) == NULL); /* no plaintext credentials in the UDR */
    free(dump);
    free(opc_hex);
    ue_init(&ue, 0);
    c = start_ok(&s, SUPI);
    o = ue_challenge(&ue, c.rand, c.autn);
    TK_ASSERT(o.kind == UE_OK && confirm(&s, c.href, o.res_star, 16, NULL) == 200);
    /* a record moved to another subscriber id cannot be used (the SUPI is bound as associated data) */
    copy = g5c_json_dup(stored);
    g5c_udr_put(s.store, "imsi-001010000000002", UDR_AUTH, copy);
    TK_ASSERT(start_auth(&s, "imsi-001010000000002", NULL, NULL, NULL) != 201);
    g5c_json_free(stored);
    unstack(&s);
}

typedef struct {
    S *s;
    uint8_t autn[16];
    int ok;
} job_t;

static void *job(void *a)
{
    job_t *j = a;
    g5c_json *v = NULL;
    char *u = g5c_xasprintf("%s/nausf-auth/v1/ue-authentications", j->s->ausf), err[100];
    g5c_resp r;
    const char *body = "{\"supiOrSuci\":\"" SUPI "\",\"servingNetworkName\":\"" SNN "\"}";
    if (g5c_client_request(j->s->client, "POST", u, NULL, 0, G5C_JSON_TYPE, body, strlen(body), &r, err, sizeof err) == 0) {
        if (r.status == 201) {
            v = g5c_resp_parse_json(&r);
            h(g5c_json_get_str(g5c_json_get(v, "5gAuthData"), "autn"), j->autn, 16);
            j->ok = 1;
        }
        g5c_resp_free(&r);
    }
    g5c_json_free(v);
    free(u);
    return NULL;
}

static void test_concurrent_sqn(void)
{
    S s;
    pthread_t th[40];
    job_t jobs[40];
    g5c_json *v;
    char want[16];
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    for (int i = 0; i < 40; i++) {
        jobs[i] = (job_t){&s, {0}, 0};
        pthread_create(&th[i], NULL, job, &jobs[i]);
    }
    for (int i = 0; i < 40; i++) {
        pthread_join(th[i], NULL);
        TK_ASSERT(jobs[i].ok);
    }
    /* equal AUTNs would mean a reused (RAND, SQN) */
    for (int i = 0; i < 40; i++)
        for (int j = i + 1; j < 40; j++)
            TK_ASSERT(memcmp(jobs[i].autn, jobs[j].autn, 16) != 0);
    TK_ASSERT(admin(&s, "GET", "/admin/v1/subscribers/" SUPI, NULL, &v) == 200);
    snprintf(want, sizeof want, "%012x", 40 * 32); /* every vector advanced the SQN exactly once */
    TK_ASSERT(strcmp(g5c_json_get_str(v, "sqn"), want) == 0);
    g5c_json_free(v);
    unstack(&s);
}

static void test_admin_api(void)
{
    S s;
    g5c_json *v;
    char *u;
    stack(&s, false, NULL);
    u = g5c_xasprintf("%s/admin/v1/subscribers", s.udm);
    TK_ASSERT(call(&s, "GET", u, NULL, false, NULL) == 401); /* no token */
    free(u);
    {
        static const char *const bad[] = {
            "{\"supi\":\"nope\",\"k\":\"" K "\",\"op\":\"" OP "\"}",
            "{\"supi\":\"" SUPI "\",\"k\":\"1234\",\"op\":\"" OP "\"}",
            "{\"supi\":\"" SUPI "\",\"k\":\"" K "\"}",
            "{\"supi\":\"" SUPI "\",\"k\":\"" K "\",\"op\":\"" OP "\",\"opc\":\"" OP "\"}",
            "{\"supi\":\"" SUPI "\",\"k\":\"" K "\",\"op\":\"" OP "\",\"slices\":[{\"sst\":1,\"sd\":\"xyz\"}]}",
            "{\"supi\":\"" SUPI "\",\"k\":\"" K "\",\"op\":\"" OP "\",\"unexpected\":1}"};
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
            TK_ASSERT(admin(&s, "POST", "/admin/v1/subscribers", bad[i], NULL) == 400);
    }
    provision(&s, SUPI, "000000000000");
    TK_ASSERT(admin(&s, "GET", "/admin/v1/subscribers", NULL, &v) == 200 && g5c_json_len(v) == 1);
    TK_ASSERT(strcmp(g5c_json_str(g5c_json_at(v, 0)), SUPI) == 0);
    g5c_json_free(v);
    TK_ASSERT(admin(&s, "GET", "/admin/v1/subscribers/" SUPI, NULL, &v) == 200);
    {
        char *dump = g5c_json_to_string(v, NULL);
        TK_ASSERT(strstr(dump, K) == NULL);
        free(dump);
    }
    g5c_json_free(v);
    TK_ASSERT(admin(&s, "DELETE", "/admin/v1/subscribers/" SUPI, NULL, NULL) == 204);
    TK_ASSERT(admin(&s, "GET", "/admin/v1/subscribers/" SUPI, NULL, NULL) == 404);
    unstack(&s);
}

/* ---- AUSF faults: every way the UDM can misbehave, and malformed requests from the AMF side ------------------------ */
static atomic_int udm_mode;

static void h_fake_udm(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    switch (atomic_load(&udm_mode)) {
    case 1:
        g5c_resp_problem_simple(resp, 404, "USER_NOT_FOUND", NULL);
        break;
    case 2:
        g5c_resp_problem_simple(resp, 403, "AUTHENTICATION_REJECTED", "AUTS MAC-S verification failed");
        break;
    case 3:
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", NULL);
        break;
    case 4:
        g5c_resp_problem_simple(resp, 429, "TOO_MANY_REQUESTS", NULL); /* any other status is reported as a server error */
        break;
    case 5:
        g5c_resp_content(resp, 200, G5C_JSON_TYPE, "garbage", 7);
        break;
    case 6: { /* well formed JSON, vector incomplete */
        const char *b = "{\"authType\":\"5G_AKA\",\"supi\":\"imsi-001010000000001\",\"authenticationVector\":{\"rand\":\"00\"}}";
        g5c_resp_content(resp, 200, G5C_JSON_TYPE, b, strlen(b));
        break;
    }
    default: { /* complete but the hex is wrong */
        const char *b = "{\"authType\":\"5G_AKA\",\"supi\":\"imsi-001010000000001\",\"authenticationVector\":{\"avType\":\"5G_HE_AKA\","
                        "\"rand\":\"zz\",\"autn\":\"00\",\"xresStar\":\"00\",\"kausf\":\"00\"}}";
        g5c_resp_content(resp, 200, G5C_JSON_TYPE, b, strlen(b));
        break;
    }
    }
}

static int ausf_call(g5c_client *c, const char *method, const char *url, const char *body, g5c_json **out)
{
    char err[160];
    g5c_resp r;
    int st;
    if (g5c_client_request(c, method, url, NULL, 0, G5C_JSON_TYPE, body, body ? strlen(body) : 0, &r, err, sizeof err) != 0)
        return -1;
    st = r.status;
    if (out)
        *out = g5c_resp_parse_json(&r);
    g5c_resp_free(&r);
    return st;
}

static void test_ausf_udm_faults(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_router *fr = g5c_router_new(), *ar;
    g5c_server *fs, *as;
    g5c_client *c = g5c_client_new(2000, NULL);
    g5c_registry *m = g5c_registry_new();
    ausf *a;
    char fake[64], base[64], err[160], url[200];
    const char *start = "{\"supiOrSuci\":\"" SUPI "\",\"servingNetworkName\":\"" SNN "\"}";
    static const struct {
        int mode, want;
    } faults[] = {{1, 404}, {2, 403}, {3, 500}, {4, 429}, {5, 500}, {6, 500}, {7, 500}};
    g5c_json *v = NULL;

    g5c_router_route(fr, "POST", "/nudm-ueau/v1/{supi}/security-information/generate-auth-data", h_fake_udm, NULL);
    fs = g5c_server_start(&cfg, fr, err, sizeof err);
    TK_ASSERT(fs != NULL);
    snprintf(fake, sizeof fake, "http://127.0.0.1:%u", g5c_server_port(fs));
    a = ausf_new(c, fake, NULL, "", "ausf-fault", m, NULL);
    ar = ausf_router(a);
    as = g5c_server_start(&cfg, ar, err, sizeof err);
    TK_ASSERT(as != NULL);
    snprintf(base, sizeof base, "http://127.0.0.1:%u", g5c_server_port(as));
    snprintf(url, sizeof url, "%s/nausf-auth/v1/ue-authentications", base);

    for (size_t i = 0; i < sizeof faults / sizeof *faults; i++) {
        int st;
        atomic_store(&udm_mode, faults[i].mode);
        st = ausf_call(c, "POST", url, start, &v);
        if (st != faults[i].want)
            TK_FAIL("UDM fault mode %d produced %d, wanted %d", faults[i].mode, st, faults[i].want);
        g5c_json_free(v);
    }
    /* requests from the AMF side */
    TK_ASSERT(ausf_call(c, "POST", url, "{", NULL) == 400);
    TK_ASSERT(ausf_call(c, "POST", url, "{\"supiOrSuci\":\"x\"}", NULL) == 400);
    TK_ASSERT(ausf_call(c, "POST", url, "{\"servingNetworkName\":\"" SNN "\"}", NULL) == 400);
    TK_ASSERT(ausf_call(c, "POST", url, "[]", NULL) == 400);
    snprintf(url, sizeof url, "%s/nausf-auth/v1/ue-authentications/no-such-context/5g-aka-confirmation", base);
    TK_ASSERT(ausf_call(c, "PUT", url, "{\"resStar\":\"00000000000000000000000000000000\"}", NULL) == 404);
    TK_ASSERT(ausf_call(c, "PUT", url, "{", NULL) == 400);
    TK_ASSERT(ausf_call(c, "PUT", url, "{}", NULL) == 400 || ausf_call(c, "PUT", url, "{}", NULL) == 404);
    TK_ASSERT(ausf_call(c, "DELETE", url, NULL, NULL) == 404 || ausf_call(c, "DELETE", url, NULL, NULL) == 405);
    /* UDM gone */
    g5c_server_stop(fs);
    snprintf(url, sizeof url, "%s/nausf-auth/v1/ue-authentications", base);
    TK_ASSERT(ausf_call(c, "POST", url, start, NULL) == 504);

    g5c_server_stop(as);
    g5c_client_free(c);
    g5c_router_free(ar);
    g5c_router_free(fr);
    ausf_free(a);
    g5c_registry_free(m);
}

/* UDM reads damaged or unsupported credentials out of the UDR: it must refuse, not guess. */
static void put_udr(S *s, const char *supi, const g5c_json *doc)
{
    /* straight into the store: the damaged documents of these tests are what the UDR API itself would refuse */
    (void)g5c_udr_put(s->store, supi, UDR_AUTH, g5c_json_dup(doc));
}

static g5c_json *get_udr(S *s, const char *supi)
{
    char url[256], err[160];
    g5c_resp r;
    g5c_json *j;
    snprintf(url, sizeof url, "%s/nudr-dr/v1/subscription-data/%s/authentication-data/authentication-subscription", s->udr, supi);
    TK_ASSERT(g5c_client_get(s->client, url, &r, err, sizeof err) == 0 && r.status == 200);
    j = g5c_resp_parse_json(&r);
    g5c_resp_free(&r);
    TK_ASSERT(j != NULL);
    return j;
}

static int gen_vector(S *s, const char *body, g5c_json **out)
{
    char url[256];
    snprintf(url, sizeof url, "%s/nudm-ueau/v1/" SUPI "/security-information/generate-auth-data", s->udm);
    return ausf_call(s->client, "POST", url, body, out);
}

static void test_udm_damaged_credentials(void)
{
    S s;
    const char *body = "{\"servingNetworkName\":\"" SNN "\"}";
    g5c_json *orig, *d, *v = NULL;
    stack(&s, true, NULL);
    provision(&s, SUPI, "000000000020");
    orig = get_udr(&s, SUPI);
    TK_ASSERT(gen_vector(&s, body, &v) == 200);
    g5c_json_free(v);

    d = g5c_json_dup(orig); /* an authentication method the UDM does not implement: the user cannot be authenticated with it */
    g5c_json_set_str(d, "authenticationMethod", "EAP_TLS");
    put_udr(&s, SUPI, d);
    TK_ASSERT(gen_vector(&s, body, &v) == 403);
    g5c_json_free(v);
    g5c_json_free(d);

    d = g5c_json_dup(orig); /* ciphertext of another subscriber / bit-rot: authentication tag fails */
    g5c_json_set_str(d, "encPermanentKey", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    put_udr(&s, SUPI, d);
    TK_ASSERT(gen_vector(&s, body, &v) == 500);
    g5c_json_free(v);
    g5c_json_free(d);

    d = g5c_json_dup(orig); /* OPc missing */
    g5c_json_remove(d, "encOpcKey");
    put_udr(&s, SUPI, d);
    TK_ASSERT(gen_vector(&s, body, &v) == 500);
    g5c_json_free(v);
    g5c_json_free(d);

    d = g5c_json_dup(orig); /* protection scheme unknown */
    g5c_json_set_str(d, "protectionParameterId", "rot13");
    put_udr(&s, SUPI, d);
    TK_ASSERT(gen_vector(&s, body, &v) == 500);
    g5c_json_free(v);
    g5c_json_free(d);

    d = g5c_json_dup(orig); /* SQN damaged */
    g5c_json_set_str(g5c_json_get_mut(d, "sequenceNumber"), "sqn", "not-hex");
    put_udr(&s, SUPI, d);
    TK_ASSERT(gen_vector(&s, body, &v) == 500);
    g5c_json_free(v);
    g5c_json_free(d);

    put_udr(&s, SUPI, orig); /* restored: service resumes */
    TK_ASSERT(gen_vector(&s, body, &v) == 200);
    g5c_json_free(v);

    /* resynchronizationInfo: malformed -> 400, well formed but forged -> 403 (covered in test_forged_auts) */
    TK_ASSERT(gen_vector(&s, "{\"servingNetworkName\":\"" SNN "\",\"resynchronizationInfo\":{\"rand\":\"zz\",\"auts\":\"zz\"}}", &v) == 400);
    g5c_json_free(v);
    TK_ASSERT(gen_vector(&s, "{\"servingNetworkName\":\"" SNN "\",\"resynchronizationInfo\":{\"rand\":\"00\"}}", &v) == 400);
    g5c_json_free(v);
    /* request-level validation */
    TK_ASSERT(gen_vector(&s, "{}", &v) == 400);
    g5c_json_free(v);
    TK_ASSERT(gen_vector(&s, "{\"servingNetworkName\":\"not a serving network name\"}", &v) == 403);
    g5c_json_free(v);
    g5c_json_free(orig);
    unstack(&s);
}

#include "test_more.inc"

int main(void)
{
    g5c_log_init("error", false);
    test_full_aka();
    test_wrong_res_star();
    test_sqn_advances();
    test_resync();
    test_forged_auts();
    test_suci();
    test_error_cases();
    test_context_expiry();
    test_encrypted_at_rest();
    test_concurrent_sqn();
    test_admin_api();
    test_ausf_udm_faults();
    test_udm_damaged_credentials();
    test_more();
    puts("ausf: ok");
    return 0;
}
