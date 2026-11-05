/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* UDM: unit tests (AKA, key protection, identity, util) and service tests over real sockets against udr. */
#define _DEFAULT_SOURCE
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "g5c/eapaka.h"
#include "g5c/testkit.h"
#include "g5c/udm.h"
#include "g5c/udr.h"

#define ADMIN "admin-token-0123456789"
#define SUPI "imsi-001010000000001"
#define K_HEX "465b5ce8b199b49faa5f0a2ee238a6bc"
#define OP_HEX "cdc202d5123e20f62b6d676ac72cb318"

/* ---- unit tests ---- */

static void h(const char *hex, uint8_t *out, size_t n)
{
    TK_ASSERT(tk_unhex(hex, out, n) == (long)n);
}

static void test_aka(void)
{
    uint8_t k[16], opc[16], rand[16], mine[16];
    udm_heav av;
    char hx[13];
    uint64_t v = 0;
    h(K_HEX, k, 16);
    h("cd63cb71954a9f4e48a5994e37a02baf", opc, 16);
    h("23553cbe9637a89d218ae64dae47bf35", rand, 16);

    TK_ASSERT(udm_next_sqn(0) == 32);
    TK_ASSERT(udm_next_sqn(0xffffffffffe0ULL) == 0); /* wraps at 48 bits */
    udm_sqn_to_hex(0x21, hx);
    TK_ASSERT(strcmp(hx, "000000000021") == 0);
    TK_ASSERT(udm_sqn_from_hex("000000000021", &v) && v == 0x21);
    TK_ASSERT(!udm_sqn_from_hex("21", &v) && !udm_sqn_from_hex("zzzzzzzzzzzz", &v));

    /* TS 35.208 set 1: SQN ff9bb4d0b607, AMF b9b9 -> AUTN = (SQN xor AK) || AMF || MAC-A */
    TK_ASSERT(udm_generate_av(k, opc, 0xff9bb4d0b607ULL, (const uint8_t[]){0xb9, 0xb9}, rand,
                              "5G:mnc001.mcc001.3gppnetwork.org", &av) == 0);
    TK_EQ_HEX(av.autn, "55f328b43577b9b94a9ffac354dfafb3", 16);

    {   /* resync recovers SQNms and rejects forgeries */
        g5c_milenage m;
        g5c_milenage_vector mv;
        uint8_t o3[16], r9[16], sqn_ms[6] = {0, 0, 0, 0, 0x12, 0x34}, auts[14], mac_a[8], mac_s[8];
        uint64_t got = 0;
        memset(o3, 3, 16);
        memset(r9, 9, 16);
        g5c_milenage_init(&m, k, o3);
        TK_ASSERT(g5c_milenage_f2345(&m, r9, &mv) == 0);
        TK_ASSERT(g5c_milenage_f1(&m, r9, sqn_ms, (const uint8_t[]){0, 0}, mac_a, mac_s) == 0);
        for (int i = 0; i < 6; i++)
            auts[i] = (uint8_t)(sqn_ms[i] ^ mv.ak_star[i]);
        memcpy(auts + 6, mac_s, 8);
        TK_ASSERT(udm_resync(k, o3, r9, auts, &got) == 0 && got == 0x1234);
        auts[13] ^= 1;
        TK_ASSERT(udm_resync(k, o3, r9, auts, &got) == 1);
    }
    (void)mine;
}

static void test_keys(void)
{
    udm_keys none, aes, wrong;
    uint8_t m7[32], m8[32], key[16], out[32];
    char *s, *s2;
    const char *id;
    size_t n = 0;
    memset(m7, 7, 32);
    memset(m8, 8, 32);
    memset(key, 0xab, 16);

    udm_keys_none(&none);
    {
        const uint8_t p[3] = {1, 2, 3};
        TK_ASSERT(udm_protect(&none, p, 3, "imsi-1", &s, &id) == 0 && strcmp(s, "010203") == 0 && strcmp(id, UDM_PROT_NONE) == 0);
        TK_ASSERT(udm_unprotect(&none, s, id, "imsi-1", out, sizeof out, &n) == 0 && n == 3 && out[2] == 3);
        TK_ASSERT(udm_unprotect(&none, s, NULL, "imsi-1", out, sizeof out, &n) == 0 && n == 3);
        free(s);
    }
    udm_keys_with_master(&aes, m7);
    udm_keys_with_master(&wrong, m8);
    TK_ASSERT(udm_protect(&aes, key, 16, "imsi-001010000000001", &s, &id) == 0 && strcmp(id, UDM_PROT_AES256GCM) == 0);
    TK_ASSERT(strstr(s, "abababab") == NULL); /* ciphertext must not leak the key */
    TK_ASSERT(udm_unprotect(&aes, s, id, "imsi-001010000000001", out, sizeof out, &n) == 0 && n == 16 && memcmp(out, key, 16) == 0);
    TK_ASSERT(udm_unprotect(&aes, s, id, "imsi-001010000000002", out, sizeof out, &n) == UDM_KEY_DECRYPT); /* other subscriber */
    {
        char *flipped = g5c_xstrdup(s);
        flipped[28] = flipped[28] == '0' ? '1' : '0'; /* a ciphertext nibble */
        TK_ASSERT(udm_unprotect(&aes, flipped, id, "imsi-001010000000001", out, sizeof out, &n) == UDM_KEY_DECRYPT);
        free(flipped);
    }
    TK_ASSERT(udm_unprotect(&wrong, s, id, "imsi-001010000000001", out, sizeof out, &n) == UDM_KEY_DECRYPT);
    TK_ASSERT(udm_protect(&aes, key, 16, "imsi-001010000000001", &s2, &id) == 0 && strcmp(s, s2) != 0); /* fresh nonce */
    free(s);
    free(s2);
    TK_ASSERT(udm_unprotect(&none, "zz", NULL, "x", out, sizeof out, &n) == UDM_KEY_MALFORMED);
    TK_ASSERT(udm_unprotect(&none, "00", UDM_PROT_AES256GCM, "x", out, sizeof out, &n) == UDM_KEY_NO_MASTER);
    TK_ASSERT(udm_unprotect(&none, "00", "rot13", "x", out, sizeof out, &n) == UDM_KEY_SCHEME);
    TK_ASSERT(udm_unprotect(&aes, "0011", UDM_PROT_AES256GCM, "x", out, sizeof out, &n) == UDM_KEY_MALFORMED);
    {
        udm_keys k;
        TK_ASSERT(udm_keys_from_hex(&k, "abc") != 0);
        TK_ASSERT(udm_keys_from_hex(&k, "abababababababababababababababababababababababababababababababab\n") == 0 && k.has_master);
    }
}

static void test_identity(void)
{
    char supi[48];
    udm_hnkey k;
    uint8_t hn_pub[33], eph[32], msin[8], out[64];
    size_t pl = 0, ml = 0, ol = 0;
    char *suci, *hex;
    memset(&k, 0, sizeof k);
    k.id = 1;
    k.profile = G5C_PROFILE_A;
    h("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d", k.secret, 32);

    TK_ASSERT(udm_resolve("imsi-001010000000001", NULL, 0, supi, sizeof supi) == 0 && strcmp(supi, "imsi-001010000000001") == 0);
    TK_ASSERT(udm_resolve("imsi-12", NULL, 0, supi, sizeof supi) == UDM_ID_MALFORMED);
    TK_ASSERT(udm_resolve("imsi-0010100000000a1", NULL, 0, supi, sizeof supi) == UDM_ID_MALFORMED);
    TK_ASSERT(udm_resolve("nai-foo@bar", NULL, 0, supi, sizeof supi) == UDM_ID_MALFORMED);

    TK_ASSERT(udm_resolve("suci-0-001-01-0000-0-0-0000000001", NULL, 0, supi, sizeof supi) == 0 && strcmp(supi, "imsi-001010000000001") == 0);
    TK_ASSERT(udm_resolve("suci-1-001-01-0000-0-0-0000000001", NULL, 0, supi, sizeof supi) == UDM_ID_UNSUPPORTED);
    TK_ASSERT(udm_resolve("suci-0-001-01-0000-0-0-", NULL, 0, supi, sizeof supi) == UDM_ID_MALFORMED);
    TK_ASSERT(udm_resolve("suci-0-001-01-0000-9-0-00", NULL, 0, supi, sizeof supi) == UDM_ID_UNSUPPORTED);

    /* Profile A with the TS 33.501 Annex C key: conceal on the "UE side", resolve on the UDM side */
    memset(eph, 0x77, 32);
    TK_ASSERT(g5c_suci_public_key(G5C_PROFILE_A, k.secret, hn_pub, sizeof hn_pub, &pl) == 0);
    TK_ASSERT(g5c_msin_to_bcd("0000000001", msin, sizeof msin, &ml) == 0);
    TK_ASSERT(g5c_suci_conceal(G5C_PROFILE_A, hn_pub, pl, eph, msin, ml, out, sizeof out, &ol) == 0);
    hex = g5c_hex_encode(out, ol);
    suci = g5c_xasprintf("suci-0-001-01-0000-1-1-%s", hex);
    TK_ASSERT(udm_resolve(suci, &k, 1, supi, sizeof supi) == 0 && strcmp(supi, "imsi-001010000000001") == 0);
    {
        char *bad = g5c_xasprintf("suci-0-001-01-0000-1-9-%s", hex); /* unknown key id */
        TK_ASSERT(udm_resolve(bad, &k, 1, supi, sizeof supi) == UDM_ID_UNKNOWN_KEY);
        free(bad);
        bad = g5c_xasprintf("suci-0-001-01-0000-2-1-%s", hex); /* wrong profile */
        TK_ASSERT(udm_resolve(bad, &k, 1, supi, sizeof supi) == UDM_ID_UNKNOWN_KEY);
        free(bad);
        bad = g5c_xstrdup(suci);
        bad[strlen(bad) - 1] = bad[strlen(bad) - 1] == '0' ? '1' : '0'; /* tampered tag */
        TK_ASSERT(udm_resolve(bad, &k, 1, supi, sizeof supi) == UDM_ID_DECONCEAL);
        free(bad);
    }
    free(suci);
    free(hex);
}

static void test_util(void)
{
    char t[21], plmn[16];
    udm_iso8601_utc(0, t);
    TK_ASSERT(strcmp(t, "1970-01-01T00:00:00Z") == 0);
    udm_iso8601_utc(951782400, t);
    TK_ASSERT(strcmp(t, "2000-02-29T00:00:00Z") == 0);
    udm_iso8601_utc(1782864000ULL + 3661, t);
    TK_ASSERT(strcmp(t, "2026-07-01T01:01:01Z") == 0);
    udm_iso8601_utc(4102444799ULL, t);
    TK_ASSERT(strcmp(t, "2099-12-31T23:59:59Z") == 0);
    TK_ASSERT(udm_plmn_from_query("{\"mcc\":\"001\",\"mnc\":\"01\"}", plmn, sizeof plmn) && strcmp(plmn, "00101") == 0);
    TK_ASSERT(!udm_plmn_from_query("nonsense", plmn, sizeof plmn) && !udm_plmn_from_query(NULL, plmn, sizeof plmn));
    TK_ASSERT(udm_valid_snn("5G:mnc001.mcc001.3gppnetwork.org") && udm_valid_snn("5G:mnc260.mcc310.3gppnetwork.org"));
    TK_ASSERT(!udm_valid_snn("5G:mnc01.mcc001.3gppnetwork.org") && !udm_valid_snn("5G:mnc001.mcc001.example.org"));
    TK_ASSERT(!udm_valid_snn("EPS:mnc001.mcc001.3gppnetwork.org") && !udm_valid_snn(""));
    TK_ASSERT(udm_valid_snn("5G:mnc001.mcc001.3gppnetwork.org:0123456789A")); /* SNPN: ServingNetworkName pattern of TS 29.503 */
    TK_ASSERT(!udm_valid_snn("5G:mnc001.mcc001.3gppnetwork.org:0123456789a")); /* lower-case hex */
    TK_ASSERT(!udm_valid_snn("5G:mnc001.mcc001.3gppnetwork.org:0123456789"));  /* 10 digits */
    TK_ASSERT(!udm_valid_snn("5G:mnc001.mcc001.3gppnetwork.org:0123456789AB"));
    TK_ASSERT(!udm_valid_snn("5G:mnc001.mcc001.3gppnetwork.org:"));
    TK_ASSERT(!udm_valid_snn("5G:mnc001.mcc001.3gppnetwork.orgX"));
    TK_ASSERT(!udm_valid_snn("5G:mnc001.mcc001.3gppnetwork.org "));
}

/* ---- service fixtures ---- */

typedef struct {
    g5c_udr_store *store;
    g5c_router *udr_router;
    g5c_server *udr_srv;
    g5c_registry *metrics;
    g5c_client *client;
    udm u;
    g5c_router *udm_router;
    g5c_server *udm_srv;
    char base[64];
    udm_keys keys;
    uint8_t fixed_rand[16];
    int use_fixed;
} T;

static int fixed_rand(void *ctx, uint8_t out[16])
{
    T *t = ctx;
    if (t->use_fixed) {
        memcpy(out, t->fixed_rand, 16);
        return 0;
    }
    return g5c_random(out, 16);
}

static g5c_json *J(const char *s)
{
    g5c_json *j = g5c_json_parse(s, strlen(s), NULL, 0);
    TK_ASSERT(j != NULL);
    return j;
}

/* Returns the HTTP status; *out (optional) gets the parsed body, *loc (optional) a copy of the Location header. */
static int rq(T *t, const char *method, const char *path, const char *body, bool admin, g5c_json **out, char **loc)
{
    char *url = g5c_xasprintf("%s%s", t->base, path), auth[64], err[160];
    g5c_kv hdr = {"authorization", auth};
    g5c_resp r;
    int st;
    snprintf(auth, sizeof auth, "Bearer %s", ADMIN);
    TK_ASSERT(g5c_client_request(t->client, method, url, admin ? &hdr : NULL, admin ? 1 : 0, G5C_JSON_TYPE, body,
                                 body ? strlen(body) : 0, &r, err, sizeof err) == 0);
    free(url);
    st = r.status;
    if (out)
        *out = g5c_resp_parse_json(&r);
    if (loc) {
        const char *l = g5c_resp_header_get(&r, "location");
        *loc = l ? g5c_xstrdup(l) : NULL;
    }
    g5c_resp_free(&r);
    return st;
}

static void setup_ex(T *t, bool encrypt, const char *udr_token)
{
    char udr_url[64], err[160];
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    uint8_t master[32];
    memset(t, 0, sizeof *t);
    t->store = g5c_udr_store_memory();
    if (udr_token != NULL) { /* a UDR that wants the provisioning token */
        udr_opts uo;
        memset(&uo, 0, sizeof uo);
        uo.provisioning_token = udr_token;
        t->udr_router = g5c_udr_router_opts(t->store, &uo);
    } else {
        t->udr_router = g5c_udr_router(t->store);
    }
    t->udr_srv = g5c_server_start(&cfg, t->udr_router, err, sizeof err);
    TK_ASSERT(t->udr_srv != NULL);
    snprintf(udr_url, sizeof udr_url, "http://127.0.0.1:%u", g5c_server_port(t->udr_srv));
    t->client = g5c_client_new(5000, NULL);
    t->metrics = g5c_registry_new();
    if (encrypt) {
        memset(master, 9, 32);
        udm_keys_with_master(&t->keys, master);
    } else {
        udm_keys_none(&t->keys);
    }
    udm_init(&t->u, t->client, udr_url, &t->keys, NULL, 0, "00101", "udm-test", t->metrics);
    if (udr_token != NULL)
        udm_udr_set_token(&t->u.udr, udr_token);
    t->u.admin_token = g5c_xstrdup(ADMIN);
    t->u.rand_fn = fixed_rand;
    t->u.rand_ctx = t;
    t->udm_router = udm_router(&t->u);
    t->udm_srv = g5c_server_start(&cfg, t->udm_router, err, sizeof err);
    TK_ASSERT(t->udm_srv != NULL);
    snprintf(t->base, sizeof t->base, "http://127.0.0.1:%u", g5c_server_port(t->udm_srv));
    TK_ASSERT(rq(t, "POST", "/admin/v1/subscribers",
                 "{\"supi\":\"" SUPI "\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\","
                 "\"slices\":[{\"sst\":1},{\"sst\":2,\"sd\":\"010203\"}],"
                 "\"dnns\":{\"internet\":{},\"ims\":{\"qi5\":5,\"session_types\":[\"IPV4V6\",\"IPV4\"]}}}",
                 true, NULL, NULL) == 201);
}

static void setup(T *t, bool encrypt)
{
    setup_ex(t, encrypt, NULL);
}

static void teardown(T *t)
{
    g5c_server_stop(t->udm_srv);
    g5c_server_stop(t->udr_srv);
    g5c_client_free(t->client);
    g5c_router_free(t->udm_router);
    g5c_router_free(t->udr_router);
    udm_destroy(&t->u);
    g5c_udr_store_free(t->store);
    g5c_registry_free(t->metrics);
}

static const char *PLMN = "%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D";

#define EXPECT_STR(j, key, want) TK_ASSERT(strcmp(g5c_json_get_str((j), (key)), (want)) == 0)

/* ---- SDM ---- */

static void test_sdm(void)
{
    T t;
    g5c_json *v;
    char path[512];
    setup(&t, false);
    for (int i = 0; i < 2; i++) {
        const char *ver = i == 0 ? "v2" : "v1";
        snprintf(path, sizeof path, "/nudm-sdm/%s/" SUPI "/am-data?plmn-id=%s", ver, PLMN);
        TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200);
        EXPECT_STR(g5c_json_get(v, "subscribedUeAmbr"), "uplink", "1 Gbps");
        TK_ASSERT(g5c_json_len(g5c_json_get(g5c_json_get(v, "nssai"), "singleNssais")) == 2);
        {
            g5c_json *want = J("[{\"sst\":1}]");
            TK_ASSERT(g5c_json_equal(g5c_json_get(g5c_json_get(v, "nssai"), "defaultSingleNssais"), want));
            g5c_json_free(want);
        }
        g5c_json_free(v);
    }
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/" SUPI "/am-data", NULL, false, NULL, NULL) == 200); /* plmn-id optional */

    snprintf(path, sizeof path, "/nudm-sdm/v2/" SUPI "/sm-data?plmn-id=%s", PLMN);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200 && g5c_json_len(v) == 2);
    g5c_json_free(v);
    snprintf(path, sizeof path, "/nudm-sdm/v2/" SUPI "/sm-data?plmn-id=%s&single-nssai=%%7B%%22sst%%22%%3A2%%2C%%22sd%%22%%3A%%22010203%%22%%7D&dnn=ims", PLMN);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200 && g5c_json_len(v) == 1);
    {
        const g5c_json *cfgs = g5c_json_get(g5c_json_at(v, 0), "dnnConfigurations"), *ims = g5c_json_get(cfgs, "ims");
        int64_t qi = 0;
        TK_ASSERT(g5c_json_len(cfgs) == 1 && ims != NULL);
        TK_ASSERT(g5c_json_get_int(g5c_json_get(ims, "5gQosProfile"), "5qi", &qi) && qi == 5);
        EXPECT_STR(g5c_json_get(ims, "pduSessionTypes"), "defaultSessionType", "IPV4V6");
    }
    g5c_json_free(v);
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/" SUPI "/sm-data?single-nssai=%7B%22sst%22%3A9%7D", NULL, false, NULL, NULL) == 404);

    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/" SUPI "/nssai", NULL, false, &v, NULL) == 200);
    EXPECT_STR(g5c_json_at(g5c_json_get(v, "singleNssais"), 1), "sd", "010203");
    g5c_json_free(v);
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/" SUPI "/smf-select-data", NULL, false, &v, NULL) == 200);
    {
        const g5c_json *infos = g5c_json_get(g5c_json_get(g5c_json_get(v, "subscribedSnssaiInfos"), "2-010203"), "dnnInfos");
        bool found = false;
        for (size_t i = 0; i < g5c_json_len(infos); i++)
            if (g5c_streq(g5c_json_get_str(g5c_json_at(infos, i), "dnn"), "ims"))
                found = true;
        TK_ASSERT(found);
    }
    g5c_json_free(v);
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/imsi-001010000000099/am-data", NULL, false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/not-a-supi/am-data", NULL, false, NULL, NULL) == 400);
    teardown(&t);
}

static void test_sdm_subscriptions(void)
{
    T t;
    g5c_json *v;
    char path[256], *loc = NULL, id[32];
    const char *body = "{\"nfInstanceId\":\"amf-1\",\"callbackReference\":\"http://127.0.0.1:1/cb\",\"monitoredResourceUris\":[\"/x\"]}";
    setup(&t, false);
    TK_ASSERT(rq(&t, "POST", "/nudm-sdm/v2/" SUPI "/sdm-subscriptions", body, false, &v, &loc) == 201);
    snprintf(id, sizeof id, "%s", g5c_json_get_str(v, "subscriptionId"));
    g5c_json_free(v);
    snprintf(path, sizeof path, "/sdm-subscriptions/%s", id);
    TK_ASSERT(loc != NULL && strlen(loc) > strlen(path) && strcmp(loc + strlen(loc) - strlen(path), path) == 0);
    free(loc);
    snprintf(path, sizeof path, "/nudm-sdm/v2/" SUPI "/sdm-subscriptions/%s", id);
    TK_ASSERT(rq(&t, "PATCH", path, "[]", false, NULL, NULL) == 204);
    TK_ASSERT(rq(&t, "DELETE", path, NULL, false, NULL, NULL) == 204);
    TK_ASSERT(rq(&t, "DELETE", path, NULL, false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "POST", "/nudm-sdm/v2/" SUPI "/sdm-subscriptions", "{\"nfInstanceId\":\"x\"}", false, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/nudm-sdm/v2/imsi-001010000000099/sdm-subscriptions", body, false, NULL, NULL) == 404);
    teardown(&t);
}

static atomic_int sdm_notifs;
static char sdm_rid[96], sdm_op[16], sdm_path[32];

static void h_sdm_notify(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_resp err;
    g5c_json *j = g5c_req_json(req, &err);
    const g5c_json *it, *chg;
    (void)ctx;
    TK_ASSERT(j != NULL);
    it = g5c_json_at(g5c_json_get(j, "notifyItems"), 0);
    chg = g5c_json_at(g5c_json_get(it, "changes"), 0);
    snprintf(sdm_rid, sizeof sdm_rid, "%s", g5c_json_get_str(it, "resourceId"));
    snprintf(sdm_op, sizeof sdm_op, "%s", g5c_json_get_str(chg, "op"));
    snprintf(sdm_path, sizeof sdm_path, "%s", g5c_json_get_str(chg, "path"));
    g5c_json_free(j);
    atomic_fetch_add(&sdm_notifs, 1);
    g5c_resp_status(resp, 204);
}

/* Re-provisioning a subscriber notifies the holders of its sdm-subscriptions (TS 29.503 ModificationNotification). */
static void test_sdm_notification(void)
{
    T t;
    g5c_router *cbr = g5c_router_new();
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_server *cbs;
    char body[320], id[32], path[256];
    g5c_json *v;
    setup(&t, false);
    g5c_router_route(cbr, "POST", "/sdmcb", h_sdm_notify, NULL);
    cbs = g5c_server_start(&cfg, cbr, NULL, 0);
    snprintf(body, sizeof body, "{\"nfInstanceId\":\"amf-1\",\"callbackReference\":\"http://127.0.0.1:%u/sdmcb\","
             "\"monitoredResourceUris\":[\"/" SUPI "/am-data\"]}", g5c_server_port(cbs));
    TK_ASSERT(rq(&t, "POST", "/nudm-sdm/v2/" SUPI "/sdm-subscriptions", body, false, &v, NULL) == 201);
    snprintf(id, sizeof id, "%s", g5c_json_get_str(v, "subscriptionId"));
    g5c_json_free(v);
    atomic_store(&sdm_notifs, 0);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers",
                 "{\"supi\":\"" SUPI "\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[{\"sst\":1}]}",
                 true, NULL, NULL) < 300);
    TK_ASSERT(atomic_load(&sdm_notifs) == 1);
    TK_ASSERT(strcmp(sdm_rid, "/" SUPI "/am-data") == 0 && strcmp(sdm_op, "REPLACE") == 0 && strcmp(sdm_path, "/") == 0);
    snprintf(path, sizeof path, "/nudm-sdm/v2/" SUPI "/sdm-subscriptions/%s", id);
    TK_ASSERT(rq(&t, "DELETE", path, NULL, false, NULL, NULL) == 204);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers",
                 "{\"supi\":\"" SUPI "\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}", true, NULL, NULL) < 300);
    TK_ASSERT(atomic_load(&sdm_notifs) == 1); /* unsubscribed: nothing more is sent */
    g5c_server_stop(cbs);
    g5c_router_free(cbr);
    teardown(&t);
}

/* Retrieval of multiple data sets (TS 29.503 5.2.2.2.9) */
static void test_sdm_multiple_datasets(void)
{
    T t;
    g5c_json *v;
    const char *base = "/nudm-sdm/v2/" SUPI "?plmn-id=%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D&dataset-names=";
    char path[300];
    setup(&t, false);
    snprintf(path, sizeof path, "%sAM,SMF_SEL,SM,UEC_SMF", base);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200);
    TK_ASSERT(g5c_json_get(v, "amData") != NULL && g5c_json_get(v, "smfSelData") != NULL);
    TK_ASSERT(g5c_json_is(g5c_json_get(v, "smData"), G5C_J_ARRAY) && g5c_json_len(g5c_json_get(v, "smData")) >= 1);
    TK_ASSERT(g5c_json_get(v, "uecSmfData") != NULL && g5c_json_get(v, "traceData") == NULL);
    g5c_json_free(v);
    snprintf(path, sizeof path, "%sAM,SMF_SEL,TRACE,SMS_SUB", base); /* data this UDM does not hold: no member, no error */
    TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200 && g5c_json_get(v, "amData") != NULL && g5c_json_get(v, "traceData") == NULL);
    g5c_json_free(v);
    snprintf(path, sizeof path, "%sAM", base); /* minItems 2 */
    TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 400);
    snprintf(path, sizeof path, "%sAM,AM", base); /* uniqueItems */
    TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/" SUPI, NULL, false, NULL, NULL) == 400); /* parameter is required */
    snprintf(path, sizeof path, "/nudm-sdm/v2/imsi-001019999999999?dataset-names=AM,SM");
    TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 404);
    snprintf(path, sizeof path, "/nudm-sdm/v1/" SUPI "?dataset-names=AM,SMF_SEL"); /* also under v1 */
    TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 200);
    teardown(&t);
}

/* ---- UECM ---- */

static atomic_int dereg_calls;
static char dereg_reason[64], dereg_access[64];

static void h_dereg(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *j = g5c_req_json(req, resp);
    (void)ctx;
    if (j == NULL)
        return;
    snprintf(dereg_reason, sizeof dereg_reason, "%s", g5c_json_get_str(j, "deregReason"));
    snprintf(dereg_access, sizeof dereg_access, "%s", g5c_json_get_str(j, "accessType"));
    atomic_fetch_add(&dereg_calls, 1);
    g5c_json_free(j);
    g5c_resp_status(resp, 204);
}

static char *amf_reg(const char *instance, const char *cb)
{
    return g5c_xasprintf("{\"amfInstanceId\":\"%s\",\"deregCallbackUri\":\"%s\",\"guami\":{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"amfId\":\"020040\"},\"ratType\":\"NR\"}",
                         instance, cb);
}

static void test_uecm(void)
{
    T t;
    g5c_router *cbr = g5c_router_new();
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_server *cbs;
    char cb[96], *body, *loc = NULL;
    const char *path = "/nudm-uecm/v1/" SUPI "/registrations/amf-3gpp-access";
    g5c_json *v;
    setup(&t, false);
    g5c_router_route(cbr, "POST", "/dereg", h_dereg, NULL);
    cbs = g5c_server_start(&cfg, cbr, NULL, 0);
    snprintf(cb, sizeof cb, "http://127.0.0.1:%u/dereg", g5c_server_port(cbs));

    body = amf_reg("amf-old", cb);
    TK_ASSERT(rq(&t, "PUT", path, body, false, NULL, &loc) == 201 && loc != NULL);
    free(loc);
    TK_ASSERT(rq(&t, "PUT", path, body, false, NULL, NULL) == 200); /* refresh by the same AMF */
    TK_ASSERT(atomic_load(&dereg_calls) == 0);
    free(body);
    body = amf_reg("amf-new", "http://127.0.0.1:1/never");
    TK_ASSERT(rq(&t, "PUT", path, body, false, NULL, NULL) == 200); /* takeover: the old AMF is told */
    free(body);
    TK_ASSERT(atomic_load(&dereg_calls) == 1);
    TK_ASSERT(strcmp(dereg_reason, "UE_INITIAL_REGISTRATION") == 0 && strcmp(dereg_access, "3GPP_ACCESS") == 0);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200);
    EXPECT_STR(v, "amfInstanceId", "amf-new");
    g5c_json_free(v);

    TK_ASSERT(rq(&t, "PATCH", path, "{\"purgeFlag\":true}", false, NULL, NULL) == 204);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200);
    {
        bool b = false;
        TK_ASSERT(g5c_json_get_bool(v, "purgeFlag", &b) && b);
    }
    g5c_json_free(v);
    TK_ASSERT(rq(&t, "PATCH", path, "{\"amfInstanceId\":\"evil\"}", false, NULL, NULL) == 403);
    TK_ASSERT(rq(&t, "DELETE", path, NULL, false, NULL, NULL) == 204);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "DELETE", path, NULL, false, NULL, NULL) == 404);

    g5c_server_stop(cbs);
    g5c_router_free(cbr);
    teardown(&t);
}

static void test_uecm_validation_and_smf(void)
{
    T t;
    g5c_json *v;
    char *body;
    const char *smf5 = "/nudm-uecm/v1/" SUPI "/registrations/smf-registrations/5";
    const char *reg = "{\"smfInstanceId\":\"smf-1\",\"pduSessionId\":5,\"singleNssai\":{\"sst\":1},\"dnn\":\"internet\",\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"}}";
    setup(&t, false);
    TK_ASSERT(rq(&t, "PUT", "/nudm-uecm/v1/" SUPI "/registrations/amf-3gpp-access", "{\"amfInstanceId\":\"a\"}", false, NULL, NULL) == 400);
    body = amf_reg("a", "http://x/y");
    TK_ASSERT(rq(&t, "PUT", "/nudm-uecm/v1/imsi-001010000000099/registrations/amf-3gpp-access", body, false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "PUT", "/nudm-uecm/v1/zzz/registrations/amf-3gpp-access", body, false, NULL, NULL) == 400);
    free(body);

    TK_ASSERT(rq(&t, "PUT", smf5, reg, false, NULL, NULL) == 201);
    TK_ASSERT(rq(&t, "PUT", smf5, reg, false, NULL, NULL) == 200);
    TK_ASSERT(rq(&t, "PUT", "/nudm-uecm/v1/" SUPI "/registrations/smf-registrations/0", reg, false, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "PUT", smf5, "{\"smfInstanceId\":\"x\"}", false, NULL, NULL) == 400);

    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/" SUPI "/ue-context-in-smf-data", NULL, false, &v, NULL) == 200);
    EXPECT_STR(g5c_json_get(g5c_json_get(v, "pduSessions"), "5"), "dnn", "internet");
    EXPECT_STR(g5c_json_get(g5c_json_get(v, "pduSessions"), "5"), "smfInstanceId", "smf-1");
    g5c_json_free(v);
    TK_ASSERT(rq(&t, "DELETE", smf5, NULL, false, NULL, NULL) == 204);
    TK_ASSERT(rq(&t, "DELETE", smf5, NULL, false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/" SUPI "/ue-context-in-smf-data", NULL, false, &v, NULL) == 200);
    TK_ASSERT(g5c_json_len(g5c_json_get(v, "pduSessions")) == 0);
    g5c_json_free(v);
    teardown(&t);
}

/* TS 29.500 requires absolute URIs in Location headers; Open5GS's AUSF rejects relative ones. */
/* ---- Nudm_EventExposure: a fake AMF and a fake subscriber over real sockets ---- */

static atomic_int ee_amf_posts, ee_amf_deletes, ee_cb_calls;
static char ee_amf_body[2048], ee_cb_body[2048];

static void h_ee_amf_create(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *j = g5c_req_json(req, resp), *o, *rl;
    bool imm = false;
    (void)ctx;
    if (j == NULL)
        return;
    {
        char *s = g5c_json_to_string(j, NULL);
        snprintf(ee_amf_body, sizeof ee_amf_body, "%s", s);
        free(s);
    }
    (void)g5c_json_get_bool(g5c_json_get(j, "subscription"), "immediateFlag", &imm);
    atomic_fetch_add(&ee_amf_posts, 1);
    o = g5c_json_new_obj();
    g5c_json_set_str(o, "subscriptionId", "77");
    if (imm) { /* the AMF answers with the current state */
        rl = g5c_json_set(o, "reportList", g5c_json_new_arr());
        {
            g5c_json *rep = g5c_json_push(rl, g5c_json_new_obj()), *cm = g5c_json_set(rep, "cmInfoList", g5c_json_new_arr());
            g5c_json_set_str(rep, "type", "CONNECTIVITY_STATE_REPORT");
            g5c_json_set_str(rep, "timeStamp", "2026-11-02T10:00:00Z");
            g5c_json_set_str(g5c_json_push(cm, g5c_json_new_obj()), "cmState", "IDLE");
        }
    }
    g5c_resp_json(resp, 201, o);
    g5c_json_free(o);
    g5c_json_free(j);
}

static void h_ee_amf_delete(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    TK_ASSERT(strcmp(g5c_req_param(req, "subscriptionId"), "77") == 0);
    atomic_fetch_add(&ee_amf_deletes, 1);
    g5c_resp_status(resp, 204);
}

static void h_ee_cb(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_json *j = g5c_req_json(req, resp);
    (void)ctx;
    if (j == NULL)
        return;
    {
        char *s = g5c_json_to_string(j, NULL);
        snprintf(ee_cb_body, sizeof ee_cb_body, "%s", s);
        free(s);
    }
    atomic_fetch_add(&ee_cb_calls, 1);
    g5c_json_free(j);
    g5c_resp_status(resp, 204);
}

/* the path of the notification URI the UDM gave the AMF */
static void ee_notify_path(char *out, size_t cap)
{
    g5c_json *j = g5c_json_parse(ee_amf_body, strlen(ee_amf_body), NULL, 0);
    const char *u = g5c_json_get_str(g5c_json_get(j, "subscription"), "eventNotifyUri"), *p = u ? strstr(u, "/nudm-ee/") : NULL;
    TK_ASSERT(p != NULL);
    snprintf(out, cap, "%s", p);
    g5c_json_free(j);
}

static void test_ee(void)
{
    T t;
    g5c_router *amfr = g5c_router_new(), *cbr = g5c_router_new();
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_server *amf, *cbs;
    char amf_base[64], dereg[96], body[900], notify[160], *regb, id[16], path[200], sf[80];
    const char *reg = "/nudm-uecm/v1/" SUPI "/registrations/amf-3gpp-access";
    g5c_json *v;
    setup(&t, false);
    g5c_router_route(amfr, "POST", "/namf-evts/v1/subscriptions", h_ee_amf_create, NULL);
    g5c_router_route(amfr, "DELETE", "/namf-evts/v1/subscriptions/{subscriptionId}", h_ee_amf_delete, NULL);
    amf = g5c_server_start(&cfg, amfr, NULL, 0);
    g5c_router_route(cbr, "POST", "/eecb", h_ee_cb, NULL);
    cbs = g5c_server_start(&cfg, cbr, NULL, 0);
    snprintf(amf_base, sizeof amf_base, "http://127.0.0.1:%u", g5c_server_port(amf));
    snprintf(dereg, sizeof dereg, "%s/dereg", amf_base);
    t.u.ee_self_uri = g5c_xstrdup(t.base);
    snprintf(sf, sizeof sf, "/tmp/g5c-ee-state-%d.json", (int)getpid());
    unlink(sf);
    t.u.ee_state_file = g5c_xstrdup(sf); /* A-05: the subscriptions are written down after every change */
    atomic_store(&ee_amf_posts, 0);
    atomic_store(&ee_amf_deletes, 0);
    atomic_store(&ee_cb_calls, 0);
    snprintf(body, sizeof body,
             "{\"callbackReference\":\"http://127.0.0.1:%u/eecb\",\"monitoringConfigurations\":{\"1\":{\"eventType\":\"LOSS_OF_CONNECTIVITY\"},"
             "\"2\":{\"eventType\":\"UE_CONNECTION_MANAGEMENT_STATE\",\"immediateFlag\":true}},\"reportingOptions\":{\"maxNumOfReports\":5}}",
             g5c_server_port(cbs));

    /* no AMF registration yet: nobody to subscribe at */
    TK_ASSERT(rq(&t, "POST", "/nudm-ee/v1/" SUPI "/ee-subscriptions", body, false, NULL, NULL) == 404);
    regb = amf_reg("amf-1", dereg);
    TK_ASSERT(rq(&t, "PUT", reg, regb, false, NULL, NULL) == 201);
    free(regb);

    /* validation */
    TK_ASSERT(rq(&t, "POST", "/nudm-ee/v1/" SUPI "/ee-subscriptions", "{\"callbackReference\":\"x\",\"monitoringConfigurations\":{}}", false, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/nudm-ee/v1/" SUPI "/ee-subscriptions", "{\"callbackReference\":\"http://h/x\",\"monitoringConfigurations\":{\"1\":{\"eventType\":\"ROAMING_STATUS\"}}}", false, NULL, NULL) == 501);
    TK_ASSERT(rq(&t, "POST", "/nudm-ee/v1/" SUPI "/ee-subscriptions", "{\"callbackReference\":\"http://h/x\",\"monitoringConfigurations\":{\"abc\":{\"eventType\":\"LOSS_OF_CONNECTIVITY\"}}}", false, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/nudm-ee/v1/extgroupid-g@x/ee-subscriptions", body, false, NULL, NULL) == 501);
    TK_ASSERT(rq(&t, "POST", "/nudm-ee/v1/msisdn-99999999/ee-subscriptions", body, false, NULL, NULL) == 404);
    TK_ASSERT(atomic_load(&ee_amf_posts) == 0);

    /* a subscription: translated for the AMF, the current state returned at once */
    TK_ASSERT(rq(&t, "POST", "/nudm-ee/v1/" SUPI "/ee-subscriptions", body, false, &v, NULL) == 201);
    TK_ASSERT(atomic_load(&ee_amf_posts) == 1);
    snprintf(id, sizeof id, "%s", g5c_json_get_str(g5c_json_get(v, "eeSubscription"), "subscriptionId"));
    TK_ASSERT(g5c_json_len(g5c_json_get(v, "eventReports")) == 1);
    {
        const g5c_json *mr = g5c_json_at(g5c_json_get(v, "eventReports"), 0);
        int64_t ref = 0;
        TK_ASSERT(g5c_json_get_int(mr, "referenceId", &ref) && ref == 2);
        EXPECT_STR(mr, "eventType", "UE_CONNECTION_MANAGEMENT_STATE");
        EXPECT_STR(g5c_json_at(g5c_json_get(g5c_json_get(mr, "report"), "newCmInfoList"), 0), "cmState", "IDLE");
    }
    g5c_json_free(v);
    TK_ASSERT(strstr(ee_amf_body, "\"LOSS_OF_CONNECTIVITY\"") && strstr(ee_amf_body, "\"CONNECTIVITY_STATE_REPORT\"") && strstr(ee_amf_body, "\"supi\":\"" SUPI "\""));
    ee_notify_path(notify, sizeof notify);

    /* a report from the AMF reaches the subscriber as a MonitoringReport with the subscriber's reference id */
    TK_ASSERT(rq(&t, "POST", notify, "{\"reportList\":[{\"type\":\"LOSS_OF_CONNECTIVITY\",\"lossOfConnectReason\":\"UE_DEREGISTERED\",\"timeStamp\":\"2026-11-02T10:01:00Z\"}]}", false, NULL, NULL) == 204);
    TK_ASSERT(atomic_load(&ee_cb_calls) == 1);
    TK_ASSERT(strstr(ee_cb_body, "\"referenceId\":1") && strstr(ee_cb_body, "\"eventType\":\"LOSS_OF_CONNECTIVITY\"") && strstr(ee_cb_body, "\"lossOfConnectReason\":\"UE_DEREGISTERED\""));
    TK_ASSERT(ee_cb_body[0] == '[');
    /* a type nobody subscribed to produces nothing */
    TK_ASSERT(rq(&t, "POST", notify, "{\"reportList\":[{\"type\":\"LOCATION_REPORT\",\"timeStamp\":\"2026-11-02T10:01:30Z\"}]}", false, NULL, NULL) == 204);
    TK_ASSERT(atomic_load(&ee_cb_calls) == 1);

    /* a restart of the UDM: the table is forgotten and read again from the file; everything below then works on the restored subscription */
    {
        char buf[4096];
        size_t k;
        FILE *f = fopen(sf, "rb");
        TK_ASSERT(f != NULL);
        k = fread(buf, 1, sizeof buf - 1, f);
        buf[k] = 0;
        fclose(f);
        TK_ASSERT(strstr(buf, "\"amfSub\":\"77\"") != NULL && strstr(buf, "\"sent\":1") != NULL && strstr(buf, "\"next\"") != NULL);
        pthread_mutex_lock(&t.u.mu);
        g5c_json_free(t.u.ee_subs);
        t.u.ee_subs = g5c_json_new_obj();
        t.u.next_ee = 1;
        pthread_mutex_unlock(&t.u.mu);
        udm_ee_load(&t.u);
        TK_ASSERT(g5c_json_len(t.u.ee_subs) == 1 && t.u.next_ee > 1);
    }
    /* modification: at most two reports; the second ends the subscription at the UDM and at the AMF */
    snprintf(path, sizeof path, "/nudm-ee/v1/" SUPI "/ee-subscriptions/%s", id);
    TK_ASSERT(rq(&t, "PATCH", path, "[{\"op\":\"replace\",\"path\":\"/reportingOptions/maxNumOfReports\",\"value\":2}]", false, NULL, NULL) == 204);
    TK_ASSERT(rq(&t, "PATCH", path, "[{\"op\":\"replace\",\"path\":\"/monitoringConfigurations\",\"value\":{}}]", false, NULL, NULL) == 403);
    TK_ASSERT(rq(&t, "PATCH", "/nudm-ee/v1/" SUPI "/ee-subscriptions/999", "[{\"op\":\"replace\",\"path\":\"/callbackReference\",\"value\":\"http://h/y\"}]", false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "POST", notify, "{\"reportList\":[{\"type\":\"CONNECTIVITY_STATE_REPORT\",\"cmInfoList\":[{\"cmState\":\"CONNECTED\"}],\"timeStamp\":\"2026-11-02T10:02:00Z\"}]}", false, NULL, NULL) == 204);
    TK_ASSERT(atomic_load(&ee_cb_calls) == 2 && strstr(ee_cb_body, "\"referenceId\":2") && strstr(ee_cb_body, "\"newCmInfoList\""));
    TK_ASSERT(atomic_load(&ee_amf_deletes) == 1);
    TK_ASSERT(rq(&t, "POST", notify, "{\"reportList\":[]}", false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "DELETE", path, NULL, false, NULL, NULL) == 404);

    /* unsubscribe by the subscriber */
    TK_ASSERT(rq(&t, "POST", "/nudm-ee/v1/" SUPI "/ee-subscriptions", body, false, &v, NULL) == 201);
    snprintf(path, sizeof path, "/nudm-ee/v1/" SUPI "/ee-subscriptions/%s", g5c_json_get_str(g5c_json_get(v, "eeSubscription"), "subscriptionId"));
    g5c_json_free(v);
    TK_ASSERT(rq(&t, "DELETE", path, NULL, false, NULL, NULL) == 204);
    TK_ASSERT(atomic_load(&ee_amf_deletes) == 2);

    /* any UE: the configured AMF */
    t.u.ee_amf_uri = g5c_xstrdup(amf_base);
    TK_ASSERT(rq(&t, "POST", "/nudm-ee/v1/anyUE/ee-subscriptions", body, false, NULL, NULL) == 201);
    TK_ASSERT(strstr(ee_amf_body, "\"anyUE\":true") && !strstr(ee_amf_body, "\"supi\""));

    unlink(sf);
    g5c_server_stop(amf);
    g5c_server_stop(cbs);
    g5c_router_free(amfr);
    g5c_router_free(cbr);
    teardown(&t);
}

static void test_location_absolute(void)
{
    T t;
    char *loc = NULL, expect[256], *body;
    setup(&t, false);
    TK_ASSERT(rq(&t, "PUT", "/nudm-uecm/v1/" SUPI "/registrations/smf-registrations/5",
                 "{\"smfInstanceId\":\"smf-1\",\"pduSessionId\":5,\"singleNssai\":{\"sst\":1},\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"}}", false, NULL, &loc) == 201);
    snprintf(expect, sizeof expect, "%s/nudm-uecm/v1/" SUPI "/registrations/smf-registrations/5", t.base);
    TK_ASSERT(loc && strcmp(loc, expect) == 0);
    free(loc);
    body = amf_reg("a", "http://127.0.0.1:1/x");
    TK_ASSERT(rq(&t, "PUT", "/nudm-uecm/v1/" SUPI "/registrations/amf-3gpp-access", body, false, NULL, &loc) == 201);
    free(body);
    snprintf(expect, sizeof expect, "%s/nudm-uecm/", t.base);
    TK_ASSERT(loc && strncmp(loc, expect, strlen(expect)) == 0);
    free(loc);
    TK_ASSERT(rq(&t, "POST", "/nudm-ueau/v1/" SUPI "/auth-events",
                 "{\"nfInstanceId\":\"ausf\",\"success\":true,\"timeStamp\":\"2026-10-01T00:00:00Z\",\"authType\":\"5G_AKA\",\"servingNetworkName\":\"5G:mnc001.mcc001.3gppnetwork.org\"}",
                 false, NULL, &loc) == 201);
    snprintf(expect, sizeof expect, "%s/nudm-ueau/v1/" SUPI "/auth-events/", t.base);
    TK_ASSERT(loc && strncmp(loc, expect, strlen(expect)) == 0);
    free(loc);
    TK_ASSERT(rq(&t, "POST", "/nudm-sdm/v2/" SUPI "/sdm-subscriptions", "{\"callbackReference\":\"http://x/y\"}", false, NULL, &loc) == 201);
    snprintf(expect, sizeof expect, "%s/nudm-sdm/v2/" SUPI "/sdm-subscriptions/", t.base);
    TK_ASSERT(loc && strncmp(loc, expect, strlen(expect)) == 0);
    free(loc);
    teardown(&t);
}

/* Open5GS's AUSF sends PUT /nudm-ueau/v1/{supi}/auth-events (auth removal) after de-registration. */
static void test_auth_removal(void)
{
    T t;
    const char *body = "{\"nfInstanceId\":\"ausf\",\"success\":true,\"timeStamp\":\"2026-10-01T00:00:00Z\",\"authType\":\"5G_AKA\",\"servingNetworkName\":\"5G:mnc001.mcc001.3gppnetwork.org\",\"authRemovalInd\":true}";
    setup(&t, false);
    TK_ASSERT(rq(&t, "PUT", "/nudm-ueau/v1/" SUPI "/auth-events", body, false, NULL, NULL) == 204);
    TK_ASSERT(rq(&t, "PUT", "/nudm-ueau/v1/" SUPI "/auth-events/some-id", body, false, NULL, NULL) == 204);
    TK_ASSERT(rq(&t, "PUT", "/nudm-ueau/v1/imsi-001010000000099/auth-events", body, false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "PUT", "/nudm-ueau/v1/bogus/auth-events", body, false, NULL, NULL) == 400);
    teardown(&t);
}

/* ---- UEAU ---- */

static void test_ueau(bool encrypt)
{
    T t;
    g5c_json *v, *stored;
    const char *snn = "5G:mnc001.mcc001.3gppnetwork.org";
    char body[256], path[256], *rand_hex;
    const char *gen = "/nudm-ueau/v1/" SUPI "/security-information/generate-auth-data";
    setup(&t, encrypt);
    t.use_fixed = 1;
    h("23553cbe9637a89d218ae64dae47bf35", t.fixed_rand, 16);
    snprintf(body, sizeof body, "{\"servingNetworkName\":\"%s\"}", snn);

    TK_ASSERT(rq(&t, "POST", gen, body, false, &v, NULL) == 200);
    EXPECT_STR(v, "authType", "5G_AKA");
    EXPECT_STR(v, "supi", SUPI);
    {
        const g5c_json *av = g5c_json_get(v, "authenticationVector");
        EXPECT_STR(av, "avType", "5G_HE_AKA");
        EXPECT_STR(av, "rand", "23553cbe9637a89d218ae64dae47bf35");
        TK_ASSERT(strlen(g5c_json_get_str(av, "autn")) == 32 && strlen(g5c_json_get_str(av, "xresStar")) == 32 &&
                  strlen(g5c_json_get_str(av, "kausf")) == 64);
    }
    g5c_json_free(v);

    /* SQN advanced and stored by 32 before the vector was returned */
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers/" SUPI, NULL, true, &v, NULL) == 200);
    EXPECT_STR(v, "sqn", "000000000020");
    EXPECT_STR(v, "protectionParameterId", encrypt ? UDM_PROT_AES256GCM : UDM_PROT_NONE);
    TK_ASSERT(g5c_json_get(v, "encPermanentKey") == NULL); /* credentials are never returned */
    g5c_json_free(v);
    TK_ASSERT(rq(&t, "POST", gen, body, false, NULL, NULL) == 200);
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers/" SUPI, NULL, true, &v, NULL) == 200);
    EXPECT_STR(v, "sqn", "000000000040");
    g5c_json_free(v);

    /* at rest: the UDR holds K as ciphertext when a master key is configured */
    stored = g5c_udr_get(t.store, SUPI, UDR_AUTH);
    TK_ASSERT(stored != NULL);
    if (encrypt)
        TK_ASSERT(strstr(g5c_json_get_str(stored, "encPermanentKey"), K_HEX) == NULL);
    else
        EXPECT_STR(stored, "encPermanentKey", K_HEX);
    g5c_json_free(stored);

    /* resynchronisation: the UE reports SQNms 0x1000; the next vector continues from 0x1020 */
    {
        g5c_milenage m;
        g5c_milenage_vector mv;
        uint8_t k[16], op[16], opc[16], sqn_ms[6] = {0, 0, 0, 0, 0x10, 0x00}, mac_a[8], mac_s[8], auts[14], rnd[16];
        char *auts_hex;
        h(K_HEX, k, 16);
        h(OP_HEX, op, 16);
        TK_ASSERT(g5c_milenage_derive_opc(k, op, opc) == 0);
        memcpy(rnd, t.fixed_rand, 16);
        g5c_milenage_init(&m, k, opc);
        TK_ASSERT(g5c_milenage_f2345(&m, rnd, &mv) == 0 && g5c_milenage_f1(&m, rnd, sqn_ms, (const uint8_t[]){0, 0}, mac_a, mac_s) == 0);
        for (int i = 0; i < 6; i++)
            auts[i] = (uint8_t)(sqn_ms[i] ^ mv.ak_star[i]);
        memcpy(auts + 6, mac_s, 8);
        auts_hex = g5c_hex_encode(auts, 14);
        rand_hex = g5c_hex_encode(rnd, 16);
        snprintf(body, sizeof body, "{\"servingNetworkName\":\"%s\",\"resynchronizationInfo\":{\"rand\":\"%s\",\"auts\":\"%s\"}}", snn, rand_hex, auts_hex);
        TK_ASSERT(rq(&t, "POST", gen, body, false, NULL, NULL) == 200);
        TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers/" SUPI, NULL, true, &v, NULL) == 200);
        EXPECT_STR(v, "sqn", "000000001020");
        g5c_json_free(v);
        auts[13] ^= 1; /* forged AUTS */
        free(auts_hex);
        auts_hex = g5c_hex_encode(auts, 14);
        snprintf(body, sizeof body, "{\"servingNetworkName\":\"%s\",\"resynchronizationInfo\":{\"rand\":\"%s\",\"auts\":\"%s\"}}", snn, rand_hex, auts_hex);
        TK_ASSERT(rq(&t, "POST", gen, body, false, NULL, NULL) == 403);
        free(auts_hex);
        free(rand_hex);
    }

    /* rejections */
    TK_ASSERT(rq(&t, "POST", gen, "{\"servingNetworkName\":\"5G:mnc01.mcc001.3gppnetwork.org\"}", false, NULL, NULL) == 403);
    TK_ASSERT(rq(&t, "POST", gen, "{}", false, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/nudm-ueau/v1/imsi-001010000000099/security-information/generate-auth-data", "{\"servingNetworkName\":\"5G:mnc001.mcc001.3gppnetwork.org\"}", false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "POST", "/nudm-ueau/v1/zzz/security-information/generate-auth-data", "{\"servingNetworkName\":\"5G:mnc001.mcc001.3gppnetwork.org\"}", false, NULL, NULL) == 400);

    /* an auth event is stored */
    snprintf(path, sizeof path, "/nudm-ueau/v1/" SUPI "/auth-events");
    TK_ASSERT(rq(&t, "POST", path, "{\"nfInstanceId\":\"ausf\",\"success\":false,\"timeStamp\":\"2026-10-01T00:00:00Z\",\"authType\":\"5G_AKA\",\"servingNetworkName\":\"5G:mnc001.mcc001.3gppnetwork.org\"}", false, NULL, NULL) == 201);
    stored = g5c_udr_get(t.store, SUPI, UDR_AUTH_STATUS);
    TK_ASSERT(stored != NULL);
    {
        bool b = true;
        TK_ASSERT(g5c_json_get_bool(stored, "success", &b) && !b);
    }
    g5c_json_free(stored);
    TK_ASSERT(rq(&t, "POST", path, "{\"success\":true}", false, NULL, NULL) == 400);
    teardown(&t);
}

/* suci.null_scheme: reject (TS 33.501 5.2.5): a SUCI in clear is refused, a concealed one and a SUPI on the SBI still work */
/* device groups (backlog H-04): GetGroupIdentifiers, the group ids in am-data, a reload, the configuration errors */
static void test_groups(void)
{
    T t;
    g5c_json *v = NULL, *cfg;
    char err[200], path[512];
    const char *ext = "extgroupid-meters%40example.com", *gen = "/nudm-sdm/v2/group-data/group-identifiers";
    udm_groups *gs;
    cfg = J("[{\"ext_group_id\":\"extgroupid-meters@example.com\",\"int_group_id\":\"0000000a-001-01-0a\",\"members\":[\"" SUPI "\",\"imsi-001010000000009\"],\"supi_ranges\":[{\"start\":\"001010000000100\",\"end\":\"001010000000199\"}]},"
            "{\"ext_group_id\":\"extgroupid-cams@example.com\",\"int_group_id\":\"0000000b-001-01-0b\",\"supi_ranges\":[{\"start\":\"001010000000001\",\"end\":\"001010000000001\"}]}]");
    gs = udm_groups_parse(cfg, err, sizeof err);
    TK_ASSERT(gs != NULL && udm_groups_count(gs) == 2);
    setup(&t, false);
    udm_set_groups(&t.u, gs);
    g5c_json_free(cfg);
    snprintf(path, sizeof path, "%s?ext-group-id=%s&ue-id-ind=true", gen, ext);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "intGroupId"), "0000000a-001-01-0a") == 0 && g5c_json_len(g5c_json_get(v, "ueIdList")) == 2);
    g5c_json_free(v);
    snprintf(path, sizeof path, "%s?int-group-id=0000000a-001-01-0a", gen);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200 && strcmp(g5c_json_get_str(v, "extGroupId"), "extgroupid-meters@example.com") == 0 && g5c_json_get(v, "ueIdList") == NULL);
    g5c_json_free(v);
    snprintf(path, sizeof path, "%s?ext-group-id=extgroupid-none%%40example.com", gen);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "GET", gen, NULL, false, NULL, NULL) == 400); /* neither */
    snprintf(path, sizeof path, "%s?ext-group-id=%s&int-group-id=0000000a-001-01-0a", gen, ext);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 400); /* both */
    snprintf(path, sizeof path, "%s?int-group-id=nonsense", gen);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 400);
    /* the member's access and mobility data carries the identifiers of its groups */
    snprintf(path, sizeof path, "/nudm-sdm/v2/" SUPI "/am-data?plmn-id=%s", PLMN);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200);
    {
        const g5c_json *ids = g5c_json_get(v, "internalGroupIds");
        TK_ASSERT(g5c_json_len(ids) == 2 && strcmp(g5c_json_str(g5c_json_at(ids, 0)), "0000000a-001-01-0a") == 0 && strcmp(g5c_json_str(g5c_json_at(ids, 1)), "0000000b-001-01-0b") == 0);
    }
    g5c_json_free(v);
    /* a reload replaces them */
    cfg = J("[{\"ext_group_id\":\"extgroupid-only@example.com\",\"int_group_id\":\"0000000c-001-01-0c\",\"members\":[\"imsi-001010000000777\"]}]");
    TK_ASSERT(udm_reload_groups(&t.u, NULL, cfg, err, sizeof err) == 0);
    g5c_json_free(cfg);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200 && g5c_json_get(v, "internalGroupIds") == NULL);
    g5c_json_free(v);
    cfg = J("[{\"ext_group_id\":\"bad\",\"int_group_id\":\"0000000c-001-01-0c\"}]");
    TK_ASSERT(udm_reload_groups(&t.u, NULL, cfg, err, sizeof err) == -1 && strstr(err, "ext_group_id") != NULL);
    g5c_json_free(cfg);
    TK_ASSERT(udm_groups_count(t.u.groups) == 1); /* the refused reload changed nothing */
    {   /* configuration errors */
        static const char *const bad[] = {
            "[{\"ext_group_id\":\"extgroupid-a@b\",\"int_group_id\":\"123\"}]",
            "[{\"ext_group_id\":\"extgroupid-a@b\",\"int_group_id\":\"0000000a-001-01-0a\",\"members\":[\"msisdn-1\"]}]",
            "[{\"ext_group_id\":\"extgroupid-a@b\",\"int_group_id\":\"0000000a-001-01-0a\",\"supi_ranges\":[{\"start\":\"2\",\"end\":\"1\"}]}]",
            "[{\"ext_group_id\":\"extgroupid-a@b\",\"int_group_id\":\"0000000a-001-01-0a\",\"surprise\":1}]",
            "[{\"ext_group_id\":\"extgroupid-a@b\",\"int_group_id\":\"0000000a-001-01-0a\"},{\"ext_group_id\":\"extgroupid-c@b\",\"int_group_id\":\"0000000a-001-01-0a\"}]",
            "{}",
        };
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
            g5c_json *c = J(bad[i]);
            err[0] = 0;
            TK_ASSERT(udm_groups_parse(c, err, sizeof err) == NULL && err[0] != 0);
            g5c_json_free(c);
        }
    }
    teardown(&t);
}

/* auth_hook (backlog G-03): a program supplies the vector for the subscribers it serves; for the others it says so and the UDM derives it */
static void test_auth_hook(void)
{
    T t;
    char path[] = "/tmp/g5c-authhook-XXXXXX", err[200];
    const char *body = "{\"servingNetworkName\":\"5G:mnc001.mcc001.3gppnetwork.org\"}";
    const char *gen = "/security-information/generate-auth-data";
    char url[160];
    g5c_json *v = NULL;
    FILE *f;
    int fd = mkstemp(path);
    TK_ASSERT(fd >= 0);
    f = fdopen(fd, "w");
    fputs("#!/bin/sh\nread line\ncase \"$line\" in\n"
          " *imsi-001010000000007*) printf '{\"authType\":\"5G_AKA\",\"authenticationVector\":{\"rand\":\"00112233445566778899aabbccddeeff\",\"xresStar\":\"ffeeddccbbaa99887766554433221100\","
          "\"autn\":\"0f0e0d0c0b0a09080706050403020100\",\"kausf\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\"}}'; exit 0;;\n"
          " *imsi-001010000000008*) exit 4;;\n *imsi-001010000000009*) exit 5;;\n"
          " *imsi-001010000000010*) printf 'not json'; exit 0;;\n"
          " *imsi-001010000000011*) printf '{\"authType\":\"5G_AKA\",\"authenticationVector\":{\"rand\":\"00\"}}'; exit 0;;\n"
          " *imsi-001010000000012*) sleep 30;;\n *) exit 3;;\nesac\n", f);
    fclose(f);
    TK_ASSERT(chmod(path, 0755) == 0);
    setup(&t, false);
    t.u.auth_hook = g5c_hookcall_new("auth_vector", path, 1, t.u.metrics, err, sizeof err);
    TK_ASSERT(t.u.auth_hook != NULL);
    snprintf(url, sizeof url, "/nudm-ueau/v1/imsi-001010000000007%s", gen);
    TK_ASSERT(rq(&t, "POST", url, body, false, &v, NULL) == 200); /* not provisioned in the UDR: the program serves it */
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authType"), "5G_AKA") == 0 && strcmp(g5c_json_get_str(v, "supi"), "imsi-001010000000007") == 0 &&
              strcmp(g5c_json_get_str(g5c_json_get(v, "authenticationVector"), "avType"), "5G_HE_AKA") == 0 &&
              strcmp(g5c_json_get_str(g5c_json_get(v, "authenticationVector"), "rand"), "00112233445566778899aabbccddeeff") == 0);
    g5c_json_free(v);
    snprintf(url, sizeof url, "/nudm-ueau/v1/imsi-001010000000008%s", gen);
    TK_ASSERT(rq(&t, "POST", url, body, false, NULL, NULL) == 404);
    snprintf(url, sizeof url, "/nudm-ueau/v1/imsi-001010000000009%s", gen);
    TK_ASSERT(rq(&t, "POST", url, body, false, NULL, NULL) == 403);
    snprintf(url, sizeof url, "/nudm-ueau/v1/imsi-001010000000010%s", gen);
    TK_ASSERT(rq(&t, "POST", url, body, false, NULL, NULL) == 500); /* an answer that is not a vector */
    snprintf(url, sizeof url, "/nudm-ueau/v1/imsi-001010000000011%s", gen);
    TK_ASSERT(rq(&t, "POST", url, body, false, NULL, NULL) == 500); /* a vector with the wrong sizes */
    snprintf(url, sizeof url, "/nudm-ueau/v1/imsi-001010000000012%s", gen);
    TK_ASSERT(rq(&t, "POST", url, body, false, NULL, NULL) == 500); /* the program takes longer than its timeout and is killed */
    TK_ASSERT(rq(&t, "POST", "/nudm-ueau/v1/" SUPI "/security-information/generate-auth-data", body, false, NULL, NULL) == 200); /* "not mine": derived from the stored K and OPc */
    {
        char *m = g5c_registry_render(t.u.metrics);
        TK_ASSERT(strstr(m, "g5c_hook_items_total{hook=\"auth_vector\",result=\"timeout\"} 1") != NULL);
        free(m);
    }
    teardown(&t);
    unlink(path);
}

static void test_null_scheme_policy(void)
{
    T t;
    udm_hnkey k = {.id = 1, .profile = G5C_PROFILE_A};
    uint8_t eph[32], hn_pub[64], msin[16], out[128];
    size_t pl = 0, ml = 0, ol = 0;
    char *hex, path[400], supi[32];
    const char *body = "{\"servingNetworkName\":\"5G:mnc001.mcc001.3gppnetwork.org\"}";
    const char *clear = "/nudm-ueau/v1/suci-0-001-01-0000-0-0-0000000001/security-information/generate-auth-data";
    g5c_json *v = NULL;
    setup(&t, false);
    memset(k.secret, 0x42, 32);
    t.u.hn_keys = &k;
    t.u.nhn_keys = 1;
    TK_ASSERT(rq(&t, "POST", clear, body, false, &v, NULL) == 200); /* the default accepts it */
    g5c_json_free(v);
    t.u.refuse_null_scheme = true;
    TK_ASSERT(rq(&t, "POST", clear, body, false, &v, NULL) == 403);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "cause"), "AUTHENTICATION_REJECTED") == 0 && strstr(g5c_json_get_str(v, "detail"), "null protection scheme") != NULL);
    g5c_json_free(v);
    TK_ASSERT(rq(&t, "POST", "/nudm-ueau/v1/" SUPI "/security-information/generate-auth-data", body, false, NULL, NULL) == 200); /* a SUPI between functions is not a SUCI */
    memset(eph, 0x77, 32);
    TK_ASSERT(g5c_suci_public_key(G5C_PROFILE_A, k.secret, hn_pub, sizeof hn_pub, &pl) == 0);
    TK_ASSERT(g5c_msin_to_bcd("0000000001", msin, sizeof msin, &ml) == 0);
    TK_ASSERT(g5c_suci_conceal(G5C_PROFILE_A, hn_pub, pl, eph, msin, ml, out, sizeof out, &ol) == 0);
    hex = g5c_hex_encode(out, ol);
    snprintf(path, sizeof path, "/nudm-ueau/v1/suci-0-001-01-0000-1-1-%s/security-information/generate-auth-data", hex);
    free(hex);
    TK_ASSERT(rq(&t, "POST", path, body, false, NULL, NULL) == 200); /* a concealed SUCI is not affected */
    TK_ASSERT(udm_resolve_ex("suci-0-001-01-0000-0-0-0000000001", NULL, 0, false, supi, sizeof supi) == UDM_ID_NULL_SCHEME);
    t.u.hn_keys = NULL; /* the stack array is not the UDM's to free */
    t.u.nhn_keys = 0;
    teardown(&t);
}

/* EAP-AKA' (TS 33.501 6.1.3.1 step 1 and 2) */
static void test_ueau_eap(void)
{
    T t;
    g5c_json *v, *orig;
    const char *snn = "5G:mnc001.mcc001.3gppnetwork.org", *eap_supi = "imsi-001010000000002";
    char body[256];
    const char *gen = "/nudm-ueau/v1/imsi-001010000000002/security-information/generate-auth-data";
    setup(&t, true);
    t.use_fixed = 1;
    h("23553cbe9637a89d218ae64dae47bf35", t.fixed_rand, 16);
    snprintf(body, sizeof body, "{\"supi\":\"%s\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"auth_method\":\"EAP_AKA_PRIME\"}", eap_supi);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", body, true, NULL, NULL) == 201);
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers/imsi-001010000000002", NULL, true, &v, NULL) == 200);
    EXPECT_STR(v, "authenticationMethod", "EAP_AKA_PRIME");
    g5c_json_free(v);
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers/" SUPI, NULL, true, &v, NULL) == 200);
    EXPECT_STR(v, "authenticationMethod", "5G_AKA"); /* the default */
    g5c_json_free(v);
    snprintf(body, sizeof body, "{\"servingNetworkName\":\"%s\",\"ausfInstanceId\":\"ausf-1\"}", snn);
    TK_ASSERT(rq(&t, "POST", gen, body, false, &v, NULL) == 200);
    EXPECT_STR(v, "authType", "EAP_AKA_PRIME");
    EXPECT_STR(v, "supi", eap_supi);
    {
        const g5c_json *av = g5c_json_get(v, "authenticationVector");
        g5c_milenage m;
        g5c_milenage_vector mv;
        uint8_t k[16], op[16], opc[16], rnd[16], autn[16], ckp[16], ikp[16], got[16];
        EXPECT_STR(av, "avType", "EAP_AKA_PRIME");
        EXPECT_STR(av, "rand", "23553cbe9637a89d218ae64dae47bf35");
        TK_ASSERT(g5c_json_get(av, "xresStar") == NULL && g5c_json_get(av, "kausf") == NULL); /* nothing of the 5G AKA vector */
        h(K_HEX, k, 16);
        h(OP_HEX, op, 16);
        h("23553cbe9637a89d218ae64dae47bf35", rnd, 16);
        TK_ASSERT(g5c_milenage_derive_opc(k, op, opc) == 0);
        g5c_milenage_init(&m, k, opc);
        TK_ASSERT(g5c_milenage_f2345(&m, rnd, &mv) == 0);
        h(g5c_json_get_str(av, "autn"), autn, 16);
        TK_ASSERT((autn[6] & 0x80) != 0); /* the AMF separation bit (RFC 5448 3.3) */
        TK_ASSERT(g5c_ck_ik_prime(mv.ck, mv.ik, snn, autn, ckp, ikp) == 0);
        h(g5c_json_get_str(av, "ckPrime"), got, 16);
        TK_ASSERT(memcmp(got, ckp, 16) == 0);
        h(g5c_json_get_str(av, "ikPrime"), got, 16);
        TK_ASSERT(memcmp(got, ikp, 16) == 0);
        TK_ASSERT(strlen(g5c_json_get_str(av, "xres")) == 16); /* the 64 bit Milenage RES */
        h(g5c_json_get_str(av, "xres"), got, 8);
        TK_ASSERT(memcmp(got, mv.res, 8) == 0);
    }
    g5c_json_free(v);
    /* the SQN moved before the vector was released, as for 5G AKA */
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers/imsi-001010000000002", NULL, true, &v, NULL) == 200);
    EXPECT_STR(v, "sqn", "000000000020");
    g5c_json_free(v);
    /* EAP-TLS is stored but the UDM cannot run it: the user cannot be authenticated with that method (TS 29.509 6.1.7.3) */
    orig = g5c_udr_get(t.store, eap_supi, UDR_AUTH);
    TK_ASSERT(orig != NULL);
    g5c_json_set_str(orig, "authenticationMethod", "EAP_TLS");
    g5c_udr_put(t.store, eap_supi, UDR_AUTH, orig);
    TK_ASSERT(rq(&t, "POST", gen, body, false, &v, NULL) == 403);
    EXPECT_STR(v, "cause", "AUTHENTICATION_REJECTED");
    g5c_json_free(v);
    /* the admin API takes the two methods and nothing else */
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"auth_method\":\"EAP_TLS\"}", true, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"auth_method\":5}", true, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"auth_method\":\"5G_AKA\"}", true, NULL, NULL) == 201);

    /* the FN-RG answer (TS 29.503 6.3.3.3): the SUPI and the indication of the W-AGF */
    {
        const char *rg = "/nudm-ueau/v1/suci-0-001-01-0000-0-0-0000000001/security-information-rg";
        char path[300];
        bool b = false;
        snprintf(path, sizeof path, "%s?authenticated-ind=true", rg);
        TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200);
        EXPECT_STR(v, "supi", SUPI);
        TK_ASSERT(g5c_json_get_bool(v, "authInd", &b) && b);
        g5c_json_free(v);
        snprintf(path, sizeof path, "%s?authenticated-ind=false", rg);
        TK_ASSERT(rq(&t, "GET", path, NULL, false, &v, NULL) == 200);
        TK_ASSERT(g5c_json_get_bool(v, "authInd", &b) && !b);
        g5c_json_free(v);
        TK_ASSERT(rq(&t, "GET", rg, NULL, false, &v, NULL) == 400); /* the indication is mandatory */
        g5c_json_free(v);
        snprintf(path, sizeof path, "%s?authenticated-ind=maybe", rg);
        TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 400);
        snprintf(path, sizeof path, "/nudm-ueau/v1/suci-0-001-01-0000-0-0-0000000099/security-information-rg?authenticated-ind=true");
        TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 404);
        snprintf(path, sizeof path, "/nudm-ueau/v1/zzz/security-information-rg?authenticated-ind=true");
        TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 400);
    }
    teardown(&t);
}

/* The UDR's provisioning extensions need its bearer token */
static void test_udr_provisioning_token(void)
{
    static const char *const body = "{\"supi\":\"imsi-001010000000009\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}";
    T t;
    char path[256];
    setup_ex(&t, false, "provisioning-token-0123456789"); /* the subscriber of setup() was provisioned with the token */
    udm_udr_set_token(&t.u.udr, NULL);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", body, true, NULL, NULL) >= 500);
    udm_udr_set_token(&t.u.udr, "wrong-token-wrong-token");
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", body, true, NULL, NULL) >= 500);
    udm_udr_set_token(&t.u.udr, "provisioning-token-0123456789");
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", body, true, NULL, NULL) == 201);
    udm_udr_set_token(&t.u.udr, NULL);
    snprintf(path, sizeof path, "/nudm-sdm/v2/" SUPI "/am-data?plmn-id=%s", PLMN);
    TK_ASSERT(rq(&t, "GET", path, NULL, false, NULL, NULL) == 200); /* a read needs no token */
    teardown(&t);
}

static void test_admin(void)
{
    T t;
    g5c_json *v;
    char err[160];
    setup(&t, false);
    /* admin guard: no/incorrect token -> 401, API disabled -> 404 */
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers", NULL, false, NULL, NULL) == 401);
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers", NULL, true, &v, NULL) == 200 && g5c_json_len(v) == 1);
    g5c_json_free(v);
    /* validation */
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", "{\"supi\":\"imsi-1\",\"k\":\"" K_HEX "\",\"opc\":\"" K_HEX "\"}", true, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", "{\"supi\":\"imsi-001010000000002\",\"k\":\"zz\",\"opc\":\"" K_HEX "\"}", true, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", "{\"supi\":\"imsi-001010000000002\",\"k\":\"" K_HEX "\"}", true, NULL, NULL) == 400); /* neither op nor opc */
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", "{\"supi\":\"imsi-001010000000002\",\"k\":\"" K_HEX "\",\"opc\":\"" K_HEX "\",\"typo\":1}", true, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", "{\"supi\":\"imsi-001010000000002\",\"k\":\"" K_HEX "\",\"opc\":\"" K_HEX "\",\"slices\":[{\"sst\":1,\"sd\":\"xyz\"}]}", true, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", "{\"supi\":\"imsi-001010000000002\",\"k\":\"" K_HEX "\",\"opc\":\"" K_HEX "\",\"dnns\":{\"x\":{\"session_types\":[\"IPV5\"]}}}", true, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", "{\"supi\":\"imsi-001010000000002\",\"k\":\"" K_HEX "\",\"opc\":\"" K_HEX "\"}", true, NULL, NULL) == 201);
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers", NULL, true, &v, NULL) == 200 && g5c_json_len(v) == 2);
    g5c_json_free(v);
    TK_ASSERT(rq(&t, "DELETE", "/admin/v1/subscribers/imsi-001010000000002", NULL, true, NULL, NULL) == 204);
    TK_ASSERT(rq(&t, "DELETE", "/admin/v1/subscribers/imsi-001010000000002", NULL, true, NULL, NULL) == 404);

    /* with no token configured the admin API does not exist */
    free(t.u.admin_token);
    t.u.admin_token = NULL;
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers", NULL, true, NULL, NULL) == 404);

    /* config loading: short admin token rejected */
    {
        g5c_json *cfg = J("{\"udr\":{\"uri\":\"http://127.0.0.1:1\"}}");
        g5c_common c;
        g5c_nf *nf;
        udm *u;
        char *ycfg = g5c_xstrdup("name: u\nplmn: {mcc: '001', mnc: '01'}\nsbi: {address: 127.0.0.1, port: 1}\n");
        g5c_json *root = g5c_yaml_parse(ycfg, strlen(ycfg), err, sizeof err);
        TK_ASSERT(root && g5c_common_parse(root, &c, err, sizeof err) == 0);
        nf = g5c_nf_new(&c, err, sizeof err);
        TK_ASSERT(nf != NULL);
        setenv("G5C_UDM_ADMIN_TOKEN", "short", 1);
        TK_ASSERT(udm_from_config(cfg, nf, err, sizeof err) == NULL && strstr(err, "at least 16") != NULL);
        setenv("G5C_UDM_ADMIN_TOKEN", ADMIN, 1);
        setenv("G5C_UDM_MASTER_KEY", "nothex", 1);
        TK_ASSERT(udm_from_config(cfg, nf, err, sizeof err) == NULL && strstr(err, "master key") != NULL);
        unsetenv("G5C_UDM_MASTER_KEY");
        u = udm_from_config(cfg, nf, err, sizeof err);
        TK_ASSERT(u != NULL && u->admin_token != NULL && strcmp(u->admin_token, ADMIN) == 0);
        udm_destroy(u);
        free(u);
        {   /* suci.null_scheme */
            g5c_json *c1 = J("{\"udr\":{\"uri\":\"http://127.0.0.1:1\"},\"suci\":{\"null_scheme\":\"reject\"}}"), *c2 = J("{\"udr\":{\"uri\":\"http://127.0.0.1:1\"},\"suci\":{\"null_scheme\":\"maybe\"}}"),
                     *c3 = J("{\"udr\":{\"uri\":\"http://127.0.0.1:1\"},\"suci\":{\"surprise\":1}}");
            u = udm_from_config(c1, nf, err, sizeof err);
            TK_ASSERT(u != NULL && u->refuse_null_scheme);
            udm_destroy(u);
            free(u);
            TK_ASSERT(udm_from_config(c2, nf, err, sizeof err) == NULL && strstr(err, "suci.null_scheme") != NULL);
            TK_ASSERT(udm_from_config(c3, nf, err, sizeof err) == NULL && strstr(err, "suci") != NULL);
            g5c_json_free(c1);
            g5c_json_free(c2);
            g5c_json_free(c3);
        }
        unsetenv("G5C_UDM_ADMIN_TOKEN");
        g5c_nf_free(nf);
        g5c_json_free(root);
        g5c_json_free(cfg);
        free(ycfg);
    }
    teardown(&t);
}

/* ---- roles and tenants of the admin API (backlog F-03) ---- */

static int rq_as(T *t, const char *method, const char *path, const char *body, const char *token, g5c_json **out)
{
    char *url = g5c_xasprintf("%s%s", t->base, path), auth[96], err[160];
    g5c_kv hdr = {"authorization", auth};
    g5c_resp r;
    int st;
    snprintf(auth, sizeof auth, "Bearer %s", token);
    TK_ASSERT(g5c_client_request(t->client, method, url, &hdr, 1, G5C_JSON_TYPE, body, body ? strlen(body) : 0, &r, err, sizeof err) == 0);
    free(url);
    st = r.status;
    if (out)
        *out = g5c_resp_parse_json(&r);
    g5c_resp_free(&r);
    return st;
}

static char *sub_json(const char *supi)
{
    return g5c_xasprintf("{\"supi\":\"%s\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}", supi);
}

static bool list_has_supi(const g5c_json *l, const char *supi)
{
    for (size_t i = 0; l != NULL && i < g5c_json_len(l); i++) {
        const g5c_json *e = g5c_json_at(l, i);
        const char *s = g5c_json_str(e) != NULL ? g5c_json_str(e) : g5c_json_get_str(e, "supi");
        if (s != NULL && strcmp(s, supi) == 0)
            return true;
    }
    return false;
}

static void test_roles_and_tenants(void)
{
    T t;
    char dir[] = "/tmp/g5c-udm-roles-XXXXXX", file[96], err[200], h[4][65], *body;
    const char *tok[4] = {"noc-token-0123456789ab", "acme-token-0123456789a", "beta-token-0123456789a", "keys-token-0123456789a"};
    FILE *f;
    g5c_json *v = NULL;
    setup(&t, false); /* imsi-001010000000001 exists */
    TK_ASSERT(mkdtemp(dir) != NULL);
    snprintf(file, sizeof file, "%s/tokens.json", dir);
    for (int i = 0; i < 4; i++)
        g5c_authz_hash(tok[i], h[i]);
    f = fopen(file, "w");
    TK_ASSERT(f != NULL);
    fprintf(f,
            "{\"tokens\":[{\"name\":\"noc\",\"sha256\":\"%s\",\"roles\":[\"read\"]},"
            "{\"name\":\"acme\",\"sha256\":\"%s\",\"roles\":[\"read\",\"provision\"],\"tenant\":\"acme\"},"
            "{\"name\":\"beta\",\"sha256\":\"%s\",\"roles\":[\"read\",\"provision\"],\"tenant\":\"beta\"},"
            "{\"name\":\"keys\",\"sha256\":\"%s\",\"roles\":[\"key-admin\"]}],"
            "\"tenants\":{\"acme\":{\"supi_prefixes\":[\"imsi-0010199\"]},\"beta\":{\"supi_prefixes\":[\"imsi-0010288\"]}}}",
            h[0], h[1], h[2], h[3]);
    fclose(f);
    t.u.authz = g5c_authz_new(file, ADMIN, err, sizeof err);
    TK_ASSERT(t.u.authz != NULL);

    /* nobody, a stranger, a read-only operator */
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers", NULL, "stranger-token-0123456", NULL) == 401);
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers", NULL, false, NULL, NULL) == 401);
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers", NULL, tok[0], &v) == 200 && list_has_supi(v, SUPI)); /* read sees everything */
    g5c_json_free(v);
    body = sub_json("imsi-001019900000001");
    TK_ASSERT(rq_as(&t, "POST", "/admin/v1/subscribers", body, tok[0], &v) == 403 && strstr(g5c_json_get_str(v, "detail"), "provision") != NULL); /* the answer names the role that is missing */
    g5c_json_free(v);
    TK_ASSERT(rq_as(&t, "DELETE", "/admin/v1/subscribers/" SUPI, NULL, tok[0], NULL) == 403);
    TK_ASSERT(rq_as(&t, "POST", "/admin/v1/subscribers-bulk", "[]", tok[0], NULL) == 403);
    TK_ASSERT(rq_as(&t, "POST", "/admin/v1/keys/rewrap", NULL, tok[1], NULL) == 403); /* a tenant never re-wraps keys */
    {
        int st = rq_as(&t, "POST", "/admin/v1/keys/rewrap", NULL, tok[3], NULL);
        TK_ASSERT(st != 401 && st != 403); /* key-admin gets through to the handler (which says there is no master key here) */
    }
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers", NULL, tok[3], NULL) == 403); /* ... and can do nothing else */
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers", NULL, true, NULL, NULL) == 200); /* the single admin token is still every role */
    free(body);

    /* a tenant provisions inside its ranges and nowhere else */
    body = sub_json("imsi-001019900000001");
    TK_ASSERT(rq_as(&t, "POST", "/admin/v1/subscribers", body, tok[1], NULL) == 201);
    free(body);
    body = sub_json("imsi-001028800000001");
    TK_ASSERT(rq_as(&t, "POST", "/admin/v1/subscribers", body, tok[1], &v) == 403 && strstr(g5c_json_get_str(v, "detail"), "tenant") != NULL);
    g5c_json_free(v);
    TK_ASSERT(rq_as(&t, "POST", "/admin/v1/subscribers", body, tok[2], NULL) == 201); /* it is beta's range */
    free(body);
    body = sub_json("imsi-001010000000009");
    TK_ASSERT(rq_as(&t, "POST", "/admin/v1/subscribers", body, tok[1], NULL) == 403 && rq_as(&t, "POST", "/admin/v1/subscribers", body, tok[2], NULL) == 403);
    free(body);

    /* what is not the tenant's is not there for it: not a 403 that would say it exists */
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers/imsi-001019900000001", NULL, tok[1], NULL) == 200);
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers/imsi-001028800000001", NULL, tok[1], NULL) == 404);
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers/" SUPI, NULL, tok[1], NULL) == 404);
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers/imsi-001028800000001", NULL, tok[0], NULL) == 200); /* the read-only operator sees it */
    TK_ASSERT(rq_as(&t, "DELETE", "/admin/v1/subscribers/imsi-001028800000001", NULL, tok[1], NULL) == 404);
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers/imsi-001028800000001", NULL, tok[0], NULL) == 200); /* and it is still there */

    /* a tenant lists only its own */
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers", NULL, tok[1], &v) == 200);
    TK_ASSERT(g5c_json_len(v) == 1 && list_has_supi(v, "imsi-001019900000001"));
    g5c_json_free(v);
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers", NULL, tok[0], &v) == 200 && g5c_json_len(v) >= 3);
    g5c_json_free(v);

    /* bulk: each record is judged on its own */
    TK_ASSERT(rq_as(&t, "POST", "/admin/v1/subscribers-bulk",
                    "[{\"supi\":\"imsi-001019900000002\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"},"
                    "{\"supi\":\"imsi-001028800000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"},"
                    "{\"supi\":\"imsi-001019900000004\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}]",
                    tok[1], &v) == 200);
    {
        int64_t created = 0, failed = 0, s2 = 0;
        TK_ASSERT(g5c_json_get_int(v, "created", &created) && g5c_json_get_int(v, "failed", &failed) && created == 2 && failed == 1);
        TK_ASSERT(g5c_json_get_int(g5c_json_at(g5c_json_get(v, "results"), 1), "status", &s2) && s2 == 403);
    }
    g5c_json_free(v);
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers/imsi-001028800000003", NULL, tok[0], NULL) == 404); /* the refused one was not created */

    /* a tenant deletes its own */
    TK_ASSERT(rq_as(&t, "DELETE", "/admin/v1/subscribers/imsi-001019900000002", NULL, tok[1], NULL) == 204);

    /* revoking a token works without a restart */
    sleep(1);
    f = fopen(file, "w");
    TK_ASSERT(f != NULL);
    fprintf(f, "{\"tokens\":[{\"name\":\"noc\",\"sha256\":\"%s\",\"roles\":[\"read\"]}]}", h[0]);
    fclose(f);
    sleep(2);
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers", NULL, tok[1], NULL) == 401);
    TK_ASSERT(rq_as(&t, "GET", "/admin/v1/subscribers", NULL, tok[0], NULL) == 200);
    unlink(file);
    rmdir(dir);
    teardown(&t);
}

/* ---- negative, abuse and failure-injection tests (strategy 4.1: component layer, Phase 1 test plan) ---- */

/* Every malformed provisioning request is refused with 400 and stores nothing. */
static void test_admin_validation(void)
{
    static const char *const bad_bodies[] = {
        "[]", "\"x\"", "null", "{",
        "{\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}",                                              /* no supi */
        "{\"supi\":\"imsi-001010000000003\",\"op\":\"" OP_HEX "\"}",                                  /* no k */
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"bogus\":1}", /* unknown key */
        "{\"supi\":\"imsi-12\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}",                          /* too short */
        "{\"supi\":\"imsi-0010100000000031\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}",            /* 16 digits */
        "{\"supi\":\"imsi-00101000000000x\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}",             /* non-digit */
        "{\"supi\":\"nai-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}",              /* not an imsi */
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"abcd\",\"op\":\"" OP_HEX "\"}",                  /* short k */
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"zz5b5ce8b199b49faa5f0a2ee238a6bc\",\"op\":\"" OP_HEX "\"}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\"}",                                    /* neither op nor opc */
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"opc\":\"" OP_HEX "\"}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"opc\":\"1234\"}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"1234\"}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"amf\":\"zz00\"}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"amf\":\"80\"}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"sqn\":\"12\"}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":{}}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[]}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[1]}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[{\"sst\":256}]}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[{\"sst\":-1}]}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[{}]}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[{\"sst\":1,\"sd\":123}]}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[{\"sst\":1,\"sd\":\"12\"}]}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[{\"sst\":1,\"sd\":\"zzzzzz\"}]}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[{\"sst\":1,\"x\":1}]}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":[]}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{}}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{\"x\":1}}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{\"\":{}}}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{\"a\":{\"qi5\":300}}}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{\"a\":{\"qi5\":\"x\"}}}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{\"a\":{\"session_types\":[]}}}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{\"a\":{\"session_types\":[\"IPV5\"]}}}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{\"a\":{\"session_types\":[7]}}}",
        "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{\"a\":{\"zzz\":1}}}",
    };
    T t;
    g5c_json *v;
    setup(&t, false);
    for (size_t i = 0; i < sizeof bad_bodies / sizeof *bad_bodies; i++) {
        int st = rq(&t, "POST", "/admin/v1/subscribers", bad_bodies[i], true, NULL, NULL);
        if (st != 400)
            TK_FAIL("case %zu returned %d: %s", i, st, bad_bodies[i]);
    }
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers/imsi-001010000000003", NULL, true, NULL, NULL) == 404); /* nothing stored */
    /* a fully specified valid one, including the optional fields */
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers",
                 "{\"supi\":\"imsi-001010000000003\",\"k\":\"" K_HEX "\",\"opc\":\"" OP_HEX "\",\"amf\":\"8001\",\"sqn\":\"0000000000ff\","
                 "\"ue_ambr_ul\":\"2 Gbps\",\"ue_ambr_dl\":\"3 Gbps\",\"slices\":[{\"sst\":3,\"sd\":\"0A0B0C\"}],"
                 "\"dnns\":{\"iot\":{\"qi5\":7,\"ambr_ul\":\"1 Mbps\",\"ambr_dl\":\"2 Mbps\",\"session_types\":[\"IPV6\",\"IPV4V6\"]}}}",
                 true, NULL, NULL) == 201);
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/imsi-001010000000003/am-data?plmn-id=" "%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D", NULL, false, &v, NULL) == 200);
    EXPECT_STR(g5c_json_get(v, "subscribedUeAmbr"), "uplink", "2 Gbps");
    EXPECT_STR(g5c_json_get(v, "subscribedUeAmbr"), "downlink", "3 Gbps");
    g5c_json_free(v);
    teardown(&t);
}

/* Garbage, wrong methods, unknown paths and oversized bodies never crash the NF and get the right status. */
/* F-02: the bulk endpoint stores each record on its own and says what became of each */
static void test_bulk(void)
{
    T t;
    g5c_json *v;
    const g5c_json *res;
    setup(&t, true);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers-bulk", "[]", false, NULL, NULL) == 401); /* the admin token is needed */
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers-bulk", "[]", true, NULL, NULL) == 400);  /* and at least one record */
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers-bulk", "{\"nope\":1}", true, NULL, NULL) == 400);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers-bulk",
                 "[{\"supi\":\"imsi-001010000000041\",\"k\":\"" K_HEX "\",\"opc\":\"" K_HEX "\"},"
                 "{\"supi\":\"imsi-001010000000042\",\"k\":\"short\",\"opc\":\"" K_HEX "\"},"
                 "{\"supi\":\"imsi-001010000000043\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"slices\":[{\"sst\":1}]},"
                 "{\"supi\":\"imsi-001010000000044\",\"k\":\"" K_HEX "\",\"opc\":\"" K_HEX "\",\"typo\":1},"
                 "42]",
                 true, &v, NULL) == 200);
    res = g5c_json_get(v, "results");
    {
        int64_t total = 0, created = 0, failed = 0, st = 0;
        TK_ASSERT(g5c_json_get_int(v, "total", &total) && total == 5 && g5c_json_get_int(v, "created", &created) && created == 2 && g5c_json_get_int(v, "failed", &failed) && failed == 3);
        TK_ASSERT(g5c_json_len(res) == 5);
        TK_ASSERT(g5c_json_get_int(g5c_json_at(res, 0), "status", &st) && st == 201 && strcmp(g5c_json_get_str(g5c_json_at(res, 0), "supi"), "imsi-001010000000041") == 0);
        TK_ASSERT(g5c_json_get_int(g5c_json_at(res, 1), "status", &st) && st == 400 && strstr(g5c_json_get_str(g5c_json_at(res, 1), "detail"), "32 hex") != NULL);
        TK_ASSERT(g5c_json_get_int(g5c_json_at(res, 2), "status", &st) && st == 201);
        TK_ASSERT(g5c_json_get_int(g5c_json_at(res, 3), "status", &st) && st == 400 && strstr(g5c_json_get_str(g5c_json_at(res, 3), "detail"), "typo") != NULL);
        TK_ASSERT(g5c_json_get_int(g5c_json_at(res, 4), "status", &st) && st == 400);
    }
    g5c_json_free(v);
    /* the two good ones are really there, the bad ones are not */
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers/imsi-001010000000041", NULL, true, NULL, NULL) == 200);
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers/imsi-001010000000043", NULL, true, NULL, NULL) == 200);
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers/imsi-001010000000042", NULL, true, NULL, NULL) == 404);
    teardown(&t);
}

/* F-01: the console page is served, with a policy that allows only its own script, and not at all when the admin API is off */
static void test_console(void)
{
    T t;
    char *url, err[160];
    g5c_resp r;
    const char *csp;
    setup(&t, false);
    url = g5c_xasprintf("%s/console", t.base);
    TK_ASSERT(g5c_client_request(t.client, "GET", url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) == 0);
    TK_ASSERT(r.status == 200 && strncmp(g5c_resp_header_get(&r, "content-type"), "text/html", 9) == 0);
    csp = g5c_resp_header_get(&r, "content-security-policy");
    TK_ASSERT(csp != NULL && strstr(csp, "default-src 'none'") != NULL && strstr(csp, "script-src 'sha256-") != NULL && strstr(csp, "unsafe-inline") == NULL && strstr(csp, "frame-ancestors 'none'") != NULL);
    TK_ASSERT(r.body_len > 2000 && strstr((const char *)r.body, "<title>g5c console</title>") != NULL && strcmp(g5c_resp_header_get(&r, "x-frame-options"), "DENY") == 0);
    g5c_resp_free(&r);
    free(t.u.admin_token);
    t.u.admin_token = NULL;
    TK_ASSERT(g5c_client_request(t.client, "GET", url, NULL, 0, NULL, NULL, 0, &r, err, sizeof err) == 0 && r.status == 404); /* the admin API is off: so is the console */
    g5c_resp_free(&r);
    free(url);
    teardown(&t);
}

static void test_protocol_abuse(void)
{
    static const struct {
        const char *method, *path;
    } json_endpoints[] = {
        {"POST", "/nudm-ueau/v1/" SUPI "/security-information/generate-auth-data"},
        {"POST", "/nudm-ueau/v1/" SUPI "/auth-events"},
        {"PUT", "/nudm-ueau/v1/" SUPI "/auth-events"},
        {"POST", "/nudm-sdm/v2/" SUPI "/sdm-subscriptions"},
        {"PUT", "/nudm-uecm/v1/" SUPI "/registrations/amf-3gpp-access"},
        {"PATCH", "/nudm-uecm/v1/" SUPI "/registrations/amf-3gpp-access"},
        {"PUT", "/nudm-uecm/v1/" SUPI "/registrations/smf-registrations/5"},
    };
    static const char *const garbage[] = {"{", "not json", "[1,2", "{\"a\":}", "ÿþ", ""};
    T t;
    char *big;
    setup(&t, false);
    for (size_t i = 0; i < sizeof json_endpoints / sizeof *json_endpoints; i++)
        for (size_t g = 0; g < sizeof garbage / sizeof *garbage; g++) {
            int st = rq(&t, json_endpoints[i].method, json_endpoints[i].path, garbage[g], false, NULL, NULL);
            if (st != 400)
                TK_FAIL("%s %s with garbage %zu returned %d", json_endpoints[i].method, json_endpoints[i].path, g, st);
        }
    /* unknown resources and methods */
    TK_ASSERT(rq(&t, "GET", "/nudm-nothing/v1/x", NULL, false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "GET", "/", NULL, false, NULL, NULL) == 404);
    {
        int st = rq(&t, "DELETE", "/nudm-ueau/v1/" SUPI "/security-information/generate-auth-data", NULL, false, NULL, NULL);
        TK_ASSERT(st == 404 || st == 405);
        st = rq(&t, "GET", "/nudm-ueau/v1/" SUPI "/security-information/generate-auth-data", NULL, false, NULL, NULL);
        TK_ASSERT(st == 404 || st == 405);
    }
    /* the admin API is never reachable without the token, whatever the method */
    TK_ASSERT(rq(&t, "GET", "/admin/v1/subscribers/" SUPI, NULL, false, NULL, NULL) == 401);
    TK_ASSERT(rq(&t, "DELETE", "/admin/v1/subscribers/" SUPI, NULL, false, NULL, NULL) == 401);
    TK_ASSERT(rq(&t, "POST", "/admin/v1/subscribers", "{}", false, NULL, NULL) == 401);
    /* unknown subscriber everywhere it is looked up */
    TK_ASSERT(rq(&t, "POST", "/nudm-ueau/v1/imsi-001019999999999/security-information/generate-auth-data",
                 "{\"servingNetworkName\":\"5G:mnc001.mcc001.3gppnetwork.org\"}", false, NULL, NULL) == 404);
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/imsi-001019999999999/nssai", NULL, false, NULL, NULL) == 404);
    /* a request body over the limit is refused, and the server keeps working afterwards */
    big = malloc(G5C_SBI_MAX_BODY + 64);
    TK_ASSERT(big != NULL);
    memset(big, 'a', G5C_SBI_MAX_BODY + 63);
    big[G5C_SBI_MAX_BODY + 63] = 0;
    TK_ASSERT(rq(&t, "POST", "/nudm-sdm/v2/" SUPI "/sdm-subscriptions", big, false, NULL, NULL) == 413);
    free(big);
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/" SUPI "/nssai", NULL, false, NULL, NULL) == 200);
    /* deeply nested JSON is rejected, not recursed into */
    {
        char *deep = malloc(2 * 4000 + 8);
        TK_ASSERT(deep != NULL);
        memset(deep, '[', 4000);
        memset(deep + 4000, ']', 4000);
        deep[8000] = 0;
        TK_ASSERT(rq(&t, "POST", "/nudm-sdm/v2/" SUPI "/sdm-subscriptions", deep, false, NULL, NULL) == 400);
        free(deep);
    }
    teardown(&t);
}

/* Failure injection: the UDR misbehaves in each way the client side can see. */
static atomic_int fake_mode; /* 1: 500, 2: 200 with a body that is not JSON, 3: 404 */

static void h_fake_udr(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    switch (atomic_load(&fake_mode)) {
    case 1:
        g5c_resp_problem_simple(resp, 500, "SYSTEM_FAILURE", "boom");
        break;
    case 2:
        g5c_resp_content(resp, 200, G5C_JSON_TYPE, "not json at all", 15);
        break;
    default:
        g5c_resp_problem_simple(resp, 404, "USER_NOT_FOUND", NULL);
        break;
    }
}

static void test_udr_failures(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    g5c_router *fr = g5c_router_new(), *ur;
    g5c_server *fs, *us;
    g5c_client *cl = g5c_client_new(2000, NULL);
    g5c_registry *m = g5c_registry_new();
    udm_keys keys;
    udm u;
    char fake[64], base[64], err[160];
    const char *gen = "/nudm-ueau/v1/" SUPI "/security-information/generate-auth-data";
    const char *body = "{\"servingNetworkName\":\"5G:mnc001.mcc001.3gppnetwork.org\"}";
    T t;
    g5c_router_route(fr, "GET", "/nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription", h_fake_udr, NULL);
    g5c_router_route(fr, "GET", "/nudr-dr/v1/subscription-data/{supi}/{a}/{b}", h_fake_udr, NULL);
    g5c_router_route(fr, "GET", "/nudr-dr/v1/subscription-data/{supi}/{a}/{b}/{c}", h_fake_udr, NULL);
    g5c_router_route(fr, "GET", "/nudr-dr/v1/subscription-data/{supi}/{a}/{b}/{c}/{d}", h_fake_udr, NULL);
    fs = g5c_server_start(&cfg, fr, err, sizeof err);
    TK_ASSERT(fs != NULL);
    snprintf(fake, sizeof fake, "http://127.0.0.1:%u", g5c_server_port(fs));
    udm_keys_none(&keys);
    udm_init(&u, cl, fake, &keys, NULL, 0, "00101", "udm-fail", m);
    ur = udm_router(&u);
    us = g5c_server_start(&cfg, ur, err, sizeof err);
    TK_ASSERT(us != NULL);
    snprintf(base, sizeof base, "http://127.0.0.1:%u", g5c_server_port(us));
    memset(&t, 0, sizeof t);
    t.client = cl;
    snprintf(t.base, sizeof t.base, "%s", base);

    atomic_store(&fake_mode, 1);
    {
        int st = rq(&t, "POST", gen, body, false, NULL, NULL);
        if (st != 500)
            TK_FAIL("UDR 500 mapped to %d", st);
    }
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/" SUPI "/nssai", NULL, false, NULL, NULL) == 500);
    atomic_store(&fake_mode, 2);
    TK_ASSERT(rq(&t, "POST", gen, body, false, NULL, NULL) == 500);
    atomic_store(&fake_mode, 3);
    TK_ASSERT(rq(&t, "POST", gen, body, false, NULL, NULL) == 404);
    /* UDR gone entirely: the UDM answers 503 and keeps serving */
    g5c_server_stop(fs);
    TK_ASSERT(rq(&t, "POST", gen, body, false, NULL, NULL) == 503);
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/" SUPI "/am-data", NULL, false, NULL, NULL) < 600);
    TK_ASSERT(rq(&t, "GET", "/nudm-nothing", NULL, false, NULL, NULL) == 404);

    g5c_server_stop(us);
    g5c_client_free(cl);
    g5c_router_free(ur);
    g5c_router_free(fr);
    udm_destroy(&u);
    g5c_registry_free(m);
}

/* Algorithmic-complexity abuse: a body with tens of thousands of members must not pin a worker for long. */
static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void test_complexity_abuse(void)
{
    T t;
    g5c_bytes b;
    double t0;
    int st;
    char head[256];
    setup(&t, false);
    g5c_bytes_init(&b);
    snprintf(head, sizeof head, "{\"supi\":\"imsi-001010000000004\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\",\"dnns\":{");
    g5c_bytes_append(&b, head, strlen(head));
    for (int i = 0; i < 40000; i++) {
        char e[48];
        int n = snprintf(e, sizeof e, "%s\"d%d\":{}", i ? "," : "", i);
        g5c_bytes_append(&b, e, (size_t)n);
    }
    g5c_bytes_append(&b, "}}", 2);
    TK_ASSERT(b.len < G5C_SBI_MAX_BODY);
    t0 = now_s();
    st = rq(&t, "POST", "/admin/v1/subscribers", (const char *)b.data, true, NULL, NULL);
    if (now_s() - t0 > 5.0)
        TK_FAIL("40000 DNNs took %.1f s (status %d): quadratic behaviour", now_s() - t0, st);
    TK_ASSERT(st == 400); /* over the implementation limit of 256 DNNs */
    g5c_bytes_free(&b);
    /* the NF is still responsive */
    t0 = now_s();
    TK_ASSERT(rq(&t, "GET", "/nudm-sdm/v2/" SUPI "/nssai", NULL, false, NULL, NULL) == 200);
    TK_ASSERT(now_s() - t0 < 2.0);
    teardown(&t);
}

int main(void)
{
    g5c_log_init("error", false);
    test_aka();
    test_keys();
    test_identity();
    test_util();
    test_sdm();
    test_sdm_subscriptions();
    test_sdm_notification();
    test_sdm_multiple_datasets();
    test_uecm();
    test_uecm_validation_and_smf();
    test_location_absolute();
    test_ee();
    test_auth_removal();
    test_ueau(false);
    test_ueau(true);
    test_ueau_eap();
    test_null_scheme_policy();
    test_auth_hook();
    test_groups();
    test_admin();
    test_roles_and_tenants();
    test_udr_provisioning_token();
    test_admin_validation();
    test_protocol_abuse();
    test_console();
    test_bulk();
    test_udr_failures();
    test_complexity_abuse();
    puts("udm: ok");
    return 0;
}
