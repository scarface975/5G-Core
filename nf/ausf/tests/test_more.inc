/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Part two of test_ausf.c (included before main): EAP-AKA' with an independent peer, the removal of a result, the clean-up of a security context, SoR and UPU
 * protection, the state file, the configuration, the FN-RG authentication and the limits of the tables. */

#define IMSI "001010000000001"
#define SNN_B64_URL "/nausf-auth/v1/ue-authentications"

static const char *PLMN_SUPI(int i)
{
    static char buf[8][40];
    snprintf(buf[i], sizeof buf[i], "imsi-0010100000%05d", 100 + i);
    return buf[i];
}

static void provision_m(S *s, const char *supi, const char *method)
{
    char body[320];
    snprintf(body, sizeof body, "{\"supi\":\"%s\",\"k\":\"%s\",\"op\":\"%s\",\"sqn\":\"000000000000\"%s%s%s}", supi, K, OP, method ? ",\"auth_method\":\"" : "",
             method ? method : "", method ? "\"" : "");
    TK_ASSERT(admin(s, "POST", "/admin/v1/subscribers", body, NULL) == 201);
}

static void auth_status_of(S *s, const char *supi, g5c_json **out)
{
    char *u = g5c_xasprintf("%s/nudr-dr/v1/subscription-data/%s/authentication-data/authentication-status", s->udr, supi);
    TK_ASSERT(call(s, "GET", u, NULL, false, out) == 200);
    free(u);
}

static uint64_t udm_counter(S *s, const char *name)
{
    return g5c_counter_value(g5c_counter_get(s->metrics_udm, name, "x", NULL, 0));
}

/* ---- an EAP-AKA' peer, written from RFC 4187 / RFC 5448 / TS 33.501 Annex F and the test vectors of RFC 9048 ------------------------------------------ */

enum { F_NONE = 0, F_BAD_RES = 1, F_BAD_MAC = 2, F_KDF = 4, F_NO_IND = 8, F_BAD_AMF = 16, F_KDF_ECHO = 32 };

typedef struct {
    ue_t ue;
    g5c_eapaka_keys keys;
    uint8_t kausf[32], kseaf[32];
    char snn[40];
    bool have_keys;
} eue_t;

typedef enum { EUE_OK, EUE_SYNC, EUE_REJECT } eue_kind;

static void eue_init(eue_t *e, uint64_t sqn_ms)
{
    memset(e, 0, sizeof *e);
    ue_init(&e->ue, sqn_ms);
}

static eue_kind eue_challenge(eue_t *e, const uint8_t *req, size_t n, const char *imsi, unsigned flags, uint8_t *out, size_t *outn)
{
    g5c_eap_pkt p;
    const g5c_eap_attr *ra, *au, *kd, *kin, *ind;
    g5c_milenage m;
    g5c_milenage_vector v;
    uint8_t rand[16], autn[16], sqn[6], mac_a[8], mac_s[8], ckp[16], ikp[16], resv[18] = {0}, macv[18] = {0}, indv[2] = {0}, kdfv[2] = {0, 2}, autsv[14], kdf1[2] = {0, 1};
    uint64_t sqn_n = 0;
    size_t nl;
    g5c_eap_attr at[6];
    size_t na = 0;
    TK_ASSERT(g5c_eap_parse(req, n, &p) && p.code == G5C_EAP_REQUEST && p.method == G5C_EAP_TYPE_AKA_PRIME && p.subtype == G5C_EAPAKA_CHALLENGE);
    ra = g5c_eap_find(&p, G5C_AT_RAND);
    au = g5c_eap_find(&p, G5C_AT_AUTN);
    kd = g5c_eap_find(&p, G5C_AT_KDF);
    kin = g5c_eap_find(&p, G5C_AT_KDF_INPUT);
    ind = g5c_eap_find(&p, G5C_AT_RESULT_IND);
    TK_ASSERT(ra && au && kd && kin && g5c_eap_find(&p, G5C_AT_MAC) != NULL);
    TK_ASSERT(ra->vlen == 18 && au->vlen == 18 && kd->vlen == 2 && kd->val[0] == 0 && kd->val[1] == 1 && kin->vlen >= 4);
    memcpy(rand, ra->val + 2, 16);
    memcpy(autn, au->val + 2, 16);
    nl = ((size_t)kin->val[0] << 8) | kin->val[1];
    TK_ASSERT(nl > 0 && nl + 2 <= kin->vlen && (kin->vlen + 2) % 4 == 0 && nl < sizeof e->snn);
    memcpy(e->snn, kin->val + 2, nl);
    e->snn[nl] = 0;
    TK_ASSERT(strncmp(e->snn, "5G:", 3) == 0); /* RFC 9048 5.3.1: the prefix says "5G" */
    for (size_t i = nl; i < kin->vlen - 2; i++)
        TK_ASSERT(kin->val[2 + i] == 0); /* padding is zero octets */
    g5c_milenage_init(&m, e->ue.k, e->ue.opc);
    TK_ASSERT(g5c_milenage_f2345(&m, rand, &v) == 0);
    for (int i = 0; i < 6; i++)
        sqn[i] = (uint8_t)(autn[i] ^ v.ak[i]);
    TK_ASSERT(g5c_milenage_f1(&m, rand, sqn, autn + 6, mac_a, mac_s) == 0);
    if (memcmp(mac_a, autn + 8, 8) != 0)
        return EUE_REJECT;
    TK_ASSERT((autn[6] & 0x80) != 0 || (flags & F_BAD_AMF)); /* RFC 5448 3.3: the separation bit */
    for (int i = 0; i < 6; i++)
        sqn_n = (sqn_n << 8) | sqn[i];
    if (sqn_n <= e->ue.sqn_ms) {
        uint8_t ms6[6];
        for (int i = 0; i < 6; i++)
            ms6[i] = (uint8_t)(e->ue.sqn_ms >> (8 * (5 - i)));
        TK_ASSERT(g5c_milenage_f1(&m, rand, ms6, (const uint8_t[]){0, 0}, mac_a, mac_s) == 0);
        for (int i = 0; i < 6; i++)
            autsv[i] = (uint8_t)(ms6[i] ^ v.ak_star[i]);
        memcpy(autsv + 6, mac_s, 8);
        at[0] = (g5c_eap_attr){G5C_AT_AUTS, autsv, 14};
        at[1] = (g5c_eap_attr){G5C_AT_KDF, kdf1, 2}; /* RFC 5448 3.2: a copy of the AT_KDF attributes */
        TK_ASSERT(g5c_eap_build(G5C_EAP_RESPONSE, p.id, G5C_EAPAKA_SYNC_FAILURE, at, 2, out, 256, outn) == 0);
        return EUE_SYNC;
    }
    e->ue.sqn_ms = sqn_n;
    TK_ASSERT(g5c_ck_ik_prime(v.ck, v.ik, e->snn, autn, ckp, ikp) == 0);
    TK_ASSERT(g5c_eapaka_prime_keys(ckp, ikp, imsi, &e->keys) == 0);
    e->have_keys = true;
    TK_ASSERT(g5c_eap_mac_ok(req, n, e->keys.k_aut, NULL, 0)); /* the server's AT_MAC verifies with the keys derived on this side */
    g5c_eapaka_kausf(&e->keys, e->kausf);
    TK_ASSERT(g5c_kseaf(e->kausf, e->snn, e->kseaf) == 0);
    resv[0] = 0;
    resv[1] = 64; /* RES length in bits */
    memcpy(resv + 2, v.res, 8);
    if (flags & F_BAD_RES)
        resv[5] ^= 0x40;
    at[na++] = (g5c_eap_attr){G5C_AT_RES, resv, 10};
    if (ind != NULL && !(flags & F_NO_IND))
        at[na++] = (g5c_eap_attr){G5C_AT_RESULT_IND, indv, 2};
    if (flags & F_KDF)
        at[na++] = (g5c_eap_attr){G5C_AT_KDF, kdfv, 2};
    if (flags & F_KDF_ECHO)
        at[na++] = (g5c_eap_attr){G5C_AT_KDF, kdf1, 2};
    at[na++] = (g5c_eap_attr){G5C_AT_MAC, macv, 18};
    TK_ASSERT(g5c_eap_build(G5C_EAP_RESPONSE, p.id, G5C_EAPAKA_CHALLENGE, at, na, out, 256, outn) == 0);
    TK_ASSERT(g5c_eap_mac_set(out, *outn, e->keys.k_aut, NULL, 0) == 0);
    if (flags & F_BAD_MAC)
        out[*outn - 1] ^= 1;
    return EUE_OK;
}

typedef struct {
    char href[300];
    uint8_t pkt[1100];
    size_t len;
} esess;

/* start an EAP-AKA' authentication; checks the shape of the UEAuthenticationCtx */
static int eap_begin(S *s, const char *id, esess *e, g5c_json **keep)
{
    g5c_json *v = NULL;
    int st = start_auth(s, id, NULL, NULL, &v);
    const char *pl;
    long n;
    if (st != 201) {
        if (keep)
            *keep = v;
        else
            g5c_json_free(v);
        return st;
    }
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authType"), "EAP_AKA_PRIME") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "servingNetworkName"), SNN) == 0);
    pl = g5c_json_get_str(v, "5gAuthData"); /* the EAP packet, base64 (TS 29.509 6.1.6.2.4) */
    TK_ASSERT(pl != NULL);
    n = g5c_base64_decode(pl, e->pkt, sizeof e->pkt);
    TK_ASSERT(n > 8);
    e->len = (size_t)n;
    snprintf(e->href, sizeof e->href, "%s", g5c_json_get_str(g5c_json_get(g5c_json_get(v, "_links"), "eap-session"), "href"));
    TK_ASSERT(strstr(e->href, "/eap-session") != NULL);
    if (keep)
        *keep = v;
    else
        g5c_json_free(v);
    return 201;
}

static int eap_post(S *s, const char *href, const uint8_t *pkt, size_t n, g5c_json **out)
{
    char *b64 = pkt != NULL ? g5c_base64_encode(pkt, n) : NULL, *body = g5c_xasprintf("{\"eapPayload\":%s%s%s}", b64 ? "\"" : "null", b64 ? b64 : "", b64 ? "\"" : "");
    int st = call(s, "POST", href, body, false, out);
    free(b64);
    free(body);
    return st;
}

/* the answer's EAP packet */
static size_t eap_of(const g5c_json *v, uint8_t *buf, size_t cap)
{
    const char *pl = g5c_json_get_str(v, "eapPayload");
    long n;
    TK_ASSERT(pl != NULL);
    n = g5c_base64_decode(pl, buf, cap);
    TK_ASSERT(n >= 4);
    return (size_t)n;
}

static void test_eap_full(void)
{
    S s;
    eue_t ue;
    esess es;
    g5c_json *v = NULL, *st = NULL;
    uint8_t out[300], rsp[300], kausf[32];
    size_t on = 0, rn;
    g5c_eap_pkt p;
    char *kx;
    bool b = false;
    stack(&s, false, NULL);
    provision_m(&s, SUPI, "EAP_AKA_PRIME");
    eue_init(&ue, 0);
    TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
    {
        g5c_eap_pkt q;
        TK_ASSERT(g5c_eap_parse(es.pkt, es.len, &q) && q.code == G5C_EAP_REQUEST && q.method == 50 && q.subtype == G5C_EAPAKA_CHALLENGE);
        TK_ASSERT(g5c_eap_find(&q, G5C_AT_RESULT_IND) == NULL); /* off unless configured */
    }
    TK_ASSERT(eue_challenge(&ue, es.pkt, es.len, IMSI, F_NONE, out, &on) == EUE_OK);
    TK_ASSERT(eap_post(&s, es.href, out, on, &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_SUCCESS") == 0);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "supi"), SUPI) == 0);
    rn = eap_of(v, rsp, sizeof rsp);
    TK_ASSERT(g5c_eap_parse(rsp, rn, &p) && p.code == G5C_EAP_SUCCESS && rn == 4);
    kx = g5c_hex_encode(ue.kseaf, 32); /* the peer derived the same anchor key from the EMSK */
    TK_ASSERT(strcmp(g5c_json_get_str(v, "kSeaf"), kx) == 0);
    free(kx);
    g5c_json_free(v);
    /* the AUSF keeps the KAUSF, the first 256 bits of the EMSK (TS 33.501 6.1.3.1 step 10) */
    {
        uint16_t cs = 0, cu = 0;
        TK_ASSERT(ausf_ue_kausf(s.a, SUPI, kausf, &cs, &cu) && memcmp(kausf, ue.kausf, 32) == 0 && cs == 1 && cu == 1);
    }
    auth_status_of(&s, SUPI, &st); /* the UDM recorded the result as EAP-AKA' */
    TK_ASSERT(g5c_json_get_bool(st, "success", &b) && b && strcmp(g5c_json_get_str(st, "authType"), "EAP_AKA_PRIME") == 0);
    g5c_json_free(st);
    TK_ASSERT(eap_post(&s, es.href, out, on, NULL) == 404); /* the session is over */
    /* the result is removed through the eap-session resource, and only through it */
    {
        char *cf = g5c_xasprintf("%s", es.href);
        char *slash = strstr(cf, "/eap-session");
        uint64_t before = udm_counter(&s, "g5c_udm_auth_removals_total");
        char *conf;
        TK_ASSERT(slash != NULL);
        conf = g5c_xasprintf("%.*s/5g-aka-confirmation", (int)(slash - cf), cf);
        TK_ASSERT(call(&s, "DELETE", conf, NULL, false, NULL) == 404); /* not a 5G AKA context */
        TK_ASSERT(call(&s, "DELETE", es.href, NULL, false, NULL) == 204);
        TK_ASSERT(udm_counter(&s, "g5c_udm_auth_removals_total") == before + 1);
        TK_ASSERT(call(&s, "DELETE", es.href, NULL, false, NULL) == 404);
        free(conf);
        free(cf);
    }
    unstack(&s);
}

static void test_eap_result_indication(void)
{
    S s;
    eue_t ue;
    esess es;
    g5c_json *v = NULL;
    uint8_t out[300], rsp[300], note[64];
    size_t on = 0, rn, nn = 0;
    g5c_eap_pkt p;
    g5c_eap_attr at[1];
    uint8_t macv[18] = {0};
    char *href2;
    g5c_eap_pkt q;
    g_eap_ind = true;
    stack(&s, false, NULL);
    g_eap_ind = false;
    provision_m(&s, SUPI, "EAP_AKA_PRIME");
    eue_init(&ue, 0);
    TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
    TK_ASSERT(g5c_eap_parse(es.pkt, es.len, &q) && g5c_eap_find(&q, G5C_AT_RESULT_IND) != NULL);
    TK_ASSERT(eue_challenge(&ue, es.pkt, es.len, IMSI, F_NONE, out, &on) == EUE_OK);
    TK_ASSERT(eap_post(&s, es.href, out, on, &v) == 200);
    /* RFC 4187 6.2: both sides asked for result indications, so a notification with "Success" and a valid AT_MAC comes first */
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_ONGOING") == 0 && g5c_json_get(v, "kSeaf") == NULL);
    rn = eap_of(v, rsp, sizeof rsp);
    TK_ASSERT(g5c_eap_parse(rsp, rn, &p) && p.code == G5C_EAP_REQUEST && p.subtype == G5C_EAPAKA_NOTIFICATION);
    {
        const g5c_eap_attr *nt = g5c_eap_find(&p, G5C_AT_NOTIFICATION);
        TK_ASSERT(nt != NULL && nt->vlen == 2 && nt->val[0] == 0x80 && nt->val[1] == 0x00);
        TK_ASSERT(g5c_eap_mac_ok(rsp, rn, ue.keys.k_aut, NULL, 0));
    }
    href2 = g5c_xstrdup(g5c_json_get_str(g5c_json_get(g5c_json_get(v, "_links"), "eap-session"), "href"));
    g5c_json_free(v);
    /* the peer acknowledges (with AT_MAC, as the notification had P = 0) */
    at[0] = (g5c_eap_attr){G5C_AT_MAC, macv, 18};
    TK_ASSERT(g5c_eap_build(G5C_EAP_RESPONSE, p.id, G5C_EAPAKA_NOTIFICATION, at, 1, note, sizeof note, &nn) == 0);
    TK_ASSERT(g5c_eap_mac_set(note, nn, ue.keys.k_aut, NULL, 0) == 0);
    TK_ASSERT(eap_post(&s, href2, note, nn, &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_SUCCESS") == 0);
    {
        char *kx = g5c_hex_encode(ue.kseaf, 32);
        TK_ASSERT(strcmp(g5c_json_get_str(v, "kSeaf"), kx) == 0);
        free(kx);
        rn = eap_of(v, rsp, sizeof rsp);
        TK_ASSERT(rn == 4 && rsp[0] == G5C_EAP_SUCCESS);
    }
    g5c_json_free(v);
    free(href2);
    /* an AT_KDF that repeats the value in use (UERANSIM sends it) is tolerated */
    eue_init(&ue, 32);
    TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
    TK_ASSERT(eue_challenge(&ue, es.pkt, es.len, IMSI, F_NO_IND | F_KDF_ECHO, out, &on) == EUE_OK);
    TK_ASSERT(eap_post(&s, es.href, out, on, &v) == 200 && strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_SUCCESS") == 0);
    g5c_json_free(v);
    /* a peer that does not echo AT_RESULT_IND gets EAP-Success right away */
    eue_init(&ue, 32);
    TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
    TK_ASSERT(eue_challenge(&ue, es.pkt, es.len, IMSI, F_NO_IND, out, &on) == EUE_OK);
    TK_ASSERT(eap_post(&s, es.href, out, on, &v) == 200 && strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_SUCCESS") == 0);
    g5c_json_free(v);
    unstack(&s);
}

/* a failed challenge round: notification with a failure code (no AT_MAC, the P bit is set), then EAP-Failure after its acknowledgement (RFC 4187 Figure 2) */
static void expect_failure_flow(S *s, esess *es, const uint8_t *bad, size_t bn, const char *supi)
{
    g5c_json *v = NULL, *st = NULL;
    uint8_t rsp[300], ack[16];
    size_t rn, an = 0;
    g5c_eap_pkt p;
    char *href2;
    bool b = true;
    TK_ASSERT(eap_post(s, es->href, bad, bn, &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_ONGOING") == 0 && g5c_json_get(v, "kSeaf") == NULL);
    rn = eap_of(v, rsp, sizeof rsp);
    TK_ASSERT(g5c_eap_parse(rsp, rn, &p) && p.code == G5C_EAP_REQUEST && p.subtype == G5C_EAPAKA_NOTIFICATION);
    {
        const g5c_eap_attr *nt = g5c_eap_find(&p, G5C_AT_NOTIFICATION);
        TK_ASSERT(nt != NULL && nt->val[0] == 0x40 && nt->val[1] == 0x00); /* 16384: general failure, S = 0, P = 1 */
        TK_ASSERT(g5c_eap_find(&p, G5C_AT_MAC) == NULL);
    }
    href2 = g5c_xstrdup(g5c_json_get_str(g5c_json_get(g5c_json_get(v, "_links"), "eap-session"), "href"));
    g5c_json_free(v);
    TK_ASSERT(g5c_eap_build(G5C_EAP_RESPONSE, p.id, G5C_EAPAKA_NOTIFICATION, NULL, 0, ack, sizeof ack, &an) == 0);
    TK_ASSERT(eap_post(s, href2, ack, an, &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_FAILURE") == 0 && g5c_json_get(v, "kSeaf") == NULL);
    rn = eap_of(v, rsp, sizeof rsp);
    TK_ASSERT(rn == 4 && rsp[0] == G5C_EAP_FAILURE);
    g5c_json_free(v);
    free(href2);
    auth_status_of(s, supi, &st);
    TK_ASSERT(g5c_json_get_bool(st, "success", &b) && !b);
    g5c_json_free(st);
}

static void test_eap_failures(void)
{
    S s;
    eue_t ue;
    esess es;
    g5c_json *v = NULL;
    uint8_t out[300], rsp[300], buf[64];
    size_t on = 0, rn;
    g5c_eap_pkt p;
    stack(&s, false, NULL);
    provision_m(&s, SUPI, "EAP_AKA_PRIME");
    eue_init(&ue, 0);
    /* wrong RES, wrong MAC, a different key derivation function: each is a failed verification */
    {
        static const unsigned flags[] = {F_BAD_RES, F_BAD_MAC, F_KDF};
        for (size_t i = 0; i < 3; i++) {
            TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
            TK_ASSERT(eue_challenge(&ue, es.pkt, es.len, IMSI, flags[i], out, &on) == EUE_OK);
            expect_failure_flow(&s, &es, out, on, SUPI);
            ue.ue.sqn_ms = 0; /* the peer did not accept the vector in the failed rounds: its SQN did not move in a real USIM either */
        }
    }
    /* the peer rejects AUTN, or reports an error: EAP-Failure at once */
    {
        g5c_eap_attr at[1];
        uint8_t code[2] = {0, 0};
        at[0] = (g5c_eap_attr){G5C_AT_CLIENT_ERROR_CODE, code, 2};
        TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
        TK_ASSERT(g5c_eap_parse(es.pkt, es.len, &p));
        TK_ASSERT(g5c_eap_build(G5C_EAP_RESPONSE, p.id, G5C_EAPAKA_CLIENT_ERROR, at, 1, buf, sizeof buf, &on) == 0);
        TK_ASSERT(eap_post(&s, es.href, buf, on, &v) == 200 && strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_FAILURE") == 0);
        rn = eap_of(v, rsp, sizeof rsp);
        TK_ASSERT(rn == 4 && rsp[0] == G5C_EAP_FAILURE && rsp[1] == p.id); /* the identifier repeats the response's */
        g5c_json_free(v);
        TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
        TK_ASSERT(g5c_eap_parse(es.pkt, es.len, &p));
        TK_ASSERT(g5c_eap_build(G5C_EAP_RESPONSE, p.id, G5C_EAPAKA_AUTH_REJECT, NULL, 0, buf, sizeof buf, &on) == 0);
        TK_ASSERT(eap_post(&s, es.href, buf, on, &v) == 200 && strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_FAILURE") == 0);
        g5c_json_free(v);
    }
    /* the AMF got nothing from the UE (null), and what is not an EAP-AKA' response at all */
    TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
    TK_ASSERT(eap_post(&s, es.href, NULL, 0, &v) == 200 && strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_FAILURE") == 0);
    g5c_json_free(v);
    TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
    {
        static const uint8_t junk[] = {0x02, 0x01, 0x00, 0x09, 0x17, 0x01, 0x00, 0x00, 0x00}; /* EAP-AKA (type 23), not AKA' */
        TK_ASSERT(eap_post(&s, es.href, junk, sizeof junk, &v) == 200 && strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_ONGOING") == 0);
        g5c_json_free(v);
    }
    /* requests the AUSF cannot accept: they do not end the session */
    TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
    eue_init(&ue, 0);
    TK_ASSERT(eue_challenge(&ue, es.pkt, es.len, IMSI, F_NONE, out, &on) == EUE_OK);
    {
        char *u2 = g5c_xasprintf("%s", es.href);
        TK_ASSERT(call(&s, "POST", u2, "{\"eapPayload\":\"!!!\"}", false, NULL) == 400);
        TK_ASSERT(call(&s, "POST", u2, "{}", false, NULL) == 400);
        TK_ASSERT(call(&s, "POST", u2, "{\"eapPayload\":5}", false, NULL) == 400);
        TK_ASSERT(call(&s, "POST", u2, "[", false, NULL) == 400);
        out[1] ^= 0x55; /* the identifier of another request */
        TK_ASSERT(eap_post(&s, es.href, out, on, NULL) == 400);
        out[1] ^= 0x55;
        TK_ASSERT(eap_post(&s, es.href, out, on, &v) == 200 && strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_SUCCESS") == 0);
        g5c_json_free(v);
        free(u2);
    }
    {
        char *u2 = g5c_xasprintf("%s/nausf-auth/v1/ue-authentications/nope/eap-session", s.ausf);
        TK_ASSERT(eap_post(&s, u2, out, on, NULL) == 404);
        free(u2);
    }
    unstack(&s);
}

static void test_eap_resync(void)
{
    S s;
    eue_t ue;
    esess es;
    g5c_json *v = NULL;
    uint8_t out[300], rsp[300], first_rand[16];
    size_t on = 0, rn;
    g5c_eap_pkt p, q;
    stack(&s, false, NULL);
    provision_m(&s, SUPI, "EAP_AKA_PRIME");
    eue_init(&ue, 0x10000); /* the USIM is far ahead of the network */
    TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
    TK_ASSERT(g5c_eap_parse(es.pkt, es.len, &q));
    memcpy(first_rand, g5c_eap_find(&q, G5C_AT_RAND)->val + 2, 16);
    TK_ASSERT(eue_challenge(&ue, es.pkt, es.len, IMSI, F_NONE, out, &on) == EUE_SYNC);
    TK_ASSERT(eap_post(&s, es.href, out, on, &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_ONGOING") == 0);
    rn = eap_of(v, rsp, sizeof rsp);
    TK_ASSERT(g5c_eap_parse(rsp, rn, &p) && p.subtype == G5C_EAPAKA_CHALLENGE && p.id != q.id); /* a new challenge with a new identifier */
    TK_ASSERT(memcmp(first_rand, g5c_eap_find(&p, G5C_AT_RAND)->val + 2, 16) != 0);
    memcpy(es.pkt, rsp, rn);
    es.len = rn;
    snprintf(es.href, sizeof es.href, "%s", g5c_json_get_str(g5c_json_get(g5c_json_get(v, "_links"), "eap-session"), "href"));
    g5c_json_free(v);
    TK_ASSERT(eue_challenge(&ue, es.pkt, es.len, IMSI, F_NONE, out, &on) == EUE_OK);
    TK_ASSERT(ue.ue.sqn_ms == 0x10000 + 32);
    TK_ASSERT(eap_post(&s, es.href, out, on, &v) == 200 && strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_SUCCESS") == 0);
    g5c_json_free(v);
    /* a peer that keeps reporting synchronisation failures is cut off after two resynchronisations */
    eue_init(&ue, 0x80000);
    TK_ASSERT(eap_begin(&s, SUPI, &es, NULL) == 201);
    for (int i = 0; i < 3; i++) {
        ue.ue.sqn_ms = 0x80000 + (uint64_t)(i + 1) * 0x100000; /* every new vector is behind what the USIM holds */
        TK_ASSERT(eue_challenge(&ue, es.pkt, es.len, IMSI, F_NONE, out, &on) == EUE_SYNC);
        TK_ASSERT(eap_post(&s, es.href, out, on, &v) == 200);
        if (i < 2) {
            TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_ONGOING") == 0);
            es.len = eap_of(v, es.pkt, sizeof es.pkt);
        } else {
            TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_FAILURE") == 0);
        }
        g5c_json_free(v);
    }
    unstack(&s);
}

static void test_removal_and_deregister(void)
{
    S s;
    ue_t ue;
    chal c;
    ue_out o;
    g5c_json *v;
    char *conf, *none, *dereg;
    uint8_t k[32];
    uint64_t before;
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    ue_init(&ue, 0);
    dereg = g5c_xasprintf("%s" SNN_B64_URL "/deregister", s.ausf);

    /* removal of the result of a 5G AKA authentication (TS 29.509 5.2.2.2.5): the UDM is told, the second DELETE finds nothing */
    c = start_ok(&s, SUPI);
    o = ue_challenge(&ue, c.rand, c.autn);
    TK_ASSERT(confirm(&s, c.href, o.res_star, 16, NULL) == 200);
    before = udm_counter(&s, "g5c_udm_auth_removals_total");
    TK_ASSERT(call(&s, "DELETE", c.href, NULL, false, NULL) == 204);
    TK_ASSERT(udm_counter(&s, "g5c_udm_auth_removals_total") == before + 1);
    TK_ASSERT(call(&s, "DELETE", c.href, NULL, false, NULL) == 404);
    /* a context that never got its confirmation: nothing to remove at the UDM, still 204 */
    c = start_ok(&s, SUPI);
    before = udm_counter(&s, "g5c_udm_auth_removals_total");
    TK_ASSERT(call(&s, "DELETE", c.href, NULL, false, NULL) == 204);
    TK_ASSERT(udm_counter(&s, "g5c_udm_auth_removals_total") == before);
    TK_ASSERT(confirm(&s, c.href, o.res_star, 16, NULL) == 404);
    /* a newer authentication replaces an older result: removing the old one does not touch the UDM's record of the new one */
    {
        chal c1 = start_ok(&s, SUPI), c2;
        ue_out o1 = ue_challenge(&ue, c1.rand, c1.autn), o2;
        TK_ASSERT(confirm(&s, c1.href, o1.res_star, 16, NULL) == 200);
        c2 = start_ok(&s, SUPI);
        o2 = ue_challenge(&ue, c2.rand, c2.autn);
        TK_ASSERT(confirm(&s, c2.href, o2.res_star, 16, NULL) == 200);
        before = udm_counter(&s, "g5c_udm_auth_removals_total");
        TK_ASSERT(call(&s, "DELETE", c1.href, NULL, false, NULL) == 204);
        TK_ASSERT(udm_counter(&s, "g5c_udm_auth_removals_total") == before);
        TK_ASSERT(call(&s, "DELETE", c2.href, NULL, false, NULL) == 204);
        TK_ASSERT(udm_counter(&s, "g5c_udm_auth_removals_total") == before + 1);
    }
    /* the DELETE belongs to the confirmation resource; the context resource itself has no DELETE */
    c = start_ok(&s, SUPI);
    conf = g5c_xstrdup(c.href);
    *strstr(conf, "/5g-aka-confirmation") = 0;
    none = g5c_xasprintf("%s", conf);
    TK_ASSERT(call(&s, "DELETE", none, NULL, false, NULL) == 404 || call(&s, "DELETE", none, NULL, false, NULL) == 405);
    free(conf);
    free(none);

    /* deregister: the latest KAUSF is cleared (TS 29.509 5.2.2.3) */
    TK_ASSERT(ausf_ue_kausf(s.a, SUPI, k, NULL, NULL));
    TK_ASSERT(call(&s, "POST", dereg, "{\"supi\":\"" SUPI "\"}", false, NULL) == 204);
    TK_ASSERT(!ausf_ue_kausf(s.a, SUPI, k, NULL, NULL));
    TK_ASSERT(call(&s, "POST", dereg, "{\"supi\":\"" SUPI "\"}", false, &v) == 404 && strcmp(g5c_json_get_str(v, "cause"), "CONTEXT_NOT_FOUND") == 0);
    g5c_json_free(v);
    TK_ASSERT(call(&s, "POST", dereg, "{}", false, NULL) == 400);
    TK_ASSERT(call(&s, "POST", dereg, "{\"supi\":\"../x\"}", false, NULL) == 400);
    TK_ASSERT(call(&s, "POST", dereg, "{\"supi\":5}", false, NULL) == 400);
    free(dereg);
    unstack(&s);
}

/* ---- SoR and UPU protection ------------------------------------------------------------------------------------------------------------------- */

static void mac_of(const uint8_t kausf[32], uint8_t fc, const uint8_t *p0, size_t l0, const uint8_t *p1, size_t l1, const uint8_t *p2, size_t l2, uint8_t out[16])
{
    const uint8_t *p[3] = {p0, p1, p2};
    size_t l[3] = {l0, l1, l2};
    uint8_t full[32];
    TK_ASSERT(g5c_kdf(kausf, 32, fc, p, l, p2 != NULL ? 3 : 2, full) == 0);
    memcpy(out, full + 16, 16); /* the 128 least significant bits */
}

static int prot_call(S *s, const char *service, const char *supi, const char *op, const char *body, g5c_json **out)
{
    char *u = g5c_xasprintf("%s/%s/v1/%s/%s", s->ausf, service, supi, op);
    int st = call(s, "POST", u, body, false, out);
    free(u);
    return st;
}

static void authenticate_5g(S *s, ue_t *ue, const char *supi)
{
    chal c = start_ok(s, supi);
    ue_out o = ue_challenge(ue, c.rand, c.autn);
    TK_ASSERT(o.kind == UE_OK && confirm(s, c.href, o.res_star, 16, NULL) == 200);
}

static void test_sor(void)
{
    S s;
    ue_t ue;
    g5c_json *v = NULL;
    uint8_t k[32], mac[16], ctr[2], hdr;
    char *hx;
    const uint8_t list1[] = {0x00, 0xF1, 0x10, 0x08, 0x00}; /* PLMN 001/01, NR: MCC2|MCC1 MNC3|MCC3 MNC2|MNC1 (TS 24.008), NG-RAN (TS 31.102) */
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    ue_init(&ue, 0);
    /* no security context yet */
    TK_ASSERT(prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data", "{\"ackInd\":false}", &v) == 404);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "cause"), "CONTEXT_NOT_FOUND") == 0);
    g5c_json_free(v);
    authenticate_5g(&s, &ue, SUPI);
    TK_ASSERT(ausf_ue_kausf(s.a, SUPI, k, NULL, NULL));

    /* list of PLMN / access technology, acknowledgement requested: header 0b1110 (ACK, list type PLMN, list given, data type 0) */
    TK_ASSERT(prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data",
                        "{\"ackInd\":true,\"steeringContainer\":[{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"accessTechList\":[\"NR\"]}]}", &v) == 200);
    hdr = 0x0E;
    ctr[0] = 0;
    ctr[1] = 1; /* CounterSoR starts at 0x0001 */
    mac_of(k, 0x77, &hdr, 1, ctr, 2, list1, sizeof list1, mac);
    hx = g5c_hex_encode(mac, 16);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "sorMacIausf"), hx) == 0 && strcmp(g5c_json_get_str(v, "counterSor"), "0001") == 0);
    free(hx);
    {
        const uint8_t one = 1;
        mac_of(k, 0x78, &one, 1, ctr, 2, NULL, 0, mac); /* SoR-XMAC-IUE: FC 0x78, 0x01 and the counter */
        hx = g5c_hex_encode(mac, 16);
        TK_ASSERT(strcmp(g5c_json_get_str(v, "sorXmacIue"), hx) == 0);
        free(hx);
    }
    g5c_json_free(v);

    /* the counter goes up with every MAC; without ackInd there is no XMAC; several entries, other technologies, a 3 digit MNC */
    TK_ASSERT(prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data",
                        "{\"ackInd\":false,\"steeringContainer\":[{\"plmnId\":{\"mcc\":\"310\",\"mnc\":\"260\"},\"accessTechList\":[\"EUTRAN_IN_NBS1_MODE_ONLY\",\"UTRAN\"]},"
                        "{\"plmnId\":{\"mcc\":\"262\",\"mnc\":\"01\"}}]}",
                        &v) == 200);
    {
        /* 310/260: 13 | 0 0 -> MCC2=1,MCC1=3 -> 0x13; MNC3=0,MCC3=0 -> 0x00; MNC2=6,MNC1=2 -> 0x62; E-UTRAN NB-S1 only 0x50 and UTRAN 0x80 -> 0xD0, GSM none -> 0x00.
         * 262/01: MCC2=6,MCC1=2 -> 0x62; MNC3=F,MCC3=2 -> 0xF2; MNC2=1,MNC1=0 -> 0x10; every technology: 0xCC 0xF0 */
        const uint8_t list3[] = {0x13, 0x00, 0x62, 0xD0, 0x00, 0x62, 0xF2, 0x10, 0xCC, 0xF0};
        hdr = 0x06; /* list type PLMN, list given, no ACK */
        ctr[1] = 2;
        mac_of(k, 0x77, &hdr, 1, ctr, 2, list3, sizeof list3, mac);
        hx = g5c_hex_encode(mac, 16);
        TK_ASSERT(strcmp(g5c_json_get_str(v, "sorMacIausf"), hx) == 0 && strcmp(g5c_json_get_str(v, "counterSor"), "0002") == 0);
        free(hx);
        TK_ASSERT(g5c_json_get(v, "sorXmacIue") == NULL);
        g5c_json_free(v);
    }
    /* a secured packet: list type 0, list given */
    TK_ASSERT(prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data", "{\"ackInd\":false,\"steeringContainer\":\"AQID\"}", &v) == 200);
    {
        const uint8_t pk[] = {1, 2, 3};
        hdr = 0x02;
        ctr[1] = 3;
        mac_of(k, 0x77, &hdr, 1, ctr, 2, pk, 3, mac);
        hx = g5c_hex_encode(mac, 16);
        TK_ASSERT(strcmp(g5c_json_get_str(v, "sorMacIausf"), hx) == 0);
        free(hx);
        g5c_json_free(v);
    }
    /* no change needed: an empty list (or none), header 0x00 or 0x08 with ACK, and the MAC covers the header and the counter only */
    TK_ASSERT(prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data", "{\"ackInd\":true,\"steeringContainer\":[]}", &v) == 200);
    hdr = 0x08;
    ctr[1] = 4;
    mac_of(k, 0x77, &hdr, 1, ctr, 2, NULL, 0, mac);
    hx = g5c_hex_encode(mac, 16);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "sorMacIausf"), hx) == 0 && g5c_json_get_str(v, "sorXmacIue") != NULL);
    free(hx);
    g5c_json_free(v);
    TK_ASSERT(prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data", "{\"ackInd\":false}", &v) == 200);
    {
        uint16_t cs = 0;
        TK_ASSERT(ausf_ue_kausf(s.a, SUPI, k, &cs, NULL) && cs == 6);
    }
    g5c_json_free(v);

    /* invalid requests */
    {
        static const char *const bad[] = {"{}", "{\"ackInd\":\"yes\"}", "{\"ackInd\":true,\"steeringContainer\":5}", "{\"ackInd\":true,\"steeringContainer\":[{\"plmnId\":{\"mcc\":\"00\",\"mnc\":\"01\"}}]}",
                                          "{\"ackInd\":true,\"steeringContainer\":[{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"accessTechList\":[\"WIFI\"]}]}",
                                          "{\"ackInd\":true,\"steeringContainer\":[{\"accessTechList\":[\"NR\"]}]}", "{\"ackInd\":true,\"steeringContainer\":\"!!\"}", "["};
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
            if (prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data", bad[i], NULL) != 400)
                TK_FAIL("SoR request %zu was not refused", i);
        {
            /* 17 entries: more than the container holds */
            g5c_bytes b;
            int st;
            g5c_bytes_init(&b);
            g5c_bytes_append_str(&b, "{\"ackInd\":false,\"steeringContainer\":[");
            for (int i = 0; i < 17; i++)
                g5c_bytes_append_str(&b, i ? ",{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"}}" : "{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"}}");
            g5c_bytes_append_str(&b, "]}");
            st = prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data", (const char *)b.data, NULL);
            g5c_bytes_free(&b);
            TK_ASSERT(st == 400);
        }
        TK_ASSERT(prot_call(&s, "nausf-sorprotection", "not-a-supi", "ue-sor/generate-sor-data", "{\"ackInd\":false}", NULL) == 400);
    }
    /* the counter is about to wrap: the service is suspended until the UE authenticates again (TS 33.501 6.14.2.3) */
    TK_ASSERT(ausf_ue_set_counters(s.a, SUPI, 0xFFFE, 1));
    TK_ASSERT(prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data", "{\"ackInd\":false}", &v) == 200 && strcmp(g5c_json_get_str(v, "counterSor"), "fffe") == 0);
    g5c_json_free(v);
    TK_ASSERT(prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data", "{\"ackInd\":false}", &v) == 503 && strcmp(g5c_json_get_str(v, "cause"), "COUNTER_WRAP") == 0);
    g5c_json_free(v);
    authenticate_5g(&s, &ue, SUPI); /* a fresh KAUSF: counters back to 1, the service resumes */
    TK_ASSERT(prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data", "{\"ackInd\":false}", &v) == 200 && strcmp(g5c_json_get_str(v, "counterSor"), "0001") == 0);
    g5c_json_free(v);
    unstack(&s);
}

static void test_upu(void)
{
    S s;
    ue_t ue;
    g5c_json *v = NULL;
    uint8_t k[32], mac[16], ctr[2] = {0, 1};
    char *hx;
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    ue_init(&ue, 0);
    TK_ASSERT(prot_call(&s, "nausf-upuprotection", SUPI, "ue-upu/generate-upu-data", "{\"upuDataList\":[{\"secPacket\":\"AQID\"}],\"upuHeader\":\"02\",\"upuAckInd\":true}", NULL) == 404);
    authenticate_5g(&s, &ue, SUPI);
    TK_ASSERT(ausf_ue_kausf(s.a, SUPI, k, NULL, NULL));
    /* a secured packet, the default configured NSSAI and the routing indicator of the ME: three data sets (TS 24.501 9.11.3.53A) */
    TK_ASSERT(prot_call(&s, "nausf-upuprotection", SUPI, "ue-upu/generate-upu-data",
                        "{\"upuDataList\":[{\"secPacket\":\"AQID\",\"defaultConfNssai\":[{\"sst\":1},{\"sst\":2,\"sd\":\"010203\"}],\"routingId\":\"1234\"},{\"routingId\":\"12\"}],"
                        "\"upuHeader\":\"06\",\"upuAckInd\":true}",
                        &v) == 200);
    {
        const uint8_t list[] = {0x01, 0x00, 0x03, 0x01, 0x02, 0x03,                                            /* type 1: the secured packet */
                                0x02, 0x00, 0x07, 0x01, 0x01, 0x04, 0x02, 0x01, 0x02, 0x03,                    /* type 2: S-NSSAI values with their length octets */
                                0x04, 0x00, 0x02, 0x21, 0x43,                                                  /* type 4: routing indicator digits 1,2 and 3,4 */
                                0x04, 0x00, 0x02, 0x21, 0xFF};                                                 /* "12": the unused digits are 1111 */
        const uint8_t one = 1;
        mac_of(k, 0x7B, list, sizeof list, ctr, 2, NULL, 0, mac);
        hx = g5c_hex_encode(mac, 16);
        TK_ASSERT(strcmp(g5c_json_get_str(v, "upuMacIausf"), hx) == 0 && strcmp(g5c_json_get_str(v, "counterUpu"), "0001") == 0);
        free(hx);
        mac_of(k, 0x7C, &one, 1, ctr, 2, NULL, 0, mac);
        hx = g5c_hex_encode(mac, 16);
        TK_ASSERT(strcmp(g5c_json_get_str(v, "upuXmacIue"), hx) == 0);
        free(hx);
    }
    g5c_json_free(v);
    /* the counters of SoR and UPU are independent; UPU goes up by one per MAC, no XMAC without the indication */
    TK_ASSERT(prot_call(&s, "nausf-upuprotection", SUPI, "ue-upu/generate-upu-data", "{\"upuDataList\":[{\"routingId\":\"7\"}],\"upuHeader\":\"00\",\"upuAckInd\":false}", &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "counterUpu"), "0002") == 0 && g5c_json_get(v, "upuXmacIue") == NULL);
    g5c_json_free(v);
    {
        uint16_t cs = 0, cu = 0;
        TK_ASSERT(ausf_ue_kausf(s.a, SUPI, k, &cs, &cu) && cs == 1 && cu == 3);
    }
    {
        static const char *const bad[] = {
            "{}", "{\"upuDataList\":[],\"upuHeader\":\"00\",\"upuAckInd\":false}", "{\"upuDataList\":[{}],\"upuHeader\":\"00\",\"upuAckInd\":false}",
            "{\"upuDataList\":[{\"routingId\":\"12345\"}],\"upuHeader\":\"00\",\"upuAckInd\":false}", "{\"upuDataList\":[{\"routingId\":\"ab\"}],\"upuHeader\":\"00\",\"upuAckInd\":false}",
            "{\"upuDataList\":[{\"routingId\":\"1\"}],\"upuHeader\":\"0\",\"upuAckInd\":false}", "{\"upuDataList\":[{\"routingId\":\"1\"}],\"upuHeader\":\"01\",\"upuAckInd\":false}",
            "{\"upuDataList\":[{\"routingId\":\"1\"}],\"upuHeader\":\"zz\",\"upuAckInd\":false}", "{\"upuDataList\":[{\"routingId\":\"1\"}],\"upuHeader\":\"00\"}",
            "{\"upuDataList\":[{\"defaultConfNssai\":[]}],\"upuHeader\":\"00\",\"upuAckInd\":false}", "{\"upuDataList\":[{\"defaultConfNssai\":[{\"sst\":300}]}],\"upuHeader\":\"00\",\"upuAckInd\":false}",
            "{\"upuDataList\":[{\"defaultConfNssai\":[{\"sst\":1,\"sd\":\"12\"}]}],\"upuHeader\":\"00\",\"upuAckInd\":false}", "{\"upuDataList\":[{\"secPacket\":\"!!\"}],\"upuHeader\":\"00\",\"upuAckInd\":false}"};
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
            if (prot_call(&s, "nausf-upuprotection", SUPI, "ue-upu/generate-upu-data", bad[i], NULL) != 400)
                TK_FAIL("UPU request %zu was not refused", i);
    }
    TK_ASSERT(ausf_ue_set_counters(s.a, SUPI, 1, 0xFFFF));
    TK_ASSERT(prot_call(&s, "nausf-upuprotection", SUPI, "ue-upu/generate-upu-data", "{\"upuDataList\":[{\"routingId\":\"7\"}],\"upuHeader\":\"00\",\"upuAckInd\":false}", &v) == 503);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "cause"), "COUNTER_WRAP") == 0);
    g5c_json_free(v);
    unstack(&s);
}

/* ---- the state file -------------------------------------------------------------------------------------------------------------------------------- */

static ausf *state_ausf(S *s, const char *path, const uint8_t *key, char *err, size_t cap)
{
    ausf_opts o;
    ausf *a;
    ausf_opts_default(&o);
    o.state_file = g5c_xstrdup(path);
    if (key != NULL) {
        memcpy(o.master_key, key, 32);
        o.has_master_key = true;
    }
    a = ausf_new(s->client, s->udm, NULL, "", "ausf-state", s->metrics_ausf, &o);
    ausf_opts_free(&o);
    if (ausf_start(a, err, cap) != 0) {
        ausf_free(a);
        return NULL;
    }
    return a;
}

static void test_state_file(void)
{
    S s;
    ue_t ue;
    char path[128], err[200];
    uint8_t key[32], key2[32], k1[32], k2[32];
    uint16_t cs1 = 0, cu1 = 0, cs2 = 0, cu2 = 0;
    ausf *a2;
    g5c_json *v;
    size_t len = 0;
    char *text;
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    ue_init(&ue, 0);
    snprintf(path, sizeof path, "/tmp/g5c-ausf-state-%d.json", (int)getpid());
    unlink(path);
    memset(key, 0x42, 32);
    memset(key2, 0x43, 32);
    ausf_free(s.a); /* replace the AUSF of the stack by one with a state file */
    s.a = state_ausf(&s, path, key, err, sizeof err);
    TK_ASSERT(s.a != NULL);
    {
        g5c_router_free(s.ausf_r);
        g5c_server_stop(s.ausf_s);
        s.ausf_r = ausf_router(s.a);
        {
            g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
            s.ausf_s = g5c_server_start(&cfg, s.ausf_r, err, sizeof err);
            TK_ASSERT(s.ausf_s != NULL);
            snprintf(s.ausf, sizeof s.ausf, "http://127.0.0.1:%u", g5c_server_port(s.ausf_s));
        }
    }
    authenticate_5g(&s, &ue, SUPI);
    TK_ASSERT(prot_call(&s, "nausf-sorprotection", SUPI, "ue-sor/generate-sor-data", "{\"ackInd\":false}", &v) == 200);
    g5c_json_free(v);
    TK_ASSERT(ausf_ue_kausf(s.a, SUPI, k1, &cs1, &cu1) && cs1 == 2);
    TK_ASSERT(ausf_flush(s.a) == 0);
    /* the file holds the SUPI in clear (it is only an index) but not the key */
    text = g5c_read_file(path, 1 << 20, &len);
    TK_ASSERT(text != NULL && strstr(text, SUPI) != NULL);
    {
        char *kh = g5c_hex_encode(k1, 32);
        TK_ASSERT(strstr(text, kh) == NULL);
        free(kh);
    }

    /* a restart: the KAUSF is back, the counters are not behind what was used (they are ahead by a margin) */
    a2 = state_ausf(&s, path, key, err, sizeof err);
    TK_ASSERT(a2 != NULL);
    TK_ASSERT(ausf_ue_kausf(a2, SUPI, k2, &cs2, &cu2) && memcmp(k1, k2, 32) == 0 && cs2 >= cs1 && cu2 >= cu1);
    TK_ASSERT(ausf_ue_count(a2) == 1);
    ausf_free(a2);
    /* the wrong master key, a missing key, a damaged file, a tampered ciphertext, an unknown format */
    TK_ASSERT(state_ausf(&s, path, key2, err, sizeof err) == NULL && strstr(err, "master key") != NULL);
    TK_ASSERT(state_ausf(&s, path, NULL, err, sizeof err) == NULL);
    {
        char *t2 = g5c_xstrdup(text);
        char *p = strstr(t2, "\"kausf\":\"");
        TK_ASSERT(p != NULL);
        p += 9;
        *p = (*p == '0') ? '1' : '0';
        {
            FILE *f = fopen(path, "wb");
            TK_ASSERT(f != NULL);
            fputs(t2, f);
            fclose(f);
        }
        TK_ASSERT(state_ausf(&s, path, key, err, sizeof err) == NULL);
        {
            FILE *f = fopen(path, "wb");
            TK_ASSERT(f != NULL);
            fputs("{not json", f);
            fclose(f);
        }
        TK_ASSERT(state_ausf(&s, path, key, err, sizeof err) == NULL && strstr(err, "JSON") != NULL);
        {
            FILE *f = fopen(path, "wb");
            TK_ASSERT(f != NULL);
            fputs("{\"version\":9,\"contexts\":[]}", f);
            fclose(f);
        }
        TK_ASSERT(state_ausf(&s, path, key, err, sizeof err) == NULL && strstr(err, "format") != NULL);
        free(t2);
    }
    /* a bound KAUSF cannot be moved to another SUPI: the SUPI is the associated data */
    {
        char *t3 = g5c_xstrdup(text), *p = strstr(t3, SUPI);
        FILE *f;
        TK_ASSERT(p != NULL);
        p[strlen(SUPI) - 1] = '2';
        f = fopen(path, "wb");
        TK_ASSERT(f != NULL);
        fputs(t3, f);
        fclose(f);
        TK_ASSERT(state_ausf(&s, path, key, err, sizeof err) == NULL);
        free(t3);
    }
    free(text);
    unlink(path);
    {
        char tmp[140];
        snprintf(tmp, sizeof tmp, "%s.tmp", path);
        unlink(tmp);
    }
    unstack(&s);
}

/* ---- configuration ----------------------------------------------------------------------------------------------------------------------------------- */

static ausf *config_ausf(const char *yaml, char *err, size_t cap, g5c_nf **nf_out)
{
    g5c_json *j = g5c_yaml_parse(yaml, strlen(yaml), err, cap);
    g5c_common common;
    g5c_nf *nf;
    ausf *a;
    TK_ASSERT(j != NULL && g5c_common_parse(j, &common, err, cap) == 0);
    common.port = 0;
    nf = g5c_nf_new(&common, err, cap);
    TK_ASSERT(nf != NULL);
    a = ausf_from_config(j, nf, err, cap);
    g5c_json_free(j);
    if (a == NULL || nf_out == NULL)
        g5c_nf_free(nf);
    else
        *nf_out = nf;
    return a;
}

static void test_config(void)
{
    static const char *const base = "name: ausf-test\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\nudm: { uri: 'http://127.0.0.1:1' }\n";
    static const struct {
        const char *extra, *needle;
    } bad[] = {
        {"ausf: 5\n", "mapping"},
        {"ausf: { colour: red }\n", "colour"},
        {"ausf: { context_lifetime: 0 }\n", "context_lifetime"},
        {"ausf: { context_lifetime: 'x' }\n", "context_lifetime"},
        {"ausf: { max_contexts: 0 }\n", "max_contexts"},
        {"ausf: { max_ue_contexts: -3 }\n", "max_ue_contexts"},
        {"ausf: { result_retention: 0 }\n", "result_retention"},
        {"ausf: { serving_networks: [] }\n", "serving_networks"},
        {"ausf: { serving_networks: ['evil.example.org'] }\n", "serving_networks"},
        {"ausf: { serving_networks: ['5G:mnc01.mcc001.3gppnetwork.org'] }\n", "serving_networks"},
        {"ausf: { eap: 5 }\n", "eap"},
        {"ausf: { eap: { result_indication: 'maybe' } }\n", "result_indication"},
        {"ausf: { eap: { speed: 1 } }\n", "speed"},
        {"ausf: { state_file: '/tmp/x.json' }\n", "master key"},
        {"ausf: { state_file: '' }\n", "state_file"},
        {"ausf: { self_uri: 'ftp://x' }\n", "self_uri"},
        {"ausf: { supi_ranges: [] }\n", "supi_ranges"},
        {"ausf: { supi_ranges: [{ start: '1', end: '2' }] }\n", "supi_ranges"},
        {"ausf: { supi_ranges: [{ start: '001010000000010', end: '001010000000001' }] }\n", "supi_ranges"},
        {"ausf: { routing_indicators: ['12345'] }\n", "routing_indicators"},
        {"ausf: { routing_indicators: [] }\n", "routing_indicators"},
        {"udm: { uri: 5 }\n", "udm"},
        {"udm: { colour: red, uri: 'http://x' }\n", "colour"},
    };
    char err[300];
    g5c_nf *nf = NULL;
    ausf *a;
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        char *y = g5c_xasprintf("%s%s", strncmp(bad[i].extra, "udm:", 4) == 0 ? "name: ausf-test\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\n" : base, bad[i].extra);
        a = config_ausf(y, err, sizeof err, NULL);
        if (a != NULL)
            TK_FAIL("configuration %zu was accepted: %s", i, bad[i].extra);
        if (strstr(err, bad[i].needle) == NULL)
            TK_FAIL("configuration %zu: the error \"%s\" does not mention %s", i, err, bad[i].needle);
        free(y);
    }
    /* neither a UDM nor an NRF */
    {
        a = config_ausf("name: ausf-test\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\n", err, sizeof err, NULL);
        TK_ASSERT(a == NULL && strstr(err, "udm.uri") != NULL);
    }
    /* the UDM found through the NRF */
    a = config_ausf("name: ausf-test\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\nnrf: { uri: 'http://127.0.0.1:1' }\n", err, sizeof err, &nf);
    TK_ASSERT(a != NULL);
    ausf_free(a);
    g5c_nf_free(nf);
    /* everything set */
    {
        char *y = g5c_xasprintf("%s%s", base,
                                "ausf:\n  context_lifetime: 12\n  result_retention: 600\n  max_contexts: 50\n  max_ue_contexts: 60\n  serving_networks: ['5G:mnc001.mcc001.3gppnetwork.org']\n"
                                "  eap: { result_indication: true }\n  self_uri: 'http://ausf.example:7774'\n  group_id: 'ausfgroup1'\n"
                                "  supi_ranges: [{ start: '001010000000001', end: '001010000999999' }]\n  routing_indicators: ['0', '1234']\n");
        const g5c_json *info;
        a = config_ausf(y, err, sizeof err, &nf);
        free(y);
        TK_ASSERT(a != NULL);
        info = ausf_nrf_info(a);
        TK_ASSERT(info != NULL && strcmp(g5c_json_get_str(info, "groupId"), "ausfgroup1") == 0);
        TK_ASSERT(g5c_json_len(g5c_json_get(info, "supiRanges")) == 1 && g5c_json_len(g5c_json_get(info, "routingIndicators")) == 2);
        TK_ASSERT(strcmp(g5c_json_get_str(g5c_json_at(g5c_json_get(info, "supiRanges"), 0), "end"), "001010000999999") == 0);
        ausf_free(a);
        g5c_nf_free(nf);
    }
}

/* ---- serving network, limits, supersession, FN-RG ------------------------------------------------------------------------------------------------------- */

static void test_serving_network(void)
{
    S s;
    g5c_json *v = NULL;
    char body[300], *u;
    static const char *const bad[] = {"", "5G:mnc01.mcc001.3gppnetwork.org", "5G:mnc001.mcc001.3gppnetwork.org ", "5g:mnc001.mcc001.3gppnetwork.org", "5G:mnc00a.mcc001.3gppnetwork.org",
                                      "5G:mnc001.mcc001.3gppnetwork.com", "EPS:mnc001.mcc001.3gppnetwork.org", "5G:mnc001.mcc001"};
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    u = g5c_xasprintf("%s" SNN_B64_URL, s.ausf);
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        snprintf(body, sizeof body, "{\"supiOrSuci\":\"" SUPI "\",\"servingNetworkName\":\"%s\"}", bad[i]);
        TK_ASSERT(call(&s, "POST", u, body, false, &v) == 403);
        TK_ASSERT(strcmp(g5c_json_get_str(v, "cause"), "SERVING_NETWORK_NOT_AUTHORIZED") == 0);
        g5c_json_free(v);
    }
    /* the SUPI and SUCI forms that are not acceptable: 400 */
    {
        static const char *const ids[] = {"", "imsi-12", "imsi-1234567890123456", "imsi-0010100000000a1", "../etc/passwd", "imsi-001010000000001/../x", "suci-", "x"};
        for (size_t i = 0; i < sizeof ids / sizeof *ids; i++) {
            snprintf(body, sizeof body, "{\"supiOrSuci\":\"%s\",\"servingNetworkName\":\"" SNN "\"}", ids[i]);
            TK_ASSERT(call(&s, "POST", u, body, false, NULL) == 400);
        }
    }
    TK_ASSERT(call(&s, "POST", u, "{\"supiOrSuci\":\"" SUPI "\",\"servingNetworkName\":\"" SNN "\",\"n5gcInd\":true}", false, &v) == 403);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "cause"), "AUTHENTICATION_REJECTED") == 0);
    g5c_json_free(v);
    free(u);
    unstack(&s);
}

static void test_allow_list(void)
{
    S s;
    g5c_json *v = NULL;
    char err[100];
    ausf_opts o;
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char *u, *ok_body = g5c_xstrdup("{\"supiOrSuci\":\"" SUPI "\",\"servingNetworkName\":\"" SNN "\"}");
    char *list[1] = {(char *)"5G:mnc002.mcc002.3gppnetwork.org"};
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    ausf_free(s.a);
    ausf_opts_default(&o);
    o.snn_allow = list;
    o.n_snn_allow = 1;
    s.a = ausf_new(s.client, s.udm, NULL, "", "ausf-allow", s.metrics_ausf, &o);
    g5c_router_free(s.ausf_r);
    g5c_server_stop(s.ausf_s);
    s.ausf_r = ausf_router(s.a);
    s.ausf_s = g5c_server_start(&cfg, s.ausf_r, err, sizeof err);
    TK_ASSERT(s.ausf_s != NULL);
    snprintf(s.ausf, sizeof s.ausf, "http://127.0.0.1:%u", g5c_server_port(s.ausf_s));
    u = g5c_xasprintf("%s" SNN_B64_URL, s.ausf);
    TK_ASSERT(call(&s, "POST", u, ok_body, false, &v) == 403 && strcmp(g5c_json_get_str(v, "cause"), "SERVING_NETWORK_NOT_AUTHORIZED") == 0);
    g5c_json_free(v);
    free(ok_body);
    ok_body = g5c_xstrdup("{\"supiOrSuci\":\"" SUPI "\",\"servingNetworkName\":\"5G:mnc002.mcc002.3gppnetwork.org\"}");
    TK_ASSERT(call(&s, "POST", u, ok_body, false, &v) == 201);
    g5c_json_free(v);
    free(ok_body);
    free(u);
    unstack(&s);
}

static void test_supersede_and_limits(void)
{
    S s;
    ue_t ue;
    chal c1, c2, c3;
    ue_out o;
    ausf_opts opt;
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[100];
    g5c_json *v = NULL;
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    provision(&s, PLMN_SUPI(1), "000000000000");
    provision(&s, PLMN_SUPI(2), "000000000000");
    ue_init(&ue, 0);
    /* a new start for the same UE and serving network replaces the pending one (TS 29.509 5.2.2.2.2) */
    c1 = start_ok(&s, SUPI);
    c2 = start_ok(&s, SUPI);
    TK_ASSERT(ausf_context_count(s.a) == 1);
    o = ue_challenge(&ue, c1.rand, c1.autn);
    TK_ASSERT(o.kind == UE_OK && confirm(&s, c1.href, o.res_star, 16, NULL) == 404);
    ue.sqn_ms = 0;
    o = ue_challenge(&ue, c2.rand, c2.autn);
    TK_ASSERT(o.kind == UE_OK && confirm(&s, c2.href, o.res_star, 16, NULL) == 200);
    /* the table is bounded: a start beyond it is answered 503 and nothing else is lost */
    ausf_free(s.a);
    ausf_opts_default(&opt);
    opt.max_contexts = 2;
    s.a = ausf_new(s.client, s.udm, NULL, "", "ausf-limit", s.metrics_ausf, &opt);
    g5c_router_free(s.ausf_r);
    g5c_server_stop(s.ausf_s);
    s.ausf_r = ausf_router(s.a);
    s.ausf_s = g5c_server_start(&cfg, s.ausf_r, err, sizeof err);
    TK_ASSERT(s.ausf_s != NULL);
    snprintf(s.ausf, sizeof s.ausf, "http://127.0.0.1:%u", g5c_server_port(s.ausf_s));
    c1 = start_ok(&s, SUPI);
    c2 = start_ok(&s, PLMN_SUPI(1));
    TK_ASSERT(start_auth(&s, PLMN_SUPI(2), NULL, NULL, &v) == 503);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "cause"), "INSUFFICIENT_RESOURCES") == 0);
    g5c_json_free(v);
    ue.sqn_ms = 0;
    o = ue_challenge(&ue, c1.rand, c1.autn);
    TK_ASSERT(o.kind == UE_OK && confirm(&s, c1.href, o.res_star, 16, NULL) == 200); /* finished contexts are the first to give way */
    c3 = start_ok(&s, PLMN_SUPI(2));
    (void)c2;
    (void)c3;
    unstack(&s);
}

static void test_rg(void)
{
    S s;
    g5c_json *v = NULL;
    char *u;
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    u = g5c_xasprintf("%s/nausf-auth/v1/rg-authentications", s.ausf);
    /* the W-AGF has authenticated the gateway: the AUSF learns the SUPI and does not authenticate again (TS 29.509 5.2.2.2.4) */
    TK_ASSERT(call(&s, "POST", u, "{\"suci\":\"suci-0-001-01-0000-0-0-0000000001\",\"authenticatedInd\":true}", false, &v) == 201);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_SUCCESS") == 0 && strcmp(g5c_json_get_str(v, "supi"), SUPI) == 0);
    {
        bool b = false;
        TK_ASSERT(g5c_json_get_bool(v, "authInd", &b) && b);
    }
    g5c_json_free(v);
    TK_ASSERT(call(&s, "POST", u, "{\"suci\":\"suci-0-001-01-0000-0-0-0000000001\",\"authenticatedInd\":false}", false, &v) == 201);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_FAILURE") == 0 && g5c_json_get(v, "supi") == NULL);
    g5c_json_free(v);
    TK_ASSERT(call(&s, "POST", u, "{\"suci\":\"suci-0-001-01-0000-0-0-0000000009\",\"authenticatedInd\":true}", false, &v) == 404);
    g5c_json_free(v);
    TK_ASSERT(call(&s, "POST", u, "{\"authenticatedInd\":true}", false, NULL) == 400);
    TK_ASSERT(call(&s, "POST", u, "{\"suci\":\"suci-0-001-01-0000-0-0-0000000001\"}", false, NULL) == 400);
    TK_ASSERT(call(&s, "POST", u, "{\"suci\":\"../x\",\"authenticatedInd\":true}", false, NULL) == 400);
    free(u);
    unstack(&s);
}

typedef struct {
    S *s;
    int idx, ok, rounds;
} wk_t;

static void *worker(void *arg)
{
    wk_t *w = arg;
    ue_t ue;
    const char *supi = PLMN_SUPI(w->idx);
    ue_init(&ue, 0);
    for (int i = 0; i < w->rounds; i++) {
        g5c_json *v = NULL;
        char err[100], *u = g5c_xasprintf("%s" SNN_B64_URL, w->s->ausf), body[200], *rsx;
        g5c_resp rs;
        chal c;
        ue_out o;
        snprintf(body, sizeof body, "{\"supiOrSuci\":\"%s\",\"servingNetworkName\":\"" SNN "\"}", supi);
        if (g5c_client_request(w->s->client, "POST", u, NULL, 0, G5C_JSON_TYPE, body, strlen(body), &rs, err, sizeof err) != 0 || rs.status != 201) {
            free(u);
            return NULL;
        }
        v = g5c_resp_parse_json(&rs);
        g5c_resp_free(&rs);
        free(u);
        {
            const g5c_json *d = g5c_json_get(v, "5gAuthData");
            h(g5c_json_get_str(d, "rand"), c.rand, 16);
            h(g5c_json_get_str(d, "autn"), c.autn, 16);
            snprintf(c.href, sizeof c.href, "%s", g5c_json_get_str(g5c_json_get(g5c_json_get(v, "_links"), "5g-aka"), "href"));
        }
        g5c_json_free(v);
        o = ue_challenge(&ue, c.rand, c.autn);
        if (o.kind != UE_OK)
            return NULL;
        rsx = g5c_hex_encode(o.res_star, 16);
        snprintf(body, sizeof body, "{\"resStar\":\"%s\"}", rsx);
        free(rsx);
        if (g5c_client_request(w->s->client, "PUT", c.href, NULL, 0, G5C_JSON_TYPE, body, strlen(body), &rs, err, sizeof err) != 0 || rs.status != 200)
            return NULL;
        g5c_resp_free(&rs);
        w->ok++;
    }
    return NULL;
}

static void test_concurrent_auth(void)
{
    S s;
    pthread_t th[8];
    wk_t w[8];
    stack(&s, false, NULL);
    for (int i = 0; i < 8; i++)
        provision(&s, PLMN_SUPI(i), "000000000000");
    for (int i = 0; i < 8; i++) {
        w[i] = (wk_t){&s, i, 0, 12};
        pthread_create(&th[i], NULL, worker, &w[i]);
    }
    for (int i = 0; i < 8; i++) {
        pthread_join(th[i], NULL);
        TK_ASSERT(w[i].ok == 12);
    }
    TK_ASSERT(ausf_ue_count(s.a) == 8);
    TK_ASSERT(ausf_context_count(s.a) == 8 * 12);
    unstack(&s);
}

static void test_routes_and_metrics(void)
{
    S s;
    ue_t ue;
    g5c_router *r = g5c_router_new();
    char *txt;
    static const char *const want[] = {"POST /nausf-auth/v1/ue-authentications", "POST /nausf-auth/v1/ue-authentications/deregister",
                                       "PUT /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation", "DELETE /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation",
                                       "POST /nausf-auth/v1/ue-authentications/{authCtxId}/eap-session", "DELETE /nausf-auth/v1/ue-authentications/{authCtxId}/eap-session",
                                       "POST /nausf-auth/v1/rg-authentications", "POST /nausf-sorprotection/v1/{supi}/ue-sor/generate-sor-data",
                                       "POST /nausf-upuprotection/v1/{supi}/ue-upu/generate-upu-data"};
    ausf_routes(r, NULL); /* the route table does not depend on state */
    TK_ASSERT(g5c_router_count(r) == sizeof want / sizeof *want);
    for (size_t i = 0; i < g5c_router_count(r); i++) {
        const char *m, *t;
        char line[200];
        bool found = false;
        TK_ASSERT(g5c_router_route_at(r, i, &m, &t));
        snprintf(line, sizeof line, "%s %s", m, t);
        for (size_t k = 0; k < sizeof want / sizeof *want; k++)
            found = found || strcmp(line, want[k]) == 0;
        if (!found)
            TK_FAIL("unexpected route %s", line);
    }
    g5c_router_free(r);
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    ue_init(&ue, 0);
    authenticate_5g(&s, &ue, SUPI);
    txt = g5c_registry_render(s.metrics_ausf);
    TK_ASSERT(strstr(txt, "g5c_ausf_authentications_total{method=\"5g-aka\",result=\"started\"} 1") != NULL);
    TK_ASSERT(strstr(txt, "g5c_ausf_authentications_total{method=\"5g-aka\",result=\"success\"} 1") != NULL);
    TK_ASSERT(strstr(txt, "g5c_ausf_security_contexts 1") != NULL && strstr(txt, "g5c_ausf_contexts{state=\"finished\"} 1") != NULL &&
              strstr(txt, "g5c_ausf_contexts{state=\"pending\"} 0") != NULL);
    free(txt);
    {   /* the answer that carries links is 3GPP hypermedia, and nothing that carries keys or challenges may be cached */
        char err[100], *u = g5c_xasprintf("%s" SNN_B64_URL, s.ausf);
        const char *body = "{\"supiOrSuci\":\"" SUPI "\",\"servingNetworkName\":\"" SNN "\"}";
        g5c_resp hr;
        TK_ASSERT(g5c_client_request(s.client, "POST", u, NULL, 0, G5C_JSON_TYPE, body, strlen(body), &hr, err, sizeof err) == 0 && hr.status == 201);
        TK_ASSERT(strncmp(g5c_resp_header_get(&hr, "content-type"), "application/3gppHal+json", 24) == 0);
        TK_ASSERT(strcmp(g5c_resp_header_get(&hr, "cache-control"), "no-store") == 0);
        g5c_resp_free(&hr);
        free(u);
    }
    unstack(&s);
}

/* a null RES* is the AMF's way of saying that the UE did not answer (TS 29.509 5.2.2.2.2 step 3): a failure, reported to the UDM, no key; a malformed one is 400 and
 * leaves the context as it was */
static void test_null_res_star(void)
{
    S s;
    ue_t ue;
    chal c;
    ue_out o;
    g5c_json *v = NULL, *st = NULL;
    bool b = true;
    stack(&s, false, NULL);
    provision(&s, SUPI, "000000000000");
    ue_init(&ue, 0);
    c = start_ok(&s, SUPI);
    TK_ASSERT(call(&s, "PUT", c.href, "{\"resStar\":\"zz\"}", false, NULL) == 400);
    TK_ASSERT(call(&s, "PUT", c.href, "{\"resStar\":12}", false, NULL) == 400);
    TK_ASSERT(call(&s, "PUT", c.href, "{\"resStar\":null}", false, &v) == 200);
    TK_ASSERT(strcmp(g5c_json_get_str(v, "authResult"), "AUTHENTICATION_FAILURE") == 0 && g5c_json_get(v, "kseaf") == NULL);
    g5c_json_free(v);
    auth_status_of(&s, SUPI, &st);
    TK_ASSERT(g5c_json_get_bool(st, "success", &b) && !b);
    g5c_json_free(st);
    TK_ASSERT(call(&s, "PUT", c.href, "{\"resStar\":null}", false, NULL) == 404); /* single use */
    TK_ASSERT(ausf_ue_count(s.a) == 0);                                          /* a failure stores no key */
    c = start_ok(&s, SUPI);
    o = ue_challenge(&ue, c.rand, c.autn);
    TK_ASSERT(o.kind == UE_OK && confirm(&s, c.href, o.res_star, 16, NULL) == 200 && ausf_ue_count(s.a) == 1);
    unstack(&s);
}

static void test_more(void)
{
    test_null_res_star();
    test_eap_full();
    test_eap_result_indication();
    test_eap_failures();
    test_eap_resync();
    test_removal_and_deregister();
    test_sor();
    test_upu();
    test_state_file();
    test_config();
    test_serving_network();
    test_allow_list();
    test_supersede_and_limits();
    test_rg();
    test_concurrent_auth();
    test_routes_and_metrics();
}
