/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* g5c-ctl driven in-process against a real UDM + udr + PCF. */
#define _DEFAULT_SOURCE
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/ctl.h"
#include "g5c/pcf.h"
#include "g5c/testkit.h"
#include "g5c/udm.h"
#include "g5c/udr.h"

#define TOKEN "ctl-test-token-0123456789"
#define SUPI "imsi-001010000000007"
#define K_HEX "465b5ce8b199b49faa5f0a2ee238a6bc"
#define OP_HEX "cdc202d5123e20f62b6d676ac72cb318"

static char *slurp(FILE *f)
{
    long n;
    char *b;
    fflush(f);
    n = ftell(f);
    b = calloc((size_t)n + 1, 1);
    TK_ASSERT(b != NULL);
    rewind(f);
    TK_ASSERT(fread(b, 1, (size_t)n, f) == (size_t)n);
    rewind(f);
    return b;
}

/* run g5c-ctl with the given arguments; output goes to *out / *err (malloc'd), returns the exit code */
static int ctl(const char *udm_base, const char *pcf_base, char **out, char **err, int n, ...)
{
    FILE *fo = tmpfile(), *fe = tmpfile();
    char *argv[32], ub[96], pb[96];
    int argc = 0, rc;
    va_list ap;
    argv[argc++] = "g5c-ctl";
    argv[argc++] = "--udm";
    snprintf(ub, sizeof ub, "%s", udm_base);
    snprintf(pb, sizeof pb, "%s", pcf_base);
    argv[argc++] = ub;
    argv[argc++] = "--pcf";
    argv[argc++] = pb;
    va_start(ap, n);
    for (int i = 0; i < n; i++)
        argv[argc++] = va_arg(ap, char *);
    va_end(ap);
    TK_ASSERT(fo != NULL && fe != NULL);
    rc = g5c_ctl_main(argc, argv, fo, fe);
    *out = slurp(fo);
    *err = slurp(fe);
    fclose(fo);
    fclose(fe);
    return rc;
}

#define CTL(rc_want, ...)                                                                                                  do {                                                                                                                       free(o);                                                                                                               free(e);                                                                                                               TK_ASSERT(ctl(udm_url, pcf_url, &o, &e, (int)(sizeof((char *[]){__VA_ARGS__}) / sizeof(char *)), __VA_ARGS__) == (rc_want));     } while (0)

int main(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[160], udr_url[64], udm_url[64], pcf_url[64], *o = NULL, *e = NULL;
    g5c_client *client = g5c_client_new(5000, NULL);
    g5c_registry *m = g5c_registry_new();
    g5c_udr_store *store = g5c_udr_store_memory();
    g5c_router *udr_r = g5c_udr_router(store);
    g5c_server *udr_s = g5c_server_start(&cfg, udr_r, err, sizeof err), *udm_s, *pcf_s;
    udm_keys keys;
    udm u;
    pcf p;
    pcf_policy pol;
    g5c_json *py = g5c_yaml_parse("default: {}\n", 12, err, sizeof err);
    g5c_router *udm_r, *pcf_r;

    TK_ASSERT(udr_s != NULL && py != NULL);
    snprintf(udr_url, sizeof udr_url, "http://127.0.0.1:%u", g5c_server_port(udr_s));
    udm_keys_none(&keys);
    udm_init(&u, client, udr_url, &keys, NULL, 0, "00101", "udm-ctl", m);
    u.admin_token = g5c_xstrdup(TOKEN);
    udm_r = udm_router(&u);
    udm_s = g5c_server_start(&cfg, udm_r, err, sizeof err);
    TK_ASSERT(udm_s != NULL);
    snprintf(udm_url, sizeof udm_url, "http://127.0.0.1:%u", g5c_server_port(udm_s));
    TK_ASSERT(pcf_policy_parse(py, true, &pol, err, sizeof err) == 0);
    g5c_json_free(py);
    pcf_init(&p, &pol, client, udr_url, m);
    p.admin_token = g5c_xstrdup(TOKEN);
    pcf_r = pcf_router(&p);
    pcf_s = g5c_server_start(&cfg, pcf_r, err, sizeof err);
    TK_ASSERT(pcf_s != NULL);
    snprintf(pcf_url, sizeof pcf_url, "http://127.0.0.1:%u", g5c_server_port(pcf_s));

    setenv("G5C_ADMIN_TOKEN", TOKEN, 1);

    /* usage errors */
    CTL(2, "subscriber", "bogus");
    CTL(2, "subscriber", "add", "--supi", SUPI, "--k", K_HEX); /* neither op nor opc */
    CTL(2, "subscriber", "add", "--supi", SUPI, "--k", K_HEX, "--op", OP_HEX, "--opc", OP_HEX);
    CTL(2, "subscriber", "get", "imsi/../x");
    TK_ASSERT(strstr(e, "usage:") != NULL);

    /* subscriber lifecycle */
    CTL(0, "subscriber", "add", "--supi", SUPI, "--k", K_HEX, "--op", OP_HEX, "--slice", "1", "--slice", "2:010203", "--dnn", "internet");
    CTL(0, "subscriber", "get", SUPI);
    TK_ASSERT(strstr(o, SUPI) != NULL);
    TK_ASSERT(strstr(o, K_HEX) == NULL && strstr(o, OP_HEX) == NULL); /* the admin API never echoes key material */
    CTL(0, "subscriber", "list");
    TK_ASSERT(strstr(o, SUPI) != NULL);
    CTL(0, "subscriber", "delete", SUPI);
    CTL(1, "subscriber", "get", SUPI);
    TK_ASSERT(strstr(e, "404") != NULL);

    /* wrong token is rejected by the server */
    setenv("G5C_ADMIN_TOKEN", "not-the-right-token-123456", 1);
    CTL(1, "subscriber", "list");
    TK_ASSERT(strstr(e, "401") != NULL);
    setenv("G5C_ADMIN_TOKEN", TOKEN, 1);

    /* policy and sessions */
    CTL(1, "policy", "get", SUPI);
    {
        FILE *f = fopen("ctl_policy_test.yaml", "wb");
        TK_ASSERT(f != NULL);
        fputs("default:\n  session_ambr: { uplink: 5 Mbps, downlink: 10 Mbps }\n", f);
        fclose(f);
    }
    CTL(0, "policy", "put", SUPI, "ctl_policy_test.yaml");
    CTL(0, "policy", "get", SUPI);
    TK_ASSERT(strstr(o, "5 Mbps") != NULL);
    CTL(0, "policy", "delete", SUPI);
    remove("ctl_policy_test.yaml");
    CTL(0, "session", "list");
    CTL(1, "session", "terminate", "no-such-session");

    /* unreachable server */
    free(o);
    free(e);
    TK_ASSERT(ctl("http://127.0.0.1:1", pcf_url, &o, &e, 2, "subscriber", "list") == 3);
    free(o);
    free(e);

    g5c_server_stop(pcf_s);
    g5c_server_stop(udm_s);
    g5c_server_stop(udr_s);
    g5c_client_free(client);
    g5c_router_free(pcf_r);
    g5c_router_free(udm_r);
    g5c_router_free(udr_r);
    pcf_destroy(&p);
    udm_destroy(&u);
    g5c_udr_store_free(store);
    g5c_registry_free(m);
    printf("ctl tests passed\n");
    return 0;
}
