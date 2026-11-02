/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* g5c-ctl: subscriber provisioning (UDM) and policy / session operations (PCF) over their /admin/v1 APIs.
 *
 *   g5c-ctl [--udm URL] [--pcf URL] [--token-file FILE] <command>
 *     subscriber add --supi S --k HEX (--op HEX | --opc HEX) [--amf HEX] [--sqn HEX] [--slice SST[:SD]]... [--dnn NAME]...
 *     subscriber add --json FILE|-          (the raw /admin/v1/subscribers body)
 *     subscriber get SUPI | list | delete SUPI
 *     policy get SUPI | delete SUPI | put SUPI FILE|-   (JSON or YAML policy document)
 *     session list | terminate SMPOLICYID
 *
 * The admin token is read from --token-file or G5C_ADMIN_TOKEN; it is never printed. */
#define _DEFAULT_SOURCE
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "g5c/config.h"
#include "g5c/ctl.h"
#include "g5c/nfcore.h"
#include "g5c/sbi.h"

enum { RC_OK = 0, RC_HTTP = 1, RC_USAGE = 2, RC_NET = 3 };

typedef struct {
    const char *udm, *pcf;
    char *token;
    FILE *out, *err;
    g5c_client *client;
} ctl;

static int usage(ctl *c, const char *why)
{
    if (why)
        fprintf(c->err, "g5c-ctl: %s\n", why);
    fputs("usage: g5c-ctl [--udm URL] [--pcf URL] [--token-file FILE] <command>\n"
          "  subscriber add --supi S --k HEX (--op HEX | --opc HEX) [--amf HEX] [--sqn HEX] [--slice SST[:SD]]... [--dnn NAME]...\n"
          "  subscriber add --json FILE|-\n"
          "  subscriber get SUPI | list | delete SUPI\n"
          "  policy get SUPI | delete SUPI | put SUPI FILE|-\n"
          "  session list | terminate SMPOLICYID\n",
          c->err);
    return RC_USAGE;
}

/* Identifiers go into URL paths: refuse anything that would need escaping. */
static bool safe_id(const char *s)
{
    if (s == NULL || *s == 0 || strlen(s) > 128)
        return false;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && strchr("._:-", *s) == NULL)
            return false;
    return true;
}

/* Perform one admin call. Prints the JSON answer (if any) to out; on an error status prints the problem body to err. */
static int call(ctl *c, const char *method, const char *base, const char *path, const g5c_json *body)
{
    char *url = g5c_xasprintf("%s%s", base, path), auth[512], errbuf[200];
    g5c_kv h = {"authorization", auth};
    g5c_resp r;
    char *bs = body ? g5c_json_to_string(body, NULL) : NULL;
    int rc, st;
    snprintf(auth, sizeof auth, "Bearer %s", c->token ? c->token : "");
    st = g5c_client_request(c->client, method, url, c->token ? &h : NULL, c->token ? 1 : 0, G5C_JSON_TYPE, bs, bs ? strlen(bs) : 0,
                            &r, errbuf, sizeof errbuf);
    free(url);
    free(bs);
    OPENSSL_cleanse(auth, sizeof auth);
    if (st != 0) {
        fprintf(c->err, "g5c-ctl: %s unreachable: %s\n", base, errbuf);
        return RC_NET;
    }
    if (r.status >= 200 && r.status < 300) {
        if (r.body_len > 0)
            fprintf(c->out, "%s\n", (const char *)r.body);
        else
            fprintf(c->out, "OK (%d)\n", r.status);
        rc = RC_OK;
    } else {
        fprintf(c->err, "g5c-ctl: HTTP %d%s%s\n", r.status, r.body_len ? ": " : "", r.body_len ? (const char *)r.body : "");
        rc = RC_HTTP;
    }
    g5c_resp_free(&r);
    return rc;
}

/* A JSON or YAML document from a file, or stdin when path is "-". */
static g5c_json *load_doc(ctl *c, const char *path)
{
    char *buf = NULL, e[160];
    size_t n = 0;
    g5c_json *j;
    if (strcmp(path, "-") == 0) {
        size_t cap = 0, got;
        char tmp[4096];
        while ((got = fread(tmp, 1, sizeof tmp, stdin)) > 0) {
            if (n + got > 1u << 20)
                break;
            if (n + got + 1 > cap) {
                cap = (n + got + 1) * 2;
                buf = realloc(buf, cap);
                if (buf == NULL)
                    return NULL;
            }
            memcpy(buf + n, tmp, got);
            n += got;
        }
        if (buf == NULL)
            buf = g5c_xstrdup("");
        else
            buf[n] = 0;
    } else {
        buf = g5c_read_file(path, 1u << 20, &n);
        if (buf == NULL) {
            fprintf(c->err, "g5c-ctl: cannot read %s\n", path);
            return NULL;
        }
    }
    j = g5c_json_parse(buf, n, e, sizeof e);
    if (j == NULL)
        j = g5c_yaml_parse(buf, n, e, sizeof e);
    if (j == NULL)
        fprintf(c->err, "g5c-ctl: %s: %s\n", path, e);
    free(buf);
    return j;
}

static int subscriber_add_flags(ctl *c, int argc, char **argv)
{
    g5c_json *b = g5c_json_new_obj(), *slices = g5c_json_new_arr(), *dnns = g5c_json_new_obj();
    int rc = RC_USAGE;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (v == NULL) {
            usage(c, "missing value after option");
            goto out;
        }
        if (strcmp(a, "--supi") == 0 || strcmp(a, "--k") == 0 || strcmp(a, "--op") == 0 || strcmp(a, "--opc") == 0 ||
            strcmp(a, "--amf") == 0 || strcmp(a, "--sqn") == 0) {
            g5c_json_set_str(b, a + 2, v);
        } else if (strcmp(a, "--slice") == 0) {
            char *end;
            long sst = strtol(v, &end, 10);
            g5c_json *s;
            if (end == v || sst < 0 || sst > 255 || (*end != 0 && *end != ':') || (*end == ':' && strlen(end + 1) != 6)) {
                usage(c, "--slice expects SST or SST:SD (SD = 6 hex digits)");
                goto out;
            }
            s = g5c_json_push(slices, g5c_json_new_obj());
            g5c_json_set_int(s, "sst", sst);
            if (*end == ':')
                g5c_json_set_str(s, "sd", end + 1);
        } else if (strcmp(a, "--dnn") == 0) {
            if (!safe_id(v)) {
                usage(c, "invalid --dnn");
                goto out;
            }
            g5c_json_set(dnns, v, g5c_json_new_obj());
        } else {
            usage(c, "unknown option for `subscriber add`");
            goto out;
        }
        i++;
    }
    if (g5c_json_get(b, "supi") == NULL || g5c_json_get(b, "k") == NULL ||
        (g5c_json_get(b, "op") == NULL) == (g5c_json_get(b, "opc") == NULL)) {
        usage(c, "`subscriber add` needs --supi, --k and exactly one of --op / --opc");
        goto out;
    }
    if (g5c_json_len(slices))
        g5c_json_set(b, "slices", g5c_json_dup(slices));
    if (g5c_json_len(dnns))
        g5c_json_set(b, "dnns", g5c_json_dup(dnns));
    rc = call(c, "POST", c->udm, "/admin/v1/subscribers", b);
out:
    g5c_json_free(b);
    g5c_json_free(slices);
    g5c_json_free(dnns);
    return rc;
}

static int cmd_subscriber(ctl *c, int argc, char **argv)
{
    char *path;
    int rc;
    if (argc < 1)
        return usage(c, "subscriber: command required");
    if (strcmp(argv[0], "add") == 0) {
        if (argc == 3 && strcmp(argv[1], "--json") == 0) {
            g5c_json *j = load_doc(c, argv[2]);
            if (j == NULL)
                return RC_USAGE;
            rc = call(c, "POST", c->udm, "/admin/v1/subscribers", j);
            g5c_json_free(j);
            return rc;
        }
        return subscriber_add_flags(c, argc - 1, argv + 1);
    }
    if (strcmp(argv[0], "list") == 0 && argc == 1)
        return call(c, "GET", c->udm, "/admin/v1/subscribers", NULL);
    if ((strcmp(argv[0], "get") == 0 || strcmp(argv[0], "delete") == 0) && argc == 2) {
        if (!safe_id(argv[1]))
            return usage(c, "invalid SUPI");
        path = g5c_xasprintf("/admin/v1/subscribers/%s", argv[1]);
        rc = call(c, argv[0][0] == 'g' ? "GET" : "DELETE", c->udm, path, NULL);
        free(path);
        return rc;
    }
    return usage(c, "unknown subscriber command");
}

static int cmd_policy(ctl *c, int argc, char **argv)
{
    char *path;
    int rc;
    if (argc < 2 || !safe_id(argv[1]))
        return usage(c, "policy: command and SUPI required");
    path = g5c_xasprintf("/admin/v1/policies/%s", argv[1]);
    if ((strcmp(argv[0], "get") == 0 || strcmp(argv[0], "delete") == 0) && argc == 2) {
        rc = call(c, argv[0][0] == 'g' ? "GET" : "DELETE", c->pcf, path, NULL);
    } else if (strcmp(argv[0], "put") == 0 && argc == 3) {
        g5c_json *j = load_doc(c, argv[2]);
        rc = j ? call(c, "PUT", c->pcf, path, j) : RC_USAGE;
        g5c_json_free(j);
    } else {
        rc = usage(c, "unknown policy command");
    }
    free(path);
    return rc;
}

static int cmd_session(ctl *c, int argc, char **argv)
{
    char *path;
    int rc;
    if (argc == 1 && strcmp(argv[0], "list") == 0)
        return call(c, "GET", c->pcf, "/admin/v1/sessions", NULL);
    if (argc == 2 && strcmp(argv[0], "terminate") == 0) {
        if (!safe_id(argv[1]))
            return usage(c, "invalid session id");
        path = g5c_xasprintf("/admin/v1/sessions/%s", argv[1]);
        rc = call(c, "DELETE", c->pcf, path, NULL);
        free(path);
        return rc;
    }
    return usage(c, "unknown session command");
}

int g5c_ctl_main(int argc, char **argv, FILE *out, FILE *err)
{
    ctl c = {getenv("G5C_UDM_URL") ? getenv("G5C_UDM_URL") : "http://127.0.0.1:7773",
             getenv("G5C_PCF_URL") ? getenv("G5C_PCF_URL") : "http://127.0.0.1:7777", NULL, out, err, NULL};
    const char *token_file = NULL;
    char ferr[200], tlserr[200];
    int i = 1, rc;
    for (; i + 1 < argc && strncmp(argv[i], "--", 2) == 0; i += 2) {
        if (strcmp(argv[i], "--udm") == 0)
            c.udm = argv[i + 1];
        else if (strcmp(argv[i], "--pcf") == 0)
            c.pcf = argv[i + 1];
        else if (strcmp(argv[i], "--token-file") == 0)
            token_file = argv[i + 1];
        else
            break;
    }
    if (i >= argc)
        return usage(&c, NULL);
    c.token = g5c_secret_from_env_or_file("G5C_ADMIN_TOKEN", token_file, ferr, sizeof ferr);
    if (c.token == NULL && ferr[0]) {
        fprintf(err, "g5c-ctl: %s\n", ferr);
        return RC_USAGE;
    }
    c.client = g5c_client_new_env(10000, tlserr, sizeof tlserr);
    if (c.client == NULL) {
        fprintf(err, "g5c-ctl: %s\n", tlserr);
        return RC_USAGE;
    }
    if (strcmp(argv[i], "subscriber") == 0)
        rc = cmd_subscriber(&c, argc - i - 1, argv + i + 1);
    else if (strcmp(argv[i], "policy") == 0)
        rc = cmd_policy(&c, argc - i - 1, argv + i + 1);
    else if (strcmp(argv[i], "session") == 0)
        rc = cmd_session(&c, argc - i - 1, argv + i + 1);
    else
        rc = usage(&c, "unknown command");
    g5c_client_free(c.client);
    if (c.token) {
        OPENSSL_cleanse(c.token, strlen(c.token));
        free(c.token);
    }
    return rc;
}
