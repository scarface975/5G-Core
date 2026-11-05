/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* g5c-policy-eval: what the PCF's policy would decide for a session, from a configuration file, without a running function (backlog G-02).
 *
 *   g5c-policy-eval pcf.yaml supi=imsi-001010000000001 dnn=iot sst=1 [sd=000001] [qi5=9]
 *
 * Checks the whole `policy` section as the PCF does at start (syntax of every condition, limits, bit rates), then names the policy script whose condition holds for the session (the first one)
 * and prints the session AMBR and default QoS that result. Exit 0 with the result on stdout (JSON; a session that matches no script is still 0), 2 when the policy is invalid. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/base.h"
#include "g5c/config.h"
#include "g5c/json.h"
#include "g5c/pcf.h"

int main(int argc, char **argv)
{
    char err[400], field[200], reason[200];
    g5c_json *root, *out;
    pcf_policy pol, sub;
    g5c_json *subdoc = g5c_json_new_obj();
    g5c_json *groups = g5c_json_set(subdoc, "groups", g5c_json_new_arr());
    int rc = 0;
    pcf_session_info s;
    pcf_resolved r;
    int m;
    char *txt;
    if (argc < 2) {
        fprintf(stderr, "usage: %s config.yaml [supi=...] [dnn=...] [sst=N] [sd=hhhhhh] [qi5=N] [group=name ...]\n", argv[0]);
        g5c_json_free(subdoc);
        return 2;
    }
    root = g5c_config_load(argv[1], err, sizeof err);
    if (root == NULL) {
        fprintf(stderr, "%s: %s\n", argv[1], err);
        g5c_json_free(subdoc);
        return 2;
    }
    if (pcf_policy_parse(g5c_json_get(root, "policy"), true, &pol, err, sizeof err) != 0) {
        fprintf(stderr, "policy: %s\n", err);
        g5c_json_free(root);
        g5c_json_free(subdoc);
        return 2;
    }
    if (pcf_policy_validate(&pol, true, field, sizeof field, reason, sizeof reason) != 0) {
        fprintf(stderr, "policy: %s: %s\n", field, reason);
        pcf_policy_free(&pol);
        g5c_json_free(root);
        g5c_json_free(subdoc);
        return 2;
    }
    memset(&s, 0, sizeof s);
    memset(&sub, 0, sizeof sub);
    s.supi = g5c_xstrdup("");
    s.dnn = g5c_xstrdup("internet");
    s.sst = 1;
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i], *eq = strchr(a, '=');
        if (eq == NULL) {
            fprintf(stderr, "argument `%s` is not key=value\n", a);
            rc = 2;
            goto done;
        }
        if (strncmp(a, "supi=", 5) == 0) {
            free(s.supi);
            s.supi = g5c_xstrdup(eq + 1);
        } else if (strncmp(a, "dnn=", 4) == 0) {
            free(s.dnn);
            s.dnn = g5c_xstrdup(eq + 1);
        } else if (strncmp(a, "sd=", 3) == 0) {
            s.sd = g5c_xstrdup(eq + 1);
        } else if (strncmp(a, "sst=", 4) == 0) {
            s.sst = atoi(eq + 1);
        } else if (strncmp(a, "group=", 6) == 0) {
            g5c_json_push_str(groups, eq + 1);
        } else if (strncmp(a, "qi5=", 4) == 0) {
            s.subs_def_qos = g5c_json_new_obj();
            g5c_json_set_int(s.subs_def_qos, "5qi", atoi(eq + 1));
        } else {
            fprintf(stderr, "unknown key in `%s` (supi, dnn, sst, sd, qi5, group)\n", a);
            rc = 2;
            goto done;
        }
    }
    if (pcf_policy_parse(subdoc, false, &sub, err, sizeof err) != 0) {
        fprintf(stderr, "group: %s\n", err);
        rc = 2;
        goto done;
    }
    m = pcf_policy_match_script(&pol, &s, &sub);
    r = pcf_resolve(&s, &pol, &sub);
    out = g5c_json_new_obj();
    g5c_json_set_int(out, "scripts", (int64_t)pol.nscripts);
    g5c_json_set(out, "matched", m >= 0 ? g5c_json_new_int(m) : g5c_json_new_null());
    if (m >= 0)
        g5c_json_set_str(out, "when", pol.scripts[m].when);
    if (r.ambr.uplink != NULL) {
        g5c_json *a = g5c_json_set(out, "session_ambr", g5c_json_new_obj());
        g5c_json_set_str(a, "uplink", r.ambr.uplink);
        g5c_json_set_str(a, "downlink", r.ambr.downlink);
    }
    g5c_json_set_int(g5c_json_set(out, "default_qos", g5c_json_new_obj()), "qi5", r.qos.qi5);
    txt = g5c_json_to_string(out, NULL);
    printf("%s\n", txt);
    free(txt);
    g5c_json_free(out);
    pcf_resolved_free(&r);
done:
    pcf_session_info_free(&s);
    pcf_policy_free(&sub);
    g5c_json_free(subdoc);
    pcf_policy_free(&pol);
    g5c_json_free(root);
    return rc;
}
