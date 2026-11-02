/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Soak and failure-injection test for the Phase 1-2 core (strategy 4.1, non-functional layer).
 *
 * UDM + PCF + udr run in one process; worker threads drive a mixed workload (authentication vectors, SDM reads,
 * UECM registrations, SDM subscriptions, SM and AM policy lifecycles, admin reads). A fault injector repeatedly stops and
 * restarts the UDR on the same port. Pass criteria:
 *   - no response outside {expected status, 503/transport error while the UDR is down} (never a 500, never a hang),
 *   - the first request after each restart succeeds without restarting the UDM or PCF (pooled connections recover),
 *   - no leaked policy sessions or associations,
 *   - RSS and open file descriptors do not keep growing (checked when the run is long enough to be meaningful).
 * G5C_SOAK_SECONDS sets the duration (default 8); G5C_SOAK_CHECK_MEM=0 disables the RSS/FD assertions (sanitizer builds). */
#define _DEFAULT_SOURCE
#include <dirent.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "g5c/pcf.h"
#include "g5c/testkit.h"
#include "g5c/udm.h"
#include "g5c/udr.h"

#define ADMIN "admin-token-0123456789"
#define SUBS 50
#define WORKERS 12
#define K_HEX "465b5ce8b199b49faa5f0a2ee238a6bc"
#define OP_HEX "cdc202d5123e20f62b6d676ac72cb318"
#define SNN "5G:mnc001.mcc001.3gppnetwork.org"

static atomic_int udr_down;            /* 1 while the injector has the UDR stopped (plus a short grace period) */
static atomic_bool stop_flag;
static atomic_long n_ok, n_expected_outage, n_bad;
static g5c_client *cl;
static char udm_base[64], pcf_base[64];

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static long rss_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[128];
    long v = -1;
    if (f == NULL)
        return -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "VmRSS: %ld kB", &v) == 1)
            break;
    fclose(f);
    return v;
}

static int open_fds(void)
{
    DIR *d = opendir("/proc/self/fd");
    int n = 0;
    if (d == NULL)
        return -1;
    while (readdir(d) != NULL)
        n++;
    closedir(d);
    return n - 3; /* ".", "..", and the directory handle itself */
}

/* One request; returns the HTTP status or -1 on a transport failure. */
static int call(const char *method, const char *base, const char *path, const char *body, bool admin, g5c_json **out, char **loc)
{
    char *url = g5c_xasprintf("%s%s", base, path), auth[64], err[128];
    g5c_kv hdr = {"authorization", auth};
    g5c_resp r;
    int st;
    snprintf(auth, sizeof auth, "Bearer %s", ADMIN);
    if (g5c_client_request(cl, method, url, admin ? &hdr : NULL, admin ? 1 : 0, G5C_JSON_TYPE, body, body ? strlen(body) : 0, &r, err,
                           sizeof err) != 0) {
        free(url);
        if (out)
            *out = NULL;
        if (loc)
            *loc = NULL;
        return -1;
    }
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

/* classify: `want` is the healthy status; 503 or a transport failure is tolerated only while the UDR is down */
static void judge(const char *what, int st, int want)
{
    if (st == want) {
        atomic_fetch_add(&n_ok, 1);
    } else if ((st == 503 || st == -1) && atomic_load(&udr_down)) {
        atomic_fetch_add(&n_expected_outage, 1);
    } else {
        atomic_fetch_add(&n_bad, 1);
        fprintf(stderr, "soak: unexpected status %d from %s (wanted %d, udr_down=%d)\n", st, what, want, atomic_load(&udr_down));
    }
}

static char *sm_body(int n)
{
    return g5c_xasprintf("{\"supi\":\"imsi-0010100000%05d\",\"pduSessionId\":%d,\"pduSessionType\":\"IPV4\",\"dnn\":\"internet\","
                         "\"notificationUri\":\"http://127.0.0.1:1/nsmf/%d\",\"sliceInfo\":{\"sst\":1},\"accessType\":\"3GPP_ACCESS\","
                         "\"ratType\":\"NR\",\"subsSessAmbr\":{\"uplink\":\"100 Mbps\",\"downlink\":\"200 Mbps\"},"
                         "\"subsDefQos\":{\"5qi\":9,\"arp\":{\"priorityLevel\":8,\"preemptCap\":\"NOT_PREEMPT\",\"preemptVuln\":\"NOT_PREEMPTABLE\"},\"priorityLevel\":80},"
                         "\"servingNetwork\":{\"mcc\":\"001\",\"mnc\":\"01\"}}",
                         n % SUBS, 1 + n % 15, n);
}

static void *worker(void *arg)
{
    tk_rng rng = {0x9e3779b97f4a7c15ULL + (uint64_t)(uintptr_t)arg * 7919u};
    long iter = 0;
    while (!atomic_load(&stop_flag)) {
        unsigned op = (unsigned)(tk_rng_next(&rng) % 8);
        int sub = (int)(tk_rng_next(&rng) % SUBS);
        char path[256], supi[40], *body, *loc = NULL;
        g5c_json *v = NULL;
        int st;
        iter++;
        snprintf(supi, sizeof supi, "imsi-0010100000%05d", sub);
        switch (op) {
        case 0:
        case 1: /* the hot path: authentication vectors */
            snprintf(path, sizeof path, "/nudm-ueau/v1/%s/security-information/generate-auth-data", supi);
            st = call("POST", udm_base, path, "{\"servingNetworkName\":\"" SNN "\"}", false, &v, NULL);
            judge("generate-auth-data", st, 200);
            g5c_json_free(v);
            break;
        case 2:
            snprintf(path, sizeof path, "/nudm-sdm/v2/%s/nssai", supi);
            judge("sdm nssai", call("GET", udm_base, path, NULL, false, &v, NULL), 200);
            g5c_json_free(v);
            break;
        case 3: /* UECM registration (201 first time, 200 on refresh: both healthy) */
            snprintf(path, sizeof path, "/nudm-uecm/v1/%s/registrations/amf-3gpp-access", supi);
            body = g5c_xasprintf("{\"amfInstanceId\":\"amf-%ld\",\"deregCallbackUri\":\"http://127.0.0.1:1/dereg\","
                                 "\"guami\":{\"plmnId\":{\"mcc\":\"001\",\"mnc\":\"01\"},\"amfId\":\"020040\"},\"ratType\":\"NR\"}",
                                 iter % 3);
            st = call("PUT", udm_base, path, body, false, &v, NULL);
            judge("uecm amf put", st == 201 ? 200 : st, 200);
            g5c_json_free(v);
            free(body);
            break;
        case 4: { /* SDM subscription create + delete */
            char *sbody = g5c_xasprintf("{\"nfInstanceId\":\"amf-s\",\"callbackReference\":\"http://127.0.0.1:1/cb\"}");
            snprintf(path, sizeof path, "/nudm-sdm/v2/%s/sdm-subscriptions", supi);
            st = call("POST", udm_base, path, sbody, false, &v, &loc);
            judge("sdm subscription", st, 201);
            if (st == 201 && loc != NULL) {
                const char *p = strstr(loc, "/nudm-sdm/");
                if (p != NULL)
                    judge("sdm subscription delete", call("DELETE", udm_base, p, NULL, false, NULL, NULL), 204);
            }
            free(loc);
            g5c_json_free(v);
            free(sbody);
            break;
        }
        case 5: { /* SM policy: create, update, delete */
            int n = (int)(iter % 1000000);
            body = sm_body(n + sub);
            st = call("POST", pcf_base, "/npcf-smpolicycontrol/v1/sm-policies", body, false, &v, &loc);
            judge("sm policy create", st, 201);
            g5c_json_free(v);
            free(body);
            if (st == 201 && loc != NULL) {
                const char *p = strstr(loc, "/npcf-smpolicycontrol/");
                char up[300], dl[300];
                if (p != NULL) {
                    snprintf(up, sizeof up, "%s/update", p);
                    snprintf(dl, sizeof dl, "%s/delete", p);
                    judge("sm policy update", call("POST", pcf_base, up, "{}", false, &v, NULL), 200);
                    g5c_json_free(v);
                    judge("sm policy delete", call("POST", pcf_base, dl, "{}", false, NULL, NULL), 204);
                }
            }
            free(loc);
            break;
        }
        case 6: { /* AM policy: create, delete */
            char *ab = g5c_xasprintf("{\"notificationUri\":\"http://127.0.0.1:1/am\",\"supi\":\"%s\",\"suppFeat\":\"\"}", supi);
            st = call("POST", pcf_base, "/npcf-am-policy-control/v1/policies", ab, false, &v, &loc);
            judge("am policy create", st, 201);
            g5c_json_free(v);
            free(ab);
            if (st == 201 && loc != NULL) {
                const char *p = strstr(loc, "/npcf-am-policy-control/");
                if (p != NULL)
                    judge("am policy delete", call("DELETE", pcf_base, p, NULL, false, NULL, NULL), 204);
            }
            free(loc);
            break;
        }
        default: /* admin read */
            snprintf(path, sizeof path, "/admin/v1/subscribers/%s", supi);
            judge("admin get", call("GET", udm_base, path, NULL, true, &v, NULL), 200);
            g5c_json_free(v);
            break;
        }
    }
    return NULL;
}

int main(void)
{
    g5c_server_cfg cfg = {"127.0.0.1", 0, NULL};
    char err[160], udr_url[64];
    double seconds = getenv("G5C_SOAK_SECONDS") ? atof(getenv("G5C_SOAK_SECONDS")) : 8.0, t0, warm_t;
    bool check_mem = !(getenv("G5C_SOAK_CHECK_MEM") && strcmp(getenv("G5C_SOAK_CHECK_MEM"), "0") == 0);
    g5c_registry *m = g5c_registry_new();
    g5c_udr_store *store = g5c_udr_store_memory();
    g5c_router *udr_r = g5c_udr_router(store), *udm_r, *pcf_r;
    g5c_server *udr_s, *udm_s, *pcf_s;
    udm_keys keys;
    uint8_t master[32];
    udm u;
    pcf p;
    pcf_policy pol;
    g5c_json *py;
    pthread_t th[WORKERS];
    long rss_warm = 0, rss_end = 0;
    int fd_warm = 0, fd_end = 0, outages = 0, recoveries = 0;
    uint16_t udr_port;

    g5c_log_init("error", false);
    udr_s = g5c_server_start(&cfg, udr_r, err, sizeof err);
    TK_ASSERT(udr_s != NULL);
    udr_port = g5c_server_port(udr_s);
    snprintf(udr_url, sizeof udr_url, "http://127.0.0.1:%u", udr_port);
    cl = g5c_client_new(3000, NULL);
    memset(master, 7, sizeof master);
    udm_keys_with_master(&keys, master);
    udm_init(&u, cl, udr_url, &keys, NULL, 0, "00101", "udm-soak", m);
    u.admin_token = g5c_xstrdup(ADMIN);
    udm_r = udm_router(&u);
    udm_s = g5c_server_start(&cfg, udm_r, err, sizeof err);
    TK_ASSERT(udm_s != NULL);
    snprintf(udm_base, sizeof udm_base, "http://127.0.0.1:%u", g5c_server_port(udm_s));
    py = g5c_yaml_parse("default: {}\n", 12, err, sizeof err);
    TK_ASSERT(py != NULL && pcf_policy_parse(py, true, &pol, err, sizeof err) == 0);
    g5c_json_free(py);
    pcf_init(&p, &pol, cl, udr_url, m);
    p.admin_token = g5c_xstrdup(ADMIN);
    pcf_r = pcf_router(&p);
    pcf_s = g5c_server_start(&cfg, pcf_r, err, sizeof err);
    TK_ASSERT(pcf_s != NULL);
    snprintf(pcf_base, sizeof pcf_base, "http://127.0.0.1:%u", g5c_server_port(pcf_s));

    for (int i = 0; i < SUBS; i++) {
        char body[256];
        snprintf(body, sizeof body, "{\"supi\":\"imsi-0010100000%05d\",\"k\":\"" K_HEX "\",\"op\":\"" OP_HEX "\"}", i);
        TK_ASSERT(call("POST", udm_base, "/admin/v1/subscribers", body, true, NULL, NULL) == 201);
    }

    for (long i = 0; i < WORKERS; i++)
        TK_ASSERT(pthread_create(&th[i], NULL, worker, (void *)(uintptr_t)(i + 1)) == 0);
    t0 = now_s();
    warm_t = t0 + (seconds >= 6.0 ? 2.0 : 0.0);
    {   /* main thread is the fault injector: it owns the UDR server handle */
        bool warmed = false;
        double next_outage = t0 + 2.5;
        while (now_s() - t0 < seconds) {
            usleep(50000);
            if (!warmed && now_s() >= warm_t) {
                warmed = true;
                rss_warm = rss_kb();
                fd_warm = open_fds();
            }
            if (seconds >= 4.0 && now_s() >= next_outage && now_s() - t0 < seconds - 1.5) {
                g5c_json *v = NULL;
                int st;
                atomic_store(&udr_down, 1);
                g5c_server_stop(udr_s);
                udr_s = NULL;
                outages++;
                usleep(400000); /* long enough for in-flight and new requests to hit the dead UDR */
                {
                    g5c_server_cfg again = {"127.0.0.1", udr_port, NULL};
                    for (int tries = 0; tries < 50 && udr_s == NULL; tries++) {
                        udr_s = g5c_server_start(&again, udr_r, err, sizeof err);
                        if (udr_s == NULL)
                            usleep(100000);
                    }
                }
                TK_ASSERT(udr_s != NULL);
                /* recovery: the very next authentication request must work, with no restart of the UDM */
                st = call("POST", udm_base, "/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data",
                          "{\"servingNetworkName\":\"" SNN "\"}", false, &v, NULL);
                if (st == 200)
                    recoveries++;
                else
                    fprintf(stderr, "soak: first request after UDR restart returned %d\n", st);
                g5c_json_free(v);
                usleep(300000); /* grace period for requests that were already in flight */
                atomic_store(&udr_down, 0);
                next_outage = now_s() + 2.0;
            }
        }
    }
    atomic_store(&stop_flag, true);
    for (int i = 0; i < WORKERS; i++)
        pthread_join(th[i], NULL);
    usleep(200000);
    rss_end = rss_kb();
    fd_end = open_fds();

    printf("soak: %.1fs, %ld ok, %ld tolerated during %d UDR outages (%d clean recoveries), %ld unexpected\n", seconds, atomic_load(&n_ok),
           atomic_load(&n_expected_outage), outages, recoveries, atomic_load(&n_bad));
    printf("soak: RSS %ld kB -> %ld kB, open fds %d -> %d, policy sessions left %zu\n", rss_warm, rss_end, fd_warm, fd_end,
           pcf_session_count(&p));
    TK_ASSERT(atomic_load(&n_bad) == 0);
    TK_ASSERT(atomic_load(&n_ok) > 100);
    TK_ASSERT(recoveries == outages);
    TK_ASSERT(pcf_session_count(&p) == 0);
    if (check_mem && seconds >= 6.0 && rss_warm > 0) {
        TK_ASSERT(rss_end < rss_warm + rss_warm / 4 + 16384); /* < 25% + 16 MiB growth after warm-up */
        TK_ASSERT(fd_end <= fd_warm + 8);
    }

    g5c_server_stop(pcf_s);
    g5c_server_stop(udm_s);
    g5c_server_stop(udr_s);
    g5c_client_free(cl);
    g5c_router_free(pcf_r);
    g5c_router_free(udm_r);
    g5c_router_free(udr_r);
    pcf_destroy(&p);
    udm_destroy(&u);
    g5c_udr_store_free(store);
    g5c_registry_free(m);
    puts("soak: ok");
    return 0;
}
