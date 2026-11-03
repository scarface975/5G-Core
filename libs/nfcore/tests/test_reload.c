/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Configuration reload: a function started from a file reads it again. What is invalid changes nothing; what is valid is applied where the function can (overload, events, log.level and the sections it
 * registered), listed as restart-required where it cannot, undone as a whole when a later section fails, and undone when the function suffers after the change. Also over the admin endpoint. */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "g5c/nfcore.h"
#include "g5c/testkit.h"

static char dir[64], path[128], tokpath[128];

typedef struct {
    atomic_int alpha; /* read by the handler threads while a reload writes it */
    int beta;
    int alpha_calls, beta_calls;
    int refuse_beta; /* a beta equal to this is not acceptable */
} demo_t;

static demo_t demo = {.alpha = 1, .beta = 2};

static int hook_alpha(void *ctx, const g5c_json *from, const g5c_json *to, char *err, size_t cap)
{
    demo_t *d = ctx;
    int64_t v = 0;
    (void)from;
    (void)err;
    (void)cap;
    TK_ASSERT(to == NULL || g5c_json_int(to, &v));
    d->alpha = (int)v;
    d->alpha_calls++;
    return 0;
}

static int hook_beta(void *ctx, const g5c_json *from, const g5c_json *to, char *err, size_t cap)
{
    demo_t *d = ctx;
    int64_t v = 0;
    (void)from;
    TK_ASSERT(to == NULL || g5c_json_int(to, &v));
    if (d->refuse_beta != 0 && v == d->refuse_beta) {
        snprintf(err, cap, "beta %d is not acceptable", (int)v);
        return -1;
    }
    d->beta = (int)v;
    d->beta_calls++;
    return 0;
}

static void h_work(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    (void)ctx;
    (void)req;
    g5c_resp_status(resp, demo.alpha == 99 ? 500 : 200); /* alpha 99 is a change that breaks the function */
}

static void write_cfg(const char *extra)
{
    FILE *f = fopen(path, "w");
    TK_ASSERT(f != NULL);
    fprintf(f, "name: reload-test\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 7777 }\nreload: { token_file: %s, settle_ms: 400 }\n%s", tokpath, extra);
    fclose(f);
}

static g5c_nf *make_nf(const char *extra)
{
    char err[200];
    g5c_json *j;
    g5c_common c;
    g5c_nf *nf;
    write_cfg(extra);
    j = g5c_config_load(path, err, sizeof err); /* records the path for the reload */
    TK_ASSERT(j != NULL && g5c_common_parse(j, &c, err, sizeof err) == 0 && g5c_common_validate(&c, err, sizeof err) == 0);
    g5c_json_free(j);
    c.port = 0;
    free(c.address);
    c.address = g5c_xstrdup("127.0.0.1");
    nf = g5c_nf_new(&c, err, sizeof err);
    TK_ASSERT(nf != NULL);
    return nf;
}

static const char *result_of(const g5c_json *rep)
{
    return g5c_json_get_str(rep, "result");
}

static bool list_has(const g5c_json *rep, const char *key, const char *item)
{
    const g5c_json *l = g5c_json_get(rep, key);
    for (size_t i = 0; l != NULL && i < g5c_json_len(l); i++)
        if (strcmp(g5c_json_str(g5c_json_at(l, i)), item) == 0)
            return true;
    return false;
}

static int status_of(const char *base, const char *p)
{
    char url[160], err[100];
    g5c_client *c = g5c_client_new(2000, NULL); /* a client of its own: no back-off memory */
    g5c_resp r;
    int st;
    snprintf(url, sizeof url, "%s%s", base, p);
    st = g5c_client_get(c, url, &r, err, sizeof err) == 0 ? r.status : -1;
    if (st >= 0)
        g5c_resp_free(&r);
    g5c_client_free(c);
    return st;
}

typedef struct {
    const char *base;
    atomic_bool stop;
    atomic_int seen500;
} pump_t;

static void *pump(void *arg)
{
    pump_t *p = arg;
    while (!atomic_load(&p->stop)) {
        if (status_of(p->base, "/work") == 500)
            atomic_fetch_add(&p->seen500, 1);
        usleep(10000);
    }
    return NULL;
}

static g5c_json *http_reload(const char *base, const char *token, const char *method, const char *query, int *status)
{
    char url[200], err[100], auth[200];
    g5c_client *c = g5c_client_new(5000, NULL);
    g5c_kv h[1];
    g5c_resp r;
    g5c_json *j = NULL;
    snprintf(url, sizeof url, "%s/admin/v1/reload%s", base, query);
    snprintf(auth, sizeof auth, "Bearer %s", token != NULL ? token : "");
    h[0] = (g5c_kv){"authorization", auth};
    TK_ASSERT(g5c_client_request(c, method, url, token != NULL ? h : NULL, token != NULL ? 1 : 0, NULL, NULL, 0, &r, err, sizeof err) == 0);
    *status = r.status;
    j = g5c_resp_parse_json(&r);
    g5c_resp_free(&r);
    g5c_client_free(c);
    return j;
}

int main(void)
{
    g5c_nf *nf;
    g5c_router *routes = g5c_router_new();
    g5c_nrf_reg reg = {"UDM", NULL, 0, NULL};
    g5c_nf_inst *run;
    g5c_json *rep;
    char err[200], base[64];
    FILE *tf;
    int st;
    const char *token = "reload-token-0123456789";
    snprintf(dir, sizeof dir, "/tmp/g5c-reload-XXXXXX");
    TK_ASSERT(mkdtemp(dir) != NULL);
    snprintf(path, sizeof path, "%s/cfg.yaml", dir);
    snprintf(tokpath, sizeof tokpath, "%s/token", dir);
    tf = fopen(tokpath, "w");
    TK_ASSERT(tf != NULL);
    fprintf(tf, "%s\n", token);
    fclose(tf);
    chmod(tokpath, 0600);

    nf = make_nf("demo: { alpha: 1, beta: 2 }\n");
    g5c_nf_on_reload(nf, "demo.alpha", hook_alpha, &demo);
    g5c_nf_on_reload(nf, "demo.beta", hook_beta, &demo);
    g5c_router_route(routes, "GET", "/work", h_work, NULL);
    run = g5c_nf_start(nf, routes, &reg, err, sizeof err);
    TK_ASSERT(run != NULL);
    snprintf(base, sizeof base, "http://127.0.0.1:%u", g5c_nf_inst_port(run));

    /* nothing changed */
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "unchanged") == 0 && g5c_json_len(g5c_json_get(rep, "applied")) == 0);
    g5c_json_free(rep);

    /* overload is off: a dry run says what would happen and does nothing */
    write_cfg("demo: { alpha: 1, beta: 2 }\noverload: { rate_per_source: 5, burst: 5 }\n");
    rep = g5c_nf_reload(nf, true);
    TK_ASSERT(strcmp(result_of(rep), "dry-run") == 0 && list_has(rep, "applied", "overload"));
    g5c_json_free(rep);
    for (int i = 0; i < 20; i++)
        TK_ASSERT(status_of(base, "/work") == 200);
    /* ... and for real: the limit is in force at once, without a restart */
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "applied") == 0 && list_has(rep, "applied", "overload"));
    g5c_json_free(rep);
    {
        int ok = 0, limited = 0;
        for (int i = 0; i < 20; i++) {
            st = status_of(base, "/work");
            if (st == 200)
                ok++;
            else if (st == 429)
                limited++;
        }
        TK_ASSERT(ok >= 4 && ok <= 7 && limited >= 12);
    }
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "unchanged") == 0); /* the baseline moved on */
    g5c_json_free(rep);
    write_cfg("demo: { alpha: 1, beta: 2 }\n"); /* off again */
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "applied") == 0);
    g5c_json_free(rep);
    usleep(300000);
    for (int i = 0; i < 20; i++)
        TK_ASSERT(status_of(base, "/work") == 200);

    /* two keys of one section, applied in order */
    write_cfg("demo: { alpha: 5, beta: 6 }\n");
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "applied") == 0 && list_has(rep, "applied", "demo.alpha") && list_has(rep, "applied", "demo.beta"));
    TK_ASSERT(demo.alpha == 5 && demo.beta == 6);
    g5c_json_free(rep);

    /* a key nobody can change live, and a section that needs the restart: listed, not applied, and listed again next time */
    write_cfg("demo: { alpha: 5, beta: 6, gamma: 7 }\n");
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "restart-required") == 0 && list_has(rep, "restartRequired", "demo.gamma") && g5c_json_len(g5c_json_get(rep, "applied")) == 0);
    g5c_json_free(rep);
    write_cfg("demo: { alpha: 8, beta: 6, gamma: 7 }\nsbi: { address: 127.0.0.1, port: 7778 }\n");
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "applied") == 0 && list_has(rep, "applied", "demo.alpha") && list_has(rep, "restartRequired", "demo.gamma") && list_has(rep, "restartRequired", "sbi"));
    TK_ASSERT(demo.alpha == 8);
    g5c_json_free(rep);

    /* what is invalid changes nothing */
    {
        static const char *const bad[] = {
            "demo: { alpha: 9, beta: 6 }\noverload: { rate_per_source: -3 }\n",
            "demo: { alpha: 9, beta: 6 }\nevents: { syslog: { host: h, proto: tls } }\n",
            "demo: { alpha: 9\n",
        };
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
            write_cfg(bad[i]);
            rep = g5c_nf_reload(nf, false);
            TK_ASSERT(strcmp(result_of(rep), "rejected") == 0 && g5c_json_get_str(rep, "error") != NULL && demo.alpha == 8);
            g5c_json_free(rep);
        }
    }
    TK_ASSERT(unlink(path) == 0); /* the file is gone */
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "rejected") == 0 && demo.alpha == 8);
    g5c_json_free(rep);

    /* a later section fails: the earlier one is put back (its function is called the other way round) */
    demo.refuse_beta = 77;
    {
        int before = demo.alpha_calls;
        write_cfg("demo: { alpha: 11, beta: 77, gamma: 7 }\n");
        rep = g5c_nf_reload(nf, false);
        TK_ASSERT(strcmp(result_of(rep), "rolled-back") == 0 && strcmp(g5c_json_get_str(rep, "failedSection"), "demo.beta") == 0);
        TK_ASSERT(strstr(g5c_json_get_str(rep, "error"), "not acceptable") != NULL);
        TK_ASSERT(demo.alpha == 8 && demo.beta == 6 && demo.alpha_calls == before + 2); /* applied, then undone */
        g5c_json_free(rep);
    }
    demo.refuse_beta = 0;

    /* a change that breaks the function is taken back by itself */
    {
        pump_t p = {.base = base};
        pthread_t th;
        atomic_init(&p.stop, false);
        atomic_init(&p.seen500, 0);
        TK_ASSERT(pthread_create(&th, NULL, pump, &p) == 0);
        write_cfg("demo: { alpha: 99, beta: 6, gamma: 7 }\n");
        rep = g5c_nf_reload(nf, false);
        atomic_store(&p.stop, true);
        pthread_join(th, NULL);
        TK_ASSERT(atomic_load(&p.seen500) >= 3);
        TK_ASSERT(strcmp(result_of(rep), "rolled-back") == 0 && strstr(g5c_json_get_str(rep, "error"), "server errors") != NULL);
        TK_ASSERT(demo.alpha == 8);
        g5c_json_free(rep);
        TK_ASSERT(status_of(base, "/work") == 200);
    }
    /* a change that does no harm is kept after the same watch */
    write_cfg("demo: { alpha: 12, beta: 6, gamma: 7 }\n");
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "applied") == 0 && demo.alpha == 12);
    g5c_json_free(rep);

    /* the log level, live */
    write_cfg("demo: { alpha: 12, beta: 6, gamma: 7 }\nlog: { level: debug }\n");
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "applied") == 0 && list_has(rep, "applied", "log.level") && g5c_log_enabled(G5C_LOG_DEBUG));
    g5c_json_free(rep);
    write_cfg("demo: { alpha: 12, beta: 6, gamma: 7 }\nlog: { level: warn }\n");
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "applied") == 0 && !g5c_log_enabled(G5C_LOG_INFO));
    g5c_json_free(rep);
    write_cfg("demo: { alpha: 12, beta: 6, gamma: 7 }\nlog: { level: info, json: true }\n");
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(list_has(rep, "applied", "log.level") && list_has(rep, "restartRequired", "log.json") && g5c_log_enabled(G5C_LOG_INFO));
    g5c_json_free(rep);

    /* event streaming switched on and off while the function runs */
    TK_ASSERT(nf->events == NULL);
    write_cfg("demo: { alpha: 12, beta: 6, gamma: 7 }\nlog: { level: info, json: true }\nevents: { syslog: { host: 127.0.0.1, port: 9, proto: udp } }\n");
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "applied") == 0 && list_has(rep, "applied", "events") && nf->events != NULL);
    g5c_json_free(rep);
    write_cfg("demo: { alpha: 12, beta: 6, gamma: 7 }\nlog: { level: info, json: true }\n");
    rep = g5c_nf_reload(nf, false);
    TK_ASSERT(strcmp(result_of(rep), "applied") == 0 && nf->events == NULL);
    g5c_json_free(rep);

    /* the admin endpoint: a token, a dry run, the real thing, the last report */
    write_cfg("demo: { alpha: 20, beta: 6, gamma: 7 }\nlog: { level: info, json: true }\n");
    rep = http_reload(base, NULL, "POST", "", &st);
    TK_ASSERT(st == 401);
    g5c_json_free(rep);
    rep = http_reload(base, "wrong-token-wrong-token", "POST", "", &st);
    TK_ASSERT(st == 401 && demo.alpha == 12);
    g5c_json_free(rep);
    rep = http_reload(base, token, "POST", "?dry-run=true", &st);
    TK_ASSERT(st == 200 && strcmp(result_of(rep), "dry-run") == 0 && demo.alpha == 12);
    g5c_json_free(rep);
    rep = http_reload(base, token, "POST", "", &st);
    TK_ASSERT(st == 200 && strcmp(result_of(rep), "applied") == 0 && demo.alpha == 20);
    g5c_json_free(rep);
    rep = http_reload(base, token, "GET", "", &st);
    TK_ASSERT(st == 200 && strcmp(result_of(rep), "applied") == 0 && list_has(rep, "applied", "demo.alpha"));
    g5c_json_free(rep);
    write_cfg("demo: { alpha: 20, beta: 6, gamma: 7 }\noverload: { rate_per_source: 0 }\n");
    rep = http_reload(base, token, "POST", "", &st);
    TK_ASSERT(st == 400 && strcmp(result_of(rep), "rejected") == 0); /* a refusal is a 400 */
    g5c_json_free(rep);
    demo.refuse_beta = 31;
    write_cfg("demo: { alpha: 21, beta: 31, gamma: 7 }\n");
    rep = http_reload(base, token, "POST", "", &st);
    TK_ASSERT(st == 409 && strcmp(result_of(rep), "rolled-back") == 0 && demo.alpha == 20); /* a rollback is a 409 */
    g5c_json_free(rep);

    {   /* the counters */
        g5c_label l[1] = {{"result", "applied"}};
        TK_ASSERT(g5c_counter_value(g5c_counter_get(nf->metrics, "g5c_config_reloads_total", "x", l, 1)) >= 8);
    }
    g5c_nf_stop(run);
    g5c_nf_free(nf);
    unlink(tokpath);
    rmdir(dir);
    printf("reload: PASS\n");
    return 0;
}
