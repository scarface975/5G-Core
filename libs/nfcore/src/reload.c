/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _GNU_SOURCE
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "g5c/base.h"
#include "g5c/nfcore.h"

#define MAX_HOOKS 16
#define MAX_STEPS 32
#define ERRORS_TO_ROLL_BACK 3 /* 5xx answers during the settle time: fewer is a dependency having a bad moment, not the change */

typedef struct {
    char *path; /* "section" or "section.key" */
    g5c_reload_fn fn;
    void *ctx;
} hook_t;

struct g5c_reload {
    pthread_mutex_t mu;
    hook_t hooks[MAX_HOOKS];
    size_t nhooks;
    char *path;          /* the file the function was started from */
    g5c_json *root;      /* what is in force */
    g5c_json *last;      /* the report of the last reload */
    char *token;         /* POST /admin/v1/reload */
};

typedef enum { S_HOOK, S_OVERLOAD, S_EVENTS, S_LOG } step_kind;

typedef struct {
    step_kind kind;
    char label[80];
    g5c_json *from, *to; /* subtrees (owned copies, may be NULL) */
    hook_t *hook;
    bool applied;
} step_t;

static const char *const RESTART_ONLY[] = {"name", "plmn", "sbi", "nrf", "oauth2", "scp_client", "reload", NULL};

/* ---- helpers ---- */

static g5c_json *at_path(const g5c_json *root, const char *path)
{
    const char *dot = strchr(path, '.');
    if (dot == NULL)
        return (g5c_json *)(uintptr_t)g5c_json_get(root, path);
    {
        char head[64];
        size_t n = (size_t)(dot - path);
        const g5c_json *sec;
        if (n >= sizeof head)
            return NULL;
        memcpy(head, path, n);
        head[n] = 0;
        sec = g5c_json_get(root, head);
        return sec != NULL && g5c_json_is(sec, G5C_J_OBJECT) ? (g5c_json *)(uintptr_t)g5c_json_get(sec, dot + 1) : NULL;
    }
}

static bool same(const g5c_json *a, const g5c_json *b)
{
    if (a == NULL || b == NULL)
        return a == b;
    return g5c_json_equal(a, b);
}

static bool in_list(const char *const *l, const char *s)
{
    for (; *l != NULL; l++)
        if (strcmp(*l, s) == 0)
            return true;
    return false;
}

static void add_str(g5c_json *arr, const char *s)
{
    g5c_json_push_str(arr, s);
}

static int level_of(const char *s)
{
    if (s == NULL)
        return G5C_LOG_INFO;
    if (strcasecmp(s, "error") == 0)
        return G5C_LOG_ERROR;
    if (strcasecmp(s, "warn") == 0)
        return G5C_LOG_WARN;
    if (strcasecmp(s, "debug") == 0)
        return G5C_LOG_DEBUG;
    if (strcasecmp(s, "trace") == 0)
        return G5C_LOG_TRACE;
    return G5C_LOG_INFO;
}

static void free_events_cfg(g5c_events_cfg *e)
{
    free(e->syslog_host);
    free(e->syslog_proto);
    free(e->syslog_ca);
    free(e->http_uri);
    free(e->http_ca);
    memset(e, 0, sizeof *e);
}

/* ---- the steps that the core applies itself ---- */

typedef struct {
    g5c_common nc; /* the new configuration, parsed and validated */
    g5c_events_cfg old_events;
    g5c_overload_cfg old_overload;
    int old_level;
    char *old_log_level; /* the setting before a log step, until it is kept or put back */
    bool have_old_events;
} core_t;

static int apply_overload(g5c_nf *nf, core_t *c)
{
    c->old_overload = nf->common.overload;
    nf->common.overload = c->nc.overload;
    g5c_overload_reconfigure(nf->overload, &nf->common.overload);
    return 0;
}

static void revert_overload(g5c_nf *nf, core_t *c)
{
    nf->common.overload = c->old_overload;
    g5c_overload_reconfigure(nf->overload, &nf->common.overload);
}

static int start_events(g5c_nf *nf, char *err, size_t errcap)
{
    nf->events = NULL;
    if (!nf->common.events.enabled)
        return 0;
    nf->events = g5c_events_start(&nf->common.events, nf->common.name, nf->instance_id, nf->metrics, err, errcap);
    return nf->events != NULL ? 0 : -1;
}

static int apply_events(g5c_nf *nf, core_t *c, char *err, size_t errcap)
{
    g5c_events_stop(nf->events);
    nf->events = NULL;
    c->old_events = nf->common.events;
    c->have_old_events = true;
    nf->common.events = c->nc.events;
    memset(&c->nc.events, 0, sizeof c->nc.events);
    if (start_events(nf, err, errcap) != 0) { /* the old stream comes back */
        free_events_cfg(&nf->common.events);
        nf->common.events = c->old_events;
        c->have_old_events = false;
        (void)start_events(nf, NULL, 0);
        return -1;
    }
    return 0;
}

static void revert_events(g5c_nf *nf, core_t *c)
{
    if (!c->have_old_events)
        return;
    g5c_events_stop(nf->events);
    nf->events = NULL;
    free_events_cfg(&nf->common.events);
    nf->common.events = c->old_events;
    c->have_old_events = false;
    (void)start_events(nf, NULL, 0);
}

static int apply_step(g5c_nf *nf, step_t *s, core_t *c, char *err, size_t errcap)
{
    switch (s->kind) {
    case S_OVERLOAD:
        return apply_overload(nf, c);
    case S_EVENTS:
        return apply_events(nf, c, err, errcap);
    case S_LOG:
        c->old_level = level_of(nf->common.log_level);
        g5c_log_set_level((g5c_log_level)level_of(c->nc.log_level));
        c->old_log_level = nf->common.log_level;
        nf->common.log_level = g5c_xstrdup(c->nc.log_level);
        return 0;
    case S_HOOK:
        return s->hook->fn(s->hook->ctx, s->from, s->to, err, errcap);
    }
    return -1;
}

static void revert_step(g5c_nf *nf, step_t *s, core_t *c)
{
    char err[200];
    switch (s->kind) {
    case S_OVERLOAD:
        revert_overload(nf, c);
        break;
    case S_EVENTS:
        revert_events(nf, c);
        break;
    case S_LOG:
        g5c_log_set_level((g5c_log_level)c->old_level);
        free(nf->common.log_level);
        nf->common.log_level = c->old_log_level;
        c->old_log_level = NULL;
        break;
    case S_HOOK:
        (void)s->hook->fn(s->hook->ctx, s->to, s->from, err, sizeof err); /* the same function, the other way round */
        break;
    }
}

/* ---- the diff ---- */

typedef struct {
    step_t steps[MAX_STEPS];
    size_t n;
    g5c_json *restart; /* sections that changed and need a restart */
} plan_t;

static void add_step(plan_t *p, step_kind k, const char *label, const g5c_json *from, const g5c_json *to, hook_t *h)
{
    step_t *s;
    if (p->n >= MAX_STEPS)
        return;
    s = &p->steps[p->n++];
    memset(s, 0, sizeof *s);
    s->kind = k;
    snprintf(s->label, sizeof s->label, "%s", label);
    s->from = from != NULL ? g5c_json_dup(from) : NULL;
    s->to = to != NULL ? g5c_json_dup(to) : NULL;
    s->hook = h;
}

static hook_t *find_hook(struct g5c_reload *rl, const char *path)
{
    for (size_t i = 0; i < rl->nhooks; i++)
        if (strcmp(rl->hooks[i].path, path) == 0)
            return &rl->hooks[i];
    return NULL;
}

static bool has_hook_below(struct g5c_reload *rl, const char *key)
{
    size_t n = strlen(key);
    for (size_t i = 0; i < rl->nhooks; i++)
        if (strncmp(rl->hooks[i].path, key, n) == 0 && rl->hooks[i].path[n] == '.')
            return true;
    return false;
}

static void make_plan(struct g5c_reload *rl, const g5c_json *old, const g5c_json *neu, plan_t *p)
{
    const g5c_json *srcs[2] = {old, neu};
    p->n = 0;
    p->restart = g5c_json_new_arr();
    for (int s = 0; s < 2; s++) {
        for (size_t i = 0; i < g5c_json_len(srcs[s]); i++) {
            const char *key = g5c_json_key_at(srcs[s], i);
            const g5c_json *o = g5c_json_get(old, key), *n = g5c_json_get(neu, key);
            bool seen = false;
            for (size_t k = 0; k < p->n && !seen; k++)
                seen = strcmp(p->steps[k].label, key) == 0;
            if (s == 1 && g5c_json_get(old, key) != NULL)
                continue; /* handled in the pass over the old keys */
            if (seen || same(o, n))
                continue;
            if (strcmp(key, "overload") == 0) {
                add_step(p, S_OVERLOAD, key, o, n, NULL);
            } else if (strcmp(key, "events") == 0) {
                add_step(p, S_EVENTS, key, o, n, NULL);
            } else if (strcmp(key, "log") == 0) {
                const char *lo = g5c_json_get_str(o, "level"), *ln = g5c_json_get_str(n, "level");
                bool jo = false, jn = false;
                (void)g5c_json_get_bool(o, "json", &jo);
                (void)g5c_json_get_bool(n, "json", &jn);
                if ((lo == NULL) != (ln == NULL) || (lo != NULL && strcmp(lo, ln) != 0))
                    add_step(p, S_LOG, "log.level", o, n, NULL);
                if (jo != jn)
                    add_str(p->restart, "log.json");
            } else if (in_list(RESTART_ONLY, key)) {
                add_str(p->restart, key);
            } else if (find_hook(rl, key) != NULL) {
                add_step(p, S_HOOK, key, o, n, find_hook(rl, key));
            } else if (has_hook_below(rl, key) && (o == NULL || g5c_json_is(o, G5C_J_OBJECT)) && (n == NULL || g5c_json_is(n, G5C_J_OBJECT))) {
                const g5c_json *both[2] = {o, n};
                for (int b = 0; b < 2; b++)
                    for (size_t j = 0; both[b] != NULL && j < g5c_json_len(both[b]); j++) {
                        const char *sub = g5c_json_key_at(both[b], j);
                        char path[128];
                        const g5c_json *so = o != NULL ? g5c_json_get(o, sub) : NULL, *sn = n != NULL ? g5c_json_get(n, sub) : NULL;
                        bool dup = false;
                        snprintf(path, sizeof path, "%s.%s", key, sub);
                        for (size_t k = 0; k < p->n && !dup; k++)
                            dup = strcmp(p->steps[k].label, path) == 0;
                        if (dup || same(so, sn))
                            continue;
                        if (find_hook(rl, path) != NULL) {
                            add_step(p, S_HOOK, path, so, sn, find_hook(rl, path));
                        } else {
                            bool listed = false;
                            for (size_t k = 0; k < g5c_json_len(p->restart); k++)
                                listed = listed || strcmp(g5c_json_str(g5c_json_at(p->restart, k)), path) == 0;
                            if (!listed)
                                add_str(p->restart, path);
                        }
                    }
            } else {
                add_str(p->restart, key);
            }
        }
    }
}

static void plan_free(plan_t *p)
{
    for (size_t i = 0; i < p->n; i++) {
        g5c_json_free(p->steps[i].from);
        g5c_json_free(p->steps[i].to);
    }
    g5c_json_free(p->restart);
}

/* ---- the baseline after a reload: what was in force, with the applied parts replaced by the new values ---- */

static void set_path(g5c_json *root, const char *path, const g5c_json *val)
{
    const char *dot = strchr(path, '.');
    if (dot == NULL) {
        if (val != NULL)
            g5c_json_set(root, path, g5c_json_dup(val));
        else
            g5c_json_remove(root, path);
        return;
    }
    {
        char head[64];
        size_t n = (size_t)(dot - path);
        g5c_json *sec;
        if (n >= sizeof head)
            return;
        memcpy(head, path, n);
        head[n] = 0;
        sec = g5c_json_get_mut(root, head);
        if (sec == NULL || !g5c_json_is(sec, G5C_J_OBJECT))
            sec = g5c_json_set(root, head, g5c_json_new_obj());
        if (val != NULL)
            g5c_json_set(sec, dot + 1, g5c_json_dup(val));
        else
            g5c_json_remove(sec, dot + 1);
    }
}

/* ---- the reload ---- */

static g5c_json *report(const char *result, const g5c_json *applied, const g5c_json *restart, const char *error, bool dry)
{
    g5c_json *r = g5c_json_new_obj();
    char ts[40];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tm);
    g5c_json_set_str(r, "result", result);
    g5c_json_set_str(r, "time", ts);
    g5c_json_set_bool(r, "dryRun", dry);
    g5c_json_set(r, "applied", applied != NULL ? g5c_json_dup(applied) : g5c_json_new_arr());
    g5c_json_set(r, "restartRequired", restart != NULL ? g5c_json_dup(restart) : g5c_json_new_arr());
    if (error != NULL)
        g5c_json_set_str(r, "error", error);
    return r;
}

static void count(g5c_nf *nf, const char *result)
{
    g5c_label l[1] = {{"result", result}};
    g5c_counter_inc(g5c_counter_get(nf->metrics, "g5c_config_reloads_total", "Configuration reloads, by result.", l, 1));
}

static bool healthy_for(g5c_nf *nf, unsigned ms, char *why, size_t cap)
{
    unsigned long e0 = atomic_load(&nf->server_errors);
    for (unsigned waited = 0; waited < ms; waited += 25) {
        usleep(25000);
        if (!atomic_load(&nf->ready)) {
            snprintf(why, cap, "the function stopped being ready");
            return false;
        }
        if (atomic_load(&nf->server_errors) >= e0 + ERRORS_TO_ROLL_BACK) {
            snprintf(why, cap, "%lu server errors in %u ms after the change", atomic_load(&nf->server_errors) - e0, waited + 25);
            return false;
        }
    }
    return true;
}

g5c_json *g5c_nf_reload(g5c_nf *nf, bool dry_run)
{
    struct g5c_reload *rl = nf->reload;
    g5c_json *neu = NULL, *rep, *applied = g5c_json_new_arr();
    g5c_common nc;
    plan_t plan;
    core_t core;
    char err[300] = "";
    size_t done = 0;
    bool have_nc = false;
    memset(&core, 0, sizeof core);
    if (pthread_mutex_trylock(&rl->mu) != 0) {
        rep = report("rejected", NULL, NULL, "another reload is running", dry_run);
        goto out_nolock;
    }
    if (rl->path == NULL || rl->root == NULL) {
        rep = report("rejected", NULL, NULL, "the function was not started from a configuration file", dry_run);
        count(nf, "rejected");
        goto out;
    }
    neu = g5c_config_load(rl->path, err, sizeof err);
    if (neu == NULL || g5c_common_parse(neu, &nc, err, sizeof err) != 0) {
        rep = report("rejected", NULL, NULL, err, dry_run);
        count(nf, "rejected");
        G5C_LOGE("g5c_audit", "%s: config reload rejected: %s", nf->common.name, err);
        goto out;
    }
    have_nc = true;
    if (g5c_common_validate(&nc, err, sizeof err) != 0) {
        rep = report("rejected", NULL, NULL, err, dry_run);
        count(nf, "rejected");
        G5C_LOGE("g5c_audit", "%s: config reload rejected: %s", nf->common.name, err);
        goto out;
    }
    make_plan(rl, rl->root, neu, &plan);
    if (plan.n == 0) {
        rep = report(g5c_json_len(plan.restart) > 0 ? "restart-required" : "unchanged", NULL, plan.restart, NULL, dry_run);
        if (!dry_run)
            count(nf, "unchanged");
        plan_free(&plan);
        goto out;
    }
    for (size_t i = 0; i < plan.n; i++)
        add_str(applied, plan.steps[i].label);
    if (dry_run) {
        rep = report("dry-run", applied, plan.restart, NULL, true);
        plan_free(&plan);
        goto out;
    }
    core.nc = nc;
    for (; done < plan.n; done++) { /* apply in order; the first failure undoes what was applied */
        err[0] = 0;
        if (apply_step(nf, &plan.steps[done], &core, err, sizeof err) != 0) {
            for (size_t i = done; i > 0; i--)
                revert_step(nf, &plan.steps[i - 1], &core);
            rep = report("rolled-back", NULL, plan.restart, err[0] ? err : "a section could not be applied", false);
            g5c_json_set_str(rep, "failedSection", plan.steps[done].label);
            count(nf, "rolled_back");
            G5C_LOGE("g5c_audit", "%s: config reload rolled back: %s: %s", nf->common.name, plan.steps[done].label, err);
            plan_free(&plan);
            goto out_core;
        }
    }
    if (nf->common.reload.settle_ms > 0 && !healthy_for(nf, nf->common.reload.settle_ms, err, sizeof err)) {
        for (size_t i = plan.n; i > 0; i--)
            revert_step(nf, &plan.steps[i - 1], &core);
        rep = report("rolled-back", NULL, plan.restart, err, false);
        count(nf, "rolled_back");
        G5C_LOGE("g5c_audit", "%s: config reload rolled back: %s", nf->common.name, err);
        plan_free(&plan);
        goto out_core;
    }
    {   /* kept: the baseline takes over what was applied */
        g5c_json *base = g5c_json_dup(rl->root);
        for (size_t i = 0; i < plan.n; i++)
            set_path(base, plan.steps[i].label, at_path(neu, plan.steps[i].label));
        g5c_json_free(rl->root);
        rl->root = base;
    }
    rep = report("applied", applied, plan.restart, NULL, false);
    count(nf, "applied");
    {
        char *list = g5c_json_to_string(applied, NULL);
        G5C_LOGI("g5c_audit", "%s: config reload applied %s%s", nf->common.name, list, g5c_json_len(plan.restart) > 0 ? " (some changes need a restart)" : "");
        free(list);
    }
    plan_free(&plan);
out_core:
    /* the parts of the new configuration that moved into the function stay there (or were handed back); the rest is freed with it */
    if (core.have_old_events)
        free_events_cfg(&core.old_events);
    free(core.old_log_level);
    g5c_common_free(&core.nc);
    have_nc = false;
out:
    g5c_json_free(rl->last);
    rl->last = g5c_json_dup(rep);
    pthread_mutex_unlock(&rl->mu);
out_nolock:
    if (have_nc)
        g5c_common_free(&nc);
    g5c_json_free(neu);
    g5c_json_free(applied);
    return rep;
}

/* ---- registration, lifecycle, admin endpoint ---- */

void g5c_nf_on_reload(g5c_nf *nf, const char *path, g5c_reload_fn fn, void *ctx)
{
    struct g5c_reload *rl = nf->reload;
    if (rl->nhooks < MAX_HOOKS) {
        rl->hooks[rl->nhooks].path = g5c_xstrdup(path);
        rl->hooks[rl->nhooks].fn = fn;
        rl->hooks[rl->nhooks].ctx = ctx;
        rl->nhooks++;
    }
}

void g5c_reload_init(g5c_nf *nf)
{
    struct g5c_reload *rl = g5c_xcalloc(1, sizeof *rl);
    char *path = g5c_xstrdup(g5c_config_last_path()); /* a copy: g5c_config_load writes that buffer */
    char err[200];
    pthread_mutex_init(&rl->mu, NULL);
    if (path[0] != '\0') {
        rl->root = g5c_config_load(path, err, sizeof err);
        if (rl->root != NULL)
            rl->path = g5c_xstrdup(path);
    }
    free(path);
    if (nf->common.reload.token_file != NULL || getenv("G5C_RELOAD_TOKEN") != NULL) {
        char terr[200] = "";
        rl->token = g5c_secret_from_env_or_file("G5C_RELOAD_TOKEN", nf->common.reload.token_file, terr, sizeof terr);
        if (rl->token == NULL && terr[0] != '\0')
            G5C_LOGW("g5c_nfcore", "%s: reload token: %s (POST /admin/v1/reload is off)", nf->common.name, terr);
    }
    nf->reload = rl;
}

void g5c_reload_free(g5c_nf *nf)
{
    struct g5c_reload *rl = nf->reload;
    if (rl == NULL)
        return;
    for (size_t i = 0; i < rl->nhooks; i++)
        free(rl->hooks[i].path);
    g5c_json_free(rl->root);
    g5c_json_free(rl->last);
    free(rl->path);
    if (rl->token != NULL) {
        OPENSSL_cleanse(rl->token, strlen(rl->token));
        free(rl->token);
    }
    pthread_mutex_destroy(&rl->mu);
    free(rl);
    nf->reload = NULL;
}

static bool token_ok(const g5c_nf *nf, const g5c_req *req)
{
    const char *given = g5c_bearer_token(req), *want = nf->reload->token;
    return given != NULL && want != NULL && strlen(given) == strlen(want) && CRYPTO_memcmp(given, want, strlen(want)) == 0;
}

static void h_reload_post(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_nf *nf = ctx;
    char *dry = g5c_req_query_decoded(req, "dry-run");
    bool dry_run = dry != NULL && (strcmp(dry, "true") == 0 || strcmp(dry, "1") == 0);
    g5c_json *rep;
    const char *res;
    free(dry);
    if (!token_ok(nf, req)) {
        g5c_resp_problem_simple(resp, 401, "UNAUTHORIZED", "a bearer token is required");
        return;
    }
    G5C_LOGI("g5c_audit", "%s: config reload requested over the admin API%s", nf->common.name, dry_run ? " (dry run)" : "");
    rep = g5c_nf_reload(nf, dry_run);
    res = g5c_json_get_str(rep, "result");
    g5c_resp_json(resp, strcmp(res, "rejected") == 0 ? 400 : strcmp(res, "rolled-back") == 0 ? 409 : 200, rep);
    g5c_json_free(rep);
}

static void h_reload_get(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    g5c_nf *nf = ctx;
    if (!token_ok(nf, req)) {
        g5c_resp_problem_simple(resp, 401, "UNAUTHORIZED", "a bearer token is required");
        return;
    }
    pthread_mutex_lock(&nf->reload->mu);
    if (nf->reload->last != NULL)
        g5c_resp_json(resp, 200, nf->reload->last);
    else
        g5c_resp_problem_simple(resp, 404, "RESOURCE_NOT_FOUND", "no reload has run yet");
    pthread_mutex_unlock(&nf->reload->mu);
}

void g5c_reload_routes(g5c_nf *nf, g5c_router *r)
{
    if (nf->reload->token == NULL)
        return;
    g5c_router_route_flags(r, "POST", "/admin/v1/reload", h_reload_post, nf, G5C_ROUTE_OWN_AUTH);
    g5c_router_route_flags(r, "GET", "/admin/v1/reload", h_reload_get, nf, G5C_ROUTE_OWN_AUTH);
}
