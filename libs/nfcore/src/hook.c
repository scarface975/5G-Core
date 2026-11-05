/* SPDX-License-Identifier: LicenseRef-Proprietary */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "g5c/base.h"
#include "g5c/config.h"
#include "g5c/hook.h"

struct g5c_hook {
    char *point;
    char **argv;
    unsigned qmax, timeout_s;
    pthread_mutex_t mu;
    pthread_cond_t cv, idle;
    char **q;
    unsigned qlen, busy;
    bool stop;
    pthread_t th;
    g5c_registry *metrics;
};

static void count(g5c_hook *h, const char *result)
{
    g5c_label l[] = {{"hook", h->point}, {"result", result}};
    g5c_counter_inc(g5c_counter_get(h->metrics, "g5c_hook_items_total", "Items handed to extension hooks, by hook point and result.", l, 2));
}

static double mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* The argv of a hook command: an absolute path to an executable file, arguments after it split on blanks (at most 32). NULL with err otherwise. */
static char **split_command(const char *point, const char *command, char *err, size_t errcap)
{
    char **argv, *dup, *tok, *save = NULL;
    size_t na = 0;
    struct stat st;
    if (command == NULL || command[0] != '/') {
        snprintf(err, errcap, "invalid config: the command of the %s hook must be an absolute path (arguments after it, split on blanks)", point);
        return NULL;
    }
    argv = g5c_xcalloc(34, sizeof *argv);
    dup = g5c_xstrdup(command);
    for (tok = strtok_r(dup, " \t", &save); tok != NULL && na < 32; tok = strtok_r(NULL, " \t", &save))
        argv[na++] = g5c_xstrdup(tok);
    free(dup);
    if (na == 0 || stat(argv[0], &st) != 0 || !S_ISREG(st.st_mode) || access(argv[0], X_OK) != 0) {
        snprintf(err, errcap, "invalid config: the %s hook %s is not an executable file", point, na > 0 ? argv[0] : "(empty)");
        for (size_t i = 0; i < na; i++)
            free(argv[i]);
        free(argv);
        return NULL;
    }
    return argv;
}

/* one program run: 0 taken, 1 failed, 2 timeout */
static int run_one(g5c_hook *h, const char *line)
{
    int in[2];
    pid_t pid;
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t at;
    char env_point[96];
    char *envp[4];
    size_t n = strlen(line);
    double end = mono() + h->timeout_s;
    int status = 0, rc;
    if (pipe2(in, O_CLOEXEC) != 0)
        return 1;
    snprintf(env_point, sizeof env_point, "G5C_HOOK=%s", h->point);
    envp[0] = env_point;
    envp[1] = (char *)"G5C_HOOK_API=1";
    envp[2] = (char *)"PATH=/usr/bin:/bin";
    envp[3] = NULL;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, in[0], 0);
    posix_spawnattr_init(&at);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETPGROUP); /* its own process group: a timeout kills the program and whatever it started */
    posix_spawnattr_setpgroup(&at, 0);
    rc = posix_spawn(&pid, h->argv[0], &fa, &at, h->argv, envp);
    posix_spawnattr_destroy(&at);
    posix_spawn_file_actions_destroy(&fa);
    close(in[0]);
    if (rc != 0) {
        close(in[1]);
        return 1;
    }
    {
        ssize_t w = write(in[1], line, n);
        if (w == (ssize_t)n && write(in[1], "\n", 1) < 0)
            w = -1;
        (void)w;
    }
    close(in[1]);
    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
        if (r < 0 && errno != EINTR)
            return 1;
        if (mono() >= end) {
            kill(-pid, SIGKILL);
            (void)waitpid(pid, &status, 0);
            return 2;
        }
        {
            struct timespec ts = {0, 5 * 1000000L};
            nanosleep(&ts, NULL);
        }
    }
}

static void *worker(void *arg)
{
    g5c_hook *h = arg;
    pthread_mutex_lock(&h->mu);
    for (;;) {
        char *line;
        int r;
        while (h->qlen == 0 && !h->stop)
            pthread_cond_wait(&h->cv, &h->mu);
        if (h->qlen == 0 && h->stop)
            break;
        line = h->q[0];
        memmove(h->q, h->q + 1, (h->qlen - 1) * sizeof *h->q);
        h->qlen--;
        h->busy = 1;
        pthread_mutex_unlock(&h->mu);
        r = run_one(h, line);
        count(h, r == 0 ? "ok" : r == 2 ? "timeout" : "failed");
        free(line);
        pthread_mutex_lock(&h->mu);
        h->busy = 0;
        pthread_cond_broadcast(&h->idle);
    }
    pthread_mutex_unlock(&h->mu);
    return NULL;
}

g5c_hook *g5c_hook_new(const char *point, const char *command, unsigned queue_max, unsigned timeout_s, g5c_registry *metrics, char *err, size_t errcap)
{
    g5c_hook *h;
    char **argv = split_command(point, command, err, errcap);
    if (argv == NULL)
        return NULL;
    h = g5c_xcalloc(1, sizeof *h);
    h->point = g5c_xstrdup(point);
    h->qmax = queue_max != 0 ? queue_max : 1024;
    h->timeout_s = timeout_s != 0 ? timeout_s : 10;
    h->metrics = metrics;
    h->argv = argv;
    h->q = g5c_xcalloc(h->qmax, sizeof *h->q);
    pthread_mutex_init(&h->mu, NULL);
    pthread_cond_init(&h->cv, NULL);
    pthread_cond_init(&h->idle, NULL);
    if (pthread_create(&h->th, NULL, worker, h) != 0) {
        snprintf(err, errcap, "cannot start the %s hook worker", point);
        h->th = 0;
        g5c_hook_free(h);
        return NULL;
    }
    return h;
}

g5c_hook *g5c_hook_from_config(const g5c_json *blk, const char *point, const char *where, g5c_registry *metrics, char *err, size_t errcap)
{
    static const char *const keys[] = {"command", "timeout_s", "queue", NULL};
    int64_t to = 10, qm = 1024;
    err[0] = '\0';
    if (blk == NULL)
        return NULL;
    if (!g5c_json_is(blk, G5C_J_OBJECT) || g5c_json_check_keys(blk, keys, where, err, errcap) != 0 || g5c_json_get_str(blk, "command") == NULL ||
        (g5c_json_get(blk, "timeout_s") != NULL && (!g5c_json_get_int(blk, "timeout_s", &to) || to < 1 || to > 300)) ||
        (g5c_json_get(blk, "queue") != NULL && (!g5c_json_get_int(blk, "queue", &qm) || qm < 1 || qm > 1000000))) {
        if (err[0] == '\0')
            snprintf(err, errcap, "invalid config: `%s` takes `command` (an absolute path), `timeout_s` 1..=300 and `queue` 1..=1000000", where);
        return NULL;
    }
    return g5c_hook_new(point, g5c_json_get_str(blk, "command"), (unsigned)qm, (unsigned)to, metrics, err, errcap);
}

void g5c_hook_emit(g5c_hook *h, const char *line)
{
    if (h == NULL)
        return;
    pthread_mutex_lock(&h->mu);
    if (h->qlen >= h->qmax) {
        pthread_mutex_unlock(&h->mu);
        count(h, "dropped");
        return;
    }
    h->q[h->qlen++] = g5c_xstrdup(line);
    pthread_cond_signal(&h->cv);
    pthread_mutex_unlock(&h->mu);
}

bool g5c_hook_flush(g5c_hook *h, int timeout_ms)
{
    struct timespec ts;
    bool done;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&h->mu);
    while (h->qlen != 0 || h->busy)
        if (pthread_cond_timedwait(&h->idle, &h->mu, &ts) != 0)
            break;
    done = h->qlen == 0 && !h->busy;
    pthread_mutex_unlock(&h->mu);
    return done;
}

void g5c_hook_free(g5c_hook *h)
{
    if (h == NULL)
        return;
    if (h->th != 0) {
        pthread_mutex_lock(&h->mu);
        h->stop = true;
        pthread_cond_broadcast(&h->cv);
        pthread_mutex_unlock(&h->mu);
        pthread_join(h->th, NULL);
        pthread_mutex_destroy(&h->mu);
        pthread_cond_destroy(&h->cv);
        pthread_cond_destroy(&h->idle);
    }
    for (unsigned i = 0; h->q != NULL && i < h->qlen; i++)
        free(h->q[i]);
    free(h->q);
    for (size_t i = 0; h->argv != NULL && h->argv[i] != NULL; i++)
        free(h->argv[i]);
    free(h->argv);
    free(h->point);
    free(h);
}

/* ---- a hook that is asked (backlog G-03) ---- */

struct g5c_hookcall {
    char *point;
    char **argv;
    unsigned timeout_s;
    g5c_registry *metrics;
};

static void count_call(g5c_hookcall *h, const char *result)
{
    g5c_label l[] = {{"hook", h->point}, {"result", result}};
    g5c_counter_inc(g5c_counter_get(h->metrics, "g5c_hook_items_total", "Items handed to extension hooks, by hook point and result.", l, 2));
}

g5c_hookcall *g5c_hookcall_new(const char *point, const char *command, unsigned timeout_s, g5c_registry *metrics, char *err, size_t errcap)
{
    g5c_hookcall *h = g5c_xcalloc(1, sizeof *h);
    h->point = g5c_xstrdup(point);
    h->timeout_s = timeout_s != 0 ? timeout_s : 5;
    h->metrics = metrics;
    h->argv = split_command(point, command, err, errcap);
    if (h->argv == NULL) {
        free(h->point);
        free(h);
        return NULL;
    }
    return h;
}

int g5c_hookcall_run(g5c_hookcall *h, const char *in, char *out, size_t outcap)
{
    int inp[2], outp[2], status = 0, rc;
    pid_t pid;
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t at;
    char env_point[96];
    char *envp[4];
    size_t got = 0, n = strlen(in), sent = 0;
    double end = mono() + h->timeout_s;
    bool overflow = false;
    if (outcap == 0)
        return -1;
    out[0] = '\0';
    if (pipe2(inp, O_CLOEXEC) != 0)
        return -1;
    if (pipe2(outp, O_CLOEXEC) != 0) {
        close(inp[0]);
        close(inp[1]);
        return -1;
    }
    snprintf(env_point, sizeof env_point, "G5C_HOOK=%s", h->point);
    envp[0] = env_point;
    envp[1] = (char *)"G5C_HOOK_API=1";
    envp[2] = (char *)"PATH=/usr/bin:/bin";
    envp[3] = NULL;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, inp[0], 0);
    posix_spawn_file_actions_adddup2(&fa, outp[1], 1);
    posix_spawnattr_init(&at);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&at, 0);
    rc = posix_spawn(&pid, h->argv[0], &fa, &at, h->argv, envp);
    posix_spawnattr_destroy(&at);
    posix_spawn_file_actions_destroy(&fa);
    close(inp[0]);
    close(outp[1]);
    if (rc != 0) {
        close(inp[1]);
        close(outp[0]);
        count_call(h, "failed");
        return -1;
    }
    /* the request is small (below the size of a pipe), so one write does not block; the answer is read with a deadline */
    if (n < 4096) {
        ssize_t w = write(inp[1], in, n);
        if (w == (ssize_t)n && write(inp[1], "\n", 1) < 0)
            w = -1;
        sent = w == (ssize_t)n ? n : 0;
    }
    close(inp[1]);
    for (;;) {
        struct pollfd pf = {outp[0], POLLIN, 0};
        double left = end - mono();
        int pr;
        if (left <= 0)
            break;
        pr = poll(&pf, 1, (int)(left * 1000) + 1);
        if (pr < 0 && errno == EINTR)
            continue;
        if (pr <= 0)
            break;
        {
            char buf[512];
            ssize_t r = read(outp[0], buf, sizeof buf);
            if (r <= 0)
                break;
            for (ssize_t i = 0; i < r; i++) {
                if (got + 1 < outcap)
                    out[got++] = buf[i];
                else
                    overflow = true;
            }
        }
    }
    out[got] = '\0';
    close(outp[0]);
    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            int code = WIFEXITED(status) ? WEXITSTATUS(status) : 255;
            if (sent == 0 || overflow)
                code = -1;
            count_call(h, code == 0 ? "ok" : "failed");
            return code;
        }
        if (r < 0 && errno != EINTR) {
            count_call(h, "failed");
            return -1;
        }
        if (mono() >= end) {
            kill(-pid, SIGKILL);
            (void)waitpid(pid, &status, 0);
            count_call(h, "timeout");
            return -2;
        }
        {
            struct timespec ts = {0, 2 * 1000000L};
            nanosleep(&ts, NULL);
        }
    }
}

void g5c_hookcall_free(g5c_hookcall *h)
{
    if (h == NULL)
        return;
    for (char **a = h->argv; *a != NULL; a++)
        free(*a);
    free(h->argv);
    free(h->point);
    free(h);
}
