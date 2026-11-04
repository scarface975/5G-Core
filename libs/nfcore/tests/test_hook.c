/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Extension hooks: every item reaches the program as a line on its standard input with the hook point and the contract version in the environment, a failing program is counted, a program
 * that does not finish is killed at the timeout, a full queue drops the newest item, and a command that is not an absolute path to an executable is refused. */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "g5c/hook.h"
#include "g5c/testkit.h"

static void script(const char *path, const char *body)
{
    FILE *f = fopen(path, "w");
    TK_ASSERT(f != NULL);
    fputs(body, f);
    fclose(f);
    chmod(path, 0755);
}

static double counter(g5c_registry *r, const char *hook, const char *result)
{
    g5c_label l[] = {{"hook", hook}, {"result", result}};
    return (double)g5c_counter_value(g5c_counter_get(r, "g5c_hook_items_total", "Items handed to extension hooks, by hook point and result.", l, 2));
}

static size_t lines_of(const char *path)
{
    FILE *f = fopen(path, "r");
    size_t n = 0;
    int c;
    if (f == NULL)
        return 0;
    while ((c = fgetc(f)) != EOF)
        n += c == '\n';
    fclose(f);
    return n;
}

int main(void)
{
    char dir[] = "/tmp/g5c-hook-XXXXXX", sink[300], good[300], bad[300], slow[300], cmd[700], err[200], first[300];
    g5c_registry *reg = g5c_registry_new();
    g5c_hook *h;
    FILE *f;
    char buf[300] = "";
    TK_ASSERT(mkdtemp(dir) != NULL);
    snprintf(sink, sizeof sink, "%s/sink.txt", dir);
    snprintf(good, sizeof good, "%s/good.sh", dir);
    snprintf(bad, sizeof bad, "%s/bad.sh", dir);
    snprintf(slow, sizeof slow, "%s/slow.sh", dir);
    snprintf(first, sizeof first, "%s/env.txt", dir);
    snprintf(cmd, sizeof cmd, "#!/bin/sh\ncat >> %s\necho \"$G5C_HOOK $G5C_HOOK_API $HOME\" > %s\nexit 0\n", sink, first);
    script(good, cmd);
    script(bad, "#!/bin/sh\ncat > /dev/null\nexit 3\n");
    script(slow, "#!/bin/sh\nsleep 30\n");

    h = g5c_hook_new("cdr_sink", good, 8, 5, reg, err, sizeof err);
    TK_ASSERT(h != NULL);
    g5c_hook_emit(h, "{\"supi\":\"imsi-1\",\"totalOctets\":10}");
    g5c_hook_emit(h, "{\"supi\":\"imsi-2\",\"totalOctets\":20}");
    TK_ASSERT(g5c_hook_flush(h, 5000));
    TK_ASSERT(lines_of(sink) == 2 && counter(reg, "cdr_sink", "ok") == 2);
    f = fopen(first, "r");
    TK_ASSERT(f != NULL && fgets(buf, sizeof buf, f) != NULL);
    fclose(f);
    TK_ASSERT(strncmp(buf, "cdr_sink 1 \n", 12) == 0); /* the hook point and the contract version; nothing of the function's environment (HOME is empty) */
    g5c_hook_free(h);

    h = g5c_hook_new("bad_sink", bad, 8, 5, reg, err, sizeof err);
    TK_ASSERT(h != NULL);
    g5c_hook_emit(h, "{}");
    TK_ASSERT(g5c_hook_flush(h, 5000) && counter(reg, "bad_sink", "failed") == 1);
    g5c_hook_free(h);

    h = g5c_hook_new("slow_sink", slow, 2, 1, reg, err, sizeof err);
    TK_ASSERT(h != NULL);
    g5c_hook_emit(h, "{\"n\":1}"); /* picked up by the worker and killed after 1 s */
    usleep(200000);
    g5c_hook_emit(h, "{\"n\":2}"); /* queued */
    g5c_hook_emit(h, "{\"n\":3}"); /* queued */
    g5c_hook_emit(h, "{\"n\":4}"); /* the queue of two is full: dropped */
    TK_ASSERT(counter(reg, "slow_sink", "dropped") == 1);
    TK_ASSERT(g5c_hook_flush(h, 10000) && counter(reg, "slow_sink", "timeout") == 3);
    g5c_hook_free(h);

    snprintf(cmd, sizeof cmd, "%s --verbose", good);
    h = g5c_hook_new("args", cmd, 4, 5, reg, err, sizeof err);
    TK_ASSERT(h != NULL); /* arguments after the path are accepted */
    g5c_hook_free(h);
    TK_ASSERT(g5c_hook_new("x", "relative.sh", 4, 5, reg, err, sizeof err) == NULL && strstr(err, "absolute") != NULL);
    TK_ASSERT(g5c_hook_new("x", "/nonexistent/program", 4, 5, reg, err, sizeof err) == NULL && strstr(err, "not an executable") != NULL);
    TK_ASSERT(g5c_hook_new("x", dir, 4, 5, reg, err, sizeof err) == NULL); /* a directory is not a program */

    unlink(sink);
    unlink(good);
    unlink(bad);
    unlink(slow);
    unlink(first);
    rmdir(dir);
    g5c_registry_free(reg);
    printf("hook: OK\n");
    return 0;
}
