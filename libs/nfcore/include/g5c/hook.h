/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Extension hooks (contract "g5c-hook/1"): a partner program receives what a function produces without the function being forked.
 *
 * A hook is an absolute path with optional arguments (split on blanks, no shell). For every item the function starts the program, writes the item as one line of JSON to its standard
 * input, closes it and waits up to `timeout_s` seconds; a program that does not finish is killed. The program environment is empty except G5C_HOOK (the hook point, e.g. cdr_sink),
 * G5C_HOOK_API (the contract version, 1) and PATH=/usr/bin:/bin. Its exit status 0 means taken; anything else is counted as failed (the function does not retry: write what you
 * cannot lose to a file first). Items wait in a bounded queue and one worker thread runs the programs one after another, so a slow hook never delays the function: when the queue is
 * full the newest item is dropped and counted. Metrics: g5c_hook_items_total{hook,result="ok|failed|timeout|dropped"}. */
#ifndef G5C_HOOK_H
#define G5C_HOOK_H

#include <stdbool.h>
#include <stddef.h>

#include "g5c/json.h"
#include "g5c/metrics.h"

typedef struct g5c_hook g5c_hook;

/* NULL with err when the command is not an absolute path to an executable file. */
g5c_hook *g5c_hook_new(const char *point, const char *command, unsigned queue_max, unsigned timeout_s, g5c_registry *metrics, char *err, size_t errcap);
/* The hook of a configuration block `{ command: /abs/path args, timeout_s: 1..300, queue: 1..1000000 }`. NULL with err[0] == 0 when `blk` is absent (no hook), NULL with a message when it is invalid. */
g5c_hook *g5c_hook_from_config(const g5c_json *blk, const char *point, const char *where, g5c_registry *metrics, char *err, size_t errcap);
/* Queues one line (without the newline). Never blocks. */
void g5c_hook_emit(g5c_hook *h, const char *line);
/* Waits until everything queued has been handed to the program (or dropped); false on timeout. */
bool g5c_hook_flush(g5c_hook *h, int timeout_ms);
void g5c_hook_free(g5c_hook *h);

/* A hook that is asked, not told (backlog G-03): the program is started for one question and its answer is used at once. The request line goes to its standard input; what it writes to its
 * standard output (up to outcap - 1 bytes) is the answer; its exit status says how it went (the function defines the codes). The same environment, process group and kill on timeout as above.
 * Metrics: g5c_hook_items_total{hook,result="ok|failed|timeout"}. Safe from several threads at once; every call starts its own process. */
typedef struct g5c_hookcall g5c_hookcall;
g5c_hookcall *g5c_hookcall_new(const char *point, const char *command, unsigned timeout_s, g5c_registry *metrics, char *err, size_t errcap);
/* The exit status of the program (0..255); -1 when it cannot be started, does not take the request or writes more than fits; -2 after a timeout (killed). */
int g5c_hookcall_run(g5c_hookcall *h, const char *request, char *out, size_t outcap);
void g5c_hookcall_free(g5c_hookcall *h);

#endif
