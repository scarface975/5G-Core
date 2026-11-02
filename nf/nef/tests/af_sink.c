/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* A notification receiver for tests and labs (an AF that only listens): af_sink <address> <port> <file>. Every POST body is appended to the file as one line and
 * answered 204; the process runs until it is killed. */
#define _DEFAULT_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "g5c/sbi.h"

typedef struct {
    pthread_mutex_t mu;
    FILE *f;
} sink_t;

static void handler(void *ctx, const g5c_req *req, g5c_resp *resp)
{
    sink_t *s = ctx;
    pthread_mutex_lock(&s->mu);
    fprintf(s->f, "%s %s\n", req->path != NULL ? req->path : "-", req->body_len > 0 ? (const char *)req->body : "");
    fflush(s->f);
    pthread_mutex_unlock(&s->mu);
    g5c_resp_status(resp, 204);
}

int main(int argc, char **argv)
{
    sink_t s;
    g5c_router *r;
    g5c_server *srv;
    g5c_server_cfg cfg;
    char err[160];
    if (argc != 4) {
        fprintf(stderr, "usage: af_sink <address> <port> <file>\n");
        return 2;
    }
    s.f = fopen(argv[3], "a");
    if (s.f == NULL) {
        perror(argv[3]);
        return 1;
    }
    pthread_mutex_init(&s.mu, NULL);
    r = g5c_router_new();
    g5c_router_route(r, "POST", "/{p1}", handler, &s);
    g5c_router_route(r, "POST", "/{p1}/{p2}", handler, &s);
    g5c_router_route(r, "POST", "/{p1}/{p2}/{p3}", handler, &s);
    g5c_router_route(r, "POST", "/{p1}/{p2}/{p3}/{p4}", handler, &s);
    cfg.address = argv[1];
    cfg.port = (uint16_t)atoi(argv[2]);
    cfg.tls = NULL;
    srv = g5c_server_start(&cfg, r, err, sizeof err);
    if (srv == NULL) {
        fprintf(stderr, "af_sink: %s\n", err);
        return 1;
    }
    for (;;)
        pause();
}
