/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* UPF runtime: binds the engine (upf.h) to UDP sockets for N4 and N3, a TUN device (or a supplied descriptor) for N6, and a
 * timer, in one epoll loop (Stage A of the plan: a correct userspace datapath; AF_XDP/eBPF follows). Linux only. */
#ifndef G5C_UPF_RT_H
#define G5C_UPF_RT_H

#include "g5c/json.h"
#include "g5c/upf.h"

typedef struct {
    upf_config engine;    /* n4_addr / n3_addr are what the SMF is told, and what we bind to */
    char tun_dev[16];     /* N6 device (a TUN interface that already exists, or can be created by this process) */
    int n6_fd;            /* >= 0: use this descriptor for N6 instead of a TUN (tests: a datagram socketpair end) */
} upf_rt_config;

typedef struct upf_rt upf_rt;

void upf_rt_config_defaults(upf_rt_config *c);
/* The "upf:" section of an NF configuration (strict: unknown keys are errors). 0 or -1 with err filled. */
int upf_rt_config_parse(const g5c_json *section, upf_rt_config *out, char *err, size_t errcap);

upf_rt *upf_rt_new(const upf_rt_config *cfg, g5c_registry *metrics, char *err, size_t errcap);
void upf_rt_free(upf_rt *rt);
upf *upf_rt_engine(upf_rt *rt);
/* Counters and the session count as of the last control-plane message or timer tick; safe to call from any thread while the loop runs (the
 * engine itself belongs to the loop thread). */
void upf_rt_snapshot(upf_rt *rt, upf_stats *st, size_t *sessions);
uint16_t upf_rt_pfcp_port(const upf_rt *rt);
uint16_t upf_rt_gtpu_port(const upf_rt *rt);
/* Run the loop until upf_rt_stop() (callable from another thread or a signal handler). */
int upf_rt_run(upf_rt *rt);
void upf_rt_stop(upf_rt *rt);

#endif
