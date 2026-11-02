/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include <string.h>
#include <time.h>

#include "priv.h"

void upf_config_defaults(upf_config *c)
{
    memset(c, 0, sizeof *c);
    c->n4_addr.port = 8805;
    c->n3_addr.port = 2152;
    c->check_source = true;
    c->heartbeat_interval = 5;
    c->heartbeat_retries = 3;
    c->buffer_max_packets = 256;
    c->buffer_max_bytes = 1u << 20;
    c->buffer_max_age = 10.0;
    c->max_sessions = 65536;
    c->delete_on_peer_loss = true;
}

upf *upf_new(const upf_config *cfg, const upf_io *io, g5c_registry *metrics)
{
    upf *u = g5c_xcalloc(1, sizeof *u);
    u->cfg = *cfg;
    u->io = *io;
    u->metrics = metrics;
    u->recovery_ts = (uint32_t)((uint64_t)time(NULL) + UPF_NTP_UNIX_OFFSET);
    u->by_seid = ptrmap_new();
    u->by_teid = ptrmap_new();
    u->by_ue4 = ptrmap_new();
    u->by_ue6 = ptrmap_new();
    u->next_teid = (uint32_t)(u->recovery_ts & 0x0fffffff); /* a TEID space that differs after a restart */
    return u;
}

void upf_free(upf *u)
{
    if (u == NULL)
        return;
    for (size_t i = 0; i < u->nsessions; i++)
        if (u->sessions[i] != NULL) {
            sess_free(u, u->sessions[i]);
            u->sessions[i] = NULL;
        }
    for (size_t i = 0; i < sizeof u->pend / sizeof *u->pend; i++)
        if (u->pend[i].used)
            free(u->pend[i].msg);
    for (size_t i = 0; i < sizeof u->cache / sizeof *u->cache; i++)
        free(u->cache[i].resp);
    free(u->sessions);
    free(u->peers);
    ptrmap_free(u->by_seid);
    ptrmap_free(u->by_teid);
    ptrmap_free(u->by_ue4);
    ptrmap_free(u->by_ue6);
    free(u);
}

void upf_tick(upf *u, double now)
{
    u->now = now;
    urr_tick(u, now);
    dp_buffer_expire(u, now);
    n4_timers(u, now);
}

size_t upf_session_count(const upf *u)
{
    return ptrmap_len(u->by_seid);
}

upf_session *upf_session_by_seid(const upf *u, uint64_t seid)
{
    return ptrmap_get(u->by_seid, seid);
}
