/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The "upf:" section of the NF configuration. */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "g5c/config.h"
#include "g5c/upf_rt.h"

static int fail(char *err, size_t cap, const char *what, const char *why)
{
    if (err && cap)
        snprintf(err, cap, "invalid upf config: `%s` %s", what, why);
    return -1;
}

static int parse_endpoint(const g5c_json *o, const char *name, upf_addr *a, char *err, size_t cap)
{
    static const char *const keys[] = {"address", "port", NULL};
    const char *ip = g5c_json_get_str(o, "address");
    int64_t port = a->port;
    char where[32];
    snprintf(where, sizeof where, "upf.%s", name);
    if (!g5c_json_is(o, G5C_J_OBJECT))
        return fail(err, cap, where, "section is required: { address: <IPv4>, port: <n> }");
    if (g5c_json_check_keys(o, keys, where, err, cap) != 0)
        return -1;
    if (ip == NULL || inet_pton(AF_INET, ip, a->b) != 1)
        return fail(err, cap, where, "needs `address`: an IPv4 address");
    if (a->b[0] == 0 && a->b[1] == 0 && a->b[2] == 0 && a->b[3] == 0)
        return fail(err, cap, where, "must be a specific address: it is advertised to the SMF (F-SEID, F-TEID)");
    if (g5c_json_get(o, "port") != NULL && (!g5c_json_get_int(o, "port", &port) || port < 1 || port > 65535))
        return fail(err, cap, where, "port must be 1..65535");
    a->port = (uint16_t)port;
    return 0;
}

static int get_uint(const g5c_json *o, const char *key, int64_t max, uint32_t *out, char *err, size_t cap, const char *where)
{
    int64_t v;
    if (g5c_json_get(o, key) == NULL)
        return 0;
    if (!g5c_json_get_int(o, key, &v) || v < 0 || v > max)
        return fail(err, cap, where, "has an out-of-range number");
    *out = (uint32_t)v;
    return 0;
}

int upf_rt_config_parse(const g5c_json *u, upf_rt_config *out, char *err, size_t errcap)
{
    static const char *const top[] = {"pfcp", "gtpu", "n6", "check_source", "heartbeat", "buffer", "max_sessions", NULL};
    static const char *const hb[] = {"interval", "retries", "delete_on_loss", NULL};
    static const char *const bf[] = {"max_packets", "max_bytes", "max_age", NULL};
    static const char *const n6k[] = {"device", NULL};
    const g5c_json *x;
    bool b;
    double d;
    upf_rt_config_defaults(out);
    if (!g5c_json_is(u, G5C_J_OBJECT))
        return fail(err, errcap, "upf", "section is required");
    if (g5c_json_check_keys(u, top, "upf", err, errcap) != 0)
        return -1;
    if (parse_endpoint(g5c_json_get(u, "pfcp"), "pfcp", &out->engine.n4_addr, err, errcap) != 0)
        return -1;
    if (parse_endpoint(g5c_json_get(u, "gtpu"), "gtpu", &out->engine.n3_addr, err, errcap) != 0)
        return -1;
    if ((x = g5c_json_get(u, "n6")) != NULL) {
        const char *dev = g5c_json_get_str(x, "device");
        if (!g5c_json_is(x, G5C_J_OBJECT) || g5c_json_check_keys(x, n6k, "upf.n6", err, errcap) != 0)
            return -1;
        if (dev == NULL || *dev == 0 || strlen(dev) >= sizeof out->tun_dev)
            return fail(err, errcap, "upf.n6.device", "must be an interface name of at most 15 characters");
        snprintf(out->tun_dev, sizeof out->tun_dev, "%s", dev);
    }
    if (g5c_json_get_bool(u, "check_source", &b))
        out->engine.check_source = b;
    else if (g5c_json_get(u, "check_source") != NULL)
        return fail(err, errcap, "upf.check_source", "must be true or false");
    if (get_uint(u, "max_sessions", 10000000, &out->engine.max_sessions, err, errcap, "upf.max_sessions") != 0)
        return -1;
    if ((x = g5c_json_get(u, "heartbeat")) != NULL) {
        if (!g5c_json_is(x, G5C_J_OBJECT) || g5c_json_check_keys(x, hb, "upf.heartbeat", err, errcap) != 0)
            return -1;
        if (get_uint(x, "interval", 3600, &out->engine.heartbeat_interval, err, errcap, "upf.heartbeat") != 0 ||
            get_uint(x, "retries", 100, &out->engine.heartbeat_retries, err, errcap, "upf.heartbeat") != 0)
            return -1;
        if (g5c_json_get_bool(x, "delete_on_loss", &b))
            out->engine.delete_on_peer_loss = b;
        if (out->engine.heartbeat_interval > 0 && out->engine.heartbeat_retries == 0)
            return fail(err, errcap, "upf.heartbeat.retries", "must be at least 1 when heartbeats are on");
    }
    if ((x = g5c_json_get(u, "buffer")) != NULL) {
        if (!g5c_json_is(x, G5C_J_OBJECT) || g5c_json_check_keys(x, bf, "upf.buffer", err, errcap) != 0)
            return -1;
        if (get_uint(x, "max_packets", 1000000, &out->engine.buffer_max_packets, err, errcap, "upf.buffer") != 0 ||
            get_uint(x, "max_bytes", 1u << 30, &out->engine.buffer_max_bytes, err, errcap, "upf.buffer") != 0)
            return -1;
        if (g5c_json_get(x, "max_age") != NULL) {
            if (!g5c_json_num(g5c_json_get(x, "max_age"), &d) || d <= 0 || d > 3600)
                return fail(err, errcap, "upf.buffer.max_age", "must be 0 < seconds <= 3600");
            out->engine.buffer_max_age = d;
        }
    }
    return 0;
}
