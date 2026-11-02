/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* IPFilterRule parsing and matching for PDR SDF filters. */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/upf.h"

static void seterr(char *err, size_t cap, const char *m)
{
    if (err && cap)
        snprintf(err, cap, "%s", m);
}

static bool parse_ports(const char *s, upf_net *n)
{
    char buf[96], *tok, *save = NULL;
    if (strlen(s) >= sizeof buf)
        return false;
    snprintf(buf, sizeof buf, "%s", s);
    for (tok = strtok_r(buf, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save)) {
        char *end;
        unsigned long a = strtoul(tok, &end, 10), b = a;
        if (end == tok || a > 65535)
            return false;
        if (*end == '-') {
            char *e2;
            b = strtoul(end + 1, &e2, 10);
            if (e2 == end + 1 || *e2 != 0 || b > 65535 || b < a)
                return false;
        } else if (*end != 0) {
            return false;
        }
        if (n->nports == UPF_MAX_PORTS)
            return false;
        n->pmin[n->nports] = (uint16_t)a;
        n->pmax[n->nports] = (uint16_t)b;
        n->nports++;
    }
    return n->nports > 0;
}

static bool parse_net(const char *tok, upf_net *n)
{
    char buf[64], *slash;
    memset(n, 0, sizeof *n);
    if (strcmp(tok, "any") == 0) {
        n->any = true;
        return true;
    }
    if (strcmp(tok, "assigned") == 0) {
        n->assigned = true;
        return true;
    }
    if (strlen(tok) >= sizeof buf)
        return false;
    snprintf(buf, sizeof buf, "%s", tok);
    slash = strchr(buf, '/');
    if (slash)
        *slash++ = 0;
    if (inet_pton(AF_INET, buf, n->addr) == 1) {
        n->plen = 32;
    } else if (inet_pton(AF_INET6, buf, n->addr) == 1) {
        n->v6 = true;
        n->plen = 128;
    } else {
        return false;
    }
    if (slash) {
        char *end;
        unsigned long l = strtoul(slash, &end, 10);
        if (end == slash || *end != 0 || l > (n->v6 ? 128u : 32u))
            return false;
        n->plen = (uint8_t)l;
    }
    return true;
}

int upf_sdf_parse(const char *rule, upf_sdf *out, char *err, size_t errcap)
{
    char buf[256], *tok[16], *save = NULL, *t;
    size_t n = 0, i = 0;
    memset(out, 0, sizeof *out);
    if (strlen(rule) >= sizeof buf) {
        seterr(err, errcap, "rule too long");
        return -1;
    }
    snprintf(buf, sizeof buf, "%s", rule);
    for (t = strtok_r(buf, " \t", &save); t != NULL && n < 16; t = strtok_r(NULL, " \t", &save))
        tok[n++] = t;
    if (n < 6 || (strcmp(tok[0], "permit") != 0 && strcmp(tok[0], "deny") != 0) || (strcmp(tok[1], "out") != 0 && strcmp(tok[1], "in") != 0)) {
        seterr(err, errcap, "expected: permit|deny out|in <proto> from <src> [ports] to <dst> [ports]");
        return -1;
    }
    out->permit = tok[0][0] == 'p';
    if (strcmp(tok[2], "ip") == 0) {
        out->proto = -1;
    } else {
        char *end;
        unsigned long p = strtoul(tok[2], &end, 10);
        if (end == tok[2] || *end != 0 || p > 255) {
            seterr(err, errcap, "bad protocol");
            return -1;
        }
        out->proto = (int)p;
    }
    if (strcmp(tok[3], "from") != 0) {
        seterr(err, errcap, "missing 'from'");
        return -1;
    }
    i = 4;
    if (i >= n || !parse_net(tok[i], &out->src)) {
        seterr(err, errcap, "bad source address");
        return -1;
    }
    i++;
    if (i < n && strcmp(tok[i], "to") != 0) {
        if (!parse_ports(tok[i], &out->src)) {
            seterr(err, errcap, "bad source ports");
            return -1;
        }
        i++;
    }
    if (i >= n || strcmp(tok[i], "to") != 0) {
        seterr(err, errcap, "missing 'to'");
        return -1;
    }
    i++;
    if (i >= n || !parse_net(tok[i], &out->dst)) {
        seterr(err, errcap, "bad destination address");
        return -1;
    }
    i++;
    if (i < n && !parse_ports(tok[i], &out->dst)) {
        seterr(err, errcap, "bad destination ports");
        return -1;
    }
    return 0;
}

static bool prefix_match(const uint8_t *a, const uint8_t *b, unsigned plen)
{
    unsigned full = plen / 8, rem = plen % 8;
    if (memcmp(a, b, full) != 0)
        return false;
    if (rem == 0)
        return true;
    return ((a[full] ^ b[full]) & (uint8_t)(0xff << (8 - rem))) == 0;
}

static bool net_match(const upf_net *n, bool v6, const uint8_t *ip, uint16_t port, bool has_port, const upf_addr *ue4, const upf_addr *ue6)
{
    if (!n->any) {
        if (n->assigned) {
            if (v6) {
                if (!ue6 || !prefix_match(ue6->b, ip, 64))
                    return false;
            } else if (!ue4 || memcmp(ue4->b, ip, 4) != 0) {
                return false;
            }
        } else {
            if (n->v6 != v6 || !prefix_match(n->addr, ip, n->plen))
                return false;
        }
    }
    if (n->nports > 0) {
        bool ok = false;
        if (!has_port)
            return false;
        for (size_t i = 0; i < n->nports; i++)
            if (port >= n->pmin[i] && port <= n->pmax[i])
                ok = true;
        if (!ok)
            return false;
    }
    return true;
}

bool upf_sdf_match(const upf_sdf *r, const upf_flow *f, const upf_addr *ue4, const upf_addr *ue6)
{
    bool has_port = f->proto == 6 || f->proto == 17 || f->proto == 132;
    if (!r->permit)
        return false;
    if (r->proto >= 0 && r->proto != f->proto)
        return false;
    return net_match(&r->src, f->v6, f->src, f->sport, has_port, ue4, ue6) && net_match(&r->dst, f->v6, f->dst, f->dport, has_port, ue4, ue6);
}

bool upf_flow_from_packet(const uint8_t *p, size_t len, upf_flow *f)
{
    size_t off;
    int proto;
    memset(f, 0, sizeof *f);
    if (len < 20)
        return false;
    if ((p[0] >> 4) == 4) {
        size_t ihl = (size_t)(p[0] & 15) * 4;
        if (ihl < 20 || len < ihl)
            return false;
        f->proto = p[9];
        memcpy(f->src, p + 12, 4);
        memcpy(f->dst, p + 16, 4);
        off = ihl;
        if ((((unsigned)p[6] << 8 | p[7]) & 0x1fff) != 0) /* not the first fragment: no ports */
            return true;
    } else if ((p[0] >> 4) == 6) {
        if (len < 40)
            return false;
        f->v6 = true;
        memcpy(f->src, p + 8, 16);
        memcpy(f->dst, p + 24, 16);
        proto = p[6];
        off = 40;
        for (int hops = 0; hops < 4 && (proto == 0 || proto == 43 || proto == 60); hops++) {
            if (len < off + 8)
                return true;
            proto = p[off];
            off += ((size_t)p[off + 1] + 1) * 8;
        }
        f->proto = proto;
    } else {
        return false;
    }
    if ((f->proto == 6 || f->proto == 17 || f->proto == 132) && len >= off + 4) {
        f->sport = (uint16_t)((p[off] << 8) | p[off + 1]);
        f->dport = (uint16_t)((p[off + 2] << 8) | p[off + 3]);
    }
    return true;
}

bool upf_addr_equal_ip(const upf_addr *a, const upf_addr *b)
{
    return a->v6 == b->v6 && memcmp(a->b, b->b, a->v6 ? 16 : 4) == 0;
}
