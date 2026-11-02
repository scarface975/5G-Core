/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* UE address pools (TS 23.501 5.8.2.2) */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/smf.h"

struct smf_pool {
    pthread_mutex_t mu;
    bool has4, has6;
    uint32_t base4; /* host order, network address */
    uint32_t count4; /* assignable addresses: network+2 .. broadcast-1 (network+1 is the gateway) */
    uint8_t *bits4;
    uint32_t cur4, used4;
    uint64_t base6; /* the 64 bits of the /plen prefix */
    uint32_t count6;
    uint8_t *bits6;
    uint32_t cur6, used6;
};

static int parse_cidr(const char *s, int af, void *addr, unsigned *plen, char *err, size_t cap)
{
    char buf[64], *slash;
    char *end;
    long l;
    if (strlen(s) >= sizeof buf) {
        snprintf(err, cap, "address range `%s` is too long", s);
        return -1;
    }
    memcpy(buf, s, strlen(s) + 1);
    slash = strchr(buf, '/');
    if (slash == NULL) {
        snprintf(err, cap, "address range `%s` needs a prefix length", s);
        return -1;
    }
    *slash++ = 0;
    l = strtol(slash, &end, 10);
    if (*slash == 0 || *end != 0 || l < 0 || l > (af == AF_INET ? 32 : 128)) {
        snprintf(err, cap, "bad prefix length in `%s`", s);
        return -1;
    }
    if (inet_pton(af, buf, addr) != 1) {
        snprintf(err, cap, "bad address in `%s`", s);
        return -1;
    }
    *plen = (unsigned)l;
    return 0;
}

smf_pool *smf_pool_new(const char *cidr4, const char *cidr6, char *err, size_t cap)
{
    smf_pool *p = g5c_xcalloc(1, sizeof *p);
    pthread_mutex_init(&p->mu, NULL);
    if (cidr4 != NULL) {
        uint8_t a[4];
        unsigned plen;
        uint64_t total;
        if (parse_cidr(cidr4, AF_INET, a, &plen, err, cap) != 0)
            goto fail;
        if (plen < 8 || plen > 30) {
            snprintf(err, cap, "IPv4 pool `%s`: prefix length must be 8..=30", cidr4);
            goto fail;
        }
        p->base4 = ((uint32_t)a[0] << 24 | (uint32_t)a[1] << 16 | (uint32_t)a[2] << 8 | a[3]) & (0xffffffffu << (32 - plen));
        total = 1ull << (32 - plen);
        p->count4 = (uint32_t)(total - 3); /* network, gateway, broadcast */
        p->bits4 = g5c_xcalloc((p->count4 + 7) / 8, 1);
        p->has4 = true;
    }
    if (cidr6 != NULL) {
        uint8_t a[16];
        unsigned plen;
        uint64_t n;
        if (parse_cidr(cidr6, AF_INET6, a, &plen, err, cap) != 0)
            goto fail;
        if (plen < 48 || plen > 63) {
            snprintf(err, cap, "IPv6 pool `%s`: prefix length must be 48..=63 (it is split into /64s)", cidr6);
            goto fail;
        }
        for (int i = 0; i < 8; i++)
            p->base6 = p->base6 << 8 | a[i];
        p->base6 &= ~0ull << (64 - plen);
        n = 1ull << (64 - plen);
        p->count6 = (uint32_t)(n > 65536 ? 65536 : n);
        p->bits6 = g5c_xcalloc((p->count6 + 7) / 8, 1);
        p->has6 = true;
    }
    if (!p->has4 && !p->has6) {
        snprintf(err, cap, "a pool needs an IPv4 or an IPv6 range");
        goto fail;
    }
    return p;
fail:
    smf_pool_free(p);
    return NULL;
}

void smf_pool_free(smf_pool *p)
{
    if (p == NULL)
        return;
    pthread_mutex_destroy(&p->mu);
    free(p->bits4);
    free(p->bits6);
    free(p);
}

bool smf_pool_has4(const smf_pool *p)
{
    return p != NULL && p->has4;
}

bool smf_pool_has6(const smf_pool *p)
{
    return p != NULL && p->has6;
}

static bool bit_get(const uint8_t *b, uint32_t i)
{
    return (b[i / 8] >> (i % 8)) & 1;
}

static void bit_set(uint8_t *b, uint32_t i, bool v)
{
    if (v)
        b[i / 8] = (uint8_t)(b[i / 8] | (1u << (i % 8)));
    else
        b[i / 8] = (uint8_t)(b[i / 8] & ~(1u << (i % 8)));
}

/* find a free index starting at *cur; -1 when full */
static long find_free(const uint8_t *b, uint32_t count, uint32_t *cur)
{
    for (uint32_t k = 0; k < count; k++) {
        uint32_t i = (*cur + k) % count;
        if (!bit_get(b, i)) {
            *cur = (i + 1) % count;
            return (long)i;
        }
    }
    return -1;
}

int smf_pool_alloc4(smf_pool *p, uint8_t ip[4])
{
    long i;
    uint32_t a;
    if (p == NULL || !p->has4)
        return -1;
    pthread_mutex_lock(&p->mu);
    i = find_free(p->bits4, p->count4, &p->cur4);
    if (i >= 0) {
        bit_set(p->bits4, (uint32_t)i, true);
        p->used4++;
    }
    pthread_mutex_unlock(&p->mu);
    if (i < 0)
        return -1;
    a = p->base4 + 2 + (uint32_t)i;
    ip[0] = (uint8_t)(a >> 24);
    ip[1] = (uint8_t)(a >> 16);
    ip[2] = (uint8_t)(a >> 8);
    ip[3] = (uint8_t)a;
    return 0;
}

void smf_pool_release4(smf_pool *p, const uint8_t ip[4])
{
    uint32_t a = (uint32_t)ip[0] << 24 | (uint32_t)ip[1] << 16 | (uint32_t)ip[2] << 8 | ip[3];
    if (p == NULL || !p->has4 || a < p->base4 + 2)
        return;
    a -= p->base4 + 2;
    pthread_mutex_lock(&p->mu);
    if (a < p->count4 && bit_get(p->bits4, a)) {
        bit_set(p->bits4, a, false);
        p->used4--;
    }
    pthread_mutex_unlock(&p->mu);
}

int smf_pool_alloc6(smf_pool *p, uint8_t prefix[8])
{
    long i;
    uint64_t v;
    if (p == NULL || !p->has6)
        return -1;
    pthread_mutex_lock(&p->mu);
    i = find_free(p->bits6, p->count6, &p->cur6);
    if (i >= 0) {
        bit_set(p->bits6, (uint32_t)i, true);
        p->used6++;
    }
    pthread_mutex_unlock(&p->mu);
    if (i < 0)
        return -1;
    v = p->base6 + (uint64_t)i;
    for (int k = 0; k < 8; k++)
        prefix[k] = (uint8_t)(v >> (8 * (7 - k)));
    return 0;
}

void smf_pool_release6(smf_pool *p, const uint8_t prefix[8])
{
    uint64_t v = 0;
    if (p == NULL || !p->has6)
        return;
    for (int k = 0; k < 8; k++)
        v = v << 8 | prefix[k];
    if (v < p->base6)
        return;
    v -= p->base6;
    pthread_mutex_lock(&p->mu);
    if (v < p->count6 && bit_get(p->bits6, (uint32_t)v)) {
        bit_set(p->bits6, (uint32_t)v, false);
        p->used6--;
    }
    pthread_mutex_unlock(&p->mu);
}

bool smf_pool_reserve4(smf_pool *p, const uint8_t ip[4])
{
    uint32_t a = (uint32_t)ip[0] << 24 | (uint32_t)ip[1] << 16 | (uint32_t)ip[2] << 8 | ip[3];
    bool ok = false;
    if (p == NULL || !p->has4 || a < p->base4 + 2)
        return false;
    a -= p->base4 + 2;
    pthread_mutex_lock(&p->mu);
    if (a < p->count4 && !bit_get(p->bits4, a)) {
        bit_set(p->bits4, a, true);
        p->used4++;
        ok = true;
    }
    pthread_mutex_unlock(&p->mu);
    return ok;
}

bool smf_pool_reserve6(smf_pool *p, const uint8_t prefix[8])
{
    uint64_t v = 0;
    bool ok = false;
    if (p == NULL || !p->has6)
        return false;
    for (int k = 0; k < 8; k++)
        v = v << 8 | prefix[k];
    if (v < p->base6)
        return false;
    v -= p->base6;
    pthread_mutex_lock(&p->mu);
    if (v < p->count6 && !bit_get(p->bits6, (uint32_t)v)) {
        bit_set(p->bits6, (uint32_t)v, true);
        p->used6++;
        ok = true;
    }
    pthread_mutex_unlock(&p->mu);
    return ok;
}

size_t smf_pool_used4(smf_pool *p)
{
    size_t n;
    pthread_mutex_lock(&p->mu);
    n = p->used4;
    pthread_mutex_unlock(&p->mu);
    return n;
}

size_t smf_pool_used6(smf_pool *p)
{
    size_t n;
    pthread_mutex_lock(&p->mu);
    n = p->used6;
    pthread_mutex_unlock(&p->mu);
    return n;
}

/* ---- bit rates ---- */

bool smf_parse_bitrate(const char *s, uint64_t *kbps)
{
    const char *p = s;
    char *end;
    double v, mult;
    if (s == NULL || !isdigit((unsigned char)*s))
        return false;
    while (isdigit((unsigned char)*p))
        p++;
    if (*p == '.') {
        p++;
        if (!isdigit((unsigned char)*p))
            return false;
        while (isdigit((unsigned char)*p))
            p++;
    }
    if (*p != ' ')
        return false;
    v = strtod(s, &end);
    if (end != p)
        return false;
    p++;
    if (strcmp(p, "bps") == 0)
        mult = 0.001;
    else if (strcmp(p, "Kbps") == 0)
        mult = 1;
    else if (strcmp(p, "Mbps") == 0)
        mult = 1e3;
    else if (strcmp(p, "Gbps") == 0)
        mult = 1e6;
    else if (strcmp(p, "Tbps") == 0)
        mult = 1e9;
    else
        return false;
    v = ceil(v * mult - 1e-9);
    if (v < 0 || v > 4e12) /* BitRate values beyond NGAP's 4 Tbit/s limit are not representable downstream */
        return false;
    *kbps = (uint64_t)v;
    return true;
}

char *smf_format_bitrate(uint64_t kbps)
{
    if (kbps != 0 && kbps % 1000000000u == 0)
        return g5c_xasprintf("%llu Tbps", (unsigned long long)(kbps / 1000000000u));
    if (kbps != 0 && kbps % 1000000u == 0)
        return g5c_xasprintf("%llu Gbps", (unsigned long long)(kbps / 1000000u));
    if (kbps != 0 && kbps % 1000u == 0)
        return g5c_xasprintf("%llu Mbps", (unsigned long long)(kbps / 1000u));
    return g5c_xasprintf("%llu Kbps", (unsigned long long)kbps);
}
