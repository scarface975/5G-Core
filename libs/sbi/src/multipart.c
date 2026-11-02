/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include "g5c/multipart.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define MAX_BOUNDARY 70

static int ieq_prefix(const char *s, const char *p)
{
    return strncasecmp(s, p, strlen(p)) == 0;
}

int g5c_mp_is_multipart(const char *ct)
{
    while (ct != NULL && (*ct == ' ' || *ct == '\t'))
        ct++;
    return ct != NULL && ieq_prefix(ct, "multipart/related");
}

/* Extract the boundary parameter into out (MAX_BOUNDARY + 1 bytes). */
static int boundary_of(const char *ct, char *out)
{
    const char *p = ct;
    while ((p = strchr(p, ';')) != NULL) {
        p++;
        while (*p == ' ' || *p == '\t')
            p++;
        if (ieq_prefix(p, "boundary=")) {
            size_t n = 0;
            p += 9;
            if (*p == '"') {
                p++;
                while (*p != '"' && *p != 0 && n < MAX_BOUNDARY)
                    out[n++] = *p++;
                if (*p != '"')
                    return -1;
            } else {
                while (*p != ';' && *p != 0 && *p != ' ' && n < MAX_BOUNDARY)
                    out[n++] = *p++;
                if (*p != ';' && *p != 0 && *p != ' ')
                    return -1;
            }
            out[n] = 0;
            return n > 0 ? 0 : -1;
        }
    }
    return -1;
}

static const uint8_t *find_mem(const uint8_t *h, size_t hl, const uint8_t *n, size_t nl)
{
    if (nl == 0 || hl < nl)
        return NULL;
    for (size_t i = 0; i + nl <= hl; i++)
        if (h[i] == n[0] && memcmp(h + i, n, nl) == 0)
            return h + i;
    return NULL;
}

static char *trim_dup(const uint8_t *p, size_t n)
{
    while (n > 0 && (*p == ' ' || *p == '\t')) {
        p++;
        n--;
    }
    while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t' || p[n - 1] == '\r'))
        n--;
    return g5c_xstrndup((const char *)p, n);
}

void g5c_mp_free(g5c_mp *m)
{
    for (size_t i = 0; i < m->n; i++) {
        free(m->parts[i].content_id);
        free(m->parts[i].content_type);
    }
    memset(m, 0, sizeof *m);
}

const g5c_mp_part *g5c_mp_find(const g5c_mp *m, const char *id)
{
    if (id == NULL)
        return NULL;
    for (size_t i = 0; i < m->n; i++)
        if (m->parts[i].content_id != NULL && strcmp(m->parts[i].content_id, id) == 0)
            return &m->parts[i];
    return NULL;
}

/* Parse the header block h[0..hl) of one part. */
static int part_headers(const uint8_t *h, size_t hl, g5c_mp_part *p)
{
    size_t pos = 0;
    while (pos < hl) {
        const uint8_t *eol = memchr(h + pos, '\n', hl - pos), *colon;
        size_t ll = eol != NULL ? (size_t)(eol - (h + pos)) : hl - pos;
        colon = memchr(h + pos, ':', ll);
        if (colon == NULL)
            return -1;
        {
            size_t nl = (size_t)(colon - (h + pos));
            const uint8_t *v = colon + 1;
            size_t vl = ll - nl - 1;
            if (nl == 10 && strncasecmp((const char *)h + pos, "content-id", 10) == 0) {
                char *id = trim_dup(v, vl);
                size_t l = strlen(id);
                free(p->content_id);
                if (l >= 2 && id[0] == '<' && id[l - 1] == '>') {
                    memmove(id, id + 1, l - 2);
                    id[l - 2] = 0;
                }
                p->content_id = id;
            } else if (nl == 12 && strncasecmp((const char *)h + pos, "content-type", 12) == 0) {
                free(p->content_type);
                p->content_type = trim_dup(v, vl);
            }
        }
        pos += ll + (eol != NULL ? 1 : 0);
    }
    return 0;
}

int g5c_mp_parse(const char *ct, const uint8_t *body, size_t len, g5c_mp *out)
{
    char bnd[MAX_BOUNDARY + 1], delim[MAX_BOUNDARY + 8];
    size_t dl;
    const uint8_t *p, *end = body + len;
    memset(out, 0, sizeof *out);
    if (ct == NULL || !g5c_mp_is_multipart(ct) || boundary_of(ct, bnd) != 0)
        return -1;
    dl = (size_t)snprintf(delim, sizeof delim, "\r\n--%s", bnd);
    /* the first delimiter may sit at the very start (no preceding CRLF) */
    if (len >= dl - 2 && memcmp(body, delim + 2, dl - 2) == 0) {
        p = body + dl - 2;
    } else {
        p = find_mem(body, len, (const uint8_t *)delim, dl);
        if (p == NULL)
            return -1;
        p += dl;
    }
    for (;;) {
        const uint8_t *hs, *he, *next;
        g5c_mp_part *part;
        if (end - p >= 2 && p[0] == '-' && p[1] == '-') { /* close delimiter */
            if (out->n > 0)
                return 0;
            return -1;
        }
        while (p < end && (*p == ' ' || *p == '\t')) /* transport padding */
            p++;
        if (end - p < 2 || p[0] != '\r' || p[1] != '\n')
            goto bad;
        p += 2;
        hs = p;
        if (end - p >= 2 && p[0] == '\r' && p[1] == '\n') { /* no headers */
            he = p;
            p += 2;
        } else {
            he = find_mem(p, (size_t)(end - p), (const uint8_t *)"\r\n\r\n", 4);
            if (he == NULL)
                goto bad;
            p = he + 4;
        }
        next = find_mem(p, (size_t)(end - p), (const uint8_t *)delim, dl);
        if (next == NULL || out->n >= G5C_MP_MAX_PARTS)
            goto bad;
        part = &out->parts[out->n];
        memset(part, 0, sizeof *part);
        out->n++;
        if (part_headers(hs, (size_t)(he - hs), part) != 0)
            goto bad;
        part->data = p;
        part->len = (size_t)(next - p);
        p = next + dl;
        if (end - p < 2)
            goto bad;
    }
bad:
    g5c_mp_free(out);
    return -1;
}

int g5c_mp_build(const g5c_mp_part *parts, size_t n, g5c_bytes *body, char **ct)
{
    char bnd[33];
    uint8_t r[16];
    if (n == 0 || g5c_random(r, sizeof r) != 0)
        return -1;
    for (size_t i = 0; i < 16; i++)
        snprintf(bnd + 2 * i, 3, "%02x", r[i]);
    for (size_t i = 0; i < n; i++) {
        if (g5c_bytes_printf(body, "--%s\r\n", bnd) != 0)
            return -1;
        if (parts[i].content_type != NULL && g5c_bytes_printf(body, "Content-Type: %s\r\n", parts[i].content_type) != 0)
            return -1;
        if (parts[i].content_id != NULL && g5c_bytes_printf(body, "Content-Id: %s\r\n", parts[i].content_id) != 0)
            return -1;
        if (g5c_bytes_append_str(body, "\r\n") != 0 || (parts[i].len > 0 && g5c_bytes_append(body, parts[i].data, parts[i].len) != 0) ||
            g5c_bytes_append_str(body, "\r\n") != 0)
            return -1;
    }
    if (g5c_bytes_printf(body, "--%s--\r\n", bnd) != 0)
        return -1;
    *ct = g5c_xasprintf("multipart/related; boundary=%s", bnd);
    return 0;
}
