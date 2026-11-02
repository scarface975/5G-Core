/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* multipart/related bodies of the SBI (TS 29.500 clause 6.1.6.4, RFC 2387/2046) */
#ifndef G5C_MULTIPART_H
#define G5C_MULTIPART_H

#include <stddef.h>
#include <stdint.h>

#include "g5c/base.h"

#define G5C_MP_MAX_PARTS 8

typedef struct {
    char *content_id;   /* without angle brackets; NULL when the part has none */
    char *content_type; /* NULL when absent */
    const uint8_t *data;
    size_t len;
} g5c_mp_part;

typedef struct {
    g5c_mp_part parts[G5C_MP_MAX_PARTS];
    size_t n;
} g5c_mp;

/* `content_type` is the request's Content-Type header. 0, or -1 (not multipart/related, no boundary, malformed framing, too many parts) */
int g5c_mp_parse(const char *content_type, const uint8_t *body, size_t len, g5c_mp *out);
void g5c_mp_free(g5c_mp *m);
const g5c_mp_part *g5c_mp_find(const g5c_mp *m, const char *content_id);
/* True when a Content-Type header names multipart/related. */
int g5c_mp_is_multipart(const char *content_type);

/* Build a body from parts (the first one is the JSON part); *content_type receives the header value (caller frees) */
int g5c_mp_build(const g5c_mp_part *parts, size_t n, g5c_bytes *body, char **content_type);

#endif
