/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Tiny test helpers shared by all C unit tests. */
#ifndef G5C_TESTKIT_H
#define G5C_TESTKIT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline int tk_hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Decode hex into out (capacity cap). Returns the byte count, or -1 on bad input / overflow. */
static inline long tk_unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = strlen(s);
    if (n % 2 != 0 || n / 2 > cap)
        return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int h = tk_hexval(s[2 * i]), l = tk_hexval(s[2 * i + 1]);
        if (h < 0 || l < 0)
            return -1;
        out[i] = (uint8_t)(h * 16 + l);
    }
    return (long)(n / 2);
}

/* Like tk_unhex but spaces (and newlines) between digits are ignored: tk_hex("2001 000c", ...). */
static inline long tk_hex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    int hi = -1;
    for (; *s; s++) {
        int v;
        if (*s == ' ' || *s == 10 || *s == 9)
            continue;
        v = tk_hexval(*s);
        if (v < 0)
            return -1;
        if (hi < 0) {
            hi = v;
        } else {
            if (n == cap)
                return -1;
            out[n++] = (uint8_t)(hi * 16 + v);
            hi = -1;
        }
    }
    return hi < 0 ? (long)n : -1;
}

/* Deterministic xorshift64 generator for fuzz-style tests. */
typedef struct {
    uint64_t s;
} tk_rng;

static inline uint64_t tk_rng_next(tk_rng *r)
{
    uint64_t x = r->s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    r->s = x;
    return x;
}

static inline void tk_rng_bytes(tk_rng *r, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)(tk_rng_next(r) >> 24);
}

#define TK_FAIL(...)                                                                           \
    do {                                                                                       \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);                                            \
        printf(__VA_ARGS__);                                                                   \
        printf("\n");                                                                          \
        exit(1);                                                                               \
    } while (0)

#define TK_ASSERT(cond)                                                                        \
    do {                                                                                       \
        if (!(cond))                                                                           \
            TK_FAIL("assertion failed: %s", #cond);                                            \
    } while (0)

/* Compare got[0..n) with hex string `want`. */
#define TK_EQ_HEX(got, want, n)                                                                \
    do {                                                                                       \
        uint8_t w_[4096];                                                                      \
        if (tk_unhex((want), w_, sizeof w_) != (long)(n) || memcmp((got), w_, (n)) != 0)       \
            TK_FAIL("mismatch vs %s", (want));                                                 \
    } while (0)

#endif
