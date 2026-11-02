/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Standalone driver for the libFuzzer targets, for compilers without -fsanitize=fuzzer (gcc) */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint64_t rng_state = 0x2545F4914F6CDD1DULL;

static uint64_t rnd(void)
{
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return rng_state = x;
}

static int hexv(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static void run(const uint8_t *d, size_t n, unsigned mutations)
{
    uint8_t *m = malloc(n + 16);
    LLVMFuzzerTestOneInput(d, n);
    for (size_t cut = 0; cut < n && cut < 512; cut++)
        LLVMFuzzerTestOneInput(d, cut);
    for (unsigned k = 0; k < mutations && n > 0; k++) {
        size_t len = n;
        memcpy(m, d, n);
        for (unsigned f = 0, flips = 1 + (unsigned)(rnd() % 4); f < flips; f++)
            m[rnd() % n] ^= (uint8_t)(1U << (rnd() % 8));
        if (rnd() % 8 == 0)
            len = (size_t)(rnd() % (n + 1));
        LLVMFuzzerTestOneInput(m, len);
    }
    free(m);
}

int main(int argc, char **argv)
{
    unsigned total = 0, mutations = getenv("G5C_FUZZ_MUTATIONS") ? (unsigned)strtoul(getenv("G5C_FUZZ_MUTATIONS"), NULL, 10) : 1500;
    for (int a = 1; a < argc; a++) {
        FILE *f = fopen(argv[a], "rb");
        char *buf;
        long sz;
        size_t len = strlen(argv[a]);
        if (f == NULL) {
            fprintf(stderr, "cannot open %s\n", argv[a]);
            return 2;
        }
        fseek(f, 0, SEEK_END);
        sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        buf = malloc((size_t)sz + 1);
        if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
            fclose(f);
            return 2;
        }
        buf[sz] = 0;
        fclose(f);
        if (len > 4 && strcmp(argv[a] + len - 4, ".hex") == 0) {
            char *save = NULL, *line;
            for (line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
                char *sp = strchr(line, ' ');
                uint8_t d[8192];
                size_t n = 0;
                if (!sp)
                    continue;
                for (sp++; hexv(sp[0]) >= 0 && hexv(sp[1]) >= 0 && n < sizeof d; sp += 2)
                    d[n++] = (uint8_t)(hexv(sp[0]) * 16 + hexv(sp[1]));
                run(d, n, mutations);
                total++;
            }
        } else {
            run((const uint8_t *)buf, (size_t)sz, mutations);
            total++;
        }
        free(buf);
    }
    printf("replayed %u inputs with mutations: no crash\n", total);
    return 0;
}
