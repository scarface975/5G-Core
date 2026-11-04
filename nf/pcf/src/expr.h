/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The condition language of policy scripts (nf/pcf/src/expr.c). */
#ifndef G5C_PCF_EXPR_H
#define G5C_PCF_EXPR_H

#include <stdbool.h>
#include <stddef.h>

typedef struct pcf_expr pcf_expr;

/* What a condition can see of a session. Strings may be NULL (empty). */
typedef struct {
    const char *supi, *dnn, *sd;
    int sst;
    int qi5;
} pcf_expr_ctx;

/* NULL with a message in err on a syntax error, an unknown field or an expression over the limits (400 characters, 64 nodes, 16 levels). */
pcf_expr *pcf_expr_parse(const char *src, char *err, size_t cap);
bool pcf_expr_eval(const pcf_expr *e, const pcf_expr_ctx *c);
void pcf_expr_free(pcf_expr *e);

#endif
