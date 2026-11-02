/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The store the UDR tests run on */
#ifndef G5C_UDR_STORE_ENV_H
#define G5C_UDR_STORE_ENV_H

#include <stdio.h>
#include <stdlib.h>

#include "g5c/udr.h"

static inline g5c_udr_store *test_store_new(void)
{
    const char *pg = getenv("G5C_UDR_TEST_PG");
    char err[256];
    if (pg != NULL && pg[0] != '\0') {
        g5c_udr_store *s = g5c_udr_store_postgres(pg, 4, err, sizeof err);
        g5c_json *ids;
        if (s == NULL) {
            fprintf(stderr, "cannot open the test database: %s\n", err);
            exit(1);
        }
        ids = g5c_udr_ids(s);
        for (size_t i = 0; i < g5c_json_len(ids); i++)
            (void)g5c_udr_remove(s, g5c_json_str(g5c_json_at(ids, i)));
        g5c_json_free(ids);
        (void)g5c_udr_remove(s, "_"); /* the global partition: subscriptions and aliases */
        (void)g5c_udr_remove(s, "group:g1");
        return s;
    }
    return g5c_udr_store_memory();
}

#endif
