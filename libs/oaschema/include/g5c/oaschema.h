/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Validation of JSON bodies against the schemas of the pinned 3GPP OpenAPI files, from a pool that tools/oa_pool.py flattened
 * (a compact JSON array of schemas; a reference is {"$": index}). Used by the producers that validate what they are sent (UDR, NSSF). */
#ifndef G5C_OASCHEMA_H
#define G5C_OASCHEMA_H

#include <stddef.h>

#include "g5c/json.h"

typedef struct oa_schemas oa_schemas;

/* The pool text in pieces (a single literal would exceed the portable limit) and the number of schemas it must hold. */
oa_schemas *oa_schemas_load(const char *const *chunks, size_t nchunks, size_t count, char *err, size_t errcap);
void oa_schemas_free(oa_schemas *s);
/* 0 when `doc` conforms to schema `id` (a negative id accepts anything); otherwise -1 and "<json pointer>: <reason>" in err. Members the
 * schema does not describe are accepted (the 3GPP schemas are open); references into specifications that are not pinned accept anything;
 * `oneOf` accepts when one alternative matches. Thread-safe. */
int oa_validate(const oa_schemas *s, int id, const g5c_json *doc, char *err, size_t errcap);
const g5c_json *oa_schema_node(const oa_schemas *s, int id);

#endif
