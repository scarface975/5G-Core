/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The UDR's schema pool (generated, api_schemas.gen.c) behind the shared validator of libs/oaschema. */
#include "api.h"

udr_schemas *udr_schemas_load(char *err, size_t errcap)
{
    return oa_schemas_load(udr_schema_chunks, udr_schema_nchunks, udr_schema_count, err, errcap);
}

void udr_schemas_free(udr_schemas *s)
{
    oa_schemas_free(s);
}

int udr_schema_validate(const udr_schemas *s, int id, const g5c_json *doc, char *err, size_t errcap)
{
    return oa_validate(s, id, doc, err, errcap);
}

const g5c_json *udr_schema_node(const udr_schemas *s, int id)
{
    return oa_schema_node(s, id);
}
