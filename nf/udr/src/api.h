/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* UDR internals: the generated API tables (tools/gen_udr_api.py), the schema validator and the storage interface. */
#ifndef G5C_UDR_API_H
#define G5C_UDR_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "g5c/json.h"
#include "g5c/oaschema.h"

/* ---- generated tables ---- */

typedef enum { UDR_PART_UE, UDR_PART_GROUP, UDR_PART_GLOBAL } udr_part_kind;

#define UDR_CT_JSON 1u
#define UDR_CT_JSON_PATCH 2u
#define UDR_CT_MERGE_PATCH 4u
#define UDR_OK_200 1u
#define UDR_OK_201 2u
#define UDR_OK_204 4u

/* One operation of TS 29.505 / TS 29.519. The partition of a resource is the subscriber, the group or the global one */
typedef struct {
    const char *method, *path, *op, *src;
    int req_schema, resp_schema, resp201_schema; /* index into the schema pool, -1 none */
    unsigned req_ct;
    int has_fields; /* the operation takes the `fields` query parameter */
    unsigned ok_mask;
    udr_part_kind part;
    const char *key;
    bool coll;        /* the path is a collection: a template with one more {parameter} segment exists */
    bool post_create; /* POST that creates a child with a server-allocated id */
    const char *query;
} udr_op_def;

extern const udr_op_def udr_ops[];
extern const size_t udr_ops_count;

/* A GET of `parent` assembles the member `prop` from the document (or the collection) at `child`. */
typedef struct {
    const char *parent, *prop, *child;
    bool list;
} udr_composite;
extern const udr_composite udr_composites[];
extern const size_t udr_composites_count;

extern const char *const udr_schema_chunks[];
extern const size_t udr_schema_nchunks;
extern const size_t udr_schema_count;

/* ---- schema validation (schema.c) ---- */

typedef oa_schemas udr_schemas;
udr_schemas *udr_schemas_load(char *err, size_t errcap);
void udr_schemas_free(udr_schemas *s);
/* 0 when `doc` conforms to schema `id`; otherwise -1 and "<json pointer>: <reason>" in err */
int udr_schema_validate(const udr_schemas *s, int id, const g5c_json *doc, char *err, size_t errcap);
/* The schema (JSON text of the simplified form) for diagnostics. */
const g5c_json *udr_schema_node(const udr_schemas *s, int id);

/* ---- storage interface ---- */

/* A stored document with its revision (the entity tag) and modification time (seconds since the epoch). */
typedef struct {
    g5c_json *doc; /* owned by whoever received the record */
    uint64_t rev;
    int64_t mtime;
} udr_rec;

typedef enum { UDR_COND_NONE = 0, UDR_COND_MATCH, UDR_COND_NOT_EXISTS, UDR_COND_EXISTS } udr_cond_kind;
typedef struct {
    udr_cond_kind kind;
    uint64_t rev; /* for UDR_COND_MATCH */
} udr_cond;

typedef struct {
    char **keys;
    udr_rec *recs;
    size_t n;
} udr_list;
void udr_list_free(udr_list *l);

/* Edits *doc in place (the backend hands it a private copy); a non-zero return aborts with err filled. */
typedef int (*udr_mutator)(g5c_json **doc, void *arg, char *err, size_t errcap);

/* Result codes of put/del/mutate. */
#define UDR_DB_OK 0
#define UDR_DB_PRECONDITION 1
#define UDR_DB_ABSENT 2
#define UDR_DB_REJECTED 3
#define UDR_DB_ERROR (-1)

typedef struct {
    const char *name;
    /* 1 found (rec filled), 0 absent, -1 error */
    int (*get)(void *self, const char *part, const char *key, udr_rec *out);
    /* Replace or create; takes doc. *created tells which */
    int (*put)(void *self, const char *part, const char *key, g5c_json *doc, const udr_cond *c, bool *created,
               udr_rec *out, udr_rec *old);
    /* Remove; old (optional) receives the removed record. */
    int (*del)(void *self, const char *part, const char *key, const udr_cond *c, udr_rec *old);
    /* Read-modify-write atomically. out (optional) receives the new record (doc a copy), old (optional) the previous one. */
    int (*mutate)(void *self, const char *part, const char *key, udr_mutator fn, void *arg, const udr_cond *c,
                  udr_rec *out, udr_rec *old, char *err, size_t errcap);
    /* Every record of the partition whose key starts with "<prefix>/", in key order. */
    int (*list)(void *self, const char *part, const char *prefix, udr_list *out);
    /* 1 when the partition holds at least one record. */
    int (*part_exists)(void *self, const char *part);
    /* Sorted array of the partition names (strings) appended to out. */
    int (*parts)(void *self, g5c_json *out);
    /* Remove the whole partition; 1 when it existed. */
    int (*del_part)(void *self, const char *part);
    /* Number of records (for the gauge). */
    size_t (*count)(void *self);
    void (*close)(void *self);
} udr_db_ops;

typedef struct {
    const udr_db_ops *ops;
    void *self;
} udr_db;

udr_db *udr_db_memory(void);
/* Memory with write-behind persistence in a snapshot + journal (path, path.journal). NULL + err on a bad file. */
udr_db *udr_db_file(const char *path, char *err, size_t errcap);
/* PostgreSQL through libpq (db_pg.c); NULL + err when the build has no libpq or the server is unreachable. */
udr_db *udr_db_postgres(const char *conninfo, int pool, char *err, size_t errcap);
void udr_db_free(udr_db *d);

/* The precondition against the current state: true when the write may go on. */
bool udr_cond_ok(const udr_cond *c, bool exists, uint64_t rev);
uint64_t udr_etag_rev(const char *etag); /* parse "\"<hex>\"" (W/ accepted); 0 when malformed */
char *udr_etag_str(uint64_t rev);        /* "\"<hex>\"" */

/* RFC 7396 merge patch into *doc. */
void udr_merge_patch(g5c_json **doc, const g5c_json *patch);

#endif
