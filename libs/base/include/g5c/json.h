/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Small JSON DOM (RFC 8259). Strict parser with depth limit, insertion-ordered objects, last duplicate key wins. */
#ifndef G5C_JSON_H
#define G5C_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "g5c/base.h"

#define G5C_JSON_MAX_DEPTH 64

typedef enum {
    G5C_J_NULL,
    G5C_J_BOOL,
    G5C_J_INT,
    G5C_J_DOUBLE,
    G5C_J_STRING,
    G5C_J_ARRAY,
    G5C_J_OBJECT
} g5c_jtype;

typedef struct g5c_json g5c_json;

/* Parse; returns NULL and fills err (if non-NULL) on failure. Trailing garbage is an error. */
g5c_json *g5c_json_parse(const char *s, size_t len, char *err, size_t errcap);
void g5c_json_free(g5c_json *j);

g5c_jtype g5c_json_type(const g5c_json *j);
bool g5c_json_is(const g5c_json *j, g5c_jtype t);

/* Accessors; all are NULL/false-safe and return NULL/false for a wrong type. */
const g5c_json *g5c_json_get(const g5c_json *obj, const char *key);
size_t g5c_json_len(const g5c_json *arr_or_obj);
const g5c_json *g5c_json_at(const g5c_json *arr, size_t i);
const char *g5c_json_key_at(const g5c_json *obj, size_t i);
const g5c_json *g5c_json_val_at(const g5c_json *obj, size_t i);
const char *g5c_json_str(const g5c_json *j);
bool g5c_json_int(const g5c_json *j, int64_t *out);
bool g5c_json_bool(const g5c_json *j, bool *out);
bool g5c_json_num(const g5c_json *j, double *out); /* INT or DOUBLE */

/* Shorthand lookups on objects. */
const char *g5c_json_get_str(const g5c_json *obj, const char *key);
bool g5c_json_get_int(const g5c_json *obj, const char *key, int64_t *out);
bool g5c_json_get_bool(const g5c_json *obj, const char *key, bool *out);

/* Construction. Containers take ownership of inserted values. */
g5c_json *g5c_json_new_null(void);
g5c_json *g5c_json_new_bool(bool b);
g5c_json *g5c_json_new_int(int64_t i);
g5c_json *g5c_json_new_double(double d);
g5c_json *g5c_json_new_str(const char *s);
g5c_json *g5c_json_new_strn(const char *s, size_t n);
g5c_json *g5c_json_new_arr(void);
g5c_json *g5c_json_new_obj(void);

/* Sets (replacing an existing key) and returns val. obj must be an object; otherwise val is freed, NULL returned. */
g5c_json *g5c_json_set(g5c_json *obj, const char *key, g5c_json *val);
g5c_json *g5c_json_set_str(g5c_json *obj, const char *key, const char *s);
g5c_json *g5c_json_set_int(g5c_json *obj, const char *key, int64_t i);
g5c_json *g5c_json_set_bool(g5c_json *obj, const char *key, bool b);
g5c_json *g5c_json_push(g5c_json *arr, g5c_json *val);
g5c_json *g5c_json_push_str(g5c_json *arr, const char *s);
bool g5c_json_remove(g5c_json *obj, const char *key);
/* Removes and returns the value for key (caller owns it), or NULL. */
g5c_json *g5c_json_detach(g5c_json *obj, const char *key);
/* Mutable lookup. */
g5c_json *g5c_json_get_mut(g5c_json *obj, const char *key);

/* Mutable array access (used by JSON Patch). Index operations return false/NULL when out of range. */
g5c_json *g5c_json_at_mut(g5c_json *arr, size_t i);
bool g5c_json_arr_insert(g5c_json *arr, size_t i, g5c_json *val); /* i <= len; on failure val is freed */
bool g5c_json_arr_remove(g5c_json *arr, size_t i);
bool g5c_json_arr_replace(g5c_json *arr, size_t i, g5c_json *val); /* i < len; on failure val is freed */

g5c_json *g5c_json_dup(const g5c_json *j);
bool g5c_json_equal(const g5c_json *a, const g5c_json *b);

/* Serialise compactly; returns 0 / -1. */
int g5c_json_write(const g5c_json *j, g5c_bytes *out);
/* Convenience: heap string (caller frees). */
char *g5c_json_to_string(const g5c_json *j, size_t *len);

/* ---- YAML subset (configuration files) -------------------------------------
 * Block mappings/sequences by indentation, flow {..} and [..], quoted and plain scalars, comments.
 * Plain scalars become bool/int/null when unambiguous (leading zeros stay strings: 001 is "001"). Anchors, tags,
 * multi-line scalars and multiple documents are rejected. */
g5c_json *g5c_yaml_parse(const char *s, size_t len, char *err, size_t errcap);

/* ---- JSON Patch (RFC 6902): add, replace, remove ---------------------------------------------------- */

typedef enum { G5C_PATCH_OK = 0, G5C_PATCH_ITEM = -1, G5C_PATCH_PATH = -2 } g5c_patch_rc;

/* Apply `items` (an array) to *doc in order. On error the document may be partially modified: patch a copy when
 * atomicity matters. *doc may be replaced (patch of the root). err gets a message (may be NULL). */
int g5c_json_patch(g5c_json **doc, const g5c_json *items, char *err, size_t errcap);


#endif
