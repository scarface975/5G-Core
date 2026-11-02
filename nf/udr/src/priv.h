/* SPDX-License-Identifier: LicenseRef-Proprietary */
#ifndef G5C_UDR_PRIV_H
#define G5C_UDR_PRIV_H

#include "api.h"
#include "g5c/udr.h"

#define UDR_GLOBAL_PART "_"
#define UDR_GROUP_PREFIX "group:"
#define UDR_ALIAS_KEY "alias" /* global partition: alias/<gpsi> -> {"supi": ...} */

struct g5c_udr_store {
    udr_db *db;
    void **owned;
    size_t nowned;
    g5c_udr *svc; /* service created by g5c_udr_router*, freed with the store */
};

typedef struct udr_notifier udr_notifier;
udr_notifier *udr_notifier_new(g5c_udr *u);
void udr_notifier_free(udr_notifier *n);
udr_notifier *udr_notifier_of(g5c_udr *u);
/* A document changed (before / after NULL when it did not exist / no longer exists; key NULL: the whole partition).
 * `suppress`: the 3gpp-Sbi-Notification-Correlation header of the request (subscriptions that are not to be notified). */
void udr_notify(g5c_udr *u, const char *part, const char *key, const g5c_json *before, const g5c_json *after,
                const char *suppress);
bool udr_is_subscription_key(const char *key);
void udr_subscriptions_changed(g5c_udr *u);
size_t udr_subscription_count(g5c_udr *u, const char *collection_key);
void udr_register_groupid_routes(g5c_udr *u, g5c_router *r);
/* memory the service frees with itself (route contexts) */
void udr_track_alloc(g5c_udr *u, void *p);
udr_db *udr_db_get(g5c_udr *u);
const udr_opts *udr_opts_get(const g5c_udr *u);

/* the partition of a subscriber (GPSI aware), a group or the global one */
char *udr_part_for_id(g5c_udr *u, udr_part_kind kind, const char *id);
/* the (partition, key) a resource URI of this API names */
bool udr_resolve_uri(g5c_udr *u, const char *uri, char **part, char **key);

/* S-NSSAI equality: sd FFFFFF is the same as no sd (TS 23.003 28.4.2) */
bool udr_snssai_equal(const g5c_json *a, const g5c_json *b);

/* date formats (timeutil.c) */
int64_t udr_parse_http_date(const char *s);
void udr_http_date(int64_t t, char *out, size_t cap);
int64_t udr_parse_rfc3339(const char *s);
void udr_rfc3339(int64_t t, char *out, size_t cap);

#endif
