/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The state file: the bindings as JSON, written atomically (write to a temporary file, rename). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "priv.h"

void bsf_state_save(bsf *b)
{
    g5c_json *root, *arr;
    char *text, *tmp;
    FILE *f;
    size_t len = 0;
    bool ok = false;
    if (b->cfg->state_file == NULL)
        return;
    root = g5c_json_new_obj();
    arr = g5c_json_set(root, "bindings", g5c_json_new_arr());
    pthread_mutex_lock(&b->mu);
    for (size_t i = 0; i < b->nall; i++) {
        g5c_json *e = g5c_json_push(arr, g5c_json_new_obj());
        g5c_json_set_str(e, "id", b->all[i]->id);
        g5c_json_set(e, "binding", g5c_json_dup(b->all[i]->doc));
    }
    pthread_mutex_unlock(&b->mu);
    text = g5c_json_to_string(root, &len);
    g5c_json_free(root);
    tmp = g5c_xasprintf("%s.tmp", b->cfg->state_file);
    f = text != NULL ? fopen(tmp, "wb") : NULL;
    if (f != NULL) {
        ok = fwrite(text, 1, len, f) == len && fflush(f) == 0;
        if (fclose(f) != 0)
            ok = false;
        ok = ok && rename(tmp, b->cfg->state_file) == 0;
        if (!ok)
            (void)remove(tmp);
    }
    if (!ok)
        G5C_LOGE("g5c_bsf", "cannot write the state file %s", b->cfg->state_file);
    free(tmp);
    free(text);
}

int bsf_state_load(bsf *b, char *err, size_t errcap)
{
    size_t len = 0;
    char *text;
    g5c_json *root;
    const g5c_json *arr;
    size_t dropped = 0;
    if (b->cfg->state_file == NULL)
        return 0;
    text = g5c_read_file(b->cfg->state_file, 512U << 20, &len);
    if (text == NULL) { /* first start: the file is created when something changes */
        FILE *f = fopen(b->cfg->state_file, "ab");
        if (f == NULL) {
            snprintf(err, errcap, "cannot create the state file %s", b->cfg->state_file);
            return -1;
        }
        fclose(f);
        return 0;
    }
    root = len > 0 ? g5c_json_parse(text, len, err, errcap) : g5c_json_new_obj();
    free(text);
    if (root == NULL || !g5c_json_is(root, G5C_J_OBJECT)) {
        if (root != NULL)
            snprintf(err, errcap, "%s: not a JSON object", b->cfg->state_file);
        g5c_json_free(root);
        return -1;
    }
    arr = g5c_json_get(root, "bindings");
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const g5c_json *x = g5c_json_at(arr, i);
        char e[160];
        if (!bsf_insert_doc(b, g5c_json_get_str(x, "id"), g5c_json_get(x, "binding"), e, sizeof e))
            dropped++;
    }
    if (dropped > 0)
        G5C_LOGW("g5c_bsf", "%zu bindings of the state file were not valid and are dropped", dropped);
    g5c_json_free(root);
    return 0;
}
