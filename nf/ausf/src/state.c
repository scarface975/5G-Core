/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* The state file of the AUSF */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "priv.h"

#define COUNTER_MARGIN 256
#define STATE_VERSION 1

static int wrap(const uint8_t key[32], const char *supi, const uint8_t kausf[32], char **hex)
{
    uint8_t buf[12 + 32 + 16];
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, rc = -1;
    if (c == NULL || g5c_random(buf, 12) != 0)
        goto done;
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, buf) != 1 || EVP_EncryptUpdate(c, NULL, &l, (const uint8_t *)supi, (int)strlen(supi)) != 1 ||
        EVP_EncryptUpdate(c, buf + 12, &l, kausf, 32) != 1 || l != 32 || EVP_EncryptFinal_ex(c, buf + 12 + 32, &l) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, buf + 12 + 32) != 1)
        goto done;
    *hex = g5c_hex_encode(buf, sizeof buf);
    rc = 0;
done:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

static int unwrap(const uint8_t key[32], const char *supi, const char *hex, uint8_t kausf[32])
{
    uint8_t buf[12 + 32 + 16];
    EVP_CIPHER_CTX *c;
    int l = 0, rc = -1;
    if (hex == NULL || strlen(hex) != 2 * sizeof buf || g5c_hex_decode(hex, buf, sizeof buf) != (long)sizeof buf)
        return -1;
    c = EVP_CIPHER_CTX_new();
    if (c == NULL)
        return -1;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, buf) == 1 && EVP_DecryptUpdate(c, NULL, &l, (const uint8_t *)supi, (int)strlen(supi)) == 1 &&
        EVP_DecryptUpdate(c, kausf, &l, buf + 12, 32) == 1 && l == 32 && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, buf + 12 + 32) == 1 &&
        EVP_DecryptFinal_ex(c, kausf + 32, &l) == 1)
        rc = 0;
    EVP_CIPHER_CTX_free(c);
    return rc;
}

typedef struct {
    char *supi, *snn;
    uint8_t kausf[32];
    int method;
    uint16_t cs, cu;
    int64_t t;
} snap_t;

typedef struct {
    snap_t *v;
    size_t n, cap;
} snaps_t;

static void collect(const char *key, void *val, void *arg)
{
    snaps_t *s = arg;
    ausf_ue *u = val;
    snap_t *e;
    (void)key;
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 256;
        s->v = g5c_xrealloc(s->v, s->cap * sizeof *s->v);
    }
    e = &s->v[s->n++];
    e->supi = g5c_xstrdup(u->supi);
    e->snn = g5c_xstrdup(u->snn != NULL ? u->snn : "");
    memcpy(e->kausf, u->kausf, 32);
    e->method = (int)u->method;
    e->cs = u->counter_sor;
    e->cu = u->counter_upu;
    e->t = u->t_ms;
}

int state_save(ausf *a)
{
    snaps_t s = {0};
    g5c_json *doc, *arr;
    char *text, *tmp;
    FILE *f;
    int rc = -1;
    if (a->o.state_file == NULL)
        return 0;
    pthread_mutex_lock(&a->mu);
    hmap_each(&a->ues, collect, &s);
    pthread_mutex_unlock(&a->mu);
    doc = g5c_json_new_obj();
    g5c_json_set_int(doc, "version", STATE_VERSION);
    arr = g5c_json_set(doc, "contexts", g5c_json_new_arr());
    for (size_t i = 0; i < s.n; i++) {
        g5c_json *e = g5c_json_push(arr, g5c_json_new_obj());
        char *w = NULL;
        uint32_t cs = (uint32_t)s.v[i].cs + COUNTER_MARGIN, cu = (uint32_t)s.v[i].cu + COUNTER_MARGIN;
        if (wrap(a->o.master_key, s.v[i].supi, s.v[i].kausf, &w) != 0) {
            g5c_json_free(doc);
            goto out;
        }
        g5c_json_set_str(e, "supi", s.v[i].supi);
        g5c_json_set_str(e, "snn", s.v[i].snn);
        g5c_json_set_str(e, "kausf", w);
        free(w);
        g5c_json_set_int(e, "method", s.v[i].method);
        g5c_json_set_int(e, "counterSor", cs > 0xFFFF ? 0xFFFF : cs);
        g5c_json_set_int(e, "counterUpu", cu > 0xFFFF ? 0xFFFF : cu);
        g5c_json_set_int(e, "time", s.v[i].t);
    }
    text = g5c_json_to_string(doc, NULL);
    g5c_json_free(doc);
    tmp = g5c_xasprintf("%s.tmp", a->o.state_file);
    f = fopen(tmp, "wb");
    if (f != NULL) {
        if (fputs(text, f) >= 0 && fflush(f) == 0 && fsync(fileno(f)) == 0 && fclose(f) == 0 && rename(tmp, a->o.state_file) == 0)
            rc = 0;
        else
            G5C_LOGE(AUSF_LOG, "cannot write %s: %s", a->o.state_file, strerror(errno));
    } else {
        G5C_LOGE(AUSF_LOG, "cannot open %s: %s", tmp, strerror(errno));
    }
    free(tmp);
    OPENSSL_cleanse(text, strlen(text));
    free(text);
out:
    for (size_t i = 0; i < s.n; i++) {
        free(s.v[i].supi);
        free(s.v[i].snn);
        OPENSSL_cleanse(s.v[i].kausf, 32);
    }
    free(s.v);
    return rc;
}

int ausf_flush(ausf *a)
{
    return state_save(a);
}

int state_load(ausf *a, char *err, size_t errcap)
{
    size_t len = 0;
    char *text, perr[160];
    g5c_json *doc;
    const g5c_json *arr;
    size_t loaded = 0;
    if (access(a->o.state_file, F_OK) != 0)
        return 0; /* the first start */
    text = g5c_read_file(a->o.state_file, 1ULL << 30, &len);
    if (text == NULL) {
        snprintf(err, errcap, "cannot read the state file %s", a->o.state_file);
        return -1;
    }
    doc = g5c_json_parse(text, len, perr, sizeof perr);
    OPENSSL_cleanse(text, len);
    free(text);
    if (doc == NULL) {
        snprintf(err, errcap, "the state file %s is not valid JSON: %s", a->o.state_file, perr);
        return -1;
    }
    arr = g5c_json_get(doc, "contexts");
    {
        int64_t v = 0;
        if (!g5c_json_get_int(doc, "version", &v) || v != STATE_VERSION || !g5c_json_is(arr, G5C_J_ARRAY)) {
            snprintf(err, errcap, "the state file %s has an unknown format", a->o.state_file);
            g5c_json_free(doc);
            return -1;
        }
    }
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const g5c_json *e = g5c_json_at(arr, i);
        const char *supi = g5c_json_get_str(e, "supi");
        int64_t cs = 1, cu = 1, m = M_5GAKA, t = 0;
        uint8_t k[32];
        ausf_ue *u;
        if (!ausf_valid_supi(supi) || unwrap(a->o.master_key, supi, g5c_json_get_str(e, "kausf"), k) != 0) {
            snprintf(err, errcap, "the state file %s does not decrypt with this master key (entry %zu)", a->o.state_file, i);
            g5c_json_free(doc);
            return -1;
        }
        (void)g5c_json_get_int(e, "counterSor", &cs);
        (void)g5c_json_get_int(e, "counterUpu", &cu);
        (void)g5c_json_get_int(e, "method", &m);
        (void)g5c_json_get_int(e, "time", &t);
        u = g5c_xcalloc(1, sizeof *u);
        u->supi = g5c_xstrdup(supi);
        u->snn = g5c_xstrdup(g5c_json_get_str(e, "snn") != NULL ? g5c_json_get_str(e, "snn") : "");
        memcpy(u->kausf, k, 32);
        OPENSSL_cleanse(k, sizeof k);
        u->method = m == M_EAP_PRIME ? M_EAP_PRIME : M_5GAKA;
        u->counter_sor = (uint16_t)(cs < 1 ? 1 : cs > 0xFFFF ? 0xFFFF : cs);
        u->counter_upu = (uint16_t)(cu < 1 ? 1 : cu > 0xFFFF ? 0xFFFF : cu);
        u->t_ms = t;
        hmap_put(&a->ues, supi, u);
        loaded++;
    }
    g5c_json_free(doc);
    G5C_LOGI(AUSF_LOG, "restored %zu security contexts from %s", loaded, a->o.state_file);
    return 0;
}

static void *writer_main(void *arg)
{
    ausf *a = arg;
    pthread_mutex_lock(&a->mu);
    while (!a->stop) {
        struct timespec t0, t1, ts;
        if (!a->dirty) {
            pthread_cond_wait(&a->cv, &a->mu);
            continue;
        }
        /* coalesce a burst: wait for a short gap, then write what is there */
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += (long)a->gap_ms * 1000000L;
        ts.tv_sec += ts.tv_nsec / 1000000000L;
        ts.tv_nsec %= 1000000000L;
        while (!a->stop && pthread_cond_timedwait(&a->cv, &a->mu, &ts) == 0)
            ; /* woken by another mark_dirty: keep the gap */
        if (a->stop)
            break;
        a->dirty = false;
        pthread_mutex_unlock(&a->mu);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (state_save(a) != 0) {
            pthread_mutex_lock(&a->mu);
            a->dirty = true; /* try again later */
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        pthread_mutex_lock(&a->mu);
        {
            long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
            a->gap_ms = ms * 4 > 100 ? (int)(ms * 4 > 5000 ? 5000 : ms * 4) : 100; /* a large store is not rewritten more often than it takes */
        }
    }
    pthread_mutex_unlock(&a->mu);
    return NULL;
}

void state_start_writer(ausf *a)
{
    a->stop = false;
    if (pthread_create(&a->writer, NULL, writer_main, a) == 0)
        a->writer_on = true;
}

void state_stop_writer(ausf *a)
{
    if (a->writer_on) {
        pthread_mutex_lock(&a->mu);
        a->stop = true;
        pthread_cond_broadcast(&a->cv);
        pthread_mutex_unlock(&a->mu);
        pthread_join(a->writer, NULL);
        a->writer_on = false;
    }
    if (a->o.state_file != NULL)
        (void)state_save(a); /* what was marked since the last write */
}
