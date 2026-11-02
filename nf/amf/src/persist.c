/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Externalised UE contexts (the "stateless-ready" requirement): registered UEs are written to a state file as one JSON document and read back at
 * start-up, so that a restarted AMF still knows the GUTI, the security context and the PDU session references of its UEs. The file is the
 * complete state of the idle contexts; it is rewritten atomically (coalesced) after changes. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "priv.h"

static g5c_json *hexj(const uint8_t *p, size_t n)
{
    char *h = g5c_hex_encode(p, n);
    g5c_json *j = g5c_json_new_str(h);
    free(h);
    return j;
}

static g5c_json *snssai_obj(const nas_snssai *s)
{
    g5c_json *o = g5c_json_new_obj();
    g5c_json_set_int(o, "sst", s->sst);
    if (s->has_sd)
        g5c_json_set_int(o, "sd", s->sd);
    return o;
}

static bool snssai_from(const g5c_json *o, nas_snssai *s)
{
    int64_t v;
    memset(s, 0, sizeof *s);
    if (!g5c_json_get_int(o, "sst", &v) || v < 0 || v > 255)
        return false;
    s->sst = (uint8_t)v;
    if (g5c_json_get_int(o, "sd", &v) && v >= 0 && v <= 0xffffff) {
        s->has_sd = true;
        s->sd = (uint32_t)v;
    }
    return true;
}

g5c_json *amf_ue_to_json(const amf_ue *u)
{
    g5c_json *o = g5c_json_new_obj(), *s, *arr;
    g5c_json_set_str(o, "supi", u->supi);
    if (u->pei[0] != 0)
        g5c_json_set_str(o, "pei", u->pei);
    g5c_json_set_int(o, "tmsi", u->tmsi);
    s = g5c_json_set(o, "sec", g5c_json_new_obj());
    g5c_json_set_int(s, "ngksi", u->sec.ngksi);
    g5c_json_set(s, "kamf", hexj(u->sec.kamf, 32));
    g5c_json_set(s, "abba", hexj(u->sec.abba, 2));
    g5c_json_set_int(s, "int", u->sec.int_alg);
    g5c_json_set_int(s, "enc", u->sec.enc_alg);
    g5c_json_set_int(s, "ul", u->sec.ul_count);
    g5c_json_set_int(s, "dl", u->sec.dl_count);
    g5c_json_set(s, "cap", hexj(u->ue_cap, u->ue_cap_len));
    arr = g5c_json_set(o, "allowed", g5c_json_new_arr());
    for (size_t i = 0; i < u->nallowed; i++)
        g5c_json_push(arr, snssai_obj(&u->allowed[i]));
    arr = g5c_json_set(o, "subscribed", g5c_json_new_arr());
    for (size_t i = 0; i < u->nsubscribed; i++)
        g5c_json_push(arr, snssai_obj(&u->subscribed[i]));
    g5c_json_set_int(o, "ndefault", (int64_t)u->ndefault);
    g5c_json_set_int(o, "ambr_ul", (int64_t)u->ambr_ul);
    g5c_json_set_int(o, "ambr_dl", (int64_t)u->ambr_dl);
    arr = g5c_json_set(o, "tais", g5c_json_new_arr());
    for (size_t i = 0; i < u->ntai; i++) {
        g5c_json *t = g5c_json_push(arr, g5c_json_new_obj());
        g5c_json_set(t, "plmn", hexj(u->tai_list[i].plmn, 3));
        g5c_json_set_int(t, "tac", u->tai_list[i].tac);
    }
    if (u->has_loc) {
        g5c_json *t = g5c_json_set(o, "loc", g5c_json_new_obj());
        g5c_json_set(t, "plmn", hexj(u->loc.plmn, 3));
        g5c_json_set_int(t, "tac", u->loc.tac);
    }
    if (u->pcf_url[0] != 0)
        g5c_json_set_str(o, "pcf", u->pcf_url);
    g5c_json_set_bool(o, "uecm", u->uecm);
    g5c_json_set_bool(o, "sdm", u->sdm_subscribed);
    if (u->sdm_sub_id[0] != 0)
        g5c_json_set_str(o, "sdmId", u->sdm_sub_id);
    g5c_json_set_int(o, "reg_type", u->reg_type);
    arr = g5c_json_set(o, "pdus", g5c_json_new_arr());
    for (unsigned i = 1; i <= AMF_MAX_PSI; i++) {
        const amf_pdu *p = &u->pdu[i];
        g5c_json *e;
        if (!p->used)
            continue;
        e = g5c_json_push(arr, g5c_json_new_obj());
        g5c_json_set_int(e, "psi", i);
        g5c_json_set_str(e, "url", p->sm_url);
        g5c_json_set_str(e, "dnn", p->dnn);
        if (p->has_snssai)
            g5c_json_set(e, "snssai", snssai_obj(&p->snssai));
    }
    return o;
}

amf_ue *amf_ue_from_json(amf *a, const g5c_json *j)
{
    const char *supi = g5c_json_get_str(j, "supi");
    const g5c_json *s = g5c_json_get(j, "sec"), *arr;
    amf_ue *u;
    int64_t v;
    uint8_t b[64];
    if (supi == NULL || strlen(supi) >= sizeof u->supi || s == NULL)
        return NULL;
    u = amf_ue_get_or_create(a, supi);
    pthread_mutex_lock(&u->mu);
    if (g5c_json_get_str(j, "pei") != NULL)
        snprintf(u->pei, sizeof u->pei, "%s", g5c_json_get_str(j, "pei"));
    if (g5c_json_get_int(s, "ngksi", &v))
        u->sec.ngksi = (uint8_t)v;
    if (g5c_json_get_str(s, "kamf") != NULL && g5c_hex_decode(g5c_json_get_str(s, "kamf"), b, 32) == 32)
        memcpy(u->sec.kamf, b, 32);
    if (g5c_json_get_str(s, "abba") != NULL && g5c_hex_decode(g5c_json_get_str(s, "abba"), b, 2) == 2)
        memcpy(u->sec.abba, b, 2);
    if (g5c_json_get_int(s, "int", &v))
        u->sec.int_alg = (uint8_t)v;
    if (g5c_json_get_int(s, "enc", &v))
        u->sec.enc_alg = (uint8_t)v;
    if (g5c_json_get_int(s, "ul", &v))
        u->sec.ul_count = (uint32_t)v;
    if (g5c_json_get_int(s, "dl", &v))
        u->sec.dl_count = (uint32_t)v + 128u; /* messages may have followed the last write: stay above what the UE expects */
    {
        long n = g5c_json_get_str(s, "cap") != NULL ? g5c_hex_decode(g5c_json_get_str(s, "cap"), b, sizeof u->ue_cap) : 0;
        if (n > 0) {
            memcpy(u->ue_cap, b, (size_t)n);
            u->ue_cap_len = (size_t)n;
        }
    }
    u->sec.valid = true;
    sec_derive_nas_keys(&u->sec);
    arr = g5c_json_get(j, "allowed");
    for (size_t i = 0; i < g5c_json_len(arr) && u->nallowed < AMF_MAX_SLICE; i++)
        if (snssai_from(g5c_json_at(arr, i), &u->allowed[u->nallowed]))
            u->nallowed++;
    arr = g5c_json_get(j, "subscribed");
    for (size_t i = 0; i < g5c_json_len(arr) && u->nsubscribed < AMF_MAX_SLICE; i++)
        if (snssai_from(g5c_json_at(arr, i), &u->subscribed[u->nsubscribed]))
            u->nsubscribed++;
    if (g5c_json_get_int(j, "ndefault", &v) && v >= 0 && (size_t)v <= u->nsubscribed)
        u->ndefault = (size_t)v;
    if (g5c_json_get_int(j, "ambr_ul", &v) && v >= 0)
        u->ambr_ul = (uint64_t)v;
    if (g5c_json_get_int(j, "ambr_dl", &v) && v >= 0)
        u->ambr_dl = (uint64_t)v;
    arr = g5c_json_get(j, "tais");
    for (size_t i = 0; i < g5c_json_len(arr) && u->ntai < AMF_MAX_TAI; i++) {
        const g5c_json *t = g5c_json_at(arr, i);
        amf_tai *d = &u->tai_list[u->ntai];
        if (g5c_json_get_str(t, "plmn") != NULL && g5c_hex_decode(g5c_json_get_str(t, "plmn"), d->plmn, 3) == 3 && g5c_json_get_int(t, "tac", &v)) {
            d->tac = (uint32_t)v;
            u->ntai++;
        }
    }
    if (g5c_json_get(j, "loc") != NULL) {
        const g5c_json *t = g5c_json_get(j, "loc");
        if (g5c_json_get_str(t, "plmn") != NULL && g5c_hex_decode(g5c_json_get_str(t, "plmn"), u->loc.plmn, 3) == 3 && g5c_json_get_int(t, "tac", &v)) {
            u->loc.tac = (uint32_t)v;
            u->has_loc = true;
        }
    }
    if (g5c_json_get_str(j, "pcf") != NULL)
        snprintf(u->pcf_url, sizeof u->pcf_url, "%s", g5c_json_get_str(j, "pcf"));
    {
        bool b2;
        if (g5c_json_get_bool(j, "uecm", &b2))
            u->uecm = b2;
        if (g5c_json_get_bool(j, "sdm", &b2))
            u->sdm_subscribed = b2;
        if (g5c_json_get_str(j, "sdmId") != NULL)
            snprintf(u->sdm_sub_id, sizeof u->sdm_sub_id, "%s", g5c_json_get_str(j, "sdmId"));
    }
    if (g5c_json_get_int(j, "reg_type", &v))
        u->reg_type = (uint8_t)v;
    arr = g5c_json_get(j, "pdus");
    for (size_t i = 0; i < g5c_json_len(arr); i++) {
        const g5c_json *e = g5c_json_at(arr, i);
        int64_t psi;
        if (g5c_json_get_int(e, "psi", &psi) && psi >= 1 && psi <= AMF_MAX_PSI && g5c_json_get_str(e, "url") != NULL) {
            amf_pdu *p = &u->pdu[psi];
            p->used = true;
            snprintf(p->sm_url, sizeof p->sm_url, "%s", g5c_json_get_str(e, "url"));
            if (g5c_json_get_str(e, "dnn") != NULL)
                snprintf(p->dnn, sizeof p->dnn, "%s", g5c_json_get_str(e, "dnn"));
            if (snssai_from(g5c_json_get(e, "snssai"), &p->snssai))
                p->has_snssai = true;
        }
    }
    if (g5c_json_get_int(j, "tmsi", &v) && v > 0)
        amf_ue_set_tmsi(u, (uint32_t)v);
    u->mm = MM_REGISTERED;
    u->cm = CM_IDLE;
    ue_timer_start(u, UT_REACH, a->cfg.t3512 + a->cfg.reach_grace);
    pthread_mutex_unlock(&u->mu);
    return u; /* referenced */
}

/* ---- file ------------------------------------------------------------------------------------------------------------------------------------ */

void amf_persist_timer(amf *a)
{
    double t0 = g5c_now_seconds(), took;
    pthread_mutex_lock(&a->pmu);
    a->persist_dirty = false;
    pthread_mutex_unlock(&a->pmu);
    amf_persist_flush(a);
    /* the file is every registered UE: keep its cost to about a tenth of a core however many there are */
    took = g5c_now_seconds() - t0;
    pthread_mutex_lock(&a->pmu);
    a->persist_gap_ms = took * 10000.0 < AMF_PERSIST_GAP_MS ? AMF_PERSIST_GAP_MS : took * 10000.0 > 5000 ? 5000 : (unsigned)(took * 10000.0);
    pthread_mutex_unlock(&a->pmu);
}

/* write-behind: the file is rewritten (all registered UEs) at most once per AMF_PERSIST_GAP_MS, however many changes arrive in between */
void amf_persist_request(amf *a)
{
    bool arm = false;
    unsigned gap = AMF_PERSIST_GAP_MS;
    if (a->cfg.state_file == NULL)
        return;
    pthread_mutex_lock(&a->pmu);
    if (!a->persist_dirty) {
        a->persist_dirty = true;
        arm = true;
    }
    if (a->persist_gap_ms != 0)
        gap = a->persist_gap_ms;
    pthread_mutex_unlock(&a->pmu);
    if (arm && !a->stop)
        amf_timer_start(a, gap, 0, AMF_TIMER_PERSIST, 0, 0);
}

void amf_persist_flush(amf *a)
{
    amf_ue **list = NULL;
    size_t n = 0, cap = 0;
    g5c_json *doc, *arr;
    char *tmp, *txt;
    FILE *f;
    if (a->cfg.state_file == NULL)
        return;
    pthread_mutex_lock(&a->tmu);
    for (amf_ue *u = a->ues; u != NULL; u = u->next_all) {
        if (n == cap) {
            cap = cap != 0 ? cap * 2 : 32;
            list = g5c_xrealloc(list, cap * sizeof *list);
        }
        u->refs++;
        list[n++] = u;
    }
    pthread_mutex_unlock(&a->tmu);
    doc = g5c_json_new_obj();
    g5c_json_set_int(doc, "version", 1);
    g5c_json_set_str(doc, "amf", a->instance_id);
    arr = g5c_json_set(doc, "ues", g5c_json_new_arr());
    for (size_t i = 0; i < n; i++) {
        amf_ue *u = list[i];
        pthread_mutex_lock(&u->mu);
        if (u->mm == MM_REGISTERED && u->sec.valid && !u->removed)
            g5c_json_push(arr, amf_ue_to_json(u));
        pthread_mutex_unlock(&u->mu);
        amf_ue_unref(u);
    }
    free(list);
    txt = g5c_json_to_string(doc, NULL);
    g5c_json_free(doc);
    tmp = g5c_xasprintf("%s.tmp", a->cfg.state_file);
    f = fopen(tmp, "wb");
    if (f != NULL) {
        size_t l = strlen(txt);
        bool ok = fwrite(txt, 1, l, f) == l && fflush(f) == 0;
        ok = fclose(f) == 0 && ok;
        if (ok && rename(tmp, a->cfg.state_file) != 0)
            ok = false;
        if (!ok) {
            G5C_LOGW(AMF_LOG, "cannot write the state file %s: %s", a->cfg.state_file, strerror(errno));
            (void)unlink(tmp);
        }
    } else {
        G5C_LOGW(AMF_LOG, "cannot write the state file %s: %s", a->cfg.state_file, strerror(errno));
    }
    OPENSSL_cleanse(txt, strlen(txt));
    free(txt);
    free(tmp);
}

int amf_persist_restore(amf *a)
{
    size_t len = 0, n = 0;
    char *txt, err[120];
    g5c_json *doc;
    const g5c_json *ues;
    if (a->cfg.state_file == NULL)
        return 0;
    txt = g5c_read_file(a->cfg.state_file, 64u << 20, &len);
    if (txt == NULL)
        return 0;
    doc = g5c_json_parse(txt, len, err, sizeof err);
    OPENSSL_cleanse(txt, len);
    free(txt);
    if (doc == NULL) {
        G5C_LOGW(AMF_LOG, "the state file %s is unreadable (%s): starting empty", a->cfg.state_file, err);
        return -1;
    }
    ues = g5c_json_get(doc, "ues");
    for (size_t i = 0; i < g5c_json_len(ues); i++) {
        amf_ue *u = amf_ue_from_json(a, g5c_json_at(ues, i));
        if (u != NULL) {
            amf_ue_unref(u);
            n++;
        }
    }
    g5c_json_free(doc);
    G5C_LOGI(AMF_LOG, "restored %zu UE context(s) from %s", n, a->cfg.state_file);
    return 0;
}
