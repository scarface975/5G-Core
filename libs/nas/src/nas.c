/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* Table-driven NAS framing: decode/encode every 5GMM and 5GSM message from the generated message tables. */
#include "g5c/nas.h"

#include <stdlib.h>
#include <string.h>

const char *nas_strerror(int err)
{
    switch (err) {
    case NAS_OK: return "ok";
    case NAS_E_TRUNCATED: return "truncated NAS message";
    case NAS_E_EPD: return "unknown extended protocol discriminator";
    case NAS_E_MSGTYPE: return "unknown message type";
    case NAS_E_MISSING: return "mandatory IE missing";
    case NAS_E_PROTECTED: return "security-protected message";
    case NAS_E_INVALID: return "IE value invalid";
    case NAS_E_SECURITY: return "security processing failed";
    case NAS_E_TOO_MANY_IES: return "too many IEs";
    default: return "error";
    }
}

const nas_msgdef *nas_lookup(nas_proto proto, uint8_t msg_type)
{
    for (size_t i = 0; i < NAS_NMESSAGES; i++)
        if (NAS_MESSAGES[i].proto == proto && NAS_MESSAGES[i].msg_type == msg_type)
            return &NAS_MESSAGES[i];
    return NULL;
}

const nas_msgdef *nas_lookup_name(const char *name)
{
    for (size_t i = 0; i < NAS_NMESSAGES; i++)
        if (strcmp(NAS_MESSAGES[i].name, name) == 0)
            return &NAS_MESSAGES[i];
    return NULL;
}

bool nas_msg_init(nas_msg *m, const char *name)
{
    memset(m, 0, sizeof *m);
    m->def = nas_lookup_name(name);
    return m->def != NULL;
}

void nas_msg_free(nas_msg *m)
{
    for (size_t i = 0; i < m->nies; i++)
        free(m->ies[i].value);
    free(m->ies);
    memset(m, 0, sizeof *m);
}

const char *nas_msg_name(const nas_msg *m)
{
    return m->def ? m->def->name : "";
}

const uint8_t *nas_msg_get(const nas_msg *m, const char *name, size_t *len)
{
    for (size_t i = 0; i < m->nies; i++)
        if (strcmp(m->ies[i].name, name) == 0) {
            if (len)
                *len = m->ies[i].len;
            return m->ies[i].value;
        }
    return NULL;
}

/* Append an IE (copying the value); returns false when over the IE limit. */
static bool add_ie(nas_msg *m, const char *name, int16_t iei, uint8_t format, const uint8_t *v, size_t n)
{
    nas_ie *e;
    if (m->nies >= NAS_MAX_IES)
        return false;
    if (m->nies == m->cap) {
        m->cap = m->cap ? m->cap * 2 : 8;
        m->ies = g5c_xrealloc(m->ies, m->cap * sizeof *m->ies);
    }
    e = &m->ies[m->nies++];
    e->name = name;
    e->iei = iei;
    e->format = format;
    e->value = g5c_xmalloc(n ? n : 1);
    if (n)
        memcpy(e->value, v, n);
    e->len = n;
    return true;
}

bool nas_msg_set(nas_msg *m, const char *name, const uint8_t *value, size_t len)
{
    const nas_iedef *d = NULL;
    for (size_t i = 0; i < m->def->nies; i++)
        if (strcmp(m->def->ies[i].name, name) == 0) {
            d = &m->def->ies[i];
            break;
        }
    if (d == NULL)
        return false;
    for (size_t i = 0; i < m->nies; i++)
        if (strcmp(m->ies[i].name, name) == 0) {
            free(m->ies[i].value);
            m->ies[i].value = g5c_xmalloc(len ? len : 1);
            if (len)
                memcpy(m->ies[i].value, value, len);
            m->ies[i].len = len;
            m->ies[i].iei = d->iei;
            m->ies[i].format = d->format;
            return true;
        }
    return add_ie(m, d->name, d->iei, d->format, value, len);
}

bool nas_msg_equal(const nas_msg *a, const nas_msg *b)
{
    if (a->def != b->def || a->pdu_session_id != b->pdu_session_id || a->pti != b->pti || a->nies != b->nies)
        return false;
    for (size_t i = 0; i < a->nies; i++) {
        const nas_ie *x = &a->ies[i], *y = &b->ies[i];
        if (strcmp(x->name, y->name) != 0 || x->iei != y->iei || x->format != y->format || x->len != y->len ||
            (x->len && memcmp(x->value, y->value, x->len) != 0))
            return false;
    }
    return true;
}

/* ---- decode ---- */

static const uint8_t *take(const uint8_t *b, size_t blen, size_t *pos, size_t n)
{
    const uint8_t *p;
    if (n > blen - *pos)
        return NULL;
    p = b + *pos;
    *pos += n;
    return p;
}

static int decode_body(nas_msg *m, const uint8_t *b, size_t blen)
{
    const nas_msgdef *def = m->def;
    size_t pos = 0, slot = 0;
    bool half_open = false;
    const uint8_t *p;
    int rc;

    /* untagged (mandatory / conditional) part, in spec order */
    for (; slot < def->nies && def->ies[slot].iei < 0; slot++) {
        const nas_iedef *d = &def->ies[slot];
        uint8_t half_val;
        if (d->format == NAS_FMT_V && d->half) {
            if (pos >= blen)
                return NAS_E_TRUNCATED;
            if (half_open) {
                half_open = false;
                half_val = (uint8_t)(b[pos] >> 4);
                pos++;
            } else {
                half_open = true;
                half_val = (uint8_t)(b[pos] & 0x0f);
            }
            if (!add_ie(m, d->name, -1, d->format, &half_val, 1))
                return NAS_E_TOO_MANY_IES;
            continue;
        }
        if (half_open) {
            half_open = false;
            pos++;
        }
        switch (d->format) {
        case NAS_FMT_V:
            p = take(b, blen, &pos, d->min);
            if (p == NULL)
                return NAS_E_TRUNCATED;
            if (!add_ie(m, d->name, -1, d->format, p, d->min))
                return NAS_E_TOO_MANY_IES;
            break;
        case NAS_FMT_LV: {
            const uint8_t *l = take(b, blen, &pos, 1);
            size_t n;
            if (l == NULL)
                return NAS_E_TRUNCATED;
            n = l[0];
            p = take(b, blen, &pos, n);
            if (p == NULL)
                return NAS_E_TRUNCATED;
            if (!add_ie(m, d->name, -1, d->format, p, n))
                return NAS_E_TOO_MANY_IES;
            break;
        }
        case NAS_FMT_LVE: {
            const uint8_t *l = take(b, blen, &pos, 2);
            size_t n;
            if (l == NULL)
                return NAS_E_TRUNCATED;
            n = ((size_t)l[0] << 8) | l[1];
            p = take(b, blen, &pos, n);
            if (p == NULL)
                return NAS_E_TRUNCATED;
            if (!add_ie(m, d->name, -1, d->format, p, n))
                return NAS_E_TOO_MANY_IES;
            break;
        }
        default:
            return NAS_E_INVALID; /* untagged IE with a tagged format */
        }
    }
    if (half_open)
        pos++; /* the remaining nibble is spare */

    /* tagged (optional) part, any order */
    while (pos < blen) {
        uint8_t t = b[pos];
        const nas_iedef *d = NULL;
        for (size_t i = 0; i < def->nies; i++) {
            const nas_iedef *c = &def->ies[i];
            if (c->iei >= 0 && (c->half_iei ? c->iei == (t >> 4) : c->iei == t)) {
                d = c;
                break;
            }
        }
        if (d != NULL && d->half_iei) {
            uint8_t v = (uint8_t)(t & 0x0f);
            pos++;
            if (!add_ie(m, d->name, d->iei, NAS_FMT_TV, &v, 1))
                return NAS_E_TOO_MANY_IES;
        } else if (d != NULL) {
            size_t n = 0;
            pos++;
            switch (d->format) {
            case NAS_FMT_T:
                p = b;
                n = 0;
                break;
            case NAS_FMT_TV:
                n = d->min > 0 ? d->min - 1 : 0;
                p = take(b, blen, &pos, n);
                if (p == NULL)
                    return NAS_E_TRUNCATED;
                break;
            case NAS_FMT_TLV: {
                const uint8_t *l = take(b, blen, &pos, 1);
                if (l == NULL)
                    return NAS_E_TRUNCATED;
                n = l[0];
                p = take(b, blen, &pos, n);
                if (p == NULL)
                    return NAS_E_TRUNCATED;
                break;
            }
            case NAS_FMT_TLVE: {
                const uint8_t *l = take(b, blen, &pos, 2);
                if (l == NULL)
                    return NAS_E_TRUNCATED;
                n = ((size_t)l[0] << 8) | l[1];
                p = take(b, blen, &pos, n);
                if (p == NULL)
                    return NAS_E_TRUNCATED;
                break;
            }
            default:
                return NAS_E_INVALID; /* tagged IE with an untagged format */
            }
            if (!add_ie(m, d->name, d->iei, d->format, p, n))
                return NAS_E_TOO_MANY_IES;
        } else if (t & 0x80) {
            /* unknown type 1 / type 2 IE (TS 24.007 11.2.1.1.3): a single octet, kept whole in iei */
            pos++;
            if (!add_ie(m, "unknown", t, NAS_FMT_T, b, 0))
                return NAS_E_TOO_MANY_IES;
        } else {
            /* unknown comprehension-optional IE: TLV, skipped but preserved */
            const uint8_t *l;
            size_t n;
            pos++;
            l = take(b, blen, &pos, 1);
            if (l == NULL)
                return NAS_E_TRUNCATED;
            n = l[0];
            p = take(b, blen, &pos, n);
            if (p == NULL)
                return NAS_E_TRUNCATED;
            if (!add_ie(m, "unknown", t, NAS_FMT_TLV, p, n))
                return NAS_E_TOO_MANY_IES;
        }
    }
    for (size_t i = 0; i < def->nies; i++) {
        if (def->ies[i].presence != NAS_PRES_M)
            continue;
        if (nas_msg_get(m, def->ies[i].name, NULL) == NULL) {
            m->err_name = def->ies[i].name;
            return NAS_E_MISSING;
        }
    }
    rc = NAS_OK;
    return rc;
}

int nas_msg_decode(const uint8_t *b, size_t len, nas_msg *out)
{
    nas_proto proto;
    size_t hdr;
    uint8_t msg_type, psi = 0, pti = 0;
    const nas_msgdef *def;
    int rc;
    memset(out, 0, sizeof *out);
    if (len == 0)
        return NAS_E_TRUNCATED;
    if (b[0] == NAS_EPD_5GMM) {
        if (len < 3)
            return NAS_E_TRUNCATED;
        if (b[1] & 0x0f)
            return NAS_E_PROTECTED;
        proto = NAS_PROTO_MM;
        hdr = 3;
        msg_type = b[2];
    } else if (b[0] == NAS_EPD_5GSM) {
        if (len < 4)
            return NAS_E_TRUNCATED;
        proto = NAS_PROTO_SM;
        hdr = 4;
        psi = b[1];
        pti = b[2];
        msg_type = b[3];
    } else {
        return NAS_E_EPD;
    }
    def = nas_lookup(proto, msg_type);
    if (def == NULL)
        return NAS_E_MSGTYPE;
    out->def = def;
    out->pdu_session_id = psi;
    out->pti = pti;
    rc = decode_body(out, b + hdr, len - hdr);
    if (rc != NAS_OK) {
        const char *keep = out->err_name;
        nas_msg_free(out);
        out->err_name = keep;
    }
    return rc;
}

/* ---- encode ---- */

static int put(g5c_bytes *out, uint8_t f, int16_t iei, bool half_iei, const uint8_t *v, size_t n)
{
    if (half_iei) {
        char c = (char)(((iei < 0 ? 0 : iei) << 4) | (n ? (v[0] & 0x0f) : 0));
        return g5c_bytes_putc(out, c) == 0 ? NAS_OK : NAS_E_INVALID;
    }
    if (iei >= 0 && g5c_bytes_putc(out, (char)iei) != 0)
        return NAS_E_INVALID;
    switch (f) {
    case NAS_FMT_V:
    case NAS_FMT_TV:
        break;
    case NAS_FMT_T:
        return NAS_OK;
    case NAS_FMT_LV:
    case NAS_FMT_TLV:
        if (n > 255 || g5c_bytes_putc(out, (char)n) != 0)
            return NAS_E_INVALID;
        break;
    default: /* LVE, TLVE */
        if (n > 65535 || g5c_bytes_putc(out, (char)(n >> 8)) != 0 || g5c_bytes_putc(out, (char)n) != 0)
            return NAS_E_INVALID;
        break;
    }
    return g5c_bytes_append(out, v, n) == 0 ? NAS_OK : NAS_E_INVALID;
}

int nas_msg_encode(const nas_msg *m, g5c_bytes *out)
{
    const nas_msgdef *def = m->def;
    size_t half_at = (size_t)-1; /* index of the octet whose high nibble is still free */
    int rc;
    if (def->proto == NAS_PROTO_MM) {
        const char h[3] = {NAS_EPD_5GMM, 0, (char)def->msg_type};
        if (g5c_bytes_append(out, h, 3) != 0)
            return NAS_E_INVALID;
    } else {
        const char h[4] = {NAS_EPD_5GSM, (char)m->pdu_session_id, (char)m->pti, (char)def->msg_type};
        if (g5c_bytes_append(out, h, 4) != 0)
            return NAS_E_INVALID;
    }
    for (size_t i = 0; i < def->nies; i++) {
        const nas_iedef *d = &def->ies[i];
        const nas_ie *ie = NULL;
        if (d->iei >= 0)
            continue;
        for (size_t k = 0; k < m->nies; k++)
            if (strcmp(m->ies[k].name, d->name) == 0) {
                ie = &m->ies[k];
                break;
            }
        if (ie == NULL) {
            if (d->presence == NAS_PRES_M)
                return NAS_E_MISSING;
            continue;
        }
        if (d->format == NAS_FMT_V && d->half) {
            uint8_t nib = (uint8_t)((ie->len ? ie->value[0] : 0) & 0x0f);
            if (half_at == (size_t)-1) {
                half_at = out->len;
                if (g5c_bytes_putc(out, (char)nib) != 0)
                    return NAS_E_INVALID;
            } else {
                out->data[half_at] = (uint8_t)(out->data[half_at] | (nib << 4));
                half_at = (size_t)-1;
            }
            continue;
        }
        half_at = (size_t)-1;
        rc = put(out, d->format, -1, false, ie->value, ie->len);
        if (rc != NAS_OK)
            return rc;
    }
    for (size_t k = 0; k < m->nies; k++) {
        const nas_ie *ie = &m->ies[k];
        bool half = false;
        if (ie->iei < 0)
            continue;
        for (size_t i = 0; i < def->nies; i++)
            if (strcmp(def->ies[i].name, ie->name) == 0 && def->ies[i].half_iei)
                half = true;
        rc = put(out, ie->format, ie->iei, half, ie->value, ie->len);
        if (rc != NAS_OK)
            return rc;
    }
    return NAS_OK;
}
