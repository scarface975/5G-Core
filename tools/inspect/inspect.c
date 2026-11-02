/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* g5c-inspect: documentation helper used by tools/gen_dashboard.py. Everything it prints comes from the real code.
 *
 *   g5c-inspect routes          JSON object: NF name -> [{"method", "path"}] built from the routers the NFs really register
 *   g5c-inspect decode          reads lines "<id> <hex NGAP PDU>" on stdin, prints one JSON object per line with the
 *                               decoded NGAP tree and, when the PDU carries a NAS-PDU, the NAS message decoded by libs/nas
 */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/amf.h"
#include "g5c/nrf.h"
#include "g5c/ausf.h"
#include "g5c/json.h"
#include "g5c/nas.h"
#include "g5c/ngap.h"
#include "g5c/pcf.h"
#include "g5c/smf.h"
#include "g5c/udm.h"
#include "g5c/udr.h"

static void routes_of(g5c_json *out, const char *nf, g5c_router *r, bool with_base)
{
    g5c_json *list = g5c_json_set(out, nf, g5c_json_new_arr());
    for (size_t i = 0; i < g5c_router_count(r); i++) {
        const char *m, *p;
        g5c_json *e;
        if (!g5c_router_route_at(r, i, &m, &p))
            continue;
        e = g5c_json_push(list, g5c_json_new_obj());
        g5c_json_set_str(e, "method", m);
        g5c_json_set_str(e, "path", p);
    }
    if (with_base) { /* added by libs/nfcore for every NF */
        static const char *const base[] = {"/health/live", "/health/ready", "/metrics"};
        for (size_t i = 0; i < 3; i++) {
            g5c_json *e = g5c_json_push(list, g5c_json_new_obj());
            g5c_json_set_str(e, "method", "GET");
            g5c_json_set_str(e, "path", base[i]);
        }
    }
}

static int cmd_routes(void)
{
    g5c_json *out = g5c_json_new_obj();
    g5c_registry *m = g5c_registry_new();
    g5c_udr_store *store = g5c_udr_store_memory();
    g5c_router *udr_r = g5c_udr_router(store), *udm_r, *ausf_r, *pcf_r;
    udm_keys keys;
    udm u;
    pcf p;
    pcf_policy pol;
    char err[100];
    g5c_json *py = g5c_yaml_parse("default: {}\n", 12, err, sizeof err);

    udm_keys_none(&keys);
    udm_init(&u, NULL, "http://127.0.0.1:1", &keys, NULL, 0, "00101", "inspect", m);
    udm_r = udm_router(&u);
    ausf_r = g5c_router_new();
    ausf_routes(ausf_r, NULL); /* the route table does not depend on the AUSF's state */
    if (py == NULL || pcf_policy_parse(py, true, &pol, err, sizeof err) != 0)
        return 1;
    g5c_json_free(py);
    pcf_init(&p, &pol, NULL, "http://127.0.0.1:1", m);
    pcf_r = pcf_router(&p);

    routes_of(out, "udr", udr_r, true);
    routes_of(out, "udm", udm_r, true);
    routes_of(out, "ausf", ausf_r, true);
    routes_of(out, "pcf", pcf_r, true);
    {   /* the route table does not depend on the SMF's state */
        g5c_router *smf_r = g5c_router_new();
        smf_sm_routes(smf_r, NULL);
        routes_of(out, "smf", smf_r, true);
        g5c_router_free(smf_r);
        {
            g5c_router *amf_r = g5c_router_new();
            amf_routes(amf_r, NULL);
            routes_of(out, "amf", amf_r, true);
            g5c_router_free(amf_r);
        }
    }
    {
        g5c_router *nrf_r = g5c_router_new();
        nrf_routes(nrf_r, NULL);
        routes_of(out, "nrf", nrf_r, true);
        g5c_router_free(nrf_r);
    }
    routes_of(out, "upf", g5c_router_new(), true); /* the UPF is not an SBI function: health and metrics only */
    {
        char *s = g5c_json_to_string(out, NULL);
        puts(s);
        free(s);
    }
    g5c_json_free(out);
    return 0;
}

/* ---- NAS ------------------------------------------------------------------------------------------------------- */

static char *hex_of(const uint8_t *b, size_t n)
{
    return g5c_hex_encode(b, n);
}

static g5c_json *nas_msg_to_json(const nas_msg *m, int depth);

static void typed_decode(g5c_json *ie, const nas_ie *x)
{
    if (strcmp(x->name, "5GS mobile identity") == 0 || strcmp(x->name, "Additional GUTI") == 0) {
        nas_mobile_identity id;
        if (nas_mobile_identity_decode(x->value, x->len, &id) == 0) {
            if (id.kind == NAS_ID_SUCI) {
                char *s = nas_suci_to_string(&id);
                g5c_json_set_str(ie, "decoded", s ? s : "SUCI");
                free(s);
            } else if (id.kind == NAS_ID_GUTI) {
                char b[128];
                snprintf(b, sizeof b, "5G-GUTI mcc %s mnc %s, AMF region %u set %u pointer %u, 5G-TMSI %08x", id.mcc, id.mnc,
                         id.amf_region, id.amf_set, id.amf_pointer, id.tmsi);
                g5c_json_set_str(ie, "decoded", b);
            } else if (id.kind == NAS_ID_IMEI || id.kind == NAS_ID_IMEISV) {
                g5c_json_set_str(ie, "decoded", id.digits);
            }
        }
    } else if (strstr(x->name, "NSSAI") != NULL || strcmp(x->name, "S-NSSAI") == 0) {
        nas_snssai list[16];
        int n = strstr(x->name, "NSSAI") != NULL && strcmp(x->name, "S-NSSAI") != 0 ? nas_nssai_decode(x->value, x->len, list, 16)
                                                                                      : (nas_snssai_decode(x->value, x->len, list) == 0 ? 1 : -1);
        if (n > 0) {
            char b[256] = {0};
            size_t o = 0;
            for (int i = 0; i < n && o + 32 < sizeof b; i++) {
                o += (size_t)snprintf(b + o, sizeof b - o, "%sSST %u", i ? ", " : "", list[i].sst);
                if (list[i].has_sd)
                    o += (size_t)snprintf(b + o, sizeof b - o, " SD %06x", list[i].sd);
            }
            g5c_json_set_str(ie, "decoded", b);
        }
    } else if (strcmp(x->name, "DNN") == 0) {
        char d[128];
        if (nas_dnn_decode(x->value, x->len, d, sizeof d) >= 0)
            g5c_json_set_str(ie, "decoded", d);
    }
}

static g5c_json *nas_msg_to_json(const nas_msg *m, int depth)
{
    g5c_json *o = g5c_json_new_obj(), *ies = g5c_json_set(o, "ies", g5c_json_new_arr());
    g5c_json_set_str(o, "name", nas_msg_name(m));
    g5c_json_set_str(o, "protocol", m->def->proto == NAS_PROTO_MM ? "5GMM" : "5GSM");
    if (m->def->proto == NAS_PROTO_SM) {
        g5c_json_set_int(o, "pduSessionId", m->pdu_session_id);
        g5c_json_set_int(o, "pti", m->pti);
    }
    for (size_t i = 0; i < m->nies; i++) {
        const nas_ie *x = &m->ies[i];
        char *h = hex_of(x->value, x->len);
        g5c_json *ie = g5c_json_push(ies, g5c_json_new_obj());
        g5c_json_set_str(ie, "name", x->name);
        if (x->iei >= 0)
            g5c_json_set_int(ie, "iei", x->iei);
        g5c_json_set_str(ie, "hex", h);
        free(h);
        typed_decode(ie, x);
        if (depth < 2 && (strstr(x->name, "payload container") != NULL || strstr(x->name, "Payload container") != NULL)) {
            nas_msg inner;
            if (nas_msg_decode(x->value, x->len, &inner) == 0) {
                g5c_json_set(ie, "nested", nas_msg_to_json(&inner, depth + 1));
                nas_msg_free(&inner);
            }
        }
    }
    return o;
}

static g5c_json *nas_pdu_to_json(const uint8_t *b, size_t n)
{
    nas_any a;
    g5c_json *o = g5c_json_new_obj();
    int rc = nas_any_decode(b, n, &a);
    if (rc != 0) {
        g5c_json_set_str(o, "error", nas_strerror(rc));
        return o;
    }
    if (!a.is_protected) {
        g5c_json_set_bool(o, "protected", false);
        g5c_json_set(o, "message", nas_msg_to_json(&a.plain, 0));
        nas_any_free(&a);
        return o;
    }
    g5c_json_set_bool(o, "protected", true);
    {
        g5c_json *sec = g5c_json_set(o, "security", g5c_json_new_obj());
        char *mac = hex_of(a.prot.mac, 4);
        static const char *const sht[] = {"plain", "integrity protected", "integrity protected and ciphered", "integrity protected with new security context",
                                          "integrity protected and ciphered with new security context"};
        g5c_json_set_int(sec, "securityHeaderType", a.prot.sht);
        g5c_json_set_str(sec, "securityHeader", a.prot.sht <= 4 ? sht[a.prot.sht] : "?");
        g5c_json_set_str(sec, "mac", mac);
        g5c_json_set_int(sec, "sequenceNumber", a.prot.seq);
        free(mac);
    }
    {   /* integrity-only, or ciphered with the null algorithm: the inner message is readable; otherwise report it as ciphered */
        nas_msg inner;
        if (nas_msg_decode(a.prot.payload, a.prot.payload_len, &inner) == 0) {
            g5c_json_set(o, "message", nas_msg_to_json(&inner, 0));
            nas_msg_free(&inner);
        } else {
            g5c_json_set_bool(o, "ciphered", true);
            g5c_json_set_int(o, "payloadBytes", (int64_t)a.prot.payload_len);
        }
    }
    nas_any_free(&a);
    return o;
}

static int cmd_decode(void)
{
    char line[1 << 16];
    while (fgets(line, sizeof line, stdin) != NULL) {
        char *sp = strchr(line, ' '), *id = line, *hex, err[100];
        uint8_t buf[8192];
        long n;
        g5c_json *res, *pdu;
        const g5c_json *msg, *nas_hex;
        if (sp == NULL)
            continue;
        *sp = 0;
        hex = sp + 1;
        hex[strcspn(hex, "\r\n")] = 0;
        n = (long)g5c_hex_decode(hex, buf, sizeof buf);
        res = g5c_json_new_obj();
        g5c_json_set_str(res, "id", id);
        pdu = n > 0 ? ngap_decode(buf, (size_t)n, err, sizeof err) : NULL;
        if (pdu == NULL) {
            g5c_json_set_str(res, "error", n > 0 ? err : "bad hex");
        } else {
            const char *kind = ngap_pdu_kind(pdu), *name = ngap_procedure_name(pdu);
            g5c_json_set_str(res, "kind", kind ? kind : "?");
            g5c_json_set_str(res, "procedure", name ? name : "?");
            msg = ngap_pdu_message(pdu);
            nas_hex = msg ? ngap_find_ie(msg, NGAP_IE_NAS_PDU) : NULL;
            if (g5c_json_str(nas_hex) != NULL) {
                uint8_t nb[4096];
                long nl = (long)g5c_hex_decode(g5c_json_str(nas_hex), nb, sizeof nb);
                if (nl > 0)
                    g5c_json_set(res, "nas", nas_pdu_to_json(nb, (size_t)nl));
            }
            g5c_json_set(res, "ngap", pdu);
        }
        {
            char *s = g5c_json_to_string(res, NULL);
            puts(s);
            free(s);
        }
        g5c_json_free(res);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "routes") == 0)
        return cmd_routes();
    if (argc == 2 && strcmp(argv[1], "decode") == 0)
        return cmd_decode();
    fprintf(stderr, "usage: g5c-inspect routes | decode\n");
    return 2;
}
