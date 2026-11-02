/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: the AMF's whole receive path. The first byte selects the surface:
 *   bit 0 clear: an NGAP PDU from a gNB (as if it arrived over SCTP). Bit 1 set: the NAS PDU inside an Initial UE Message / Uplink NAS Transport is
 *                wrapped in a valid integrity protected envelope of a registered UE first, so that mutations of the inner message reach the 5GMM state
 *                machine instead of stopping at the MAC check.
 *   bit 0 set:   an SBI request body for one of the AMF's routes (byte 1 selects the route, bit 0 of byte 2 multipart / JSON).
 * The AMF's peers are unreachable (connection refused), so a handler that needs one fails fast. Whatever the input, the AMF must neither crash nor
 * leak nor take a lock twice. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "g5c/amf.h"
#include "g5c/crypto.h"
#include "g5c/nas.h"
#include "g5c/ngap.h"

static amf *A;
static g5c_nf *NF;
static g5c_router *R;
static nas_sec_ctx CTX;
static uint32_t UL;
static const char SUPI[] = "imsi-001010000000001";

static void setup_once(void)
{
    static const char yaml[] = "name: amf-fuzz\nplmn: { mcc: '001', mnc: '01' }\nsbi: { address: 127.0.0.1, port: 1 }\n"
                               "amf:\n  guami: { region: 2, set: 1, pointer: 0 }\n  ngap: { address: 127.0.0.1, port: 0 }\n  tais: [ { tac: 1 } ]\n"
                               "  slices: [ { sst: 1 } ]\n  ausf: { uri: 'http://127.0.0.1:9' }\n  udm: { uri: 'http://127.0.0.1:9' }\n"
                               "  smf: { uri: 'http://127.0.0.1:9' }\n  workers: 2\n  max_unauthenticated: 128\n"
                               "  timers: { t3513: 1, t3550: 1, t3560: 1, t3570: 1, t3522: 1 }\n";
    char err[256];
    g5c_json *j;
    g5c_common common;
    uint8_t kamf[32];
    memset(kamf, 0x5a, sizeof kamf);
    g5c_log_init("error", false);
    j = g5c_yaml_parse(yaml, strlen(yaml), err, sizeof err);
    if (j == NULL || g5c_common_parse(j, &common, err, sizeof err) != 0)
        abort();
    common.port = 0;
    NF = g5c_nf_new(&common, err, sizeof err);
    if (NF == NULL)
        abort();
    A = amf_from_config(j, NF, err, sizeof err);
    g5c_json_free(j);
    if (A == NULL || amf_test_start(A) != 0)
        abort();
    amf_test_gnb(A, 0, 1);
    amf_test_add_ue(A, SUPI, 0xc0ffee01u, kamf);
    memset(&CTX, 0, sizeof CTX);
    (void)g5c_algo_key(kamf, G5C_ALG_NAS_INT, 2, CTX.knas_int);
    (void)g5c_algo_key(kamf, G5C_ALG_NAS_ENC, 2, CTX.knas_enc);
    CTX.int_alg = NAS_IA2;
    CTX.enc_alg = NAS_EA2;
    R = amf_router(A);
}

/* find the NAS-PDU IE of a decoded NGAP PDU and wrap its plain content in an integrity protected message of the registered UE */
static void protect_nas(g5c_json *pdu)
{
    const g5c_json *m = ngap_pdu_message(pdu), *ies = g5c_json_get(m, "protocolIEs");
    for (size_t i = 0; i < g5c_json_len(ies); i++) {
        const g5c_json *ie = g5c_json_at(ies, i);
        int64_t id;
        const char *hex;
        if (!g5c_json_get_int(ie, "id", &id) || id != NGAP_IE_NAS_PDU)
            continue;
        hex = g5c_json_str(g5c_json_get(ie, "value"));
        if (hex != NULL && strlen(hex) >= 6 && strlen(hex) <= 4096) {
            uint8_t plain[2048];
            long n = g5c_hex_decode(hex, plain, sizeof plain);
            if (n > 0) {
                g5c_bytes out;
                g5c_bytes_init(&out);
                if (nas_protect(&CTX, 1, G5C_DIR_UL, UL++, plain, (size_t)n, &out) == NAS_OK) {
                    char *h = g5c_hex_encode(out.data, out.len);
                    g5c_json *nv = g5c_json_new_str(h);
                    g5c_json *mut = g5c_json_get_mut(g5c_json_get_mut(g5c_json_get_mut(pdu, g5c_json_key_at(pdu, 0)), "value"), "protocolIEs");
                    g5c_json *mie = g5c_json_at_mut(mut, i);
                    free(h);
                    g5c_json_set(mie, "value", nv);
                }
                g5c_bytes_free(&out);
            }
        }
        return;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char *const ROUTES[6] = {"/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages",
                                          "/namf-callback/v1/smf-status/imsi-001010000000001/1",
                                          "/namf-callback/v1/dereg-notify/imsi-001010000000001",
                                          "/namf-callback/v1/am-policy/imsi-001010000000001/update",
                                          "/namf-callback/v1/sdm-notify/imsi-001010000000001",
                                          "/namf-evts/v1/subscriptions"};
    if (A == NULL)
        setup_once();
    if (size == 0)
        return 0;
    if (data[0] & 1) {
        const char *ct = "application/json";
        if (size < 3)
            return 0;
        if (data[2] & 1)
            ct = "multipart/related; boundary=fuzz; type=\"application/json\"";
        amf_test_sbi(A, R, "POST", ROUTES[data[1] % 6], ct, data + 3, size - 3);
    } else if (size > 1) {
        if (data[0] & 2) {
            char err[64];
            g5c_json *j = ngap_decode(data + 1, size - 1, err, sizeof err);
            if (j != NULL) {
                g5c_bytes out;
                g5c_bytes_init(&out);
                protect_nas(j);
                if (ngap_encode(j, &out, err, sizeof err) == 0)
                    amf_test_inject(A, 0, out.data, out.len);
                g5c_bytes_free(&out);
                g5c_json_free(j);
            } else {
                amf_test_inject(A, 0, data + 1, size - 1);
            }
        } else {
            amf_test_inject(A, 0, data + 1, size - 1);
        }
    }
    amf_test_drain(A);
    return 0;
}
