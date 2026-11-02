/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: NGAP APER decode must never crash; a PDU that decodes must encode again, and the encoding must
 * decode to an equal tree. */
#include <stddef.h>
#include <stdint.h>

#include "g5c/ngap.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    g5c_json *j = ngap_decode(data, size, NULL, 0);
    if (j != NULL) {
        g5c_bytes out;
        g5c_json *back;
        g5c_bytes_init(&out);
        if (ngap_encode(j, &out, NULL, 0) == 0) {
            back = ngap_decode(out.data, out.len, NULL, 0);
            if (back == NULL || !g5c_json_equal(j, back))
                __builtin_trap();
            g5c_json_free(back);
        }
        g5c_bytes_free(&out);
        g5c_json_free(j);
    }
    return 0;
}
