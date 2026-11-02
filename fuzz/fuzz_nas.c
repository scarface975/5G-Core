/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: NAS decode must never crash, and what decodes must re-encode and decode to the same value. */
#include <stddef.h>
#include <stdint.h>

#include "g5c/nas.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    nas_msg m, m2;
    nas_any a;
    if (nas_any_decode(data, size, &a) == 0)
        nas_any_free(&a);
    if (nas_msg_decode(data, size, &m) == 0) {
        g5c_bytes re;
        g5c_bytes_init(&re);
        if (nas_msg_encode(&m, &re) != 0 || nas_msg_decode(re.data, re.len, &m2) != 0 || !nas_msg_equal(&m, &m2))
            __builtin_trap();
        nas_msg_free(&m2);
        g5c_bytes_free(&re);
        nas_msg_free(&m);
    }
    return 0;
}
