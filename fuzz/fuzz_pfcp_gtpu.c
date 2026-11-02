/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: PFCP and GTP-U header decoders. */
#include <stddef.h>
#include <stdint.h>

#include "g5c/gtpu.h"
#include "g5c/pfcp.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    pfcp_header ph;
    gtpu_header gh;
    const uint8_t *body, *payload;
    size_t blen, plen, pos = 0;
    pfcp_ie ie;
    if (pfcp_decode(data, size, &ph, &body, &blen) == 0)
        while (pfcp_ie_next(body, blen, &pos, &ie) == 1)
            ;
    (void)gtpu_decode(data, size, &gh, &payload, &plen);
    return 0;
}
