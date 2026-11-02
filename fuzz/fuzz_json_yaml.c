/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* libFuzzer target: the JSON and YAML-subset parsers (every SBI body and configuration file goes through them). */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "g5c/json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    g5c_json *j = g5c_json_parse((const char *)data, size, NULL, 0), *y;
    if (j != NULL) {
        size_t n = 0;
        char *s = g5c_json_to_string(j, &n);
        g5c_json *back = s ? g5c_json_parse(s, n, NULL, 0) : NULL;
        if (back == NULL || !g5c_json_equal(j, back))
            __builtin_trap();
        g5c_json_free(back);
        free(s);
        g5c_json_free(j);
    }
    y = g5c_yaml_parse((const char *)data, size, NULL, 0);
    g5c_json_free(y);
    return 0;
}
