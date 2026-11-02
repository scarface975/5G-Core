/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* g5c-ctl: operator command line for the UDM and PCF admin APIs (/admin/v1). The whole tool is this library function so
 * tests can drive it in-process; main() only forwards argv. */
#ifndef G5C_CTL_H
#define G5C_CTL_H

#include <stdio.h>

/* argv[0] is the program name. Writes results (JSON) to `out` and diagnostics to `err`.
 * Returns 0 on success, 1 when the server answered with an error status, 2 on usage errors, 3 when the server is unreachable. */
int g5c_ctl_main(int argc, char **argv, FILE *out, FILE *err);

#endif
