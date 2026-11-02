/* SPDX-License-Identifier: LicenseRef-Proprietary */
/* g5c-ctl: operator command line for the UDM and PCF admin APIs (/admin/v1) */
#ifndef G5C_CTL_H
#define G5C_CTL_H

#include <stdio.h>

/* argv[0] is the program name. Writes results (JSON) to `out` and diagnostics to `err` */
int g5c_ctl_main(int argc, char **argv, FILE *out, FILE *err);

#endif
