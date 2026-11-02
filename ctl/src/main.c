/* SPDX-License-Identifier: LicenseRef-Proprietary */
#include <stdio.h>

#include "g5c/ctl.h"

int main(int argc, char **argv)
{
    return g5c_ctl_main(argc, argv, stdout, stderr);
}
