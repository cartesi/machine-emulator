/* Copyright Cartesi and individual authors (see AUTHORS)
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uarch-defines.h>

#include "custom-pristine-halt.h"

/* Halts on the last uarch cycle before UARCH_CYCLE_MAX */
.equ HALT_CYCLE, UARCH_CYCLE_MAX_DEF - 1

RVTEST_RV64U
RVTEST_CODE_BEGIN
    custom_pristine_halt HALT_CYCLE
