/* Copyright Cartesi and individual authors (see AUTHORS)
 * SPDX-License-Identifier: Apache-2.0
 */

#include "riscv_test.h"

RVTEST_RV64U
RVTEST_CODE_BEGIN
    /* 2 setup instructions + 2 * 524285 loop instructions + 2-instruction halt = 1048574. */
    li t0, 524285
1:  addi t0, t0, -1
    bnez t0, 1b
    RVTEST_HALT
