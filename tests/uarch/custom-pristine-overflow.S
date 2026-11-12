/* Copyright Cartesi and individual authors (see AUTHORS)
 * SPDX-License-Identifier: Apache-2.0
 */

#include "riscv_test.h"

/* Pristine uarch program for the collector tests that never halts, so every run reaches UARCH_CYCLE_MAX */
RVTEST_RV64U
RVTEST_CODE_BEGIN
1:  j 1b
