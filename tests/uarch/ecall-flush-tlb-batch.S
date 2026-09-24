/* Copyright Cartesi and individual authors (see AUTHORS)
 * SPDX-License-Identifier: Apache-2.0
 */

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64U
RVTEST_CODE_BEGIN

  li a7, UARCH_ECALL_FN_WRITE_TLB_DEF
  li a0, 2
  li a1, 255
  li a2, AR_CMIO_RX_BUFFER_START_DEF
  li a3, 7
  li a4, 3
  ecall

  li a1, 256 - UARCH_TLB_FLUSH_BATCH_SIZE_DEF
  ecall
  addi a1, a1, -1
  ecall

  li a7, UARCH_ECALL_FN_FLUSH_TLB_BATCH_DEF
  li a1, 256 - UARCH_TLB_FLUSH_BATCH_SIZE_DEF
  ecall

  li t0, AR_SHADOW_TLB_START_DEF + (2 * 8192) + ((256 - UARCH_TLB_FLUSH_BATCH_SIZE_DEF) * 32)
  li t1, UARCH_TLB_FLUSH_BATCH_SIZE_DEF
  li t3, -1
1:
  ld t2, 0(t0)
  bne t2, t3, test_fail
  ld t2, 8(t0)
  bnez t2, test_fail
  ld t2, 16(t0)
  bne t2, t3, test_fail
  ld t2, 24(t0)
  bnez t2, test_fail
  addi t0, t0, 32
  addi t1, t1, -1
  bnez t1, 1b

  li t0, AR_SHADOW_TLB_START_DEF + (2 * 8192) + ((255 - UARCH_TLB_FLUSH_BATCH_SIZE_DEF) * 32)
  ld t2, 0(t0)
  bne t2, a2, test_fail
  ld t2, 8(t0)
  bne t2, a3, test_fail
  ld t2, 16(t0)
  bne t2, a4, test_fail

RVTEST_CODE_END

test_fail:
  RVTEST_FAIL

  .data
RVTEST_DATA_BEGIN
TEST_DATA
RVTEST_DATA_END
