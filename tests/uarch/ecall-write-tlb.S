/* Copyright Cartesi and individual authors (see AUTHORS)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64U
RVTEST_CODE_BEGIN

  // Arguments passed to ecall/write_tlb
  .equ set_index,   2    // TLB_WRITE
  .equ slot_index,  255  // last slot in set
  .equ vaddr_page,  AR_CMIO_RX_BUFFER_START_DEF
  .equ vp_offset,   7
  .equ pma_index,   3

  // ----------------------------------------------
  // Test writing a TLB entry
  // ----------------------------------------------

  li a7, UARCH_ECALL_FN_WRITE_TLB_DEF
  li a0, set_index
  li a1, slot_index
  li a2, vaddr_page
  li a3, vp_offset
  li a4, pma_index
  ecall

  // Read back and verify the TLB entry written
  .equ tlb_set_length, 8192
  .equ tlb_slot_length, 32
  .equ slot_offset,  (set_index * tlb_set_length) + (slot_index * tlb_slot_length)

  // Compute t0 =  TLB slot address
  li t0, slot_offset
  li t1, AR_SHADOW_TLB_START_DEF
  add t0, t0, t1

  // Check vaddr_page
  ld t2, 0(t0)
  li t3, vaddr_page
  bne t2, t3, test_fail

  // Check vp_offset
  ld t2, 8(t0)
  li t3, vp_offset
  bne t2, t3, test_fail

  // Check pma_index
  ld t2, 16(t0)
  li t3, pma_index
  bne t2, t3, test_fail

  // check padding is zero
  ld t2, 24(t0)
  bnez t2, test_fail

  // ----------------------------------------------
  // Tst invalidation of TLB entry
  // ----------------------------------------------

  .equ TLB_INVALID_PAGE, 0xFFFFFFFFFFFFFFFF

  li a7, UARCH_ECALL_FN_WRITE_TLB_DEF
  li a0, set_index
  li a1, slot_index
  li a2, TLB_INVALID_PAGE
  li a3, vp_offset
  li a4, pma_index
  ecall

  // t0 still contains the slot address that was computed earlier

  // Check vaddr_page is set to invalid
  ld t2, 0(t0)
  li t3, TLB_INVALID_PAGE
  bne t2, t3, test_fail

  // Check vp_offset is zeroed out
  ld t2, 8(t0)
  li t3, vp_offset
  bne t2, t3, test_fail

  // Check pma_index is set to invalid
  ld t2, 16(t0)
  li t3, pma_index
  bne t2, t3, test_fail

  // check padding is zero
  ld t2, 24(t0)
  beqz t2, test_pass
  j test_fail

test_pass:

RVTEST_CODE_END

test_fail:
  RVTEST_FAIL

  .data
RVTEST_DATA_BEGIN
TEST_DATA
RVTEST_DATA_END
