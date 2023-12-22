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


/*
Tests to improve code coverage of AMO instructions.
*/

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN
  # amominu.w
  TEST_CASE(1, a4, 0xfffffffffffff800, \
    li a0, 0xfffffffffffff800; \
    li a1, 0xffffffff80000000; \
    la a3, amo_operand; \
    sw a0, 0(a3); \
    amominu.w   a4, a1, 0(a3); \
  )
  TEST_CASE(2, a5, 0xffffffff80000000, lw a5, 0(a3))

  # amominu.d
  TEST_CASE(3, a4, 0xfffffffffffff800, \
    li a0, 0xfffffffffffff800; \
    li a1, 0xffffffff80000000; \
    la a3, amo_operand; \
    sd a0, 0(a3); \
    amominu.d   a4, a1, 0(a3); \
  )
  TEST_CASE(4, a5, 0xffffffff80000000, ld a5, 0(a3))

  # amomaxu.w
  TEST_CASE(5, a4, 0xfffffffffffff800, \
    li a0, 0xfffffffffffff800; \
    li a1, 0xffffffff80000000; \
    la a3, amo_operand; \
    sw a0, 0(a3); \
    amomaxu.w   a4, a1, 0(a3); \
  )
  TEST_CASE(6, a5, 0xfffffffffffff800, lw a5, 0(a3))

  # amomaxu.d
  TEST_CASE(7, a4, 0xfffffffffffff800, \
    li a0, 0xfffffffffffff800; \
    li a1, 0xffffffff80000000; \
    la a3, amo_operand; \
    sd a0, 0(a3); \
    amomaxu.d   a4, a1, 0(a3); \
  )
  TEST_CASE(8, a5, 0xfffffffffffff800, ld a5, 0(a3))

  # amomax.w
  TEST_CASE(9, a4, 0xfffffffffffff800, \
    li a0, 0xfffffffffffff800; \
    li a1, 0xffffffff80000000; \
    la a3, amo_operand; \
    sw a0, 0(a3); \
    amomax.w    a4, a1, 0(a3); \
  )
  TEST_CASE(10, a5, 0xfffffffffffff800, lw a5, 0(a3))

  # amomax.d
  TEST_CASE(11, a4, 0xfffffffffffff800, \
    li a0, 0xfffffffffffff800; \
    li a1, 0xffffffff80000000; \
    la a3, amo_operand; \
    sd a0, 0(a3); \
    amomax.d    a4, a1, 0(a3); \
  )
  TEST_CASE(12, a5, 0xfffffffffffff800, ld a5, 0(a3))

  TEST_PASSFAIL

RVTEST_CODE_END

.data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END

  .bss
  .align 3
amo_operand:
  .dword 0
