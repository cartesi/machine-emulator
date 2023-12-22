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
#include "float_util.h"

RVTEST_RV64UF
RVTEST_CODE_BEGIN

TEST_FCLASS_S(1, 8, 0x80000000);
TEST_FCLASS_S(2, 4, 0x807fffff);
TEST_FCLASS_S(3, 2, 0xbf800000);
TEST_FCLASS_S(4, 1, 0xff800000);
TEST_FCLASS_S(5, 2, 0xff7fffff);
TEST_FCLASS_S(6, 4, 0x80000001);
TEST_FCLASS_S(7, 256, 0xff800001);
TEST_FCLASS_S(8, 512, 0xffc00000);
TEST_FCLASS_S(9, 16, 0x00);
TEST_FCLASS_S(10, 32, 0x7fffff);
TEST_FCLASS_S(11, 64, 0x3f800000);
TEST_FCLASS_S(12, 128, 0x7f800000);
TEST_FCLASS_S(13, 64, 0x7f7fffff);
TEST_FCLASS_S(14, 32, 0x01);
TEST_FCLASS_S(15, 256, 0x7f800001);
TEST_FCLASS_S(16, 512, 0x7fc00000);
TEST_FCLASS_S(17, 64, 0x800000);
TEST_FCLASS_S(18, 2, 0x80800000);
TEST_FCLASS_S(19, 64, 0x40066666);
TEST_FCLASS_S(20, 2, 0xc0066666);
TEST_FCLASS_S(21, 64, 0x3f000000);
TEST_FCLASS_S(22, 2, 0xbf000000);
TEST_FCLASS_S(23, 64, 0x4e000000);
TEST_FCLASS_S(24, 64, 0x5f000000);
TEST_FCLASS_S(25, 2, 0xcfffd7ff);
TEST_FCLASS_D(26, 8, 0x8000000000000000);
TEST_FCLASS_D(27, 4, 0x800fffffffffffff);
TEST_FCLASS_D(28, 2, 0xbff0000000000000);
TEST_FCLASS_D(29, 1, 0xfff0000000000000);
TEST_FCLASS_D(30, 2, 0xffefffffffffffff);
TEST_FCLASS_D(31, 4, 0x8000000000000001);
TEST_FCLASS_D(32, 256, 0xfff0000000000001);
TEST_FCLASS_D(33, 512, 0xfff8000000000000);
TEST_FCLASS_D(34, 16, 0x00);
TEST_FCLASS_D(35, 32, 0xfffffffffffff);
TEST_FCLASS_D(36, 64, 0x3ff0000000000000);
TEST_FCLASS_D(37, 128, 0x7ff0000000000000);
TEST_FCLASS_D(38, 64, 0x7fefffffffffffff);
TEST_FCLASS_D(39, 32, 0x01);
TEST_FCLASS_D(40, 256, 0x7ff0000000000001);
TEST_FCLASS_D(41, 512, 0x7ff8000000000000);
TEST_FCLASS_D(42, 64, 0x10000000000000);
TEST_FCLASS_D(43, 2, 0x8010000000000000);
TEST_FCLASS_D(44, 64, 0x4000cccccccccccd);
TEST_FCLASS_D(45, 2, 0xc000cccccccccccd);
TEST_FCLASS_D(46, 64, 0x3fe0000000000000);
TEST_FCLASS_D(47, 2, 0xbfe0000000000000);
TEST_FCLASS_D(48, 64, 0x4fc0000000000000);
TEST_FCLASS_D(49, 64, 0x5fe0000000000000);
TEST_FCLASS_D(50, 64, 0x3f3240fef40a55d0);

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END

