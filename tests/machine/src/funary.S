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

TEST_FP_OP1_RM_S(1, fsqrt.s, 0x00, 0f:80000000, 0f:80000000, rne);
TEST_FP_OP1_RM_S(2, fsqrt.s, 0x10, 0f:7fc00000, 0f:807fffff, rne);
TEST_FP_OP1_RM_S(3, fsqrt.s, 0x10, 0f:7fc00000, 0f:bf800000, rne);
TEST_FP_OP1_RM_S(4, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff800000, rne);
TEST_FP_OP1_RM_S(5, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff7fffff, rne);
TEST_FP_OP1_RM_S(6, fsqrt.s, 0x10, 0f:7fc00000, 0f:80000001, rne);
TEST_FP_OP1_RM_S(7, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff800001, rne);
TEST_FP_OP1_RM_S(8, fsqrt.s, 0x00, 0f:7fc00000, 0f:ffc00000, rne);
TEST_FP_OP1_RM_S(9, fsqrt.s, 0x00, 0f:00000000, 0f:00000000, rne);
TEST_FP_OP1_RM_S(10, fsqrt.s, 0x01, 0f:1fffffff, 0f:007fffff, rne);
TEST_FP_OP1_RM_S(11, fsqrt.s, 0x00, 0f:3f800000, 0f:3f800000, rne);
TEST_FP_OP1_RM_S(12, fsqrt.s, 0x00, 0f:7f800000, 0f:7f800000, rne);
TEST_FP_OP1_RM_S(13, fsqrt.s, 0x01, 0f:5f7fffff, 0f:7f7fffff, rne);
TEST_FP_OP1_RM_S(14, fsqrt.s, 0x01, 0f:1a3504f3, 0f:00000001, rne);
TEST_FP_OP1_RM_S(15, fsqrt.s, 0x10, 0f:7fc00000, 0f:7f800001, rne);
TEST_FP_OP1_RM_S(16, fsqrt.s, 0x00, 0f:7fc00000, 0f:7fc00000, rne);
TEST_FP_OP1_RM_S(17, fsqrt.s, 0x00, 0f:20000000, 0f:00800000, rne);
TEST_FP_OP1_RM_S(18, fsqrt.s, 0x10, 0f:7fc00000, 0f:80800000, rne);
TEST_FP_OP1_RM_S(19, fsqrt.s, 0x01, 0f:3fb97d58, 0f:40066666, rne);
TEST_FP_OP1_RM_S(20, fsqrt.s, 0x10, 0f:7fc00000, 0f:c0066666, rne);
TEST_FP_OP1_RM_S(21, fsqrt.s, 0x01, 0f:3f3504f3, 0f:3f000000, rne);
TEST_FP_OP1_RM_S(22, fsqrt.s, 0x10, 0f:7fc00000, 0f:bf000000, rne);
TEST_FP_OP1_RM_S(23, fsqrt.s, 0x01, 0f:46b504f3, 0f:4e000000, rne);
TEST_FP_OP1_RM_S(24, fsqrt.s, 0x01, 0f:4f3504f3, 0f:5f000000, rne);
TEST_FP_OP1_RM_S(25, fsqrt.s, 0x10, 0f:7fc00000, 0f:cfffd7ff, rne);
TEST_FP_OP1_RM_S(26, fsqrt.s, 0x00, 0f:80000000, 0f:80000000, rtz);
TEST_FP_OP1_RM_S(27, fsqrt.s, 0x10, 0f:7fc00000, 0f:807fffff, rtz);
TEST_FP_OP1_RM_S(28, fsqrt.s, 0x10, 0f:7fc00000, 0f:bf800000, rtz);
TEST_FP_OP1_RM_S(29, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff800000, rtz);
TEST_FP_OP1_RM_S(30, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff7fffff, rtz);
TEST_FP_OP1_RM_S(31, fsqrt.s, 0x10, 0f:7fc00000, 0f:80000001, rtz);
TEST_FP_OP1_RM_S(32, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff800001, rtz);
TEST_FP_OP1_RM_S(33, fsqrt.s, 0x00, 0f:7fc00000, 0f:ffc00000, rtz);
TEST_FP_OP1_RM_S(34, fsqrt.s, 0x00, 0f:00000000, 0f:00000000, rtz);
TEST_FP_OP1_RM_S(35, fsqrt.s, 0x01, 0f:1ffffffe, 0f:007fffff, rtz);
TEST_FP_OP1_RM_S(36, fsqrt.s, 0x00, 0f:3f800000, 0f:3f800000, rtz);
TEST_FP_OP1_RM_S(37, fsqrt.s, 0x00, 0f:7f800000, 0f:7f800000, rtz);
TEST_FP_OP1_RM_S(38, fsqrt.s, 0x01, 0f:5f7fffff, 0f:7f7fffff, rtz);
TEST_FP_OP1_RM_S(39, fsqrt.s, 0x01, 0f:1a3504f3, 0f:00000001, rtz);
TEST_FP_OP1_RM_S(40, fsqrt.s, 0x10, 0f:7fc00000, 0f:7f800001, rtz);
TEST_FP_OP1_RM_S(41, fsqrt.s, 0x00, 0f:7fc00000, 0f:7fc00000, rtz);
TEST_FP_OP1_RM_S(42, fsqrt.s, 0x00, 0f:20000000, 0f:00800000, rtz);
TEST_FP_OP1_RM_S(43, fsqrt.s, 0x10, 0f:7fc00000, 0f:80800000, rtz);
TEST_FP_OP1_RM_S(44, fsqrt.s, 0x01, 0f:3fb97d57, 0f:40066666, rtz);
TEST_FP_OP1_RM_S(45, fsqrt.s, 0x10, 0f:7fc00000, 0f:c0066666, rtz);
TEST_FP_OP1_RM_S(46, fsqrt.s, 0x01, 0f:3f3504f3, 0f:3f000000, rtz);
TEST_FP_OP1_RM_S(47, fsqrt.s, 0x10, 0f:7fc00000, 0f:bf000000, rtz);
TEST_FP_OP1_RM_S(48, fsqrt.s, 0x01, 0f:46b504f3, 0f:4e000000, rtz);
TEST_FP_OP1_RM_S(49, fsqrt.s, 0x01, 0f:4f3504f3, 0f:5f000000, rtz);
TEST_FP_OP1_RM_S(50, fsqrt.s, 0x10, 0f:7fc00000, 0f:cfffd7ff, rtz);
TEST_FP_OP1_RM_S(51, fsqrt.s, 0x00, 0f:80000000, 0f:80000000, rdn);
TEST_FP_OP1_RM_S(52, fsqrt.s, 0x10, 0f:7fc00000, 0f:807fffff, rdn);
TEST_FP_OP1_RM_S(53, fsqrt.s, 0x10, 0f:7fc00000, 0f:bf800000, rdn);
TEST_FP_OP1_RM_S(54, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff800000, rdn);
TEST_FP_OP1_RM_S(55, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff7fffff, rdn);
TEST_FP_OP1_RM_S(56, fsqrt.s, 0x10, 0f:7fc00000, 0f:80000001, rdn);
TEST_FP_OP1_RM_S(57, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff800001, rdn);
TEST_FP_OP1_RM_S(58, fsqrt.s, 0x00, 0f:7fc00000, 0f:ffc00000, rdn);
TEST_FP_OP1_RM_S(59, fsqrt.s, 0x00, 0f:00000000, 0f:00000000, rdn);
TEST_FP_OP1_RM_S(60, fsqrt.s, 0x01, 0f:1ffffffe, 0f:007fffff, rdn);
TEST_FP_OP1_RM_S(61, fsqrt.s, 0x00, 0f:3f800000, 0f:3f800000, rdn);
TEST_FP_OP1_RM_S(62, fsqrt.s, 0x00, 0f:7f800000, 0f:7f800000, rdn);
TEST_FP_OP1_RM_S(63, fsqrt.s, 0x01, 0f:5f7fffff, 0f:7f7fffff, rdn);
TEST_FP_OP1_RM_S(64, fsqrt.s, 0x01, 0f:1a3504f3, 0f:00000001, rdn);
TEST_FP_OP1_RM_S(65, fsqrt.s, 0x10, 0f:7fc00000, 0f:7f800001, rdn);
TEST_FP_OP1_RM_S(66, fsqrt.s, 0x00, 0f:7fc00000, 0f:7fc00000, rdn);
TEST_FP_OP1_RM_S(67, fsqrt.s, 0x00, 0f:20000000, 0f:00800000, rdn);
TEST_FP_OP1_RM_S(68, fsqrt.s, 0x10, 0f:7fc00000, 0f:80800000, rdn);
TEST_FP_OP1_RM_S(69, fsqrt.s, 0x01, 0f:3fb97d57, 0f:40066666, rdn);
TEST_FP_OP1_RM_S(70, fsqrt.s, 0x10, 0f:7fc00000, 0f:c0066666, rdn);
TEST_FP_OP1_RM_S(71, fsqrt.s, 0x01, 0f:3f3504f3, 0f:3f000000, rdn);
TEST_FP_OP1_RM_S(72, fsqrt.s, 0x10, 0f:7fc00000, 0f:bf000000, rdn);
TEST_FP_OP1_RM_S(73, fsqrt.s, 0x01, 0f:46b504f3, 0f:4e000000, rdn);
TEST_FP_OP1_RM_S(74, fsqrt.s, 0x01, 0f:4f3504f3, 0f:5f000000, rdn);
TEST_FP_OP1_RM_S(75, fsqrt.s, 0x10, 0f:7fc00000, 0f:cfffd7ff, rdn);
TEST_FP_OP1_RM_S(76, fsqrt.s, 0x00, 0f:80000000, 0f:80000000, rup);
TEST_FP_OP1_RM_S(77, fsqrt.s, 0x10, 0f:7fc00000, 0f:807fffff, rup);
TEST_FP_OP1_RM_S(78, fsqrt.s, 0x10, 0f:7fc00000, 0f:bf800000, rup);
TEST_FP_OP1_RM_S(79, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff800000, rup);
TEST_FP_OP1_RM_S(80, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff7fffff, rup);
TEST_FP_OP1_RM_S(81, fsqrt.s, 0x10, 0f:7fc00000, 0f:80000001, rup);
TEST_FP_OP1_RM_S(82, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff800001, rup);
TEST_FP_OP1_RM_S(83, fsqrt.s, 0x00, 0f:7fc00000, 0f:ffc00000, rup);
TEST_FP_OP1_RM_S(84, fsqrt.s, 0x00, 0f:00000000, 0f:00000000, rup);
TEST_FP_OP1_RM_S(85, fsqrt.s, 0x01, 0f:1fffffff, 0f:007fffff, rup);
TEST_FP_OP1_RM_S(86, fsqrt.s, 0x00, 0f:3f800000, 0f:3f800000, rup);
TEST_FP_OP1_RM_S(87, fsqrt.s, 0x00, 0f:7f800000, 0f:7f800000, rup);
TEST_FP_OP1_RM_S(88, fsqrt.s, 0x01, 0f:5f800000, 0f:7f7fffff, rup);
TEST_FP_OP1_RM_S(89, fsqrt.s, 0x01, 0f:1a3504f4, 0f:00000001, rup);
TEST_FP_OP1_RM_S(90, fsqrt.s, 0x10, 0f:7fc00000, 0f:7f800001, rup);
TEST_FP_OP1_RM_S(91, fsqrt.s, 0x00, 0f:7fc00000, 0f:7fc00000, rup);
TEST_FP_OP1_RM_S(92, fsqrt.s, 0x00, 0f:20000000, 0f:00800000, rup);
TEST_FP_OP1_RM_S(93, fsqrt.s, 0x10, 0f:7fc00000, 0f:80800000, rup);
TEST_FP_OP1_RM_S(94, fsqrt.s, 0x01, 0f:3fb97d58, 0f:40066666, rup);
TEST_FP_OP1_RM_S(95, fsqrt.s, 0x10, 0f:7fc00000, 0f:c0066666, rup);
TEST_FP_OP1_RM_S(96, fsqrt.s, 0x01, 0f:3f3504f4, 0f:3f000000, rup);
TEST_FP_OP1_RM_S(97, fsqrt.s, 0x10, 0f:7fc00000, 0f:bf000000, rup);
TEST_FP_OP1_RM_S(98, fsqrt.s, 0x01, 0f:46b504f4, 0f:4e000000, rup);
TEST_FP_OP1_RM_S(99, fsqrt.s, 0x01, 0f:4f3504f4, 0f:5f000000, rup);
TEST_FP_OP1_RM_S(100, fsqrt.s, 0x10, 0f:7fc00000, 0f:cfffd7ff, rup);
TEST_FP_OP1_RM_S(101, fsqrt.s, 0x00, 0f:80000000, 0f:80000000, rmm);
TEST_FP_OP1_RM_S(102, fsqrt.s, 0x10, 0f:7fc00000, 0f:807fffff, rmm);
TEST_FP_OP1_RM_S(103, fsqrt.s, 0x10, 0f:7fc00000, 0f:bf800000, rmm);
TEST_FP_OP1_RM_S(104, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff800000, rmm);
TEST_FP_OP1_RM_S(105, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff7fffff, rmm);
TEST_FP_OP1_RM_S(106, fsqrt.s, 0x10, 0f:7fc00000, 0f:80000001, rmm);
TEST_FP_OP1_RM_S(107, fsqrt.s, 0x10, 0f:7fc00000, 0f:ff800001, rmm);
TEST_FP_OP1_RM_S(108, fsqrt.s, 0x00, 0f:7fc00000, 0f:ffc00000, rmm);
TEST_FP_OP1_RM_S(109, fsqrt.s, 0x00, 0f:00000000, 0f:00000000, rmm);
TEST_FP_OP1_RM_S(110, fsqrt.s, 0x01, 0f:1fffffff, 0f:007fffff, rmm);
TEST_FP_OP1_RM_S(111, fsqrt.s, 0x00, 0f:3f800000, 0f:3f800000, rmm);
TEST_FP_OP1_RM_S(112, fsqrt.s, 0x00, 0f:7f800000, 0f:7f800000, rmm);
TEST_FP_OP1_RM_S(113, fsqrt.s, 0x01, 0f:5f7fffff, 0f:7f7fffff, rmm);
TEST_FP_OP1_RM_S(114, fsqrt.s, 0x01, 0f:1a3504f3, 0f:00000001, rmm);
TEST_FP_OP1_RM_S(115, fsqrt.s, 0x10, 0f:7fc00000, 0f:7f800001, rmm);
TEST_FP_OP1_RM_S(116, fsqrt.s, 0x00, 0f:7fc00000, 0f:7fc00000, rmm);
TEST_FP_OP1_RM_S(117, fsqrt.s, 0x00, 0f:20000000, 0f:00800000, rmm);
TEST_FP_OP1_RM_S(118, fsqrt.s, 0x10, 0f:7fc00000, 0f:80800000, rmm);
TEST_FP_OP1_RM_S(119, fsqrt.s, 0x01, 0f:3fb97d58, 0f:40066666, rmm);
TEST_FP_OP1_RM_S(120, fsqrt.s, 0x10, 0f:7fc00000, 0f:c0066666, rmm);
TEST_FP_OP1_RM_S(121, fsqrt.s, 0x01, 0f:3f3504f3, 0f:3f000000, rmm);
TEST_FP_OP1_RM_S(122, fsqrt.s, 0x10, 0f:7fc00000, 0f:bf000000, rmm);
TEST_FP_OP1_RM_S(123, fsqrt.s, 0x01, 0f:46b504f3, 0f:4e000000, rmm);
TEST_FP_OP1_RM_S(124, fsqrt.s, 0x01, 0f:4f3504f3, 0f:5f000000, rmm);
TEST_FP_OP1_RM_S(125, fsqrt.s, 0x10, 0f:7fc00000, 0f:cfffd7ff, rmm);
TEST_FP_OP1_RM_D(126, fsqrt.d, 0x00, 0f:8000000000000000, 0f:8000000000000000, rne);
TEST_FP_OP1_RM_D(127, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:800fffffffffffff, rne);
TEST_FP_OP1_RM_D(128, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:bff0000000000000, rne);
TEST_FP_OP1_RM_D(129, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:fff0000000000000, rne);
TEST_FP_OP1_RM_D(130, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:ffefffffffffffff, rne);
TEST_FP_OP1_RM_D(131, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:8000000000000001, rne);
TEST_FP_OP1_RM_D(132, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:fff0000000000001, rne);
TEST_FP_OP1_RM_D(133, fsqrt.d, 0x00, 0f:7ff8000000000000, 0f:fff8000000000000, rne);
TEST_FP_OP1_RM_D(134, fsqrt.d, 0x00, 0f:0000000000000000, 0f:0000000000000000, rne);
TEST_FP_OP1_RM_D(135, fsqrt.d, 0x01, 0f:1fffffffffffffff, 0f:000fffffffffffff, rne);
TEST_FP_OP1_RM_D(136, fsqrt.d, 0x00, 0f:3ff0000000000000, 0f:3ff0000000000000, rne);
TEST_FP_OP1_RM_D(137, fsqrt.d, 0x00, 0f:7ff0000000000000, 0f:7ff0000000000000, rne);
TEST_FP_OP1_RM_D(138, fsqrt.d, 0x01, 0f:5fefffffffffffff, 0f:7fefffffffffffff, rne);
TEST_FP_OP1_RM_D(139, fsqrt.d, 0x00, 0f:1e60000000000000, 0f:0000000000000001, rne);
TEST_FP_OP1_RM_D(140, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:7ff0000000000001, rne);
TEST_FP_OP1_RM_D(141, fsqrt.d, 0x00, 0f:7ff8000000000000, 0f:7ff8000000000000, rne);
TEST_FP_OP1_RM_D(142, fsqrt.d, 0x00, 0f:2000000000000000, 0f:0010000000000000, rne);
TEST_FP_OP1_RM_D(143, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:8010000000000000, rne);
TEST_FP_OP1_RM_D(144, fsqrt.d, 0x01, 0f:3ff72faafc7e3cd7, 0f:4000cccccccccccd, rne);
TEST_FP_OP1_RM_D(145, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:c000cccccccccccd, rne);
TEST_FP_OP1_RM_D(146, fsqrt.d, 0x01, 0f:3fe6a09e667f3bcd, 0f:3fe0000000000000, rne);
TEST_FP_OP1_RM_D(147, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:bfe0000000000000, rne);
TEST_FP_OP1_RM_D(148, fsqrt.d, 0x01, 0f:47d6a09e667f3bcd, 0f:4fc0000000000000, rne);
TEST_FP_OP1_RM_D(149, fsqrt.d, 0x01, 0f:4fe6a09e667f3bcd, 0f:5fe0000000000000, rne);
TEST_FP_OP1_RM_D(150, fsqrt.d, 0x01, 0f:3f9116ff033cb0d0, 0f:3f3240fef40a55d0, rne);
TEST_FP_OP1_RM_D(151, fsqrt.d, 0x00, 0f:8000000000000000, 0f:8000000000000000, rtz);
TEST_FP_OP1_RM_D(152, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:800fffffffffffff, rtz);
TEST_FP_OP1_RM_D(153, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:bff0000000000000, rtz);
TEST_FP_OP1_RM_D(154, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:fff0000000000000, rtz);
TEST_FP_OP1_RM_D(155, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:ffefffffffffffff, rtz);
TEST_FP_OP1_RM_D(156, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:8000000000000001, rtz);
TEST_FP_OP1_RM_D(157, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:fff0000000000001, rtz);
TEST_FP_OP1_RM_D(158, fsqrt.d, 0x00, 0f:7ff8000000000000, 0f:fff8000000000000, rtz);
TEST_FP_OP1_RM_D(159, fsqrt.d, 0x00, 0f:0000000000000000, 0f:0000000000000000, rtz);
TEST_FP_OP1_RM_D(160, fsqrt.d, 0x01, 0f:1ffffffffffffffe, 0f:000fffffffffffff, rtz);
TEST_FP_OP1_RM_D(161, fsqrt.d, 0x00, 0f:3ff0000000000000, 0f:3ff0000000000000, rtz);
TEST_FP_OP1_RM_D(162, fsqrt.d, 0x00, 0f:7ff0000000000000, 0f:7ff0000000000000, rtz);
TEST_FP_OP1_RM_D(163, fsqrt.d, 0x01, 0f:5fefffffffffffff, 0f:7fefffffffffffff, rtz);
TEST_FP_OP1_RM_D(164, fsqrt.d, 0x00, 0f:1e60000000000000, 0f:0000000000000001, rtz);
TEST_FP_OP1_RM_D(165, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:7ff0000000000001, rtz);
TEST_FP_OP1_RM_D(166, fsqrt.d, 0x00, 0f:7ff8000000000000, 0f:7ff8000000000000, rtz);
TEST_FP_OP1_RM_D(167, fsqrt.d, 0x00, 0f:2000000000000000, 0f:0010000000000000, rtz);
TEST_FP_OP1_RM_D(168, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:8010000000000000, rtz);
TEST_FP_OP1_RM_D(169, fsqrt.d, 0x01, 0f:3ff72faafc7e3cd6, 0f:4000cccccccccccd, rtz);
TEST_FP_OP1_RM_D(170, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:c000cccccccccccd, rtz);
TEST_FP_OP1_RM_D(171, fsqrt.d, 0x01, 0f:3fe6a09e667f3bcc, 0f:3fe0000000000000, rtz);
TEST_FP_OP1_RM_D(172, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:bfe0000000000000, rtz);
TEST_FP_OP1_RM_D(173, fsqrt.d, 0x01, 0f:47d6a09e667f3bcc, 0f:4fc0000000000000, rtz);
TEST_FP_OP1_RM_D(174, fsqrt.d, 0x01, 0f:4fe6a09e667f3bcc, 0f:5fe0000000000000, rtz);
TEST_FP_OP1_RM_D(175, fsqrt.d, 0x01, 0f:3f9116ff033cb0d0, 0f:3f3240fef40a55d0, rtz);
TEST_FP_OP1_RM_D(176, fsqrt.d, 0x00, 0f:8000000000000000, 0f:8000000000000000, rdn);
TEST_FP_OP1_RM_D(177, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:800fffffffffffff, rdn);
TEST_FP_OP1_RM_D(178, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:bff0000000000000, rdn);
TEST_FP_OP1_RM_D(179, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:fff0000000000000, rdn);
TEST_FP_OP1_RM_D(180, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:ffefffffffffffff, rdn);
TEST_FP_OP1_RM_D(181, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:8000000000000001, rdn);
TEST_FP_OP1_RM_D(182, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:fff0000000000001, rdn);
TEST_FP_OP1_RM_D(183, fsqrt.d, 0x00, 0f:7ff8000000000000, 0f:fff8000000000000, rdn);
TEST_FP_OP1_RM_D(184, fsqrt.d, 0x00, 0f:0000000000000000, 0f:0000000000000000, rdn);
TEST_FP_OP1_RM_D(185, fsqrt.d, 0x01, 0f:1ffffffffffffffe, 0f:000fffffffffffff, rdn);
TEST_FP_OP1_RM_D(186, fsqrt.d, 0x00, 0f:3ff0000000000000, 0f:3ff0000000000000, rdn);
TEST_FP_OP1_RM_D(187, fsqrt.d, 0x00, 0f:7ff0000000000000, 0f:7ff0000000000000, rdn);
TEST_FP_OP1_RM_D(188, fsqrt.d, 0x01, 0f:5fefffffffffffff, 0f:7fefffffffffffff, rdn);
TEST_FP_OP1_RM_D(189, fsqrt.d, 0x00, 0f:1e60000000000000, 0f:0000000000000001, rdn);
TEST_FP_OP1_RM_D(190, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:7ff0000000000001, rdn);
TEST_FP_OP1_RM_D(191, fsqrt.d, 0x00, 0f:7ff8000000000000, 0f:7ff8000000000000, rdn);
TEST_FP_OP1_RM_D(192, fsqrt.d, 0x00, 0f:2000000000000000, 0f:0010000000000000, rdn);
TEST_FP_OP1_RM_D(193, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:8010000000000000, rdn);
TEST_FP_OP1_RM_D(194, fsqrt.d, 0x01, 0f:3ff72faafc7e3cd6, 0f:4000cccccccccccd, rdn);
TEST_FP_OP1_RM_D(195, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:c000cccccccccccd, rdn);
TEST_FP_OP1_RM_D(196, fsqrt.d, 0x01, 0f:3fe6a09e667f3bcc, 0f:3fe0000000000000, rdn);
TEST_FP_OP1_RM_D(197, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:bfe0000000000000, rdn);
TEST_FP_OP1_RM_D(198, fsqrt.d, 0x01, 0f:47d6a09e667f3bcc, 0f:4fc0000000000000, rdn);
TEST_FP_OP1_RM_D(199, fsqrt.d, 0x01, 0f:4fe6a09e667f3bcc, 0f:5fe0000000000000, rdn);
TEST_FP_OP1_RM_D(200, fsqrt.d, 0x01, 0f:3f9116ff033cb0d0, 0f:3f3240fef40a55d0, rdn);
TEST_FP_OP1_RM_D(201, fsqrt.d, 0x00, 0f:8000000000000000, 0f:8000000000000000, rup);
TEST_FP_OP1_RM_D(202, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:800fffffffffffff, rup);
TEST_FP_OP1_RM_D(203, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:bff0000000000000, rup);
TEST_FP_OP1_RM_D(204, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:fff0000000000000, rup);
TEST_FP_OP1_RM_D(205, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:ffefffffffffffff, rup);
TEST_FP_OP1_RM_D(206, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:8000000000000001, rup);
TEST_FP_OP1_RM_D(207, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:fff0000000000001, rup);
TEST_FP_OP1_RM_D(208, fsqrt.d, 0x00, 0f:7ff8000000000000, 0f:fff8000000000000, rup);
TEST_FP_OP1_RM_D(209, fsqrt.d, 0x00, 0f:0000000000000000, 0f:0000000000000000, rup);
TEST_FP_OP1_RM_D(210, fsqrt.d, 0x01, 0f:1fffffffffffffff, 0f:000fffffffffffff, rup);
TEST_FP_OP1_RM_D(211, fsqrt.d, 0x00, 0f:3ff0000000000000, 0f:3ff0000000000000, rup);
TEST_FP_OP1_RM_D(212, fsqrt.d, 0x00, 0f:7ff0000000000000, 0f:7ff0000000000000, rup);
TEST_FP_OP1_RM_D(213, fsqrt.d, 0x01, 0f:5ff0000000000000, 0f:7fefffffffffffff, rup);
TEST_FP_OP1_RM_D(214, fsqrt.d, 0x00, 0f:1e60000000000000, 0f:0000000000000001, rup);
TEST_FP_OP1_RM_D(215, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:7ff0000000000001, rup);
TEST_FP_OP1_RM_D(216, fsqrt.d, 0x00, 0f:7ff8000000000000, 0f:7ff8000000000000, rup);
TEST_FP_OP1_RM_D(217, fsqrt.d, 0x00, 0f:2000000000000000, 0f:0010000000000000, rup);
TEST_FP_OP1_RM_D(218, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:8010000000000000, rup);
TEST_FP_OP1_RM_D(219, fsqrt.d, 0x01, 0f:3ff72faafc7e3cd7, 0f:4000cccccccccccd, rup);
TEST_FP_OP1_RM_D(220, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:c000cccccccccccd, rup);
TEST_FP_OP1_RM_D(221, fsqrt.d, 0x01, 0f:3fe6a09e667f3bcd, 0f:3fe0000000000000, rup);
TEST_FP_OP1_RM_D(222, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:bfe0000000000000, rup);
TEST_FP_OP1_RM_D(223, fsqrt.d, 0x01, 0f:47d6a09e667f3bcd, 0f:4fc0000000000000, rup);
TEST_FP_OP1_RM_D(224, fsqrt.d, 0x01, 0f:4fe6a09e667f3bcd, 0f:5fe0000000000000, rup);
TEST_FP_OP1_RM_D(225, fsqrt.d, 0x01, 0f:3f9116ff033cb0d1, 0f:3f3240fef40a55d0, rup);
TEST_FP_OP1_RM_D(226, fsqrt.d, 0x00, 0f:8000000000000000, 0f:8000000000000000, rmm);
TEST_FP_OP1_RM_D(227, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:800fffffffffffff, rmm);
TEST_FP_OP1_RM_D(228, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:bff0000000000000, rmm);
TEST_FP_OP1_RM_D(229, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:fff0000000000000, rmm);
TEST_FP_OP1_RM_D(230, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:ffefffffffffffff, rmm);
TEST_FP_OP1_RM_D(231, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:8000000000000001, rmm);
TEST_FP_OP1_RM_D(232, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:fff0000000000001, rmm);
TEST_FP_OP1_RM_D(233, fsqrt.d, 0x00, 0f:7ff8000000000000, 0f:fff8000000000000, rmm);
TEST_FP_OP1_RM_D(234, fsqrt.d, 0x00, 0f:0000000000000000, 0f:0000000000000000, rmm);
TEST_FP_OP1_RM_D(235, fsqrt.d, 0x01, 0f:1fffffffffffffff, 0f:000fffffffffffff, rmm);
TEST_FP_OP1_RM_D(236, fsqrt.d, 0x00, 0f:3ff0000000000000, 0f:3ff0000000000000, rmm);
TEST_FP_OP1_RM_D(237, fsqrt.d, 0x00, 0f:7ff0000000000000, 0f:7ff0000000000000, rmm);
TEST_FP_OP1_RM_D(238, fsqrt.d, 0x01, 0f:5fefffffffffffff, 0f:7fefffffffffffff, rmm);
TEST_FP_OP1_RM_D(239, fsqrt.d, 0x00, 0f:1e60000000000000, 0f:0000000000000001, rmm);
TEST_FP_OP1_RM_D(240, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:7ff0000000000001, rmm);
TEST_FP_OP1_RM_D(241, fsqrt.d, 0x00, 0f:7ff8000000000000, 0f:7ff8000000000000, rmm);
TEST_FP_OP1_RM_D(242, fsqrt.d, 0x00, 0f:2000000000000000, 0f:0010000000000000, rmm);
TEST_FP_OP1_RM_D(243, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:8010000000000000, rmm);
TEST_FP_OP1_RM_D(244, fsqrt.d, 0x01, 0f:3ff72faafc7e3cd7, 0f:4000cccccccccccd, rmm);
TEST_FP_OP1_RM_D(245, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:c000cccccccccccd, rmm);
TEST_FP_OP1_RM_D(246, fsqrt.d, 0x01, 0f:3fe6a09e667f3bcd, 0f:3fe0000000000000, rmm);
TEST_FP_OP1_RM_D(247, fsqrt.d, 0x10, 0f:7ff8000000000000, 0f:bfe0000000000000, rmm);
TEST_FP_OP1_RM_D(248, fsqrt.d, 0x01, 0f:47d6a09e667f3bcd, 0f:4fc0000000000000, rmm);
TEST_FP_OP1_RM_D(249, fsqrt.d, 0x01, 0f:4fe6a09e667f3bcd, 0f:5fe0000000000000, rmm);
TEST_FP_OP1_RM_D(250, fsqrt.d, 0x01, 0f:3f9116ff033cb0d0, 0f:3f3240fef40a55d0, rmm);

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END

