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

#ifndef _UARCH_ENV_FOR_RISCV_TESTS_H
#define _UARCH_ENV_FOR_RISCV_TESTS_H

#include <uarch-defines.h>

#define RVTEST_RV64U                                                    \
  .macro init;                                                          \
  .endm

#define RVTEST_CODE_BEGIN                                               \
        .section .text.init;                                            \
        .globl _start;                                                  \
_start:                                                                 \


#define RVTEST_HALT                                                     \
        li  a7, UARCH_ECALL_FN_HALT_DEF;                                \
        ecall;                                                          \

//-----------------------------------------------------------------------
// End Macro
//-----------------------------------------------------------------------

#define TESTNUM gp
#define TEST_SUCCEEDED 0xbe1e7aaa
#define TEST_FAILED   0xdeadbeef

#define RVTEST_CODE_END                                                 \
        li ra, TEST_SUCCEEDED;                                          \
        RVTEST_HALT

//-----------------------------------------------------------------------
// Pass/Fail Macro
//-----------------------------------------------------------------------

#define RVTEST_PASS                                                     \
        li ra, TEST_SUCCEEDED;                                          \
        li TESTNUM, 1;                                                  \

#define RVTEST_FAIL                                                     \
        li ra, TEST_FAILED;                                             \
        RVTEST_HALT

//-----------------------------------------------------------------------
// Data Section Macro
//-----------------------------------------------------------------------

#define EXTRA_DATA \
  ;

#define RVTEST_DATA_BEGIN                                               \
  ;

#define RVTEST_DATA_END  \
  ;

#endif
