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


#include <address-range-defines.h>

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
  li gp, imm; \
  j exit;

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
  // Set the exception handler to trap
  // This is just in case an exception happens
  la t0, trap;
  csrw mtvec, t0;
do_break:
  ebreak
  j fail

// catch exception and exit
trap:
  li t1, 0x3 // MCAUSE_BREAKPOINT
  csrr t0, mcause
  bne t0, t1, fail
  la t1, do_break
  csrr t0, mtval
// software breakpoint exceptions write PC to xtval
  bne t0, t1, fail
  j exit

fail:
  exit_imm(1);

// Exits via HTIF using gp content as the exit code
exit:
  // HTIF exits with dev = cmd = 0 and a payload with lsb set.
  // the exit code is taken from payload >> 2
  slli gp, gp, 16;
  srli gp, gp, 15;
  ori gp, gp, 1;
1:
  li t0, AR_HTIF_START_DEF
  sd gp, 0(t0);
  j 1b; // Should not be necessary

