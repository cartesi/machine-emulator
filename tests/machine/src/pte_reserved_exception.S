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


#include <pma-defines.h>

#define MSTATUS_MPP 0x1800
#define CAUSE_USER_ECALL 0x8
#define CAUSE_INSTRUCTION_PAGE_FAULT 0xc
#define PTE_FLAGS 0x3f // V | R | W | X | G | U
#define PTE_RESERVED 4 // right shift to the PTE reserved field
#define SATP_SV39 0x8000000000000000

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
  li gp, imm; \
  j exit;

.section .text.init
.align 2;
.global _start;
_start:

// Set the exception handler to trap
// This is just in case an exception happens
  la t0, trap;
  csrw mtvec, t0;

// Set up a page table entry that maps 0x0... to 0x8...
  la      t0, page_table
  srl     t0, t0, 12
  li      t1, SATP_SV39
  or      t0, t0, t1
  csrw    satp, t0

// Set user mode
  csrr    t1, mstatus
  li      t0, ~MSTATUS_MPP
  and     t1, t0, t1
  csrw    mstatus, t1

  la      t0, (user - 0x80000000)
  csrw    mepc, t0

  mret

user:
  ecall

// catch exception and exit
trap:
  csrr t0, mcause
// page fault because reserved PTE bit is set
  li t1, CAUSE_INSTRUCTION_PAGE_FAULT
  beq t0, t1, success
  exit_imm(1);

success:
  exit_imm(0);

// Exits via HTIF using gp content as the exit code
exit:
// HTIF exits with dev = cmd = 0 and a payload with lsb set.
// the exit code is taken from payload >> 2
  slli gp, gp, 16;
  srli gp, gp, 15;
  ori gp, gp, 1;
1:
  li t0, PMA_HTIF_START_DEF
  sd gp, 0(t0);
  j 1b; // Should not be necessary

.data
.align 12
.skip 176
page_table:
  .word   ((0x80000000 >> 2) | PTE_FLAGS)
  .word   (0x80000000 >> PTE_RESERVED)
