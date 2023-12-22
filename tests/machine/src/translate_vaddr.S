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
#include <encoding.h>

#define PTE_FLAGS (PTE_V | PTE_R | PTE_W | PTE_X | PTE_U)
#define PTE_RESERVED 4 // right shift to the PTE reserved field
#define SATP_MODE_SHIFT 60

#define MSTATUS_MPP_MASK 0x1800
#define MSTATUS_MPP_S    0x800

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
  li gp, imm; \
  j exit;

.section .text.init
.align 2;
.global _start;
_start:
    // Set the exception handler
    la t0, skip_fetch_page_fault_trap;
    csrw mtvec, t0;

    // Enable virtual address translation in user mode
    la      t0, page_table
    srl     t0, t0, RISCV_PGSHIFT
    li      t1, (SATP_MODE_SV39 << SATP_MODE_SHIFT)
    or      t0, t0, t1
    csrw    satp, t0

test1:
    //Setting reserved bits in PTE should raise a page fault
    li t0, (PTE_RSVD | PTE_V | PTE_R | PTE_W | PTE_X | PTE_U)
    la t1, page_table
    sd t0, (t1)
    li a0, 0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

test2:
    // Svpbmt is not implemented, setting its bits in PTE should raise a page fault
    li t0, (PTE_PBMT | PTE_V | PTE_R | PTE_W | PTE_X | PTE_U)
    la t1, page_table
    sd t0, (t1)
    li a0, 0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

test3:
    // Svnapot is not implemented, setting its bits in PTE should raise a page fault
    li t0, (PTE_N | PTE_V | PTE_R | PTE_W | PTE_X | PTE_U)
    la t1, page_table
    sd t0, (t1)
    li a0, 0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

test4:
    // PTE with V unset should raise a page fault
    li t0, (PTE_R | PTE_W | PTE_X | PTE_U)
    la t1, page_table
    sd t0, (t1)
    li a0, 0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

test5: // Reserved PTE protection bits (write + execute) are disallowed
    li t0, (PTE_V | PTE_W | PTE_X | PTE_U)
    la t1, page_table
    sd t0, (t1)
    li a0, 0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

test6: // Attempt to execute a read-only page
    li t0, (PTE_V | PTE_R | PTE_U)
    la t1, page_table
    sd t0, (t1)
    li a0, 0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

test7: // U-mode is not allowed to access privileged memory
    li t0, (PTE_V | PTE_R | PTE_X)
    la t1, page_table
    sd t0, (t1)
    li a0, 0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

test8: // PTE with memory out of range
    li t0, (PTE_V | PTE_U)
    li t1, (1 << 38)
    srli t1, t1, 2
    or t0, t0, t1
    la t1, page_table
    sd t0, (t1)
    li a0, 0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

test9: // Recursive PTE should raise a page fault
    li t0, PTE_V
    la t1, page_table
    srli t1, t1, 2
    or t0, t0, t1
    la t1, page_table
    sd t0, (t1)
    li a0, 0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

test10:
    // Unused significant bits in virtual address must be
    // filled with copies of most significant bit of its VPN,
    // otherwise a page fault should be raised
    li t0, (PTE_V | PTE_R | PTE_W | PTE_X | PTE_U)
    la t1, page_table
    sd t0, (t1)
    li a0, (1 << 39) // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

test13:
    // S-mode can never execute instructions from user pages,
    // regardless of the state of SUM

    // Enable SUM in mstatus
    li      t0, MSTATUS_SUM
    csrs    mstatus, t0

    // Set PTE entry
    li t0, (PTE_V | PTE_R | PTE_X | PTE_U)
    la t1, page_table
    sd t0, (t1)

    // Set vaddr PC and enter U-mode
    li a0, 0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_supervisor_mode

test11: // We should be able to execute instructions in U-mode using virtual memory
    // Set the exception handler
    la t0, skip_user_ecall_trap;
    csrw mtvec, t0;

    // Set PTE entry
    li t0, (PTE_V | PTE_R | PTE_X | PTE_U)
    la t1, user_ecall
    srli t1, t1, 2
    or t0, t0, t1
    la t1, page_table
    sd t0, (t1)

    // Set vaddr PC and enter U-mode
    la t0, user_ecall
    li a0, 4095
    and a0, a0, t0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

test12:
    // We should be able to read from execute-only pages in less privileged mode
    // only when mstatus.MXR is enabled

    // Set PTE entry
    li t0, (PTE_V | PTE_X | PTE_U)
    la t1, user_read_pc
    srli t1, t1, 12
    slli t1, t1, 10
    or t0, t0, t1
    la t1, page_table
    sd t0, (t1)

    // Set the exception handler
    la t0, skip_load_page_fault_trap;
    csrw mtvec, t0;

    // Set vaddr PC and enter U-mode
    la t0, user_read_pc
    li a0, 4095
    and a0, a0, t0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

    // Enable MXR in mstatus
    li      t0, MSTATUS_MXR
    csrs    mstatus, t0

    // Set PTE entry
    li t0, (PTE_V | PTE_X | PTE_U)
    la t1, user_read_pc
    srli t1, t1, 12
    slli t1, t1, 10
    or t0, t0, t1
    la t1, page_table
    sd t0, (t1)

    // Set the exception handler
    la t0, skip_user_ecall_trap;
    csrw mtvec, t0;

    // Set vaddr PC and enter U-mode
    la t0, user_read_pc
    li a0, 4095
    and a0, a0, t0 // vaddr pc
    auipc a1, 0 // return pc
    j enter_user_mode

success:
    exit_imm(0);

user_ecall:
    ecall
    exit_imm(1)

user_read_pc:
    auipc t0, 0
    lw t0, (t0)
    li t1, 0x00000297 // hexcode for "auipc t0, t0"
    bne t0, t1, fail
    ecall
    exit_imm(1)

enter_user_mode:
    csrr    t1, mstatus
    li      t0, ~MSTATUS_MPP
    and     t1, t0, t1
    csrw    mstatus, t1
    csrw    mepc, a0
    mret
    exit_imm(1)

enter_supervisor_mode:
    li t0, MSTATUS_MPP_MASK
    csrc mstatus, t0
    li t0, MSTATUS_MPP_S
    csrs mstatus, t0
    csrw mepc, a0
    mret
    exit_imm(1)

skip_user_ecall_trap:
    csrr t0, mcause
    li t1, CAUSE_USER_ECALL
    bne t0, t1, fail
    jalr a1, 8

skip_fetch_page_fault_trap:
    csrr t0, mcause
    li t1, CAUSE_FETCH_PAGE_FAULT
    bne t0, t1, fail
    jalr a1, 8

skip_load_page_fault_trap:
    csrr t0, mcause
    li t1, CAUSE_LOAD_PAGE_FAULT
    bne t0, t1, fail
    jalr a1, 8

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
    li t0, PMA_HTIF_START_DEF
    sd gp, 0(t0);
    j 1b; // Should not be necessary

.data
.align 12; page_table: .dword 0
