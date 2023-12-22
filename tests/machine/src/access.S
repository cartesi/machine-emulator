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

#define exit_imm(imm) \
    li gp, imm; \
    j exit;

#define MSTATUS_FS_MASK     (3<<13)

#define MCAUSE_INSN_ADDRESS_MISALIGNED 0x0      ///< Instruction address misaligned
#define MCAUSE_INSN_ACCESS_FAULT 0x1            ///< Instruction access fault
#define MCAUSE_ILLEGAL_INSN 0x2                 ///< Illegal instruction
#define MCAUSE_BREAKPOINT 0x3                   ///< Breakpoint
#define MCAUSE_LOAD_ADDRESS_MISALIGNED 0x4      ///< Load address misaligned
#define MCAUSE_LOAD_ACCESS_FAULT 0x5            ///< Load access fault
#define MCAUSE_STORE_AMO_ADDRESS_MISALIGNED 0x6 ///< Store/AMO address misaligned
#define MCAUSE_STORE_AMO_ACCESS_FAULT 0x7       ///< Store/AMO access fault
#define MCAUSE_ECALL_BASE 0x8                   ///< Environment call (+0: from U-mode, +1: from S-mode, +3: from M-mode)
#define MCAUSE_SUPERVISOR_ECALL 0x9             ///< Environment call from S-mode
#define MCAUSE_MACHINE_ECALL 0xb                ///< Environment call from M-mode
#define MCAUSE_FETCH_PAGE_FAULT 0xc             ///< Instruction page fault
#define MCAUSE_LOAD_PAGE_FAULT 0xd              ///< Load page fault
#define MCAUSE_STORE_AMO_PAGE_FAULT 0xf         ///< Store/AMO page fault

#define HTIF_IHALT_ADDR      0x40008010
#define HTIF_INVALID_ADDR    0x40008100
#define MEM_FLASH_DRIVE_ADDR 0x80000000000000

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    // Set a trap that will ignore the failing instruction and resume to next instruction
    la t0, skip_instruction_trap
    csrw mtvec, t0
    li a5, 0xc00fd00d

    // Enable FS state
    li t0, MSTATUS_FS_MASK;
    csrs mstatus, t0;

    // Writes in the shadow area should raise store access fault exception
    li gp, 0
    sd zero, (zero)
    li t0, MCAUSE_STORE_AMO_ACCESS_FAULT
    bne gp, t0, exit

    // Attempt to store a float in the shadow should raise store access fault exception
    li gp, 0
    fsd f0, (zero)
    li t0, MCAUSE_STORE_AMO_ACCESS_FAULT
    bne gp, t0, exit

    // Attempts to read invalid addresses in HTIF should raise load access fault exception
    mv a0, a5
    li a1, HTIF_INVALID_ADDR
    li gp, 0
    ld a0, (a1)
    bne a0, a5, fail
    li t0, MCAUSE_LOAD_ACCESS_FAULT
    bne gp, t0, exit

    // HTIF ihalt should be readable but not writable,
    // therefore writes to it should raise an store access fault exception
    mv a0, a5
    li a3, HTIF_IHALT_ADDR
    li gp, 0
    amoswap.d a0, zero, (a3)
    bne a0, a5, fail
    li t0, MCAUSE_STORE_AMO_ACCESS_FAULT
    bne gp, t0, exit

    // Attempt to read an invalid CSR should raise an illegal instruction exception
    li gp, 0
    csrr a0, 0x800
    li t0, MCAUSE_ILLEGAL_INSN
    bne gp, t0, exit

    // Attempt to set a bit in an invalid CSR should raise an illegal instruction exception
    li gp, 0
    csrrci a0, 0x800, 1
    li t0, MCAUSE_ILLEGAL_INSN
    bne gp, t0, exit

    // Attempt to set a bit in an non-writable CSR should raise an illegal instruction exception
    li gp, 0
    csrrci a0, mvendorid, 1
    li t0, MCAUSE_ILLEGAL_INSN
    bne gp, t0, exit

    // Memory flash drivers are not executable,
    // executing instructions on it should raise an instruction access fault
    la t0, jalr_trap
    csrw mtvec, t0
    li t0, MEM_FLASH_DRIVE_ADDR
    jalr t0

    exit_imm(254)

jalr_trap:
    csrr gp, mcause
    li t0, MCAUSE_INSN_ACCESS_FAULT
    bne gp, t0, exit
    exit_imm(0)

fail:
    exit_imm(255)

skip_instruction_trap:
    csrr t0, mepc
    addi t0, t0, 4
    csrw mepc, t0
    csrr gp, mcause
    mret
    exit_imm(1)

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
