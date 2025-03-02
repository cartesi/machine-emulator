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


// This test case tests software interrupts and interrupt delegation

#include <address-range-defines.h>

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
    li gp, imm; \
    j exit;

#define SSI_CODE            1
#define MTI_CODE            7
#define SSI_MASK            (1<<SSI_CODE)
#define MTI_MASK            (1<<MTI_CODE)

#define MCAUSE_INT_BIT      63
#define MCAUSE_SSIP         ((1<<MCAUSE_INT_BIT) | SSI_CODE)
#define MCAUSE_MTIP         ((1<<MCAUSE_INT_BIT) | MTI_CODE)

#define MTIMECMP_ADDR       (AR_CLINT_START_DEF + 0x4000)

#define MSTATUS_MPP_MASK 0x1800
#define MSTATUS_SPP_MASK 0x100
#define MSTATUS_SIE_MASK (1<<1)
#define MSTATUS_MIE_MASK (1<<3)
#define MSTATUS_MPP_S    0x800

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    // Set the M-mode interrupt handler trap
    la t0, machine_trap_SSI
    csrw mtvec, t0

    // Store 1 in MTIMECMP
    li t0, MTIMECMP_ADDR
    li t1, 1
    sd t1, 0(t0)

    // Set interrupt counter to 0
    li t5, 0

    // Enable M-mode interrupts in MSTATUS
    csrsi mstatus, MSTATUS_MIE_MASK

    // Enable timer/software interrupts
    li t0, (MTI_MASK | SSI_MASK)
    csrs mie, t0

    // Trigger software interrupt
    csrsi mip, SSI_MASK

    // When interrupt is processed, interrupt counter should have been incremented by 1
    li t0, 1
    bne t5, t0, fail

    // Delegate software interrupts to S-mode
    csrsi mideleg, SSI_MASK

    // Set the M-mode interrupt handler trap
    la t0, machine_trap_MTI_exit
    csrw mtvec, t0

    // Enter supervisor mode
    la t0, in_supervisor
    csrw mepc, t0
    li t0, MSTATUS_MPP_MASK
    csrc mstatus, t0
    li t0, MSTATUS_MPP_S
    csrs mstatus, t0
    mret
    exit_imm(1)

in_supervisor:
    // Set the S-mode interrupt handler trap
    la t0, supervisor_trap_SSI
    csrw stvec, t0

    // Enable S-mode interrupts in MSTATUS
    csrsi sstatus, MSTATUS_SIE_MASK

    // Trigger software interrupts
    csrsi sip, SSI_MASK

    // When interrupt is processed, interrupt counter should have been incremented by 1
    li t0, 2
    bne t5, t0, fail

    // Enter U-mode
    la t0, in_user
    csrw sepc, t0
    li t0, MSTATUS_SPP_MASK
    csrc sstatus, t0
    sret
    exit_imm(1)

in_user:
    // At some point timer interrupt will be triggered and the loop will break
    nop
    j in_user

supervisor_trap_SSI:
    // Check the interrupt cause
    csrr t4, scause
    li t3, MCAUSE_SSIP
    bne t4, t3, fail

    // Clear the interrupt pending bit
    csrci sip, SSI_MASK

    // Increment interrupt counter
    addi t5, t5, 1

    // Return
    sret

machine_trap_SSI:
    // Check the interrupt cause
    csrr t4, mcause
    li t3, MCAUSE_SSIP
    bne t4, t3, fail

    // Clear the interrupt pending bit
    csrci mip, SSI_MASK

    // Increment interrupt counter
    addi t5, t5, 1

    // Return
    mret

machine_trap_MTI_exit:
    // Check the interrupt cause
    csrr t4, mcause
    li t3, MCAUSE_MTIP
    bne t4, t3, fail

    // Clear the interrupt pending bit
    li t4, MTI_MASK
    csrc mip, t4

    // Increment interrupt counter
    addi t5, t5, 1

    // When interrupt is processed, interrupt counter should have been incremented by 1
    li t0, 3
    bne t5, t0, fail

    // Success
    exit_imm(0)

fail:
    exit_imm(1)

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
