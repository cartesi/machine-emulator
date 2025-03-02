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


// This test case tests many CSR semantics in different privilege modes

#include <address-range-defines.h>

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
    li gp, imm; \
    j exit;

#define MSTATUS_MPP_MASK    0x1800
#define MSTATUS_MPRV_MASK   (1<<17)
#define MSTATUS_SPP_MASK    0x100
#define MSTATUS_FS_MASK     (3<<13)
#define MSTATUS_TVM_MASK    (1<<20)
#define MSTATUS_TW_MASK     (1<<21)
#define MSTATUS_MPP_U       0x0
#define MSTATUS_MPP_S       0x800
#define MSTATUS_MPP_HS      0x1000
#define MSTATUS_MPP_M       0x1800
#define MCAUSE_SUPERVISOR_ECALL 9
#define MCAUSE_ILLEGAL_INSN     0x2

#define menvcfg 0x30a
#define senvcfg 0x10a

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    // Set the exception handler to trap
    // This is just in case an exception happens
    la t0, fail_trap
    csrw mtvec, t0

    // Set MPRV, we will check later if its cleared after MRET
    li t0, MSTATUS_MPRV_MASK
    csrs mstatus, t0

    // Check if HS-mode is supported (currently it's not)
    li t0, MSTATUS_MPP_MASK
    csrc mstatus, t0        // set MPP to U-mode
    li t1, MSTATUS_MPP_HS
    csrs mstatus, t1        // attempt to set MPP to HS-mode
    csrr t2, mstatus
    and t2, t2, t0          // read MPP
    bne t2, zero, fail      // MPP should be in U-mode

    // Check if S-mode is supported
    li t0, MSTATUS_MPP_MASK
    csrc mstatus, t0        // set MPP to U-mode
    li t1, MSTATUS_MPP_S
    csrs mstatus, t1        // attempt to set MPP to S-mode
    csrr t2, mstatus
    and t2, t2, t0          // read MPP
    bne t2, t1, fail        // MPP should be in S-mode

    // Check if M-mode is supported
    li t0, MSTATUS_MPP_MASK
    csrc mstatus, t0        // set MPP to U-mode
    li t1, MSTATUS_MPP_M
    csrs mstatus, t1        // attempt to set MPP to S-mode
    csrr t2, mstatus
    and t2, t2, t0          // read MPP
    bne t2, t1, fail        // MPP should be in M-mode

    // Writing invalid modes to satp doesn't change it
    csrr t0, satp
    li t1, (2 << 60) // mode 2 is reserved and invalid
    csrw satp, t1
    csrr t1, satp
    bne t0, t1, fail

    // We should be able to read/write mtval
    li t0, 0xff
    csrw mtval, t0
    csrr t1, mtval
    bne t1, t0, fail

    // We should be able to read/write mcause
    li t0, 0xff
    csrw mcause, t0
    csrr t1, mcause
    bne t1, t0, fail

    // We should be able to read/write menvcfg
    li t0, 0xff
    csrw menvcfg, t0
    csrr t1, menvcfg
    li t0, 1
    bne t1, t0, fail

    // Enter supervisor mode.
    la t0, in_supervisor1
    csrw mepc, t0
    li t0, MSTATUS_MPP_MASK
    csrc mstatus, t0
    li t1, MSTATUS_MPP_S
    csrs mstatus, t1
    mret
    exit_imm(1)

in_supervisor1:
    // We should be able to read/write scause
    li t0, 1337
    csrw scause, t0
    csrr t1, scause
    bne t0, t1, fail

    // We should be able to read/write stval
    li t0, 1337
    csrw stval, t0
    csrr t1, stval
    bne t0, t1, fail

    // We should be able to read/write senvcfg
    li t0, 0xff
    csrw senvcfg, t0
    csrr t1, senvcfg
    li t0, 1
    bne t1, t0, fail

    // We should be able to read/write satp
    li t0, 1
    csrw satp, t0
    csrr t1, satp
    li t0, 1
    bne t1, t0, fail

    // WFI should work when TW is 0
    li t5, 0
    wfi
    bne t5, zero, fail

    ecall
    exit_imm(1)

in_machine_again:
    // MPRV should have been cleared by last MRET
    csrr t1, mstatus
    li t0, MSTATUS_MPRV_MASK
    and t1, t1, t0
    bne t1, zero, fail

    // Enable TVM (trap virtual memory) bit
    li t0, MSTATUS_TVM_MASK
    csrrs t0, mstatus, t0

    // Enable TW (timeout wait) bit
    li t0, MSTATUS_TW_MASK
    csrrs t0, mstatus, t0

    // Set a trap that will ignore the failing instruction and resume to next instruction
    la t0, skip_illegal_insn_trap
    csrw mtvec, t0

    // We should not be able to read/write fflags because FS state is disabled
    li t5, 0
    csrr t0, fflags
    beq t5, zero, fail
    li t5, 0
    csrw fflags, 0
    beq t5, zero, fail

    // We should not be able to read/write frm because FS state is disabled
    li t5, 0
    csrr t0, frm
    beq t5, zero, fail
    li t5, 0
    csrw frm, 0
    beq t5, zero, fail

    // We should not be able to read/write fcsr because FS state is disabled
    li t5, 0
    csrr t0, fcsr
    beq t5, zero, fail
    li t5, 0
    csrw fcsr, 0
    beq t5, zero, fail

    // We should not be able to read/write invalid CSRs
    li t5, 0
    csrr t0, 0x800
    beq t5, zero, fail
    li t5, 0
    csrw 0x800, 0
    beq t5, zero, fail

    // Enable FS state
    li t0, MSTATUS_FS_MASK
    csrs mstatus, t0

    // We should not be able to execute float instructions with float rounding mode disabled
    csrwi frm, 7
    li t5, 0
    fadd.d f0, f0, f0
    fmadd.d f0, f0, f0, f0
    fsqrt.d f0, f0
    fcvt.s.d f0, f0
    fcvt.l.d t0, f0
    fcvt.d.l f0, t0
    li t0, 6
    bne t5, t0, fail

    // Enter supervisor mode again
    la t0, in_supervisor2
    csrw mepc, t0
    li t0, MSTATUS_MPP_MASK
    csrc mstatus, t0
    li t1, MSTATUS_MPP_S
    csrs mstatus, t1
    mret
    exit_imm(1)

in_supervisor2:
    // We should not be able to write a M-mode CSR
    li t5, 0
    csrw minstret, 0
    beq t5, zero, fail
    li t5, 0
    csrrwi t0, minstret, 0
    beq t5, zero, fail

    // We should not be able to read stap when TVM is 1
    li t5, 0
    csrr t0, satp
    beq t5, zero, fail

    // We should not be able to write stap when TVM is 1
    li t0, 0
    li t5, 0
    csrw satp, t0
    beq t5, zero, fail

    // SFENCE should fail when TVM is 1
    li t5, 0
    sfence.vma
    beq t5, zero, fail

    // WFI should fail when TW is 1
    li t5, 0
    wfi
    beq t5, zero, fail

    // MRET should fail while in S-mode
    li t5, 0
    mret
    beq t5, zero, fail

    // Enter U-mode
    la t0, in_user
    csrw sepc, t0
    li t0, MSTATUS_SPP_MASK
    csrc sstatus, t0
    sret
    exit_imm(1)

in_user:
    // SFENCE should fail in U-mode
    li t5, 0
    sfence.vma
    beq t5, zero, fail

    // SRET should fail in U-mode
    li t5, 0
    sret
    beq t5, zero, fail

    // WFI should fail in U-mode
    li t5, 0
    wfi
    beq t5, zero, fail

    exit_imm(0)

// catch exception and exit
fail_trap:
    csrr t0, mcause
    li t1, MCAUSE_SUPERVISOR_ECALL
    beq t0, t1, in_machine_again
    exit_imm(1)

skip_illegal_insn_trap:
    csrr gp, mcause
    li t4, MCAUSE_ILLEGAL_INSN
    bne gp, t4, exit
    csrr t4, mepc
    addi t4, t4, 4
    csrw mepc, t4
    addi t5, t5, 1
    mret
    exit_imm(1)

// on fail halt with 1
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
