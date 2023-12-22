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


// This test case tests all hardware counters in different privilege modes

#include <pma-defines.h>

#define exit_imm(imm) \
    li gp, imm; \
    j exit;

#define check_minstret(n) \
    csrr t0, minstret; \
    li t1, n; \
    bne t0, t1, fail;

#define set_minstret(n) \
    csrwi minstret, n;

#define MSTATUS_MPP_MASK 0x1800
#define MSTATUS_SPP_MASK 0x100
#define MSTATUS_MPP_S    0x800
#define MCAUSE_INSN_ADDRESS_MISALIGNED 0
#define MCAUSE_ILLEGAL_INSN 2
#define MCAUSE_BREAKPOINT 3
#define MCAUSE_USER_ECALL 8
#define MCAUSE_MACHINE_ECALL 11

#define CSR_WRITE_AND_READ_0(csrname) \
    li t0, 1; \
    csrw csrname, t0; \
    csrr t0, csrname; \
    bne t0, zero, fail;

#define CSR_READ_FAIL_EXPECTED(csrname) \
    li t6, 0; \
    csrr t0, csrname; \
    beq t6, zero, fail;

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    // Set the fail exception handler to trap
    la t0, fail;
    csrw mtvec, t0;

    // Illegal instruction counter
    li t6, 0;

    // Expect time read to be valid
    li t0, 0;
    rdtime t0;

    // Expect cycle greater than 0
    li t0, 0;
    rdcycle t0;
    beq t0, zero, fail;

    // Expect instret to be greater than 0
    li t0, 0;
    rdinstret t0;
    beq t0, zero, fail;

    // Expect mcountinhibit to read 0
    li t0, 1;
    csrr t0, mcountinhibit;
    bne t0, zero, fail;

    // Expect all hpmcounters to always read 0 even after writing to it
    CSR_WRITE_AND_READ_0(mhpmcounter3)
    CSR_WRITE_AND_READ_0(mhpmcounter4)
    CSR_WRITE_AND_READ_0(mhpmcounter5)
    CSR_WRITE_AND_READ_0(mhpmcounter6)
    CSR_WRITE_AND_READ_0(mhpmcounter7)
    CSR_WRITE_AND_READ_0(mhpmcounter8)
    CSR_WRITE_AND_READ_0(mhpmcounter9)
    CSR_WRITE_AND_READ_0(mhpmcounter10)
    CSR_WRITE_AND_READ_0(mhpmcounter11)
    CSR_WRITE_AND_READ_0(mhpmcounter12)
    CSR_WRITE_AND_READ_0(mhpmcounter13)
    CSR_WRITE_AND_READ_0(mhpmcounter14)
    CSR_WRITE_AND_READ_0(mhpmcounter15)
    CSR_WRITE_AND_READ_0(mhpmcounter16)
    CSR_WRITE_AND_READ_0(mhpmcounter17)
    CSR_WRITE_AND_READ_0(mhpmcounter18)
    CSR_WRITE_AND_READ_0(mhpmcounter19)
    CSR_WRITE_AND_READ_0(mhpmcounter20)
    CSR_WRITE_AND_READ_0(mhpmcounter21)
    CSR_WRITE_AND_READ_0(mhpmcounter22)
    CSR_WRITE_AND_READ_0(mhpmcounter23)
    CSR_WRITE_AND_READ_0(mhpmcounter24)
    CSR_WRITE_AND_READ_0(mhpmcounter25)
    CSR_WRITE_AND_READ_0(mhpmcounter26)
    CSR_WRITE_AND_READ_0(mhpmcounter27)
    CSR_WRITE_AND_READ_0(mhpmcounter28)
    CSR_WRITE_AND_READ_0(mhpmcounter29)
    CSR_WRITE_AND_READ_0(mhpmcounter30)
    CSR_WRITE_AND_READ_0(mhpmcounter31)

    // Expect all hpmevents to always read 0
    CSR_WRITE_AND_READ_0(mhpmevent3)
    CSR_WRITE_AND_READ_0(mhpmevent4)
    CSR_WRITE_AND_READ_0(mhpmevent5)
    CSR_WRITE_AND_READ_0(mhpmevent6)
    CSR_WRITE_AND_READ_0(mhpmevent7)
    CSR_WRITE_AND_READ_0(mhpmevent8)
    CSR_WRITE_AND_READ_0(mhpmevent9)
    CSR_WRITE_AND_READ_0(mhpmevent10)
    CSR_WRITE_AND_READ_0(mhpmevent11)
    CSR_WRITE_AND_READ_0(mhpmevent12)
    CSR_WRITE_AND_READ_0(mhpmevent13)
    CSR_WRITE_AND_READ_0(mhpmevent14)
    CSR_WRITE_AND_READ_0(mhpmevent15)
    CSR_WRITE_AND_READ_0(mhpmevent16)
    CSR_WRITE_AND_READ_0(mhpmevent17)
    CSR_WRITE_AND_READ_0(mhpmevent18)
    CSR_WRITE_AND_READ_0(mhpmevent19)
    CSR_WRITE_AND_READ_0(mhpmevent20)
    CSR_WRITE_AND_READ_0(mhpmevent21)
    CSR_WRITE_AND_READ_0(mhpmevent22)
    CSR_WRITE_AND_READ_0(mhpmevent23)
    CSR_WRITE_AND_READ_0(mhpmevent24)
    CSR_WRITE_AND_READ_0(mhpmevent25)
    CSR_WRITE_AND_READ_0(mhpmevent26)
    CSR_WRITE_AND_READ_0(mhpmevent27)
    CSR_WRITE_AND_READ_0(mhpmevent28)
    CSR_WRITE_AND_READ_0(mhpmevent29)
    CSR_WRITE_AND_READ_0(mhpmevent30)
    CSR_WRITE_AND_READ_0(mhpmevent31)

    // Set a trap that will ignore the failing instruction and resume to next instruction
    la t0, skip_insn_trap;
    csrw mtvec, t0;

    // No instructions between instret read and write, it should stay 0
    set_minstret(0);
    check_minstret(0);

    // One instruction must, increment instret by 1
    set_minstret(0);
    nop; // increment 1 instruction
    check_minstret(1);

    // EBREAK
    set_minstret(0);
    ebreak; // exception raised, increment only 4 trap instructions
    check_minstret(4);

    // ECALL
    set_minstret(0);
    ecall; // exception raised, increment only 4 trap instructions
    check_minstret(4);

    // LR/SC for invalid addresses
    set_minstret(0);
    li t0, 0xffffffffffffffff; // increment 1 instruction
    lr.w t0, (t0); // exception raised, increment only 4 trap instructions
    li t0, 0xffffffffffffffff; // increment 1 instruction
    sc.w t0, t0, (t0); // exception raised increment only 4 trap instructions
    check_minstret(10);

    // LW/SW for invalid addresses
    set_minstret(0);
    li t0, 0xffffffffffffffff; // increment 1 instruction
    lw t0, (t0); // exception raised, increment only 4 trap instructions
    li t0, 0xffffffffffffffff; // increment 1 instruction
    sw t0, 0(t0); // exception raised, increment only 4 trap instructions
    check_minstret(10);

    // Set a trap that will ignore the failing illegal instructions and resume to next instruction
    la t0, skip_illegal_insn_trap;
    csrw mtvec, t0;

    // Allow reading time/cycle/instret in S-mode
    li t0, 7
    csrw mcounteren, t0
    csrr t1, mcounteren
    bne t1, t0, fail

    // Allow delegation user ECALL in S-mode
    li t0, (1 << MCAUSE_USER_ECALL)
    csrw medeleg, t0
    li t1, 0
    csrr t1, medeleg
    bne t1, t0, fail

    // Enter supervisor mode
    la t0, in_supervisor
    csrw mepc, t0
    li t0, MSTATUS_MPP_MASK
    csrc mstatus, t0
    li t0, MSTATUS_MPP_S
    csrs mstatus, t0
    mret
    exit_imm(1);

in_supervisor:
    // Expect cycle greater than 0
    li t0, 0
    rdcycle t0
    beq t0, zero, fail

    // Expect instret to be greater than 0
    li t0, 0
    rdinstret t0
    beq t0, zero, fail

    // Expect time read to be valid
    li t6, 0
    rdtime t0
    bne t6, zero, fail

    // Expect all hpmcounters reads to fail in supervisor mode
    CSR_READ_FAIL_EXPECTED(hpmcounter3)
    CSR_READ_FAIL_EXPECTED(hpmcounter4)
    CSR_READ_FAIL_EXPECTED(hpmcounter5)
    CSR_READ_FAIL_EXPECTED(hpmcounter6)
    CSR_READ_FAIL_EXPECTED(hpmcounter7)
    CSR_READ_FAIL_EXPECTED(hpmcounter8)
    CSR_READ_FAIL_EXPECTED(hpmcounter9)
    CSR_READ_FAIL_EXPECTED(hpmcounter10)
    CSR_READ_FAIL_EXPECTED(hpmcounter11)
    CSR_READ_FAIL_EXPECTED(hpmcounter12)
    CSR_READ_FAIL_EXPECTED(hpmcounter13)
    CSR_READ_FAIL_EXPECTED(hpmcounter14)
    CSR_READ_FAIL_EXPECTED(hpmcounter15)
    CSR_READ_FAIL_EXPECTED(hpmcounter16)
    CSR_READ_FAIL_EXPECTED(hpmcounter17)
    CSR_READ_FAIL_EXPECTED(hpmcounter18)
    CSR_READ_FAIL_EXPECTED(hpmcounter19)
    CSR_READ_FAIL_EXPECTED(hpmcounter20)
    CSR_READ_FAIL_EXPECTED(hpmcounter21)
    CSR_READ_FAIL_EXPECTED(hpmcounter22)
    CSR_READ_FAIL_EXPECTED(hpmcounter23)
    CSR_READ_FAIL_EXPECTED(hpmcounter24)
    CSR_READ_FAIL_EXPECTED(hpmcounter25)
    CSR_READ_FAIL_EXPECTED(hpmcounter26)
    CSR_READ_FAIL_EXPECTED(hpmcounter27)
    CSR_READ_FAIL_EXPECTED(hpmcounter28)
    CSR_READ_FAIL_EXPECTED(hpmcounter29)
    CSR_READ_FAIL_EXPECTED(hpmcounter30)
    CSR_READ_FAIL_EXPECTED(hpmcounter31)

    // Allow U-mode to read access to cycle
    li t0, 1
    csrw scounteren, t0
    csrr t1, scounteren
    bne t1, t0, fail

    // Set a trap handler for user mode
    la t0, ecall_trap
    csrw stvec, t0

    // Enter user mode
    la t0, in_user1
    csrw sepc, t0
    li t0, MSTATUS_SPP_MASK
    csrc sstatus, t0
    sret
    exit_imm(1);

in_user1:
    // We should be able to read cycle
    li t0, 0
    csrr t0, cycle
    beq t0, zero, fail

    // We should not be able to read instret
    li t0, 0
    li t6, 0
    rdinstret t0
    bne t0, zero, fail
    beq t6, zero, fail

    // We should not be able to read time
    li t0, 0
    li t6, 0
    rdtime t0
    bne t0, zero, fail
    beq t6, zero, fail

    ecall
    exit_imm(1);

ecall_trap:
    // We should be coming from a U-mode ECALL back to S-mode
    li t1, MCAUSE_USER_ECALL
    csrr t0, scause
    bne t0, t1, fail

    // ECALL should tval should be 0
    csrr t0, stval
    bne t0, zero, fail

    // Disallow reading cycle in U-mode
    li t0, 0
    csrw scounteren, t0
    csrr t1, scounteren
    bne t0, t1, fail

    // Enter user mode again
    la t0, in_user2
    csrw sepc, t0
    li t0, MSTATUS_SPP_MASK
    csrc sstatus, t0
    sret
    exit_imm(1);

in_user2:
    // We should not be able to read cycle
    li t0, 0
    li t6, 0
    rdcycle t0
    bne t0, zero, fail
    beq t6, zero, fail

    exit_imm(0);

skip_illegal_insn_trap:
    csrr gp, mcause
    li t4, MCAUSE_ILLEGAL_INSN
    bne gp, t4, exit
    csrr t4, mepc
    addi t4, t4, 4
    csrw mepc, t4
    addi t6, t6, 1
    mret
    exit_imm(1)

skip_insn_trap:
    csrr t6, mepc
    addi t6, t6, 4
    csrw mepc, t6
    mret
    exit_imm(1)

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
    li t0, PMA_HTIF_START_DEF
    sd gp, 0(t0);
    j 1b; // Should not be necessary
