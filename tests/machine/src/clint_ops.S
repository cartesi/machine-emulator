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


// This programs exercise load/writes in the CLINT device.

#include <address-range-defines.h>

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
    li gp, imm; \
    j exit;

#define expect_trap(cause, code...) \
    li a0, cause; \
    li a1, 1; \
    code \
    bnez a1, fail;

#define MCAUSE_STORE_AMO_ACCESS_FAULT 0x7
#define MCAUSE_LOAD_ACCESS_FAULT 0x5

#define O_MSIP 0
#define O_MTIMECMP 0x4000
#define O_MTIME 0xbff8

#define MIP_MSIP_MASK (1 << 3)

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    // Set the exception handler to trap
    la t0, fail;
    csrw mtvec, t0;

    // Load CLINT.MTIME, it should equal to zero at the very start
    li t0, AR_CLINT_START_DEF + O_MTIME;
    ld t1, 0(t0);
    bnez t1, fail;

    // Store and load CLINT.MSIP
    li t0, AR_CLINT_START_DEF + O_MSIP;
    li t1, 0xffffffffff;
    sw t1, 0(t0);
    lw t2, 0(t0); // note that this won't raise an interrupts, because mip should be 0
    li t3, 1;
    bne t2, t3, fail; // make sure only the less significant bit is set
    csrr t2, mip;
    li t3, MIP_MSIP_MASK;
    bne t2, t3, fail; // make sure mie.MSIP is set

    // Store and load CLINT.MTIMECMP
    li t0, AR_CLINT_START_DEF + O_MTIMECMP;
    li t1, 0xffffffffffffffff;
    sd t1, 0(t0);
    ld t2, 0(t0);
    bne t1, t2, fail;

    // Set the exception handler to skip instructions
    la t0, skip_insn_trap;
    csrw mtvec, t0;

    // Attempt to load a non 4-bytes value from CLINT.MSIP
    expect_trap(MCAUSE_LOAD_ACCESS_FAULT,
        li t0, AR_CLINT_START_DEF + O_MSIP;
        ld t1, 0(t0);
    )

    // Attempt to load a non 8-bytes value from CLINT.MTIMECMP
    expect_trap(MCAUSE_LOAD_ACCESS_FAULT,
        li t0, AR_CLINT_START_DEF + O_MTIMECMP;
        lw t1, 0(t0);
    )

    // Attempt to load a non 8-bytes value from CLINT.MTIME
    expect_trap(MCAUSE_LOAD_ACCESS_FAULT,
        li t0, AR_CLINT_START_DEF + O_MTIME;
        lw t1, 0(t0);
    )

    // Attempt to load from an invalid CLINT offset
    expect_trap(MCAUSE_LOAD_ACCESS_FAULT,
        li t0, AR_CLINT_START_DEF + 1;
        lb t1, 0(t0);
    )

    // Attempt to store a non 4-bytes value in CLINT.MSIP
    expect_trap(MCAUSE_STORE_AMO_ACCESS_FAULT,
        li t0, AR_CLINT_START_DEF + O_MSIP;
        sd zero, 0(t0);
    )

    // Attempt to store a non 8-bytes value in CLINT.MTIMECMP
    expect_trap(MCAUSE_STORE_AMO_ACCESS_FAULT,
        li t0, AR_CLINT_START_DEF + O_MTIMECMP;
        sw zero, 0(t0);
    )

    // Attempt to write to CLINT.MTIME
    expect_trap(MCAUSE_STORE_AMO_ACCESS_FAULT,
        li t0, AR_CLINT_START_DEF + O_MTIME;
        sd zero, 0(t0);
    )

    // Attempt to store in an invalid CLINT offset
    expect_trap(MCAUSE_STORE_AMO_ACCESS_FAULT,
        li t0, AR_CLINT_START_DEF + 1;
        sb zero, 0(t0);
    )

    exit_imm(0);

skip_insn_trap:
    csrr gp, mcause;
    bne gp, a0, exit;
    csrr t5, mepc;
    addi t5, t5, 4;
    csrw mepc, t5;
    addi a1, a1, -1;
    mret;

fail:
    exit_imm(1);

// Exits via HTIF using gp content as the exit code
exit:
    slli gp, gp, 16;
    srli gp, gp, 15;
    ori gp, gp, 1;
1:
    li t0, AR_HTIF_START_DEF
    sd gp, 0(t0);
    j 1b;
