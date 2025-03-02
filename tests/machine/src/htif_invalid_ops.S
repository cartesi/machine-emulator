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


// This programs exercise invalid load/writes in the HTIF device.

#include "htif_util.h"

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

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    // Set the exception handler to trap
    la t0, fail;
    csrw mtvec, t0;

    // Unknown HTIF devices are silently ignored
    li t0, AR_HTIF_START_DEF;
    li t1, htif_const(0xff, 0, 0);
    sd zero, O_FROMHOST(t0);
    sd t1, O_TOHOST(t0);
    ld t2, O_FROMHOST(t0);
    bnez t2, fail;

    // HTIF halt with invalid commands is silently ignored
    li t0, AR_HTIF_START_DEF;
    li t1, htif_const(HTIF_DEV_HALT_DEF, 0xff, 3);
    sd zero, O_FROMHOST(t0);
    sd t1, O_TOHOST(t0);
    ld t2, O_FROMHOST(t0);
    bnez t2, fail;

    // HTIF halt with exit least-signed bit unset is silently ignored
    li t0, AR_HTIF_START_DEF;
    li t1, htif_const(HTIF_DEV_HALT_DEF, HTIF_HALT_CMD_HALT_DEF, 2);
    sd zero, O_FROMHOST(t0);
    sd t1, O_TOHOST(t0);
    ld t2, O_FROMHOST(t0);
    bnez t2, fail;

    // Set the exception handler to skip instructions
    la t0, skip_insn_trap;
    csrw mtvec, t0;

    // Attempt to load a non 8-bytes value from HTIF
    expect_trap(MCAUSE_LOAD_ACCESS_FAULT,
        li t0, AR_HTIF_START_DEF;
        lw t1, O_TOHOST(t0);
    )

    // Attempt to load from a misaligned HTIF offset
    expect_trap(MCAUSE_LOAD_ACCESS_FAULT,
        li t0, AR_HTIF_START_DEF;
        lb t1, 1(t0);
    )

    // Attempt to load from an invalid HTIF offset
    expect_trap(MCAUSE_LOAD_ACCESS_FAULT,
        li t0, AR_HTIF_START_DEF;
        ld t1, (O_IYIELD+8)(t0);
    )

    // Attempt to store a non 8-bytes value in HTIF
    expect_trap(MCAUSE_STORE_AMO_ACCESS_FAULT,
        li t0, AR_HTIF_START_DEF;
        li t1, 3;
        sw t1, O_TOHOST(t0);
    )

    // Attempt to store in a misaligned HTIF offset
    expect_trap(MCAUSE_STORE_AMO_ACCESS_FAULT,
        li t0, AR_HTIF_START_DEF;
        li t1, 3;
        sb t1, 1(t0);
    )

    // Attempt to store in an invalid HTIF offset
    expect_trap(MCAUSE_STORE_AMO_ACCESS_FAULT,
        li t0, AR_HTIF_START_DEF;
        li t1, 3;
        sd t1, (O_IYIELD+8)(t0);
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
