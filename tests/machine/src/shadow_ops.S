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


// This programs exercise load/writes in the shadow.

#include <pma-defines.h>

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
#define SHADOWS_PMA_LAST_ENTRY_ISTART (31*16)
#define SHADOWS_PMA_LAST_ENTRY_ILENGTH (31*16+8)
#define SHADOWS_PMA_TOTAL_SIZE (32*16)
#define EMPTY_PMA_ISTART (4)
#define EMPTY_PMA_ILENGTH (0)

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    // Set the exception handler to trap
    la t0, fail;
    csrw mtvec, t0;

    // We are allowed to read the shadow PMAs
    li t0, PMA_SHADOW_PMAS_START_DEF;
    ld t1, SHADOWS_PMA_LAST_ENTRY_ISTART(t0);
    li t2, EMPTY_PMA_ISTART
    bne t1, t2, fail;
    ld t1, SHADOWS_PMA_LAST_ENTRY_ILENGTH(t0);
    li t2, EMPTY_PMA_ILENGTH
    bne t1, t2, fail;

    // Set the exception handler to skip instructions
    la t0, skip_insn_trap;
    csrw mtvec, t0;

    // Attempt to load a value from the shadow state
    expect_trap(MCAUSE_LOAD_ACCESS_FAULT,
        li t0, PMA_SHADOW_STATE_START_DEF;
        ld t1, 8(t0);
    )

    // Attempt to load a value from the shadow TLB
    expect_trap(MCAUSE_LOAD_ACCESS_FAULT,
        li t0, PMA_SHADOW_TLB_START_DEF;
        ld t1, 0(t0);
    )

    // Attempt to store a value in the shadow PMAs
    expect_trap(MCAUSE_STORE_AMO_ACCESS_FAULT,
        li t0, PMA_SHADOW_PMAS_START_DEF;
        sd x0, 0(t0);
    )

    // Attempt to store a value in the shadow state
    expect_trap(MCAUSE_STORE_AMO_ACCESS_FAULT,
        li t0, PMA_SHADOW_STATE_START_DEF;
        sd x0, 8(t0);
    )

    // Attempt to store a value in the shadow TLB
    expect_trap(MCAUSE_STORE_AMO_ACCESS_FAULT,
        li t0, PMA_SHADOW_TLB_START_DEF;
        sd x0, 0(t0);
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
    li t0, PMA_HTIF_START_DEF
    sd gp, 0(t0);
    j 1b;
