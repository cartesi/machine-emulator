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

#define MSTATUS_FS_MASK                 (3<<13)
#define MCAUSE_ILLEGAL_INSN             0x2
#define MCAUSE_BREAKPOINT               0x3
#define MCAUSE_LOAD_ACCESS_FAULT        0x5
#define MCAUSE_STORE_AMO_ACCESS_FAULT   0x7
#define C_NOP 0x0001

#define C_INSN(code...)     \
    .option push; .option rvc;   \
    code;                        \
    c.nop;                       \
    .option pop;

#define TEST_RAWC_HINT(insn)     \
    li x8, -1;                   \
    .half (C_NOP);               \
    .half (insn);                \
    li t5, -1;                   \
    bne t5, x8, fail;            \
    xor t5, t5, t5;              \
    bne t5, x0, fail;

#define TEST_RAWC_ILLEGAL_INSN(insn)\
    li a0, MCAUSE_ILLEGAL_INSN;     \
    li t5, 0;                       \
    .half (insn);                   \
    .half (C_NOP);                  \
    li t0, 1;                       \
    bne t5, t0, fail;

#define TEST_C_TRAP_INSN(cause, code...)\
    li a0, cause;     \
    li t5, 0;                       \
    .option push; .option rvc;      \
    code;                           \
    c.nop;                          \
    .option pop;                    \
    li t0, 1;                       \
    bne t5, t0, fail;

#define SHIFT_C_OPCODE 0
#define SHIFT_C_Q0_RD 2
#define SHIFT_C_Q1_RD 7
#define SHIFT_C_Q2_RD 7
#define SHIFT_C_Q1_IMM 5
#define SHIFT_C_Q2_IMM 2
#define SHIFT_C_Q2_RS2 2
#define SHIFT_C_FUNCT3 13
#define SHIFT_C_FUNCT4 12

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    // Set the exception handler to trap
    la t0, fail;
    csrw mtvec, t0;

    // Enable FS state
    li t3, MSTATUS_FS_MASK;
    csrs mstatus, t3;

test_float_insns:
    la s0, my_float0;
    ld a0, 0(s0);

    // C.FLD should load float from 0(s0) into fs0 correctly
    la s0, my_float0;
    C_INSN(c.fld fs0, 0(s0))
    fmv.x.d a0, fs0;
    ld t1, 0(s0);
    bne a0, t1, fail;

    // C.FLD should load float from 0(sp) into fs0 correctly
    la sp, my_float0;
    C_INSN(c.fldsp fs0, 0(sp))
    fmv.x.d a0, fs0;
    ld t1, 0(sp);
    bne a0, t1, fail;

    // C.FSD should store float from fs0 into 0(s1) correctly
    la s1, my_float1;
    C_INSN(c.fsd fs0, 0(s1))
    ld t1, 0(s1);
    bne a0, t1, fail;
    sd zero, 0(s1); // undo the memory change

    // C.FSDSP should store float from fs0 into 0(sp) correctly
    la sp, my_float1;
    C_INSN(c.fsdsp fs0, 0(sp))
    ld t1, 0(sp);
    bne a0, t1, fail;
    sd zero, 0(sp); // undo the memory change

test_hint_insns:
    // Quadrant 1
    TEST_RAWC_HINT((0b000 << SHIFT_C_FUNCT3) | (0 << SHIFT_C_Q1_RD) | (1 << SHIFT_C_Q1_IMM) | (1 << SHIFT_C_OPCODE)) // C.NOP with imm!=0
    TEST_RAWC_HINT((0b000 << SHIFT_C_FUNCT3) | (8 << SHIFT_C_Q1_RD) | (0 << SHIFT_C_Q1_IMM) | (1 << SHIFT_C_OPCODE)) // C.ADDI with imm=0
    TEST_RAWC_HINT((0b010 << SHIFT_C_FUNCT3) | (0 << SHIFT_C_Q1_RD) | (1 << SHIFT_C_Q1_IMM) | (1 << SHIFT_C_OPCODE)) // C.LI with rd=0
    TEST_RAWC_HINT((0b011 << SHIFT_C_FUNCT3) | (0 << SHIFT_C_Q1_RD) | (1 << SHIFT_C_Q1_IMM) | (1 << SHIFT_C_OPCODE)) // C.LUI with rd=0
    TEST_RAWC_HINT((0b100 << SHIFT_C_FUNCT3) | (0b00001 << SHIFT_C_Q1_RD) | (1 << SHIFT_C_OPCODE)) // C.SRLI64
    TEST_RAWC_HINT((0b100 << SHIFT_C_FUNCT3) | (0b01001 << SHIFT_C_Q1_RD) | (1 << SHIFT_C_OPCODE)) // C.SRAI64

    // Quadrant 2
    TEST_RAWC_HINT((0b1000 << SHIFT_C_FUNCT4) | (0 << SHIFT_C_Q2_RD) | (8 << SHIFT_C_Q2_RS2) | (2 << SHIFT_C_OPCODE)) // C.MV with rd=0
    TEST_RAWC_HINT((0b1001 << SHIFT_C_FUNCT4) | (0 << SHIFT_C_Q2_RD) | (8 << SHIFT_C_Q2_RS2) | (2 << SHIFT_C_OPCODE)) // C.ADD with rd=0
    TEST_RAWC_HINT((0b000 << SHIFT_C_FUNCT3) | (0 << SHIFT_C_Q2_RD) | (1 << SHIFT_C_Q2_IMM) | (2 << SHIFT_C_OPCODE)) // C.SLLI with rd=0
    TEST_RAWC_HINT((0b000 << SHIFT_C_FUNCT3) | (8 << SHIFT_C_Q2_RD) | (2 << SHIFT_C_OPCODE)) // C.SLLI64

test_illegal_insns:
    // Set a trap that will ignore the failing illegal instructions and resume to next instruction
    la t0, skip_insn_trap;
    csrw mtvec, t0;

    // Invalid instruction (no bit set)
    TEST_RAWC_ILLEGAL_INSN(0x0)

    // Reserved ranges
    TEST_RAWC_ILLEGAL_INSN((0b100 << SHIFT_C_FUNCT3) | (0 << SHIFT_C_OPCODE))
    TEST_RAWC_ILLEGAL_INSN((0b100 << SHIFT_C_FUNCT3) | (0b111 << 10) | (0b10 << 5) | (1 << SHIFT_C_OPCODE))
    TEST_RAWC_ILLEGAL_INSN((0b100 << SHIFT_C_FUNCT3) | (0b111 << 10) | (0b11 << 5) | (1 << SHIFT_C_OPCODE))

    // Quadrant 0
    TEST_RAWC_ILLEGAL_INSN((0 << SHIFT_C_FUNCT3) | (1 << SHIFT_C_Q0_RD) | (0 << SHIFT_C_OPCODE)) // C.ADDI4SPN with imm=0

    // Quadrant 1
    TEST_RAWC_ILLEGAL_INSN((0b001 << SHIFT_C_FUNCT3) | (0 << SHIFT_C_Q1_RD) | (1 << SHIFT_C_OPCODE)) // C.ADDIW with rd=0
    TEST_RAWC_ILLEGAL_INSN((0b011 << SHIFT_C_FUNCT3) | (2 << SHIFT_C_Q1_RD) | (1 << SHIFT_C_OPCODE)) // C.ADDI16SP with imm=0
    TEST_RAWC_ILLEGAL_INSN((0b011 << SHIFT_C_FUNCT3) | (1 << SHIFT_C_Q1_RD) | (1 << SHIFT_C_OPCODE)) // C.LUI with imm=0

    // Quadrant 2
    TEST_RAWC_ILLEGAL_INSN((0b010 << SHIFT_C_FUNCT3) | (2 << SHIFT_C_OPCODE)) // C.LWSP with rd=0
    TEST_RAWC_ILLEGAL_INSN((0b011 << SHIFT_C_FUNCT3) | (2 << SHIFT_C_OPCODE)) // C.LDSP with rd=0
    TEST_RAWC_ILLEGAL_INSN((0b100 << SHIFT_C_FUNCT3) | (2 << SHIFT_C_OPCODE)) // C.JR with rs1=0

    // Invalid memory access
    li s0, 0x9000000000000;
    li sp, 0x9000000000000;
    TEST_C_TRAP_INSN(MCAUSE_LOAD_ACCESS_FAULT, c.lw s0, 0(s0))
    TEST_C_TRAP_INSN(MCAUSE_LOAD_ACCESS_FAULT, c.ld s0, 0(s0))
    TEST_C_TRAP_INSN(MCAUSE_LOAD_ACCESS_FAULT, c.fld fs0, 0(s0))
    TEST_C_TRAP_INSN(MCAUSE_LOAD_ACCESS_FAULT, c.fldsp fs0, 0(sp))
    TEST_C_TRAP_INSN(MCAUSE_STORE_AMO_ACCESS_FAULT, c.sw s0, 0(s0))
    TEST_C_TRAP_INSN(MCAUSE_STORE_AMO_ACCESS_FAULT, c.sd s0, 0(s0))
    TEST_C_TRAP_INSN(MCAUSE_STORE_AMO_ACCESS_FAULT, c.fsd fs0, 0(s0))
    TEST_C_TRAP_INSN(MCAUSE_STORE_AMO_ACCESS_FAULT, c.fsdsp fs0, 0(sp))

    // Disable FS state
    li t3, MSTATUS_FS_MASK;
    csrc mstatus, t3;

    // Float instructions while float state is disabled
    TEST_C_TRAP_INSN(MCAUSE_ILLEGAL_INSN, c.fld fs0, 0(s0))
    TEST_C_TRAP_INSN(MCAUSE_ILLEGAL_INSN, c.fldsp fs0, 0(sp))
    TEST_C_TRAP_INSN(MCAUSE_ILLEGAL_INSN, c.fsd fs0, 0(s0))
    TEST_C_TRAP_INSN(MCAUSE_ILLEGAL_INSN, c.fsdsp fs0, 0(sp))


    // Breakpoint
    TEST_C_TRAP_INSN(MCAUSE_BREAKPOINT, c.ebreak)

success:
    exit_imm(0)

fail:
    exit_imm(1);

skip_insn_trap:
    // Expected an illegal instruction exception
    csrr gp, mcause;
    bne gp, a0, exit;

    // Increment illegal instruction counter
    addi t5, t5, 1;

    // Resume to next instruction
    csrr t6, mepc;
    addi t6, t6, 4;
    csrw mepc, t6;
    mret;

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

.data;
.align 3;
my_float0: .dword 0x3f3240fef40a55d0; // 0.00027853226132753834
my_float1: .dword 0x0; // 0.0
