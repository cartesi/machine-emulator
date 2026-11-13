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


// This test case checks that an SC passes the alignment and permission checks of a store
// whether or not it holds the reservation. A failed SC must still trap on a misaligned
// address or on an address a store could not write. The trap handler records mcause and
// mtval and skips the trapping instruction. Each failed check exits with its own code.

#include <address-range-defines.h>

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
	li gp, imm; \
	j exit;

#define MCAUSE_STORE_AMO_ADDRESS_MISALIGNED	6
#define MCAUSE_STORE_AMO_ACCESS_FAULT		7
#define NO_TRAP					-1

// Data in RAM, away from the code
#define DATA_ADDR	(AR_RAM_START_DEF + 0x2000)
// An address no memory range covers
#define UNMAPPED_ADDR	0x1000000000

// Exits with the given code unless the last instruction trapped with the given cause and address
#define check_trap(cause, addr, code) \
	li t0, cause; \
	bne s0, t0, 1f; \
	li t0, addr; \
	beq s1, t0, 2f; \
1: \
	exit_imm(code); \
2:

// Exits with the given code unless no instruction trapped and the register holds the value
#define check_no_trap(reg, value, code) \
	li t0, NO_TRAP; \
	bne s0, t0, 1f; \
	li t0, value; \
	beq reg, t0, 2f; \
1: \
	exit_imm(code); \
2:

#define reset_trap li s0, NO_TRAP

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
	la t0, trap;
	csrw mtvec, t0;
	li s2, DATA_ADDR;

	// A misaligned SC.W without a reservation traps as a misaligned store
	reset_trap
	li a0, DATA_ADDR + 1;
	sc.w a1, zero, (a0);
	check_trap(MCAUSE_STORE_AMO_ADDRESS_MISALIGNED, DATA_ADDR + 1, 1)

	// So does a misaligned SC.D
	reset_trap
	li a0, DATA_ADDR + 4;
	sc.d a1, zero, (a0);
	check_trap(MCAUSE_STORE_AMO_ADDRESS_MISALIGNED, DATA_ADDR + 4, 2)

	// An aligned SC.W without a reservation to an address no store can write takes the access fault
	reset_trap
	li a0, UNMAPPED_ADDR;
	sc.w a1, zero, (a0);
	check_trap(MCAUSE_STORE_AMO_ACCESS_FAULT, UNMAPPED_ADDR, 3)

	// An aligned SC.W without a reservation to RAM fails with no trap and leaves memory alone
	li t1, 0x1234;
	sw t1, 0(s2);
	reset_trap
	li t2, 0x5678;
	sc.w a1, t2, (s2);
	check_no_trap(a1, 1, 4)
	lw t1, 0(s2);
	check_no_trap(t1, 0x1234, 5)

	// An SC.W that holds the reservation succeeds and writes
	lr.w t1, (s2);
	sc.w a1, t2, (s2);
	check_no_trap(a1, 0, 6)
	lw t1, 0(s2);
	check_no_trap(t1, 0x5678, 7)

	exit_imm(0);

// Records the cause and address of a trap and resumes after the trapping instruction
trap:
	csrr s0, mcause;
	csrr s1, mtval;
	csrr t0, mepc;
	addi t0, t0, 4;
	csrw mepc, t0;
	mret;

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
