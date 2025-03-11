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


// This test case sets up a mtimer interrupt for MTIME=10 and then waits in a
// WFI loop for this interrupt to happen. When the interrupt occurs, the test
// checks whether the cause CSR is set properly.

#include <address-range-defines.h>

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
	li gp, imm; \
	j exit;

// MTIMECMP is a CLINT register that is mapped to RAM
#define MTIMECMP_ADDR	(AR_CLINT_START_DEF + 0x4000)

#define MTIE_MASK	(1<<7)
#define MIE_MASK	(1<<3)

#define MCAUSE_INT_BIT		63
#define MCAUSE_MTIP_CODE	7
#define MCAUSE_MTIP		((1<<MCAUSE_INT_BIT) | MCAUSE_MTIP_CODE)

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
	// Set the exception handler to trap
	la t0, trap;
	csrw mtvec, t0;

	// Enable MIE interrupts in MSTATUS
	csrsi mstatus, MIE_MASK;

	// Store 2 in MTIMECMP
	li t0, MTIMECMP_ADDR;
	li t1, 2;
	sd t1, 0(t0);

	// Enable timer interrupts in MIE
	li t0, MTIE_MASK;
	csrs mie, t0;

loop:
	// Loop until the interrupt happens
	wfi;
	csrr t0, mie;
	andi t0, t0, MTIE_MASK;
	bnez t0, loop;

	exit_imm(0);

trap:
	// Check the interrupt cause
	csrr t0, mcause;
	li t1, MCAUSE_MTIP;
	bne t0, t1, wrong_interrupt;

	// Clear mie when the interrupt happens
	li t0, MTIE_MASK;
	csrc mie, t0;

	mret;

wrong_interrupt:
	// Return error (1) if the interrupt was not caused by the timer
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
