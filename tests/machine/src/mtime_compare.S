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


// This test case checks that mip.MTIP is pending exactly while mtime >= mtimecmp,
// as unsigned integers, both right after mtimecmp is written and after RTC ticks.
// Interrupts stay disabled, so the test only reads mip. Each failed check exits
// with its own code.

#include <address-range-defines.h>

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
	li gp, imm; \
	j exit;

#define MTIMECMP_ADDR	(AR_CLINT_START_DEF + 0x4000)
#define MTIME_ADDR	(AR_CLINT_START_DEF + 0xbff8)
#define MIP_MTIP_SHIFT	7

// More than three RTC ticks, at two instructions per iteration
#define WAIT_ITERATIONS	(2 * 8192)

// Exits with the given code unless mip.MTIP equals the expected bit
#define check_mtip(expected, code) \
	csrr t0, mip; \
	srli t0, t0, MIP_MTIP_SHIFT; \
	andi t0, t0, 1; \
	li t1, expected; \
	beq t0, t1, 1f; \
	exit_imm(code); \
1:

// Busy-waits across several RTC ticks
#define wait_ticks \
	li t0, WAIT_ITERATIONS; \
2: \
	addi t0, t0, -1; \
	bnez t0, 2b;

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
	li t2, MTIMECMP_ADDR;

	// A new machine starts with the timer off
	check_mtip(0, 1)

	// mtime >= 0 always holds, so writing 0 makes the interrupt pending at once
	sd zero, 0(t2);
	check_mtip(1, 2)

	// It stays pending at later ticks
	wait_ticks
	check_mtip(1, 3)

	// Writing the largest value turns the timer off at once
	li t1, -1;
	sd t1, 0(t2);
	check_mtip(0, 4)

	// A deadline whose cycle count does not fit in 64 bits is never reached
	li t1, 0x8000000000001;
	sd t1, 0(t2);
	wait_ticks
	check_mtip(0, 5)

	// A deadline one tick ahead is not pending yet, and becomes pending once mtime reaches it
	li t3, MTIME_ADDR;
	ld t1, 0(t3);
	addi t1, t1, 1;
	sd t1, 0(t2);
	check_mtip(0, 6)
	wait_ticks
	check_mtip(1, 7)

	exit_imm(0);

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
