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


#include <pma-defines.h>

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
	li gp, imm; \
	j exit;

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
	// Set the machine exception handler to mtrap
	la t0, mtrap;
	csrw mtvec, t0;

	// Set the supervisor exception handler to strap
	la t0, strap;
	csrw stvec, t0;

switch_to_supervisor_mode:
	// set supervisor mode start address
	la t0, trigger_exception;
	csrw mepc, t0;
	// Read current mstatus
	csrr a0, mstatus;
	// Mask out the MPP bits in A0
	li  a1,~0x1800;
	and  a0, a0, a1;
	// Set the supervisor mode and MPIE bits.
	li  a1, 0x880;
	or  a0, a0, a1;
	// after this point:
	//   MPP = supervisor level.
	//   MPIE = 1
	csrw mstatus, a0;
	mret;

trigger_exception:
	// Trigger exception with ecall
	ecall;

	// fallback if exception was not triggered
	exit_imm(1);

// catch m-mode exception
mtrap:
	// Read current mstatus
	csrr a0, mstatus;
	// Read MPIE bit and compare
	li  a1, 0x80;
	and a2, a0, a1;
	bnez a2, switch_to_user_with_supervisor_delegate;
	exit_imm(1);


switch_to_user_with_supervisor_delegate:
	// set delegate MCAUSE_ECALL_BASE + PRV_U
	li t0, 0x100;
	csrw medeleg, t0;
	// set user mode start address
	la t0, trigger_exception;
	csrw mepc, t0;
	// Read current mstatus
	csrr a0, mstatus;
	// Mask out the MPP bits in A0
	li  a1,~0x1800;
	and  a0, a0, a1;
	// Set the user mode and SIE bits.
	li  a1, 0x2;
	or  a0, a0, a1;
	// after this point:
	//   MPP = user level.
	//   SIE = 1
	csrw mstatus, a0;
	mret;

// catch s-mode exception and exit
strap:
	// Read current sstatus (mstatus view)
	csrr a0, sstatus;
	// Read SPIE bit and compare
	li  a1, 0x20;
	and a2, a0, a1;
	seqz gp, a2;
	j exit;

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
