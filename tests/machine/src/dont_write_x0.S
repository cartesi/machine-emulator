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

#define MSTATUS_FS_MASK     (3<<13)

// Uses HTIF to exit the emulator with exit code in an immediate
#define exit_imm(imm) \
	li gp, imm; \
	j exit;

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
	// Set the exception handler to trap
	// This is just in case an exception happens
	la t0, fail;
	csrw mtvec, t0;

    // Enable FS state
    li t3, MSTATUS_FS_MASK;
    csrs mstatus, t3;

    // Load float f0 and f1
	li t3, 0xff800000 // -inf
	fmv.w.x f0, t3;
	li t3, 0xfff0000000000000 // -inf
	fmv.d.x f1, t3;

execute_LR:
	la t1, foo;
	lr.w x0, (t0);
	bnez x0, fail;

execute_SC:
	sc.w x0, t0, (t1);
	bnez x0, fail;

execute_AMO:
	amoadd.w x0, t0, (t1);
	bnez x0, fail;

execute_csr_RW:
	csrrw x0, sscratch, x0;
	bnez x0, fail;

execute_csr_SC:
	csrrs x0, sscratch, t1;
	bnez x0, fail;

execute_csr_SCI:
	csrrsi x0, sscratch, 4;
	bnez x0, fail;

execute_arithmetic:
	add x0, t0, t1;
	bnez x0, fail;

execute_arithmetic_imm:
	addi x0, x0, 9;
	bnez x0, fail;

execute_L:
	lb x0, (t1)
	bnez x0, fail;

execute_LUI:
	lui x0, 0x00001;
	bnez x0, fail;

execute_AUIPC:
	auipc x0, 0x00001;
	bnez x0, fail;

execute_JAL:
	jal x0, jal_test;
jal_test:
	bnez x0, fail;

execute_JALR:
	la t2, jalr_test;
	jalr x0, t2, 0;
jalr_test:
	bnez x0, fail;

execute_FMV_X_W:
	fmv.x.w	x0, f0;
	bnez x0, fail;

execute_FMV_X_D:
	fmv.x.d	x0, f1;
	bnez x0, fail;

execute_FCVT_W_S:
	fcvt.w.s x0, f0;
	bnez x0, fail;

execute_FCVT_L_D:
	fcvt.l.d x0, f1;
	bnez x0, fail;

execute_FCLASS_S:
	fclass.s x0, f0;
	bnez x0, fail;

execute_FCLASS_D:
	fclass.d x0, f1;
	bnez x0, fail;

execute_FEQ_S:
	feq.s x0, f0, f0;
	bnez x0, fail;

execute_FEQ_D:
	feq.d x0, f1, f1;
	bnez x0, fail;

success:
	exit_imm(0);

// catch exception and exit
fail:
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

.data
foo: .word 0;
