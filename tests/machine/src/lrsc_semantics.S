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

#define exit_imm(imm) \
    li gp, imm; \
    j exit;

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    // Set the trap handler
    la t0, fail;
    csrw mtvec, t0;

    la a0, foo;         // load address of foo into a0
    la a1, boo;         // load address of foo into a0
    li a2, 0xc0ffee;    // save dummy value for testing purposes

    // Test valid LR/SC
    lr.d t0, (a0);      // load and reserve a0
    sc.d t1, a2, (a0);  // store a2 into a0
    bnez t0, fail;      // t0 should be 0, that is, the initial value of 'foo'
    bnez t1, fail;      // t1 should be 1, that is, SC success
    ld t0, (a0);        // loads 'foo' value into t0
    bne t0, a2, fail;   // t0 should be equal to a2

    // Attempt to reuse old LR
    sc.d t1, a0, (a0);  // attempt to store a0 into a0 (it should fail)
    beqz t1, fail;      // t1 should be 1, that is, SC failure
    ld t0, (a0);        // loads 'foo' value into t0
    bne t0, a2, fail;   // t0 should be equal to a2

    // Test SC reservation clear
    lr.d t0, (a0);
    sc.d zero, zero, (a1); // invalid SC just to clear reservation
    sc.d t0, a0, (a0);  // attempt to store a0 into a0 (it should fail)
    ld t0, (a0);        // loads 'foo' value into t0
    bne t0, a2, fail;   // t0 should be equal to a2

    exit_imm(0);

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
    li t0, PMA_HTIF_START_DEF
    sd gp, 0(t0);
    j 1b; // Should not be necessary

.data
.align 3; foo: .dword 0
.align 3; boo: .dword 0