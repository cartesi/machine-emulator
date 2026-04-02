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

// Thrashes all three TLB sets (code, read, write) by touching more pages
// than TLB_SET_SIZE (256), filling every slot and exercising do_write_tlb.
//
// Pages accessed: RAM_START + i*PAGE_SIZE for i in [1 .. TLB_SET_SIZE+1]
// (257 pages starting from page 1 to avoid overwriting code at page 0).
//
// Slot index for page i = ((RAM_START >> 12) + i) & 0xFF.
// Pages 1..255 fill slots 1..255; page 256 fills slot 0; page 257 evicts
// slot 1, giving one more access than the TLB capacity.
//
// Write loop:    stores RET_INSN at offset 0 of each page -> fills TLB_WRITE,
//                and sets up executable stubs for the code phase.
// Read loop:     loads from offset 0 of each page         -> fills TLB_READ.
// Code loop:     jalr into the ret stub on each page       -> fills TLB_CODE.
//
// RAM requirement: at least (TLB_SET_SIZE + 2) * PAGE_SIZE = 258 * 4096 bytes.

#include <address-range-defines.h>

#define exit_imm(imm) \
    li gp, imm; \
    j exit;

#define TLB_SET_SIZE  256
#define NUM_PAGES     (TLB_SET_SIZE + 1)

// 32-bit encoding of "ret" (jalr x0, ra, 0) for rv64g (no compressed ext.)
#define RET_INSN      0x00008067

.section .text.init
.align 2
.global _start
_start:
    la   t0, fail
    csrw mtvec, t0

    // t4 = RAM_START + PAGE_SIZE (page 1, first data page)
    // Use la for PC-relative load of _start (= RAM_START), avoiding
    // sign-extension issues with 0x80000000 as a 32-bit immediate.
    la   t4, _start
    lui  t5, 1                   // t5 = 0x1000 (PAGE_SIZE); used as loop step
    add  t4, t4, t5              // t4 = RAM_START + PAGE_SIZE = page 1

    // ---------------------------------------------------------------
    // WRITE TLB: store RET_INSN at byte 0 of pages 1..NUM_PAGES.
    // Fills all 256 TLB_WRITE slots; the 257th store evicts slot 1.
    // Also sets up the ret stubs needed by the code loop below.
    // ---------------------------------------------------------------
    mv   t0, t4
    li   t1, NUM_PAGES
    li   t3, RET_INSN
write_loop:
    sw   t3, 0(t0)
    add  t0, t0, t5
    addi t1, t1, -1
    bnez t1, write_loop

    // ---------------------------------------------------------------
    // READ TLB: load from byte 0 of pages 1..NUM_PAGES.
    // Fills all 256 TLB_READ slots; the 257th load evicts slot 1.
    // ---------------------------------------------------------------
    mv   t0, t4
    li   t1, NUM_PAGES
read_loop:
    lw   t2, 0(t0)
    add  t0, t0, t5
    addi t1, t1, -1
    bnez t1, read_loop

    // ---------------------------------------------------------------
    // CODE TLB: call the ret stub at byte 0 of pages 1..NUM_PAGES.
    // Each jalr causes an instruction fetch from the target page,
    // filling its TLB_CODE slot.  257 calls fill all 256 slots with
    // one eviction.
    // ---------------------------------------------------------------
    mv   t0, t4
    li   t1, NUM_PAGES
code_loop:
    jalr ra, 0(t0)               // fetch + execute ret at t0; fills TLB_CODE
    add  t0, t0, t5
    addi t1, t1, -1
    bnez t1, code_loop

    exit_imm(0)

fail:
    exit_imm(1)

exit:
    slli gp, gp, 16
    srli gp, gp, 15
    ori  gp, gp, 1
1:
    li   t0, AR_HTIF_START_DEF
    sd   gp, 0(t0)
    j    1b
