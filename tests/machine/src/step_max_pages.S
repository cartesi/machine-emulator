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

/* Worst-case step-log page footprint for a single mcycle.
 *
 * One mcycle records every distinct 4 KiB page the interpreter reads or writes
 * while executing one big-machine instruction. This program maximizes that set:
 * it runs a load in S-mode under sv48 (4-level page walk -- the deepest mode the
 * Cartesi machine supports; sv57 is compiled out via NO_SATP_MODE_SV57), with the
 * code and data virtual addresses routed through disjoint page-table pages, and an
 * sfence.vma immediately before the load so the TLB is cold and both the fetch and
 * the load perform full table walks during the recorded mcycle.
 *
 * vaddr layout (sv48): VPN3|VPN2|VPN1|VPN0|offset, 9 bits each + 12.
 *   code vaddr Vc = 1<<39  (VPN3=1, rest 0)
 *   data vaddr Vd = 2<<39  (VPN3=2, rest 0)
 * Sharing only the root table page, each walk touches 3 further distinct table
 * pages, so fetch + load span 7 table pages + 1 code page + 1 data page, plus the
 * shadow-registers page, the PMA page, and the CODE/READ TLB shadow pages.
 */

#include <address-range-defines.h>
#include <encoding.h>

#define SATP_MODE_SHIFT 60
#define MSTATUS_MPP_MASK 0x1800
#define MSTATUS_MPP_S    0x800

#define VC (1 << 39)
#define VD (2 << 39)

#define PTE_PTR  PTE_V
#define PTE_LEAF_RX (PTE_V | PTE_R | PTE_X | PTE_A | PTE_D)
#define PTE_LEAF_RW (PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)

/* write a PTE: parent[idx] = (phys(target) >> 12 << 10) | flags */
.macro set_pte parent, idx, target, flags
    la   t1, \target
    srli t1, t1, 12
    slli t1, t1, 10
    li   t2, \flags
    or   t1, t1, t2
    la   t0, \parent
    li   t3, (\idx) * 8
    add  t0, t0, t3
    sd   t1, (t0)
.endm

.section .text.init
.align 2;
.global _start;
_start:
    // M-mode trap handler (catches the supervisor ecall used to exit)
    la t0, m_trap
    csrw mtvec, t0

    // Build the sv48 page tables.
    // root[1] -> l1c ; root[2] -> l1d   (diverge at the root index VPN3)
    set_pte root_table, 1, l1c, PTE_PTR
    set_pte root_table, 2, l1d, PTE_PTR
    // code chain: l1c[0]->l2c->l3c->code_page (l3c[0] is the leaf)
    set_pte l1c, 0, l2c, PTE_PTR
    set_pte l2c, 0, l3c, PTE_PTR
    set_pte l3c, 0, code_page, PTE_LEAF_RX
    // data chain: l1d[0]->l2d->l3d->data_page (l3d[0] is the leaf)
    set_pte l1d, 0, l2d, PTE_PTR
    set_pte l2d, 0, l3d, PTE_PTR
    set_pte l3d, 0, data_page, PTE_LEAF_RW

    // satp = sv48 | (root_table >> 12)
    la   t0, root_table
    srli t0, t0, 12
    li   t1, (SATP_MODE_SV48 << SATP_MODE_SHIFT)
    or   t0, t0, t1
    csrw satp, t0

    // Enter S-mode at Vc with a0 = Vd.
    li   a0, VD
    li   t0, MSTATUS_MPP_MASK
    csrc mstatus, t0
    li   t0, MSTATUS_MPP_S
    csrs mstatus, t0
    li   t0, VC
    csrw mepc, t0
    mret

// M-mode trap: supervisor ecall exits 0, anything else exits 1.
m_trap:
    csrr t0, mcause
    li   t1, CAUSE_SUPERVISOR_ECALL
    beq  t0, t1, exit_ok
    li   gp, 1
    j    exit
exit_ok:
    li   gp, 0
    j    exit

// HTIF exit, code in gp.
exit:
    slli gp, gp, 16
    srli gp, gp, 15
    ori  gp, gp, 1
1:
    li   t0, AR_HTIF_START_DEF
    sd   gp, 0(t0)
    j    1b

// The S-mode payload, page-aligned so Vc (offset 0) lands on its first insn.
.balign 4096
.global code_page
code_page:
    sfence.vma           // flush TLB: the next mcycle re-walks cold
    ld   x1, 0(a0)       // worst mcycle: cold fetch walk + cold load walk
    ecall                // trap to M-mode to exit
1:  j 1b

// sv48 table pages and the data page (zeroed scratch; filled at runtime).
.section .bss
.balign 4096
root_table: .skip 4096
l1c: .skip 4096
l2c: .skip 4096
l3c: .skip 4096
l1d: .skip 4096
l2d: .skip 4096
l3d: .skip 4096
data_page: .skip 4096
