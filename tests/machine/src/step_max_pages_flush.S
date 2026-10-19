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

/* Worst-case step-log page footprint for a single mcycle: a TLB flush.
 *
 * When sfence.vma (or a satp write) flushes the write TLB, the recorder marks
 * every valid write entry's page dirty and records it. The write TLB has 256
 * slots (slot = (vaddr>>12) & 255), so first dirtying 256 distinct pages on 256
 * distinct slots and then flushing makes one mcycle touch all 256 of them plus
 * the 6 TLB shadow pages, the shadow-registers page, and the PMA page.
 *
 * This needs no virtual memory: in M-mode (bare) the TLB still caches the
 * identity mapping, so the stores populate the write TLB directly.
 */

#include <address-range-defines.h>

#define NPAGES 256
#define BASE 0x80100000   // 1 MiB into RAM, clear of this code

/* Stride between dirtied pages. The default (one page) keeps them contiguous;
 * a stride of 257 pages (0x101000) still lands each on a distinct write-TLB slot
 * (slot = (vaddr>>12) & 255) but scatters them ~1 MiB apart to inflate the merkle
 * sibling count. Override with -DSTRIDE_BYTES=... ; the larger stride needs a RAM
 * large enough to hold BASE + NPAGES*STRIDE_BYTES. */
#ifndef STRIDE_BYTES
#define STRIDE_BYTES 0x1000
#endif

.section .text.init
.align 2;
.global _start;
_start:
    li   a0, BASE
    li   a1, NPAGES
    li   a2, 0
    li   a3, STRIDE_BYTES
1:                      // dirty NPAGES distinct pages -> NPAGES distinct write-TLB slots
    sd   a2, 0(a0)
    add  a0, a0, a3
    addi a2, a2, 1
    blt  a2, a1, 1b

    sfence.vma          // worst mcycle: flush records every dirty cached page

    li   gp, 0
exit:
    slli gp, gp, 16
    srli gp, gp, 15
    ori  gp, gp, 1
1:
    li   t0, AR_HTIF_START_DEF
    sd   gp, 0(t0)
    j    1b
