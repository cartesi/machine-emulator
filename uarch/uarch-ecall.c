// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#include "uarch-ecall.h"
#include "compiler-defines.h"
#include "uarch-defines.h"

#include <stddef.h>
#include <stdint.h>

void ua_halt_ECALL() {
    // NOLINTNEXTLINE(hicpp-no-assembler)
    asm volatile("mv a7, %0\n"
                 "ecall\n"
                 : // no output
                 : "r"(UARCH_ECALL_FN_HALT_DEF)
                 : "a7" // modified registers
    );
}

void ua_putchar_ECALL(uint8_t c) {
    // NOLINTNEXTLINE(hicpp-no-assembler)
    asm volatile("mv a7, %0\n"
                 "mv a0, %1\n"
                 "ecall\n"
                 : // no output
                 : "r"(UARCH_ECALL_FN_PUTCHAR_DEF),
                 "r"(c)       // character to print
                 : "a7", "a0" // clobbered registers
    );
}

void ua_mark_dirty_page_ECALL(uint64_t paddr, uint64_t pma_index) {
    // NOLINTNEXTLINE(hicpp-no-assembler)
    asm volatile("mv a7, %0\n"
                 "mv a0, %1\n"
                 "mv a1, %2\n"
                 "ecall\n"
                 : // no output
                 : "r"(UARCH_ECALL_FN_MARK_DIRTY_PAGE_DEF), "r"(paddr), "r"(pma_index)
                 : "a7", "a0", "a1" // clobbered registers
    );
}

void ua_write_tlb_ECALL(uint64_t use, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
    uint64_t pma_index) {
    // NOLINTNEXTLINE(hicpp-no-assembler)
    asm volatile("mv a7, %0\n"
                 "mv a0, %1\n"
                 "mv a1, %2\n"
                 "mv a2, %3\n"
                 "mv a3, %4\n"
                 "mv a4, %5\n"
                 "ecall\n"
                 : // no output
                 : "r"(UARCH_ECALL_FN_WRITE_TLB_DEF), "r"(use), "r"(slot_index),
                 "r"(vaddr_page), "r"(vp_offset), "r"(pma_index)
                 : "a7", "a0", "a1", "a2", "a3", "a4" // clobbered registers
    );
}
