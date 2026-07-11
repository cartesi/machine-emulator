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

#ifndef UARCH_ECALL_H
#define UARCH_ECALL_H

#include "uarch-defines.h"

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

// Inline, register-pinned ecall wrappers. Keeping these in the header lets call
// sites inline them, which matters for write_tlb: a TLB flush issues one call per
// slot (3 sets x 256), so per-call argument marshalling multiplies into the
// dominant uarch cycle cost of an SFENCE.VMA. The "memory" clobber orders the
// ecall against shadow-state loads and stores around it.

static inline void ua_halt_ECALL(void) {
    register uint64_t a7 __asm__("a7") = UARCH_ECALL_FN_HALT_DEF;
    // NOLINTNEXTLINE(hicpp-no-assembler)
    __asm__ volatile("ecall" : : "r"(a7) : "memory");
}

static inline void ua_putchar_ECALL(uint8_t c) {
    register uint64_t a7 __asm__("a7") = UARCH_ECALL_FN_PUTCHAR_DEF;
    register uint64_t a0 __asm__("a0") = c;
    // NOLINTNEXTLINE(hicpp-no-assembler)
    __asm__ volatile("ecall" : : "r"(a7), "r"(a0) : "memory");
}

static inline void ua_write_tlb_ECALL(uint64_t use, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
    uint64_t pma_index) {
    register uint64_t a7 __asm__("a7") = UARCH_ECALL_FN_WRITE_TLB_DEF;
    register uint64_t a0 __asm__("a0") = use;
    register uint64_t a1 __asm__("a1") = slot_index;
    register uint64_t a2 __asm__("a2") = vaddr_page;
    register uint64_t a3 __asm__("a3") = vp_offset;
    register uint64_t a4 __asm__("a4") = pma_index;
    // NOLINTNEXTLINE(hicpp-no-assembler)
    __asm__ volatile("ecall" : : "r"(a7), "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4) : "memory");
}

#endif
