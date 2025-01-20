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

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif

void ua_halt_ECALL();
void ua_putchar_ECALL(uint8_t c);
void ua_mark_dirty_page_ECALL(uint64_t paddr, uint64_t pma_index);
void ua_write_tlb_ECALL(uint64_t use, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset, uint64_t pma_index);

#ifdef __cplusplus
}
#endif

#endif
