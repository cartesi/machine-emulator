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

#ifndef UARCH_DEFINES_H
#define UARCH_DEFINES_H

#include "pma-defines.h"
// NOLINTBEGIN(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
/// \brief Start address of the entire uarch memory range: shadow and ram
#define UARCH_STATE_START_ADDRESS_DEF PMA_SHADOW_UARCH_STATE_START_DEF

/// \brief Log2 size of the entire uarch memory range: shadow and ram
#define UARCH_STATE_LOG2_SIZE_DEF 22

// microarchitecture ecall function codes
#define UARCH_ECALL_FN_HALT_DEF 1            // halt uarch
#define UARCH_ECALL_FN_PUTCHAR_DEF 2         // putchar
#define UARCH_ECALL_FN_MARK_DIRTY_PAGE_DEF 3 // mark_dirty_page
#define UARCH_ECALL_FN_WRITE_TLB_DEF 4       // write_tlb

// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#endif /* end of include guard: UARCH_DEFINES_H */
