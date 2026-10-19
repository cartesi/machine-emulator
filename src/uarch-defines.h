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

#include "address-range-defines.h"
#include "rollup-defines.h"
// NOLINTBEGIN(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
/// \brief Start address of the entire uarch memory range: shadow and ram
#define UARCH_STATE_START_ADDRESS_DEF AR_SHADOW_UARCH_STATE_START_DEF

/// \brief Log2 size of the entire uarch memory range: shadow and ram
#define UARCH_STATE_LOG2_SIZE_DEF 22

/// \brief Initial value of the uarch halt register
#define UARCH_HALT_INIT_DEF 0

/// \brief Initial value of a uarch general-purpose register
#define UARCH_X_INIT_DEF 0

/// \brief Initial value of the uarch program counter
#define UARCH_PC_INIT_DEF AR_UARCH_RAM_START_DEF

/// \brief Initial value of the uarch cycle register
#define UARCH_CYCLE_INIT_DEF 0

/// \brief Log2 of the expected maximum uarch cycle
#define UARCH_LOG2_CYCLE_MAX_DEF ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE_DEF

/// \brief Maximum uarch cycle
#define UARCH_CYCLE_MAX_DEF ((1ULL << UARCH_LOG2_CYCLE_MAX_DEF) - 1)

// uarch ecall function codes
// function code 3 was mark_dirty_page, now removed, and the gap is intentional
#define UARCH_ECALL_FN_HALT_DEF 1      // halt uarch
#define UARCH_ECALL_FN_PUTCHAR_DEF 2   // putchar
#define UARCH_ECALL_FN_WRITE_TLB_DEF 4 // write_tlb

// helper for using UINT64_C with defines
#ifndef EXPAND_UINT64_C
#define EXPAND_UINT64_C(a) UINT64_C(a)
#endif

// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#endif /* end of include guard: UARCH_DEFINES_H */
