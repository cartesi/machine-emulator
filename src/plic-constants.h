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

#ifndef PLIC_CONSTANTS_H
#define PLIC_CONSTANTS_H

#include <cstdint>

/// \file
/// \brief Platform-Level Interrupt Controller constants.

namespace cartesi {

enum PLIC_constants : uint64_t {
    PLIC_ENABLED_IRQ_MASK = UINT64_C(0xfffffffe), // Interrupt mask for all enabled interrupt sources (1-31)
    PLIC_LOWEST_IRQ_PRIORITY = 1,
};

/// \brief Mapping between CSRs and their relative addresses in PLIC memory
enum plic_csr_rel_addr : uint64_t {
    priority1 = UINT64_C(0x4),   // Interrupt source 1 priority
    priority2 = UINT64_C(0x8),   // Interrupt source 2 priority
    priority3 = UINT64_C(0xc),   // Interrupt source 3 priority
    priority4 = UINT64_C(0x10),  // Interrupt source 4 priority
    priority5 = UINT64_C(0x14),  // Interrupt source 5 priority
    priority6 = UINT64_C(0x18),  // Interrupt source 6 priority
    priority7 = UINT64_C(0x1c),  // Interrupt source 7 priority
    priority8 = UINT64_C(0x20),  // Interrupt source 8 priority
    priority9 = UINT64_C(0x24),  // Interrupt source 9 priority
    priority10 = UINT64_C(0x28), // Interrupt source 10 priority
    priority11 = UINT64_C(0x2c), // Interrupt source 11 priority
    priority12 = UINT64_C(0x30), // Interrupt source 12 priority
    priority13 = UINT64_C(0x34), // Interrupt source 13 priority
    priority14 = UINT64_C(0x38), // Interrupt source 14 priority
    priority15 = UINT64_C(0x3c), // Interrupt source 15 priority
    priority16 = UINT64_C(0x40), // Interrupt source 16 priority
    priority17 = UINT64_C(0x44), // Interrupt source 17 priority
    priority18 = UINT64_C(0x48), // Interrupt source 18 priority
    priority19 = UINT64_C(0x4c), // Interrupt source 19 priority
    priority20 = UINT64_C(0x50), // Interrupt source 20 priority
    priority21 = UINT64_C(0x54), // Interrupt source 21 priority
    priority22 = UINT64_C(0x58), // Interrupt source 22 priority
    priority23 = UINT64_C(0x5c), // Interrupt source 23 priority
    priority24 = UINT64_C(0x60), // Interrupt source 24 priority
    priority25 = UINT64_C(0x64), // Interrupt source 25 priority
    priority26 = UINT64_C(0x68), // Interrupt source 26 priority
    priority27 = UINT64_C(0x6c), // Interrupt source 27 priority
    priority28 = UINT64_C(0x70), // Interrupt source 28 priority
    priority29 = UINT64_C(0x74), // Interrupt source 29 priority
    priority30 = UINT64_C(0x78), // Interrupt source 30 priority
    priority31 = UINT64_C(0x7c), // Interrupt source 31 priority
    // ... Interrupt source priority 32-1023 (unsupported)
    pending = UINT64_C(0x1000), // Interrupt pending bits for sources 0-31
    // ... Interrupt pending bits 32-1023 (unsupported)
    enabled = UINT64_C(0x2000), // Interrupt enabled bits for sources 0-31 on context 0
    // ... Interrupt enabled bits for sources 0-1023 on contexts 1-15871 (unsupported)
    threshold = UINT64_C(0x200000),      // Priority threshold for context 0
    claim_complete = UINT64_C(0x200004), // Claim/complete for context 0
    // .. Interrupt threshold and claim_complete for other sources and contexts (unsupported)
};

} // namespace cartesi

#endif
