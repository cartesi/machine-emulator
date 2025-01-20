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

#ifndef SHADOW_PEEK_H
#define SHADOW_PEEK_H

#include <cstdint>
#include <cstring>

#include "machine-reg.h"
#include "machine.h"
#include "pma.h"

namespace cartesi {

/// \file
/// \brief Peeks part of a shadow
template <typename READ_REG_F>
static bool shadow_peek(READ_REG_F read_reg, const pma_entry &pma, const machine &m, uint64_t offset, uint64_t length,
    const unsigned char **data, unsigned char *scratch) {
    // Must be inside range
    if (!pma.contains(pma.get_start() + offset, length)) {
        *data = nullptr;
        return false;
    }
    // Initial, potentially partial register read
    const uint64_t offset_aligned = offset & ~(sizeof(uint64_t) - 1);
    if (offset > offset_aligned) {
        const auto val = read_reg(m, pma.get_start() + offset_aligned);
        const auto partial = offset - offset_aligned;
        memcpy(scratch, &val, partial);
        length -= partial;
        offset += partial;
    }
    // Now we are aligned, do all complete registers
    const uint64_t paddr_start = pma.get_start() + offset;
    const uint64_t length_aligned = length & ~(sizeof(uint64_t) - 1);
    const uint64_t paddr_end = paddr_start + length_aligned;
    for (uint64_t paddr = paddr_start; paddr < paddr_end; paddr += sizeof(uint64_t)) {
        const auto val = read_reg(m, paddr);
        aliased_aligned_write<uint64_t>(scratch + (paddr - paddr_start), val);
    }
    // Final, potentially partial register read
    if (length > length_aligned) {
        const auto partial = length - length_aligned;
        const auto val = read_reg(m, paddr_end);
        memcpy(scratch + length_aligned, &val, partial);
    }
    *data = scratch;
    return true;
}

} // namespace cartesi

#endif
