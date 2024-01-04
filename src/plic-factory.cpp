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

#include "plic-factory.h"

namespace cartesi {

/// \brief PLIC device peek callback. See ::pma_peek.
static bool plic_peek(const pma_entry &pma, const machine &m, uint64_t page_offset, const unsigned char **page_data,
    unsigned char *) {
    (void) m;
    // PLIC range can be represented as pristine because its state is already represented in shadow CSRs
    *page_data = nullptr;
    return (page_offset % PMA_PAGE_SIZE) == 0 && page_offset < pma.get_length();
}

pma_entry make_plic_pma_entry(uint64_t start, uint64_t length) {
    const pma_entry::flags f{
        true,                // R
        true,                // W
        false,               // X
        false,               // IR
        false,               // IW
        PMA_ISTART_DID::PLIC // DID
    };
    return make_device_pma_entry("PLIC device", start, length, plic_peek, &plic_driver).set_flags(f);
}

} // namespace cartesi
