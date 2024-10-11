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

#include <cstdint>

#include "clint-factory.h"
#include "clint.h"
#include "machine.h"
#include "pma-constants.h"
#include "pma.h"

namespace cartesi {

/// \brief CLINT device peek callback. See ::pma_peek.
static bool clint_peek(const pma_entry &pma, const machine &m, uint64_t page_offset, const unsigned char **page_data,
    unsigned char *) {
    (void) m;
    *page_data = nullptr;
    return (page_offset % PMA_PAGE_SIZE) == 0 && page_offset < pma.get_length();
}

pma_entry make_clint_pma_entry(uint64_t start, uint64_t length) {
    const pma_entry::flags f{
        true,                 // R
        true,                 // W
        false,                // X
        false,                // IR
        false,                // IW
        PMA_ISTART_DID::CLINT // DID
    };
    return make_device_pma_entry("CLINT device", start, length, clint_peek, &clint_driver).set_flags(f);
}

} // namespace cartesi
