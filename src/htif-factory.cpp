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

#include "htif-factory.h"
#include "htif.h"
#include "pma-constants.h"
#include "pma.h"

namespace cartesi {

pma_entry make_htif_pma_entry(uint64_t start, uint64_t length) {
    const pma_entry::flags f{.R = true, .W = true, .X = false, .IR = false, .IW = false, .DID = PMA_ISTART_DID::HTIF};
    return make_device_pma_entry("HTIF device", start, length, pma_peek_pristine, &htif_driver).set_flags(f);
}

} // namespace cartesi
