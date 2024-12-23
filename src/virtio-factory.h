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

#ifndef VIRTIO_FACTORY_H
#define VIRTIO_FACTORY_H

#include <cstdint>
#include <string>

#include "pma-driver.h"
#include "pma.h"

namespace cartesi {

/// \brief Creates a PMA entry for a VirtIO device
/// \param start Start address for memory range.
/// \param length Length of memory range.
/// \returns Corresponding PMA entry
pma_entry make_virtio_pma_entry(uint64_t start, uint64_t length, const std::string &description,
    const pma_driver *driver, void *context);

} // namespace cartesi

#endif
