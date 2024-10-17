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

#ifndef PMA_DRIVER_H
#define PMA_DRIVER_H

#include <cstdint>

#include "interpret.h"

namespace cartesi {

/// \file
/// \brief Declares pma_driver, which provides callback functions for reading and writing to device memory ranges

// Forward declarations
class i_device_state_access;

/// \brief Prototype for callback invoked when machine wants to read from a device range.
/// \param context Device-specific context
/// \param da Object through which the machine state can be accessed.
/// \param offset Offset of requested value from range base address.
/// \param val Pointer to word where value will be stored.
/// \param log2_size log<sub>2</sub> of size of value to read (0 = uint8_t, 1 = uint16_t, 2 = uint32_t, 3 = uint64_t).
/// \returns True if operation succeeded, false otherwise.
using device_read = bool (*)(void *context, i_device_state_access *da, uint64_t offset, uint64_t *val, int log2_size);

/// \brief Default read callback issues error on reads.
bool device_read_error(void *context, i_device_state_access *da, uint64_t offset, uint64_t *val, int log2_size);

/// \brief Prototype for callback invoked when machine wants to write to a range.
/// \param context Device-specific context
/// \param da Object through which the machine state can be accessed.
/// \param offset Offset of requested value from range base address.
/// \param val Word to be written at \p offset.
/// \param log2_size log<sub>2</sub> of size of value to read (0 = uint8_t, 1 = uint16_t, 2 = uint32_t, 3 = uint64_t).
/// \returns execute::failure if operation failed, otherwise other success enumeration if operation succeeded.
using device_write = execute_status (*)(void *context, i_device_state_access *da, uint64_t offset, uint64_t val,
    int log2_size);

/// \brief Default write callback issues error on write.
execute_status device_write_error(void *context, i_device_state_access *da, uint64_t offset, uint64_t val,
    int log2_size);

/// \brief Driver for device memory ranges.
struct pma_driver final {
    const char *name{""};
    device_read read{device_read_error};
    device_write write{device_write_error};
};

} // namespace cartesi

#endif
