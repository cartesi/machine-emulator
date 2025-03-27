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

#ifndef PRISTINE_ADDRESS_RANGE_H
#define PRISTINE_ADDRESS_RANGE_H

#include "address-range.h"

namespace cartesi {

// Forward declarations
class machine;

/// \file
/// \brief An address range that appears pristine in the state

class pristine_address_range : public address_range {
public:
    /// \brief Constructor
    /// \param description Description of address range for use in error messages
    /// \param start Target physical address where range starts
    /// \param length Length of range, in bytes
    /// \param f Physical memory attribute flags for range
    template <typename ABRT>
    pristine_address_range(const char *description, uint64_t start, uint64_t length, pmas_flags f, ABRT abrt) :
        address_range{description, start, length, f, abrt} {
        ;
    }

    pristine_address_range(const pristine_address_range &other) = default;
    pristine_address_range &operator=(const pristine_address_range &other) = default;
    pristine_address_range(pristine_address_range &&other) = default;
    pristine_address_range &operator=(pristine_address_range &&other) = default;
    ~pristine_address_range() override = default;

private:
    bool do_peek(const machine & /*m*/, uint64_t offset, uint64_t length, const unsigned char **data,
        unsigned char * /*scratch*/) const noexcept override {
        *data = nullptr;
        return contains_relative(offset, length);
    }
};

} // namespace cartesi

#endif
