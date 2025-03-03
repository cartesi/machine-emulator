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

#ifndef CLINT_ADDRESS_RANGE_H
#define CLINT_ADDRESS_RANGE_H

#include <cstdint>

#include "address-range-constants.h"
#include "pristine-address-range.h"

/// \file
/// \brief Core-Local Interruptor device.

namespace cartesi {

class clint_address_range final : public pristine_address_range {

    static constexpr pmas_flags m_clint_flags{
        .M = false,
        .IO = true,
        .R = true,
        .W = true,
        .X = false,
        .IR = false,
        .IW = false,
        .DID = PMA_ISTART_DID::CLINT,
    };

public:
    template <typename ABRT>
    explicit clint_address_range(ABRT abrt) :
        pristine_address_range("CLINT device", AR_CLINT_START, AR_CLINT_LENGTH, m_clint_flags, abrt) {
        ;
    }

    clint_address_range(const clint_address_range &other) = default;
    clint_address_range &operator=(const clint_address_range &other) = default;
    clint_address_range(clint_address_range &&other) = default;
    clint_address_range &operator=(clint_address_range &&other) = default;
    ~clint_address_range() override = default;

private:
    bool do_read_device(i_device_state_access *a, uint64_t offset, int log2_size,
        uint64_t *pval) const noexcept override;
    execute_status do_write_device(i_device_state_access *a, uint64_t offset, int log2_size,
        uint64_t val) noexcept override;
};

template <typename ABRT>
static inline clint_address_range make_clint_address_range(ABRT abrt) {
    return clint_address_range{abrt};
}

} // namespace cartesi

#endif
