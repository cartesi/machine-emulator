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

#ifndef HTIF_ADDRESS_RANGE_HPP
#define HTIF_ADDRESS_RANGE_HPP

#include <cstdint>

#include "address-range-constants.hpp"
#include "address-range.hpp"
#include "i-device-state-access-fwd.hpp"
#include "interpret.hpp"
#include "pmas-constants.hpp"
#include "pmas.hpp"

/// \file
/// \brief Host-Target InterFace device.

namespace cartesi {

class htif_address_range final : public address_range {

    static constexpr pmas_flags m_htif_flags{
        .M = false,
        .IO = true,
        .R = true,
        .W = true,
        .X = false,
        .IR = false,
        .IW = false,
        .DID = PMA_ISTART_DID::HTIF,
    };

public:
    template <typename ABRT>
    explicit htif_address_range(ABRT abrt) :
        address_range("HTIF device", AR_HTIF_START, AR_HTIF_LENGTH, m_htif_flags, abrt) {
        ;
    }

    htif_address_range(const htif_address_range &other) = default;
    htif_address_range &operator=(const htif_address_range &other) = default;
    htif_address_range(htif_address_range &&other) = default;
    htif_address_range &operator=(htif_address_range &&other) = default;
    ~htif_address_range() override = default;

private:
    bool do_read_device(i_device_state_access *a, uint64_t offset, int log2_size,
        uint64_t *pval) const noexcept override;
    execute_status do_write_device(i_device_state_access *a, uint64_t offset, int log2_size,
        uint64_t val) noexcept override;
};

} // namespace cartesi

#endif
