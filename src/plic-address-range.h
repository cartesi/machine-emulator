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

#ifndef PLIC_ADDRESS_RANGE_H
#define PLIC_ADDRESS_RANGE_H

#include <cstdint>

#include "i-device-state-access.h"
#include "plic-constants.h"
#include "pristine-address-range.h"

/// \file
/// \brief Platform-Level Interrupt Controller address range.

namespace cartesi {

/// \brief Sets a new pending interrupt request.
/// \details This is called only by devices to notify an external interrupt.
void plic_set_pending_irq(i_device_state_access *a, uint32_t irq_id);

/// \brief Clears a pending interrupt request.
/// \details This is called only by devices to remove an external interrupt notification.
void plic_reset_pending_irq(i_device_state_access *a, uint32_t irq_id);

class plic_address_range final : public pristine_address_range {

    static constexpr pma_flags m_plic_flags{
        .M = false,
        .IO = true,
        .E = false,
        .R = true,
        .W = true,
        .X = false,
        .IR = false,
        .IW = false,
        .DID = PMA_ISTART_DID::PLIC,
    };

public:
    template <typename ABRT>
    plic_address_range(uint64_t start, uint64_t length, ABRT abrt) :
        pristine_address_range("PLIC device", start, length, m_plic_flags, abrt) {
        ;
    }

    plic_address_range(const plic_address_range &other) = default;
    plic_address_range &operator=(const plic_address_range &other) = default;
    plic_address_range(plic_address_range &&other) = default;
    plic_address_range &operator=(plic_address_range &&other) = default;
    ~plic_address_range() override = default;

private:
    bool do_read_device(i_device_state_access *a, uint64_t offset, int log2_size,
        uint64_t *pval) const noexcept override;
    execute_status do_write_device(i_device_state_access *a, uint64_t offset, int log2_size,
        uint64_t val) noexcept override;
};

template <typename ABRT>
static inline plic_address_range make_plic_address_range(uint64_t start, uint64_t length, ABRT abrt) {
    return plic_address_range{start, length, abrt};
}

} // namespace cartesi

#endif
