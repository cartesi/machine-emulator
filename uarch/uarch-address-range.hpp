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

#ifndef UARCH_ADDRESS_RANGE_HPP
#define UARCH_ADDRESS_RANGE_HPP

#include <array>
#include <cstdint>

#include "address-range.hpp"
#include "clint-address-range.hpp"
#include "htif-address-range.hpp"
#include "plic-address-range.hpp"
#include "pmas-constants.hpp"

namespace cartesi {

/// Guest PMA cache: memory ranges need only packed metadata, not host objects.
/// Device objects hold no machine state; their existing handlers use the accessor.
class uarch_address_range {
    uint64_t m_istart{};
    uint64_t m_length{};
    address_range *m_device{};
    bool m_initialized{};

    template <typename AR, typename ABRT>
    static address_range &device_range(ABRT abrt) {
        // Initialize on first use; resetting the guest restores this cache as well.
        // NOLINTNEXTLINE(bugprone-dynamic-static-initializers)
        static AR ar{abrt};
        return ar;
    }

public:
    bool is_initialized() const noexcept {
        return m_initialized;
    }

    template <typename ABRT>
    void initialize(uint64_t istart, uint64_t ilength, ABRT abrt) {
        // A previously cached descriptor takes precedence over newly read metadata.
        if (m_initialized) {
            return;
        }
        if ((istart & PMA_ISTART_M_MASK) != 0) {
            const uint64_t start = istart & PMA_ISTART_START_MASK;
            // Match the memory factory's nonempty, aligned, strictly bounded range.
            if (ilength == 0 || (ilength & ~PMA_ISTART_START_MASK) != 0 || start >= UINT64_MAX - ilength) {
                abrt("invalid mock memory range");
                __builtin_trap();
            }
        } else if (ilength == 0) {
            if (istart != 0) {
                abrt("incompatible mock address range");
                __builtin_trap();
            }
        } else {
            const auto did = static_cast<PMA_ISTART_DID>((istart & PMA_ISTART_DID_MASK) >> PMA_ISTART_DID_SHIFT);
            switch (did) {
                case PMA_ISTART_DID::CLINT:
                    m_device = &device_range<clint_address_range>(abrt);
                    break;
                case PMA_ISTART_DID::PLIC:
                    m_device = &device_range<plic_address_range>(abrt);
                    break;
                case PMA_ISTART_DID::HTIF:
                    m_device = &device_range<htif_address_range>(abrt);
                    break;
                default:
                    abrt("unhandled mock address range");
                    __builtin_trap();
            }
            if (m_device->get_istart() != istart || m_device->get_length() != ilength) {
                abrt("incompatible mock address range");
                __builtin_trap();
            }
        }
        m_istart = istart;
        m_length = ilength;
        m_initialized = true;
    }

    uint64_t get_istart() const noexcept {
        return m_istart;
    }

    uint64_t get_start() const noexcept {
        return m_istart & PMA_ISTART_START_MASK;
    }

    uint64_t get_length() const noexcept {
        return m_length;
    }

    PMA_ISTART_DID get_driver_id() const noexcept {
        return static_cast<PMA_ISTART_DID>((m_istart & PMA_ISTART_DID_MASK) >> PMA_ISTART_DID_SHIFT);
    }

    bool contains_absolute(uint64_t start, uint64_t length) const noexcept {
        return start >= get_start() && length <= m_length && start - get_start() <= m_length - length;
    }

    bool is_empty() const noexcept {
        return m_length == 0;
    }

    bool is_memory() const noexcept {
        return (m_istart & PMA_ISTART_M_MASK) != 0;
    }

    bool is_device() const noexcept {
        return (m_istart & PMA_ISTART_IO_MASK) != 0;
    }

    bool is_readable() const noexcept {
        return (m_istart & PMA_ISTART_R_MASK) != 0;
    }

    bool is_writeable() const noexcept {
        return (m_istart & PMA_ISTART_W_MASK) != 0;
    }

    bool is_executable() const noexcept {
        return (m_istart & PMA_ISTART_X_MASK) != 0;
    }

    bool read_device(i_device_state_access *da, uint64_t offset, int log2_size, uint64_t *pval) const noexcept {
        return m_device != nullptr && m_device->read_device(da, offset, log2_size, pval);
    }

    execute_status write_device(i_device_state_access *da, uint64_t offset, int log2_size, uint64_t val) noexcept {
        return m_device != nullptr ? m_device->write_device(da, offset, log2_size, val) : execute_status::failure;
    }
};

using uarch_address_ranges = std::array<uarch_address_range, PMA_MAX>;

} // namespace cartesi

#endif
