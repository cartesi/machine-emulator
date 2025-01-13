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

#ifndef MOCK_PMA_ENTRY_H
#define MOCK_PMA_ENTRY_H

#include "clint.h"
#include "htif.h"
#include "plic.h"
#include "pma-constants.h"
#include "shadow-state.h"
#include "shadow-tlb.h"

namespace cartesi {

class mock_pma_entry {
public:
    struct flags {
        bool M;
        bool IO;
        bool E;
        bool R;
        bool W;
        bool X;
        bool IR;
        bool IW;
        PMA_ISTART_DID DID;
    };

private:
    uint64_t m_pma_index;
    uint64_t m_start;
    uint64_t m_length;
    flags m_flags;
    const pma_driver *m_driver{nullptr};

    static constexpr flags split_flags(uint64_t istart) {
        flags f{};
        f.M = ((istart & PMA_ISTART_M_MASK) >> PMA_ISTART_M_SHIFT) != 0;
        f.IO = ((istart & PMA_ISTART_IO_MASK) >> PMA_ISTART_IO_SHIFT) != 0;
        f.E = ((istart & PMA_ISTART_E_MASK) >> PMA_ISTART_E_SHIFT) != 0;
        f.R = ((istart & PMA_ISTART_R_MASK) >> PMA_ISTART_R_SHIFT) != 0;
        f.W = ((istart & PMA_ISTART_W_MASK) >> PMA_ISTART_W_SHIFT) != 0;
        f.X = ((istart & PMA_ISTART_X_MASK) >> PMA_ISTART_X_SHIFT) != 0;
        f.IR = ((istart & PMA_ISTART_IR_MASK) >> PMA_ISTART_IR_SHIFT) != 0;
        f.IW = ((istart & PMA_ISTART_IW_MASK) >> PMA_ISTART_IW_SHIFT) != 0;
        f.DID = static_cast<PMA_ISTART_DID>((istart & PMA_ISTART_DID_MASK) >> PMA_ISTART_DID_SHIFT);
        return f;
    }

public:
    template <typename ERR_F>
    mock_pma_entry(uint64_t pma_index, uint64_t istart, uint64_t ilength, ERR_F errf) :
        m_pma_index{pma_index},
        m_start{istart & PMA_ISTART_START_MASK},
        m_length{ilength},
        m_flags{split_flags(istart)} {
        if (m_flags.IO) {
            switch (m_flags.DID) {
                case PMA_ISTART_DID::shadow_state:
                    m_driver = &shadow_state_driver;
                    break;
                case PMA_ISTART_DID::shadow_TLB:
                    m_driver = &shadow_tlb_driver;
                    break;
                case PMA_ISTART_DID::CLINT:
                    m_driver = &clint_driver;
                    break;
                case PMA_ISTART_DID::PLIC:
                    m_driver = &plic_driver;
                    break;
                case PMA_ISTART_DID::HTIF:
                    m_driver = &htif_driver;
                    break;
                default:
                    errf("unsupported device in mock_pma_entry");
                    break;
            }
        }
    }

    uint64_t get_index() const {
        return m_pma_index;
    }

    flags get_flags() const {
        return m_flags;
    }

    uint64_t get_start() const {
        return m_start;
    }

    uint64_t get_length() const {
        return m_length;
    }

    bool get_istart_M() const {
        return m_flags.M;
    }

    bool get_istart_IO() const {
        return m_flags.IO;
    }

    bool get_istart_E() const {
        return m_flags.E;
    }

    bool get_istart_R() const {
        return m_flags.R;
    }

    bool get_istart_W() const {
        return m_flags.W;
    }

    bool get_istart_X() const {
        return m_flags.X;
    }

    bool get_istart_IR() const {
        return m_flags.IR;
    }

    const auto *get_driver() const {
        return m_driver;
    }

    const auto &get_device_noexcept() const {
        return *this;
    }

    static void *get_context() {
        return nullptr;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void mark_dirty_page(uint64_t address_in_range) {
        (void) address_in_range;
        // Dummy implementation.
    }
};

template <typename ERR_F>
static inline mock_pma_entry make_mock_pma_entry(uint64_t index, uint64_t istart, uint64_t ilength, ERR_F errf) {
    return mock_pma_entry{index, istart, ilength, errf};
}

} // namespace cartesi

#endif
