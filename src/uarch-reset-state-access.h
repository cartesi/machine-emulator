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

#ifndef UARCH_RESET_STATE_ACCESS
#define UARCH_RESET_STATE_ACCESS

/// \file
/// \brief State access implementation that record and logs all accesses

#include "i-uarch-reset-state-access.h"
#include "uarch-state.h"

namespace cartesi {

/// \details The uarch_reset_state_access logs all access to the machine state.
class uarch_reset_state_access : public i_uarch_reset_state_access<uarch_reset_state_access> {
    uarch_state &m_us; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    /// \brief Constructor from machine and uarch states.
    /// \param um Reference to uarch state.
    /// \param m Reference to machine state.
    explicit uarch_reset_state_access(uarch_state &us) : m_us(us) {}

    /// \brief No copy constructor
    uarch_reset_state_access(const uarch_reset_state_access &) = delete;
    /// \brief No copy assignment
    uarch_reset_state_access &operator=(const uarch_reset_state_access &) = delete;
    /// \brief No move constructor
    uarch_reset_state_access(uarch_reset_state_access &&) = delete;
    /// \brief No move assignment
    uarch_reset_state_access &operator=(uarch_reset_state_access &&) = delete;
    /// \brief Default destructor
    ~uarch_reset_state_access() = default;

private:
    // Declare interface as friend to it can forward calls to the "overridden" methods.
    friend i_uarch_reset_state_access<uarch_reset_state_access>;

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    void do_push_bracket(bracket_type type, const char *text) {
        (void) type;
        (void) text;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    int do_make_scoped_note(const char *text) {
        (void) text;
        return 0;
    }

    void do_reset_state(void) {
        m_us.halt_flag = false;
        m_us.pc = UARCH_PC_INIT;
        m_us.cycle = UARCH_CYCLE_INIT;
        for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
            m_us.x[i] = UARCH_X_INIT;
        }
        // Load embedded pristine RAM image
        if (uarch_pristine_ram_len > m_us.ram.get_length()) {
            throw std::runtime_error("embedded uarch ram image does not fit in uarch ram pma");
        }
        memset(m_us.ram.get_memory().get_host_memory(), 0, m_us.ram.get_length());
        memcpy(m_us.ram.get_memory().get_host_memory(), uarch_pristine_ram, uarch_pristine_ram_len);
    }
};

} // namespace cartesi

#endif
