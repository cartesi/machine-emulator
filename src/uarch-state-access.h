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

#ifndef UARCH_STATE_ACCESS_H
#define UARCH_STATE_ACCESS_H

#include "i-uarch-state-access.h"
#include "machine-state.h"
#include "uarch-bridge.h"
#include "uarch-state.h"

namespace cartesi {

class uarch_state_access : public i_uarch_state_access<uarch_state_access> {
    uarch_state &m_us;
    machine_state &m_s;

    /// \brief Obtain Memory PMA entry that covers a given physical memory region
    /// \param paddr Start of physical memory region.
    /// \param length Length of physical memory region.
    /// \returns Corresponding entry if found, or a sentinel entry
    /// for an empty range.
    pma_entry &find_memory_pma_entry(uint64_t paddr, size_t length) {
        // First, search microarchitecture private PMA entries
        if (m_us.ram.contains(paddr, length)) {
            return m_us.ram;
        }
        int i = 0;
        // Search machine memory PMA entries (not devices or anything else)
        while (true) {
            auto &pma = m_s.pmas[i];
            // The pmas array always contain a sentinel. It is an entry with
            // zero length. If we hit it, return it
            if (pma.get_length() == 0) {
                return pma;
            }
            if (pma.get_istart_M() && pma.contains(paddr, length)) {
                return pma;
            }
            i++;
        }
    }

public:
    /// \brief Constructor from machine and uarch states.
    /// \param um Reference to uarch state.
    /// \param m Reference to machine state.
    explicit uarch_state_access(uarch_state &us, machine_state &s) : m_us(us), m_s(s) {
        ;
    }

    /// \brief No copy constructor
    uarch_state_access(const uarch_state_access &) = delete;
    /// \brief No copy assignment
    uarch_state_access &operator=(const uarch_state_access &) = delete;
    /// \brief No move constructor
    uarch_state_access(uarch_state_access &&) = delete;
    /// \brief No move assignment
    uarch_state_access &operator=(uarch_state_access &&) = delete;
    /// \brief Default destructor
    ~uarch_state_access() = default;

private:
    friend i_uarch_state_access<uarch_state_access>;

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

    uint64_t do_read_x(int reg) const {
        return m_us.x[reg];
    }

    void do_write_x(int reg, uint64_t val) {
        assert(reg != 0);
        m_us.x[reg] = val;
    }

    uint64_t do_read_pc() const {
        return m_us.pc;
    }

    void do_write_pc(uint64_t val) {
        m_us.pc = val;
    }

    uint64_t do_read_cycle() const {
        return m_us.cycle;
    }

    void do_write_cycle(uint64_t val) {
        m_us.cycle = val;
    }

    bool do_read_halt_flag() const {
        return m_us.halt_flag;
    }

    void do_set_halt_flag() {
        m_us.halt_flag = true;
    }

    void do_reset_halt_flag() {
        m_us.halt_flag = false;
    }

    uint64_t do_read_word(uint64_t paddr) {
        // Find a memory range that contains the specified address
        auto &pma = find_memory_pma_entry(paddr, sizeof(uint64_t));
        if (pma.get_istart_E()) {
            // This word doesn't fall within any memory PMA range.
            // Check if uarch is trying to access a machine state register
            return read_register(paddr);
        }
        if (!pma.get_istart_R()) {
            throw std::runtime_error("pma is not readable");
        }
        // Found a writable memory range. Access host memory accordingly.
        const uint64_t hoffset = paddr - pma.get_start();
        unsigned char *hmem = pma.get_memory().get_host_memory() + hoffset;
        return aliased_aligned_read<uint64_t>(hmem);
    }

    /// \brief Reads a uint64 machine state register mapped to a memory address
    /// \param paddr Address of the state register
    /// \param data Pointer receiving register value
    uint64_t read_register(uint64_t paddr) {
        return uarch_bridge::read_register(paddr, m_s);
    }

    /// \brief Fallback to error on all other word sizes
    void do_write_word(uint64_t paddr, uint64_t data) {
        // Find a memory range that contains the specified address
        auto &pma = find_memory_pma_entry(paddr, sizeof(uint64_t));
        if (pma.get_istart_E()) {
            // This word doesn't fall within any memory PMA range.
            // Check if uarch is trying to access a machine state register
            return write_register(paddr, data);
        }
        if (!pma.get_istart_W()) {
            throw std::runtime_error("pma is not writable");
        }
        // Found a writable memory range. Access host memory accordingly.
        const uint64_t hoffset = paddr - pma.get_start();
        unsigned char *hmem = pma.get_memory().get_host_memory() + hoffset;
        aliased_aligned_write(hmem, data);
        const uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        pma.mark_dirty_page(paddr_page - pma.get_start());
    }

    /// \brief Writes a uint64 machine state register mapped to a memory address
    /// \param paddr Address of the state register
    /// \param data New register value
    void write_register(uint64_t paddr, uint64_t data) {
        return uarch_bridge::write_register(paddr, m_s, data);
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
