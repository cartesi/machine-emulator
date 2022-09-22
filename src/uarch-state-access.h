// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef uarch_machine_H
#define uarch_machine_H

#include "i-uarch-state-access.h"
#include "uarch-bridge.h"
#include "uarch-constants.h"
#include "uarch-machine.h"
#include "uarch-memory-bridge.h"

namespace cartesi {

template <typename MACRO_STATE_ACCESS>
class uarch_state_access : public i_uarch_state_access<uarch_state_access<MACRO_STATE_ACCESS>> {
    uarch_machine &m_um;
    MACRO_STATE_ACCESS &m_a;

public:
    explicit uarch_state_access(uarch_machine &um, MACRO_STATE_ACCESS &a) : m_um(um), m_a(a) {
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

    uint64_t do_read_x(int reg) const {
        return m_um.get_state().x[reg];
    }

    void do_write_x(int reg, uint64_t val) {
        assert(reg != 0);
        m_um.get_state().x[reg] = val;
    }

    uint64_t do_read_pc() const {
        return m_um.get_state().pc;
    }

    void do_write_pc(uint64_t val) {
        m_um.get_state().pc = val;
    }

    uint64_t do_read_cycle() const {
        return m_um.get_state().cycle;
    }

    void do_write_cycle(uint64_t val) {
        m_um.get_state().cycle = val;
    }

    template <typename T>
    void do_read_word(uint64_t paddr, T *data) {
        auto &pma = find_pma_entry<T>(paddr);
        if (pma.get_istart_E()) {
            return uarch_bridge<MACRO_STATE_ACCESS>::read_word(m_a, paddr, data);
        }
        if (!pma.get_istart_R()) {
            throw std::runtime_error("pma is not readable");
        }
        if (!pma.get_istart_M()) {
            throw std::runtime_error("Attempt to read non-memory pma");
        }

        uint64_t hoffset = paddr - pma.get_start();
        unsigned char *hmem = pma.get_memory().get_host_memory() + hoffset;
        *data = aliased_aligned_read<T>(hmem);
    }

    template <typename T>
    void do_write_word(uint64_t paddr, T data) {
        auto &pma = find_pma_entry<T>(paddr);
        if (pma.get_istart_E()) {
            return uarch_bridge<MACRO_STATE_ACCESS>::write_word(m_a, paddr, data);
        }
        if (!pma.get_istart_W()) {
            throw std::runtime_error("pma is not writable");
        }
        if (!pma.get_istart_M()) {
            throw std::runtime_error("Attempt to write non-memory pma");
        }

        uint64_t hoffset = paddr - pma.get_start();
        unsigned char *hmem = pma.get_memory().get_host_memory() + hoffset;
        aliased_aligned_write(hmem, data);
        uint64_t paddr_page = paddr & ~PAGE_OFFSET_MASK;
        pma.mark_dirty_page(paddr_page - pma.get_start());
    }

    template <typename T>
    pma_entry &find_pma_entry(uint64_t paddr) {
        int i = 0;
        while (true) {
            auto &pma = m_um.get_state().pmas[i];
            if (pma.get_length() == 0) {
                return pma; // sentinel  == end of pmas
            }
            if (paddr >= pma.get_start() && paddr - pma.get_start() <= pma.get_length() - sizeof(T)) {
                return pma;
            }
            i++;
        }
    }
};

} // namespace cartesi

#endif
