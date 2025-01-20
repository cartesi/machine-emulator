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

#ifndef UARCH_MACHINE_BRIDGE_H
#define UARCH_MACHINE_BRIDGE_H

#include <cstddef>
#include <cstdint>

#include "tlb.h"

namespace cartesi {

class machine;

/// \brief Allows microarchitecture code to access the machine state
class uarch_machine_bridge {

    machine &m_m; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

public:
    explicit uarch_machine_bridge(machine &m) : m_m(m) {
        ;
    }
    uint64_t read_word(uint64_t paddr) const;
    void write_word(uint64_t paddr, uint64_t val);
    void mark_dirty_page(uint64_t paddr, uint64_t pma_index);
    void write_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
        uint64_t pma_index);
    static const char *get_what_name(uint64_t paddr);

private:
    void write_shadow_state(uint64_t paddr, uint64_t val);
    void write_memory_word(uint64_t paddr, uint64_t val);
    void write_uarch_memory_word(uint64_t paddr, uint64_t val);
    uint64_t read_shadow_state(uint64_t paddr) const;
    uint64_t read_memory_word(uint64_t paddr) const;
    uint64_t read_uarch_memory_word(uint64_t paddr) const;
    uint64_t read_shadow_tlb(uint64_t paddr) const;
};

} // namespace cartesi

#endif
