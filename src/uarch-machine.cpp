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

#include "uarch-machine.h"

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <utility>

#include "pma-constants.h"
#include "pma.h"
#include "riscv-constants.h"
#include "shadow-uarch-state-factory.h"
#include "uarch-config.h"
#include "uarch-constants.h"
#include "uarch-pristine.h"

namespace cartesi {

using namespace std::string_literals;

const pma_entry::flags ram_flags{
    true,                  // R
    true,                  // W
    true,                  // X
    true,                  // IR
    true,                  // IW
    PMA_ISTART_DID::memory // DID
};

uarch_machine::uarch_machine(uarch_config c) : m_c{c} {
    m_s.pc = c.processor.pc;
    m_s.cycle = c.processor.cycle;
    m_s.halt_flag = c.processor.halt_flag;
    // General purpose registers
    for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
        m_s.x[i] = c.processor.x[i];
    }
    // Register shadow state
    m_s.shadow_state = make_shadow_uarch_state_pma_entry(PMA_SHADOW_UARCH_STATE_START, PMA_SHADOW_UARCH_STATE_LENGTH);
    // Register RAM
    constexpr auto ram_description = "uarch RAM";
    if (!c.ram.image_filename.empty()) {
        // Load RAM image from file
        m_s.ram =
            make_callocd_memory_pma_entry(ram_description, PMA_UARCH_RAM_START, UARCH_RAM_LENGTH, c.ram.image_filename)
                .set_flags(ram_flags);
    } else {
        // Load embedded pristine RAM image
        m_s.ram = make_callocd_memory_pma_entry(ram_description, PMA_UARCH_RAM_START, PMA_UARCH_RAM_LENGTH)
                      .set_flags(ram_flags);
        if (uarch_pristine_ram_len > m_s.ram.get_length()) {
            throw std::runtime_error("embedded uarch ram image does not fit in uarch ram pma");
        }
        memcpy(m_s.ram.get_memory().get_host_memory(), uarch_pristine_ram, uarch_pristine_ram_len);
    }
}

pma_entry &uarch_machine::find_pma_entry(uint64_t paddr, uint64_t length) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): remove const to reuse code
    return const_cast<pma_entry &>(std::as_const(*this).find_pma_entry(paddr, length));
}

const pma_entry &uarch_machine::find_pma_entry(uint64_t paddr, uint64_t length) const {
    if (m_s.ram.contains(paddr, length)) {
        return m_s.ram;
    }
    return m_s.empty_pma;
}

} // namespace cartesi
