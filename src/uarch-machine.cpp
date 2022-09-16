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

#include <utility>

#include "uarch-machine.h"

namespace cartesi {

const pma_entry::flags uarch_machine::m_rom_flags{
    true,                  // R
    false,                 // W
    true,                  // X
    true,                  // IR
    false,                 // IW
    PMA_ISTART_DID::memory // DID
};

const pma_entry::flags uarch_machine::m_ram_flags{
    true,                  // R
    true,                  // W
    true,                  // X
    true,                  // IR
    true,                  // IW
    PMA_ISTART_DID::memory // DID
};

uarch_machine::uarch_machine(uarch_config c) : m_s{}, m_c{std::move(c)} {
    m_s.pc = m_c.processor.pc;
    m_s.cycle = m_c.processor.cycle;
    m_s.rom_length = m_c.rom.length;
    m_s.ram_length = m_c.ram.length;
    // General purpose registers
    for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
        m_s.x[i] = m_c.processor.x[i];
    }
    // Register memory PMAs
    if (!m_c.ram.image_filename.empty()) {
        register_pma_entry(make_callocd_memory_pma_entry(PMA_UARCH_RAM_START, m_c.ram.length, m_c.ram.image_filename)
                               .set_flags(m_ram_flags));
    } else if (m_c.ram.length > 0) {
        register_pma_entry(make_callocd_memory_pma_entry(PMA_UARCH_RAM_START, m_c.ram.length).set_flags(m_ram_flags));
    }

    if (!m_c.rom.image_filename.empty()) {
        register_pma_entry(make_callocd_memory_pma_entry(PMA_UARCH_ROM_START, m_c.rom.length, m_c.rom.image_filename)
                               .set_flags(m_rom_flags));
    } else if (m_c.rom.length > 0) {
        register_pma_entry(make_callocd_memory_pma_entry(PMA_UARCH_ROM_START, m_c.rom.length).set_flags(m_rom_flags));
    }

    register_pma_entry(make_empty_pma_entry(0, 0));
}

pma_entry &uarch_machine::register_pma_entry(pma_entry &&pma) {
    if (m_s.pmas.capacity() <= m_s.pmas.size()) { // NOLINT(readability-static-accessed-through-instance)
        throw std::runtime_error{"too many PMAs"};
    }
    auto start = pma.get_start();
    if ((start & (PMA_PAGE_SIZE - 1)) != 0) {
        throw std::invalid_argument{"PMA start must be aligned to page boundary"};
    }
    auto length = pma.get_length();
    if ((length & (PMA_PAGE_SIZE - 1)) != 0) {
        throw std::invalid_argument{"PMA length must be multiple of page size"};
    }
    // Range A overlaps with B if A starts before B ends and A ends after B starts
    for (const auto &existing_pma : m_s.pmas) {
        if (start < existing_pma.get_start() + existing_pma.get_length() && start + length > existing_pma.get_start()) {
            throw std::invalid_argument{"PMA overlaps with existing PMA"};
        }
    }
    m_s.pmas.push_back(std::move(pma));
    return m_s.pmas.back();
}

uint64_t uarch_machine::read_cycle(void) const {
    return m_s.cycle;
}

void uarch_machine::write_cycle(uint64_t val) {
    m_s.cycle = val;
}

uint64_t uarch_machine::read_pc(void) const {
    return m_s.pc;
}

void uarch_machine::write_pc(uint64_t val) {
    m_s.pc = val;
}

uint64_t uarch_machine::read_x(int i) const {
    return m_s.x[i];
}

void uarch_machine::write_x(int i, uint64_t val) {
    if (i > 0) {
        m_s.x[i] = val;
    }
}

uint64_t uarch_machine::read_rom_length(void) const {
    return m_s.rom_length;
}

uint64_t uarch_machine::read_ram_length(void) const {
    return m_s.ram_length;
}

pma_entry &uarch_machine::find_pma_entry(uint64_t paddr, size_t length) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): remove const to reuse code
    return const_cast<pma_entry &>(std::as_const(*this).find_pma_entry(paddr, length));
}

const pma_entry &uarch_machine::find_pma_entry(uint64_t paddr, size_t length) const {
    for (const auto &pma : m_s.pmas) {
        // Stop at first empty PMA
        if (pma.get_length() == 0) {
            return pma;
        }
        // Check if data is in range
        if (paddr >= pma.get_start() && pma.get_length() >= length &&
            paddr - pma.get_start() <= pma.get_length() - length) {
            return pma;
        }
    }
    // Last PMA is always the empty range
    return m_s.pmas.back();
}

} // namespace cartesi
