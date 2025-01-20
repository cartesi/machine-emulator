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

#include <ios>
#include <sstream>

#include "machine.h"
#include "riscv-constants.h"
#include "shadow-pmas.h"
#include "shadow-state.h"
#include "shadow-tlb.h"
#include "strict-aliasing.h"
#include "uarch-machine-bridge.h"

namespace cartesi {

const char *uarch_machine_bridge::get_what_name(uint64_t paddr) {
    if (paddr >= PMA_UARCH_RAM_START && paddr - PMA_UARCH_RAM_START < PMA_UARCH_RAM_LENGTH) {
        return "uarch.ram";
    }
    // If in shadow, return refined name
    if (paddr >= PMA_SHADOW_TLB_START && paddr - PMA_SHADOW_TLB_START < PMA_SHADOW_TLB_LENGTH) {
        [[maybe_unused]] TLB_set_index set_index{};
        [[maybe_unused]] uint64_t slot_index{};
        return shadow_tlb_get_what_name(shadow_tlb_get_what(paddr, set_index, slot_index));
    }
    if (paddr >= PMA_SHADOW_STATE_START && paddr - PMA_SHADOW_STATE_START < PMA_SHADOW_STATE_LENGTH) {
        return shadow_state_get_what_name(shadow_state_get_what(paddr));
    }
    if (paddr >= PMA_SHADOW_PMAS_START && paddr - PMA_SHADOW_PMAS_START < PMA_SHADOW_PMAS_LENGTH) {
        return shadow_pmas_get_what_name(shadow_pmas_get_what(paddr));
    }
    if (paddr >= PMA_SHADOW_UARCH_STATE_START && paddr - PMA_SHADOW_UARCH_STATE_START < PMA_SHADOW_UARCH_STATE_LENGTH) {
        return shadow_uarch_state_get_what_name(shadow_uarch_state_get_what(paddr));
    }
    return "memory";
}

void uarch_machine_bridge::write_word(uint64_t paddr, uint64_t val) {
    if ((paddr & (sizeof(uint64_t) - 1)) != 0) {
        throw std::runtime_error("misaligned write via uarch-machine bridge");
    }
    if (paddr >= PMA_UARCH_RAM_START && paddr - PMA_UARCH_RAM_START < PMA_UARCH_RAM_LENGTH) {
        write_uarch_memory_word(paddr, val);
        return;
    }
    if (paddr >= PMA_SHADOW_STATE_START && paddr - PMA_SHADOW_STATE_START < PMA_SHADOW_STATE_LENGTH) {
        write_shadow_state(paddr, val);
        return;
    }
    write_memory_word(paddr, val);
}

uint64_t uarch_machine_bridge::read_word(uint64_t paddr) const {
    if ((paddr & (sizeof(uint64_t) - 1)) != 0) {
        throw std::runtime_error("misaligned read via uarch-machine bridge");
    }
    if (paddr >= PMA_UARCH_RAM_START && paddr - PMA_UARCH_RAM_START < PMA_UARCH_RAM_LENGTH) {
        return read_uarch_memory_word(paddr);
    }
    if (paddr >= PMA_SHADOW_STATE_START && paddr - PMA_SHADOW_STATE_START < PMA_SHADOW_STATE_LENGTH) {
        return read_shadow_state(paddr);
    }
    if (paddr >= PMA_SHADOW_TLB_START && paddr - PMA_SHADOW_TLB_START < PMA_SHADOW_TLB_LENGTH) {
        return read_shadow_tlb(paddr);
    }
    return read_memory_word(paddr);
}

uint64_t uarch_machine_bridge::read_memory_word(uint64_t paddr) const {
    const auto &pma = m_m.find_pma_entry(paddr, sizeof(uint64_t));
    if (pma.get_istart_E() || !pma.get_istart_M()) {
        std::ostringstream err;
        err << "unhandled memory read from " << pma.get_description() << " at address 0x" << std::hex << paddr << "("
            << std::dec << paddr << ")";
    }
    if (!pma.get_istart_R()) {
        std::ostringstream err;
        err << "attempted memory read from (non-readable) " << pma.get_description() << " at address 0x" << std::hex
            << paddr << "(" << std::dec << paddr << ")";
        throw std::runtime_error{err.str()};
    }
    const auto offset = paddr - pma.get_start();
    return aliased_aligned_read<uint64_t>(pma.get_memory().get_host_memory() + offset);
}

uint64_t uarch_machine_bridge::read_uarch_memory_word(uint64_t paddr) const {
    const auto &pma = m_m.get_uarch_state().ram;
    const auto offset = paddr - pma.get_start();
    return aliased_aligned_read<uint64_t>(pma.get_memory().get_host_memory() + offset);
}

void uarch_machine_bridge::write_uarch_memory_word(uint64_t paddr, uint64_t val) {
    auto &pma = m_m.get_uarch_state().ram;
    const auto offset = paddr - pma.get_start();
    aliased_aligned_write<uint64_t>(pma.get_memory().get_host_memory() + offset, val);
}

uint64_t uarch_machine_bridge::read_shadow_state(uint64_t paddr) const {
    auto reg = shadow_state_get_what(paddr);
    if (reg == shadow_state_what::unknown_) {
        throw std::runtime_error("unhandled shadow state read via uarch-machine bridge");
    }
    return m_m.read_reg(machine_reg_enum(reg));
}

uint64_t uarch_machine_bridge::read_shadow_tlb(uint64_t paddr) const {
    TLB_set_index set_index{};
    uint64_t slot_index{};
    auto reg = shadow_tlb_get_what(paddr, set_index, slot_index);
    if (reg == shadow_tlb_what::unknown_) {
        throw std::runtime_error("unhandled shadow TLB read via uarch-machine bridge");
    }
    return m_m.read_shadow_tlb(set_index, slot_index, reg);
}

void uarch_machine_bridge::write_shadow_state(uint64_t paddr, uint64_t val) {
    auto reg = shadow_state_get_what(paddr);
    if (reg == shadow_state_what::unknown_) {
        throw std::runtime_error("unhandled shadow state write via uarch-machine bridge");
    }
    if (reg == shadow_state_what::x0) {
        throw std::runtime_error("invalid write to shadow state x0 via uarch-machine bridge");
    }
    m_m.write_reg(machine_reg_enum(reg), val);
}

void uarch_machine_bridge::mark_dirty_page(uint64_t paddr, uint64_t pma_index) {
    m_m.mark_dirty_page(paddr, pma_index);
}

void uarch_machine_bridge::write_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page,
    uint64_t vp_offset, uint64_t pma_index) {
    m_m.check_shadow_tlb(set_index, slot_index, vaddr_page, vp_offset, pma_index,
        "invalid write to shadow TLB via uarch-machine bridge: ");
    m_m.write_shadow_tlb(set_index, slot_index, vaddr_page, vp_offset, pma_index);
}

void uarch_machine_bridge::write_memory_word(uint64_t paddr, uint64_t val) {
    auto &pma = m_m.find_pma_entry(paddr, sizeof(uint64_t));
    if (pma.get_istart_E() || !pma.get_istart_M()) {
        std::ostringstream err;
        err << "unhandled memory write to " << pma.get_description() << " at address 0x" << std::hex << paddr << "("
            << std::dec << paddr << ")";
        throw std::runtime_error{err.str()};
    }
    if (!pma.get_istart_W()) {
        std::ostringstream err;
        err << "attempted memory write to (non-writeable) " << pma.get_description() << " at address 0x" << std::hex
            << paddr << "(" << std::dec << paddr << ")";
        throw std::runtime_error{err.str()};
    }
    const auto offset = paddr - pma.get_start();
    aliased_aligned_write<uint64_t>(pma.get_memory().get_host_memory() + offset, val);
}

} // namespace cartesi
