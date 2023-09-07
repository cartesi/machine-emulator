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

#include <boost/range/adaptor/sliced.hpp>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <future>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sys/stat.h>
#include <thread>

#include "clint-factory.h"
#include "htif-factory.h"
#include "interpret.h"
#include "machine.h"
#include "riscv-constants.h"
#include "rom.h"
#include "rtc.h"
#include "shadow-pmas-factory.h"
#include "shadow-state-factory.h"
#include "shadow-tlb-factory.h"
#include "state-access.h"
#include "strict-aliasing.h"
#include "translate-virtual-address.h"
#include "uarch-interpret.h"
#include "uarch-record-state-access.h"
#include "uarch-replay-state-access.h"
#include "uarch-state-access.h"
#include "uarch-step.h"
#include "unique-c-ptr.h"

/// \file
/// \brief Cartesi machine implementation

namespace cartesi {

using namespace std::string_literals;
using namespace boost::adaptors;

const pma_entry::flags machine::m_ram_flags{
    true,                  // R
    true,                  // W
    true,                  // X
    true,                  // IR
    true,                  // IW
    PMA_ISTART_DID::memory // DID
};

const pma_entry::flags machine::m_rom_flags{
    true,                  // R
    false,                 // W
    true,                  // X
    true,                  // IR
    false,                 // IW
    PMA_ISTART_DID::memory // DID
};

const pma_entry::flags machine::m_flash_drive_flags{
    true,                       // R
    true,                       // W
    false,                      // X
    true,                       // IR
    true,                       // IW
    PMA_ISTART_DID::flash_drive // DID
};

const pma_entry::flags machine::m_rollup_rx_buffer_flags{
    true,                            // R
    false,                           // W
    false,                           // X
    true,                            // IR
    true,                            // IW
    PMA_ISTART_DID::rollup_rx_buffer // DID
};

const pma_entry::flags machine::m_rollup_tx_buffer_flags{
    true,                            // R
    true,                            // W
    false,                           // X
    true,                            // IR
    true,                            // IW
    PMA_ISTART_DID::rollup_tx_buffer // DID
};

const pma_entry::flags machine::m_rollup_input_metadata_flags{
    true,                                 // R
    false,                                // W
    false,                                // X
    true,                                 // IR
    true,                                 // IW
    PMA_ISTART_DID::rollup_input_metadata // DID
};

const pma_entry::flags machine::m_rollup_voucher_hashes_flags{
    true,                                 // R
    true,                                 // W
    false,                                // X
    true,                                 // IR
    true,                                 // IW
    PMA_ISTART_DID::rollup_voucher_hashes // DID
};

const pma_entry::flags machine::m_rollup_notice_hashes_flags{
    true,                                // R
    true,                                // W
    false,                               // X
    true,                                // IR
    true,                                // IW
    PMA_ISTART_DID::rollup_notice_hashes // DID
};

pma_entry machine::make_memory_range_pma_entry(const std::string &description, const memory_range_config &c) {
    if (c.image_filename.empty()) {
        return make_callocd_memory_pma_entry(description, c.start, c.length);
    }
    return make_mmapd_memory_pma_entry(description, c.start, c.length, c.image_filename, c.shared);
}

pma_entry machine::make_flash_drive_pma_entry(const std::string &description, const memory_range_config &c) {
    return make_memory_range_pma_entry(description, c).set_flags(m_flash_drive_flags);
}

pma_entry machine::make_rollup_rx_buffer_pma_entry(const memory_range_config &c) {
    return make_memory_range_pma_entry("rollup rx buffer memory range"s, c).set_flags(m_rollup_rx_buffer_flags);
}

pma_entry machine::make_rollup_tx_buffer_pma_entry(const memory_range_config &c) {
    return make_memory_range_pma_entry("rollup tx buffer memory range"s, c).set_flags(m_rollup_tx_buffer_flags);
}

pma_entry machine::make_rollup_input_metadata_pma_entry(const memory_range_config &c) {
    return make_memory_range_pma_entry("rollup input metadata memory range"s, c)
        .set_flags(m_rollup_input_metadata_flags);
}

pma_entry machine::make_rollup_voucher_hashes_pma_entry(const memory_range_config &c) {
    return make_memory_range_pma_entry("rollup voucher hashes memory range"s, c)
        .set_flags(m_rollup_voucher_hashes_flags);
}

pma_entry machine::make_rollup_notice_hashes_pma_entry(const memory_range_config &c) {
    return make_memory_range_pma_entry("rollup notice hashes memory range"s, c).set_flags(m_rollup_notice_hashes_flags);
}

pma_entry &machine::register_pma_entry(pma_entry &&pma) {
    if (m_s.pmas.capacity() <= m_s.pmas.size()) { // NOLINT(readability-static-accessed-through-instance)
        throw std::runtime_error{"too many PMAs when adding "s + pma.get_description()};
    }
    auto start = pma.get_start();
    if ((start & (PMA_PAGE_SIZE - 1)) != 0) {
        throw std::invalid_argument{"start of "s + pma.get_description() + " ("s + std::to_string(start) +
            ") must be aligned to page boundary of "s + std::to_string(PMA_PAGE_SIZE) + " bytes"s};
    }
    auto length = pma.get_length();
    if ((length & (PMA_PAGE_SIZE - 1)) != 0) {
        throw std::invalid_argument{"length of "s + pma.get_description() + " ("s + std::to_string(length) +
            ") must be multiple of page size "s + std::to_string(PMA_PAGE_SIZE)};
    }
    // Check PMA range, when not the sentinel PMA entry
    if (length != 0 || start != 0) {
        if (length == 0) {
            throw std::invalid_argument{"length of "s + pma.get_description() + " cannot be zero"s};
        }
        // Checks if PMA is in addressable range, safe unsigned overflows
        if (start > PMA_ADDRESSABLE_MASK || (length - 1) > (PMA_ADDRESSABLE_MASK - start)) {
            throw std::invalid_argument{
                "range of "s + pma.get_description() + " must use at most 56 bits to be addressable"s};
        }
    }
    // Range A overlaps with B if A starts before B ends and A ends after B starts
    for (const auto &existing_pma : m_s.pmas) {
        if (start < existing_pma.get_start() + existing_pma.get_length() && start + length > existing_pma.get_start()) {
            throw std::invalid_argument{"range of "s + pma.get_description() + " overlaps with range of existing "s +
                existing_pma.get_description()};
        }
    }
    pma.set_index(static_cast<int>(m_s.pmas.size()));
    m_s.pmas.push_back(std::move(pma));
    return m_s.pmas.back();
}

static bool DID_is_protected(PMA_ISTART_DID DID) {
    switch (DID) {
        case PMA_ISTART_DID::flash_drive:
            return false;
        case PMA_ISTART_DID::rollup_rx_buffer:
            return false;
        case PMA_ISTART_DID::rollup_tx_buffer:
            return false;
        case PMA_ISTART_DID::rollup_input_metadata:
            return false;
        case PMA_ISTART_DID::rollup_voucher_hashes:
            return false;
        case PMA_ISTART_DID::rollup_notice_hashes:
            return false;
        default:
            return true;
    }
}

void machine::replace_memory_range(const memory_range_config &range) {
    for (auto &pma : m_s.pmas) {
        if (pma.get_start() == range.start && pma.get_length() == range.length) {
            const auto curr = pma.get_istart_DID();
            if (DID_is_protected(curr)) {
                throw std::invalid_argument{"attempt to replace a protected range "s + pma.get_description()};
            }
            // replace range preserving original flags
            pma = make_memory_range_pma_entry(pma.get_description(), range).set_flags(pma.get_flags());
            return;
        }
    }
    throw std::invalid_argument{"attempt to replace inexistent memory range"};
}

template <TLB_entry_type ETYPE>
static void load_tlb_entry(machine &m, uint64_t eidx, unsigned char *hmem) {
    tlb_hot_entry &tlbhe = m.get_state().tlb.hot[ETYPE][eidx];
    tlb_cold_entry &tlbce = m.get_state().tlb.cold[ETYPE][eidx];
    auto vaddr_page = aliased_aligned_read<uint64_t>(hmem + tlb_get_vaddr_page_rel_addr<ETYPE>(eidx));
    auto paddr_page = aliased_aligned_read<uint64_t>(hmem + tlb_get_paddr_page_rel_addr<ETYPE>(eidx));
    auto pma_index = aliased_aligned_read<uint64_t>(hmem + tlb_get_pma_index_rel_addr<ETYPE>(eidx));
    if (vaddr_page != TLB_INVALID_PAGE) {
        if ((vaddr_page & ~PAGE_OFFSET_MASK) != vaddr_page) {
            throw std::invalid_argument{"misaligned virtual page address in TLB entry"};
        }
        if ((paddr_page & ~PAGE_OFFSET_MASK) != paddr_page) {
            throw std::invalid_argument{"misaligned physical page address in TLB entry"};
        }
        const pma_entry &pma = m.find_pma_entry<uint64_t>(paddr_page);
        // Checks if the PMA still valid
        if (pma.get_length() == 0 || !pma.get_istart_M() || pma_index >= m.get_state().pmas.size() ||
            &pma != &m.get_state().pmas[pma_index]) {
            throw std::invalid_argument{"invalid PMA for TLB entry"};
        }
        const unsigned char *hpage = pma.get_memory().get_host_memory() + (paddr_page - pma.get_start());
        // Valid TLB entry
        tlbhe.vaddr_page = vaddr_page;
        tlbhe.vh_offset = cast_ptr_to_addr<uint64_t>(hpage) - vaddr_page;
        tlbce.paddr_page = paddr_page;
        tlbce.pma_index = pma_index;
    } else { // Empty or invalidated TLB entry
        tlbhe.vaddr_page = vaddr_page;
        tlbhe.vh_offset = 0;
        tlbce.paddr_page = paddr_page;
        tlbce.pma_index = pma_index;
    }
}

template <TLB_entry_type ETYPE>
static void init_tlb_entry(machine &m, uint64_t eidx) {
    tlb_hot_entry &tlbhe = m.get_state().tlb.hot[ETYPE][eidx];
    tlb_cold_entry &tlbce = m.get_state().tlb.cold[ETYPE][eidx];
    tlbhe.vaddr_page = TLB_INVALID_PAGE;
    tlbhe.vh_offset = 0;
    tlbce.paddr_page = TLB_INVALID_PAGE;
    tlbce.pma_index = TLB_INVALID_PMA;
}

machine::machine(const machine_config &c, const machine_runtime_config &r) :
    m_s{},
    m_t{},
    m_c{c},
    m_uarch{c.uarch},
    m_r{r} {

    if (m_c.processor.marchid == UINT64_C(-1)) {
        m_c.processor.marchid = MARCHID_INIT;
    }

    if (m_c.processor.marchid != MARCHID_INIT && !r.skip_version_check) {
        throw std::invalid_argument{"marchid mismatch, emulator version is incompatible"};
    }

    if (m_c.processor.mvendorid == UINT64_C(-1)) {
        m_c.processor.mvendorid = MVENDORID_INIT;
    }

    if (m_c.processor.mvendorid != MVENDORID_INIT && !r.skip_version_check) {
        throw std::invalid_argument{"mvendorid mismatch, emulator version is incompatible"};
    }

    if (m_c.processor.mimpid == UINT64_C(-1)) {
        m_c.processor.mimpid = MIMPID_INIT;
    }

    if (m_c.processor.mimpid != MIMPID_INIT && !r.skip_version_check) {
        throw std::invalid_argument{"mimpid mismatch, emulator version is incompatible"};
    }

    // General purpose registers
    for (int i = 1; i < X_REG_COUNT; i++) {
        write_x(i, m_c.processor.x[i]);
    }

    // Floating-point registers
    for (int i = 0; i < F_REG_COUNT; i++) {
        write_f(i, m_c.processor.f[i]);
    }

    write_pc(m_c.processor.pc);
    write_fcsr(m_c.processor.fcsr);
    write_mcycle(m_c.processor.mcycle);
    write_icycleinstret(m_c.processor.icycleinstret);
    write_mstatus(m_c.processor.mstatus);
    write_mtvec(m_c.processor.mtvec);
    write_mscratch(m_c.processor.mscratch);
    write_mepc(m_c.processor.mepc);
    write_mcause(m_c.processor.mcause);
    write_mtval(m_c.processor.mtval);
    write_misa(m_c.processor.misa);
    write_mie(m_c.processor.mie);
    write_mip(m_c.processor.mip);
    write_medeleg(m_c.processor.medeleg);
    write_mideleg(m_c.processor.mideleg);
    write_mcounteren(m_c.processor.mcounteren);
    write_menvcfg(m_c.processor.menvcfg);
    write_stvec(m_c.processor.stvec);
    write_sscratch(m_c.processor.sscratch);
    write_sepc(m_c.processor.sepc);
    write_scause(m_c.processor.scause);
    write_stval(m_c.processor.stval);
    write_satp(m_c.processor.satp);
    write_scounteren(m_c.processor.scounteren);
    write_senvcfg(m_c.processor.senvcfg);
    write_ilrsc(m_c.processor.ilrsc);
    write_iflags(m_c.processor.iflags);

    // Register RAM
    if (m_c.ram.image_filename.empty()) {
        register_pma_entry(make_callocd_memory_pma_entry("RAM"s, PMA_RAM_START, m_c.ram.length).set_flags(m_ram_flags));
    } else {
        register_pma_entry(make_callocd_memory_pma_entry("RAM"s, PMA_RAM_START, m_c.ram.length, m_c.ram.image_filename)
                               .set_flags(m_ram_flags));
    }

    // Register ROM
    pma_entry &rom = register_pma_entry((m_c.rom.image_filename.empty() ?
            make_callocd_memory_pma_entry("ROM"s, PMA_ROM_START, PMA_ROM_LENGTH) :
            make_callocd_memory_pma_entry("ROM"s, PMA_ROM_START, PMA_ROM_LENGTH, m_c.rom.image_filename))
                                            .set_flags(m_rom_flags));

    // Register all flash drives
    int i = 0;
    for (auto &f : m_c.flash_drive) {
        const std::string flash_description = "flash drive "s + std::to_string(i++);
        // Auto detect flash drive image length
        if (f.length == UINT64_C(-1)) {
            auto fp = unique_fopen(f.image_filename.c_str(), "rb");
            if (fseek(fp.get(), 0, SEEK_END) != 0) {
                throw std::system_error{errno, std::generic_category(),
                    "unable to obtain length of image file '"s + f.image_filename + "' when initializing "s +
                        flash_description};
            }
            const auto length = ftell(fp.get());
            if (length < 0) {
                throw std::system_error{errno, std::generic_category(),
                    "unable to obtain length of image file '"s + f.image_filename + "' when initializing "s +
                        flash_description};
            }
            f.length = length;
        }
        register_pma_entry(make_flash_drive_pma_entry(flash_description, f));
    }

    // Register rollup memory ranges
    if (m_c.rollup.has_value()) {
        if (m_c.rollup->rx_buffer.length == 0 || m_c.rollup->rx_buffer.start == 0 ||
            m_c.rollup->tx_buffer.length == 0 || m_c.rollup->tx_buffer.start == 0 ||
            m_c.rollup->input_metadata.length == 0 || m_c.rollup->input_metadata.start == 0 ||
            m_c.rollup->voucher_hashes.length == 0 || m_c.rollup->voucher_hashes.start == 0 ||
            m_c.rollup->notice_hashes.length == 0 || m_c.rollup->notice_hashes.start == 0) {
            throw std::invalid_argument{"incomplete rollup configuration"};
        }
        register_pma_entry(make_rollup_tx_buffer_pma_entry(m_c.rollup->tx_buffer));
        register_pma_entry(make_rollup_rx_buffer_pma_entry(m_c.rollup->rx_buffer));
        register_pma_entry(make_rollup_input_metadata_pma_entry(m_c.rollup->input_metadata));
        register_pma_entry(make_rollup_voucher_hashes_pma_entry(m_c.rollup->voucher_hashes));
        register_pma_entry(make_rollup_notice_hashes_pma_entry(m_c.rollup->notice_hashes));
    }

    // Register HTIF device
    register_pma_entry(make_htif_pma_entry(PMA_HTIF_START, PMA_HTIF_LENGTH, &m_r.htif));

    // Copy HTIF state to from config to machine
    write_htif_tohost(m_c.htif.tohost);
    write_htif_fromhost(m_c.htif.fromhost);
    // Only command in halt device is command 0 and it is always available
    const uint64_t htif_ihalt = static_cast<uint64_t>(true) << HTIF_HALT_HALT;
    write_htif_ihalt(htif_ihalt);
    const uint64_t htif_iconsole = static_cast<uint64_t>(m_c.htif.console_getchar) << HTIF_CONSOLE_GETCHAR |
        static_cast<uint64_t>(true) << HTIF_CONSOLE_PUTCHAR;
    write_htif_iconsole(htif_iconsole);
    const uint64_t htif_iyield = static_cast<uint64_t>(m_c.htif.yield_manual) << HTIF_YIELD_MANUAL |
        static_cast<uint64_t>(m_c.htif.yield_automatic) << HTIF_YIELD_AUTOMATIC;
    write_htif_iyield(htif_iyield);
    // Resiter CLINT device
    register_pma_entry(make_clint_pma_entry(PMA_CLINT_START, PMA_CLINT_LENGTH));
    // Copy CLINT state to from config to machine
    write_clint_mtimecmp(m_c.clint.mtimecmp);

    // Register TLB device
    register_pma_entry(make_shadow_tlb_pma_entry(PMA_SHADOW_TLB_START, PMA_SHADOW_TLB_LENGTH));

    // Register state shadow device
    register_pma_entry(make_shadow_state_pma_entry(PMA_SHADOW_STATE_START, PMA_SHADOW_STATE_LENGTH));

    // Register pma board shadow device
    register_pma_entry(make_shadow_pmas_pma_entry(PMA_SHADOW_PMAS_START, PMA_SHADOW_PMAS_LENGTH));

    // Initialize PMA extension metadata on ROM
    rom_init(m_c, rom.get_memory().get_host_memory(), PMA_ROM_LENGTH);

    // Add sentinel to PMA vector
    register_pma_entry(make_empty_pma_entry("sentinel"s, 0, 0));

    // Initialize the vector of the pmas used by the merkle tree to compute hashes.
    // First, add all pmas from the machine state, except the sentinel
    for (auto &pma : m_s.pmas | sliced(0, m_s.pmas.size() - 1)) {
        m_pmas.push_back(&pma);
    }
    // Second, add the pmas visible only to the microarchitecture interpreter
    if (!m_uarch.get_state().ram.get_istart_E()) {
        m_pmas.push_back(&m_uarch.get_state().ram);
    }
    // Last, add sentinel
    m_pmas.push_back(&m_s.empty_pma);

    // Initialize TLB device
    // this must be done after all PMA entries are already registered, so we can lookup page addresses
    if (!m_c.tlb.image_filename.empty()) {
        // Create a temporary PMA entry just to load TLB contents from an image file
        pma_entry tlb_image_pma = make_mmapd_memory_pma_entry("shadow TLB device"s, PMA_SHADOW_TLB_START,
            PMA_SHADOW_TLB_LENGTH, m_c.tlb.image_filename, false);
        unsigned char *hmem = tlb_image_pma.get_memory().get_host_memory();
        for (uint64_t i = 0; i < PMA_TLB_SIZE; ++i) {
            load_tlb_entry<TLB_CODE>(*this, i, hmem);
            load_tlb_entry<TLB_READ>(*this, i, hmem);
            load_tlb_entry<TLB_WRITE>(*this, i, hmem);
        }
    } else {
        for (uint64_t i = 0; i < PMA_TLB_SIZE; ++i) {
            init_tlb_entry<TLB_CODE>(*this, i);
            init_tlb_entry<TLB_READ>(*this, i);
            init_tlb_entry<TLB_WRITE>(*this, i);
        }
    }

    // Initialize TTY if console input is enabled
    if (m_c.htif.console_getchar) {
        tty_initialize();
    }
}

static void load_hash(const std::string &dir, machine::hash_type &h) {
    auto name = dir + "/hash";
    auto fp = unique_fopen(name.c_str(), "rb");
    if (fread(h.data(), 1, h.size(), fp.get()) != h.size()) {
        throw std::runtime_error{"error reading from '" + name + "'"};
    }
}

machine::machine(const std::string &dir, const machine_runtime_config &r) : machine{machine_config::load(dir), r} {
    if (r.skip_root_hash_check) {
        return;
    }
    hash_type hstored;
    hash_type hrestored;
    load_hash(dir, hstored);
    if (!update_merkle_tree()) {
        throw std::runtime_error{"error updating Merkle tree"};
    }
    m_t.get_root_hash(hrestored);
    if (hstored != hrestored) {
        throw std::runtime_error{"stored and restored hashes do not match"};
    }
}

machine_config machine::get_serialization_config(void) const {
    // Initialize with copy of original config
    machine_config c = m_c;
    // Copy current processor state to config
    for (int i = 1; i < X_REG_COUNT; ++i) {
        c.processor.x[i] = read_x(i);
    }
    for (int i = 0; i < F_REG_COUNT; ++i) {
        c.processor.f[i] = read_f(i);
    }
    c.processor.pc = read_pc();
    c.processor.fcsr = read_fcsr();
    c.processor.mvendorid = read_mvendorid();
    c.processor.marchid = read_marchid();
    c.processor.mimpid = read_mimpid();
    c.processor.mcycle = read_mcycle();
    c.processor.icycleinstret = read_icycleinstret();
    c.processor.mstatus = read_mstatus();
    c.processor.mtvec = read_mtvec();
    c.processor.mscratch = read_mscratch();
    c.processor.mepc = read_mepc();
    c.processor.mcause = read_mcause();
    c.processor.mtval = read_mtval();
    c.processor.misa = read_misa();
    c.processor.mie = read_mie();
    c.processor.mip = read_mip();
    c.processor.medeleg = read_medeleg();
    c.processor.mideleg = read_mideleg();
    c.processor.mcounteren = read_mcounteren();
    c.processor.menvcfg = read_menvcfg();
    c.processor.stvec = read_stvec();
    c.processor.sscratch = read_sscratch();
    c.processor.sepc = read_sepc();
    c.processor.scause = read_scause();
    c.processor.stval = read_stval();
    c.processor.satp = read_satp();
    c.processor.scounteren = read_scounteren();
    c.processor.senvcfg = read_senvcfg();
    c.processor.ilrsc = read_ilrsc();
    c.processor.iflags = read_iflags();
    // Copy current CLINT state to config
    c.clint.mtimecmp = read_clint_mtimecmp();
    // Copy current HTIF state to config
    c.htif.tohost = read_htif_tohost();
    c.htif.fromhost = read_htif_fromhost();
    // c.htif.halt = read_htif_ihalt(); // hard-coded to true
    c.htif.console_getchar = static_cast<bool>(read_htif_iconsole() & (1 << HTIF_CONSOLE_GETCHAR));
    c.htif.yield_manual = static_cast<bool>(read_htif_iyield() & (1 << HTIF_YIELD_MANUAL));
    c.htif.yield_automatic = static_cast<bool>(read_htif_iyield() & (1 << HTIF_YIELD_AUTOMATIC));
    // Ensure we don't mess with ROM by writing the original bootargs
    // over the potentially modified memory region we serialize
    c.rom.bootargs.clear();
    // Remove image filenames from serialization
    // (they will be ignored by save and load for security reasons)
    c.rom.image_filename.clear();
    c.ram.image_filename.clear();
    c.uarch.ram.image_filename.clear();
    c.tlb.image_filename.clear();
    for (auto &f : c.flash_drive) {
        f.image_filename.clear();
    }
    if (c.rollup.has_value()) {
        auto &r = c.rollup.value();
        r.rx_buffer.image_filename.clear();
        r.tx_buffer.image_filename.clear();
        r.input_metadata.image_filename.clear();
        r.voucher_hashes.image_filename.clear();
        r.notice_hashes.image_filename.clear();
    }
    c.uarch.processor.cycle = read_uarch_cycle();
    c.uarch.processor.halt_flag = read_uarch_halt_flag();
    c.uarch.processor.pc = read_uarch_pc();
    for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
        c.uarch.processor.x[i] = read_uarch_x(i);
    }
    return c;
}

static void store_device_pma(const machine &m, const pma_entry &pma, const std::string &dir) {
    if (!pma.get_istart_IO()) {
        throw std::runtime_error{"attempt to save non-device PMA"};
    }
    auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE); // will throw if it fails
    auto name = machine_config::get_image_filename(dir, pma.get_start(), pma.get_length());
    auto fp = unique_fopen(name.c_str(), "wb");
    for (uint64_t page_start_in_range = 0; page_start_in_range < pma.get_length();
         page_start_in_range += PMA_PAGE_SIZE) {
        const unsigned char *page_data = nullptr;
        auto peek = pma.get_peek();
        if (!peek(pma, m, page_start_in_range, &page_data, scratch.get())) {
            throw std::runtime_error{"peek failed"};
        } else {
            if (!page_data) {
                memset(scratch.get(), 0, PMA_PAGE_SIZE);
                page_data = scratch.get();
            }
            if (fwrite(page_data, 1, PMA_PAGE_SIZE, fp.get()) != PMA_PAGE_SIZE) {
                throw std::system_error{errno, std::generic_category(), "error writing to '" + name + "'"};
            }
        }
    }
}

static void store_memory_pma(const pma_entry &pma, const std::string &dir) {
    if (!pma.get_istart_M()) {
        throw std::runtime_error{"attempt to save non-memory PMA"};
    }
    auto name = machine_config::get_image_filename(dir, pma.get_start(), pma.get_length());
    auto fp = unique_fopen(name.c_str(), "wb");
    const pma_memory &mem = pma.get_memory();
    if (fwrite(mem.get_host_memory(), 1, pma.get_length(), fp.get()) != pma.get_length()) {
        throw std::runtime_error{"error writing to '" + name + "'"};
    }
}

pma_entry &machine::find_pma_entry(uint64_t paddr, size_t length) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): remove const to reuse code
    return const_cast<pma_entry &>(std::as_const(*this).find_pma_entry(paddr, length));
}

const pma_entry &machine::find_pma_entry(uint64_t paddr, size_t length) const {
    return find_pma_entry(m_s.pmas, paddr, length);
}

template <typename CONTAINER>
pma_entry &machine::find_pma_entry(const CONTAINER &pmas, uint64_t paddr, size_t length) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): remove const to reuse code
    return const_cast<pma_entry &>(std::as_const(*this).find_pma_entry(pmas, paddr, length));
}

template <typename CONTAINER>
const pma_entry &machine::find_pma_entry(const CONTAINER &pmas, uint64_t paddr, size_t length) const {
    for (const auto &p : pmas) {
        const auto &pma = deref(p);
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
    return deref(pmas.back());
}

template <typename T>
static inline T &deref(T &t) {
    return t;
}

template <typename T>
static inline T &deref(T *t) {
    return *t;
}

void machine::store_pmas(const machine_config &c, const std::string &dir) const {
    store_memory_pma(find_pma_entry<uint64_t>(PMA_ROM_START), dir);
    store_memory_pma(find_pma_entry<uint64_t>(PMA_RAM_START), dir);
    store_device_pma(*this, find_pma_entry<uint64_t>(PMA_SHADOW_TLB_START), dir);
    // Could iterate over PMAs checking for those with a drive DID
    // but this is easier
    for (const auto &f : c.flash_drive) {
        store_memory_pma(find_pma_entry<uint64_t>(f.start), dir);
    }
    if (c.rollup.has_value()) {
        const auto &r = c.rollup.value();
        store_memory_pma(find_pma_entry<uint64_t>(r.rx_buffer.start), dir);
        store_memory_pma(find_pma_entry<uint64_t>(r.tx_buffer.start), dir);
        store_memory_pma(find_pma_entry<uint64_t>(r.input_metadata.start), dir);
        store_memory_pma(find_pma_entry<uint64_t>(r.voucher_hashes.start), dir);
        store_memory_pma(find_pma_entry<uint64_t>(r.notice_hashes.start), dir);
    }
    if (!m_uarch.get_state().ram.get_istart_E()) {
        store_memory_pma(m_uarch.get_state().ram, dir);
    }
}

static void store_hash(const machine::hash_type &h, const std::string &dir) {
    auto name = dir + "/hash";
    auto fp = unique_fopen(name.c_str(), "wb");
    if (fwrite(h.data(), 1, h.size(), fp.get()) != h.size()) {
        throw std::runtime_error{"error writing to '" + name + "'"};
    }
}

void machine::store(const std::string &dir) const {
    if (mkdir(dir.c_str(), 0700)) {
        throw std::runtime_error{"error creating directory '" + dir + "'"};
    }
    if (!update_merkle_tree()) {
        throw std::runtime_error{"error updating Merkle tree"};
    }
    hash_type h;
    m_t.get_root_hash(h);
    store_hash(h, dir);
    auto c = get_serialization_config();
    c.store(dir);
    store_pmas(c, dir);
}

// NOLINTNEXTLINE(modernize-use-equals-default)
machine::~machine() {
    // Cleanup TTY if console input was enabled
    if (m_c.htif.console_getchar) {
        tty_finalize();
    }
#ifdef DUMP_HIST
    (void) fprintf(stderr, "\nInstruction Histogram:\n");
    for (auto v : m_s.insn_hist) {
        (void) fprintf(stderr, "%s: %" PRIu64 "\n", v.first.c_str(), v.second);
    }
#endif
#if DUMP_COUNTERS
#define TLB_HIT_RATIO(s, a, b) (((double) (s).stats.b) / ((s).stats.a + (s).stats.b))
    (void) fprintf(stderr, "\nMachine Counters:\n");
    (void) fprintf(stderr, "inner loops: %" PRIu64 "\n", m_s.stats.inner_loop);
    (void) fprintf(stderr, "outers loops: %" PRIu64 "\n", m_s.stats.outer_loop);
    (void) fprintf(stderr, "supervisor ints: %" PRIu64 "\n", m_s.stats.sv_int);
    (void) fprintf(stderr, "supervisor ex: %" PRIu64 "\n", m_s.stats.sv_ex);
    (void) fprintf(stderr, "machine ints: %" PRIu64 "\n", m_s.stats.m_int);
    (void) fprintf(stderr, "machine ex: %" PRIu64 "\n", m_s.stats.m_ex);
    (void) fprintf(stderr, "atomic mem ops: %" PRIu64 "\n", m_s.stats.atomic_mop);
    (void) fprintf(stderr, "fence: %" PRIu64 "\n", m_s.stats.fence);
    (void) fprintf(stderr, "fence.i: %" PRIu64 "\n", m_s.stats.fence_i);
    (void) fprintf(stderr, "fence.vma: %" PRIu64 "\n", m_s.stats.fence_vma);
    (void) fprintf(stderr, "max asid: %" PRIu64 "\n", m_s.stats.max_asid);
    (void) fprintf(stderr, "User mode: %" PRIu64 "\n", m_s.stats.priv_level[PRV_U]);
    (void) fprintf(stderr, "Supervisor mode: %" PRIu64 "\n", m_s.stats.priv_level[PRV_S]);
    (void) fprintf(stderr, "Machine mode: %" PRIu64 "\n", m_s.stats.priv_level[PRV_M]);

    (void) fprintf(stderr, "tlb code hit ratio: %.4f\n", TLB_HIT_RATIO(m_s, tlb_cmiss, tlb_chit));
    (void) fprintf(stderr, "tlb read hit ratio: %.4f\n", TLB_HIT_RATIO(m_s, tlb_rmiss, tlb_rhit));
    (void) fprintf(stderr, "tlb write hit ratio: %.4f\n", TLB_HIT_RATIO(m_s, tlb_wmiss, tlb_whit));
    (void) fprintf(stderr, "tlb_chit: %" PRIu64 "\n", m_s.stats.tlb_chit);
    (void) fprintf(stderr, "tlb_cmiss: %" PRIu64 "\n", m_s.stats.tlb_cmiss);
    (void) fprintf(stderr, "tlb_rhit: %" PRIu64 "\n", m_s.stats.tlb_rhit);
    (void) fprintf(stderr, "tlb_rmiss: %" PRIu64 "\n", m_s.stats.tlb_rmiss);
    (void) fprintf(stderr, "tlb_whit: %" PRIu64 "\n", m_s.stats.tlb_whit);
    (void) fprintf(stderr, "tlb_wmiss: %" PRIu64 "\n", m_s.stats.tlb_wmiss);
    (void) fprintf(stderr, "tlb_flush_all: %" PRIu64 "\n", m_s.stats.tlb_flush_all);
    (void) fprintf(stderr, "tlb_flush_read: %" PRIu64 "\n", m_s.stats.tlb_flush_read);
    (void) fprintf(stderr, "tlb_flush_write: %" PRIu64 "\n", m_s.stats.tlb_flush_write);
    (void) fprintf(stderr, "tlb_flush_vaddr: %" PRIu64 "\n", m_s.stats.tlb_flush_vaddr);
    (void) fprintf(stderr, "tlb_flush_satp: %" PRIu64 "\n", m_s.stats.tlb_flush_satp);
    (void) fprintf(stderr, "tlb_flush_mstatus: %" PRIu64 "\n", m_s.stats.tlb_flush_mstatus);
    (void) fprintf(stderr, "tlb_flush_set_priv: %" PRIu64 "\n", m_s.stats.tlb_flush_set_priv);
    (void) fprintf(stderr, "tlb_flush_fence_vma_all: %" PRIu64 "\n", m_s.stats.tlb_flush_fence_vma_all);
    (void) fprintf(stderr, "tlb_flush_fence_vma_asid: %" PRIu64 "\n", m_s.stats.tlb_flush_fence_vma_asid);
    (void) fprintf(stderr, "tlb_flush_fence_vma_vaddr: %" PRIu64 "\n", m_s.stats.tlb_flush_fence_vma_vaddr);
    (void) fprintf(stderr, "tlb_flush_fence_vma_asid_vaddr: %" PRIu64 "\n", m_s.stats.tlb_flush_fence_vma_asid_vaddr);
#endif
}

uint64_t machine::read_x(int i) const {
    return m_s.x[i];
}

uint64_t machine::get_x_address(int i) {
    return shadow_state_get_x_abs_addr(i);
}

uint64_t machine::get_uarch_x_address(int i) {
    return shadow_state_get_uarch_x_abs_addr(i);
}

void machine::write_x(int i, uint64_t val) {
    if (i > 0) {
        m_s.x[i] = val;
    }
}

uint64_t machine::read_f(int i) const {
    return m_s.f[i];
}

uint64_t machine::get_f_address(int i) {
    return shadow_state_get_f_abs_addr(i);
}

void machine::write_f(int i, uint64_t val) {
    m_s.f[i] = val;
}

uint64_t machine::read_pc(void) const {
    return m_s.pc;
}

void machine::write_pc(uint64_t val) {
    m_s.pc = val;
}

uint64_t machine::read_fcsr(void) const {
    return m_s.fcsr;
}

void machine::write_fcsr(uint64_t val) {
    m_s.fcsr = val;
}

uint64_t machine::read_mvendorid(void) const { // NOLINT(readability-convert-member-functions-to-static)
    return MVENDORID_INIT;
}

uint64_t machine::read_marchid(void) const { // NOLINT(readability-convert-member-functions-to-static)
    return MARCHID_INIT;
}

uint64_t machine::read_mimpid(void) const { // NOLINT(readability-convert-member-functions-to-static)
    return MIMPID_INIT;
}

uint64_t machine::read_mcycle(void) const {
    return m_s.mcycle;
}

void machine::write_mcycle(uint64_t val) {
    m_s.mcycle = val;
}

uint64_t machine::read_icycleinstret(void) const {
    return m_s.icycleinstret;
}

void machine::write_icycleinstret(uint64_t val) {
    m_s.icycleinstret = val;
}

uint64_t machine::read_mstatus(void) const {
    return m_s.mstatus;
}

void machine::write_mstatus(uint64_t val) {
    m_s.mstatus = val;
}

uint64_t machine::read_mtvec(void) const {
    return m_s.mtvec;
}

void machine::write_mtvec(uint64_t val) {
    m_s.mtvec = val;
}

uint64_t machine::read_mscratch(void) const {
    return m_s.mscratch;
}

void machine::write_mscratch(uint64_t val) {
    m_s.mscratch = val;
}

uint64_t machine::read_mepc(void) const {
    return m_s.mepc;
}

void machine::write_mepc(uint64_t val) {
    m_s.mepc = val;
}

uint64_t machine::read_mcause(void) const {
    return m_s.mcause;
}

void machine::write_mcause(uint64_t val) {
    m_s.mcause = val;
}

uint64_t machine::read_mtval(void) const {
    return m_s.mtval;
}

void machine::write_mtval(uint64_t val) {
    m_s.mtval = val;
}

uint64_t machine::read_misa(void) const {
    return m_s.misa;
}

void machine::write_misa(uint64_t val) {
    m_s.misa = val;
}

uint64_t machine::read_mip(void) const {
    return m_s.mip;
}

void machine::write_mip(uint64_t val) {
    m_s.mip = val;
}

uint64_t machine::read_mie(void) const {
    return m_s.mie;
}

void machine::write_mie(uint64_t val) {
    m_s.mie = val;
}

uint64_t machine::read_medeleg(void) const {
    return m_s.medeleg;
}

void machine::write_medeleg(uint64_t val) {
    m_s.medeleg = val;
}

uint64_t machine::read_mideleg(void) const {
    return m_s.mideleg;
}

void machine::write_mideleg(uint64_t val) {
    m_s.mideleg = val;
}

uint64_t machine::read_mcounteren(void) const {
    return m_s.mcounteren;
}

void machine::write_mcounteren(uint64_t val) {
    m_s.mcounteren = val;
}

uint64_t machine::read_menvcfg(void) const {
    return m_s.menvcfg;
}

void machine::write_menvcfg(uint64_t val) {
    m_s.menvcfg = val;
}

uint64_t machine::read_stvec(void) const {
    return m_s.stvec;
}

void machine::write_stvec(uint64_t val) {
    m_s.stvec = val;
}

uint64_t machine::read_sscratch(void) const {
    return m_s.sscratch;
}

void machine::write_sscratch(uint64_t val) {
    m_s.sscratch = val;
}

uint64_t machine::read_sepc(void) const {
    return m_s.sepc;
}

void machine::write_sepc(uint64_t val) {
    m_s.sepc = val;
}

uint64_t machine::read_scause(void) const {
    return m_s.scause;
}

void machine::write_scause(uint64_t val) {
    m_s.scause = val;
}

uint64_t machine::read_stval(void) const {
    return m_s.stval;
}

void machine::write_stval(uint64_t val) {
    m_s.stval = val;
}

uint64_t machine::read_satp(void) const {
    return m_s.satp;
}

void machine::write_satp(uint64_t val) {
    m_s.satp = val;
}

uint64_t machine::read_scounteren(void) const {
    return m_s.scounteren;
}

void machine::write_scounteren(uint64_t val) {
    m_s.scounteren = val;
}

uint64_t machine::read_senvcfg(void) const {
    return m_s.senvcfg;
}

void machine::write_senvcfg(uint64_t val) {
    m_s.senvcfg = val;
}

uint64_t machine::read_ilrsc(void) const {
    return m_s.ilrsc;
}

void machine::write_ilrsc(uint64_t val) {
    m_s.ilrsc = val;
}

uint64_t machine::read_iflags(void) const {
    return m_s.read_iflags();
}

void machine::write_iflags(uint64_t val) {
    m_s.write_iflags(val);
}

uint64_t machine::read_htif_tohost(void) const {
    return m_s.htif.tohost;
}

uint64_t machine::read_htif_tohost_dev(void) const {
    return HTIF_DEV_FIELD(m_s.htif.tohost);
}

uint64_t machine::read_htif_tohost_cmd(void) const {
    return HTIF_CMD_FIELD(m_s.htif.tohost);
}

uint64_t machine::read_htif_tohost_data(void) const {
    return HTIF_DATA_FIELD(m_s.htif.tohost);
}

void machine::write_htif_tohost(uint64_t val) {
    m_s.htif.tohost = val;
}

uint64_t machine::read_htif_fromhost(void) const {
    return m_s.htif.fromhost;
}

void machine::write_htif_fromhost(uint64_t val) {
    m_s.htif.fromhost = val;
}

void machine::write_htif_fromhost_data(uint64_t val) {
    m_s.htif.fromhost = HTIF_REPLACE_DATA(m_s.htif.fromhost, val);
}

uint64_t machine::read_htif_ihalt(void) const {
    return m_s.htif.ihalt;
}

void machine::write_htif_ihalt(uint64_t val) {
    m_s.htif.ihalt = val;
}

uint64_t machine::read_htif_iconsole(void) const {
    return m_s.htif.iconsole;
}

void machine::write_htif_iconsole(uint64_t val) {
    m_s.htif.iconsole = val;
}

uint64_t machine::read_htif_iyield(void) const {
    return m_s.htif.iyield;
}

void machine::write_htif_iyield(uint64_t val) {
    m_s.htif.iyield = val;
}

uint64_t machine::read_clint_mtimecmp(void) const {
    return m_s.clint.mtimecmp;
}

void machine::write_clint_mtimecmp(uint64_t val) {
    m_s.clint.mtimecmp = val;
}

uint64_t machine::read_csr(csr r) const {
    switch (r) {
        case csr::pc:
            return read_pc();
        case csr::fcsr:
            return read_fcsr();
        case csr::mvendorid:
            return read_mvendorid();
        case csr::marchid:
            return read_marchid();
        case csr::mimpid:
            return read_mimpid();
        case csr::mcycle:
            return read_mcycle();
        case csr::icycleinstret:
            return read_icycleinstret();
        case csr::mstatus:
            return read_mstatus();
        case csr::mtvec:
            return read_mtvec();
        case csr::mscratch:
            return read_mscratch();
        case csr::mepc:
            return read_mepc();
        case csr::mcause:
            return read_mcause();
        case csr::mtval:
            return read_mtval();
        case csr::misa:
            return read_misa();
        case csr::mie:
            return read_mie();
        case csr::mip:
            return read_mip();
        case csr::medeleg:
            return read_medeleg();
        case csr::mideleg:
            return read_mideleg();
        case csr::mcounteren:
            return read_mcounteren();
        case csr::menvcfg:
            return read_menvcfg();
        case csr::stvec:
            return read_stvec();
        case csr::sscratch:
            return read_sscratch();
        case csr::sepc:
            return read_sepc();
        case csr::scause:
            return read_scause();
        case csr::stval:
            return read_stval();
        case csr::satp:
            return read_satp();
        case csr::scounteren:
            return read_scounteren();
        case csr::senvcfg:
            return read_senvcfg();
        case csr::ilrsc:
            return read_ilrsc();
        case csr::iflags:
            return read_iflags();
        case csr::clint_mtimecmp:
            return read_clint_mtimecmp();
        case csr::htif_tohost:
            return read_htif_tohost();
        case csr::htif_fromhost:
            return read_htif_fromhost();
        case csr::htif_ihalt:
            return read_htif_ihalt();
        case csr::htif_iconsole:
            return read_htif_iconsole();
        case csr::htif_iyield:
            return read_htif_iyield();
        case csr::uarch_cycle:
            return read_uarch_cycle();
        case csr::uarch_halt_flag:
            return read_uarch_halt_flag();
        case csr::uarch_pc:
            return read_uarch_pc();
        case csr::uarch_ram_length:
            return read_uarch_ram_length();
        default:
            throw std::invalid_argument{"unknown CSR"};
            return 0; // never reached
    }
}

void machine::write_csr(csr csr, uint64_t value) {
    switch (csr) {
        case csr::pc:
            return write_pc(value);
        case csr::fcsr:
            return write_fcsr(value);
        case csr::mcycle:
            return write_mcycle(value);
        case csr::icycleinstret:
            return write_icycleinstret(value);
        case csr::mstatus:
            return write_mstatus(value);
        case csr::mtvec:
            return write_mtvec(value);
        case csr::mscratch:
            return write_mscratch(value);
        case csr::mepc:
            return write_mepc(value);
        case csr::mcause:
            return write_mcause(value);
        case csr::mtval:
            return write_mtval(value);
        case csr::misa:
            return write_misa(value);
        case csr::mie:
            return write_mie(value);
        case csr::mip:
            return write_mip(value);
        case csr::medeleg:
            return write_medeleg(value);
        case csr::mideleg:
            return write_mideleg(value);
        case csr::mcounteren:
            return write_mcounteren(value);
        case csr::menvcfg:
            return write_menvcfg(value);
        case csr::stvec:
            return write_stvec(value);
        case csr::sscratch:
            return write_sscratch(value);
        case csr::sepc:
            return write_sepc(value);
        case csr::scause:
            return write_scause(value);
        case csr::stval:
            return write_stval(value);
        case csr::satp:
            return write_satp(value);
        case csr::scounteren:
            return write_scounteren(value);
        case csr::senvcfg:
            return write_senvcfg(value);
        case csr::ilrsc:
            return write_ilrsc(value);
        case csr::iflags:
            return write_iflags(value);
        case csr::clint_mtimecmp:
            return write_clint_mtimecmp(value);
        case csr::htif_tohost:
            return write_htif_tohost(value);
        case csr::htif_fromhost:
            return write_htif_fromhost(value);
        case csr::htif_ihalt:
            return write_htif_ihalt(value);
        case csr::htif_iconsole:
            return write_htif_iconsole(value);
        case csr::htif_iyield:
            return write_htif_iyield(value);
        case csr::uarch_cycle:
            return write_uarch_cycle(value);
        case csr::uarch_halt_flag:
            return set_uarch_halt_flag();
        case csr::uarch_pc:
            return write_uarch_pc(value);
        case csr::mvendorid:
            [[fallthrough]];
        case csr::marchid:
            [[fallthrough]];
        case csr::mimpid:
            throw std::invalid_argument{"CSR is read-only"};
        case csr::uarch_ram_length:
            throw std::invalid_argument{"CSR is read-only"};
        default:
            throw std::invalid_argument{"unknown CSR"};
    }
}

uint64_t machine::get_csr_address(csr csr) {
    switch (csr) {
        case csr::pc:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::pc);
        case csr::fcsr:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::fcsr);
        case csr::mvendorid:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mvendorid);
        case csr::marchid:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::marchid);
        case csr::mimpid:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mimpid);
        case csr::mcycle:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mcycle);
        case csr::icycleinstret:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::icycleinstret);
        case csr::mstatus:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mstatus);
        case csr::mtvec:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mtvec);
        case csr::mscratch:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mscratch);
        case csr::mepc:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mepc);
        case csr::mcause:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mcause);
        case csr::mtval:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mtval);
        case csr::misa:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::misa);
        case csr::mie:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mie);
        case csr::mip:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mip);
        case csr::medeleg:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::medeleg);
        case csr::mideleg:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mideleg);
        case csr::mcounteren:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::mcounteren);
        case csr::menvcfg:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::menvcfg);
        case csr::stvec:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::stvec);
        case csr::sscratch:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::sscratch);
        case csr::sepc:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::sepc);
        case csr::scause:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::scause);
        case csr::stval:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::stval);
        case csr::satp:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::satp);
        case csr::scounteren:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::scounteren);
        case csr::senvcfg:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::senvcfg);
        case csr::ilrsc:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::ilrsc);
        case csr::iflags:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::iflags);
        case csr::htif_tohost:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::htif_tohost);
        case csr::htif_fromhost:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::htif_fromhost);
        case csr::htif_ihalt:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::htif_ihalt);
        case csr::htif_iconsole:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::htif_iconsole);
        case csr::htif_iyield:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::htif_iyield);
        case csr::clint_mtimecmp:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::clint_mtimecmp);
        case csr::uarch_pc:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::uarch_pc);
        case csr::uarch_cycle:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::uarch_cycle);
        case csr::uarch_halt_flag:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::uarch_halt_flag);
        case csr::uarch_ram_length:
            return shadow_state_get_csr_abs_addr(shadow_state_csr::uarch_ram_length);
        default:
            throw std::invalid_argument{"unknown CSR"};
    }
}

uint8_t machine::read_iflags_PRV(void) const {
    return m_s.iflags.PRV;
}

bool machine::read_iflags_Y(void) const {
    return m_s.iflags.Y;
}

void machine::reset_iflags_Y(void) {
    m_s.iflags.Y = false;
}

void machine::set_iflags_Y(void) {
    m_s.iflags.Y = true;
}

bool machine::read_iflags_X(void) const {
    return m_s.iflags.X;
}

void machine::reset_iflags_X(void) {
    m_s.iflags.X = false;
}

void machine::set_iflags_X(void) {
    m_s.iflags.X = true;
}

bool machine::read_iflags_H(void) const {
    return m_s.iflags.H;
}

void machine::set_iflags_H(void) {
    m_s.iflags.H = true;
}

#if 0 // Unused
static double now(void) {
    using namespace std::chrono;
    return static_cast<double>(duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch()).count()) *
        1.e-6;
}
#endif

void machine::mark_write_tlb_dirty_pages(void) const {
    for (uint64_t i = 0; i < PMA_TLB_SIZE; ++i) {
        const tlb_hot_entry &tlbhe = m_s.tlb.hot[TLB_WRITE][i];
        if (tlbhe.vaddr_page != TLB_INVALID_PAGE) {
            const tlb_cold_entry &tlbce = m_s.tlb.cold[TLB_WRITE][i];
            pma_entry &pma = m_s.pmas[tlbce.pma_index];
            pma.mark_dirty_page(tlbce.paddr_page - pma.get_start());
        }
    }
}

bool machine::verify_dirty_page_maps(void) const {
    // double begin = now();
    static_assert(PMA_PAGE_SIZE == machine_merkle_tree::get_page_size(),
        "PMA and machine_merkle_tree page sizes must match");
    machine_merkle_tree::hasher_type h;
    auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE, std::nothrow_t{});
    if (!scratch) {
        return false;
    }
    bool broken = false;
    // Go over the write TLB and mark as dirty all pages currently there
    mark_write_tlb_dirty_pages();
    // Now go over all memory PMAs verifying that all dirty pages are marked
    for (const auto &pma : m_s.pmas) {
        auto peek = pma.get_peek();
        for (uint64_t page_start_in_range = 0; page_start_in_range < pma.get_length();
             page_start_in_range += PMA_PAGE_SIZE) {
            const uint64_t page_address = pma.get_start() + page_start_in_range;
            if (pma.get_istart_M()) {
                const unsigned char *page_data = nullptr;
                peek(pma, *this, page_start_in_range, &page_data, scratch.get());
                hash_type stored;
                hash_type real;
                m_t.get_page_node_hash(page_address, stored);
                m_t.get_page_node_hash(h, page_data, real);
                const bool marked_dirty = pma.is_page_marked_dirty(page_start_in_range);
                const bool is_dirty = (real != stored);
                if (is_dirty && !marked_dirty) {
                    broken = true;
                    std::cerr << std::setfill('0') << std::setw(8) << std::hex << page_address
                              << " should have been dirty\n";
                    std::cerr << "  expected " << stored << '\n';
                    std::cerr << "  got " << real << '\n';
                    break;
                }
            } else if (pma.get_istart_IO()) {
                if (!pma.is_page_marked_dirty(page_start_in_range)) {
                    broken = true;
                    std::cerr << std::setfill('0') << std::setw(8) << std::hex << page_address
                              << " should have been dirty\n";
                    std::cerr << "  all pages in IO PMAs must be set to dirty\n";
                    break;
                }
            }
        }
    }
    return !broken;
}

static uint64_t get_task_concurrency(uint64_t value) {
    const uint64_t concurrency = value > 0 ? value : std::max(std::thread::hardware_concurrency(), 1U);
    return std::min(concurrency, static_cast<uint64_t>(THREADS_MAX));
}

bool machine::update_merkle_tree(void) const {
    machine_merkle_tree::hasher_type gh;
    // double begin = now();
    static_assert(PMA_PAGE_SIZE == machine_merkle_tree::get_page_size(),
        "PMA and machine_merkle_tree page sizes must match");
    // Go over the write TLB and mark as dirty all pages currently there
    mark_write_tlb_dirty_pages();
    // Now go over all PMAs and updating the Merkle tree
    m_t.begin_update();
    for (const auto &pma : m_pmas) {
        auto peek = pma->get_peek();
        // Each PMA has a number of pages
        auto pages_in_range = (pma->get_length() + PMA_PAGE_SIZE - 1) / PMA_PAGE_SIZE;
        // For each PMA, we launch as many threads (n) as defined on concurrency
        // runtime config or as the hardware supports.
        const uint64_t n = get_task_concurrency(m_r.concurrency.update_merkle_tree);
        // The update_page_node_hash function in the machine_merkle_tree is not thread
        // safe, so we protect it with a mutex
        std::mutex updatex;
        // Each thread is launched as a future, whose value tells if the
        // computation succeeded
        std::vector<std::future<bool>> futures;
        futures.reserve(n);
        for (uint64_t j = 0; j < n; ++j) {
            futures.emplace_back(std::async((n == 1) ? std::launch::deferred : std::launch::async,
                [&](int j) -> bool {
                    auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE, std::nothrow_t{});
                    if (!scratch) {
                        return false;
                    }
                    machine_merkle_tree::hasher_type h;
                    // Thread j is responsible for page i if i % n == j.
                    for (uint64_t i = j; i < pages_in_range; i += n) {
                        const uint64_t page_start_in_range = i * PMA_PAGE_SIZE;
                        const uint64_t page_address = pma->get_start() + page_start_in_range;
                        const unsigned char *page_data = nullptr;
                        // Skip any clean pages
                        if (!pma->is_page_marked_dirty(page_start_in_range)) {
                            continue;
                        }
                        // If the peek failed, or if it returned a page for update but
                        // we failed updating it, the entire process failed
                        if (!peek(*pma, *this, page_start_in_range, &page_data, scratch.get())) {
                            return false;
                        }
                        if (page_data) {
                            const bool is_pristine = std::all_of(page_data, page_data + PMA_PAGE_SIZE,
                                [](unsigned char pp) -> bool { return pp == '\0'; });

                            if (is_pristine) {
                                const std::lock_guard<std::mutex> lock(updatex);
                                if (!m_t.update_page_node_hash(page_address,
                                        machine_merkle_tree::get_pristine_hash(
                                            machine_merkle_tree::get_log2_page_size()))) {
                                    return false;
                                }
                            } else {
                                hash_type hash;
                                m_t.get_page_node_hash(h, page_data, hash);
                                {
                                    const std::lock_guard<std::mutex> lock(updatex);
                                    if (!m_t.update_page_node_hash(page_address, hash)) {
                                        return false;
                                    }
                                }
                            }
                        }
                    }
                    return true;
                },
                j));
        }
        // Check if any thread failed
        bool succeeded = true;
        for (auto &f : futures) {
            succeeded = succeeded && f.get();
        }
        // If so, we also failed
        if (!succeeded) {
            m_t.end_update(gh);
            return false;
        }
        // Otherwise, mark all pages in PMA as clean and move on to next
        pma->mark_pages_clean();
    }
    // std::cerr << "page updates done in " << now()-begin << "s\n";
    // begin = now();
    const bool ret = m_t.end_update(gh);
    // std::cerr << "inner tree updates done in " << now()-begin << "s\n";
    return ret;
}

bool machine::update_merkle_tree_page(uint64_t address) {
    static_assert(PMA_PAGE_SIZE == machine_merkle_tree::get_page_size(),
        "PMA and machine_merkle_tree page sizes must match");
    // Align address to begining of page
    address &= ~(PMA_PAGE_SIZE - 1);
    pma_entry &pma = find_pma_entry(m_pmas, address, sizeof(uint64_t));
    const uint64_t page_start_in_range = address - pma.get_start();
    machine_merkle_tree::hasher_type h;
    auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE, std::nothrow_t{});
    if (!scratch) {
        return false;
    }
    m_t.begin_update();
    const unsigned char *page_data = nullptr;
    auto peek = pma.get_peek();
    if (!peek(pma, *this, page_start_in_range, &page_data, scratch.get())) {
        m_t.end_update(h);
        return false;
    }
    if (page_data) {
        const uint64_t page_address = pma.get_start() + page_start_in_range;
        hash_type hash;
        m_t.get_page_node_hash(h, page_data, hash);
        if (!m_t.update_page_node_hash(page_address, hash)) {
            m_t.end_update(h);
            return false;
        }
    }
    pma.mark_clean_page(page_start_in_range);
    return m_t.end_update(h);
}

const boost::container::static_vector<pma_entry, PMA_MAX> &machine::get_pmas(void) const {
    return m_s.pmas;
}

void machine::dump_pmas(void) const {
    auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE);
    for (const auto &pma : m_pmas) {
        if (pma->get_length() == 0) {
            break;
        }
        std::array<char, 256> filename{};
        (void) snprintf(filename.data(), filename.size(), "%016" PRIx64 "--%016" PRIx64 ".bin", pma->get_start(),
            pma->get_length());
        std::cerr << "writing to " << filename.data() << '\n';
        auto fp = unique_fopen(filename.data(), "wb");
        for (uint64_t page_start_in_range = 0; page_start_in_range < pma->get_length();
             page_start_in_range += PMA_PAGE_SIZE) {
            const unsigned char *page_data = nullptr;
            auto peek = pma->get_peek();
            if (!peek(*pma, *this, page_start_in_range, &page_data, scratch.get())) {
                throw std::runtime_error{"peek failed"};
            } else {
                if (!page_data) {
                    memset(scratch.get(), 0, PMA_PAGE_SIZE);
                    page_data = scratch.get();
                }
                if (fwrite(page_data, 1, PMA_PAGE_SIZE, fp.get()) != PMA_PAGE_SIZE) {
                    throw std::system_error{errno, std::generic_category(),
                        "error writing to '"s + filename.data() + "'"s};
                }
            }
        }
    }
}

void machine::get_root_hash(hash_type &hash) const {
    if (!update_merkle_tree()) {
        throw std::runtime_error{"error updating Merkle tree"};
    }
    m_t.get_root_hash(hash);
}

bool machine::verify_merkle_tree(void) const {
    return m_t.verify_tree();
}

machine_merkle_tree::proof_type machine::get_proof(uint64_t address, int log2_size, skip_merkle_tree_update_t) const {
    static_assert(PMA_PAGE_SIZE == machine_merkle_tree::get_page_size(),
        "PMA and machine_merkle_tree page sizes must match");
    // Check for valid target node size
    if (log2_size > machine_merkle_tree::get_log2_root_size() ||
        log2_size < machine_merkle_tree::get_log2_word_size()) {
        throw std::invalid_argument{"invalid log2_size"};
    }
    // Check target address alignment
    if (address & ((~UINT64_C(0)) >> (64 - log2_size))) {
        throw std::invalid_argument{"address not aligned to log2_size"};
    }
    // If proof concerns range smaller than a page, we may need to rebuild part
    // of the proof from the contents of a page inside some PMA range.
    // PMA range starts and lengths are multiple of the page size, which is a
    // power of 2.
    // The size of the desired range is smaller than the page size, but its
    // size is a power of 2, and it is aligned to its size.
    // Therefore, it is is either entirely inside a PMA range,
    // or entirely outside it.
    if (log2_size < machine_merkle_tree::get_log2_page_size()) {
        const uint64_t length = UINT64_C(1) << log2_size;
        const pma_entry &pma = find_pma_entry(m_pmas, address, length);
        auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE);
        const unsigned char *page_data = nullptr;
        // If the PMA range is empty, we know the desired range is
        // entirely outside of any non-pristine PMA.
        // Therefore, the entire page where it lies is also pristine
        // Otherwise, the entire desired range is inside it.
        if (!pma.get_istart_E()) {
            const uint64_t page_start_in_range = (address - pma.get_start()) & (~(PMA_PAGE_SIZE - 1));
            auto peek = pma.get_peek();
            if (!peek(pma, *this, page_start_in_range, &page_data, scratch.get())) {
                throw std::runtime_error{"PMA peek failed"};
            }
        }
        return m_t.get_proof(address, log2_size, page_data);
        // If proof concerns range bigger than a page, we already have its hash
        // stored in the tree itself
    } else {
        return m_t.get_proof(address, log2_size, nullptr);
    }
}

machine_merkle_tree::proof_type machine::get_proof(uint64_t address, int log2_size) const {
    if (!update_merkle_tree()) {
        throw std::runtime_error{"error updating Merkle tree"};
    }
    return get_proof(address, log2_size, skip_merkle_tree_update);
}

void machine::read_memory(uint64_t address, unsigned char *data, uint64_t length) const {
    if (length == 0) {
        return;
    }
    if (!data) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    const pma_entry &pma = find_pma_entry(m_pmas, address, length);
    if (pma.get_istart_M()) {
        memcpy(data, pma.get_memory().get_host_memory() + (address - pma.get_start()), length);
        return;
    }

    auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE);
    // relative request address inside pma
    uint64_t shift = address - pma.get_start();
    // relative page address inside pma
    constexpr const auto log2_page_size = PMA_constants::PMA_PAGE_SIZE_LOG2;
    uint64_t page_address = (shift >> log2_page_size) << log2_page_size;
    // relative request address inside page
    shift -= page_address;

    const unsigned char *page_data = nullptr;
    auto peek = pma.get_peek();

    while (length != 0) {
        const uint64_t bytes_to_write = std::min(length, PMA_PAGE_SIZE - shift);
        // avoid copying to the intermediate buffer when getting the whole page
        if (bytes_to_write == PMA_PAGE_SIZE) {
            if (!peek(pma, *this, page_address, &page_data, data)) {
                throw std::runtime_error{"peek failed"};
            } else if (!page_data) {
                memset(data, 0, bytes_to_write);
            }
        } else {
            if (!peek(pma, *this, page_address, &page_data, scratch.get())) {
                throw std::runtime_error{"peek failed"};
            } else if (!page_data) {
                memset(data, 0, bytes_to_write);
            } else {
                memcpy(data, page_data + shift, bytes_to_write);
            }
        }

        page_address += PMA_PAGE_SIZE;
        length -= bytes_to_write;
        data += bytes_to_write;
        shift = 0;
    }
}

void machine::write_memory(uint64_t address, const unsigned char *data, size_t length) {
    if (length == 0) {
        return;
    }
    if (!data) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    pma_entry &pma = find_pma_entry(m_pmas, address, length);
    if (!pma.get_istart_M() || pma.get_istart_E()) {
        throw std::invalid_argument{"address range not entirely in memory PMA"};
    }
    constexpr const auto log2_page_size = PMA_constants::PMA_PAGE_SIZE_LOG2;
    uint64_t page_in_range = ((address - pma.get_start()) >> log2_page_size) << log2_page_size;
    constexpr const auto page_size = PMA_constants::PMA_PAGE_SIZE;
    auto npages = (length + page_size - 1) / page_size;
    for (decltype(npages) i = 0; i < npages; ++i) {
        pma.mark_dirty_page(page_in_range);
        page_in_range += page_size;
    }
    memcpy(pma.get_memory().get_host_memory() + (address - pma.get_start()), data, length);
}

void machine::read_virtual_memory(uint64_t vaddr_start, unsigned char *data, uint64_t length) {
    state_access a(*this);
    if (length == 0) {
        return;
    }
    if (!data) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    const uint64_t vaddr_limit = vaddr_start + length;
    const uint64_t vaddr_page_start = vaddr_start & ~(PMA_PAGE_SIZE - 1);                       // align page backward
    const uint64_t vaddr_page_limit = (vaddr_limit + PMA_PAGE_SIZE - 1) & ~(PMA_PAGE_SIZE - 1); // align page forward
    // copy page by page, because we need to perform address translation again for each page
    for (uint64_t vaddr_page = vaddr_page_start; vaddr_page < vaddr_page_limit; vaddr_page += PMA_PAGE_SIZE) {
        uint64_t paddr_page = 0;
        if (!translate_virtual_address<state_access, false>(a, &paddr_page, vaddr_page, PTE_XWR_R_SHIFT)) {
            throw std::invalid_argument{"page fault"};
        }
        uint64_t paddr = paddr_page;
        uint64_t vaddr = vaddr_page;
        uint64_t chunklen = std::min<uint64_t>(PMA_PAGE_SIZE, vaddr_limit - vaddr);
        if (vaddr_page < vaddr_start) {
            const uint64_t off = vaddr_start - vaddr_page;
            paddr += off;
            vaddr += off;
            chunklen -= off;
        }
        const uint64_t chunkoff = vaddr - vaddr_start;
        read_memory(paddr, data + chunkoff, chunklen);
    }
}

void machine::write_virtual_memory(uint64_t vaddr_start, const unsigned char *data, size_t length) {
    state_access a(*this);
    if (length == 0) {
        return;
    }
    if (!data) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    const uint64_t vaddr_limit = vaddr_start + length;
    const uint64_t vaddr_page_start = vaddr_start & ~(PMA_PAGE_SIZE - 1);                       // align page backward
    const uint64_t vaddr_page_limit = (vaddr_limit + PMA_PAGE_SIZE - 1) & ~(PMA_PAGE_SIZE - 1); // align page forward
    // copy page by page, because we need to perform address translation again for each page
    for (uint64_t vaddr_page = vaddr_page_start; vaddr_page < vaddr_page_limit; vaddr_page += PMA_PAGE_SIZE) {
        uint64_t paddr_page = 0;
        // perform address translation using read access mode,
        // so we can write any reachable virtual memory range
        if (!translate_virtual_address<state_access, false>(a, &paddr_page, vaddr_page, PTE_XWR_R_SHIFT)) {
            throw std::invalid_argument{"page fault"};
        }
        uint64_t paddr = paddr_page;
        uint64_t vaddr = vaddr_page;
        uint64_t chunklen = std::min<uint64_t>(PMA_PAGE_SIZE, vaddr_limit - vaddr);
        if (vaddr_page < vaddr_start) {
            const uint64_t off = vaddr_start - vaddr_page;
            paddr += off;
            vaddr += off;
            chunklen -= off;
        }
        const uint64_t chunkoff = vaddr - vaddr_start;
        write_memory(paddr, data + chunkoff, chunklen);
    }
}

uint64_t machine::read_word(uint64_t word_address) const {
    // Make sure address is aligned
    if (word_address & (PMA_WORD_SIZE - 1)) {
        throw std::invalid_argument{"address not aligned"};
    }
    const pma_entry &pma = find_pma_entry<uint64_t>(word_address);
    // ??D We should split peek into peek_word and peek_page
    // for performance. On the other hand, this function
    // will almost never be used, so one wonders if it is worth it...
    auto scratch = unique_calloc<unsigned char>(PMA_PAGE_SIZE);
    const unsigned char *page_data = nullptr;
    const uint64_t page_start_in_range = (word_address - pma.get_start()) & (~(PMA_PAGE_SIZE - 1));
    auto peek = pma.get_peek();
    if (!peek(pma, *this, page_start_in_range, &page_data, scratch.get())) {
        throw std::invalid_argument{"peek failed"};
    }
    // If peek returns a page, read from it
    if (page_data) {
        const uint64_t word_start_in_range = (word_address - pma.get_start()) & (PMA_PAGE_SIZE - 1);
        return aliased_aligned_read<uint64_t>(page_data + word_start_in_range);
        // Otherwise, page is always pristine
    } else {
        return 0;
    }
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
uint64_t machine::read_uarch_x(int i) const {
    return m_uarch.read_x(i);
}

void machine::write_uarch_x(int i, uint64_t val) {
    m_uarch.write_x(i, val);
}

uint64_t machine::read_uarch_pc(void) const {
    return m_uarch.read_pc();
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
void machine::write_uarch_pc(uint64_t val) {
    m_uarch.write_pc(val);
}

uint64_t machine::read_uarch_cycle(void) const {
    return m_uarch.read_cycle();
}

void machine::write_uarch_cycle(uint64_t val) {
    return m_uarch.write_cycle(val);
}

/// \brief Reads the value of the microarchitecture halt flag.
/// \returns The current microarchitecture halt value.
bool machine::read_uarch_halt_flag(void) const {
    return m_uarch.read_halt_flag();
}

/// \brief Sets the value ofthe microarchitecture halt flag.
void machine::set_uarch_halt_flag() {
    m_uarch.set_halt_flag();
}

void machine::reset_uarch_state() {
    m_uarch.reset_state();
}

uint64_t machine::read_uarch_ram_length(void) const {
    return m_uarch.read_ram_length();
}

void machine::verify_access_log(const access_log &log, const machine_runtime_config &r, bool one_based) {
    (void) r;
    // There must be at least one access in log
    if (log.get_accesses().empty()) {
        throw std::invalid_argument{"too few accesses in log"};
    }
    uarch_replay_state_access a(log, log.get_log_type().has_proofs(), one_based);
    uarch_step(a);
    a.finish();
}

machine_config machine::get_default_config(void) {
    return machine_config{};
}

void machine::verify_state_transition(const hash_type &root_hash_before, const access_log &log,
    const hash_type &root_hash_after, const machine_runtime_config &r, bool one_based) {
    (void) r;
    // We need proofs in order to verify the state transition
    if (!log.get_log_type().has_proofs()) {
        throw std::invalid_argument{"log has no proofs"};
    }
    // There must be at least one access in log
    if (log.get_accesses().empty()) {
        throw std::invalid_argument{"too few accesses in log"};
    }
    // It must contain proofs
    if (!log.get_accesses().front().get_proof().has_value()) {
        throw std::invalid_argument{"access has no proof"};
    }
    // Make sure the access log starts from the same root hash as the state
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    if (log.get_accesses().front().get_proof().value().get_root_hash() != root_hash_before) {
        throw std::invalid_argument{"mismatch in root hash before replay"};
    }
    // Verify all intermediate state transitions
    uarch_replay_state_access a(log, true /* verify proofs! */, one_based);
    uarch_step(a);
    a.finish();
    // Make sure the access log ends at the same root hash as the state
    hash_type obtained_root_hash;
    a.get_root_hash(obtained_root_hash);
    if (obtained_root_hash != root_hash_after) {
        throw std::invalid_argument{"mismatch in root hash after replay"};
    }
}

access_log machine::step_uarch(const access_log::type &log_type, bool one_based) {
    if (m_uarch.get_state().ram.get_istart_E()) {
        throw std::runtime_error("microarchitecture RAM is not present");
    }
    hash_type root_hash_before;
    if (log_type.has_proofs()) {
        update_merkle_tree();
        get_root_hash(root_hash_before);
    }
    // Call interpret with a logged state access object
    uarch_record_state_access a(m_uarch.get_state(), *this, log_type);
    a.push_bracket(bracket_type::begin, "step");
    uarch_step(a);
    a.push_bracket(bracket_type::end, "step");
    // Verify access log before returning
    if (log_type.has_proofs()) {
        hash_type root_hash_after;
        update_merkle_tree();
        get_root_hash(root_hash_after);
        verify_state_transition(root_hash_before, *a.get_log(), root_hash_after, m_r, one_based);
    } else {
        verify_access_log(*a.get_log(), m_r, one_based);
    }
    return std::move(*a.get_log());
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
uarch_interpreter_break_reason machine::run_uarch(uint64_t uarch_cycle_end) {
    if (m_uarch.get_state().ram.get_istart_E()) {
        throw std::runtime_error("microarchitecture RAM is not present");
    }
    uarch_state_access a(m_uarch.get_state(), get_state());
    return uarch_interpret(a, uarch_cycle_end);
}

interpreter_break_reason machine::run(uint64_t mcycle_end) {
    if (mcycle_end < read_mcycle()) {
        throw std::invalid_argument{"mcycle is past"};
    }
    state_access a(*this);
    return interpret(a, mcycle_end);
}

} // namespace cartesi
