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

#include "machine.h"

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>

#include <boost/container/static_vector.hpp>
#include <boost/range/adaptor/sliced.hpp>

#include "access-log.h"
#include "bracket-note.h"
#include "clint-factory.h"
#include "dtb.h"
#include "htif-factory.h"
#include "htif.h"
#include "i-device-state-access.h"
#include "interpret.h"
#include "machine-config.h"
#include "machine-memory-range-descr.h"
#include "machine-runtime-config.h"
#include "os.h"
#include "plic-factory.h"
#include "pma-constants.h"
#include "pma-defines.h"
#include "pma.h"
#include "record-state-access.h"
#include "replay-state-access.h"
#include "riscv-constants.h"
#include "send-cmio-response.h"
#include "shadow-pmas-factory.h"
#include "shadow-state-factory.h"
#include "shadow-state.h"
#include "shadow-tlb-factory.h"
#include "shadow-tlb.h"
#include "shadow-uarch-state.h"
#include "state-access.h"
#include "strict-aliasing.h"
#include "translate-virtual-address.h"
#include "uarch-interpret.h"
#include "uarch-record-state-access.h"
#include "uarch-replay-state-access.h"
#include "uarch-reset-state.h"
#include "uarch-state-access.h"
#include "uarch-step.h"
#include "unique-c-ptr.h"
#include "virtio-console.h"
#include "virtio-device.h"
#include "virtio-factory.h"
#include "virtio-net-carrier-slirp.h"
#include "virtio-net-carrier-tuntap.h"
#include "virtio-net.h"
#include "virtio-p9fs.h"

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

// When we pass a RNG seed in a FDT stored in DTB,
// Linux will wipe out its contents as a security measure,
// therefore we need to make DTB writable, otherwise boot will hang.
const pma_entry::flags machine::m_dtb_flags{
    true,                  // R
    true,                  // W
    true,                  // X
    true,                  // IR
    true,                  // IW
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

const pma_entry::flags machine::m_cmio_rx_buffer_flags{
    true,                          // R
    false,                         // W
    false,                         // X
    true,                          // IR
    true,                          // IW
    PMA_ISTART_DID::cmio_rx_buffer // DID
};

const pma_entry::flags machine::m_cmio_tx_buffer_flags{
    true,                          // R
    true,                          // W
    false,                         // X
    true,                          // IR
    true,                          // IW
    PMA_ISTART_DID::cmio_tx_buffer // DID
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

pma_entry machine::make_cmio_rx_buffer_pma_entry(const cmio_config &c) {
    const auto description = "cmio rx buffer memory range"s;
    if (!c.rx_buffer.image_filename.empty()) {
        return make_mmapd_memory_pma_entry(description, PMA_CMIO_RX_BUFFER_START, PMA_CMIO_RX_BUFFER_LENGTH,
            c.rx_buffer.image_filename, c.rx_buffer.shared)
            .set_flags(m_cmio_rx_buffer_flags);
    }
    return make_callocd_memory_pma_entry(description, PMA_CMIO_RX_BUFFER_START, PMA_CMIO_RX_BUFFER_LENGTH)
        .set_flags(m_cmio_rx_buffer_flags);
}

pma_entry machine::make_cmio_tx_buffer_pma_entry(const cmio_config &c) {
    const auto description = "cmio tx buffer memory range"s;
    if (!c.tx_buffer.image_filename.empty()) {
        return make_mmapd_memory_pma_entry(description, PMA_CMIO_TX_BUFFER_START, PMA_CMIO_TX_BUFFER_LENGTH,
            c.tx_buffer.image_filename, c.tx_buffer.shared)
            .set_flags(m_cmio_tx_buffer_flags);
    }
    return make_callocd_memory_pma_entry(description, PMA_CMIO_TX_BUFFER_START, PMA_CMIO_TX_BUFFER_LENGTH)
        .set_flags(m_cmio_tx_buffer_flags);
}

pma_entry &machine::register_pma_entry(pma_entry &&pma) {
    if (decltype(m_s.pmas)::capacity() <= m_s.pmas.size()) {
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
        case PMA_ISTART_DID::cmio_rx_buffer:
        case PMA_ISTART_DID::cmio_tx_buffer:
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

machine::machine(const machine_config &c, const machine_runtime_config &r) : m_c{c}, m_uarch{c.uarch}, m_r{r} {

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

    m_s.soft_yield = r.soft_yield;

    // General purpose registers
    for (int i = 1; i < X_REG_COUNT; i++) {
        write_reg(static_cast<reg>(reg::x0 + i), m_c.processor.x[i]);
    }

    // Floating-point registers
    for (int i = 0; i < F_REG_COUNT; i++) {
        write_reg(static_cast<reg>(reg::f0 + i), m_c.processor.f[i]);
    }

    write_reg(reg::pc, m_c.processor.pc);
    write_reg(reg::fcsr, m_c.processor.fcsr);
    write_reg(reg::mcycle, m_c.processor.mcycle);
    write_reg(reg::icycleinstret, m_c.processor.icycleinstret);
    write_reg(reg::mstatus, m_c.processor.mstatus);
    write_reg(reg::mtvec, m_c.processor.mtvec);
    write_reg(reg::mscratch, m_c.processor.mscratch);
    write_reg(reg::mepc, m_c.processor.mepc);
    write_reg(reg::mcause, m_c.processor.mcause);
    write_reg(reg::mtval, m_c.processor.mtval);
    write_reg(reg::misa, m_c.processor.misa);
    write_reg(reg::mie, m_c.processor.mie);
    write_reg(reg::mip, m_c.processor.mip);
    write_reg(reg::medeleg, m_c.processor.medeleg);
    write_reg(reg::mideleg, m_c.processor.mideleg);
    write_reg(reg::mcounteren, m_c.processor.mcounteren);
    write_reg(reg::menvcfg, m_c.processor.menvcfg);
    write_reg(reg::stvec, m_c.processor.stvec);
    write_reg(reg::sscratch, m_c.processor.sscratch);
    write_reg(reg::sepc, m_c.processor.sepc);
    write_reg(reg::scause, m_c.processor.scause);
    write_reg(reg::stval, m_c.processor.stval);
    write_reg(reg::satp, m_c.processor.satp);
    write_reg(reg::scounteren, m_c.processor.scounteren);
    write_reg(reg::senvcfg, m_c.processor.senvcfg);
    write_reg(reg::ilrsc, m_c.processor.ilrsc);
    write_reg(reg::iflags, m_c.processor.iflags);
    write_reg(reg::iunrep, m_c.processor.iunrep);

    // Register RAM
    if (m_c.ram.image_filename.empty()) {
        register_pma_entry(make_callocd_memory_pma_entry("RAM"s, PMA_RAM_START, m_c.ram.length).set_flags(m_ram_flags));
    } else {
        register_pma_entry(make_callocd_memory_pma_entry("RAM"s, PMA_RAM_START, m_c.ram.length, m_c.ram.image_filename)
                               .set_flags(m_ram_flags));
    }

    // Register DTB
    pma_entry &dtb = register_pma_entry((m_c.dtb.image_filename.empty() ?
            make_callocd_memory_pma_entry("DTB"s, PMA_DTB_START, PMA_DTB_LENGTH) :
            make_callocd_memory_pma_entry("DTB"s, PMA_DTB_START, PMA_DTB_LENGTH, m_c.dtb.image_filename))
                                            .set_flags(m_dtb_flags));

    // Register all flash drives
    int i = 0; // NOLINT(misc-const-correctness)
    for (auto &f : m_c.flash_drive) {
        const std::string flash_description = "flash drive "s + std::to_string(i);
        // Auto detect flash drive start address
        if (f.start == UINT64_C(-1)) {
            f.start = PMA_DRIVE_START + PMA_DRIVE_OFFSET_DEF * i;
        }
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
        i++;
    }

    // Register cmio memory ranges
    register_pma_entry(make_cmio_tx_buffer_pma_entry(m_c.cmio));
    register_pma_entry(make_cmio_rx_buffer_pma_entry(m_c.cmio));

    // Register HTIF device
    register_pma_entry(make_htif_pma_entry(PMA_HTIF_START, PMA_HTIF_LENGTH, &m_r.htif));

    // Copy HTIF state to from config to machine
    write_reg(reg::htif_tohost, m_c.htif.tohost);
    write_reg(reg::htif_fromhost, m_c.htif.fromhost);
    // Only command in halt device is command 0 and it is always available
    const uint64_t htif_ihalt = static_cast<uint64_t>(true) << HTIF_HALT_CMD_HALT;
    write_reg(reg::htif_ihalt, htif_ihalt);
    const uint64_t htif_iconsole = static_cast<uint64_t>(m_c.htif.console_getchar) << HTIF_CONSOLE_CMD_GETCHAR |
        static_cast<uint64_t>(true) << HTIF_CONSOLE_CMD_PUTCHAR;
    write_reg(reg::htif_iconsole, htif_iconsole);
    const uint64_t htif_iyield = static_cast<uint64_t>(m_c.htif.yield_manual) << HTIF_YIELD_CMD_MANUAL |
        static_cast<uint64_t>(m_c.htif.yield_automatic) << HTIF_YIELD_CMD_AUTOMATIC;
    write_reg(reg::htif_iyield, htif_iyield);

    // Register CLINT device
    register_pma_entry(make_clint_pma_entry(PMA_CLINT_START, PMA_CLINT_LENGTH));
    // Copy CLINT state to from config to machine
    write_reg(reg::clint_mtimecmp, m_c.clint.mtimecmp);

    // Register PLIC device
    register_pma_entry(make_plic_pma_entry(PMA_PLIC_START, PMA_PLIC_LENGTH));
    // Copy PLIC state from config to machine
    write_reg(reg::plic_girqpend, m_c.plic.girqpend);
    write_reg(reg::plic_girqsrvd, m_c.plic.girqsrvd);

    // Register TLB device
    register_pma_entry(make_shadow_tlb_pma_entry(PMA_SHADOW_TLB_START, PMA_SHADOW_TLB_LENGTH));

    // Register state shadow device
    register_pma_entry(make_shadow_state_pma_entry(PMA_SHADOW_STATE_START, PMA_SHADOW_STATE_LENGTH));

    // Register pma board shadow device
    register_pma_entry(make_shadow_pmas_pma_entry(PMA_SHADOW_PMAS_START, PMA_SHADOW_PMAS_LENGTH));

    // Initialize VirtIO devices
    if (!m_c.virtio.empty()) {
        // VirtIO devices are disallowed in unreproducible mode
        if (m_c.processor.iunrep == 0) {
            throw std::invalid_argument{"virtio devices are only supported in unreproducible machines"};
        }

        for (const auto &vdev_config_entry : m_c.virtio) {
            std::visit(
                [&](const auto &vdev_config) {
                    using T = std::decay_t<decltype(vdev_config)>;
                    std::string pma_name = "VirtIO device"; // NOLINT(misc-const-correctness): // no, can't be const
                    std::unique_ptr<virtio_device> vdev;
                    if constexpr (std::is_same_v<T, cartesi::virtio_console_config>) {
                        pma_name = "VirtIO Console";
                        vdev = std::make_unique<virtio_console>(m_vdevs.size());
                    } else if constexpr (std::is_same_v<T, cartesi::virtio_p9fs_config>) {
#ifdef HAVE_POSIX_FS
                        pma_name = "VirtIO 9P";
                        vdev = std::make_unique<virtio_p9fs_device>(m_vdevs.size(), vdev_config.tag,
                            vdev_config.host_directory);
#else
                        throw std::invalid_argument("virtio 9p device is unsupported in this platform");
#endif
                    } else if constexpr (std::is_same_v<T, cartesi::virtio_net_user_config>) {
#ifdef HAVE_SLIRP
                        pma_name = "VirtIO Net User";
                        vdev = std::make_unique<virtio_net>(m_vdevs.size(),
                            std::make_unique<virtio_net_carrier_slirp>(vdev_config));
#else
                        throw std::invalid_argument("virtio network user device is unsupported in this platform");

#endif
                    } else if constexpr (std::is_same_v<T, cartesi::virtio_net_tuntap_config>) {
#ifdef HAVE_TUNTAP
                        pma_name = "VirtIO Net TUN/TAP";
                        vdev = std::make_unique<virtio_net>(m_vdevs.size(),
                            std::make_unique<virtio_net_carrier_tuntap>(vdev_config.iface));
#else

                        throw std::invalid_argument("virtio network TUN/TAP device is unsupported in this platform");
#endif
                    } else {
                        throw std::invalid_argument("invalid virtio device configuration");
                    }
                    register_pma_entry(
                        make_virtio_pma_entry(PMA_FIRST_VIRTIO_START + vdev->get_virtio_index() * PMA_VIRTIO_LENGTH,
                            PMA_VIRTIO_LENGTH, pma_name, &virtio_driver, vdev.get()));
                    m_vdevs.push_back(std::move(vdev));
                },
                vdev_config_entry);
        }
    }

    // Initialize DTB
    if (m_c.dtb.image_filename.empty()) {
        // Write the FDT (flattened device tree) into DTB
        dtb_init(m_c, dtb.get_memory().get_host_memory(), PMA_DTB_LENGTH);
    }

    // Add sentinel to PMA vector
    register_pma_entry(make_empty_pma_entry("sentinel"s, 0, 0));

    // Initialize the vector of the pmas used by the merkle tree to compute hashes.
    // First, add the pmas visible to the big machine, except the sentinel
    for (auto &pma : m_s.pmas | sliced(0, m_s.pmas.size() - 1)) {
        m_pmas.push_back(&pma);
    }

    // Second, push uarch pmas that are visible only to the microarchitecture interpreter
    m_pmas.push_back(&m_uarch.get_state().shadow_state);
    m_pmas.push_back(&m_uarch.get_state().ram);

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
    if (m_c.htif.console_getchar || has_virtio_console()) {
        if (m_c.processor.iunrep == 0) {
            throw std::invalid_argument{"TTY stdin is only supported in unreproducible machines"};
        }
        os_open_tty();
    }

    // Initialize memory range descriptions returned by get_memory_ranges method
    for (auto *pma : m_pmas) {
        if (pma->get_length() != 0) {
            m_mrds.push_back(machine_memory_range_descr{pma->get_start(), pma->get_length(), pma->get_description()});
        }
    }
    // Sort it by increasing start address
    std::sort(m_mrds.begin(), m_mrds.end(),
        [](const machine_memory_range_descr &a, const machine_memory_range_descr &b) { return a.start < b.start; });

    // Disable SIGPIPE handler, because this signal can be raised and terminate the emulator process
    // when calling write() on closed file descriptors.
    // This can happen with the stdout console file descriptors or network file descriptors.
    os_disable_sigpipe();
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

void machine::prepare_virtio_devices_select(select_fd_sets *fds, uint64_t *timeout_us) {
    for (auto &vdev : m_vdevs) {
        vdev->prepare_select(fds, timeout_us);
    }
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
bool machine::poll_selected_virtio_devices(int select_ret, select_fd_sets *fds, i_device_state_access *da) {
    bool interrupt_requested = false; // NOLINT(misc-const-correctness)
    for (auto &vdev : m_vdevs) {
        interrupt_requested |= vdev->poll_selected(select_ret, fds, da);
    }
    return interrupt_requested;
}

// NOLINTNEXTLINE(readability-non-const-parameter)
bool machine::poll_virtio_devices(uint64_t *timeout_us, i_device_state_access *da) {
    return os_select_fds(
        [&](select_fd_sets *fds, uint64_t *timeout_us) -> void { prepare_virtio_devices_select(fds, timeout_us); },
        [&](int select_ret, select_fd_sets *fds) -> bool { return poll_selected_virtio_devices(select_ret, fds, da); },
        timeout_us);
}

bool machine::has_virtio_devices() const {
    return !m_vdevs.empty();
}

bool machine::has_virtio_console() const {
    // When present, the console device is guaranteed to be the first VirtIO device,
    // therefore we only need to check the first device.
    return !m_vdevs.empty() && m_vdevs[0]->get_device_id() == VIRTIO_DEVICE_CONSOLE;
}

bool machine::has_htif_console() const {
    return static_cast<bool>(read_reg(reg::htif_iconsole) & (1 << HTIF_CONSOLE_CMD_GETCHAR));
}

/// \brief Returns copy of initialization config.
const machine_config &machine::get_initial_config() const {
    return m_c;
}

/// \brief Returns the machine runtime config.
const machine_runtime_config &machine::get_runtime_config() const {
    return m_r;
}

/// \brief Changes the machine runtime config.
void machine::set_runtime_config(const machine_runtime_config &r) {
    if (r.htif.no_console_putchar != m_r.htif.no_console_putchar) {
        throw std::runtime_error{"cannot change htif runtime configuration"};
    }
    m_r = r;
    m_s.soft_yield = m_r.soft_yield;
}

machine_config machine::get_serialization_config() const {
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error{"cannot serialize configuration of unreproducible machines"};
    }
    // Initialize with copy of original config
    machine_config c = m_c;
    // Copy current processor state to config
    for (int i = 1; i < X_REG_COUNT; ++i) {
        c.processor.x[i] = read_reg(static_cast<reg>(reg::x0 + i));
    }
    for (int i = 0; i < F_REG_COUNT; ++i) {
        c.processor.f[i] = read_reg(static_cast<reg>(reg::f0 + i));
    }
    c.processor.pc = read_reg(reg::pc);
    c.processor.fcsr = read_reg(reg::fcsr);
    c.processor.mvendorid = read_reg(reg::mvendorid);
    c.processor.marchid = read_reg(reg::marchid);
    c.processor.mimpid = read_reg(reg::mimpid);
    c.processor.mcycle = read_reg(reg::mcycle);
    c.processor.icycleinstret = read_reg(reg::icycleinstret);
    c.processor.mstatus = read_reg(reg::mstatus);
    c.processor.mtvec = read_reg(reg::mtvec);
    c.processor.mscratch = read_reg(reg::mscratch);
    c.processor.mepc = read_reg(reg::mepc);
    c.processor.mcause = read_reg(reg::mcause);
    c.processor.mtval = read_reg(reg::mtval);
    c.processor.misa = read_reg(reg::misa);
    c.processor.mie = read_reg(reg::mie);
    c.processor.mip = read_reg(reg::mip);
    c.processor.medeleg = read_reg(reg::medeleg);
    c.processor.mideleg = read_reg(reg::mideleg);
    c.processor.mcounteren = read_reg(reg::mcounteren);
    c.processor.menvcfg = read_reg(reg::menvcfg);
    c.processor.stvec = read_reg(reg::stvec);
    c.processor.sscratch = read_reg(reg::sscratch);
    c.processor.sepc = read_reg(reg::sepc);
    c.processor.scause = read_reg(reg::scause);
    c.processor.stval = read_reg(reg::stval);
    c.processor.satp = read_reg(reg::satp);
    c.processor.scounteren = read_reg(reg::scounteren);
    c.processor.senvcfg = read_reg(reg::senvcfg);
    c.processor.ilrsc = read_reg(reg::ilrsc);
    c.processor.iflags = read_reg(reg::iflags);
    c.processor.iunrep = read_reg(reg::iunrep);
    // Copy current CLINT state to config
    c.clint.mtimecmp = read_reg(reg::clint_mtimecmp);
    // Copy current PLIC state to config
    c.plic.girqpend = read_reg(reg::plic_girqpend);
    c.plic.girqsrvd = read_reg(reg::plic_girqsrvd);
    // Copy current HTIF state to config
    c.htif.tohost = read_reg(reg::htif_tohost);
    c.htif.fromhost = read_reg(reg::htif_fromhost);
    // c.htif.halt = read_reg(reg::htif_ihalt); // hard-coded to true
    c.htif.console_getchar = static_cast<bool>(read_reg(reg::htif_iconsole) & (1 << HTIF_CONSOLE_CMD_GETCHAR));
    c.htif.yield_manual = static_cast<bool>(read_reg(reg::htif_iyield) & (1 << HTIF_YIELD_CMD_MANUAL));
    c.htif.yield_automatic = static_cast<bool>(read_reg(reg::htif_iyield) & (1 << HTIF_YIELD_CMD_AUTOMATIC));
    // Ensure we don't mess with DTB by writing the original bootargs
    // over the potentially modified memory region we serialize
    c.dtb.bootargs.clear();
    // Remove image filenames from serialization
    // (they will be ignored by save and load for security reasons)
    c.dtb.image_filename.clear();
    c.ram.image_filename.clear();
    c.uarch.ram.image_filename.clear();
    c.tlb.image_filename.clear();
    for (auto &f : c.flash_drive) {
        f.image_filename.clear();
    }
    c.cmio.rx_buffer.image_filename.clear();
    c.cmio.tx_buffer.image_filename.clear();
    c.uarch.processor.cycle = read_reg(reg::uarch_cycle);
    c.uarch.processor.halt_flag = (read_reg(reg::uarch_halt_flag) != 0);
    c.uarch.processor.pc = read_reg(reg::uarch_pc);
    for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
        c.uarch.processor.x[i] = read_reg(static_cast<reg>(reg::uarch_x0 + i));
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
        }
        if (page_data == nullptr) {
            memset(scratch.get(), 0, PMA_PAGE_SIZE);
            page_data = scratch.get();
        }
        if (fwrite(page_data, 1, PMA_PAGE_SIZE, fp.get()) != PMA_PAGE_SIZE) {
            throw std::system_error{errno, std::generic_category(), "error writing to '" + name + "'"};
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

pma_entry &machine::find_pma_entry(uint64_t paddr, uint64_t length) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): remove const to reuse code
    return const_cast<pma_entry &>(std::as_const(*this).find_pma_entry(paddr, length));
}

const pma_entry &machine::find_pma_entry(uint64_t paddr, uint64_t length) const {
    return find_pma_entry(m_s.pmas, paddr, length);
}

template <typename CONTAINER>
pma_entry &machine::find_pma_entry(const CONTAINER &pmas, uint64_t paddr, uint64_t length) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): remove const to reuse code
    return const_cast<pma_entry &>(std::as_const(*this).find_pma_entry(pmas, paddr, length));
}

template <typename CONTAINER>
const pma_entry &machine::find_pma_entry(const CONTAINER &pmas, uint64_t paddr, uint64_t length) const {
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
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error{"cannot store PMAs of unreproducible machines"};
    }
    store_memory_pma(find_pma_entry<uint64_t>(PMA_DTB_START), dir);
    store_memory_pma(find_pma_entry<uint64_t>(PMA_RAM_START), dir);
    store_device_pma(*this, find_pma_entry<uint64_t>(PMA_SHADOW_TLB_START), dir);
    // Could iterate over PMAs checking for those with a drive DID
    // but this is easier
    for (const auto &f : c.flash_drive) {
        store_memory_pma(find_pma_entry<uint64_t>(f.start), dir);
    }
    store_memory_pma(find_pma_entry<uint64_t>(PMA_CMIO_RX_BUFFER_START), dir);
    store_memory_pma(find_pma_entry<uint64_t>(PMA_CMIO_TX_BUFFER_START), dir);
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
    if (os_mkdir(dir.c_str(), 0700) != 0) {
        throw std::system_error{errno, std::generic_category(), "error creating directory '"s + dir + "'"s};
    }
    if (!m_r.skip_root_hash_store) {
        if (!update_merkle_tree()) {
            throw std::runtime_error{"error updating Merkle tree"};
        }
        hash_type h;
        m_t.get_root_hash(h);
        store_hash(h, dir);
    }
    auto c = get_serialization_config();
    c.store(dir);
    store_pmas(c, dir);
}

machine::~machine() {
    // Cleanup TTY if console input was enabled
    if (m_c.htif.console_getchar || has_virtio_console()) {
        os_close_tty();
    }
#ifdef DUMP_HIST
    std::ignore = fprintf(stderr, "\nInstruction Histogram:\n");
    for (auto v : m_s.insn_hist) {
        std::ignore = fprintf(stderr, "%12" PRIu64 "  %s\n", v.second, v.first.c_str());
    }
#endif
#if DUMP_COUNTERS
#define TLB_HIT_RATIO(s, a, b) (((double) (s).stats.b) / ((s).stats.a + (s).stats.b))
    std::ignore = fprintf(stderr, "\nMachine Counters:\n");
    std::ignore = fprintf(stderr, "inner loops: %" PRIu64 "\n", m_s.stats.inner_loop);
    std::ignore = fprintf(stderr, "outers loops: %" PRIu64 "\n", m_s.stats.outer_loop);
    std::ignore = fprintf(stderr, "supervisor ints: %" PRIu64 "\n", m_s.stats.sv_int);
    std::ignore = fprintf(stderr, "supervisor ex: %" PRIu64 "\n", m_s.stats.sv_ex);
    std::ignore = fprintf(stderr, "machine ints: %" PRIu64 "\n", m_s.stats.m_int);
    std::ignore = fprintf(stderr, "machine ex: %" PRIu64 "\n", m_s.stats.m_ex);
    std::ignore = fprintf(stderr, "atomic mem ops: %" PRIu64 "\n", m_s.stats.atomic_mop);
    std::ignore = fprintf(stderr, "fence: %" PRIu64 "\n", m_s.stats.fence);
    std::ignore = fprintf(stderr, "fence.i: %" PRIu64 "\n", m_s.stats.fence_i);
    std::ignore = fprintf(stderr, "fence.vma: %" PRIu64 "\n", m_s.stats.fence_vma);
    std::ignore = fprintf(stderr, "max asid: %" PRIu64 "\n", m_s.stats.max_asid);
    std::ignore = fprintf(stderr, "User mode: %" PRIu64 "\n", m_s.stats.priv_level[PRV_U]);
    std::ignore = fprintf(stderr, "Supervisor mode: %" PRIu64 "\n", m_s.stats.priv_level[PRV_S]);
    std::ignore = fprintf(stderr, "Machine mode: %" PRIu64 "\n", m_s.stats.priv_level[PRV_M]);

    std::ignore = fprintf(stderr, "tlb code hit ratio: %.4f\n", TLB_HIT_RATIO(m_s, tlb_cmiss, tlb_chit));
    std::ignore = fprintf(stderr, "tlb read hit ratio: %.4f\n", TLB_HIT_RATIO(m_s, tlb_rmiss, tlb_rhit));
    std::ignore = fprintf(stderr, "tlb write hit ratio: %.4f\n", TLB_HIT_RATIO(m_s, tlb_wmiss, tlb_whit));
    std::ignore = fprintf(stderr, "tlb_chit: %" PRIu64 "\n", m_s.stats.tlb_chit);
    std::ignore = fprintf(stderr, "tlb_cmiss: %" PRIu64 "\n", m_s.stats.tlb_cmiss);
    std::ignore = fprintf(stderr, "tlb_rhit: %" PRIu64 "\n", m_s.stats.tlb_rhit);
    std::ignore = fprintf(stderr, "tlb_rmiss: %" PRIu64 "\n", m_s.stats.tlb_rmiss);
    std::ignore = fprintf(stderr, "tlb_whit: %" PRIu64 "\n", m_s.stats.tlb_whit);
    std::ignore = fprintf(stderr, "tlb_wmiss: %" PRIu64 "\n", m_s.stats.tlb_wmiss);
    std::ignore = fprintf(stderr, "tlb_flush_all: %" PRIu64 "\n", m_s.stats.tlb_flush_all);
    std::ignore = fprintf(stderr, "tlb_flush_read: %" PRIu64 "\n", m_s.stats.tlb_flush_read);
    std::ignore = fprintf(stderr, "tlb_flush_write: %" PRIu64 "\n", m_s.stats.tlb_flush_write);
    std::ignore = fprintf(stderr, "tlb_flush_vaddr: %" PRIu64 "\n", m_s.stats.tlb_flush_vaddr);
    std::ignore = fprintf(stderr, "tlb_flush_satp: %" PRIu64 "\n", m_s.stats.tlb_flush_satp);
    std::ignore = fprintf(stderr, "tlb_flush_mstatus: %" PRIu64 "\n", m_s.stats.tlb_flush_mstatus);
    std::ignore = fprintf(stderr, "tlb_flush_set_priv: %" PRIu64 "\n", m_s.stats.tlb_flush_set_priv);
    std::ignore = fprintf(stderr, "tlb_flush_fence_vma_all: %" PRIu64 "\n", m_s.stats.tlb_flush_fence_vma_all);
    std::ignore = fprintf(stderr, "tlb_flush_fence_vma_asid: %" PRIu64 "\n", m_s.stats.tlb_flush_fence_vma_asid);
    std::ignore = fprintf(stderr, "tlb_flush_fence_vma_vaddr: %" PRIu64 "\n", m_s.stats.tlb_flush_fence_vma_vaddr);
    std::ignore =
        fprintf(stderr, "tlb_flush_fence_vma_asid_vaddr: %" PRIu64 "\n", m_s.stats.tlb_flush_fence_vma_asid_vaddr);
#endif
}

uint64_t machine::read_reg(reg r) const {
    switch (r) {
        case reg::x0:
            return m_s.x[0];
        case reg::x1:
            return m_s.x[1];
        case reg::x2:
            return m_s.x[2];
        case reg::x3:
            return m_s.x[3];
        case reg::x4:
            return m_s.x[4];
        case reg::x5:
            return m_s.x[5];
        case reg::x6:
            return m_s.x[6];
        case reg::x7:
            return m_s.x[7];
        case reg::x8:
            return m_s.x[8];
        case reg::x9:
            return m_s.x[9];
        case reg::x10:
            return m_s.x[10];
        case reg::x11:
            return m_s.x[11];
        case reg::x12:
            return m_s.x[12];
        case reg::x13:
            return m_s.x[13];
        case reg::x14:
            return m_s.x[14];
        case reg::x15:
            return m_s.x[15];
        case reg::x16:
            return m_s.x[16];
        case reg::x17:
            return m_s.x[17];
        case reg::x18:
            return m_s.x[18];
        case reg::x19:
            return m_s.x[19];
        case reg::x20:
            return m_s.x[20];
        case reg::x21:
            return m_s.x[21];
        case reg::x22:
            return m_s.x[22];
        case reg::x23:
            return m_s.x[23];
        case reg::x24:
            return m_s.x[24];
        case reg::x25:
            return m_s.x[25];
        case reg::x26:
            return m_s.x[26];
        case reg::x27:
            return m_s.x[27];
        case reg::x28:
            return m_s.x[28];
        case reg::x29:
            return m_s.x[29];
        case reg::x30:
            return m_s.x[30];
        case reg::x31:
            return m_s.x[31];
        case reg::f0:
            return m_s.f[0];
        case reg::f1:
            return m_s.f[1];
        case reg::f2:
            return m_s.f[2];
        case reg::f3:
            return m_s.f[3];
        case reg::f4:
            return m_s.f[4];
        case reg::f5:
            return m_s.f[5];
        case reg::f6:
            return m_s.f[6];
        case reg::f7:
            return m_s.f[7];
        case reg::f8:
            return m_s.f[8];
        case reg::f9:
            return m_s.f[9];
        case reg::f10:
            return m_s.f[10];
        case reg::f11:
            return m_s.f[11];
        case reg::f12:
            return m_s.f[12];
        case reg::f13:
            return m_s.f[13];
        case reg::f14:
            return m_s.f[14];
        case reg::f15:
            return m_s.f[15];
        case reg::f16:
            return m_s.f[16];
        case reg::f17:
            return m_s.f[17];
        case reg::f18:
            return m_s.f[18];
        case reg::f19:
            return m_s.f[19];
        case reg::f20:
            return m_s.f[20];
        case reg::f21:
            return m_s.f[21];
        case reg::f22:
            return m_s.f[22];
        case reg::f23:
            return m_s.f[23];
        case reg::f24:
            return m_s.f[24];
        case reg::f25:
            return m_s.f[25];
        case reg::f26:
            return m_s.f[26];
        case reg::f27:
            return m_s.f[27];
        case reg::f28:
            return m_s.f[28];
        case reg::f29:
            return m_s.f[29];
        case reg::f30:
            return m_s.f[30];
        case reg::f31:
            return m_s.f[31];
        case reg::pc:
            return m_s.pc;
        case reg::fcsr:
            return m_s.fcsr;
        case reg::mvendorid:
            return MVENDORID_INIT;
        case reg::marchid:
            return MARCHID_INIT;
        case reg::mimpid:
            return MIMPID_INIT;
        case reg::mcycle:
            return m_s.mcycle;
        case reg::icycleinstret:
            return m_s.icycleinstret;
        case reg::mstatus:
            return m_s.mstatus;
        case reg::mtvec:
            return m_s.mtvec;
        case reg::mscratch:
            return m_s.mscratch;
        case reg::mepc:
            return m_s.mepc;
        case reg::mcause:
            return m_s.mcause;
        case reg::mtval:
            return m_s.mtval;
        case reg::misa:
            return m_s.misa;
        case reg::mie:
            return m_s.mie;
        case reg::mip:
            return m_s.mip;
        case reg::medeleg:
            return m_s.medeleg;
        case reg::mideleg:
            return m_s.mideleg;
        case reg::mcounteren:
            return m_s.mcounteren;
        case reg::menvcfg:
            return m_s.menvcfg;
        case reg::stvec:
            return m_s.stvec;
        case reg::sscratch:
            return m_s.sscratch;
        case reg::sepc:
            return m_s.sepc;
        case reg::scause:
            return m_s.scause;
        case reg::stval:
            return m_s.stval;
        case reg::satp:
            return m_s.satp;
        case reg::scounteren:
            return m_s.scounteren;
        case reg::senvcfg:
            return m_s.senvcfg;
        case reg::ilrsc:
            return m_s.ilrsc;
        case reg::iflags:
            return m_s.read_iflags();
        case reg::iunrep:
            return m_s.iunrep;
        case reg::clint_mtimecmp:
            return m_s.clint.mtimecmp;
        case reg::plic_girqpend:
            return m_s.plic.girqpend;
        case reg::plic_girqsrvd:
            return m_s.plic.girqsrvd;
        case reg::htif_tohost:
            return m_s.htif.tohost;
        case reg::htif_fromhost:
            return m_s.htif.fromhost;
        case reg::htif_ihalt:
            return m_s.htif.ihalt;
        case reg::htif_iconsole:
            return m_s.htif.iconsole;
        case reg::htif_iyield:
            return m_s.htif.iyield;
        case reg::uarch_x0:
            return m_uarch.get_state().x[0];
        case reg::uarch_x1:
            return m_uarch.get_state().x[1];
        case reg::uarch_x2:
            return m_uarch.get_state().x[2];
        case reg::uarch_x3:
            return m_uarch.get_state().x[3];
        case reg::uarch_x4:
            return m_uarch.get_state().x[4];
        case reg::uarch_x5:
            return m_uarch.get_state().x[5];
        case reg::uarch_x6:
            return m_uarch.get_state().x[6];
        case reg::uarch_x7:
            return m_uarch.get_state().x[7];
        case reg::uarch_x8:
            return m_uarch.get_state().x[8];
        case reg::uarch_x9:
            return m_uarch.get_state().x[9];
        case reg::uarch_x10:
            return m_uarch.get_state().x[10];
        case reg::uarch_x11:
            return m_uarch.get_state().x[11];
        case reg::uarch_x12:
            return m_uarch.get_state().x[12];
        case reg::uarch_x13:
            return m_uarch.get_state().x[13];
        case reg::uarch_x14:
            return m_uarch.get_state().x[14];
        case reg::uarch_x15:
            return m_uarch.get_state().x[15];
        case reg::uarch_x16:
            return m_uarch.get_state().x[16];
        case reg::uarch_x17:
            return m_uarch.get_state().x[17];
        case reg::uarch_x18:
            return m_uarch.get_state().x[18];
        case reg::uarch_x19:
            return m_uarch.get_state().x[19];
        case reg::uarch_x20:
            return m_uarch.get_state().x[20];
        case reg::uarch_x21:
            return m_uarch.get_state().x[21];
        case reg::uarch_x22:
            return m_uarch.get_state().x[22];
        case reg::uarch_x23:
            return m_uarch.get_state().x[23];
        case reg::uarch_x24:
            return m_uarch.get_state().x[24];
        case reg::uarch_x25:
            return m_uarch.get_state().x[25];
        case reg::uarch_x26:
            return m_uarch.get_state().x[26];
        case reg::uarch_x27:
            return m_uarch.get_state().x[27];
        case reg::uarch_x28:
            return m_uarch.get_state().x[28];
        case reg::uarch_x29:
            return m_uarch.get_state().x[29];
        case reg::uarch_x30:
            return m_uarch.get_state().x[30];
        case reg::uarch_x31:
            return m_uarch.get_state().x[31];
        case reg::uarch_pc:
            return m_uarch.get_state().pc;
        case reg::uarch_cycle:
            return m_uarch.get_state().cycle;
        case reg::uarch_halt_flag:
            return static_cast<uint64_t>(m_uarch.get_state().halt_flag);
        case reg::iflags_prv:
            return m_s.iflags.PRV;
        case reg::iflags_x:
            return static_cast<uint64_t>(m_s.iflags.X);
        case reg::iflags_y:
            return static_cast<uint64_t>(m_s.iflags.Y);
        case reg::iflags_h:
            return static_cast<uint64_t>(m_s.iflags.H);
        case reg::htif_tohost_dev:
            return HTIF_DEV_FIELD(m_s.htif.tohost);
        case reg::htif_tohost_cmd:
            return HTIF_CMD_FIELD(m_s.htif.tohost);
        case reg::htif_tohost_reason:
            return HTIF_REASON_FIELD(m_s.htif.tohost);
        case reg::htif_tohost_data:
            return HTIF_DATA_FIELD(m_s.htif.tohost);
        case reg::htif_fromhost_dev:
            return HTIF_DEV_FIELD(m_s.htif.fromhost);
        case reg::htif_fromhost_cmd:
            return HTIF_CMD_FIELD(m_s.htif.fromhost);
        case reg::htif_fromhost_reason:
            return HTIF_REASON_FIELD(m_s.htif.fromhost);
        case reg::htif_fromhost_data:
            return HTIF_DATA_FIELD(m_s.htif.fromhost);
        default:
            throw std::invalid_argument{"unknown register"};
            return 0; // never reached
    }
}

void machine::write_reg(reg w, uint64_t value) {
    switch (w) {
        case reg::x0:
            throw std::invalid_argument{"register is read-only"};
        case reg::x1:
            m_s.x[1] = value;
            break;
        case reg::x2:
            m_s.x[2] = value;
            break;
        case reg::x3:
            m_s.x[3] = value;
            break;
        case reg::x4:
            m_s.x[4] = value;
            break;
        case reg::x5:
            m_s.x[5] = value;
            break;
        case reg::x6:
            m_s.x[6] = value;
            break;
        case reg::x7:
            m_s.x[7] = value;
            break;
        case reg::x8:
            m_s.x[8] = value;
            break;
        case reg::x9:
            m_s.x[9] = value;
            break;
        case reg::x10:
            m_s.x[10] = value;
            break;
        case reg::x11:
            m_s.x[11] = value;
            break;
        case reg::x12:
            m_s.x[12] = value;
            break;
        case reg::x13:
            m_s.x[13] = value;
            break;
        case reg::x14:
            m_s.x[14] = value;
            break;
        case reg::x15:
            m_s.x[15] = value;
            break;
        case reg::x16:
            m_s.x[16] = value;
            break;
        case reg::x17:
            m_s.x[17] = value;
            break;
        case reg::x18:
            m_s.x[18] = value;
            break;
        case reg::x19:
            m_s.x[19] = value;
            break;
        case reg::x20:
            m_s.x[20] = value;
            break;
        case reg::x21:
            m_s.x[21] = value;
            break;
        case reg::x22:
            m_s.x[22] = value;
            break;
        case reg::x23:
            m_s.x[23] = value;
            break;
        case reg::x24:
            m_s.x[24] = value;
            break;
        case reg::x25:
            m_s.x[25] = value;
            break;
        case reg::x26:
            m_s.x[26] = value;
            break;
        case reg::x27:
            m_s.x[27] = value;
            break;
        case reg::x28:
            m_s.x[28] = value;
            break;
        case reg::x29:
            m_s.x[29] = value;
            break;
        case reg::x30:
            m_s.x[30] = value;
            break;
        case reg::x31:
            m_s.x[31] = value;
            break;
        case reg::f0:
            m_s.f[0] = value;
            break;
        case reg::f1:
            m_s.f[1] = value;
            break;
        case reg::f2:
            m_s.f[2] = value;
            break;
        case reg::f3:
            m_s.f[3] = value;
            break;
        case reg::f4:
            m_s.f[4] = value;
            break;
        case reg::f5:
            m_s.f[5] = value;
            break;
        case reg::f6:
            m_s.f[6] = value;
            break;
        case reg::f7:
            m_s.f[7] = value;
            break;
        case reg::f8:
            m_s.f[8] = value;
            break;
        case reg::f9:
            m_s.f[9] = value;
            break;
        case reg::f10:
            m_s.f[10] = value;
            break;
        case reg::f11:
            m_s.f[11] = value;
            break;
        case reg::f12:
            m_s.f[12] = value;
            break;
        case reg::f13:
            m_s.f[13] = value;
            break;
        case reg::f14:
            m_s.f[14] = value;
            break;
        case reg::f15:
            m_s.f[15] = value;
            break;
        case reg::f16:
            m_s.f[16] = value;
            break;
        case reg::f17:
            m_s.f[17] = value;
            break;
        case reg::f18:
            m_s.f[18] = value;
            break;
        case reg::f19:
            m_s.f[19] = value;
            break;
        case reg::f20:
            m_s.f[20] = value;
            break;
        case reg::f21:
            m_s.f[21] = value;
            break;
        case reg::f22:
            m_s.f[22] = value;
            break;
        case reg::f23:
            m_s.f[23] = value;
            break;
        case reg::f24:
            m_s.f[24] = value;
            break;
        case reg::f25:
            m_s.f[25] = value;
            break;
        case reg::f26:
            m_s.f[26] = value;
            break;
        case reg::f27:
            m_s.f[27] = value;
            break;
        case reg::f28:
            m_s.f[28] = value;
            break;
        case reg::f29:
            m_s.f[29] = value;
            break;
        case reg::f30:
            m_s.f[30] = value;
            break;
        case reg::f31:
            m_s.f[31] = value;
            break;
        case reg::pc:
            m_s.pc = value;
            break;
        case reg::fcsr:
            m_s.fcsr = value;
            break;
        case reg::mvendorid:
            throw std::invalid_argument{"register is read-only"};
        case reg::marchid:
            [[fallthrough]];
        case reg::mimpid:
            throw std::invalid_argument{"register is read-only"};
        case reg::mcycle:
            m_s.mcycle = value;
            break;
        case reg::icycleinstret:
            m_s.icycleinstret = value;
            break;
        case reg::mstatus:
            m_s.mstatus = value;
            break;
        case reg::mtvec:
            m_s.mtvec = value;
            break;
        case reg::mscratch:
            m_s.mscratch = value;
            break;
        case reg::mepc:
            m_s.mepc = value;
            break;
        case reg::mcause:
            m_s.mcause = value;
            break;
        case reg::mtval:
            m_s.mtval = value;
            break;
        case reg::misa:
            m_s.misa = value;
            break;
        case reg::mie:
            m_s.mie = value;
            break;
        case reg::mip:
            m_s.mip = value;
            break;
        case reg::medeleg:
            m_s.medeleg = value;
            break;
        case reg::mideleg:
            m_s.mideleg = value;
            break;
        case reg::mcounteren:
            m_s.mcounteren = value;
            break;
        case reg::menvcfg:
            m_s.menvcfg = value;
            break;
        case reg::stvec:
            m_s.stvec = value;
            break;
        case reg::sscratch:
            m_s.sscratch = value;
            break;
        case reg::sepc:
            m_s.sepc = value;
            break;
        case reg::scause:
            m_s.scause = value;
            break;
        case reg::stval:
            m_s.stval = value;
            break;
        case reg::satp:
            m_s.satp = value;
            break;
        case reg::scounteren:
            m_s.scounteren = value;
            break;
        case reg::senvcfg:
            m_s.senvcfg = value;
            break;
        case reg::ilrsc:
            m_s.ilrsc = value;
            break;
        case reg::iflags:
            m_s.write_iflags(value);
            break;
        case reg::iunrep:
            m_s.iunrep = value;
            break;
        case reg::clint_mtimecmp:
            m_s.clint.mtimecmp = value;
            break;
        case reg::plic_girqpend:
            m_s.plic.girqpend = value;
            break;
        case reg::plic_girqsrvd:
            m_s.plic.girqsrvd = value;
            break;
        case reg::htif_tohost:
            m_s.htif.tohost = value;
            break;
        case reg::htif_fromhost:
            m_s.htif.fromhost = value;
            break;
        case reg::htif_ihalt:
            m_s.htif.ihalt = value;
            break;
        case reg::htif_iconsole:
            m_s.htif.iconsole = value;
            break;
        case reg::htif_iyield:
            m_s.htif.iyield = value;
            break;
        case reg::uarch_x0:
            throw std::invalid_argument{"register is read-only"};
        case reg::uarch_x1:
            m_uarch.get_state().x[1] = value;
            break;
        case reg::uarch_x2:
            m_uarch.get_state().x[2] = value;
            break;
        case reg::uarch_x3:
            m_uarch.get_state().x[3] = value;
            break;
        case reg::uarch_x4:
            m_uarch.get_state().x[4] = value;
            break;
        case reg::uarch_x5:
            m_uarch.get_state().x[5] = value;
            break;
        case reg::uarch_x6:
            m_uarch.get_state().x[6] = value;
            break;
        case reg::uarch_x7:
            m_uarch.get_state().x[7] = value;
            break;
        case reg::uarch_x8:
            m_uarch.get_state().x[8] = value;
            break;
        case reg::uarch_x9:
            m_uarch.get_state().x[9] = value;
            break;
        case reg::uarch_x10:
            m_uarch.get_state().x[10] = value;
            break;
        case reg::uarch_x11:
            m_uarch.get_state().x[11] = value;
            break;
        case reg::uarch_x12:
            m_uarch.get_state().x[12] = value;
            break;
        case reg::uarch_x13:
            m_uarch.get_state().x[13] = value;
            break;
        case reg::uarch_x14:
            m_uarch.get_state().x[14] = value;
            break;
        case reg::uarch_x15:
            m_uarch.get_state().x[15] = value;
            break;
        case reg::uarch_x16:
            m_uarch.get_state().x[16] = value;
            break;
        case reg::uarch_x17:
            m_uarch.get_state().x[17] = value;
            break;
        case reg::uarch_x18:
            m_uarch.get_state().x[18] = value;
            break;
        case reg::uarch_x19:
            m_uarch.get_state().x[19] = value;
            break;
        case reg::uarch_x20:
            m_uarch.get_state().x[20] = value;
            break;
        case reg::uarch_x21:
            m_uarch.get_state().x[21] = value;
            break;
        case reg::uarch_x22:
            m_uarch.get_state().x[22] = value;
            break;
        case reg::uarch_x23:
            m_uarch.get_state().x[23] = value;
            break;
        case reg::uarch_x24:
            m_uarch.get_state().x[24] = value;
            break;
        case reg::uarch_x25:
            m_uarch.get_state().x[25] = value;
            break;
        case reg::uarch_x26:
            m_uarch.get_state().x[26] = value;
            break;
        case reg::uarch_x27:
            m_uarch.get_state().x[27] = value;
            break;
        case reg::uarch_x28:
            m_uarch.get_state().x[28] = value;
            break;
        case reg::uarch_x29:
            m_uarch.get_state().x[29] = value;
            break;
        case reg::uarch_x30:
            m_uarch.get_state().x[30] = value;
            break;
        case reg::uarch_x31:
            m_uarch.get_state().x[31] = value;
            break;
        case reg::uarch_pc:
            m_uarch.get_state().pc = value;
            break;
        case reg::uarch_cycle:
            m_uarch.get_state().cycle = value;
            break;
        case reg::uarch_halt_flag:
            m_uarch.get_state().halt_flag = static_cast<bool>(value);
            break;
        case reg::iflags_prv:
            m_s.iflags.PRV = static_cast<uint8_t>(value);
            break;
        case reg::iflags_x:
            m_s.iflags.X = static_cast<bool>(value);
            break;
        case reg::iflags_y:
            m_s.iflags.Y = static_cast<bool>(value);
            break;
        case reg::iflags_h:
            m_s.iflags.H = static_cast<bool>(value);
            break;
        case reg::htif_tohost_dev:
            m_s.htif.tohost = HTIF_REPLACE_DEV(m_s.htif.tohost, value);
            break;
        case reg::htif_tohost_cmd:
            m_s.htif.tohost = HTIF_REPLACE_CMD(m_s.htif.tohost, value);
            break;
        case reg::htif_tohost_reason:
            m_s.htif.tohost = HTIF_REPLACE_REASON(m_s.htif.tohost, value);
            break;
        case reg::htif_tohost_data:
            m_s.htif.tohost = HTIF_REPLACE_DATA(m_s.htif.tohost, value);
            break;
        case reg::htif_fromhost_dev:
            m_s.htif.fromhost = HTIF_REPLACE_DEV(m_s.htif.fromhost, value);
            break;
        case reg::htif_fromhost_cmd:
            m_s.htif.fromhost = HTIF_REPLACE_CMD(m_s.htif.fromhost, value);
            break;
        case reg::htif_fromhost_reason:
            m_s.htif.fromhost = HTIF_REPLACE_REASON(m_s.htif.fromhost, value);
            break;
        case reg::htif_fromhost_data:
            m_s.htif.fromhost = HTIF_REPLACE_DATA(m_s.htif.fromhost, value);
            break;
        default:
            throw std::invalid_argument{"unknown register"};
    }
}

uint64_t machine::get_reg_address(reg r) {
    switch (r) {
        case reg::x0:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x0);
        case reg::x1:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x1);
        case reg::x2:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x2);
        case reg::x3:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x3);
        case reg::x4:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x4);
        case reg::x5:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x5);
        case reg::x6:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x6);
        case reg::x7:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x7);
        case reg::x8:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x8);
        case reg::x9:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x9);
        case reg::x10:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x10);
        case reg::x11:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x11);
        case reg::x12:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x12);
        case reg::x13:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x13);
        case reg::x14:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x14);
        case reg::x15:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x15);
        case reg::x16:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x16);
        case reg::x17:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x17);
        case reg::x18:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x18);
        case reg::x19:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x19);
        case reg::x20:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x20);
        case reg::x21:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x21);
        case reg::x22:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x22);
        case reg::x23:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x23);
        case reg::x24:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x24);
        case reg::x25:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x25);
        case reg::x26:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x26);
        case reg::x27:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x27);
        case reg::x28:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x28);
        case reg::x29:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x29);
        case reg::x30:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x30);
        case reg::x31:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::x31);
        case reg::f0:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f0);
        case reg::f1:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f1);
        case reg::f2:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f2);
        case reg::f3:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f3);
        case reg::f4:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f4);
        case reg::f5:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f5);
        case reg::f6:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f6);
        case reg::f7:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f7);
        case reg::f8:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f8);
        case reg::f9:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f9);
        case reg::f10:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f10);
        case reg::f11:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f11);
        case reg::f12:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f12);
        case reg::f13:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f13);
        case reg::f14:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f14);
        case reg::f15:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f15);
        case reg::f16:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f16);
        case reg::f17:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f17);
        case reg::f18:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f18);
        case reg::f19:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f19);
        case reg::f20:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f20);
        case reg::f21:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f21);
        case reg::f22:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f22);
        case reg::f23:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f23);
        case reg::f24:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f24);
        case reg::f25:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f25);
        case reg::f26:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f26);
        case reg::f27:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f27);
        case reg::f28:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f28);
        case reg::f29:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f29);
        case reg::f30:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f30);
        case reg::f31:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::f31);
        case reg::pc:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::pc);
        case reg::fcsr:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::fcsr);
        case reg::mvendorid:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mvendorid);
        case reg::marchid:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::marchid);
        case reg::mimpid:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mimpid);
        case reg::mcycle:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mcycle);
        case reg::icycleinstret:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::icycleinstret);
        case reg::mstatus:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mstatus);
        case reg::mtvec:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mtvec);
        case reg::mscratch:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mscratch);
        case reg::mepc:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mepc);
        case reg::mcause:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mcause);
        case reg::mtval:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mtval);
        case reg::misa:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::misa);
        case reg::mie:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mie);
        case reg::mip:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mip);
        case reg::medeleg:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::medeleg);
        case reg::mideleg:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mideleg);
        case reg::mcounteren:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::mcounteren);
        case reg::menvcfg:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::menvcfg);
        case reg::stvec:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::stvec);
        case reg::sscratch:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::sscratch);
        case reg::sepc:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::sepc);
        case reg::scause:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::scause);
        case reg::stval:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::stval);
        case reg::satp:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::satp);
        case reg::scounteren:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::scounteren);
        case reg::senvcfg:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::senvcfg);
        case reg::ilrsc:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::ilrsc);
        case reg::iflags:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::iflags);
        case reg::iunrep:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::iunrep);
        case reg::htif_tohost:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::htif_tohost);
        case reg::htif_fromhost:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::htif_fromhost);
        case reg::htif_ihalt:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::htif_ihalt);
        case reg::htif_iconsole:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::htif_iconsole);
        case reg::htif_iyield:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::htif_iyield);
        case reg::clint_mtimecmp:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::clint_mtimecmp);
        case reg::plic_girqpend:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::plic_girqpend);
        case reg::plic_girqsrvd:
            return shadow_state_get_reg_abs_addr(shadow_state_reg::plic_girqsrvd);
        case reg::uarch_x0:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x0);
        case reg::uarch_x1:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x1);
        case reg::uarch_x2:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x2);
        case reg::uarch_x3:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x3);
        case reg::uarch_x4:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x4);
        case reg::uarch_x5:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x5);
        case reg::uarch_x6:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x6);
        case reg::uarch_x7:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x7);
        case reg::uarch_x8:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x8);
        case reg::uarch_x9:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x9);
        case reg::uarch_x10:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x10);
        case reg::uarch_x11:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x11);
        case reg::uarch_x12:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x12);
        case reg::uarch_x13:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x13);
        case reg::uarch_x14:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x14);
        case reg::uarch_x15:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x15);
        case reg::uarch_x16:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x16);
        case reg::uarch_x17:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x17);
        case reg::uarch_x18:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x18);
        case reg::uarch_x19:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x19);
        case reg::uarch_x20:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x20);
        case reg::uarch_x21:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x21);
        case reg::uarch_x22:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x22);
        case reg::uarch_x23:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x23);
        case reg::uarch_x24:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x24);
        case reg::uarch_x25:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x25);
        case reg::uarch_x26:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x26);
        case reg::uarch_x27:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x27);
        case reg::uarch_x28:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x28);
        case reg::uarch_x29:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x29);
        case reg::uarch_x30:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x30);
        case reg::uarch_x31:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::x31);
        case reg::uarch_pc:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::pc);
        case reg::uarch_cycle:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::cycle);
        case reg::uarch_halt_flag:
            return shadow_uarch_state_get_reg_abs_addr(shadow_uarch_state_reg::halt_flag);
        default:
            throw std::invalid_argument{"unknown register"};
    }
}

void machine::mark_write_tlb_dirty_pages() const {
    for (uint64_t i = 0; i < PMA_TLB_SIZE; ++i) {
        const tlb_hot_entry &tlbhe = m_s.tlb.hot[TLB_WRITE][i];
        if (tlbhe.vaddr_page != TLB_INVALID_PAGE) {
            const tlb_cold_entry &tlbce = m_s.tlb.cold[TLB_WRITE][i];
            if (tlbce.pma_index >= m_s.pmas.size()) {
                throw std::runtime_error{"could not mark dirty page for a TLB entry: TLB is corrupt"};
            }
            pma_entry &pma = m_s.pmas[tlbce.pma_index];
            if (!pma.contains(tlbce.paddr_page, PMA_PAGE_SIZE)) {
                throw std::runtime_error{"could not mark dirty page for a TLB entry: TLB is corrupt"};
            }
            pma.mark_dirty_page(tlbce.paddr_page - pma.get_start());
        }
    }
}

bool machine::verify_dirty_page_maps() const {
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
    const uint64_t concurrency = value > 0 ? value : std::max(os_get_concurrency(), UINT64_C(1));
    return std::min(concurrency, static_cast<uint64_t>(THREADS_MAX));
}

bool machine::update_merkle_tree() const {
    machine_merkle_tree::hasher_type gh;
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
        const bool succeeded = os_parallel_for(n, [&](int j, const parallel_for_mutex &mutex) -> bool {
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
                if (page_data != nullptr) {
                    const bool is_pristine = std::all_of(page_data, page_data + PMA_PAGE_SIZE,
                        [](unsigned char pp) -> bool { return pp == '\0'; });

                    if (is_pristine) {
                        // The update_page_node_hash function in the machine_merkle_tree is not thread
                        // safe, so we protect it with a mutex
                        const parallel_for_mutex_guard lock(mutex);
                        if (!m_t.update_page_node_hash(page_address,
                                machine_merkle_tree::get_pristine_hash(machine_merkle_tree::get_log2_page_size()))) {
                            return false;
                        }
                    } else {
                        hash_type hash;
                        m_t.get_page_node_hash(h, page_data, hash);
                        {
                            // The update_page_node_hash function in the machine_merkle_tree is not thread
                            // safe, so we protect it with a mutex
                            const parallel_for_mutex_guard lock(mutex);
                            if (!m_t.update_page_node_hash(page_address, hash)) {
                                return false;
                            }
                        }
                    }
                }
            }
            return true;
        });
        // If any thread failed, we also failed
        if (!succeeded) {
            m_t.end_update(gh);
            return false;
        }
        // Otherwise, mark all pages in PMA as clean and move on to next
        pma->mark_pages_clean();
    }
    const bool ret = m_t.end_update(gh);
    return ret;
}

bool machine::update_merkle_tree_page(uint64_t address) {
    static_assert(PMA_PAGE_SIZE == machine_merkle_tree::get_page_size(),
        "PMA and machine_merkle_tree page sizes must match");
    // Align address to beginning of page
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
    if (page_data != nullptr) {
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

const boost::container::static_vector<pma_entry, PMA_MAX> &machine::get_pmas() const {
    return m_s.pmas;
}

void machine::get_root_hash(hash_type &hash) const {
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error("cannot compute root hash of unreproducible machines");
    }
    if (!update_merkle_tree()) {
        throw std::runtime_error{"error updating Merkle tree"};
    }
    m_t.get_root_hash(hash);
}

bool machine::verify_merkle_tree() const {
    return m_t.verify_tree();
}

machine_merkle_tree::proof_type machine::get_proof(uint64_t address, int log2_size,
    skip_merkle_tree_update_t /*unused*/) const {
    static_assert(PMA_PAGE_SIZE == machine_merkle_tree::get_page_size(),
        "PMA and machine_merkle_tree page sizes must match");
    // Check for valid target node size
    if (log2_size > machine_merkle_tree::get_log2_root_size() ||
        log2_size < machine_merkle_tree::get_log2_word_size()) {
        throw std::invalid_argument{"invalid log2_size"};
    }
    // Check target address alignment
    if ((address & ((~UINT64_C(0)) >> (64 - log2_size))) != 0) {
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
    }
    return m_t.get_proof(address, log2_size, nullptr);
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
    if (data == nullptr) {
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
            }
            if (page_data == nullptr) {
                memset(data, 0, bytes_to_write);
            }
        } else {
            if (!peek(pma, *this, page_address, &page_data, scratch.get())) {
                throw std::runtime_error{"peek failed"};
            }
            if (page_data == nullptr) {
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

void machine::write_memory(uint64_t address, const unsigned char *data, uint64_t length) {
    if (length == 0) {
        return;
    }
    if (data == nullptr) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    pma_entry &pma = find_pma_entry(m_pmas, address, length);
    if (!pma.get_istart_M() || pma.get_istart_E()) {
        throw std::invalid_argument{"address range not entirely in memory PMA"};
    }
    pma.write_memory(address, data, length);
}

void machine::fill_memory(uint64_t address, uint8_t data, uint64_t length) {
    if (length == 0) {
        return;
    }
    pma_entry &pma = find_pma_entry(m_pmas, address, length);
    if (!pma.get_istart_M() || pma.get_istart_E()) {
        throw std::invalid_argument{"address range not entirely in memory PMA"};
    }
    pma.fill_memory(address, data, length);
}

void machine::read_virtual_memory(uint64_t vaddr_start, unsigned char *data, uint64_t length) {
    const state_access a(*this);
    if (length == 0) {
        return;
    }
    if (data == nullptr) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    const uint64_t vaddr_limit = vaddr_start + length;
    const uint64_t vaddr_page_start = vaddr_start & ~(PMA_PAGE_SIZE - 1);                       // align page backward
    const uint64_t vaddr_page_limit = (vaddr_limit + PMA_PAGE_SIZE - 1) & ~(PMA_PAGE_SIZE - 1); // align page forward
    // copy page by page, because we need to perform address translation again for each page
    for (uint64_t vaddr_page = vaddr_page_start; vaddr_page < vaddr_page_limit; vaddr_page += PMA_PAGE_SIZE) {
        uint64_t paddr_page = 0;
        if (!cartesi::translate_virtual_address<state_access, false>(a, &paddr_page, vaddr_page, PTE_XWR_R_SHIFT)) {
            throw std::domain_error{"page fault"};
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

void machine::write_virtual_memory(uint64_t vaddr_start, const unsigned char *data, uint64_t length) {
    const state_access a(*this);
    if (length == 0) {
        return;
    }
    if (data == nullptr) {
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
        if (!cartesi::translate_virtual_address<state_access, false>(a, &paddr_page, vaddr_page, PTE_XWR_R_SHIFT)) {
            throw std::domain_error{"page fault"};
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

uint64_t machine::translate_virtual_address(uint64_t vaddr) {
    const state_access a(*this);
    // perform address translation using read access mode
    uint64_t paddr = 0;
    if (!cartesi::translate_virtual_address<state_access, false>(a, &paddr, vaddr, PTE_XWR_R_SHIFT)) {
        throw std::domain_error{"page fault"};
    }
    return paddr;
}

uint64_t machine::read_word(uint64_t word_address) const {
    // Make sure address is aligned
    if ((word_address & (PMA_WORD_SIZE - 1)) != 0) {
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
    if (page_data != nullptr) {
        const uint64_t word_start_in_range = (word_address - pma.get_start()) & (PMA_PAGE_SIZE - 1);
        return aliased_aligned_read<uint64_t>(page_data + word_start_in_range);
        // Otherwise, page is always pristine
    }
    return 0;
}

void machine::send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) {
    state_access a(*this);
    cartesi::send_cmio_response(a, reason, data, length);
}

access_log machine::log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const access_log::type &log_type) {
    hash_type root_hash_before;
    get_root_hash(root_hash_before);
    // Call send_cmio_response  with the recording state accessor
    record_state_access a(*this, log_type);
    a.push_bracket(bracket_type::begin, "send cmio response");
    cartesi::send_cmio_response(a, reason, data, length);
    a.push_bracket(bracket_type::end, "send cmio response");
    // Verify access log before returning
    hash_type root_hash_after;
    update_merkle_tree();
    get_root_hash(root_hash_after);
    verify_send_cmio_response(reason, data, length, root_hash_before, *a.get_log(), root_hash_after);
    return std::move(*a.get_log());
}

void machine::verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const hash_type &root_hash_before, const access_log &log, const hash_type &root_hash_after) {
    // There must be at least one access in log
    if (log.get_accesses().empty()) {
        throw std::invalid_argument{"too few accesses in log"};
    }

    // Verify all intermediate state transitions
    replay_state_access a(log, root_hash_before);
    cartesi::send_cmio_response(a, reason, data, length);
    a.finish();

    // Make sure the access log ends at the same root hash as the state
    hash_type obtained_root_hash;
    a.get_root_hash(obtained_root_hash);
    if (obtained_root_hash != root_hash_after) {
        throw std::invalid_argument{"mismatch in root hash after replay"};
    }
}

void machine::reset_uarch() {
    uarch_state_access a(m_uarch.get_state(), get_state());
    uarch_reset_state(a);
}

access_log machine::log_reset_uarch(const access_log::type &log_type) {
    hash_type root_hash_before;
    get_root_hash(root_hash_before);
    // Call uarch_reset_state with a uarch_record_state_access object
    uarch_record_state_access a(m_uarch.get_state(), *this, log_type);
    a.push_bracket(bracket_type::begin, "reset uarch state");
    uarch_reset_state(a);
    a.push_bracket(bracket_type::end, "reset uarch state");
    // Verify access log before returning
    hash_type root_hash_after;
    update_merkle_tree();
    get_root_hash(root_hash_after);
    verify_reset_uarch(root_hash_before, *a.get_log(), root_hash_after);
    return std::move(*a.get_log());
}

void machine::verify_reset_uarch(const hash_type &root_hash_before, const access_log &log,
    const hash_type &root_hash_after) {
    // There must be at least one access in log
    if (log.get_accesses().empty()) {
        throw std::invalid_argument{"too few accesses in log"};
    }
    // Verify all intermediate state transitions
    uarch_replay_state_access a(log, root_hash_before);
    uarch_reset_state(a);
    a.finish();
    // Make sure the access log ends at the same root hash as the state
    hash_type obtained_root_hash;
    a.get_root_hash(obtained_root_hash);
    if (obtained_root_hash != root_hash_after) {
        throw std::invalid_argument{"mismatch in root hash after replay"};
    }
}

// Declaration of explicit instantiation in module uarch-step.cpp
extern template UArchStepStatus uarch_step(uarch_record_state_access &a);

access_log machine::log_step_uarch(const access_log::type &log_type) {
    if (m_uarch.get_state().ram.get_istart_E()) {
        throw std::runtime_error("microarchitecture RAM is not present");
    }
    hash_type root_hash_before;
    get_root_hash(root_hash_before);
    // Call interpret with a logged state access object
    uarch_record_state_access a(m_uarch.get_state(), *this, log_type);
    a.push_bracket(bracket_type::begin, "step");
    uarch_step(a);
    a.push_bracket(bracket_type::end, "step");
    // Verify access log before returning
    hash_type root_hash_after;
    get_root_hash(root_hash_after);
    verify_step_uarch(root_hash_before, *a.get_log(), root_hash_after);
    return std::move(*a.get_log());
}

// Declaration of explicit instantiation in module uarch-step.cpp
extern template UArchStepStatus uarch_step(uarch_replay_state_access &a);

void machine::verify_step_uarch(const hash_type &root_hash_before, const access_log &log,
    const hash_type &root_hash_after) {
    // There must be at least one access in log
    if (log.get_accesses().empty()) {
        throw std::invalid_argument{"too few accesses in log"};
    }
    // Verify all intermediate state transitions
    uarch_replay_state_access a(log, root_hash_before);
    uarch_step(a);
    a.finish();
    // Make sure the access log ends at the same root hash as the state
    hash_type obtained_root_hash;
    a.get_root_hash(obtained_root_hash);
    if (obtained_root_hash != root_hash_after) {
        throw std::invalid_argument{"mismatch in root hash after replay"};
    }
}

machine_config machine::get_default_config() {
    return machine_config{};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
uarch_interpreter_break_reason machine::run_uarch(uint64_t uarch_cycle_end) {
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error("microarchitecture cannot be used with unreproducible machines");
    }
    if (m_uarch.get_state().ram.get_istart_E()) {
        throw std::runtime_error("microarchitecture RAM is not present");
    }
    uarch_state_access a(m_uarch.get_state(), get_state());
    return uarch_interpret(a, uarch_cycle_end);
}

interpreter_break_reason machine::run(uint64_t mcycle_end) {
    if (mcycle_end < read_reg(reg::mcycle)) {
        throw std::invalid_argument{"mcycle is past"};
    }
    const state_access a(*this);
    return interpret(a, mcycle_end);
}

} // namespace cartesi
