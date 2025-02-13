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
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>

#include <boost/container/static_vector.hpp>

#include "access-log.h"
#include "clint-factory.h"
#include "compiler-defines.h"
#include "device-state-access.h"
#include "dtb.h"
#include "host-addr.h"
#include "htif-factory.h"
#include "htif.h"
#include "i-device-state-access.h"
#include "i-hasher.h"
#include "interpret.h"
#include "is-pristine.h"
#include "machine-config.h"
#include "machine-memory-range-descr.h"
#include "machine-reg.h"
#include "machine-runtime-config.h"
#include "plic-factory.h"
#include "pma-constants.h"
#include "pma-defines.h"
#include "pma.h"
#include "record-send-cmio-state-access.h"
#include "record-step-state-access.h"
#include "replay-send-cmio-state-access.h"
#include "replay-step-state-access.h"
#include "riscv-constants.h"
#include "rtc.h"
#include "send-cmio-response.h"
#include "shadow-pmas-factory.h"
#include "shadow-pmas.h"
#include "shadow-state-factory.h"
#include "shadow-state.h"
#include "shadow-tlb-factory.h"
#include "shadow-tlb.h"
#include "shadow-uarch-state-factory.h"
#include "shadow-uarch-state.h"
#include "state-access.h"
#include "strict-aliasing.h"
#include "tlb.h"
#include "translate-virtual-address.h"
#include "uarch-config.h"
#include "uarch-constants.h"
#include "uarch-interpret.h"
#include "uarch-pristine-state-hash.h"
#include "uarch-pristine.h"
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

const pma_entry::flags machine::m_ram_flags{.R = true,
    .W = true,
    .X = true,
    .IR = true,
    .IW = true,
    .DID = PMA_ISTART_DID::memory};

// When we pass a RNG seed in a FDT stored in DTB,
// Linux will wipe out its contents as a security measure,
// therefore we need to make DTB writable, otherwise boot will hang.
const pma_entry::flags machine::m_dtb_flags{.R = true,
    .W = true,
    .X = true,
    .IR = true,
    .IW = true,
    .DID = PMA_ISTART_DID::memory};

const pma_entry::flags machine::m_flash_drive_flags{.R = true,
    .W = true,
    .X = false,
    .IR = true,
    .IW = true,
    .DID = PMA_ISTART_DID::flash_drive};

const pma_entry::flags machine::m_cmio_rx_buffer_flags{.R = true,
    .W = false,
    .X = false,
    .IR = true,
    .IW = true,
    .DID = PMA_ISTART_DID::cmio_rx_buffer};

const pma_entry::flags machine::m_cmio_tx_buffer_flags{.R = true,
    .W = true,
    .X = false,
    .IR = true,
    .IW = true,
    .DID = PMA_ISTART_DID::cmio_tx_buffer};

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
        case PMA_ISTART_DID::memory:
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
            if (pma.get_length() == 0 || DID_is_protected(curr)) {
                throw std::invalid_argument{"attempt to replace a protected range "s + pma.get_description()};
            }
            // replace range preserving original flags
            pma = make_memory_range_pma_entry(pma.get_description(), range).set_flags(pma.get_flags());
            return;
        }
    }
    throw std::invalid_argument{"attempt to replace inexistent memory range"};
}

void machine::init_tlb() {
    for (auto set_index : {TLB_CODE, TLB_READ, TLB_WRITE}) {
        for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
            write_tlb(set_index, slot_index, TLB_INVALID_PAGE, host_addr{}, TLB_INVALID_PMA_INDEX);
        }
    }
}

void machine::init_tlb(const shadow_tlb_state &shadow_tlb) {
    for (auto set_index : {TLB_CODE, TLB_READ, TLB_WRITE}) {
        for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
            const auto vaddr_page = shadow_tlb[set_index][slot_index].vaddr_page;
            const auto vp_offset = shadow_tlb[set_index][slot_index].vp_offset;
            const auto pma_index = shadow_tlb[set_index][slot_index].pma_index;
            check_shadow_tlb(set_index, slot_index, vaddr_page, vp_offset, pma_index, "stored TLB is corrupt: "s);
            write_shadow_tlb(set_index, slot_index, vaddr_page, vp_offset, pma_index);
        }
    }
}

void machine::init_uarch(const uarch_config &config) {
    using reg = machine_reg;
    write_reg(reg::uarch_pc, config.processor.pc);
    write_reg(reg::uarch_cycle, config.processor.cycle);
    write_reg(reg::uarch_halt_flag, config.processor.halt_flag);
    // General purpose registers
    for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
        write_reg(machine_reg_enum(reg::uarch_x0, i), config.processor.x[i]);
    }
    // Register shadow state
    m_us.shadow_state = make_shadow_uarch_state_pma_entry(PMA_SHADOW_UARCH_STATE_START, PMA_SHADOW_UARCH_STATE_LENGTH);
    // Register RAM
    constexpr auto ram_description = "uarch RAM";
    if (!config.ram.image_filename.empty()) {
        // Load RAM image from file
        m_us.ram = make_callocd_memory_pma_entry(ram_description, PMA_UARCH_RAM_START, UARCH_RAM_LENGTH,
            config.ram.image_filename)
                       .set_flags(m_ram_flags);
    } else {
        // Load embedded pristine RAM image
        m_us.ram = make_callocd_memory_pma_entry(ram_description, PMA_UARCH_RAM_START, PMA_UARCH_RAM_LENGTH)
                       .set_flags(m_ram_flags);
        if (uarch_pristine_ram_len > m_us.ram.get_length()) {
            throw std::runtime_error("embedded uarch RAM image does not fit in uarch ram PMA");
        }
        memcpy(m_us.ram.get_memory().get_host_memory(), uarch_pristine_ram, uarch_pristine_ram_len);
    }
}

// ??D It is best to leave the std::move() on r because it may one day be necessary!
// NOLINTNEXTLINE(hicpp-move-const-arg,performance-move-const-arg)
machine::machine(machine_config c, machine_runtime_config r) : m_c{std::move(c)}, m_r{std::move(r)} {

    init_uarch(m_c.uarch);

    if (m_c.processor.marchid == UINT64_C(-1)) {
        m_c.processor.marchid = MARCHID_INIT;
    }

    if (m_c.processor.marchid != MARCHID_INIT && !m_r.skip_version_check) {
        throw std::invalid_argument{"marchid mismatch, emulator version is incompatible"};
    }

    if (m_c.processor.mvendorid == UINT64_C(-1)) {
        m_c.processor.mvendorid = MVENDORID_INIT;
    }

    if (m_c.processor.mvendorid != MVENDORID_INIT && !m_r.skip_version_check) {
        throw std::invalid_argument{"mvendorid mismatch, emulator version is incompatible"};
    }

    if (m_c.processor.mimpid == UINT64_C(-1)) {
        m_c.processor.mimpid = MIMPID_INIT;
    }

    if (m_c.processor.mimpid != MIMPID_INIT && !m_r.skip_version_check) {
        throw std::invalid_argument{"mimpid mismatch, emulator version is incompatible"};
    }

    m_s.soft_yield = m_r.soft_yield;

    // General purpose registers
    for (int i = 1; i < X_REG_COUNT; i++) {
        write_reg(machine_reg_enum(reg::x0, i), m_c.processor.x[i]);
    }

    // Floating-point registers
    for (int i = 0; i < F_REG_COUNT; i++) {
        write_reg(machine_reg_enum(reg::f0, i), m_c.processor.f[i]);
    }

    // Named registers
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
    write_reg(reg::iprv, m_c.processor.iprv);
    write_reg(reg::iflags_X, m_c.processor.iflags_X);
    write_reg(reg::iflags_Y, m_c.processor.iflags_Y);
    write_reg(reg::iflags_H, m_c.processor.iflags_H);
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
            auto fp = make_unique_fopen(f.image_filename.c_str(), "rb");
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
    register_pma_entry(make_htif_pma_entry(PMA_HTIF_START, PMA_HTIF_LENGTH));

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

    // Register memory range that holds shadow PMA state, keep pointer to populate later
    shadow_pmas_state *shadow_pmas = nullptr;
    {
        auto shadow_pmas_pma_entry = make_shadow_pmas_pma_entry(PMA_SHADOW_PMAS_START, PMA_SHADOW_PMAS_LENGTH);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        shadow_pmas = reinterpret_cast<shadow_pmas_state *>(shadow_pmas_pma_entry.get_memory().get_host_memory());
        register_pma_entry(std::move(shadow_pmas_pma_entry));
    }

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
                        make_virtio_pma_entry(PMA_FIRST_VIRTIO_START + (vdev->get_virtio_index() * PMA_VIRTIO_LENGTH),
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

    // Last, add empty sentinels until we reach capacity (need at least one sentinel)
    register_pma_entry(make_empty_pma_entry("sentinel"s, 0, 0));
    // NOLINTNEXTLINE(readability-static-accessed-through-instance)
    if (m_s.pmas.capacity() != PMA_MAX) {
        throw std::logic_error{"PMAs array must be able to hold PMA_MAX entries"};
    }
    while (m_s.pmas.size() < PMA_MAX) {
        register_pma_entry(make_empty_pma_entry("sentinel"s, 0, 0));
    }

    // Populate shadow PMAs
    populate_shadow_pmas_state(m_s.pmas, shadow_pmas);

    // Initialize TLB device.
    // This must be done after all PMA entries are already registered, so we can lookup page addresses
    if (!m_c.tlb.image_filename.empty()) {
        auto shadow_tlb = make_unique_mmap<shadow_tlb_state>(m_c.tlb.image_filename.c_str(), 1, false /* not shared */);
        init_tlb(*shadow_tlb);
    } else {
        init_tlb();
    }

    // Initialize TTY if console input is enabled
    if (m_c.htif.console_getchar || has_virtio_console()) {
        if (m_c.processor.iunrep == 0) {
            throw std::invalid_argument{"TTY stdin is only supported in unreproducible machines"};
        }
        os_open_tty();
    }
    os_silence_putchar(m_r.htif.no_console_putchar);

    // Disable SIGPIPE handler, because this signal can be raised and terminate the emulator process
    // when calling write() on closed file descriptors.
    // This can happen with the stdout console file descriptors or network file descriptors.
    os_disable_sigpipe();

    // Include machine PMAs in set considered by the Merkle tree.
    for (auto &pma : m_s.pmas) {
        if (!pma.get_istart_E()) {
            m_merkle_pmas.push_back(&pma);
        }
    }
    m_merkle_pmas.push_back(&m_us.shadow_state);
    m_merkle_pmas.push_back(&m_us.ram);
    // Last, add sentinel PMA
    m_merkle_pmas.push_back(&m_s.empty_pma);

    // Initialize memory range descriptions returned by get_memory_ranges method
    for (const auto *pma : m_merkle_pmas) {
        if (pma->get_length() != 0) {
            m_mrds.push_back(machine_memory_range_descr{.start = pma->get_start(),
                .length = pma->get_length(),
                .description = pma->get_description()});
        }
    }
    // Sort it by increasing start address
    std::sort(m_mrds.begin(), m_mrds.end(),
        [](const machine_memory_range_descr &a, const machine_memory_range_descr &b) { return a.start < b.start; });
}

static void load_hash(const std::string &dir, machine::hash_type &h) {
    auto name = dir + "/hash";
    auto fp = make_unique_fopen(name.c_str(), "rb");
    if (fread(h.data(), 1, h.size(), fp.get()) != h.size()) {
        throw std::runtime_error{"error reading from '" + name + "'"};
    }
}

// ??D It is best to leave the std::move() on r because it may one day be necessary!
// NOLINTNEXTLINE(hicpp-move-const-arg,performance-move-const-arg)
machine::machine(const std::string &dir, machine_runtime_config r) : machine{machine_config::load(dir), std::move(r)} {
    if (m_r.skip_root_hash_check) {
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
void machine::set_runtime_config(machine_runtime_config r) {
    m_r = std::move(r); // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
    m_s.soft_yield = m_r.soft_yield;
    os_silence_putchar(m_r.htif.no_console_putchar);
}

machine_config machine::get_serialization_config() const {
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error{"cannot serialize configuration of unreproducible machines"};
    }
    // Initialize with copy of original config
    machine_config c = m_c;
    // Copy current processor state to config
    for (int i = 1; i < X_REG_COUNT; ++i) {
        c.processor.x[i] = read_reg(machine_reg_enum(reg::x0, i));
    }
    for (int i = 0; i < F_REG_COUNT; ++i) {
        c.processor.f[i] = read_reg(machine_reg_enum(reg::f0, i));
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
    c.processor.iprv = read_reg(reg::iprv);
    c.processor.iflags_X = read_reg(reg::iflags_X);
    c.processor.iflags_Y = read_reg(reg::iflags_Y);
    c.processor.iflags_H = read_reg(reg::iflags_H);
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
    c.uarch.processor.halt_flag = read_reg(reg::uarch_halt_flag);
    c.uarch.processor.pc = read_reg(reg::uarch_pc);
    for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
        c.uarch.processor.x[i] = read_reg(machine_reg_enum(reg::uarch_x0, i));
    }
    return c;
}

static void store_device_pma(const machine &m, const pma_entry &pma, const std::string &dir) {
    if (!pma.get_istart_IO()) {
        throw std::runtime_error{"attempt to save non-device PMA"};
    }
    auto scratch = make_unique_calloc<unsigned char>(PMA_PAGE_SIZE); // will throw if it fails
    auto name = machine_config::get_image_filename(dir, pma.get_start(), pma.get_length());
    auto fp = make_unique_fopen(name.c_str(), "wb");
    for (uint64_t page_start_in_range = 0; page_start_in_range < pma.get_length();
        page_start_in_range += PMA_PAGE_SIZE) {
        const unsigned char *page_data = nullptr;
        auto peek = pma.get_peek();
        if (!peek(pma, m, page_start_in_range, PMA_PAGE_SIZE, &page_data, scratch.get())) {
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
    auto fp = make_unique_fopen(name.c_str(), "wb");
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

uint64_t machine::get_paddr(host_addr haddr, uint64_t pma_index) const {
    return static_cast<uint64_t>(haddr + get_hp_offset(pma_index));
}

host_addr machine::get_host_addr(uint64_t paddr, uint64_t pma_index) const {
    return host_addr{paddr} - get_hp_offset(pma_index);
}

void machine::mark_dirty_page(uint64_t paddr, uint64_t pma_index) {
    auto &pma = m_s.pmas[static_cast<int>(pma_index)];
    pma.mark_dirty_page(paddr - pma.get_start());
}

void machine::mark_dirty_page(host_addr haddr, uint64_t pma_index) {
    auto paddr = get_paddr(haddr, pma_index);
    mark_dirty_page(paddr, pma_index);
}

uint64_t machine::read_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what reg) const {
    switch (reg) {
        case shadow_tlb_what::vaddr_page:
            return m_s.tlb.hot[set_index][slot_index].vaddr_page;
        case shadow_tlb_what::vp_offset: {
            const auto vaddr_page = m_s.tlb.hot[set_index][slot_index].vaddr_page;
            if (vaddr_page != TLB_INVALID_PAGE) {
                const auto vh_offset = m_s.tlb.hot[set_index][slot_index].vh_offset;
                const auto haddr_page = vaddr_page + vh_offset;
                const auto pma_index = m_s.tlb.cold[set_index][slot_index].pma_index;
                return get_paddr(haddr_page, pma_index) - vaddr_page;
            }
            return 0;
        }
        case shadow_tlb_what::pma_index:
            return m_s.tlb.cold[set_index][slot_index].pma_index;
        case shadow_tlb_what::zero_padding_:
            return 0;
        default:
            throw std::domain_error{"unknown shadow TLB register"};
    }
}

void machine::check_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
    uint64_t pma_index, const std::string &prefix) const {
    if (set_index > TLB_LAST_) {
        throw std::domain_error{prefix + "TLB set index is out of range"s};
    }
    if (slot_index >= TLB_SET_SIZE) {
        throw std::domain_error{prefix + "TLB slot index is out of range"s};
    }
    if (vaddr_page != TLB_INVALID_PAGE) {
        if (pma_index >= m_s.pmas.size()) {
            throw std::domain_error{prefix + "pma_index is out of range"s};
        }
        const auto &pma = m_s.pmas[pma_index];
        if (pma.get_length() == 0 || !pma.get_istart_M()) {
            throw std::invalid_argument{prefix + "pma_index does not point to memory range"s};
        }
        if ((vaddr_page & PAGE_OFFSET_MASK) != 0) {
            throw std::invalid_argument{prefix + "vaddr_page is not aligned"s};
        }
        const auto paddr_page = vaddr_page + vp_offset;
        if ((paddr_page & PAGE_OFFSET_MASK) != 0) {
            throw std::invalid_argument{prefix + "vp_offset is not aligned"s};
        }
        const auto pma_end = pma.get_start() + (pma.get_length() - PMA_PAGE_SIZE);
        if (paddr_page < pma.get_start() || paddr_page > pma_end) {
            throw std::invalid_argument{prefix + "vp_offset is inconsistent with pma_index"s};
        }
    } else if (pma_index != TLB_INVALID_PMA_INDEX || vp_offset != 0) {
        throw std::domain_error{prefix + "inconsistent empty TLB slot"};
    }
}

void machine::write_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, host_addr vh_offset,
    uint64_t pma_index) {
    m_s.tlb.hot[set_index][slot_index].vaddr_page = vaddr_page;
    m_s.tlb.hot[set_index][slot_index].vh_offset = vh_offset;
    m_s.tlb.cold[set_index][slot_index].pma_index = pma_index;
}

void machine::write_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, uint64_t vp_offset,
    uint64_t pma_index) {
    if (vaddr_page != TLB_INVALID_PAGE) {
        auto paddr_page = vaddr_page + vp_offset;
        const auto vh_offset = get_host_addr(paddr_page, pma_index) - vaddr_page;
        write_tlb(set_index, slot_index, vaddr_page, vh_offset, pma_index);
    } else {
        write_tlb(set_index, slot_index, TLB_INVALID_PAGE, host_addr{0}, TLB_INVALID_PMA_INDEX);
    }
}

host_addr machine::get_hp_offset(uint64_t pma_index) const {
    if (pma_index >= m_s.pmas.size()) {
        throw std::domain_error{"PMA index is out of range (" + std::to_string(pma_index) + ")"};
    }
    const auto &pma = m_s.pmas[static_cast<int>(pma_index)];
    if (!pma.get_istart_M()) {
        throw std::domain_error{"PMA is not memory (" + pma.get_description() + ")"};
    }
    auto haddr = cast_ptr_to_host_addr(pma.get_memory().get_host_memory());
    auto paddr = pma.get_start();
    return paddr - haddr;
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
    return t; // NOLINT(bugprone-return-const-ref-from-parameter)
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
    if (!m_us.ram.get_istart_E()) {
        store_memory_pma(m_us.ram, dir);
    }
}

static void store_hash(const machine::hash_type &h, const std::string &dir) {
    auto name = dir + "/hash";
    auto fp = make_unique_fopen(name.c_str(), "wb");
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

void machine::dump_insn_hist() {
#ifdef DUMP_INSN_HIST
    D_PRINTF("\nInstruction Histogram:\n", "");
    for (const auto &[key, val] : m_counters) {
        if (key.starts_with("insn.")) {
            D_PRINTF("%s: %" PRIu64 "\n", key.c_str(), val);
        }
    }
#endif
}

void machine::dump_stats() {
#if DUMP_STATS
    const auto hr = [](uint64_t a, uint64_t b) {
        // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
        return static_cast<double>(b) / (a + b);
    };

    D_PRINTF("\nMachine Counters:\n", "");
    D_PRINTF("inner loops: %" PRIu64 "\n", m_counters["stats.inner_loop"]);
    D_PRINTF("outers loops: %" PRIu64 "\n", m_counters["stats.outer_loop"]);
    D_PRINTF("supervisor ints: %" PRIu64 "\n", m_counters["stats.sv_int"]);
    D_PRINTF("supervisor ex: %" PRIu64 "\n", m_counters["stats.sv_ex"]);
    D_PRINTF("machine ints: %" PRIu64 "\n", m_counters["stats.m_int"]);
    D_PRINTF("machine ex: %" PRIu64 "\n", m_counters["stats.m_ex"]);
    D_PRINTF("atomic mem ops: %" PRIu64 "\n", m_counters["stats.atomic_mop"]);
    D_PRINTF("fence: %" PRIu64 "\n", m_counters["stats.fence"]);
    D_PRINTF("fence.i: %" PRIu64 "\n", m_counters["stats.fence_i"]);
    D_PRINTF("fence.vma: %" PRIu64 "\n", m_counters["stats.fence_vma"]);
    D_PRINTF("max asid: %" PRIu64 "\n", m_counters["stats.max_asid"]);
    D_PRINTF("User mode: %" PRIu64 "\n", m_counters["stats.prv.U"]);
    D_PRINTF("Supervisor mode: %" PRIu64 "\n", m_counters["stats.prv.S"]);
    D_PRINTF("Machine mode: %" PRIu64 "\n", m_counters["stats.prv.M"]);
    D_PRINTF("tlb code hit ratio: %.4f\n", hr(m_counters["stats.tlb.cmiss"], m_counters["stats.tlb.chit"]));
    D_PRINTF("tlb read hit ratio: %.4f\n", hr(m_counters["stats.tlb.rmiss"], m_counters["stats.tlb.rhit"]));
    D_PRINTF("tlb write hit ratio: %.4f\n", hr(m_counters["stats.tlb.wmiss"], m_counters["stats.tlb.whit"]));
    D_PRINTF("tlb.chit: %" PRIu64 "\n", m_counters["stats.tlb.chit"]);
    D_PRINTF("tlb.cmiss: %" PRIu64 "\n", m_counters["stats.tlb.cmiss"]);
    D_PRINTF("tlb.rhit: %" PRIu64 "\n", m_counters["stats.tlb.rhit"]);
    D_PRINTF("tlb.rmiss: %" PRIu64 "\n", m_counters["stats.tlb.rmiss"]);
    D_PRINTF("tlb.whit: %" PRIu64 "\n", m_counters["stats.tlb.whit"]);
    D_PRINTF("tlb.wmiss: %" PRIu64 "\n", m_counters["stats.tlb.wmiss"]);
    D_PRINTF("tlb.flush_all: %" PRIu64 "\n", m_counters["stats.tlb.flush_all"]);
    D_PRINTF("tlb.flush_read: %" PRIu64 "\n", m_counters["stats.tlb.flush_read"]);
    D_PRINTF("tlb.flush_write: %" PRIu64 "\n", m_counters["stats.tlb.flush_write"]);
    D_PRINTF("tlb.flush_vaddr: %" PRIu64 "\n", m_counters["stats.tlb.flush_vaddr"]);
    D_PRINTF("tlb.flush_satp: %" PRIu64 "\n", m_counters["stats.tlb.flush_satp"]);
    D_PRINTF("tlb.flush_mstatus: %" PRIu64 "\n", m_counters["stats.tlb.flush_mstatus"]);
    D_PRINTF("tlb.flush_set_prv: %" PRIu64 "\n", m_counters["stats.tlb.flush_set_prv"]);
    D_PRINTF("tlb.flush_fence_vma_all: %" PRIu64 "\n", m_counters["stats.tlb.flush_fence_vma_all"]);
    D_PRINTF("tlb.flush_fence_vma_asid: %" PRIu64 "\n", m_counters["stats.tlb.flush_fence_vma_asid"]);
    D_PRINTF("tlb.flush_fence_vma_vaddr: %" PRIu64 "\n", m_counters["stats.tlb.flush_fence_vma_vaddr"]);
    D_PRINTF("tlb.flush_fence_vma_asid_vaddr: %" PRIu64 "\n", m_counters["stats.tlb.flush_fence_vma_asid_vaddr"]);
#undef TLB_HIT_RATIO
#endif
}

machine::~machine() {
    // Cleanup TTY if console input was enabled
    if (m_c.htif.console_getchar || has_virtio_console()) {
        os_close_tty();
    }
    dump_insn_hist();
    dump_stats();
}

uint64_t machine::read_reg(reg r) const {
    using reg = machine_reg;
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
        case reg::iprv:
            return m_s.iprv;
        case reg::iflags_X:
            return m_s.iflags.X;
        case reg::iflags_Y:
            return m_s.iflags.Y;
        case reg::iflags_H:
            return m_s.iflags.H;
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
            return m_us.x[0];
        case reg::uarch_x1:
            return m_us.x[1];
        case reg::uarch_x2:
            return m_us.x[2];
        case reg::uarch_x3:
            return m_us.x[3];
        case reg::uarch_x4:
            return m_us.x[4];
        case reg::uarch_x5:
            return m_us.x[5];
        case reg::uarch_x6:
            return m_us.x[6];
        case reg::uarch_x7:
            return m_us.x[7];
        case reg::uarch_x8:
            return m_us.x[8];
        case reg::uarch_x9:
            return m_us.x[9];
        case reg::uarch_x10:
            return m_us.x[10];
        case reg::uarch_x11:
            return m_us.x[11];
        case reg::uarch_x12:
            return m_us.x[12];
        case reg::uarch_x13:
            return m_us.x[13];
        case reg::uarch_x14:
            return m_us.x[14];
        case reg::uarch_x15:
            return m_us.x[15];
        case reg::uarch_x16:
            return m_us.x[16];
        case reg::uarch_x17:
            return m_us.x[17];
        case reg::uarch_x18:
            return m_us.x[18];
        case reg::uarch_x19:
            return m_us.x[19];
        case reg::uarch_x20:
            return m_us.x[20];
        case reg::uarch_x21:
            return m_us.x[21];
        case reg::uarch_x22:
            return m_us.x[22];
        case reg::uarch_x23:
            return m_us.x[23];
        case reg::uarch_x24:
            return m_us.x[24];
        case reg::uarch_x25:
            return m_us.x[25];
        case reg::uarch_x26:
            return m_us.x[26];
        case reg::uarch_x27:
            return m_us.x[27];
        case reg::uarch_x28:
            return m_us.x[28];
        case reg::uarch_x29:
            return m_us.x[29];
        case reg::uarch_x30:
            return m_us.x[30];
        case reg::uarch_x31:
            return m_us.x[31];
        case reg::uarch_pc:
            return m_us.pc;
        case reg::uarch_cycle:
            return m_us.cycle;
        case reg::uarch_halt_flag:
            return m_us.halt_flag;
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
        case reg::iprv:
            m_s.iprv = value;
            break;
        case reg::iflags_X:
            m_s.iflags.X = value;
            break;
        case reg::iflags_Y:
            m_s.iflags.Y = value;
            break;
        case reg::iflags_H:
            m_s.iflags.H = value;
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
            m_us.x[1] = value;
            break;
        case reg::uarch_x2:
            m_us.x[2] = value;
            break;
        case reg::uarch_x3:
            m_us.x[3] = value;
            break;
        case reg::uarch_x4:
            m_us.x[4] = value;
            break;
        case reg::uarch_x5:
            m_us.x[5] = value;
            break;
        case reg::uarch_x6:
            m_us.x[6] = value;
            break;
        case reg::uarch_x7:
            m_us.x[7] = value;
            break;
        case reg::uarch_x8:
            m_us.x[8] = value;
            break;
        case reg::uarch_x9:
            m_us.x[9] = value;
            break;
        case reg::uarch_x10:
            m_us.x[10] = value;
            break;
        case reg::uarch_x11:
            m_us.x[11] = value;
            break;
        case reg::uarch_x12:
            m_us.x[12] = value;
            break;
        case reg::uarch_x13:
            m_us.x[13] = value;
            break;
        case reg::uarch_x14:
            m_us.x[14] = value;
            break;
        case reg::uarch_x15:
            m_us.x[15] = value;
            break;
        case reg::uarch_x16:
            m_us.x[16] = value;
            break;
        case reg::uarch_x17:
            m_us.x[17] = value;
            break;
        case reg::uarch_x18:
            m_us.x[18] = value;
            break;
        case reg::uarch_x19:
            m_us.x[19] = value;
            break;
        case reg::uarch_x20:
            m_us.x[20] = value;
            break;
        case reg::uarch_x21:
            m_us.x[21] = value;
            break;
        case reg::uarch_x22:
            m_us.x[22] = value;
            break;
        case reg::uarch_x23:
            m_us.x[23] = value;
            break;
        case reg::uarch_x24:
            m_us.x[24] = value;
            break;
        case reg::uarch_x25:
            m_us.x[25] = value;
            break;
        case reg::uarch_x26:
            m_us.x[26] = value;
            break;
        case reg::uarch_x27:
            m_us.x[27] = value;
            break;
        case reg::uarch_x28:
            m_us.x[28] = value;
            break;
        case reg::uarch_x29:
            m_us.x[29] = value;
            break;
        case reg::uarch_x30:
            m_us.x[30] = value;
            break;
        case reg::uarch_x31:
            m_us.x[31] = value;
            break;
        case reg::uarch_pc:
            m_us.pc = value;
            break;
        case reg::uarch_cycle:
            m_us.cycle = value;
            break;
        case reg::uarch_halt_flag:
            m_us.halt_flag = value;
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
    if (machine_reg_address(r) >= machine_reg_address(reg::uarch_first_) &&
        machine_reg_address(r) <= machine_reg_address(reg::uarch_last_)) {
        return machine_reg_address(r);
    }
    if (machine_reg_address(r) >= machine_reg_address(reg::first_) &&
        machine_reg_address(r) <= machine_reg_address(reg::last_)) {
        return machine_reg_address(r);
    }
    throw std::domain_error{"invalid register"};
}

void machine::mark_write_tlb_dirty_pages() const {
    auto &hot_set = m_s.tlb.hot[TLB_WRITE];
    auto &cold_set = m_s.tlb.cold[TLB_WRITE];
    for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
        const auto &hot_slot = hot_set[slot_index];
        if (hot_slot.vaddr_page != TLB_INVALID_PAGE) {
            auto haddr_page = hot_slot.vaddr_page + hot_slot.vh_offset;
            const auto &cold_slot = cold_set[slot_index];
            if (cold_slot.pma_index >= m_s.pmas.size()) {
                throw std::runtime_error{"could not mark dirty page for a TLB entry: TLB is corrupt"};
            }
            auto paddr_page = get_paddr(haddr_page, cold_slot.pma_index);
            pma_entry &pma = m_s.pmas[cold_slot.pma_index];
            if (!pma.contains(paddr_page, PMA_PAGE_SIZE)) {
                throw std::runtime_error{"could not mark dirty page for a TLB entry: TLB is corrupt"};
            }
            pma.mark_dirty_page(paddr_page - pma.get_start());
        }
    }
}

bool machine::verify_dirty_page_maps() const {
    static_assert(PMA_PAGE_SIZE == machine_merkle_tree::get_page_size(),
        "PMA and machine_merkle_tree page sizes must match");
    machine_merkle_tree::hasher_type h;
    auto scratch = make_unique_calloc<unsigned char>(PMA_PAGE_SIZE, std::nothrow_t{});
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
                peek(pma, *this, page_start_in_range, PMA_PAGE_SIZE, &page_data, scratch.get());
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
    for (const auto &pma : m_merkle_pmas) {
        auto peek = pma->get_peek();
        // Each PMA has a number of pages
        auto pages_in_range = (pma->get_length() + PMA_PAGE_SIZE - 1) / PMA_PAGE_SIZE;
        // For each PMA, we launch as many threads (n) as defined on concurrency
        // runtime config or as the hardware supports.
        const uint64_t n = get_task_concurrency(m_r.concurrency.update_merkle_tree);
        const bool succeeded = os_parallel_for(n, [&](int j, const parallel_for_mutex &mutex) -> bool {
            auto scratch = make_unique_calloc<unsigned char>(PMA_PAGE_SIZE, std::nothrow_t{});
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
                if (!peek(*pma, *this, page_start_in_range, PMA_PAGE_SIZE, &page_data, scratch.get())) {
                    return false;
                }
                if (page_data != nullptr) {
                    if (is_pristine(page_data, PMA_PAGE_SIZE)) {
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
    pma_entry &pma = find_pma_entry(m_merkle_pmas, address, sizeof(uint64_t));
    const uint64_t page_start_in_range = address - pma.get_start();
    machine_merkle_tree::hasher_type h;
    auto scratch = make_unique_calloc<unsigned char>(PMA_PAGE_SIZE, std::nothrow_t{});
    if (!scratch) {
        return false;
    }
    m_t.begin_update();
    const unsigned char *page_data = nullptr;
    auto peek = pma.get_peek();
    if (!peek(pma, *this, page_start_in_range, PMA_PAGE_SIZE, &page_data, scratch.get())) {
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

machine::hash_type machine::get_merkle_tree_node_hash(uint64_t address, int log2_size,
    skip_merkle_tree_update_t /* unused */) const {
    if (log2_size < 0 || log2_size >= machine_merkle_tree::get_log2_root_size()) {
        throw std::domain_error{"log2_size is out of bounds"};
    }
    if (log2_size >= machine_merkle_tree::get_log2_page_size()) {
        return m_t.get_node_hash(address, log2_size);
    }
    if ((address >> log2_size) << log2_size != address) {
        throw std::domain_error{"address not aligned to log2_size"};
    }
    const auto size = UINT64_C(1) << log2_size;
    auto scratch = make_unique_calloc<unsigned char>(size);
    read_memory(address, scratch.get(), size);
    machine_merkle_tree::hasher_type h;
    machine_merkle_tree::hash_type hash;
    get_merkle_tree_hash(h, scratch.get(), size, machine_merkle_tree::get_word_size(), hash);
    return hash;
}

const char *machine::get_what_name(uint64_t paddr) {
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

machine::hash_type machine::get_merkle_tree_node_hash(uint64_t address, int log2_size) const {
    if (!update_merkle_tree()) {
        throw std::runtime_error{"error updating Merkle tree"};
    }
    return get_merkle_tree_node_hash(address, log2_size, skip_merkle_tree_update);
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
        throw std::domain_error{"address not aligned to log2_size"};
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
        const pma_entry &pma = find_pma_entry(m_merkle_pmas, address, length);
        auto scratch = make_unique_calloc<unsigned char>(PMA_PAGE_SIZE);
        const unsigned char *page_data = nullptr;
        // If the PMA range is empty, we know the desired range is
        // entirely outside of any non-pristine PMA.
        // Therefore, the entire page where it lies is also pristine
        // Otherwise, the entire desired range is inside it.
        if (!pma.get_istart_E()) {
            const uint64_t page_start_in_range = (address - pma.get_start()) & (~(PMA_PAGE_SIZE - 1));
            auto peek = pma.get_peek();
            if (!peek(pma, *this, page_start_in_range, PMA_PAGE_SIZE, &page_data, scratch.get())) {
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

void machine::read_memory(uint64_t paddr, unsigned char *data, uint64_t length) const {
    if (length == 0) {
        return;
    }
    if (data == nullptr) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    // Compute the distance between the initial paddr and the first page boundary
    const uint64_t align_paddr = (paddr & PAGE_OFFSET_MASK) != 0 ? (paddr | PAGE_OFFSET_MASK) + 1 : paddr;
    uint64_t align_length = align_paddr - paddr;
    const uint64_t page_size = PMA_PAGE_SIZE;
    align_length = (align_length == 0) ? page_size : align_length;
    // First peek goes at most to the next page boundary, or up to length
    uint64_t peek_length = std::min(align_length, length);
    // The outer loop finds the PMA for all peeks performed by the inner loop
    // The inner loop peeks at most min(page_size, length) from the PMA per iteration
    // All peeks but the absolute first peek start at a page boundary.
    // That first peek reads at most up to the next page boundary.
    // So the inner loop iterations never cross page boundaries.
    for (;;) {
        const pma_entry &pma = find_pma_entry(m_merkle_pmas, paddr, peek_length);
        const auto peek = pma.get_peek();
        const auto pma_start = pma.get_start();
        const auto pma_empty = pma.get_istart_E();
        const auto pma_length = pma.get_length();
        // If the PMA is empty, the inner loop will break after a single iteration.
        // But it is safe to return pristine data for that one iteration, without even peeking.
        // This is because the inner iteration never reads past a page boundary, and the next
        // non-empty PMA starts at the earliest on the next page boundary after paddr.
        for (;;) {
            const unsigned char *peek_data = nullptr;
            // If non-empty PMA, peek, otherwise leave peek_data as nullptr (i.e. pristine)
            if (!pma_empty && !peek(pma, *this, paddr - pma_start, peek_length, &peek_data, data)) {
                throw std::runtime_error{"peek failed"};
            }
            // If the chunk is pristine, copy zero data to buffer
            if (peek_data == nullptr) {
                memset(data, 0, peek_length);
                // If peek returned pointer to internal buffer, copy to data buffer
            } else if (peek_data != data) {
                memcpy(data, peek_data, peek_length);
            }
            // Otherwise, peek copied data straight into the data buffer
            // If we read everything we wanted to read, we are done
            length -= peek_length;
            if (length == 0) {
                return;
            }
            paddr += peek_length;
            data += peek_length;
            peek_length = std::min(page_size, length);
            // If the PMA was empty, break to check if next read is in another PMA
            if (pma_empty) {
                break;
            }
            // If the next read does not fit in current PMA, break to get the next one
            // There can be no overflow in the condition.
            // Since the PMA is non-empty, (paddr-pma_start) >= 0.
            // Moreover, pma_length >= page_size.
            // Since, peek_length <= page_size, we get (pma_length-peek_length) >= 0.
            if (paddr - pma_start >= pma_length - peek_length) {
                break;
            }
        }
    }
}

void machine::write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
    if (length == 0) {
        return;
    }
    if (data == nullptr) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    pma_entry &pma = find_pma_entry(m_merkle_pmas, paddr, length);
    if (pma.get_istart_IO()) {
        throw std::invalid_argument{"attempted write to device memory range"};
    }
    if (!pma.get_istart_M() || pma.get_istart_E()) {
        throw std::invalid_argument{"address range not entirely in single memory range"};
    }
    if (DID_is_protected(pma.get_istart_DID())) {
        throw std::invalid_argument{"attempt to write to protected memory range"};
    }
    pma.write_memory(paddr, data, length);
}

void machine::fill_memory(uint64_t address, uint8_t data, uint64_t length) {
    if (length == 0) {
        return;
    }
    pma_entry &pma = find_pma_entry(m_merkle_pmas, address, length);
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

uint64_t machine::read_word(uint64_t paddr) const {
    // Make sure address is aligned
    if ((paddr & (sizeof(uint64_t) - 1)) != 0) {
        throw std::domain_error{"attempted misaligned read from word"};
    }
    // Use read_memory
    alignas(sizeof(uint64_t)) std::array<unsigned char, sizeof(uint64_t)> scratch{};
    read_memory(paddr, scratch.data(), scratch.size());
    return aliased_aligned_read<uint64_t>(scratch.data());
}

void machine::write_word(uint64_t paddr, uint64_t val) {
    // Make sure address is aligned
    if ((paddr & (sizeof(uint64_t) - 1)) != 0) {
        throw std::domain_error{"attempted misaligned write to word"};
    }
    // If in shadow, forward to write_reg
    if (paddr >= PMA_SHADOW_STATE_START && paddr - PMA_SHADOW_STATE_START < PMA_SHADOW_STATE_LENGTH) {
        auto reg = shadow_state_get_what(paddr);
        if (reg == shadow_state_what::unknown_) {
            throw std::runtime_error("unhandled write to shadow state");
        }
        write_reg(machine_reg_enum(reg), val);
        return;
    }
    // If in uarch shadow, forward to write_reg
    if (paddr >= PMA_SHADOW_UARCH_STATE_START && paddr - PMA_SHADOW_UARCH_STATE_START < PMA_SHADOW_UARCH_STATE_LENGTH) {
        auto reg = shadow_uarch_state_get_what(paddr);
        if (reg == shadow_uarch_state_what::unknown_) {
            throw std::runtime_error("unhandled write to shadow uarch state");
        }
        write_reg(machine_reg_enum(reg), val);
        return;
    }
    // Otherwise, try the slow path
    auto &pma = find_pma_entry(m_merkle_pmas, paddr, sizeof(uint64_t));
    if (pma.get_istart_E() || !pma.get_istart_M()) {
        std::ostringstream err;
        err << "attempted memory write to " << pma.get_description() << " at address 0x" << std::hex << paddr << "("
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

void machine::send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) {
    const state_access a(*this);
    cartesi::send_cmio_response(a, reason, data, length);
}

access_log machine::log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const access_log::type &log_type) {
    hash_type root_hash_before;
    get_root_hash(root_hash_before);
    access_log log(log_type);
    // Call send_cmio_response  with the recording state accessor
    const record_send_cmio_state_access a(*this, log);
    {
        [[maybe_unused]] auto note = a.make_scoped_note("send_cmio_response");
        cartesi::send_cmio_response(a, reason, data, length);
    }
    // Verify access log before returning
    hash_type root_hash_after;
    update_merkle_tree();
    get_root_hash(root_hash_after);
    verify_send_cmio_response(reason, data, length, root_hash_before, log, root_hash_after);
    return log;
}

void machine::verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const hash_type &root_hash_before, const access_log &log, const hash_type &root_hash_after) {
    replay_send_cmio_state_access::context context(log, root_hash_before);
    // Verify all intermediate state transitions
    replay_send_cmio_state_access a(context);
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
    using reg = machine_reg;
    write_reg(reg::uarch_halt_flag, UARCH_HALT_FLAG_INIT);
    write_reg(reg::uarch_pc, UARCH_PC_INIT);
    write_reg(reg::uarch_cycle, UARCH_CYCLE_INIT);
    // General purpose registers
    for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
        write_reg(machine_reg_enum(reg::uarch_x0, i), UARCH_X_INIT);
    }
    // Load embedded pristine RAM image
    if (uarch_pristine_ram_len > m_us.ram.get_length()) {
        throw std::runtime_error("embedded uarch ram image does not fit in uarch ram pma");
    }
    // Reset RAM to initial state
    m_us.ram.fill_memory(m_us.ram.get_start(), 0, m_us.ram.get_length());
    m_us.ram.write_memory(m_us.ram.get_start(), uarch_pristine_ram, uarch_pristine_ram_len);
}

access_log machine::log_reset_uarch(const access_log::type &log_type) {
    hash_type root_hash_before;
    get_root_hash(root_hash_before);
    // Call uarch_reset_state with a uarch_record_state_access object
    access_log log(log_type);
    uarch_record_state_access a(*this, log);
    {
        [[maybe_unused]] auto note = a.make_scoped_note("reset_uarch_state");
        uarch_reset_state(a);
    }
    // Verify access log before returning
    hash_type root_hash_after;
    update_merkle_tree();
    get_root_hash(root_hash_after);
    verify_reset_uarch(root_hash_before, log, root_hash_after);
    return log;
}

void machine::verify_reset_uarch(const hash_type &root_hash_before, const access_log &log,
    const hash_type &root_hash_after) {
    // Verify all intermediate state transitions
    uarch_replay_state_access::context context{log, root_hash_before};
    uarch_replay_state_access a(context);
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
    if (m_us.ram.get_istart_E()) {
        throw std::runtime_error("microarchitecture RAM is not present");
    }
    hash_type root_hash_before;
    get_root_hash(root_hash_before);
    access_log log(log_type);
    // Call interpret with a logged state access object
    const uarch_record_state_access a(*this, log);
    {
        [[maybe_unused]] auto note = a.make_scoped_note("step");
        uarch_step(a);
    }
    // Verify access log before returning
    hash_type root_hash_after;
    get_root_hash(root_hash_after);
    verify_step_uarch(root_hash_before, log, root_hash_after);
    return log;
}

// Declaration of explicit instantiation in module uarch-step.cpp
extern template UArchStepStatus uarch_step(uarch_replay_state_access &a);

void machine::verify_step_uarch(const hash_type &root_hash_before, const access_log &log,
    const hash_type &root_hash_after) {
    // Verify all intermediate state transitions
    uarch_replay_state_access::context context{log, root_hash_before};
    uarch_replay_state_access a(context);
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
    if (m_us.ram.get_istart_E()) {
        throw std::runtime_error("microarchitecture RAM is not present");
    }
    const uarch_state_access a(*this);
    return uarch_interpret(a, uarch_cycle_end);
}

interpreter_break_reason machine::log_step(uint64_t mcycle_count, const std::string &filename) {
    if (!update_merkle_tree()) {
        throw std::runtime_error{"error updating Merkle tree"};
    }
    // Ensure that the microarchitecture is reset
    auto current_uarch_state_hash =
        get_merkle_tree_node_hash(PMA_SHADOW_UARCH_STATE_START, UARCH_STATE_LOG2_SIZE, skip_merkle_tree_update);
    if (current_uarch_state_hash != get_uarch_pristine_state_hash()) {
        throw std::runtime_error{"microarchitecture is not reset"};
    }
    hash_type root_hash_before;
    get_root_hash(root_hash_before);
    record_step_state_access::context context(filename);
    record_step_state_access a(context, *this);
    uint64_t mcycle_end{};
    if (__builtin_add_overflow(a.read_mcycle(), mcycle_count, &mcycle_end)) {
        mcycle_end = UINT64_MAX;
    }
    auto break_reason = interpret(a, mcycle_end);
    a.finish();
    hash_type root_hash_after;
    get_root_hash(root_hash_after);
    verify_step(root_hash_before, filename, mcycle_count, root_hash_after);
    return break_reason;
}

interpreter_break_reason machine::verify_step(const hash_type &root_hash_before, const std::string &filename,
    uint64_t mcycle_count, const hash_type &root_hash_after) {
    auto data_length = os_get_file_length(filename.c_str(), "step log file");
    auto data = make_unique_mmap<unsigned char>(filename.c_str(), data_length, false /* not shared */);
    replay_step_state_access::context context;
    replay_step_state_access a(context, data.get(), data_length, root_hash_before);
    uint64_t mcycle_end{};
    if (__builtin_add_overflow(a.read_mcycle(), mcycle_count, &mcycle_end)) {
        mcycle_end = UINT64_MAX;
    }
    auto break_reason = interpret(a, mcycle_end);
    a.finish(root_hash_after);
    return break_reason;
}

interpreter_break_reason machine::run(uint64_t mcycle_end) {
    const auto mcycle = read_reg(reg::mcycle);
    if (mcycle_end < mcycle) {
        throw std::invalid_argument{"mcycle is past"};
    }
    const state_access a(*this);
    return interpret(a, mcycle_end);
}

//??D How come this function seems to never signal we have an inteerrupt???
std::pair<uint64_t, execute_status> machine::poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max) {
    const auto status = execute_status::success;
    // Only poll external interrupts if we are in unreproducible mode
    if (unlikely(m_s.iunrep)) {
        // Convert the relative interval of cycles we can wait to the interval of host time we can wait
        uint64_t timeout_us = (mcycle_max - mcycle) / RTC_CYCLES_PER_US;
        int64_t start_us = 0;
        if (timeout_us > 0) {
            start_us = os_now_us();
        }
        const state_access a(*this);
        device_state_access da(a, mcycle);
        // Poll virtio for events (e.g console stdin, network sockets)
        // Timeout may be decremented in case a device has deadline timers (e.g network device)
        if (has_virtio_devices() && has_virtio_console()) { // VirtIO + VirtIO console
            poll_virtio_devices(&timeout_us, &da);
            // VirtIO console device will poll TTY
        } else if (has_virtio_devices()) { // VirtIO without a console
            poll_virtio_devices(&timeout_us, &da);
            if (has_htif_console()) { // VirtIO + HTIF console
                // Poll tty without waiting more time, because the pool above should have waited enough time
                os_poll_tty(0);
            }
        } else if (has_htif_console()) { // Only HTIF console
            os_poll_tty(timeout_us);
        } else if (timeout_us > 0) { // No interrupts to check, just keep the CPU idle
            os_sleep_us(timeout_us);
        }
        // If timeout is greater than zero, we should also increment mcycle relative to the elapsed time
        if (timeout_us > 0) {
            const int64_t end_us = os_now_us();
            const uint64_t elapsed_us = static_cast<uint64_t>(std::max(end_us - start_us, INT64_C(0)));
            const uint64_t next_mcycle = mcycle + (elapsed_us * RTC_CYCLES_PER_US);
            mcycle = std::min(std::max(next_mcycle, mcycle), mcycle_max);
        }
    }
    return {mcycle, status};
}

std::string machine::get_counter_key(const char *name, const char *domain) {
    if (name == nullptr) {
        throw std::invalid_argument{"invalid name argument"};
    }
    std::string key{(domain != nullptr) ? domain : name};
    if (domain != nullptr) {
        key.append(name);
    }
    return key;
}

void machine::increment_counter(const char *name, const char *domain) {
    ++m_counters[get_counter_key(name, domain)];
}

uint64_t machine::read_counter(const char *name, const char *domain) {
    return m_counters[get_counter_key(name, domain)];
}

void machine::write_counter(uint64_t val, const char *name, const char *domain) {
    m_counters[get_counter_key(name, domain)] = val;
}

} // namespace cartesi
