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
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

#include "access-log.h"
#include "address-range-constants.h"
#include "address-range.h"
#include "algorithm.h"
#include "assert-printf.h"
#include "back-merkle-tree.h"
#include "collect-mcycle-hashes-state-access.h"
#include "collect-uarch-cycle-hashes-state-access.h"
#include "compiler-defines.h"
#include "device-state-access.h"
#include "dtb.h"
#include "hash-tree-constants.h"
#include "hash-tree-stats.h"
#include "hash-tree.h"
#include "host-addr.h"
#include "hot-tlb.h"
#include "htif-constants.h"
#include "i-device-state-access.h"
#include "interpret.h"
#include "is-pristine.h"
#include "machine-config.h"
#include "machine-hash.h"
#include "machine-reg.h"
#include "machine-runtime-config.h"
#include "mcycle-root-hashes.h"
#include "os-filesystem.h"
#include "os-mmap.h"
#include "os.h"
#include "pmas-constants.h"
#include "pmas.h"
#include "processor-state.h"
#include "record-send-cmio-state-access.h"
#include "record-step-state-access.h"
#include "replay-send-cmio-state-access.h"
#include "replay-step-state-access.h"
#include "riscv-constants.h"
#include "rtc.h"
#include "scope-exit.h"
#include "scope-remove.h"
#include "send-cmio-response.h"
#include "shadow-registers.h"
#include "shadow-tlb.h"
#include "shadow-uarch-state.h"
#include "state-access.h"
#include "strict-aliasing.h"
#include "translate-virtual-address.h"
#include "uarch-constants.h"
#include "uarch-cycle-root-hashes.h"
#include "uarch-interpret.h"
#include "uarch-pristine.h"
#include "uarch-record-state-access.h"
#include "uarch-replay-state-access.h"
#include "uarch-reset-state.h"
#include "uarch-state-access.h"
#include "uarch-step.h"
#include "variant-hasher.h"
#include "virtio-address-range.h"

/// \file
/// \brief Cartesi machine implementation

namespace cartesi {

static_assert(static_cast<int>(AR_LOG2_PAGE_SIZE) == static_cast<int>(LOG2_PAGE_SIZE),
    "address range page size must match RISC-V page size");
static_assert(static_cast<int>(AR_LOG2_PAGE_SIZE) == static_cast<int>(HASH_TREE_LOG2_PAGE_SIZE),
    "address range page size must match hash-tree page size");

using namespace std::string_literals;

hash_tree_stats machine::get_hash_tree_stats(bool clear) noexcept {
    return m_ht.get_stats(clear);
}

void machine::init_uarch_processor(const uarch_processor_config &p) {
    if (p.backing_store.newly_created()) {
        // Initialize to default values first
        *m_us = uarch_processor_state{};

        // Initialize registers
        write_reg(reg::uarch_pc, p.registers.pc);
        write_reg(reg::uarch_cycle, p.registers.cycle);
        write_reg(reg::uarch_halt_flag, p.registers.halt_flag);
        // General purpose registers
        for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
            write_reg(machine_reg_enum(reg::uarch_x0, i), p.registers.x[i]);
        }
    }

    // Ensure uarch x0 is actually zero
    if (m_us->registers.x[0] != 0) {
        throw std::invalid_argument{"uarch x0 register is corrupt"};
    }
}

void machine::init_processor(const processor_config &p, const machine_runtime_config &r) {
    if (p.backing_store.newly_created()) {
        // Initialize to default values first
        *m_s = processor_state{};

        // General purpose registers
        for (int i = 1; i < X_REG_COUNT; i++) {
            write_reg(machine_reg_enum(reg::x0, i), p.registers.x[i]);
        }

        // Floating-point registers
        for (int i = 0; i < F_REG_COUNT; i++) {
            write_reg(machine_reg_enum(reg::f0, i), p.registers.f[i]);
        }

        // Named registers
        write_reg(reg::pc, p.registers.pc);
        write_reg(reg::fcsr, p.registers.fcsr);
        write_reg(reg::mcycle, p.registers.mcycle);
        write_reg(reg::icycleinstret, p.registers.icycleinstret);
        write_reg(reg::mstatus, p.registers.mstatus);
        write_reg(reg::mtvec, p.registers.mtvec);
        write_reg(reg::mscratch, p.registers.mscratch);
        write_reg(reg::mepc, p.registers.mepc);
        write_reg(reg::mcause, p.registers.mcause);
        write_reg(reg::mtval, p.registers.mtval);
        write_reg(reg::misa, p.registers.misa);
        write_reg(reg::mie, p.registers.mie);
        write_reg(reg::mip, p.registers.mip);
        write_reg(reg::medeleg, p.registers.medeleg);
        write_reg(reg::mideleg, p.registers.mideleg);
        write_reg(reg::mcounteren, p.registers.mcounteren);
        write_reg(reg::menvcfg, p.registers.menvcfg);
        write_reg(reg::stvec, p.registers.stvec);
        write_reg(reg::sscratch, p.registers.sscratch);
        write_reg(reg::sepc, p.registers.sepc);
        write_reg(reg::scause, p.registers.scause);
        write_reg(reg::stval, p.registers.stval);
        write_reg(reg::satp, p.registers.satp);
        write_reg(reg::scounteren, p.registers.scounteren);
        write_reg(reg::senvcfg, p.registers.senvcfg);
        write_reg(reg::ilrsc, p.registers.ilrsc);
        write_reg(reg::iprv, p.registers.iprv);
        write_reg(reg::iflags_X, p.registers.iflags.X);
        write_reg(reg::iflags_Y, p.registers.iflags.Y);
        write_reg(reg::iflags_H, p.registers.iflags.H);
        write_reg(reg::iunrep, p.registers.iunrep);

        // HTIF registers
        write_reg(reg::htif_tohost, p.registers.htif.tohost);
        write_reg(reg::htif_fromhost, p.registers.htif.fromhost);
        write_reg(reg::htif_ihalt, p.registers.htif.ihalt);
        write_reg(reg::htif_iconsole, p.registers.htif.iconsole);
        write_reg(reg::htif_iyield, p.registers.htif.iyield);

        // CLINT registers
        write_reg(reg::clint_mtimecmp, p.registers.clint.mtimecmp);

        // PLIC registers
        write_reg(reg::plic_girqpend, p.registers.plic.girqpend);
        write_reg(reg::plic_girqsrvd, p.registers.plic.girqsrvd);
    }

    // Check if registers are consistent
    validate_processor_shadow(r.skip_version_check);
}

void machine::validate_processor_shadow(bool skip_version_check) const {
    // Ensure emulator version is compatible
    if (!skip_version_check) {
        if (m_s->shadow.registers.marchid != MARCHID_INIT) {
            throw std::invalid_argument{"marchid mismatch, emulator version is incompatible"};
        }
        if (m_s->shadow.registers.mvendorid != MVENDORID_INIT) {
            throw std::invalid_argument{"mvendorid mismatch, emulator version is incompatible"};
        }
        if (m_s->shadow.registers.mimpid != MIMPID_INIT) {
            throw std::invalid_argument{"mimpid mismatch, emulator version is incompatible"};
        }
    }
    // Ensure x0 is actually zero
    if (m_s->shadow.registers.x[0] != 0) {
        throw std::invalid_argument{"x0 register is corrupt"};
    }
    // Ensure padding bytes are consistent
    if (!is_pristine(std::span<const unsigned char>{// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<unsigned char *>(&m_s->shadow.registers_padding_[0]),
            sizeof(m_s->shadow.registers_padding_)}) ||
        !is_pristine(std::span<const unsigned char>{// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<unsigned char *>(&m_s->shadow.tlb_padding_[0]), sizeof(m_s->shadow.tlb_padding_)})) {
        throw std::invalid_argument{"shadow padding bytes are corrupt"};
    }
}

void machine::init_pmas_contents(const pmas_config &config) {
    static_assert(sizeof(pmas_state) == PMA_MAX * 2 * sizeof(uint64_t), "inconsistent PMAs state length");
    static_assert(AR_PMAS_LENGTH >= sizeof(pmas_state), "PMAs address range too short");
    auto &pmas = m_ars.find(AR_PMAS_START, AR_PMAS_LENGTH);
    if (!pmas.is_memory()) {
        throw std::runtime_error{"initialization error: PMAs memory address range not found"};
    }
    pmas_state pmas_state{};
    std::ranges::transform(m_ars.pmas_view(), pmas_state.begin(),
        [](const auto &ar) { return pmas_entry{.istart = ar.get_istart(), .ilength = ar.get_ilength()}; });

    if (config.backing_store.newly_created()) {
        memcpy(pmas.get_host_memory(), pmas_state.data(), sizeof(pmas_state));
    } else {
        // Validate PMAs state is consistent
        if (memcmp(pmas.get_host_memory(), pmas_state.data(), sizeof(pmas_state)) != 0) {
            throw std::runtime_error{"PMA state is inconsistent machine address ranges"};
        }
    }
}

void machine::init_hot_tlb_contents() {
    for (auto set_index : {TLB_CODE, TLB_READ, TLB_WRITE}) {
        for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
            const auto &shadow_slot = m_s->shadow.tlb[set_index][slot_index];
            const auto vaddr_page = shadow_slot.vaddr_page;
            const auto vp_offset = shadow_slot.vp_offset;
            const auto pma_index = shadow_slot.pma_index;
            const auto zero_padding_ = shadow_slot.zero_padding_;
            host_addr vh_offset{};
            if (zero_padding_ != 0) {
                throw std::domain_error{"stored TLB is corrupt: inconsistent padding"};
            }
            if (vaddr_page != TLB_INVALID_PAGE) {
                const auto &ar = read_pma(pma_index);
                if (!ar.is_memory()) {
                    throw std::invalid_argument{"stored TLB is corrupt: pma_index does not point to memory range"s};
                }
                if ((vaddr_page & PAGE_OFFSET_MASK) != 0) {
                    throw std::invalid_argument{"stored TLB is corrupt: vaddr_page is not aligned"s};
                }
                const auto paddr_page = vaddr_page + vp_offset;
                if ((paddr_page & PAGE_OFFSET_MASK) != 0) {
                    throw std::invalid_argument{"stored TLB is corrupt: vp_offset is not aligned"s};
                }
                const auto pmas_end = ar.get_start() + (ar.get_length() - AR_PAGE_SIZE);
                if (paddr_page < ar.get_start() || paddr_page > pmas_end) {
                    throw std::invalid_argument{"stored TLB is corrupt: vp_offset is inconsistent with pma_index"s};
                }
                vh_offset = get_host_addr(paddr_page, pma_index) - vaddr_page;
            } else if (pma_index != TLB_INVALID_PMA_INDEX || vp_offset != 0) {
                throw std::domain_error{"stored TLB is corrupt: inconsistent empty slot"};
            }
            auto &hot_slot = m_s->penumbra.tlb[set_index][slot_index];
            hot_slot.vaddr_page = vaddr_page;
            hot_slot.vh_offset = vh_offset;
        }
    }
}

void machine::init_dtb_contents(const machine_config &config) {
    if (config.dtb.backing_store.newly_created()) {
        auto &dtb = m_ars.find(AR_DTB_START, AR_DTB_LENGTH);
        if (!dtb.is_memory()) {
            throw std::runtime_error{"initialization error: DTB memory address range not found"};
        }
        dtb_init(config, dtb.get_host_memory(), dtb.get_length());
    }
}

// ??D It is best to leave the std::move() on r because it may one day be necessary!
machine::machine(machine_config c, machine_runtime_config r, const std::string &dir, scope_remove remover) :
    m_c{std::move(c).adjust_defaults()}, // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
    m_r{std::move(r)},                   // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
    m_ars{m_c, m_r, dir, remover},
    m_ht{m_c.hash_tree, m_r.concurrency.update_hash_tree, m_ars, m_c.hash_tree.hash_function},
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    m_s{reinterpret_cast<processor_state *>(
        m_ars.find(AR_SHADOW_STATE_START, AR_SHADOW_STATE_LENGTH).get_host_memory())},
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    m_us{reinterpret_cast<uarch_processor_state *>(
        m_ars.find(AR_SHADOW_UARCH_STATE_START, AR_SHADOW_UARCH_STATE_LENGTH).get_host_memory())} {
    init_processor(m_c.processor, m_r);
    init_uarch_processor(m_c.uarch.processor);
    init_pmas_contents(m_c.pmas);
    init_hot_tlb_contents();
    init_dtb_contents(m_c);
    init_tty();
    // Disable SIGPIPE handler, because this signal can be raised and terminate the emulator process
    // when calling write() on closed file descriptors.
    // This can happen with the stdout console file descriptors or network file descriptors.
    os_disable_sigpipe();
    // Construction succeeded, keep all created files and directories
    remover.retain_all();
}

void machine::init_tty() {
    // Initialize TTY if console input is enabled
    if (has_htif_console() || has_virtio_console()) {
        if (read_reg(reg::iunrep) == 0) {
            throw std::invalid_argument{"TTY stdin is only supported in unreproducible machines"};
        }
        os_open_tty();
        m_tty_opened = true;
    }
}

// ??D It is best to leave the std::move() on r because it may one day be necessary!
machine::machine(const std::string &dir, machine_runtime_config r, sharing_mode sharing) :
    // NOLINTNEXTLINE(hicpp-move-const-arg,performance-move-const-arg)
    machine{machine_config::load(dir, sharing), std::move(r)} {}

void machine::prepare_virtio_devices_select(select_fd_sets *fds, uint64_t *timeout_us) {
    for (auto &v : m_ars.virtio_view()) {
        v.prepare_select(fds, timeout_us);
    }
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
bool machine::poll_selected_virtio_devices(int select_ret, select_fd_sets *fds, i_device_state_access *da) {
    bool interrupt_requested = false; // NOLINT(misc-const-correctness)
    for (auto &v : m_ars.virtio_view()) {
        interrupt_requested |= v.poll_selected(select_ret, fds, da);
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
    return !m_ars.virtio_view().empty();
}

bool machine::has_virtio_console() const {
    // When present, the console device is guaranteed to be the first VirtIO device,
    // therefore we only need to check the first device.
    return has_virtio_devices() && m_ars.virtio_view().front().get_device_id() == VIRTIO_DEVICE_CONSOLE;
}

bool machine::has_htif_console() const {
    return static_cast<bool>(read_reg(reg::htif_iconsole) & HTIF_CONSOLE_CMD_GETCHAR_MASK);
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
}

static void store_address_range(const backing_store_config &from_config, const address_range &ar, bool read_only,
    const std::string &dir, sharing_mode sharing, scope_remove &remover) {
    if (ar.is_empty()) {
        throw std::runtime_error{"attempt to store empty address range "s.append(ar.get_description())};
    }
    if (!ar.is_memory() || ar.get_host_memory() == nullptr) {
        throw std::runtime_error{"attempt to store non-memory address range "s.append(ar.get_description())};
    }
    // Write the memory data to a file
    const std::string &data_filename = machine_config::get_data_filename(dir, ar.get_start(), ar.get_length());
    if (sharing == sharing_mode::all || (sharing == sharing_mode::config && from_config.shared)) {
        os::create_file(data_filename, std::span{ar.get_host_memory(), static_cast<size_t>(ar.get_length())});
    } else { // Copy unshared backing store
        if (from_config.data_filename.empty()) {
            throw std::runtime_error{"attempt to restore unbacked address range "s.append(ar.get_description())};
        }
        if (from_config.shared) {
            throw std::runtime_error{"attempt to restore shared address range "s.append(ar.get_description())};
        }
        os::copy_file(from_config.data_filename, data_filename, ar.get_length());
    }
    remover.add_file(data_filename);
    if (read_only) {
        // Mark host read-only ranges as read-only
        os::change_writable(data_filename, false);
    }
}

void machine::store(const std::string &dir, sharing_mode sharing) const {
    if (dir.empty()) {
        throw std::invalid_argument{"directory name cannot be empty"};
    }
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error{"cannot store unreproducible machines"};
    }
    scope_remove remover;
    // Create directory
    os::create_directory(dir);
    remover.add_directory(dir);
    // Store config
    remover.add_file(m_c.store(dir, sharing));
    // Store all address ranges
    store_address_range(m_c.processor.backing_store, m_ars.find<uint64_t>(AR_SHADOW_STATE_START), false, dir, sharing,
        remover);
    store_address_range(m_c.pmas.backing_store, m_ars.find<uint64_t>(AR_PMAS_START), true, dir, sharing, remover);
    store_address_range(m_c.dtb.backing_store, m_ars.find<uint64_t>(AR_DTB_START), false, dir, sharing, remover);
    store_address_range(m_c.ram.backing_store, m_ars.find<uint64_t>(AR_RAM_START), false, dir, sharing, remover);
    store_address_range(m_c.cmio.rx_buffer.backing_store, m_ars.find<uint64_t>(AR_CMIO_RX_BUFFER_START), false, dir,
        sharing, remover);
    store_address_range(m_c.cmio.tx_buffer.backing_store, m_ars.find<uint64_t>(AR_CMIO_TX_BUFFER_START), false, dir,
        sharing, remover);
    store_address_range(m_c.uarch.processor.backing_store, m_ars.find<uint64_t>(AR_SHADOW_UARCH_STATE_START), false,
        dir, sharing, remover);
    store_address_range(m_c.uarch.ram.backing_store, m_ars.find<uint64_t>(AR_UARCH_RAM_START), false, dir, sharing,
        remover);
    for (const auto &f : m_c.flash_drive) {
        store_address_range(f.backing_store, m_ars.find<uint64_t>(f.start), f.read_only, dir, sharing, remover);
    }
    // Retain all stored files
    remover.retain_all();
}

static void clone_address_range(const backing_store_config &from, const backing_store_config &to,
    scope_remove &remover) {
    os::clone_file(from.data_filename, to.data_filename);
    remover.add_file(to.data_filename);
}

void machine::clone_stored(const std::string &from_dir, const std::string &to_dir) {
    if (from_dir.empty() || to_dir.empty()) {
        throw std::invalid_argument{"directory name cannot be empty"};
    }
    const auto from_c = machine_config::load(from_dir);
    const auto to_c = machine_config(from_c).adjust_backing_stores(to_dir);

    scope_remove remover;

    // Create directory
    os::create_directory(to_dir);
    remover.add_directory(to_dir);

    // Clone config
    const auto from_config_filename = machine_config::get_config_filename(from_dir);
    const auto to_config_filename = machine_config::get_config_filename(to_dir);
    os::clone_file(from_config_filename, to_config_filename);
    remover.add_file(to_config_filename);

    // Clone all address ranges
    clone_address_range(from_c.processor.backing_store, to_c.processor.backing_store, remover);
    clone_address_range(from_c.pmas.backing_store, to_c.pmas.backing_store, remover);
    clone_address_range(from_c.dtb.backing_store, to_c.dtb.backing_store, remover);
    clone_address_range(from_c.ram.backing_store, to_c.ram.backing_store, remover);
    clone_address_range(from_c.cmio.rx_buffer.backing_store, to_c.cmio.rx_buffer.backing_store, remover);
    clone_address_range(from_c.cmio.tx_buffer.backing_store, to_c.cmio.tx_buffer.backing_store, remover);
    clone_address_range(from_c.uarch.processor.backing_store, to_c.uarch.processor.backing_store, remover);
    clone_address_range(from_c.uarch.ram.backing_store, to_c.uarch.ram.backing_store, remover);
    for (size_t i = 0; i < to_c.flash_drive.size(); ++i) {
        clone_address_range(from_c.flash_drive[i].backing_store, to_c.flash_drive[i].backing_store, remover);
    }

    // Retain all stored files
    remover.retain_all();
}

void machine::remove_stored(const std::string &dir) {
    if (dir.empty()) {
        throw std::invalid_argument{"directory name cannot be empty"};
    }
    const auto config = machine_config::load(dir);

    // Remove all address ranges
    os::remove_file(config.processor.backing_store.data_filename);
    os::remove_file(config.pmas.backing_store.data_filename);
    os::remove_file(config.dtb.backing_store.data_filename);
    os::remove_file(config.ram.backing_store.data_filename);
    os::remove_file(config.cmio.rx_buffer.backing_store.data_filename);
    os::remove_file(config.cmio.tx_buffer.backing_store.data_filename);
    os::remove_file(config.uarch.processor.backing_store.data_filename);
    os::remove_file(config.uarch.ram.backing_store.data_filename);
    for (const auto &f : config.flash_drive) {
        os::remove_file(f.backing_store.data_filename);
    }

    // Remove config
    os::remove_file(machine_config::get_config_filename(dir));

    // Remove directory
    os::remove_directory(dir);
}

void machine::dump_insn_hist() {
#ifdef DUMP_INSN_HIST
    d_printf("\nInstruction Histogram:\n");
    for (const auto &[key, val] : m_counters) {
        if (key.starts_with("insn.")) {
            d_printf("%s: %" PRIu64 "\n", key.c_str(), val);
        }
    }
#endif
}

void machine::dump_stats() {
#ifdef DUMP_STATS
    const auto hr = [](uint64_t a, uint64_t b) { return static_cast<double>(b) / static_cast<double>(a + b); };

    d_printf("\nMachine Counters:\n");
    d_printf("inner loops: %" PRIu64 "\n", m_counters["stats.inner_loop"]);
    d_printf("outers loops: %" PRIu64 "\n", m_counters["stats.outer_loop"]);
    d_printf("supervisor ints: %" PRIu64 "\n", m_counters["stats.sv_int"]);
    d_printf("supervisor ex: %" PRIu64 "\n", m_counters["stats.sv_ex"]);
    d_printf("machine ints: %" PRIu64 "\n", m_counters["stats.m_int"]);
    d_printf("machine ex: %" PRIu64 "\n", m_counters["stats.m_ex"]);
    d_printf("atomic mem ops: %" PRIu64 "\n", m_counters["stats.atomic_mop"]);
    d_printf("fence: %" PRIu64 "\n", m_counters["stats.fence"]);
    d_printf("fence.i: %" PRIu64 "\n", m_counters["stats.fence_i"]);
    d_printf("fence.vma: %" PRIu64 "\n", m_counters["stats.fence_vma"]);
    d_printf("max asid: %" PRIu64 "\n", m_counters["stats.max_asid"]);
    d_printf("User mode: %" PRIu64 "\n", m_counters["stats.prv.U"]);
    d_printf("Supervisor mode: %" PRIu64 "\n", m_counters["stats.prv.S"]);
    d_printf("Machine mode: %" PRIu64 "\n", m_counters["stats.prv.M"]);
    d_printf("tlb code hit ratio: %.4f\n", hr(m_counters["stats.tlb.cmiss"], m_counters["stats.tlb.chit"]));
    d_printf("tlb read hit ratio: %.4f\n", hr(m_counters["stats.tlb.rmiss"], m_counters["stats.tlb.rhit"]));
    d_printf("tlb write hit ratio: %.4f\n", hr(m_counters["stats.tlb.wmiss"], m_counters["stats.tlb.whit"]));
    d_printf("tlb.chit: %" PRIu64 "\n", m_counters["stats.tlb.chit"]);
    d_printf("tlb.cmiss: %" PRIu64 "\n", m_counters["stats.tlb.cmiss"]);
    d_printf("tlb.rhit: %" PRIu64 "\n", m_counters["stats.tlb.rhit"]);
    d_printf("tlb.rmiss: %" PRIu64 "\n", m_counters["stats.tlb.rmiss"]);
    d_printf("tlb.whit: %" PRIu64 "\n", m_counters["stats.tlb.whit"]);
    d_printf("tlb.wmiss: %" PRIu64 "\n", m_counters["stats.tlb.wmiss"]);
    d_printf("tlb.flush_all: %" PRIu64 "\n", m_counters["stats.tlb.flush_all"]);
    d_printf("tlb.flush_read: %" PRIu64 "\n", m_counters["stats.tlb.flush_read"]);
    d_printf("tlb.flush_write: %" PRIu64 "\n", m_counters["stats.tlb.flush_write"]);
    d_printf("tlb.flush_vaddr: %" PRIu64 "\n", m_counters["stats.tlb.flush_vaddr"]);
    d_printf("tlb.flush_satp: %" PRIu64 "\n", m_counters["stats.tlb.flush_satp"]);
    d_printf("tlb.flush_mstatus: %" PRIu64 "\n", m_counters["stats.tlb.flush_mstatus"]);
    d_printf("tlb.flush_set_prv: %" PRIu64 "\n", m_counters["stats.tlb.flush_set_prv"]);
    d_printf("tlb.flush_fence_vma_all: %" PRIu64 "\n", m_counters["stats.tlb.flush_fence_vma_all"]);
    d_printf("tlb.flush_fence_vma_asid: %" PRIu64 "\n", m_counters["stats.tlb.flush_fence_vma_asid"]);
    d_printf("tlb.flush_fence_vma_vaddr: %" PRIu64 "\n", m_counters["stats.tlb.flush_fence_vma_vaddr"]);
    d_printf("tlb.flush_fence_vma_asid_vaddr: %" PRIu64 "\n", m_counters["stats.tlb.flush_fence_vma_asid_vaddr"]);
#undef TLB_HIT_RATIO
#endif
}

machine::~machine() {
    if (m_tty_opened) {
        os_close_tty();
    }
    dump_insn_hist();
    dump_stats();
}

uint64_t machine::read_reg(reg r) const {
    switch (r) {
        case reg::x0:
            return m_s->shadow.registers.x[0];
        case reg::x1:
            return m_s->shadow.registers.x[1];
        case reg::x2:
            return m_s->shadow.registers.x[2];
        case reg::x3:
            return m_s->shadow.registers.x[3];
        case reg::x4:
            return m_s->shadow.registers.x[4];
        case reg::x5:
            return m_s->shadow.registers.x[5];
        case reg::x6:
            return m_s->shadow.registers.x[6];
        case reg::x7:
            return m_s->shadow.registers.x[7];
        case reg::x8:
            return m_s->shadow.registers.x[8];
        case reg::x9:
            return m_s->shadow.registers.x[9];
        case reg::x10:
            return m_s->shadow.registers.x[10];
        case reg::x11:
            return m_s->shadow.registers.x[11];
        case reg::x12:
            return m_s->shadow.registers.x[12];
        case reg::x13:
            return m_s->shadow.registers.x[13];
        case reg::x14:
            return m_s->shadow.registers.x[14];
        case reg::x15:
            return m_s->shadow.registers.x[15];
        case reg::x16:
            return m_s->shadow.registers.x[16];
        case reg::x17:
            return m_s->shadow.registers.x[17];
        case reg::x18:
            return m_s->shadow.registers.x[18];
        case reg::x19:
            return m_s->shadow.registers.x[19];
        case reg::x20:
            return m_s->shadow.registers.x[20];
        case reg::x21:
            return m_s->shadow.registers.x[21];
        case reg::x22:
            return m_s->shadow.registers.x[22];
        case reg::x23:
            return m_s->shadow.registers.x[23];
        case reg::x24:
            return m_s->shadow.registers.x[24];
        case reg::x25:
            return m_s->shadow.registers.x[25];
        case reg::x26:
            return m_s->shadow.registers.x[26];
        case reg::x27:
            return m_s->shadow.registers.x[27];
        case reg::x28:
            return m_s->shadow.registers.x[28];
        case reg::x29:
            return m_s->shadow.registers.x[29];
        case reg::x30:
            return m_s->shadow.registers.x[30];
        case reg::x31:
            return m_s->shadow.registers.x[31];
        case reg::f0:
            return m_s->shadow.registers.f[0];
        case reg::f1:
            return m_s->shadow.registers.f[1];
        case reg::f2:
            return m_s->shadow.registers.f[2];
        case reg::f3:
            return m_s->shadow.registers.f[3];
        case reg::f4:
            return m_s->shadow.registers.f[4];
        case reg::f5:
            return m_s->shadow.registers.f[5];
        case reg::f6:
            return m_s->shadow.registers.f[6];
        case reg::f7:
            return m_s->shadow.registers.f[7];
        case reg::f8:
            return m_s->shadow.registers.f[8];
        case reg::f9:
            return m_s->shadow.registers.f[9];
        case reg::f10:
            return m_s->shadow.registers.f[10];
        case reg::f11:
            return m_s->shadow.registers.f[11];
        case reg::f12:
            return m_s->shadow.registers.f[12];
        case reg::f13:
            return m_s->shadow.registers.f[13];
        case reg::f14:
            return m_s->shadow.registers.f[14];
        case reg::f15:
            return m_s->shadow.registers.f[15];
        case reg::f16:
            return m_s->shadow.registers.f[16];
        case reg::f17:
            return m_s->shadow.registers.f[17];
        case reg::f18:
            return m_s->shadow.registers.f[18];
        case reg::f19:
            return m_s->shadow.registers.f[19];
        case reg::f20:
            return m_s->shadow.registers.f[20];
        case reg::f21:
            return m_s->shadow.registers.f[21];
        case reg::f22:
            return m_s->shadow.registers.f[22];
        case reg::f23:
            return m_s->shadow.registers.f[23];
        case reg::f24:
            return m_s->shadow.registers.f[24];
        case reg::f25:
            return m_s->shadow.registers.f[25];
        case reg::f26:
            return m_s->shadow.registers.f[26];
        case reg::f27:
            return m_s->shadow.registers.f[27];
        case reg::f28:
            return m_s->shadow.registers.f[28];
        case reg::f29:
            return m_s->shadow.registers.f[29];
        case reg::f30:
            return m_s->shadow.registers.f[30];
        case reg::f31:
            return m_s->shadow.registers.f[31];
        case reg::pc:
            return m_s->shadow.registers.pc;
        case reg::fcsr:
            return m_s->shadow.registers.fcsr;
        case reg::mvendorid:
            return MVENDORID_INIT;
        case reg::marchid:
            return MARCHID_INIT;
        case reg::mimpid:
            return MIMPID_INIT;
        case reg::mcycle:
            return m_s->shadow.registers.mcycle;
        case reg::icycleinstret:
            return m_s->shadow.registers.icycleinstret;
        case reg::mstatus:
            return m_s->shadow.registers.mstatus;
        case reg::mtvec:
            return m_s->shadow.registers.mtvec;
        case reg::mscratch:
            return m_s->shadow.registers.mscratch;
        case reg::mepc:
            return m_s->shadow.registers.mepc;
        case reg::mcause:
            return m_s->shadow.registers.mcause;
        case reg::mtval:
            return m_s->shadow.registers.mtval;
        case reg::misa:
            return m_s->shadow.registers.misa;
        case reg::mie:
            return m_s->shadow.registers.mie;
        case reg::mip:
            return m_s->shadow.registers.mip;
        case reg::medeleg:
            return m_s->shadow.registers.medeleg;
        case reg::mideleg:
            return m_s->shadow.registers.mideleg;
        case reg::mcounteren:
            return m_s->shadow.registers.mcounteren;
        case reg::menvcfg:
            return m_s->shadow.registers.menvcfg;
        case reg::stvec:
            return m_s->shadow.registers.stvec;
        case reg::sscratch:
            return m_s->shadow.registers.sscratch;
        case reg::sepc:
            return m_s->shadow.registers.sepc;
        case reg::scause:
            return m_s->shadow.registers.scause;
        case reg::stval:
            return m_s->shadow.registers.stval;
        case reg::satp:
            return m_s->shadow.registers.satp;
        case reg::scounteren:
            return m_s->shadow.registers.scounteren;
        case reg::senvcfg:
            return m_s->shadow.registers.senvcfg;
        case reg::ilrsc:
            return m_s->shadow.registers.ilrsc;
        case reg::iprv:
            return m_s->shadow.registers.iprv;
        case reg::iflags_X:
            return m_s->shadow.registers.iflags.X;
        case reg::iflags_Y:
            return m_s->shadow.registers.iflags.Y;
        case reg::iflags_H:
            return m_s->shadow.registers.iflags.H;
        case reg::iunrep:
            return m_s->shadow.registers.iunrep;
        case reg::clint_mtimecmp:
            return m_s->shadow.registers.clint.mtimecmp;
        case reg::plic_girqpend:
            return m_s->shadow.registers.plic.girqpend;
        case reg::plic_girqsrvd:
            return m_s->shadow.registers.plic.girqsrvd;
        case reg::htif_tohost:
            return m_s->shadow.registers.htif.tohost;
        case reg::htif_fromhost:
            return m_s->shadow.registers.htif.fromhost;
        case reg::htif_ihalt:
            return m_s->shadow.registers.htif.ihalt;
        case reg::htif_iconsole:
            return m_s->shadow.registers.htif.iconsole;
        case reg::htif_iyield:
            return m_s->shadow.registers.htif.iyield;
        case reg::uarch_x0:
            return m_us->registers.x[0];
        case reg::uarch_x1:
            return m_us->registers.x[1];
        case reg::uarch_x2:
            return m_us->registers.x[2];
        case reg::uarch_x3:
            return m_us->registers.x[3];
        case reg::uarch_x4:
            return m_us->registers.x[4];
        case reg::uarch_x5:
            return m_us->registers.x[5];
        case reg::uarch_x6:
            return m_us->registers.x[6];
        case reg::uarch_x7:
            return m_us->registers.x[7];
        case reg::uarch_x8:
            return m_us->registers.x[8];
        case reg::uarch_x9:
            return m_us->registers.x[9];
        case reg::uarch_x10:
            return m_us->registers.x[10];
        case reg::uarch_x11:
            return m_us->registers.x[11];
        case reg::uarch_x12:
            return m_us->registers.x[12];
        case reg::uarch_x13:
            return m_us->registers.x[13];
        case reg::uarch_x14:
            return m_us->registers.x[14];
        case reg::uarch_x15:
            return m_us->registers.x[15];
        case reg::uarch_x16:
            return m_us->registers.x[16];
        case reg::uarch_x17:
            return m_us->registers.x[17];
        case reg::uarch_x18:
            return m_us->registers.x[18];
        case reg::uarch_x19:
            return m_us->registers.x[19];
        case reg::uarch_x20:
            return m_us->registers.x[20];
        case reg::uarch_x21:
            return m_us->registers.x[21];
        case reg::uarch_x22:
            return m_us->registers.x[22];
        case reg::uarch_x23:
            return m_us->registers.x[23];
        case reg::uarch_x24:
            return m_us->registers.x[24];
        case reg::uarch_x25:
            return m_us->registers.x[25];
        case reg::uarch_x26:
            return m_us->registers.x[26];
        case reg::uarch_x27:
            return m_us->registers.x[27];
        case reg::uarch_x28:
            return m_us->registers.x[28];
        case reg::uarch_x29:
            return m_us->registers.x[29];
        case reg::uarch_x30:
            return m_us->registers.x[30];
        case reg::uarch_x31:
            return m_us->registers.x[31];
        case reg::uarch_pc:
            return m_us->registers.pc;
        case reg::uarch_cycle:
            return m_us->registers.cycle;
        case reg::uarch_halt_flag:
            return m_us->registers.halt_flag;
        case reg::htif_tohost_dev:
            return HTIF_DEV_FIELD(m_s->shadow.registers.htif.tohost);
        case reg::htif_tohost_cmd:
            return HTIF_CMD_FIELD(m_s->shadow.registers.htif.tohost);
        case reg::htif_tohost_reason:
            return HTIF_REASON_FIELD(m_s->shadow.registers.htif.tohost);
        case reg::htif_tohost_data:
            return HTIF_DATA_FIELD(m_s->shadow.registers.htif.tohost);
        case reg::htif_fromhost_dev:
            return HTIF_DEV_FIELD(m_s->shadow.registers.htif.fromhost);
        case reg::htif_fromhost_cmd:
            return HTIF_CMD_FIELD(m_s->shadow.registers.htif.fromhost);
        case reg::htif_fromhost_reason:
            return HTIF_REASON_FIELD(m_s->shadow.registers.htif.fromhost);
        case reg::htif_fromhost_data:
            return HTIF_DATA_FIELD(m_s->shadow.registers.htif.fromhost);
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
            m_s->shadow.registers.x[1] = value;
            break;
        case reg::x2:
            m_s->shadow.registers.x[2] = value;
            break;
        case reg::x3:
            m_s->shadow.registers.x[3] = value;
            break;
        case reg::x4:
            m_s->shadow.registers.x[4] = value;
            break;
        case reg::x5:
            m_s->shadow.registers.x[5] = value;
            break;
        case reg::x6:
            m_s->shadow.registers.x[6] = value;
            break;
        case reg::x7:
            m_s->shadow.registers.x[7] = value;
            break;
        case reg::x8:
            m_s->shadow.registers.x[8] = value;
            break;
        case reg::x9:
            m_s->shadow.registers.x[9] = value;
            break;
        case reg::x10:
            m_s->shadow.registers.x[10] = value;
            break;
        case reg::x11:
            m_s->shadow.registers.x[11] = value;
            break;
        case reg::x12:
            m_s->shadow.registers.x[12] = value;
            break;
        case reg::x13:
            m_s->shadow.registers.x[13] = value;
            break;
        case reg::x14:
            m_s->shadow.registers.x[14] = value;
            break;
        case reg::x15:
            m_s->shadow.registers.x[15] = value;
            break;
        case reg::x16:
            m_s->shadow.registers.x[16] = value;
            break;
        case reg::x17:
            m_s->shadow.registers.x[17] = value;
            break;
        case reg::x18:
            m_s->shadow.registers.x[18] = value;
            break;
        case reg::x19:
            m_s->shadow.registers.x[19] = value;
            break;
        case reg::x20:
            m_s->shadow.registers.x[20] = value;
            break;
        case reg::x21:
            m_s->shadow.registers.x[21] = value;
            break;
        case reg::x22:
            m_s->shadow.registers.x[22] = value;
            break;
        case reg::x23:
            m_s->shadow.registers.x[23] = value;
            break;
        case reg::x24:
            m_s->shadow.registers.x[24] = value;
            break;
        case reg::x25:
            m_s->shadow.registers.x[25] = value;
            break;
        case reg::x26:
            m_s->shadow.registers.x[26] = value;
            break;
        case reg::x27:
            m_s->shadow.registers.x[27] = value;
            break;
        case reg::x28:
            m_s->shadow.registers.x[28] = value;
            break;
        case reg::x29:
            m_s->shadow.registers.x[29] = value;
            break;
        case reg::x30:
            m_s->shadow.registers.x[30] = value;
            break;
        case reg::x31:
            m_s->shadow.registers.x[31] = value;
            break;
        case reg::f0:
            m_s->shadow.registers.f[0] = value;
            break;
        case reg::f1:
            m_s->shadow.registers.f[1] = value;
            break;
        case reg::f2:
            m_s->shadow.registers.f[2] = value;
            break;
        case reg::f3:
            m_s->shadow.registers.f[3] = value;
            break;
        case reg::f4:
            m_s->shadow.registers.f[4] = value;
            break;
        case reg::f5:
            m_s->shadow.registers.f[5] = value;
            break;
        case reg::f6:
            m_s->shadow.registers.f[6] = value;
            break;
        case reg::f7:
            m_s->shadow.registers.f[7] = value;
            break;
        case reg::f8:
            m_s->shadow.registers.f[8] = value;
            break;
        case reg::f9:
            m_s->shadow.registers.f[9] = value;
            break;
        case reg::f10:
            m_s->shadow.registers.f[10] = value;
            break;
        case reg::f11:
            m_s->shadow.registers.f[11] = value;
            break;
        case reg::f12:
            m_s->shadow.registers.f[12] = value;
            break;
        case reg::f13:
            m_s->shadow.registers.f[13] = value;
            break;
        case reg::f14:
            m_s->shadow.registers.f[14] = value;
            break;
        case reg::f15:
            m_s->shadow.registers.f[15] = value;
            break;
        case reg::f16:
            m_s->shadow.registers.f[16] = value;
            break;
        case reg::f17:
            m_s->shadow.registers.f[17] = value;
            break;
        case reg::f18:
            m_s->shadow.registers.f[18] = value;
            break;
        case reg::f19:
            m_s->shadow.registers.f[19] = value;
            break;
        case reg::f20:
            m_s->shadow.registers.f[20] = value;
            break;
        case reg::f21:
            m_s->shadow.registers.f[21] = value;
            break;
        case reg::f22:
            m_s->shadow.registers.f[22] = value;
            break;
        case reg::f23:
            m_s->shadow.registers.f[23] = value;
            break;
        case reg::f24:
            m_s->shadow.registers.f[24] = value;
            break;
        case reg::f25:
            m_s->shadow.registers.f[25] = value;
            break;
        case reg::f26:
            m_s->shadow.registers.f[26] = value;
            break;
        case reg::f27:
            m_s->shadow.registers.f[27] = value;
            break;
        case reg::f28:
            m_s->shadow.registers.f[28] = value;
            break;
        case reg::f29:
            m_s->shadow.registers.f[29] = value;
            break;
        case reg::f30:
            m_s->shadow.registers.f[30] = value;
            break;
        case reg::f31:
            m_s->shadow.registers.f[31] = value;
            break;
        case reg::pc:
            m_s->shadow.registers.pc = value;
            break;
        case reg::fcsr:
            m_s->shadow.registers.fcsr = value;
            break;
        case reg::mvendorid:
            throw std::invalid_argument{"register is read-only"};
        case reg::marchid:
            [[fallthrough]];
        case reg::mimpid:
            throw std::invalid_argument{"register is read-only"};
        case reg::mcycle:
            m_s->shadow.registers.mcycle = value;
            break;
        case reg::icycleinstret:
            m_s->shadow.registers.icycleinstret = value;
            break;
        case reg::mstatus:
            m_s->shadow.registers.mstatus = value;
            break;
        case reg::mtvec:
            m_s->shadow.registers.mtvec = value;
            break;
        case reg::mscratch:
            m_s->shadow.registers.mscratch = value;
            break;
        case reg::mepc:
            m_s->shadow.registers.mepc = value;
            break;
        case reg::mcause:
            m_s->shadow.registers.mcause = value;
            break;
        case reg::mtval:
            m_s->shadow.registers.mtval = value;
            break;
        case reg::misa:
            m_s->shadow.registers.misa = value;
            break;
        case reg::mie:
            m_s->shadow.registers.mie = value;
            break;
        case reg::mip:
            m_s->shadow.registers.mip = value;
            break;
        case reg::medeleg:
            m_s->shadow.registers.medeleg = value;
            break;
        case reg::mideleg:
            m_s->shadow.registers.mideleg = value;
            break;
        case reg::mcounteren:
            m_s->shadow.registers.mcounteren = value;
            break;
        case reg::menvcfg:
            m_s->shadow.registers.menvcfg = value;
            break;
        case reg::stvec:
            m_s->shadow.registers.stvec = value;
            break;
        case reg::sscratch:
            m_s->shadow.registers.sscratch = value;
            break;
        case reg::sepc:
            m_s->shadow.registers.sepc = value;
            break;
        case reg::scause:
            m_s->shadow.registers.scause = value;
            break;
        case reg::stval:
            m_s->shadow.registers.stval = value;
            break;
        case reg::satp:
            m_s->shadow.registers.satp = value;
            break;
        case reg::scounteren:
            m_s->shadow.registers.scounteren = value;
            break;
        case reg::senvcfg:
            m_s->shadow.registers.senvcfg = value;
            break;
        case reg::ilrsc:
            m_s->shadow.registers.ilrsc = value;
            break;
        case reg::iprv:
            m_s->shadow.registers.iprv = value;
            break;
        case reg::iflags_X:
            m_s->shadow.registers.iflags.X = value;
            break;
        case reg::iflags_Y:
            m_s->shadow.registers.iflags.Y = value;
            break;
        case reg::iflags_H:
            m_s->shadow.registers.iflags.H = value;
            break;
        case reg::iunrep:
            m_s->shadow.registers.iunrep = value;
            break;
        case reg::clint_mtimecmp:
            m_s->shadow.registers.clint.mtimecmp = value;
            break;
        case reg::plic_girqpend:
            m_s->shadow.registers.plic.girqpend = value;
            break;
        case reg::plic_girqsrvd:
            m_s->shadow.registers.plic.girqsrvd = value;
            break;
        case reg::htif_tohost:
            m_s->shadow.registers.htif.tohost = value;
            break;
        case reg::htif_fromhost:
            m_s->shadow.registers.htif.fromhost = value;
            break;
        case reg::htif_ihalt:
            m_s->shadow.registers.htif.ihalt = value;
            break;
        case reg::htif_iconsole:
            m_s->shadow.registers.htif.iconsole = value;
            break;
        case reg::htif_iyield:
            m_s->shadow.registers.htif.iyield = value;
            break;
        case reg::uarch_x0:
            throw std::invalid_argument{"register is read-only"};
        case reg::uarch_x1:
            m_us->registers.x[1] = value;
            break;
        case reg::uarch_x2:
            m_us->registers.x[2] = value;
            break;
        case reg::uarch_x3:
            m_us->registers.x[3] = value;
            break;
        case reg::uarch_x4:
            m_us->registers.x[4] = value;
            break;
        case reg::uarch_x5:
            m_us->registers.x[5] = value;
            break;
        case reg::uarch_x6:
            m_us->registers.x[6] = value;
            break;
        case reg::uarch_x7:
            m_us->registers.x[7] = value;
            break;
        case reg::uarch_x8:
            m_us->registers.x[8] = value;
            break;
        case reg::uarch_x9:
            m_us->registers.x[9] = value;
            break;
        case reg::uarch_x10:
            m_us->registers.x[10] = value;
            break;
        case reg::uarch_x11:
            m_us->registers.x[11] = value;
            break;
        case reg::uarch_x12:
            m_us->registers.x[12] = value;
            break;
        case reg::uarch_x13:
            m_us->registers.x[13] = value;
            break;
        case reg::uarch_x14:
            m_us->registers.x[14] = value;
            break;
        case reg::uarch_x15:
            m_us->registers.x[15] = value;
            break;
        case reg::uarch_x16:
            m_us->registers.x[16] = value;
            break;
        case reg::uarch_x17:
            m_us->registers.x[17] = value;
            break;
        case reg::uarch_x18:
            m_us->registers.x[18] = value;
            break;
        case reg::uarch_x19:
            m_us->registers.x[19] = value;
            break;
        case reg::uarch_x20:
            m_us->registers.x[20] = value;
            break;
        case reg::uarch_x21:
            m_us->registers.x[21] = value;
            break;
        case reg::uarch_x22:
            m_us->registers.x[22] = value;
            break;
        case reg::uarch_x23:
            m_us->registers.x[23] = value;
            break;
        case reg::uarch_x24:
            m_us->registers.x[24] = value;
            break;
        case reg::uarch_x25:
            m_us->registers.x[25] = value;
            break;
        case reg::uarch_x26:
            m_us->registers.x[26] = value;
            break;
        case reg::uarch_x27:
            m_us->registers.x[27] = value;
            break;
        case reg::uarch_x28:
            m_us->registers.x[28] = value;
            break;
        case reg::uarch_x29:
            m_us->registers.x[29] = value;
            break;
        case reg::uarch_x30:
            m_us->registers.x[30] = value;
            break;
        case reg::uarch_x31:
            m_us->registers.x[31] = value;
            break;
        case reg::uarch_pc:
            m_us->registers.pc = value;
            break;
        case reg::uarch_cycle:
            m_us->registers.cycle = value;
            break;
        case reg::uarch_halt_flag:
            m_us->registers.halt_flag = value;
            break;
        case reg::htif_tohost_dev:
            m_s->shadow.registers.htif.tohost = HTIF_REPLACE_DEV(m_s->shadow.registers.htif.tohost, value);
            break;
        case reg::htif_tohost_cmd:
            m_s->shadow.registers.htif.tohost = HTIF_REPLACE_CMD(m_s->shadow.registers.htif.tohost, value);
            break;
        case reg::htif_tohost_reason:
            m_s->shadow.registers.htif.tohost = HTIF_REPLACE_REASON(m_s->shadow.registers.htif.tohost, value);
            break;
        case reg::htif_tohost_data:
            m_s->shadow.registers.htif.tohost = HTIF_REPLACE_DATA(m_s->shadow.registers.htif.tohost, value);
            break;
        case reg::htif_fromhost_dev:
            m_s->shadow.registers.htif.fromhost = HTIF_REPLACE_DEV(m_s->shadow.registers.htif.fromhost, value);
            break;
        case reg::htif_fromhost_cmd:
            m_s->shadow.registers.htif.fromhost = HTIF_REPLACE_CMD(m_s->shadow.registers.htif.fromhost, value);
            break;
        case reg::htif_fromhost_reason:
            m_s->shadow.registers.htif.fromhost = HTIF_REPLACE_REASON(m_s->shadow.registers.htif.fromhost, value);
            break;
        case reg::htif_fromhost_data:
            m_s->shadow.registers.htif.fromhost = HTIF_REPLACE_DATA(m_s->shadow.registers.htif.fromhost, value);
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
    auto &hot_set = m_s->penumbra.tlb[TLB_WRITE];
    auto &shadow_set = m_s->shadow.tlb[TLB_WRITE];
    for (uint64_t slot_index = 0; slot_index < TLB_SET_SIZE; ++slot_index) {
        const auto &hot_slot = hot_set[slot_index];
        if (hot_slot.vaddr_page != TLB_INVALID_PAGE) {
            const auto &shadow_slot = shadow_set[slot_index];
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            auto &ar = const_cast<address_range &>(read_pma(shadow_slot.pma_index));
            if (!ar.is_memory()) {
                throw std::runtime_error{"could not mark dirty page for a TLB entry: TLB is corrupt"};
            }
            auto paddr_page = hot_slot.vaddr_page + shadow_slot.vp_offset;
            if (!ar.contains_absolute(paddr_page, AR_PAGE_SIZE)) {
                throw std::runtime_error{"could not mark dirty page for a TLB entry: TLB is corrupt"};
            }
            ar.get_dirty_page_tree().mark_dirty_page_and_up(paddr_page - ar.get_start());
        }
    }
}

bool machine::update_hash_tree() const {
    mark_write_tlb_dirty_pages();
    m_ars.mark_always_dirty_pages();
    return m_ht.update(m_ars);
}

machine_hash machine::get_root_hash() const {
    if (!update_hash_tree()) {
        throw std::runtime_error{"update hash tree failed"};
    }
    return m_ht.get_root_hash();
}

const char *machine::get_what_name(uint64_t paddr) {
    if (paddr >= AR_UARCH_RAM_START && paddr - AR_UARCH_RAM_START < AR_UARCH_RAM_LENGTH) {
        return "uarch.ram";
    }
    // If in shadow, return refined name
    if (paddr >= AR_SHADOW_REGISTERS_START && paddr - AR_SHADOW_REGISTERS_START < AR_SHADOW_REGISTERS_LENGTH) {
        return shadow_registers_get_what_name(shadow_registers_get_what(paddr));
    }
    if (paddr >= AR_SHADOW_TLB_START && paddr - AR_SHADOW_TLB_START < AR_SHADOW_TLB_LENGTH) {
        [[maybe_unused]] TLB_set_index set_index{};
        [[maybe_unused]] uint64_t slot_index{};
        return shadow_tlb_get_what_name(shadow_tlb_get_what(paddr, set_index, slot_index));
    }
    if (paddr >= AR_PMAS_START && paddr - AR_PMAS_START < AR_PMAS_LENGTH) {
        return pmas_get_what_name(pmas_get_what(paddr));
    }
    if (paddr >= AR_SHADOW_UARCH_STATE_START && paddr - AR_SHADOW_UARCH_STATE_START < AR_SHADOW_UARCH_STATE_LENGTH) {
        return shadow_uarch_state_get_what_name(shadow_uarch_state_get_what(paddr));
    }
    return "memory";
}

machine_hash machine::get_node_hash(uint64_t address, int log2_size) const {
    if (!update_hash_tree()) {
        throw std::runtime_error{"update hash tree failed"};
    }
    return get_node_hash(address, log2_size, skip_hash_tree_update);
}

bool machine::verify_hash_tree() const {
    mark_write_tlb_dirty_pages();
    m_ars.mark_always_dirty_pages();
    return m_ht.verify(m_ars);
}

machine::proof_type machine::get_proof(uint64_t address, int log2_size) const {
    if (!update_hash_tree()) {
        throw std::runtime_error{"update hash tree failed"};
    }
    return get_proof(address, log2_size, skip_hash_tree_update);
}

template <typename F>
static inline void foreach_aligned_chunk(uint64_t start, uint64_t length, uint64_t alignment, F f) {
    // Optional first chunk brings start to alignment
    if (const auto rem = start % alignment; rem != 0) {
        const auto first_length = std::min(length, alignment - rem);
        f(start, first_length);
        start += first_length;
        length -= first_length;
    }
    // Intermediate chunks start aligned and cover exactly alignment bytes
    while (length >= alignment) {
        f(start, alignment);
        start += alignment;
        length -= alignment;
    }
    // Last chunk completes the span
    if (length != 0) {
        f(start, length);
    }
}

//??D I think we should have something like this in the address_range interface
//??D Something that combines a check with contains and returns an optional view
static std::optional<std::span<const unsigned char>> ar_host_memory_view(const address_range &ar, uint64_t offset,
    uint64_t length) {
    if (!ar.contains_relative(offset, length)) {
        throw std::logic_error{"invalid access to address range "s.append(ar.get_description())};
    }
    if (ar.is_memory()) {
        if (ar.get_host_memory() == nullptr) {
            throw std::runtime_error{
                "memory address range "s.append(ar.get_description()).append("has no host memory")};
        }
        return std::span<const unsigned char>{ar.get_host_memory() + offset, static_cast<size_t>(length)};
    }
    return {};
}

//??D change this to use a span, or perhaps a contiguous_range of byte-like elements
void machine::read_memory(uint64_t paddr, unsigned char *data, uint64_t length) const {
    if (length == 0) {
        return;
    }
    if (data == nullptr) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    uint64_t gap_start = 0;
    auto view = m_ars.hash_tree_view() |
        std::views::drop_while([paddr, &gap_start](const address_range &ar) { // Only those that end after paddr
            const auto ar_end = ar.get_end();
            if (paddr >= ar_end) {
                gap_start = ar_end;
                return true;
            }
            return false;
        });
    for (const auto &ar : view) {
        const auto ar_start = ar.get_start();
        // Write as much as possible from pristine gap between last address range and current address range
        if (paddr >= gap_start && paddr < ar_start) {
            const auto from_gap = std::min(ar_start - paddr, length);
            memset(data, 0, from_gap);
            length -= from_gap;
            paddr += from_gap;
            data += from_gap;
        }
        gap_start = ar.get_end();
        // Write as much as possible from current address range
        if (paddr >= ar_start && paddr < gap_start) {
            const auto from_ar = std::min(gap_start - paddr, length);
            auto data_view = std::span<unsigned char>{data, static_cast<size_t>(from_ar)};
            auto ar_view = ar_host_memory_view(ar, paddr - ar_start, from_ar);
            if (ar_view) {
                std::ranges::copy(*ar_view, data_view.begin());
            } else {
                std::ranges::fill(data_view, 0);
            }
            length -= from_ar;
            if (length == 0) {
                return;
            }
            paddr += from_ar;
            data += from_ar;
        }
    }
    if (length != 0) {
        // Finish up with pristine padding after last address range
        memset(data, 0, length);
    }
}

//??D change this to use a span, or perhaps a contiguous_range of byte-like elements
void machine::write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
    if (length == 0) {
        return;
    }
    if (data == nullptr) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    auto &ar = m_ars.find(paddr, length);
    const auto *ar_descr = ar.get_description();
    if (ar.is_device()) {
        throw std::invalid_argument{"attempted write to device memory range "s.append(ar_descr)};
    }
    if (!ar.is_memory()) {
        throw std::invalid_argument{"attempted write is not entirely within single memory range"};
    }
    if (ar.is_host_read_only()) {
        throw std::invalid_argument{"attempted write to host-read-only memory range "s.append(ar_descr)};
    }
    // Handle special case for writing to shadow memory, allowing manual snapshots
    // for machines with shared layouts via read_memory()/write_memory()
    if (paddr == AR_SHADOW_STATE_START && length == AR_SHADOW_STATE_LENGTH) {
        // Save the current processor state for potential rollback
        static const auto s = *m_s;
        // Overwrite the processor shadow state with the provided data
        static_assert(AR_SHADOW_STATE_LENGTH == sizeof(m_s->shadow));
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        memcpy(reinterpret_cast<unsigned char *>(&m_s->shadow), data, sizeof(m_s->shadow));
        // Ensure processor state rollback in case of failure during subsequent operations
        auto state_reverter = scope_fail([&] { *m_s = s; });
        // Ensure the new processor shadow state is consistent
        validate_processor_shadow(m_r.skip_version_check);
        // Reinitialize the hot TLB to reflect changes in the shadow TLB and verify consistency
        init_hot_tlb_contents();
        return;
    }
    if (pmas_is_protected(ar.get_driver_id())) {
        throw std::invalid_argument{"attempted write to protected memory range "s.append(ar_descr)};
    }
    //??D In C++23, change this to use std::span and std::views::chunk std::views::drop/take and std::views::chain
    foreach_aligned_chunk(paddr, length, AR_PAGE_SIZE, [&ar, paddr, data](auto chunk_start, auto chunk_length) {
        const auto *src = data + (chunk_start - paddr);
        const auto offset = chunk_start - ar.get_start();
        auto *dest = ar.get_host_memory() + offset;
        if (memcmp(dest, src, chunk_length) != 0) {
            // Page is different, we have to copy memory
            memcpy(dest, src, chunk_length);
            ar.get_dirty_page_tree().mark_dirty_page_and_up(offset);
        }
    });
}

void machine::fill_memory(uint64_t paddr, uint8_t val, uint64_t length) {
    if (length == 0) {
        return;
    }
    auto &ar = m_ars.find(paddr, length);
    const auto *ar_descr = ar.get_description();
    if (ar.is_device()) {
        throw std::invalid_argument{"attempted fill to device memory range "s.append(ar_descr)};
    }
    if (!ar.is_memory()) {
        throw std::invalid_argument{"attempted fill is not entirely within single memory range"};
    }
    if (ar.is_host_read_only()) {
        throw std::invalid_argument{"attempted fill to host-read-only memory range "s.append(ar_descr)};
    }
    if (pmas_is_protected(ar.get_driver_id())) {
        throw std::invalid_argument{"attempted fill to protected memory range "s.append(ar_descr)};
    }
    // The case of filling a range with zeros is special and optimized for uarch reset
    //??D In C++23, change this to use std::span and std::views::chunk std::views::drop/take and std::views::chain
    foreach_aligned_chunk(paddr, length, AR_PAGE_SIZE, [&ar, val](auto chunk_start, auto chunk_length) {
        const auto offset = chunk_start - ar.get_start();
        const auto dest = ar.get_host_memory() + offset;
        if (val != 0 || !is_pristine(std::span<const unsigned char>{dest, static_cast<size_t>(chunk_length)})) {
            memset(dest, val, chunk_length);
            ar.get_dirty_page_tree().mark_dirty_page_and_up(offset);
        }
    });
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
    const uint64_t vaddr_page_start = vaddr_start & ~(AR_PAGE_SIZE - 1);                      // align page backward
    const uint64_t vaddr_page_limit = (vaddr_limit + AR_PAGE_SIZE - 1) & ~(AR_PAGE_SIZE - 1); // align page forward
    // copy page by page, because we need to perform address translation again for each page
    for (uint64_t vaddr_page = vaddr_page_start; vaddr_page < vaddr_page_limit; vaddr_page += AR_PAGE_SIZE) {
        uint64_t paddr_page = 0;
        if (!cartesi::translate_virtual_address<state_access, false>(a, &paddr_page, vaddr_page, PTE_XWR_R_SHIFT)) {
            throw std::domain_error{"page fault"};
        }
        uint64_t paddr = paddr_page;
        uint64_t vaddr = vaddr_page;
        uint64_t chunklen = std::min<uint64_t>(AR_PAGE_SIZE, vaddr_limit - vaddr);
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
    const uint64_t vaddr_page_start = vaddr_start & ~(AR_PAGE_SIZE - 1);                      // align page backward
    const uint64_t vaddr_page_limit = (vaddr_limit + AR_PAGE_SIZE - 1) & ~(AR_PAGE_SIZE - 1); // align page forward
    // copy page by page, because we need to perform address translation again for each page
    for (uint64_t vaddr_page = vaddr_page_start; vaddr_page < vaddr_page_limit; vaddr_page += AR_PAGE_SIZE) {
        uint64_t paddr_page = 0;
        // perform address translation using read access mode,
        // so we can write any reachable virtual memory range
        if (!cartesi::translate_virtual_address<state_access, false>(a, &paddr_page, vaddr_page, PTE_XWR_R_SHIFT)) {
            throw std::domain_error{"page fault"};
        }
        uint64_t paddr = paddr_page;
        uint64_t vaddr = vaddr_page;
        uint64_t chunklen = std::min<uint64_t>(AR_PAGE_SIZE, vaddr_limit - vaddr);
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
    if (paddr >= AR_SHADOW_REGISTERS_START && paddr - AR_SHADOW_REGISTERS_START < AR_SHADOW_REGISTERS_LENGTH) {
        auto reg = shadow_registers_get_what(paddr);
        if (reg == shadow_registers_what::unknown_) {
            throw std::runtime_error("unhandled write to shadow state");
        }
        write_reg(machine_reg_enum(reg), val);
        return;
    }
    // If in uarch shadow, forward to write_reg
    if (paddr >= AR_SHADOW_UARCH_STATE_START && paddr - AR_SHADOW_UARCH_STATE_START < AR_SHADOW_UARCH_STATE_LENGTH) {
        auto reg = shadow_uarch_state_get_what(paddr);
        if (reg == shadow_uarch_state_what::unknown_) {
            throw std::runtime_error("unhandled write to shadow uarch state");
        }
        write_reg(machine_reg_enum(reg), val);
        return;
    }
    auto &ar = m_ars.find(paddr, sizeof(uint64_t));
    if (!ar.is_memory() || ar.get_host_memory() == nullptr) {
        std::ostringstream err;
        err << "attempted memory write to " << ar.get_description() << " at address 0x" << std::hex << paddr << "("
            << std::dec << paddr << ")";
        throw std::runtime_error{err.str()};
    }
    if (ar.is_host_read_only()) {
        std::ostringstream err;
        err << "attempted memory write to read-only " << ar.get_description() << " at address 0x" << std::hex << paddr
            << "(" << std::dec << paddr << ")";
        throw std::runtime_error{err.str()};
    }
    if (pmas_is_protected(ar.get_driver_id())) {
        std::ostringstream err;
        err << "attempted memory word write to protected memory range " << ar.get_description() << " at address 0x"
            << std::hex << paddr << "(" << std::dec << paddr << ")";
        throw std::runtime_error{err.str()};
    }
    const auto offset = paddr - ar.get_start();
    aliased_aligned_write<uint64_t>(ar.get_host_memory() + offset, val);
    ar.get_dirty_page_tree().mark_dirty_page_and_up(offset);
}

void machine::send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length) {
    const state_access a(*this);
    cartesi::send_cmio_response(a, reason, data, length);
}

access_log machine::log_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const access_log::type &log_type) {
    if (m_c.hash_tree.hash_function != hash_function_type::keccak256) {
        throw std::runtime_error{
            "access logs can only be used with hash tree configured with Keccak-256 hash function"};
    }
    auto root_hash_before = get_root_hash();
    access_log log(log_type);
    // Call send_cmio_response  with the recording state accessor
    const record_send_cmio_state_access a(*this, log);
    {
        [[maybe_unused]] auto note = a.make_scoped_note("send_cmio_response");
        cartesi::send_cmio_response(a, reason, data, length);
    }
    auto root_hash_after = get_root_hash();
    verify_send_cmio_response(reason, data, length, root_hash_before, log, root_hash_after);
    return log;
}

void machine::verify_send_cmio_response(uint16_t reason, const unsigned char *data, uint64_t length,
    const machine_hash &root_hash_before, const access_log &log, const machine_hash &root_hash_after) {
    replay_send_cmio_state_access::context context{log, root_hash_before, hash_function_type::keccak256};
    // Verify all intermediate state transitions
    replay_send_cmio_state_access a(context);
    cartesi::send_cmio_response(a, reason, data, length);
    a.finish();
    // Make sure the access log ends at the same root hash as the state
    auto obtained_root_hash = a.get_root_hash();
    if (obtained_root_hash != root_hash_after) {
        throw std::invalid_argument{"mismatch in root hash after replay"};
    }
}

void machine::reset_uarch() {
    if (m_c.hash_tree.hash_function != hash_function_type::keccak256) {
        throw std::runtime_error{
            "microarchitecture can only be used with hash tree configured with Keccak-256 hash function"};
    }
    write_reg(reg::uarch_halt_flag, UARCH_HALT_FLAG_INIT);
    write_reg(reg::uarch_pc, UARCH_PC_INIT);
    write_reg(reg::uarch_cycle, UARCH_CYCLE_INIT);
    // General purpose registers
    for (int i = 1; i < UARCH_X_REG_COUNT; i++) {
        write_reg(machine_reg_enum(reg::uarch_x0, i), UARCH_X_INIT);
    }
    // Reset RAM to initial state
    write_memory(AR_UARCH_RAM_START, uarch_pristine_ram, uarch_pristine_ram_len);
    if (AR_UARCH_RAM_LENGTH > uarch_pristine_ram_len) {
        fill_memory(AR_UARCH_RAM_START + uarch_pristine_ram_len, 0, AR_UARCH_RAM_LENGTH - uarch_pristine_ram_len);
    }
}

access_log machine::log_reset_uarch(const access_log::type &log_type) {
    if (m_c.hash_tree.hash_function != hash_function_type::keccak256) {
        throw std::runtime_error{
            "microarchitecture can only be used with hash tree configured with Keccak-256 hash function"};
    }
    const machine_hash root_hash_before = get_root_hash();
    // Call uarch_reset_state with a uarch_record_state_access object
    access_log log(log_type);
    uarch_record_state_access a(*this, log);
    {
        [[maybe_unused]] auto note = a.make_scoped_note("reset_uarch_state");
        uarch_reset_state(a);
    }
    const auto root_hash_after = get_root_hash();
    verify_reset_uarch(root_hash_before, log, root_hash_after);
    return log;
}

void machine::verify_reset_uarch(const machine_hash &root_hash_before, const access_log &log,
    const machine_hash &root_hash_after) {
    // Verify all intermediate state transitions
    uarch_replay_state_access::context context{log, root_hash_before};
    uarch_replay_state_access a(context);
    uarch_reset_state(a);
    a.finish();
    // Make sure the access log ends at the same root hash as the state
    const machine_hash obtained_root_hash = a.get_root_hash();
    if (obtained_root_hash != root_hash_after) {
        throw std::invalid_argument{"mismatch in root hash after replay"};
    }
}

// Declaration of explicit instantiation in module uarch-step.cpp
extern template UArchStepStatus uarch_step(uarch_record_state_access &a);

access_log machine::log_step_uarch(const access_log::type &log_type) {
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error("microarchitecture cannot be used with unreproducible machines");
    }
    if (m_c.hash_tree.hash_function != hash_function_type::keccak256) {
        throw std::runtime_error{
            "microarchitecture can only be used with hash tree configured with Keccak-256 hash function"};
    }
    auto root_hash_before = get_root_hash();
    access_log log(log_type);
    // Call interpret with a logged state access object
    const uarch_record_state_access a(*this, log);
    {
        [[maybe_unused]] auto note = a.make_scoped_note("step");
        uarch_step(a);
    }
    // Verify access log before returning
    auto root_hash_after = get_root_hash();
    os_silence_putchar(m_r.htif.no_console_putchar);
    verify_step_uarch(root_hash_before, log, root_hash_after);
    return log;
}

// Declaration of explicit instantiation in module uarch-step.cpp
extern template UArchStepStatus uarch_step(uarch_replay_state_access &a);

void machine::verify_step_uarch(const machine_hash &root_hash_before, const access_log &log,
    const machine_hash &root_hash_after) {
    // Verify all intermediate state transitions
    uarch_replay_state_access::context context{log, root_hash_before};
    uarch_replay_state_access a(context);
    uarch_step(a);
    a.finish();
    // Make sure the access log ends at the same root hash as the state
    auto obtained_root_hash = a.get_root_hash();
    if (obtained_root_hash != root_hash_after) {
        throw std::invalid_argument{"mismatch in root hash after replay"};
    }
}

machine_config machine::get_default_config() {
    return machine_config{};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
uarch_interpreter_break_reason machine::run_uarch(uint64_t uarch_cycle_end) {
    if (m_c.hash_tree.hash_function != hash_function_type::keccak256) {
        throw std::runtime_error{
            "microarchitecture can only be used with hash tree configured with Keccak-256 hash function"};
    }
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error("microarchitecture cannot be used with unreproducible machines");
    }
    const uarch_state_access a(*this);
    os_silence_putchar(m_r.htif.no_console_putchar);
    return uarch_interpret(a, uarch_cycle_end);
}

interpreter_break_reason machine::log_step(uint64_t mcycle_count, const std::string &filename) {
    if (read_reg(reg::uarch_cycle) != 0) {
        throw std::runtime_error{"microarchitecture is not reset"};
    }
    auto root_hash_before = get_root_hash();
    record_step_state_access::context context(filename, m_c.hash_tree.hash_function);
    record_step_state_access a(context, *this);
    const uint64_t mcycle_end = saturating_add(a.read_mcycle(), mcycle_count);
    os_silence_putchar(m_r.htif.no_console_putchar);
    auto break_reason = interpret(a, mcycle_end);
    a.finish();
    auto root_hash_after = get_root_hash();
    verify_step(root_hash_before, filename, mcycle_count, root_hash_after);
    return break_reason;
}

interpreter_break_reason machine::verify_step(const machine_hash &root_hash_before, const std::string &filename,
    uint64_t mcycle_count, const machine_hash &root_hash_after) {
    auto data_length = os::file_size(filename);
    auto data = make_unique_mmap<unsigned char>(data_length, os_mmap_flags{}, filename, data_length);
    replay_step_state_access::context context;
    replay_step_state_access a(context, data.get(), data_length, root_hash_before);
    const uint64_t mcycle_end = saturating_add(a.read_mcycle(), mcycle_count);
    auto break_reason = interpret(a, mcycle_end);
    a.finish(root_hash_after);
    return break_reason;
}

interpreter_break_reason machine::run(uint64_t mcycle_end) {
    const auto mcycle = read_reg(reg::mcycle);
    if (mcycle_end < mcycle) {
        throw std::invalid_argument{"mcycle is past"};
    }
    const auto uarch_cycle = read_reg(reg::uarch_cycle);
    if (uarch_cycle != 0) {
        throw std::invalid_argument{"microarchitecture is not reset"};
    }
    const state_access a(*this);
    os_silence_putchar(m_r.htif.no_console_putchar);
    return interpret(a, mcycle_end);
}

//??D How come this function seems to never signal we have an inteerrupt???
std::pair<uint64_t, execute_status> machine::poll_external_interrupts(uint64_t mcycle, uint64_t mcycle_max) {
    const auto status = execute_status::success;
    // Only poll external interrupts if we are in unreproducible mode
    if (unlikely(m_s->shadow.registers.iunrep)) {
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
            const uint64_t elapsed_us = static_cast<uint64_t>(std::max<int64_t>(end_us - start_us, 0));
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

mcycle_root_hashes machine::collect_mcycle_root_hashes(uint64_t mcycle_end, uint64_t mcycle_period,
    uint64_t mcycle_phase, int32_t log2_bundle_mcycle_count,
    const std::optional<back_merkle_tree> &previous_back_tree) {
    const uint64_t mcycle_start = read_reg(reg::mcycle);

    // Check preconditions
    if (mcycle_end < mcycle_start) {
        throw std::runtime_error{"mcycle is past"};
    }
    if (mcycle_period == 0) {
        throw std::runtime_error{"mcycle_period cannot be 0"};
    }
    if (mcycle_phase >= mcycle_period) {
        throw std::runtime_error{"mcycle_phase must be in {0, ..., mcycle_period-1}"};
    }
    if (previous_back_tree.has_value() &&
        (previous_back_tree->get_log2_max_leaves() != log2_bundle_mcycle_count ||
            previous_back_tree->get_hash_function() != m_c.hash_tree.hash_function)) {
        throw std::runtime_error{"back tree context is incompatible"};
    }
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error{"cannot collect hashes from unreproducible machines"};
    }
    if (m_r.soft_yield) {
        throw std::runtime_error{"cannot collect hashes when soft yield is enabled"};
    }
    if (!update_hash_tree()) {
        throw std::runtime_error{"update hash tree failed"};
    }
    if (read_reg(reg::uarch_cycle) != 0) {
        throw std::runtime_error{"microarchitecture is not reset"};
    }

    // If the collection loop does not advance mcycle, keep the original mcycle_phase
    // and set the break reason to indicate the target mcycle was reached
    mcycle_root_hashes result;
    result.mcycle_phase = mcycle_phase;
    result.break_reason = interpreter_break_reason::reached_target_mcycle;

    // Check halted and yielded break reasons first to behave with same priority as the interpreter
    if (read_reg(reg::iflags_H) != 0) {
        result.break_reason = interpreter_break_reason::halted;
        return result;
    }
    if (read_reg(reg::iflags_Y) != 0) {
        result.break_reason = interpreter_break_reason::yielded_manually;
        return result;
    }

    // Initialize back tree
    if (previous_back_tree.has_value()) {
        result.back_tree = *previous_back_tree;
    } else {
        result.back_tree = back_merkle_tree{log2_bundle_mcycle_count, m_c.hash_tree.hash_function};
    }
    auto &back_tree = result.back_tree.value();

    collect_mcycle_hashes_state_access::context context{};
    const collect_mcycle_hashes_state_access a(context, *this);
    os_silence_putchar(m_r.htif.no_console_putchar);

    // Reserve space before entering the loop to minimize dynamic memory allocations,
    // the reserved sizes below are based on empirical benchmarks to balance performance and memory usage,
    // and are clamped to avoid over-allocation
    const uint64_t max_result_hashes =
        ((mcycle_end - mcycle_start) / (mcycle_period * (UINT64_C(1) << log2_bundle_mcycle_count))) + 1;
    result.hashes.reserve(std::clamp<uint64_t>(max_result_hashes, 1, 16384));
    context.dirty_pages.reserve(std::clamp<uint64_t>(mcycle_period * 4, 16, 4096));

    // The first iteration will target the next mcycle_period boundary,
    // but will not exceed mcycle_end if that limit is reached first
    uint64_t mcycle_target = saturating_add(mcycle_start, mcycle_period - mcycle_phase, mcycle_end);
    uint64_t mcycle_reached = read_reg(reg::mcycle);
    bool at_fixed_point = false;

    // Run until reaching next mcycle target
    while (mcycle_reached < mcycle_target) {
        assert(!at_fixed_point);

        // Attempt to execute until finishing this period
        result.break_reason = interpret(a, mcycle_target);

        // Mark dirty pages tracked by the context
        for (const uint64_t paddr_page : context.dirty_pages) {
            auto &ar = find_address_range(paddr_page, HASH_TREE_PAGE_SIZE);
            ar.get_dirty_page_tree().mark_dirty_pages_and_up(paddr_page - ar.get_start(), HASH_TREE_PAGE_SIZE);
        }
        context.dirty_pages.clear();

        // Update hash tree and retrieve root hash
        if (!m_ht.update(m_ars)) {
            throw std::runtime_error{"update hash tree failed"};
        }

        mcycle_reached = read_reg(reg::mcycle);

        // Check if we reached a fixed point
        at_fixed_point = result.break_reason == interpreter_break_reason::halted ||
            result.break_reason == interpreter_break_reason::yielded_manually || mcycle_reached == UINT64_MAX;

        // Compute the new phase
        result.mcycle_phase = (((mcycle_reached - mcycle_start) % mcycle_period) + mcycle_phase) % mcycle_period;

        // Add the current root hash to the back tree whenever we reach a period boundary or a fixed point
        // This ensures we only append at the correct intervals, even when mcycle_end does not align with the period
        if (result.mcycle_phase == 0 || at_fixed_point) {
            // Append root hash relative to this period to the result
            back_tree.push_back(m_ht.get_root_hash());

            // When back tree is full, we can append the bundled root hash and reset it
            if (back_tree.full()) {
                result.hashes.emplace_back(back_tree.get_root_hash());
                back_tree.clear();
            }
        }

        // If last iteration broke due to any other reason than reaching its target mcycle, we are done
        if (at_fixed_point || result.break_reason != interpreter_break_reason::reached_target_mcycle) {
            break;
        }

        // The next iteration will target the next mcycle_period boundary,
        // but will not exceed mcycle_end if that limit is reached first
        mcycle_target = saturating_add(mcycle_target, mcycle_period, mcycle_end);
    }

    // If the machine yielded manually or halted, then append bundled root hashes with padding
    if (at_fixed_point && log2_bundle_mcycle_count > 0) {
        // Construct pad tree containing repetitions of the current root hash
        const auto pad_hashes = back_merkle_tree::make_pad_hashes(m_ht.get_root_hash(), log2_bundle_mcycle_count,
            m_c.hash_tree.hash_function);

        // Pad back tree when partially filled and append its bundled root hash
        if (!back_tree.empty()) {
            assert(!back_tree.full());
            back_tree.pad_back(back_tree.get_remaining_leaf_count(), pad_hashes);
            result.hashes.emplace_back(back_tree.get_root_hash());
            back_tree.clear();
        }

        // Append bundled root hash containing only repetitions of the last root hash
        result.hashes.emplace_back(pad_hashes[log2_bundle_mcycle_count]);
    }

    // There is no need to return the back tree when it's empty
    if (back_tree.empty()) {
        result.back_tree.reset();
    }

    return result;
}

uarch_cycle_root_hashes machine::collect_uarch_cycle_root_hashes(uint64_t mcycle_end,
    int32_t log2_bundle_uarch_cycle_count) {
    const uint64_t mcycle_start = read_reg(reg::mcycle);

    // Check preconditions
    if (mcycle_end < mcycle_start) {
        throw std::runtime_error{"mcycle is past"};
    }
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error{"cannot collect hashes from unreproducible machines"};
    }
    if (m_r.soft_yield) {
        throw std::runtime_error{"cannot collect hashes when soft yield is enabled"};
    }
    if (m_c.hash_tree.hash_function != hash_function_type::keccak256) {
        throw std::runtime_error{
            "microarchitecture can only be used with hash tree configured with Keccak-256 hash function"};
    }
    if (!update_hash_tree()) {
        throw std::runtime_error{"update hash tree failed"};
    }
    if (read_reg(reg::uarch_cycle) != 0) {
        throw std::runtime_error{"microarchitecture is not reset"};
    }

    // If the collection loop does not advance mcycle, set the break reason to indicate the target mcycle was reached
    uarch_cycle_root_hashes result;
    result.break_reason = interpreter_break_reason::reached_target_mcycle;

    // Initialize back tree
    back_merkle_tree back_tree(log2_bundle_uarch_cycle_count, m_c.hash_tree.hash_function);

    hash_tree::dirty_words_type reset_dirty_words;
    collect_uarch_cycle_hashes_state_access::context context{};
    const collect_uarch_cycle_hashes_state_access a(context, *this);
    os_silence_putchar(m_r.htif.no_console_putchar);

    // Reserve space before entering the loop to minimize dynamic memory allocations,
    // the reserved sizes below are based on empirical benchmarks to balance performance and memory usage
    const uint64_t mcycle_count = mcycle_end - mcycle_start;
    result.hashes.reserve(mcycle_count * 512);
    result.reset_indices.reserve(mcycle_count);
    context.dirty_words.reserve(8);
    reset_dirty_words.reserve(64);

    // The first iteration will target the next mcycle,
    // but will not exceed mcycle_end if that limit is reached first
    uint64_t mcycle_target = saturating_add(mcycle_start, UINT64_C(1), mcycle_end);
    uint64_t mcycle_reached = read_reg(reg::mcycle);

    // In case we start at fixed point, we will attempt to execute one extra mcycle which
    bool at_fixed_point = read_reg(reg::iflags_H) != 0 || read_reg(reg::iflags_Y) != 0 || mcycle_start == UINT64_MAX;
    if (at_fixed_point) {
        mcycle_target = mcycle_reached;
    }

    // Run until reaching next mcycle target, or one more time when at a fixed point
    while (mcycle_reached < mcycle_target || at_fixed_point) {
        uint64_t uarch_cycle_reached = read_reg(reg::uarch_cycle);
        assert(back_tree.empty());
        assert(uarch_cycle_reached == 0);

        // Add one hash after each uarch cycle
        for (uint64_t uarch_cycle_target = 1;         // First uarch cycle target  should always be 1
            uarch_cycle_reached < uarch_cycle_target; // Run until reaching uarch cycle target
            ++uarch_cycle_target) {
            // Attempt to advance to the next uarch cycle
            const auto uarch_break_reason = uarch_interpret(a, uarch_cycle_target);
            uarch_cycle_reached = read_reg(reg::uarch_cycle);

            // Update hash tree and retrieve root hash
            if (!m_ht.update_words(m_ars, context.dirty_words)) {
                throw std::runtime_error{"update hash tree failed"};
            }

            // Track dirty uarch words to be reset later
            for (auto word_paddr : context.dirty_words) {
                if (word_paddr >= UARCH_STATE_START_ADDRESS &&
                    word_paddr - UARCH_STATE_START_ADDRESS < UARCH_STATE_LENGTH) {
                    reset_dirty_words.insert(word_paddr);
                }
            }
            context.dirty_words.clear();

            // If the uarch cycle counter overflows, this is catastrophic and machine execution cannot continue
            if (uarch_break_reason == uarch_interpreter_break_reason::cycle_overflow) {
                throw std::runtime_error{"uarch reached its maximum cycle and cannot advance more uarch cycles"};
            }
            // If the uarch is halted, we can break the loop
            if (uarch_break_reason == uarch_interpreter_break_reason::uarch_halted) {
                break;
            }

            // Sanity check to ensure the loop is working correctly, this should always be true
            assert(uarch_cycle_reached == uarch_cycle_target);
            assert(uarch_break_reason == uarch_interpreter_break_reason::reached_target_cycle);

            // Append root hash to the result
            back_tree.push_back(m_ht.get_root_hash());

            // When back tree is full, we can append the bundled root hash and reset it
            if (back_tree.full()) {
                result.hashes.emplace_back(back_tree.get_root_hash());
                back_tree.clear();
            }
        }

        // Sanity check to ensure the loop is working correctly, this should always be true
        assert(read_reg(reg::uarch_halt_flag) != 0);

        const auto halt_root_hash = m_ht.get_root_hash();

        // Perform reset uarch directly (as an optimization), we need to only revert dirty words in its state
        // Reset uarch registers
        m_us->registers = uarch_registers_state{};
        // Reset dirty words in uarch ram
        auto &uram = find_address_range(AR_UARCH_RAM_START, AR_UARCH_RAM_LENGTH);
        for (auto word_paddr : reset_dirty_words) {
            if (word_paddr >= AR_UARCH_RAM_START && word_paddr - AR_UARCH_RAM_START < AR_UARCH_RAM_LENGTH) {
                const uint64_t word_start_offset = word_paddr - AR_UARCH_RAM_START;
                // Word is aligned and inside range, there can be no overflow
                const uint64_t word_end_offset = word_start_offset + HASH_TREE_WORD_SIZE;
                if (word_end_offset <= uarch_pristine_ram_len) { // Word is entirely inside pristine uarch ram image
                    std::memcpy(uram.get_host_memory() + word_start_offset, uarch_pristine_ram + word_start_offset,
                        HASH_TREE_WORD_SIZE);
                } else if (word_start_offset >= uarch_pristine_ram_len) { // Word is entirely outside image
                    std::memset(uram.get_host_memory() + word_start_offset, 0, HASH_TREE_WORD_SIZE);
                } else { // Word stradles image boundary
                    std::memcpy(uram.get_host_memory() + word_start_offset, uarch_pristine_ram + word_start_offset,
                        uarch_pristine_ram_len - word_start_offset);
                    std::memset(uram.get_host_memory() + uarch_pristine_ram_len, 0,
                        word_end_offset - uarch_pristine_ram_len);
                }
            }
        }
        // Update hash tree and retrieve root hash
        if (!m_ht.update_words(m_ars, reset_dirty_words)) {
            throw std::runtime_error{"update hash tree failed"};
        }
        reset_dirty_words.clear();
        const auto reset_root_hash = m_ht.get_root_hash();

        // Add one hash after the uarch reset
        if (log2_bundle_uarch_cycle_count > 0) {
            const auto halt_pad_hashes = back_merkle_tree::make_pad_hashes(halt_root_hash,
                log2_bundle_uarch_cycle_count, m_c.hash_tree.hash_function);

            // Pad back tree when partially filled and then append its bundled root hash
            if (!back_tree.empty()) {
                assert(!back_tree.full());
                back_tree.pad_back(back_tree.get_remaining_leaf_count(), halt_pad_hashes);
                result.hashes.emplace_back(back_tree.get_root_hash());
                back_tree.clear();
            }

            // Append bundled root hash containing only repetitions of the halt root hash
            result.hashes.emplace_back(halt_pad_hashes[log2_bundle_uarch_cycle_count]);

            // Append bundled root hash containing repetitions of the halt root hash on the left
            // and one reset root hash on the right
            assert(back_tree.empty());
            back_tree.pad_back((1 << log2_bundle_uarch_cycle_count) - 1, halt_pad_hashes);
            back_tree.push_back(reset_root_hash);
            assert(back_tree.full());
            result.hashes.emplace_back(back_tree.get_root_hash());
            back_tree.clear();

            // Add the index where reset happened
            result.reset_indices.emplace_back(result.hashes.size() - 1);
        } else {
            result.hashes.push_back(reset_root_hash);

            // Add the index where reset happened
            result.reset_indices.emplace_back(result.hashes.size() - 1);
        }

        mcycle_reached = read_reg(reg::mcycle);

        // Sanity check to ensure the loop is working correctly, this should always be true
        assert(mcycle_reached == mcycle_target);

        // Retrieve break reason
        if (read_reg(reg::iflags_H) != 0) {
            result.break_reason = interpreter_break_reason::halted;
        } else if (read_reg(reg::iflags_Y) != 0) {
            result.break_reason = interpreter_break_reason::yielded_manually;
        } else if (read_reg(reg::iflags_X) != 0) {
            result.break_reason = interpreter_break_reason::yielded_automatically;
            break;
        }

        // If we already attempted to advance one mcycle over a fixed point, we are done
        if (at_fixed_point) {
            break;
        }

        // If the machine halted, yielded manuallly or reached mcycle UINT64_MAX,
        // then we are at a fixed point and should always attempt to advance one more mcycle
        at_fixed_point = result.break_reason == interpreter_break_reason::halted ||
            result.break_reason == interpreter_break_reason::yielded_manually || mcycle_reached == UINT64_MAX;

        if (!at_fixed_point) {
            // The next iteration will target the next mcycle successor,
            // but will not exceed mcycle_end if that limit is reached first
            mcycle_target = saturating_add(mcycle_target, UINT64_C(1), mcycle_end);
        }
    }

    assert(back_tree.empty());

    return result;
}

} // namespace cartesi
