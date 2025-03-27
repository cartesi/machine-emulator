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
#include <bit>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

#include "access-log.h"
#include "address-range-constants.h"
#include "address-range.h"
#include "compiler-defines.h"
#include "device-state-access.h"
#include "dtb.h"
#include "host-addr.h"
#include "hot-tlb.h"
#include "htif-constants.h"
#include "i-device-state-access.h"
#include "i-hasher.h"
#include "interpret.h"
#include "is-pristine.h"
#include "machine-config.h"
#include "machine-reg.h"
#include "machine-runtime-config.h"
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
#include "send-cmio-response.h"
#include "shadow-tlb.h"
#include "state-access.h"
#include "strict-aliasing.h"
#include "translate-virtual-address.h"
#include "uarch-constants.h"
#include "uarch-interpret.h"
#include "uarch-pristine-state-hash.h"
#include "uarch-record-state-access.h"
#include "uarch-replay-state-access.h"
#include "uarch-reset-state.h"
#include "uarch-state-access.h"
#include "uarch-step.h"
#include "unique-c-ptr.h"
#include "virtio-address-range.h"

/// \file
/// \brief Cartesi machine implementation

namespace cartesi {

using namespace std::string_literals;

void machine::init_uarch_processor(const uarch_processor_config &p) {
    if (p.backing_store.data_filename.empty() || p.backing_store.create) {
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
}

void machine::init_processor(processor_config &p, const machine_runtime_config &r) {
    if (p.backing_store.data_filename.empty() || p.backing_store.create) {
        // Initialize to default values first
        *m_s = processor_state{};

        // Initialize registers
        if (p.registers.marchid == UINT64_C(-1)) {
            p.registers.marchid = MARCHID_INIT;
        }

        if (p.registers.marchid != MARCHID_INIT && !r.skip_version_check) {
            throw std::invalid_argument{"marchid mismatch, emulator version is incompatible"};
        }

        if (p.registers.mvendorid == UINT64_C(-1)) {
            p.registers.mvendorid = MVENDORID_INIT;
        }

        if (p.registers.mvendorid != MVENDORID_INIT && !r.skip_version_check) {
            throw std::invalid_argument{"mvendorid mismatch, emulator version is incompatible"};
        }

        if (p.registers.mimpid == UINT64_C(-1)) {
            p.registers.mimpid = MIMPID_INIT;
        }

        if (p.registers.mimpid != MIMPID_INIT && !r.skip_version_check) {
            throw std::invalid_argument{"mimpid mismatch, emulator version is incompatible"};
        }

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
}

void machine::init_pmas_contents(const pmas_config &config) {
    static_assert(sizeof(pmas_state) == PMA_MAX * 2 * sizeof(uint64_t), "inconsistent PMAs state length");
    static_assert(AR_PMAS_LENGTH >= sizeof(pmas_state), "PMAs address range too short");
    if (config.backing_store.data_filename.empty() || config.backing_store.create) {
        auto &pmas = m_ars.find(AR_PMAS_START, AR_PMAS_LENGTH);
        if (!pmas.is_memory()) {
            throw std::runtime_error{"initialization error: PMAs memory address range not found"};
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto &dest = *reinterpret_cast<pmas_state *>(pmas.get_host_memory());
        std::ranges::transform(m_ars.interpret(), dest.begin(),
            [](const auto &ar) { return pmas_entry{.istart = ar.get_istart(), .ilength = ar.get_ilength()}; });
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
    if (config.dtb.backing_store.data_filename.empty() || config.dtb.backing_store.create) {
        auto &dtb = m_ars.find(AR_DTB_START, AR_DTB_LENGTH);
        if (!dtb.is_memory()) {
            throw std::runtime_error{"initialization error: DTB memory address range not found"};
        }
        dtb_init(config, dtb.get_host_memory(), dtb.get_length());
    }
}

// ??D It is best to leave the std::move() on r because it may one day be necessary!
machine::machine(machine_config c, machine_runtime_config r) :
    m_c{std::move(c)}, // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
    m_r{std::move(r)}, // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
    m_ars{m_c},
    m_s{std::bit_cast<processor_state *>(m_ars.find(AR_SHADOW_STATE_START, AR_SHADOW_STATE_LENGTH).get_host_memory())},
    m_us{std::bit_cast<uarch_processor_state *>(
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
    for (auto &v : m_ars.virtio()) {
        v.prepare_select(fds, timeout_us);
    }
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
bool machine::poll_selected_virtio_devices(int select_ret, select_fd_sets *fds, i_device_state_access *da) {
    bool interrupt_requested = false; // NOLINT(misc-const-correctness)
    for (auto &v : m_ars.virtio()) {
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
    return !m_ars.virtio().empty();
}

bool machine::has_virtio_console() const {
    // When present, the console device is guaranteed to be the first VirtIO device,
    // therefore we only need to check the first device.
    return has_virtio_devices() && m_ars.virtio().front().get_device_id() == VIRTIO_DEVICE_CONSOLE;
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

uint64_t machine::get_paddr(host_addr haddr, uint64_t pma_index) const {
    return static_cast<uint64_t>(haddr + get_hp_offset(pma_index));
}

host_addr machine::get_host_addr(uint64_t paddr, uint64_t pma_index) const {
    return host_addr{paddr} - get_hp_offset(pma_index);
}

void machine::mark_dirty_page(uint64_t paddr, uint64_t pma_index) {
    auto &ar = read_pma(pma_index);
    ar.mark_dirty_page(paddr - ar.get_start());
}

void machine::mark_dirty_page(host_addr haddr, uint64_t pma_index) {
    auto paddr = get_paddr(haddr, pma_index);
    mark_dirty_page(paddr, pma_index);
}

uint64_t machine::read_shadow_tlb(TLB_set_index set_index, uint64_t slot_index, shadow_tlb_what reg) const {
    switch (reg) {
        case shadow_tlb_what::vaddr_page:
            return m_s->shadow.tlb[set_index][slot_index].vaddr_page;
        case shadow_tlb_what::vp_offset:
            return m_s->shadow.tlb[set_index][slot_index].vp_offset;
        case shadow_tlb_what::pma_index:
            return m_s->shadow.tlb[set_index][slot_index].pma_index;
        case shadow_tlb_what::zero_padding_:
            return m_s->shadow.tlb[set_index][slot_index].zero_padding_;
        default:
            throw std::domain_error{"unknown shadow TLB register"};
    }
}

void machine::write_tlb(TLB_set_index set_index, uint64_t slot_index, uint64_t vaddr_page, host_addr vh_offset,
    uint64_t pma_index) {
    uint64_t vp_offset = 0;
    if (vaddr_page != TLB_INVALID_PAGE) {
        vp_offset = get_paddr(vh_offset, pma_index);
    }
    m_s->penumbra.tlb[set_index][slot_index].vaddr_page = vaddr_page;
    m_s->penumbra.tlb[set_index][slot_index].vh_offset = vh_offset;
    m_s->shadow.tlb[set_index][slot_index].vaddr_page = vaddr_page;
    m_s->shadow.tlb[set_index][slot_index].vp_offset = vp_offset;
    m_s->shadow.tlb[set_index][slot_index].pma_index = pma_index;
    m_s->shadow.tlb[set_index][slot_index].zero_padding_ = 0;
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
    const auto &ar = read_pma(pma_index);
    if (!ar.is_memory()) {
        throw std::domain_error{"PMA index is not of memory range ("s + ar.get_description() + ")"};
    }
    auto haddr = cast_ptr_to_host_addr(ar.get_host_memory());
    auto paddr = ar.get_start();
    return paddr - haddr;
}

static void store_hash(const machine::hash_type &h, const std::string &dir) {
    auto name = dir + "/hash";
    auto fp = make_unique_fopen(name.c_str(), "wb");
    if (fwrite(h.data(), 1, h.size(), fp.get()) != h.size()) {
        throw std::runtime_error{"error writing to '" + name + "'"};
    }
}

void machine::store_address_ranges(const machine_config &c, const std::string &dir) const {
    store_address_range(m_ars.find<uint64_t>(AR_DTB_START), dir);
    store_address_range(m_ars.find<uint64_t>(AR_RAM_START), dir);
    store_address_range(m_ars.find<uint64_t>(AR_SHADOW_STATE_START), dir);
    for (const auto &f : c.flash_drive) {
        store_address_range(m_ars.find<uint64_t>(f.start), dir);
    }
    store_address_range(m_ars.find<uint64_t>(AR_CMIO_RX_BUFFER_START), dir);
    store_address_range(m_ars.find<uint64_t>(AR_CMIO_TX_BUFFER_START), dir);
    store_address_range(m_ars.find<uint64_t>(AR_SHADOW_UARCH_STATE_START), dir);
    store_address_range(m_ars.find<uint64_t>(AR_UARCH_RAM_START), dir);
    store_address_range(m_ars.find<uint64_t>(AR_PMAS_START), dir);
}

void machine::store_address_range(const address_range &ar, const std::string &dir) {
    if (ar.is_empty()) {
        throw std::runtime_error{"attempt to store empty address range "s.append(ar.get_description())};
    }
    auto name = machine_config::get_data_filename(dir, ar.get_start(), ar.get_length());
    auto fp = make_unique_fopen(name.c_str(), "wb"); // will throw if it fails
    if (!ar.is_memory() || ar.get_host_memory() == nullptr) {
        throw std::runtime_error{"attempt to store non memory address range "s.append(ar.get_description())};
    }
    if (fwrite(ar.get_host_memory(), 1, ar.get_length(), fp.get()) != ar.get_length()) {
        throw std::runtime_error{"error writing to '" + name + "'"};
    }
}

void machine::store(const std::string &dir) const {
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error{"cannot store unreproducible machines"};
    }
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
    machine_config c = m_c;
    c.adjust_backing_stores(".");
    c.store(dir);
    store_address_ranges(c, dir);
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
#if DUMP_STATS
    const auto hr = [](uint64_t a, uint64_t b) {
        // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
        return static_cast<double>(b) / (a + b);
    };

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
            ar.mark_dirty_page(paddr_page - ar.get_start());
        }
    }
}

bool machine::verify_dirty_page_maps() const {
    static_assert(AR_PAGE_SIZE == machine_merkle_tree::get_page_size(),
        "PMA and machine_merkle_tree page sizes must match");
    machine_merkle_tree::hasher_type h;
    auto scratch = make_unique_calloc<unsigned char>(AR_PAGE_SIZE, std::nothrow_t{});
    if (!scratch) {
        return false;
    }
    bool broken = false;
    // Go over the write TLB and mark as dirty all pages currently there
    mark_write_tlb_dirty_pages();
    // Now go over all memory PMAs verifying that all dirty pages are marked
    for (const auto &ar : m_ars.all()) {
        for (uint64_t page_address = ar.get_start(); page_address < ar.get_end(); page_address += AR_PAGE_SIZE) {
            const auto offset = page_address - ar.get_start();
            if (ar.is_memory()) {
                const unsigned char *page_data = nullptr;
                ar.peek(*this, offset, AR_PAGE_SIZE, &page_data, scratch.get());
                hash_type stored;
                hash_type real;
                m_t.get_page_node_hash(page_address, stored);
                m_t.get_page_node_hash(h, page_data, real);
                const bool marked_dirty = ar.is_page_marked_dirty(offset);
                const bool is_dirty = (real != stored);
                if (is_dirty && !marked_dirty) {
                    broken = true;
                    std::cerr << std::setfill('0') << std::setw(8) << std::hex << page_address
                              << " should have been dirty\n";
                    std::cerr << "  expected " << stored << '\n';
                    std::cerr << "  got " << real << '\n';
                    break;
                }
            } else if (ar.is_device()) {
                if (!ar.is_page_marked_dirty(offset)) {
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
    static_assert(AR_PAGE_SIZE == machine_merkle_tree::get_page_size(),
        "PMA and machine_merkle_tree page sizes must match");
    // Go over the write TLB and mark as dirty all pages currently there
    mark_write_tlb_dirty_pages();
    // Now go over all PMAs and updating the Merkle tree
    m_t.begin_update();
    for (auto &ar : m_ars.merkle()) {
        // Each PMA has a number of pages
        auto pages_in_range = (ar.get_length() + AR_PAGE_SIZE - 1) / AR_PAGE_SIZE;
        // For each PMA, we launch as many threads (n) as defined on concurrency
        // runtime config or as the hardware supports.
        const uint64_t n = get_task_concurrency(m_r.concurrency.update_merkle_tree);
        const bool succeeded = os_parallel_for(n, [&](int j, const parallel_for_mutex &mutex) -> bool {
            auto scratch = make_unique_calloc<unsigned char>(AR_PAGE_SIZE, std::nothrow_t{});
            if (!scratch) {
                return false;
            }
            machine_merkle_tree::hasher_type h;
            // Thread j is responsible for page i if i % n == j.
            for (uint64_t i = j; i < pages_in_range; i += n) {
                const uint64_t page_start_in_range = i * AR_PAGE_SIZE;
                const uint64_t page_address = ar.get_start() + page_start_in_range;
                const unsigned char *page_data = nullptr;
                // Skip any clean pages
                if (!ar.is_page_marked_dirty(page_start_in_range)) {
                    continue;
                }
                // If the peek failed, or if it returned a page for update but
                // we failed updating it, the entire process failed
                if (!ar.peek(*this, page_start_in_range, AR_PAGE_SIZE, &page_data, scratch.get())) {
                    return false;
                }
                if (page_data != nullptr) {
                    if (is_pristine(page_data, AR_PAGE_SIZE)) {
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
        ar.mark_pages_clean();
    }
    const bool ret = m_t.end_update(gh);
    return ret;
}

bool machine::update_merkle_tree_page(uint64_t address) {
    static_assert(AR_PAGE_SIZE == machine_merkle_tree::get_page_size(),
        "PMA and machine_merkle_tree page sizes must match");
    // Align address to beginning of page
    address &= ~(AR_PAGE_SIZE - 1);
    auto &ar = m_ars.find<uint8_t>(address);
    const uint64_t page_start_in_range = address - ar.get_start();
    machine_merkle_tree::hasher_type h;
    auto scratch = make_unique_calloc<unsigned char>(AR_PAGE_SIZE, std::nothrow_t{});
    if (!scratch) {
        return false;
    }
    m_t.begin_update();
    const unsigned char *page_data = nullptr;
    if (!ar.peek(*this, page_start_in_range, AR_PAGE_SIZE, &page_data, scratch.get())) {
        m_t.end_update(h);
        return false;
    }
    if (page_data != nullptr) {
        const uint64_t page_address = ar.get_start() + page_start_in_range;
        hash_type hash;
        m_t.get_page_node_hash(h, page_data, hash);
        if (!m_t.update_page_node_hash(page_address, hash)) {
            m_t.end_update(h);
            return false;
        }
    }
    ar.mark_clean_page(page_start_in_range);
    return m_t.end_update(h);
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
    static_assert(AR_PAGE_SIZE == machine_merkle_tree::get_page_size(),
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
    // If proof concerns range smaller than a page, we may need to rebuild part of the proof from
    // the contents of a page inside some PMA range.
    // PMA range starts and lengths are multiple of the page size, which is a power of 2.
    // The size of the desired range is smaller than the page size, but its size is a power of 2,
    // and it is aligned to its size.
    // Therefore, it is is either entirely inside a PMA range, or entirely outside it.
    if (log2_size < machine_merkle_tree::get_log2_page_size()) {
        const uint64_t length = UINT64_C(1) << log2_size;
        const auto &ar = m_ars.find(address, length);
        auto scratch = make_unique_calloc<unsigned char>(AR_PAGE_SIZE);
        const unsigned char *page_data = nullptr;
        // If the PMA range is empty, we know the desired range is entirely outside of any non-pristine PMA.
        // Therefore, the entire page where it lies is also pristine.
        // Otherwise, the entire desired range is inside it.
        if (!ar.is_empty()) {
            const uint64_t page_start_in_range = (address - ar.get_start()) & (~(AR_PAGE_SIZE - 1));
            if (!ar.peek(*this, page_start_in_range, AR_PAGE_SIZE, &page_data, scratch.get())) {
                throw std::runtime_error{"PMA peek failed"};
            }
        }
        return m_t.get_proof(address, log2_size, page_data);
        // If proof concerns range bigger than a page, we already have its hash stored in the tree itself
    }
    return m_t.get_proof(address, log2_size, nullptr);
}

machine_merkle_tree::proof_type machine::get_proof(uint64_t address, int log2_size) const {
    if (!update_merkle_tree()) {
        throw std::runtime_error{"error updating Merkle tree"};
    }
    return get_proof(address, log2_size, skip_merkle_tree_update);
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

void machine::read_memory(uint64_t paddr, unsigned char *data, uint64_t length) const {
    if (length == 0) {
        return;
    }
    if (data == nullptr) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    uint64_t gap_start = 0;
    auto view = m_ars.merkle() |
        std::views::drop_while([paddr, &gap_start](const address_range &ar) { // Only those that end after paddr
            const auto ar_end = ar.get_end();
            if (paddr >= ar_end) {
                gap_start = ar_end;
                return true;
            }
            return false;
        });
    for (auto &ar : view) {
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
            const unsigned char *peek_data = nullptr;
            if (!ar.peek(*this, paddr - ar_start, from_ar, &peek_data, data)) {
                throw std::runtime_error{"peek failed"};
            }
            if (peek_data == nullptr) {
                // If the chunk is pristine, copy zero data to buffer
                memset(data, 0, from_ar);
            } else if (peek_data != data) {
                // If peek returned pointer to internal buffer, copy to data buffer
                memcpy(data, peek_data, from_ar);
            }
            // Otherwise, peek already copied to data buffer
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

void machine::write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
    if (length == 0) {
        return;
    }
    if (data == nullptr) {
        throw std::invalid_argument{"invalid data buffer"};
    }
    auto &ar = m_ars.find(paddr, length);
    if (ar.is_device()) {
        throw std::invalid_argument{"attempted write to device memory range"};
    }
    if (!ar.is_memory()) {
        throw std::invalid_argument{"address range to write is not entirely in single memory range"};
    }
    if (ar.is_host_read_only()) {
        throw std::invalid_argument{"address range to write is read-only in the host"};
    }
    foreach_aligned_chunk(paddr, length, AR_PAGE_SIZE, [&ar, paddr, data](auto chunk_start, auto chunk_length) {
        const auto *src = data + (chunk_start - paddr);
        const auto offset = chunk_start - ar.get_start();
        auto *dest = ar.get_host_memory() + offset;
        if (memcmp(dest, src, chunk_length) != 0) {
            // Page is different, we have to copy memory
            memcpy(dest, src, chunk_length);
            ar.mark_dirty_page(offset);
        }
    });
    if (pmas_range_overlaps(paddr, length, AR_SHADOW_TLB_START, AR_SHADOW_TLB_LENGTH)) {
        // Must reinitialize hot TLB again to reflect changes in the shadow TLB
        init_hot_tlb_contents();
    }
}

void machine::fill_memory(uint64_t paddr, uint8_t val, uint64_t length) {
    if (length == 0) {
        return;
    }
    auto &ar = m_ars.find(paddr, length);
    if (ar.is_device()) {
        throw std::invalid_argument{"attempted fill to device memory range"};
    }
    if (!ar.is_memory()) {
        throw std::invalid_argument{"address range to fill is not entirely in memory PMA"};
    }
    if (ar.is_host_read_only()) {
        throw std::invalid_argument{"address range is read-only in the host"};
    }
    if (pmas_range_overlaps(paddr, length, AR_SHADOW_TLB_START, AR_SHADOW_TLB_LENGTH)) {
        // Filling shadow TLB memory doesn't make sense because it would leave
        // its state corrupted in most situations.
        throw std::invalid_argument{"attempted fill to shadow TLB memory range"};
    }
    // The case of filling a range with zeros is special and optimized for uarch reset
    foreach_aligned_chunk(paddr, length, AR_PAGE_SIZE, [&ar, val](auto chunk_start, auto chunk_length) {
        const auto offset = chunk_start - ar.get_start();
        const auto dest = ar.get_host_memory() + offset;
        if (val != 0 || !is_pristine(dest, chunk_length)) {
            memset(dest, val, chunk_length);
            ar.mark_dirty_page(offset);
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
    if (pmas_range_overlaps(paddr, sizeof(uint64_t), AR_SHADOW_TLB_START, AR_SHADOW_TLB_LENGTH)) {
        // Writing a single word to shadow TLB memory is not supported,
        // it would leave corrupt its state in most situations.
        throw std::invalid_argument{"attempted memory word write to shadow TLB memory range"};
    }
    const auto offset = paddr - ar.get_start();
    aliased_aligned_write<uint64_t>(ar.get_host_memory() + offset, val);
    ar.mark_dirty_page(offset);
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
    if (read_reg(reg::iunrep) != 0) {
        throw std::runtime_error("microarchitecture cannot be used with unreproducible machines");
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
    os_silence_putchar(m_r.htif.no_console_putchar);
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
    const uarch_state_access a(*this);
    os_silence_putchar(m_r.htif.no_console_putchar);
    return uarch_interpret(a, uarch_cycle_end);
}

interpreter_break_reason machine::log_step(uint64_t mcycle_count, const std::string &filename) {
    if (!update_merkle_tree()) {
        throw std::runtime_error{"error updating Merkle tree"};
    }
    // Ensure that the microarchitecture is reset
    auto current_uarch_state_hash =
        get_merkle_tree_node_hash(AR_SHADOW_UARCH_STATE_START, UARCH_STATE_LOG2_SIZE, skip_merkle_tree_update);
    if (current_uarch_state_hash != uarch_pristine_state_hash) {
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
    os_silence_putchar(m_r.htif.no_console_putchar);
    verify_step(root_hash_before, filename, mcycle_count, root_hash_after);
    return break_reason;
}

interpreter_break_reason machine::verify_step(const hash_type &root_hash_before, const std::string &filename,
    uint64_t mcycle_count, const hash_type &root_hash_after) {
    auto data_length = os_get_file_length(filename.c_str(), "step log file");
    auto data = make_unique_mmap<unsigned char>(data_length, os_mmap_flags{}, filename, data_length);
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
