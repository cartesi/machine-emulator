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

/// \file
/// \brief Shared utilities for fuzz harnesses.
///
/// Provides the fuzz input reader, constants, and machine setup logic
/// used by all fuzz targets.

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <machine-c-api.h>
#include <pmas.h>
#include <processor-state.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <json.hpp>

// Constants

static constexpr uint64_t RAM_START = CM_AR_RAM_START;   // 0x80000000
static constexpr uint64_t RAM_LENGTH = 1U << 22;         // 4 MiB — room for page tables + code
static constexpr uint64_t MAX_MCYCLE = 2000;              // bound execution

// SV39 constants (from riscv-constants.h)
static constexpr uint64_t SATP_MODE_SV39 = UINT64_C(8) << 60;
static constexpr int LOG2_PAGE_SIZE = 12;
static constexpr uint64_t PAGE_SIZE = UINT64_C(1) << LOG2_PAGE_SIZE;
static constexpr uint64_t PTE_V = UINT64_C(1) << 0;
static constexpr uint64_t PTE_R = UINT64_C(1) << 1;
static constexpr uint64_t PTE_W = UINT64_C(1) << 2;
static constexpr uint64_t PTE_X = UINT64_C(1) << 3;
static constexpr uint64_t PTE_U = UINT64_C(1) << 4;
static constexpr uint64_t PTE_A = UINT64_C(1) << 6;
static constexpr uint64_t PTE_D = UINT64_C(1) << 7;

// RAM layout:
//   [RAM_START .. +PAGE_TABLE_REGION)  page tables (3 pages = 12 KiB)
//   [CODE_START .. +code_size)         fuzzed instructions
static constexpr uint64_t PAGE_TABLE_REGION = 3 * PAGE_SIZE; // 3 pages for SV39 3-level tables
static constexpr uint64_t CODE_START = RAM_START + PAGE_TABLE_REGION;

// Fuzz input reader

struct fuzz_reader {
    const uint8_t *data;
    size_t remaining;

    template <typename T>
    T read() {
        T val{};
        const auto n = std::min(sizeof(T), remaining);
        std::memcpy(&val, data, n);
        data += n;
        remaining -= n;
        return val;
    }

    void read_bytes(void *dst, size_t n) {
        n = std::min(n, remaining);
        std::memcpy(dst, data, n);
        data += n;
        remaining -= n;
    }

    void skip(size_t n) {
        n = std::min(n, remaining);
        data += n;
        remaining -= n;
    }
};

/// \brief Reads fuzzed register state from the input.
/// \param r Fuzz reader to consume bytes from.
/// \param regs Output registers_state, filled from fuzz data.
/// \param enable_vm Output flag: whether virtual memory should be enabled.
/// \details Reads a registers_state directly from the fuzz input, then
/// derives control flags (privilege level, VM mode, MPRV, SUM, MXR, FS)
/// from the first two bytes of the input, adjusting mstatus accordingly.
/// The struct layout matches the shadow state exactly, so the same bytes
/// can be used both for cm_write_reg (fuzz-interpret) and for direct
/// shadow state writes (fuzz-shadow-state).
static void fuzz_read_registers(fuzz_reader &r, cartesi::registers_state &regs, bool &enable_vm) {
    // Read the control bytes first (consumed before registers)
    const uint8_t priv_byte = r.read<uint8_t>();
    const uint8_t flags_byte = r.read<uint8_t>();

    // Read the entire registers_state from fuzz input
    r.read_bytes(&regs, sizeof(regs));

    // Derive control flags
    static constexpr uint64_t priv_map[] = {0 /*U*/, 1 /*S*/, 3 /*M*/, 3 /*M*/};
    const uint64_t priv = priv_map[priv_byte & 0x3];

    enable_vm = (flags_byte & 0x01) != 0;
    const bool enable_mprv = (flags_byte & 0x02) != 0;
    const bool enable_sum = (flags_byte & 0x04) != 0;
    const bool enable_mxr = (flags_byte & 0x08) != 0;
    const bool enable_fs = (flags_byte & 0x10) != 0;

    // Apply control flags to mstatus
    regs.mstatus = (regs.mstatus & ~(UINT64_C(3) << 11)) | (priv << 11);
    if (enable_mprv) {
        regs.mstatus |= (UINT64_C(1) << 17);
    } else {
        regs.mstatus &= ~(UINT64_C(1) << 17);
    }
    if (enable_sum) {
        regs.mstatus |= (UINT64_C(1) << 18);
    } else {
        regs.mstatus &= ~(UINT64_C(1) << 18);
    }
    if (enable_mxr) {
        regs.mstatus |= (UINT64_C(1) << 19);
    } else {
        regs.mstatus &= ~(UINT64_C(1) << 19);
    }
    if (enable_fs) {
        regs.mstatus |= (UINT64_C(3) << 13);
    }

    // Set privilege level
    regs.iprv = priv;

    // PC always points to the code region
    regs.pc = CODE_START;

    // mcycle starts at 0
    regs.mcycle = 0;

    // Ensure the machine is not halted or yielded, otherwise cm_run returns immediately
    regs.iflags.H = 0;
    regs.iflags.Y = 0;
}

/// \brief Writes registers from a registers_state to a machine via cm_write_reg.
/// \param machine Target machine.
/// \param regs Source register values.
static void fuzz_write_registers_to_machine(cm_machine *machine, const cartesi::registers_state &regs) {
    // GPRs (x0 is read-only, skip it)
    for (int i = 1; i < 32; i++) {
        cm_write_reg(machine, static_cast<cm_reg>(CM_REG_X0 + i), regs.x[i]);
    }

    // FPRs
    for (int i = 0; i < 32; i++) {
        cm_write_reg(machine, static_cast<cm_reg>(CM_REG_F0 + i), regs.f[i]);
    }
    cm_write_reg(machine, CM_REG_FCSR, regs.fcsr);

    // CSRs
    cm_write_reg(machine, CM_REG_MSTATUS, regs.mstatus);
    cm_write_reg(machine, CM_REG_MEDELEG, regs.medeleg);
    cm_write_reg(machine, CM_REG_MIDELEG, regs.mideleg);
    cm_write_reg(machine, CM_REG_MIE, regs.mie);
    cm_write_reg(machine, CM_REG_MIP, regs.mip);
    cm_write_reg(machine, CM_REG_MTVEC, regs.mtvec);
    cm_write_reg(machine, CM_REG_MSCRATCH, regs.mscratch);
    cm_write_reg(machine, CM_REG_MEPC, regs.mepc);
    cm_write_reg(machine, CM_REG_MCAUSE, regs.mcause);
    cm_write_reg(machine, CM_REG_MTVAL, regs.mtval);
    cm_write_reg(machine, CM_REG_MENVCFG, regs.menvcfg);
    cm_write_reg(machine, CM_REG_STVEC, regs.stvec);
    cm_write_reg(machine, CM_REG_SSCRATCH, regs.sscratch);
    cm_write_reg(machine, CM_REG_SEPC, regs.sepc);
    cm_write_reg(machine, CM_REG_SCAUSE, regs.scause);
    cm_write_reg(machine, CM_REG_STVAL, regs.stval);
    cm_write_reg(machine, CM_REG_SENVCFG, regs.senvcfg);
    cm_write_reg(machine, CM_REG_MCOUNTEREN, regs.mcounteren);
    cm_write_reg(machine, CM_REG_SCOUNTEREN, regs.scounteren);
    cm_write_reg(machine, CM_REG_SATP, regs.satp);

    // Cartesi-specific
    cm_write_reg(machine, CM_REG_IPRV, regs.iprv);
    cm_write_reg(machine, CM_REG_PC, regs.pc);
    cm_write_reg(machine, CM_REG_MCYCLE, regs.mcycle);
    cm_write_reg(machine, CM_REG_ILRSC, regs.ilrsc);
    cm_write_reg(machine, CM_REG_ICYCLEINSTRET, regs.icycleinstret);
    cm_write_reg(machine, CM_REG_IUNREP, regs.iunrep);

    // iflags
    cm_write_reg(machine, CM_REG_IFLAGS_H, regs.iflags.H);
    cm_write_reg(machine, CM_REG_IFLAGS_Y, regs.iflags.Y);
    cm_write_reg(machine, CM_REG_IFLAGS_X, regs.iflags.X);

    // CLINT
    cm_write_reg(machine, CM_REG_CLINT_MTIMECMP, regs.clint.mtimecmp);

    // PLIC
    cm_write_reg(machine, CM_REG_PLIC_GIRQPEND, regs.plic.girqpend);
    cm_write_reg(machine, CM_REG_PLIC_GIRQSRVD, regs.plic.girqsrvd);

    // HTIF
    cm_write_reg(machine, CM_REG_HTIF_TOHOST, regs.htif.tohost);
    cm_write_reg(machine, CM_REG_HTIF_FROMHOST, regs.htif.fromhost);
    cm_write_reg(machine, CM_REG_HTIF_IHALT, regs.htif.ihalt);
    cm_write_reg(machine, CM_REG_HTIF_ICONSOLE, regs.htif.iconsole);
    cm_write_reg(machine, CM_REG_HTIF_IYIELD, regs.htif.iyield);
}

/// \brief Creates a machine with fuzzed state from the fuzz input.
/// \param r Fuzz reader to consume bytes from.
/// \param regs Register state (already read via fuzz_read_registers).
/// \param enable_vm Whether to set up SV39 virtual memory.
/// \returns Pointer to the new machine, or nullptr on failure.
/// \details Sets up RAM (page tables + code), writes registers via cm_write_reg.
/// The caller is responsible for calling cm_delete().
static cm_machine *fuzz_create_machine(fuzz_reader &r, const cartesi::registers_state &regs, bool enable_vm) {
    // Page table entries (when VM enabled)
    uint8_t pt_data[PAGE_TABLE_REGION] = {};
    size_t pt_data_size = 0;
    if (enable_vm) {
        pt_data_size = std::min(r.remaining, sizeof(pt_data));
        r.read_bytes(pt_data, pt_data_size);
    }

    // Remaining = code/data
    const uint8_t *code_data = r.data;
    const size_t code_size = r.remaining;

    if (code_size < 4) {
        return nullptr; // need at least one instruction
    }

    // Create machine
    nlohmann::json config;
    config["ram"]["length"] = RAM_LENGTH;
    const auto config_str = config.dump();

    cm_machine *machine = nullptr;
    if (cm_create_new(config_str.c_str(), nullptr, nullptr, &machine) != CM_ERROR_OK) {
        return nullptr;
    }

    // Write page tables into RAM
    if (enable_vm && pt_data_size > 0) {
        cm_write_memory(machine, RAM_START, pt_data, pt_data_size);

        const uint64_t root_ppn = (RAM_START) >> LOG2_PAGE_SIZE;
        const uint64_t l1_page_addr = RAM_START + PAGE_SIZE;
        const uint64_t l0_page_addr = RAM_START + 2 * PAGE_SIZE;
        const uint64_t code_ppn = CODE_START >> LOG2_PAGE_SIZE;

        const int vpn2 = static_cast<int>((CODE_START >> 30) & 0x1FF);
        const int vpn1 = static_cast<int>((CODE_START >> 21) & 0x1FF);
        const int vpn0 = static_cast<int>((CODE_START >> 12) & 0x1FF);

        const uint64_t l2_pte = PTE_V | ((l1_page_addr >> LOG2_PAGE_SIZE) << 10);
        cm_write_memory(machine, RAM_START + vpn2 * 8, reinterpret_cast<const uint8_t *>(&l2_pte), 8);

        const uint64_t l1_pte = PTE_V | ((l0_page_addr >> LOG2_PAGE_SIZE) << 10);
        cm_write_memory(machine, l1_page_addr + vpn1 * 8, reinterpret_cast<const uint8_t *>(&l1_pte), 8);

        const uint64_t l0_pte = PTE_V | PTE_R | PTE_W | PTE_X | PTE_U | PTE_A | PTE_D | (code_ppn << 10);
        cm_write_memory(machine, l0_page_addr + vpn0 * 8, reinterpret_cast<const uint8_t *>(&l0_pte), 8);

        cm_write_reg(machine, CM_REG_SATP, SATP_MODE_SV39 | root_ppn);
    }

    // Write code into RAM
    const auto write_len = std::min(code_size, static_cast<size_t>(RAM_LENGTH - PAGE_TABLE_REGION));
    if (write_len > 0) {
        cm_write_memory(machine, CODE_START, code_data, write_len);
    }

    // Write registers
    fuzz_write_registers_to_machine(machine, regs);

    return machine;
}

/// \brief Info about a PMA discovered from the machine's PMA array.
struct pma_info {
    uint64_t index;  ///< PMA index (for shadow TLB slot)
    uint64_t start;  ///< Physical start address
    uint64_t length; ///< Length in bytes
    bool is_memory;  ///< True if memory-backed (M flag set)
};

/// \brief Reads the PMA array from a machine and returns info about all non-empty PMAs.
static std::vector<pma_info> fuzz_discover_pmas(cm_machine *machine) {
    using namespace cartesi;
    pmas_state pmas{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    cm_read_memory(machine, AR_PMAS_START_DEF, reinterpret_cast<uint8_t *>(&pmas), sizeof(pmas));

    std::vector<pma_info> result;
    for (uint64_t i = 0; i < PMA_MAX; i++) {
        uint64_t start = 0;
        const auto flags = pmas_unpack_istart(pmas[i].istart, start);
        const uint64_t length = pmas[i].ilength;
        if (length == 0 && start == 0) {
            continue;
        }
        result.push_back({i, start, length, flags.M});
    }
    return result;
}

/// \brief Crafts a single TLB slot entry targeting a specific PMA.
/// \param slot_index The TLB slot index — vaddr_page is crafted to match it.
/// \param vaddr_bits Fuzz-provided upper bits for the virtual address.
/// \param page_select Fuzz-provided value to select a page within the PMA.
/// \param pma Target PMA to map to.
/// \returns A shadow_tlb_slot that will pass verification for memory PMAs.
static cartesi::shadow_tlb_slot fuzz_craft_valid_tlb_slot(uint64_t slot_index, uint64_t vaddr_bits,
    uint64_t page_select, const pma_info &pma) {
    const uint64_t vaddr_page = ((vaddr_bits >> 20) << 20) | (slot_index << LOG2_PAGE_SIZE);
    const uint64_t num_pages = pma.length / PAGE_SIZE;
    const uint64_t target_page = num_pages > 0 ? (page_select % num_pages) * PAGE_SIZE : 0;
    const uint64_t paddr_page = pma.start + target_page;
    return {vaddr_page, paddr_page - vaddr_page, pma.index, 0};
}

/// \brief Crafts a TLB slot for a known virtual address (e.g. CODE_START or a GPR value).
/// \param vaddr The virtual address to create a mapping for.
/// \param pma Target PMA to map to.
/// \param page_select Fuzz-provided value to select a page within the PMA.
/// \returns A shadow_tlb_slot whose vaddr_page matches tlb_slot_index(vaddr).
static cartesi::shadow_tlb_slot fuzz_craft_targeted_tlb_slot(uint64_t vaddr, const pma_info &pma,
    uint64_t page_select) {
    const uint64_t vaddr_page = vaddr & ~static_cast<uint64_t>(cartesi::PAGE_OFFSET_MASK);
    const uint64_t num_pages = pma.length / PAGE_SIZE;
    const uint64_t target_page = num_pages > 0 ? (page_select % num_pages) * PAGE_SIZE : 0;
    const uint64_t paddr_page = pma.start + target_page;
    return {vaddr_page, paddr_page - vaddr_page, pma.index, 0};
}

/// \brief Fills a shadow TLB state with fuzz-driven entries targeting discovered PMAs.
/// \param r Fuzz reader for TLB control data.
/// \param regs Register state — GPR values are used to create targeted TLB entries
///        for addresses the interpreter will actually access.
/// \param pmas Discovered PMAs from the machine.
/// \param tlb Output TLB state to fill.
/// \details
/// The code TLB (set 0) gets a targeted entry for CODE_START's page (controlled by
/// a fuzz bit — sometimes omitted to exercise instruction fetch page walks).
///
/// The read and write TLB sets (sets 1-2) get targeted entries for pages derived
/// from GPR values, since those are addresses load/store instructions will use.
/// A fuzz bit per GPR controls whether an entry is placed (hit) or omitted (miss).
///
/// Remaining slots are filled based on a fuzz byte selector:
///   0x00-0xAF (68.75%): valid memory-backed PMA entry
///   0xB0-0xCF (12.5%): non-memory PMA entry (should fail verification)
///   0xD0-0xDF (6.25%): out-of-bounds pma_index (tests bounds checking)
///   0xE0-0xFF (12.5%): completely raw fuzz bytes (various validation failures)
static void fuzz_fill_tlb(fuzz_reader &r, const cartesi::registers_state &regs,
    const std::vector<pma_info> &pmas, cartesi::shadow_tlb_state &tlb) {
    // Separate memory and non-memory PMAs
    std::vector<const pma_info *> mem_pmas;
    std::vector<const pma_info *> dev_pmas;
    for (const auto &p : pmas) {
        if (p.is_memory && p.length >= PAGE_SIZE) {
            mem_pmas.push_back(&p);
        } else if (!p.is_memory) {
            dev_pmas.push_back(&p);
        }
    }

    // Control bits for targeted entries
    const uint64_t control = r.read<uint64_t>();

    // Code TLB (set 0): targeted entry for CODE_START
    if ((control & 1) && !mem_pmas.empty()) {
        const auto slot_idx = cartesi::tlb_slot_index(CODE_START);
        const auto *pma = mem_pmas[r.read<uint8_t>() % mem_pmas.size()];
        tlb[cartesi::TLB_CODE][slot_idx] = fuzz_craft_targeted_tlb_slot(CODE_START, *pma, r.read<uint64_t>());
    }

    // Read/Write TLB (sets 1-2): targeted entries for GPR-derived addresses
    for (int xi = 1; xi < 32; xi++) {
        if (!((control >> xi) & 1) || mem_pmas.empty()) {
            continue;
        }
        const uint64_t vaddr = regs.x[xi];
        const auto slot_idx = cartesi::tlb_slot_index(vaddr);
        const auto *pma = mem_pmas[r.read<uint8_t>() % mem_pmas.size()];
        const uint64_t page_sel = r.read<uint64_t>();
        // Place in both read and write TLB sets
        tlb[cartesi::TLB_READ][slot_idx] = fuzz_craft_targeted_tlb_slot(vaddr, *pma, page_sel);
        tlb[cartesi::TLB_WRITE][slot_idx] = fuzz_craft_targeted_tlb_slot(vaddr, *pma, page_sel);
    }

    // Fill remaining empty slots with fuzz-driven entries
    for (auto &set : tlb) {
        for (uint64_t i = 0; i < set.size(); i++) {
            auto &slot = set[i];
            // Skip slots already populated by targeted entries
            if (slot.vaddr_page != cartesi::TLB_INVALID_PAGE) {
                continue;
            }

            const uint8_t selector = r.read<uint8_t>();
            const uint64_t vaddr_bits = r.read<uint64_t>();
            const uint64_t page_select = r.read<uint64_t>();

            if (selector < 0xB0 && !mem_pmas.empty()) {
                // Valid memory-backed entry
                const auto *pma = mem_pmas[selector % mem_pmas.size()];
                slot = fuzz_craft_valid_tlb_slot(i, vaddr_bits, page_select, *pma);
            } else if (selector < 0xD0 && !dev_pmas.empty()) {
                // Non-memory PMA — should be rejected by verification
                const auto *pma = dev_pmas[selector % dev_pmas.size()];
                const uint64_t vaddr_page = ((vaddr_bits >> 20) << 20) | (i << LOG2_PAGE_SIZE);
                slot.vaddr_page = vaddr_page;
                slot.vp_offset = pma->start - vaddr_page;
                slot.pma_index = pma->index;
                slot.zero_padding_ = 0;
            } else if (selector < 0xE0) {
                // Out-of-bounds pma_index
                const uint64_t vaddr_page = ((vaddr_bits >> 20) << 20) | (i << LOG2_PAGE_SIZE);
                slot.vaddr_page = vaddr_page;
                slot.vp_offset = page_select;
                slot.pma_index = 0xFF + selector;
                slot.zero_padding_ = 0;
            } else {
                // Completely raw — random bytes, various validation failures
                slot.vaddr_page = vaddr_bits;
                slot.vp_offset = page_select;
                slot.pma_index = selector;
                slot.zero_padding_ = vaddr_bits & 0xFF;
            }
        }
    }
}

#endif // FUZZ_COMMON_H
