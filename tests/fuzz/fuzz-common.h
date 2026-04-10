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
/// All fuzz targets consume their input in the same order:
///
///   Offset  Size     Field
///   0       1        Privilege byte (2 bits used: U/S/M)
///   1       1        Flags byte (VM, MPRV, SUM, MXR, FS)
///   2       848      registers_state struct (GPRs, FPRs, CSRs, etc.)
///   850     0/20480  Page table data (5 pages, only when VM enabled)
///   ...     varies   Code/data (written at CODE_START in RAM)
///
/// The code region also doubles as TLB seed data: the fuzz reader is NOT
/// advanced past it, so fuzz_fill_tlb() reuses the same bytes. This gives
/// TLB entries diverse, input-dependent values without needing extra bytes.
///
/// Machine state is divided into two parts:
///   - RAM: holds code and (when VM enabled) SV39 page tables.
///   - Shadow state: holds all registers and the TLB. The shadow is the
///     emulator's authoritative state; writing it as a bulk block also
///     reinitializes the hot TLB cache.
///
/// Callers set up RAM first (via fuzz_create_machine or manual writes),
/// then build a shadow_state struct and write it in one cm_write_memory() call.

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <cm.h>
#include <pmas.hpp>
#include <processor-state.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <json.hpp>

#include <cstdio>
#include <cstdlib>

/// \brief Abort with a message (signals a bug to libFuzzer).
[[noreturn]] static void fuzz_abort(const char *msg) {
    fprintf(stderr, "FUZZ BUG: %s\n", msg);
    abort();
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

static constexpr uint64_t RAM_START = CM_AR_RAM_START;   // 0x80000000
static constexpr uint64_t RAM_LENGTH = 1U << 16;         // 64 KiB (small for fast zeroing)
static constexpr uint64_t MAX_MCYCLE = 2000;              // execution budget per input

// SV39 virtual memory constants
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

// RAM layout when VM is enabled (SV39 three-level page table):
//   page 0: L2 root page table
//   page 1: L1 page table (user space)
//   page 2: L1 page table (ext I/O)
//   page 3: L1 page table (kernel)
//   page 4: L0 leaf page table (user space)
//   page 5+: fuzzed code/data at CODE_START
static constexpr uint64_t PAGE_TABLE_REGION = 5 * PAGE_SIZE;
static constexpr uint64_t CODE_START = RAM_START + PAGE_TABLE_REGION;

// ---------------------------------------------------------------------------
// Fuzz input reader
// ---------------------------------------------------------------------------

/// \brief Sequential reader over a fuzz input byte array.
/// All read methods are safe: if not enough bytes remain, the output is
/// zero-padded. This means the fuzzer can always make progress even with
/// short inputs.
struct fuzz_reader {
    const uint8_t *data;
    size_t remaining;

    /// Read a value of type T, zero-padded if the input is too short.
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

// ---------------------------------------------------------------------------
// Register parsing
// ---------------------------------------------------------------------------

/// \brief Decode the first part of a fuzz input into a registers_state.
///
/// Reads 2 control bytes (privilege level, VM/MPRV/SUM/MXR/FS flags) followed
/// by the raw registers_state struct. The control bytes override specific mstatus
/// fields and iprv so the fuzzer can reliably explore all privilege modes and
/// VM configurations without needing to discover the right mstatus encoding.
static void fuzz_read_registers(fuzz_reader &r, cartesi::registers_state &regs, bool &enable_vm) {
    const uint8_t priv_byte = r.read<uint8_t>();
    const uint8_t flags_byte = r.read<uint8_t>();

    // Read the full register struct from fuzz data
    r.read_bytes(&regs, sizeof(regs));

    // Map 2-bit privilege selector to RISC-V privilege levels (U=0, S=1, M=3)
    static constexpr uint64_t priv_map[] = {0 /*U*/, 1 /*S*/, 3 /*M*/, 3 /*M*/};
    const uint64_t priv = priv_map[priv_byte & 0x3];

    // Extract individual feature flags
    enable_vm = (flags_byte & 0x01) != 0;
    const bool enable_mprv = (flags_byte & 0x02) != 0;
    const bool enable_sum = (flags_byte & 0x04) != 0;
    const bool enable_mxr = (flags_byte & 0x08) != 0;
    const bool enable_fs = (flags_byte & 0x10) != 0;

    // Patch mstatus with the control flags
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

    regs.iprv = priv;
    regs.mcycle = 0;
    regs.iflags.H = 0; // not halted
    regs.iflags.Y = 0; // not yielded
}

// ---------------------------------------------------------------------------
// Machine creation (fresh mode only)
// ---------------------------------------------------------------------------

/// \brief Create a new machine and write page tables + code into RAM.
///
/// Registers and TLB are NOT set here. The caller must build a shadow_state
/// and write it via cm_write_memory() after this returns.
///
/// The fuzz reader is NOT advanced past the code bytes (see file-level comment).
static cm_machine *fuzz_create_machine(fuzz_reader &r, bool enable_vm) {
    uint8_t pt_data[PAGE_TABLE_REGION] = {};
    size_t pt_data_size = 0;
    if (enable_vm) {
        pt_data_size = std::min(r.remaining, sizeof(pt_data));
        r.read_bytes(pt_data, pt_data_size);
    }

    const uint8_t *code_data = r.data;
    const size_t code_size = r.remaining;

    if (code_size < 4) {
        return nullptr;
    }

    nlohmann::json config;
    config["ram"]["length"] = RAM_LENGTH;
    const auto config_str = config.dump();

    cm_machine *machine = nullptr;
    if (cm_create_new(config_str.c_str(), nullptr, nullptr, &machine) != CM_ERROR_OK) {
        return nullptr;
    }

    // Write page tables and overlay PTEs for CODE_START
    if (enable_vm && pt_data_size > 0) {
        cm_write_memory(machine, RAM_START, pt_data, pt_data_size);

        const uint64_t l1_page_addr = RAM_START + 1 * PAGE_SIZE;
        const uint64_t l0_page_addr = RAM_START + 4 * PAGE_SIZE;
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

    }

    const auto write_len = std::min(code_size, static_cast<size_t>(RAM_LENGTH - PAGE_TABLE_REGION));
    if (write_len > 0) {
        cm_write_memory(machine, CODE_START, code_data, write_len);
    }

    return machine;
}

// ---------------------------------------------------------------------------
// PMA discovery
// ---------------------------------------------------------------------------

/// \brief Info about a Physical Memory Attribute region.
/// PMAs define the machine's physical address map: which ranges exist,
/// whether they are memory-backed or device I/O, and their permissions.
struct pma_info {
    uint64_t index;  ///< PMA index (used in TLB slots to identify the region)
    uint64_t start;  ///< Physical start address
    uint64_t length; ///< Length in bytes
    bool is_memory;  ///< True if memory-backed (M flag), false if device I/O
};

/// \brief Read the machine's PMA array and return info about all active regions.
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

// ---------------------------------------------------------------------------
// TLB construction
// ---------------------------------------------------------------------------
//
// The emulator has a two-level TLB:
//   - Shadow TLB: stored in the shadow state, part of the machine's verifiable
//     state. Contains {vaddr_page, vp_offset, pma_index} per slot.
//   - Hot TLB: a host-side runtime cache derived from the shadow TLB. Contains
//     host pointers for fast memory access. Rebuilt lazily after shadow writes.
//
// The interpreter checks the hot TLB on every memory access. A hit means a
// direct host-memory access; a miss triggers a full page walk through the
// SV39 page tables. By fuzzing the shadow TLB contents we exercise both
// the fast path (valid entries) and the slow path (invalid/mismatched entries
// that fail verification and force page walks).
//
// Three TLB sets exist: CODE (instruction fetch), READ, and WRITE.
// Each set has 256 slots, indexed by bits [19:12] of the virtual address.

/// \brief Craft a valid shadow TLB slot for a given slot index.
/// The vaddr_page is constructed so that its slot index bits match the slot,
/// while the upper bits come from fuzz data for diversity.
static cartesi::shadow_tlb_slot fuzz_craft_valid_tlb_slot(uint64_t slot_index, uint64_t vaddr_bits,
    uint64_t page_select, const pma_info &pma) {
    const uint64_t vaddr_page = ((vaddr_bits >> 20) << 20) | (slot_index << LOG2_PAGE_SIZE);
    const uint64_t num_pages = pma.length / PAGE_SIZE;
    const uint64_t target_page = num_pages > 0 ? (page_select % num_pages) * PAGE_SIZE : 0;
    const uint64_t paddr_page = pma.start + target_page;
    return {vaddr_page, paddr_page - vaddr_page, pma.index, 0};
}

/// \brief Craft a shadow TLB slot for a specific virtual address.
/// Used to pre-populate TLB entries for addresses the interpreter is likely
/// to access (e.g. CODE_START for instruction fetch, GPR values for loads/stores).
static cartesi::shadow_tlb_slot fuzz_craft_targeted_tlb_slot(uint64_t vaddr, const pma_info &pma,
    uint64_t page_select) {
    const uint64_t vaddr_page = vaddr & ~static_cast<uint64_t>(cartesi::PAGE_OFFSET_MASK);
    const uint64_t num_pages = pma.length / PAGE_SIZE;
    const uint64_t target_page = num_pages > 0 ? (page_select % num_pages) * PAGE_SIZE : 0;
    const uint64_t paddr_page = pma.start + target_page;
    return {vaddr_page, paddr_page - vaddr_page, pma.index, 0};
}

/// \brief Fill all shadow TLB slots from fuzz data.
///
/// Strategy:
///   1. A fuzz uint64_t provides per-bit control over targeted entries.
///   2. Bit 0: whether to place a CODE TLB entry for CODE_START.
///      Omitting it forces instruction-fetch page walks.
///   3. Bits 1-31: whether to place READ/WRITE entries for each GPR's value.
///      These are the addresses load/store instructions will use.
///   4. Remaining empty slots are filled based on a fuzz byte selector:
///        0x00-0xAF (68.75%): valid entry pointing to a memory-backed PMA
///        0xB0-0xCF (12.5%): entry pointing to a device PMA (fails verification)
///        0xD0-0xDF (6.25%): out-of-bounds pma_index (tests bounds checking)
///        0xE0-0xFF (12.5%): raw fuzz bytes (various validation failures)
///
/// This mix ensures the fuzzer explores TLB hits, misses, verification
/// failures, and bounds checks in proportion to their importance.
static void fuzz_fill_tlb(fuzz_reader &r, const cartesi::registers_state &regs,
    const std::vector<pma_info> &pmas, cartesi::shadow_tlb_state &tlb) {
    // Partition PMAs into memory-backed (valid TLB targets) and device I/O
    std::vector<const pma_info *> mem_pmas;
    std::vector<const pma_info *> dev_pmas;
    for (const auto &p : pmas) {
        if (p.is_memory && p.length >= PAGE_SIZE) {
            mem_pmas.push_back(&p);
        } else if (!p.is_memory) {
            dev_pmas.push_back(&p);
        }
    }

    const uint64_t control = r.read<uint64_t>();

    // Targeted CODE TLB entry for instruction fetch
    if ((control & 1) && !mem_pmas.empty()) {
        const auto slot_idx = cartesi::tlb_slot_index(CODE_START);
        const auto *pma = mem_pmas[r.read<uint8_t>() % mem_pmas.size()];
        tlb[cartesi::TLB_CODE][slot_idx] = fuzz_craft_targeted_tlb_slot(CODE_START, *pma, r.read<uint64_t>());
    }

    // Targeted READ/WRITE TLB entries for GPR-derived addresses
    for (int xi = 1; xi < 32; xi++) {
        if (!((control >> xi) & 1) || mem_pmas.empty()) {
            continue;
        }
        const uint64_t vaddr = regs.x[xi];
        const auto slot_idx = cartesi::tlb_slot_index(vaddr);
        const auto *pma = mem_pmas[r.read<uint8_t>() % mem_pmas.size()];
        const uint64_t page_sel = r.read<uint64_t>();
        tlb[cartesi::TLB_READ][slot_idx] = fuzz_craft_targeted_tlb_slot(vaddr, *pma, page_sel);
        tlb[cartesi::TLB_WRITE][slot_idx] = fuzz_craft_targeted_tlb_slot(vaddr, *pma, page_sel);
    }

    // Fill remaining empty slots with fuzz-driven entries of varying validity
    for (auto &set : tlb) {
        for (uint64_t i = 0; i < set.size(); i++) {
            auto &slot = set[i];
            if (slot.vaddr_page != cartesi::TLB_INVALID_PAGE) {
                continue; // already populated by a targeted entry
            }

            const uint8_t selector = r.read<uint8_t>();
            const uint64_t vaddr_bits = r.read<uint64_t>();
            const uint64_t page_select = r.read<uint64_t>();

            if (selector < 0xB0 && !mem_pmas.empty()) {
                // Valid memory-backed entry
                const auto *pma = mem_pmas[selector % mem_pmas.size()];
                slot = fuzz_craft_valid_tlb_slot(i, vaddr_bits, page_select, *pma);
            } else if (selector < 0xD0 && !dev_pmas.empty()) {
                // Device PMA entry (should fail TLB verification)
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
                // Raw fuzz bytes (various validation failures)
                slot.vaddr_page = vaddr_bits;
                slot.vp_offset = page_select;
                slot.pma_index = selector;
                slot.zero_padding_ = vaddr_bits & 0xFF;
            }
        }
    }
}

#endif // FUZZ_COMMON_H
