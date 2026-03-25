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
/// \brief libFuzzer harness for machine configuration and memory access.
///
/// Fuzzes the machine_config (RAM size, flash drives) and then runs a fixed
/// RISC-V program that exercises every load, store, and atomic memory
/// instruction variant against fuzz-selected physical addresses.
///
/// The fuzz input is consumed as:
///   1. Machine config: RAM length selector, flash drive count and parameters
///   2. Target addresses: for each of 8 GPRs, a PMA selector byte and a
///      32-bit offset. The address is computed as pma.start + (offset % pma.length),
///      targeting a discovered address range.
///
/// The fixed program uses x1..x8 as base addresses and executes, for each:
///   - All integer loads: lb, lh, lw, ld, lbu, lhu, lwu
///   - All integer stores: sb, sh, sw, sd
///   - FP loads/stores: flw, fld, fsw, fsd
///   - Atomics: lr.w, sc.w, lr.d, sc.d, amoswap.w/d, amoadd.w/d
///
/// This tests the machine constructor with varied configs (PMA layout,
/// address range validation, DTB generation) and the interpreter's memory
/// access paths against unusual physical address maps.

#include "fuzz-common.h"

// ---------------------------------------------------------------------------
// Fixed RISC-V program: all memory access instruction variants
// ---------------------------------------------------------------------------

// Instruction encoding helpers
static constexpr uint32_t rv_load(int rd, int rs1, int funct3) {
    return static_cast<uint32_t>((rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x03);
}

static constexpr uint32_t rv_store(int rs2, int rs1, int funct3) {
    return static_cast<uint32_t>((rs2 << 20) | (rs1 << 15) | (funct3 << 12) | 0x23);
}

static constexpr uint32_t rv_fload(int rd, int rs1, int funct3) {
    return static_cast<uint32_t>((rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x07);
}

static constexpr uint32_t rv_fstore(int rs2, int rs1, int funct3) {
    return static_cast<uint32_t>((rs2 << 20) | (rs1 << 15) | (funct3 << 12) | 0x27);
}

static constexpr uint32_t rv_amo(int funct5, int rs2, int rs1, int funct3, int rd) {
    return static_cast<uint32_t>((funct5 << 27) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x2F);
}

// All load, store, FP load/store, and atomic instructions for one base register.
// Uses x10 (a0) as scratch for integer ops and f0 for FP ops.
// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define MEMOPS(N)                                                                                                      \
    /* Integer loads */                                                                                                \
    rv_load(10, N, 0), /* lb  x10, 0(xN) */                                                                           \
    rv_load(10, N, 1), /* lh  x10, 0(xN) */                                                                           \
    rv_load(10, N, 2), /* lw  x10, 0(xN) */                                                                           \
    rv_load(10, N, 3), /* ld  x10, 0(xN) */                                                                           \
    rv_load(10, N, 4), /* lbu x10, 0(xN) */                                                                           \
    rv_load(10, N, 5), /* lhu x10, 0(xN) */                                                                           \
    rv_load(10, N, 6), /* lwu x10, 0(xN) */                                                                           \
    /* FP loads */                                                                                                     \
    rv_fload(0, N, 2), /* flw f0, 0(xN) */                                                                            \
    rv_fload(0, N, 3), /* fld f0, 0(xN) */                                                                            \
    /* Integer stores */                                                                                               \
    rv_store(10, N, 0), /* sb x10, 0(xN) */                                                                           \
    rv_store(10, N, 1), /* sh x10, 0(xN) */                                                                           \
    rv_store(10, N, 2), /* sw x10, 0(xN) */                                                                           \
    rv_store(10, N, 3), /* sd x10, 0(xN) */                                                                           \
    /* FP stores */                                                                                                    \
    rv_fstore(0, N, 2), /* fsw f0, 0(xN) */                                                                           \
    rv_fstore(0, N, 3), /* fsd f0, 0(xN) */                                                                           \
    /* Atomics (.w) */                                                                                                 \
    rv_amo(0b00010, 0, N, 2, 10),  /* lr.w      x10, (xN) */                                                          \
    rv_amo(0b00011, 10, N, 2, 10), /* sc.w      x10, x10, (xN) */                                                     \
    rv_amo(0b00001, 10, N, 2, 10), /* amoswap.w x10, x10, (xN) */                                                     \
    rv_amo(0b00000, 10, N, 2, 10), /* amoadd.w  x10, x10, (xN) */                                                     \
    /* Atomics (.d) */                                                                                                 \
    rv_amo(0b00010, 0, N, 3, 10),  /* lr.d      x10, (xN) */                                                          \
    rv_amo(0b00011, 10, N, 3, 10), /* sc.d      x10, x10, (xN) */                                                     \
    rv_amo(0b00001, 10, N, 3, 10), /* amoswap.d x10, x10, (xN) */                                                     \
    rv_amo(0b00000, 10, N, 3, 10)  /* amoadd.d  x10, x10, (xN) */
// NOLINTEND(cppcoreguidelines-macro-usage)

static constexpr uint32_t PROGRAM[] = {
    MEMOPS(1), MEMOPS(2), MEMOPS(3), MEMOPS(4),
    MEMOPS(5), MEMOPS(6), MEMOPS(7), MEMOPS(8),
    0x00000000, // unimp (illegal instruction trap → halt)
};

#undef MEMOPS

// ---------------------------------------------------------------------------
// Address selection
// ---------------------------------------------------------------------------

/// \brief Pick a physical address within a discovered PMA.
static uint64_t fuzz_pick_address(fuzz_reader &r, const std::vector<pma_info> &pmas) {
    if (pmas.empty()) {
        return 0;
    }
    const auto &pma = pmas[r.read<uint8_t>() % pmas.size()];
    const uint32_t offset = r.read<uint32_t>();
    return pma.start + (pma.length > 0 ? offset % pma.length : 0);
}

// ---------------------------------------------------------------------------
// Fuzzer entry point
// ---------------------------------------------------------------------------

/// \brief mstatus.FS field (bits 14:13). Set to 3 (Dirty) to enable FP instructions.
static constexpr uint64_t MSTATUS_FS_DIRTY = UINT64_C(3) << 13;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        return 0;
    }

    fuzz_reader r{data, size};

    // -- Build machine config from fuzz input --------------------------------

    nlohmann::json config;

    // RAM: page-aligned length, 4 KiB to 1 MiB
    const uint64_t ram_length =
        std::max(static_cast<uint64_t>(r.read<uint32_t>() % (1U << 20)), PAGE_SIZE) & ~(PAGE_SIZE - 1);
    config["ram"]["length"] = ram_length;

    // Flash drives: 0 to 9 (max valid is FLASH_DRIVE_MAX=8, so 9 tests the rejection path).
    // Each drive's start is derived from the previous drive's end plus a fuzz-controlled
    // gap. The gap is usually positive (valid non-overlapping layout) but a fuzz byte
    // selects edge cases:
    //   0x00-0x0F: same start as previous (duplicate)
    //   0x10-0x1F: overlap by one page into previous
    //   0x20-0x2F: adjacent (gap = 0, starts exactly where previous ends)
    //   0x30-0xFF: normal gap (pages between drives)
    const uint8_t num_flash = r.read<uint8_t>() % 10;
    if (num_flash > 0) {
        auto flash = nlohmann::json::array();
        uint64_t next_start = RAM_START + ram_length;
        for (uint8_t i = 0; i < num_flash; i++) {
            const uint64_t length =
                std::max(static_cast<uint64_t>(r.read<uint32_t>() % (1U << 20)), PAGE_SIZE) & ~(PAGE_SIZE - 1);
            const uint8_t gap_sel = r.read<uint8_t>();
            uint64_t start = 0;
            if (gap_sel < 0x10) {
                start = next_start - length;
            } else if (gap_sel < 0x20) {
                start = (next_start >= PAGE_SIZE) ? next_start - PAGE_SIZE : next_start;
            } else if (gap_sel < 0x30) {
                start = next_start;
            } else {
                start = next_start + (static_cast<uint64_t>(gap_sel - 0x30) + 1) * PAGE_SIZE;
            }
            start &= ~(PAGE_SIZE - 1);

            nlohmann::json fd;
            fd["start"] = start;
            fd["length"] = length;
            fd["read_only"] = (r.read<uint8_t>() & 1) != 0;
            flash.push_back(fd);

            next_start = start + length;
        }
        config["flash_drive"] = flash;
    }

    // -- Create machine ------------------------------------------------------

    const auto config_str = config.dump();
    cm_machine *machine = nullptr;
    if (cm_create_new(config_str.c_str(), nullptr, nullptr, &machine) != CM_ERROR_OK) {
        return 0;
    }

    // -- Set up target addresses in x1..x8 -----------------------------------

    const auto pmas = fuzz_discover_pmas(machine);

    for (int i = 1; i <= 8; i++) {
        cm_write_reg(machine, static_cast<cm_reg>(CM_REG_X0 + i), fuzz_pick_address(r, pmas));
    }

    // Enable FP instructions (mstatus.FS = Dirty)
    uint64_t mstatus = 0;
    cm_read_reg(machine, CM_REG_MSTATUS, &mstatus);
    cm_write_reg(machine, CM_REG_MSTATUS, mstatus | MSTATUS_FS_DIRTY);

    // -- Write fixed program into RAM and run --------------------------------

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    cm_write_memory(machine, RAM_START, reinterpret_cast<const uint8_t *>(PROGRAM), sizeof(PROGRAM));

    cm_break_reason break_reason{};
    cm_run(machine, MAX_MCYCLE, &break_reason);

    cm_delete(machine);
    return 0;
}
